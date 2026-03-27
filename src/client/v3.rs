//! SNMPv3-specific client functionality.
//!
//! This module contains V3 security configuration, key derivation, engine discovery,
//! and V3 message building/handling.

use crate::ber::Decoder;
use crate::error::internal::{AuthErrorKind, CryptoErrorKind, DecodeErrorKind, EncodeErrorKind};
use crate::error::{Error, ErrorStatus, Result};
use crate::format::hex;
use crate::message::{MsgFlags, MsgGlobalData, ScopedPdu, V3Message};
use crate::pdu::{Pdu, PduType};
use crate::transport::Transport;
use crate::v3::{
    UsmSecurityParams,
    auth::{authenticate_message, verify_message},
    is_not_in_time_window_report, is_unknown_engine_id_report,
};
use bytes::Bytes;
use std::net::SocketAddr;
use std::time::Instant;
use tracing::{Span, instrument};

use super::Client;

// V3-specific Client implementation
impl<T: Transport> Client<T> {
    /// Ensure engine ID is discovered for V3 operations.
    #[instrument(level = "debug", skip(self), fields(snmp.target = %self.peer_addr()))]
    pub(super) async fn ensure_engine_discovered(&self) -> Result<()> {
        // Check if already discovered
        {
            let state = self
                .inner
                .engine_state
                .read()
                .expect("engine_state lock poisoned");
            if state.is_some() {
                return Ok(());
            }
        }

        // Check shared cache first
        if let Some(cache) = &self.inner.engine_cache
            && let Some(cached_state) = cache.get(&self.peer_addr())
        {
            tracing::debug!(target: "async_snmp::client", "using cached engine state");
            let mut state = self
                .inner
                .engine_state
                .write()
                .expect("engine_state lock poisoned");
            *state = Some(cached_state.clone());
            // Derive keys for this engine
            if let Some(security) = &self.inner.config.v3_security {
                let keys = security.derive_keys(&cached_state.engine_id);
                let mut derived = self
                    .inner
                    .derived_keys
                    .write()
                    .expect("derived_keys lock poisoned");
                *derived = Some(keys);
            }
            return Ok(());
        }

        // Perform discovery with retry (same policy as normal requests)
        tracing::debug!(target: "async_snmp::client", "performing engine discovery");

        let max_attempts = if self.inner.transport.is_reliable() {
            0
        } else {
            self.inner.config.retry.max_attempts
        };

        let mut last_error: Option<Box<Error>> = None;
        let mut response_data_opt: Option<(Bytes, SocketAddr)> = None;

        'discovery: for attempt in 0..=max_attempts {
            if attempt > 0 {
                tracing::debug!(target: "async_snmp::client", "retrying engine discovery");
            }

            let msg_id = self.next_request_id();
            let discovery_msg = V3Message::discovery_request(msg_id);
            let discovery_data = discovery_msg.encode();

            self.inner
                .transport
                .register_request(msg_id, self.inner.config.timeout);
            self.inner.transport.send(&discovery_data).await?;

            match self.inner.transport.recv(msg_id).await {
                Ok(result) => {
                    response_data_opt = Some(result);
                    break 'discovery;
                }
                Err(e) if matches!(*e, Error::Timeout { .. }) => {
                    last_error = Some(e);
                    if attempt < max_attempts {
                        let delay = self.inner.config.retry.compute_delay(attempt);
                        if !delay.is_zero() {
                            tracing::debug!(target: "async_snmp::client", { delay_ms = delay.as_millis() as u64 }, "backing off");
                            tokio::time::sleep(delay).await;
                        }
                    }
                    continue;
                }
                Err(e) => return Err(e),
            }
        }

        let (response_data, _source) = response_data_opt.ok_or_else(|| {
            last_error.unwrap_or_else(|| {
                Error::Timeout {
                    target: self.peer_addr(),
                    elapsed: std::time::Duration::ZERO,
                    retries: max_attempts,
                }
                .boxed()
            })
        })?;

        // Parse response
        let response = V3Message::decode(response_data)?;

        let reported_msg_max_size = response.global_data.msg_max_size as u32;
        let session_max = self.inner.transport.max_message_size();
        let engine_state = crate::v3::parse_discovery_response_with_limits(
            &response.security_params,
            reported_msg_max_size,
            session_max,
        )?;
        tracing::debug!(target: "async_snmp::client", { snmp.engine_id = %hex::Bytes(&engine_state.engine_id), snmp.engine_boots = engine_state.engine_boots, snmp.engine_time = engine_state.engine_time, snmp.msg_max_size = engine_state.msg_max_size }, "discovered engine");

        // Derive keys for this engine
        if let Some(security) = &self.inner.config.v3_security {
            let keys = security.derive_keys(&engine_state.engine_id);
            let mut derived = self
                .inner
                .derived_keys
                .write()
                .expect("derived_keys lock poisoned");
            *derived = Some(keys);
        }

        // Store in local cache
        {
            let mut state = self
                .inner
                .engine_state
                .write()
                .expect("engine_state lock poisoned");
            *state = Some(engine_state.clone());
        }

        // Store in shared cache if present
        if let Some(cache) = &self.inner.engine_cache {
            cache.insert(self.peer_addr(), engine_state);
        }

        Ok(())
    }

    /// Build and encode a V3 message with authentication and/or encryption.
    ///
    /// The `msg_id` parameter is separate from `pdu.request_id` per RFC 3412
    /// Section 6.2: retransmissions SHOULD use a new msgID for each attempt.
    pub(super) fn build_v3_message(&self, pdu: &Pdu, msg_id: i32) -> Result<Vec<u8>> {
        let security = self.inner.config.v3_security.as_ref().ok_or_else(|| {
            tracing::debug!(target: "async_snmp::client", { kind = %EncodeErrorKind::NoSecurityConfig }, "V3 security not configured");
            Error::Config("V3 security not configured".into()).boxed()
        })?;

        let engine_state = self
            .inner
            .engine_state
            .read()
            .expect("engine_state lock poisoned");
        let engine_state = engine_state.as_ref().ok_or_else(|| {
            tracing::debug!(target: "async_snmp::client", { kind = %EncodeErrorKind::EngineNotDiscovered }, "engine not discovered");
            Error::Config("engine not discovered".into()).boxed()
        })?;

        let derived = self
            .inner
            .derived_keys
            .read()
            .expect("derived_keys lock poisoned");

        let security_level = security.security_level();

        // Build scoped PDU
        let scoped_pdu = ScopedPdu::new(
            engine_state.engine_id.clone(),
            security.context_name.clone(),
            pdu.clone(),
        );

        // Get current engine time estimate
        let engine_boots = engine_state.engine_boots;
        let engine_time = engine_state.estimated_time();

        // Handle encryption if needed
        let (msg_data, priv_params) = if security_level.requires_priv() {
            tracing::trace!(target: "async_snmp::client", "encrypting scoped PDU");

            // Get mutable priv_key - we need interior mutability for salt counter
            // Since PrivKey uses internal counter, we need to clone and use
            let derived_ref = derived.as_ref().ok_or_else(|| {
                tracing::debug!(target: "async_snmp::client", { kind = %EncodeErrorKind::KeysNotDerived }, "keys not derived");
                Error::Config("keys not derived".into()).boxed()
            })?;
            let mut priv_key = derived_ref
                .priv_key
                .as_ref()
                .ok_or_else(|| {
                    tracing::debug!(target: "async_snmp::client", { kind = %EncodeErrorKind::NoPrivKey }, "privacy key not available");
                    Error::Config("privacy key not available".into()).boxed()
                })?
                .clone();

            // Encode scoped PDU
            let scoped_pdu_bytes = scoped_pdu.encode_to_bytes();

            // Encrypt
            let (ciphertext, salt) = priv_key
                .encrypt(
                    &scoped_pdu_bytes,
                    engine_boots,
                    engine_time,
                    Some(&self.inner.salt_counter),
                )
                .map_err(|e| {
                    tracing::warn!(target: "async_snmp::crypto", { peer = %self.peer_addr(), error = %e }, "encryption failed");
                    Error::Auth {
                        target: self.peer_addr(),
                    }
                    .boxed()
                })?;

            tracing::trace!(target: "async_snmp::client", { plaintext_len = scoped_pdu_bytes.len(), ciphertext_len = ciphertext.len() }, "encrypted scoped PDU");

            (crate::message::V3MessageData::Encrypted(ciphertext), salt)
        } else {
            (
                crate::message::V3MessageData::Plaintext(scoped_pdu),
                Bytes::new(),
            )
        };

        // Build USM security parameters
        let mac_len = if security_level.requires_auth() {
            derived
                .as_ref()
                .and_then(|d| d.auth_key.as_ref())
                .map(|k| k.mac_len())
                .unwrap_or(12)
        } else {
            0
        };

        let mut usm_params = UsmSecurityParams::new(
            engine_state.engine_id.clone(),
            engine_boots,
            engine_time,
            security.username.clone(),
        );

        if security_level.requires_auth() {
            usm_params = usm_params.with_auth_placeholder(mac_len);
        }

        if security_level.requires_priv() {
            usm_params = usm_params.with_priv_params(priv_params);
        }

        let usm_encoded = usm_params.encode();

        // Build global data
        let msg_flags = MsgFlags::new(security_level, true); // reportable=true for requests
        let global_data = MsgGlobalData::new(msg_id, 65507, msg_flags);

        // Build complete message
        let msg = match msg_data {
            crate::message::V3MessageData::Plaintext(scoped_pdu) => {
                V3Message::new(global_data, usm_encoded, scoped_pdu)
            }
            crate::message::V3MessageData::Encrypted(ciphertext) => {
                V3Message::new_encrypted(global_data, usm_encoded, ciphertext)
            }
        };

        let mut encoded = msg.encode().to_vec();

        // Apply authentication if needed
        if security_level.requires_auth() {
            tracing::trace!(target: "async_snmp::client", "applying HMAC authentication");

            let auth_key = derived
                .as_ref()
                .and_then(|d| d.auth_key.as_ref())
                .ok_or_else(|| {
                    tracing::debug!(target: "async_snmp::client", { kind = %EncodeErrorKind::MissingAuthKey }, "auth key not available for encoding");
                    Error::Config("auth key not available".into()).boxed()
                })?;

            // Find auth params position and apply HMAC
            if let Some((offset, len)) = UsmSecurityParams::find_auth_params_offset(&encoded) {
                authenticate_message(auth_key, &mut encoded, offset, len);
                tracing::trace!(target: "async_snmp::client", { auth_params_offset = offset, auth_params_len = len }, "applied HMAC authentication");
            } else {
                tracing::debug!(target: "async_snmp::client", { kind = %EncodeErrorKind::MissingAuthParams }, "could not find auth params position");
                return Err(Error::Config("could not find auth params position".into()).boxed());
            }
        }

        Ok(encoded)
    }

    /// Verify HMAC authentication on a V3 response message.
    fn verify_response_auth(&self, response_data: &[u8]) -> Result<()> {
        tracing::trace!(target: "async_snmp::client", "verifying HMAC authentication on response");

        let derived = self
            .inner
            .derived_keys
            .read()
            .expect("derived_keys lock poisoned");
        let auth_key = derived
            .as_ref()
            .and_then(|d| d.auth_key.as_ref())
            .ok_or_else(|| {
                tracing::warn!(target: "async_snmp::client", { peer = %self.peer_addr(), kind = %AuthErrorKind::NoAuthKey }, "authentication failed");
                Error::Auth {
                    target: self.peer_addr(),
                }
                .boxed()
            })?;

        let (offset, len) = UsmSecurityParams::find_auth_params_offset(response_data).ok_or_else(
            || {
                tracing::warn!(target: "async_snmp::client", { peer = %self.peer_addr(), kind = %AuthErrorKind::AuthParamsNotFound }, "authentication failed");
                Error::Auth {
                    target: self.peer_addr(),
                }
                .boxed()
            },
        )?;

        if !verify_message(auth_key, response_data, offset, len) {
            tracing::warn!(target: "async_snmp::client", { peer = %self.peer_addr(), kind = %AuthErrorKind::HmacMismatch }, "authentication failed");
            return Err(Error::Auth {
                target: self.peer_addr(),
            }
            .boxed());
        }

        tracing::trace!(target: "async_snmp::client", { auth_params_offset = offset, auth_params_len = len }, "HMAC verification successful");
        Ok(())
    }

    /// Decrypt an encrypted V3 response and extract the PDU.
    fn decrypt_response_pdu(&self, response: V3Message, security_params: &Bytes) -> Result<Pdu> {
        match response.data {
            crate::message::V3MessageData::Encrypted(ciphertext) => {
                tracing::trace!(target: "async_snmp::client", { ciphertext_len = ciphertext.len() }, "decrypting response");

                let derived = self
                    .inner
                    .derived_keys
                    .read()
                    .expect("derived_keys lock poisoned");
                let priv_key =
                    derived
                        .as_ref()
                        .and_then(|d| d.priv_key.as_ref())
                        .ok_or_else(|| {
                            tracing::warn!(target: "async_snmp::client", { peer = %self.peer_addr(), kind = %CryptoErrorKind::NoPrivKey }, "decryption failed");
                            Error::Auth {
                                target: self.peer_addr(),
                            }
                            .boxed()
                        })?;

                let usm_params = UsmSecurityParams::decode(security_params.clone())?;
                let plaintext = priv_key
                    .decrypt(
                        &ciphertext,
                        usm_params.engine_boots,
                        usm_params.engine_time,
                        &usm_params.priv_params,
                    )
                    .map_err(|e| {
                        tracing::warn!(target: "async_snmp::crypto", { peer = %self.peer_addr(), error = %e }, "decryption failed");
                        Error::Auth {
                            target: self.peer_addr(),
                        }
                        .boxed()
                    })?;

                tracing::trace!(target: "async_snmp::client", { plaintext_len = plaintext.len() }, "decrypted response");

                let mut decoder = Decoder::with_target(plaintext, self.peer_addr());
                let scoped_pdu = ScopedPdu::decode(&mut decoder)?;
                Ok(scoped_pdu.pdu)
            }
            crate::message::V3MessageData::Plaintext(scoped_pdu) => Ok(scoped_pdu.pdu),
        }
    }

    /// Send a V3 request and handle the response.
    #[instrument(
        level = "debug",
        skip(self, pdu),
        fields(
            snmp.target = %self.peer_addr(),
            snmp.request_id = pdu.request_id,
            snmp.security_level = ?self.inner.config.v3_security.as_ref().map(|s| s.security_level()),
            snmp.attempt = tracing::field::Empty,
            snmp.elapsed_ms = tracing::field::Empty,
        )
    )]
    pub(super) async fn send_v3_and_recv(&self, pdu: Pdu) -> Result<Pdu> {
        let start = Instant::now();

        // Ensure engine is discovered first
        self.ensure_engine_discovered().await?;

        let security = self.inner.config.v3_security.as_ref().ok_or_else(|| {
            tracing::debug!(target: "async_snmp::client", { kind = %EncodeErrorKind::NoSecurityConfig }, "V3 security not configured");
            Error::Config("V3 security not configured".into()).boxed()
        })?;
        let security_level = security.security_level();

        let mut last_error: Option<Box<Error>> = None;
        let max_attempts = if self.inner.transport.is_reliable() {
            0
        } else {
            self.inner.config.retry.max_attempts
        };

        for attempt in 0..=max_attempts {
            Span::current().record("snmp.attempt", attempt);
            if attempt > 0 {
                tracing::debug!(target: "async_snmp::client", "retrying V3 request");
            }

            // RFC 3412 Section 6.2: use fresh msgID for each transmission attempt
            let msg_id = self.next_request_id();
            let data = self.build_v3_message(&pdu, msg_id)?;

            tracing::debug!(target: "async_snmp::client", { snmp.pdu_type = ?pdu.pdu_type, snmp.varbind_count = pdu.varbinds.len(), snmp.msg_id = msg_id }, "sending V3 {} request", pdu.pdu_type);
            tracing::trace!(target: "async_snmp::client", { snmp.bytes = data.len() }, "sending V3 request");

            // Register (or re-register) with fresh deadline before sending
            self.inner
                .transport
                .register_request(msg_id, self.inner.config.timeout);

            // Send request
            self.inner.transport.send(&data).await?;

            // Wait for response (deadline was set by register_request)
            match self.inner.transport.recv(msg_id).await {
                Ok((response_data, _source)) => {
                    tracing::trace!(target: "async_snmp::client", { snmp.bytes = response_data.len() }, "received V3 response");

                    // Verify authentication if required
                    if security_level.requires_auth() {
                        self.verify_response_auth(&response_data)?;
                    }

                    // Decode response
                    let response = V3Message::decode(response_data)?;

                    // Check for Report PDU (error response)
                    if let Some(scoped_pdu) = response.scoped_pdu()
                        && scoped_pdu.pdu.pdu_type == PduType::Report
                    {
                        // Check for time window error - resync and retry
                        if is_not_in_time_window_report(&scoped_pdu.pdu) {
                            tracing::debug!(target: "async_snmp::client", "not in time window, resyncing");
                            // Update engine time from response
                            let usm_params =
                                UsmSecurityParams::decode(response.security_params.clone())?;
                            {
                                let mut state = self
                                    .inner
                                    .engine_state
                                    .write()
                                    .expect("engine_state lock poisoned");
                                if let Some(ref mut s) = *state {
                                    s.update_time(usm_params.engine_boots, usm_params.engine_time);
                                }
                            }
                            last_error = Some(
                                Error::Auth {
                                    target: self.peer_addr(),
                                }
                                .boxed(),
                            );
                            // Apply backoff delay before retry (if not last attempt)
                            if attempt < max_attempts {
                                let delay = self.inner.config.retry.compute_delay(attempt);
                                if !delay.is_zero() {
                                    tracing::debug!(target: "async_snmp::client", { delay_ms = delay.as_millis() as u64 }, "backing off");
                                    tokio::time::sleep(delay).await;
                                }
                            }
                            continue;
                        }

                        // Check for unknown engine ID
                        if is_unknown_engine_id_report(&scoped_pdu.pdu) {
                            tracing::warn!(target: "async_snmp::client", { peer = %self.peer_addr() }, "unknown engine ID");
                            return Err(Error::Auth {
                                target: self.peer_addr(),
                            }
                            .boxed());
                        }

                        // Other Report errors
                        return Err(Error::Snmp {
                            target: self.peer_addr(),
                            status: ErrorStatus::GenErr,
                            index: 0,
                            oid: scoped_pdu.pdu.varbinds.first().map(|vb| vb.oid.clone()),
                        }
                        .boxed());
                    }

                    // Extract security params before consuming response
                    let response_security_params = response.security_params.clone();

                    // Extract PDU (with decryption if required)
                    let response_pdu = if security_level.requires_priv() {
                        self.decrypt_response_pdu(response, &response_security_params)?
                    } else {
                        response.into_pdu().ok_or_else(|| {
                            tracing::debug!(target: "async_snmp::client", { peer = %self.peer_addr(), kind = %DecodeErrorKind::MissingPdu }, "missing PDU in response");
                            Error::MalformedResponse {
                                target: self.peer_addr(),
                            }
                            .boxed()
                        })?
                    };

                    // Validate request ID
                    if response_pdu.request_id != pdu.request_id {
                        tracing::warn!(target: "async_snmp::client", { expected_request_id = pdu.request_id, actual_request_id = response_pdu.request_id, peer = %self.peer_addr() }, "request ID mismatch in response");
                        return Err(Error::MalformedResponse {
                            target: self.peer_addr(),
                        }
                        .boxed());
                    }

                    tracing::debug!(target: "async_snmp::client", { snmp.pdu_type = ?response_pdu.pdu_type, snmp.varbind_count = response_pdu.varbinds.len(), snmp.error_status = response_pdu.error_status, snmp.error_index = response_pdu.error_index }, "received V3 {} response", response_pdu.pdu_type);

                    // Update engine time from successful response
                    {
                        let usm_params = UsmSecurityParams::decode(response_security_params)?;
                        let mut state = self
                            .inner
                            .engine_state
                            .write()
                            .expect("engine_state lock poisoned");
                        if let Some(ref mut s) = *state {
                            s.update_time(usm_params.engine_boots, usm_params.engine_time);
                        }
                    }

                    // Check for SNMP error
                    if response_pdu.is_error() {
                        let status = response_pdu.error_status_enum();
                        // error_index is 1-based; 0 means error applies to PDU, not a specific varbind
                        let oid = (response_pdu.error_index as usize)
                            .checked_sub(1)
                            .and_then(|idx| response_pdu.varbinds.get(idx))
                            .map(|vb| vb.oid.clone());

                        Span::current()
                            .record("snmp.elapsed_ms", start.elapsed().as_millis() as u64);
                        return Err(Error::Snmp {
                            target: self.peer_addr(),
                            status,
                            index: response_pdu.error_index.max(0) as u32,
                            oid,
                        }
                        .boxed());
                    }

                    Span::current().record("snmp.elapsed_ms", start.elapsed().as_millis() as u64);
                    return Ok(response_pdu);
                }
                Err(e) if matches!(*e, Error::Timeout { .. }) => {
                    last_error = Some(e);
                    // Apply backoff delay before next retry (if not last attempt)
                    if attempt < max_attempts {
                        let delay = self.inner.config.retry.compute_delay(attempt);
                        if !delay.is_zero() {
                            tracing::debug!(target: "async_snmp::client", { delay_ms = delay.as_millis() as u64 }, "backing off");
                            tokio::time::sleep(delay).await;
                        }
                    }
                    continue;
                }
                Err(e) => {
                    Span::current().record("snmp.elapsed_ms", start.elapsed().as_millis() as u64);
                    return Err(e);
                }
            }
        }

        // All retries exhausted
        let elapsed = start.elapsed();
        Span::current().record("snmp.elapsed_ms", elapsed.as_millis() as u64);
        tracing::debug!(target: "async_snmp::client", { request_id = pdu.request_id, peer = %self.peer_addr(), ?elapsed, retries = max_attempts }, "request timed out");
        Err(last_error.unwrap_or_else(|| {
            Error::Timeout {
                target: self.peer_addr(),
                elapsed,
                retries: max_attempts,
            }
            .boxed()
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::UsmConfig;
    use crate::client::ClientConfig;
    use crate::message::V3MessageData;
    use crate::oid;
    use crate::transport::Transport;
    use crate::v3::EngineState;
    use bytes::Bytes;
    use std::future::ready;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    #[derive(Clone)]
    struct TestTransport {
        peer: SocketAddr,
    }

    impl TestTransport {
        fn new() -> Self {
            Self {
                peer: SocketAddr::from((Ipv4Addr::LOCALHOST, 161)),
            }
        }
    }

    impl Transport for TestTransport {
        fn send(&self, _data: &[u8]) -> impl std::future::Future<Output = Result<()>> + Send {
            ready(Ok(()))
        }

        fn recv(
            &self,
            _request_id: i32,
        ) -> impl std::future::Future<Output = Result<(Bytes, SocketAddr)>> + Send {
            ready(Err(Error::Config(
                "test transport does not receive data".into(),
            )
            .boxed()))
        }

        fn peer_addr(&self) -> SocketAddr {
            self.peer
        }

        fn local_addr(&self) -> SocketAddr {
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
        }

        fn is_reliable(&self) -> bool {
            false
        }

        fn register_request(&self, _request_id: i32, _timeout: Duration) {}
    }

    #[test]
    fn test_build_v3_message_uses_configured_context_name() {
        let transport = TestTransport::new();
        let config = ClientConfig {
            version: crate::version::Version::V3,
            v3_security: Some(UsmConfig::new("user").context_name("ctx")),
            ..ClientConfig::default()
        };
        let client = Client::new(transport, config);

        {
            let mut state = client
                .inner
                .engine_state
                .write()
                .expect("engine_state lock poisoned");
            *state = Some(EngineState::new(Bytes::from_static(b"engine"), 1, 42));
        }

        let pdu = Pdu::get_request(123, &[oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)]);

        let encoded = client
            .build_v3_message(&pdu, 456)
            .expect("v3 message should encode");
        let decoded = V3Message::decode(Bytes::from(encoded)).expect("v3 message should decode");
        let scoped = match decoded.data {
            V3MessageData::Plaintext(scoped) => scoped,
            V3MessageData::Encrypted(_) => panic!("expected plaintext scoped PDU"),
        };

        assert_eq!(scoped.context_name.as_ref(), b"ctx");
    }

    /// Transport that times out on the first recv call, then returns a valid
    /// discovery response on subsequent calls.
    #[derive(Clone)]
    struct RetryTestTransport {
        peer: SocketAddr,
        recv_count: Arc<AtomicU32>,
        discovery_response: Bytes,
    }

    impl RetryTestTransport {
        fn new(discovery_response: Bytes) -> Self {
            Self {
                peer: SocketAddr::from((Ipv4Addr::LOCALHOST, 161)),
                recv_count: Arc::new(AtomicU32::new(0)),
                discovery_response,
            }
        }
    }

    impl Transport for RetryTestTransport {
        fn send(&self, _data: &[u8]) -> impl std::future::Future<Output = Result<()>> + Send {
            ready(Ok(()))
        }

        fn recv(
            &self,
            _request_id: i32,
        ) -> impl std::future::Future<Output = Result<(Bytes, SocketAddr)>> + Send {
            let count = self.recv_count.fetch_add(1, Ordering::Relaxed);
            let peer = self.peer;
            let response = self.discovery_response.clone();
            async move {
                if count == 0 {
                    // First call: simulate a timeout
                    Err(Error::Timeout {
                        target: peer,
                        elapsed: Duration::from_secs(5),
                        retries: 0,
                    }
                    .boxed())
                } else {
                    Ok((response, peer))
                }
            }
        }

        fn peer_addr(&self) -> SocketAddr {
            self.peer
        }

        fn local_addr(&self) -> SocketAddr {
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
        }

        fn is_reliable(&self) -> bool {
            false
        }

        fn register_request(&self, _request_id: i32, _timeout: Duration) {}
    }

    /// Build a minimal valid discovery response with the given engine ID.
    fn build_discovery_response(engine_id: &[u8]) -> Bytes {
        use crate::message::{MsgFlags, MsgGlobalData, ScopedPdu, V3Message};
        use crate::pdu::{Pdu, PduType};
        use crate::v3::UsmSecurityParams;
        use crate::value::Value;
        use crate::varbind::VarBind;

        let report_pdu = Pdu {
            pdu_type: PduType::Report,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbinds: vec![VarBind::new(
                crate::oid!(1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0),
                Value::Counter32(0),
            )],
        };

        let global = MsgGlobalData::new(
            1,
            65507,
            MsgFlags::new(crate::message::SecurityLevel::NoAuthNoPriv, false),
        );
        let usm = UsmSecurityParams::new(Bytes::copy_from_slice(engine_id), 1, 100, Bytes::new());
        let scoped = ScopedPdu::new(Bytes::copy_from_slice(engine_id), Bytes::new(), report_pdu);

        V3Message::new(global, usm.encode(), scoped).encode()
    }

    #[tokio::test]
    async fn test_discovery_retries_on_timeout() {
        let engine_id = b"test-engine";
        let response = build_discovery_response(engine_id);
        let transport = RetryTestTransport::new(response);
        let recv_count = transport.recv_count.clone();

        let config = ClientConfig {
            version: crate::version::Version::V3,
            v3_security: Some(UsmConfig::new("user")),
            retry: crate::client::Retry::fixed(1, Duration::ZERO),
            ..ClientConfig::default()
        };
        let client = Client::new(transport, config);

        client
            .ensure_engine_discovered()
            .await
            .expect("discovery should succeed after retry");

        // recv was called twice: once for the timeout, once for the success
        assert_eq!(recv_count.load(Ordering::Relaxed), 2);

        // Engine state should be set
        let state = client
            .inner
            .engine_state
            .read()
            .expect("engine_state lock poisoned");
        assert!(state.is_some());
        assert_eq!(state.as_ref().unwrap().engine_id.as_ref(), engine_id);
    }

    #[tokio::test]
    async fn test_discovery_fails_when_all_retries_timeout() {
        // Transport that always times out
        #[derive(Clone)]
        struct AlwaysTimeoutTransport {
            peer: SocketAddr,
        }
        impl Transport for AlwaysTimeoutTransport {
            fn send(&self, _data: &[u8]) -> impl std::future::Future<Output = Result<()>> + Send {
                ready(Ok(()))
            }
            fn recv(
                &self,
                _request_id: i32,
            ) -> impl std::future::Future<Output = Result<(Bytes, SocketAddr)>> + Send {
                let peer = self.peer;
                async move {
                    Err(Error::Timeout {
                        target: peer,
                        elapsed: Duration::from_secs(5),
                        retries: 0,
                    }
                    .boxed())
                }
            }
            fn peer_addr(&self) -> SocketAddr {
                self.peer
            }
            fn local_addr(&self) -> SocketAddr {
                SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
            }
            fn is_reliable(&self) -> bool {
                false
            }
            fn register_request(&self, _request_id: i32, _timeout: Duration) {}
        }

        let transport = AlwaysTimeoutTransport {
            peer: SocketAddr::from((Ipv4Addr::LOCALHOST, 161)),
        };
        let config = ClientConfig {
            version: crate::version::Version::V3,
            v3_security: Some(UsmConfig::new("user")),
            retry: crate::client::Retry::fixed(2, Duration::ZERO),
            ..ClientConfig::default()
        };
        let client = Client::new(transport, config);

        let result = client.ensure_engine_discovered().await;
        assert!(
            matches!(*result.unwrap_err(), Error::Timeout { .. }),
            "should return Timeout after all retries exhausted"
        );
    }
}
