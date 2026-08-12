//! SNMPv3-specific client functionality.
//!
//! This module contains V3 security configuration, key derivation, engine discovery,
//! and V3 message building/handling.

use crate::ber::EncodeBuf;
use crate::error::internal::{AuthErrorKind, CryptoErrorKind};
use crate::error::{Error, Result};
use crate::format::hex;
use crate::message::{
    RawMsgData, RawV3Message, ScopedPdu, SecurityLevel, V3Message, combine_staged_v3_anomalies,
    decode_scoped_pdu_with_policies,
};
use crate::pdu::{Pdu, PduType};
use crate::transport::{Candidate, RequestRegistration, Transport};
use crate::v3::{
    EngineCache, EngineState, ReportStatus, UsmSecurityParams, auth::verify_message,
    classify_report, validate_engine_id,
};
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tracing::{Span, instrument};

use super::{Client, ClientEngine, DecodedResponse, ResponseMetadata};

struct EncodedV3Request {
    data: Vec<u8>,
    context_engine_id: Bytes,
    context_name: Bytes,
}

struct PacketLocalEngineTime {
    engine_id: Bytes,
    boots: u32,
    time: u32,
}

struct ValidatedV3Response {
    usm: UsmSecurityParams,
    received_level: SecurityLevel,
    scoped_pdu: ScopedPdu,
    authenticated_generation: Option<Arc<()>>,
    decode_anomalies: Vec<crate::DecodeAnomaly>,
}

struct DiscoveryResponse {
    engine_state: EngineState,
    metadata: ResponseMetadata,
}

fn check_and_update_engine_timeliness(
    state: &mut EngineState,
    cache: Option<&EngineCache>,
    target: SocketAddr,
    engine_id: &[u8],
    msg_boots: u32,
    msg_time: u32,
) -> Option<bool> {
    if state.engine_id.as_ref() != engine_id {
        return None;
    }

    if let Some(cache) = cache {
        let (timely, cached_state) =
            cache.check_and_update_timeliness(&target, state, engine_id, msg_boots, msg_time)?;
        state.merge_from(&cached_state);
        return Some(timely);
    }

    let timely = state.check_and_update_timeliness(msg_boots, msg_time);
    Some(timely)
}

// V3-specific Client implementation
impl<T: Transport> Client<T> {
    /// Ensure engine ID is discovered for V3 operations.
    #[instrument(level = "debug", skip(self), fields(snmp.target = %self.peer_addr()))]
    pub(super) async fn ensure_engine_discovered(&self) -> Result<ResponseMetadata> {
        // Fast path: already discovered.
        {
            let engine = self
                .inner
                .engine
                .read()
                .map_err(|_| Error::Config("engine lock poisoned".into()).boxed())?;
            if engine.is_some() {
                return Ok(ResponseMetadata::default());
            }
        }

        // Serialize concurrent discovery attempts. Only one task runs discovery
        // at a time; the rest wait here and then take the fast path above.
        let _guard = self.inner.discovery_lock.lock().await;
        self.discover_engine_locked(false).await
    }

    /// Discover and replace the established authoritative engine.
    ///
    /// This is the intentional recovery path when a device at the target
    /// address has been replaced or reconfigured with a new engine ID.
    /// Discovery never replaces an established identity during ordinary
    /// request processing. The current identity, localized keys, and shared
    /// cache mapping remain usable until a fresh response has been strictly
    /// validated and replacement keys have been derived. A failed or cancelled
    /// rediscovery therefore leaves the previous generation intact.
    ///
    /// Client clones share a successful replacement because they share the
    /// same live engine state. Independently constructed clients retain their
    /// own established identity until explicitly rediscovered. For UDP,
    /// source-address policy is controlled by
    /// [`ClientBuilder::strict_source`](crate::ClientBuilder::strict_source) or
    /// by the supplied transport handle.
    ///
    /// This convenience method discards accepted discovery-response metadata.
    /// Use [`Self::rediscover_engine_with_metadata`] to retain it.
    pub async fn rediscover_engine(&self) -> Result<()> {
        self.rediscover_engine_with_metadata().await.map(|_| ())
    }

    /// Discover and replace the authoritative engine while retaining accepted
    /// wire deviations from the discovery Report.
    pub async fn rediscover_engine_with_metadata(&self) -> Result<ResponseMetadata> {
        if !self.is_v3() {
            return Err(Error::Config("engine discovery requires SNMPv3".into()).boxed());
        }

        let _guard = self.inner.discovery_lock.lock().await;
        self.discover_engine_locked(true).await
    }

    /// Load or discover an engine while `discovery_lock` is held.
    async fn discover_engine_locked(
        &self,
        replace_cached_identity: bool,
    ) -> Result<ResponseMetadata> {
        // Re-check after acquiring the lock: a previous waiter may have
        // completed ordinary discovery while we were blocked. Explicit
        // rediscovery always reaches the peer even with a live identity.
        if !replace_cached_identity {
            let engine = self
                .inner
                .engine
                .read()
                .map_err(|_| Error::Config("engine lock poisoned".into()).boxed())?;
            if engine.is_some() {
                return Ok(ResponseMetadata::default());
            }
        }

        // Explicit rediscovery must reach the peer even if another client
        // refreshes the previous target mapping while discovery is in progress.
        if !replace_cached_identity
            && let Some(cache) = &self.inner.engine_cache
            && let Some(cached_state) = cache.get(&self.peer_addr())
        {
            tracing::debug!(target: "async_snmp::client", "using cached engine state");
            let security = self
                .inner
                .config
                .usm_config()
                .ok_or_else(|| Error::Config("V3 security not configured".into()).boxed())?;
            let derived_keys = security
                .derive_keys(&cached_state.engine_id)
                .map_err(|e| Error::Config(e.to_string().into()).boxed())?;
            let mut engine = self
                .inner
                .engine
                .write()
                .map_err(|_| Error::Config("engine lock poisoned".into()).boxed())?;
            *engine = Some(ClientEngine::new(cached_state, derived_keys));
            return Ok(ResponseMetadata::default());
        }

        // Perform discovery with retry (same policy as normal requests)
        tracing::debug!(target: "async_snmp::client", "performing engine discovery");
        let start = std::time::Instant::now();

        let max_attempts = if self.inner.transport.is_reliable() {
            0
        } else {
            self.inner.config.retry.max_attempts()
        };

        let mut discovery_opt: Option<DiscoveryResponse> = None;

        'discovery: for attempt in 0..=max_attempts {
            if attempt > 0 {
                tracing::debug!(target: "async_snmp::client", "retrying engine discovery");
            }

            let msg_id = self.next_request_id();
            let discovery_msg = V3Message::discovery_request(
                msg_id,
                self.inner.transport.receive_limits().advertised(),
            )?;
            let discovery_data = discovery_msg.encode()?;
            self.enforce_outbound_size(discovery_data.len(), None)?;

            let registration = RequestRegistration::v3(msg_id, self.inner.config.request_timeout)
                .with_decode_policy(self.inner.config.decode_policy);

            match self
                .inner
                .transport
                .request_with(&discovery_data, registration, |data, source| {
                    let Ok(decoded) = RawV3Message::decode_bounded_with_target_and_compatibility(
                        data,
                        self.inner.transport.receive_limits().accepted(),
                        source,
                        self.inner.config.decode_policy,
                        self.inner.config.compatibility_policy,
                    ) else {
                        return Ok(Candidate::Reject);
                    };
                    match self.validate_discovery_response(decoded, msg_id, source) {
                        Ok(response) => Ok(Candidate::Accept(response)),
                        Err(_) => Ok(Candidate::Reject),
                    }
                })
                .await
            {
                Ok(discovery) => {
                    discovery_opt = Some(discovery);
                    break 'discovery;
                }
                Err(e) if matches!(*e, Error::Timeout { .. }) => {
                    if attempt < max_attempts {
                        let delay = self.inner.config.retry.compute_delay(attempt);
                        if !delay.is_zero() {
                            tracing::debug!(target: "async_snmp::client", { delay_ms = delay.as_millis() as u64 }, "backing off");
                            tokio::time::sleep(delay).await;
                        }
                    }
                    // fall thru to next loop iteration
                }
                Err(e) => return Err(e),
            }
        }

        let discovery = discovery_opt.ok_or_else(|| {
            Error::Timeout {
                target: self.peer_addr(),
                elapsed: start.elapsed(),
                retries: max_attempts,
            }
            .boxed()
        })?;
        let engine_state = discovery.engine_state;
        let metadata = discovery.metadata;
        tracing::debug!(target: "async_snmp::client", { snmp.engine_id = %hex::Bytes(&engine_state.engine_id), snmp.msg_max_size = engine_state.msg_max_size.as_usize() }, "discovered engine identity");

        let install_result: Result<()> = (|| {
            let security = self
                .inner
                .config
                .usm_config()
                .ok_or_else(|| Error::Config("V3 security not configured".into()).boxed())?;

            // Prepare replacement keys before changing either the live generation
            // or its cache mapping. Ordinary discovery must first resolve any
            // canonical state already installed by another client sharing the
            // cache, then derive keys for that identity.
            let replacement_keys = if replace_cached_identity {
                Some(
                    security
                        .derive_keys(&engine_state.engine_id)
                        .map_err(|e| Error::Config(e.to_string().into()).boxed())?,
                )
            } else {
                None
            };

            if let Some(derived_keys) = replacement_keys {
                // Lock the live generation before publishing its cache mapping.
                // This matches the live-then-cache lock order used by authenticated
                // timeliness updates and prevents clones from observing a new
                // mapping alongside the old identity-localized keys. Reloading the
                // cache state also adopts trusted time already shared by another
                // target for the newly discovered engine ID.
                let mut engine = self
                    .inner
                    .engine
                    .write()
                    .map_err(|_| Error::Config("engine lock poisoned".into()).boxed())?;
                let engine_state = if let Some(cache) = &self.inner.engine_cache {
                    cache.replace_target(self.peer_addr(), engine_state)?
                } else {
                    engine_state
                };
                *engine = Some(ClientEngine::new(engine_state, derived_keys));
                return Ok(());
            }

            // A concurrent client sharing this cache may already have installed a
            // newer identity/time generation. Merge ordinary discovery without
            // replacing an active target mapping, then derive keys for the
            // canonical identity.
            let engine_state = if let Some(cache) = &self.inner.engine_cache {
                cache.insert(self.peer_addr(), engine_state.clone());
                cache.get(&self.peer_addr()).unwrap_or(engine_state)
            } else {
                engine_state
            };
            let derived_keys = security
                .derive_keys(&engine_state.engine_id)
                .map_err(|e| Error::Config(e.to_string().into()).boxed())?;
            let mut engine = self
                .inner
                .engine
                .write()
                .map_err(|_| Error::Config("engine lock poisoned".into()).boxed())?;
            *engine = Some(ClientEngine::new(engine_state, derived_keys));
            Ok(())
        })();

        install_result.map_err(|error| error.with_prior_response_metadata(&metadata))?;

        Ok(metadata)
    }

    fn validate_discovery_response(
        &self,
        decoded: crate::message::DecodeOutcome<RawV3Message>,
        expected_msg_id: i32,
        source: std::net::SocketAddr,
    ) -> Result<DiscoveryResponse> {
        let malformed = || Error::MalformedResponse { target: source }.boxed();
        let response = decoded.value;

        // Discovery is deliberately unauthenticated. Authenticated or private
        // messages are not an alternative discovery response shape. RFC 3412
        // requires a received Report's reportableFlag to be treated as zero,
        // so that bit does not affect acceptance.
        if response.security_level() != SecurityLevel::NoAuthNoPriv {
            return Err(malformed());
        }

        // Decode and validate the candidate before parsing the plaintext PDU,
        // preserving USM-before-scoped-PDU processing order. Boots/time are
        // syntactically decoded but discarded as unauthenticated input.
        let usm = UsmSecurityParams::decode_with_context_and_compatibility(
            response.security_params.clone(),
            response.security_params_offset,
            source,
            self.inner.config.compatibility_policy,
        )?;
        let engine_state = crate::v3::discovered_engine_state(
            usm.engine_id.clone(),
            response.global_data.msg_max_size,
        )
        .map_err(|_| malformed())?;
        if !usm.username.is_empty() || !usm.auth_params.is_empty() || !usm.priv_params.is_empty() {
            return Err(malformed());
        }

        let RawMsgData::Plaintext {
            data: bytes,
            offset,
        } = &response.msg_data
        else {
            return Err(malformed());
        };
        let scoped = decode_scoped_pdu_with_policies(
            bytes.clone(),
            *offset,
            source,
            None,
            self.inner.config.compatibility_policy,
        )?;
        let decode_anomalies = combine_staged_v3_anomalies(decoded.anomalies, scoped.anomalies);
        let scoped_pdu = scoped.value;

        // Bind the Internal-class Report to the exact outstanding discovery
        // attempt only after Security Model processing and scoped-PDU parsing.
        if response.global_data.msg_id != expected_msg_id {
            tracing::warn!(target: "async_snmp::client", { peer = %self.peer_addr(), expected_msg_id, actual_msg_id = response.global_data.msg_id }, "msgID mismatch in discovery response");
            return Err(malformed());
        }

        if scoped_pdu.context_engine_id != engine_state.engine_id
            || !scoped_pdu.context_name.is_empty()
        {
            return Err(malformed());
        }

        if !matches!(
            classify_report(&scoped_pdu.pdu),
            Ok(ReportStatus::UnknownEngineId { .. })
        ) {
            return Err(malformed());
        }

        Ok(DiscoveryResponse {
            engine_state,
            metadata: ResponseMetadata::from_decode_anomalies(decode_anomalies),
        })
    }

    fn refresh_engine_from_cache(&self) -> Result<()> {
        let Some(cache) = &self.inner.engine_cache else {
            return Ok(());
        };
        let Some(cached_state) = cache.get(&self.peer_addr()) else {
            return Ok(());
        };
        let mut engine = self
            .inner
            .engine
            .write()
            .map_err(|_| Error::Config("engine lock poisoned".into()).boxed())?;
        if let Some(engine) = engine.as_mut() {
            engine.state.merge_from(&cached_state);
        }
        Ok(())
    }

    /// Build and encode a V3 message with authentication and/or encryption.
    ///
    /// The `msg_id` parameter is separate from `pdu.request_id` per RFC 3412
    /// Section 6.2: retransmissions SHOULD use a new msgID for each attempt.
    fn build_v3_message(
        &self,
        pdu: &Pdu,
        msg_id: i32,
        engine_time_override: Option<&PacketLocalEngineTime>,
    ) -> Result<EncodedV3Request> {
        let security = self
            .inner
            .config
            .usm_config()
            .ok_or_else(|| Error::Config("V3 security not configured".into()).boxed())?;

        self.refresh_engine_from_cache()?;
        let engine = self
            .inner
            .engine
            .read()
            .map_err(|_| Error::Config("engine lock poisoned".into()).boxed())?;
        let engine = engine
            .as_ref()
            .ok_or_else(|| Error::Config("engine not discovered".into()).boxed())?;

        let context_engine_id = engine.state.engine_id.clone();
        let context_name = security.configured_context_name().clone();
        let (engine_boots, engine_time) = if let Some(engine_time) = engine_time_override {
            // Keep the untrusted tuple bound to the engine generation that
            // supplied it. Concurrent explicit rediscovery must not combine
            // one engine's tuple with another engine's identity/localized keys.
            if engine_time.engine_id != engine.state.engine_id {
                return Err(Error::MalformedResponse {
                    target: self.peer_addr(),
                }
                .boxed());
            }
            (engine_time.boots, engine_time.time)
        } else {
            engine.state.estimated_boots_time()
        };
        let data = crate::v3::encode::encode_v3_message(
            pdu,
            msg_id,
            &context_engine_id,
            engine_boots,
            engine_time,
            security,
            Some(&engine.derived_keys),
            self.inner.salt_counter.as_ref(),
            true, // reportable=true for requests
            // RFC 3412 Section 6.3: msgMaxSize advertises THIS sender's own
            // receive capacity, not the remote's. `engine_state.msg_max_size`
            // holds the remote's advertised limit (used to constrain our
            // outbound size), so advertise the local transport capacity here.
            self.inner.transport.receive_limits().advertised(),
        )?;
        self.enforce_outbound_size(data.len(), Some(engine.state.msg_max_size))?;

        Ok(EncodedV3Request {
            data,
            context_engine_id,
            context_name,
        })
    }

    /// Apply the received USM identity, capability, and authentication policy.
    ///
    /// The cached localized keys are valid only for the configured security
    /// name and discovered authoritative engine. Bind the received parameters
    /// to that tuple before using the keys, then perform RFC 3414 Step 5
    /// capability checks before Step 6 HMAC verification.
    fn verify_response_security(
        &self,
        response_data: &[u8],
        response_usm: &UsmSecurityParams,
        received_level: SecurityLevel,
    ) -> Result<Arc<()>> {
        let security = self
            .inner
            .config
            .usm_config()
            .ok_or_else(|| Error::Config("V3 security not configured".into()).boxed())?;

        validate_engine_id(&response_usm.engine_id).map_err(|_| {
            Error::Auth {
                target: self.peer_addr(),
            }
            .boxed()
        })?;
        response_usm
            .validate_for_security_level(received_level)
            .map_err(|_| {
                Error::Auth {
                    target: self.peer_addr(),
                }
                .boxed()
            })?;

        if response_usm.username != security.username() {
            tracing::warn!(target: "async_snmp::client", { peer = %self.peer_addr() }, "USM security name does not select the configured user");
            return Err(Error::Auth {
                target: self.peer_addr(),
            }
            .boxed());
        }

        let engine = self
            .inner
            .engine
            .read()
            .map_err(|_| Error::Config("engine lock poisoned".into()).boxed())?;
        let engine = engine
            .as_ref()
            .ok_or_else(|| Error::Config("engine not discovered".into()).boxed())?;
        if engine.state.engine_id != response_usm.engine_id {
            tracing::warn!(target: "async_snmp::client", { peer = %self.peer_addr() }, "USM authoritative engine does not select the cached localized keys");
            return Err(Error::Auth {
                target: self.peer_addr(),
            }
            .boxed());
        }
        let generation = Arc::clone(&engine.generation);

        if !received_level.requires_auth() {
            if security.security_level().requires_auth()
                && !self.inner.config.allow_unauthenticated_v3_time_correction
            {
                tracing::warn!(target: "async_snmp::client", { peer = %self.peer_addr() }, "unauthenticated reply on authenticated session");
                return Err(Error::Auth {
                    target: self.peer_addr(),
                }
                .boxed());
            }
            return Ok(generation);
        }

        tracing::trace!(target: "async_snmp::client", "verifying HMAC authentication on response");

        let derived = &engine.derived_keys;
        let auth_key = derived.auth_key.as_ref().ok_or_else(|| {
            tracing::warn!(target: "async_snmp::client", { peer = %self.peer_addr(), kind = %AuthErrorKind::NoAuthKey }, "authentication failed");
            Error::Auth {
                target: self.peer_addr(),
            }
            .boxed()
        })?;

        if received_level.requires_priv() && derived.priv_key.is_none() {
            tracing::warn!(target: "async_snmp::client", { peer = %self.peer_addr(), kind = %CryptoErrorKind::NoPrivKey }, "received security level is unsupported");
            return Err(Error::Auth {
                target: self.peer_addr(),
            }
            .boxed());
        }

        let (offset, len) = UsmSecurityParams::find_auth_params_offset(response_data).ok_or_else(
            || {
                tracing::warn!(target: "async_snmp::client", { peer = %self.peer_addr(), kind = %AuthErrorKind::AuthParamsNotFound }, "authentication failed");
                Error::Auth {
                    target: self.peer_addr(),
                }
                .boxed()
            },
        )?;

        if !verify_message(auth_key, response_data, offset, len)
            .map_err(|e| Error::Config(e.to_string().into()).boxed())?
        {
            tracing::warn!(target: "async_snmp::client", { peer = %self.peer_addr(), kind = %AuthErrorKind::HmacMismatch }, "authentication failed");
            return Err(Error::Auth {
                target: self.peer_addr(),
            }
            .boxed());
        }

        tracing::trace!(target: "async_snmp::client", { auth_params_offset = offset, auth_params_len = len }, "HMAC verification successful");
        Ok(generation)
    }

    /// Decrypt an encrypted scoped PDU and parse it.
    fn decrypt_scoped_pdu(
        &self,
        ciphertext: &Bytes,
        usm_params: &UsmSecurityParams,
        source: std::net::SocketAddr,
    ) -> Result<crate::message::DecodeOutcome<ScopedPdu>> {
        tracing::trace!(target: "async_snmp::client", { ciphertext_len = ciphertext.len() }, "decrypting response");

        let engine = self
            .inner
            .engine
            .read()
            .map_err(|_| Error::Config("engine lock poisoned".into()).boxed())?;
        let priv_key = engine
            .as_ref()
            .and_then(|engine| engine.derived_keys.priv_key.as_ref())
            .ok_or_else(|| {
                tracing::warn!(target: "async_snmp::client", { peer = %self.peer_addr(), kind = %CryptoErrorKind::NoPrivKey }, "decryption failed");
                Error::Auth {
                    target: self.peer_addr(),
                }
                .boxed()
            })?;

        let plaintext = priv_key
            .decrypt(
                ciphertext,
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

        decode_scoped_pdu_with_policies(
            plaintext,
            0,
            source,
            Some(priv_key.protocol()),
            self.inner.config.compatibility_policy,
        )
    }

    fn validate_v3_candidate(
        &self,
        response_data: Bytes,
        source: SocketAddr,
        msg_ids: &[i32],
        request: &EncodedV3Request,
        expected_pdu_id: i32,
        expected_level: SecurityLevel,
    ) -> Result<Candidate<ValidatedV3Response>> {
        let Ok(decoded) = RawV3Message::decode_bounded_with_target_and_compatibility(
            response_data.clone(),
            self.inner.transport.receive_limits().accepted(),
            source,
            self.inner.config.decode_policy,
            self.inner.config.compatibility_policy,
        ) else {
            return Ok(Candidate::Reject);
        };
        let trailing_bytes = decoded
            .anomalies
            .iter()
            .find_map(|anomaly| match anomaly {
                crate::DecodeAnomaly::TrailingBytes {
                    original_length, ..
                } => Some(*original_length),
                _ => None,
            })
            .unwrap_or(0);
        let envelope_len = response_data.len() - trailing_bytes;
        let authenticated_message = response_data.slice(..envelope_len);
        let mut decode_anomalies = decoded.anomalies;
        let raw = decoded.value;
        let received_level = raw.security_level();
        let Ok(usm) = UsmSecurityParams::decode_with_context_and_compatibility(
            raw.security_params.clone(),
            raw.security_params_offset,
            source,
            self.inner.config.compatibility_policy,
        ) else {
            return Ok(Candidate::Reject);
        };

        let validated_generation =
            match self.verify_response_security(&authenticated_message, &usm, received_level) {
                Ok(generation) => generation,
                Err(error) if matches!(*error, Error::Config(_)) => return Err(error),
                Err(_) => return Ok(Candidate::Reject),
            };

        if received_level.requires_auth() {
            let local_state = self
                .inner
                .engine
                .read()
                .map_err(|_| Error::Config("engine lock poisoned".into()).boxed())?
                .as_ref()
                .filter(|engine| Arc::ptr_eq(&engine.generation, &validated_generation))
                .ok_or_else(|| {
                    Error::Auth {
                        target: self.peer_addr(),
                    }
                    .boxed()
                })?
                .state
                .clone();
            let timely = self
                .inner
                .engine_cache
                .as_deref()
                .and_then(|cache| {
                    cache.timeliness_candidate(
                        &self.peer_addr(),
                        &local_state,
                        &usm.engine_id,
                        usm.engine_boots,
                        usm.engine_time,
                    )
                })
                .map_or_else(
                    || {
                        local_state
                            .clone()
                            .check_and_update_timeliness(usm.engine_boots, usm.engine_time)
                    },
                    |(timely, _)| timely,
                );
            if !timely {
                return Ok(Candidate::Reject);
            }
        }

        let scoped_outcome = match &raw.msg_data {
            RawMsgData::Plaintext { data, offset } => {
                match decode_scoped_pdu_with_policies(
                    data.clone(),
                    *offset,
                    source,
                    None,
                    self.inner.config.compatibility_policy,
                ) {
                    Ok(scoped) => scoped,
                    Err(_) => return Ok(Candidate::Reject),
                }
            }
            RawMsgData::Encrypted(ciphertext) => {
                match self.decrypt_scoped_pdu(ciphertext, &usm, source) {
                    Ok(scoped) => scoped,
                    Err(error) if matches!(*error, Error::Config(_)) => return Err(error),
                    Err(_) => return Ok(Candidate::Reject),
                }
            }
        };
        decode_anomalies = combine_staged_v3_anomalies(decode_anomalies, scoped_outcome.anomalies);
        let scoped_pdu = scoped_outcome.value;

        if !msg_ids.contains(&raw.global_data.msg_id) {
            return Ok(Candidate::Reject);
        }

        if scoped_pdu.pdu.pdu_type() == PduType::Report {
            if classify_report(&scoped_pdu.pdu).is_err() {
                return Ok(Candidate::Reject);
            }
        } else if received_level != expected_level
            || scoped_pdu.context_engine_id != request.context_engine_id
            || scoped_pdu.context_name != request.context_name
            || scoped_pdu.pdu.pdu_type() != PduType::Response
            || scoped_pdu.pdu.request_id != expected_pdu_id
        {
            return Ok(Candidate::Reject);
        }

        Ok(Candidate::Accept(ValidatedV3Response {
            usm,
            received_level,
            scoped_pdu,
            authenticated_generation: received_level
                .requires_auth()
                .then_some(validated_generation),
            decode_anomalies,
        }))
    }

    /// Send a V3 request and handle the response.
    #[instrument(
        level = "debug",
        skip(self, pdu),
        fields(
            snmp.target = %self.peer_addr(),
            snmp.request_id = pdu.request_id,
            snmp.security_level = ?self.inner.config.usm_config().map(crate::v3::UsmConfig::security_level),
            snmp.attempt = tracing::field::Empty,
            snmp.protocol_correction = tracing::field::Empty,
            snmp.elapsed_ms = tracing::field::Empty,
        )
    )]
    pub(super) async fn send_v3_and_recv(&self, pdu: Pdu) -> Result<DecodedResponse> {
        let start = Instant::now();

        // Validate the caller's structured PDU before engine discovery, which
        // may perform network I/O. The PDU is encoded again after discovery
        // once the authoritative engine details are available.
        let mut validation_buf = EncodeBuf::new();
        pdu.encode_for(
            &mut validation_buf,
            crate::Version::V3,
            crate::pdu::PduDirection::Request,
        )?;

        let mut exchange_metadata = self.ensure_engine_discovered().await?;

        let security = self
            .inner
            .config
            .usm_config()
            .ok_or_else(|| Error::Config("V3 security not configured".into()).boxed())
            .map_err(|error| error.with_prior_response_metadata(&exchange_metadata))?;
        let security_level = security.security_level();

        let max_timeout_retries = if self.inner.transport.is_reliable() {
            0
        } else {
            self.inner.config.retry.max_attempts()
        };
        let mut timeout_retries = 0;
        let mut correction_used = false;
        let mut packet_local_engine_time = None;
        let mut pdu = pdu;
        // msgIDs transmitted for the current exchange. A response correlating to
        // any of them is acceptable; corrections reset the window because the
        // corrected message is a new exchange.
        let mut msg_id_window: Vec<i32> = Vec::new();

        loop {
            Span::current().record("snmp.attempt", timeout_retries);
            Span::current().record("snmp.protocol_correction", correction_used);

            // RFC 3412 Section 6.2: use fresh msgID for every transmission. Prior
            // attempts' msgIDs stay acceptable via the window below. A
            // compatibility tuple is consumed by exactly one packet and is never
            // available to a timeout retransmission.
            let msg_id = self.next_request_id();
            let engine_time_override = packet_local_engine_time.take();
            let request = self
                .build_v3_message(&pdu, msg_id, engine_time_override.as_ref())
                .map_err(|error| error.with_prior_response_metadata(&exchange_metadata))?;

            tracing::debug!(target: "async_snmp::client", { snmp.pdu_type = ?pdu.pdu_type(), snmp.varbind_count = pdu.varbinds.len(), snmp.msg_id = msg_id }, "sending V3 {} request", pdu.pdu_type());
            tracing::trace!(target: "async_snmp::client", { snmp.bytes = request.data.len() }, "sending V3 request");

            let registration = RequestRegistration::v3(msg_id, self.inner.config.request_timeout)
                .with_decode_policy(self.inner.config.decode_policy)
                .with_aliases(msg_id_window.iter().copied());
            msg_id_window.push(msg_id);

            // Send request and wait for response as a single unit so reliable
            // transports own their stream lock for the whole exchange.
            match self
                .inner
                .transport
                .request_with(&request.data, registration, |data, source| {
                    self.validate_v3_candidate(
                        data,
                        source,
                        &msg_id_window,
                        &request,
                        pdu.request_id,
                        security_level,
                    )
                })
                .await
            {
                Ok(validated) => {
                    let response_usm = validated.usm;
                    let received_level = validated.received_level;
                    let scoped_pdu = validated.scoped_pdu;
                    let message_metadata =
                        ResponseMetadata::from_decode_anomalies(validated.decode_anomalies);
                    exchange_metadata.append(message_metadata);

                    // Publish candidate timeliness state only after every deep
                    // validation check has accepted the response.
                    #[cfg(test)]
                    if validated.authenticated_generation.is_some() {
                        let hook = self
                            .inner
                            .authenticated_response_validated_hook
                            .read()
                            .expect("authenticated response hook lock poisoned")
                            .clone();
                        if let Some(hook) = hook {
                            hook();
                        }
                    }
                    if let Some(validated_generation) = validated.authenticated_generation {
                        let publication = {
                            let mut engine = self
                                .inner
                                .engine
                                .write()
                                .map_err(|_| Error::Config("engine lock poisoned".into()).boxed())
                                .map_err(|error| {
                                    error.with_prior_response_metadata(&exchange_metadata)
                                })?;
                            let engine = engine
                                .as_mut()
                                .ok_or_else(|| {
                                    Error::Config("engine not discovered".into()).boxed()
                                })
                                .map_err(|error| {
                                    error.with_prior_response_metadata(&exchange_metadata)
                                })?;
                            if !Arc::ptr_eq(&engine.generation, &validated_generation) {
                                None
                            } else {
                                check_and_update_engine_timeliness(
                                    &mut engine.state,
                                    self.inner.engine_cache.as_deref(),
                                    self.peer_addr(),
                                    &response_usm.engine_id,
                                    response_usm.engine_boots,
                                    response_usm.engine_time,
                                )
                            }
                        };
                        let Some(timely) = publication else {
                            return Err(Error::MalformedResponse {
                                target: self.peer_addr(),
                            }
                            .boxed()
                            .with_prior_response_metadata(&exchange_metadata));
                        };
                        if !timely {
                            return Err(Error::Auth {
                                target: self.peer_addr(),
                            }
                            .boxed()
                            .with_prior_response_metadata(&exchange_metadata));
                        }
                    }

                    // Report action begins only after USM processing and exact
                    // outer-msgID correlation. Strict classification prevents
                    // an OID hidden in a malformed/multi-status Report from
                    // triggering a corrected send.
                    if scoped_pdu.pdu.pdu_type() == PduType::Report {
                        let status = classify_report(&scoped_pdu.pdu).map_err(|_| {
                            Error::MalformedResponse {
                                target: self.peer_addr(),
                            }
                            .boxed()
                            .with_prior_response_metadata(&exchange_metadata)
                        })?;

                        if matches!(status, ReportStatus::NotInTimeWindow { .. })
                            && received_level.requires_auth()
                            && !correction_used
                        {
                            // RFC 3414 Step 7(b) above has already established
                            // the authenticated tuple. One protocol correction
                            // is allowed independently of timeout retries and
                            // transport reliability. A corrected message is a
                            // new request and receives fresh message and PDU IDs.
                            correction_used = true;
                            pdu.set_request_id(self.next_request_id());
                            msg_id_window.clear();
                            Span::current().record("snmp.protocol_correction", true);
                            tracing::debug!(target: "async_snmp::client", { snmp.report_status = %status }, "sending SNMPv3 protocol correction");
                            continue;
                        }

                        if matches!(status, ReportStatus::NotInTimeWindow { .. })
                            && received_level == SecurityLevel::NoAuthNoPriv
                            && security_level.requires_auth()
                            && self.inner.config.allow_unauthenticated_v3_time_correction
                            && response_usm.auth_params.is_empty()
                            && response_usm.priv_params.is_empty()
                            && !correction_used
                        {
                            // Compatibility for devices that violate RFC 3414
                            // Step 7(a) by returning this Report without HMAC.
                            // Identity, username, source policy, msgID, and exact
                            // Report shape have all been checked. The untrusted
                            // tuple is consumed by one authenticated packet and
                            // is never installed into live or cache state.
                            correction_used = true;
                            packet_local_engine_time = Some(PacketLocalEngineTime {
                                engine_id: response_usm.engine_id.clone(),
                                boots: response_usm.engine_boots,
                                time: response_usm.engine_time,
                            });
                            pdu.set_request_id(self.next_request_id());
                            msg_id_window.clear();
                            Span::current().record("snmp.protocol_correction", true);
                            tracing::debug!(target: "async_snmp::client", { snmp.report_status = %status }, "sending packet-local SNMPv3 compatibility correction");
                            continue;
                        }

                        // Credential failures, unknown statuses, disabled or
                        // repeated unauthenticated time Reports, and repeated
                        // authenticated time Reports are typed terminal
                        // protocol outcomes, never timeouts.
                        return Err(Error::Report {
                            target: self.peer_addr(),
                            status: Box::new(status),
                            metadata: Box::new(exchange_metadata),
                        }
                        .boxed());
                    }

                    // Validate security level matches what we sent (prevent downgrade attacks)
                    if received_level != security_level {
                        tracing::warn!(target: "async_snmp::client", {
                            peer = %self.peer_addr(),
                            expected = ?security_level,
                            actual = ?received_level
                        }, "security level mismatch in response");
                        return Err(Error::MalformedResponse {
                            target: self.peer_addr(),
                        }
                        .boxed()
                        .with_prior_response_metadata(&exchange_metadata));
                    }

                    // Validate engine ID matches our cached engine state
                    {
                        let engine = self
                            .inner
                            .engine
                            .read()
                            .map_err(|_| Error::Config("engine lock poisoned".into()).boxed())
                            .map_err(|error| {
                                error.with_prior_response_metadata(&exchange_metadata)
                            })?;
                        if let Some(ref engine) = *engine
                            && response_usm.engine_id != engine.state.engine_id
                        {
                            tracing::warn!(target: "async_snmp::client", {
                                peer = %self.peer_addr()
                            }, "engine ID mismatch in response");
                            return Err(Error::MalformedResponse {
                                target: self.peer_addr(),
                            }
                            .boxed()
                            .with_prior_response_metadata(&exchange_metadata));
                        }
                    }

                    // Validate username matches what we sent
                    if response_usm.username != security.username() {
                        tracing::warn!(target: "async_snmp::client", {
                            peer = %self.peer_addr()
                        }, "username mismatch in response");
                        return Err(Error::MalformedResponse {
                            target: self.peer_addr(),
                        }
                        .boxed()
                        .with_prior_response_metadata(&exchange_metadata));
                    }

                    // RFC 3412 Section 7.2: an ordinary Response must match
                    // both scoped-context values cached for the request.
                    if scoped_pdu.context_engine_id != request.context_engine_id
                        || scoped_pdu.context_name != request.context_name
                    {
                        tracing::warn!(target: "async_snmp::client", {
                            peer = %self.peer_addr()
                        }, "scoped context mismatch in response");
                        return Err(Error::MalformedResponse {
                            target: self.peer_addr(),
                        }
                        .boxed()
                        .with_prior_response_metadata(&exchange_metadata));
                    }

                    let response_pdu = scoped_pdu.pdu;

                    // RFC 3416 Section 4.2: only a Response-PDU may answer a
                    // request; reject echoed request-type PDUs (Report PDUs
                    // were classified above)
                    if response_pdu.pdu_type() != PduType::Response {
                        tracing::warn!(target: "async_snmp::client", { peer = %self.peer_addr(), pdu_type = ?response_pdu.pdu_type() }, "non-Response PDU in response");
                        return Err(Error::MalformedResponse {
                            target: self.peer_addr(),
                        }
                        .boxed()
                        .with_prior_response_metadata(&exchange_metadata));
                    }

                    // Validate request ID
                    if response_pdu.request_id != pdu.request_id {
                        tracing::warn!(target: "async_snmp::client", { expected_request_id = pdu.request_id, actual_request_id = response_pdu.request_id, peer = %self.peer_addr() }, "request ID mismatch in response");
                        return Err(Error::MalformedResponse {
                            target: self.peer_addr(),
                        }
                        .boxed()
                        .with_prior_response_metadata(&exchange_metadata));
                    }

                    tracing::debug!(target: "async_snmp::client", { snmp.pdu_type = ?response_pdu.pdu_type(), snmp.varbind_count = response_pdu.varbinds.len(), snmp.error_status = response_pdu.error_status(), snmp.error_index = response_pdu.error_index() }, "received V3 {} response", response_pdu.pdu_type());

                    // Check for SNMP error
                    if let Some(err) = super::pdu_to_snmp_error(
                        &response_pdu,
                        self.peer_addr(),
                        exchange_metadata.clone(),
                    ) {
                        Span::current()
                            .record("snmp.elapsed_ms", start.elapsed().as_millis() as u64);
                        return Err(err);
                    }

                    Span::current().record("snmp.elapsed_ms", start.elapsed().as_millis() as u64);
                    return Ok(DecodedResponse {
                        pdu: response_pdu,
                        decode_anomalies: exchange_metadata.decode_anomalies,
                    });
                }
                Err(e) if matches!(*e, Error::Timeout { .. }) => {
                    // A spoofable compatibility tuple is authorized for one
                    // authenticated packet only, not a retransmission.
                    if engine_time_override.is_some() || timeout_retries >= max_timeout_retries {
                        break;
                    }

                    let delay = self.inner.config.retry.compute_delay(timeout_retries);
                    timeout_retries += 1;
                    // Retain the PDU request-id across timeout retransmissions,
                    // matching deployed net-snmp and SNMP4J behavior. RFC 3414
                    // Section 11.1 literally requires distinct request-ids in all
                    // Request PDUs sent during a TimeWindow, so this is a deliberate
                    // interoperability deviation. A fresh msgID still distinguishes
                    // each transmission, and any current-window msgID remains valid.
                    tracing::debug!(target: "async_snmp::client", { timeout_retries, delay_ms = delay.as_millis() as u64 }, "retransmitting V3 request after timeout");
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                }
                Err(e) => {
                    Span::current().record("snmp.elapsed_ms", start.elapsed().as_millis() as u64);
                    return Err(e.with_prior_response_metadata(&exchange_metadata));
                }
            }
        }

        // Only transport timeouts reach loop exhaustion. Reports always take a
        // protocol transition or return their typed terminal outcome.
        let elapsed = start.elapsed();
        Span::current().record("snmp.elapsed_ms", elapsed.as_millis() as u64);
        tracing::debug!(target: "async_snmp::client", { request_id = pdu.request_id, peer = %self.peer_addr(), ?elapsed, retries = timeout_retries }, "request timed out");
        Err(Error::Timeout {
            target: self.peer_addr(),
            elapsed,
            retries: timeout_retries,
        }
        .boxed()
        .with_prior_response_metadata(&exchange_metadata))
    }

    /// Ensure keys are derived against the local engine ID for V3 trap sending.
    pub(super) fn ensure_local_keys_derived(&self) -> Result<()> {
        // Fast path: already derived.
        {
            let keys =
                self.inner.local_derived_keys.read().map_err(|_| {
                    Error::Config("local_derived_keys lock poisoned".into()).boxed()
                })?;
            if keys.is_some() {
                return Ok(());
            }
        }

        let local_engine = self.local_engine_for_trap()?;

        let security = self
            .inner
            .config
            .usm_config()
            .ok_or_else(|| Error::Config("V3 security not configured".into()).boxed())?;

        let keys = security
            .derive_keys(local_engine.engine_id())
            .map_err(|e| Error::Config(e.to_string().into()).boxed())?;

        let mut derived = self
            .inner
            .local_derived_keys
            .write()
            .map_err(|_| Error::Config("local_derived_keys lock poisoned".into()).boxed())?;
        *derived = Some(keys);

        Ok(())
    }

    fn local_engine_for_trap(&self) -> Result<&crate::v3::AuthoritativeEngine> {
        self.inner
            .config
            .local_authoritative_engine
            .as_ref()
            .ok_or_else(|| {
                Error::Config(
                    "local authoritative engine state required for V3 trap sending".into(),
                )
                .boxed()
            })
    }

    /// Build and encode a V3 trap message using local engine ID.
    ///
    /// Per RFC 3412 Section 6.4, the sender is the authoritative engine for
    /// trap PDUs. Uses the persisted local engine state and sets
    /// reportable=false (no Report PDU expected for traps).
    pub(super) fn build_v3_trap_message(&self, pdu: &Pdu, msg_id: i32) -> Result<Vec<u8>> {
        let security = self
            .inner
            .config
            .usm_config()
            .ok_or_else(|| Error::Config("V3 security not configured".into()).boxed())?;

        let local_engine = self.local_engine_for_trap()?;

        let derived = self
            .inner
            .local_derived_keys
            .read()
            .map_err(|_| Error::Config("local_derived_keys lock poisoned".into()).boxed())?;

        let (engine_boots, engine_time) = local_engine.current_boots_time()?;

        crate::v3::encode::encode_v3_message(
            pdu,
            msg_id,
            local_engine.engine_id(),
            engine_boots,
            engine_time,
            security,
            derived.as_ref(),
            self.inner.salt_counter.as_ref(),
            false, // reportable=false for traps
            self.inner.transport.receive_limits().advertised(),
        )
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
    use crate::value::Value;
    use crate::varbind::VarBind;
    use bytes::Bytes;
    use std::future::ready;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
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
            _registration: RequestRegistration,
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
    }

    #[tokio::test]
    async fn v3_client_rejects_malformed_requests_before_discovery() {
        let config = ClientConfig {
            auth: crate::Auth::Usm(UsmConfig::new("user")),
            ..ClientConfig::default()
        };
        let client = Client::new(TestTransport::new(), config).expect("valid client config");
        let name = oid!(1, 3, 6, 1);
        let malformed = [
            Pdu {
                request_id: 7,
                body: crate::pdu::PduBody::GetBulk {
                    non_repeaters: crate::pdu::MAX_GET_BULK_VALUE + 1,
                    max_repetitions: 10,
                },
                varbinds: vec![VarBind::null(name.clone())],
            },
            Pdu::standard(
                crate::pdu::StandardPduType::GetRequest,
                7,
                1,
                0,
                vec![VarBind::null(name.clone())],
            ),
            Pdu::standard(
                crate::pdu::StandardPduType::GetRequest,
                7,
                0,
                0,
                vec![VarBind::new(name.clone(), Value::NoSuchObject)],
            ),
            Pdu::set_request(
                7,
                vec![VarBind::new(
                    name,
                    Value::Unknown {
                        tag: 0x48,
                        data: Bytes::from_static(b"raw"),
                    },
                )],
            ),
        ];

        for pdu in malformed {
            let original = pdu.clone();
            let error = client.send_v3_and_recv(pdu.clone()).await.unwrap_err();
            assert!(matches!(&*error, Error::InvalidMessage(_)));
            assert_eq!(pdu, original);
        }
    }

    #[tokio::test]
    async fn direct_config_requires_authoritative_state_before_sending_v3_trap() {
        let config = ClientConfig {
            auth: crate::Auth::Usm(UsmConfig::new("trapuser")),
            ..ClientConfig::default()
        };
        let client = Client::new(TestTransport::new(), config).expect("valid client config");

        let err = client
            .send_trap(&oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1), 0, vec![])
            .await
            .unwrap_err();
        assert!(matches!(*err, Error::Config(_)));
    }

    #[test]
    fn test_rejected_message_does_not_reinsert_missing_cache_entry() {
        let cache = EngineCache::new();
        let target = SocketAddr::from((Ipv4Addr::LOCALHOST, 161));
        let engine_id = Bytes::from_static(b"engine");
        let mut state = EngineState::new(engine_id.clone(), 5, 1000);

        let timely = check_and_update_engine_timeliness(
            &mut state,
            Some(&cache),
            target,
            &engine_id,
            4,
            5000,
        );

        assert_eq!(timely, None);
        assert!(cache.get(&target).is_none());
        assert!(cache.is_empty());
    }

    #[test]
    fn test_deferred_time_revalidation_rejects_concurrently_stale_response() {
        let cache = EngineCache::new();
        let target = SocketAddr::from((Ipv4Addr::LOCALHOST, 161));
        let engine_id = Bytes::from_static(b"engine");
        let mut state = EngineState::new(engine_id.clone(), 1, 1000);
        cache.insert(target, state.clone());

        let (initially_timely, _) = cache
            .timeliness_candidate(&target, &state, &engine_id, 1, 1100)
            .expect("cached identity");
        assert!(initially_timely);

        assert_eq!(
            check_and_update_engine_timeliness(
                &mut state,
                Some(&cache),
                target,
                &engine_id,
                1,
                1400,
            ),
            Some(true)
        );
        assert_eq!(
            check_and_update_engine_timeliness(
                &mut state,
                Some(&cache),
                target,
                &engine_id,
                1,
                1100,
            ),
            Some(false)
        );
    }

    #[test]
    fn test_build_v3_message_uses_configured_context_name() {
        let transport = TestTransport::new();
        let config = ClientConfig {
            auth: crate::Auth::Usm(UsmConfig::new("user").context_name("ctx")),
            ..ClientConfig::default()
        };
        let client = Client::new(transport, config).expect("valid client config");

        {
            let security = client.inner.config.usm_config().unwrap();
            let state = EngineState::new(Bytes::from_static(b"engine"), 1, 42);
            let derived_keys = security.derive_keys(&state.engine_id).unwrap();
            *client.inner.engine.write().expect("engine lock poisoned") =
                Some(ClientEngine::new(state, derived_keys));
        }

        let pdu = Pdu::get_request(123, &[oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)]);

        let encoded = client
            .build_v3_message(&pdu, 456, None)
            .expect("v3 message should encode");
        let decoded =
            V3Message::decode(Bytes::from(encoded.data)).expect("v3 message should decode");
        let scoped = match decoded.data {
            V3MessageData::Plaintext(scoped) => scoped,
            V3MessageData::Encrypted(_) => panic!("expected plaintext scoped PDU"),
        };

        assert_eq!(scoped.context_name.as_ref(), b"ctx");
    }

    #[test]
    fn test_packet_local_time_rejects_changed_engine_generation() {
        let transport = TestTransport::new();
        let config = ClientConfig {
            auth: crate::Auth::Usm(UsmConfig::new("user")),
            ..ClientConfig::default()
        };
        let client = Client::new(transport, config).expect("valid client config");

        {
            let security = client.inner.config.usm_config().unwrap();
            let state = EngineState::new(Bytes::from_static(b"engine-a"), 1, 42);
            let derived_keys = security.derive_keys(&state.engine_id).unwrap();
            *client.inner.engine.write().expect("engine lock poisoned") =
                Some(ClientEngine::new(state, derived_keys));
        }

        let pdu = Pdu::get_request(123, &[oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)]);
        let packet_time = PacketLocalEngineTime {
            engine_id: Bytes::from_static(b"engine-b"),
            boots: 9,
            time: 99,
        };
        let err = client
            .build_v3_message(&pdu, 456, Some(&packet_time))
            .err()
            .expect("changed engine generation must fail");

        assert!(matches!(*err, Error::MalformedResponse { .. }));
    }

    /// Transport that times out on the first recv call, then returns a valid
    /// discovery response on subsequent calls.
    #[derive(Clone)]
    struct RetryTestTransport {
        peer: SocketAddr,
        recv_count: Arc<AtomicU32>,
        engine_id: Bytes,
    }

    impl RetryTestTransport {
        fn new(engine_id: Bytes) -> Self {
            Self {
                peer: SocketAddr::from((Ipv4Addr::LOCALHOST, 161)),
                recv_count: Arc::new(AtomicU32::new(0)),
                engine_id,
            }
        }
    }

    impl Transport for RetryTestTransport {
        fn send(&self, _data: &[u8]) -> impl std::future::Future<Output = Result<()>> + Send {
            ready(Ok(()))
        }

        fn recv(
            &self,
            registration: RequestRegistration,
        ) -> impl std::future::Future<Output = Result<(Bytes, SocketAddr)>> + Send {
            let request_id = registration.request_id();
            let count = self.recv_count.fetch_add(1, Ordering::Relaxed);
            let peer = self.peer;
            let engine_id = self.engine_id.clone();
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
                    Ok((build_discovery_response(&engine_id, request_id), peer))
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
    }

    #[derive(Clone)]
    struct DiscoveryLimitTransport {
        peer: SocketAddr,
        engine_id: Bytes,
        remote_limit: crate::MessageSize,
        sends: Arc<AtomicUsize>,
    }

    impl Transport for DiscoveryLimitTransport {
        fn send(&self, _data: &[u8]) -> impl std::future::Future<Output = Result<()>> + Send {
            self.sends.fetch_add(1, Ordering::Relaxed);
            ready(Ok(()))
        }

        fn recv(
            &self,
            registration: RequestRegistration,
        ) -> impl std::future::Future<Output = Result<(Bytes, SocketAddr)>> + Send {
            ready(Ok((
                build_discovery_response_with_size(
                    &self.engine_id,
                    registration.request_id(),
                    self.remote_limit,
                ),
                self.peer,
            )))
        }

        fn peer_addr(&self) -> SocketAddr {
            self.peer
        }

        fn local_addr(&self) -> SocketAddr {
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
        }

        fn is_reliable(&self) -> bool {
            true
        }
    }

    /// Build a minimal valid discovery response with the given engine ID.
    fn build_discovery_response(engine_id: &[u8], msg_id: i32) -> Bytes {
        build_discovery_response_with_size(
            engine_id,
            msg_id,
            crate::MessageSize::new(65507).unwrap(),
        )
    }

    fn build_discovery_response_with_size(
        engine_id: &[u8],
        msg_id: i32,
        msg_max_size: crate::MessageSize,
    ) -> Bytes {
        use crate::message::{MsgFlags, MsgGlobalData, ScopedPdu, V3Message};
        use crate::pdu::Pdu;
        use crate::v3::UsmSecurityParams;
        use crate::value::Value;
        use crate::varbind::VarBind;

        let report_pdu = Pdu::standard(
            crate::pdu::StandardPduType::Report,
            1,
            0,
            0,
            vec![VarBind::new(
                crate::oid!(1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0),
                Value::Counter32(0),
            )],
        );

        let global = MsgGlobalData::new(
            msg_id,
            msg_max_size,
            MsgFlags::new(crate::message::SecurityLevel::NoAuthNoPriv, false),
        )
        .unwrap();
        let usm = UsmSecurityParams::new(Bytes::copy_from_slice(engine_id), 1, 100, Bytes::new())
            .unwrap();
        let scoped = ScopedPdu::new(Bytes::copy_from_slice(engine_id), Bytes::new(), report_pdu);

        V3Message::new(global, usm.encode().unwrap(), scoped)
            .unwrap()
            .encode()
            .unwrap()
    }

    #[tokio::test]
    async fn test_discovery_retries_on_timeout() {
        let engine_id = b"test-engine";
        let transport = RetryTestTransport::new(Bytes::copy_from_slice(engine_id));
        let recv_count = transport.recv_count.clone();

        let config = ClientConfig {
            auth: crate::Auth::Usm(UsmConfig::new("user")),
            retry: crate::client::Retry::fixed(1, Duration::ZERO),
            ..ClientConfig::default()
        };
        let client = Client::new(transport, config).expect("valid client config");

        client
            .ensure_engine_discovered()
            .await
            .expect("discovery should succeed after retry");

        // recv was called twice: once for the timeout, once for the success
        assert_eq!(recv_count.load(Ordering::Relaxed), 2);

        // Engine identity should be set without trusting discovery time.
        let engine = client.inner.engine.read().expect("engine lock poisoned");
        assert!(engine.is_some());
        let state = &engine.as_ref().unwrap().state;
        assert_eq!(state.engine_id.as_ref(), engine_id);
        assert!(state.trusted_time().is_none());
    }

    #[tokio::test]
    async fn discovery_learns_remote_limit_and_rejects_oversized_request_before_second_send() {
        let remote_limit = crate::MessageSize::new(crate::MESSAGE_SIZE_MINIMUM).unwrap();
        let sends = Arc::new(AtomicUsize::new(0));
        let transport = DiscoveryLimitTransport {
            peer: SocketAddr::from((Ipv4Addr::LOCALHOST, 161)),
            engine_id: Bytes::from_static(b"limited-engine"),
            remote_limit,
            sends: Arc::clone(&sends),
        };
        let config = ClientConfig {
            auth: crate::Auth::Usm(UsmConfig::new("user")),
            retry: crate::client::Retry::none(),
            ..ClientConfig::default()
        };
        let client = Client::new(transport, config).expect("valid client config");
        let oversized = Pdu::set_request(
            7,
            vec![crate::VarBind::new(
                oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
                crate::Value::OctetString(Bytes::from(vec![0; 512])),
            )],
        );

        let error = client.send_v3_and_recv(oversized).await.unwrap_err();
        assert!(matches!(
            *error,
            Error::OutboundMessageTooLarge { limit, .. }
                if limit == crate::MESSAGE_SIZE_MINIMUM
        ));
        assert_eq!(
            sends.load(Ordering::Relaxed),
            1,
            "only discovery may reach transport send"
        );
        let engine = client.inner.engine.read().unwrap();
        assert_eq!(engine.as_ref().unwrap().state.msg_max_size, remote_limit);
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
                _registration: RequestRegistration,
            ) -> impl std::future::Future<Output = Result<(Bytes, SocketAddr)>> + Send {
                let peer = self.peer;
                async move {
                    tokio::time::sleep(Duration::from_millis(5)).await;
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
        }

        let transport = AlwaysTimeoutTransport {
            peer: SocketAddr::from((Ipv4Addr::LOCALHOST, 161)),
        };
        let config = ClientConfig {
            auth: crate::Auth::Usm(UsmConfig::new("user")),
            retry: crate::client::Retry::fixed(2, Duration::ZERO),
            ..ClientConfig::default()
        };
        let client = Client::new(transport, config).expect("valid client config");

        let error = client.ensure_engine_discovered().await.unwrap_err();
        match *error {
            Error::Timeout {
                elapsed, retries, ..
            } => {
                assert_eq!(retries, 2);
                assert!(elapsed >= Duration::from_millis(15));
                assert!(
                    elapsed < Duration::from_secs(5),
                    "discovery must replace per-attempt timeout metadata with total elapsed time"
                );
            }
            ref other => panic!("should return Timeout after all retries exhausted, got {other}"),
        }
    }
}

#[cfg(all(test, any(feature = "crypto-rustcrypto", feature = "crypto-fips")))]
mod response_validation_tests {
    use super::*;
    use crate::UsmConfig;
    use crate::client::ClientConfig;
    use crate::message::{MsgFlags, MsgGlobalData, ScopedPdu, SecurityLevel, V3MessageData};
    use crate::oid;
    use crate::v3::auth::authenticate_message;
    use crate::v3::{AuthProtocol, EngineState, LocalizedKey};
    use bytes::Bytes;
    use std::future::ready;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::time::Duration;

    /// Transport that answers every request with one canned response.
    #[derive(Clone)]
    struct CannedTransport {
        peer: SocketAddr,
        response: Bytes,
        max_size: u32,
        send_size: usize,
        sends: Arc<AtomicUsize>,
    }

    impl CannedTransport {
        fn new(response: Bytes) -> Self {
            Self {
                peer: SocketAddr::from((Ipv4Addr::LOCALHOST, 161)),
                response,
                max_size: crate::MAX_UDP_PAYLOAD as u32,
                send_size: crate::MAX_UDP_PAYLOAD,
                sends: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    impl Transport for CannedTransport {
        fn send(&self, _data: &[u8]) -> impl std::future::Future<Output = Result<()>> + Send {
            self.sends.fetch_add(1, Ordering::Relaxed);
            ready(Ok(()))
        }

        fn receive_limits(&self) -> crate::ReceiveLimits {
            crate::ReceiveLimits::udp(self.max_size as usize).unwrap()
        }

        fn send_capacity(&self) -> usize {
            self.send_size
        }

        fn recv(
            &self,
            _registration: RequestRegistration,
        ) -> impl std::future::Future<Output = Result<(Bytes, SocketAddr)>> + Send {
            ready(Ok((self.response.clone(), self.peer)))
        }

        fn peer_addr(&self) -> SocketAddr {
            self.peer
        }

        fn local_addr(&self) -> SocketAddr {
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
        }

        fn is_reliable(&self) -> bool {
            true
        }

        fn alloc_request_id(&self) -> i32 {
            // Canned responses in this module are intentionally built for ID 99.
            99
        }
    }

    #[derive(Clone)]
    struct DeferredUpdateTransport {
        peer: SocketAddr,
        response_number: Arc<AtomicU32>,
        next_request_id: Arc<AtomicI32>,
    }

    impl DeferredUpdateTransport {
        fn new() -> Self {
            Self {
                peer: SocketAddr::from((Ipv4Addr::LOCALHOST, 161)),
                response_number: Arc::new(AtomicU32::new(0)),
                next_request_id: Arc::new(AtomicI32::new(100)),
            }
        }
    }

    impl Transport for DeferredUpdateTransport {
        async fn send(&self, _data: &[u8]) -> Result<()> {
            Ok(())
        }

        async fn recv(&self, _registration: RequestRegistration) -> Result<(Bytes, SocketAddr)> {
            Err(Error::Config("DeferredUpdateTransport uses request()".into()).boxed())
        }

        async fn request_with<U, F>(
            &self,
            data: &[u8],
            _registration: RequestRegistration,
            mut validate: F,
        ) -> Result<U>
        where
            U: Send,
            F: FnMut(Bytes, SocketAddr) -> Result<Candidate<U>> + Send,
        {
            let response_number = self.response_number.fetch_add(1, Ordering::SeqCst);
            let response = build_deferred_update_response(data, response_number);
            match validate(response, self.peer)? {
                Candidate::Accept(value) => Ok(value),
                Candidate::Reject => Err(Error::Timeout {
                    target: self.peer,
                    elapsed: Duration::ZERO,
                    retries: 0,
                }
                .boxed()),
            }
        }

        fn peer_addr(&self) -> SocketAddr {
            self.peer
        }

        fn local_addr(&self) -> SocketAddr {
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
        }

        fn alloc_request_id(&self) -> i32 {
            self.next_request_id.fetch_add(1, Ordering::Relaxed)
        }

        fn is_reliable(&self) -> bool {
            false
        }
    }

    #[derive(Clone)]
    struct RediscoveryRaceTransport {
        peer: SocketAddr,
        next_request_id: Arc<AtomicI32>,
    }

    impl RediscoveryRaceTransport {
        fn new() -> Self {
            Self {
                peer: SocketAddr::from((Ipv4Addr::LOCALHOST, 161)),
                next_request_id: Arc::new(AtomicI32::new(200)),
            }
        }
    }

    impl Transport for RediscoveryRaceTransport {
        async fn send(&self, _data: &[u8]) -> Result<()> {
            Ok(())
        }

        async fn recv(&self, _registration: RequestRegistration) -> Result<(Bytes, SocketAddr)> {
            Err(Error::Config("RediscoveryRaceTransport uses request()".into()).boxed())
        }

        async fn request_with<U, F>(
            &self,
            data: &[u8],
            _registration: RequestRegistration,
            mut validate: F,
        ) -> Result<U>
        where
            U: Send,
            F: FnMut(Bytes, SocketAddr) -> Result<Candidate<U>> + Send,
        {
            let request = V3Message::decode(Bytes::copy_from_slice(data)).unwrap();
            let usm = UsmSecurityParams::decode(request.security_params.clone()).unwrap();
            let response = if usm.engine_id.is_empty() {
                build_rediscovery_race_discovery_response(request)
            } else {
                build_rediscovery_race_authenticated_response(request)
            };
            match validate(response, self.peer)? {
                Candidate::Accept(value) => Ok(value),
                Candidate::Reject => Err(Error::Timeout {
                    target: self.peer,
                    elapsed: Duration::ZERO,
                    retries: 0,
                }
                .boxed()),
            }
        }

        fn peer_addr(&self) -> SocketAddr {
            self.peer
        }

        fn local_addr(&self) -> SocketAddr {
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
        }

        fn alloc_request_id(&self) -> i32 {
            self.next_request_id.fetch_add(1, Ordering::Relaxed)
        }

        fn is_reliable(&self) -> bool {
            true
        }
    }

    const ENGINE_ID: &[u8] = b"engine";
    const REPLACEMENT_ENGINE_ID: &[u8] = b"replacement-engine";

    /// Build a v3 response message under ENGINE_ID for user "user". With
    /// `auth_password` the message is authNoPriv and HMAC-signed; otherwise
    /// noAuthNoPriv.
    fn build_response(
        pdu_type: PduType,
        request_id: i32,
        engine_boots: u32,
        engine_time: u32,
        auth_password: Option<&[u8]>,
    ) -> Bytes {
        let security_level = if auth_password.is_some() {
            SecurityLevel::AuthNoPriv
        } else {
            SecurityLevel::NoAuthNoPriv
        };
        let global = MsgGlobalData::new(
            99,
            crate::MessageSize::new(65507).unwrap(),
            MsgFlags::new(security_level, false),
        )
        .unwrap();
        let mut usm = UsmSecurityParams::new(
            Bytes::from_static(ENGINE_ID),
            engine_boots,
            engine_time,
            Bytes::from_static(b"user"),
        )
        .unwrap();
        let auth_key = auth_password.map(|password| {
            LocalizedKey::from_password(AuthProtocol::Sha1, password, ENGINE_ID).unwrap()
        });
        if let Some(key) = &auth_key {
            usm = usm.with_auth_placeholder(key.mac_len()).unwrap();
        }
        let scoped = ScopedPdu::new(
            Bytes::from_static(ENGINE_ID),
            Bytes::new(),
            Pdu::standard(
                crate::pdu::StandardPduType::try_from(pdu_type).unwrap(),
                request_id,
                0,
                0,
                vec![],
            ),
        );
        let msg = V3Message::new(global, usm.encode().unwrap(), scoped).unwrap();
        match auth_key {
            Some(key) => {
                let mut bytes = msg.encode().unwrap().to_vec();
                let (offset, len) = UsmSecurityParams::find_auth_params_offset(&bytes).unwrap();
                authenticate_message(&key, &mut bytes, offset, len).unwrap();
                Bytes::from(bytes)
            }
            None => msg.encode().unwrap(),
        }
    }

    fn build_rediscovery_race_authenticated_response(request: V3Message) -> Bytes {
        let msg_id = request.global_data.msg_id;
        let scoped_request = match request.data {
            V3MessageData::Plaintext(scoped) => scoped,
            V3MessageData::Encrypted(_) => panic!("expected authNoPriv request"),
        };
        let global = MsgGlobalData::new(
            msg_id,
            crate::MessageSize::new(65507).unwrap(),
            MsgFlags::new(SecurityLevel::AuthNoPriv, false),
        )
        .unwrap();
        let auth_key =
            LocalizedKey::from_password(AuthProtocol::Sha1, b"authpass12345678", ENGINE_ID)
                .unwrap();
        let usm = UsmSecurityParams::new(
            Bytes::from_static(ENGINE_ID),
            1,
            1100,
            Bytes::from_static(b"user"),
        )
        .unwrap()
        .with_auth_placeholder(auth_key.mac_len())
        .unwrap();
        let scoped = ScopedPdu::new(
            scoped_request.context_engine_id,
            scoped_request.context_name,
            Pdu::response(scoped_request.pdu.request_id, 0, 0, vec![]),
        );
        let mut response = V3Message::new(global, usm.encode().unwrap(), scoped)
            .unwrap()
            .encode()
            .unwrap()
            .to_vec();
        let (offset, len) = UsmSecurityParams::find_auth_params_offset(&response).unwrap();
        authenticate_message(&auth_key, &mut response, offset, len).unwrap();
        Bytes::from(response)
    }

    fn build_rediscovery_race_discovery_response(request: V3Message) -> Bytes {
        let global = MsgGlobalData::new(
            request.global_data.msg_id,
            crate::MessageSize::new(65507).unwrap(),
            MsgFlags::new(SecurityLevel::NoAuthNoPriv, false),
        )
        .unwrap();
        let usm = UsmSecurityParams::new(
            Bytes::from_static(REPLACEMENT_ENGINE_ID),
            9,
            9000,
            Bytes::new(),
        )
        .unwrap();
        let report = Pdu::standard(
            crate::pdu::StandardPduType::Report,
            1,
            0,
            0,
            vec![crate::VarBind::new(
                crate::v3::report_oids::unknown_engine_ids(),
                crate::Value::Counter32(1),
            )],
        );
        let scoped = ScopedPdu::new(
            Bytes::from_static(REPLACEMENT_ENGINE_ID),
            Bytes::new(),
            report,
        );
        V3Message::new(global, usm.encode().unwrap(), scoped)
            .unwrap()
            .encode()
            .unwrap()
    }

    fn build_deferred_update_response(request_data: &[u8], response_number: u32) -> Bytes {
        let request = V3Message::decode(Bytes::copy_from_slice(request_data)).unwrap();
        let scoped_request = match request.data {
            V3MessageData::Plaintext(scoped) => scoped,
            V3MessageData::Encrypted(_) => panic!("expected authNoPriv request"),
        };
        let (level, engine_time, pdu) = match response_number {
            0 => (
                SecurityLevel::NoAuthNoPriv,
                1100,
                Pdu::standard(
                    crate::pdu::StandardPduType::Report,
                    0,
                    0,
                    0,
                    vec![crate::VarBind::new(
                        crate::v3::report_oids::not_in_time_windows(),
                        crate::Value::Counter32(1),
                    )],
                ),
            ),
            1 => (
                SecurityLevel::AuthNoPriv,
                1100,
                Pdu::response(scoped_request.pdu.request_id, 0, 0, vec![]),
            ),
            2 => (
                SecurityLevel::AuthNoPriv,
                1400,
                Pdu::response(scoped_request.pdu.request_id, 0, 0, vec![]),
            ),
            _ => panic!("unexpected deferred-update response {response_number}"),
        };
        let global = MsgGlobalData::new(
            request.global_data.msg_id,
            crate::MessageSize::new(65507).unwrap(),
            MsgFlags::new(level, false),
        )
        .unwrap();
        let auth_key = (level == SecurityLevel::AuthNoPriv).then(|| {
            LocalizedKey::from_password(AuthProtocol::Sha1, b"authpass12345678", ENGINE_ID).unwrap()
        });
        let mut usm = UsmSecurityParams::new(
            Bytes::from_static(ENGINE_ID),
            1,
            engine_time,
            Bytes::from_static(b"user"),
        )
        .unwrap();
        if let Some(key) = &auth_key {
            usm = usm.with_auth_placeholder(key.mac_len()).unwrap();
        }
        let scoped = ScopedPdu::new(
            scoped_request.context_engine_id,
            scoped_request.context_name,
            pdu,
        );
        let mut response = V3Message::new(global, usm.encode().unwrap(), scoped)
            .unwrap()
            .encode()
            .unwrap()
            .to_vec();
        if let Some(key) = auth_key {
            let (offset, len) = UsmSecurityParams::find_auth_params_offset(&response).unwrap();
            authenticate_message(&key, &mut response, offset, len).unwrap();
        }
        Bytes::from(response)
    }

    /// Build a client over `response` with engine state (and derived keys,
    /// when authenticated) preset so no discovery round-trip runs.
    fn canned_client(
        response: Bytes,
        engine_boots: u32,
        engine_time: u32,
        security: UsmConfig,
    ) -> Client<CannedTransport> {
        let config = ClientConfig {
            auth: crate::Auth::Usm(security.clone()),
            ..ClientConfig::default()
        };
        let client =
            Client::new(CannedTransport::new(response), config).expect("valid client config");
        {
            let state = EngineState::new(Bytes::from_static(ENGINE_ID), engine_boots, engine_time);
            let derived_keys = security.derive_keys(ENGINE_ID).unwrap();
            *client.inner.engine.write().unwrap() = Some(ClientEngine::new(state, derived_keys));
        }
        client
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn v3_deferred_update_revalidates_after_concurrent_advancement() {
        let transport = DeferredUpdateTransport::new();
        let security = UsmConfig::new("user").auth(AuthProtocol::Sha1, "authpass12345678");
        let cache = Arc::new(EngineCache::new());
        let config = ClientConfig {
            auth: crate::Auth::Usm(security.clone()),
            retry: crate::client::Retry::none(),
            allow_unauthenticated_v3_time_correction: true,
            ..ClientConfig::default()
        };
        let client = Client::with_engine_cache(transport, config, cache.clone())
            .expect("valid client config");
        let state = EngineState::new(Bytes::from_static(ENGINE_ID), 1, 1000);
        let derived_keys = security.derive_keys(ENGINE_ID).unwrap();
        cache.insert(client.peer_addr(), state.clone());
        *client.inner.engine.write().unwrap() = Some(ClientEngine::new(state, derived_keys));

        let (candidate_checked_tx, candidate_checked_rx) = std::sync::mpsc::channel();
        let (advancement_complete_tx, advancement_complete_rx) = std::sync::mpsc::channel();
        let advancement_complete_rx = std::sync::Mutex::new(advancement_complete_rx);
        let first_authenticated_response = AtomicBool::new(true);
        *client
            .inner
            .authenticated_response_validated_hook
            .write()
            .unwrap() = Some(Arc::new(move || {
            if !first_authenticated_response.swap(false, Ordering::SeqCst) {
                return;
            }
            candidate_checked_tx
                .send(())
                .expect("candidate-check waiter dropped");
            advancement_complete_rx
                .lock()
                .expect("advancement-complete lock poisoned")
                .recv_timeout(Duration::from_secs(5))
                .expect("concurrent advancement did not complete");
        }));

        let stale_client = client.clone();
        let stale_request = tokio::spawn(async move {
            stale_client
                .send_v3_and_recv(Pdu::get_request(1, &[oid!(1, 3, 6, 1, 1)]))
                .await
        });
        tokio::task::spawn_blocking(move || {
            candidate_checked_rx.recv_timeout(Duration::from_secs(5))
        })
        .await
        .expect("candidate-check waiter panicked")
        .expect("provisional timeliness check did not complete");

        client
            .send_v3_and_recv(Pdu::get_request(2, &[oid!(1, 3, 6, 1, 1)]))
            .await
            .expect("concurrent response should advance trusted time");
        advancement_complete_tx
            .send(())
            .expect("advancement-complete waiter dropped");

        let err = stale_request.await.unwrap().unwrap_err();
        assert!(matches!(*err, Error::Auth { .. }));
        let engine = client.inner.engine.read().unwrap();
        let trusted = engine.as_ref().unwrap().state.trusted_time().unwrap();
        assert_eq!(trusted.latest_received_time(), 1400);
        assert_eq!(
            cache
                .get(&client.peer_addr())
                .unwrap()
                .trusted_time()
                .unwrap()
                .latest_received_time(),
            1400
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn v3_rediscovery_between_validation_and_publication_preserves_new_generation() {
        let transport = RediscoveryRaceTransport::new();
        let security = UsmConfig::new("user").auth(AuthProtocol::Sha1, "authpass12345678");
        let cache = Arc::new(EngineCache::new());
        let config = ClientConfig {
            auth: crate::Auth::Usm(security.clone()),
            retry: crate::client::Retry::none(),
            ..ClientConfig::default()
        };
        let client = Client::with_engine_cache(transport, config, cache.clone())
            .expect("valid client config");
        let state = EngineState::new(Bytes::from_static(ENGINE_ID), 1, 1000);
        let derived_keys = security.derive_keys(ENGINE_ID).unwrap();
        cache.insert(client.peer_addr(), state.clone());
        *client.inner.engine.write().unwrap() = Some(ClientEngine::new(state, derived_keys));

        let response_validated = Arc::new(Barrier::new(2));
        let allow_publication = Arc::new(Barrier::new(2));
        let hook_response_validated = Arc::clone(&response_validated);
        let hook_allow_publication = Arc::clone(&allow_publication);
        *client
            .inner
            .authenticated_response_validated_hook
            .write()
            .unwrap() = Some(Arc::new(move || {
            hook_response_validated.wait();
            hook_allow_publication.wait();
        }));

        let stale_client = client.clone();
        let stale_request = tokio::spawn(async move {
            stale_client
                .send_v3_and_recv(Pdu::get_request(1, &[oid!(1, 3, 6, 1, 1)]))
                .await
        });
        tokio::task::spawn_blocking(move || response_validated.wait())
            .await
            .expect("response-validation barrier waiter panicked");

        let rediscovery = client.rediscover_engine().await;
        tokio::task::spawn_blocking(move || allow_publication.wait())
            .await
            .expect("publication barrier waiter panicked");
        rediscovery.expect("rediscovery should install the replacement engine");

        let err = stale_request.await.unwrap().unwrap_err();
        assert!(matches!(*err, Error::MalformedResponse { .. }));
        let engine = client.inner.engine.read().unwrap();
        let state = &engine.as_ref().unwrap().state;
        assert_eq!(state.engine_id(), REPLACEMENT_ENGINE_ID);
        assert!(state.trusted_time().is_none());
        let cached = cache.get(&client.peer_addr()).unwrap();
        assert_eq!(cached.engine_id(), REPLACEMENT_ENGINE_ID);
        assert!(cached.trusted_time().is_none());
    }

    /// RFC 3412 Section 6.3: an outgoing request advertises the manager's own
    /// receive capacity (the transport's `max_message_size`), not the remote
    /// engine's cached advertised limit.
    #[tokio::test]
    async fn v3_advertises_local_receive_capacity_not_remote() {
        let security = UsmConfig::new("user").auth(AuthProtocol::Sha1, "authpass12345678");
        let transport = CannedTransport {
            peer: SocketAddr::from((Ipv4Addr::LOCALHOST, 161)),
            response: Bytes::new(),
            max_size: 1400,
            send_size: crate::MAX_UDP_PAYLOAD,
            sends: Arc::new(AtomicUsize::new(0)),
        };
        let config = ClientConfig {
            auth: crate::Auth::Usm(security.clone()),
            ..ClientConfig::default()
        };
        let client = Client::new(transport, config).expect("valid client config");
        {
            // Cached remote capacity differs from the local transport limit.
            let state = EngineState::with_msg_max_size(
                Bytes::from_static(ENGINE_ID),
                5,
                1000,
                crate::MessageSize::new(9000).unwrap(),
            );
            let derived_keys = security.derive_keys(ENGINE_ID).unwrap();
            *client.inner.engine.write().unwrap() = Some(ClientEngine::new(state, derived_keys));
        }

        let pdu = Pdu::get_request(123, &[oid!(1, 3, 6, 1, 1)]);
        let request = client.build_v3_message(&pdu, 1, None).unwrap();
        let msg = V3Message::decode(Bytes::from(request.data)).unwrap();
        assert_eq!(
            msg.global_data.msg_max_size, 1400,
            "request must advertise the local transport capacity, not the remote's cached 9000"
        );
        assert_eq!(
            client.inner.transport.send_capacity(),
            crate::MAX_UDP_PAYLOAD
        );
        let error = client
            .enforce_outbound_size(9001, Some(crate::MessageSize::new(9000).unwrap()))
            .unwrap_err();
        assert!(matches!(
            *error,
            Error::OutboundMessageTooLarge {
                size: 9001,
                limit: 9000
            }
        ));
    }

    #[tokio::test]
    async fn v3_atomic_request_enforces_exact_remote_receive_boundary_before_send() {
        let security = UsmConfig::new("user");
        let response = build_response(PduType::Response, 123, 1, 1001, None);
        let client = canned_client(response, 1, 1000, security.clone());

        let pdu_with_encoded_size = |wanted: usize| {
            (0..1024).find_map(|length| {
                let pdu = Pdu::set_request(
                    123,
                    vec![crate::VarBind::new(
                        oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
                        crate::Value::OctetString(Bytes::from(vec![0; length])),
                    )],
                );
                let encoded = client.build_v3_message(&pdu, 99, None).unwrap();
                (encoded.data.len() == wanted).then_some(pdu)
            })
        };
        let exact_pdu = pdu_with_encoded_size(484).expect("construct exact-boundary request");
        let oversized_pdu =
            pdu_with_encoded_size(485).expect("construct one-byte-oversized request");

        let remote_capacity = crate::MessageSize::new(484).unwrap();
        let state =
            EngineState::with_msg_max_size(Bytes::from_static(ENGINE_ID), 1, 1000, remote_capacity);
        let derived_keys = security.derive_keys(ENGINE_ID).unwrap();
        *client.inner.engine.write().unwrap() = Some(ClientEngine::new(state, derived_keys));

        client.send_v3_and_recv(exact_pdu).await.unwrap();
        assert_eq!(client.inner.transport.sends.load(Ordering::Relaxed), 1);

        let error = client.send_v3_and_recv(oversized_pdu).await.unwrap_err();
        assert!(matches!(
            *error,
            Error::OutboundMessageTooLarge {
                size: 485,
                limit: 484
            }
        ));
        assert_eq!(
            client.inner.transport.sends.load(Ordering::Relaxed),
            1,
            "oversized request must be rejected before transport send"
        );
    }

    /// A received message claiming authentication on a client configured
    /// without authentication must be rejected for the missing capability,
    /// not processed unauthenticated (RFC 3412 Section 7.2 processes at the
    /// received level).
    #[tokio::test]
    async fn v3_noauth_client_rejects_received_auth_response() {
        let pdu = Pdu::get_request(123, &[oid!(1, 3, 6, 1, 1)]);
        let response = build_response(PduType::Response, 123, 1, 1001, Some(b"authpass12345678"));
        let client = canned_client(response, 1, 1000, UsmConfig::new("user"));

        let err = client.send_v3_and_recv(pdu).await.unwrap_err();
        assert!(
            matches!(*err, Error::MalformedResponse { .. }),
            "test transport must surface rejected unverifiable candidate, got: {err}"
        );
    }

    /// RFC 3416 Section 4.2: an echoed request-type PDU with a matching
    /// request-id is not a Response and must be rejected.
    #[tokio::test]
    async fn v3_rejects_echoed_request_pdu() {
        let pdu = Pdu::get_request(123, &[oid!(1, 3, 6, 1, 1)]);
        let response = build_response(PduType::GetRequest, 123, 1, 1001, None);
        let client = canned_client(response, 1, 1000, UsmConfig::new("user"));

        let err = client.send_v3_and_recv(pdu).await.unwrap_err();
        assert!(
            matches!(*err, Error::MalformedResponse { .. }),
            "expected MalformedResponse, got: {err}"
        );
    }

    /// Control for the timeliness test: an authenticated response with a
    /// fresh engine time passes.
    #[tokio::test]
    async fn v3_accepts_timely_authenticated_response() {
        let security = UsmConfig::new("user").auth(AuthProtocol::Sha1, "authpass12345678");
        let pdu = Pdu::get_request(123, &[oid!(1, 3, 6, 1, 1)]);
        let response = build_response(PduType::Response, 123, 1, 1200, Some(b"authpass12345678"));
        let client = canned_client(response, 1, 1000, security);

        let result = client.send_v3_and_recv(pdu).await;
        assert!(result.is_ok(), "expected Ok, got: {:?}", result.err());
    }

    /// RFC 3414 Section 3.2 Step 7b: an authenticated response whose engine
    /// time is more than 150 seconds behind the local notion is a replay and
    /// must be rejected.
    #[tokio::test]
    async fn v3_rejects_stale_authenticated_response() {
        let security = UsmConfig::new("user").auth(AuthProtocol::Sha1, "authpass12345678");
        let pdu = Pdu::get_request(123, &[oid!(1, 3, 6, 1, 1)]);
        // Local notion is time 1000; 500 is beyond the 150-second window.
        let response = build_response(PduType::Response, 123, 1, 500, Some(b"authpass12345678"));
        let client = canned_client(response, 1, 1000, security);

        let err = client.send_v3_and_recv(pdu).await.unwrap_err();
        assert!(
            matches!(*err, Error::MalformedResponse { .. }),
            "test transport must surface rejected stale candidate, got: {err}"
        );
    }
}
