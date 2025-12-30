//! SNMPv3-specific client functionality.
//!
//! This module contains V3 security configuration, key derivation, engine discovery,
//! and V3 message building/handling.

use crate::ber::Decoder;
use crate::error::{
    AuthErrorKind, CryptoErrorKind, DecodeErrorKind, EncodeErrorKind, Error, ErrorStatus, Result,
};
use crate::message::{MsgFlags, MsgGlobalData, ScopedPdu, SecurityLevel, V3Message};
use crate::pdu::{Pdu, PduType};
use crate::transport::Transport;
use crate::util::HexBytes;
use crate::v3::{AuthProtocol, PrivProtocol};
use crate::v3::{
    LocalizedKey, PrivKey, UsmSecurityParams,
    auth::{authenticate_message, verify_message},
    is_not_in_time_window_report, is_unknown_engine_id_report,
};
use bytes::Bytes;
use std::time::Instant;
use tracing::{Span, instrument};

use super::Client;

/// SNMPv3 security configuration.
///
/// Stores the credentials needed for authenticated and/or encrypted communication.
/// Keys are derived when the engine ID is discovered.
#[derive(Clone)]
pub struct V3SecurityConfig {
    /// Username for USM authentication
    pub username: Bytes,
    /// Authentication protocol and password
    pub auth: Option<(AuthProtocol, Vec<u8>)>,
    /// Privacy protocol and password
    pub privacy: Option<(PrivProtocol, Vec<u8>)>,
}

impl V3SecurityConfig {
    /// Create a new V3 security config with just a username (noAuthNoPriv).
    pub fn new(username: impl Into<Bytes>) -> Self {
        Self {
            username: username.into(),
            auth: None,
            privacy: None,
        }
    }

    /// Add authentication (authNoPriv or authPriv).
    pub fn auth(mut self, protocol: AuthProtocol, password: impl Into<Vec<u8>>) -> Self {
        self.auth = Some((protocol, password.into()));
        self
    }

    /// Add privacy/encryption (authPriv).
    pub fn privacy(mut self, protocol: PrivProtocol, password: impl Into<Vec<u8>>) -> Self {
        self.privacy = Some((protocol, password.into()));
        self
    }

    /// Get the security level based on configured auth/privacy.
    pub fn security_level(&self) -> SecurityLevel {
        match (&self.auth, &self.privacy) {
            (None, _) => SecurityLevel::NoAuthNoPriv,
            (Some(_), None) => SecurityLevel::AuthNoPriv,
            (Some(_), Some(_)) => SecurityLevel::AuthPriv,
        }
    }

    /// Derive localized keys for a specific engine ID.
    pub fn derive_keys(&self, engine_id: &[u8]) -> V3DerivedKeys {
        let auth_key = self.auth.as_ref().map(|(protocol, password)| {
            LocalizedKey::from_password(*protocol, password, engine_id)
        });

        let priv_key = match (&self.auth, &self.privacy) {
            (Some((auth_protocol, _)), Some((priv_protocol, priv_password))) => Some(
                PrivKey::from_password(*auth_protocol, *priv_protocol, priv_password, engine_id),
            ),
            _ => None,
        };

        V3DerivedKeys { auth_key, priv_key }
    }
}

impl std::fmt::Debug for V3SecurityConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("V3SecurityConfig")
            .field("username", &String::from_utf8_lossy(&self.username))
            .field("auth", &self.auth.as_ref().map(|(p, _)| p))
            .field("privacy", &self.privacy.as_ref().map(|(p, _)| p))
            .finish()
    }
}

/// Derived keys for a specific engine ID.
pub struct V3DerivedKeys {
    pub auth_key: Option<LocalizedKey>,
    pub priv_key: Option<PrivKey>,
}

// V3-specific Client implementation
impl<T: Transport> Client<T> {
    /// Ensure engine ID is discovered for V3 operations.
    #[instrument(level = "debug", skip(self), fields(snmp.target = %self.peer_addr()))]
    pub(super) async fn ensure_engine_discovered(&self) -> Result<()> {
        // Check if already discovered
        {
            let state = self.inner.engine_state.read().unwrap();
            if state.is_some() {
                return Ok(());
            }
        }

        // Check shared cache first
        if let Some(cache) = &self.inner.engine_cache
            && let Some(cached_state) = cache.get(&self.peer_addr())
        {
            tracing::debug!("using cached engine state");
            let mut state = self.inner.engine_state.write().unwrap();
            *state = Some(cached_state.clone());
            // Derive keys for this engine
            if let Some(security) = &self.inner.config.v3_security {
                let keys = security.derive_keys(&cached_state.engine_id);
                let mut derived = self.inner.derived_keys.write().unwrap();
                *derived = Some(keys);
            }
            return Ok(());
        }

        // Perform discovery
        tracing::debug!("performing engine discovery");
        let msg_id = self.next_request_id();
        let discovery_msg = V3Message::discovery_request(msg_id);
        let discovery_data = discovery_msg.encode();

        // Send discovery and wait for response
        self.inner.transport.send(&discovery_data).await?;
        let (response_data, _source) = self
            .inner
            .transport
            .recv(msg_id, self.inner.config.timeout)
            .await?;

        // Parse response
        let response = V3Message::decode(response_data)?;

        // Extract engine state from USM params
        let engine_state = crate::v3::parse_discovery_response(&response.security_params)?;
        tracing::debug!(
            snmp.engine_id = %HexBytes(&engine_state.engine_id),
            snmp.engine_boots = engine_state.engine_boots,
            snmp.engine_time = engine_state.engine_time,
            "discovered engine"
        );

        // Derive keys for this engine
        if let Some(security) = &self.inner.config.v3_security {
            let keys = security.derive_keys(&engine_state.engine_id);
            let mut derived = self.inner.derived_keys.write().unwrap();
            *derived = Some(keys);
        }

        // Store in local cache
        {
            let mut state = self.inner.engine_state.write().unwrap();
            *state = Some(engine_state.clone());
        }

        // Store in shared cache if present
        if let Some(cache) = &self.inner.engine_cache {
            cache.insert(self.peer_addr(), engine_state);
        }

        Ok(())
    }

    /// Build and encode a V3 message with authentication and/or encryption.
    pub(super) fn build_v3_message(&self, pdu: &Pdu) -> Result<(Vec<u8>, i32)> {
        let security = self
            .inner
            .config
            .v3_security
            .as_ref()
            .ok_or_else(|| Error::encode(EncodeErrorKind::NoSecurityConfig))?;

        let engine_state = self.inner.engine_state.read().unwrap();
        let engine_state = engine_state
            .as_ref()
            .ok_or_else(|| Error::encode(EncodeErrorKind::EngineNotDiscovered))?;

        let derived = self.inner.derived_keys.read().unwrap();

        let security_level = security.security_level();
        let msg_id = pdu.request_id; // Use request_id as msg_id for correlation

        // Build scoped PDU
        let scoped_pdu = ScopedPdu::new(
            engine_state.engine_id.clone(),
            Bytes::new(), // empty context name
            pdu.clone(),
        );

        // Get current engine time estimate
        let engine_boots = engine_state.engine_boots;
        let engine_time = engine_state.estimated_time();

        // Handle encryption if needed
        let (msg_data, priv_params) = if security_level.requires_priv() {
            // Get mutable priv_key - we need interior mutability for salt counter
            // Since PrivKey uses internal counter, we need to clone and use
            let derived_ref = derived
                .as_ref()
                .ok_or_else(|| Error::encode(EncodeErrorKind::KeysNotDerived))?;
            let mut priv_key = derived_ref
                .priv_key
                .as_ref()
                .ok_or_else(|| Error::encode(EncodeErrorKind::NoPrivKey))?
                .clone();

            // Encode scoped PDU
            let scoped_pdu_bytes = scoped_pdu.encode_to_bytes();

            // Encrypt
            let (ciphertext, salt) = priv_key.encrypt(
                &scoped_pdu_bytes,
                engine_boots,
                engine_time,
                Some(&self.inner.salt_counter),
            )?;

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
            let auth_key = derived
                .as_ref()
                .and_then(|d| d.auth_key.as_ref())
                .ok_or_else(|| Error::encode(EncodeErrorKind::MissingAuthKey))?;

            // Find auth params position and apply HMAC
            if let Some((offset, len)) = UsmSecurityParams::find_auth_params_offset(&encoded) {
                authenticate_message(auth_key, &mut encoded, offset, len);
            } else {
                return Err(Error::encode(EncodeErrorKind::MissingAuthParams));
            }
        }

        Ok((encoded, msg_id))
    }

    /// Send a V3 request and handle the response.
    #[instrument(
        level = "debug",
        skip(self, pdu),
        fields(
            snmp.target = %self.peer_addr(),
            snmp.request_id = pdu.request_id,
            snmp.security_level = ?self.inner.config.v3_security.as_ref().map(|s| s.security_level()),
            snmp.retries = tracing::field::Empty,
            snmp.elapsed_ms = tracing::field::Empty,
        )
    )]
    pub(super) async fn send_v3_and_recv(&self, pdu: Pdu) -> Result<Pdu> {
        let start = Instant::now();

        // Ensure engine is discovered first
        self.ensure_engine_discovered().await?;

        let security = self
            .inner
            .config
            .v3_security
            .as_ref()
            .ok_or_else(|| Error::encode(EncodeErrorKind::NoSecurityConfig))?;
        let security_level = security.security_level();

        let mut last_error = None;
        let retries = if self.inner.transport.is_stream() {
            0
        } else {
            self.inner.config.retries
        };

        for attempt in 0..=retries {
            Span::current().record("snmp.retries", attempt);
            if attempt > 0 {
                tracing::debug!("retrying V3 request");
            }

            // Build message (may need fresh timestamps on retry)
            let (data, msg_id) = self.build_v3_message(&pdu)?;

            // Send request
            self.inner.transport.send(&data).await?;

            // Wait for response
            match self
                .inner
                .transport
                .recv(msg_id, self.inner.config.timeout)
                .await
            {
                Ok((response_data, _source)) => {
                    // Verify authentication if required
                    if security_level.requires_auth() {
                        let derived = self.inner.derived_keys.read().unwrap();
                        let auth_key = derived
                            .as_ref()
                            .and_then(|d| d.auth_key.as_ref())
                            .ok_or_else(|| {
                                Error::auth(Some(self.peer_addr()), AuthErrorKind::NoAuthKey)
                            })?;

                        if let Some((offset, len)) =
                            UsmSecurityParams::find_auth_params_offset(&response_data)
                        {
                            if !verify_message(auth_key, &response_data, offset, len) {
                                return Err(Error::auth(
                                    Some(self.peer_addr()),
                                    AuthErrorKind::HmacMismatch,
                                ));
                            }
                        } else {
                            return Err(Error::auth(
                                Some(self.peer_addr()),
                                AuthErrorKind::AuthParamsNotFound,
                            ));
                        }
                    }

                    // Decode response
                    let response = V3Message::decode(response_data.clone())?;

                    // Check for Report PDU (error response)
                    if let Some(scoped_pdu) = response.scoped_pdu()
                        && scoped_pdu.pdu.pdu_type == PduType::Report
                    {
                        // Check for time window error - resync and retry
                        if is_not_in_time_window_report(&scoped_pdu.pdu) {
                            tracing::debug!("not in time window, resyncing");
                            // Update engine time from response
                            let usm_params =
                                UsmSecurityParams::decode(response.security_params.clone())?;
                            {
                                let mut state = self.inner.engine_state.write().unwrap();
                                if let Some(ref mut s) = *state {
                                    s.update_time(usm_params.engine_boots, usm_params.engine_time);
                                }
                            }
                            last_error = Some(Error::NotInTimeWindow {
                                target: Some(self.peer_addr()),
                            });
                            continue;
                        }

                        // Check for unknown engine ID
                        if is_unknown_engine_id_report(&scoped_pdu.pdu) {
                            return Err(Error::UnknownEngineId {
                                target: Some(self.peer_addr()),
                            });
                        }

                        // Other Report errors
                        return Err(Error::Snmp {
                            target: Some(self.peer_addr()),
                            status: ErrorStatus::GenErr,
                            index: 0,
                            oid: scoped_pdu.pdu.varbinds.first().map(|vb| vb.oid.clone()),
                        });
                    }

                    // Extract security params before consuming response
                    let response_security_params = response.security_params.clone();

                    // Handle encrypted response
                    let response_pdu = if security_level.requires_priv() {
                        match response.data {
                            crate::message::V3MessageData::Encrypted(ciphertext) => {
                                // Decrypt
                                let derived = self.inner.derived_keys.read().unwrap();
                                let priv_key = derived
                                    .as_ref()
                                    .and_then(|d| d.priv_key.as_ref())
                                    .ok_or_else(|| {
                                    Error::decrypt(
                                        Some(self.peer_addr()),
                                        CryptoErrorKind::NoPrivKey,
                                    )
                                })?;

                                let usm_params =
                                    UsmSecurityParams::decode(response_security_params.clone())?;
                                let plaintext = priv_key.decrypt(
                                    &ciphertext,
                                    usm_params.engine_boots,
                                    usm_params.engine_time,
                                    &usm_params.priv_params,
                                )?;

                                // Decode scoped PDU
                                let mut decoder = Decoder::new(plaintext);
                                let scoped_pdu = ScopedPdu::decode(&mut decoder)?;
                                scoped_pdu.pdu
                            }
                            crate::message::V3MessageData::Plaintext(scoped_pdu) => scoped_pdu.pdu,
                        }
                    } else {
                        response
                            .into_pdu()
                            .ok_or_else(|| Error::decode(0, DecodeErrorKind::MissingPdu))?
                    };

                    // Validate request ID
                    if response_pdu.request_id != pdu.request_id {
                        return Err(Error::RequestIdMismatch {
                            expected: pdu.request_id,
                            actual: response_pdu.request_id,
                        });
                    }

                    // Update engine time from successful response
                    {
                        let usm_params = UsmSecurityParams::decode(response_security_params)?;
                        let mut state = self.inner.engine_state.write().unwrap();
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
                            target: Some(self.peer_addr()),
                            status,
                            index: response_pdu.error_index as u32,
                            oid,
                        });
                    }

                    Span::current().record("snmp.elapsed_ms", start.elapsed().as_millis() as u64);
                    return Ok(response_pdu);
                }
                Err(e @ Error::Timeout { .. }) => {
                    last_error = Some(e);
                    continue;
                }
                Err(e) => {
                    Span::current().record("snmp.elapsed_ms", start.elapsed().as_millis() as u64);
                    return Err(e);
                }
            }
        }

        // All retries exhausted
        Span::current().record("snmp.elapsed_ms", start.elapsed().as_millis() as u64);
        Err(last_error.unwrap_or(Error::Timeout {
            target: Some(self.peer_addr()),
            elapsed: self.inner.config.timeout * (retries + 1),
            request_id: pdu.request_id,
            retries,
        }))
    }
}
