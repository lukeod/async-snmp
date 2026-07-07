//! V3 response building for the SNMP agent.

use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;

use crate::error::internal::{AuthErrorKind, CryptoErrorKind, EncodeErrorKind};
use crate::error::{Error, Result};
use crate::message::{MsgFlags, MsgGlobalData, ScopedPdu, SecurityLevel, V3Message};
use crate::notification::DerivedKeys;
use crate::oid::Oid;
use crate::pdu::{Pdu, PduType};
use crate::v3::auth::authenticate_message;
use crate::v3::{MAX_ENGINE_TIME, UsmSecurityParams};
use crate::value::Value;
use crate::varbind::VarBind;

use super::Agent;

impl Agent {
    /// Send a V3 Report PDU.
    ///
    /// Per RFC 3412 Section 7.1 Step 3, Report PDUs may only be sent if:
    /// - The PDU is from the Confirmed Class, OR
    /// - The reportableFlag is set AND the PDU class cannot be determined
    ///
    /// When this function is called, we haven't successfully decoded the PDU
    /// (due to auth/decryption errors), so we must check reportableFlag.
    ///
    /// With `auth_key` the report is sent authenticated at authNoPriv, as
    /// RFC 3414 Section 3.2 Step 7a requires for notInTimeWindows reports so
    /// the sender can trust the boots/time for resynchronization. Otherwise
    /// it is sent noAuthNoPriv.
    pub(super) fn send_v3_report(
        &self,
        incoming: &V3Message,
        incoming_usm: &UsmSecurityParams,
        report_oid: Oid,
        counter_value: u32,
        auth_key: Option<&crate::v3::LocalizedKey>,
        _source: SocketAddr,
    ) -> Result<Option<Bytes>> {
        // Check reportableFlag before sending Report (RFC 3412 Section 7.1 Step 3)
        if !incoming.global_data.msg_flags.reportable {
            tracing::debug!(target: "async_snmp::agent", "message has reportable=false, not sending report");
            return Ok(None);
        }

        let engine_boots = self.inner.state.engine_boots.load(Ordering::Relaxed);
        let engine_time = self.inner.state.engine_time.load(Ordering::Relaxed);

        let report_pdu = Pdu {
            pdu_type: PduType::Report,
            request_id: incoming.global_data.msg_id,
            error_status: 0,
            error_index: 0,
            varbinds: vec![VarBind::new(report_oid, Value::Counter32(counter_value))],
        };

        let security_level = if auth_key.is_some() {
            SecurityLevel::AuthNoPriv
        } else {
            SecurityLevel::NoAuthNoPriv
        };
        let response_global = MsgGlobalData::new(
            incoming.global_data.msg_id,
            incoming.global_data.msg_max_size,
            MsgFlags::new(security_level, false),
        );

        let mut response_usm = UsmSecurityParams::new(
            self.inner.state.engine_id.clone(),
            engine_boots,
            engine_time,
            incoming_usm.username.clone(),
        );
        if let Some(key) = auth_key {
            response_usm = response_usm.with_auth_placeholder(key.mac_len());
        }

        let response_scoped =
            ScopedPdu::new(self.inner.state.engine_id.clone(), Bytes::new(), report_pdu);

        let response_msg = V3Message::new(response_global, response_usm.encode(), response_scoped);

        match auth_key {
            Some(key) => {
                let response_bytes =
                    self.sign_response(response_msg.encode().to_vec(), key, self.inner.local_addr)?;
                Ok(Some(Bytes::from(response_bytes)))
            }
            None => Ok(Some(response_msg.encode())),
        }
    }

    /// Build a V3 response message with appropriate security.
    pub(super) fn build_v3_response(
        &self,
        incoming: &V3Message,
        incoming_usm: &UsmSecurityParams,
        response_pdu: Pdu,
        context_engine_id: Bytes,
        context_name: Bytes,
        derived_keys: Option<&DerivedKeys>,
    ) -> Result<Option<Bytes>> {
        let security_level = incoming.global_data.msg_flags.security_level;
        let engine_boots = self.inner.state.engine_boots.load(Ordering::Relaxed);
        let engine_time = self.inner.state.engine_time.load(Ordering::Relaxed);

        // RFC 3414 Section 2.3: refuse authenticated messages when boots latched
        if security_level.requires_auth() && engine_boots == MAX_ENGINE_TIME {
            tracing::warn!(target: "async_snmp::agent", "engine boots at maximum, refusing authenticated response");
            self.inner
                .state
                .snmp_silent_drops
                .fetch_add(1, Ordering::Relaxed);
            return Ok(None);
        }

        let response_global = MsgGlobalData::new(
            incoming.global_data.msg_id,
            incoming.global_data.msg_max_size,
            MsgFlags::new(security_level, false),
        );

        let response_scoped = ScopedPdu::new(context_engine_id, context_name, response_pdu);

        match security_level {
            SecurityLevel::NoAuthNoPriv => {
                let response_usm = UsmSecurityParams::new(
                    self.inner.state.engine_id.clone(),
                    engine_boots,
                    engine_time,
                    incoming_usm.username.clone(),
                );
                let response_msg =
                    V3Message::new(response_global, response_usm.encode(), response_scoped);
                Ok(Some(response_msg.encode()))
            }
            SecurityLevel::AuthNoPriv => {
                let local_addr = self.inner.local_addr;
                let (_, auth_key, mac_len) = self.extract_auth_key(derived_keys, local_addr)?;

                let response_usm = UsmSecurityParams::new(
                    self.inner.state.engine_id.clone(),
                    engine_boots,
                    engine_time,
                    incoming_usm.username.clone(),
                )
                .with_auth_placeholder(mac_len);

                let response_msg =
                    V3Message::new(response_global, response_usm.encode(), response_scoped);

                let response_bytes =
                    self.sign_response(response_msg.encode().to_vec(), auth_key, local_addr)?;

                Ok(Some(Bytes::from(response_bytes)))
            }
            SecurityLevel::AuthPriv => {
                let local_addr = self.inner.local_addr;
                let (keys, auth_key, mac_len) = self.extract_auth_key(derived_keys, local_addr)?;
                let priv_key = keys.priv_key.as_ref().ok_or_else(|| {
                    tracing::debug!(target: "async_snmp::agent", { kind = %CryptoErrorKind::NoPrivKey }, "no privacy key for response");
                    Error::Auth { target: local_addr }.boxed()
                })?;

                // Encrypt the scoped PDU
                let scoped_pdu_bytes = response_scoped.encode_to_bytes();
                let (encrypted, priv_params) = priv_key
                    .encrypt(
                        &scoped_pdu_bytes,
                        engine_boots,
                        engine_time,
                        Some(&self.inner.salt_counter),
                    )
                    .map_err(|e| {
                        tracing::debug!(target: "async_snmp::agent", { error = %e }, "encryption failed for response");
                        Error::Auth { target: local_addr }.boxed()
                    })?;

                let response_usm = UsmSecurityParams::new(
                    self.inner.state.engine_id.clone(),
                    engine_boots,
                    engine_time,
                    incoming_usm.username.clone(),
                )
                .with_auth_placeholder(mac_len)
                .with_priv_params(priv_params);

                let response_msg =
                    V3Message::new_encrypted(response_global, response_usm.encode(), encrypted);

                let response_bytes =
                    self.sign_response(response_msg.encode().to_vec(), auth_key, local_addr)?;

                Ok(Some(Bytes::from(response_bytes)))
            }
        }
    }

    /// Validate `derived_keys` and return the keys along with the auth key and its MAC length.
    fn extract_auth_key<'a>(
        &self,
        derived_keys: Option<&'a DerivedKeys>,
        local_addr: SocketAddr,
    ) -> Result<(&'a DerivedKeys, &'a crate::v3::LocalizedKey, usize)> {
        let keys = derived_keys.ok_or_else(|| {
            tracing::debug!(target: "async_snmp::agent", { kind = %AuthErrorKind::NoCredentials }, "no credentials for response");
            Error::Auth { target: local_addr }.boxed()
        })?;
        let auth_key = keys.auth_key.as_ref().ok_or_else(|| {
            tracing::debug!(target: "async_snmp::agent", { kind = %AuthErrorKind::NoAuthKey }, "no auth key for response");
            Error::Auth { target: local_addr }.boxed()
        })?;
        let mac_len = auth_key.mac_len();
        Ok((keys, auth_key, mac_len))
    }

    /// Apply HMAC authentication to an already-encoded response message.
    fn sign_response(
        &self,
        mut response_bytes: Vec<u8>,
        auth_key: &crate::v3::LocalizedKey,
        local_addr: SocketAddr,
    ) -> Result<Vec<u8>> {
        let (auth_offset, auth_len) =
            UsmSecurityParams::find_auth_params_offset(&response_bytes).ok_or_else(|| {
                tracing::debug!(target: "async_snmp::agent", { kind = %EncodeErrorKind::MissingAuthParams }, "could not find auth params in response");
                Error::MalformedResponse { target: local_addr }.boxed()
            })?;
        authenticate_message(auth_key, &mut response_bytes, auth_offset, auth_len)
            .map_err(|e| Error::Config(e.to_string().into()).boxed())?;
        Ok(response_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::Agent;
    use crate::oid;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    use crate::handler::{BoxFuture, GetNextResult, GetResult, MibHandler};

    struct DummyHandler;

    impl MibHandler for DummyHandler {
        fn get<'a>(
            &'a self,
            _ctx: &'a crate::handler::RequestContext,
            _oid: &'a Oid,
        ) -> BoxFuture<'a, GetResult> {
            Box::pin(async { GetResult::NoSuchObject })
        }

        fn get_next<'a>(
            &'a self,
            _ctx: &'a crate::handler::RequestContext,
            _oid: &'a Oid,
        ) -> BoxFuture<'a, GetNextResult> {
            Box::pin(async { GetNextResult::EndOfMibView })
        }
    }

    async fn test_agent() -> Agent {
        Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), Arc::new(DummyHandler))
            .build()
            .await
            .unwrap()
    }

    fn dummy_v3_msg(security_level: SecurityLevel) -> V3Message {
        let global = MsgGlobalData::new(1, 65507, MsgFlags::new(security_level, true));
        let pdu = Pdu {
            pdu_type: PduType::Response,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbinds: vec![],
        };
        let scoped = ScopedPdu::new(Bytes::from_static(b"engine"), Bytes::new(), pdu);
        V3Message::new(global, Bytes::new(), scoped)
    }

    fn dummy_usm() -> UsmSecurityParams {
        UsmSecurityParams::new(
            Bytes::from_static(b"engine"),
            1,
            100,
            Bytes::from_static(b"testuser"),
        )
    }

    fn dummy_response_pdu() -> Pdu {
        Pdu {
            pdu_type: PduType::Response,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbinds: vec![],
        }
    }

    #[tokio::test]
    async fn test_boots_latched_drops_auth_nopriv_response() {
        let agent = test_agent().await;
        agent
            .inner
            .state
            .engine_boots
            .store(MAX_ENGINE_TIME, Ordering::Relaxed);

        let msg = dummy_v3_msg(SecurityLevel::AuthNoPriv);
        let usm = dummy_usm();

        let result = agent
            .build_v3_response(
                &msg,
                &usm,
                dummy_response_pdu(),
                Bytes::from_static(b"engine"),
                Bytes::new(),
                None,
            )
            .unwrap();

        assert!(
            result.is_none(),
            "authenticated response should be dropped when boots is latched"
        );
        assert_eq!(
            agent.inner.state.snmp_silent_drops.load(Ordering::Relaxed),
            1,
            "snmpSilentDrops should be incremented"
        );
    }

    #[tokio::test]
    async fn test_boots_latched_drops_auth_priv_response() {
        let agent = test_agent().await;
        agent
            .inner
            .state
            .engine_boots
            .store(MAX_ENGINE_TIME, Ordering::Relaxed);

        let msg = dummy_v3_msg(SecurityLevel::AuthPriv);
        let usm = dummy_usm();

        let result = agent
            .build_v3_response(
                &msg,
                &usm,
                dummy_response_pdu(),
                Bytes::from_static(b"engine"),
                Bytes::new(),
                None,
            )
            .unwrap();

        assert!(
            result.is_none(),
            "authpriv response should be dropped when boots is latched"
        );
    }

    #[tokio::test]
    async fn test_boots_latched_allows_noauth_response() {
        let agent = test_agent().await;
        agent
            .inner
            .state
            .engine_boots
            .store(MAX_ENGINE_TIME, Ordering::Relaxed);

        let msg = dummy_v3_msg(SecurityLevel::NoAuthNoPriv);
        let usm = dummy_usm();

        let result = agent
            .build_v3_response(
                &msg,
                &usm,
                dummy_response_pdu(),
                Bytes::from_static(b"engine"),
                Bytes::new(),
                None,
            )
            .unwrap();

        assert!(
            result.is_some(),
            "noAuthNoPriv response should still be sent when boots is latched"
        );
    }

    #[tokio::test]
    async fn test_boots_latched_allows_report() {
        let agent = test_agent().await;
        agent
            .inner
            .state
            .engine_boots
            .store(MAX_ENGINE_TIME, Ordering::Relaxed);

        // Unauthenticated reports are noAuthNoPriv, so they should still work
        let msg = dummy_v3_msg(SecurityLevel::AuthNoPriv);
        let usm = dummy_usm();

        let result = agent
            .send_v3_report(
                &msg,
                &usm,
                crate::v3::report_oids::not_in_time_windows(),
                1,
                None,
                "127.0.0.1:12345".parse().unwrap(),
            )
            .unwrap();

        assert!(
            result.is_some(),
            "Report PDUs should still be sent when boots is latched"
        );
    }

    #[tokio::test]
    async fn test_boots_below_max_allows_auth_response() {
        let agent = test_agent().await;
        // Boots just below max - should NOT trigger the latched check
        agent
            .inner
            .state
            .engine_boots
            .store(MAX_ENGINE_TIME - 1, Ordering::Relaxed);

        let msg = dummy_v3_msg(SecurityLevel::NoAuthNoPriv);
        let usm = dummy_usm();

        // NoAuthNoPriv should work regardless
        let result = agent
            .build_v3_response(
                &msg,
                &usm,
                dummy_response_pdu(),
                Bytes::from_static(b"engine"),
                Bytes::new(),
                None,
            )
            .unwrap();

        assert!(
            result.is_some(),
            "noAuthNoPriv should work when boots is below max"
        );
    }
}
