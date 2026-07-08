//! Request handling for different SNMP versions.

use bytes::Bytes;
use std::net::SocketAddr;

use crate::ber::Decoder;
use crate::error::internal::DecodeErrorKind;
use crate::error::{Error, Result};
use crate::handler::{RequestContext, SecurityModel};
use crate::message::{
    CommunityMessage, MsgFlags, MsgGlobalData, ScopedPdu, SecurityLevel, V3Message, V3MessageData,
};
use crate::pdu::{Pdu, PduType};
use crate::v3::auth::verify_message;
use crate::v3::{MAX_ENGINE_TIME, UsmSecurityParams};
use crate::value::Value;
use crate::varbind::VarBind;
use crate::version::Version;

use std::sync::atomic::Ordering;

use super::Agent;

impl Agent {
    /// Handle `SNMPv1` request.
    pub(super) async fn handle_v1(&self, data: Bytes, source: SocketAddr) -> Result<Option<Bytes>> {
        self.handle_community(data, source, Version::V1).await
    }

    /// Handle `SNMPv2c` request.
    pub(super) async fn handle_v2c(
        &self,
        data: Bytes,
        source: SocketAddr,
    ) -> Result<Option<Bytes>> {
        self.handle_community(data, source, Version::V2c).await
    }

    /// Handle an `SNMPv1` or `SNMPv2c` community-based request.
    async fn handle_community(
        &self,
        data: Bytes,
        source: SocketAddr,
        version: Version,
    ) -> Result<Option<Bytes>> {
        let msg = CommunityMessage::decode(data)?;

        // Validate community
        if !self.validate_community(&msg.community) {
            tracing::debug!(target: "async_snmp::agent", { snmp.source = %source }, "invalid community string");
            return Ok(None);
        }

        // Skip non-request PDUs (TrapV1 and other non-request types are ignored)
        let pdu = match msg.pdu.standard() {
            Some(p) if is_request_pdu(p.pdu_type) => p,
            _ => return Ok(None),
        };

        let security_model = match version {
            Version::V1 => SecurityModel::V1,
            Version::V2c => SecurityModel::V2c,
            Version::V3 => unreachable!("handle_community called with V3"),
        };

        // Build request context
        let mut ctx = RequestContext {
            source,
            version,
            security_model,
            security_name: msg.community.clone(),
            security_level: SecurityLevel::NoAuthNoPriv,
            context_name: Bytes::new(),
            request_id: pdu.request_id,
            pdu_type: pdu.pdu_type,
            group_name: None,
            read_view: None,
            write_view: None,
            msg_max_size: None,
        };

        // VACM resolution (if enabled)
        self.resolve_vacm(&mut ctx);

        let response_pdu = self.dispatch_request(&ctx, pdu).await?;
        let response_msg = match version {
            Version::V1 => CommunityMessage::v1(msg.community, response_pdu),
            Version::V2c => CommunityMessage::v2c(msg.community, response_pdu),
            Version::V3 => unreachable!("handle_community called with V3"),
        };

        Ok(Some(response_msg.encode()))
    }

    /// Handle `SNMPv3` request.
    pub(super) async fn handle_v3(&self, data: Bytes, source: SocketAddr) -> Result<Option<Bytes>> {
        let msg = V3Message::decode(data.clone())?;
        let security_level = msg.global_data.msg_flags.security_level;

        // Decode USM parameters
        let usm_params = UsmSecurityParams::decode(msg.security_params.clone())?;

        // Check if this is a discovery request (empty engine ID)
        if usm_params.engine_id.is_empty() {
            return Ok(self.handle_v3_discovery(&msg, source));
        }

        // Verify engine ID matches ours
        if usm_params.engine_id.as_ref() != self.inner.state.engine_id.as_ref() {
            tracing::debug!(target: "async_snmp::agent", { snmp.source = %source }, "engine ID mismatch");
            let count = self
                .inner
                .state
                .usm_unknown_engine_ids
                .fetch_add(1, Ordering::Relaxed)
                + 1;
            return self.send_v3_report(
                &msg,
                &usm_params,
                crate::v3::report_oids::unknown_engine_ids(),
                count,
                None,
                source,
            );
        }

        // Look up user credentials
        let user_config = self.inner.usm_users.get(&usm_params.username);
        let derived_keys = user_config
            .map(|u| u.derive_keys(&self.inner.state.engine_id))
            .transpose()
            .map_err(|e| Error::Config(e.to_string().into()).boxed())?;

        // RFC 3414 section 3.2 step 1: for non-discovery messages (non-empty username),
        // the user MUST exist in the local user database regardless of security level.
        if user_config.is_none() {
            tracing::debug!(target: "async_snmp::agent", { snmp.source = %source, snmp.username = %String::from_utf8_lossy(&usm_params.username) }, "unknown user");
            let count = self
                .inner
                .state
                .usm_unknown_usernames
                .fetch_add(1, Ordering::Relaxed)
                + 1;
            return self.send_v3_report(
                &msg,
                &usm_params,
                crate::v3::report_oids::unknown_user_names(),
                count,
                None,
                source,
            );
        }

        // RFC 3414 Section 3.2 Step 5: the user must support the requested
        // security level, checked before authentication (Step 6), timeliness
        // (Step 7), and the Section 2.3 boots-latched gate below. A user lacking
        // the auth key required for authNoPriv/authPriv, or the privacy key
        // required for authPriv, does not support the level and is rejected here
        // regardless of the message's HMAC, boots, or time.
        if security_level.requires_auth() {
            let supported = derived_keys.as_ref().is_some_and(|k| {
                k.auth_key.is_some()
                    && (security_level != SecurityLevel::AuthPriv || k.priv_key.is_some())
            });
            if !supported {
                tracing::debug!(target: "async_snmp::agent", { snmp.source = %source, snmp.username = %String::from_utf8_lossy(&usm_params.username) }, "user does not support requested security level");
                let count = self
                    .inner
                    .state
                    .usm_unsupported_sec_levels
                    .fetch_add(1, Ordering::Relaxed)
                    + 1;
                return self.send_v3_report(
                    &msg,
                    &usm_params,
                    crate::v3::report_oids::unsupported_sec_levels(),
                    count,
                    None,
                    source,
                );
            }
        }

        // RFC 3414 Section 2.3: when engine boots is latched at maximum,
        // reject all authenticated inbound messages with notInTimeWindows.
        // The agent cannot perform timeliness checks in this state.
        if security_level.requires_auth()
            && self.inner.state.engine_boots.load(Ordering::Relaxed) == MAX_ENGINE_TIME
        {
            tracing::warn!(target: "async_snmp::agent", { snmp.source = %source }, "engine boots at maximum, rejecting authenticated request");
            let count = self
                .inner
                .state
                .usm_not_in_time_windows
                .fetch_add(1, Ordering::Relaxed)
                + 1;
            // Unlike the Step 7a rejection below, the message's HMAC has not
            // been verified at this point, so the report is not authenticated.
            return self.send_v3_report(
                &msg,
                &usm_params,
                crate::v3::report_oids::not_in_time_windows(),
                count,
                None,
                source,
            );
        }

        // Verify authentication if required (RFC 3414 Section 3.2 Step 6). The
        // auth key is guaranteed present by the Step 5 check above.
        if security_level.requires_auth() {
            let auth_key = derived_keys
                .as_ref()
                .and_then(|keys| keys.auth_key.as_ref())
                .expect("authenticated request without an auth key is rejected at Step 5");
            let (auth_offset, auth_len) = UsmSecurityParams::find_auth_params_offset(&data)
                .ok_or_else(|| {
                    tracing::debug!(target: "async_snmp::agent", { source = %source }, "could not find auth params in message");
                    Error::Auth { target: source }.boxed()
                })?;

            if !verify_message(auth_key, &data, auth_offset, auth_len)
                .map_err(|_| Error::Auth { target: source }.boxed())?
            {
                tracing::debug!(target: "async_snmp::agent", { snmp.source = %source }, "authentication failed");
                let count = self
                    .inner
                    .state
                    .usm_wrong_digests
                    .fetch_add(1, Ordering::Relaxed)
                    + 1;
                return self.send_v3_report(
                    &msg,
                    &usm_params,
                    crate::v3::report_oids::wrong_digests(),
                    count,
                    None,
                    source,
                );
            }

            // Verify time window (RFC 3414 Section 3.2 Step 7a):
            // boots must match and time must be within 150 seconds.
            let our_boots = self.inner.state.engine_boots.load(Ordering::Relaxed);
            let our_time = self.inner.state.engine_time.load(Ordering::Relaxed);
            if !crate::v3::in_authoritative_time_window(
                our_boots,
                our_time,
                usm_params.engine_boots,
                usm_params.engine_time,
            ) {
                tracing::debug!(target: "async_snmp::agent", { snmp.source = %source }, "message outside time window");
                let count = self
                    .inner
                    .state
                    .usm_not_in_time_windows
                    .fetch_add(1, Ordering::Relaxed)
                    + 1;
                // RFC 3414 Section 3.2 Step 7a: the report must be
                // authenticated at authNoPriv so the sender can trust
                // the boots/time for resynchronization.
                return self.send_v3_report(
                    &msg,
                    &usm_params,
                    crate::v3::report_oids::not_in_time_windows(),
                    count,
                    Some(auth_key),
                    source,
                );
            }
        }

        // Decrypt if needed
        let scoped_pdu = if security_level == SecurityLevel::AuthPriv {
            // Privacy key presence was checked at Step 5 above.
            let priv_key = derived_keys
                .as_ref()
                .and_then(|keys| keys.priv_key.as_ref())
                .expect("authPriv without a privacy key is rejected at Step 5");
            let encrypted_data = match &msg.data {
                V3MessageData::Encrypted(data) => data,
                V3MessageData::Plaintext(_) => {
                    tracing::debug!(target: "async_snmp::agent", { source = %source, kind = %DecodeErrorKind::ExpectedEncryption }, "expected encrypted scoped PDU");
                    return Err(Error::MalformedResponse { target: source }.boxed());
                }
            };

            let decrypted = match priv_key.decrypt(
                encrypted_data,
                usm_params.engine_boots,
                usm_params.engine_time,
                &usm_params.priv_params,
            ) {
                Ok(data) => data,
                Err(e) => {
                    tracing::debug!(target: "async_snmp::agent", { source = %source, error = %e }, "decryption failed");
                    let count = self
                        .inner
                        .state
                        .usm_decryption_errors
                        .fetch_add(1, Ordering::Relaxed)
                        + 1;
                    return self.send_v3_report(
                        &msg,
                        &usm_params,
                        crate::v3::report_oids::decryption_errors(),
                        count,
                        None,
                        source,
                    );
                }
            };

            let mut decoder = Decoder::with_target(decrypted, source);
            ScopedPdu::decode(&mut decoder)?
        } else if let Some(sp) = msg.scoped_pdu() {
            sp.clone()
        } else {
            tracing::debug!(target: "async_snmp::agent", { source = %source, kind = %DecodeErrorKind::UnexpectedEncryption }, "unexpected encrypted scoped PDU");
            return Err(Error::MalformedResponse { target: source }.boxed());
        };

        let pdu = &scoped_pdu.pdu;

        // Skip non-request PDUs
        if !is_request_pdu(pdu.pdu_type) {
            return Ok(None);
        }

        // Build request context
        let mut ctx = RequestContext {
            source,
            version: Version::V3,
            security_model: SecurityModel::Usm,
            security_name: usm_params.username.clone(),
            security_level,
            context_name: scoped_pdu.context_name.clone(),
            request_id: pdu.request_id,
            pdu_type: pdu.pdu_type,
            group_name: None,
            read_view: None,
            write_view: None,
            msg_max_size: Some(msg.global_data.msg_max_size as u32),
        };

        // VACM resolution (if enabled)
        self.resolve_vacm(&mut ctx);

        let response_pdu = self.dispatch_request(&ctx, pdu).await?;

        // Build response
        self.build_v3_response(
            &msg,
            &usm_params,
            response_pdu,
            scoped_pdu.context_engine_id.clone(),
            scoped_pdu.context_name.clone(),
            derived_keys.as_ref(),
        )
    }

    /// Populate VACM group and view fields on a request context.
    fn resolve_vacm(&self, ctx: &mut RequestContext) {
        if let Some(ref vacm) = self.inner.vacm
            && let Some(group) = vacm.get_group(ctx.security_model, &ctx.security_name)
        {
            ctx.group_name = Some(group.clone());
            if let Some(access) = vacm.get_access(
                group,
                &ctx.context_name,
                ctx.security_model,
                ctx.security_level,
            ) {
                ctx.read_view = Some(access.read_view.clone());
                ctx.write_view = Some(access.write_view.clone());
            } else {
                tracing::warn!(
                    target: "async_snmp::agent",
                    group = %String::from_utf8_lossy(group),
                    context = %String::from_utf8_lossy(&ctx.context_name),
                    security_model = ?ctx.security_model,
                    security_level = ?ctx.security_level,
                    "VACM group has no matching access entry, denying access"
                );
            }
        }
    }

    /// Handle `SNMPv3` discovery request.
    ///
    /// Per RFC 3412 Section 7.1 Step 3, Report PDUs may only be sent if:
    /// - The PDU is from the Confirmed Class, OR
    /// - The reportableFlag is set AND the PDU class cannot be determined
    ///
    /// For discovery requests, the PDU content cannot be determined (empty engine ID),
    /// so we check the reportableFlag.
    pub(super) fn handle_v3_discovery(
        &self,
        incoming: &V3Message,
        _source: SocketAddr,
    ) -> std::option::Option<bytes::Bytes> {
        // Check reportableFlag before sending Report (RFC 3412 Section 7.1 Step 3)
        if !incoming.global_data.msg_flags.reportable {
            tracing::debug!(target: "async_snmp::agent", "discovery request has reportable=false, not sending report");
            return None;
        }

        let engine_boots = self.inner.state.engine_boots.load(Ordering::Relaxed);
        let engine_time = self.inner.state.engine_time.load(Ordering::Relaxed);

        // Increment usmStatsUnknownEngineIDs for discovery requests (RFC 3414 Section 3.2 Step 3b)
        let unknown_engine_ids_count = self
            .inner
            .state
            .usm_unknown_engine_ids
            .fetch_add(1, Ordering::Relaxed)
            + 1;

        // Build Report PDU with usmStatsUnknownEngineIDs.
        // RFC 3412 Section 7.1 Step 3c4: request-id is the value extracted from the
        // original request PDU, or 0 when it cannot be extracted. Discovery requests
        // carry no decodable scopedPDU here, so the original request-id is unavailable.
        let report_pdu = Pdu {
            pdu_type: PduType::Report,
            request_id: 0,
            error_status: 0,
            error_index: 0,
            varbinds: vec![VarBind::new(
                crate::v3::report_oids::unknown_engine_ids(),
                Value::Counter32(unknown_engine_ids_count),
            )],
        };

        let response_global = MsgGlobalData::new(
            incoming.global_data.msg_id,
            incoming.global_data.msg_max_size,
            MsgFlags::new(SecurityLevel::NoAuthNoPriv, false),
        );

        let response_usm = UsmSecurityParams::new(
            self.inner.state.engine_id.clone(),
            engine_boots,
            engine_time,
            Bytes::new(),
        );

        let response_scoped =
            ScopedPdu::new(self.inner.state.engine_id.clone(), Bytes::new(), report_pdu);

        let response_msg = V3Message::new(response_global, response_usm.encode(), response_scoped);

        Some(response_msg.encode())
    }
}

/// Check if a PDU type is a request that should be handled.
///
/// `InformRequest` is a confirmed-class PDU (RFC 3416) that requires a Response.
/// While Informs are typically handled by notification receivers, agents should
/// also respond to them per RFC 3413 Section 4.
pub(super) fn is_request_pdu(pdu_type: PduType) -> bool {
    matches!(
        pdu_type,
        PduType::GetRequest
            | PduType::GetNextRequest
            | PduType::GetBulkRequest
            | PduType::SetRequest
            | PduType::InformRequest
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_request_pdu() {
        assert!(is_request_pdu(PduType::GetRequest));
        assert!(is_request_pdu(PduType::GetNextRequest));
        assert!(is_request_pdu(PduType::GetBulkRequest));
        assert!(is_request_pdu(PduType::SetRequest));
        assert!(is_request_pdu(PduType::InformRequest));
        assert!(!is_request_pdu(PduType::Response));
        assert!(!is_request_pdu(PduType::TrapV2));
    }

    /// Build an authPriv V3 message for `username` whose HMAC is computed with
    /// `auth_password` (pass a wrong password to force a digest mismatch). The
    /// ciphertext is deliberately invalid; callers exercising Step 5 never
    /// reach decryption.
    fn build_authpriv_bad_hmac(engine_id: &[u8], username: &[u8], auth_password: &[u8]) -> Bytes {
        use crate::v3::auth::authenticate_message;
        use crate::v3::{AuthProtocol, LocalizedKey};

        let auth_key =
            LocalizedKey::from_password(AuthProtocol::Sha1, auth_password, engine_id).unwrap();

        let global = MsgGlobalData::new(1, 65507, MsgFlags::new(SecurityLevel::AuthPriv, true));
        let usm_params = UsmSecurityParams::new(
            Bytes::copy_from_slice(engine_id),
            7,
            123_456,
            Bytes::copy_from_slice(username),
        )
        .with_auth_placeholder(auth_key.mac_len())
        .with_priv_params(Bytes::from_static(b"bad"));

        let msg = V3Message::new_encrypted(
            global,
            usm_params.encode(),
            Bytes::from_static(b"not-a-valid-ciphertext"),
        );
        let mut msg_bytes = msg.encode().to_vec();
        let (auth_offset, auth_len) =
            UsmSecurityParams::find_auth_params_offset(&msg_bytes).unwrap();
        authenticate_message(&auth_key, &mut msg_bytes, auth_offset, auth_len).unwrap();
        Bytes::from(msg_bytes)
    }

    /// Build an authNoPriv V3 message for `username` with a plaintext scoped PDU
    /// and an arbitrary auth-parameter placeholder. Callers exercising the
    /// auth-key-missing half of Step 5 never reach authentication, so the digest
    /// value is irrelevant.
    fn build_authnopriv_msg(engine_id: &[u8], username: &[u8]) -> Bytes {
        let global = MsgGlobalData::new(1, 65507, MsgFlags::new(SecurityLevel::AuthNoPriv, true));
        let usm_params = UsmSecurityParams::new(
            Bytes::copy_from_slice(engine_id),
            7,
            123_456,
            Bytes::copy_from_slice(username),
        )
        .with_auth_params(Bytes::from_static(&[0u8; 12]));

        let scoped = ScopedPdu::new(
            Bytes::copy_from_slice(engine_id),
            Bytes::new(),
            Pdu {
                pdu_type: PduType::GetRequest,
                request_id: 99,
                error_status: 0,
                error_index: 0,
                varbinds: vec![],
            },
        );
        let msg = V3Message::new(global, usm_params.encode(), scoped);
        msg.encode()
    }

    /// RFC 3414 Section 3.2 orders Step 5 before Step 7: even when engine boots
    /// is latched at maximum (the Section 2.3 rejection that otherwise returns
    /// usmStatsNotInTimeWindows), an authNoPriv request for a user configured
    /// without an auth key is still reported as usmStatsUnsupportedSecLevels.
    /// Pins the auth-key-missing half of Step 5 ahead of the latched-boots gate.
    #[tokio::test]
    async fn test_v3_authnopriv_for_noauth_user_reported_before_latched_boots() {
        let engine_id = b"\x80\x00\x00\x00\x01agenteng".to_vec();
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .engine_id(engine_id.clone())
            .usm_user("noauthuser", |u| u)
            .build()
            .await
            .unwrap();
        agent
            .inner
            .state
            .engine_boots
            .store(MAX_ENGINE_TIME, Ordering::Relaxed);

        let msg = build_authnopriv_msg(&engine_id, b"noauthuser");
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let report = agent
            .handle_v3(msg, source)
            .await
            .unwrap()
            .expect("a reportable request must produce a Report");
        assert_eq!(agent.usm_unsupported_sec_levels(), 1);
        assert_eq!(agent.usm_not_in_time_windows(), 0);
        assert_eq!(agent.usm_wrong_digests(), 0);

        let decoded = V3Message::decode(report).unwrap();
        let vb = &decoded.pdu().unwrap().varbinds[0];
        assert_eq!(vb.oid, crate::v3::report_oids::unsupported_sec_levels());
    }

    /// RFC 3414 Section 3.2 Step 5 precedes Step 6: an authPriv request for a
    /// user configured without privacy increments usmStatsUnsupportedSecLevels
    /// even when its HMAC is invalid, not usmStatsWrongDigests.
    #[tokio::test]
    async fn test_v3_authpriv_for_auth_only_user_counts_unsupported_sec_level() {
        use crate::v3::AuthProtocol;

        let engine_id = b"\x80\x00\x00\x00\x01agenteng".to_vec();
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .engine_id(engine_id.clone())
            .usm_user("trapuser", |u| {
                u.auth(AuthProtocol::Sha1, b"authpass12345678")
            })
            .build()
            .await
            .unwrap();

        let msg = build_authpriv_bad_hmac(&engine_id, b"trapuser", b"wrong-password-1234");
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let result = agent.handle_v3(msg, source).await.unwrap();
        let report = result.expect("a reportable authPriv request must produce a Report");
        assert_eq!(agent.usm_unsupported_sec_levels(), 1);
        assert_eq!(agent.usm_wrong_digests(), 0);

        // Pin the emitted report varbind to usmStatsUnsupportedSecLevels and
        // Counter32(1): the counter increment and the report OID are separate
        // arguments, so the counter assertions above would still pass if the
        // OID were swapped for a sibling (e.g. wrongDigests).
        let decoded = V3Message::decode(report).unwrap();
        let pdu = decoded.pdu().expect("report carries a PDU");
        assert_eq!(pdu.pdu_type, PduType::Report);
        let vb = &pdu.varbinds[0];
        assert_eq!(vb.oid, crate::v3::report_oids::unsupported_sec_levels());
        assert_eq!(vb.value, Value::Counter32(1));
    }

    /// RFC 3414 Section 3.2 orders Step 5 before Step 7: even when engine boots
    /// is latched at maximum (the Section 2.3 rejection that otherwise returns
    /// usmStatsNotInTimeWindows), an authPriv request for a user without a
    /// privacy key is still reported as usmStatsUnsupportedSecLevels. Pins the
    /// Step-5-before-latched-boots ordering, which the boots-normal test above
    /// does not exercise.
    #[tokio::test]
    async fn test_v3_authpriv_for_auth_only_user_reported_before_latched_boots() {
        use crate::v3::AuthProtocol;

        let engine_id = b"\x80\x00\x00\x00\x01agenteng".to_vec();
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .engine_id(engine_id.clone())
            .usm_user("trapuser", |u| {
                u.auth(AuthProtocol::Sha1, b"authpass12345678")
            })
            .build()
            .await
            .unwrap();
        // Latch engine boots so the Section 2.3 notInTimeWindows rejection
        // would fire first if Step 5 did not precede it.
        agent
            .inner
            .state
            .engine_boots
            .store(MAX_ENGINE_TIME, Ordering::Relaxed);

        let msg = build_authpriv_bad_hmac(&engine_id, b"trapuser", b"wrong-password-1234");
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let report = agent
            .handle_v3(msg, source)
            .await
            .unwrap()
            .expect("a reportable request must produce a Report");
        assert_eq!(agent.usm_unsupported_sec_levels(), 1);
        assert_eq!(agent.usm_not_in_time_windows(), 0);

        let decoded = V3Message::decode(report).unwrap();
        let vb = &decoded.pdu().unwrap().varbinds[0];
        assert_eq!(vb.oid, crate::v3::report_oids::unsupported_sec_levels());
    }
}
