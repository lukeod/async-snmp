//! Request handling for different SNMP versions.

use bytes::Bytes;
use std::net::SocketAddr;

use crate::error::Result;
use crate::handler::{RequestContext, SecurityModel};
use crate::message::{CommunityMessage, SecurityLevel};
use crate::pdu::PduType;
use crate::v3::process::{MpdCounters, V3Inbound, V3LocalContext, V3Role, process_v3_inbound};
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
    ///
    /// USM processing (RFC 3414 Section 3.2) runs in the shared
    /// [`process_v3_inbound`] core in the authoritative role.
    pub(super) async fn handle_v3(&self, data: Bytes, source: SocketAddr) -> Result<Option<Bytes>> {
        let state = &self.inner.state;
        let usm_ctx = V3LocalContext {
            engine_id: &state.engine_id,
            engine_boots: state.engine_boots.load(Ordering::Relaxed),
            engine_time: state.engine_time.load(Ordering::Relaxed),
            usm_users: &self.inner.usm_users,
            stats: &state.usm_stats,
            mpd: Some(MpdCounters {
                invalid_msgs: &state.snmp_invalid_msgs,
                unknown_security_models: &state.snmp_unknown_security_models,
            }),
            source,
        };

        let inbound = match process_v3_inbound(data, &usm_ctx, &V3Role::Authoritative)? {
            V3Inbound::Failed { report, .. } => return Ok(report),
            // Step 7b does not apply to the authoritative role.
            V3Inbound::RemoteNotInTimeWindow => return Ok(None),
            V3Inbound::Message(inbound) => inbound,
        };
        let msg = &inbound.msg;
        let usm_params = &inbound.usm_params;
        let scoped_pdu = &inbound.scoped_pdu;
        let security_level = inbound.security_level;

        let pdu = &scoped_pdu.pdu;

        // Skip non-request PDUs
        if !is_request_pdu(pdu.pdu_type) {
            return Ok(None);
        }

        // RFC 3413 Section 3.2: the scopedPDU contextEngineID selects the
        // context (SNMP entity) that services the request. This engine serves
        // only its own (single, default) context, so the contextEngineID must
        // either be empty (the default context) or match the local engine ID.
        // A request naming any other engine is answered with an
        // snmpUnknownContexts Report rather than being dispatched blindly
        // against the local MIB and echoed back.
        //
        // Multi-context support (an agent proxying for several contextEngineIDs
        // via a context table) is not implemented; only the local engine's
        // context is recognised.
        let ctx_engine_id = &scoped_pdu.context_engine_id;
        if !ctx_engine_id.is_empty() && ctx_engine_id.as_ref() != state.engine_id.as_ref() {
            tracing::debug!(
                target: "async_snmp::agent",
                { snmp.source = %source, context_engine_id = %crate::format::hex::Bytes(ctx_engine_id) },
                "scopedPDU contextEngineID does not match local engine, rejecting with snmpUnknownContexts"
            );
            state.snmp_unknown_contexts.fetch_add(1, Ordering::Relaxed);

            let report_pdu = crate::pdu::Pdu {
                pdu_type: PduType::Report,
                request_id: pdu.request_id,
                error_status: 0,
                error_index: 0,
                varbinds: vec![crate::VarBind {
                    oid: snmp_unknown_contexts_oid(),
                    value: crate::Value::Counter32(
                        state.snmp_unknown_contexts.load(Ordering::Relaxed),
                    ),
                }],
            };

            // The report is generated by the local engine, so it carries the
            // local engine ID as its contextEngineID rather than echoing the
            // rejected value.
            return self.build_v3_response(
                msg,
                usm_params,
                report_pdu,
                state.engine_id.clone(),
                scoped_pdu.context_name.clone(),
                Some(&inbound.derived_keys),
            );
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
            msg,
            usm_params,
            response_pdu,
            scoped_pdu.context_engine_id.clone(),
            scoped_pdu.context_name.clone(),
            Some(&inbound.derived_keys),
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
}

/// The snmpUnknownContexts counter object (RFC 3413, SNMP-TARGET-MIB).
///
/// `1.3.6.1.6.3.12.1.5.0` - reported when a request names a contextEngineID
/// this engine does not serve.
fn snmp_unknown_contexts_oid() -> crate::Oid {
    crate::oid!(1, 3, 6, 1, 6, 3, 12, 1, 5, 0)
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
    use crate::message::{MsgFlags, MsgGlobalData, ScopedPdu, V3Message};
    use crate::pdu::Pdu;
    use crate::v3::{MAX_ENGINE_TIME, UsmSecurityParams};
    use crate::value::Value;
    use bytes::Bytes;

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

    /// Build a noAuthNoPriv GetRequest whose scopedPDU carries an explicit
    /// `context_engine_id`. The USM engine ID always matches the agent so the
    /// message passes Step 3; only the scopedPDU context varies.
    fn build_noauth_msg(engine_id: &[u8], username: &[u8], context_engine_id: &[u8]) -> Bytes {
        let global = MsgGlobalData::new(1, 65507, MsgFlags::new(SecurityLevel::NoAuthNoPriv, true));
        let usm_params = UsmSecurityParams::new(
            Bytes::copy_from_slice(engine_id),
            0,
            0,
            Bytes::copy_from_slice(username),
        );
        let scoped = ScopedPdu::new(
            Bytes::copy_from_slice(context_engine_id),
            Bytes::new(),
            Pdu {
                pdu_type: PduType::GetRequest,
                request_id: 77,
                error_status: 0,
                error_index: 0,
                varbinds: vec![],
            },
        );
        let msg = V3Message::new(global, usm_params.encode(), scoped);
        msg.encode()
    }

    /// RFC 3413 Section 3.2: a request whose scopedPDU contextEngineID names an
    /// engine other than the local one is answered with an snmpUnknownContexts
    /// Report and not dispatched against the local MIB.
    #[tokio::test]
    async fn test_v3_mismatched_context_engine_id_reports_unknown_context() {
        let engine_id = b"\x80\x00\x00\x00\x01agenteng".to_vec();
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .engine_id(engine_id.clone())
            .usm_user("noauthuser", |u| u)
            .build()
            .await
            .unwrap();

        let msg = build_noauth_msg(&engine_id, b"noauthuser", b"\x80\x00\x00\x00\x01otherengn");
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let report = agent
            .handle_v3(msg, source)
            .await
            .unwrap()
            .expect("mismatched contextEngineID must produce a Report");
        assert_eq!(agent.snmp_unknown_contexts(), 1);

        let decoded = V3Message::decode(report).unwrap();
        let pdu = decoded.pdu().expect("report carries a PDU");
        assert_eq!(pdu.pdu_type, PduType::Report);
        assert_eq!(pdu.varbinds[0].oid, super::snmp_unknown_contexts_oid());
        // The report is generated by the local engine, so it must carry the
        // local engine ID as its contextEngineID, not echo the rejected value.
        let scoped = decoded.scoped_pdu().expect("report has a scoped PDU");
        assert_eq!(scoped.context_engine_id.as_ref(), engine_id.as_slice());
    }

    /// A request whose scopedPDU contextEngineID matches the local engine is
    /// dispatched normally (no snmpUnknownContexts increment).
    #[tokio::test]
    async fn test_v3_matching_context_engine_id_dispatched() {
        let engine_id = b"\x80\x00\x00\x00\x01agenteng".to_vec();
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .engine_id(engine_id.clone())
            .usm_user("noauthuser", |u| u)
            .build()
            .await
            .unwrap();

        let msg = build_noauth_msg(&engine_id, b"noauthuser", &engine_id);
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let response = agent
            .handle_v3(msg, source)
            .await
            .unwrap()
            .expect("matching contextEngineID must produce a Response");
        assert_eq!(agent.snmp_unknown_contexts(), 0);

        let decoded = V3Message::decode(response).unwrap();
        assert_eq!(decoded.pdu().unwrap().pdu_type, PduType::Response);
    }

    /// An empty scopedPDU contextEngineID selects the default (local) context
    /// and is dispatched normally.
    #[tokio::test]
    async fn test_v3_empty_context_engine_id_dispatched() {
        let engine_id = b"\x80\x00\x00\x00\x01agenteng".to_vec();
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .engine_id(engine_id.clone())
            .usm_user("noauthuser", |u| u)
            .build()
            .await
            .unwrap();

        let msg = build_noauth_msg(&engine_id, b"noauthuser", b"");
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let response = agent
            .handle_v3(msg, source)
            .await
            .unwrap()
            .expect("empty contextEngineID must produce a Response");
        assert_eq!(agent.snmp_unknown_contexts(), 0);

        let decoded = V3Message::decode(response).unwrap();
        assert_eq!(decoded.pdu().unwrap().pdu_type, PduType::Response);
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
