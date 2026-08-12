//! Request handling for different SNMP versions.

use bytes::Bytes;
use std::net::SocketAddr;

use crate::error::Result;
use crate::handler::{RequestContext, SecurityModel, SecurityName};
use crate::message::{CommunityMessage, SecurityLevel};
use crate::pdu::PduType;
use crate::v3::process::{MpdCounters, V3Inbound, V3LocalContext, V3Role, process_v3_inbound};
use crate::value::Value;
use crate::version::Version;

use std::sync::atomic::Ordering;

use super::Agent;
#[cfg(test)]
use super::RESPONSE_OVERHEAD;

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
        let msg = CommunityMessage::decode_with_target_and_policies(
            data,
            Some(source),
            self.inner.state.decode_policy,
            self.inner.state.compatibility_policy,
        )?
        .value;

        // Validate community
        if !self.validate_community(msg.community().as_bytes()) {
            tracing::debug!(target: "async_snmp::agent", { snmp.source = %source }, "invalid community string");
            return Ok(None);
        }

        // Skip non-request PDUs (TrapV1 and other non-request types are ignored)
        let pdu = match msg.pdu().standard() {
            Some(p) if is_request_pdu(p.pdu_type()) => p,
            _ => return Ok(None),
        };

        // Counter64 is not part of the SNMPv1 data types. Decode it so the
        // receive path remains bounded and unambiguous, then silently drop the
        // accepted request before authorization resolution or handler dispatch.
        if version == Version::V1
            && pdu
                .varbinds
                .iter()
                .any(|vb| matches!(vb.value, Value::Counter64(_)))
        {
            self.inner
                .state
                .snmp_in_asn_parse_errs
                .fetch_add(1, Ordering::Relaxed);
            tracing::debug!(
                target: "async_snmp::agent",
                source = %source,
                pdu_type = ?pdu.pdu_type(),
                "dropping SNMPv1 request containing Counter64"
            );
            return Ok(None);
        }

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
            security_name: SecurityName::Community(msg.community().clone()),
            security_level: SecurityLevel::NoAuthNoPriv,
            context_name: Bytes::new(),
            request_id: pdu.request_id,
            pdu_type: pdu.pdu_type(),
            group_name: None,
            read_view: None,
            write_view: None,
            msg_max_size: None,
        };

        let encode = |response_pdu| {
            let response_msg = match version {
                Version::V1 => CommunityMessage::v1(msg.community().clone(), response_pdu),
                Version::V2c => CommunityMessage::v2c(msg.community().clone(), response_pdu),
                Version::V3 => unreachable!("handle_community called with V3"),
            }?;
            response_msg.encode()
        };

        // SET processing must not commit a change whose echoed Response cannot
        // fit. Run the same exact finalizer before dispatch; a fitting candidate
        // permits the transaction, while an alternate/drop terminates it.
        if pdu.pdu_type() == PduType::SetRequest {
            match crate::response_finalizer::finalize_response(
                version,
                pdu,
                pdu.to_response(),
                self.inner.state.max_message_size,
                None,
                &self.inner.state.snmp_silent_drops,
                encode,
            )? {
                crate::response_finalizer::FinalizedResponse::Candidate(_) => {}
                finalized => return Ok(finalized.into_bytes()),
            }
        }

        let response_pdu = if self.resolve_vacm(&mut ctx) {
            self.dispatch_request(&ctx, pdu).await?
        } else {
            let (status, error_index) = if version == Version::V1 {
                if pdu.varbinds.is_empty() {
                    return Ok(None);
                }
                (crate::error::ErrorStatus::NoSuchName, 1)
            } else {
                (crate::error::ErrorStatus::AuthorizationError, 0)
            };
            pdu.to_error_response(status, error_index)
        };
        let finalized = crate::response_finalizer::finalize_response(
            version,
            pdu,
            response_pdu,
            self.inner.state.max_message_size,
            None,
            &self.inner.state.snmp_silent_drops,
            encode,
        )?;
        Ok(finalized.into_bytes())
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
            local_receive_capacity: state.local_receive_capacity,
            accepted_receive_size: crate::UDP_RECEIVE_LIMITS.accepted(),
            decode_policy: state.decode_policy,
            compatibility_policy: state.compatibility_policy,
            outbound_limit: state.max_message_size,
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
        let global_data = &inbound.global_data;
        let usm_params = &inbound.usm_params;
        let scoped_pdu = &inbound.scoped_pdu;
        let security_level = inbound.security_level;

        let pdu = &scoped_pdu.pdu;

        // Skip non-request PDUs
        if !is_request_pdu(pdu.pdu_type()) {
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

            let report_pdu = crate::pdu::Pdu::standard(
                crate::pdu::StandardPduType::Report,
                pdu.request_id,
                0,
                0,
                vec![crate::VarBind {
                    oid: snmp_unknown_contexts_oid(),
                    value: crate::Value::Counter32(
                        state.snmp_unknown_contexts.load(Ordering::Relaxed),
                    ),
                }],
            );

            // The report is generated by the local engine, so it carries the
            // local engine ID as its contextEngineID rather than echoing the
            // rejected value.
            return self
                .finalize_v3_response(
                    global_data,
                    usm_params,
                    pdu,
                    report_pdu,
                    state.engine_id.clone(),
                    scoped_pdu.context_name.clone(),
                    Some(&inbound.derived_keys),
                )
                .map(crate::response_finalizer::FinalizedResponse::into_bytes);
        }

        // Build request context
        let mut ctx = RequestContext {
            source,
            version: Version::V3,
            security_model: SecurityModel::from(global_data.msg_security_model),
            security_name: SecurityName::Usm(usm_params.username.clone()),
            security_level,
            context_name: scoped_pdu.context_name.clone(),
            request_id: pdu.request_id,
            pdu_type: pdu.pdu_type(),
            group_name: None,
            read_view: None,
            write_view: None,
            msg_max_size: Some(global_data.msg_max_size.as_usize()),
        };

        // A successful SET echoes the request varbinds. Preserve the exact
        // preflight bytes so the authoritative boots/time tuple (and authPriv
        // salt) cannot be sampled independently after commit and cross a BER
        // length boundary after side effects have occurred.
        let preflight_success = if pdu.pdu_type() == PduType::SetRequest {
            let success_pdu = pdu.to_response();
            match self.finalize_v3_response(
                global_data,
                usm_params,
                pdu,
                success_pdu.clone(),
                scoped_pdu.context_engine_id.clone(),
                scoped_pdu.context_name.clone(),
                Some(&inbound.derived_keys),
            )? {
                crate::response_finalizer::FinalizedResponse::Candidate(bytes) => {
                    Some((success_pdu, bytes))
                }
                finalized => return Ok(finalized.into_bytes()),
            }
        } else {
            None
        };

        let response_pdu = if self.resolve_vacm(&mut ctx) {
            self.dispatch_request(&ctx, pdu).await?
        } else {
            pdu.to_error_response(crate::error::ErrorStatus::AuthorizationError, 0)
        };
        if let Some((success_pdu, bytes)) = preflight_success
            && response_pdu == success_pdu
        {
            return Ok(Some(bytes));
        }

        // Build and exactly finalize non-SET responses and SET error responses.
        self.finalize_v3_response(
            global_data,
            usm_params,
            pdu,
            response_pdu,
            scoped_pdu.context_engine_id.clone(),
            scoped_pdu.context_name.clone(),
            Some(&inbound.derived_keys),
        )
        .map(crate::response_finalizer::FinalizedResponse::into_bytes)
    }

    /// Populate VACM group and view fields on a request context.
    fn resolve_vacm(&self, ctx: &mut RequestContext) -> bool {
        let Some(vacm) = self.inner.authorization.vacm() else {
            return true;
        };
        let Some(group) = vacm.get_group(ctx.security_model, ctx.security_name.as_bytes()) else {
            tracing::warn!(target: "async_snmp::agent", security_model = ?ctx.security_model, "VACM has no group for accepted security name");
            return false;
        };
        ctx.group_name = Some(group.clone());
        let Some(access) = vacm.get_access(
            group,
            &ctx.context_name,
            ctx.security_model,
            ctx.security_level,
        ) else {
            tracing::warn!(
                target: "async_snmp::agent",
                group = %String::from_utf8_lossy(group),
                context = %String::from_utf8_lossy(&ctx.context_name),
                security_model = ?ctx.security_model,
                security_level = ?ctx.security_level,
                "VACM group has no matching access entry"
            );
            return false;
        };

        ctx.read_view = Some(access.read_view.clone());
        ctx.write_view = Some(access.write_view.clone());
        let required_view = match ctx.pdu_type {
            PduType::GetRequest | PduType::GetNextRequest | PduType::GetBulkRequest => {
                &access.read_view
            }
            PduType::SetRequest => &access.write_view,
            PduType::InformRequest => &access.notify_view,
            _ => return false,
        };
        if required_view.is_empty() || !vacm.has_view(required_view) {
            tracing::warn!(
                target: "async_snmp::agent",
                group = %String::from_utf8_lossy(group),
                pdu_type = ?ctx.pdu_type,
                "VACM access entry has no defined view for request class"
            );
            return false;
        }
        true
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
    use crate::handler::{
        BoxFuture, GetNextResult, GetResult, HandlerResult, MibHandler, PreparedSet,
        RequestContext, SetCommitResult, SetTestResult,
    };
    use crate::message::{MsgFlags, MsgGlobalData, ScopedPdu, V3Message};
    use crate::oid;
    use crate::oid::Oid;
    use crate::pdu::Pdu;
    use crate::v3::{MAX_ENGINE_TIME, UsmSecurityParams};
    use crate::varbind::VarBind;
    use bytes::Bytes;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct CallbackCounts {
        get: AtomicU32,
        get_next: AtomicU32,
        test_set: AtomicU32,
        commit_set: Arc<AtomicU32>,
    }

    struct CountCommit(Arc<AtomicU32>);

    impl PreparedSet for CountCommit {
        fn commit<'a>(
            &'a mut self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
            _value: &'a Value,
        ) -> BoxFuture<'a, SetCommitResult> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Box::pin(async { Ok(()) })
        }
    }

    impl MibHandler for CallbackCounts {
        fn get<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
        ) -> BoxFuture<'a, HandlerResult<GetResult>> {
            self.get.fetch_add(1, Ordering::Relaxed);
            Box::pin(async { Ok(GetResult::Value(Value::Integer(7))) })
        }

        fn get_next<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
        ) -> BoxFuture<'a, HandlerResult<GetNextResult>> {
            self.get_next.fetch_add(1, Ordering::Relaxed);
            Box::pin(async {
                Ok(GetNextResult::Value(VarBind::new(
                    oid!(1, 3, 6, 1, 4, 1, 99999, 2, 0),
                    Value::Integer(8),
                )))
            })
        }

        fn test_set<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
            _value: &'a Value,
        ) -> BoxFuture<'a, SetTestResult> {
            self.test_set.fetch_add(1, Ordering::Relaxed);
            Box::pin(async move {
                Ok(Box::new(CountCommit(self.commit_set.clone())) as Box<dyn PreparedSet>)
            })
        }
    }

    fn encode_community_pdu(version: Version, community: &[u8], pdu: &Pdu) -> Bytes {
        let mut buf = crate::ber::EncodeBuf::new();
        buf.try_push_sequence(|buf| {
            pdu.encode(buf)?;
            buf.push_octet_string(community);
            buf.push_integer(version.as_i32());
            Ok(())
        })
        .unwrap();
        buf.finish()
    }

    fn community_request(
        version: Version,
        pdu_type: PduType,
        community: &'static [u8],
        value: Value,
    ) -> Bytes {
        encode_community_pdu(
            version,
            community,
            &Pdu::standard(
                crate::pdu::StandardPduType::try_from(pdu_type).unwrap(),
                41,
                0,
                0,
                vec![VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0), value)],
            ),
        )
    }

    fn community_set_with_integer_content(version: Version, content: &[u8]) -> Bytes {
        let mut buf = crate::ber::EncodeBuf::new();
        buf.try_push_sequence(|buf| {
            buf.try_push_constructed(PduType::SetRequest.tag(), |buf| {
                buf.try_push_sequence(|buf| {
                    buf.try_push_sequence(|buf| {
                        let mut encoded = vec![crate::ber::tag::universal::INTEGER];
                        encoded.push(u8::try_from(content.len()).unwrap());
                        encoded.extend_from_slice(content);
                        buf.push_bytes(&encoded);
                        buf.push_oid(&oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0))
                    })
                })?;
                buf.push_integer(0);
                buf.push_integer(0);
                buf.push_integer(41);
                Ok(())
            })?;
            buf.push_octet_string(b"public");
            buf.push_integer(version.as_i32());
            Ok(())
        })
        .unwrap();
        buf.finish()
    }

    async fn community_test_agent(callbacks: Arc<CallbackCounts>) -> Agent {
        Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), callbacks)
            .allow_all_access()
            .build()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn community_agent_envelope_policy_covers_v1_and_v2c() {
        let source = "127.0.0.1:9999".parse().unwrap();
        for version in [Version::V1, Version::V2c] {
            let callbacks = Arc::new(CallbackCounts::default());
            let strict = Agent::builder()
                .bind("127.0.0.1:0")
                .community(b"public")
                .handler(oid!(1, 3, 6, 1, 4, 1, 99999), callbacks)
                .allow_all_access()
                .strict_decoding()
                .build()
                .await
                .unwrap();
            let mut request =
                community_request(version, PduType::GetRequest, b"public", Value::Null).to_vec();
            request.extend_from_slice(&[0x05, 0]);
            let result = match version {
                Version::V1 => strict.handle_v1(Bytes::from(request), source).await,
                Version::V2c => strict.handle_v2c(Bytes::from(request), source).await,
                Version::V3 => unreachable!(),
            };
            assert!(result.is_err(), "strict {version:?} accepted a suffix");
        }
    }

    #[tokio::test]
    async fn community_agent_supports_strict_and_targeted_value_policy() {
        let source = "127.0.0.1:9999".parse().unwrap();
        for version in [Version::V1, Version::V2c] {
            let strict_callbacks = Arc::new(CallbackCounts::default());
            let strict = Agent::builder()
                .bind("127.0.0.1:0")
                .community(b"public")
                .handler(oid!(1, 3, 6, 1, 4, 1, 99999), strict_callbacks.clone())
                .allow_all_access()
                .compatibility_policy(crate::CompatibilityPolicy::STRICT)
                .build()
                .await
                .unwrap();
            let request = community_set_with_integer_content(version, &[1, 0, 0, 0, 9]);
            let result = match version {
                Version::V1 => strict.handle_v1(request, source).await,
                Version::V2c => strict.handle_v2c(request, source).await,
                Version::V3 => unreachable!(),
            };
            assert!(result.is_err());
            assert_eq!(strict_callbacks.test_set.load(Ordering::Relaxed), 0);

            let mut targeted = crate::CompatibilityPolicy::STRICT;
            targeted.truncate_numeric_values = true;
            let callbacks = Arc::new(CallbackCounts::default());
            let agent = Agent::builder()
                .bind("127.0.0.1:0")
                .community(b"public")
                .handler(oid!(1, 3, 6, 1, 4, 1, 99999), callbacks.clone())
                .allow_all_access()
                .compatibility_policy(targeted)
                .build()
                .await
                .unwrap();
            let request = community_set_with_integer_content(version, &[1, 0, 0, 0, 9]);
            let response = match version {
                Version::V1 => agent.handle_v1(request, source).await,
                Version::V2c => agent.handle_v2c(request, source).await,
                Version::V3 => unreachable!(),
            }
            .unwrap();
            assert!(response.is_some());
            assert_eq!(callbacks.test_set.load(Ordering::Relaxed), 1);
            assert_eq!(callbacks.commit_set.load(Ordering::Relaxed), 1);
        }
    }

    #[derive(Clone, Copy)]
    enum MissingVacmState {
        Group,
        Access,
        View,
    }

    async fn vacm_denial_agent(state: MissingVacmState, callbacks: Arc<CallbackCounts>) -> Agent {
        let builder = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), callbacks);
        let builder = match state {
            MissingVacmState::Group => builder.vacm(|vacm| vacm),
            MissingVacmState::Access => {
                builder.vacm(|vacm| vacm.group("public", SecurityModel::V2c, "readers"))
            }
            MissingVacmState::View => builder.vacm(|vacm| {
                vacm.group("public", SecurityModel::V2c, "readers").access(
                    "readers",
                    SecurityModel::V2c,
                    SecurityLevel::NoAuthNoPriv,
                    |access| access.read_view("undefined"),
                )
            }),
        };
        builder.build().await.unwrap()
    }

    #[tokio::test]
    async fn missing_vacm_group_access_or_view_returns_authorization_error() {
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        for state in [
            MissingVacmState::Group,
            MissingVacmState::Access,
            MissingVacmState::View,
        ] {
            let callbacks = Arc::new(CallbackCounts::default());
            let agent = vacm_denial_agent(state, Arc::clone(&callbacks)).await;
            let request =
                community_request(Version::V2c, PduType::GetRequest, b"public", Value::Null);
            let response = agent
                .handle_v2c(request, source)
                .await
                .unwrap()
                .expect("VACM denial returns a response");
            let response = CommunityMessage::decode(response).unwrap();
            let response = response.pdu().standard().unwrap();
            assert_eq!(
                response.error_status(),
                crate::ErrorStatus::AuthorizationError.as_i32()
            );
            assert_eq!(response.error_index(), 0);
            assert_no_callbacks(&callbacks);
        }
    }

    #[tokio::test]
    async fn vacm_denied_set_never_reaches_callbacks() {
        let callbacks = Arc::new(CallbackCounts::default());
        let agent = vacm_denial_agent(MissingVacmState::Group, Arc::clone(&callbacks)).await;
        let request = community_request(
            Version::V2c,
            PduType::SetRequest,
            b"public",
            Value::Integer(9),
        );
        let response = agent
            .handle_v2c(request, "127.0.0.1:9999".parse().unwrap())
            .await
            .unwrap()
            .expect("VACM denial returns a response");
        let response = CommunityMessage::decode(response).unwrap();
        let response = response.pdu().standard().unwrap();
        assert_eq!(
            response.error_status(),
            crate::ErrorStatus::AuthorizationError.as_i32()
        );
        assert_eq!(response.error_index(), 0);
        assert_no_callbacks(&callbacks);
    }

    fn assert_no_callbacks(callbacks: &CallbackCounts) {
        assert_eq!(callbacks.get.load(Ordering::Relaxed), 0);
        assert_eq!(callbacks.get_next.load(Ordering::Relaxed), 0);
        assert_eq!(callbacks.test_set.load(Ordering::Relaxed), 0);
        assert_eq!(callbacks.commit_set.load(Ordering::Relaxed), 0);
    }

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

    #[tokio::test]
    async fn test_v1_counter64_requests_are_dropped_before_dispatch() {
        let callbacks = Arc::new(CallbackCounts::default());
        let agent = community_test_agent(Arc::clone(&callbacks)).await;
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        for (index, pdu_type) in [
            PduType::GetRequest,
            PduType::GetNextRequest,
            PduType::SetRequest,
        ]
        .into_iter()
        .enumerate()
        {
            let request = community_request(
                Version::V1,
                pdu_type,
                b"public",
                Value::Counter64(1_u64 << 40),
            );
            assert!(agent.handle_v1(request, source).await.unwrap().is_none());
            assert_eq!(agent.snmp_in_asn_parse_errs(), index as u32 + 1);
            assert_no_callbacks(&callbacks);
        }

        let multiple_counter64s = encode_community_pdu(
            Version::V1,
            b"public",
            &Pdu::standard(
                crate::pdu::StandardPduType::SetRequest,
                42,
                0,
                0,
                vec![
                    VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0), Value::Counter64(1)),
                    VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999, 2, 0), Value::Counter64(2)),
                ],
            ),
        );
        assert!(
            agent
                .handle_v1(multiple_counter64s, source)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(agent.snmp_in_asn_parse_errs(), 4);
        assert_no_callbacks(&callbacks);
    }

    #[tokio::test]
    async fn test_v1_non_counter64_request_is_dispatched() {
        let callbacks = Arc::new(CallbackCounts::default());
        let agent = community_test_agent(Arc::clone(&callbacks)).await;
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let request = community_request(Version::V1, PduType::GetRequest, b"public", Value::Null);

        let response = agent
            .handle_v1(request, source)
            .await
            .unwrap()
            .expect("ordinary SNMPv1 GET should produce a response");
        let decoded = CommunityMessage::decode(response).unwrap();
        assert_eq!(decoded.pdu().pdu_type(), PduType::Response);
        assert_eq!(callbacks.get.load(Ordering::Relaxed), 1);
        assert_eq!(agent.snmp_in_asn_parse_errs(), 0);
    }

    async fn getbulk_call_path_agent(
        callbacks: Arc<CallbackCounts>,
        max_message_size: usize,
    ) -> Agent {
        Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .max_message_size(max_message_size)
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), callbacks)
            .without_builtin_handlers()
            .allow_all_access()
            .build()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn getbulk_first_candidates_are_exactly_finalized_before_toobig() {
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let next_vb = VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999, 2, 0), Value::Integer(8));

        for (non_repeaters, max_repetitions) in [(1, 0), (0, 1)] {
            let request_pdu = Pdu::get_bulk(
                41,
                non_repeaters,
                max_repetitions,
                vec![VarBind::null(oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0))],
            )
            .unwrap();
            let candidate_pdu = Pdu::response(41, 0, 0, vec![next_vb.clone()]);
            let candidate = CommunityMessage::v2c(Bytes::from_static(b"public"), candidate_pdu)
                .unwrap()
                .encode()
                .unwrap();
            let exact = candidate.len();
            assert!(
                RESPONSE_OVERHEAD + b"public".len() + next_vb.encoded_size() > exact,
                "test requires the conservative GETBULK budget to reject the exact-fit candidate"
            );
            let request = CommunityMessage::v2c(Bytes::from_static(b"public"), request_pdu.clone())
                .unwrap()
                .encode()
                .unwrap();

            let callbacks = Arc::new(CallbackCounts::default());
            let agent = getbulk_call_path_agent(callbacks, exact).await;
            let response = agent
                .handle_v2c(request.clone(), source)
                .await
                .unwrap()
                .expect("exact GETBULK candidate should fit");
            assert_eq!(response, candidate);
            assert_eq!(agent.snmp_silent_drops(), 0);

            let callbacks = Arc::new(CallbackCounts::default());
            let agent = getbulk_call_path_agent(callbacks, exact - 1).await;
            let response = agent
                .handle_v2c(request.clone(), source)
                .await
                .unwrap()
                .expect("tooBig fallback should fit");
            let decoded = CommunityMessage::decode(response).unwrap();
            let response_pdu = decoded.pdu().standard().unwrap();
            assert_eq!(
                response_pdu.error_status(),
                crate::ErrorStatus::TooBig.as_i32()
            );
            assert!(response_pdu.varbinds.is_empty());
            assert_eq!(agent.snmp_silent_drops(), 0);

            let callbacks = Arc::new(CallbackCounts::default());
            let agent = getbulk_call_path_agent(callbacks, 1).await;
            assert!(agent.handle_v2c(request, source).await.unwrap().is_none());
            assert_eq!(agent.snmp_silent_drops(), 1);
        }
    }

    #[tokio::test]
    async fn test_v2c_counter64_set_is_dispatched() {
        let callbacks = Arc::new(CallbackCounts::default());
        let agent = community_test_agent(Arc::clone(&callbacks)).await;
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let request = community_request(
            Version::V2c,
            PduType::SetRequest,
            b"public",
            Value::Counter64(1_u64 << 40),
        );

        let response = agent
            .handle_v2c(request, source)
            .await
            .unwrap()
            .expect("SNMPv2c Counter64 SET should produce a response");
        let decoded = CommunityMessage::decode(response).unwrap();
        assert_eq!(decoded.pdu().pdu_type(), PduType::Response);
        assert_eq!(callbacks.test_set.load(Ordering::Relaxed), 1);
        assert_eq!(callbacks.commit_set.load(Ordering::Relaxed), 1);
        assert_eq!(agent.snmp_in_asn_parse_errs(), 0);
    }

    #[tokio::test]
    async fn test_invalid_community_counter64_is_not_counted() {
        let callbacks = Arc::new(CallbackCounts::default());
        let agent = community_test_agent(Arc::clone(&callbacks)).await;
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let request = community_request(
            Version::V1,
            PduType::SetRequest,
            b"private",
            Value::Counter64(1_u64 << 40),
        );

        assert!(agent.handle_v1(request, source).await.unwrap().is_none());
        assert_eq!(agent.snmp_in_asn_parse_errs(), 0);
        assert_no_callbacks(&callbacks);
    }

    /// Build an authPriv V3 message for `username` whose HMAC is computed with
    /// `auth_password` (pass a wrong password to force a digest mismatch). The
    /// ciphertext is deliberately invalid; callers exercising Step 5 never
    /// reach decryption.
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    fn build_authpriv_bad_hmac(engine_id: &[u8], username: &[u8], auth_password: &[u8]) -> Bytes {
        use crate::v3::auth::authenticate_message;
        use crate::v3::{AuthProtocol, LocalizedKey};

        let auth_key =
            LocalizedKey::from_password(AuthProtocol::Sha1, auth_password, engine_id).unwrap();

        let global = MsgGlobalData::new(
            1,
            crate::MessageSize::new(65507).unwrap(),
            MsgFlags::new(SecurityLevel::AuthPriv, true),
        )
        .unwrap();
        let usm_params = UsmSecurityParams::new(
            Bytes::copy_from_slice(engine_id),
            7,
            123_456,
            Bytes::copy_from_slice(username),
        )
        .unwrap()
        .with_auth_placeholder(auth_key.mac_len())
        .unwrap()
        .with_priv_params(Bytes::from_static(b"bad"))
        .unwrap();

        let msg = V3Message::new_encrypted(
            global,
            usm_params.encode().unwrap(),
            Bytes::from_static(b"not-a-valid-ciphertext"),
        )
        .unwrap();
        let mut msg_bytes = msg.encode().unwrap().to_vec();
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
        let global = MsgGlobalData::new(
            1,
            crate::MessageSize::new(65507).unwrap(),
            MsgFlags::new(SecurityLevel::AuthNoPriv, true),
        )
        .unwrap();
        let usm_params = UsmSecurityParams::new(
            Bytes::copy_from_slice(engine_id),
            7,
            123_456,
            Bytes::copy_from_slice(username),
        )
        .unwrap()
        .with_auth_params(Bytes::from_static(&[0u8; 12]))
        .unwrap();

        let scoped = ScopedPdu::new(
            Bytes::copy_from_slice(engine_id),
            Bytes::new(),
            Pdu::standard(crate::pdu::StandardPduType::GetRequest, 99, 0, 0, vec![]),
        );
        let msg = V3Message::new(global, usm_params.encode().unwrap(), scoped).unwrap();
        msg.encode().unwrap()
    }

    /// Build a noAuthNoPriv GetRequest whose scopedPDU carries an explicit
    /// `context_engine_id`. The USM engine ID always matches the agent so the
    /// message passes Step 3; only the scopedPDU context varies.
    fn build_noauth_msg(engine_id: &[u8], username: &[u8], context_engine_id: &[u8]) -> Bytes {
        build_noauth_pdu(
            engine_id,
            username,
            context_engine_id,
            0,
            0,
            Pdu::standard(crate::pdu::StandardPduType::GetRequest, 77, 0, 0, vec![]),
            65507,
        )
    }

    fn build_noauth_pdu(
        engine_id: &[u8],
        username: &[u8],
        context_engine_id: &[u8],
        engine_boots: u32,
        engine_time: u32,
        pdu: Pdu,
        msg_max_size: i32,
    ) -> Bytes {
        let global = MsgGlobalData::new(
            1,
            crate::MessageSize::from_i32(msg_max_size).unwrap(),
            MsgFlags::new(SecurityLevel::NoAuthNoPriv, true),
        )
        .unwrap();
        let usm_params = UsmSecurityParams::new(
            Bytes::copy_from_slice(engine_id),
            engine_boots,
            engine_time,
            Bytes::copy_from_slice(username),
        )
        .unwrap();
        let scoped = ScopedPdu::new(Bytes::copy_from_slice(context_engine_id), Bytes::new(), pdu);
        V3Message::new(global, usm_params.encode().unwrap(), scoped)
            .unwrap()
            .encode()
            .unwrap()
    }

    #[tokio::test]
    async fn strict_v3_agent_rejects_message_suffix() {
        let engine_id = b"\x80\x00\x00\x00\x01strictagt".to_vec();
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .engine_id(engine_id.clone())
            .usm_user("noauthuser", |user| user)
            .allow_all_access()
            .strict_decoding()
            .build()
            .await
            .unwrap();
        let mut request = build_noauth_msg(&engine_id, b"noauthuser", &engine_id).to_vec();
        request.extend_from_slice(&[0x05, 0]);
        assert!(
            agent
                .handle_v3(Bytes::from(request), "127.0.0.1:9999".parse().unwrap())
                .await
                .is_err()
        );
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
            .allow_all_access()
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
        assert_eq!(pdu.pdu_type(), PduType::Report);
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
            .allow_all_access()
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
        assert_eq!(decoded.pdu().unwrap().pdu_type(), PduType::Response);
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[tokio::test]
    async fn unrestricted_agent_accepts_keyed_user_at_noauth_level() {
        use crate::v3::AuthProtocol;

        let engine_id = b"\x80\x00\x00\x00\x01agenteng".to_vec();
        let callbacks = Arc::new(CallbackCounts::default());
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .engine_id(engine_id.clone())
            .usm_user("keyed-user", |user| {
                user.auth(AuthProtocol::Sha256, b"auth-password")
            })
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), callbacks.clone())
            .allow_all_access()
            .build()
            .await
            .unwrap();
        let pdu = Pdu::get_request(77, &[oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0)]);
        let request = build_noauth_pdu(&engine_id, b"keyed-user", &engine_id, 0, 0, pdu, 65507);
        let response = agent
            .handle_v3(request, "127.0.0.1:9999".parse().unwrap())
            .await
            .unwrap()
            .expect("explicit unrestricted policy accepts the request");
        let response = V3Message::decode(response).unwrap();
        assert_eq!(
            response.global_data.msg_flags.security_level,
            SecurityLevel::NoAuthNoPriv
        );
        assert_eq!(response.pdu().unwrap().error_status(), 0);
        assert_eq!(callbacks.get.load(Ordering::Relaxed), 1);
        assert_eq!(agent.usm_unsupported_sec_levels(), 0);
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[tokio::test]
    async fn vacm_denial_uses_actual_v3_level_without_usm_failure() {
        use crate::v3::AuthProtocol;

        let engine_id = b"\x80\x00\x00\x00\x01agenteng".to_vec();
        let callbacks = Arc::new(CallbackCounts::default());
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .engine_id(engine_id.clone())
            .usm_user("keyed-user", |user| {
                user.auth(AuthProtocol::Sha256, b"auth-password")
            })
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), callbacks.clone())
            .vacm(|vacm| {
                vacm.group("keyed-user", SecurityModel::Usm, "operators")
                    .access(
                        "operators",
                        SecurityModel::Usm,
                        SecurityLevel::AuthNoPriv,
                        |access| access.read_view("all"),
                    )
                    .view("all", |view| view.include(oid!(1, 3, 6)))
            })
            .build()
            .await
            .unwrap();
        let request = build_noauth_pdu(
            &engine_id,
            b"keyed-user",
            &engine_id,
            0,
            0,
            Pdu::get_request(77, &[oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0)]),
            65507,
        );
        let response = agent
            .handle_v3(request, "127.0.0.1:9999".parse().unwrap())
            .await
            .unwrap()
            .expect("authorization denial returns a protected response");
        let response = V3Message::decode(response).unwrap();
        assert_eq!(
            response.global_data.msg_flags.security_level,
            SecurityLevel::NoAuthNoPriv
        );
        let pdu = response.pdu().unwrap();
        assert_eq!(
            pdu.error_status(),
            crate::ErrorStatus::AuthorizationError.as_i32()
        );
        assert_eq!(pdu.error_index(), 0);
        assert_no_callbacks(&callbacks);
        assert_eq!(agent.usm_unsupported_sec_levels(), 0);
    }

    #[tokio::test]
    async fn discovery_failure_precedes_agent_authorization() {
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .engine_id(b"\x80\x00\x00\x00\x01agenteng".to_vec())
            .usm_user("user", |user| user)
            .vacm(|vacm| vacm)
            .build()
            .await
            .unwrap();
        let request = V3Message::discovery_request(9, crate::UDP_RECEIVE_LIMITS.advertised())
            .unwrap()
            .encode()
            .unwrap();
        let response = agent
            .handle_v3(request, "127.0.0.1:9999".parse().unwrap())
            .await
            .unwrap()
            .expect("reportable discovery returns a Report");
        let response = V3Message::decode(response).unwrap();
        let pdu = response.pdu().unwrap();
        assert_eq!(pdu.pdu_type(), PduType::Report);
        assert_eq!(
            pdu.varbinds[0].oid,
            crate::v3::report_oids::unknown_engine_ids()
        );
        assert_eq!(agent.usm_unknown_engine_ids(), 1);
    }

    struct BoundarySetHandler {
        state: Mutex<Option<Arc<crate::agent::AgentState>>>,
        commits: Arc<AtomicU32>,
    }

    struct BoundaryPreparedSet {
        state: Arc<crate::agent::AgentState>,
        commits: Arc<AtomicU32>,
    }

    impl PreparedSet for BoundaryPreparedSet {
        fn commit<'a>(
            &'a mut self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
            _value: &'a Value,
        ) -> BoxFuture<'a, SetCommitResult> {
            self.commits.fetch_add(1, Ordering::Relaxed);
            Box::pin(async move {
                self.state.set_authoritative_elapsed_for_test(128);
                Ok(())
            })
        }
    }

    impl MibHandler for BoundarySetHandler {
        fn get<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
        ) -> BoxFuture<'a, HandlerResult<GetResult>> {
            Box::pin(async { Ok(GetResult::NoSuchObject) })
        }

        fn get_next<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
        ) -> BoxFuture<'a, HandlerResult<GetNextResult>> {
            Box::pin(async { Ok(GetNextResult::EndOfMibView) })
        }

        fn test_set<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
            _value: &'a Value,
        ) -> BoxFuture<'a, SetTestResult> {
            let state = self
                .state
                .lock()
                .unwrap()
                .as_ref()
                .expect("test state installed")
                .clone();
            Box::pin(async move {
                Ok(Box::new(BoundaryPreparedSet {
                    state,
                    commits: self.commits.clone(),
                }) as Box<dyn PreparedSet>)
            })
        }
    }

    #[tokio::test]
    async fn v3_set_reuses_exact_preflight_across_engine_time_127_to_128_boundary() {
        use crate::v3::SaltCounter;
        use crate::v3::encode::encode_v3_response;

        let engine_id = Bytes::from_static(b"\x80\x00\x00\x00\x01setclock");
        let username = Bytes::from_static(b"setuser");
        let set_pdu = Pdu::standard(
            crate::pdu::StandardPduType::SetRequest,
            91,
            0,
            0,
            vec![VarBind::new(
                oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0),
                Value::OctetString(Bytes::from(vec![0x5a; 400])),
            )],
        );
        let expected = encode_v3_response(
            set_pdu.to_response(),
            1,
            crate::UDP_RECEIVE_LIMITS.advertised(),
            SecurityLevel::NoAuthNoPriv,
            UsmSecurityParams::new(engine_id.clone(), 1, 127, username.clone()).unwrap(),
            engine_id.clone(),
            Bytes::new(),
            None,
            Some(&SaltCounter::new().unwrap()),
            "127.0.0.1:9999".parse().unwrap(),
        )
        .unwrap();
        let exact_limit = expected.len();

        let handler = Arc::new(BoundarySetHandler {
            state: Mutex::new(None),
            commits: Arc::new(AtomicU32::new(0)),
        });
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .engine_id(engine_id.to_vec())
            .usm_user(username.clone(), |u| u)
            .max_message_size(exact_limit)
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), handler.clone())
            .without_builtin_handlers()
            .allow_all_access()
            .build()
            .await
            .unwrap();
        *handler.state.lock().unwrap() = Some(agent.inner.state.clone());
        agent.inner.state.set_authoritative_elapsed_for_test(127);

        let request = build_noauth_pdu(
            &engine_id,
            &username,
            &engine_id,
            1,
            127,
            set_pdu,
            i32::try_from(exact_limit).unwrap(),
        );
        let response = agent
            .handle_v3(request, "127.0.0.1:9999".parse().unwrap())
            .await
            .unwrap()
            .expect("the preflight success response must remain sendable after commit");

        assert_eq!(handler.commits.load(Ordering::Relaxed), 1);
        assert_eq!(response.len(), exact_limit);
        assert_eq!(response, expected);
        let decoded = V3Message::decode(response).unwrap();
        assert_eq!(decoded.pdu().unwrap().error_status(), 0);
        let usm = UsmSecurityParams::decode(decoded.security_params).unwrap();
        assert_eq!(usm.engine_time, 127);
        assert_eq!(agent.snmp_silent_drops(), 0);
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
            .allow_all_access()
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
        assert_eq!(decoded.pdu().unwrap().pdu_type(), PduType::Response);
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
            .allow_all_access()
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
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
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
            .allow_all_access()
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
        assert_eq!(pdu.pdu_type(), PduType::Report);
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
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
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
            .allow_all_access()
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
