//! V3 response building for the SNMP agent.

use crate::error::Result;
use crate::message::MsgGlobalData;
use crate::pdu::Pdu;
use crate::v3::DerivedKeys;
use crate::v3::encode::encode_v3_response;
use crate::v3::{MAX_ENGINE_TIME, UsmSecurityParams};
use bytes::Bytes;

use super::Agent;

impl Agent {
    /// Build a V3 response message with appropriate security.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn finalize_v3_response(
        &self,
        incoming: &MsgGlobalData,
        incoming_usm: &UsmSecurityParams,
        request_pdu: &Pdu,
        response_pdu: Pdu,
        context_engine_id: Bytes,
        context_name: Bytes,
        derived_keys: Option<&DerivedKeys>,
    ) -> Result<crate::response_finalizer::FinalizedResponse> {
        let security_level = incoming.msg_flags.security_level;
        // Handlers are asynchronous and may run long after the receive task's
        // cached time refresh. Derive both fields from one elapsed-time sample
        // at response generation so the authoritative tuple is current and
        // cannot straddle a boots/time rollover.
        let (engine_boots, engine_time) = self.inner.state.authoritative_boots_time()?;

        // RFC 3414 Section 2.3: refuse authenticated messages when boots latched
        if security_level.requires_auth() && engine_boots == MAX_ENGINE_TIME {
            tracing::warn!(target: "async_snmp::agent", "engine boots at maximum, refusing authenticated response");
            return Ok(crate::response_finalizer::FinalizedResponse::Dropped);
        }

        let response_usm = UsmSecurityParams::new(
            self.inner.state.engine_id.clone(),
            engine_boots,
            engine_time,
            incoming_usm.username.clone(),
        );

        // RFC 3412 Section 6.3: msgMaxSize advertises this agent's own receive
        // capacity, not the requester's echoed value or the outbound response
        // size limit.
        crate::response_finalizer::finalize_response(
            crate::Version::V3,
            request_pdu,
            response_pdu,
            self.inner.state.max_message_size,
            Some(incoming.msg_max_size.as_usize()),
            &self.inner.state.snmp_silent_drops,
            |response_pdu| {
                encode_v3_response(
                    response_pdu,
                    incoming.msg_id,
                    self.inner.state.local_receive_capacity,
                    security_level,
                    response_usm.clone(),
                    context_engine_id.clone(),
                    context_name.clone(),
                    derived_keys,
                    &self.inner.salt_counter,
                    self.inner.local_addr,
                )
            },
        )
    }

    #[cfg(test)]
    pub(super) fn build_v3_response(
        &self,
        incoming: &MsgGlobalData,
        incoming_usm: &UsmSecurityParams,
        response_pdu: Pdu,
        context_engine_id: Bytes,
        context_name: Bytes,
        derived_keys: Option<&DerivedKeys>,
    ) -> Result<crate::response_finalizer::FinalizedResponse> {
        let request = Pdu::standard(
            crate::pdu::StandardPduType::GetRequest,
            response_pdu.request_id,
            0,
            0,
            Vec::new(),
        );
        self.finalize_v3_response(
            incoming,
            incoming_usm,
            &request,
            response_pdu,
            context_engine_id,
            context_name,
            derived_keys,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::Agent;
    use crate::message::{MsgFlags, SecurityLevel, V3Message};
    use crate::oid;
    use crate::oid::Oid;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    use crate::handler::{BoxFuture, GetNextResult, GetResult, HandlerResult, MibHandler};

    struct DummyHandler;

    impl MibHandler for DummyHandler {
        fn get<'a>(
            &'a self,
            _ctx: &'a crate::handler::RequestContext,
            _oid: &'a Oid,
        ) -> BoxFuture<'a, HandlerResult<GetResult>> {
            Box::pin(async { Ok(GetResult::NoSuchObject) })
        }

        fn get_next<'a>(
            &'a self,
            _ctx: &'a crate::handler::RequestContext,
            _oid: &'a Oid,
        ) -> BoxFuture<'a, HandlerResult<GetNextResult>> {
            Box::pin(async { Ok(GetNextResult::EndOfMibView) })
        }
    }

    async fn test_agent_with_boots(engine_boots: u32) -> Agent {
        Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .engine_boots(engine_boots)
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), Arc::new(DummyHandler))
            .build()
            .await
            .unwrap()
    }

    async fn test_agent() -> Agent {
        test_agent_with_boots(1).await
    }

    fn dummy_v3_msg(security_level: SecurityLevel) -> MsgGlobalData {
        MsgGlobalData::new(
            1,
            crate::MessageSize::new(65507).unwrap(),
            MsgFlags::new(security_level, true),
        )
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
        Pdu::response(1, 0, 0, vec![])
    }

    #[tokio::test]
    async fn agent_response_path_rejects_invalid_response_fields() {
        let agent = test_agent().await;
        let response = Pdu::response(1, 0, 1, vec![crate::VarBind::null(oid!(1, 3, 6, 1))]);

        let error = agent
            .build_v3_response(
                &dummy_v3_msg(SecurityLevel::NoAuthNoPriv),
                &dummy_usm(),
                response,
                Bytes::from_static(b"engine"),
                Bytes::new(),
                None,
            )
            .unwrap_err();

        assert!(matches!(&*error, crate::Error::InvalidMessage(_)));
    }

    #[tokio::test]
    async fn test_boots_latched_drops_auth_nopriv_response() {
        let agent = test_agent_with_boots(MAX_ENGINE_TIME).await;

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
            0,
            "max-engine-boots refusal is not a size-related silent drop"
        );
    }

    #[tokio::test]
    async fn test_boots_latched_drops_auth_priv_response() {
        let agent = test_agent_with_boots(MAX_ENGINE_TIME).await;

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
        let agent = test_agent_with_boots(MAX_ENGINE_TIME).await;

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
    async fn test_boots_below_max_allows_auth_response() {
        let agent = test_agent_with_boots(MAX_ENGINE_TIME - 1).await;

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

    #[tokio::test]
    async fn test_response_uses_current_coherent_authoritative_time() {
        let agent = test_agent().await;

        // Model a response generated after handler dispatch without refreshing
        // the legacy cached fields. A response must not use this stale,
        // internally inconsistent tuple.
        agent.inner.state.engine_boots.store(17, Ordering::Relaxed);
        agent
            .inner
            .state
            .engine_time
            .store(MAX_ENGINE_TIME, Ordering::Relaxed);

        let earliest = agent.inner.state.authoritative_boots_time().unwrap();
        let encoded = agent
            .build_v3_response(
                &dummy_v3_msg(SecurityLevel::NoAuthNoPriv),
                &dummy_usm(),
                dummy_response_pdu(),
                Bytes::from_static(b"engine"),
                Bytes::new(),
                None,
            )
            .unwrap()
            .expect("noAuthNoPriv response should be produced");
        let latest = agent.inner.state.authoritative_boots_time().unwrap();

        let message = V3Message::decode(encoded).unwrap();
        let response_usm = UsmSecurityParams::decode(message.security_params).unwrap();
        let response_pair = (response_usm.engine_boots, response_usm.engine_time);

        assert_ne!(response_pair, (17, MAX_ENGINE_TIME));
        assert_eq!(response_pair.0, 1);
        assert!(
            response_pair.1 >= earliest.1 && response_pair.1 <= latest.1,
            "response pair {response_pair:?} should come from one current elapsed-time sample between {earliest:?} and {latest:?}"
        );
    }

    // RFC 3412 Section 6.3: the advertised msgMaxSize is this agent's own
    // receive capacity, not the requester's echoed value.
    #[tokio::test]
    async fn test_response_advertises_local_max_size() {
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .max_message_size(1400)
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), Arc::new(DummyHandler))
            .build()
            .await
            .unwrap();

        // Keep the incoming value, local capacity, and response cap distinct.
        let mut msg = dummy_v3_msg(SecurityLevel::NoAuthNoPriv);
        msg.msg_max_size = crate::MessageSize::new(4096).unwrap();
        assert_eq!(agent.inner.state.max_message_size, 1400);
        assert_eq!(agent.inner.state.local_receive_capacity, 65507);
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
            .unwrap()
            .expect("noAuthNoPriv response should be produced");

        let decoded = V3Message::decode(result).unwrap();
        assert_eq!(
            decoded.global_data.msg_max_size, 65507,
            "response must advertise local receive capacity, not the peer value or response cap"
        );
    }
}
