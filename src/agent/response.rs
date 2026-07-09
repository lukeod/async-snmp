//! V3 response building for the SNMP agent.

use bytes::Bytes;
use std::sync::atomic::Ordering;

use crate::error::Result;
use crate::message::V3Message;
use crate::notification::DerivedKeys;
use crate::pdu::Pdu;
use crate::v3::encode::encode_v3_response;
use crate::v3::{MAX_ENGINE_TIME, UsmSecurityParams};

use super::Agent;

impl Agent {
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

        let response_usm = UsmSecurityParams::new(
            self.inner.state.engine_id.clone(),
            engine_boots,
            engine_time,
            incoming_usm.username.clone(),
        );

        encode_v3_response(
            response_pdu,
            incoming.global_data.msg_id,
            incoming.global_data.msg_max_size,
            security_level,
            response_usm,
            context_engine_id,
            context_name,
            derived_keys,
            &self.inner.salt_counter,
            self.inner.local_addr,
        )
        .map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::Agent;
    use crate::message::{MsgFlags, MsgGlobalData, ScopedPdu, SecurityLevel};
    use crate::oid;
    use crate::oid::Oid;
    use crate::pdu::PduType;
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
