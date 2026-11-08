use std::convert::Infallible;

use async_snmp::message::{CommunityMessage, MsgFlags, MsgGlobalData, ScopedPdu, V3Message};
use async_snmp::v3::UsmSecurityParams;
use async_snmp::{
    AuthoritativeEngine, EncodedInformResponse, EndpointId, LocalEngine, MessageSize, Notification,
    NotificationPdu, NotificationProcessResult, NotificationProcessor, ProcessingInput,
    ProcessingLimits, ReceiveLimits, ReceivedMessageInfo, ReceivedPacket, SecurityLevel, SessionId,
    UsmFailure, UsmSecurityContext, UsmUser, UsmUserEntry, Value, VarBind, Version, oid,
};
use bytes::Bytes;

fn engine() -> LocalEngine {
    LocalEngine::new(
        AuthoritativeEngine::install(b"socketless-notification".as_slice(), |_| {
            Ok::<_, Infallible>(())
        })
        .unwrap(),
    )
    .unwrap()
}

fn input(bytes: Bytes, limits: ProcessingLimits, tcp: bool) -> ProcessingInput {
    let local = "192.0.2.1:162".parse().unwrap();
    let peer = "192.0.2.2:40000".parse().unwrap();
    let info = if tcp {
        ReceivedMessageInfo::tcp(
            EndpointId::new(),
            SessionId::new(),
            local,
            peer,
            tokio::time::Instant::now(),
            bytes.len(),
        )
    } else {
        ReceivedMessageInfo::udp(
            EndpointId::new(),
            local,
            peer,
            Some(local.ip()),
            tokio::time::Instant::now(),
            bytes.len(),
        )
    };
    ProcessingInput::new(ReceivedPacket::new(bytes, info), limits).unwrap()
}

fn inform(version: Version, payload: usize) -> NotificationPdu {
    NotificationPdu::inform(
        version,
        42,
        100,
        &oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1),
        vec![VarBind::new(
            oid!(1, 3, 6, 1, 4, 1, 9, 1),
            Value::OctetString(Bytes::from(vec![b'x'; payload])),
        )],
    )
    .unwrap()
}

fn v3(engine_id: &[u8], username: &str, pdu: async_snmp::Pdu, reportable: bool) -> Bytes {
    let usm = if engine_id.is_empty() {
        UsmSecurityParams::discovery()
    } else {
        UsmSecurityParams::new(
            Bytes::copy_from_slice(engine_id),
            1,
            0,
            Bytes::copy_from_slice(username.as_bytes()),
        )
        .unwrap()
    };
    V3Message::new(
        MsgGlobalData::new(
            71,
            MessageSize::new(8192).unwrap(),
            MsgFlags::new(SecurityLevel::NoAuthNoPriv, reportable),
        )
        .unwrap(),
        usm.encode().unwrap(),
        ScopedPdu::new(Bytes::copy_from_slice(engine_id), Bytes::new(), pdu),
    )
    .unwrap()
    .encode()
    .unwrap()
}

fn accepted(result: NotificationProcessResult) -> async_snmp::ProcessedNotification {
    match result {
        NotificationProcessResult::Accepted(notification) => *notification,
        other => panic!("expected accepted notification, got {other:?}"),
    }
}

#[test]
fn public_processor_build_process_and_encode_require_no_tokio_runtime() {
    assert!(tokio::runtime::Handle::try_current().is_err());
    let processor = NotificationProcessor::builder()
        .community("public")
        .build()
        .unwrap();
    let trap = NotificationPdu::trap_v2(
        Version::V2c,
        7,
        0,
        &oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1),
        vec![],
    )
    .unwrap();
    let v1 = CommunityMessage::v1_trap(
        "public",
        trap.clone().to_v1_trap([192, 0, 2, 2]).unwrap().into_raw(),
    )
    .unwrap()
    .encode()
    .unwrap();
    let event = accepted(
        processor
            .process(input(v1, ProcessingLimits::UDP, false))
            .unwrap(),
    );
    assert!(matches!(event.notification, Notification::TrapV1 { .. }));
    assert!(event.inform_response.is_none());
    let v2 = CommunityMessage::v2c("public", trap.into_raw())
        .unwrap()
        .encode()
        .unwrap();
    let event = accepted(
        processor
            .process(input(v2, ProcessingLimits::UDP, false))
            .unwrap(),
    );
    assert!(matches!(event.notification, Notification::TrapV2c { .. }));
    let wire = CommunityMessage::v2c("public", inform(Version::V2c, 0).into_raw())
        .unwrap()
        .encode()
        .unwrap();
    let received = input(wire, ProcessingLimits::UDP, false);
    let info = received.info();
    let event = accepted(processor.process(received).unwrap());
    assert_eq!(event.receive_info, info);
    assert_eq!(event.wire_identity.request_id, Some(42));
    let encoded = event.inform_response.unwrap().encode().unwrap();
    assert!(matches!(encoded, EncodedInformResponse::Response(_)));

    let local = engine();
    let context = UsmSecurityContext::new([UsmUserEntry::new(UsmUser::new("user"))]).unwrap();
    let processor = NotificationProcessor::builder()
        .local_engine(local.clone())
        .security_context(context)
        .accept_all_notifications()
        .build()
        .unwrap();
    let wire = v3(
        local.engine_id(),
        "user",
        inform(Version::V3, 0).into_raw(),
        true,
    );
    let event = accepted(
        processor
            .process(input(wire, ProcessingLimits::UDP, false))
            .unwrap(),
    );
    assert!(matches!(event.notification, Notification::InformV3 { .. }));
    assert!(matches!(
        event.inform_response.unwrap().encode().unwrap(),
        EncodedInformResponse::Response(_)
    ));
    assert!(tokio::runtime::Handle::try_current().is_err());
}

#[test]
fn explicit_empty_context_requires_engine_and_acceptance_policy() {
    assert!(
        NotificationProcessor::builder()
            .security_context(UsmSecurityContext::default())
            .accept_all_notifications()
            .build()
            .is_err()
    );
    assert!(
        NotificationProcessor::builder()
            .local_engine(engine())
            .security_context(UsmSecurityContext::default())
            .build()
            .is_err()
    );
    assert!(
        NotificationProcessor::builder()
            .local_engine(engine())
            .security_context(UsmSecurityContext::default())
            .accept_all_notifications()
            .build()
            .is_ok()
    );
}

#[test]
fn community_policy_and_filter_rejection_produce_no_response_capability() {
    let wire = CommunityMessage::v2c("public", inform(Version::V2c, 0).into_raw())
        .unwrap()
        .encode()
        .unwrap();
    for processor in [
        NotificationProcessor::builder()
            .community("private")
            .build()
            .unwrap(),
        NotificationProcessor::builder()
            .acceptance_policy(|_| async_snmp::NotificationAcceptance::Reject)
            .build()
            .unwrap(),
    ] {
        assert!(matches!(
            processor
                .process(input(wire.clone(), ProcessingLimits::UDP, false))
                .unwrap(),
            NotificationProcessResult::Rejected
        ));
    }
}

#[test]
fn inform_response_is_encoded_lazily_with_exact_size_fallback() {
    let local = engine();
    let processor = NotificationProcessor::builder()
        .local_engine(local.clone())
        .build()
        .unwrap();
    let wire = CommunityMessage::v2c("public", inform(Version::V2c, 256).into_raw())
        .unwrap()
        .encode()
        .unwrap();
    for (send, suppressed) in [(64, false), (1, true)] {
        let limits = ProcessingLimits::new(ReceiveLimits::udp(8192).unwrap(), send).unwrap();
        let event = accepted(
            processor
                .process(input(wire.clone(), limits, false))
                .unwrap(),
        );
        let encoded = event.inform_response.unwrap().encode().unwrap();
        if suppressed {
            assert!(matches!(encoded, EncodedInformResponse::Suppressed));
        } else {
            let EncodedInformResponse::TooBig(bytes) = encoded else {
                panic!("expected tooBig");
            };
            assert!(bytes.len() <= send);
            let decoded = CommunityMessage::decode(bytes, async_snmp::DecodeConfig::DEFAULT)
                .unwrap()
                .value;
            assert!(decoded.pdu().standard().unwrap().varbinds().is_empty());
        }
    }
    let limits =
        ProcessingLimits::new(ReceiveLimits::tcp(128 * 1024).unwrap(), 128 * 1024).unwrap();
    let wire = CommunityMessage::v2c("public", inform(Version::V2c, 70 * 1024).into_raw())
        .unwrap()
        .encode()
        .unwrap();
    let received = input(wire, limits, true);
    let info = received.info();
    let event = accepted(processor.process(received).unwrap());
    assert_eq!(event.receive_info, info);
    let EncodedInformResponse::Response(bytes) = event.inform_response.unwrap().encode().unwrap()
    else {
        panic!("expected full stream response");
    };
    assert!(bytes.len() > async_snmp::UDP_RECEIVE_BUFFER_SIZE);
}

#[test]
fn usm_failure_keeps_report_and_unclaimed_engine_uses_authoritative_core() {
    let local = engine();
    let processor = NotificationProcessor::builder()
        .local_engine(local.clone())
        .security_context(UsmSecurityContext::default())
        .accept_all_notifications()
        .build()
        .unwrap();
    let local_wire = v3(
        local.engine_id(),
        "unknown",
        inform(Version::V3, 0).into_raw(),
        true,
    );
    let result = processor
        .process(input(local_wire.clone(), ProcessingLimits::UDP, false))
        .unwrap();
    assert!(matches!(
        result,
        NotificationProcessResult::UsmFailed {
            failure: UsmFailure::UnknownUserNames,
            report: Some(_)
        }
    ));
    let before = local.usm_stats();
    assert!(
        processor
            .report_unknown_engine(input(local_wire, ProcessingLimits::UDP, false))
            .unwrap()
            .is_none()
    );
    assert_eq!(local.usm_stats(), before);
    for id in [b"foreign-engine".as_slice(), b"".as_slice()] {
        let wire = v3(id, "unknown", inform(Version::V3, 0).into_raw(), true);
        assert!(
            processor
                .report_unknown_engine(input(wire, ProcessingLimits::UDP, false))
                .unwrap()
                .is_some()
        );
    }
    assert_eq!(local.usm_stats().unknown_engine_ids, 2);
    assert_eq!(local.usm_stats().unknown_usernames, 1);
}
