use std::convert::Infallible;

use async_snmp::message::{CommunityMessage, MsgFlags, MsgGlobalData, ScopedPdu, V3Message};
use async_snmp::v3::UsmSecurityParams;
use async_snmp::{
    AuthoritativeEngine, DecodeConfig, EncodedInformResponse, EndpointId, LocalEngine, MessageSize,
    Notification, NotificationPdu, NotificationProcessResult, NotificationProcessor,
    ProcessingInput, ProcessingLimits, ReceiveLimits, ReceivedMessageInfo, ReceivedPacket,
    SecurityLevel, SessionId, UsmFailure, UsmSecurityContext, UsmUser, UsmUserEntry, Value,
    VarBind, Version, oid,
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

fn ordinary_bytes(event: async_snmp::ProcessedNotification) -> Bytes {
    let EncodedInformResponse::Response(bytes) = event.inform_response.unwrap().encode().unwrap()
    else {
        panic!("expected ordinary Inform response");
    };
    bytes
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
    let encoded = ordinary_bytes(event);
    assert!(!encoded.is_empty());

    let local = engine();
    let context = UsmSecurityContext::new([UsmUserEntry::new(UsmUser::new("user"))]).unwrap();
    let processor = NotificationProcessor::builder()
        .local_engine(local.clone())
        .security_context(context)
        .admit_all_notifications()
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
    assert!(!ordinary_bytes(event).is_empty());
    assert!(tokio::runtime::Handle::try_current().is_err());
}

#[test]
fn explicit_empty_context_requires_engine_and_admission_policy() {
    assert!(
        NotificationProcessor::builder()
            .security_context(UsmSecurityContext::default())
            .admit_all_notifications()
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
            .admit_all_notifications()
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
            .admission_policy(|_| async_snmp::NotificationAdmissionDecision::Reject)
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
fn inform_response_fits_before_delivery_on_udp_and_tcp() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    let calls = Arc::new(AtomicUsize::new(0));
    let policy_calls = calls.clone();
    let processor = NotificationProcessor::builder()
        .local_engine(engine())
        .admission_policy(move |_| {
            policy_calls.fetch_add(1, Ordering::Relaxed);
            async_snmp::NotificationAdmissionDecision::Admit
        })
        .build()
        .unwrap();
    let request = inform(Version::V2c, 256).into_raw();
    let wire = CommunityMessage::v2c("public", request.clone())
        .unwrap()
        .encode()
        .unwrap();
    let ordinary_len = wire.len();
    for (send, suppressed) in [(ordinary_len - 1, false), (1, true)] {
        let limits = ProcessingLimits::new(ReceiveLimits::udp(8192).unwrap(), send).unwrap();
        let result = processor
            .process(input(wire.clone(), limits, false))
            .unwrap();
        let NotificationProcessResult::InformTooBig { response } = result else {
            panic!("expected oversized result: {result:?}");
        };
        assert_eq!(response.is_none(), suppressed);
        if let Some(bytes) = response {
            assert!(bytes.len() <= send);
            let decoded = CommunityMessage::decode(bytes, async_snmp::DecodeConfig::DEFAULT)
                .unwrap()
                .value;
            let pdu = decoded.pdu().standard().unwrap();
            assert_eq!(
                pdu.error_fields(),
                Some((async_snmp::ErrorStatus::TooBig.as_i32(), 0))
            );
            assert_eq!(pdu.request_id(), request.request_id());
            assert!(pdu.varbinds().is_empty());
        }
    }
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    let limits = ProcessingLimits::new(ReceiveLimits::udp(8192).unwrap(), ordinary_len).unwrap();
    let event = accepted(processor.process(input(wire, limits, false)).unwrap());
    assert_eq!(ordinary_bytes(event).len(), ordinary_len);
    assert_eq!(calls.load(Ordering::Relaxed), 3);
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
    let bytes = ordinary_bytes(event);
    assert!(bytes.len() > async_snmp::UDP_RECEIVE_BUFFER_SIZE);
    assert_eq!(calls.load(Ordering::Relaxed), 4);
}

#[test]
fn usm_failure_keeps_report_and_unclaimed_engine_uses_authoritative_core() {
    let local = engine();
    let processor = NotificationProcessor::builder()
        .local_engine(local.clone())
        .security_context(UsmSecurityContext::default())
        .admit_all_notifications()
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
        local
            .report_unknown_engine(
                input(local_wire, ProcessingLimits::UDP, false),
                DecodeConfig::DEFAULT
            )
            .unwrap()
            .is_none()
    );
    assert_eq!(local.usm_stats(), before);
    for id in [b"foreign-engine".as_slice(), b"".as_slice()] {
        let wire = v3(id, "unknown", inform(Version::V3, 0).into_raw(), true);
        assert!(
            local
                .report_unknown_engine(
                    input(wire, ProcessingLimits::UDP, false),
                    DecodeConfig::DEFAULT
                )
                .unwrap()
                .is_some()
        );
    }
    assert_eq!(local.usm_stats().unknown_engine_ids, 2);
    assert_eq!(local.usm_stats().unknown_usernames, 1);
}

#[test]
fn selected_peer_routes_by_pdu_type_when_reportable_flag_disagrees() {
    use async_snmp::v3::{ReportStatus, classify_report};

    let local = engine();
    let processor = NotificationProcessor::builder()
        .local_engine(local.clone())
        .security_context(
            UsmSecurityContext::new([UsmUserEntry::new(UsmUser::new("user"))]).unwrap(),
        )
        .admit_all_notifications()
        .build()
        .unwrap();
    let foreign = b"previous-receiver-engine";
    let inform = NotificationPdu::inform(
        Version::V3,
        -42,
        100,
        &oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1),
        vec![],
    )
    .unwrap();
    let wire = v3(foreign, "user", inform.into_raw(), false);
    let received = input(wire, ProcessingLimits::UDP, false);
    let NotificationProcessResult::UsmFailed {
        failure: UsmFailure::UnknownEngineIds,
        report: Some(report),
    } = processor.process(received).unwrap()
    else {
        panic!("expected a Report for the stale Inform");
    };
    let report = V3Message::decode(report, DecodeConfig::DEFAULT)
        .unwrap()
        .value;
    assert_eq!(report.global_data().msg_id(), 71);
    assert_eq!(
        report.global_data().msg_flags(),
        MsgFlags::new(SecurityLevel::NoAuthNoPriv, false)
    );
    let scoped = report.scoped_pdu().unwrap();
    assert_eq!(scoped.context_engine_id.as_ref(), local.engine_id());
    assert!(scoped.context_name.is_empty());
    assert_eq!(scoped.pdu.request_id(), -42);
    assert_eq!(
        classify_report(&scoped.pdu).unwrap(),
        ReportStatus::UnknownEngineId { counter: 1 },
    );
    let usm = UsmSecurityParams::decode(report.security_params().clone(), DecodeConfig::DEFAULT)
        .unwrap()
        .value;
    assert_eq!(usm.engine_id().as_ref(), local.engine_id());

    let trap = NotificationPdu::trap_v2(
        Version::V3,
        42,
        100,
        &oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1),
        vec![],
    )
    .unwrap();
    let trap = trap.into_raw();
    let received = input(
        v3(foreign, "nobody", trap.clone(), true),
        ProcessingLimits::UDP,
        false,
    );
    assert!(matches!(
        processor.process(received).unwrap(),
        NotificationProcessResult::UsmFailed {
            failure: UsmFailure::UnknownUserNames,
            report: None
        }
    ));
    let received = input(
        v3(foreign, "user", trap, true),
        ProcessingLimits::UDP,
        false,
    );
    let event = accepted(processor.process(received).unwrap());
    assert!(matches!(event.notification, Notification::TrapV3 { .. }));
    assert!(event.inform_response.is_none());
    assert_eq!(local.usm_stats().unknown_engine_ids, 1);
    assert_eq!(local.usm_stats().unknown_usernames, 1);
}

#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
#[tokio::test]
async fn caller_owned_udp_defers_two_auth_priv_informs_until_persistence() {
    use std::io::Write;
    use std::time::Duration;

    use async_snmp::{
        AuthProtocol, Client, NotificationAdmissionDecision, PrivProtocol, Retry, UdpEndpoint,
        UsmConfig,
    };
    use tokio::net::UdpSocket;
    use tokio::time::{Instant, timeout};

    const WAIT: Duration = Duration::from_secs(10);
    const USER: &str = "collector";
    let passwords = ["tenant-a-password", "tenant-b-password"];
    let engine = engine();
    let contexts = passwords.map(|password| {
        let user = UsmUser::new(USER)
            .auth_priv(
                AuthProtocol::Sha256,
                password,
                PrivProtocol::Aes128,
                password,
            )
            .unwrap();
        let entry = UsmUserEntry::for_engine(engine.engine_id().to_vec(), user).unwrap();
        UsmSecurityContext::new([entry]).unwrap()
    });
    let processors = contexts.clone().map(|context| {
        NotificationProcessor::builder()
            .local_engine(engine.clone())
            .security_context(context)
            .admission_policy(|event| {
                if event.security_level == Some(SecurityLevel::AuthPriv) {
                    NotificationAdmissionDecision::Admit
                } else {
                    NotificationAdmissionDecision::Reject
                }
            })
            .build()
            .unwrap()
    });
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let local = socket.local_addr().unwrap();
    let endpoints = [
        UdpEndpoint::spawn("127.0.0.1:0").await.unwrap(),
        UdpEndpoint::spawn("127.0.0.1:0").await.unwrap(),
    ];
    let make_client = |password: &str| {
        let security = UsmConfig::new(USER)
            .auth_priv(
                AuthProtocol::Sha256,
                password,
                PrivProtocol::Aes128,
                password,
            )
            .unwrap();
        Client::builder(local, security)
            .request_timeout(WAIT)
            .retry(Retry::none())
    };
    let client_a = make_client(passwords[0])
        .build_with(&endpoints[0])
        .await
        .unwrap();
    let client_b = make_client(passwords[1])
        .build_with(&endpoints[1])
        .await
        .unwrap();

    let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1);
    let send_a = client_a.send_inform(&trap_oid, 1, vec![]);
    let send_b = client_b.send_inform(&trap_oid, 2, vec![]);
    tokio::pin!(send_a, send_b);

    let endpoint = EndpointId::new();
    let limits = ProcessingLimits::UDP;
    let mut buffer = vec![0; limits.receive().accepted()];
    let mut pending = [None, None];
    while pending.iter().any(Option::is_none) {
        let (len, peer) = tokio::select! {
            result = &mut send_a => panic!("tenant A completed before persistence: {result:?}"),
            result = &mut send_b => panic!("tenant B completed before persistence: {result:?}"),
            packet = timeout(WAIT, socket.recv_from(&mut buffer)) => packet.unwrap().unwrap(),
        };
        let tenant = endpoints
            .iter()
            .position(|endpoint| endpoint.local_addr() == peer)
            .unwrap();
        let info = ReceivedMessageInfo::udp(endpoint, local, peer, None, Instant::now(), len);
        let packet = ReceivedPacket::new(Bytes::copy_from_slice(&buffer[..len]), info);
        let received = ProcessingInput::new(packet, limits).unwrap();
        let processor = &processors[tenant];
        match processor.process(received).unwrap() {
            NotificationProcessResult::UsmFailed {
                failure: UsmFailure::UnknownEngineIds | UsmFailure::NotInTimeWindows,
                report: Some(report),
            } => {
                socket.send_to(&report, peer).await.unwrap();
            }
            NotificationProcessResult::Accepted(event) => {
                assert_eq!(event.receive_info, info);
                assert!(
                    matches!(&event.notification, Notification::InformV3 { username, uptime, security_level: SecurityLevel::AuthPriv, .. }
                    if username.as_ref() == USER.as_bytes() && *uptime == tenant as u32 + 1)
                );
                assert!(pending[tenant].is_none());
                pending[tenant] = Some(event);
            }
            other => panic!("unexpected notification result: {other:?}"),
        }
    }
    assert!(futures::poll!(&mut send_a).is_pending());
    assert!(futures::poll!(&mut send_b).is_pending());
    let mut stored = tempfile::NamedTempFile::new().unwrap();
    for event in pending.iter().flatten() {
        writeln!(stored, "{:?}", event.notification).unwrap();
    }
    stored.as_file().sync_all().unwrap();

    for (context, event) in contexts.into_iter().zip(pending.into_iter().flatten()) {
        context.replace_users([]).unwrap();
        let peer = event.receive_info.peer_addr();
        let bytes = ordinary_bytes(*event);
        socket.send_to(&bytes, peer).await.unwrap();
    }
    let (a, b) = timeout(WAIT, async { tokio::join!(send_a, send_b) })
        .await
        .unwrap();
    a.unwrap();
    b.unwrap();
    assert_eq!(engine.usm_stats().unknown_engine_ids, 2);
}
