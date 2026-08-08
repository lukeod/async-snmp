//! Integration tests for notification sending (trap/inform).

#![cfg(feature = "agent")]

use async_snmp::agent::{Agent, SinkSkipReason, SinkStatus};
use async_snmp::message::CommunityMessage;
use async_snmp::notification::{Notification, NotificationReceiver, NotificationVarbindValidation};
use async_snmp::v3::{AuthProtocol, AuthoritativeEngine, PrivProtocol};
use async_snmp::varbind::VarBind;
use async_snmp::{Auth, Client, Pdu, PduType, Retry, Value, oid};
use bytes::Bytes;
use std::time::Duration;
use tokio::net::UdpSocket;

fn test_authoritative_engine(engine_id: Vec<u8>) -> AuthoritativeEngine {
    AuthoritativeEngine::install(engine_id, |_| Ok::<(), std::convert::Infallible>(())).unwrap()
}

// ============================================================================
// PDU constructor unit tests
// ============================================================================

#[test]
fn pdu_trap_v2_has_correct_varbind_prefix() {
    let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1); // coldStart
    let extra = vec![VarBind::new(
        oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
        Value::from("test"),
    )];

    let pdu = Pdu::trap_v2(1, 12345, &trap_oid, extra);

    assert_eq!(pdu.pdu_type, async_snmp::PduType::TrapV2);
    assert_eq!(pdu.request_id, 1);
    assert_eq!(pdu.error_status, 0);
    assert_eq!(pdu.error_index, 0);
    assert_eq!(pdu.varbinds.len(), 3);

    // First varbind: sysUpTime.0
    assert_eq!(pdu.varbinds[0].oid, oid!(1, 3, 6, 1, 2, 1, 1, 3, 0));
    assert_eq!(pdu.varbinds[0].value, Value::TimeTicks(12345));

    // Second varbind: snmpTrapOID.0
    assert_eq!(pdu.varbinds[1].oid, oid!(1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0));
    assert_eq!(
        pdu.varbinds[1].value,
        Value::ObjectIdentifier(trap_oid.clone())
    );

    // Third varbind: caller-provided
    assert_eq!(pdu.varbinds[2].oid, oid!(1, 3, 6, 1, 2, 1, 1, 1, 0));
}

#[test]
fn pdu_inform_request_has_correct_varbind_prefix() {
    let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 3); // linkDown
    let pdu = Pdu::inform_request(42, 99999, &trap_oid, vec![]);

    assert_eq!(pdu.pdu_type, async_snmp::PduType::InformRequest);
    assert_eq!(pdu.request_id, 42);
    assert_eq!(pdu.varbinds.len(), 2);

    // sysUpTime.0
    assert_eq!(pdu.varbinds[0].value, Value::TimeTicks(99999));
    // snmpTrapOID.0
    assert_eq!(
        pdu.varbinds[1].value,
        Value::ObjectIdentifier(trap_oid.clone())
    );
}

#[test]
fn pdu_trap_v2_empty_varbinds() {
    let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 2); // warmStart
    let pdu = Pdu::trap_v2(1, 0, &trap_oid, vec![]);
    assert_eq!(pdu.varbinds.len(), 2);
}

fn encode_raw_v2c_notification(
    pdu_type: PduType,
    request_id: i32,
    varbinds: Vec<VarBind>,
) -> Bytes {
    CommunityMessage::v2c(
        "public",
        Pdu {
            pdu_type,
            request_id,
            error_status: 0,
            error_index: 0,
            varbinds,
        },
    )
    .unwrap()
    .encode()
    .unwrap()
}

fn nonstandard_name_varbinds(uptime: u32) -> Vec<VarBind> {
    vec![
        VarBind::new(oid!(1, 2, 3, 4), Value::TimeTicks(uptime)),
        VarBind::new(
            oid!(1, 2, 3, 5),
            Value::ObjectIdentifier(oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 3)),
        ),
    ]
}

fn valid_sentinel_trap(request_id: i32) -> Bytes {
    CommunityMessage::v2c(
        "public",
        Pdu::trap_v2(request_id, 777, &oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1), vec![]),
    )
    .unwrap()
    .encode()
    .unwrap()
}

async fn assert_sentinel_received(
    handle: tokio::task::JoinHandle<(Notification, std::net::SocketAddr)>,
) {
    let (notification, _) = handle.await.unwrap();
    assert!(matches!(
        notification,
        Notification::TrapV2c {
            uptime: 777,
            request_id: 999,
            ..
        }
    ));
}

#[tokio::test]
async fn notification_varbind_validation_controls_trap_delivery() {
    let tolerant = NotificationReceiver::bind("127.0.0.1:0").await.unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let malformed =
        encode_raw_v2c_notification(PduType::TrapV2, 41, nonstandard_name_varbinds(1234));
    sender
        .send_to(&malformed, tolerant.local_addr())
        .await
        .unwrap();

    let (notification, _) = tokio::time::timeout(Duration::from_secs(5), tolerant.recv())
        .await
        .expect("timeout waiting for tolerant trap")
        .unwrap();
    assert!(matches!(
        notification,
        Notification::TrapV2c {
            uptime: 1234,
            request_id: 41,
            ..
        }
    ));

    let strict = NotificationReceiver::builder()
        .bind("127.0.0.1:0")
        .varbind_validation(NotificationVarbindValidation::Strict)
        .build()
        .await
        .unwrap();
    let strict_addr = strict.local_addr();
    let mut recv_handle = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(5), strict.recv())
            .await
            .expect("timeout waiting for sentinel trap")
            .unwrap()
    });
    sender.send_to(&malformed, strict_addr).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(300), &mut recv_handle)
            .await
            .is_err(),
        "strict receiver returned malformed-name Trap"
    );
    sender
        .send_to(&valid_sentinel_trap(999), strict_addr)
        .await
        .unwrap();
    assert_sentinel_received(recv_handle).await;
}

#[tokio::test]
async fn notification_varbind_validation_controls_inform_acknowledgement() {
    let tolerant = NotificationReceiver::bind("127.0.0.1:0").await.unwrap();
    let tolerant_addr = tolerant.local_addr();
    let recv_handle = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(5), tolerant.recv())
            .await
            .expect("timeout waiting for tolerant inform")
            .unwrap()
    });
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let malformed =
        encode_raw_v2c_notification(PduType::InformRequest, 42, nonstandard_name_varbinds(2345));
    sender.send_to(&malformed, tolerant_addr).await.unwrap();

    let mut response = [0u8; 2048];
    let (len, _) = tokio::time::timeout(Duration::from_secs(5), sender.recv_from(&mut response))
        .await
        .expect("timeout waiting for tolerant Inform acknowledgement")
        .unwrap();
    let response_msg = CommunityMessage::decode(Bytes::copy_from_slice(&response[..len])).unwrap();
    let response_pdu = response_msg.into_pdu().unwrap();
    assert_eq!(response_pdu.pdu_type, PduType::Response);
    assert_eq!(response_pdu.request_id, 42);
    let (notification, _) = recv_handle.await.unwrap();
    assert!(matches!(
        notification,
        Notification::InformV2c {
            uptime: 2345,
            request_id: 42,
            ..
        }
    ));

    let strict = NotificationReceiver::builder()
        .bind("127.0.0.1:0")
        .varbind_validation(NotificationVarbindValidation::Strict)
        .build()
        .await
        .unwrap();
    let strict_addr = strict.local_addr();
    let recv_handle = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(5), strict.recv())
            .await
            .expect("timeout waiting for sentinel trap")
            .unwrap()
    });
    sender.send_to(&malformed, strict_addr).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(300), sender.recv_from(&mut response))
            .await
            .is_err(),
        "strict receiver acknowledged malformed-name Inform"
    );
    sender
        .send_to(&valid_sentinel_trap(999), strict_addr)
        .await
        .unwrap();
    assert_sentinel_received(recv_handle).await;
}

#[tokio::test]
async fn notification_varbind_validation_rejects_unusable_prefixes_without_acknowledgement() {
    for policy in [
        NotificationVarbindValidation::Tolerant,
        NotificationVarbindValidation::Strict,
    ] {
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .varbind_validation(policy)
            .build()
            .await
            .unwrap();
        let receiver_addr = receiver.local_addr();
        let recv_handle = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(5), receiver.recv())
                .await
                .expect("timeout waiting for sentinel trap")
                .unwrap()
        });
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let unusable_prefixes = [
            vec![],
            vec![VarBind::new(
                oid!(1, 3, 6, 1, 2, 1, 1, 3, 0),
                Value::TimeTicks(1234),
            )],
            vec![
                VarBind::new(oid!(1, 3, 6, 1, 2, 1, 1, 3, 0), Value::Integer(1234)),
                VarBind::new(
                    oid!(1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0),
                    Value::ObjectIdentifier(oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 3)),
                ),
            ],
            vec![
                VarBind::new(oid!(1, 3, 6, 1, 2, 1, 1, 3, 0), Value::TimeTicks(1234)),
                VarBind::new(oid!(1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0), Value::Integer(3)),
            ],
        ];
        let mut response = [0u8; 2048];
        for (offset, varbinds) in unusable_prefixes.into_iter().enumerate() {
            let malformed = encode_raw_v2c_notification(
                PduType::InformRequest,
                43 + i32::try_from(offset).unwrap(),
                varbinds,
            );
            sender.send_to(&malformed, receiver_addr).await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(300), sender.recv_from(&mut response))
                    .await
                    .is_err(),
                "{policy:?} receiver acknowledged unusable-prefix Inform"
            );
        }
        sender
            .send_to(&valid_sentinel_trap(999), receiver_addr)
            .await
            .unwrap();
        assert_sentinel_received(recv_handle).await;
    }
}

// ============================================================================
// V2c trap send/receive integration test
// ============================================================================

#[tokio::test]
async fn v2c_trap_send_receive() {
    let receiver = NotificationReceiver::bind("127.0.0.1:0").await.unwrap();
    let recv_addr = receiver.local_addr();

    let client = Client::builder(recv_addr.to_string(), Auth::v2c("public"))
        .connect()
        .await
        .unwrap();

    let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1); // coldStart
    let extra = vec![VarBind::new(
        oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
        Value::from("test agent"),
    )];

    client.send_trap(&trap_oid, 12345, extra).await.unwrap();

    let (notification, _source) = tokio::time::timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("timeout waiting for trap")
        .unwrap();

    match notification {
        Notification::TrapV2c {
            community,
            uptime,
            trap_oid: received_oid,
            varbinds,
            ..
        } => {
            assert_eq!(community.as_ref(), b"public");
            assert_eq!(uptime, 12345);
            assert_eq!(received_oid, trap_oid);
            assert_eq!(varbinds.len(), 1);
            assert_eq!(varbinds[0].value.as_str(), Some("test agent"));
        }
        other => panic!("expected TrapV2c, got {other:?}"),
    }
}

// ============================================================================
// V2c inform send/receive integration test
// ============================================================================

#[tokio::test]
async fn v2c_inform_send_receive() {
    let receiver = NotificationReceiver::bind("127.0.0.1:0").await.unwrap();
    let recv_addr = receiver.local_addr();

    // Spawn receiver in background (it auto-responds to informs)
    let recv_handle = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(5), receiver.recv())
            .await
            .expect("timeout waiting for inform")
            .unwrap()
    });

    let client = Client::builder(recv_addr.to_string(), Auth::v2c("public"))
        .connect()
        .await
        .unwrap();

    let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 3); // linkDown

    // send_inform waits for acknowledgement
    client.send_inform(&trap_oid, 5000, vec![]).await.unwrap();

    let (notification, _source) = recv_handle.await.unwrap();

    match notification {
        Notification::InformV2c {
            community,
            uptime,
            trap_oid: received_oid,
            varbinds,
            ..
        } => {
            assert_eq!(community.as_ref(), b"public");
            assert_eq!(uptime, 5000);
            assert_eq!(received_oid, trap_oid);
            assert_eq!(varbinds.len(), 0);
        }
        other => panic!("expected InformV2c, got {other:?}"),
    }
}

// ============================================================================
// V3 trap send/receive integration test
// ============================================================================

#[tokio::test]
async fn v3_trap_send_receive() {
    // For V3 traps, the sender is the authoritative engine (RFC 3412 Section 6.4).
    // The receiver must be configured with the sender's engine ID so it can
    // verify the authentication.
    let shared_engine_id = b"test-trap-sender-engine".to_vec();
    let shared_engine = test_authoritative_engine(shared_engine_id);

    let receiver = NotificationReceiver::builder()
        .bind("127.0.0.1:0")
        .authoritative_engine(shared_engine.clone())
        .usm_user("trapuser", |u| {
            u.auth(AuthProtocol::Sha256, b"authpass12345678")
        })
        .build()
        .await
        .unwrap();
    let recv_addr = receiver.local_addr();

    let client = Client::builder(
        recv_addr.to_string(),
        Auth::usm("trapuser").auth(AuthProtocol::Sha256, "authpass12345678"),
    )
    .local_authoritative_engine(shared_engine)
    .connect()
    .await
    .unwrap();

    let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 2); // warmStart

    client.send_trap(&trap_oid, 99, vec![]).await.unwrap();

    let (notification, _source) = tokio::time::timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("timeout waiting for v3 trap")
        .unwrap();

    match notification {
        Notification::TrapV3 {
            username,
            uptime,
            trap_oid: received_oid,
            ..
        } => {
            assert_eq!(username.as_ref(), b"trapuser");
            assert_eq!(uptime, 99);
            assert_eq!(received_oid, trap_oid);
        }
        other => panic!("expected TrapV3, got {other:?}"),
    }
}

// ============================================================================
// V3 inform send/receive integration test
// ============================================================================

#[tokio::test]
async fn v3_inform_send_receive() {
    let engine = test_authoritative_engine(b"inform-receiver-engine".to_vec());
    let receiver = NotificationReceiver::builder()
        .bind("127.0.0.1:0")
        .authoritative_engine(engine)
        .usm_user("informuser", |u| {
            u.auth_priv(
                AuthProtocol::Sha256,
                b"authpass12345678",
                PrivProtocol::Aes128,
                b"privpass12345678",
            )
        })
        .build()
        .await
        .unwrap();
    let recv_addr = receiver.local_addr();

    let recv_handle = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(5), receiver.recv())
            .await
            .expect("timeout waiting for v3 inform")
            .unwrap()
    });

    let client = Client::builder(
        recv_addr.to_string(),
        Auth::usm("informuser").auth_priv(
            AuthProtocol::Sha256,
            "authpass12345678",
            PrivProtocol::Aes128,
            "privpass12345678",
        ),
    )
    .connect()
    .await
    .unwrap();

    let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 4); // linkUp

    client.send_inform(&trap_oid, 7777, vec![]).await.unwrap();

    let (notification, _source) = recv_handle.await.unwrap();

    match notification {
        Notification::InformV3 {
            username,
            uptime,
            trap_oid: received_oid,
            ..
        } => {
            assert_eq!(username.as_ref(), b"informuser");
            assert_eq!(uptime, 7777);
            assert_eq!(received_oid, trap_oid);
        }
        other => panic!("expected InformV3, got {other:?}"),
    }
}

// ============================================================================
// Error cases
// ============================================================================

// ============================================================================
// V1 trap send/receive integration test
// ============================================================================

#[tokio::test]
async fn v1_trap_send_receive() {
    use async_snmp::pdu::GenericTrap;

    let receiver = NotificationReceiver::bind("127.0.0.1:0").await.unwrap();
    let recv_addr = receiver.local_addr();

    let client = Client::builder(recv_addr.to_string(), Auth::v1("public"))
        .connect()
        .await
        .unwrap();

    // send_trap auto-converts the v2 trap_oid to v1 fields
    let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 3); // linkDown
    client.send_trap(&trap_oid, 5000, vec![]).await.unwrap();

    let (notification, _source) = tokio::time::timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("timeout waiting for v1 trap")
        .unwrap();

    match notification {
        Notification::TrapV1 { community, trap } => {
            assert_eq!(community.as_ref(), b"public");
            assert_eq!(trap.generic_trap, GenericTrap::LinkDown);
            assert_eq!(trap.time_stamp, 5000);
        }
        other => panic!("expected TrapV1, got {other:?}"),
    }
}

#[tokio::test]
async fn v1_trap_send_v1_trap_explicit() {
    use async_snmp::pdu::{GenericTrap, TrapV1Pdu};

    let receiver = NotificationReceiver::bind("127.0.0.1:0").await.unwrap();
    let recv_addr = receiver.local_addr();

    let client = Client::builder(recv_addr.to_string(), Auth::v1("public"))
        .connect()
        .await
        .unwrap();

    let trap = TrapV1Pdu::new(
        oid!(1, 3, 6, 1, 4, 1, 9999),
        [10, 0, 0, 1],
        GenericTrap::EnterpriseSpecific,
        42,
        99999,
        vec![VarBind::new(
            oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
            Value::from("hello"),
        )],
    );
    client.send_v1_trap(trap).await.unwrap();

    let (notification, _source) = tokio::time::timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("timeout waiting for v1 trap")
        .unwrap();

    match notification {
        Notification::TrapV1 { community, trap } => {
            assert_eq!(community.as_ref(), b"public");
            assert_eq!(trap.enterprise, oid!(1, 3, 6, 1, 4, 1, 9999));
            assert_eq!(trap.agent_addr, [10, 0, 0, 1]);
            assert_eq!(trap.generic_trap, GenericTrap::EnterpriseSpecific);
            assert_eq!(trap.specific_trap, 42);
            assert_eq!(trap.time_stamp, 99999);
            assert_eq!(trap.varbinds.len(), 1);
        }
        other => panic!("expected TrapV1, got {other:?}"),
    }
}

#[tokio::test]
async fn v1_trap_counter64_rejected() {
    // V1 cannot carry Counter64 - send_trap should fail
    let receiver = NotificationReceiver::bind("127.0.0.1:0").await.unwrap();
    let recv_addr = receiver.local_addr();

    let client = Client::builder(recv_addr.to_string(), Auth::v1("public"))
        .connect()
        .await
        .unwrap();

    let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1);
    let result = client
        .send_trap(
            &trap_oid,
            0,
            vec![VarBind::new(
                oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
                Value::Counter64(12345),
            )],
        )
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn v1_inform_returns_error() {
    let receiver = NotificationReceiver::bind("127.0.0.1:0").await.unwrap();
    let recv_addr = receiver.local_addr();

    let client = Client::builder(recv_addr.to_string(), Auth::v1("public"))
        .connect()
        .await
        .unwrap();

    let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1);
    let result = client.send_inform(&trap_oid, 0, vec![]).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn v3_trap_without_local_authoritative_engine_returns_error() {
    let engine = test_authoritative_engine(b"trap-receiver-engine".to_vec());
    let receiver = NotificationReceiver::builder()
        .bind("127.0.0.1:0")
        .authoritative_engine(engine)
        .usm_user("user", |u| {
            u.auth(AuthProtocol::Sha256, b"authpass12345678")
        })
        .build()
        .await
        .unwrap();
    let recv_addr = receiver.local_addr();

    let client = Client::builder(
        recv_addr.to_string(),
        Auth::usm("user").auth(AuthProtocol::Sha256, "authpass12345678"),
    )
    // No local authoritative engine state set.
    .connect()
    .await
    .unwrap();

    let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1);
    let result = client.send_trap(&trap_oid, 0, vec![]).await;
    assert!(result.is_err());
}

// ============================================================================
// Agent trap/inform sending tests
// ============================================================================

#[tokio::test]
async fn agent_v2c_trap_to_sink() {
    let receiver = NotificationReceiver::bind("127.0.0.1:0").await.unwrap();
    let recv_addr = receiver.local_addr();

    let agent = Agent::builder()
        .bind("127.0.0.1:0")
        .community(b"public")
        .trap_sink(recv_addr.to_string(), Auth::v2c("public"))
        .build()
        .await
        .unwrap();

    let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1); // coldStart
    let outcome = agent.send_trap(&trap_oid, 500, vec![]).await;
    assert!(outcome.all_succeeded());
    assert!(matches!(&outcome.sinks()[0].status, SinkStatus::Succeeded));

    let (notification, _source) = tokio::time::timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("timeout waiting for agent trap")
        .unwrap();

    match notification {
        Notification::TrapV2c {
            community,
            uptime,
            trap_oid: received_oid,
            ..
        } => {
            assert_eq!(community.as_ref(), b"public");
            assert_eq!(uptime, 500);
            assert_eq!(received_oid, trap_oid);
        }
        other => panic!("expected TrapV2c, got {other:?}"),
    }
}

#[tokio::test]
async fn agent_v2c_inform_to_sink() {
    let receiver = NotificationReceiver::bind("127.0.0.1:0").await.unwrap();
    let recv_addr = receiver.local_addr();

    let agent = Agent::builder()
        .bind("127.0.0.1:0")
        .community(b"public")
        .trap_sink(recv_addr.to_string(), Auth::v2c("public"))
        .build()
        .await
        .unwrap();

    let recv_handle = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(5), receiver.recv())
            .await
            .expect("timeout")
            .unwrap()
    });

    let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 2); // warmStart
    let outcome = agent.send_inform(&trap_oid, 1000, vec![]).await;
    assert!(outcome.all_succeeded());
    assert!(matches!(&outcome.sinks()[0].status, SinkStatus::Succeeded));

    let (notification, _source) = recv_handle.await.unwrap();

    match notification {
        Notification::InformV2c {
            uptime,
            trap_oid: received_oid,
            ..
        } => {
            assert_eq!(uptime, 1000);
            assert_eq!(received_oid, trap_oid);
        }
        other => panic!("expected InformV2c, got {other:?}"),
    }
}

#[tokio::test]
async fn agent_v3_trap_to_sink() {
    // Agent sends V3 trap using its own engine_id
    let engine_id = b"agent-trap-test-engine".to_vec();
    let engine = test_authoritative_engine(engine_id);

    let receiver = NotificationReceiver::builder()
        .bind("127.0.0.1:0")
        .authoritative_engine(engine.clone())
        .usm_user("trapuser", |u| {
            u.auth(AuthProtocol::Sha256, b"authpass12345678")
        })
        .build()
        .await
        .unwrap();
    let recv_addr = receiver.local_addr();

    let agent = Agent::builder()
        .bind("127.0.0.1:0")
        .community(b"public")
        .authoritative_engine(engine)
        .usm_user("trapuser", |u| {
            u.auth(AuthProtocol::Sha256, b"authpass12345678")
        })
        .trap_sink(
            recv_addr.to_string(),
            Auth::usm("trapuser").auth(AuthProtocol::Sha256, "authpass12345678"),
        )
        .build()
        .await
        .unwrap();

    let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 3); // linkDown
    let outcome = agent.send_trap(&trap_oid, 9999, vec![]).await;
    assert!(outcome.all_succeeded());
    assert!(matches!(&outcome.sinks()[0].status, SinkStatus::Succeeded));

    let (notification, _source) = tokio::time::timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("timeout waiting for v3 agent trap")
        .unwrap();

    match notification {
        Notification::TrapV3 {
            username,
            uptime,
            trap_oid: received_oid,
            ..
        } => {
            assert_eq!(username.as_ref(), b"trapuser");
            assert_eq!(uptime, 9999);
            assert_eq!(received_oid, trap_oid);
        }
        other => panic!("expected TrapV3, got {other:?}"),
    }
}

#[tokio::test]
async fn agent_multiple_sinks() {
    let recv1 = NotificationReceiver::bind("127.0.0.1:0").await.unwrap();
    let recv2 = NotificationReceiver::bind("127.0.0.1:0").await.unwrap();
    let addr1 = recv1.local_addr();
    let addr2 = recv2.local_addr();

    let agent = Agent::builder()
        .bind("127.0.0.1:0")
        .community(b"public")
        .trap_sink(addr1.to_string(), Auth::v2c("public"))
        .trap_sink(addr2.to_string(), Auth::v2c("trap-community"))
        .build()
        .await
        .unwrap();

    let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1);
    let outcome = agent.send_trap(&trap_oid, 42, vec![]).await;
    assert!(outcome.all_succeeded());
    assert_eq!(outcome.len(), 2);

    // Both receivers should get the trap
    let (n1, _) = tokio::time::timeout(Duration::from_secs(5), recv1.recv())
        .await
        .expect("timeout on receiver 1")
        .unwrap();
    let (n2, _) = tokio::time::timeout(Duration::from_secs(5), recv2.recv())
        .await
        .expect("timeout on receiver 2")
        .unwrap();

    assert_eq!(n1.uptime(), 42);
    assert_eq!(n2.uptime(), 42);

    // Verify different communities
    match n1 {
        Notification::TrapV2c { community, .. } => {
            assert_eq!(community.as_ref(), b"public");
        }
        other => panic!("expected TrapV2c, got {other:?}"),
    }
    match n2 {
        Notification::TrapV2c { community, .. } => {
            assert_eq!(community.as_ref(), b"trap-community");
        }
        other => panic!("expected TrapV2c, got {other:?}"),
    }
}

#[tokio::test]
async fn agent_v1_trap_to_sink() {
    use async_snmp::pdu::GenericTrap;

    let receiver = NotificationReceiver::bind("127.0.0.1:0").await.unwrap();
    let recv_addr = receiver.local_addr();

    let agent = Agent::builder()
        .bind("127.0.0.1:0")
        .community(b"public")
        .trap_sink(recv_addr.to_string(), Auth::v1("public"))
        .build()
        .await
        .unwrap();

    let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 2); // warmStart
    let outcome = agent.send_trap(&trap_oid, 1000, vec![]).await;
    assert!(outcome.all_succeeded());
    assert!(matches!(&outcome.sinks()[0].status, SinkStatus::Succeeded));

    let (notification, _source) = tokio::time::timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("timeout waiting for v1 agent trap")
        .unwrap();

    match notification {
        Notification::TrapV1 { community, trap } => {
            assert_eq!(community.as_ref(), b"public");
            assert_eq!(trap.generic_trap, GenericTrap::WarmStart);
            assert_eq!(trap.time_stamp, 1000);
        }
        other => panic!("expected TrapV1, got {other:?}"),
    }
}

#[tokio::test]
async fn agent_mixed_v1_v2c_sinks() {
    use async_snmp::pdu::GenericTrap;

    let recv_v1 = NotificationReceiver::bind("127.0.0.1:0").await.unwrap();
    let recv_v2 = NotificationReceiver::bind("127.0.0.1:0").await.unwrap();
    let addr_v1 = recv_v1.local_addr();
    let addr_v2 = recv_v2.local_addr();

    let agent = Agent::builder()
        .bind("127.0.0.1:0")
        .community(b"public")
        .trap_sink(addr_v1.to_string(), Auth::v1("v1comm"))
        .trap_sink(addr_v2.to_string(), Auth::v2c("v2comm"))
        .build()
        .await
        .unwrap();

    let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 4); // linkUp
    let outcome = agent.send_trap(&trap_oid, 777, vec![]).await;
    assert!(outcome.all_succeeded());
    assert_eq!(outcome.len(), 2);

    let (n1, _) = tokio::time::timeout(Duration::from_secs(5), recv_v1.recv())
        .await
        .expect("timeout on v1 receiver")
        .unwrap();
    let (n2, _) = tokio::time::timeout(Duration::from_secs(5), recv_v2.recv())
        .await
        .expect("timeout on v2 receiver")
        .unwrap();

    // V1 sink gets a TrapV1
    match n1 {
        Notification::TrapV1 { community, trap } => {
            assert_eq!(community.as_ref(), b"v1comm");
            assert_eq!(trap.generic_trap, GenericTrap::LinkUp);
            assert_eq!(trap.time_stamp, 777);
        }
        other => panic!("expected TrapV1, got {other:?}"),
    }

    // V2c sink gets a TrapV2c
    match n2 {
        Notification::TrapV2c {
            community,
            uptime,
            trap_oid: received_oid,
            ..
        } => {
            assert_eq!(community.as_ref(), b"v2comm");
            assert_eq!(uptime, 777);
            assert_eq!(received_oid, trap_oid);
        }
        other => panic!("expected TrapV2c, got {other:?}"),
    }
}

#[tokio::test]
async fn agent_no_sinks_is_noop() {
    let agent = Agent::builder()
        .bind("127.0.0.1:0")
        .community(b"public")
        // No trap sinks configured
        .build()
        .await
        .unwrap();

    let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1);
    // Primary methods report an empty (all-succeeded) outcome for no sinks.
    let trap_outcome = agent.send_trap(&trap_oid, 0, vec![]).await;
    assert!(trap_outcome.is_empty());
    assert!(trap_outcome.all_succeeded());

    let inform_outcome = agent.send_inform(&trap_oid, 0, vec![]).await;
    assert!(inform_outcome.is_empty());
    assert!(inform_outcome.all_succeeded());
}

#[tokio::test]
async fn agent_inform_reports_failing_sink() {
    // Bind a socket to reserve a port, then drop it so nothing listens there.
    // The inform to this dead destination times out and must be reported as a
    // failure in the per-sink outcome rather than silently discarded.
    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = probe.local_addr().unwrap();
    drop(probe);

    let agent = Agent::builder()
        .bind("127.0.0.1:0")
        .community(b"public")
        .trap_sink(dead_addr.to_string(), Auth::v2c("public"))
        .inform_timeout(Duration::from_millis(50))
        .inform_retry(Retry::none())
        .build()
        .await
        .unwrap();

    let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 2);
    let outcome = agent.send_inform(&trap_oid, 0, vec![]).await;

    assert_eq!(outcome.len(), 1);
    assert!(!outcome.all_succeeded());
    let failures: Vec<_> = outcome.failures().collect();
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].dest, dead_addr);
    assert!(matches!(&failures[0].status, SinkStatus::Failed(_)));
}

#[tokio::test]
async fn agent_trap_reports_total_conversion_failure() {
    let receiver = NotificationReceiver::bind("127.0.0.1:0").await.unwrap();
    let sink_addr = receiver.local_addr();
    let agent = Agent::builder()
        .bind("127.0.0.1:0")
        .community(b"public")
        .trap_sink(sink_addr.to_string(), Auth::v1("public"))
        .build()
        .await
        .unwrap();

    let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1);
    let outcome = agent
        .send_trap(
            &trap_oid,
            0,
            vec![VarBind::new(
                oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
                Value::Counter64(12345),
            )],
        )
        .await;

    assert_eq!(outcome.len(), 1);
    assert!(!outcome.all_succeeded());
    assert_eq!(outcome.sinks()[0].dest, sink_addr);
    assert!(matches!(
        &outcome.sinks()[0].status,
        SinkStatus::Failed(error)
            if matches!(&**error, async_snmp::Error::Config(_))
    ));
}

#[tokio::test]
async fn agent_trap_reports_ordered_partial_success() {
    let v1_receiver = NotificationReceiver::bind("127.0.0.1:0").await.unwrap();
    let v2_receiver = NotificationReceiver::bind("127.0.0.1:0").await.unwrap();
    let v1_addr = v1_receiver.local_addr();
    let v2_addr = v2_receiver.local_addr();
    let agent = Agent::builder()
        .bind("127.0.0.1:0")
        .community(b"public")
        .trap_sink(v1_addr.to_string(), Auth::v1("public"))
        .trap_sink(v2_addr.to_string(), Auth::v2c("public"))
        .build()
        .await
        .unwrap();

    let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1);
    let outcome = agent
        .send_trap(
            &trap_oid,
            7,
            vec![VarBind::new(
                oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
                Value::Counter64(12345),
            )],
        )
        .await;

    assert_eq!(outcome.len(), 2);
    assert!(!outcome.all_succeeded());
    assert_eq!(outcome.sinks()[0].dest, v1_addr);
    assert!(matches!(&outcome.sinks()[0].status, SinkStatus::Failed(_)));
    assert_eq!(outcome.sinks()[1].dest, v2_addr);
    assert!(matches!(&outcome.sinks()[1].status, SinkStatus::Succeeded));

    let (notification, _) = tokio::time::timeout(Duration::from_secs(5), v2_receiver.recv())
        .await
        .expect("timeout waiting for successful partial trap")
        .unwrap();
    assert_eq!(notification.uptime(), 7);
    assert!(matches!(notification, Notification::TrapV2c { .. }));
}

#[tokio::test]
async fn agent_v1_inform_is_explicitly_skipped() {
    let receiver = NotificationReceiver::bind("127.0.0.1:0").await.unwrap();
    let sink_addr = receiver.local_addr();
    let agent = Agent::builder()
        .bind("127.0.0.1:0")
        .community(b"public")
        .trap_sink(sink_addr.to_string(), Auth::v1("public"))
        .build()
        .await
        .unwrap();

    let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 2);
    let outcome = agent.send_inform(&trap_oid, 0, vec![]).await;

    assert_eq!(outcome.len(), 1);
    assert!(!outcome.is_empty());
    assert!(!outcome.all_succeeded());
    assert_eq!(outcome.failures().count(), 0);
    assert_eq!(outcome.skipped().count(), 1);
    assert_eq!(outcome.sinks()[0].dest, sink_addr);
    assert!(matches!(
        &outcome.sinks()[0].status,
        SinkStatus::Skipped(SinkSkipReason::InformUnsupportedForV1)
    ));
}

#[tokio::test]
async fn agent_best_effort_helpers_complete_after_failure_and_skip() {
    let receiver = NotificationReceiver::bind("127.0.0.1:0").await.unwrap();
    let agent = Agent::builder()
        .bind("127.0.0.1:0")
        .community(b"public")
        .trap_sink(receiver.local_addr().to_string(), Auth::v1("public"))
        .build()
        .await
        .unwrap();

    let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1);
    agent
        .send_trap_best_effort(
            &trap_oid,
            0,
            vec![VarBind::new(
                oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
                Value::Counter64(12345),
            )],
        )
        .await;
    agent.send_inform_best_effort(&trap_oid, 0, vec![]).await;
}
