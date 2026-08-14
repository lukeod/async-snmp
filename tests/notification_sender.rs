//! Integration tests for notification sending (trap/inform).

#![cfg(feature = "agent")]

#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
mod common;

use async_snmp::agent::{Agent, SinkSkipReason, SinkStatus};
use async_snmp::message::CommunityMessage;
use async_snmp::notification::{
    Notification, NotificationAcceptance, NotificationReceiver, NotificationVarbindValidation,
    ReceivedNotification,
};
#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
use async_snmp::v3::{AuthProtocol, PrivProtocol};
use async_snmp::varbind::VarBind;
use async_snmp::{
    Auth, AuthoritativeEngine, Client, NotificationPdu, NotificationSinkId, PduType, Retry,
    SecurityLevel, TrapV1Notification, Value, Version, oid,
};
use bytes::Bytes;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;

#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
use common::v3::{ScriptStep, ScriptedV3Peer, TestV3Engine, V3ReplyBuilder};

#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
fn test_authoritative_engine(engine_id: Vec<u8>) -> AuthoritativeEngine {
    AuthoritativeEngine::install(engine_id, |_| Ok::<(), std::convert::Infallible>(())).unwrap()
}

fn no_op_authoritative_engine(engine_id: &[u8]) -> AuthoritativeEngine {
    AuthoritativeEngine::install(engine_id.to_vec(), |_| {
        Ok::<(), std::convert::Infallible>(())
    })
    .unwrap()
}

fn expect_agent_build_error(
    result: async_snmp::Result<Agent>,
    message: &str,
) -> Box<async_snmp::Error> {
    match result {
        Ok(_) => panic!("{message}"),
        Err(error) => error,
    }
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

    let pdu = NotificationPdu::trap_v2(Version::V2c, 1, 12345, &trap_oid, extra).unwrap();
    let pdu = pdu.as_raw();

    assert_eq!(pdu.pdu_type(), async_snmp::PduType::TrapV2);
    assert_eq!(pdu.request_id(), 1);
    assert_eq!(pdu.error_status(), 0);
    assert_eq!(pdu.error_index(), 0);
    assert_eq!(pdu.varbinds().len(), 3);

    // First varbind: sysUpTime.0
    assert_eq!(pdu.varbinds()[0].oid, oid!(1, 3, 6, 1, 2, 1, 1, 3, 0));
    assert_eq!(pdu.varbinds()[0].value, Value::TimeTicks(12345));

    // Second varbind: snmpTrapOID.0
    assert_eq!(pdu.varbinds()[1].oid, oid!(1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0));
    assert_eq!(
        pdu.varbinds()[1].value,
        Value::ObjectIdentifier(trap_oid.clone())
    );

    // Third varbind: caller-provided
    assert_eq!(pdu.varbinds()[2].oid, oid!(1, 3, 6, 1, 2, 1, 1, 1, 0));
}

#[test]
fn pdu_inform_request_has_correct_varbind_prefix() {
    let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 3); // linkDown
    let pdu = NotificationPdu::inform(Version::V2c, 42, 99999, &trap_oid, vec![]).unwrap();
    let pdu = pdu.as_raw();

    assert_eq!(pdu.pdu_type(), async_snmp::PduType::InformRequest);
    assert_eq!(pdu.request_id(), 42);
    assert_eq!(pdu.varbinds().len(), 2);

    // sysUpTime.0
    assert_eq!(pdu.varbinds()[0].value, Value::TimeTicks(99999));
    // snmpTrapOID.0
    assert_eq!(
        pdu.varbinds()[1].value,
        Value::ObjectIdentifier(trap_oid.clone())
    );
}

#[test]
fn pdu_trap_v2_empty_varbinds() {
    let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 2); // warmStart
    let pdu = NotificationPdu::trap_v2(Version::V2c, 1, 0, &trap_oid, vec![]).unwrap();
    assert_eq!(pdu.as_raw().varbinds().len(), 2);
}

fn encode_raw_v2c_notification(
    pdu_type: PduType,
    request_id: i32,
    varbinds: Vec<VarBind>,
) -> Bytes {
    use async_snmp::ber::EncodeBuf;

    let mut buf = EncodeBuf::new();
    buf.push_sequence(|buf| {
        buf.push_constructed(pdu_type.tag(), |buf| {
            buf.push_sequence(|buf| {
                for varbind in varbinds.iter().rev() {
                    varbind.encode(buf)?;
                }
                Ok(())
            })?;
            buf.push_integer(0);
            buf.push_integer(0);
            buf.push_integer(request_id);
            Ok(())
        })?;
        buf.push_octet_string(b"public")?;
        buf.push_integer(Version::V2c.as_i32());
        Ok(())
    })
    .unwrap();
    buf.finish()
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
        NotificationPdu::trap_v2(
            Version::V2c,
            request_id,
            777,
            &oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1),
            vec![],
        )
        .unwrap(),
    )
    .unwrap()
    .encode()
    .unwrap()
}

async fn assert_sentinel_received(handle: tokio::task::JoinHandle<ReceivedNotification>) {
    let notification = handle.await.unwrap().notification;
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

    let notification = tokio::time::timeout(Duration::from_secs(5), tolerant.recv())
        .await
        .expect("timeout waiting for tolerant trap")
        .unwrap()
        .notification;
    assert!(matches!(
        notification,
        Notification::TrapV2c {
            uptime: 1234,
            request_id: 41,
            ..
        }
    ));

    let policy_calls = Arc::new(AtomicU32::new(0));
    let policy_calls_for_receiver = Arc::clone(&policy_calls);
    let strict = NotificationReceiver::builder()
        .bind("127.0.0.1:0")
        .varbind_validation(NotificationVarbindValidation::Strict)
        .acceptance_policy(move |_: &async_snmp::NotificationEnvelope<'_>| {
            policy_calls_for_receiver.fetch_add(1, Ordering::Relaxed);
            NotificationAcceptance::Accept
        })
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
    assert_eq!(policy_calls.load(Ordering::Relaxed), 0);
    sender
        .send_to(&valid_sentinel_trap(999), strict_addr)
        .await
        .unwrap();
    assert_sentinel_received(recv_handle).await;
    assert_eq!(policy_calls.load(Ordering::Relaxed), 1);
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
    let response_msg = CommunityMessage::decode(
        Bytes::copy_from_slice(&response[..len]),
        async_snmp::DecodeConfig::default(),
    )
    .unwrap()
    .value;
    let response_pdu = response_msg.into_pdu().unwrap();
    assert_eq!(response_pdu.pdu_type(), PduType::Response);
    assert_eq!(response_pdu.request_id(), 42);
    let notification = recv_handle.await.unwrap().notification;
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

    let notification = tokio::time::timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("timeout waiting for trap")
        .unwrap()
        .notification;

    match notification {
        Notification::TrapV2c {
            community,
            uptime,
            trap_oid: received_oid,
            varbinds,
            ..
        } => {
            assert!(community.matches(b"public"));
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

    let notification = recv_handle.await.unwrap().notification;

    match notification {
        Notification::InformV2c {
            community,
            uptime,
            trap_oid: received_oid,
            varbinds,
            ..
        } => {
            assert!(community.matches(b"public"));
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

#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
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
        .unwrap()
        .accept_all_notifications()
        .build()
        .await
        .unwrap();
    let recv_addr = receiver.local_addr();

    let client = Client::builder(
        recv_addr.to_string(),
        async_snmp::UsmConfig::new("trapuser")
            .auth(AuthProtocol::Sha256, "authpass12345678")
            .unwrap(),
    )
    .local_authoritative_engine(shared_engine)
    .connect()
    .await
    .unwrap();

    let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 2); // warmStart

    client.send_trap(&trap_oid, 99, vec![]).await.unwrap();

    let notification = tokio::time::timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("timeout waiting for v3 trap")
        .unwrap()
        .notification;

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

#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
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
        .unwrap()
        .accept_all_notifications()
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
        async_snmp::UsmConfig::new("informuser")
            .auth_priv(
                AuthProtocol::Sha256,
                "authpass12345678",
                PrivProtocol::Aes128,
                "privpass12345678",
            )
            .unwrap(),
    )
    .connect()
    .await
    .unwrap();

    let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 4); // linkUp

    client.send_inform(&trap_oid, 7777, vec![]).await.unwrap();

    let notification = recv_handle.await.unwrap().notification;

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

    let notification = tokio::time::timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("timeout waiting for v1 trap")
        .unwrap()
        .notification;

    match notification {
        Notification::TrapV1 {
            community, trap, ..
        } => {
            assert!(community.matches(b"public"));
            assert_eq!(trap.generic_trap(), GenericTrap::LinkDown);
            assert_eq!(trap.time_stamp(), 5000);
        }
        other => panic!("expected TrapV1, got {other:?}"),
    }
}

#[tokio::test]
async fn v1_trap_send_v1_trap_explicit() {
    use async_snmp::pdu::GenericTrap;

    let receiver = NotificationReceiver::bind("127.0.0.1:0").await.unwrap();
    let recv_addr = receiver.local_addr();

    let client = Client::builder(recv_addr.to_string(), Auth::v1("public"))
        .connect()
        .await
        .unwrap();

    let trap = TrapV1Notification::new(
        oid!(1, 3, 6, 1, 4, 1, 9999),
        [10, 0, 0, 1],
        GenericTrap::EnterpriseSpecific,
        42,
        99999,
        vec![VarBind::new(
            oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
            Value::from("hello"),
        )],
    )
    .unwrap();
    client.send_v1_trap(trap).await.unwrap();

    let notification = tokio::time::timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("timeout waiting for v1 trap")
        .unwrap()
        .notification;

    match notification {
        Notification::TrapV1 {
            community, trap, ..
        } => {
            assert!(community.matches(b"public"));
            assert_eq!(trap.enterprise(), &oid!(1, 3, 6, 1, 4, 1, 9999));
            assert_eq!(trap.agent_addr(), [10, 0, 0, 1]);
            assert_eq!(trap.generic_trap(), GenericTrap::EnterpriseSpecific);
            assert_eq!(trap.specific_trap(), 42);
            assert_eq!(trap.time_stamp(), 99999);
            assert_eq!(trap.varbinds().len(), 1);
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
    assert!(matches!(
        *result.expect_err("Counter64 cannot be converted to SNMPv1"),
        async_snmp::Error::InvalidMessage(_)
    ));
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

#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
#[tokio::test]
async fn v3_trap_without_local_authoritative_engine_returns_error() {
    let engine = test_authoritative_engine(b"trap-receiver-engine".to_vec());
    let receiver = NotificationReceiver::builder()
        .bind("127.0.0.1:0")
        .authoritative_engine(engine)
        .usm_user("user", |u| {
            u.auth(AuthProtocol::Sha256, b"authpass12345678")
        })
        .unwrap()
        .accept_all_notifications()
        .build()
        .await
        .unwrap();
    let recv_addr = receiver.local_addr();

    let client = Client::builder(
        recv_addr.to_string(),
        async_snmp::UsmConfig::new("user")
            .auth(AuthProtocol::Sha256, "authpass12345678")
            .unwrap(),
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
        .trap_sink(
            NotificationSinkId::new("v2c").unwrap(),
            recv_addr.to_string(),
            Auth::v2c("public"),
        )
        .allow_all_access()
        .build()
        .await
        .unwrap();

    let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1); // coldStart
    let outcome = agent.send_trap(&trap_oid, 500, vec![]).await;
    assert!(outcome.all_succeeded());
    assert!(matches!(&outcome.sinks()[0].status, SinkStatus::Succeeded));

    let notification = tokio::time::timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("timeout waiting for agent trap")
        .unwrap()
        .notification;

    match notification {
        Notification::TrapV2c {
            community,
            uptime,
            trap_oid: received_oid,
            ..
        } => {
            assert!(community.matches(b"public"));
            assert_eq!(uptime, 500);
            assert_eq!(received_oid, trap_oid);
        }
        other => panic!("expected TrapV2c, got {other:?}"),
    }
}

#[tokio::test]
async fn agent_trap_send_timeout_is_bounded_and_reported() {
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let recv_addr = receiver.local_addr().unwrap();
    let agent = Agent::builder()
        .bind("127.0.0.1:0")
        .community(b"public")
        .trap_sink(
            NotificationSinkId::new("timed").unwrap(),
            recv_addr.to_string(),
            Auth::v2c("public"),
        )
        .trap_send_timeout(Duration::ZERO)
        .allow_all_access()
        .build()
        .await
        .unwrap();

    let outcome = agent
        .send_trap(&oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1), 0, vec![])
        .await;
    assert_eq!(outcome.len(), 1);
    assert!(matches!(
        &outcome.sinks()[0].status,
        SinkStatus::Failed(error)
            if matches!(
                &**error,
                async_snmp::Error::Timeout {
                    target,
                    elapsed: Duration::ZERO,
                    retries: 0,
                } if *target == recv_addr
            )
    ));

    let mut buffer = [0_u8; 1];
    assert_eq!(
        receiver.try_recv_from(&mut buffer).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[tokio::test]
async fn agent_rejects_unrepresentable_trap_send_timeout() {
    let error = expect_agent_build_error(
        Agent::builder()
            .bind("127.0.0.1:0")
            .trap_send_timeout(Duration::MAX)
            .build()
            .await,
        "unrepresentable trap send timeout was accepted",
    );
    assert!(matches!(*error, async_snmp::Error::Config(_)));
}

#[tokio::test]
async fn agent_trap_stream_is_lazy_and_preserves_sink_identity() {
    let receiver = NotificationReceiver::bind("127.0.0.1:0").await.unwrap();
    let recv_addr = receiver.local_addr();
    let agent = Agent::builder()
        .bind("127.0.0.1:0")
        .community(b"public")
        .trap_sink(
            NotificationSinkId::new("lazy").unwrap(),
            recv_addr.to_string(),
            Auth::v2c("public"),
        )
        .allow_all_access()
        .build()
        .await
        .unwrap();

    let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1);
    let mut stream = agent.send_trap_stream(&trap_oid, 321, vec![]);

    assert!(
        tokio::time::timeout(Duration::from_millis(50), receiver.recv())
            .await
            .is_err(),
        "creating the stream sent a trap before it was polled"
    );

    let sink = stream.next().await.expect("configured sink outcome");
    assert_eq!(sink.sink.id().as_bytes(), b"lazy");
    assert_eq!(sink.sink.index(), 0);
    assert_eq!(sink.sink.dest(), recv_addr);
    assert!(matches!(sink.status, SinkStatus::Succeeded));
    assert!(stream.next().await.is_none());

    let notification = tokio::time::timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("timeout waiting for lazily sent trap")
        .unwrap()
        .notification;
    assert_eq!(notification.uptime(), 321);
}

#[tokio::test]
async fn agent_v2c_inform_to_sink() {
    let receiver = NotificationReceiver::bind("127.0.0.1:0").await.unwrap();
    let recv_addr = receiver.local_addr();

    let agent = Agent::builder()
        .bind("127.0.0.1:0")
        .community(b"public")
        .trap_sink(
            NotificationSinkId::new("v2c").unwrap(),
            recv_addr.to_string(),
            Auth::v2c("public"),
        )
        .allow_all_access()
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

    let notification = recv_handle.await.unwrap().notification;

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
async fn agent_inform_sinks_share_source_endpoint() {
    let first_receiver = NotificationReceiver::bind("127.0.0.1:0").await.unwrap();
    let second_receiver = NotificationReceiver::bind("127.0.0.1:0").await.unwrap();
    let first_addr = first_receiver.local_addr();
    let second_addr = second_receiver.local_addr();
    let agent = Agent::builder()
        .bind("127.0.0.1:0")
        .trap_sink(
            NotificationSinkId::new("first").unwrap(),
            first_addr.to_string(),
            Auth::v2c("public"),
        )
        .trap_sink(
            NotificationSinkId::new("second").unwrap(),
            second_addr.to_string(),
            Auth::v2c("private"),
        )
        .allow_all_access()
        .build()
        .await
        .unwrap();
    let first = tokio::spawn(async move { first_receiver.recv().await.unwrap() });
    let second = tokio::spawn(async move { second_receiver.recv().await.unwrap() });

    let outcome = agent
        .send_inform(&oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 2), 1000, vec![])
        .await;
    assert!(outcome.all_succeeded());
    let first_source = first.await.unwrap().source;
    let second_source = second.await.unwrap().source;
    assert_eq!(first_source, second_source);
    assert_ne!(first_source.port(), agent.local_addr().port());
}

#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
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
        .unwrap()
        .accept_all_notifications()
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
        .unwrap()
        .trap_sink(
            NotificationSinkId::new("v3").unwrap(),
            recv_addr.to_string(),
            async_snmp::UsmConfig::new("trapuser")
                .auth(AuthProtocol::Sha256, "authpass12345678")
                .unwrap(),
        )
        .allow_all_access()
        .build()
        .await
        .unwrap();

    let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 3); // linkDown
    let outcome = agent.send_trap(&trap_oid, 9999, vec![]).await;
    assert!(outcome.all_succeeded());
    assert!(matches!(&outcome.sinks()[0].status, SinkStatus::Succeeded));

    let notification = tokio::time::timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("timeout waiting for v3 agent trap")
        .unwrap()
        .notification;

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
        .trap_sink(
            NotificationSinkId::new("first").unwrap(),
            addr1.to_string(),
            Auth::v2c("public"),
        )
        .trap_sink(
            NotificationSinkId::new("second").unwrap(),
            addr2.to_string(),
            Auth::v2c("trap-community"),
        )
        .allow_all_access()
        .build()
        .await
        .unwrap();

    let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1);
    let outcome = agent.send_trap(&trap_oid, 42, vec![]).await;
    assert!(outcome.all_succeeded());
    assert_eq!(outcome.len(), 2);

    // Both receivers should get the trap
    let n1 = tokio::time::timeout(Duration::from_secs(5), recv1.recv())
        .await
        .expect("timeout on receiver 1")
        .unwrap()
        .notification;
    let n2 = tokio::time::timeout(Duration::from_secs(5), recv2.recv())
        .await
        .expect("timeout on receiver 2")
        .unwrap()
        .notification;

    assert_eq!(n1.uptime(), 42);
    assert_eq!(n2.uptime(), 42);

    // Verify different communities
    match n1 {
        Notification::TrapV2c { community, .. } => {
            assert!(community.matches(b"public"));
        }
        other => panic!("expected TrapV2c, got {other:?}"),
    }
    match n2 {
        Notification::TrapV2c { community, .. } => {
            assert!(community.matches(b"trap-community"));
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
        .trap_sink(
            NotificationSinkId::new("v1").unwrap(),
            recv_addr.to_string(),
            Auth::v1("public"),
        )
        .allow_all_access()
        .build()
        .await
        .unwrap();

    let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 2); // warmStart
    let outcome = agent.send_trap(&trap_oid, 1000, vec![]).await;
    assert!(outcome.all_succeeded());
    assert!(matches!(&outcome.sinks()[0].status, SinkStatus::Succeeded));

    let notification = tokio::time::timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("timeout waiting for v1 agent trap")
        .unwrap()
        .notification;

    match notification {
        Notification::TrapV1 {
            community, trap, ..
        } => {
            assert!(community.matches(b"public"));
            assert_eq!(trap.generic_trap(), GenericTrap::WarmStart);
            assert_eq!(trap.time_stamp(), 1000);
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
        .trap_sink(
            NotificationSinkId::new("v1").unwrap(),
            addr_v1.to_string(),
            Auth::v1("v1comm"),
        )
        .trap_sink(
            NotificationSinkId::new("v2c").unwrap(),
            addr_v2.to_string(),
            Auth::v2c("v2comm"),
        )
        .allow_all_access()
        .build()
        .await
        .unwrap();

    let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 4); // linkUp
    let outcome = agent.send_trap(&trap_oid, 777, vec![]).await;
    assert!(outcome.all_succeeded());
    assert_eq!(outcome.len(), 2);

    let n1 = tokio::time::timeout(Duration::from_secs(5), recv_v1.recv())
        .await
        .expect("timeout on v1 receiver")
        .unwrap()
        .notification;
    let n2 = tokio::time::timeout(Duration::from_secs(5), recv_v2.recv())
        .await
        .expect("timeout on v2 receiver")
        .unwrap()
        .notification;

    // V1 sink gets a TrapV1
    match n1 {
        Notification::TrapV1 {
            community, trap, ..
        } => {
            assert!(community.matches(b"v1comm"));
            assert_eq!(trap.generic_trap(), GenericTrap::LinkUp);
            assert_eq!(trap.time_stamp(), 777);
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
            assert!(community.matches(b"v2comm"));
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
        .allow_all_access()
        .build()
        .await
        .unwrap();

    let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1);
    let mut trap_stream = agent.send_trap_stream(&trap_oid, 0, vec![]);
    fn assert_send_unpin<T: Send + Unpin>(_: &T) {}
    assert_send_unpin(&trap_stream);
    assert!(trap_stream.next().await.is_none());
    assert!(trap_stream.next().await.is_none());

    let inform_stream = agent.send_inform_stream(&trap_oid, 0, vec![]);
    let collected: Vec<_> = futures::StreamExt::collect(inform_stream).await;
    assert!(collected.is_empty());

    // Primary methods report an empty (all-succeeded) outcome for no sinks.
    let trap_outcome = agent.send_trap(&trap_oid, 0, vec![]).await;
    assert!(trap_outcome.is_empty());
    assert!(trap_outcome.all_succeeded());

    let inform_outcome = agent.send_inform(&trap_oid, 0, vec![]).await;
    assert!(inform_outcome.is_empty());
    assert!(inform_outcome.all_succeeded());
}

#[tokio::test]
async fn agent_rejects_duplicate_sink_ids_before_bind_configuration() {
    let result = Agent::builder()
        .bind("not-a-socket-address")
        .trap_sink(
            NotificationSinkId::new("duplicate").unwrap(),
            "127.0.0.1:9",
            Auth::v1("first"),
        )
        .trap_sink(
            NotificationSinkId::new("duplicate").unwrap(),
            "127.0.0.1:10",
            Auth::v2c("second"),
        )
        .build()
        .await;

    let error = match result {
        Ok(_) => panic!("duplicate sink IDs unexpectedly accepted"),
        Err(error) => error,
    };
    assert!(matches!(&*error, async_snmp::Error::Config(_)));
    assert_eq!(
        error.to_string(),
        "configuration error: duplicate notification sink ID: duplicate"
    );
}

#[tokio::test]
async fn agent_preserves_non_utf8_sink_id_octets() {
    let id = NotificationSinkId::try_from(&b"binary\x00\xff"[..]).unwrap();
    let agent = Agent::builder()
        .bind("127.0.0.1:0")
        .trap_sink(id.clone(), "127.0.0.1:9", Auth::v1("public"))
        .build()
        .await
        .unwrap();

    assert_eq!(agent.notification_sinks().next().unwrap().id(), &id);
}

#[tokio::test]
async fn agent_sink_summaries_and_outcomes_preserve_distinct_ids_and_order() {
    const COMMUNITY_SECRET: &str = "community-summary-secret";
    const USER_SECRET: &str = "username-summary-secret";
    const CONTEXT_SECRET: &str = "context-summary-secret";

    let dest: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();
    let agent = Agent::builder()
        .bind("127.0.0.1:0")
        .authoritative_engine(no_op_authoritative_engine(b"sink-summary-engine"))
        .trap_sink(
            NotificationSinkId::new("community").unwrap(),
            dest.to_string(),
            Auth::v2c(COMMUNITY_SECRET),
        )
        .trap_sink(
            NotificationSinkId::new("usm").unwrap(),
            dest.to_string(),
            async_snmp::UsmConfig::new(USER_SECRET).context_name(CONTEXT_SECRET),
        )
        .build()
        .await
        .unwrap();

    let summaries: Vec<_> = agent.notification_sinks().cloned().collect();
    assert_eq!(summaries.len(), 2);
    assert_eq!(summaries[0].index(), 0);
    assert_eq!(summaries[0].id().as_bytes(), b"community");
    assert_eq!(summaries[0].dest(), dest);
    assert_eq!(summaries[0].version(), Version::V2c);
    assert_eq!(summaries[0].security_level(), None);
    assert_eq!(summaries[1].index(), 1);
    assert_eq!(summaries[1].id().as_bytes(), b"usm");
    assert_eq!(summaries[1].dest(), dest);
    assert_eq!(summaries[1].version(), Version::V3);
    assert_eq!(
        summaries[1].security_level(),
        Some(SecurityLevel::NoAuthNoPriv)
    );

    let rendered = format!("{summaries:?}");
    for secret in [COMMUNITY_SECRET, USER_SECRET, CONTEXT_SECRET] {
        assert!(!rendered.contains(secret), "summary exposed {secret}");
    }

    let outcome = agent
        .send_trap(&oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1), 0, vec![])
        .await;
    assert_eq!(outcome.len(), 2);
    assert_eq!(outcome.sinks()[0].sink, summaries[0]);
    assert_eq!(outcome.sinks()[1].sink, summaries[1]);
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
        .trap_sink(
            NotificationSinkId::new("dead").unwrap(),
            dead_addr.to_string(),
            Auth::v2c("public"),
        )
        .inform_timeout(Duration::from_millis(50))
        .inform_retry(Retry::none())
        .allow_all_access()
        .build()
        .await
        .unwrap();

    let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 2);
    let outcome = agent.send_inform(&trap_oid, 0, vec![]).await;

    assert_eq!(outcome.len(), 1);
    assert!(!outcome.all_succeeded());
    let failures: Vec<_> = outcome.failures().collect();
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].sink.dest(), dead_addr);
    assert!(matches!(&failures[0].status, SinkStatus::Failed(_)));
}

#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
#[tokio::test]
async fn agent_failed_v3_inform_exposes_accepted_exchange_metadata() {
    let level = SecurityLevel::AuthNoPriv;
    let peer_engine = TestV3Engine::new(Bytes::from_static(b"\x80\x00\x7e\xd9\x05inform-metadata"))
        .boots_time(7, 100)
        .user(
            async_snmp::UsmConfig::new("informuser")
                .with_master_keys(
                    async_snmp::MasterKeys::new(AuthProtocol::Sha256, b"authpass12345678").unwrap(),
                )
                .unwrap(),
        );
    let discovery_engine = peer_engine.clone();
    let correction_engine = peer_engine.clone();
    let peer = ScriptedV3Peer::udp(
        peer_engine,
        vec![
            ScriptStep::reply(move |request| {
                let mut response = V3ReplyBuilder::report_to(
                    request,
                    &discovery_engine,
                    async_snmp::v3::report_oids::unknown_engine_ids(),
                    1,
                )
                .build()?
                .to_vec();
                response.push(0xa1);
                Ok(Bytes::from(response))
            }),
            ScriptStep::reply(move |request| {
                let mut response = V3ReplyBuilder::report_to(
                    request,
                    &correction_engine,
                    async_snmp::v3::report_oids::not_in_time_windows(),
                    2,
                )
                .security_level(level)
                .engine_boots(8)
                .engine_time(10)
                .build()?
                .to_vec();
                response.extend_from_slice(&[0xa2, 0xa2]);
                Ok(Bytes::from(response))
            }),
            ScriptStep::silence(),
        ],
    )
    .await;

    let agent = Agent::builder()
        .bind("127.0.0.1:0")
        .community(b"public")
        .authoritative_engine(no_op_authoritative_engine(b"agent-inform-metadata"))
        .trap_sink(
            NotificationSinkId::new("metadata").unwrap(),
            peer.addr().to_string(),
            async_snmp::UsmConfig::new("informuser")
                .auth(AuthProtocol::Sha256, "authpass12345678")
                .unwrap(),
        )
        .inform_timeout(Duration::from_millis(50))
        .inform_retry(Retry::none())
        .allow_all_access()
        .build()
        .await
        .unwrap();

    let outcome = agent
        .send_inform(&oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 2), 0, vec![])
        .await;
    let sink = &outcome.sinks()[0];
    let SinkStatus::Failed(error) = &sink.status else {
        panic!("corrected Inform unexpectedly succeeded")
    };
    assert_eq!(error.kind(), async_snmp::ErrorKind::Timeout);
    assert_eq!(sink.metadata, *error.response_metadata().unwrap());
    assert_eq!(
        sink.metadata
            .decode_anomalies
            .iter()
            .map(|anomaly| match anomaly {
                async_snmp::DecodeAnomaly::TrailingBytes {
                    original_length, ..
                } => *original_length,
                other => panic!("expected trailing-byte anomaly, got {other:?}"),
            })
            .collect::<Vec<_>>(),
        [1, 2]
    );
    peer.finish().await.unwrap();
}

#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
#[tokio::test]
async fn agent_malformed_v3_inform_acknowledgement_retains_metadata_once() {
    let peer_engine = TestV3Engine::new(Bytes::from_static(
        b"\x80\x00\x7e\xd9\x05inform-malformed-ack",
    ))
    .boots_time(7, 100)
    .user(
        async_snmp::UsmConfig::new("informuser")
            .with_master_keys(
                async_snmp::MasterKeys::new(AuthProtocol::Sha256, b"authpass12345678").unwrap(),
            )
            .unwrap(),
    );
    let discovery_engine = peer_engine.clone();
    let response_engine = peer_engine.clone();
    let peer = ScriptedV3Peer::udp(
        peer_engine,
        vec![
            ScriptStep::reply(move |request| {
                let mut response = V3ReplyBuilder::report_to(
                    request,
                    &discovery_engine,
                    async_snmp::v3::report_oids::unknown_engine_ids(),
                    1,
                )
                .build()?
                .to_vec();
                response.push(0xa1);
                Ok(Bytes::from(response))
            }),
            ScriptStep::reply(move |request| {
                let mut response = V3ReplyBuilder::response_to(request, &response_engine)
                    .varbinds(vec![])
                    .build()?
                    .to_vec();
                response.extend_from_slice(&[0xa2, 0xa2]);
                Ok(Bytes::from(response))
            }),
        ],
    )
    .await;

    let agent = Agent::builder()
        .bind("127.0.0.1:0")
        .community(b"public")
        .authoritative_engine(no_op_authoritative_engine(b"agent-malformed-inform"))
        .trap_sink(
            NotificationSinkId::new("malformed").unwrap(),
            peer.addr().to_string(),
            async_snmp::UsmConfig::new("informuser")
                .auth(AuthProtocol::Sha256, "authpass12345678")
                .unwrap(),
        )
        .inform_timeout(Duration::from_millis(50))
        .inform_retry(Retry::none())
        .allow_all_access()
        .build()
        .await
        .unwrap();

    let outcome = agent
        .send_inform(&oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 2), 0, vec![])
        .await;
    let sink = &outcome.sinks()[0];
    let SinkStatus::Failed(error) = &sink.status else {
        panic!("malformed Inform acknowledgement unexpectedly succeeded")
    };
    assert_eq!(error.kind(), async_snmp::ErrorKind::MalformedResponse);
    assert_eq!(sink.metadata, *error.response_metadata().unwrap());
    assert_eq!(
        sink.metadata
            .decode_anomalies
            .iter()
            .map(|anomaly| match anomaly {
                async_snmp::DecodeAnomaly::TrailingBytes {
                    original_length, ..
                } => *original_length,
                other => panic!("expected trailing-byte anomaly, got {other:?}"),
            })
            .collect::<Vec<_>>(),
        [1, 2]
    );
    peer.finish().await.unwrap();
}

#[tokio::test]
async fn agent_inform_stream_yields_live_sink_before_unreachable_sink_timeout() {
    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = probe.local_addr().unwrap();
    drop(probe);

    let receiver = NotificationReceiver::bind("127.0.0.1:0").await.unwrap();
    let live_addr = receiver.local_addr();
    let agent = Agent::builder()
        .bind("127.0.0.1:0")
        .community(b"public")
        .trap_sink(
            NotificationSinkId::new("dead").unwrap(),
            dead_addr.to_string(),
            Auth::v2c("public"),
        )
        .trap_sink(
            NotificationSinkId::new("live").unwrap(),
            live_addr.to_string(),
            Auth::v2c("public"),
        )
        .inform_timeout(Duration::from_secs(2))
        .inform_retry(Retry::none())
        .allow_all_access()
        .build()
        .await
        .unwrap();

    let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 2);
    let mut stream = agent.send_inform_stream(&trap_oid, 0, vec![]);
    let receive = tokio::spawn(async move { receiver.recv().await });

    let live = tokio::time::timeout(Duration::from_millis(500), stream.next())
        .await
        .expect("live sink completion was delayed by the unreachable sink")
        .expect("live sink outcome");
    assert_eq!(live.sink.id().as_bytes(), b"live");
    assert_eq!(live.sink.index(), 1);
    assert_eq!(live.sink.dest(), live_addr);
    assert!(matches!(live.status, SinkStatus::Succeeded));

    let notification = receive.await.unwrap().unwrap().notification;
    assert!(matches!(notification, Notification::InformV2c { .. }));

    let dead = stream.next().await.expect("dead sink outcome");
    assert_eq!(dead.sink.id().as_bytes(), b"dead");
    assert_eq!(dead.sink.index(), 0);
    assert_eq!(dead.sink.dest(), dead_addr);
    assert!(matches!(dead.status, SinkStatus::Failed(_)));
    assert!(stream.next().await.is_none());
}

#[tokio::test]
async fn dropping_inform_stream_cancels_retries() {
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let agent = Agent::builder()
        .bind("127.0.0.1:0")
        .community(b"public")
        .trap_sink(
            NotificationSinkId::new("cancelled").unwrap(),
            target_addr.to_string(),
            Auth::v2c("public"),
        )
        .inform_timeout(Duration::from_millis(50))
        .inform_retry(Retry::fixed(2, Duration::ZERO).unwrap())
        .allow_all_access()
        .build()
        .await
        .unwrap();

    let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 2);
    let mut stream = agent.send_inform_stream(&trap_oid, 0, vec![]);
    let mut next = Box::pin(stream.next());
    let mut first = [0; 2048];
    tokio::select! {
        outcome = &mut next => panic!("unacknowledged Inform completed unexpectedly: {outcome:?}"),
        received = target.recv_from(&mut first) => {
            received.expect("receive first Inform");
        }
    }
    drop(next);
    drop(stream);

    let mut retry = [0; 2048];
    assert!(
        tokio::time::timeout(Duration::from_millis(200), target.recv_from(&mut retry))
            .await
            .is_err(),
        "a retry was sent after dropping the Inform stream"
    );
}

#[tokio::test]
async fn agent_inform_aggregate_restores_configuration_order() {
    let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = probe.local_addr().unwrap();
    drop(probe);

    let receiver = NotificationReceiver::bind("127.0.0.1:0").await.unwrap();
    let live_addr = receiver.local_addr();
    let agent = Agent::builder()
        .bind("127.0.0.1:0")
        .community(b"public")
        .trap_sink(
            NotificationSinkId::new("dead").unwrap(),
            dead_addr.to_string(),
            Auth::v2c("public"),
        )
        .trap_sink(
            NotificationSinkId::new("live").unwrap(),
            live_addr.to_string(),
            Auth::v2c("public"),
        )
        .inform_timeout(Duration::from_millis(100))
        .inform_retry(Retry::none())
        .allow_all_access()
        .build()
        .await
        .unwrap();

    let receive = tokio::spawn(async move { receiver.recv().await });
    let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 2);
    let outcome = agent.send_inform(&trap_oid, 0, vec![]).await;
    receive.await.unwrap().unwrap();

    assert_eq!(outcome.sinks()[0].sink.id().as_bytes(), b"dead");
    assert_eq!(outcome.sinks()[0].sink.index(), 0);
    assert!(matches!(outcome.sinks()[0].status, SinkStatus::Failed(_)));
    assert_eq!(outcome.sinks()[1].sink.id().as_bytes(), b"live");
    assert_eq!(outcome.sinks()[1].sink.index(), 1);
    assert!(matches!(outcome.sinks()[1].status, SinkStatus::Succeeded));
}

#[tokio::test]
async fn agent_trap_reports_total_conversion_failure() {
    let receiver = NotificationReceiver::bind("127.0.0.1:0").await.unwrap();
    let sink_addr = receiver.local_addr();
    let agent = Agent::builder()
        .bind("127.0.0.1:0")
        .community(b"public")
        .trap_sink(
            NotificationSinkId::new("v1").unwrap(),
            sink_addr.to_string(),
            Auth::v1("public"),
        )
        .allow_all_access()
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
    assert_eq!(outcome.sinks()[0].sink.dest(), sink_addr);
    assert!(matches!(
        &outcome.sinks()[0].status,
        SinkStatus::Failed(error)
            if matches!(&**error, async_snmp::Error::InvalidMessage(_))
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
        .trap_sink(
            NotificationSinkId::new("v1").unwrap(),
            v1_addr.to_string(),
            Auth::v1("public"),
        )
        .trap_sink(
            NotificationSinkId::new("v2c").unwrap(),
            v2_addr.to_string(),
            Auth::v2c("public"),
        )
        .allow_all_access()
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
    assert_eq!(outcome.sinks()[0].sink.dest(), v1_addr);
    assert!(matches!(&outcome.sinks()[0].status, SinkStatus::Failed(_)));
    assert_eq!(outcome.sinks()[1].sink.dest(), v2_addr);
    assert!(matches!(&outcome.sinks()[1].status, SinkStatus::Succeeded));

    let notification = tokio::time::timeout(Duration::from_secs(5), v2_receiver.recv())
        .await
        .expect("timeout waiting for successful partial trap")
        .unwrap()
        .notification;
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
        .trap_sink(
            NotificationSinkId::new("v1").unwrap(),
            sink_addr.to_string(),
            Auth::v1("public"),
        )
        .allow_all_access()
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
    assert_eq!(outcome.sinks()[0].sink.dest(), sink_addr);
    assert!(matches!(
        &outcome.sinks()[0].status,
        SinkStatus::Skipped(SinkSkipReason::InformUnsupportedForV1)
    ));
}

#[tokio::test]
async fn agent_inform_stream_yields_skipped_sink() {
    let agent = Agent::builder()
        .bind("127.0.0.1:0")
        .community(b"public")
        .trap_sink(
            NotificationSinkId::new("v1-skip").unwrap(),
            "127.0.0.1:9",
            Auth::v1("public"),
        )
        .allow_all_access()
        .build()
        .await
        .unwrap();

    let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 2);
    let mut stream = agent.send_inform_stream(&trap_oid, 0, vec![]);
    let skipped = stream.next().await.expect("skipped sink outcome");
    assert_eq!(skipped.sink.id().as_bytes(), b"v1-skip");
    assert_eq!(skipped.sink.index(), 0);
    assert!(matches!(
        skipped.status,
        SinkStatus::Skipped(SinkSkipReason::InformUnsupportedForV1)
    ));
    assert!(stream.next().await.is_none());
}

#[tokio::test]
async fn agent_best_effort_helpers_complete_after_failure_and_skip() {
    let receiver = NotificationReceiver::bind("127.0.0.1:0").await.unwrap();
    let agent = Agent::builder()
        .bind("127.0.0.1:0")
        .community(b"public")
        .trap_sink(
            NotificationSinkId::new("v1").unwrap(),
            receiver.local_addr().to_string(),
            Auth::v1("public"),
        )
        .allow_all_access()
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
