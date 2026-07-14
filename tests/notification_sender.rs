//! Integration tests for notification sending (trap/inform).

use async_snmp::agent::Agent;
use async_snmp::notification::{Notification, NotificationReceiver};
use async_snmp::v3::{AuthProtocol, PrivProtocol};
use async_snmp::varbind::VarBind;
use async_snmp::{Auth, Client, Pdu, Retry, Value, oid};
use std::time::Duration;

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

    let receiver = NotificationReceiver::builder()
        .bind("127.0.0.1:0")
        .engine_id(shared_engine_id.clone())
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
    .local_engine_id(shared_engine_id)
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
    let receiver = NotificationReceiver::builder()
        .bind("127.0.0.1:0")
        .usm_user("informuser", |u| {
            u.auth(AuthProtocol::Sha256, b"authpass12345678")
                .privacy(PrivProtocol::Aes128, b"privpass12345678")
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
        Auth::usm("informuser")
            .auth(AuthProtocol::Sha256, "authpass12345678")
            .privacy(PrivProtocol::Aes128, "privpass12345678"),
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
async fn v3_trap_without_local_engine_id_returns_error() {
    let receiver = NotificationReceiver::builder()
        .bind("127.0.0.1:0")
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
    // No local_engine_id set
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
    agent.send_trap(&trap_oid, 500, vec![]).await.unwrap();

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
    agent.send_inform(&trap_oid, 1000, vec![]).await.unwrap();

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

    let receiver = NotificationReceiver::builder()
        .bind("127.0.0.1:0")
        .engine_id(engine_id.clone())
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
        .engine_id(engine_id)
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
    agent.send_trap(&trap_oid, 9999, vec![]).await.unwrap();

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
    agent.send_trap(&trap_oid, 42, vec![]).await.unwrap();

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
    agent.send_trap(&trap_oid, 1000, vec![]).await.unwrap();

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
    agent.send_trap(&trap_oid, 777, vec![]).await.unwrap();

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
    // Should succeed without error (no sinks = no-op)
    agent.send_trap(&trap_oid, 0, vec![]).await.unwrap();
    agent.send_inform(&trap_oid, 0, vec![]).await.unwrap();

    // Detailed variants report an empty (all-succeeded) outcome for no sinks.
    let outcome = agent.send_trap_detailed(&trap_oid, 0, vec![]).await;
    assert!(outcome.is_empty());
    assert!(outcome.all_succeeded());
}

#[tokio::test]
async fn agent_inform_detailed_reports_failing_sink() {
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
    let outcome = agent.send_inform_detailed(&trap_oid, 0, vec![]).await;

    assert_eq!(outcome.len(), 1);
    assert!(!outcome.all_succeeded());
    let failures: Vec<_> = outcome.failures().collect();
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].dest, dead_addr);
    assert!(failures[0].result.is_err());

    // The lossy wrapper still returns Ok(()) for backward compatibility.
    agent.send_inform(&trap_oid, 0, vec![]).await.unwrap();
}
