#![cfg(all(
    feature = "agent",
    any(feature = "crypto-rustcrypto", feature = "crypto-fips")
))]
//! `SNMPv3` security tests using `TestAgent`.

mod common;

use async_snmp::message::{MsgFlags, MsgGlobalData, ScopedPdu, SecurityLevel, V3Message};
use async_snmp::pdu::{Pdu, PduType};
use async_snmp::v3::{AuthProtocol, PrivProtocol, ReportStatus, UsmSecurityParams};
use async_snmp::varbind::VarBind;
use async_snmp::{Auth, Client, Error, Retry, Value, oid};
use bytes::Bytes;
use common::{TestAgentBuilder, V3User};
use std::time::Duration;

const AUTH_PASS: &str = "authpassword123";
const PRIV_PASS: &str = "privpassword123";

/// V3 noAuthNoPriv works.
#[tokio::test]
async fn v3_no_auth_no_priv() {
    let agent = TestAgentBuilder::new()
        .usm_user(V3User::no_auth(b"noauthuser".to_vec()))
        .build()
        .await;

    let client = Client::builder(agent.addr().to_string(), Auth::usm("noauthuser"))
        .connect()
        .await
        .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();

    assert!(result.anomalies.is_empty());
    assert_eq!(result.varbinds[0].value.as_str(), Some("Test SNMP Agent"));
}

/// V3 authNoPriv with SHA-256.
#[tokio::test]
async fn v3_auth_sha256() {
    let agent = TestAgentBuilder::new()
        .usm_user(V3User::auth_only(
            b"authuser".to_vec(),
            AuthProtocol::Sha256,
            AUTH_PASS.as_bytes().to_vec(),
        ))
        .build()
        .await;

    let client = Client::builder(
        agent.addr().to_string(),
        Auth::usm("authuser").auth(AuthProtocol::Sha256, AUTH_PASS),
    )
    .connect()
    .await
    .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();

    assert!(result.anomalies.is_empty());
    assert_eq!(result.varbinds[0].value.as_str(), Some("Test SNMP Agent"));
}

/// End-to-end authNoPriv roundtrip for a given auth protocol.
async fn auth_only_roundtrip(protocol: AuthProtocol) {
    let agent = TestAgentBuilder::new()
        .usm_user(V3User::auth_only(
            b"authuser".to_vec(),
            protocol,
            AUTH_PASS.as_bytes().to_vec(),
        ))
        .build()
        .await;

    let client = Client::builder(
        agent.addr().to_string(),
        Auth::usm("authuser").auth(protocol, AUTH_PASS),
    )
    .connect()
    .await
    .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();

    assert!(result.anomalies.is_empty());
    assert_eq!(result.varbinds[0].value.as_str(), Some("Test SNMP Agent"));
}

/// V3 authNoPriv with SHA-224 (RFC 7860).
#[tokio::test]
async fn v3_auth_sha224() {
    auth_only_roundtrip(AuthProtocol::Sha224).await;
}

/// V3 authNoPriv with SHA-384 (RFC 7860).
#[tokio::test]
async fn v3_auth_sha384() {
    auth_only_roundtrip(AuthProtocol::Sha384).await;
}

/// V3 authNoPriv with SHA-512 (RFC 7860).
#[tokio::test]
async fn v3_auth_sha512() {
    auth_only_roundtrip(AuthProtocol::Sha512).await;
}

/// A stale whole-state cache insert cannot overwrite a newer authenticated
/// boots/time generation. A second authNoPriv client sharing the cache uses the
/// canonical tuple without causing another notInTimeWindows Report.
#[tokio::test]
async fn v3_shared_cache_rejects_stale_boots_overwrite() {
    use async_snmp::v3::{EngineCache, EngineState};
    use std::sync::Arc;

    let agent = TestAgentBuilder::new()
        .usm_user(V3User::auth_only(
            b"authuser".to_vec(),
            AuthProtocol::Sha256,
            AUTH_PASS.as_bytes().to_vec(),
        ))
        .build()
        .await;

    let cache = Arc::new(EngineCache::new());
    let client = Client::builder(
        agent.addr().to_string(),
        Auth::usm("authuser").auth(AuthProtocol::Sha256, AUTH_PASS),
    )
    .engine_cache(cache.clone())
    .connect()
    .await
    .unwrap();

    // Discovery contributes identity only, so the first authenticated request
    // synchronizes through one notInTimeWindows Report.
    client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    let baseline_reports = agent.agent().usm_not_in_time_windows();
    assert_eq!(baseline_reports, 1);

    // A stale whole-state insert must not overwrite the cache's newer trusted
    // high-water value. A second client sharing the cache adopts the canonical
    // monotonic state and sends no additional stale request.
    let good = cache.get(&agent.addr()).expect("cache seeded");
    let good_boots = good.trusted_time().unwrap().boots();
    assert!(good_boots > 0, "agent boots must be nonzero");
    cache.insert(
        agent.addr(),
        EngineState::new(
            good.engine_id().clone(),
            good_boots - 1,
            good.estimated_time(),
        ),
    );

    let client2 = Client::builder(
        agent.addr().to_string(),
        Auth::usm("authuser").auth(AuthProtocol::Sha256, AUTH_PASS),
    )
    .engine_cache(cache)
    .connect()
    .await
    .unwrap();

    let result = client2
        .get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))
        .await
        .expect("client must use the canonical shared time generation");
    assert!(result.anomalies.is_empty());
    assert_eq!(result.varbinds[0].value.as_str(), Some("Test SNMP Agent"));

    assert_eq!(
        agent.agent().usm_not_in_time_windows(),
        baseline_reports,
        "stale cache insertion must not cause another time-window rejection"
    );
}

/// The same stale-cache overwrite protection applies to authPriv clients.
#[tokio::test]
async fn v3_auth_priv_shared_cache_rejects_stale_boots_overwrite() {
    use async_snmp::v3::{EngineCache, EngineState};
    use std::sync::Arc;

    let agent = TestAgentBuilder::new()
        .usm_user(V3User::auth_priv(
            b"authprivuser".to_vec(),
            AuthProtocol::Sha256,
            AUTH_PASS.as_bytes().to_vec(),
            PrivProtocol::Aes128,
            PRIV_PASS.as_bytes().to_vec(),
        ))
        .build()
        .await;

    let cache = Arc::new(EngineCache::new());
    let client = Client::builder(
        agent.addr().to_string(),
        Auth::usm("authprivuser").auth_priv(
            AuthProtocol::Sha256,
            AUTH_PASS,
            PrivProtocol::Aes128,
            PRIV_PASS,
        ),
    )
    .engine_cache(cache.clone())
    .connect()
    .await
    .unwrap();

    client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    let baseline_reports = agent.agent().usm_not_in_time_windows();
    assert_eq!(baseline_reports, 1);

    let good = cache.get(&agent.addr()).expect("cache seeded");
    let good_boots = good.trusted_time().unwrap().boots();
    assert!(good_boots > 0, "agent boots must be nonzero");
    cache.insert(
        agent.addr(),
        EngineState::new(
            good.engine_id().clone(),
            good_boots - 1,
            good.estimated_time(),
        ),
    );

    let client2 = Client::builder(
        agent.addr().to_string(),
        Auth::usm("authprivuser").auth_priv(
            AuthProtocol::Sha256,
            AUTH_PASS,
            PrivProtocol::Aes128,
            PRIV_PASS,
        ),
    )
    .engine_cache(cache)
    .connect()
    .await
    .unwrap();

    let result = client2
        .get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))
        .await
        .expect("authPriv client must use the canonical shared time generation");
    assert!(result.anomalies.is_empty());
    assert_eq!(result.varbinds[0].value.as_str(), Some("Test SNMP Agent"));

    assert_eq!(agent.agent().usm_not_in_time_windows(), baseline_reports);
}

/// V3 authPriv with SHA-256 and AES-128.
#[tokio::test]
async fn v3_auth_priv_sha256_aes128() {
    let agent = TestAgentBuilder::new()
        .usm_user(V3User::auth_priv(
            b"authprivuser".to_vec(),
            AuthProtocol::Sha256,
            AUTH_PASS.as_bytes().to_vec(),
            PrivProtocol::Aes128,
            PRIV_PASS.as_bytes().to_vec(),
        ))
        .build()
        .await;

    let client = Client::builder(
        agent.addr().to_string(),
        Auth::usm("authprivuser").auth_priv(
            AuthProtocol::Sha256,
            AUTH_PASS,
            PrivProtocol::Aes128,
            PRIV_PASS,
        ),
    )
    .connect()
    .await
    .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();

    assert!(result.anomalies.is_empty());
    assert_eq!(result.varbinds[0].value.as_str(), Some("Test SNMP Agent"));
}

/// V3 with MD5 auth (legacy support).
#[cfg(feature = "crypto-rustcrypto")]
#[tokio::test]
async fn v3_auth_md5() {
    let agent = TestAgentBuilder::new()
        .usm_user(V3User::auth_only(
            b"md5user".to_vec(),
            AuthProtocol::Md5,
            AUTH_PASS.as_bytes().to_vec(),
        ))
        .build()
        .await;

    let client = Client::builder(
        agent.addr().to_string(),
        Auth::usm("md5user").auth(AuthProtocol::Md5, AUTH_PASS),
    )
    .connect()
    .await
    .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();

    assert!(result.anomalies.is_empty());
    assert_eq!(result.varbinds[0].value.as_str(), Some("Test SNMP Agent"));
}

/// V3 with DES privacy (legacy support).
#[cfg(feature = "crypto-rustcrypto")]
#[tokio::test]
async fn v3_auth_priv_sha1_des() {
    let agent = TestAgentBuilder::new()
        .usm_user(V3User::auth_priv(
            b"desuser".to_vec(),
            AuthProtocol::Sha1,
            AUTH_PASS.as_bytes().to_vec(),
            PrivProtocol::Des,
            PRIV_PASS.as_bytes().to_vec(),
        ))
        .build()
        .await;

    let client = Client::builder(
        agent.addr().to_string(),
        Auth::usm("desuser").auth_priv(AuthProtocol::Sha1, AUTH_PASS, PrivProtocol::Des, PRIV_PASS),
    )
    .connect()
    .await
    .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();

    assert!(result.anomalies.is_empty());
    assert_eq!(result.varbinds[0].value.as_str(), Some("Test SNMP Agent"));
}

/// A response signed with the wrong password is rejected until the exchange times out.
#[tokio::test]
async fn v3_wrong_password_fails() {
    let agent = TestAgentBuilder::new()
        .usm_user(V3User::auth_only(
            b"authuser".to_vec(),
            AuthProtocol::Sha256,
            AUTH_PASS.as_bytes().to_vec(),
        ))
        .build()
        .await;

    let client = Client::builder(
        agent.addr().to_string(),
        Auth::usm("authuser").auth(AuthProtocol::Sha256, "wrongpassword"),
    )
    .timeout(Duration::from_millis(500))
    .retry(Retry::none())
    .connect()
    .await
    .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;

    assert!(
        matches!(result, Err(ref e) if matches!(**e, Error::Timeout { .. })),
        "expected timeout after candidate rejection, got {result:?}"
    );
}

/// An authenticated unknown-user Report is rejected until the exchange times out.
///
/// When authentication is required, the agent rejects unknown users.
#[tokio::test]
async fn v3_unknown_user_auth_fails() {
    let agent = TestAgentBuilder::new()
        .usm_user(V3User::auth_only(
            b"validuser".to_vec(),
            AuthProtocol::Sha256,
            AUTH_PASS.as_bytes().to_vec(),
        ))
        .build()
        .await;

    // Try to use unknown user with authentication - should fail
    let client = Client::builder(
        agent.addr().to_string(),
        Auth::usm("unknownuser").auth(AuthProtocol::Sha256, AUTH_PASS),
    )
    .timeout(Duration::from_millis(500))
    .retry(Retry::none())
    .connect()
    .await
    .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;

    assert!(
        matches!(result, Err(ref e) if matches!(**e, Error::Timeout { .. })),
        "expected timeout after candidate rejection, got {result:?}"
    );
}

/// Unknown user with noAuthNoPriv fails (RFC 3414 section 3.2 step 1).
///
/// Non-discovery messages with an unknown username must be rejected with
/// usmStatsUnknownUserNames even when security level is noAuthNoPriv.
/// Only discovery messages (empty msgUserName) are exempt.
#[tokio::test]
async fn v3_unknown_user_no_auth_fails() {
    let agent = TestAgentBuilder::new()
        .usm_user(V3User::no_auth(b"knownuser".to_vec()))
        .build()
        .await;

    // Try to use unknown user with noAuthNoPriv - must fail per RFC 3414
    let client = Client::builder(agent.addr().to_string(), Auth::usm("unknownuser"))
        .timeout(Duration::from_millis(500))
        .retry(Retry::none())
        .connect()
        .await
        .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;

    assert!(
        matches!(
            result,
            Err(ref e)
                if matches!(
                    &**e,
                    Error::Report { status, .. }
                        if matches!(status.as_ref(), ReportStatus::UnknownUserName { .. })
                )
        ),
        "expected typed unknown-user Report for noAuthNoPriv user, got {result:?}"
    );
}

/// Engine discovery works.
#[tokio::test]
async fn v3_engine_discovery() {
    let agent = TestAgentBuilder::new()
        .usm_user(V3User::auth_only(
            b"authuser".to_vec(),
            AuthProtocol::Sha256,
            AUTH_PASS.as_bytes().to_vec(),
        ))
        .build()
        .await;

    let client = Client::builder(
        agent.addr().to_string(),
        Auth::usm("authuser").auth(AuthProtocol::Sha256, AUTH_PASS),
    )
    .connect()
    .await
    .unwrap();

    // First request triggers discovery
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert!(result.anomalies.is_empty());
    assert_eq!(result.varbinds[0].value.as_str(), Some("Test SNMP Agent"));

    // Subsequent request should use cached engine info
    let result2 = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 3, 0)).await.unwrap();
    assert!(result2.anomalies.is_empty());
    assert!(matches!(
        result2.varbinds[0].value,
        async_snmp::Value::TimeTicks(_)
    ));
}

/// Build a raw noAuthNoPriv V3 GET request with a given engine ID and username.
fn build_raw_v3_get(engine_id: Bytes, username: Bytes) -> Bytes {
    let usm = UsmSecurityParams::new(engine_id, 0, 0, username);
    let pdu = Pdu::standard(
        async_snmp::pdu::StandardPduType::GetRequest,
        1,
        0,
        0,
        vec![VarBind::new(oid!(1, 3, 6, 1, 2, 1, 1, 1, 0), Value::Null)],
    );
    let scoped = ScopedPdu::with_empty_context(pdu);
    let global = MsgGlobalData::new(
        1,
        async_snmp::MessageSize::new(65507).unwrap(),
        MsgFlags::new(SecurityLevel::NoAuthNoPriv, true),
    );
    V3Message::new(global, usm.encode(), scoped)
        .encode()
        .unwrap()
}

/// Send a raw UDP packet to addr and return the response bytes.
async fn send_raw_udp(addr: std::net::SocketAddr, data: Bytes) -> Bytes {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.send_to(&data, addr).await.unwrap();
    let mut buf = vec![0u8; 65535];
    let (n, _) = tokio::time::timeout(std::time::Duration::from_secs(2), sock.recv_from(&mut buf))
        .await
        .expect("no response within timeout")
        .unwrap();
    Bytes::copy_from_slice(&buf[..n])
}

/// Report PDU varbind counter matches the actual counter value - discovery path.
///
/// RFC 3412 Section 7.2 Step 7 requires the Report PDU to include the
/// relevant counter OID with its actual (non-zero) value. This test verifies
/// that the usmStatsUnknownEngineIDs counter in the Report PDU matches the
/// counter exposed by the Agent API.
#[tokio::test]
async fn report_pdu_counter_matches_agent_counter_discovery() {
    let agent = TestAgentBuilder::new()
        .usm_user(V3User::no_auth(b"testuser".to_vec()))
        .build()
        .await;

    let addr = agent.addr();

    // Discovery request: empty engine ID triggers usmStatsUnknownEngineIDs Report
    let msg1 = build_raw_v3_get(Bytes::new(), Bytes::new());
    let resp1 = send_raw_udp(addr, msg1).await;
    let decoded1 = V3Message::decode(resp1).unwrap();
    let pdu1 = decoded1.pdu().unwrap();
    assert_eq!(pdu1.pdu_type(), PduType::Report, "expected Report PDU");

    // The varbind should be usmStatsUnknownEngineIDs (1.3.6.1.6.3.15.1.1.4.0) with value 1
    let vb1 = &pdu1.varbinds[0];
    assert_eq!(
        vb1.oid,
        oid!(1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0),
        "Report should contain usmStatsUnknownEngineIDs OID"
    );
    let counter1 = match vb1.value {
        Value::Counter32(v) => v,
        ref v => panic!("expected Counter32, got {v:?}"),
    };
    assert_eq!(counter1, 1, "first Report should carry counter value 1");

    // Wait briefly for the agent to process before checking counter
    tokio::task::yield_now().await;
    assert_eq!(
        agent.agent().usm_unknown_engine_ids(),
        1,
        "agent counter should be 1 after first discovery"
    );

    // Second discovery request: counter should be 2
    let msg2 = build_raw_v3_get(Bytes::new(), Bytes::new());
    let resp2 = send_raw_udp(addr, msg2).await;
    let decoded2 = V3Message::decode(resp2).unwrap();
    let pdu2 = decoded2.pdu().unwrap();
    assert_eq!(pdu2.pdu_type(), PduType::Report);

    let vb2 = &pdu2.varbinds[0];
    assert_eq!(
        vb2.oid,
        oid!(1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0),
        "second Report should contain usmStatsUnknownEngineIDs OID"
    );
    let counter2 = match vb2.value {
        Value::Counter32(v) => v,
        ref v => panic!("expected Counter32, got {v:?}"),
    };
    assert_eq!(counter2, 2, "second Report should carry counter value 2");

    tokio::task::yield_now().await;
    assert_eq!(
        agent.agent().usm_unknown_engine_ids(),
        2,
        "agent counter should be 2 after second discovery"
    );
}

/// Report PDU counter matches agent counter - unknown user path.
///
/// Sending a request with a known engine ID but unknown username triggers
/// usmStatsUnknownUserNames. The Report PDU must carry the actual counter value.
#[tokio::test]
async fn report_pdu_counter_matches_agent_counter_unknown_user() {
    let agent = TestAgentBuilder::new()
        .usm_user(V3User::no_auth(b"knownuser".to_vec()))
        .build()
        .await;

    let addr = agent.addr();
    let engine_id = Bytes::copy_from_slice(agent.agent().engine_id());

    // Send a request with the correct engine ID but an unknown username.
    // reportable=true so the agent sends a Report PDU.
    let msg = build_raw_v3_get(engine_id, Bytes::from_static(b"unknownuser"));
    let resp = send_raw_udp(addr, msg).await;
    let decoded = V3Message::decode(resp).unwrap();
    let pdu = decoded.pdu().unwrap();
    assert_eq!(pdu.pdu_type(), PduType::Report, "expected Report PDU");

    let vb = &pdu.varbinds[0];
    // The OID should be usmStatsUnknownUserNames (1.3.6.1.6.3.15.1.1.3.0)
    assert_eq!(
        vb.oid,
        oid!(1, 3, 6, 1, 6, 3, 15, 1, 1, 3, 0),
        "wrong report OID"
    );

    let counter = match vb.value {
        Value::Counter32(v) => v,
        ref v => panic!("expected Counter32, got {v:?}"),
    };
    assert_eq!(counter, 1, "Report PDU counter should be 1, not 0");

    tokio::task::yield_now().await;
    assert_eq!(
        agent.agent().usm_unknown_usernames(),
        1,
        "agent usm_unknown_usernames counter should be 1"
    );
}
