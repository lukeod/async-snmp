//! Scripted-peer characterization for the SNMPv3 client receive path.

mod common;

use async_snmp::message::{SecurityLevel, V3Message, V3MessageData};
use async_snmp::transport::Transport;
use async_snmp::v3::{AuthProtocol, PrivProtocol, report_oids};
use async_snmp::{
    Auth, Client, ClientConfig, MasterKeys, Retry, UsmConfig, Value, VarBind, Version, oid,
};
use bytes::Bytes;
use common::v3::{
    ScriptStep, ScriptedTransport, ScriptedV3Peer, TestV3Engine, V3ReplyBuilder, raw_ber,
};
use std::time::Duration;

// RFC 5612 documentation PEN 32473 with RFC 3411 format 5 opaque octets.
const ENGINE_ID: &[u8] = b"\x80\x00\x7e\xd9\x05scripted-engine";
const USERNAME: &str = "testuser";
const AUTH_PASSWORD: &str = "authpassword123";
const PRIV_PASSWORD: &str = "privpassword123";
const LOOPBACK_TIMEOUT: Duration = Duration::from_millis(250);

fn user_for(level: SecurityLevel) -> UsmConfig {
    let user = UsmConfig::new(USERNAME);
    match level {
        SecurityLevel::NoAuthNoPriv => user,
        SecurityLevel::AuthNoPriv => user.with_master_keys(
            MasterKeys::new(AuthProtocol::Sha256, AUTH_PASSWORD.as_bytes()).unwrap(),
        ),
        SecurityLevel::AuthPriv => user.with_master_keys(
            MasterKeys::new(AuthProtocol::Sha256, AUTH_PASSWORD.as_bytes())
                .unwrap()
                .with_privacy(PrivProtocol::Aes128, PRIV_PASSWORD.as_bytes())
                .unwrap(),
        ),
    }
}

fn auth_for(level: SecurityLevel) -> Auth {
    match level {
        SecurityLevel::NoAuthNoPriv => Auth::usm(USERNAME).into(),
        SecurityLevel::AuthNoPriv => Auth::usm(USERNAME)
            .auth(AuthProtocol::Sha256, AUTH_PASSWORD)
            .into(),
        SecurityLevel::AuthPriv => Auth::usm(USERNAME)
            .auth(AuthProtocol::Sha256, AUTH_PASSWORD)
            .privacy(PrivProtocol::Aes128, PRIV_PASSWORD)
            .into(),
    }
}

fn engine_for(level: SecurityLevel) -> TestV3Engine {
    TestV3Engine::new(Bytes::from_static(ENGINE_ID))
        .boots_time(7, 100)
        .user(user_for(level))
}

fn discovery_step(engine: TestV3Engine) -> ScriptStep {
    ScriptStep::reply(move |request| {
        V3ReplyBuilder::report_to(request, &engine, report_oids::unknown_engine_ids(), 1).build()
    })
}

fn response_step(engine: TestV3Engine, value: &'static str) -> ScriptStep {
    ScriptStep::reply(move |request| {
        let oid = request.scoped_pdu.as_ref().unwrap().pdu.varbinds[0]
            .oid
            .clone();
        V3ReplyBuilder::response_to(request, &engine)
            .varbinds(vec![VarBind::new(
                oid,
                Value::OctetString(Bytes::from_static(value.as_bytes())),
            )])
            .build()
    })
}

fn custom_client(
    transport: ScriptedTransport,
    level: SecurityLevel,
    context_name: Option<&'static str>,
) -> Client<ScriptedTransport> {
    let mut security = user_for(level);
    if let Some(context_name) = context_name {
        security = security.context_name(context_name);
    }
    Client::new(
        transport,
        ClientConfig {
            version: Version::V3,
            timeout: LOOPBACK_TIMEOUT,
            retry: Retry::none(),
            v3_security: Some(security),
            ..ClientConfig::default()
        },
    )
}

async fn udp_success_at_level(level: SecurityLevel) {
    let engine = engine_for(level);
    let peer = ScriptedV3Peer::udp(
        engine.clone(),
        vec![
            discovery_step(engine.clone()),
            response_step(engine, "scripted response"),
        ],
    )
    .await;
    let log = peer.log();

    let client = Client::builder(peer.addr(), auth_for(level))
        .timeout(LOOPBACK_TIMEOUT)
        .retry(Retry::none())
        .connect()
        .await
        .unwrap();
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;
    let requests = log.snapshot();
    let peer_result = peer.finish().await;
    assert!(
        peer_result.is_ok(),
        "peer failed: {peer_result:?}; requests: {requests:#?}"
    );
    let result =
        result.unwrap_or_else(|error| panic!("client failed: {error}; requests: {requests:#?}"));
    assert_eq!(result.value.as_str(), Some("scripted response"));

    assert_eq!(requests.len(), 2);
    assert!(requests[0].usm.engine_id.is_empty());
    assert!(requests[0].usm.username.is_empty());
    assert_eq!(requests[1].usm.engine_id.as_ref(), ENGINE_ID);
    assert_eq!(requests[1].global_data.msg_flags.security_level, level);
    assert!(requests[1].scoped_pdu.is_some());
    assert_eq!(
        requests[1].authentication_valid,
        level.requires_auth().then_some(true)
    );
}

#[tokio::test]
async fn v3_scripted_udp_success_at_all_security_levels() {
    for level in [
        SecurityLevel::NoAuthNoPriv,
        SecurityLevel::AuthNoPriv,
        SecurityLevel::AuthPriv,
    ] {
        udp_success_at_level(level).await;
    }
}

#[tokio::test]
async fn v3_scripted_tcp_auth_priv_success() {
    let level = SecurityLevel::AuthPriv;
    let engine = engine_for(level);
    let peer = ScriptedV3Peer::tcp(
        engine.clone(),
        vec![
            discovery_step(engine.clone()),
            response_step(engine, "tcp response"),
        ],
    )
    .await;
    let log = peer.log();

    let client = Client::builder(peer.addr(), auth_for(level))
        .timeout(LOOPBACK_TIMEOUT)
        .connect_tcp()
        .await
        .unwrap();
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert_eq!(result.value.as_str(), Some("tcp response"));

    peer.finish().await.unwrap();
    let requests = log.snapshot();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[1].authentication_valid, Some(true));
    assert!(requests[1].scoped_pdu.is_some());
}

#[tokio::test]
async fn v3_scripted_auth_priv_time_window_report_correction() {
    let level = SecurityLevel::AuthPriv;
    let engine = engine_for(level);
    let report_engine = engine.clone();
    let response_engine = engine.clone();
    let peer = ScriptedV3Peer::udp(
        engine,
        vec![
            discovery_step(report_engine.clone()),
            ScriptStep::reply(move |request| {
                V3ReplyBuilder::report_to(
                    request,
                    &report_engine,
                    report_oids::not_in_time_windows(),
                    1,
                )
                .security_level(SecurityLevel::AuthNoPriv)
                .engine_boots(8)
                .engine_time(10)
                .build()
            }),
            ScriptStep::reply(move |request| {
                let oid = request.scoped_pdu.as_ref().unwrap().pdu.varbinds[0]
                    .oid
                    .clone();
                V3ReplyBuilder::response_to(request, &response_engine)
                    .engine_boots(8)
                    .engine_time(10)
                    .varbinds(vec![VarBind::new(
                        oid,
                        Value::OctetString(Bytes::from_static(b"corrected response")),
                    )])
                    .build()
            }),
        ],
    )
    .await;
    let log = peer.log();

    let client = Client::builder(peer.addr(), auth_for(level))
        .timeout(LOOPBACK_TIMEOUT)
        .retry(Retry::fixed(1, Duration::ZERO))
        .connect()
        .await
        .unwrap();
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert_eq!(result.value.as_str(), Some("corrected response"));

    peer.finish().await.unwrap();
    let requests = log.snapshot();
    assert_eq!(requests.len(), 3);
    let first = &requests[1];
    let corrected = &requests[2];
    assert_ne!(
        (first.usm.engine_boots, first.usm.engine_time),
        (corrected.usm.engine_boots, corrected.usm.engine_time),
        "the Report must change the tuple used by the corrected request"
    );
    assert_eq!(
        first.global_data.msg_flags.security_level,
        SecurityLevel::AuthPriv
    );
    assert_eq!(
        corrected.global_data.msg_flags.security_level,
        SecurityLevel::AuthPriv
    );
    assert_eq!(first.authentication_valid, Some(true));
    assert_eq!(corrected.authentication_valid, Some(true));
    assert_ne!(first.global_data.msg_id, corrected.global_data.msg_id);
    assert_eq!(
        first.scoped_pdu.as_ref().unwrap().pdu.request_id,
        corrected.scoped_pdu.as_ref().unwrap().pdu.request_id
    );
    assert_eq!(
        (corrected.usm.engine_boots, corrected.usm.engine_time),
        (8, 10)
    );
}

/// A client configured without authentication cannot verify a received
/// authenticated Report, so it must fail with an Auth error instead of
/// acting on the Report's contents (RFC 3412 Section 7.2 processes at the
/// received level; acting requires the claimed authentication to be checked).
#[tokio::test]
async fn v3_noauth_client_rejects_authenticated_report() {
    let engine = engine_for(SecurityLevel::NoAuthNoPriv);
    let report_engine = engine.clone();
    let peer = ScriptedV3Peer::udp(
        engine.clone(),
        vec![
            discovery_step(engine.clone()),
            ScriptStep::reply(move |request| {
                V3ReplyBuilder::report_to(
                    request,
                    &report_engine,
                    report_oids::not_in_time_windows(),
                    1,
                )
                .security_level(SecurityLevel::AuthNoPriv)
                .signing_user(user_for(SecurityLevel::AuthNoPriv))
                .engine_boots(8)
                .engine_time(500)
                .build()
            }),
        ],
    )
    .await;
    let log = peer.log();

    let client = Client::builder(peer.addr(), auth_for(SecurityLevel::NoAuthNoPriv))
        .timeout(LOOPBACK_TIMEOUT)
        .retry(Retry::fixed(1, Duration::ZERO))
        .connect()
        .await
        .unwrap();
    let err = client
        .get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))
        .await
        .unwrap_err();
    assert!(
        matches!(*err, async_snmp::Error::Auth { .. }),
        "expected Auth error, got: {err}"
    );

    peer.finish().await.unwrap();
    let requests = log.snapshot();
    assert_eq!(
        requests.len(),
        2,
        "the unverifiable Report must not trigger a corrected retry"
    );
}

/// A wire username which does not select the cached user's key must be
/// rejected before its authenticated boots/time or Report status are used.
#[tokio::test]
async fn v3_authenticated_wrong_username_does_not_mutate_time_or_retry() {
    let level = SecurityLevel::AuthNoPriv;
    let engine = engine_for(level);
    let report_engine = engine.clone();
    let peer = ScriptedV3Peer::udp(
        engine.clone(),
        vec![
            discovery_step(engine.clone()),
            ScriptStep::reply(move |request| {
                V3ReplyBuilder::report_to(
                    request,
                    &report_engine,
                    report_oids::not_in_time_windows(),
                    1,
                )
                .username(Bytes::from_static(b"other-user"))
                .signing_user(user_for(level))
                .engine_boots(8)
                .engine_time(500)
                .security_level(level)
                .build()
            }),
            response_step(engine, "state preserved"),
        ],
    )
    .await;
    let log = peer.log();

    let client = Client::builder(peer.addr(), auth_for(level))
        .timeout(LOOPBACK_TIMEOUT)
        .retry(Retry::none())
        .connect()
        .await
        .unwrap();
    let err = client
        .get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))
        .await
        .unwrap_err();
    assert!(
        matches!(*err, async_snmp::Error::Auth { .. }),
        "wrong security name must fail USM processing, got: {err}"
    );

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert_eq!(result.value.as_str(), Some("state preserved"));

    peer.finish().await.unwrap();
    let requests = log.snapshot();
    assert_eq!(requests.len(), 3, "the invalid Report must not add a retry");
    assert_eq!(
        requests[2].usm.engine_boots, 7,
        "wrong-user authentication must not advance engine state"
    );
}

/// An authenticated packet whose wire engine ID does not identify the cached
/// localized key must fail before Report classification.
#[tokio::test]
async fn v3_authenticated_wrong_engine_id_does_not_trigger_report_retry() {
    let level = SecurityLevel::AuthNoPriv;
    let engine = engine_for(level);
    let expected_engine_id = engine.engine_id.clone();
    let report_engine = engine.clone();
    let peer = ScriptedV3Peer::udp(
        engine.clone(),
        vec![
            discovery_step(engine),
            ScriptStep::reply(move |request| {
                V3ReplyBuilder::report_to(
                    request,
                    &report_engine,
                    report_oids::not_in_time_windows(),
                    1,
                )
                .engine_id(Bytes::from_static(b"\x80\x00\x7e\xd9\x05foreign-engine"))
                .key_engine_id(expected_engine_id)
                .security_level(level)
                .build()
            }),
        ],
    )
    .await;
    let log = peer.log();

    let client = Client::builder(peer.addr(), auth_for(level))
        .timeout(LOOPBACK_TIMEOUT)
        .retry(Retry::fixed(1, Duration::ZERO))
        .connect()
        .await
        .unwrap();
    let err = client
        .get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))
        .await
        .unwrap_err();
    assert!(
        matches!(*err, async_snmp::Error::Auth { .. }),
        "wrong authoritative engine must fail USM processing, got: {err}"
    );

    peer.finish().await.unwrap();
    assert_eq!(
        log.len(),
        2,
        "the identity-confused Report must not trigger a corrected send"
    );
}

/// Step 5 rejects a received authPriv level which the configured user cannot
/// support before HMAC-verified time can update the local notion.
#[tokio::test]
async fn v3_auth_no_priv_client_rejects_auth_priv_without_time_mutation() {
    let client_level = SecurityLevel::AuthNoPriv;
    let peer_level = SecurityLevel::AuthPriv;
    let engine = engine_for(peer_level);
    let response_engine = engine.clone();
    let peer = ScriptedV3Peer::udp(
        engine.clone(),
        vec![
            discovery_step(engine.clone()),
            ScriptStep::reply(move |request| {
                V3ReplyBuilder::response_to(request, &response_engine)
                    .security_level(peer_level)
                    .engine_boots(8)
                    .engine_time(500)
                    .build()
            }),
            response_step(engine, "state preserved"),
        ],
    )
    .await;
    let log = peer.log();

    let client = Client::builder(peer.addr(), auth_for(client_level))
        .timeout(LOOPBACK_TIMEOUT)
        .retry(Retry::none())
        .connect()
        .await
        .unwrap();
    let err = client
        .get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))
        .await
        .unwrap_err();
    assert!(
        matches!(*err, async_snmp::Error::Auth { .. }),
        "unsupported authPriv must fail capability selection, got: {err}"
    );

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert_eq!(result.value.as_str(), Some("state preserved"));

    peer.finish().await.unwrap();
    let requests = log.snapshot();
    assert_eq!(requests.len(), 3);
    assert_eq!(
        requests[2].usm.engine_boots, 7,
        "unsupported privacy must not advance engine state"
    );
}

/// A failed HMAC must stop processing before malformed plaintext ScopedPDU
/// bytes are parsed or their claimed time can mutate local state.
#[tokio::test]
async fn v3_failed_hmac_precedes_plaintext_parse_and_time_update() {
    let level = SecurityLevel::AuthNoPriv;
    let engine = engine_for(level);
    let malformed_engine = engine.clone();
    let peer = ScriptedV3Peer::udp(
        engine.clone(),
        vec![
            discovery_step(engine.clone()),
            ScriptStep::reply(move |request| {
                let usm = raw_ber::usm_security_params(
                    &malformed_engine.engine_id,
                    &[8],
                    &[0x01, 0xf4],
                    USERNAME.as_bytes(),
                    &[0xaa; 24],
                    &[],
                );
                Ok(raw_ber::v3_message(
                    &raw_ber::signed_integer_content(request.global_data.msg_id),
                    &[0x00, 0xff, 0xe3],
                    &[0x01],
                    &[3],
                    &usm,
                    &raw_ber::tlv(0x30, &[0xde, 0xad, 0xbe, 0xef]),
                ))
            }),
            response_step(engine, "state preserved"),
        ],
    )
    .await;
    let log = peer.log();

    let client = Client::builder(peer.addr(), auth_for(level))
        .timeout(LOOPBACK_TIMEOUT)
        .retry(Retry::none())
        .connect()
        .await
        .unwrap();
    let err = client
        .get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))
        .await
        .unwrap_err();
    assert!(
        matches!(*err, async_snmp::Error::Auth { .. }),
        "failed HMAC must win over malformed plaintext, got: {err}"
    );

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert_eq!(result.value.as_str(), Some("state preserved"));

    peer.finish().await.unwrap();
    let requests = log.snapshot();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[2].usm.engine_boots, 7);
}

/// Timeliness processing must reject authenticated stale authPriv input before
/// attempting to decrypt or parse its intentionally invalid ciphertext.
#[tokio::test]
async fn v3_auth_priv_timeliness_precedes_decryption() {
    let level = SecurityLevel::AuthPriv;
    let engine = engine_for(level).boots_time(7, 1000);
    let stale_engine = engine.clone();
    let peer = ScriptedV3Peer::udp(
        engine.clone(),
        vec![
            discovery_step(engine.clone()),
            ScriptStep::reply(move |request| {
                V3ReplyBuilder::response_to(request, &stale_engine)
                    .engine_time(100)
                    .ciphertext(Bytes::from_static(b"not a scoped PDU"))
                    .build()
            }),
            discovery_step(engine.clone()),
            response_step(engine, "rediscovered"),
        ],
    )
    .await;
    let log = peer.log();

    let client = Client::builder(peer.addr(), auth_for(level))
        .timeout(LOOPBACK_TIMEOUT)
        .retry(Retry::none())
        .connect()
        .await
        .unwrap();
    let err = client
        .get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))
        .await
        .unwrap_err();
    assert!(
        matches!(*err, async_snmp::Error::Auth { .. }),
        "stale ciphertext must fail timeliness before decode, got: {err}"
    );

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert_eq!(result.value.as_str(), Some("rediscovered"));

    peer.finish().await.unwrap();
    let requests = log.snapshot();
    assert_eq!(requests.len(), 4);
    assert!(
        requests[2].usm.engine_id.is_empty(),
        "timeliness rejection must occur before ciphertext decode and clear the stale notion"
    );
}

/// An authenticated session must not accept an unauthenticated reply
/// (received noAuthNoPriv on a configured authNoPriv exchange).
#[tokio::test]
async fn v3_auth_client_rejects_unauthenticated_response() {
    let level = SecurityLevel::AuthNoPriv;
    let engine = engine_for(level);
    let response_engine = engine.clone();
    let peer = ScriptedV3Peer::udp(
        engine.clone(),
        vec![
            discovery_step(engine.clone()),
            ScriptStep::reply(move |request| {
                let oid = request.scoped_pdu.as_ref().unwrap().pdu.varbinds[0]
                    .oid
                    .clone();
                V3ReplyBuilder::response_to(request, &response_engine)
                    .security_level(SecurityLevel::NoAuthNoPriv)
                    .varbinds(vec![VarBind::new(
                        oid,
                        Value::OctetString(Bytes::from_static(b"unauthenticated")),
                    )])
                    .build()
            }),
        ],
    )
    .await;

    let client = Client::builder(peer.addr(), auth_for(level))
        .timeout(LOOPBACK_TIMEOUT)
        .retry(Retry::none())
        .connect()
        .await
        .unwrap();
    let err = client
        .get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))
        .await
        .unwrap_err();
    assert!(
        matches!(*err, async_snmp::Error::Auth { .. }),
        "expected Auth error, got: {err}"
    );
    peer.finish().await.unwrap();
}

/// An ordinary Response at a lower security level must not use the
/// lower-security Report policy path. It is rejected after processing at its
/// received level.
#[tokio::test]
async fn v3_auth_priv_client_rejects_auth_no_priv_response() {
    let requested_level = SecurityLevel::AuthPriv;
    let received_level = SecurityLevel::AuthNoPriv;
    let engine = engine_for(requested_level);
    let response_engine = engine.clone();
    let peer = ScriptedV3Peer::udp(
        engine.clone(),
        vec![
            discovery_step(engine),
            ScriptStep::reply(move |request| {
                V3ReplyBuilder::response_to(request, &response_engine)
                    .security_level(received_level)
                    .build()
            }),
        ],
    )
    .await;

    let client = Client::builder(peer.addr(), auth_for(requested_level))
        .timeout(LOOPBACK_TIMEOUT)
        .retry(Retry::none())
        .connect()
        .await
        .unwrap();
    let err = client
        .get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))
        .await
        .unwrap_err();
    assert!(
        matches!(*err, async_snmp::Error::MalformedResponse { .. }),
        "lower-security ordinary Response must not be accepted: {err}"
    );
    peer.finish().await.unwrap();
}

/// An encrypted authPriv Report must be decrypted and classified as a
/// Report (here a terminal credential failure), not rejected as a
/// malformed non-Response.
#[tokio::test]
async fn v3_auth_priv_client_classifies_encrypted_report() {
    let level = SecurityLevel::AuthPriv;
    let engine = engine_for(level);
    let report_engine = engine.clone();
    let peer = ScriptedV3Peer::udp(
        engine.clone(),
        vec![
            discovery_step(engine.clone()),
            ScriptStep::reply(move |request| {
                V3ReplyBuilder::report_to(
                    request,
                    &report_engine,
                    report_oids::unknown_user_names(),
                    1,
                )
                .security_level(SecurityLevel::AuthPriv)
                .build()
            }),
        ],
    )
    .await;

    let client = Client::builder(peer.addr(), auth_for(level))
        .timeout(LOOPBACK_TIMEOUT)
        .retry(Retry::none())
        .connect()
        .await
        .unwrap();
    let err = client
        .get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))
        .await
        .unwrap_err();
    assert!(
        matches!(*err, async_snmp::Error::Auth { .. }),
        "encrypted Report must classify as a credential failure, got: {err}"
    );
    peer.finish().await.unwrap();
}

/// Reserved and reportable flag bits in a reply do not change the derived
/// security level: an authNoPriv response carrying an extra reserved bit is
/// still verified and accepted.
#[tokio::test]
async fn v3_reserved_flag_bits_in_reply_ignored_for_level() {
    let level = SecurityLevel::AuthNoPriv;
    let engine = engine_for(level);
    let response_engine = engine.clone();
    let peer = ScriptedV3Peer::udp(
        engine.clone(),
        vec![
            discovery_step(engine.clone()),
            ScriptStep::reply(move |request| {
                let oid = request.scoped_pdu.as_ref().unwrap().pdu.varbinds[0]
                    .oid
                    .clone();
                V3ReplyBuilder::response_to(request, &response_engine)
                    // auth bit plus reportable and a reserved bit
                    .raw_msg_flags(0x01 | 0x04 | 0x08)
                    .varbinds(vec![VarBind::new(
                        oid,
                        Value::OctetString(Bytes::from_static(b"reserved bits ok")),
                    )])
                    .build()
            }),
        ],
    )
    .await;

    let client = Client::builder(peer.addr(), auth_for(level))
        .timeout(LOOPBACK_TIMEOUT)
        .retry(Retry::none())
        .connect()
        .await
        .unwrap();
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert_eq!(result.value.as_str(), Some("reserved bits ok"));
    peer.finish().await.unwrap();
}

#[tokio::test]
async fn v3_scripted_udp_timeout_retry_count() {
    let level = SecurityLevel::AuthNoPriv;
    let engine = engine_for(level);
    let peer = ScriptedV3Peer::udp(
        engine.clone(),
        vec![
            discovery_step(engine.clone()),
            ScriptStep::silence(),
            ScriptStep::silence(),
            response_step(engine, "after retries"),
        ],
    )
    .await;
    let log = peer.log();

    let client = Client::builder(peer.addr(), auth_for(level))
        .timeout(LOOPBACK_TIMEOUT)
        .retry(Retry::fixed(2, Duration::ZERO))
        .connect()
        .await
        .unwrap();
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert_eq!(result.value.as_str(), Some("after retries"));

    peer.finish().await.unwrap();
    let requests = log.snapshot();
    assert_eq!(requests.len(), 4);
    let attempts = &requests[1..];
    assert_ne!(
        attempts[0].global_data.msg_id,
        attempts[1].global_data.msg_id
    );
    assert_ne!(
        attempts[1].global_data.msg_id,
        attempts[2].global_data.msg_id
    );
    assert_eq!(
        attempts[0].scoped_pdu.as_ref().unwrap().pdu.request_id,
        attempts[1].scoped_pdu.as_ref().unwrap().pdu.request_id
    );
    assert_eq!(
        attempts[1].scoped_pdu.as_ref().unwrap().pdu.request_id,
        attempts[2].scoped_pdu.as_ref().unwrap().pdu.request_id
    );
}

#[tokio::test]
async fn v3_udp_pending_map_ignores_wrong_ids_before_correlated_response() {
    let level = SecurityLevel::NoAuthNoPriv;
    let engine = engine_for(level);
    let response_engine = engine.clone();
    let peer = ScriptedV3Peer::udp(
        engine.clone(),
        vec![
            discovery_step(engine),
            ScriptStep::replies(move |request| {
                let stale = V3ReplyBuilder::response_to(request, &response_engine)
                    .msg_id(request.global_data.msg_id - 1)
                    .build()?;
                let future = V3ReplyBuilder::response_to(request, &response_engine)
                    .msg_id(request.global_data.msg_id + 1)
                    .build()?;
                let matching = V3ReplyBuilder::response_to(request, &response_engine).build()?;
                Ok(vec![stale, future, matching])
            }),
        ],
    )
    .await;

    let client = Client::builder(peer.addr(), auth_for(level))
        .timeout(LOOPBACK_TIMEOUT)
        .retry(Retry::none())
        .connect()
        .await
        .unwrap();
    client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    peer.finish().await.unwrap();
}

#[tokio::test]
async fn v3_tcp_rejects_wrong_response_msg_id() {
    let level = SecurityLevel::NoAuthNoPriv;
    let engine = engine_for(level);
    let response_engine = engine.clone();
    let peer = ScriptedV3Peer::tcp(
        engine.clone(),
        vec![
            discovery_step(engine),
            ScriptStep::reply(move |request| {
                V3ReplyBuilder::response_to(request, &response_engine)
                    .msg_id(request.global_data.msg_id + 1)
                    .build()
            }),
        ],
    )
    .await;

    let client = Client::builder(peer.addr(), auth_for(level))
        .timeout(LOOPBACK_TIMEOUT)
        .connect_tcp()
        .await
        .unwrap();
    let err = client
        .get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))
        .await
        .unwrap_err();
    assert!(
        matches!(*err, async_snmp::Error::MalformedResponse { .. }),
        "wrong TCP msgID must be terminal, got: {err}"
    );
    peer.finish().await.unwrap();
}

#[tokio::test]
async fn v3_tcp_rejects_wrong_discovery_msg_id() {
    let level = SecurityLevel::NoAuthNoPriv;
    let engine = engine_for(level);
    let report_engine = engine.clone();
    let peer = ScriptedV3Peer::tcp(
        engine,
        vec![ScriptStep::reply(move |request| {
            V3ReplyBuilder::report_to(
                request,
                &report_engine,
                report_oids::unknown_engine_ids(),
                1,
            )
            .msg_id(request.global_data.msg_id - 1)
            .build()
        })],
    )
    .await;

    let client = Client::builder(peer.addr(), auth_for(level))
        .timeout(LOOPBACK_TIMEOUT)
        .connect_tcp()
        .await
        .unwrap();
    let err = client
        .get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))
        .await
        .unwrap_err();
    assert!(matches!(*err, async_snmp::Error::MalformedResponse { .. }));
    peer.finish().await.unwrap();
}

#[tokio::test]
async fn v3_custom_transport_rejects_prior_attempt_msg_id() {
    let level = SecurityLevel::NoAuthNoPriv;
    let engine = engine_for(level);
    let response_engine = engine.clone();
    let transport = ScriptedTransport::new(
        engine.clone(),
        vec![
            discovery_step(engine),
            ScriptStep::reply(move |request| {
                V3ReplyBuilder::response_to(request, &response_engine)
                    .msg_id(request.global_data.msg_id - 1)
                    .build()
            }),
        ],
        100,
        false,
    );
    let log = transport.log();
    let client = custom_client(transport, level, None);

    let err = client
        .get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))
        .await
        .unwrap_err();
    assert!(
        matches!(*err, async_snmp::Error::MalformedResponse { .. }),
        "matching PDU request-id must not rescue a prior msgID: {err}"
    );
    let requests = log.snapshot();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[0].global_data.msg_id + 1,
        requests[1].global_data.msg_id
    );
}

#[tokio::test]
async fn v3_custom_transport_rejects_future_discovery_msg_id() {
    let level = SecurityLevel::NoAuthNoPriv;
    let engine = engine_for(level);
    let report_engine = engine.clone();
    let transport = ScriptedTransport::new(
        engine,
        vec![ScriptStep::reply(move |request| {
            V3ReplyBuilder::report_to(
                request,
                &report_engine,
                report_oids::unknown_engine_ids(),
                1,
            )
            .msg_id(request.global_data.msg_id + 1)
            .build()
        })],
        100,
        false,
    );
    let client = custom_client(transport, level, None);

    let err = client
        .get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))
        .await
        .unwrap_err();
    assert!(matches!(*err, async_snmp::Error::MalformedResponse { .. }));
}

/// RFC 3412 Section 7.2 processes the Security Model before parsing the
/// scopedPDU and correlating an Internal-class Report by msgID. The unknown
/// target on this error distinguishes USM engine-ID validation from the later
/// peer-bound parse/correlation failures.
#[tokio::test]
async fn v3_discovery_usm_processing_precedes_parse_and_correlation() {
    let level = SecurityLevel::NoAuthNoPriv;
    let engine = engine_for(level);
    let transport = ScriptedTransport::new(
        engine,
        vec![ScriptStep::reply(move |request| {
            let invalid_usm = raw_ber::usm_security_params(&[], &[0], &[0], &[], &[], &[]);
            Ok(raw_ber::v3_message(
                &raw_ber::signed_integer_content(request.global_data.msg_id + 1),
                &[0x00, 0xff, 0xe3],
                &[0],
                &[3],
                &invalid_usm,
                &raw_ber::tlv(0x05, &[]),
            ))
        })],
        100,
        false,
    );
    let client = custom_client(transport, level, None);

    let err = client
        .get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))
        .await
        .unwrap_err();
    match *err {
        async_snmp::Error::MalformedResponse { target } => {
            assert_eq!(target, std::net::SocketAddr::from(([0, 0, 0, 0], 0)));
        }
        _ => panic!("invalid discovery USM parameters must be rejected first: {err}"),
    }
}

#[tokio::test]
async fn v3_wrong_report_msg_id_does_not_trigger_correction() {
    let level = SecurityLevel::AuthNoPriv;
    let engine = engine_for(level);
    let report_engine = engine.clone();
    let advanced_engine = engine.clone().boots_time(8, 10);
    let transport = ScriptedTransport::new(
        engine.clone(),
        vec![
            discovery_step(engine),
            ScriptStep::reply(move |request| {
                V3ReplyBuilder::report_to(
                    request,
                    &report_engine,
                    report_oids::not_in_time_windows(),
                    1,
                )
                .security_level(level)
                .engine_boots(8)
                .engine_time(10)
                .msg_id(request.global_data.msg_id - 1)
                .build()
            }),
            response_step(advanced_engine, "state advanced before correlation"),
        ],
        100,
        false,
    );
    let log = transport.log();
    let mut security = user_for(level);
    security = security.context_name("requested-context");
    let client = Client::new(
        transport,
        ClientConfig {
            version: Version::V3,
            timeout: LOOPBACK_TIMEOUT,
            retry: Retry::fixed(1, Duration::ZERO),
            v3_security: Some(security),
            ..ClientConfig::default()
        },
    );

    let err = client
        .get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))
        .await
        .unwrap_err();
    assert!(
        matches!(*err, async_snmp::Error::MalformedResponse { .. }),
        "wrong-ID Report with request-id zero must not be acted on: {err}"
    );
    assert_eq!(
        log.len(),
        2,
        "wrong-ID Report must not add a corrected send"
    );

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert_eq!(
        result.value.as_str(),
        Some("state advanced before correlation")
    );
    let requests = log.snapshot();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[2].usm.engine_boots, 8);
    assert!(requests[2].usm.engine_time >= 10);
}

#[tokio::test]
async fn v3_rejects_wrong_scoped_context_at_every_security_level() {
    for level in [
        SecurityLevel::NoAuthNoPriv,
        SecurityLevel::AuthNoPriv,
        SecurityLevel::AuthPriv,
    ] {
        for wrong_context_name in [false, true] {
            let engine = engine_for(level);
            let response_engine = engine.clone();
            let transport = ScriptedTransport::new(
                engine.clone(),
                vec![
                    discovery_step(engine),
                    ScriptStep::reply(move |request| {
                        let builder = V3ReplyBuilder::response_to(request, &response_engine);
                        if wrong_context_name {
                            builder
                                .context_name(Bytes::from_static(b"wrong-context"))
                                .build()
                        } else {
                            builder
                                .context_engine_id(Bytes::from_static(
                                    b"\x80\x00\x7e\xd9\x05wrong-context-engine",
                                ))
                                .build()
                        }
                    }),
                ],
                100,
                false,
            );
            let client = custom_client(transport, level, Some("requested-context"));

            let err = client
                .get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))
                .await
                .unwrap_err();
            assert!(
                matches!(*err, async_snmp::Error::MalformedResponse { .. }),
                "{level:?}, wrong_context_name={wrong_context_name}: {err}"
            );
        }
    }
}

#[tokio::test]
async fn v3_custom_transport_accepts_matching_ids_and_context() {
    let level = SecurityLevel::AuthPriv;
    let engine = engine_for(level);
    let transport = ScriptedTransport::new(
        engine.clone(),
        vec![
            discovery_step(engine.clone()),
            response_step(engine, "custom response"),
        ],
        100,
        false,
    );
    let client = custom_client(transport, level, Some("requested-context"));

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert_eq!(result.value.as_str(), Some("custom response"));
}

#[tokio::test]
async fn scripted_transport_returns_arbitrary_bytes_without_id_filtering() {
    let request = V3Message::discovery_request(41).encode();
    let expected = Bytes::from_static(b"arbitrary response bytes");
    let transport = ScriptedTransport::new(
        TestV3Engine::new(Bytes::from_static(ENGINE_ID)),
        vec![ScriptStep::bytes(expected.clone())],
        100,
        false,
    );
    let log = transport.log();

    let (actual, _) = Transport::request(&transport, &request, 999).await.unwrap();

    assert_eq!(actual, expected);
    assert_eq!(transport.remaining_steps(), 0);
    let requests = log.snapshot();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].global_data.msg_id, 41);
    assert_eq!(requests[0].transport_request_id, Some(999));
}

#[tokio::test]
async fn report_builder_uses_reporting_engine_context() {
    let engine = engine_for(SecurityLevel::NoAuthNoPriv);
    let expected_engine_id = engine.engine_id.clone();
    let transport =
        ScriptedTransport::new(engine.clone(), vec![discovery_step(engine)], 100, false);
    let request = V3Message::discovery_request(41).encode();

    let (response, _) = Transport::request(&transport, &request, 41).await.unwrap();
    let response = V3Message::decode(response).unwrap();
    let V3MessageData::Plaintext(scoped) = response.data else {
        panic!("Report must have a plaintext scopedPDU");
    };

    assert_eq!(scoped.context_engine_id, expected_engine_id);
    assert!(scoped.context_name.is_empty());
}

#[test]
fn raw_ber_targets_invalid_flags_and_oversized_msg_ids() {
    let original = V3Message::discovery_request(7).encode().to_vec();
    let mut message = original.clone();
    raw_ber::patch_msg_flags(&mut message, 0x82).unwrap();

    let changes: Vec<_> = original
        .iter()
        .zip(&message)
        .enumerate()
        .filter_map(|(offset, (before, after))| {
            (before != after).then_some((offset, *before, *after))
        })
        .collect();
    assert_eq!(changes.len(), 1);
    let (offset, before, after) = changes[0];
    assert_eq!((before, after), (0x04, 0x82));
    assert_eq!(&message[offset - 2..offset], &[0x04, 0x01]);
    assert!(V3Message::decode(Bytes::from(message)).is_err());

    let oversized_msg_id = [1, 0, 0, 0, 0];
    let encoded_msg_id = raw_ber::integer_from_content(&oversized_msg_id);
    assert_eq!(encoded_msg_id, vec![0x02, 0x05, 1, 0, 0, 0, 0]);
    let usm = raw_ber::usm_security_params(&[], &[0], &[0], &[], &[], &[]);
    let message = raw_ber::v3_message(
        &oversized_msg_id,
        &[0x00, 0xff, 0xe3],
        &[0x04],
        &[3],
        &usm,
        &raw_ber::tlv(0x05, &[]),
    );
    assert_eq!(
        message
            .windows(encoded_msg_id.len())
            .filter(|window| *window == encoded_msg_id.as_slice())
            .count(),
        1,
        "the complete message must contain the oversized msgID"
    );
}
