//! Scripted-peer characterization for the SNMPv3 client receive path.

mod common;

use async_snmp::message::{SecurityLevel, V3Message, V3MessageData};
use async_snmp::transport::Transport;
use async_snmp::v3::{AuthProtocol, PrivProtocol, report_oids};
use async_snmp::{Auth, Client, MasterKeys, Retry, UsmConfig, Value, VarBind, oid};
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
