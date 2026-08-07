//! Scripted-peer characterization for the SNMPv3 client receive path.

mod common;

use async_snmp::message::{ScopedPdu, SecurityLevel, V3Message, V3MessageData};
use async_snmp::transport::Transport;
use async_snmp::v3::{AuthProtocol, EngineState, PrivProtocol, ReportStatus, report_oids};
use async_snmp::{
    Auth, Client, ClientConfig, EngineCache, MasterKeys, ReceiveLimits, Retry, UsmConfig, Value,
    VarBind, oid,
};
use bytes::Bytes;
use common::v3::{
    ScriptStep, ScriptedTransport, ScriptedV3Peer, TestV3Engine, V3ReplyBuilder, raw_ber,
};
use std::sync::{Arc, Mutex};
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
            .auth_priv(
                AuthProtocol::Sha256,
                AUTH_PASSWORD,
                PrivProtocol::Aes128,
                PRIV_PASSWORD,
            )
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
    custom_client_with_compatibility(transport, level, context_name, false)
}

fn custom_client_with_compatibility(
    transport: ScriptedTransport,
    level: SecurityLevel,
    context_name: Option<&'static str>,
    allow_unauthenticated_v3_time_correction: bool,
) -> Client<ScriptedTransport> {
    let mut security = user_for(level);
    if let Some(context_name) = context_name {
        security = security.context_name(context_name);
    }
    Client::new(
        transport,
        ClientConfig {
            auth: Auth::Usm(security),
            timeout: LOOPBACK_TIMEOUT,
            retry: Retry::none(),
            allow_unauthenticated_v3_time_correction,
            ..ClientConfig::default()
        },
    )
    .expect("valid client config")
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
    assert_eq!(result.varbinds[0].value.as_str(), Some("scripted response"));

    assert_eq!(requests.len(), 2);
    assert!(requests[0].usm.engine_id.is_empty());
    assert!(requests[0].usm.username.is_empty());
    assert_eq!(requests[1].usm.engine_id.as_ref(), ENGINE_ID);
    assert_eq!(
        (requests[1].usm.engine_boots, requests[1].usm.engine_time),
        (0, 0),
        "unauthenticated discovery must not seed trusted time"
    );
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
async fn v3_discovery_advertises_active_transport_receive_limit() {
    let level = SecurityLevel::NoAuthNoPriv;
    let engine = engine_for(level);
    let receive_limits = ReceiveLimits::tcp(10 * 1024 * 1024).unwrap();
    let transport = ScriptedTransport::new_with_receive_limits(
        engine.clone(),
        vec![
            discovery_step(engine.clone()),
            response_step(engine, "custom limit response"),
        ],
        100,
        true,
        receive_limits,
    );
    let log = transport.log();
    let client = custom_client(transport, level, None);

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert_eq!(
        result.varbinds[0].value.as_str(),
        Some("custom limit response")
    );

    let requests = log.snapshot();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[0].global_data.msg_max_size,
        receive_limits.advertised(),
        "discovery must advertise the active transport capacity"
    );
    assert_eq!(
        requests[1].global_data.msg_max_size,
        receive_limits.advertised(),
        "established requests must use the same transport capacity"
    );
}

type DiscoveryMutation = Box<dyn FnOnce(V3ReplyBuilder) -> V3ReplyBuilder + Send>;

#[tokio::test]
async fn v3_discovery_rejects_noncanonical_security_and_report_shapes() {
    let cases: Vec<(&str, DiscoveryMutation)> = vec![
        (
            "authNoPriv level",
            Box::new(|reply| {
                reply
                    .security_level(SecurityLevel::AuthNoPriv)
                    .username(USERNAME)
                    .signing_user(user_for(SecurityLevel::AuthNoPriv))
            }),
        ),
        (
            "authPriv level",
            Box::new(|reply| {
                reply
                    .security_level(SecurityLevel::AuthPriv)
                    .username(USERNAME)
                    .signing_user(user_for(SecurityLevel::AuthPriv))
            }),
        ),
        ("username", Box::new(|reply| reply.username(USERNAME))),
        (
            "authentication parameters",
            Box::new(|reply| reply.auth_params(Bytes::from_static(b"unexpected"))),
        ),
        (
            "privacy parameters",
            Box::new(|reply| reply.priv_params(Bytes::from_static(b"unexpected"))),
        ),
        (
            "context engine ID",
            Box::new(|reply| reply.context_engine_id(Bytes::from_static(b"wrong-context"))),
        ),
        (
            "context name",
            Box::new(|reply| reply.context_name(Bytes::from_static(b"ctx"))),
        ),
        (
            "ordinary Response PDU",
            Box::new(|reply| reply.pdu_type(async_snmp::pdu::PduType::Response)),
        ),
        ("nonzero status", Box::new(|reply| reply.error_status(1))),
        ("nonzero index", Box::new(|reply| reply.error_index(1))),
        (
            "empty varbind list",
            Box::new(|reply| reply.varbinds(vec![])),
        ),
        (
            "wrong report OID",
            Box::new(|reply| {
                reply.varbinds(vec![VarBind::new(
                    report_oids::not_in_time_windows(),
                    Value::Counter32(1),
                )])
            }),
        ),
        (
            "wrong report value type",
            Box::new(|reply| {
                reply.varbinds(vec![VarBind::new(
                    report_oids::unknown_engine_ids(),
                    Value::Integer(1),
                )])
            }),
        ),
        (
            "multiple varbinds",
            Box::new(|reply| {
                reply.varbinds(vec![
                    VarBind::new(report_oids::unknown_engine_ids(), Value::Counter32(1)),
                    VarBind::new(report_oids::not_in_time_windows(), Value::Counter32(1)),
                ])
            }),
        ),
        (
            "short engine ID",
            Box::new(|reply| reply.engine_id(Bytes::from_static(b"tiny"))),
        ),
        (
            "all-zero engine ID",
            Box::new(|reply| reply.engine_id(Bytes::from_static(b"\0\0\0\0\0"))),
        ),
        (
            "all-ff engine ID",
            Box::new(|reply| reply.engine_id(Bytes::from_static(b"\xff\xff\xff\xff\xff"))),
        ),
        (
            "overlong engine ID",
            Box::new(|reply| reply.engine_id(Bytes::from(vec![1; 33]))),
        ),
    ];

    for (case, mutate) in cases {
        let engine = engine_for(SecurityLevel::NoAuthNoPriv);
        let reply_engine = engine.clone();
        let step = ScriptStep::reply(move |request| {
            mutate(V3ReplyBuilder::report_to(
                request,
                &reply_engine,
                report_oids::unknown_engine_ids(),
                1,
            ))
            .build()
        });
        let transport = ScriptedTransport::new(engine, vec![step], 100, false);
        let client = custom_client(transport.clone(), SecurityLevel::NoAuthNoPriv, None);

        let error = client
            .get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))
            .await
            .unwrap_err();
        assert!(
            matches!(*error, async_snmp::Error::MalformedResponse { .. }),
            "{case} should be rejected as malformed, got {error}"
        );
        assert_eq!(transport.log().len(), 1, "{case} must not continue");
    }
}

#[tokio::test]
async fn v3_discovery_rejects_trailing_usm_security_parameter_data() {
    let engine = engine_for(SecurityLevel::NoAuthNoPriv);
    let reply_engine = engine.clone();
    let step = ScriptStep::reply(move |request| {
        let mut usm =
            raw_ber::usm_security_params(&reply_engine.engine_id, &[1], &[1], &[], &[], &[])
                .to_vec();
        usm.extend_from_slice(&[0x05, 0x00]);
        let scoped = ScopedPdu::new(
            reply_engine.engine_id.clone(),
            Bytes::new(),
            async_snmp::pdu::Pdu {
                pdu_type: async_snmp::pdu::PduType::Report,
                request_id: 0,
                error_status: 0,
                error_index: 0,
                varbinds: vec![VarBind::new(
                    report_oids::unknown_engine_ids(),
                    Value::Counter32(1),
                )],
            },
        )
        .encode_to_bytes()
        .unwrap();
        Ok(raw_ber::v3_message(
            &raw_ber::signed_integer_content(request.global_data.msg_id),
            &raw_ber::signed_integer_content(reply_engine.msg_max_size),
            &[0],
            &[3],
            &usm,
            &scoped,
        ))
    });
    let transport = ScriptedTransport::new(engine, vec![step], 100, false);
    let client = custom_client(transport, SecurityLevel::NoAuthNoPriv, None);

    let error = client
        .get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))
        .await
        .unwrap_err();
    assert!(matches!(
        *error,
        async_snmp::Error::MalformedResponse { .. }
    ));
}

#[tokio::test]
async fn v3_discovery_treats_reportable_flag_as_zero_on_report() {
    let level = SecurityLevel::NoAuthNoPriv;
    let engine = engine_for(level);
    let report_engine = engine.clone();
    let transport = ScriptedTransport::new(
        engine.clone(),
        vec![
            ScriptStep::reply(move |request| {
                V3ReplyBuilder::report_to(
                    request,
                    &report_engine,
                    report_oids::unknown_engine_ids(),
                    1,
                )
                .reportable(true)
                .build()
            }),
            response_step(engine, "accepted"),
        ],
        100,
        false,
    );
    let client = custom_client(transport, level, None);

    let response = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert_eq!(response.varbinds[0].value.as_str(), Some("accepted"));
}

#[tokio::test]
async fn v3_udp_discovery_source_policy_is_builder_configurable() {
    let level = SecurityLevel::NoAuthNoPriv;

    let permissive_engine = engine_for(level);
    let reply_engine = permissive_engine.clone();
    let peer = ScriptedV3Peer::udp(
        permissive_engine,
        vec![
            ScriptStep::reply_from_other_source(move |request| {
                V3ReplyBuilder::report_to(
                    request,
                    &reply_engine,
                    report_oids::unknown_engine_ids(),
                    1,
                )
                .build()
            }),
            response_step(engine_for(level), "off-source discovery accepted"),
        ],
    )
    .await;
    let client = Client::builder(peer.addr(), auth_for(level))
        .timeout(LOOPBACK_TIMEOUT)
        .retry(Retry::none())
        .connect()
        .await
        .unwrap();
    let response = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert_eq!(
        response.varbinds[0].value.as_str(),
        Some("off-source discovery accepted")
    );
    peer.finish().await.unwrap();

    let strict_engine = engine_for(level);
    let reply_engine = strict_engine.clone();
    let peer = ScriptedV3Peer::udp(
        strict_engine,
        vec![ScriptStep::reply_from_other_source(move |request| {
            V3ReplyBuilder::report_to(request, &reply_engine, report_oids::unknown_engine_ids(), 1)
                .build()
        })],
    )
    .await;
    let log = peer.log();
    let client = Client::builder(peer.addr(), auth_for(level))
        .timeout(LOOPBACK_TIMEOUT)
        .retry(Retry::none())
        .strict_source(true)
        .connect()
        .await
        .unwrap();
    let error = client
        .get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))
        .await
        .unwrap_err();
    assert!(matches!(*error, async_snmp::Error::Timeout { .. }));
    assert_eq!(log.len(), 1, "off-source discovery must not be adopted");
    peer.finish().await.unwrap();
}

#[tokio::test]
async fn v3_established_identity_ignores_ordinary_discovery_traffic() {
    let level = SecurityLevel::NoAuthNoPriv;
    let engine_a = engine_for(level);
    let engine_b = TestV3Engine::new(Bytes::from_static(
        b"\x80\x00\x7e\xd9\x05replacement-engine",
    ))
    .user(user_for(level));
    let report_engine = engine_b.clone();
    let transport = ScriptedTransport::new(
        engine_a.clone(),
        vec![
            discovery_step(engine_a.clone()),
            response_step(engine_a.clone(), "before"),
            ScriptStep::reply(move |request| {
                V3ReplyBuilder::report_to(
                    request,
                    &report_engine,
                    report_oids::unknown_engine_ids(),
                    2,
                )
                .build()
            }),
            response_step(engine_a, "after"),
        ],
        100,
        false,
    );
    let client = custom_client(transport.clone(), level, None);
    let oid = oid!(1, 3, 6, 1, 2, 1, 1, 1, 0);

    assert_eq!(
        client.get(&oid).await.unwrap().varbinds[0].value.as_str(),
        Some("before")
    );
    let error = client.get(&oid).await.unwrap_err();
    assert!(matches!(*error, async_snmp::Error::Auth { .. }));
    assert_eq!(
        client.get(&oid).await.unwrap().varbinds[0].value.as_str(),
        Some("after")
    );

    let requests = transport.log().snapshot();
    assert_eq!(requests.len(), 4);
    assert_eq!(requests[1].usm.engine_id.as_ref(), ENGINE_ID);
    assert_eq!(requests[2].usm.engine_id.as_ref(), ENGINE_ID);
    assert_eq!(requests[3].usm.engine_id.as_ref(), ENGINE_ID);
}

#[tokio::test]
async fn v3_explicit_rediscovery_replaces_identity_and_cache_mapping() {
    let level = SecurityLevel::AuthNoPriv;
    let engine_a = engine_for(level);
    let replacement_id = Bytes::from_static(b"\x80\x00\x7e\xd9\x05replacement-engine");
    let engine_b = TestV3Engine::new(replacement_id.clone()).user(user_for(level));
    let cache = Arc::new(EngineCache::new());
    let stale_cache = cache.clone();
    let stale_identity = EngineState::discovered(
        engine_a.engine_id.clone(),
        async_snmp::MessageSize::new(65_507).unwrap(),
    );
    let target = "127.0.0.1:161".parse().unwrap();
    let report_engine = engine_b.clone();
    let transport = ScriptedTransport::new(
        engine_a.clone(),
        vec![
            discovery_step(engine_a.clone()),
            response_step(engine_a, "before"),
            ScriptStep::reply(move |request| {
                // Model an independent stale client refreshing engine A's
                // mapping while rediscovery is in flight.
                stale_cache.insert(target, stale_identity);
                V3ReplyBuilder::report_to(
                    request,
                    &report_engine,
                    report_oids::unknown_engine_ids(),
                    1,
                )
                .build()
            }),
            response_step(engine_b, "after"),
        ],
        100,
        false,
    );
    let client = Client::with_engine_cache(
        transport.clone(),
        ClientConfig {
            auth: Auth::Usm(user_for(level)),
            timeout: LOOPBACK_TIMEOUT,
            retry: Retry::none(),
            ..ClientConfig::default()
        },
        cache.clone(),
    )
    .expect("valid client config");
    let oid = oid!(1, 3, 6, 1, 2, 1, 1, 1, 0);

    assert_eq!(
        client.get(&oid).await.unwrap().varbinds[0].value.as_str(),
        Some("before")
    );
    assert_eq!(
        cache.get(&client.peer_addr()).unwrap().engine_id().as_ref(),
        ENGINE_ID
    );

    client.rediscover_engine().await.unwrap();
    assert_eq!(
        cache.get(&client.peer_addr()).unwrap().engine_id(),
        replacement_id.as_ref()
    );
    assert_eq!(
        client.get(&oid).await.unwrap().varbinds[0].value.as_str(),
        Some("after")
    );

    let requests = transport.log().snapshot();
    assert_eq!(requests.len(), 4);
    assert!(requests[0].usm.engine_id.is_empty());
    assert_eq!(requests[1].usm.engine_id.as_ref(), ENGINE_ID);
    assert!(requests[2].usm.engine_id.is_empty());
    assert_eq!(requests[3].usm.engine_id, replacement_id);
}

#[tokio::test]
async fn v3_failed_rediscovery_preserves_live_identity_and_cache_mapping() {
    let level = SecurityLevel::NoAuthNoPriv;
    let engine_a = engine_for(level);
    let replacement_id = Bytes::from_static(b"replacement-engine");
    let engine_b = TestV3Engine::new(replacement_id).user(user_for(level));
    let cache = Arc::new(EngineCache::new());
    let stale_cache = cache.clone();
    let stale_identity = EngineState::discovered(
        engine_a.engine_id.clone(),
        async_snmp::MessageSize::new(65_507).unwrap(),
    );
    let target = "127.0.0.1:161".parse().unwrap();
    let report_engine = engine_b.clone();
    let transport = ScriptedTransport::new(
        engine_a.clone(),
        vec![
            discovery_step(engine_a.clone()),
            response_step(engine_a.clone(), "before"),
            ScriptStep::reply(move |request| {
                stale_cache.insert(target, stale_identity);
                V3ReplyBuilder::report_to(
                    request,
                    &report_engine,
                    report_oids::unknown_engine_ids(),
                    1,
                )
                .context_name(Bytes::from_static(b"invalid"))
                .build()
            }),
            response_step(engine_a, "after"),
        ],
        100,
        false,
    );
    let client = Client::with_engine_cache(
        transport.clone(),
        ClientConfig {
            auth: Auth::Usm(user_for(level)),
            timeout: LOOPBACK_TIMEOUT,
            retry: Retry::none(),
            ..ClientConfig::default()
        },
        cache.clone(),
    )
    .expect("valid client config");
    let oid = oid!(1, 3, 6, 1, 2, 1, 1, 1, 0);

    assert_eq!(
        client.get(&oid).await.unwrap().varbinds[0].value.as_str(),
        Some("before")
    );

    let error = client.rediscover_engine().await.unwrap_err();
    assert!(matches!(
        *error,
        async_snmp::Error::MalformedResponse { .. }
    ));
    assert_eq!(
        cache.get(&client.peer_addr()).unwrap().engine_id().as_ref(),
        ENGINE_ID
    );

    // Removing the shared mapping proves the live generation survived rather
    // than being silently reloaded from a stale cache entry.
    cache.remove(&client.peer_addr());
    assert_eq!(
        client.get(&oid).await.unwrap().varbinds[0].value.as_str(),
        Some("after")
    );

    let requests = transport.log().snapshot();
    assert_eq!(requests.len(), 4);
    assert!(requests[2].usm.engine_id.is_empty());
    assert_eq!(requests[3].usm.engine_id.as_ref(), ENGINE_ID);
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
    assert_eq!(result.varbinds[0].value.as_str(), Some("tcp response"));

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
        .retry(Retry::none())
        .connect()
        .await
        .unwrap();
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert_eq!(
        result.varbinds[0].value.as_str(),
        Some("corrected response")
    );

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
    assert_ne!(
        first.scoped_pdu.as_ref().unwrap().pdu.request_id,
        corrected.scoped_pdu.as_ref().unwrap().pdu.request_id
    );
    assert_eq!(
        (corrected.usm.engine_boots, corrected.usm.engine_time),
        (8, 10)
    );
}

#[tokio::test]
async fn v3_unauthenticated_time_report_compatibility_is_explicit() {
    let level = SecurityLevel::AuthNoPriv;
    let engine = engine_for(level);
    let report_engine = engine.clone();
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
                .build()
            }),
        ],
        175,
        false,
    );
    let log = transport.log();
    let client = custom_client(transport, level, None);

    let err = client
        .get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))
        .await
        .unwrap_err();
    assert!(
        matches!(*err, async_snmp::Error::Auth { .. }),
        "the compatibility path must remain disabled by default: {err}"
    );
    assert_eq!(log.len(), 2, "a disabled path must not send a correction");
}

#[tokio::test]
async fn v3_udp_unauthenticated_time_report_gets_packet_local_correction() {
    let level = SecurityLevel::AuthPriv;
    let engine = engine_for(level);
    let report_engine = engine.clone();
    let corrected_response_engine = engine.clone();
    let final_response_engine = engine.clone();
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
                .engine_boots(7)
                .engine_time(100)
                .build()
            }),
            response_step(corrected_response_engine, "compatibility response"),
            response_step(final_response_engine, "converged response"),
        ],
    )
    .await;
    let log = peer.log();

    let client = Client::builder(peer.addr(), auth_for(level))
        .timeout(LOOPBACK_TIMEOUT)
        .retry(Retry::none())
        .allow_unauthenticated_v3_time_correction(true)
        .connect()
        .await
        .unwrap();
    let first = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert_eq!(
        first.varbinds[0].value.as_str(),
        Some("compatibility response")
    );
    let second = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert_eq!(
        second.varbinds[0].value.as_str(),
        Some("converged response")
    );

    peer.finish().await.unwrap();
    let requests = log.snapshot();
    assert_eq!(requests.len(), 4);
    assert_eq!(
        (requests[1].usm.engine_boots, requests[1].usm.engine_time),
        (0, 0)
    );
    assert_eq!(
        (requests[2].usm.engine_boots, requests[2].usm.engine_time),
        (7, 100),
        "the unauthenticated tuple applies to the corrected packet"
    );
    assert_eq!(requests[2].authentication_valid, Some(true));
    assert_eq!(
        requests[2].global_data.msg_flags.security_level,
        SecurityLevel::AuthPriv
    );
    assert_ne!(
        requests[1].global_data.msg_id,
        requests[2].global_data.msg_id
    );
    assert_ne!(
        requests[1].scoped_pdu.as_ref().unwrap().pdu.request_id,
        requests[2].scoped_pdu.as_ref().unwrap().pdu.request_id
    );
    assert_eq!(requests[3].usm.engine_boots, 7);
    assert!(requests[3].usm.engine_time >= 100);
}

#[tokio::test]
async fn v3_udp_compatibility_respects_strict_source_policy() {
    let level = SecurityLevel::AuthNoPriv;
    let engine = engine_for(level);
    let report_engine = engine.clone();
    let peer = ScriptedV3Peer::udp(
        engine,
        vec![
            discovery_step(report_engine.clone()),
            ScriptStep::reply_from_other_source(move |request| {
                V3ReplyBuilder::report_to(
                    request,
                    &report_engine,
                    report_oids::not_in_time_windows(),
                    1,
                )
                .build()
            }),
        ],
    )
    .await;
    let log = peer.log();

    let client = Client::builder(peer.addr(), auth_for(level))
        .timeout(LOOPBACK_TIMEOUT)
        .retry(Retry::none())
        .strict_source(true)
        .allow_unauthenticated_v3_time_correction(true)
        .connect()
        .await
        .unwrap();
    let err = client
        .get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))
        .await
        .unwrap_err();
    assert!(matches!(*err, async_snmp::Error::Timeout { .. }));
    assert_eq!(log.len(), 2, "an off-source Report must not add a send");
    peer.finish().await.unwrap();
}

#[tokio::test]
async fn v3_tcp_unauthenticated_time_report_compatibility_succeeds() {
    let level = SecurityLevel::AuthNoPriv;
    let engine = engine_for(level);
    let report_engine = engine.clone();
    let response_engine = engine.clone();
    let peer = ScriptedV3Peer::tcp(
        engine,
        vec![
            discovery_step(report_engine.clone()),
            ScriptStep::reply(move |request| {
                V3ReplyBuilder::report_to(
                    request,
                    &report_engine,
                    report_oids::not_in_time_windows(),
                    2,
                )
                .engine_boots(7)
                .engine_time(100)
                .build()
            }),
            response_step(response_engine, "TCP compatibility response"),
        ],
    )
    .await;
    let log = peer.log();

    let client = Client::builder(peer.addr(), auth_for(level))
        .timeout(LOOPBACK_TIMEOUT)
        .retry(Retry::none())
        .allow_unauthenticated_v3_time_correction(true)
        .connect_tcp()
        .await
        .unwrap();
    let response = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert_eq!(
        response.varbinds[0].value.as_str(),
        Some("TCP compatibility response")
    );

    peer.finish().await.unwrap();
    let requests = log.snapshot();
    assert_eq!(requests.len(), 3);
    assert_eq!(
        (requests[2].usm.engine_boots, requests[2].usm.engine_time),
        (7, 100)
    );
    assert_eq!(requests[2].authentication_valid, Some(true));
}

#[tokio::test]
async fn v3_reliable_custom_transport_allows_packet_local_compatibility() {
    let level = SecurityLevel::AuthNoPriv;
    let engine = engine_for(level);
    let report_engine = engine.clone();
    let response_engine = engine.clone();
    let transport = ScriptedTransport::new(
        engine.clone(),
        vec![
            discovery_step(engine),
            ScriptStep::reply(move |request| {
                V3ReplyBuilder::report_to(
                    request,
                    &report_engine,
                    report_oids::not_in_time_windows(),
                    3,
                )
                .engine_boots(7)
                .engine_time(100)
                .build()
            }),
            response_step(response_engine, "custom compatibility response"),
        ],
        183,
        true,
    );
    let log = transport.log();
    let client = custom_client_with_compatibility(transport, level, None, true);

    let response = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert_eq!(
        response.varbinds[0].value.as_str(),
        Some("custom compatibility response")
    );
    let requests = log.snapshot();
    assert_eq!(requests.len(), 3);
    assert_eq!(
        (requests[2].usm.engine_boots, requests[2].usm.engine_time),
        (7, 100)
    );
    assert_eq!(requests[2].authentication_valid, Some(true));
    for request in requests {
        assert_eq!(
            request.transport_request_id,
            Some(request.global_data.msg_id)
        );
    }
}

#[tokio::test]
async fn v3_failed_packet_local_correction_preserves_trusted_time() {
    let level = SecurityLevel::AuthNoPriv;
    let engine = engine_for(level);
    let report_engine = engine.clone();
    let transport = ScriptedTransport::new(
        engine.clone(),
        vec![
            discovery_step(engine.clone()),
            response_step(engine.clone(), "established"),
            ScriptStep::reply(move |request| {
                V3ReplyBuilder::report_to(
                    request,
                    &report_engine,
                    report_oids::not_in_time_windows(),
                    3,
                )
                .engine_boots(1)
                .engine_time(2)
                .build()
            }),
            ScriptStep::silence(),
            response_step(engine, "state retained"),
        ],
        185,
        false,
    );
    let log = transport.log();
    let client = Client::new(
        transport,
        ClientConfig {
            auth: Auth::Usm(user_for(level)),
            timeout: LOOPBACK_TIMEOUT,
            retry: Retry::fixed(3, Duration::ZERO),
            allow_unauthenticated_v3_time_correction: true,
            ..ClientConfig::default()
        },
    )
    .expect("valid client config");

    client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    let err = client
        .get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))
        .await
        .unwrap_err();
    assert!(matches!(
        *err,
        async_snmp::Error::Timeout { retries: 0, .. }
    ));
    let response = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert_eq!(response.varbinds[0].value.as_str(), Some("state retained"));

    let requests = log.snapshot();
    assert_eq!(requests.len(), 5);
    assert_eq!(
        (requests[3].usm.engine_boots, requests[3].usm.engine_time),
        (1, 2),
        "the spoofable tuple may affect one packet"
    );
    assert_eq!(requests[3].authentication_valid, Some(true));
    assert_eq!(requests[4].usm.engine_boots, 7);
    assert!(
        requests[4].usm.engine_time >= 100,
        "the lower unauthenticated tuple must not enter trusted state"
    );
}

#[tokio::test]
async fn v3_repeated_unauthenticated_time_report_is_typed_and_bounded() {
    let level = SecurityLevel::AuthNoPriv;
    let engine = engine_for(level);
    let first_report_engine = engine.clone();
    let second_report_engine = engine.clone();
    let transport = ScriptedTransport::new(
        engine.clone(),
        vec![
            discovery_step(engine),
            ScriptStep::reply(move |request| {
                V3ReplyBuilder::report_to(
                    request,
                    &first_report_engine,
                    report_oids::not_in_time_windows(),
                    4,
                )
                .build()
            }),
            ScriptStep::reply(move |request| {
                V3ReplyBuilder::report_to(
                    request,
                    &second_report_engine,
                    report_oids::not_in_time_windows(),
                    5,
                )
                .build()
            }),
        ],
        187,
        false,
    );
    let log = transport.log();
    let client = custom_client_with_compatibility(transport, level, None, true);

    let err = client
        .get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))
        .await
        .unwrap_err();
    assert!(matches!(
        &*err,
        async_snmp::Error::Report { status, .. }
            if matches!(status.as_ref(), ReportStatus::NotInTimeWindow { counter: 5 })
    ));
    assert_eq!(log.len(), 3, "only one compatibility packet is allowed");
}

#[tokio::test]
async fn v3_unauthenticated_time_report_compatibility_enforces_protocol_gates() {
    type Mutate = Box<dyn FnOnce(V3ReplyBuilder) -> V3ReplyBuilder + Send>;
    let wrong_engine_id = Bytes::from_static(b"\x80\x00\x7e\xd9\x05wrong-engine");
    let cases: Vec<(&str, Mutate)> = vec![
        ("wrong msgID", Box::new(|reply| reply.msg_id(999_999))),
        (
            "wrong engine ID",
            Box::new(move |reply| reply.engine_id(wrong_engine_id)),
        ),
        ("wrong username", Box::new(|reply| reply.username("other"))),
        (
            "non-empty authentication parameters",
            Box::new(|reply| reply.auth_params(Bytes::from_static(b"not-empty"))),
        ),
        (
            "non-empty privacy parameters",
            Box::new(|reply| reply.priv_params(Bytes::from_static(b"not-empty"))),
        ),
        (
            "ordinary lower-security Response",
            Box::new(|reply| reply.pdu_type(async_snmp::pdu::PduType::Response)),
        ),
        ("malformed Report", Box::new(|reply| reply.error_status(1))),
    ];

    for (case, mutate) in cases {
        let level = SecurityLevel::AuthNoPriv;
        let engine = engine_for(level);
        let report_engine = engine.clone();
        let transport = ScriptedTransport::new(
            engine.clone(),
            vec![
                discovery_step(engine),
                ScriptStep::reply(move |request| {
                    mutate(
                        V3ReplyBuilder::report_to(
                            request,
                            &report_engine,
                            report_oids::not_in_time_windows(),
                            1,
                        )
                        .engine_boots(7)
                        .engine_time(100),
                    )
                    .build()
                }),
            ],
            190,
            false,
        );
        let log = transport.log();
        let client = custom_client_with_compatibility(transport, level, None, true);

        client
            .get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))
            .await
            .unwrap_err();
        assert_eq!(log.len(), 2, "{case} must not trigger a correction");
    }
}

#[tokio::test]
async fn v3_failed_authenticated_compatibility_reply_does_not_publish_time() {
    type Mutate = Box<dyn FnOnce(V3ReplyBuilder) -> V3ReplyBuilder + Send>;
    let cases: Vec<(&str, Mutate)> = vec![
        ("wrong msgID", Box::new(|reply| reply.msg_id(999_999))),
        (
            "wrong context engine ID",
            Box::new(|reply| reply.context_engine_id(Bytes::from_static(b"wrong-context"))),
        ),
        (
            "wrong PDU request ID",
            Box::new(|reply| reply.request_id(999_999)),
        ),
        (
            "wrong PDU type",
            Box::new(|reply| reply.pdu_type(async_snmp::pdu::PduType::GetRequest)),
        ),
    ];

    for (case, mutate) in cases {
        let level = SecurityLevel::AuthNoPriv;
        let engine = engine_for(level);
        let report_engine = engine.clone();
        let advanced_engine = engine.clone().boots_time(9, 300);
        let transport = ScriptedTransport::new(
            engine.clone(),
            vec![
                discovery_step(engine.clone()),
                response_step(engine.clone(), "established"),
                ScriptStep::reply(move |request| {
                    V3ReplyBuilder::report_to(
                        request,
                        &report_engine,
                        report_oids::not_in_time_windows(),
                        1,
                    )
                    .engine_boots(8)
                    .engine_time(200)
                    .build()
                }),
                ScriptStep::reply(move |request| {
                    mutate(V3ReplyBuilder::response_to(request, &advanced_engine)).build()
                }),
                response_step(engine, "prior state retained"),
            ],
            195,
            false,
        );
        let log = transport.log();
        let client = custom_client_with_compatibility(transport, level, None, true);

        client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
        client
            .get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))
            .await
            .unwrap_err();
        let response = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
        assert_eq!(
            response.varbinds[0].value.as_str(),
            Some("prior state retained")
        );

        let requests = log.snapshot();
        assert_eq!(requests.len(), 5, "unexpected request count for {case}");
        assert_eq!(
            requests[4].usm.engine_boots, 7,
            "{case} must not publish the authenticated tuple"
        );
        assert!(requests[4].usm.engine_time >= 100);
        assert!(requests[4].usm.engine_time < 300);
    }
}

#[tokio::test]
async fn v3_tcp_time_window_report_gets_one_protocol_correction() {
    let level = SecurityLevel::AuthPriv;
    let engine = engine_for(level);
    let report_engine = engine.clone();
    let response_engine = engine.clone().boots_time(8, 20);
    let peer = ScriptedV3Peer::tcp(
        engine,
        vec![
            discovery_step(report_engine.clone()),
            ScriptStep::reply(move |request| {
                V3ReplyBuilder::report_to(
                    request,
                    &report_engine,
                    report_oids::not_in_time_windows(),
                    2,
                )
                .security_level(SecurityLevel::AuthNoPriv)
                .engine_boots(8)
                .engine_time(20)
                .build()
            }),
            response_step(response_engine, "TCP corrected response"),
        ],
    )
    .await;
    let log = peer.log();

    let client = Client::builder(peer.addr(), auth_for(level))
        .timeout(LOOPBACK_TIMEOUT)
        .retry(Retry::none())
        .connect_tcp()
        .await
        .unwrap();
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert_eq!(
        result.varbinds[0].value.as_str(),
        Some("TCP corrected response")
    );

    peer.finish().await.unwrap();
    let requests = log.snapshot();
    assert_eq!(requests.len(), 3);
    assert_ne!(
        requests[1].global_data.msg_id,
        requests[2].global_data.msg_id
    );
    assert_ne!(
        requests[1].scoped_pdu.as_ref().unwrap().pdu.request_id,
        requests[2].scoped_pdu.as_ref().unwrap().pdu.request_id
    );
}

#[tokio::test]
async fn v3_reliable_custom_transport_allows_protocol_correction() {
    let level = SecurityLevel::AuthNoPriv;
    let engine = engine_for(level);
    let report_engine = engine.clone();
    let response_engine = engine.clone().boots_time(8, 30);
    let transport = ScriptedTransport::new(
        engine.clone(),
        vec![
            discovery_step(engine),
            ScriptStep::reply(move |request| {
                V3ReplyBuilder::report_to(
                    request,
                    &report_engine,
                    report_oids::not_in_time_windows(),
                    3,
                )
                .security_level(level)
                .engine_boots(8)
                .engine_time(30)
                .build()
            }),
            response_step(response_engine, "custom corrected response"),
        ],
        200,
        true,
    );
    let log = transport.log();
    let client = custom_client(transport, level, None);

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert_eq!(
        result.varbinds[0].value.as_str(),
        Some("custom corrected response")
    );

    let requests = log.snapshot();
    assert_eq!(requests.len(), 3);
    for request in &requests {
        assert_eq!(
            request.transport_request_id,
            Some(request.global_data.msg_id)
        );
    }
    assert_ne!(
        requests[1].scoped_pdu.as_ref().unwrap().pdu.request_id,
        requests[2].scoped_pdu.as_ref().unwrap().pdu.request_id
    );
}

#[tokio::test]
async fn v3_report_on_final_timeout_attempt_still_gets_correction() {
    let level = SecurityLevel::AuthNoPriv;
    let engine = engine_for(level);
    let report_engine = engine.clone();
    let response_engine = engine.clone().boots_time(8, 40);
    let peer = ScriptedV3Peer::udp(
        engine,
        vec![
            discovery_step(report_engine.clone()),
            ScriptStep::silence(),
            ScriptStep::reply(move |request| {
                V3ReplyBuilder::report_to(
                    request,
                    &report_engine,
                    report_oids::not_in_time_windows(),
                    4,
                )
                .security_level(level)
                .engine_boots(8)
                .engine_time(40)
                .build()
            }),
            response_step(response_engine, "corrected after final attempt"),
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
    assert_eq!(
        result.varbinds[0].value.as_str(),
        Some("corrected after final attempt")
    );

    peer.finish().await.unwrap();
    let requests = log.snapshot();
    assert_eq!(requests.len(), 4);
    let attempts = &requests[1..];
    assert_eq!(
        attempts[0].scoped_pdu.as_ref().unwrap().pdu.request_id,
        attempts[1].scoped_pdu.as_ref().unwrap().pdu.request_id,
        "timeout retransmission reuses the PDU request ID"
    );
    assert_ne!(
        attempts[1].scoped_pdu.as_ref().unwrap().pdu.request_id,
        attempts[2].scoped_pdu.as_ref().unwrap().pdu.request_id,
        "protocol correction receives a fresh PDU request ID"
    );
}

#[tokio::test]
async fn v3_repeated_time_window_report_is_typed_and_bounded() {
    let level = SecurityLevel::AuthNoPriv;
    let engine = engine_for(level);
    let first_report_engine = engine.clone();
    let second_report_engine = engine.clone();
    let transport = ScriptedTransport::new(
        engine.clone(),
        vec![
            discovery_step(engine),
            ScriptStep::reply(move |request| {
                V3ReplyBuilder::report_to(
                    request,
                    &first_report_engine,
                    report_oids::not_in_time_windows(),
                    5,
                )
                .security_level(level)
                .engine_boots(8)
                .engine_time(50)
                .build()
            }),
            ScriptStep::reply(move |request| {
                V3ReplyBuilder::report_to(
                    request,
                    &second_report_engine,
                    report_oids::not_in_time_windows(),
                    6,
                )
                .security_level(level)
                .engine_boots(8)
                .engine_time(50)
                .build()
            }),
        ],
        300,
        false,
    );
    let log = transport.log();
    let client = Client::new(
        transport,
        ClientConfig {
            auth: Auth::Usm(user_for(level)),
            timeout: LOOPBACK_TIMEOUT,
            retry: Retry::fixed(5, Duration::ZERO),
            ..ClientConfig::default()
        },
    )
    .expect("valid client config");

    let err = client
        .get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))
        .await
        .unwrap_err();
    assert!(
        matches!(
            &*err,
            async_snmp::Error::Report { status, .. }
                if matches!(status.as_ref(), ReportStatus::NotInTimeWindow { counter: 6 })
        ),
        "repeated Report must retain its status instead of becoming a timeout: {err}"
    );
    assert_eq!(log.len(), 3, "only one corrected request is allowed");
}

#[tokio::test]
async fn v3_malformed_reports_are_terminal_without_correction() {
    type Mutate = Box<dyn Fn(V3ReplyBuilder) -> V3ReplyBuilder + Send>;
    let cases: Vec<(&str, Mutate)> = vec![
        ("nonzero status", Box::new(|reply| reply.error_status(1))),
        ("nonzero index", Box::new(|reply| reply.error_index(1))),
        ("empty varbinds", Box::new(|reply| reply.varbinds(vec![]))),
        (
            "wrong standard value type",
            Box::new(|reply| {
                reply.varbinds(vec![VarBind::new(
                    report_oids::not_in_time_windows(),
                    Value::Integer(1),
                )])
            }),
        ),
        (
            "multiple statuses",
            Box::new(|reply| {
                reply.varbinds(vec![
                    VarBind::new(report_oids::not_in_time_windows(), Value::Counter32(1)),
                    VarBind::new(report_oids::wrong_digests(), Value::Counter32(1)),
                ])
            }),
        ),
    ];

    for (case, mutate) in cases {
        let level = SecurityLevel::AuthNoPriv;
        let engine = engine_for(level);
        let report_engine = engine.clone();
        let transport = ScriptedTransport::new(
            engine.clone(),
            vec![
                discovery_step(engine),
                ScriptStep::reply(move |request| {
                    mutate(
                        V3ReplyBuilder::report_to(
                            request,
                            &report_engine,
                            report_oids::not_in_time_windows(),
                            1,
                        )
                        .security_level(level)
                        .engine_boots(8)
                        .engine_time(60),
                    )
                    .build()
                }),
            ],
            400,
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
            "{case} should be malformed, got {err}"
        );
        assert_eq!(log.len(), 2, "{case} must not trigger correction");
    }
}

#[tokio::test]
async fn v3_terminal_reports_preserve_known_and_unknown_status() {
    let level = SecurityLevel::AuthNoPriv;
    let engine = engine_for(level);
    let digest_engine = engine.clone();
    let other_engine = engine.clone();
    let other_oid = oid!(1, 3, 6, 1, 6, 3, 12, 1, 5, 0);
    let expected_other_oid = other_oid.clone();
    let transport = ScriptedTransport::new(
        engine.clone(),
        vec![
            discovery_step(engine),
            ScriptStep::reply(move |request| {
                V3ReplyBuilder::report_to(request, &digest_engine, report_oids::wrong_digests(), 9)
                    .security_level(level)
                    .build()
            }),
            ScriptStep::reply(move |request| {
                V3ReplyBuilder::report_to(request, &other_engine, other_oid.clone(), 11)
                    .security_level(level)
                    .build()
            }),
        ],
        500,
        false,
    );
    let log = transport.log();
    let client = custom_client(transport, level, None);

    let first = client
        .get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))
        .await
        .unwrap_err();
    assert!(matches!(
        &*first,
        async_snmp::Error::Report { status, .. }
            if matches!(status.as_ref(), ReportStatus::WrongDigest { counter: 9 })
    ));

    let second = client
        .get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))
        .await
        .unwrap_err();
    assert!(matches!(
        &*second,
        async_snmp::Error::Report { status, .. }
            if matches!(
                status.as_ref(),
                ReportStatus::Other {
                    oid,
                    value: Value::Counter32(11),
                } if *oid == expected_other_oid
            )
    ));
    assert_eq!(log.len(), 3, "terminal Reports must not add sends");
}

#[tokio::test]
async fn v3_failed_correction_preserves_authenticated_report_time() {
    let level = SecurityLevel::AuthNoPriv;
    let engine = engine_for(level);
    let report_engine = engine.clone();
    let response_engine = engine.clone().boots_time(8, 70);
    let transport = ScriptedTransport::new(
        engine.clone(),
        vec![
            discovery_step(engine),
            ScriptStep::reply(move |request| {
                V3ReplyBuilder::report_to(
                    request,
                    &report_engine,
                    report_oids::not_in_time_windows(),
                    12,
                )
                .security_level(level)
                .engine_boots(8)
                .engine_time(70)
                .build()
            }),
            ScriptStep::silence(),
            response_step(response_engine, "state retained"),
        ],
        600,
        false,
    );
    let log = transport.log();
    let client = custom_client(transport, level, None);

    let err = client
        .get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))
        .await
        .unwrap_err();
    assert!(matches!(
        *err,
        async_snmp::Error::Timeout { retries: 0, .. }
    ));

    let response = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert_eq!(response.varbinds[0].value.as_str(), Some("state retained"));
    let requests = log.snapshot();
    assert_eq!(requests.len(), 4);
    assert_eq!(requests[3].usm.engine_boots, 8);
    assert!(requests[3].usm.engine_time >= 70);
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
    assert_eq!(result.varbinds[0].value.as_str(), Some("state preserved"));

    peer.finish().await.unwrap();
    let requests = log.snapshot();
    assert_eq!(requests.len(), 3, "the invalid Report must not add a retry");
    assert_eq!(
        requests[2].usm.engine_boots, 0,
        "wrong-user authentication must not establish trusted engine time"
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
    assert_eq!(result.varbinds[0].value.as_str(), Some("state preserved"));

    peer.finish().await.unwrap();
    let requests = log.snapshot();
    assert_eq!(requests.len(), 3);
    assert_eq!(
        requests[2].usm.engine_boots, 0,
        "unsupported privacy must not establish trusted engine time"
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
    assert_eq!(result.varbinds[0].value.as_str(), Some("state preserved"));

    peer.finish().await.unwrap();
    let requests = log.snapshot();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[2].usm.engine_boots, 0);
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
            response_step(engine.clone(), "synchronized"),
            ScriptStep::reply(move |request| {
                V3ReplyBuilder::response_to(request, &stale_engine)
                    .engine_time(100)
                    .ciphertext(Bytes::from_static(b"not a scoped PDU"))
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
    let synchronized = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert_eq!(
        synchronized.varbinds[0].value.as_str(),
        Some("synchronized")
    );

    let err = client
        .get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))
        .await
        .unwrap_err();
    assert!(
        matches!(*err, async_snmp::Error::Auth { .. }),
        "stale ciphertext must fail timeliness before decode, got: {err}"
    );

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert_eq!(result.varbinds[0].value.as_str(), Some("state preserved"));

    peer.finish().await.unwrap();
    let requests = log.snapshot();
    assert_eq!(requests.len(), 4);
    assert_eq!(
        requests[3].usm.engine_id.as_ref(),
        ENGINE_ID,
        "timeliness rejection must not clear an established identity"
    );
    assert_eq!(requests[3].usm.engine_boots, 7);
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
        matches!(
            &*err,
            async_snmp::Error::Report { status, .. }
                if matches!(status.as_ref(), ReportStatus::UnknownUserName { counter: 1 })
        ),
        "encrypted Report must retain its typed status, got: {err}"
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
    assert_eq!(result.varbinds[0].value.as_str(), Some("reserved bits ok"));
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
    assert_eq!(result.varbinds[0].value.as_str(), Some("after retries"));

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
            auth: Auth::Usm(security),
            timeout: LOOPBACK_TIMEOUT,
            retry: Retry::fixed(1, Duration::ZERO),
            ..ClientConfig::default()
        },
    )
    .expect("valid client config");

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
        result.varbinds[0].value.as_str(),
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
    assert_eq!(result.varbinds[0].value.as_str(), Some("custom response"));
}

#[tokio::test]
async fn scripted_transport_returns_arbitrary_bytes_without_id_filtering() {
    let request = V3Message::discovery_request(41, async_snmp::UDP_RECEIVE_LIMITS.advertised())
        .encode()
        .unwrap();
    let expected = Bytes::from_static(b"arbitrary response bytes");
    let transport = ScriptedTransport::new(
        TestV3Engine::new(Bytes::from_static(ENGINE_ID)),
        vec![ScriptStep::bytes(expected.clone())],
        100,
        false,
    );
    let log = transport.log();

    let (actual, _) = Transport::request(
        &transport,
        &request,
        async_snmp::RequestRegistration::v3(999, Duration::from_secs(5)),
    )
    .await
    .unwrap();

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
    let request = V3Message::discovery_request(41, async_snmp::UDP_RECEIVE_LIMITS.advertised())
        .encode()
        .unwrap();

    let (response, _) = Transport::request(
        &transport,
        &request,
        async_snmp::RequestRegistration::v3(41, Duration::from_secs(5)),
    )
    .await
    .unwrap();
    let response = V3Message::decode(response).unwrap();
    let V3MessageData::Plaintext(scoped) = response.data else {
        panic!("Report must have a plaintext scopedPDU");
    };

    assert_eq!(scoped.context_engine_id, expected_engine_id);
    assert!(scoped.context_name.is_empty());
}

#[test]
fn raw_ber_targets_invalid_flags_and_oversized_msg_ids() {
    let original = V3Message::discovery_request(7, async_snmp::UDP_RECEIVE_LIMITS.advertised())
        .encode()
        .unwrap()
        .to_vec();
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

#[tokio::test]
async fn v3_udp_accepts_late_response_to_prior_attempt() {
    let level = SecurityLevel::AuthNoPriv;
    let engine = engine_for(level);
    let response_engine = engine.clone();
    let first_attempt = Arc::new(Mutex::new(None::<i32>));
    let capture = first_attempt.clone();
    let peer = ScriptedV3Peer::udp(
        engine.clone(),
        vec![
            discovery_step(engine),
            ScriptStep::silence_with(move |request| {
                *capture.lock().unwrap() = Some(request.global_data.msg_id);
            }),
            ScriptStep::reply(move |request| {
                let prior = first_attempt.lock().unwrap().take().unwrap();
                V3ReplyBuilder::response_to(request, &response_engine)
                    .msg_id(prior)
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
    client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();

    peer.finish().await.unwrap();
    let requests = log.snapshot();
    assert_eq!(requests.len(), 3);
    assert_ne!(
        requests[1].global_data.msg_id,
        requests[2].global_data.msg_id
    );
    assert_eq!(
        requests[1].scoped_pdu.as_ref().unwrap().pdu.request_id,
        requests[2].scoped_pdu.as_ref().unwrap().pdu.request_id
    );
}

#[tokio::test]
async fn v3_custom_transport_accepts_late_response_to_prior_attempt() {
    let level = SecurityLevel::AuthNoPriv;
    let engine = engine_for(level);
    let response_engine = engine.clone();
    let first_attempt = Arc::new(Mutex::new(None::<i32>));
    let capture = first_attempt.clone();
    let transport = ScriptedTransport::new(
        engine.clone(),
        vec![
            discovery_step(engine),
            ScriptStep::silence_with(move |request| {
                *capture.lock().unwrap() = Some(request.global_data.msg_id);
            }),
            ScriptStep::reply(move |request| {
                let prior = first_attempt.lock().unwrap().take().unwrap();
                V3ReplyBuilder::response_to(request, &response_engine)
                    .msg_id(prior)
                    .build()
            }),
        ],
        100,
        false,
    );
    let log = transport.log();
    let client = Client::new(
        transport,
        ClientConfig {
            auth: Auth::Usm(user_for(level)),
            timeout: LOOPBACK_TIMEOUT,
            retry: Retry::fixed(1, Duration::ZERO),
            ..ClientConfig::default()
        },
    )
    .expect("valid client config");

    client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();

    let requests = log.snapshot();
    assert_eq!(requests.len(), 3);
    assert_ne!(
        requests[1].global_data.msg_id,
        requests[2].global_data.msg_id
    );
    assert_eq!(
        requests[1].scoped_pdu.as_ref().unwrap().pdu.request_id,
        requests[2].scoped_pdu.as_ref().unwrap().pdu.request_id
    );
}

#[tokio::test]
async fn v3_pre_correction_msg_id_rejected_after_correction() {
    let level = SecurityLevel::AuthNoPriv;
    let engine = engine_for(level);
    let report_engine = engine.clone();
    let response_engine = engine.clone().boots_time(8, 10);
    let first_attempt = Arc::new(Mutex::new(None::<i32>));
    let capture = first_attempt.clone();
    let transport = ScriptedTransport::new(
        engine.clone(),
        vec![
            discovery_step(engine),
            ScriptStep::reply(move |request| {
                *capture.lock().unwrap() = Some(request.global_data.msg_id);
                V3ReplyBuilder::report_to(
                    request,
                    &report_engine,
                    report_oids::not_in_time_windows(),
                    1,
                )
                .security_level(level)
                .engine_boots(8)
                .engine_time(10)
                .build()
            }),
            ScriptStep::reply(move |request| {
                let stale = first_attempt.lock().unwrap().take().unwrap();
                V3ReplyBuilder::response_to(request, &response_engine)
                    .msg_id(stale)
                    .build()
            }),
        ],
        100,
        false,
    );
    let log = transport.log();
    let client = Client::new(
        transport,
        ClientConfig {
            auth: Auth::Usm(user_for(level)),
            timeout: LOOPBACK_TIMEOUT,
            retry: Retry::fixed(1, Duration::ZERO),
            ..ClientConfig::default()
        },
    )
    .expect("valid client config");

    let err = client
        .get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))
        .await
        .unwrap_err();
    assert!(
        matches!(*err, async_snmp::Error::MalformedResponse { .. }),
        "correction resets the window; pre-correction msgID must not correlate: {err}"
    );
    assert_eq!(log.snapshot().len(), 3);
}

#[tokio::test]
async fn v3_windowed_report_from_prior_attempt_triggers_correction() {
    let level = SecurityLevel::AuthNoPriv;
    let engine = engine_for(level);
    let report_engine = engine.clone();
    let response_engine = engine.clone().boots_time(8, 10);
    let first_attempt = Arc::new(Mutex::new(None::<i32>));
    let capture = first_attempt.clone();
    let peer = ScriptedV3Peer::udp(
        engine.clone(),
        vec![
            discovery_step(engine),
            ScriptStep::silence_with(move |request| {
                *capture.lock().unwrap() = Some(request.global_data.msg_id);
            }),
            ScriptStep::reply(move |request| {
                let prior = first_attempt.lock().unwrap().take().unwrap();
                V3ReplyBuilder::report_to(
                    request,
                    &report_engine,
                    report_oids::not_in_time_windows(),
                    1,
                )
                .security_level(level)
                .engine_boots(8)
                .engine_time(10)
                .msg_id(prior)
                .build()
            }),
            response_step(response_engine, "corrected from windowed report"),
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
    assert_eq!(
        result.varbinds[0].value.as_str(),
        Some("corrected from windowed report")
    );

    peer.finish().await.unwrap();
    let requests = log.snapshot();
    assert_eq!(requests.len(), 4);
    assert_eq!(requests[3].usm.engine_boots, 8);
    assert!(requests[3].usm.engine_time >= 10);
    assert_eq!(
        requests[1].scoped_pdu.as_ref().unwrap().pdu.request_id,
        requests[2].scoped_pdu.as_ref().unwrap().pdu.request_id,
        "timeout retransmission reuses the PDU request ID"
    );
    assert_ne!(
        requests[2].scoped_pdu.as_ref().unwrap().pdu.request_id,
        requests[3].scoped_pdu.as_ref().unwrap().pdu.request_id,
        "protocol correction receives a fresh PDU request ID"
    );
}

#[tokio::test]
async fn v3_windowed_unauthenticated_report_from_prior_attempt_triggers_correction() {
    let level = SecurityLevel::AuthPriv;
    let engine = engine_for(level);
    let report_engine = engine.clone();
    let response_engine = engine.clone();
    let first_attempt = Arc::new(Mutex::new(None::<i32>));
    let capture = first_attempt.clone();
    let peer = ScriptedV3Peer::udp(
        engine.clone(),
        vec![
            discovery_step(engine),
            ScriptStep::silence_with(move |request| {
                *capture.lock().unwrap() = Some(request.global_data.msg_id);
            }),
            ScriptStep::reply(move |request| {
                let prior = first_attempt.lock().unwrap().take().unwrap();
                V3ReplyBuilder::report_to(
                    request,
                    &report_engine,
                    report_oids::not_in_time_windows(),
                    1,
                )
                .engine_boots(7)
                .engine_time(100)
                .msg_id(prior)
                .build()
            }),
            response_step(
                response_engine,
                "corrected from windowed compatibility report",
            ),
        ],
    )
    .await;
    let log = peer.log();

    let client = Client::builder(peer.addr(), auth_for(level))
        .timeout(LOOPBACK_TIMEOUT)
        .retry(Retry::fixed(1, Duration::ZERO))
        .allow_unauthenticated_v3_time_correction(true)
        .connect()
        .await
        .unwrap();
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert_eq!(
        result.varbinds[0].value.as_str(),
        Some("corrected from windowed compatibility report")
    );

    peer.finish().await.unwrap();
    let requests = log.snapshot();
    assert_eq!(requests.len(), 4);
    assert_ne!(
        requests[1].global_data.msg_id, requests[2].global_data.msg_id,
        "timeout retransmission receives a fresh msgID"
    );
    assert_eq!(
        requests[1].scoped_pdu.as_ref().unwrap().pdu.request_id,
        requests[2].scoped_pdu.as_ref().unwrap().pdu.request_id,
        "timeout retransmission reuses the PDU request ID"
    );
    assert_ne!(
        requests[2].scoped_pdu.as_ref().unwrap().pdu.request_id,
        requests[3].scoped_pdu.as_ref().unwrap().pdu.request_id,
        "protocol correction receives a fresh PDU request ID"
    );
    assert_eq!(
        (requests[3].usm.engine_boots, requests[3].usm.engine_time),
        (7, 100),
        "the earlier attempt's unauthenticated tuple applies to the corrected packet"
    );
    assert_eq!(requests[3].authentication_valid, Some(true));
    assert_eq!(
        requests[3].global_data.msg_flags.security_level,
        SecurityLevel::AuthPriv
    );
}

#[tokio::test]
async fn v3_repeated_report_with_pre_correction_msg_id_is_not_acted_on() {
    let level = SecurityLevel::AuthNoPriv;
    let engine = engine_for(level);
    let first_report_engine = engine.clone();
    let second_report_engine = engine.clone();
    let first_attempt = Arc::new(Mutex::new(None::<i32>));
    let capture = first_attempt.clone();
    let transport = ScriptedTransport::new(
        engine.clone(),
        vec![
            discovery_step(engine),
            ScriptStep::reply(move |request| {
                *capture.lock().unwrap() = Some(request.global_data.msg_id);
                V3ReplyBuilder::report_to(
                    request,
                    &first_report_engine,
                    report_oids::not_in_time_windows(),
                    1,
                )
                .security_level(level)
                .engine_boots(8)
                .engine_time(10)
                .build()
            }),
            ScriptStep::reply(move |request| {
                let stale = first_attempt.lock().unwrap().take().unwrap();
                V3ReplyBuilder::report_to(
                    request,
                    &second_report_engine,
                    report_oids::not_in_time_windows(),
                    2,
                )
                .security_level(level)
                .engine_boots(8)
                .engine_time(10)
                .msg_id(stale)
                .build()
            }),
        ],
        100,
        false,
    );
    let log = transport.log();
    let client = Client::new(
        transport,
        ClientConfig {
            auth: Auth::Usm(user_for(level)),
            timeout: LOOPBACK_TIMEOUT,
            retry: Retry::fixed(1, Duration::ZERO),
            ..ClientConfig::default()
        },
    )
    .expect("valid client config");

    let err = client
        .get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))
        .await
        .unwrap_err();
    assert!(
        matches!(*err, async_snmp::Error::MalformedResponse { .. }),
        "a Report stamped with the pre-correction msgID must not trigger a second correction: {err}"
    );
    assert_eq!(
        log.snapshot().len(),
        3,
        "no further send should occur after the stale-msgID report is rejected"
    );
}

#[tokio::test]
async fn v3_completed_operation_msg_id_not_accepted_for_next_operation() {
    let level = SecurityLevel::AuthNoPriv;
    let engine = engine_for(level);
    let first_response_engine = engine.clone();
    let second_response_engine = engine.clone();
    let first_op_msg_id = Arc::new(Mutex::new(None::<i32>));
    let capture = first_op_msg_id.clone();
    let transport = ScriptedTransport::new(
        engine.clone(),
        vec![
            discovery_step(engine),
            ScriptStep::reply(move |request| {
                *capture.lock().unwrap() = Some(request.global_data.msg_id);
                let oid = request.scoped_pdu.as_ref().unwrap().pdu.varbinds[0]
                    .oid
                    .clone();
                V3ReplyBuilder::response_to(request, &first_response_engine)
                    .varbinds(vec![VarBind::new(
                        oid,
                        Value::OctetString(Bytes::from_static(b"operation one")),
                    )])
                    .build()
            }),
            ScriptStep::reply(move |request| {
                let stale = first_op_msg_id.lock().unwrap().take().unwrap();
                let oid = request.scoped_pdu.as_ref().unwrap().pdu.varbinds[0]
                    .oid
                    .clone();
                V3ReplyBuilder::response_to(request, &second_response_engine)
                    .msg_id(stale)
                    .varbinds(vec![VarBind::new(
                        oid,
                        Value::OctetString(Bytes::from_static(b"operation two")),
                    )])
                    .build()
            }),
        ],
        100,
        false,
    );
    let log = transport.log();
    let client = Client::new(
        transport,
        ClientConfig {
            auth: Auth::Usm(user_for(level)),
            timeout: LOOPBACK_TIMEOUT,
            retry: Retry::fixed(1, Duration::ZERO),
            ..ClientConfig::default()
        },
    )
    .expect("valid client config");

    let first = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert_eq!(first.varbinds[0].value.as_str(), Some("operation one"));

    let err = client
        .get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))
        .await
        .unwrap_err();
    assert!(
        matches!(*err, async_snmp::Error::MalformedResponse { .. }),
        "a completed operation's msgID must not correlate to the next operation: {err}"
    );
    assert_eq!(log.snapshot().len(), 3);
}
