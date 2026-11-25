#![cfg(feature = "agent")]

use async_snmp::handler::{
    BoxFuture, GetNextResult, GetResult, HandlerResult, MibHandler, RequestContext,
};
use async_snmp::{
    Agent, AgentStatus, Auth, AuthoritativeEngine, Client, Error, ListenerSource,
    NotificationSinkId, NotificationTarget, Retry, TcpListenerSource, TcpOptions, TcpTransport,
    TransportKind, UdpEndpoint, UdpStatus, Value, oid,
};
use std::{convert::Infallible, sync::Arc, time::Duration};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};

struct BytesHandler(usize);
impl MibHandler for BytesHandler {
    fn get<'a>(
        &'a self,
        _: &'a RequestContext,
        _: &'a async_snmp::Oid,
    ) -> BoxFuture<'a, HandlerResult<GetResult>> {
        Box::pin(async move {
            Ok(GetResult::Value(Value::OctetString(
                vec![42; self.0].into(),
            )))
        })
    }
    fn get_next<'a>(
        &'a self,
        _: &'a RequestContext,
        _: &'a async_snmp::Oid,
    ) -> BoxFuture<'a, HandlerResult<GetNextResult>> {
        Box::pin(async { Ok(GetNextResult::EndOfMibView) })
    }
}

fn engine() -> AuthoritativeEngine {
    AuthoritativeEngine::install(
        b"listener-test-engine".to_vec(),
        |_| Ok::<_, Infallible>(()),
    )
    .unwrap()
}

#[tokio::test]
async fn invalid_listener_and_sink_configs_never_connect_to_an_earlier_session_peer() {
    let peer = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = peer.local_addr().unwrap();
    let agent = || Agent::builder().session(TcpTransport::builder().target(peer_addr));
    let sink = || NotificationSinkId::new("sink").unwrap();
    let auth = || Auth::v2c("public");
    let udp_bind = "127.0.0.1:0";
    let udp_target = "127.0.0.1:162";
    let options = TcpTransport::builder()
        .target(peer_addr)
        .max_message_size(8 * 1024 * 1024)
        .send_capacity(26 * 1024 * 1024)
        .max_buffered_bytes(34 * 1024 * 1024);

    for (builder, expected) in [
        (
            agent().notification_sink(
                sink(),
                NotificationTarget::shared_udp(1, udp_target),
                auth(),
            ),
            "existing UDP listener index",
        ),
        (
            agent().notification_sink(
                sink(),
                NotificationTarget::shared_udp(0, udp_target),
                auth(),
            ),
            "existing UDP listener index",
        ),
        (
            agent().listener(ListenerSource::tcp("invalid address")),
            "invalid TCP listener address",
        ),
        (
            agent().notification_sink(
                sink(),
                NotificationTarget::udp(
                    UdpEndpoint::builder().max_inflight_requests(0),
                    udp_target,
                ),
                auth(),
            ),
            "UDP max_inflight_requests",
        ),
        (
            agent().notification_sink(
                sink(),
                NotificationTarget::tcp(TcpTransport::builder()),
                auth(),
            ),
            "TCP target or connected stream is required",
        ),
        (
            agent().max_connections(1).notification_sink(
                sink(),
                NotificationTarget::tcp(TcpTransport::builder().target(peer_addr)),
                auth(),
            ),
            "invalid listener, connection or aggregate buffer limit",
        ),
        (
            agent().buffered_bytes(40 * 1024 * 1024).session(options),
            "buffer budget must accommodate",
        ),
        (
            agent()
                .listener(ListenerSource::udp(udp_bind))
                .notification_sink(
                    sink(),
                    NotificationTarget::shared_udp(1, "[::1]:162"),
                    auth(),
                ),
            "incompatible with IPv4 socket",
        ),
    ] {
        let error = builder
            .prepare()
            .await
            .err()
            .expect("invalid configuration");
        assert!(
            matches!(*error, Error::Config(ref message) if message.contains(expected)),
            "{error}"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(25), peer.accept())
                .await
                .is_err(),
            "configuration error '{expected}' followed a connection to the peer",
        );
    }

    let running = agent()
        .listener(ListenerSource::udp(udp_bind))
        .notification_sink(
            sink(),
            NotificationTarget::shared_udp(1, udp_target),
            auth(),
        )
        .spawn()
        .await
        .unwrap();
    let (connected, _) = tokio::time::timeout(Duration::from_secs(1), peer.accept())
        .await
        .expect("valid configuration must connect to its peer")
        .unwrap();
    assert_eq!(
        connected.peer_addr().unwrap(),
        running.bound_addresses()[0].local_addr
    );
    let sink = running.notification_sinks().next().unwrap();
    assert_eq!(sink.endpoint_id(), running.bound_addresses()[1].endpoint_id);
    running.shutdown().await.unwrap();
}

#[tokio::test]
async fn default_udp_listener_index_is_validated_before_bind() {
    let occupied = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let error = Agent::builder()
        .bind(occupied.local_addr().unwrap().to_string())
        .notification_sink(
            NotificationSinkId::new("sink").unwrap(),
            NotificationTarget::shared_udp(1, "127.0.0.1:162"),
            Auth::v2c("public"),
        )
        .prepare()
        .await
        .err()
        .expect("default UDP listener has index zero");
    assert!(
        matches!(*error, Error::Config(ref message) if message.contains("existing UDP listener index")),
        "{error}"
    );
}

#[tokio::test]
async fn tcp_budget_reserves_space_for_a_maximum_sized_reply() {
    for budget in [1024, 2048] {
        let mut options = TcpOptions::default();
        options.max_message_size = 1024;
        options.send_capacity = 1024;
        options.max_buffered_bytes = budget;
        let prepared = Agent::builder()
            .community(b"public")
            .allow_all_access()
            .buffered_bytes(2048)
            .max_message_size(1024)
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), Arc::new(BytesHandler(960)))
            .listener(ListenerSource::Tcp(
                TcpListenerSource::bind("127.0.0.1:0").session_options(options),
            ))
            .prepare()
            .await;
        if budget == 1024 {
            assert!(matches!(
                *prepared
                    .err()
                    .expect("input-only budget must fail preparation"),
                async_snmp::Error::Config(_)
            ));
            continue;
        }
        let agent = prepared.unwrap().spawn();
        let client = Client::builder(
            agent.bound_addresses()[0].local_addr.to_string(),
            Auth::v2c("public"),
        )
        .retry(Retry::none())
        .request_timeout(Duration::from_secs(2))
        .connect_tcp()
        .await
        .unwrap();
        let result = client
            .get(&oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0))
            .await
            .unwrap();
        assert_eq!(result.varbinds[0].value.as_bytes().unwrap().len(), 960);
        assert!(result.metadata.received_messages[0].info.received_len() <= 1024);
        agent.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn agent_buffer_partition_includes_udp_command_capacity() {
    let mut options = TcpOptions::default();
    options.max_message_size = 1024;
    options.send_capacity = 1024;
    options.max_buffered_bytes = 2048;
    let result = Agent::builder()
        .buffered_bytes(async_snmp::UDP_RECEIVE_BUFFER_SIZE)
        .listener(ListenerSource::udp("127.0.0.1:0"))
        .listener(ListenerSource::Tcp(
            TcpListenerSource::bind("127.0.0.1:0").session_options(options),
        ))
        .prepare()
        .await;
    let error = result
        .err()
        .expect("full UDP input and TCP output must fit");
    assert!(matches!(*error, async_snmp::Error::Config(_)));
}

#[tokio::test]
async fn receiver_tcp_buffer_partition_uses_only_tcp_listener_capacities() {
    for reverse in [false, true] {
        for total in [6144, 8192] {
            let mut capacities = [(1024, 4096), (4096, 1024)];
            if reverse {
                capacities.reverse();
            }
            let mut builder = async_snmp::NotificationReceiver::builder()
                .max_tcp_buffered_bytes(total)
                .listener(ListenerSource::udp("127.0.0.1:0"));
            for (receive, send) in capacities {
                let mut options = TcpOptions::default();
                options.max_message_size = receive;
                options.send_capacity = send;
                options.max_buffered_bytes = receive + send;
                builder = builder.listener(ListenerSource::Tcp(
                    TcpListenerSource::bind("127.0.0.1:0").session_options(options),
                ));
            }
            let prepared = builder.prepare().await;
            if total == 6144 {
                assert!(matches!(
                    *prepared
                        .err()
                        .expect("largest input and output must both fit"),
                    async_snmp::Error::Config(_)
                ));
            } else {
                let (receiver, runner) = prepared.unwrap().into_parts();
                assert_eq!(receiver.bound_addresses().len(), 3);
                drop(runner);
            }
        }
    }
}

#[tokio::test]
async fn mixed_owned_listeners_share_engine_and_isolate_bad_sessions() {
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let agent = Agent::builder()
        .community(b"public")
        .authoritative_engine(engine())
        .allow_all_access()
        .listener(ListenerSource::udp_socket(udp))
        .listener(ListenerSource::tcp_listener(tcp))
        .spawn()
        .await
        .unwrap();
    let bound = agent.bound_addresses();
    assert_ne!(bound[0].endpoint_id, bound[1].endpoint_id);
    assert_eq!(bound[0].transport, TransportKind::Udp);
    assert_eq!(bound[1].transport, TransportKind::Tcp);
    let udp_addr = bound[0].local_addr;
    let tcp_addr = bound[1].local_addr;
    let mut invalid = TcpStream::connect(tcp_addr).await.unwrap();
    invalid.write_all(&[0x31, 0]).await.unwrap();
    let mut stalled = TcpStream::connect(tcp_addr).await.unwrap();
    stalled.write_all(&[0x30, 0x82]).await.unwrap();
    for auth in [Auth::v1("public"), Auth::v2c("public")] {
        let udp = Client::builder(udp_addr.to_string(), auth.clone())
            .retry(Retry::none())
            .request_timeout(Duration::from_secs(2))
            .connect()
            .await
            .unwrap();
        let tcp = Client::builder(tcp_addr.to_string(), auth)
            .retry(Retry::none())
            .request_timeout(Duration::from_secs(2))
            .connect_tcp()
            .await
            .unwrap();
        for oid in [
            oid!(1, 3, 6, 1, 6, 3, 10, 2, 1, 1, 0),
            oid!(1, 3, 6, 1, 6, 3, 10, 2, 1, 2, 0),
            oid!(1, 3, 6, 1, 6, 3, 10, 2, 1, 4, 0),
        ] {
            let a = udp.get(&oid).await.unwrap();
            let b = tcp.get(&oid).await.unwrap();
            assert_eq!(a.varbinds, b.varbinds);
        }
        let next = tcp
            .get_next(&oid!(1, 3, 6, 1, 6, 3, 10, 2, 1))
            .await
            .unwrap();
        assert!(!next.varbinds.is_empty());
    }
    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn tcp_can_reply_above_udp_limit_and_reports_its_capacity() {
    let mut options = TcpOptions::default();
    options.max_message_size = 200_000;
    options.send_capacity = 200_000;
    options.max_buffered_bytes = 400_000;
    let agent = Agent::builder()
        .community(b"public")
        .allow_all_access()
        .max_message_size(200_000)
        .listener(ListenerSource::Tcp(
            TcpListenerSource::bind("127.0.0.1:0").session_options(options),
        ))
        .handler(
            oid!(1, 3, 6, 1, 4, 1, 99999),
            Arc::new(BytesHandler(90_000)),
        )
        .spawn()
        .await
        .unwrap();
    let client = Client::builder(
        agent.bound_addresses()[0].local_addr.to_string(),
        Auth::v2c("public"),
    )
    .connect_tcp()
    .await
    .unwrap();
    let result = client
        .get(&oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0))
        .await
        .unwrap();
    assert_eq!(
        result.varbinds[0].value,
        Value::OctetString(vec![42; 90_000].into())
    );
    let capacity = client
        .get(&oid!(1, 3, 6, 1, 6, 3, 10, 2, 1, 4, 0))
        .await
        .unwrap();
    assert_eq!(capacity.varbinds[0].value, Value::Integer(200_000));
    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn failed_preparation_releases_previously_prepared_listeners() {
    let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = first.local_addr().unwrap();
    let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let result = Agent::builder()
        .listener(ListenerSource::udp_socket(first))
        .listener(ListenerSource::tcp(
            occupied.local_addr().unwrap().to_string(),
        ))
        .prepare()
        .await;
    assert!(result.is_err());
    let _rebound = UdpSocket::bind(address).await.unwrap();
}

#[tokio::test]
async fn unpolled_runner_drop_is_terminal_and_final_public_handle_stops_runner() {
    let (agent, runner, _) = Agent::builder()
        .bind("127.0.0.1:0")
        .prepare()
        .await
        .unwrap()
        .into_parts();
    let control = agent.control();
    drop(runner);
    control.wait_closed().await;
    assert_eq!(control.status(), async_snmp::AgentStatus::Interrupted);
    control
        .drain_mutations(Duration::from_millis(50))
        .await
        .unwrap();
    let (agent, runner, _) = Agent::builder()
        .listener(ListenerSource::tcp("127.0.0.1:0"))
        .prepare()
        .await
        .unwrap()
        .into_parts();
    let task = tokio::spawn(runner.run());
    drop(agent);
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
#[tokio::test]
async fn v3_discovery_authentication_and_privacy_across_udp_tcp() {
    use async_snmp::{AuthProtocol, PrivProtocol, UsmConfig};
    let agent = Agent::builder()
        .authoritative_engine(engine())
        .allow_all_access()
        .usm_user("noauth", Ok)
        .unwrap()
        .usm_user("auth", |u| u.auth(AuthProtocol::Sha256, b"authpassword123"))
        .unwrap()
        .usm_user("priv", |u| {
            u.auth_priv(
                AuthProtocol::Sha256,
                b"authpassword123",
                PrivProtocol::Aes128,
                b"privpassword123",
            )
        })
        .unwrap()
        .listener(ListenerSource::udp("127.0.0.1:0"))
        .listener(ListenerSource::tcp("127.0.0.1:0"))
        .spawn()
        .await
        .unwrap();
    let auths: [Auth; 3] = [
        Auth::usm("noauth"),
        UsmConfig::new("auth")
            .auth(AuthProtocol::Sha256, "authpassword123")
            .unwrap()
            .into(),
        UsmConfig::new("priv")
            .auth_priv(
                AuthProtocol::Sha256,
                "authpassword123",
                PrivProtocol::Aes128,
                "privpassword123",
            )
            .unwrap()
            .into(),
    ];
    for auth in auths {
        let cache = Arc::new(async_snmp::v3::EngineCache::new());
        let udp = Client::builder(
            agent.bound_addresses()[0].local_addr.to_string(),
            auth.clone(),
        )
        .engine_cache(cache.clone())
        .connect()
        .await
        .unwrap();
        let tcp = Client::builder(agent.bound_addresses()[1].local_addr.to_string(), auth)
            .engine_cache(cache.clone())
            .connect_tcp()
            .await
            .unwrap();
        let oid = oid!(1, 3, 6, 1, 6, 3, 10, 2, 1, 1, 0);
        let a = udp.get(&oid).await.unwrap();
        let b = tcp.get(&oid).await.unwrap();
        assert_eq!(a.varbinds, b.varbinds);
        assert_eq!(
            a.varbinds[0].value,
            Value::OctetString(agent.engine_id().to_vec().into())
        );
        assert_eq!(
            cache
                .get(&agent.bound_addresses()[0].local_addr)
                .unwrap()
                .msg_max_size()
                .as_usize(),
            async_snmp::MAX_UDP_PAYLOAD
        );
        assert_eq!(
            cache
                .get(&agent.bound_addresses()[1].local_addr)
                .unwrap()
                .msg_max_size()
                .as_usize(),
            TcpOptions::default().max_message_size
        );
        let capacity = tcp
            .get(&oid!(1, 3, 6, 1, 6, 3, 10, 2, 1, 4, 0))
            .await
            .unwrap();
        assert_eq!(
            capacity.varbinds[0].value,
            Value::Integer(async_snmp::MAX_UDP_PAYLOAD as i32)
        );
    }
    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn agent_udp_endpoint_shutdown_preserves_tcp_commands() {
    let mut options = TcpOptions::default();
    options.max_message_size = 4096;
    let agent = Agent::builder()
        .community("public")
        .allow_all_access()
        .listener(ListenerSource::Udp(
            UdpEndpoint::builder()
                .bind("127.0.0.1:0")
                .receive_capacity(484),
        ))
        .listener(ListenerSource::Tcp(
            TcpListenerSource::bind("127.0.0.1:0").session_options(options),
        ))
        .spawn()
        .await
        .unwrap();
    let udp = agent
        .udp_endpoint(agent.bound_addresses()[0].endpoint_id)
        .unwrap()
        .control();
    let tcp = Client::builder(agent.bound_addresses()[1].local_addr, Auth::v2c("public"))
        .request_timeout(Duration::from_secs(2))
        .connect_tcp()
        .await
        .unwrap();
    let capacity_oid = oid!(1, 3, 6, 1, 6, 3, 10, 2, 1, 4, 0);
    let before = tcp.get(&capacity_oid).await.unwrap();
    assert_eq!(before.varbinds[0].value, Value::Integer(484));

    udp.shutdown().await;
    assert_eq!(udp.status(), UdpStatus::Stopped);
    let after = tcp.get(&capacity_oid).await.unwrap();
    assert_eq!(after.varbinds[0].value, Value::Integer(4096));
    assert_eq!(agent.control().status(), AgentStatus::Running);
    agent.shutdown().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn closing_the_only_udp_endpoint_leaves_agent_under_service_control() {
    let agent = Agent::builder().bind("127.0.0.1:0").spawn().await.unwrap();
    let udp = agent
        .udp_endpoint(agent.bound_addresses()[0].endpoint_id)
        .unwrap()
        .control();
    udp.shutdown().await;
    assert!(
        tokio::time::timeout(Duration::from_secs(1), agent.control().wait_closed())
            .await
            .is_err()
    );
    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn command_only_agent_ignores_informs() {
    let agent = Agent::builder()
        .bind("127.0.0.1:0")
        .community(b"public")
        .allow_all_access()
        .spawn()
        .await
        .unwrap();
    let client = Client::builder(agent.bound_addresses()[0].local_addr, Auth::v2c("public"))
        .request_timeout(Duration::from_millis(100))
        .retry(Retry::none())
        .connect()
        .await
        .unwrap();
    let error = client
        .send_inform(&oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1), 0, vec![])
        .await
        .unwrap_err();
    assert!(matches!(error.exchange_source(), Error::Timeout { .. }));
    client
        .get(&oid!(1, 3, 6, 1, 6, 3, 10, 2, 1, 1, 0))
        .await
        .unwrap();
    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn attached_receiver_acknowledges_informs_and_returns_too_big() {
    use async_snmp::message::CommunityMessage;
    use async_snmp::{
        DecodeConfig, ErrorStatus, InformAckOutcome, NotificationAcknowledgement, NotificationPdu,
        NotificationReceiver, PduType, VarBind, Version,
    };

    let mut agent = Agent::builder()
        .bind("127.0.0.1:0")
        .community(b"public")
        .allow_all_access()
        .notifications(
            NotificationReceiver::builder()
                .community(b"public")
                .max_message_size(150)
                .queue_capacity(1),
        )
        .spawn()
        .await
        .unwrap();
    let mut receiver = agent.take_notifications().unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket
        .connect(agent.bound_addresses()[0].local_addr)
        .await
        .unwrap();
    let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1);

    for (request_id, value, status) in [
        (1, Value::Integer(42), ErrorStatus::NoError),
        (
            2,
            Value::OctetString(vec![0xab; 256].into()),
            ErrorStatus::TooBig,
        ),
        (3, Value::Integer(43), ErrorStatus::NoError),
    ] {
        let payload = VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0), value);
        let inform = NotificationPdu::inform(
            Version::V2c,
            request_id,
            0,
            &trap_oid,
            vec![payload.clone()],
        )
        .unwrap()
        .into_raw();
        let wire = CommunityMessage::v2c("public", inform.clone())
            .unwrap()
            .encode()
            .unwrap();
        socket.send(&wire).await.unwrap();
        let mut reply = [0; 2048];
        let len = tokio::time::timeout(Duration::from_secs(1), socket.recv(&mut reply))
            .await
            .expect("Inform did not receive a response")
            .unwrap();
        let reply = CommunityMessage::decode(
            bytes::Bytes::copy_from_slice(&reply[..len]),
            DecodeConfig::DEFAULT,
        )
        .unwrap()
        .value;
        let response = reply.pdu().standard().unwrap();
        assert_eq!(response.pdu_type(), PduType::Response);
        assert_eq!(response.request_id(), request_id);
        assert_eq!(response.error_fields(), Some((status.as_i32(), 0)));
        if status == ErrorStatus::TooBig {
            assert!(response.varbinds().is_empty());
        } else {
            assert_eq!(response.varbinds(), inform.varbinds());
            let delivered = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
                .await
                .expect("acknowledged Inform was not delivered")
                .unwrap();
            assert_eq!(delivered.wire_identity.request_id, Some(request_id));
            assert_eq!(delivered.notification.varbinds(), &[payload]);
            assert!(matches!(
                delivered.inform_ack,
                NotificationAcknowledgement::Completed(InformAckOutcome::Sent)
            ));
        }
    }
    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn ipv6_udp_and_tcp_listener_addresses_are_explicit() {
    let agent = Agent::builder()
        .community(b"public")
        .allow_all_access()
        .listener(ListenerSource::udp("[::1]:0"))
        .listener(ListenerSource::tcp("[::1]:0"))
        .spawn()
        .await
        .unwrap();
    assert!(
        agent
            .bound_addresses()
            .iter()
            .all(|bound| bound.local_addr.is_ipv6())
    );
    let udp = Client::builder(
        agent.bound_addresses()[0].local_addr.to_string(),
        Auth::v2c("public"),
    )
    .connect()
    .await
    .unwrap();
    let tcp = Client::builder(
        agent.bound_addresses()[1].local_addr.to_string(),
        Auth::v2c("public"),
    )
    .connect_tcp()
    .await
    .unwrap();
    let oid = oid!(1, 3, 6, 1, 6, 3, 10, 2, 1, 1, 0);
    assert_eq!(
        udp.get(&oid).await.unwrap().varbinds,
        tcp.get(&oid).await.unwrap().varbinds
    );
    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn connection_limit_is_shared_and_released_when_a_session_ends() {
    use tokio::io::AsyncReadExt;
    let agent = Agent::builder()
        .community(b"public")
        .allow_all_access()
        .max_connections(1)
        .listener(ListenerSource::tcp("127.0.0.1:0"))
        .listener(ListenerSource::tcp("127.0.0.1:0"))
        .spawn()
        .await
        .unwrap();
    let first = TcpStream::connect(agent.bound_addresses()[0].local_addr)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while agent.tcp_sessions().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let mut rejected = TcpStream::connect(agent.bound_addresses()[1].local_addr)
        .await
        .unwrap();
    let mut byte = [0];
    let closed = tokio::time::timeout(Duration::from_secs(1), rejected.read(&mut byte))
        .await
        .unwrap();
    assert!(closed.is_err() || closed.unwrap() == 0);
    assert_eq!(agent.tcp_sessions().len(), 1);
    drop(first);
    tokio::time::timeout(Duration::from_secs(1), async {
        while !agent.tcp_sessions().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let client = Client::builder(
        agent.bound_addresses()[1].local_addr.to_string(),
        Auth::v2c("public"),
    )
    .connect_tcp()
    .await
    .unwrap();
    client
        .get(&oid!(1, 3, 6, 1, 6, 3, 10, 2, 1, 1, 0))
        .await
        .unwrap();
    agent.shutdown().await.unwrap();
}
