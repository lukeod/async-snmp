#![cfg(feature = "agent")]
use async_snmp::message::CommunityMessage;
use async_snmp::{
    Agent, Auth, ClientBuilder, ListenerSource, Notification, NotificationPdu,
    NotificationReceiver, NotificationSinkId, NotificationTarget, RequestTransport, Retry,
    SinkStatus, TcpTransport, TransportKind, UdpEndpoint, Value, VarBind, Version, oid,
};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};

#[path = "common/wildcard_udp.rs"]
mod wildcard_udp;
use wildcard_udp::wildcard_udp_destination;

const WAIT: Duration = Duration::from_secs(3);
fn id(value: &str) -> NotificationSinkId {
    NotificationSinkId::new(value).unwrap()
}
fn cold() -> async_snmp::Oid {
    oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1)
}
fn engine_oid() -> async_snmp::Oid {
    oid!(1, 3, 6, 1, 6, 3, 10, 2, 1, 1, 0)
}

#[tokio::test]
async fn attached_receiver_exposes_only_sources_that_serve_its_role() {
    let udp_peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let configured_peer = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sink_peer = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut agent = Agent::builder()
        .listener(ListenerSource::udp("127.0.0.1:0"))
        .listener(ListenerSource::tcp("127.0.0.1:0"))
        .session(TcpTransport::builder().target(configured_peer.local_addr().unwrap()))
        .notification_sink(
            id("dedicated-udp"),
            NotificationTarget::udp(
                UdpEndpoint::builder().bind("127.0.0.1:0"),
                udp_peer.local_addr().unwrap().to_string(),
            ),
            Auth::v2c("public"),
        )
        .notification_sink(
            id("dedicated-tcp"),
            NotificationTarget::tcp(
                TcpTransport::builder().target(sink_peer.local_addr().unwrap()),
            ),
            Auth::v2c("public"),
        )
        .notifications(NotificationReceiver::builder())
        .spawn()
        .await
        .unwrap();
    let mut receiver = agent.take_notifications().unwrap();
    let [udp, tcp, configured, dedicated_udp, dedicated_tcp] = agent.bound_addresses() else {
        panic!("expected three receiving sources and two dedicated sinks");
    };

    assert_eq!(receiver.bound_addresses(), &[*udp, *tcp, *configured]);
    assert!(receiver.udp_endpoint(udp.endpoint_id).is_some());
    assert!(receiver.udp_endpoint(dedicated_udp.endpoint_id).is_none());
    assert!(agent.udp_endpoint(dedicated_udp.endpoint_id).is_some());

    let (mut configured_peer, _) = configured_peer.accept().await.unwrap();
    let (_sink_connection, _) = sink_peer.accept().await.unwrap();
    let mut accepted_peer = TcpStream::connect(tcp.local_addr).await.unwrap();
    let trap = CommunityMessage::v2c(
        "public",
        NotificationPdu::trap_v2(Version::V2c, 1, 0, &cold(), vec![])
            .unwrap()
            .into_raw(),
    )
    .unwrap()
    .encode()
    .unwrap();
    udp_peer.send_to(&trap, udp.local_addr).await.unwrap();
    accepted_peer.write_all(&trap).await.unwrap();
    configured_peer.write_all(&trap).await.unwrap();

    let mut received_endpoints = HashSet::new();
    for _ in 0..3 {
        let event = tokio::time::timeout(WAIT, receiver.recv())
            .await
            .unwrap()
            .unwrap();
        received_endpoints.insert(event.receive_info.endpoint_id());
    }
    assert_eq!(
        received_endpoints,
        [udp.endpoint_id, tcp.endpoint_id, configured.endpoint_id].into()
    );
    let receiver_sessions: HashSet<_> = receiver
        .tcp_sessions()
        .iter()
        .map(TcpTransport::endpoint_id)
        .collect();
    assert_eq!(
        receiver_sessions,
        [tcp.endpoint_id, configured.endpoint_id].into()
    );
    assert!(
        agent
            .tcp_sessions()
            .iter()
            .any(|session| session.endpoint_id() == dedicated_tcp.endpoint_id)
    );
    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn shared_wildcard_udp_commands_and_notifications_use_one_port() {
    let mut receiver = NotificationReceiver::spawn("127.0.0.1:0").await.unwrap();
    let target = receiver.bound_addresses()[0].local_addr;
    let agent = Agent::builder()
        .bind("0.0.0.0:0")
        .community("public")
        .allow_all_access()
        .notification_sink(
            id("shared"),
            NotificationTarget::shared_udp(0, target.to_string()),
            Auth::v2c("public"),
        )
        .inform_retry(Retry::none())
        .inform_timeout(WAIT)
        .spawn()
        .await
        .unwrap();
    let port = agent.bound_addresses()[0].local_addr.port();
    let manager_endpoint = UdpEndpoint::builder()
        .bind("127.0.0.1:0")
        .spawn()
        .await
        .unwrap();
    let peer = manager_endpoint
        .handle(wildcard_udp_destination(port))
        .unwrap()
        .strict_source(true);
    let manager = ClientBuilder::new(Auth::v2c("public"))
        .retry(Retry::none())
        .request_timeout(WAIT)
        .build_with_transport(peer)
        .unwrap();
    let query = engine_oid();
    let trap = cold();
    let (get, inform, sent) = tokio::join!(
        manager.get(&query),
        agent.send_inform(&trap, 1, vec![]),
        agent.send_trap(&trap, 2, vec![])
    );
    get.unwrap();
    assert!(inform.all_succeeded(), "{inform:?}");
    assert!(sent.all_succeeded());
    for _ in 0..2 {
        let event = tokio::time::timeout(WAIT, receiver.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(event.receive_info.peer_addr().port(), port);
    }
    let summary = agent.notification_sinks().next().unwrap();
    assert_eq!(
        summary.endpoint_id(),
        agent.bound_addresses()[0].endpoint_id
    );
    assert_eq!(summary.transport(), TransportKind::Udp);
    assert_eq!(summary.session_id(), None);
    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn v1_udp_traps_use_the_sink_source_address_and_port() {
    for bind in [
        "0.0.0.0:0",
        #[cfg(target_os = "linux")]
        "[::]:0",
        #[cfg(target_os = "linux")]
        "[::ffff:127.0.0.1]:0",
    ] {
        let mut receiver = NotificationReceiver::spawn("127.0.0.1:0").await.unwrap();
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .notification_sink(
                id("udp"),
                NotificationTarget::udp(
                    UdpEndpoint::builder().bind(bind),
                    receiver.bound_addresses()[0].local_addr.to_string(),
                ),
                Auth::v1("public"),
            )
            .spawn()
            .await
            .unwrap();
        let source_port = agent
            .notification_sinks()
            .next()
            .unwrap()
            .local_addr()
            .port();

        for explicit in [None, Some([192, 0, 2, 1])] {
            let varbinds = explicit
                .into_iter()
                .map(|address| {
                    VarBind::new(
                        async_snmp::notification::oids::snmp_trap_address(),
                        Value::IpAddress(address),
                    )
                })
                .collect();
            let outcome = agent.send_trap(&cold(), 0, varbinds).await;
            assert!(outcome.all_succeeded(), "{bind}: {outcome:?}");
            let event = tokio::time::timeout(WAIT, receiver.recv())
                .await
                .unwrap()
                .unwrap();
            let source = event.receive_info.peer_addr();
            assert_eq!(source.port(), source_port, "{bind}");
            assert_eq!(source.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST), "{bind}");
            let Notification::TrapV1 { trap, .. } = event.notification else {
                panic!("expected an SNMPv1 trap from {bind}");
            };
            assert_eq!(
                trap.agent_addr(),
                explicit.unwrap_or(Ipv4Addr::LOCALHOST.octets()),
                "{bind}"
            );
        }

        agent.shutdown().await.unwrap();
        receiver.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn dedicated_udp_and_tcp_are_prepared_and_mixed_fanout_preserves_order() {
    let mut udp = NotificationReceiver::spawn("127.0.0.1:0").await.unwrap();
    let mut tcp = NotificationReceiver::builder()
        .listener(ListenerSource::tcp("127.0.0.1:0"))
        .spawn()
        .await
        .unwrap();
    let prepared = Agent::builder()
        .bind("127.0.0.1:0")
        .notification_sink(
            id("tcp"),
            NotificationTarget::tcp(
                TcpTransport::builder()
                    .target(tcp.bound_addresses()[0].local_addr)
                    .max_message_size(256 * 1024),
            ),
            Auth::v2c("public"),
        )
        .notification_sink(
            id("udp"),
            NotificationTarget::udp(
                UdpEndpoint::builder()
                    .bind("127.0.0.1:0")
                    .max_message_size(4096),
                udp.bound_addresses()[0].local_addr.to_string(),
            ),
            Auth::v2c("public"),
        )
        .inform_timeout(WAIT)
        .inform_retry(Retry::none())
        .prepare()
        .await
        .unwrap();
    let (handle, runner, notifications) = prepared.into_parts();
    assert!(notifications.is_none());
    let summaries: Vec<_> = handle.notification_sinks().collect();
    assert_eq!(summaries[0].transport(), TransportKind::Tcp);
    assert!(summaries[0].session_id().is_some());
    assert_eq!(
        summaries[0].receive_limits().advertised().as_usize(),
        256 * 1024
    );
    assert_eq!(summaries[1].receive_limits().advertised().as_usize(), 4096);
    assert_ne!(
        summaries[1].local_addr(),
        handle.bound_addresses()[0].local_addr
    );
    let task = tokio::spawn(runner.run());
    for inform in [false, true] {
        let outcome = if inform {
            handle.send_inform(&cold(), 1, vec![]).await
        } else {
            handle.send_trap(&cold(), 1, vec![]).await
        };
        assert!(outcome.all_succeeded(), "{outcome:?}");
        assert_eq!(outcome.sinks()[0].sink.id(), &id("tcp"));
        assert_eq!(outcome.sinks()[1].sink.id(), &id("udp"));
        let a = tokio::time::timeout(WAIT, tcp.recv())
            .await
            .unwrap()
            .unwrap();
        let b = tokio::time::timeout(WAIT, udp.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(a.receive_info.peer_addr(), summaries[0].local_addr());
        assert_eq!(b.receive_info.peer_addr(), summaries[1].local_addr());
    }
    handle.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn accepted_and_connected_sessions_send_both_directions_and_never_reconnect() {
    let (server, runner, server_events) = Agent::builder()
        .listener(ListenerSource::tcp("127.0.0.1:0"))
        .client_exchanges(true)
        .notifications(NotificationReceiver::builder().admit_all_notifications())
        .prepare()
        .await
        .unwrap()
        .into_parts();
    let mut server_events = server_events.unwrap();
    let server_task = tokio::spawn(runner.run());
    let mut client = Agent::builder()
        .session(TcpTransport::builder().target(server.bound_addresses()[0].local_addr))
        .client_exchanges(true)
        .notifications(NotificationReceiver::builder().admit_all_notifications())
        .spawn()
        .await
        .unwrap();
    let mut client_events = client.take_notifications().unwrap();
    let connected = client.tcp_sessions()[0].clone();
    let outbound = client
        .notification_peer(id("connected"), connected.clone(), Auth::v2c("public"))
        .unwrap();
    assert!(matches!(
        outbound.send_inform(&cold(), 1, vec![]).await.status,
        SinkStatus::Succeeded
    ));
    let event = tokio::time::timeout(WAIT, server_events.recv())
        .await
        .unwrap()
        .unwrap();
    let accepted = server
        .tcp_sessions()
        .into_iter()
        .find(|p| Some(p.session_id()) == event.receive_info.session_id())
        .unwrap();
    let reverse = server
        .notification_peer(id("accepted"), accepted.clone(), Auth::v2c("public"))
        .unwrap();
    assert_eq!(reverse.summary().session_id(), Some(accepted.session_id()));
    for inform in [false, true] {
        let result = if inform {
            reverse.send_inform(&cold(), 1, vec![]).await
        } else {
            reverse.send_trap(&cold(), 1, vec![]).await
        };
        assert!(matches!(result.status, SinkStatus::Succeeded), "{result:?}");
        let event = tokio::time::timeout(WAIT, client_events.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            event.receive_info.session_id(),
            Some(connected.session_id())
        );
    }
    assert!(matches!(
        outbound.send_trap(&cold(), 1, vec![]).await.status,
        SinkStatus::Succeeded
    ));
    tokio::time::timeout(WAIT, server_events.recv())
        .await
        .unwrap()
        .unwrap();
    accepted.control().shutdown().await;
    for inform in [false, true] {
        let result = if inform {
            reverse.send_inform(&cold(), 1, vec![]).await
        } else {
            reverse.send_trap(&cold(), 1, vec![]).await
        };
        assert!(matches!(result.status, SinkStatus::Failed(_)));
        assert_eq!(result.sink.session_id(), Some(accepted.session_id()));
    }
    assert_eq!(client.bound_addresses().len(), 1);
    server.control().request_shutdown();
    server_task.await.unwrap().unwrap();
    client.shutdown().await.unwrap();
}

#[tokio::test]
async fn dropping_final_handle_stops_shared_sink_root_and_owned_child_drivers() {
    let sink = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let prepared = Agent::builder()
        .bind("127.0.0.1:0")
        .notification_sink(
            id("shared"),
            NotificationTarget::shared_udp(0, sink.local_addr().unwrap().to_string()),
            Auth::v2c("public"),
        )
        .notification_sink(
            id("dedicated"),
            NotificationTarget::udp(
                UdpEndpoint::builder().bind("127.0.0.1:0"),
                sink.local_addr().unwrap().to_string(),
            ),
            Auth::v2c("public"),
        )
        .inform_timeout(Duration::from_millis(20))
        .inform_retry(Retry::none())
        .prepare()
        .await
        .unwrap();
    let (agent, runner, _) = prepared.into_parts();
    let bound = agent.bound_addresses().to_vec();
    let task = tokio::spawn(runner.run());
    assert!(!agent.send_inform(&cold(), 0, vec![]).await.all_succeeded());
    drop(agent);
    tokio::time::timeout(WAIT, task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    for endpoint in bound {
        UdpSocket::bind(endpoint.local_addr).await.unwrap();
    }
}

#[tokio::test]
async fn unpolled_drop_closes_prepared_children_and_disables_notifications() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let prepared = Agent::builder()
        .bind("127.0.0.1:0")
        .notification_sink(
            id("tcp"),
            NotificationTarget::tcp(TcpTransport::builder().target(listener.local_addr().unwrap())),
            Auth::v2c("public"),
        )
        .notification_sink(
            id("udp"),
            NotificationTarget::udp(UdpEndpoint::builder().bind("127.0.0.1:0"), "127.0.0.1:9"),
            Auth::v2c("public"),
        )
        .prepare()
        .await
        .unwrap();
    let (agent, runner, _) = prepared.into_parts();
    let (mut stream, _) = listener.accept().await.unwrap();
    drop(runner);
    use tokio::io::AsyncReadExt;
    assert_eq!(
        tokio::time::timeout(WAIT, stream.read(&mut [0; 1]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert!(!agent.send_trap(&cold(), 0, vec![]).await.all_succeeded());
    assert!(!agent.send_inform(&cold(), 0, vec![]).await.all_succeeded());
    let bound = agent.bound_addresses().to_vec();
    drop(agent);
    for endpoint in bound
        .into_iter()
        .filter(|b| b.transport == TransportKind::Udp)
    {
        UdpSocket::bind(endpoint.local_addr).await.unwrap();
    }
}

#[tokio::test]
async fn failed_sink_preparation_releases_prior_tcp_and_udp_resources() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    // Preparation discovers the supplied socket's state after opening the TCP sink.
    let connected = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    connected.connect(addr).await.unwrap();
    let failed = Agent::builder()
        .listener(ListenerSource::udp_socket(socket))
        .notification_sink(
            id("tcp"),
            NotificationTarget::tcp(TcpTransport::builder().target(listener.local_addr().unwrap())),
            Auth::v2c("public"),
        )
        .notification_sink(
            id("invalid"),
            NotificationTarget::udp(
                UdpEndpoint::builder().from_socket(connected),
                addr.to_string(),
            ),
            Auth::v2c("public"),
        )
        .prepare()
        .await;
    assert!(matches!(
        failed.err().as_deref(),
        Some(async_snmp::Error::Config(message))
            if message.contains("requires an unconnected socket")
    ));
    UdpSocket::bind(addr).await.unwrap();
    let (mut stream, _) = tokio::time::timeout(WAIT, listener.accept())
        .await
        .unwrap()
        .unwrap();
    use tokio::io::AsyncReadExt;
    assert_eq!(
        tokio::time::timeout(WAIT, stream.read(&mut [0; 1]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn runner_abort_wakes_pending_informs_and_blocks_external_peer_traps() {
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let external = UdpEndpoint::builder()
        .bind("127.0.0.1:0")
        .receive_capacity(8192)
        .spawn()
        .await
        .unwrap();
    let peer = external.handle(target.local_addr().unwrap()).unwrap();
    let receive_capacity = peer.receive_limits().advertised();
    let prepared = Agent::builder()
        .bind("127.0.0.1:0")
        .notification_sink(
            id("external"),
            NotificationTarget::peer(peer),
            Auth::v2c("public"),
        )
        .inform_timeout(Duration::from_secs(60))
        .inform_retry(Retry::none())
        .prepare()
        .await
        .unwrap();
    let (agent, runner, _) = prepared.into_parts();
    let engine = agent.local_engine();
    assert_eq!(
        engine.receive_capacity(),
        Some(async_snmp::UDP_RECEIVE_LIMITS.advertised())
    );
    let task = tokio::spawn(runner.run());
    let cloned = agent.clone();
    let pending = tokio::spawn(async move { cloned.send_inform(&cold(), 0, vec![]).await });
    tokio::time::timeout(WAIT, target.recv_from(&mut [0; 2048]))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        engine.receive_capacity(),
        Some(async_snmp::UDP_RECEIVE_LIMITS.advertised())
    );
    let registration = engine.register_receive_capacity(receive_capacity);
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(engine.receive_capacity(), Some(receive_capacity));
    drop(registration);
    assert_eq!(engine.receive_capacity(), None);
    let result = tokio::time::timeout(WAIT, pending).await.unwrap().unwrap();
    assert!(!result.all_succeeded());
    assert!(!agent.send_trap(&cold(), 0, vec![]).await.all_succeeded());
    assert!(
        tokio::time::timeout(Duration::from_millis(40), target.recv_from(&mut [0; 2048]))
            .await
            .is_err()
    );
    // The externally owned endpoint remains usable after the Agent terminates.
    external
        .handle(target.local_addr().unwrap())
        .unwrap()
        .send(bytes::Bytes::from_static(b"external"))
        .await
        .unwrap();
    tokio::time::timeout(WAIT, target.recv_from(&mut [0; 32]))
        .await
        .unwrap()
        .unwrap();
}

#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
#[tokio::test]
async fn shared_v3_notifications_keep_trap_and_inform_authority_separate() {
    use async_snmp::{AuthProtocol, AuthoritativeEngine, Notification, PrivProtocol, UsmConfig};
    let make_engine = |name: &[u8]| {
        AuthoritativeEngine::install(name.to_vec(), |_| Ok::<_, std::convert::Infallible>(()))
            .unwrap()
    };
    let sink_engine = make_engine(b"sink-authority");
    let local_engine = make_engine(b"originator-authority");
    let mut receiver = NotificationReceiver::builder()
        .bind("127.0.0.1:0")
        .authoritative_engine(sink_engine.clone())
        .admit_all_notifications()
        .usm_user("user", |u| {
            u.auth_priv(
                AuthProtocol::Sha256,
                b"auth-password",
                PrivProtocol::Aes128,
                b"priv-password",
            )
        })
        .unwrap()
        .spawn()
        .await
        .unwrap();
    let security = UsmConfig::new("user")
        .auth_priv(
            AuthProtocol::Sha256,
            b"auth-password",
            PrivProtocol::Aes128,
            b"priv-password",
        )
        .unwrap();
    let agent = Agent::builder()
        .bind("127.0.0.1:0")
        .authoritative_engine(local_engine.clone())
        .usm_user("user", |u| {
            u.auth_priv(
                AuthProtocol::Sha256,
                b"auth-password",
                PrivProtocol::Aes128,
                b"priv-password",
            )
        })
        .unwrap()
        .allow_all_access()
        .notification_sink(
            id("private"),
            NotificationTarget::shared_udp(0, receiver.bound_addresses()[0].local_addr.to_string()),
            security.clone(),
        )
        .inform_retry(Retry::none())
        .inform_timeout(WAIT)
        .spawn()
        .await
        .unwrap();
    let endpoint = UdpEndpoint::builder()
        .bind("127.0.0.1:0")
        .spawn()
        .await
        .unwrap();
    let client = ClientBuilder::new(security)
        .retry(Retry::none())
        .request_timeout(WAIT)
        .build_with_transport(
            endpoint
                .handle(agent.bound_addresses()[0].local_addr)
                .unwrap(),
        )
        .unwrap();
    let trap = cold();
    let query = engine_oid();
    let (command, informed, trapped) = tokio::join!(
        client.get(&query),
        agent.send_inform(&trap, 5, vec![]),
        agent.send_trap(&trap, 6, vec![])
    );
    assert!(informed.all_succeeded(), "{informed:?}");
    assert!(trapped.all_succeeded(), "{trapped:?}");
    assert_eq!(
        command.unwrap().varbinds[0].value,
        async_snmp::Value::OctetString(agent.engine_id().to_vec().into())
    );
    let mut saw_trap = false;
    let mut saw_inform = false;
    for _ in 0..2 {
        let event = tokio::time::timeout(WAIT, receiver.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            event.receive_info.peer_addr(),
            agent.bound_addresses()[0].local_addr
        );
        let wire = event.wire_identity.v3.as_ref().unwrap();
        match event.notification {
            Notification::TrapV3 { .. } => {
                saw_trap = true;
                assert_eq!(wire.authoritative_engine_id.as_ref(), agent.engine_id());
            }
            Notification::InformV3 { .. } => {
                saw_inform = true;
                assert_eq!(
                    wire.authoritative_engine_id.as_ref(),
                    sink_engine.engine_id()
                );
            }
            other => panic!("unexpected notification: {other:?}"),
        }
    }
    assert!(saw_trap && saw_inform);
    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn selected_udp_retransmissions_keep_port_and_stream_cancellation_stops_retries() {
    let (observer, _events) = async_snmp::TransportObserver::channel(16).unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let agent = Agent::builder()
        .listener(ListenerSource::Udp(
            UdpEndpoint::builder()
                .bind("127.0.0.1:0")
                .observer(observer.clone()),
        ))
        .notification_sink(
            id("retry"),
            NotificationTarget::shared_udp(0, socket.local_addr().unwrap().to_string()),
            Auth::v2c("public"),
        )
        .inform_timeout(Duration::from_millis(100))
        .inform_retry(Retry::fixed(10, Duration::from_millis(10)).unwrap())
        .spawn()
        .await
        .unwrap();
    let trap = cold();
    let mut stream = agent.send_inform_stream(&trap, 0, vec![]);
    let mut buffer = [0; 2048];
    for _ in 0..2 {
        tokio::select! {
            result = stream.next() => panic!("retry completed early: {result:?}"),
            received = tokio::time::timeout(WAIT, socket.recv_from(&mut buffer)) => {
                assert_eq!(received.unwrap().unwrap().1, agent.bound_addresses()[0].local_addr);
            }
        }
    }
    drop(stream);
    assert!(
        tokio::time::timeout(Duration::from_millis(180), socket.recv_from(&mut buffer))
            .await
            .is_err()
    );
    assert_eq!(observer.stats().sent_messages, 2);
    assert_eq!(observer.stats().received_messages, 0);
    assert_eq!(
        observer.stats().socket_written_bytes,
        observer.stats().sent_message_bytes
    );
    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn selected_peer_send_capacity_is_applied_to_traps() {
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let agent = Agent::builder()
        .bind("127.0.0.1:0")
        .notification_sink(
            id("limited"),
            NotificationTarget::udp(
                UdpEndpoint::builder().bind("127.0.0.1:0").send_capacity(16),
                target.local_addr().unwrap().to_string(),
            ),
            Auth::v2c("public"),
        )
        .spawn()
        .await
        .unwrap();
    assert_eq!(
        agent.notification_sinks().next().unwrap().send_capacity(),
        16
    );
    assert!(!agent.send_trap(&cold(), 0, vec![]).await.all_succeeded());
    assert!(
        tokio::time::timeout(Duration::from_millis(30), target.recv_from(&mut [0; 2048]))
            .await
            .is_err()
    );
    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn shared_sink_resolves_using_selected_listener_family_and_rejects_tcp_indices() {
    let mut receiver = NotificationReceiver::spawn("[::]:0").await.unwrap();
    let agent = Agent::builder()
        .listener(ListenerSource::udp("127.0.0.1:0"))
        .listener(ListenerSource::udp("[::]:0"))
        .notification_sink(
            id("ipv6"),
            NotificationTarget::shared_udp(
                1,
                format!(
                    "localhost:{}",
                    receiver.bound_addresses()[0].local_addr.port()
                ),
            ),
            Auth::v2c("public"),
        )
        .inform_timeout(WAIT)
        .inform_retry(Retry::none())
        .spawn()
        .await
        .unwrap();
    let summary = agent.notification_sinks().next().unwrap();
    assert!(summary.dest().is_ipv6());
    assert_eq!(
        summary.endpoint_id(),
        agent.bound_addresses()[1].endpoint_id
    );
    assert!(agent.send_inform(&cold(), 0, vec![]).await.all_succeeded());
    let event = tokio::time::timeout(WAIT, receiver.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        event.receive_info.peer_addr().port(),
        summary.local_addr().port()
    );
    agent.shutdown().await.unwrap();
    assert!(
        Agent::builder()
            .listener(ListenerSource::tcp("127.0.0.1:0"))
            .notification_sink(
                id("wrong-kind"),
                NotificationTarget::shared_udp(0, "127.0.0.1:9"),
                Auth::v2c("public")
            )
            .prepare()
            .await
            .is_err()
    );
}

#[tokio::test]
async fn tcp_traps_and_informs_exceed_udp_capacity() {
    let mut receiver = NotificationReceiver::builder()
        .listener(ListenerSource::tcp("127.0.0.1:0"))
        .max_message_size(256 * 1024)
        .spawn()
        .await
        .unwrap();
    let agent = Agent::builder()
        .bind("127.0.0.1:0")
        .notification_sink(
            id("large"),
            NotificationTarget::tcp(
                TcpTransport::builder()
                    .target(receiver.bound_addresses()[0].local_addr)
                    .max_message_size(256 * 1024),
            ),
            Auth::v2c("public"),
        )
        .inform_timeout(WAIT)
        .inform_retry(Retry::none())
        .spawn()
        .await
        .unwrap();
    let payload = async_snmp::VarBind::new(
        oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0),
        async_snmp::Value::OctetString(vec![42; 80_000].into()),
    );
    for inform in [false, true] {
        let result = if inform {
            agent.send_inform(&cold(), 0, vec![payload.clone()]).await
        } else {
            agent.send_trap(&cold(), 0, vec![payload.clone()]).await
        };
        assert!(result.all_succeeded(), "{result:?}");
        let event = tokio::time::timeout(WAIT, receiver.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(event.receive_info.received_len() > async_snmp::MAX_UDP_PAYLOAD);
    }
    agent.shutdown().await.unwrap();
}
