//! Real-socket application/session composition and admission boundaries.
use super::*;
use crate::{Agent, Auth, Client, ClientBuilder, NotificationReceiver, Retry, Value, oid};
use bytes::Bytes;
use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};

fn engine(id: &'static [u8]) -> crate::AuthoritativeEngine {
    crate::AuthoritativeEngine::install(id.to_vec(), |_| Ok::<_, Infallible>(())).unwrap()
}
fn agent(id: &'static [u8]) -> crate::agent::AgentBuilder {
    Agent::builder()
        .community(b"public")
        .allow_all_access()
        .authoritative_engine(engine(id))
        .client_exchanges(true)
        .notifications(NotificationReceiver::builder().admit_all_notifications())
}
fn client(session: TcpTransport, auth: Auth) -> Client<TcpTransport> {
    ClientBuilder::new(auth)
        .retry(Retry::none())
        .request_timeout(Duration::from_secs(2))
        .build_with_transport(session)
        .unwrap()
}
fn oid() -> crate::Oid {
    oid!(1, 3, 6, 1, 6, 3, 10, 2, 1, 1, 0)
}
fn trap() -> crate::Oid {
    crate::notification::oids::cold_start()
}
fn community(pdu: crate::Pdu) -> Bytes {
    crate::message::CommunityMessage::v2c("public", pdu)
        .unwrap()
        .encode()
        .unwrap()
}
fn registration(id: i32) -> RequestRegistration {
    RequestRegistration::community(
        id,
        tokio::time::Instant::now() + Duration::from_secs(2),
        crate::CommunityVersion::V2c,
        "public",
        CommunityResponsePolicy::Exact,
    )
}
async fn until(mut ready: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while !ready() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}
async fn read(stream: &mut TcpStream) -> Bytes {
    tokio::time::timeout(Duration::from_secs(2), async {
        let mut bytes = vec![0; 2];
        stream.read_exact(&mut bytes).await.unwrap();
        let len = if bytes[1] < 128 {
            bytes[1] as usize
        } else {
            let n = (bytes[1] & 127) as usize;
            bytes.resize(2 + n, 0);
            stream.read_exact(&mut bytes[2..]).await.unwrap();
            bytes[2..]
                .iter()
                .fold(0usize, |value, byte| value * 256 + *byte as usize)
        };
        let header = bytes.len();
        bytes.resize(header + len, 0);
        stream.read_exact(&mut bytes[header..]).await.unwrap();
        Bytes::from(bytes)
    })
    .await
    .unwrap()
}
async fn accepted(service: &Agent) -> TcpTransport {
    until(|| !service.tcp_sessions().is_empty()).await;
    service.tcp_sessions()[0].clone()
}

#[tokio::test]
async fn coalesced_informs_cannot_consume_session_output_budget() {
    coalesced_informs_with_budgets(2048, 8192).await;
}

#[tokio::test]
async fn coalesced_informs_cannot_consume_service_output_budget() {
    coalesced_informs_with_budgets(8192, 8192).await;
}

async fn coalesced_informs_with_budgets(session_budget: usize, service_budget: usize) {
    let options = TcpOptions {
        max_message_size: 1024,
        send_capacity: 1024,
        max_buffered_bytes: session_budget,
        ..TcpOptions::default()
    };
    let mut receiver = NotificationReceiver::builder()
        .max_tcp_buffered_bytes(service_budget)
        .queue_capacity(32)
        .listener(ListenerSource::Tcp(
            TcpListenerSource::bind("127.0.0.1:0").session_options(options),
        ))
        .spawn()
        .await
        .unwrap();
    let mut peers = Vec::new();
    let mut input = Vec::new();
    for id in 1..=8 {
        let frame = community(crate::Pdu::inform_request(
            id,
            1,
            &trap(),
            vec![crate::VarBind::new(
                oid(),
                Value::OctetString(vec![42; 800].into()),
            )],
        ));
        assert!((800..=1024).contains(&frame.len()));
        input.extend_from_slice(&frame);
    }
    for _ in 0..2 {
        let mut peer = TcpStream::connect(receiver.bound_addresses()[0].local_addr)
            .await
            .unwrap();
        peer.write_all(&input).await.unwrap();
        peers.push(peer);
    }
    for peer in &mut peers {
        let mut ids = Vec::new();
        for _ in 1..=8 {
            let response = crate::message::CommunityMessage::decode(
                read(peer).await,
                crate::DecodeConfig::DEFAULT,
            )
            .unwrap()
            .value;
            ids.push(response.pdu().standard().unwrap().request_id());
        }
        ids.sort_unstable();
        assert_eq!(ids, (1..=8).collect::<Vec<_>>());
    }
    for _ in 0..16 {
        receiver.recv().await.unwrap();
    }
    receiver.shutdown().await.unwrap();
}

#[tokio::test]
async fn accepted_and_connected_roles_exchange_both_directions_and_close_independently() {
    let mut a = agent(b"tcp-acceptor")
        .listener(ListenerSource::tcp("127.0.0.1:0"))
        .spawn()
        .await
        .unwrap();
    let mut b = agent(b"tcp-connector")
        .session(TcpTransport::builder().target(a.bound_addresses()[0].local_addr))
        .spawn()
        .await
        .unwrap();
    assert_eq!(b.bound_addresses().len(), 1);
    assert_eq!(b.bound_addresses()[0].transport, TransportKind::Tcp);
    let mut na = a.take_notifications().unwrap();
    let mut nb = b.take_notifications().unwrap();
    let sa = accepted(&a).await;
    let sb = b.tcp_sessions()[0].clone();
    assert_eq!(sa.peer_addr(), sb.local_addr());
    assert_eq!(sb.peer_addr(), sa.local_addr());
    for auth in [Auth::v1("public"), Auth::v2c("public")] {
        let ab = client(sa.clone(), auth.clone());
        let ba = client(sb.clone(), auth);
        let oid = oid();
        let (x, y) = tokio::join!(ab.get(&oid), ba.get(&oid));
        assert_eq!(
            x.unwrap().varbinds[0].value,
            Value::OctetString(b.engine_id().to_vec().into())
        );
        assert_eq!(
            y.unwrap().varbinds[0].value,
            Value::OctetString(a.engine_id().to_vec().into())
        );
        ab.send_trap(&trap(), 1, vec![]).await.unwrap();
        let event = nb.recv().await.unwrap();
        assert_eq!(event.receive_info.session_id(), Some(sb.session_id()));
        assert_eq!(event.receive_info.endpoint_id(), sb.endpoint_id());
        assert_eq!(event.receive_info.local_addr(), sb.local_addr());
        assert!(event.receive_info.received_len() > 20);
    }
    let ab = client(sa.clone(), Auth::v2c("public"));
    let ba = client(sb.clone(), Auth::v2c("public"));
    let trap = trap();
    let (x, y) = tokio::join!(
        ab.send_inform(&trap, 1, vec![]),
        ba.send_inform(&trap, 1, vec![])
    );
    x.unwrap();
    y.unwrap();
    na.recv().await.unwrap();
    nb.recv().await.unwrap();
    nb.close();
    ab.get(&oid()).await.unwrap();
    ba.get(&oid()).await.unwrap();
    ab.send_trap(&trap, 2, vec![]).await.unwrap();
    assert!(nb.recv().await.is_none());
    b.shutdown().await.unwrap();
    until(|| sa.control().is_shutdown()).await;
    assert!(ab.get(&oid()).await.is_err());
    let replacement = TcpTransport::connect(a.bound_addresses()[0].local_addr)
        .await
        .unwrap();
    until(|| !a.tcp_sessions().is_empty()).await;
    assert_ne!(a.tcp_sessions()[0].session_id(), sa.session_id());
    assert!(ab.get(&oid()).await.is_err());
    replacement.control().shutdown().await;
    a.shutdown().await.unwrap();
}

#[tokio::test]
async fn standalone_notification_mixed_sources_and_outbound_session() {
    let mut peer = agent(b"collector-peer")
        .listener(ListenerSource::tcp("127.0.0.1:0"))
        .spawn()
        .await
        .unwrap();
    let mut collector = NotificationReceiver::builder()
        .client_exchanges(true)
        .listener(ListenerSource::udp("127.0.0.1:0"))
        .listener(ListenerSource::tcp("127.0.0.1:0"))
        .session(TcpTransport::builder().target(peer.bound_addresses()[0].local_addr))
        .spawn()
        .await
        .unwrap();
    let _peer_notifications = peer.take_notifications().unwrap();
    assert_eq!(collector.bound_addresses().len(), 3);
    let outbound = collector.tcp_sessions()[0].clone();
    client(outbound.clone(), Auth::v2c("public"))
        .get(&oid())
        .await
        .unwrap();
    for bound in collector.bound_addresses().to_vec().into_iter().take(2) {
        for auth in [Auth::v1("public"), Auth::v2c("public")] {
            let builder = Client::builder(bound.local_addr.to_string(), auth).retry(Retry::none());
            if bound.transport == TransportKind::Tcp {
                let sender = builder.connect_tcp().await.unwrap();
                sender.send_trap(&trap(), 1, vec![]).await.unwrap();
            } else {
                let sender = builder.connect().await.unwrap();
                sender.send_trap(&trap(), 1, vec![]).await.unwrap();
            }
            let event = collector.recv().await.unwrap();
            assert_eq!(event.receive_info.endpoint_id(), bound.endpoint_id);
            assert_eq!(event.receive_info.transport(), bound.transport);
        }
    }
    let incoming = client(accepted(&peer).await, Auth::v2c("public"));
    incoming.send_inform(&trap(), 1, vec![]).await.unwrap();
    assert_eq!(
        collector.recv().await.unwrap().receive_info.session_id(),
        Some(outbound.session_id())
    );
    collector.close();
    client(outbound, Auth::v2c("public"))
        .get(&oid())
        .await
        .unwrap();
    collector.shutdown().await.unwrap();
    peer.shutdown().await.unwrap();
}

#[tokio::test]
async fn collision_rejection_and_identical_ids_are_session_scoped() {
    let mut service = agent(b"tcp-collision")
        .listener(ListenerSource::tcp("127.0.0.1:0"))
        .spawn()
        .await
        .unwrap();
    let mut events = service.take_notifications().unwrap();
    let mut peers = Vec::new();
    for _ in 0..2 {
        peers.push(
            TcpStream::connect(service.bound_addresses()[0].local_addr)
                .await
                .unwrap(),
        );
    }
    until(|| service.tcp_sessions().len() == 2).await;
    let mut pending = Vec::new();
    let calls = Arc::new(AtomicUsize::new(0));
    for stream in &mut peers {
        let session = service
            .tcp_sessions()
            .into_iter()
            .find(|s| s.peer_addr() == stream.local_addr().unwrap())
            .unwrap();
        let calls = calls.clone();
        pending.push(tokio::spawn(async move {
            session
                .request_with(
                    community(crate::Pdu::get_request(41, &[oid()])),
                    registration(41),
                    move |packet| {
                        let (bytes, _) = packet.into_parts();
                        let pdu = crate::message::CommunityMessage::decode(
                            bytes,
                            crate::DecodeConfig::DEFAULT,
                        )?
                        .value
                        .into_pdu()
                        .unwrap();
                        calls.fetch_add(1, Ordering::SeqCst);
                        if pdu.varbinds().is_empty() {
                            Ok(Candidate::Reject)
                        } else {
                            Ok(Candidate::Accept(()))
                        }
                    },
                )
                .await
        }));
        read(stream).await;
        stream
            .write_all(&community(crate::Pdu::inform_request(
                41,
                1,
                &trap(),
                vec![],
            )))
            .await
            .unwrap();
        read(stream).await;
        assert_eq!(
            events.recv().await.unwrap().wire_identity.request_id,
            Some(41)
        );
        stream.write_all(&[0x30, 0]).await.unwrap();
        stream
            .write_all(&community(crate::Pdu::response(41, 0, 0, vec![])))
            .await
            .unwrap();
    }
    for stream in &mut peers {
        stream
            .write_all(&community(crate::Pdu::response(
                41,
                0,
                0,
                vec![crate::VarBind::new(oid(), Value::Null)],
            )))
            .await
            .unwrap();
    }
    for request in pending {
        request.await.unwrap().unwrap();
    }
    assert_eq!(calls.load(Ordering::SeqCst), 4);
    service.shutdown().await.unwrap();
}

#[tokio::test]
async fn complete_shared_tcp_response_precedes_framing_failure() {
    let service = agent(b"tcp-final-response")
        .listener(ListenerSource::tcp("127.0.0.1:0"))
        .spawn()
        .await
        .unwrap();
    let mut stream = TcpStream::connect(service.bound_addresses()[0].local_addr)
        .await
        .unwrap();
    let session = accepted(&service).await;
    let request = |id| {
        let session = session.clone();
        tokio::spawn(async move {
            session
                .request_with(
                    community(crate::Pdu::get_request(id, &[oid()])),
                    registration(id),
                    |packet| Ok(Candidate::Accept(packet.into_parts().0)),
                )
                .await
        })
    };
    let completed = request(41);
    let unanswered = request(42);
    read(&mut stream).await;
    read(&mut stream).await;

    let response = community(crate::Pdu::response(41, 0, 0, vec![]));
    // Coalesce the invalid header with the complete response so the
    // current-thread TCP reader can encounter it before dispatch runs.
    let mut wire = response.to_vec();
    wire.extend_from_slice(&[0x30, 0x80]);
    stream.write_all(&wire).await.unwrap();

    assert_eq!(completed.await.unwrap().unwrap(), response);
    let error = unanswered.await.unwrap().unwrap_err();
    assert!(
        matches!(error.exchange_source(), crate::Error::Decode(error)
        if error.offset == 1 && error.kind == crate::DecodeErrorKind::IndefiniteLength)
    );
    service.shutdown().await.unwrap();
}

#[tokio::test]
async fn full_shared_notification_queue_closes_session_and_fails_pending_with_identity() {
    let mut service = NotificationReceiver::builder()
        .listener(ListenerSource::tcp("127.0.0.1:0"))
        .client_exchanges(true)
        .queue_capacity(1)
        .spawn()
        .await
        .unwrap();
    let mut stream = TcpStream::connect(service.bound_addresses()[0].local_addr)
        .await
        .unwrap();
    stream
        .write_all(&community(crate::Pdu::inform_request(
            1,
            1,
            &trap(),
            vec![],
        )))
        .await
        .unwrap();
    read(&mut stream).await;
    let session = service.tcp_sessions()[0].clone();
    let id = session.session_id();
    let handle = session.clone();
    let request = tokio::spawn(async move {
        handle
            .request_with(
                community(crate::Pdu::get_request(42, &[oid()])),
                registration(42),
                |_| Ok(Candidate::Accept(())),
            )
            .await
    });
    read(&mut stream).await;
    stream
        .write_all(&community(crate::Pdu::inform_request(
            2,
            1,
            &trap(),
            vec![],
        )))
        .await
        .unwrap();
    let error = request.await.unwrap().unwrap_err();
    let crate::Error::SharedOperation { source } = &*error else {
        panic!("{error:?}")
    };
    assert!(matches!(&**source, crate::Error::Session { session_id, .. } if *session_id == id));
    until(|| session.control().is_shutdown()).await;
    service.recv().await.unwrap();
    let independent = TcpTransport::connect(service.bound_addresses()[0].local_addr)
        .await
        .unwrap();
    client(independent, Auth::v2c("public"))
        .send_inform(&trap(), 1, vec![])
        .await
        .unwrap();
    service.recv().await.unwrap();
    service.shutdown().await.unwrap();
}

#[tokio::test]
async fn inbound_only_queue_pause_excludes_progress_deadline_and_times_out_separately() {
    let options = TcpOptions {
        header_timeout: Duration::from_millis(20),
        body_timeout: Duration::from_millis(20),
        ..Default::default()
    };
    let mut service = NotificationReceiver::builder()
        .listener(ListenerSource::Tcp(
            TcpListenerSource::bind("127.0.0.1:0").session_options(options),
        ))
        .queue_capacity(1)
        .overload_timeout(Duration::from_millis(350))
        .spawn()
        .await
        .unwrap();
    let mut stream = TcpStream::connect(service.bound_addresses()[0].local_addr)
        .await
        .unwrap();
    let inform = community(crate::Pdu::inform_request(1, 1, &trap(), vec![]));
    stream.write_all(&inform).await.unwrap();
    read(&mut stream).await;
    stream.write_all(&inform).await.unwrap();
    tokio::time::sleep(Duration::from_millis(70)).await;
    assert!(!service.tcp_sessions()[0].control().is_shutdown());
    service.recv().await.unwrap();
    read(&mut stream).await;
    service.recv().await.unwrap();
    stream.write_all(&inform).await.unwrap();
    read(&mut stream).await;
    let session = service.tcp_sessions()[0].clone();
    stream.write_all(&inform).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), session.control().wait_closed())
        .await
        .unwrap();
    assert!(matches!(session.control().status(), TcpStatus::Failed(_)));
    service.recv().await.unwrap();
    service.shutdown().await.unwrap();
}

#[tokio::test]
async fn shared_udp_sink_enables_exchanges_only_on_its_listener() {
    let mut receiver = NotificationReceiver::spawn("127.0.0.1:0").await.unwrap();
    let destination = receiver.bound_addresses()[0].local_addr;
    let mut service = agent(b"udp-sink-exchanges")
        .client_exchanges(false)
        .listener(ListenerSource::udp("127.0.0.1:0"))
        .listener(ListenerSource::tcp("127.0.0.1:0"))
        .listener(ListenerSource::udp("127.0.0.1:0"))
        .notification_sink(
            crate::NotificationSinkId::new("selected").unwrap(),
            crate::NotificationTarget::shared_udp(2, destination.to_string()),
            Auth::v2c("public"),
        )
        .inform_retry(Retry::none())
        .inform_timeout(Duration::from_secs(2))
        .notifications(NotificationReceiver::builder().queue_capacity(1))
        .spawn()
        .await
        .unwrap();
    let mut events = service.take_notifications().unwrap();
    let mut stream = TcpStream::connect(service.bound_addresses()[1].local_addr)
        .await
        .unwrap();

    let inform = community(crate::Pdu::inform_request(1, 1, &trap(), vec![]));
    stream.write_all(&inform).await.unwrap();
    read(&mut stream).await;
    stream.write_all(&inform).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(70), stream.read(&mut [0]))
            .await
            .is_err(),
        "the second TCP Inform should wait for queue capacity"
    );

    let outcome = service.send_inform(&trap(), 1, vec![]).await;
    assert!(outcome.all_succeeded(), "{outcome:?}");

    events.recv().await.unwrap();
    read(&mut stream).await;
    events.recv().await.unwrap();

    let unrelated = service
        .udp_endpoint(service.bound_addresses()[0].endpoint_id)
        .unwrap()
        .handle(destination)
        .unwrap();
    let error = unrelated
        .request_with(
            community(crate::Pdu::get_request(2, &[oid()])),
            registration(2),
            |_| Ok(Candidate::Accept(())),
        )
        .await
        .unwrap_err();
    assert!(matches!(error.exchange_source(), crate::Error::Config(_)));

    service.shutdown().await.unwrap();
    receiver.shutdown().await.unwrap();
}

#[tokio::test]
async fn selected_session_controls_retain_root_lifetime_without_driver_cycle() {
    let service = agent(b"tcp-lease")
        .listener(ListenerSource::tcp("127.0.0.1:0"))
        .prepare()
        .await
        .unwrap();
    let (agent, runner, _) = service.into_parts();
    let root = agent.control();
    let task = tokio::spawn(runner.run());
    let mut stream = TcpStream::connect(agent.bound_addresses()[0].local_addr)
        .await
        .unwrap();
    let selected = accepted(&agent).await;
    let control = selected.control();
    drop(selected);
    drop(agent);
    drop(root);
    stream
        .write_all(&community(crate::Pdu::get_request(1, &[oid()])))
        .await
        .unwrap();
    read(&mut stream).await;
    assert!(!task.is_finished());
    drop(control);
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn partial_notification_setup_failure_releases_owned_sources() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp = socket.local_addr().unwrap();
    assert!(
        NotificationReceiver::builder()
            .listener(ListenerSource::tcp_listener(listener))
            .listener(ListenerSource::udp_socket(socket))
            .listener(ListenerSource::tcp("invalid"))
            .prepare()
            .await
            .is_err()
    );
    tokio::net::TcpListener::bind(address).await.unwrap();
    UdpSocket::bind(udp).await.unwrap();
}

#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
fn secured_agent(id: &'static [u8]) -> crate::agent::AgentBuilder {
    agent(id)
        .usm_user("noauth", Ok)
        .unwrap()
        .usm_user("auth", |u| {
            u.auth(crate::AuthProtocol::Sha256, b"shared-auth-password")
        })
        .unwrap()
        .usm_user("priv", |u| {
            u.auth_priv(
                crate::AuthProtocol::Sha256,
                b"shared-auth-password",
                crate::PrivProtocol::Aes128,
                b"shared-priv-password",
            )
        })
        .unwrap()
}
#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
fn security(name: &str) -> crate::UsmConfig {
    let config = crate::UsmConfig::new(name.to_owned());
    match name {
        "noauth" => config,
        "auth" => config
            .auth(crate::AuthProtocol::Sha256, b"shared-auth-password")
            .unwrap(),
        _ => config
            .auth_priv(
                crate::AuthProtocol::Sha256,
                b"shared-auth-password",
                crate::PrivProtocol::Aes128,
                b"shared-priv-password",
            )
            .unwrap(),
    }
}
#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
fn secured(
    pdu: crate::Pdu,
    id: i32,
    engine: &[u8],
    config: &crate::UsmConfig,
    reportable: bool,
) -> bytes::Bytes {
    let keys = config.derive_keys(engine).unwrap();
    crate::v3::encode::encode_v3_message(
        &pdu,
        id,
        engine,
        1,
        0,
        config,
        Some(&keys),
        Some(&crate::v3::SaltCounter::new().unwrap()),
        None,
        None,
        reportable,
        crate::MessageSize::from_i32(65507).unwrap(),
    )
    .unwrap()
    .into()
}

#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
#[tokio::test]
async fn encrypted_collision_preserves_role_and_failure_ownership() {
    const COLLISION_ID: i32 = 77;
    const REMOTE_ENGINE: &[u8] = b"tcp-remote-engine";

    let mut service = secured_agent(b"tcp-secured-collision")
        .listener(ListenerSource::tcp("127.0.0.1:0"))
        .spawn()
        .await
        .unwrap();
    let mut events = service.take_notifications().unwrap();
    let mut config = security("priv");
    config.validate_and_precompute().unwrap();
    let encode = |pdu: crate::Pdu, engine| {
        let reportable = pdu.pdu_type().is_confirmed();
        secured(pdu, COLLISION_ID, engine, &config, reportable)
    };
    let outgoing = encode(
        crate::Pdu::get_request(COLLISION_ID, &[oid()]),
        REMOTE_ENGINE,
    );
    let command = encode(
        crate::Pdu::get_request(COLLISION_ID, &[oid()]),
        service.engine_id(),
    );
    let inform = encode(
        crate::Pdu::inform_request(COLLISION_ID, 1, &trap(), vec![]),
        service.engine_id(),
    );
    let remote_trap = encode(
        crate::Pdu::trap_v2(COLLISION_ID, 1, &trap(), vec![]),
        REMOTE_ENGINE,
    );
    let valid = encode(
        crate::Pdu::response(COLLISION_ID, 0, 0, vec![]),
        REMOTE_ENGINE,
    );
    let mut bad = valid.to_vec();
    *bad.last_mut().unwrap() ^= 1;

    let mut stream = TcpStream::connect(service.bound_addresses()[0].local_addr)
        .await
        .unwrap();
    let session = accepted(&service).await;
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let registration = RequestRegistration::v3(
        COLLISION_ID,
        tokio::time::Instant::now() + Duration::from_secs(2),
    )
    .with_classification_usm(config, Some(Bytes::from_static(REMOTE_ENGINE)));
    let pending = tokio::spawn(async move {
        session
            .request_with(outgoing, registration, move |packet| {
                let (_, _) = packet.into_parts();
                if count.fetch_add(1, Ordering::SeqCst) == 0 {
                    Ok(Candidate::Reject)
                } else {
                    Ok(Candidate::Accept(()))
                }
            })
            .await
    });
    read(&mut stream).await;
    for packet in [command, inform] {
        stream.write_all(&packet).await.unwrap();
        read(&mut stream).await;
    }
    events.recv().await.unwrap();
    stream.write_all(&remote_trap).await.unwrap();
    events.recv().await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    stream.write_all(&bad).await.unwrap();
    until(|| calls.load(Ordering::SeqCst) == 1).await;
    assert_eq!(events.usm_wrong_digests(), 0);
    stream.write_all(&valid).await.unwrap();
    pending.await.unwrap().unwrap();
    service.shutdown().await.unwrap();
}

#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
#[tokio::test]
async fn v3_bidirectional_commands_traps_and_informs_use_one_accepted_connected_session() {
    let mut a = secured_agent(b"tcp-v3-acceptor")
        .listener(ListenerSource::tcp("127.0.0.1:0"))
        .spawn()
        .await
        .unwrap();
    let mut b = secured_agent(b"tcp-v3-connector")
        .session(TcpTransport::builder().target(a.bound_addresses()[0].local_addr))
        .spawn()
        .await
        .unwrap();
    let mut na = a.take_notifications().unwrap();
    let mut nb = b.take_notifications().unwrap();
    let sa = accepted(&a).await;
    let sb = b.tcp_sessions()[0].clone();
    let trap_engine = crate::LocalEngine::new(engine(b"tcp-remote-trap-sender")).unwrap();
    for name in ["noauth", "auth", "priv"] {
        let ab = client(sa.clone(), security(name).into());
        let ba = client(sb.clone(), security(name).into());
        let oid = oid();
        let trap = trap();
        let (x, y) = tokio::join!(ab.get(&oid), ba.get(&oid));
        x.unwrap();
        y.unwrap();
        let (x, y) = tokio::join!(
            ab.send_inform(&trap, 1, vec![]),
            ba.send_inform(&trap, 1, vec![])
        );
        x.unwrap();
        y.unwrap();
        na.recv().await.unwrap();
        nb.recv().await.unwrap();
        let sender = ClientBuilder::new(security(name))
            .local_engine(trap_engine.clone())
            .build_with_transport(sa.clone())
            .unwrap();
        sender.send_trap(&trap, 1, vec![]).await.unwrap();
        let event = nb.recv().await.unwrap();
        assert_eq!(event.receive_info.session_id(), Some(sb.session_id()));
    }
    nb.close();
    client(sa, security("priv").into())
        .get(&oid())
        .await
        .unwrap();
    a.shutdown().await.unwrap();
    b.shutdown().await.unwrap();
}

#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
#[tokio::test]
async fn shared_discovery_allows_exact_usm_bindings_with_conflicting_defaults() {
    const REMOTE_ENGINE: &[u8] = b"shared-discovery-remote";
    let remote = secured_agent(REMOTE_ENGINE)
        .listener(ListenerSource::udp("127.0.0.1:0"))
        .listener(ListenerSource::tcp("127.0.0.1:0"))
        .spawn()
        .await
        .unwrap();
    let user = |password: &[u8]| {
        crate::UsmUser::new("auth")
            .auth(crate::AuthProtocol::Sha256, password)
            .unwrap()
    };
    let context = crate::UsmSecurityContext::new([
        crate::UsmUserEntry::new(user(b"different-auth-password")),
        crate::UsmUserEntry::for_engine(REMOTE_ENGINE, user(b"shared-auth-password")).unwrap(),
    ])
    .unwrap();
    let local = agent(b"shared-discovery-local")
        .security_context(context)
        .listener(ListenerSource::udp("127.0.0.1:0"))
        .session(TcpTransport::builder().target(remote.bound_addresses()[1].local_addr))
        .spawn()
        .await
        .unwrap();
    let udp = local
        .udp_endpoint(local.bound_addresses()[0].endpoint_id)
        .unwrap()
        .handle(remote.bound_addresses()[0].local_addr)
        .unwrap();
    let udp = ClientBuilder::new(security("auth"))
        .retry(Retry::none())
        .request_timeout(Duration::from_secs(2))
        .build_with_transport(udp)
        .unwrap();
    let tcp = client(local.tcp_sessions()[0].clone(), security("auth").into());
    let oid = oid();
    let (udp, tcp) = tokio::join!(udp.get(&oid), tcp.get(&oid));
    for response in [udp.unwrap(), tcp.unwrap()] {
        assert_eq!(
            response.varbinds[0].value,
            Value::OctetString(Bytes::from_static(REMOTE_ENGINE))
        );
        let history = &response.metadata.received_messages;
        assert_eq!(history.first().unwrap().pdu_type, crate::PduType::Report);
        assert_eq!(history.last().unwrap().pdu_type, crate::PduType::Response);
    }
    local.shutdown().await.unwrap();
    remote.shutdown().await.unwrap();
}

#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
#[tokio::test]
async fn standalone_v3_tcp_and_udp_listeners_share_engine_and_full_queue_allows_reports() {
    let mut collector = NotificationReceiver::builder()
        .client_exchanges(true)
        .queue_capacity(1)
        .listener(ListenerSource::udp("127.0.0.1:0"))
        .listener(ListenerSource::tcp("127.0.0.1:0"))
        .authoritative_engine(engine(b"tcp-collector-engine"))
        .admit_all_notifications()
        .usm_user("noauth", Ok)
        .unwrap()
        .usm_user("auth", |u| {
            u.auth(crate::AuthProtocol::Sha256, b"shared-auth-password")
        })
        .unwrap()
        .usm_user("priv", |u| {
            u.auth_priv(
                crate::AuthProtocol::Sha256,
                b"shared-auth-password",
                crate::PrivProtocol::Aes128,
                b"shared-priv-password",
            )
        })
        .unwrap()
        .spawn()
        .await
        .unwrap();
    let trap_engine = crate::LocalEngine::new(engine(b"tcp-standalone-trapper")).unwrap();
    for bound in collector.bound_addresses().to_vec() {
        for name in ["noauth", "auth", "priv"] {
            let builder = Client::builder(bound.local_addr.to_string(), security(name))
                .local_engine(trap_engine.clone())
                .retry(Retry::none());
            if bound.transport == TransportKind::Tcp {
                let sender = builder.connect_tcp().await.unwrap();
                sender.send_trap(&trap(), 1, vec![]).await.unwrap();
                collector.recv().await.unwrap();
                sender.send_inform(&trap(), 1, vec![]).await.unwrap();
            } else {
                let sender = builder.connect().await.unwrap();
                sender.send_trap(&trap(), 1, vec![]).await.unwrap();
                collector.recv().await.unwrap();
                sender.send_inform(&trap(), 1, vec![]).await.unwrap();
            }
            let event = collector.recv().await.unwrap();
            assert_eq!(event.receive_info.endpoint_id(), bound.endpoint_id);
        }
    }
    let session = TcpTransport::connect(collector.bound_addresses()[1].local_addr)
        .await
        .unwrap();
    client(session.clone(), Auth::v2c("public"))
        .send_inform(&trap(), 1, vec![])
        .await
        .unwrap();
    // The acknowledged Inform occupies the only delivery slot. Discovery
    // must still complete on this session.
    let poller = client(session.clone(), security("priv").into());
    let discovery = poller
        .rediscover_engine_with_metadata()
        .await
        .expect("discovery must succeed with the notification queue full");
    assert_eq!(discovery.received_messages.len(), 1);
    assert_eq!(
        discovery.received_messages[0].pdu_type,
        crate::PduType::Report
    );
    assert!(!session.control().is_shutdown());

    // An encrypted stale Inform also needs no delivery slot. Read the Report
    // from the same stream while the notification queue is still full.
    let mut stream = TcpStream::connect(collector.bound_addresses()[1].local_addr)
        .await
        .unwrap();
    let inform = crate::NotificationPdu::inform(crate::Version::V3, 4242, 1, &trap(), vec![])
        .unwrap()
        .into_raw();
    let wire = secured(
        inform,
        71,
        b"previous-collector-engine",
        &security("priv"),
        false,
    );
    stream.write_all(&wire).await.unwrap();
    let report =
        crate::message::V3Message::decode(read(&mut stream).await, crate::DecodeConfig::DEFAULT)
            .unwrap()
            .value;
    let scoped = report.scoped_pdu().unwrap();
    assert_eq!(report.global_data().msg_id(), 71);
    assert_eq!(scoped.pdu.request_id, 4242);
    assert_eq!(scoped.context_engine_id.as_ref(), b"tcp-collector-engine");
    assert!(matches!(
        crate::v3::classify_report(&scoped.pdu).unwrap(),
        crate::v3::ReportStatus::UnknownEngineId { .. }
    ));

    let queued = collector.recv().await.unwrap();
    assert!(matches!(
        queued.notification,
        crate::Notification::InformV2c { .. }
    ));
    collector.shutdown().await.unwrap();
}

#[tokio::test]
async fn shared_tcp_response_above_one_megabyte_retains_exact_metadata() {
    let service = agent(b"large-shared-tcp")
        .listener(ListenerSource::tcp("127.0.0.1:0"))
        .spawn()
        .await
        .unwrap();
    let mut stream = TcpStream::connect(service.bound_addresses()[0].local_addr)
        .await
        .unwrap();
    let session = accepted(&service).await;
    let id = session.session_id();
    let pending = tokio::spawn(async move {
        session
            .request_with(
                community(crate::Pdu::get_request(42, &[oid()])),
                registration(42),
                |packet| Ok(Candidate::Accept(packet.into_parts())),
            )
            .await
    });
    read(&mut stream).await;
    let bytes = community(crate::Pdu::response(
        42,
        0,
        0,
        vec![crate::VarBind::new(
            oid(),
            Value::OctetString(vec![42; 1_100_000].into()),
        )],
    ));
    stream.write_all(&bytes).await.unwrap();
    let (received, info) = pending.await.unwrap().unwrap();
    assert_eq!(received, bytes);
    assert_eq!(info.received_len(), bytes.len());
    assert_eq!(info.session_id(), Some(id));
    service.shutdown().await.unwrap();
}

#[tokio::test]
async fn configured_sessions_share_connection_budget_and_owned_stream_source() {
    let remote = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let outgoing = TcpStream::connect(remote.local_addr().unwrap())
        .await
        .unwrap();
    let (_remote, _) = remote.accept().await.unwrap();
    let service = agent(b"configured-budget")
        .max_connections(1)
        .session(TcpTransport::builder().from_stream(outgoing))
        .listener(ListenerSource::tcp("127.0.0.1:0"))
        .spawn()
        .await
        .unwrap();
    let configured = service.tcp_sessions()[0].clone();
    let mut rejected = TcpStream::connect(service.bound_addresses()[1].local_addr)
        .await
        .unwrap();
    let mut byte = [0; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), rejected.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    configured.control().shutdown().await;
    until(|| service.tcp_sessions().is_empty()).await;
    let newcomer = TcpTransport::connect(service.bound_addresses()[1].local_addr)
        .await
        .unwrap();
    client(newcomer, Auth::v2c("public"))
        .get(&oid())
        .await
        .unwrap();
    assert!(
        configured
            .send(community(crate::Pdu::get_request(3, &[oid()])))
            .await
            .is_err()
    );
    service.shutdown().await.unwrap();
}

#[tokio::test]
async fn notification_session_peer_and_control_keep_service_alive_after_consumer_drop() {
    let peer = agent(b"notification-lease-peer")
        .listener(ListenerSource::tcp("127.0.0.1:0"))
        .spawn()
        .await
        .unwrap();
    let (receiver, runner) = NotificationReceiver::builder()
        .client_exchanges(true)
        .session(TcpTransport::builder().target(peer.bound_addresses()[0].local_addr))
        .prepare()
        .await
        .unwrap()
        .into_parts();
    let selected = receiver.tcp_sessions()[0].clone();
    let control = selected.control();
    let task = tokio::spawn(runner.run());
    drop(receiver);
    client(selected.clone(), Auth::v2c("public"))
        .get(&oid())
        .await
        .unwrap();
    drop(selected);
    assert!(!task.is_finished());
    drop(control);
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    peer.shutdown().await.unwrap();
}

#[tokio::test]
async fn overloaded_session_leaves_commands_and_other_session_progressing() {
    let mut service = Agent::builder()
        .community(b"public")
        .allow_all_access()
        .client_exchanges(true)
        .listener(ListenerSource::tcp("127.0.0.1:0"))
        .notifications(NotificationReceiver::builder().queue_capacity(1))
        .spawn()
        .await
        .unwrap();
    let mut events = service.take_notifications().unwrap();
    let mut overloaded = TcpStream::connect(service.bound_addresses()[0].local_addr)
        .await
        .unwrap();
    let bytes = community(crate::Pdu::inform_request(1, 1, &trap(), vec![]));
    overloaded.write_all(&bytes).await.unwrap();
    read(&mut overloaded).await;
    let first = service.tcp_sessions()[0].clone();
    overloaded.write_all(&bytes).await.unwrap();
    let independent = TcpTransport::connect(service.bound_addresses()[0].local_addr)
        .await
        .unwrap();
    client(independent, Auth::v2c("public"))
        .get(&oid())
        .await
        .unwrap();
    until(|| first.control().is_shutdown()).await;
    // The full queue remains undrained until after the independent command finishes.
    events.recv().await.unwrap();
    service.shutdown().await.unwrap();
}

#[tokio::test]
async fn tcp_only_notification_accepts_and_acknowledges_frames_above_udp_capacity() {
    let mut service = NotificationReceiver::builder()
        .listener(ListenerSource::tcp("127.0.0.1:0"))
        .max_message_size(2_000_000)
        .spawn()
        .await
        .unwrap();
    let mut stream = TcpStream::connect(service.bound_addresses()[0].local_addr)
        .await
        .unwrap();
    let bytes = community(crate::Pdu::inform_request(
        1,
        1,
        &trap(),
        vec![crate::VarBind::new(
            oid(),
            Value::OctetString(vec![42; 1_100_000].into()),
        )],
    ));
    stream.write_all(&bytes).await.unwrap();
    let response = read(&mut stream).await;
    assert!(response.len() > 1_000_000);
    let event = service.recv().await.unwrap();
    assert_eq!(event.receive_info.received_len(), bytes.len());
    assert!(matches!(
        event.inform_ack,
        crate::NotificationAcknowledgement::Completed(crate::notification::InformAckOutcome::Sent)
    ));
    service.shutdown().await.unwrap();
}

#[tokio::test]
async fn closing_notification_role_resumes_paused_session_commands() {
    let mut service = agent(b"pause-close-notifications")
        .client_exchanges(false)
        .listener(ListenerSource::tcp("127.0.0.1:0"))
        .notifications(NotificationReceiver::builder().queue_capacity(1))
        .spawn()
        .await
        .unwrap();
    let mut events = service.take_notifications().unwrap();
    let mut stream = TcpStream::connect(service.bound_addresses()[0].local_addr)
        .await
        .unwrap();
    let inform = community(crate::Pdu::inform_request(1, 1, &trap(), vec![]));
    stream.write_all(&inform).await.unwrap();
    read(&mut stream).await;
    stream.write_all(&inform).await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    events.close();
    stream
        .write_all(&community(crate::Pdu::get_request(3, &[oid()])))
        .await
        .unwrap();
    let response = crate::message::CommunityMessage::decode(
        read(&mut stream).await,
        crate::DecodeConfig::DEFAULT,
    )
    .unwrap()
    .value
    .into_pdu()
    .unwrap();
    assert_eq!(response.request_id(), 3);
    events.recv().await.unwrap();
    assert!(events.recv().await.is_none());
    service.shutdown().await.unwrap();
}

struct GateHandler(Arc<tokio::sync::Semaphore>, Arc<AtomicUsize>);
impl crate::handler::MibHandler for GateHandler {
    fn get<'a>(
        &'a self,
        _: &'a crate::handler::RequestContext,
        _: &'a crate::Oid,
    ) -> crate::handler::BoxFuture<'a, crate::handler::HandlerResult<crate::handler::GetResult>>
    {
        Box::pin(async move {
            self.1.fetch_add(1, Ordering::SeqCst);
            let _permit = self.0.acquire().await.unwrap();
            Ok(crate::handler::GetResult::Value(Value::Null))
        })
    }
    fn get_next<'a>(
        &'a self,
        _: &'a crate::handler::RequestContext,
        _: &'a crate::Oid,
    ) -> crate::handler::BoxFuture<'a, crate::handler::HandlerResult<crate::handler::GetNextResult>>
    {
        Box::pin(async { Ok(crate::handler::GetNextResult::EndOfMibView) })
    }
}

#[tokio::test]
async fn closing_command_role_resumes_paused_session_notifications() {
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let entered = Arc::new(AtomicUsize::new(0));
    let request_oid = oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0);
    let mut service = agent(b"pause-close-commands")
        .client_exchanges(false)
        .max_concurrent_requests(1)
        .listener(ListenerSource::tcp("127.0.0.1:0"))
        .handler(
            oid!(1, 3, 6, 1, 4, 1, 99999),
            Arc::new(GateHandler(gate.clone(), entered.clone())),
        )
        .spawn()
        .await
        .unwrap();
    let mut events = service.take_notifications().unwrap();
    let mut stream = TcpStream::connect(service.bound_addresses()[0].local_addr)
        .await
        .unwrap();
    stream
        .write_all(&community(crate::Pdu::get_request(
            1,
            std::slice::from_ref(&request_oid),
        )))
        .await
        .unwrap();
    until(|| entered.load(Ordering::SeqCst) == 1).await;
    stream
        .write_all(&community(crate::Pdu::get_request(2, &[request_oid])))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    service.close_commands();
    stream
        .write_all(&community(crate::Pdu::inform_request(
            3,
            1,
            &trap(),
            vec![],
        )))
        .await
        .unwrap();
    let response = crate::message::CommunityMessage::decode(
        read(&mut stream).await,
        crate::DecodeConfig::DEFAULT,
    )
    .unwrap()
    .value
    .into_pdu()
    .unwrap();
    assert_eq!(response.request_id(), 3);
    events.recv().await.unwrap();
    gate.add_permits(1);
    read(&mut stream).await;
    assert_eq!(entered.load(Ordering::SeqCst), 1);
    service.shutdown().await.unwrap();
}

#[tokio::test]
async fn mixed_session_survives_command_closure_during_admission() {
    use super::ingress::ApplicationIngress;
    use std::sync::{Mutex, atomic::AtomicU64};
    use tokio::sync::{Semaphore, mpsc};
    use tokio_util::sync::CancellationToken;

    // Close after the initial enabled check, at each failing admission boundary.
    // The final case keeps admission open and must still terminate on overload.
    for mode in 0..4 {
        let (sender, receiver) = mpsc::channel(1);
        let receiver = Arc::new(Mutex::new(Some(receiver)));
        let disabled = CancellationToken::new();
        let hook_token = disabled.clone();
        let hook_receiver = receiver.clone();
        let ingress = ApplicationIngress {
            admission_hook: Some(Arc::new(move |ingress, before_send| {
                if before_send != (mode == 2) {
                    return;
                }
                match mode {
                    0 => hook_token.cancel(),
                    1 => {
                        hook_token.cancel();
                        let limit = ingress.session.as_ref().unwrap();
                        limit.forget_permits(limit.available_permits());
                    }
                    2 => {
                        hook_receiver.lock().unwrap().take();
                    }
                    _ => {}
                }
            })),
            sender,
            disabled,
            capacity: Arc::new(Semaphore::new(if mode == 0 || mode == 3 { 0 } else { 1 })),
            budget: Arc::new(super::framing::BufferBudget::new(32 * 1024 * 1024)),
            overload_timeout: Duration::from_secs(2),
            drops: Arc::new(AtomicU64::new(0)),
            session: (mode == 1).then(|| Arc::new(Semaphore::new(0))),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut peer = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let (observer, mut observations) = TransportObserver::channel(16).unwrap();
        let prepared = TcpTransport::builder()
            .from_stream(stream)
            .observer(observer)
            .ingress(ingress.clone(), EndpointId::new())
            .prepare()
            .await
            .unwrap();
        let (transport, runner) = prepared.into_parts();
        transport.configure_dispatch(Arc::new(dispatch::DispatchRoles::new(
            Some(ingress),
            None,
            Default::default(),
            true,
            1,
        )));
        let task = tokio::spawn(runner.run());
        peer.write_all(&community(crate::Pdu::get_request(1, &[oid()])))
            .await
            .unwrap();
        let disposition = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Some(ObservationEvent::Disposition { disposition, .. }) =
                    observations.recv().await
                {
                    break disposition;
                }
            }
        })
        .await
        .unwrap();
        if mode == 3 {
            assert_eq!(disposition, MessageDisposition::Overloaded);
            assert!(task.await.unwrap().is_err());
            continue;
        }
        assert_eq!(disposition, MessageDisposition::Disabled, "mode {mode}");
        let request = community(crate::Pdu::get_request(41, &[oid()]));
        let exchange = transport.request_with(request.clone(), registration(41), |_| {
            Ok(Candidate::Accept(()))
        });
        let remote = async {
            assert_eq!(read(&mut peer).await, request);
            peer.write_all(&community(crate::Pdu::response(41, 0, 0, vec![])))
                .await
                .unwrap();
        };
        let (result, ()) = tokio::join!(exchange, remote);
        result.unwrap();
        transport.control().shutdown().await;
        task.await.unwrap().unwrap();
    }
}
