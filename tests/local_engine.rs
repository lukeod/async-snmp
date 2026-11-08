#![cfg(feature = "agent")]

use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_snmp::message::{MsgFlags, MsgGlobalData, ScopedPdu, V3Message};
use async_snmp::v3::UsmSecurityParams;
use async_snmp::{
    Agent, Auth, AuthoritativeEngine, Client, Error, ListenerSource, LocalEngine, MessageSize,
    NotificationReceiver, RequestPdu, Retry, SecurityLevel, TcpListenerSource, TcpOptions, Value,
    Version, oid,
};
use bytes::Bytes;
use tokio::net::UdpSocket;

const WAIT: Duration = Duration::from_secs(3);

fn unknown_user_request(engine: &LocalEngine) -> Bytes {
    let request =
        RequestPdu::get(Version::V3, 17, &[oid!(1, 3, 6, 1, 6, 3, 10, 2, 1, 1, 0)]).unwrap();
    let global = MsgGlobalData::new(
        17,
        MessageSize::new(8192).unwrap(),
        MsgFlags::new(SecurityLevel::NoAuthNoPriv, true),
    )
    .unwrap();
    let usm = UsmSecurityParams::new(
        Bytes::copy_from_slice(engine.engine_id()),
        0,
        0,
        "unknown-user",
    )
    .unwrap();
    V3Message::new(
        global,
        usm.encode().unwrap(),
        ScopedPdu::with_empty_context(request),
    )
    .unwrap()
    .encode()
    .unwrap()
}

#[tokio::test]
async fn independently_prepared_agent_and_receiver_share_engine_counters() {
    let persisted = Arc::new(AtomicUsize::new(0));
    let writes = persisted.clone();
    let authoritative =
        AuthoritativeEngine::install(b"independent-shared-engine".as_slice(), move |_| {
            writes.fetch_add(1, Ordering::Relaxed);
            Ok::<_, Infallible>(())
        })
        .unwrap();
    let engine = LocalEngine::new(authoritative).unwrap();
    let agent = Agent::builder()
        .bind("127.0.0.1:0")
        .local_engine(engine.clone())
        .spawn()
        .await
        .unwrap();
    let mut receiver = NotificationReceiver::builder()
        .bind("127.0.0.1:0")
        .local_engine(engine.clone())
        .spawn()
        .await
        .unwrap();
    assert_eq!(agent.engine_id(), receiver.engine_id());
    assert_eq!(agent.local_engine().engine_id(), engine.engine_id());
    assert_eq!(receiver.local_engine().current_boots_time().unwrap().0, 1);
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let request = unknown_user_request(&engine);
    let mut buffer = [0; 2048];
    for target in [
        agent.bound_addresses()[0].local_addr,
        receiver.bound_addresses()[0].local_addr,
    ] {
        socket.send_to(&request, target).await.unwrap();
        tokio::time::timeout(WAIT, socket.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
    }
    assert_eq!(agent.usm_unknown_usernames(), 2);
    assert_eq!(receiver.usm_unknown_usernames(), 2);
    assert_eq!(persisted.load(Ordering::Relaxed), 1);
    agent.shutdown().await.unwrap();
    receiver.shutdown().await.unwrap();
}

fn tcp_source(capacity: usize) -> ListenerSource {
    let mut options = TcpOptions::default();
    options.max_message_size = capacity;
    ListenerSource::Tcp(TcpListenerSource::bind("127.0.0.1:0").session_options(options))
}

#[tokio::test]
async fn shared_engine_mib_uses_minimum_across_independent_service_lifetimes() {
    let engine = LocalEngine::new(
        AuthoritativeEngine::install(b"shared-capacity-engine".as_slice(), |_| {
            Ok::<_, Infallible>(())
        })
        .unwrap(),
    )
    .unwrap();
    let large = Agent::builder()
        .local_engine(engine.clone())
        .community("public")
        .allow_all_access()
        .listener(tcp_source(32768))
        .spawn()
        .await
        .unwrap();
    let small = Agent::builder()
        .local_engine(engine.clone())
        .community("public")
        .allow_all_access()
        .listener(tcp_source(8192))
        .spawn()
        .await
        .unwrap();
    assert_eq!(engine.receive_capacity().unwrap().as_usize(), 8192);
    let mut clients = Vec::new();
    for agent in [&large, &small] {
        let client = Client::builder(
            agent.bound_addresses()[0].local_addr.to_string(),
            Auth::v2c("public"),
        )
        .retry(Retry::none())
        .request_timeout(WAIT)
        .connect_tcp()
        .await
        .unwrap();
        let response = client
            .get(&oid!(1, 3, 6, 1, 6, 3, 10, 2, 1, 4, 0))
            .await
            .unwrap();
        assert_eq!(response.varbinds[0].value, Value::Integer(8192));
        clients.push(client);
    }
    drop(clients);
    small.shutdown().await.unwrap();
    assert_eq!(engine.receive_capacity().unwrap().as_usize(), 32768);
    large.shutdown().await.unwrap();
    assert_eq!(engine.receive_capacity(), None);
}

#[tokio::test]
async fn shared_engine_mib_includes_client_capacity_until_its_last_clone_drops() {
    let engine = LocalEngine::new(
        AuthoritativeEngine::install(b"shared-client-capacity".as_slice(), |_| {
            Ok::<_, Infallible>(())
        })
        .unwrap(),
    )
    .unwrap();
    let agent = Agent::builder()
        .local_engine(engine.clone())
        .community("public")
        .allow_all_access()
        .listener(tcp_source(32768))
        .spawn()
        .await
        .unwrap();
    let query = Client::builder(
        agent.bound_addresses()[0].local_addr.to_string(),
        Auth::v2c("public"),
    )
    .retry(Retry::none())
    .request_timeout(WAIT)
    .connect_tcp()
    .await
    .unwrap();
    let (endpoint, runner) = async_snmp::UdpEndpoint::builder()
        .bind("127.0.0.1:0")
        .receive_capacity(8192)
        .prepare()
        .await
        .unwrap()
        .into_parts();
    let originator = async_snmp::ClientBuilder::new(Auth::usm("trapuser"))
        .local_engine(engine.clone())
        .build_with_transport(endpoint.handle("127.0.0.1:9".parse().unwrap()).unwrap())
        .unwrap();
    assert_eq!(engine.receive_capacity().unwrap().as_usize(), 8192);
    let mib = oid!(1, 3, 6, 1, 6, 3, 10, 2, 1, 4, 0);
    assert_eq!(
        query.get(&mib).await.unwrap().varbinds[0].value,
        Value::Integer(8192)
    );
    let retained = originator.clone();
    drop(originator);
    assert_eq!(engine.receive_capacity().unwrap().as_usize(), 8192);
    drop(retained);
    assert_eq!(engine.receive_capacity().unwrap().as_usize(), 32768);
    assert_eq!(
        query.get(&mib).await.unwrap().varbinds[0].value,
        Value::Integer(32768)
    );
    drop(query);
    drop(endpoint);
    drop(runner);
    agent.shutdown().await.unwrap();
    assert_eq!(engine.receive_capacity(), None);
}

#[tokio::test]
async fn shared_engine_configuration_conflicts_are_rejected() {
    let authoritative = AuthoritativeEngine::install(b"shared-conflict-engine".as_slice(), |_| {
        Ok::<_, Infallible>(())
    })
    .unwrap();
    let engine = LocalEngine::new(authoritative.clone()).unwrap();
    let error = Agent::builder()
        .local_engine(engine.clone())
        .authoritative_engine(authoritative.clone())
        .bind("not an address")
        .prepare()
        .await
        .err()
        .unwrap();
    assert!(
        matches!(*error, Error::Config(ref message) if message.contains("local_engine conflicts"))
    );
    let error = NotificationReceiver::builder()
        .local_engine(engine)
        .authoritative_engine(authoritative)
        .bind("not an address")
        .prepare()
        .await
        .err()
        .unwrap();
    assert!(
        matches!(*error, Error::Config(ref message) if message.contains("local_engine conflicts"))
    );
}
