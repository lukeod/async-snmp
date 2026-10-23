//! Bidirectional commands and notifications on one explicitly shared connection.
//! Run: cargo run --example shared_tcp_roles --features agent
use async_snmp::{
    Agent, Auth, ClientBuilder, ListenerSource, NotificationReceiver, NotificationSinkId,
    SinkStatus, TcpTransport, oid,
};

#[tokio::main]
async fn main() -> async_snmp::Result<()> {
    let mut collector = Agent::builder()
        .listener(ListenerSource::tcp("127.0.0.1:0"))
        .community(b"public")
        .allow_all_access()
        .client_exchanges(true)
        .notifications(NotificationReceiver::builder().community("public"))
        .spawn()
        .await?;
    let device = Agent::builder()
        .session(TcpTransport::builder().target(collector.bound_addresses()[0].local_addr))
        .community(b"public")
        .allow_all_access()
        .client_exchanges(true)
        .spawn()
        .await?;
    let mut notifications = collector.take_notifications().unwrap();
    let originator = device.notification_peer(
        NotificationSinkId::new("collector").unwrap(),
        device.tcp_sessions()[0].clone(),
        Auth::v2c("public"),
    )?;
    let outcome = originator
        .send_inform(&oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1), 0, vec![])
        .await;
    assert!(
        matches!(outcome.status, SinkStatus::Succeeded),
        "{outcome:?}"
    );
    let event = notifications.recv().await.unwrap();
    let session = collector
        .tcp_sessions()
        .into_iter()
        .find(|session| Some(session.session_id()) == event.receive_info.session_id())
        .unwrap();
    // This library peer explicitly supports transactions in both directions.
    let poller = ClientBuilder::new(Auth::v2c("public")).build_with_transport(session)?;
    println!(
        "Peer engine: {:?}",
        poller
            .get(&oid!(1, 3, 6, 1, 6, 3, 10, 2, 1, 1, 0))
            .await?
            .varbinds
    );
    notifications.close();
    poller.get(&oid!(1, 3, 6, 1, 6, 3, 10, 2, 1, 1, 0)).await?;
    collector.shutdown().await?;
    device.shutdown().await?;
    Ok(())
}
