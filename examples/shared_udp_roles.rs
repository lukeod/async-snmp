//! Command handling, notification reception and client exchanges on one UDP port.
//! Run: cargo run --example shared_udp_roles --features agent
use async_snmp::{Agent, Auth, ClientBuilder, NotificationReceiver, oid};

#[tokio::main]
async fn main() -> async_snmp::Result<()> {
    let mut collector = Agent::builder()
        .bind("127.0.0.1:0")
        .community(b"public")
        .allow_all_access()
        .client_exchanges(true)
        .notifications(NotificationReceiver::builder().community("public"))
        .spawn()
        .await?;
    let device = Agent::builder()
        .bind("127.0.0.1:0")
        .community(b"public")
        .allow_all_access()
        .client_exchanges(true)
        .spawn()
        .await?;
    let mut notifications = collector.take_notifications().unwrap();
    let collector_bound = collector.bound_addresses()[0];
    let device_bound = device.bound_addresses()[0];
    let collector_endpoint = collector.udp_endpoint(collector_bound.endpoint_id).unwrap();
    let device_endpoint = device.udp_endpoint(device_bound.endpoint_id).unwrap();
    let poller = ClientBuilder::new(Auth::v2c("public"))
        .build_with_transport(collector_endpoint.handle(device_bound.local_addr)?)?;
    let originator = ClientBuilder::new(Auth::v2c("public"))
        .build_with_transport(device_endpoint.handle(collector_bound.local_addr)?)?;

    let engine_id = oid!(1, 3, 6, 1, 6, 3, 10, 2, 1, 1, 0);
    let cold_start = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1);
    let (poll, inform) = tokio::join!(
        poller.get(&engine_id),
        originator.send_inform(&cold_start, 0, vec![])
    );
    println!("Polling result: {:?}", poll?.varbinds);
    inform?;
    let event = notifications.recv().await.unwrap();
    println!(
        "Notification from listener port {}",
        event.receive_info.peer_addr()
    );

    // Closing the consumer leaves commands and client exchanges active.
    notifications.close();
    poller.get(&engine_id).await?;
    collector.shutdown().await?;
    device.shutdown().await?;
    Ok(())
}
