//! Run with: cargo run --example transport_observation -- 127.0.0.1:161
//! Observation is metadata-only and never blocks the endpoint's protocol work.
use async_snmp::{
    Auth, Client, DEFAULT_OBSERVATION_CAPACITY, Retry, TransportObserver, UdpEndpoint, oid,
};
use std::time::Duration;

#[tokio::main(flavor = "current_thread")]
async fn main() -> async_snmp::Result<()> {
    let target = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:161".into());
    let (observer, mut events) = TransportObserver::channel(DEFAULT_OBSERVATION_CAPACITY)?;
    let endpoint = UdpEndpoint::builder()
        .bind("0.0.0.0:0")
        .observer(observer.clone())
        .spawn()
        .await?;
    let client = Client::builder(target, Auth::v2c("public"))
        .request_timeout(Duration::from_secs(1))
        .retry(Retry::none())
        .build_with(&endpoint)
        .await?;
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;
    println!("Query completed: {}", result.is_ok());
    while let Ok(event) = events.try_recv() {
        println!("{event:?}");
    }
    println!("Counters: {:?}", observer.stats());
    endpoint.shutdown().await?;
    Ok(())
}
