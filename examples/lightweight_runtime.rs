//! Lightweight Runtime Configuration
//!
//! Most async-snmp examples use #[tokio::main], which spawns a multi-threaded
//! runtime by default. This is overkill for simple tools that talk to one or
//! a few devices.
//!
//! This example shows how to use a single-threaded runtime instead, which
//! avoids spawning worker threads and reduces overhead for simple use cases.
//!
//! Run with: cargo run --example lightweight_runtime

use async_snmp::{Auth, Client, ResponseShapePolicy, Retry, oid};
use std::time::Duration;

// current_thread: single-threaded runtime, no worker threads.
// All async work runs on the main thread. This is the lightest option
// and works well for CLI tools, scripts, and simple applications.
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target = ("127.0.0.1", 11161);

    let client = Client::builder(target, Auth::v2c("public"))
        .response_shape_policy(ResponseShapePolicy::Strict)
        .request_timeout(Duration::from_secs(5))
        .retry(Retry::fixed(2, Duration::ZERO).expect("valid retry count"))
        .connect()
        .await?;

    // GET
    let response = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await?;
    println!("sysDescr: {:?}", response.varbinds[0].value);

    // WALK
    let mut walk = client.walk(oid!(1, 3, 6, 1, 2, 1, 1))?;
    while let Some(result) = walk.next().await {
        let vb = result?;
        println!("  {}: {:?}", vb.oid, vb.value);
    }

    Ok(())
}
