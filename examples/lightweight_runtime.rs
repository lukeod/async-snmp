//! Configure a lightweight runtime
//!
//! Most async-snmp examples use `#[tokio::main]`, which creates a multithreaded
//! runtime by default. A tool that communicates with one or a few devices might
//! not need worker threads.
//!
//! This example uses a single-threaded runtime to reduce overhead.
//!
//! Run `cargo run --example lightweight_runtime`.

use async_snmp::{Auth, Client, ResponseShapePolicy, Retry, oid};
use std::time::Duration;

// The current-thread runtime runs all asynchronous work on the main thread
// without spawning worker threads.
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target = ("127.0.0.1", 11161);

    let client = Client::builder(target, Auth::v2c("public"))
        .response_shape_policy(ResponseShapePolicy::Strict)
        .request_timeout(Duration::from_secs(5))
        .retry(Retry::fixed(2, Duration::ZERO).expect("valid retry count"))
        .connect()
        .await?;

    // Retrieve sysDescr.0.
    let response = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await?;
    let varbind = response
        .single()
        .expect("strict response policy returns a singleton");
    println!("sysDescr: {:?}", varbind.value);

    // Walk the system subtree.
    let mut walk = client.walk(oid!(1, 3, 6, 1, 2, 1, 1))?;
    while let Some(result) = walk.next().await {
        let vb = result?;
        println!("  {}: {:?}", vb.oid, vb.value);
    }

    Ok(())
}
