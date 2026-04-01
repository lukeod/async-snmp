//! Using async-snmp from Synchronous Code
//!
//! async-snmp is async-first, but embedding it in a synchronous application
//! is straightforward using tokio's Runtime::block_on(). This avoids the need
//! for a separate sync SNMP library.
//!
//! This example shows two patterns:
//! - One-shot: create a runtime, do SNMP work, drop it
//! - Persistent: keep a runtime alive for repeated SNMP calls
//!
//! Run with: cargo run --example sync_wrapper

use async_snmp::{Auth, Client, Error, Retry, Value, VarBind, oid};
use std::net::SocketAddr;
use std::time::Duration;

/// One-shot pattern: spin up a runtime, do SNMP work, tear it down.
///
/// Good for CLI tools, scripts, or infrequent SNMP calls where you don't
/// want to keep a runtime alive.
fn oneshot_get(target: (&str, u16), community: &str) -> Result<VarBind, Box<Error>> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime");

    rt.block_on(async {
        let client = Client::builder(target, Auth::v2c(community))
            .timeout(Duration::from_secs(5))
            .retry(Retry::fixed(2, Duration::ZERO))
            .connect()
            .await?;

        client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await
    })
}

/// Persistent pattern: keep a runtime and client alive for repeated calls.
///
/// Wraps the async client in a struct that exposes sync methods. Useful when
/// SNMP is called from multiple places in a sync codebase.
struct SyncSnmpClient {
    rt: tokio::runtime::Runtime,
    client: Client,
}

impl SyncSnmpClient {
    fn connect(target: (&str, u16), community: &str) -> Result<Self, Box<Error>> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to create tokio runtime");

        let client = rt.block_on(async {
            Client::builder(target, Auth::v2c(community))
                .timeout(Duration::from_secs(5))
                .retry(Retry::fixed(2, Duration::ZERO))
                .connect()
                .await
        })?;

        Ok(Self { rt, client })
    }

    fn get(&self, oid: &async_snmp::Oid) -> Result<VarBind, Box<Error>> {
        self.rt.block_on(self.client.get(oid))
    }

    fn get_many(&self, oids: &[async_snmp::Oid]) -> Result<Vec<VarBind>, Box<Error>> {
        self.rt.block_on(self.client.get_many(oids))
    }

    #[allow(dead_code)]
    fn set(&self, oid: &async_snmp::Oid, value: Value) -> Result<VarBind, Box<Error>> {
        self.rt.block_on(self.client.set(oid, value))
    }

    fn walk(&self, oid: async_snmp::Oid) -> Result<Vec<VarBind>, Box<Error>> {
        self.rt.block_on(async {
            let walk = self.client.walk(oid)?;
            walk.collect().await
        })
    }

    fn peer_addr(&self) -> SocketAddr {
        self.client.peer_addr()
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target = ("127.0.0.1", 11161);

    // =========================================================================
    // One-shot: single call, no persistent runtime
    // =========================================================================
    println!("--- One-shot GET ---\n");

    match oneshot_get(target, "public") {
        Ok(vb) => println!("sysDescr: {:?}", vb.value),
        Err(e) => println!("Error: {}", e),
    }

    // =========================================================================
    // Persistent: reuse runtime and client across calls
    // =========================================================================
    println!("\n--- Persistent client ---\n");

    let client = SyncSnmpClient::connect(target, "public")?;
    println!("Connected to {}", client.peer_addr());

    // GET
    let vb = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))?;
    println!("sysDescr: {:?}", vb.value);

    // GET_MANY
    let vbs = client.get_many(&[
        oid!(1, 3, 6, 1, 2, 1, 1, 3, 0), // sysUpTime
        oid!(1, 3, 6, 1, 2, 1, 1, 5, 0), // sysName
    ])?;
    for vb in &vbs {
        println!("  {}: {:?}", vb.oid, vb.value);
    }

    // WALK
    let results = client.walk(oid!(1, 3, 6, 1, 2, 1, 1))?;
    println!("System subtree: {} OIDs", results.len());

    println!("\nExample complete!");
    Ok(())
}
