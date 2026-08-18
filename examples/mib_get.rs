//! GET named OIDs with MIB-aware output.
//!
//! This example resolves names such as `sysDescr.0` and `sysUpTime.0`, retrieves
//! their values, and formats the results with enumeration labels and display
//! hints.
//!
//! Run `cargo run --example mib_get --features mib -- 192.168.1.1`. The target
//! must run an SNMP agent.

use async_snmp::mib_support::{self, Loader};
use async_snmp::{Auth, Client};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1".to_string());

    // Load MIB modules from the system search paths.
    let mib = tokio::task::spawn_blocking(|| Loader::new().system_paths().load()).await??;

    // Resolve the object names and instance suffixes.
    let names = ["sysDescr.0", "sysUpTime.0", "sysContact.0", "sysName.0"];
    let oids: Vec<_> = names
        .iter()
        .map(|name| {
            let oid = mib_support::resolve_oid(&mib, name)
                .unwrap_or_else(|e| panic!("failed to resolve {name}: {e}"));
            println!("Resolved {name} -> {oid}");
            oid
        })
        .collect();

    // Connect to the agent and retrieve the values.
    let client = Client::builder(target, Auth::v2c("public"))
        .connect()
        .await?;

    let results = client.get_many(&oids).await?;
    for anomaly in &results.anomalies {
        eprintln!("Response shape anomaly: {anomaly:?}");
    }

    // Format each result with its MIB metadata.
    println!();
    for vb in &results.varbinds {
        println!("{}", mib_support::format_varbind(&mib, vb));
    }

    Ok(())
}
