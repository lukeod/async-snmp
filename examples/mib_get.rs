//! GET named OIDs with MIB-aware output.
//!
//! Resolves named OIDs like "sysDescr.0" and "sysUpTime.0", GETs them,
//! and shows formatted values with enum labels and display hints.
//!
//! Requires the `mib` feature:
//!   cargo run --example mib_get --features mib -- 192.168.1.1
//!
//! This example requires an SNMP agent to be running at the specified target.

use async_snmp::mib_support::{self, Loader};
use async_snmp::{Auth, Client};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1".to_string());

    // Load MIBs from system paths
    let mib = tokio::task::spawn_blocking(|| {
        Loader::new()
            .system_paths()
            .load()
            .expect("failed to load system MIBs")
    })
    .await?;

    // Resolve named OIDs
    let names = ["sysDescr.0", "sysUpTime.0", "sysContact.0", "sysName.0"];
    let oids: Vec<_> = names
        .iter()
        .map(|name| {
            let oid = mib_support::resolve_oid(&mib, name)
                .unwrap_or_else(|e| panic!("failed to resolve {}: {}", name, e));
            println!("Resolved {} -> {}", name, oid);
            oid
        })
        .collect();

    // Connect and GET
    let client = Client::builder(format!("{}:161", target), Auth::v2c("public"))
        .connect()
        .await?;

    let results = client.get_many(&oids).await?;

    // Format results with MIB metadata
    println!();
    for vb in &results {
        println!("{}", mib_support::format_varbind(&mib, vb));
    }

    Ok(())
}
