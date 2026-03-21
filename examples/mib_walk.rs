//! Walk an SNMP table with MIB-aware output.
//!
//! Loads MIBs from system paths, resolves "ifTable" by name, walks it,
//! and formats results using MIB metadata (symbolic OID names, enum labels,
//! display hints).
//!
//! Requires the `mib` feature:
//!   cargo run --example mib_walk --features mib -- 192.168.1.1
//!
//! This example requires an SNMP agent to be running at the specified target.

use async_snmp::mib_support::{self, Loader};
use async_snmp::{Auth, Client};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1".to_string());

    // Load MIBs from system paths (net-snmp, libsmi)
    let mib = tokio::task::spawn_blocking(|| {
        Loader::new()
            .system_paths()
            .load()
            .expect("failed to load system MIBs")
    })
    .await?;

    // Resolve "ifTable" by name
    let if_table = mib_support::resolve_oid(&mib, "ifTable")?;
    println!("Walking {} ({})", mib_support::format_oid(&mib, &if_table), if_table);

    // Connect and walk
    let client = Client::builder(format!("{}:161", target), Auth::v2c("public"))
        .connect()
        .await?;

    let results: Vec<_> = client.walk(if_table)?.collect().await?;

    // Format each result using MIB metadata
    for vb in &results {
        println!("{}", mib_support::format_varbind(&mib, vb));
    }

    println!("\n{} varbinds returned", results.len());
    Ok(())
}
