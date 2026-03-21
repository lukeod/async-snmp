//! Walk a table and decode results using MIB metadata.
//!
//! Uses `describe_varbind` to decode index values and group columns by row.
//! Shows programmatic use of MIB metadata beyond simple string formatting.
//!
//! Requires the `mib` feature:
//!   cargo run --example mib_table --features mib -- 192.168.1.1
//!
//! This example requires an SNMP agent to be running at the specified target.

use async_snmp::mib_support::{self, Loader};
use async_snmp::{Auth, Client, VarBind};
use smallvec::SmallVec;
use std::collections::BTreeMap;

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

    // Resolve ifTable and walk it
    let if_table = mib_support::resolve_oid(&mib, "ifTable")?;

    let client = Client::builder(format!("{}:161", target), Auth::v2c("public"))
        .connect()
        .await?;

    let results: Vec<_> = client.walk(if_table)?.collect().await?;

    // Group varbinds by row index using describe_varbind
    let mut rows: BTreeMap<SmallVec<[u32; 4]>, Vec<(&VarBind, mib_support::VarBindInfo<'_>)>> =
        BTreeMap::new();

    for vb in &results {
        if let Some(info) = mib_support::describe_varbind(&mib, vb) {
            let suffix = info.suffix.clone();
            rows.entry(suffix).or_default().push((vb, info));
        }
    }

    // Display grouped by row
    for (index, columns) in &rows {
        let index_str: Vec<_> = index.iter().map(|a| a.to_string()).collect();
        println!("--- Row index: {} ---", index_str.join("."));

        for (_, info) in columns {
            println!(
                "  {}::{}  =  {}",
                info.module_name, info.object_name, info.formatted_value
            );

            if !info.units.is_empty() {
                println!("    units: {}", info.units);
            }
        }
        println!();
    }

    println!("{} rows, {} total varbinds", rows.len(), results.len());
    Ok(())
}
