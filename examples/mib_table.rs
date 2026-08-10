//! Walk a table and decode results using MIB metadata.
//!
//! Uses `describe_varbind` to group columns by row and `decode_indexes` to
//! interpret each row's INDEX components. Shows programmatic use of MIB
//! metadata beyond simple string formatting.
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
    let mib = tokio::task::spawn_blocking(|| Loader::new().system_paths().load()).await??;

    // Resolve ifTable and walk it
    let if_table = mib_support::resolve_oid(&mib, "ifTable")?;

    let client = Client::builder(target, Auth::v2c("public"))
        .connect()
        .await?;

    let results: Vec<_> = client.walk(if_table)?.collect().await?;

    // Group varbinds by row index using describe_varbind
    type Row<'a> = (
        Vec<String>,
        Vec<(&'a VarBind, mib_support::VarBindInfo<'a>)>,
    );
    let mut rows: BTreeMap<SmallVec<[u32; 4]>, Row<'_>> = BTreeMap::new();

    for vb in &results {
        if let Some(info) = mib_support::describe_varbind(&mib, vb) {
            let indexes = mib
                .lookup_instance(&vb.oid.to_mib_oid())
                .decode_indexes()
                .into_iter()
                .map(|index| index.to_string())
                .collect();
            let suffix = info.suffix.clone();
            rows.entry(suffix)
                .or_insert_with(|| (indexes, Vec::new()))
                .1
                .push((vb, info));
        }
    }

    // Display grouped by row
    for (raw_index, (indexes, columns)) in &rows {
        if indexes.is_empty() {
            let raw: Vec<_> = raw_index.iter().map(|arc| arc.to_string()).collect();
            println!("--- Row index: {} ---", raw.join("."));
        } else {
            println!("--- Row index: {} ---", indexes.join(", "));
        }

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
