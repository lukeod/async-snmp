//! Walk a table and decode results using MIB metadata.
//!
//! This example uses `describe_varbind` to group columns by row and compiles an
//! `IndexSchema` to decode each row's INDEX components. It demonstrates
//! programmatic MIB metadata access beyond string formatting.
//!
//! Run `cargo run --example mib_table --features mib -- 192.168.1.1`. The target
//! must run an SNMP agent.

use async_snmp::mib_support::{self, DecodeOptions, IndexSchema, Loader};
use async_snmp::{Auth, Client, VarBind};
use smallvec::SmallVec;
use std::collections::{BTreeMap, btree_map::Entry};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1".to_string());

    // Load MIB modules from the system search paths.
    let mib = tokio::task::spawn_blocking(|| Loader::new().system_paths().load()).await??;

    // Resolve and walk ifTable.
    let if_table = mib_support::resolve_oid(&mib, "ifTable")?;

    let client = Client::builder(target, Auth::v2c("public"))
        .connect()
        .await?;

    let results: Vec<_> = client.walk(if_table)?.collect().await?;

    // Group variable bindings by row index and decode each index from MIB metadata.
    type Row<'a> = (
        Vec<String>,
        Vec<(&'a VarBind, mib_support::VarBindInfo<'a>)>,
    );
    let mut rows: BTreeMap<SmallVec<[u32; 4]>, Row<'_>> = BTreeMap::new();
    let mut index_schemas = BTreeMap::new();

    for vb in &results {
        if let Some(info) = mib_support::describe_varbind(&mib, vb) {
            let mib_oid = vb.oid.to_mib_oid();
            let lookup = mib.lookup_instance(&mib_oid);
            let node = lookup.node();
            let object = node.object().expect("describe_varbind found an object");
            let schema = match index_schemas.entry(node.oid().clone()) {
                Entry::Occupied(entry) => entry.into_mut(),
                Entry::Vacant(entry) => entry.insert(IndexSchema::compile(object)?),
            };
            let decoded = lookup
                .decode_indexes_exact(schema, DecodeOptions::new(lookup.suffix().len()))
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            let indexes = decoded
                .components()
                .map(|component| format!("{}={}", component.name(), component.value()))
                .collect();
            let suffix = info.suffix.clone();
            rows.entry(suffix)
                .or_insert_with(|| (indexes, Vec::new()))
                .1
                .push((vb, info));
        }
    }

    // Display the columns grouped by row.
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

    println!(
        "{} rows, {} total variable bindings",
        rows.len(),
        results.len()
    );
    Ok(())
}
