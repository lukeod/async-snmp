//! Walk an SNMP table with MIB-aware output.
//!
//! This example loads MIB modules from the system search paths, resolves
//! `ifTable`, walks the table, and formats each result with a symbolic OID,
//! enumeration labels, and display hints.
//!
//! Run `cargo run --example mib_walk --features mib -- 192.168.1.1`. The target
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

    // Resolve ifTable by name.
    let if_table = mib_support::resolve_oid(&mib, "ifTable")?;
    println!(
        "Walking {} ({})",
        mib_support::format_oid(&mib, &if_table),
        if_table
    );

    // Connect to the agent and walk the table.
    let client = Client::builder(target, Auth::v2c("public"))
        .connect()
        .await?;

    let results: Vec<_> = client.walk(if_table)?.collect().await?;

    // Format each result with its MIB metadata.
    for vb in &results {
        println!("{}", mib_support::format_varbind(&mib, vb));
    }

    println!("\n{} variable bindings returned", results.len());
    Ok(())
}
