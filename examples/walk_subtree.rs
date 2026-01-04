//! SNMP Walk Examples
//!
//! This example demonstrates walking OID subtrees using different methods:
//! - walk(): Auto-selects GETNEXT or GETBULK based on version
//! - walk_getnext(): Forces GETNEXT (SNMPv1 compatible)
//! - bulk_walk(): Uses GETBULK for efficiency (SNMPv2c/v3 only)
//!
//! The examples also show how to use futures::StreamExt for stream processing.
//!
//! Run with: cargo run --example walk_subtree

use async_snmp::format::hints;
use async_snmp::{Auth, Client, OidOrdering, WalkMode, oid};
use futures::StreamExt;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("async_snmp=info".parse()?),
        )
        .init();

    let target = "127.0.0.1:11161";

    // =========================================================================
    // Example 1: Basic walk with collect()
    // =========================================================================
    println!("--- Walk system subtree (collect all) ---\n");

    let client = Client::builder(target, Auth::v2c("public"))
        .timeout(Duration::from_secs(5))
        .connect()
        .await?;

    // walk() returns a Result<WalkStream> because GETBULK mode can fail on V1
    let walk = client.walk(oid!(1, 3, 6, 1, 2, 1, 1))?;

    // Use the inherent collect() method to gather all results
    let results = walk.collect().await?;

    println!("Found {} OIDs in system subtree:", results.len());
    for vb in &results {
        println!("  {}: {:?}", vb.oid, vb.value);
    }

    // =========================================================================
    // Example 2: Stream processing with next()
    // =========================================================================
    println!("\n--- Walk interfaces table (stream processing) ---\n");

    // Walk the ifTable (1.3.6.1.2.1.2.2)
    let mut walk = client.walk(oid!(1, 3, 6, 1, 2, 1, 2, 2))?;

    let mut count = 0;
    while let Some(result) = walk.next().await {
        match result {
            Ok(vb) => {
                count += 1;
                println!("  [{}] {}: {:?}", count, vb.oid, vb.value);

                // Example: Stop early after 10 results
                if count >= 10 {
                    println!("  ... stopping after 10 results");
                    break;
                }
            }
            Err(e) => {
                println!("  Walk error: {}", e);
                break;
            }
        }
    }

    // =========================================================================
    // Example 3: Using StreamExt for functional processing
    // =========================================================================
    println!("\n--- Walk with StreamExt (filter and map) ---\n");

    // Walk system subtree and filter for string values only
    let walk = client.walk(oid!(1, 3, 6, 1, 2, 1, 1))?;

    // Use StreamExt methods for functional-style processing
    let strings: Vec<_> = walk
        .filter_map(|result| async move {
            match result {
                Ok(vb) => vb.value.as_str().map(|s| (vb.oid, s.to_string())),
                Err(_) => None,
            }
        })
        .collect()
        .await;

    println!("String values found:");
    for (oid, value) in &strings {
        println!("  {}: {}", oid, value);
    }

    // =========================================================================
    // Example 4: GETBULK walk with custom max_repetitions
    // =========================================================================
    println!("\n--- BULKWALK with max_repetitions=50 ---\n");

    // bulk_walk allows specifying max_repetitions for efficiency
    let walk = client.bulk_walk(oid!(1, 3, 6, 1, 2, 1, 2, 2), 50);

    let results = walk.collect().await?;
    println!("BULKWALK found {} OIDs", results.len());

    // =========================================================================
    // Example 5: Force GETNEXT mode (SNMPv1 compatible)
    // =========================================================================
    println!("\n--- Force GETNEXT mode ---\n");

    // walk_getnext always uses GETNEXT, regardless of version
    // Useful for compatibility with buggy agents
    let walk = client.walk_getnext(oid!(1, 3, 6, 1, 2, 1, 1));

    let results = walk.collect().await?;
    println!("GETNEXT walk found {} OIDs", results.len());

    // =========================================================================
    // Example 6: Configure walk behavior via builder
    // =========================================================================
    println!("\n--- Configured walk behavior ---\n");

    let configured_client = Client::builder(target, Auth::v2c("public"))
        .timeout(Duration::from_secs(5))
        // Force GETNEXT mode (useful for buggy agents)
        .walk_mode(WalkMode::GetNext)
        // Allow non-increasing OIDs (some agents have bugs)
        .oid_ordering(OidOrdering::AllowNonIncreasing)
        // Limit results to prevent runaway walks
        .max_walk_results(100)
        // Set GETBULK repetitions (when using GETBULK mode)
        .max_repetitions(25)
        .connect()
        .await?;

    let walk = configured_client.walk(oid!(1, 3, 6, 1, 2, 1, 1))?;
    let results = walk.collect().await?;

    println!("Configured walk found {} OIDs (max 100)", results.len());

    // =========================================================================
    // Example 7: Walking multiple subtrees concurrently
    // =========================================================================
    println!("\n--- Concurrent walks ---\n");

    // Define subtrees to walk
    let subtrees = [
        oid!(1, 3, 6, 1, 2, 1, 1),  // system
        oid!(1, 3, 6, 1, 2, 1, 2),  // interfaces
        oid!(1, 3, 6, 1, 2, 1, 25), // host resources
    ];

    // Walk all subtrees concurrently
    let mut handles = Vec::new();

    for subtree in subtrees {
        let client = client.clone(); // Client is Clone (Arc internally)
        let handle = tokio::spawn(async move {
            let walk = client.walk(subtree.clone())?;
            let results = walk.collect().await?;
            Ok::<_, Box<async_snmp::Error>>((subtree, results.len()))
        });
        handles.push(handle);
    }

    // Collect results
    for handle in handles {
        match handle.await? {
            Ok((subtree, count)) => {
                println!("  {} - {} OIDs", subtree, count);
            }
            Err(e) => {
                println!("  Walk failed: {}", e);
            }
        }
    }

    // =========================================================================
    // Example 8: Table walking pattern
    // =========================================================================
    println!("\n--- Table walking pattern (ifTable) ---\n");

    // Walking SNMP tables: the ifTable structure
    // Each column has OIDs like: ifEntry.{column}.{row}
    //                           1.3.6.1.2.1.2.2.1.{column}.{row}

    let if_entry = oid!(1, 3, 6, 1, 2, 1, 2, 2, 1);

    let walk = client.walk(if_entry.clone())?;
    let results = walk.collect().await?;

    // Group by column using strip_prefix to extract the table index suffix
    let mut columns: std::collections::HashMap<u32, Vec<_>> = std::collections::HashMap::new();

    for vb in results {
        // strip_prefix returns the suffix: [column, row] for ifEntry OIDs
        if let Some(suffix) = vb.oid.strip_prefix(&if_entry)
            && let Some(&column) = suffix.arcs().first()
        {
            columns.entry(column).or_default().push(vb);
        }
    }

    // Standard ifTable columns
    let column_names = [
        (1, "ifIndex"),
        (2, "ifDescr"),
        (3, "ifType"),
        (5, "ifSpeed"),
        (6, "ifPhysAddress"),
        (7, "ifAdminStatus"),
        (8, "ifOperStatus"),
    ];

    for (col_id, col_name) in column_names {
        if let Some(entries) = columns.get(&col_id) {
            println!("  {} ({} entries)", col_name, entries.len());
        }
    }

    // =========================================================================
    // Example 9: Formatting values with DISPLAY-HINT
    // =========================================================================
    println!("\n--- Formatting with DISPLAY-HINT ---\n");

    // The format module provides RFC 2579 DISPLAY-HINT formatting.
    // This is useful for formatting MAC addresses, structured strings, etc.

    // ifPhysAddress (column 6) contains MAC addresses as raw bytes
    if let Some(mac_entries) = columns.get(&6) {
        println!("MAC addresses (formatted with hints::MAC_ADDRESS):");
        for vb in mac_entries.iter().take(5) {
            // Value::format_with_hint applies RFC 2579 formatting
            // hints::MAC_ADDRESS is "1x:": 1 byte, hex format, colon separator
            if let Some(formatted) = vb.value.format_with_hint(hints::MAC_ADDRESS) {
                println!("  {}: {}", vb.oid, formatted);
            } else {
                // format_with_hint returns None for non-OctetString values
                println!("  {}: {:?} (raw)", vb.oid, vb.value);
            }
        }
    }

    // You can also use the format module directly for more control
    use async_snmp::format::{display_hint, hex};

    println!("\nDirect format module usage:");

    // Format bytes as a MAC address
    let mac_bytes = [0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e];
    println!("  MAC (1x:): {}", display_hint::apply("1x:", &mac_bytes));

    // Format bytes as an IPv4 address
    let ip_bytes = [192, 168, 1, 1];
    println!("  IPv4 (1d.): {}", display_hint::apply("1d.", &ip_bytes));

    // Hex encoding for binary data (useful for engine IDs, etc.)
    let engine_id = [0x80, 0x00, 0x1f, 0x88, 0x04];
    println!("  Engine ID (hex): {}", hex::encode(&engine_id));

    // Lazy hex formatting for logging (avoids allocation if log level disabled)
    println!("  Lazy hex: {}", hex::Bytes(&engine_id));

    println!("\nExample complete!");
    Ok(())
}
