//! Walk SNMP subtrees
//!
//! The client provides these walk methods:
//!
//! - `walk` selects GETNEXT for SNMPv1 and GETBULK for SNMPv2c and SNMPv3.
//! - `walk_getnext` selects GETNEXT for every supported SNMP version.
//! - `bulk_walk` selects GETBULK for SNMPv2c and SNMPv3.
//!
//! The example also uses `TryStreamExt` for stream processing. All consumers
//! observe the same GETNEXT or GETBULK sequence. Use `Client::get` to retrieve a
//! scalar instance.
//!
//! Run `cargo run --example walk_subtree`.

use async_snmp::format::hints;
use async_snmp::{Auth, Client, OidOrdering, WalkMethod, WalkOptions, oid};
use futures::TryStreamExt;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("async_snmp=info".parse()?),
        )
        .init();

    let target = ("127.0.0.1", 11161);

    // =========================================================================
    // Example 1: Basic walk with collect()
    // =========================================================================
    println!("--- Walk system subtree (collect all) ---\n");

    let client = Client::builder(target, Auth::v2c("public"))
        .request_timeout(Duration::from_secs(5))
        .connect()
        .await?;

    // walk() validates the selected method and options before returning a stream.
    let walk = client.walk(oid!(1, 3, 6, 1, 2, 1, 1))?;

    // Use the inherent collect() method to gather the same items that next()
    // or StreamExt consumers would observe.
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

                // Stop after 10 results.
                if count >= 10 {
                    println!("  ... stopping after 10 results");
                    break;
                }
            }
            Err(e) => {
                println!("  Walk error: {e}");
                break;
            }
        }
    }

    // =========================================================================
    // Example 3: Using StreamExt for functional processing
    // =========================================================================
    println!("\n--- Walk with StreamExt (filter and map) ---\n");

    // Walk the system subtree and retain only string values.
    let walk = client.walk(oid!(1, 3, 6, 1, 2, 1, 1))?;

    // Use TryStreamExt methods for functional-style processing while preserving
    // walk errors. These consume the same sequence as next() and collect().
    let strings: Vec<_> = walk
        .try_filter_map(|vb| async move {
            let value = vb.value.as_str().map(str::to_owned);
            Ok(value.map(|value| (vb.oid, value)))
        })
        .try_collect()
        .await?;

    println!("String values found:");
    for (oid, value) in &strings {
        println!("  {oid}: {value}");
    }

    // =========================================================================
    // Example 4: GETBULK walk with custom max_repetitions
    // =========================================================================
    println!("\n--- BULKWALK with max_repetitions=50 ---\n");

    // Set max-repetitions to 50 for each GETBULK request.
    let walk = client.bulk_walk(oid!(1, 3, 6, 1, 2, 1, 2, 2), 50)?;

    let results = walk.collect().await?;
    println!("BULKWALK found {} OIDs", results.len());

    // =========================================================================
    // Example 5: Force GETNEXT mode (SNMPv1 compatible)
    // =========================================================================
    println!("\n--- Force GETNEXT mode ---\n");

    // Use GETNEXT for compatibility with agents that do not handle GETBULK.
    let walk = client.walk_getnext(oid!(1, 3, 6, 1, 2, 1, 1))?;

    let results = walk.collect().await?;
    println!("GETNEXT walk found {} OIDs", results.len());

    // =========================================================================
    // Example 6: Configure walk behavior via builder
    // =========================================================================
    println!("\n--- Configured walk behavior ---\n");

    let configured_client = Client::builder(target, Auth::v2c("public"))
        .request_timeout(Duration::from_secs(5))
        .walk_options(WalkOptions {
            method: WalkMethod::GetNext,
            max_repetitions: 25,
            ordering: OidOrdering::AllowNonIncreasing,
            result_limit: Some(100),
        })
        .connect()
        .await?;

    let walk = configured_client.walk(oid!(1, 3, 6, 1, 2, 1, 1))?;
    let results = walk.collect().await?;

    println!("Configured walk found {} OIDs (max 100)", results.len());

    // =========================================================================
    // Example 7: Walking multiple subtrees concurrently
    // =========================================================================
    println!("\n--- Concurrent walks ---\n");

    // Define the subtrees to walk.
    let subtrees = [
        oid!(1, 3, 6, 1, 2, 1, 1),  // system
        oid!(1, 3, 6, 1, 2, 1, 2),  // interfaces
        oid!(1, 3, 6, 1, 2, 1, 25), // host resources
    ];

    // Walk all subtrees concurrently.
    let mut handles = Vec::new();

    for subtree in subtrees {
        let client = client.clone();
        let handle = tokio::spawn(async move {
            let walk = client.walk(subtree.clone())?;
            let results = walk.collect().await?;
            Ok::<_, Box<async_snmp::Error>>((subtree, results.len()))
        });
        handles.push(handle);
    }

    // Collect each task's result.
    for handle in handles {
        match handle.await? {
            Ok((subtree, count)) => {
                println!("  {subtree} - {count} OIDs");
            }
            Err(e) => {
                println!("  Walk failed: {e}");
            }
        }
    }

    // =========================================================================
    // Example 8: Table walking pattern
    // =========================================================================
    println!("\n--- Table walking pattern (ifTable) ---\n");

    // An ifTable column has OIDs in the form ifEntry.{column}.{row}, or
    // 1.3.6.1.2.1.2.2.1.{column}.{row}.

    let if_entry = oid!(1, 3, 6, 1, 2, 1, 2, 2, 1);

    let walk = client.walk(if_entry.clone())?;
    let results = walk.collect().await?;

    // Group variable bindings by column after removing the ifEntry prefix.
    let mut columns: std::collections::HashMap<u32, Vec<_>> = std::collections::HashMap::new();

    for vb in results {
        // The suffix contains [column, row] for ifEntry OIDs.
        if let Some(suffix) = vb.oid.strip_prefix(&if_entry)
            && let Some(&column) = suffix.arcs().first()
        {
            columns.entry(column).or_default().push(vb);
        }
    }

    // Name selected standard ifTable columns.
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

    // The format module implements RFC 2579 DISPLAY-HINT formatting.

    // ifPhysAddress (column 6) contains MAC addresses as raw bytes.
    if let Some(mac_entries) = columns.get(&6) {
        println!("MAC addresses (formatted with hints::MAC_ADDRESS):");
        for vb in mac_entries.iter().take(5) {
            // hints::MAC_ADDRESS is "1x:": one byte in hexadecimal followed by
            // a colon separator.
            if let Some(formatted) = vb.value.format_with_hint(hints::MAC_ADDRESS) {
                println!("  {}: {}", vb.oid, formatted);
            } else {
                // format_with_hint returns None for values other than OctetString.
                println!("  {}: {:?} (raw)", vb.oid, vb.value);
            }
        }
    }
    {
        // Use the format module directly to select individual operations.
        use async_snmp::format::{display_hint, hex};

        println!("\nDirect format module usage:");

        // Format bytes as a MAC address.
        let mac_bytes = [0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e];
        println!("  MAC (1x:): {}", display_hint::apply("1x:", &mac_bytes));

        // Format bytes as an IPv4 address.
        let ip_bytes = [192, 168, 1, 1];
        println!("  IPv4 (1d.): {}", display_hint::apply("1d.", &ip_bytes));

        // Encode binary data such as an engine ID in hexadecimal.
        let engine_id = [0x80, 0x00, 0x1f, 0x88, 0x04];
        println!("  Engine ID (hex): {}", hex::encode(&engine_id));

        // Defer hexadecimal formatting until the value is displayed.
        println!("  Lazy hex: {}", hex::Bytes(&engine_id));

        println!("\nExample complete!");
    }
    Ok(())
}
