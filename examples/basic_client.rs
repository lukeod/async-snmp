//! Basic SNMPv2c Client Example
//!
//! This example demonstrates fundamental SNMP operations using SNMPv2c:
//! - GET: Retrieve a single OID value
//! - GET_MANY: Retrieve multiple OIDs in one request
//! - GETNEXT: Get the next OID in the MIB tree
//! - SET: Modify a writable OID value
//!
//! Run with: cargo run --example basic_client
//!
//! Test against net-snmp:
//!   # Start snmpd with a writable community
//!   sudo snmpd -f -Lo -c /etc/snmp/snmpd.conf
//!
//! Or use the testcontainers snmpd image:
//!   docker run -p 11161:161/udp testainers/snmpd-container

use async_snmp::{Auth, Client, Error, ErrorStatus, Retry, Value, oid};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for debug output (optional)
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("async_snmp=info".parse()?),
        )
        .init();

    // Target address - change to match your SNMP agent
    let target = "127.0.0.1:11161";

    // Create a v2c client with the "public" community string
    // The builder pattern allows configuring timeout, retries, etc.
    let client = Client::builder(target, Auth::v2c("public"))
        .timeout(Duration::from_secs(5))
        .retry(Retry::fixed(3, Duration::ZERO))
        .connect()
        .await?;

    println!("Connected to {}", client.peer_addr());

    // =========================================================================
    // GET: Retrieve a single OID
    // =========================================================================
    println!("\n--- GET sysDescr.0 ---");

    // The oid! macro creates OIDs at compile time
    let sys_descr = oid!(1, 3, 6, 1, 2, 1, 1, 1, 0);

    match client.get(&sys_descr).await {
        Ok(varbind) => {
            println!("OID: {}", varbind.oid);
            println!("Value: {:?}", varbind.value);

            // Extract string value if present
            if let Some(s) = varbind.value.as_str() {
                println!("As string: {}", s);
            }
        }
        Err(e) => {
            handle_error("GET", &e);
        }
    }

    // =========================================================================
    // GET_MANY: Retrieve multiple OIDs in a single request
    // =========================================================================
    println!("\n--- GET_MANY (system MIB) ---");

    // Define multiple OIDs to fetch
    let oids = [
        oid!(1, 3, 6, 1, 2, 1, 1, 1, 0), // sysDescr
        oid!(1, 3, 6, 1, 2, 1, 1, 3, 0), // sysUpTime
        oid!(1, 3, 6, 1, 2, 1, 1, 5, 0), // sysName
        oid!(1, 3, 6, 1, 2, 1, 1, 6, 0), // sysLocation
    ];

    match client.get_many(&oids).await {
        Ok(varbinds) => {
            for vb in varbinds {
                println!("  {}: {:?}", vb.oid, vb.value);
            }
        }
        Err(e) => {
            handle_error("GET_MANY", &e);
        }
    }

    // =========================================================================
    // GETNEXT: Get the lexicographically next OID
    // =========================================================================
    println!("\n--- GETNEXT from system ---");

    // Start from the system subtree (1.3.6.1.2.1.1)
    let system_oid = oid!(1, 3, 6, 1, 2, 1, 1);

    match client.get_next(&system_oid).await {
        Ok(varbind) => {
            println!("Next OID after {}: {}", system_oid, varbind.oid);
            println!("Value: {:?}", varbind.value);
        }
        Err(e) => {
            handle_error("GETNEXT", &e);
        }
    }

    // =========================================================================
    // SET: Modify a writable value
    // =========================================================================
    println!("\n--- SET sysContact.0 ---");

    // sysContact.0 is typically writable with the "private" community
    // Create a new client with write access
    let write_client = Client::builder(target, Auth::v2c("private"))
        .timeout(Duration::from_secs(5))
        .connect()
        .await?;

    let sys_contact = oid!(1, 3, 6, 1, 2, 1, 1, 4, 0);
    let new_value = Value::from("admin@example.com");

    match write_client.set(&sys_contact, new_value).await {
        Ok(varbind) => {
            println!("Set successful!");
            println!("  {}: {:?}", varbind.oid, varbind.value);
        }
        Err(e) => {
            // SET operations commonly fail due to access control
            handle_error("SET", &e);
        }
    }

    // =========================================================================
    // Verify the SET operation
    // =========================================================================
    println!("\n--- Verify SET ---");

    match client.get(&sys_contact).await {
        Ok(varbind) => {
            println!("Current value: {:?}", varbind.value);
        }
        Err(e) => {
            handle_error("GET (verify)", &e);
        }
    }

    println!("\nExample complete!");
    Ok(())
}

/// Handle SNMP errors with informative messages.
///
/// This demonstrates proper error handling patterns for SNMP operations.
fn handle_error(operation: &str, error: &Error) {
    match error {
        // SNMP protocol errors from the agent
        Error::Snmp {
            status, index, oid, ..
        } => {
            println!(
                "{} failed: SNMP error {:?} at index {}",
                operation, status, index
            );
            if let Some(oid) = oid {
                println!("  Problematic OID: {}", oid);
            }

            // Provide specific guidance based on error type
            match status {
                ErrorStatus::NoSuchName => {
                    println!("  -> OID does not exist on this agent");
                }
                ErrorStatus::NotWritable => {
                    println!("  -> OID is read-only");
                }
                ErrorStatus::AuthorizationError => {
                    println!("  -> Access denied (check community string)");
                }
                _ => {}
            }
        }

        // Network timeout
        Error::Timeout {
            target,
            elapsed,
            retries,
            ..
        } => {
            println!(
                "{} failed: Timeout after {:?} ({} retries)",
                operation, elapsed, retries
            );
            println!("  -> Check if agent at {} is reachable", target);
        }

        // Network errors
        Error::Network { target, source, .. } => {
            println!("{} failed: Network error - {}", operation, source);
            println!("  -> Target: {}", target);
        }

        // Other errors
        _ => {
            println!("{} failed: {}", operation, error);
        }
    }
}
