//! Use an SNMPv2c client
//!
//! The client performs these SNMPv2c operations:
//!
//! - GET retrieves one OID.
//! - `get_many` retrieves multiple OIDs in one request.
//! - GETNEXT retrieves the next OID in lexicographic order.
//! - SET modifies a writable object.
//!
//! Run `cargo run --example basic_client`.
//!
//! To use the project's net-snmp test image, run:
//!
//! ```text
//! docker build -t async-snmp-test:latest tests/containers/snmpd/
//! docker run --rm -p 11161:161/udp async-snmp-test:latest
//! ```

use async_snmp::{Auth, Client, Error, ErrorStatus, Retry, Value, oid};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for optional diagnostic output.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("async_snmp=info".parse()?),
        )
        .init();

    // Change the target to match your SNMP agent.
    let target = ("127.0.0.1", 11161);

    // Create an SNMPv2c client with the "public" community string.
    let client = Client::builder(target, Auth::v2c("public"))
        .request_timeout(Duration::from_secs(5))
        .retry(Retry::fixed(3, Duration::ZERO).expect("valid retry count"))
        .connect()
        .await?;

    println!("UDP client configured for {}", client.peer_addr());

    // =========================================================================
    // GET: Retrieve a single OID
    // =========================================================================
    println!("\n--- GET sysDescr.0 ---");

    // The oid! macro creates an OID at compile time.
    let sys_descr = oid!(1, 3, 6, 1, 2, 1, 1, 1, 0);

    match client.get(&sys_descr).await {
        Ok(response) => {
            for anomaly in &response.anomalies {
                eprintln!("Response shape anomaly: {anomaly:?}");
            }
            for varbind in &response.varbinds {
                print_varbind(varbind);
            }

            // Extract a value only from an unambiguous singleton response.
            if let Some(varbind) = response.single()
                && let Some(s) = varbind.value.as_str()
            {
                println!("As string: {s}");
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

    // Define the OIDs to retrieve.
    let oids = [
        oid!(1, 3, 6, 1, 2, 1, 1, 1, 0), // sysDescr
        oid!(1, 3, 6, 1, 2, 1, 1, 3, 0), // sysUpTime
        oid!(1, 3, 6, 1, 2, 1, 1, 5, 0), // sysName
        oid!(1, 3, 6, 1, 2, 1, 1, 6, 0), // sysLocation
    ];

    match client.get_many(&oids).await {
        Ok(response) => {
            for anomaly in &response.anomalies {
                eprintln!("Response shape anomaly: {anomaly:?}");
            }
            for vb in response.varbinds {
                print_varbind(&vb);
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

    // Start at the system subtree (1.3.6.1.2.1.1).
    let system_oid = oid!(1, 3, 6, 1, 2, 1, 1);

    match client.get_next(&system_oid).await {
        Ok(response) => {
            for anomaly in &response.anomalies {
                eprintln!("Response shape anomaly: {anomaly:?}");
            }
            for varbind in response.varbinds {
                println!("Next OID after {}: {}", system_oid, varbind.oid);
                print_varbind(&varbind);
            }
        }
        Err(e) => {
            handle_error("GETNEXT", &e);
        }
    }

    // =========================================================================
    // SET: Modify a writable value
    // =========================================================================
    println!("\n--- SET sysContact.0 ---");

    // Create a client with the "private" community to write sysContact.0.
    let write_client = Client::builder(target, Auth::v2c("private"))
        .request_timeout(Duration::from_secs(5))
        .connect()
        .await?;

    let sys_contact = oid!(1, 3, 6, 1, 2, 1, 1, 4, 0);
    let new_value = Value::from("admin@example.com");

    match write_client.set(&sys_contact, new_value).await {
        Ok(response) => {
            for anomaly in &response.anomalies {
                eprintln!("Response shape anomaly: {anomaly:?}");
            }
            for varbind in response.varbinds {
                print_varbind(&varbind);
            }
        }
        Err(e) => {
            // Access-control policy commonly rejects SET operations.
            handle_error("SET", &e);
        }
    }

    // =========================================================================
    // Verify the SET operation
    // =========================================================================
    println!("\n--- Verify SET ---");

    match client.get(&sys_contact).await {
        Ok(response) => {
            for anomaly in &response.anomalies {
                eprintln!("Response shape anomaly: {anomaly:?}");
            }
            for varbind in response.varbinds {
                print_varbind(&varbind);
            }
        }
        Err(e) => {
            handle_error("GET (verify)", &e);
        }
    }

    println!("\nExample complete!");
    Ok(())
}

/// Prints a variable binding and distinguishes SNMPv2 exception values from data.
fn print_varbind(varbind: &async_snmp::VarBind) {
    match &varbind.value {
        Value::NoSuchObject => {
            println!("  {}: object identity is not available", varbind.oid);
        }
        Value::NoSuchInstance => {
            println!("  {}: object instance does not exist", varbind.oid);
        }
        Value::EndOfMibView => {
            println!("  {}: end of MIB view", varbind.oid);
        }
        value => println!("  {}: {value:?}", varbind.oid),
    }
}

/// Reports an SNMP operation error with relevant diagnostic details.
fn handle_error(operation: &str, error: &Error) {
    match error {
        // Report an SNMP error-status returned by the agent.
        Error::Snmp {
            status, index, oid, ..
        } => {
            println!("{operation} failed: SNMP error {status:?} at index {index}");
            if let Some(oid) = oid {
                println!("  Problematic OID: {oid}");
            }

            // Provide guidance for selected error-status values.
            match status {
                ErrorStatus::NoSuchName => {
                    println!("  -> OID does not exist on this SNMPv1 agent");
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

        // Report timeouts separately from other network errors.
        Error::Timeout {
            target,
            elapsed,
            retries,
            ..
        } => {
            println!("{operation} failed: Timeout after {elapsed:?} ({retries} retries)");
            println!("  -> Check if agent at {target} is reachable");
        }

        // Report other network errors and their target.
        Error::Network { target, source, .. } => {
            println!("{operation} failed: Network error - {source}");
            println!("  -> Target: {target}");
        }

        // Use the error's display representation for all other variants.
        _ => {
            println!("{operation} failed: {error}");
        }
    }
}
