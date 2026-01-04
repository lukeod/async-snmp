//! Shared Transport for High-Throughput Polling
//!
//! This example demonstrates using a shared UdpTransport for polling many
//! targets efficiently. A single UDP socket is shared across all clients
//! using request-ID correlation, reducing file descriptor usage.
//!
//! Key concepts:
//! - UdpTransport: A single UDP socket shared across multiple clients
//! - `.build_with(&transport)`: Creates a client using the shared transport
//! - Request ID correlation: Responses are matched to requests by ID
//! - Engine cache: Share SNMPv3 engine discovery across clients
//!
//! Run with: cargo run --example shared_transport
//!
//! Uses the async-snmp test container:
//!   docker build -t async-snmp-test:latest tests/containers/snmpd/
//!   docker run -d -p 11161:161/udp async-snmp-test:latest

use async_snmp::transport::UdpTransport;
use async_snmp::{Auth, AuthProtocol, Client, EngineCache, MasterKeys, PrivProtocol, Retry, oid};
use futures::stream::{FuturesUnordered, StreamExt};
use std::net::SocketAddr;
use std::sync::Arc;
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

    let container_target: SocketAddr = "127.0.0.1:11161".parse()?;

    // =========================================================================
    // Example 1: Basic shared transport setup
    // =========================================================================
    println!("--- Basic Shared Transport ---\n");

    // Create a shared transport bound to an ephemeral port.
    // Using [::]:0 creates a dual-stack socket that handles both IPv4 and IPv6.
    let shared = UdpTransport::bind("[::]:0").await?;

    println!("Shared transport bound to {}", shared.local_addr());

    // Create clients for different targets - all use the same underlying socket
    let client1 =
        Client::builder(container_target.to_string(), Auth::v2c("public")).build_with(&shared)?;
    let client2 = Client::builder("192.0.2.1:161", Auth::v2c("public")) // TEST-NET-1 (unreachable)
        .build_with(&shared)?;

    println!(
        "Created clients for {} and {}",
        client1.peer_addr(),
        client2.peer_addr()
    );
    println!("Both clients share local addr: {}\n", shared.local_addr());

    // =========================================================================
    // Example 2: Concurrent polling with shared transport
    // =========================================================================
    println!("--- Concurrent Polling ---\n");

    // Poll multiple OIDs concurrently through the same shared transport
    let shared = UdpTransport::bind("[::]:0").await?;

    let oids = [
        oid!(1, 3, 6, 1, 2, 1, 1, 1, 0), // sysDescr
        oid!(1, 3, 6, 1, 2, 1, 1, 3, 0), // sysUpTime
        oid!(1, 3, 6, 1, 2, 1, 1, 5, 0), // sysName
        oid!(1, 3, 6, 1, 2, 1, 1, 6, 0), // sysLocation
    ];

    // Spawn concurrent GET requests
    let mut futures = FuturesUnordered::new();

    for oid in &oids {
        let client = Client::builder(container_target.to_string(), Auth::v2c("public"))
            .timeout(Duration::from_secs(5))
            .retry(Retry::fixed(2, Duration::ZERO))
            .build_with(&shared)?;
        let oid = oid.clone();

        futures.push(async move {
            let result = client.get(&oid).await;
            (oid, result)
        });
    }

    println!("Polling {} OIDs concurrently...", oids.len());

    while let Some((oid, result)) = futures.next().await {
        match result {
            Ok(vb) => println!("  {}: {:?}", oid, vb.value),
            Err(e) => println!("  {}: {}", oid, e),
        }
    }

    // =========================================================================
    // Example 3: SNMPv3 with shared engine cache and master keys
    // =========================================================================
    println!("\n--- SNMPv3 with Shared Engine Cache ---\n");

    // For SNMPv3, engine discovery results are cached to avoid repeated
    // discovery requests. The EngineCache can be shared across clients.
    let engine_cache = Arc::new(EngineCache::new());

    // Pre-compute master keys once (expensive: ~850us for SHA-256).
    // These can be reused across all clients with the same credentials.
    let master_keys = MasterKeys::new(AuthProtocol::Sha256, b"authpass123")
        .with_privacy(PrivProtocol::Aes192, b"privpass123");

    println!("Master keys derived (one-time cost)");
    println!("Engine cache created for sharing\n");

    let shared_v3 = UdpTransport::bind("[::]:0").await?;

    // Poll multiple OIDs using V3 with shared resources
    let v3_oids = [
        oid!(1, 3, 6, 1, 2, 1, 1, 1, 0), // sysDescr
        oid!(1, 3, 6, 1, 2, 1, 1, 3, 0), // sysUpTime
    ];

    for oid in &v3_oids {
        // Create auth with master keys (cheap: just clones Arc)
        // Uses container user: privaes192_user (SHA-256 + AES-192)
        let auth = Auth::usm("privaes192_user").with_master_keys(master_keys.clone());

        let client = Client::builder(container_target.to_string(), auth)
            .timeout(Duration::from_secs(5))
            .retry(Retry::fixed(2, Duration::ZERO))
            .engine_cache(engine_cache.clone())
            .build_with(&shared_v3)?;

        match client.get(oid).await {
            Ok(vb) => println!("  {}: {:?}", oid, vb.value),
            Err(e) => println!("  {}: {}", oid, e),
        }
    }

    // =========================================================================
    // Example 4: Mixed reachable and unreachable targets
    // =========================================================================
    println!("\n--- Mixed Target Polling ---\n");

    // Demonstrates behavior when some targets are unreachable.
    // Uses TEST-NET-1 (192.0.2.0/24) for unreachable addresses.
    let targets = vec![
        container_target.to_string(), // Reachable
        "192.0.2.1:161".to_string(),  // TEST-NET-1 (unreachable)
        "192.0.2.2:161".to_string(),  // TEST-NET-1 (unreachable)
    ];

    let shared = UdpTransport::bind("[::]:0").await?;

    let mut futures = FuturesUnordered::new();

    for target in &targets {
        let client = Client::builder(target, Auth::v2c("public"))
            .timeout(Duration::from_millis(500))
            .retry(Retry::none())
            .build_with(&shared)?;

        futures.push(async move {
            let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;
            (client.peer_addr(), result)
        });
    }

    let mut success = 0;
    let mut timeout = 0;

    while let Some((addr, result)) = futures.next().await {
        match result {
            Ok(vb) => {
                success += 1;
                println!("  {}: {:?}", addr, vb.value);
            }
            Err(e) => match *e {
                async_snmp::Error::Timeout { .. } => {
                    timeout += 1;
                    println!("  {}: timeout", addr);
                }
                _ => println!("  {}: {}", addr, e),
            },
        }
    }

    println!("\nResults: {} success, {} timeout", success, timeout);

    println!("\nExample complete!");
    Ok(())
}
