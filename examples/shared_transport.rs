//! Shared Transport for High-Throughput Polling
//!
//! This example demonstrates using a shared UdpTransport for polling many
//! targets efficiently. A single UDP socket is shared across all clients
//! using protocol-aware correlation, reducing file descriptor usage.
//!
//! Key concepts:
//! - UdpTransport: A single UDP socket shared across multiple clients
//! - `TargetClientBuilder::build_with(&transport)`: Resolves each target and
//!   derives its `UdpHandle` from the preconstructed shared socket
//! - Correlation: Community responses use request-id, version, and community;
//!   V3 uses the outer msgID (the PDU request-id is distinct)
//! - Source policy: Opt-in strict matching is available through
//!   `TargetClientBuilder::strict_source()` or `UdpHandle::strict_source()`
//! - Engine cache: Share V3 target identities and trusted engine time
//! - Endpoint stats: counters are observable through the transport or clients
//!
//! Run with: cargo run --example shared_transport
//!
//! Uses the async-snmp test container:
//!   docker build -t async-snmp-test:latest tests/containers/snmpd/
//!   docker run -d -p 11161:161/udp async-snmp-test:latest

use async_snmp::transport::UdpTransport;
use async_snmp::{
    Auth, AuthProtocol, Client, EngineCache, MasterKeys, PrivProtocol, ResponseShapePolicy, Retry,
    oid,
};
use futures::stream::{FuturesUnordered, StreamExt};
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

    let container_target = ("127.0.0.1", 11161);

    // =========================================================================
    // Example 1: Basic shared transport setup
    // =========================================================================
    println!("--- Basic Shared Transport ---\n");

    // Create a shared transport bound to an ephemeral port.
    let shared = UdpTransport::bind("0.0.0.0:0").await?;

    println!("Shared transport bound to {}", shared.local_addr());

    // Create clients for different targets - all use the same underlying socket.
    // This local agent has a stable response address, so require source matching;
    // exact community matching remains the default.
    let client1 = Client::builder(container_target, Auth::v2c("public"))
        .strict_source(true)
        .build_with(&shared)
        .await?;
    let client2 = Client::builder(("192.0.2.1", 161), Auth::v2c("public")) // TEST-NET-1 (unreachable)
        .build_with(&shared)
        .await?;

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
    let shared = UdpTransport::bind("0.0.0.0:0").await?;

    let oids = [
        oid!(1, 3, 6, 1, 2, 1, 1, 1, 0), // sysDescr
        oid!(1, 3, 6, 1, 2, 1, 1, 3, 0), // sysUpTime
        oid!(1, 3, 6, 1, 2, 1, 1, 5, 0), // sysName
        oid!(1, 3, 6, 1, 2, 1, 1, 6, 0), // sysLocation
    ];

    // Queue concurrent GET requests. Reuse one client so request IDs and target
    // state are shared as well as the underlying socket.
    let mut futures = FuturesUnordered::new();

    let client = Client::builder(container_target, Auth::v2c("public"))
        .response_shape_policy(ResponseShapePolicy::Strict)
        .request_timeout(Duration::from_secs(5))
        .retry(Retry::fixed(2, Duration::ZERO))
        .build_with(&shared)
        .await?;

    for oid in &oids {
        let client = client.clone();
        let oid = oid.clone();

        futures.push(async move {
            let result = client.get(&oid).await;
            (oid, result)
        });
    }

    println!("Polling {} OIDs concurrently...", oids.len());

    while let Some((oid, result)) = futures.next().await {
        match result {
            Ok(response) => println!("  {oid}: {:?}", response.varbinds[0].value),
            Err(e) => println!("  {oid}: {e}"),
        }
    }

    // =========================================================================
    // Example 3: SNMPv3 with shared engine cache and master keys
    // =========================================================================
    println!("\n--- SNMPv3 with Shared Engine Cache ---\n");

    // For SNMPv3, target-to-engine identity mappings are cached to avoid
    // repeated discovery, while trusted time is shared by authoritative engine
    // ID. TTL expiry affects future cache lookups; a live client retains its
    // established identity until rediscover_engine() is called explicitly.
    let engine_cache = Arc::new(EngineCache::new());

    // Pre-compute master keys once. Password-to-key derivation is substantially
    // more expensive than per-engine localization, and these keys can be reused
    // across clients with the same credentials.
    let master_keys = MasterKeys::new(AuthProtocol::Sha256, b"authpass123")?
        .with_privacy(PrivProtocol::Aes192, b"privpass123")?;

    println!("Master keys derived (one-time cost)");
    println!("Engine cache created for sharing\n");

    let shared_v3 = UdpTransport::bind("0.0.0.0:0").await?;

    // Poll multiple OIDs using V3 with shared resources
    let v3_oids = [
        oid!(1, 3, 6, 1, 2, 1, 1, 1, 0), // sysDescr
        oid!(1, 3, 6, 1, 2, 1, 1, 3, 0), // sysUpTime
    ];

    // Uses container user: privaes192_user (SHA-256 + AES-192). Other clients
    // with these credentials can cheaply clone the master keys and engine cache.
    let auth = Auth::usm_builder("privaes192_user")
        .with_master_keys(master_keys.clone())
        .build();
    let client = Client::builder(container_target, auth)
        .response_shape_policy(ResponseShapePolicy::Strict)
        .request_timeout(Duration::from_secs(5))
        .retry(Retry::fixed(2, Duration::ZERO))
        .engine_cache(engine_cache.clone())
        .build_with(&shared_v3)
        .await?;

    for oid in &v3_oids {
        match client.get(oid).await {
            Ok(response) => println!("  {oid}: {:?}", response.varbinds[0].value),
            Err(e) => println!("  {oid}: {e}"),
        }
    }

    // =========================================================================
    // Example 4: Mixed reachable and unreachable targets
    // =========================================================================
    println!("\n--- Mixed Target Polling ---\n");

    // Demonstrates behavior when some targets are unreachable.
    // Uses TEST-NET-1 (192.0.2.0/24) for unreachable addresses.
    let targets: Vec<(&str, u16)> = vec![
        container_target,   // Reachable
        ("192.0.2.1", 161), // TEST-NET-1 (unreachable)
        ("192.0.2.2", 161), // TEST-NET-1 (unreachable)
    ];

    let shared = UdpTransport::bind("0.0.0.0:0").await?;

    let mut futures = FuturesUnordered::new();

    for target in &targets {
        let client = Client::builder(*target, Auth::v2c("public"))
            .response_shape_policy(ResponseShapePolicy::Strict)
            .request_timeout(Duration::from_millis(500))
            .retry(Retry::none())
            .build_with(&shared)
            .await?;

        futures.push(async move {
            let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;
            (client.peer_addr(), result)
        });
    }

    let mut success = 0;
    let mut timeout = 0;

    while let Some((addr, result)) = futures.next().await {
        match result {
            Ok(response) => {
                success += 1;
                println!("  {}: {:?}", addr, response.varbinds[0].value);
            }
            Err(e) => match *e {
                async_snmp::Error::Timeout { .. } => {
                    timeout += 1;
                    println!("  {addr}: timeout");
                }
                _ => println!("  {addr}: {e}"),
            },
        }
    }

    println!("\nResults: {success} success, {timeout} timeout");

    // Endpoint-level counters: correlated datagrams, expired request
    // registrations, discarded datagrams, and malformed datagrams.
    let stats = shared.stats();
    println!(
        "UDP stats: correlated={} expired={} discarded={} malformed={}",
        stats.correlated_datagrams,
        stats.expired_registrations,
        stats.discarded_datagrams,
        stats.malformed_datagrams
    );

    println!("\nExample complete!");
    Ok(())
}
