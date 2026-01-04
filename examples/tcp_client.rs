//! TCP Transport Example
//!
//! This example demonstrates using SNMP over TCP instead of UDP.
//! TCP transport is useful when:
//! - Large responses exceed UDP's 64KB limit
//! - Firewalls block UDP but allow TCP
//! - Reliable delivery is required without retries
//!
//! Key differences from UDP:
//! - Messages are framed using BER self-describing length
//! - No retries (TCP guarantees delivery or connection failure)
//! - Connection-oriented (one TCP connection per target)
//! - Requests are serialized per connection
//!
//! Run with: cargo run --example tcp_client
//!
//! Uses the async-snmp test container (supports TCP on same port):
//!   docker build -t async-snmp-test:latest tests/containers/snmpd/
//!   docker run -d -p 11161:161/udp -p 11161:161/tcp async-snmp-test:latest

use async_snmp::{
    Auth, AuthProtocol, Client, ClientConfig, PrivProtocol, Retry, TcpTransport, Transport, oid,
};
use std::net::SocketAddr;
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

    // =========================================================================
    // Example 1: Basic TCP connection
    // =========================================================================
    println!("--- Basic TCP Client ---\n");

    let target = "127.0.0.1:11161";

    // Use connect_tcp() instead of connect()
    let client = Client::builder(target, Auth::v2c("public"))
        .timeout(Duration::from_secs(10))
        // Note: retries are ignored for TCP (is_reliable = true)
        .retry(Retry::fixed(3, Duration::ZERO))
        .connect_tcp()
        .await?;

    println!("Connected to {} via TCP", client.peer_addr());

    // Perform GET request
    match client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await {
        Ok(vb) => {
            println!("sysDescr: {:?}", vb.value);
        }
        Err(e) => {
            println!("GET failed: {}", e);
        }
    }

    // =========================================================================
    // Example 2: Manual TCP transport construction
    // =========================================================================
    println!("\n--- Manual TCP Transport ---\n");

    // Create TCP transport directly for more control
    let addr: SocketAddr = "127.0.0.1:11161".parse()?;

    match TcpTransport::connect(addr).await {
        Ok(transport) => {
            println!("TCP transport connected");
            println!("  Local:  {}", transport.local_addr());
            println!("  Remote: {}", transport.peer_addr());
            println!("  Reliable: {}", transport.is_reliable()); // Always true for TCP

            // Use Client::new for manual transport construction
            let config = ClientConfig {
                timeout: Duration::from_secs(10),
                ..Default::default()
            };
            let client = Client::new(transport, config);

            match client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 5, 0)).await {
                Ok(vb) => println!("sysName: {:?}", vb.value),
                Err(e) => println!("GET failed: {}", e),
            }
        }
        Err(e) => {
            println!("TCP connection failed: {}", e);
        }
    }

    // =========================================================================
    // Example 3: TCP with connection timeout
    // =========================================================================
    println!("\n--- TCP with Connection Timeout ---\n");

    let connect_timeout = Duration::from_secs(5);
    let addr: SocketAddr = "127.0.0.1:11161".parse()?;

    match TcpTransport::connect_timeout(addr, connect_timeout).await {
        Ok(transport) => {
            println!("Connected with {}s timeout", connect_timeout.as_secs());

            let config = ClientConfig {
                timeout: Duration::from_secs(10),
                ..Default::default()
            };
            let client = Client::new(transport, config);

            // Walk system subtree over TCP
            let walk = client.walk(oid!(1, 3, 6, 1, 2, 1, 1))?;
            let results: Vec<_> = walk.collect().await?;

            println!("Walk found {} OIDs", results.len());
            for vb in &results {
                println!("  {}: {:?}", vb.oid, vb.value);
            }
        }
        Err(e) => {
            println!("Connection failed: {}", e);
        }
    }

    // =========================================================================
    // Example 4: SNMPv3 over TCP
    // =========================================================================
    println!("\n--- SNMPv3 over TCP ---\n");

    // Uses container user: privaes128_user (SHA + AES-128)
    let auth = Auth::usm("privaes128_user")
        .auth(AuthProtocol::Sha1, "authpass123")
        .privacy(PrivProtocol::Aes128, "privpass123");

    match Client::builder(target, auth)
        .timeout(Duration::from_secs(15))
        .connect_tcp()
        .await
    {
        Ok(client) => {
            println!("SNMPv3 TCP client connected");

            match client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await {
                Ok(vb) => println!("sysDescr: {:?}", vb.value),
                Err(e) => println!("GET failed: {}", e),
            }
        }
        Err(e) => {
            println!("SNMPv3 TCP connection failed: {}", e);
        }
    }

    // =========================================================================
    // Example 5: Comparing UDP vs TCP behavior
    // =========================================================================
    println!("\n--- UDP vs TCP Comparison ---\n");

    // UDP client - retries on timeout
    let udp_client = Client::builder(target, Auth::v2c("public"))
        .timeout(Duration::from_secs(2))
        .retry(Retry::fixed(3, Duration::ZERO)) // Will retry up to 3 times on timeout
        .connect()
        .await;

    println!("UDP client:");
    println!("  Retries: 3 (configured)");
    println!("  Behavior: Retries on timeout\n");

    // TCP client - no retries
    let tcp_client = Client::builder(target, Auth::v2c("public"))
        .timeout(Duration::from_secs(2))
        .retry(Retry::fixed(3, Duration::ZERO)) // Ignored for TCP!
        .connect_tcp()
        .await;

    println!("TCP client:");
    println!("  Retries: Ignored (is_reliable = true)");
    println!("  Behavior: Single attempt, TCP guarantees delivery");

    // Demonstrate both clients work the same way
    if let Ok(client) = udp_client {
        match client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 3, 0)).await {
            Ok(vb) => println!("\nUDP sysUpTime: {:?}", vb.value),
            Err(e) => println!("\nUDP error: {}", e),
        }
    }

    if let Ok(client) = tcp_client {
        match client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 3, 0)).await {
            Ok(vb) => println!("TCP sysUpTime: {:?}", vb.value),
            Err(e) => println!("TCP error: {}", e),
        }
    }

    println!("\nExample complete!");
    Ok(())
}
