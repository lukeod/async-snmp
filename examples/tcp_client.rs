//! TCP Transport Example
//!
//! This example demonstrates using SNMP over TCP instead of UDP.
//! TCP transport is useful when:
//! - Large responses exceed UDP's 64KB limit
//! - Firewalls block UDP but allow TCP
//! - Reliable delivery is required without timeout retransmissions
//!
//! Key differences from UDP:
//! - Messages are framed using BER self-describing length
//! - No timeout retransmissions (TCP guarantees delivery or connection failure)
//! - SNMPv3 protocol correction remains available independently
//! - Connection-oriented (one TCP connection per target)
//! - Requests are serialized per connection
//!
//! Run with: cargo run --example tcp_client
//!
//! Uses the async-snmp test container (supports TCP on same port):
//!   docker build -t async-snmp-test:latest tests/containers/snmpd/
//!   docker run -d -p 11161:161/udp -p 11161:161/tcp async-snmp-test:latest

use async_snmp::{
    Auth, AuthProtocol, Client, ClientBuilder, PrivProtocol, ResponseShapePolicy, Retry,
    TcpTransport, Transport, oid,
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

    let target = ("127.0.0.1", 11161);

    // Use connect_tcp() instead of connect()
    let client = Client::builder(target, Auth::v2c("public"))
        .response_shape_policy(ResponseShapePolicy::Strict)
        .request_timeout(Duration::from_secs(10))
        // Timeout retries are ignored for TCP (is_reliable = true).
        // SNMPv3 protocol correction is a separate state transition.
        .retry(Retry::fixed(3, Duration::ZERO))
        .connect_tcp()
        .await?;

    println!("Connected to {} via TCP", client.peer_addr());

    // Perform GET request
    match client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await {
        Ok(response) => {
            println!("sysDescr: {:?}", response.varbinds[0].value);
        }
        Err(e) => {
            println!("GET failed: {e}");
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

            // Configure client policy independently of the preconstructed transport.
            let client = ClientBuilder::new(Auth::v2c("public"))
                .request_timeout(Duration::from_secs(10))
                .response_shape_policy(ResponseShapePolicy::Strict)
                .build_with_transport(transport)?;

            match client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 5, 0)).await {
                Ok(response) => println!("sysName: {:?}", response.varbinds[0].value),
                Err(e) => println!("GET failed: {e}"),
            }
        }
        Err(e) => {
            println!("TCP connection failed: {e}");
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

            let client = ClientBuilder::new(Auth::v2c("public"))
                .request_timeout(Duration::from_secs(10))
                .build_with_transport(transport)?;

            // Walk system subtree over TCP
            let walk = client.walk(oid!(1, 3, 6, 1, 2, 1, 1))?;
            let results: Vec<_> = walk.collect().await?;

            println!("Walk found {} OIDs", results.len());
            for vb in &results {
                println!("  {}: {:?}", vb.oid, vb.value);
            }
        }
        Err(e) => {
            println!("Connection failed: {e}");
        }
    }

    // =========================================================================
    // Example 4: SNMPv3 over TCP
    // =========================================================================
    println!("\n--- SNMPv3 over TCP ---\n");

    // Uses container user: privaes128_user (SHA + AES-128)
    let auth = Auth::usm_builder("privaes128_user")
        .auth_priv(
            AuthProtocol::Sha1,
            "authpass123",
            PrivProtocol::Aes128,
            "privpass123",
        )
        .build();

    match Client::builder(target, auth)
        .response_shape_policy(ResponseShapePolicy::Strict)
        .request_timeout(Duration::from_secs(15))
        .connect_tcp()
        .await
    {
        Ok(client) => {
            println!("SNMPv3 TCP client connected");

            match client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await {
                Ok(response) => println!("sysDescr: {:?}", response.varbinds[0].value),
                Err(e) => println!("GET failed: {e}"),
            }
        }
        Err(e) => {
            println!("SNMPv3 TCP connection failed: {e}");
        }
    }

    // =========================================================================
    // Example 5: Comparing UDP vs TCP behavior
    // =========================================================================
    println!("\n--- UDP vs TCP Comparison ---\n");

    // UDP client - retries on timeout
    let udp_client = Client::builder(target, Auth::v2c("public"))
        .response_shape_policy(ResponseShapePolicy::Strict)
        .request_timeout(Duration::from_secs(2))
        .retry(Retry::fixed(3, Duration::ZERO)) // Will retry up to 3 times on timeout
        .connect()
        .await;

    println!("UDP client:");
    println!("  Retries: 3 (configured)");
    println!("  Behavior: Retries on timeout\n");

    // TCP client - no timeout retransmissions
    let tcp_client = Client::builder(target, Auth::v2c("public"))
        .response_shape_policy(ResponseShapePolicy::Strict)
        .request_timeout(Duration::from_secs(2))
        .retry(Retry::fixed(3, Duration::ZERO)) // Ignored for TCP!
        .connect_tcp()
        .await;

    println!("TCP client:");
    println!("  Timeout retries: Ignored (is_reliable = true)");
    println!("  Behavior: Single transmission unless SNMPv3 protocol correction is needed");

    // Demonstrate both clients work the same way
    if let Ok(client) = udp_client {
        match client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 3, 0)).await {
            Ok(response) => println!("\nUDP sysUpTime: {:?}", response.varbinds[0].value),
            Err(e) => println!("\nUDP error: {e}"),
        }
    }

    if let Ok(client) = tcp_client {
        match client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 3, 0)).await {
            Ok(response) => println!("TCP sysUpTime: {:?}", response.varbinds[0].value),
            Err(e) => println!("TCP error: {e}"),
        }
    }

    println!("\nExample complete!");
    Ok(())
}
