//! Use SNMP over TCP
//!
//! TCP transport can support large messages and networks that do not pass UDP.
//! It also avoids application-level retransmission after a response timeout.
//!
//! Compared with UDP, TCP transport:
//!
//! - frames messages with their BER-encoded lengths;
//! - does not retransmit requests after a response timeout;
//! - can still perform independent SNMPv3 protocol correction;
//! - uses one connection per target; and
//! - serializes requests on each connection.
//!
//! Run `cargo run --example tcp_client`.
//!
//! To start the async-snmp test container with UDP and TCP listeners, run:
//!
//! ```text
//! docker build -t async-snmp-test:latest tests/containers/snmpd/
//! docker run -d -p 11161:161/udp -p 11161:161/tcp async-snmp-test:latest
//! ```

use async_snmp::{
    Auth, AuthProtocol, Client, ClientBuilder, PrivProtocol, ResponseShapePolicy, Retry,
    TcpTransport, Transport, oid,
};
use std::net::SocketAddr;
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

    // =========================================================================
    // Example 1: Basic TCP connection
    // =========================================================================
    println!("--- Basic TCP client ---\n");

    let target = ("127.0.0.1", 11161);

    // Use connect_tcp() to create a TCP client.
    let client = Client::builder(target, Auth::v2c("public"))
        .response_shape_policy(ResponseShapePolicy::Strict)
        .request_timeout(Duration::from_secs(10))
        // Timeout retries are ignored for TCP (is_reliable = true).
        // SNMPv3 protocol correction is a separate state transition.
        .retry(Retry::fixed(3, Duration::ZERO).expect("valid retry count"))
        .connect_tcp()
        .await?;

    println!("Connected to {} via TCP", client.peer_addr());

    // Retrieve sysDescr.0.
    match client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await {
        Ok(response) => {
            println!(
                "sysDescr: {:?}",
                response
                    .single()
                    .expect("strict response policy returns a singleton")
                    .value
            );
        }
        Err(e) => {
            println!("GET failed: {e}");
        }
    }

    // =========================================================================
    // Example 2: Manual TCP transport construction
    // =========================================================================
    println!("\n--- Manual TCP transport ---\n");

    // Construct a TCP transport before creating the client.
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
                Ok(response) => println!(
                    "sysName: {:?}",
                    response
                        .single()
                        .expect("strict response policy returns a singleton")
                        .value
                ),
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
    println!("\n--- TCP with a connection timeout ---\n");

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
    let auth = async_snmp::UsmConfig::new("privaes128_user").auth_priv(
        AuthProtocol::Sha1,
        "authpass123",
        PrivProtocol::Aes128,
        "privpass123",
    )?;

    match Client::builder(target, auth)
        .response_shape_policy(ResponseShapePolicy::Strict)
        .request_timeout(Duration::from_secs(15))
        .connect_tcp()
        .await
    {
        Ok(client) => {
            println!("SNMPv3 TCP client connected");

            match client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await {
                Ok(response) => println!(
                    "sysDescr: {:?}",
                    response
                        .single()
                        .expect("strict response policy returns a singleton")
                        .value
                ),
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
    println!("\n--- UDP and TCP comparison ---\n");

    // Configure a UDP client to retry after response timeouts.
    let udp_client = Client::builder(target, Auth::v2c("public"))
        .response_shape_policy(ResponseShapePolicy::Strict)
        .request_timeout(Duration::from_secs(2))
        // Retry up to three times after a timeout.
        .retry(Retry::fixed(3, Duration::ZERO).expect("valid retry count"))
        .connect()
        .await;

    println!("UDP client:");
    println!("  Retries: 3 (configured)");
    println!("  Behavior: Retries on timeout\n");

    // Configure the same retry policy on TCP. TCP ignores timeout retries.
    let tcp_client = Client::builder(target, Auth::v2c("public"))
        .response_shape_policy(ResponseShapePolicy::Strict)
        .request_timeout(Duration::from_secs(2))
        .retry(Retry::fixed(3, Duration::ZERO).expect("valid retry count")) // Ignored for TCP.
        .connect_tcp()
        .await;

    println!("TCP client:");
    println!("  Timeout retries: Ignored (is_reliable = true)");
    println!("  Behavior: Single transmission unless SNMPv3 protocol correction is needed");

    // Use the same client operation with each transport.
    if let Ok(client) = udp_client {
        match client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 3, 0)).await {
            Ok(response) => println!(
                "\nUDP sysUpTime: {:?}",
                response
                    .single()
                    .expect("strict response policy returns a singleton")
                    .value
            ),
            Err(e) => println!("\nUDP error: {e}"),
        }
    }

    if let Ok(client) = tcp_client {
        match client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 3, 0)).await {
            Ok(response) => println!(
                "TCP sysUpTime: {:?}",
                response
                    .single()
                    .expect("strict response policy returns a singleton")
                    .value
            ),
            Err(e) => println!("TCP error: {e}"),
        }
    }

    println!("\nExample complete!");
    Ok(())
}
