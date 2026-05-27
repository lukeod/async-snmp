//! SNMP Notification Sender Example
//!
//! Demonstrates two approaches to sending SNMP traps and informs:
//!
//! 1. **Agent-based** (recommended for devices running an agent): trap sinks are
//!    configured on the agent builder; the agent sends to all sinks using its own
//!    socket, engine ID, and credentials. No persistent per-destination state.
//!
//! 2. **Client-based** (for standalone tools like snmptrap/snmpinform): a Client
//!    is created per destination, useful for one-shot sends.
//!
//! Run with: cargo run --example notification_sender

use async_snmp::agent::Agent;
use async_snmp::notification::{Notification, NotificationReceiver};
use async_snmp::varbind::VarBind;
use async_snmp::{Auth, AuthProtocol, Client, PrivProtocol, Value, oid};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("async_snmp=info".parse()?),
        )
        .init();

    // Start a local receiver so we can verify the notifications arrive.
    let engine_id = b"example-sender-engine".to_vec();
    let receiver = NotificationReceiver::builder()
        .bind("127.0.0.1:0")
        .engine_id(engine_id.clone())
        .usm_user("v3user", |u| {
            u.auth(AuthProtocol::Sha256, b"authpass12345678")
                .privacy(PrivProtocol::Aes128, b"privpass12345678")
        })
        .build()
        .await?;
    let recv_addr = receiver.local_addr();
    println!("Receiver listening on {recv_addr}\n");

    // Spawn receiver loop (expects 5 notifications total)
    let recv_handle = tokio::spawn(async move {
        for _ in 0..5 {
            match tokio::time::timeout(Duration::from_secs(5), receiver.recv()).await {
                Ok(Ok((notification, source))) => {
                    print_notification(&notification, source);
                }
                Ok(Err(e)) => eprintln!("Receive error: {e}"),
                Err(_) => eprintln!("Timeout waiting for notification"),
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(10)).await;

    // =========================================================================
    // Agent-based sending (recommended for embedded devices)
    // =========================================================================
    println!("=== Agent-based sending ===\n");

    let agent = Agent::builder()
        .bind("127.0.0.1:0")
        .community(b"public")
        .engine_id(engine_id.clone())
        .usm_user("v3user", |u| {
            u.auth(AuthProtocol::Sha256, b"authpass12345678")
                .privacy(PrivProtocol::Aes128, b"privpass12345678")
        })
        // Configure trap sinks - agent sends to all of them
        .trap_sink(recv_addr.to_string(), Auth::v2c("public"))
        .build()
        .await?;

    // Send v2c trap to all configured sinks
    println!("--- Agent: sending v2c trap ---");
    let cold_start = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1);
    agent.send_trap(&cold_start, 12345, vec![]).await?;
    println!("Sent v2c trap (coldStart)\n");

    // Send v2c inform to all configured sinks (waits for ack)
    println!("--- Agent: sending v2c inform ---");
    let warm_start = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 2);
    let extra = vec![VarBind::new(
        oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
        Value::from("example agent"),
    )];
    agent.send_inform(&warm_start, 5000, extra).await?;
    println!("Sent v2c inform (warmStart) - acknowledged\n");

    // =========================================================================
    // Client-based sending (for standalone tools)
    // =========================================================================
    println!("=== Client-based sending ===\n");

    // V2c trap via client
    println!("--- Client: sending v2c trap ---");
    let client = Client::builder(recv_addr.to_string(), Auth::v2c("public"))
        .connect()
        .await?;
    let link_down = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 3);
    client.send_trap(&link_down, 99999, vec![]).await?;
    println!("Sent v2c trap (linkDown)\n");

    // V3 trap via client (needs local_engine_id)
    println!("--- Client: sending v3 trap ---");
    let v3_client = Client::builder(
        recv_addr.to_string(),
        Auth::usm("v3user").auth(AuthProtocol::Sha256, "authpass12345678"),
    )
    .local_engine_id(engine_id)
    .connect()
    .await?;
    let link_up = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 4);
    v3_client.send_trap(&link_up, 100_000, vec![]).await?;
    println!("Sent v3 trap (linkUp, authNoPriv)\n");

    // V3 inform via client (uses engine discovery)
    println!("--- Client: sending v3 inform ---");
    let v3_priv_client = Client::builder(
        recv_addr.to_string(),
        Auth::usm("v3user")
            .auth(AuthProtocol::Sha256, "authpass12345678")
            .privacy(PrivProtocol::Aes128, "privpass12345678"),
    )
    .connect()
    .await?;
    let auth_failure = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 5);
    v3_priv_client
        .send_inform(&auth_failure, 200_000, vec![])
        .await?;
    println!("Sent v3 inform (authenticationFailure, authPriv) - acknowledged\n");

    recv_handle.await?;
    println!("Done!");
    Ok(())
}

fn print_notification(notification: &Notification, source: std::net::SocketAddr) {
    let trap_oid = notification.trap_oid().unwrap();
    println!(
        "  Received from {}: {:?} trap_oid={} uptime={} varbinds={}",
        source,
        notification.version(),
        trap_oid,
        notification.uptime(),
        notification.varbinds().len(),
    );
}
