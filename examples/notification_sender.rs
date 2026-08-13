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
//! Run with: cargo run --example notification_sender --features agent

use async_snmp::agent::{Agent, NotificationOutcome, SinkStatus};
use async_snmp::notification::{Notification, NotificationAcceptance, NotificationReceiver};
use async_snmp::v3::AuthoritativeEngine;
use async_snmp::varbind::VarBind;
use async_snmp::{
    Auth, AuthProtocol, Client, NotificationSinkId, PrivProtocol, SecurityLevel, Value, oid,
};
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
    // This example uses a no-op persistence callback. A deployed application
    // must store both fields durably and use AuthoritativeEngine::restart on
    // subsequent process starts. Concrete Error + Send + Sync callback failures
    // are preserved by AuthoritativeEnginePersistenceError.
    let engine =
        AuthoritativeEngine::install(engine_id, |_| Ok::<(), std::convert::Infallible>(()))?;
    let receiver = NotificationReceiver::builder()
        .bind("127.0.0.1:0")
        .authoritative_engine(engine.clone())
        .usm_user("v3user", |u| {
            u.auth_priv(
                AuthProtocol::Sha256,
                b"authpass12345678",
                PrivProtocol::Aes128,
                b"privpass12345678",
            )
        })
        // This local demo also receives cleartext v2c messages. For v3, require
        // authentication because configured keyed users also support spoofable
        // noAuthNoPriv input.
        .acceptance_policy(|notification| match notification.security_level {
            None => NotificationAcceptance::Accept,
            Some(level) if level >= SecurityLevel::AuthNoPriv => NotificationAcceptance::Accept,
            Some(_) => NotificationAcceptance::Reject,
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
        .authoritative_engine(engine.clone())
        .usm_user("v3user", |u| {
            u.auth_priv(
                AuthProtocol::Sha256,
                b"authpass12345678",
                PrivProtocol::Aes128,
                b"privpass12345678",
            )
        })
        // Configure trap sinks - agent sends to all of them
        .trap_sink(
            NotificationSinkId::new("local-receiver").unwrap(),
            recv_addr.to_string(),
            Auth::v2c("public"),
        )
        .allow_all_access()
        .build()
        .await?;

    // Send v2c trap to all configured sinks
    println!("--- Agent: sending v2c trap ---");
    let cold_start = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1);
    let outcome = agent.send_trap(&cold_start, 12345, vec![]).await;
    print_outcome("v2c trap (coldStart)", &outcome);

    // Send v2c inform and process each sink as its acknowledgement completes.
    println!("--- Agent: sending v2c inform ---");
    let warm_start = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 2);
    let extra = vec![VarBind::new(
        oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
        Value::from("example agent"),
    )];
    let mut completions = agent.send_inform_stream(&warm_start, 5000, extra);
    while let Some(sink) = completions.next().await {
        print_sink_outcome("v2c inform (warmStart)", &sink);
    }
    println!();

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

    // V3 trap via client (needs local authoritative engine state)
    println!("--- Client: sending v3 trap ---");
    let v3_client = Client::builder(
        recv_addr.to_string(),
        Auth::usm_builder("v3user")
            .auth(AuthProtocol::Sha256, "authpass12345678")
            .build(),
    )
    .local_authoritative_engine(engine)
    .connect()
    .await?;
    let link_up = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 4);
    v3_client.send_trap(&link_up, 100_000, vec![]).await?;
    println!("Sent v3 trap (linkUp, authNoPriv)\n");

    // V3 inform via client (uses engine discovery)
    println!("--- Client: sending v3 inform ---");
    let v3_priv_client = Client::builder(
        recv_addr.to_string(),
        Auth::usm_builder("v3user")
            .auth_priv(
                AuthProtocol::Sha256,
                "authpass12345678",
                PrivProtocol::Aes128,
                "privpass12345678",
            )
            .build(),
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

fn print_outcome(label: &str, outcome: &NotificationOutcome) {
    for sink in outcome.sinks() {
        print_sink_outcome(label, sink);
    }
    println!();
}

fn print_sink_outcome(label: &str, sink: &async_snmp::SinkOutcome) {
    match &sink.status {
        SinkStatus::Succeeded => println!(
            "{label}: {} ({}) succeeded",
            sink.sink.id(),
            sink.sink.dest()
        ),
        SinkStatus::Failed(error) => eprintln!(
            "{label}: {} ({}) failed: {error}",
            sink.sink.id(),
            sink.sink.dest()
        ),
        SinkStatus::Skipped(reason) => eprintln!(
            "{label}: {} ({}) skipped: {reason}",
            sink.sink.id(),
            sink.sink.dest()
        ),
    }
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
