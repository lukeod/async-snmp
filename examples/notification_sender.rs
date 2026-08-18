//! Send SNMP notifications
//!
//! The library provides two ways to send SNMP traps and Inform requests:
//!
//! 1. Agent-based sending configures notification sinks on the agent builder.
//!    The agent sends through its own socket, engine ID, and credentials without
//!    retaining persistent per-destination state.
//!
//! 2. Client-based sending creates one `Client` per destination. This approach
//!    suits standalone tools such as `snmptrap` and `snmpinform`.
//!
//! Run `cargo run --example notification_sender --features agent`.

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

    // Start a local receiver to observe each notification.
    let engine_id = b"example-sender-engine".to_vec();
    // This example uses a no-op persistence callback. A deployed application
    // must store the engine state durably and call AuthoritativeEngine::restart
    // after later process starts. AuthoritativeEnginePersistenceError preserves
    // concrete Error + Send + Sync callback failures.
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
        .unwrap()
        // This local example also receives cleartext SNMPv2c messages. For
        // SNMPv3, require authentication because configured keyed users also
        // support spoofable noAuthNoPriv input.
        .acceptance_policy(|notification| match notification.security_level {
            None => NotificationAcceptance::Accept,
            Some(level) if level >= SecurityLevel::AuthNoPriv => NotificationAcceptance::Accept,
            Some(_) => NotificationAcceptance::Reject,
        })
        .build()
        .await?;
    let recv_addr = receiver.local_addr();
    println!("Receiver listening on {recv_addr}\n");

    // Spawn a receive loop for the five notifications sent below.
    let recv_handle = tokio::spawn(async move {
        for _ in 0..5 {
            match tokio::time::timeout(Duration::from_secs(5), receiver.recv()).await {
                Ok(Ok(received)) => {
                    print_notification(&received.notification, received.source);
                    if let Some(outcome) = received.inform_ack {
                        println!("  Inform acknowledgement: {outcome:?}");
                    }
                }
                Ok(Err(e)) => eprintln!("Receive error: {e}"),
                Err(_) => eprintln!("Timeout waiting for notification"),
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(10)).await;

    // =========================================================================
    // Agent-based sending for devices that run an agent
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
        .unwrap()
        // Configure a sink. The agent sends each notification to all sinks.
        .trap_sink(
            NotificationSinkId::new("local-receiver").unwrap(),
            recv_addr.to_string(),
            Auth::v2c("public"),
        )
        .allow_all_access()
        .build()
        .await?;

    // Send an SNMPv2c trap to all configured sinks.
    println!("--- Agent: sending SNMPv2c trap ---");
    let cold_start = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1);
    let outcome = agent.send_trap(&cold_start, 12345, vec![]).await;
    print_outcome("SNMPv2c trap (coldStart)", &outcome);

    // Send an SNMPv2c Inform and process each completed acknowledgement.
    println!("--- Agent: sending SNMPv2c Inform ---");
    let warm_start = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 2);
    let extra = vec![VarBind::new(
        oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
        Value::from("example agent"),
    )];
    let mut completions = agent.send_inform_stream(&warm_start, 5000, extra);
    while let Some(sink) = completions.next().await {
        print_sink_outcome("SNMPv2c Inform (warmStart)", &sink);
    }
    println!();

    // =========================================================================
    // Client-based sending for standalone tools
    // =========================================================================
    println!("=== Client-based sending ===\n");

    // Send an SNMPv2c trap through a client.
    println!("--- Client: sending SNMPv2c trap ---");
    let client = Client::builder(recv_addr.to_string(), Auth::v2c("public"))
        .connect()
        .await?;
    let link_down = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 3);
    client.send_trap(&link_down, 99999, vec![]).await?;
    println!("Sent SNMPv2c trap (linkDown)\n");

    // Send an SNMPv3 trap through a client with local authoritative state.
    println!("--- Client: sending SNMPv3 trap ---");
    let v3_client = Client::builder(
        recv_addr.to_string(),
        async_snmp::UsmConfig::new("v3user").auth(AuthProtocol::Sha256, "authpass12345678")?,
    )
    .local_authoritative_engine(engine)
    .connect()
    .await?;
    let link_up = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 4);
    v3_client.send_trap(&link_up, 100_000, vec![]).await?;
    println!("Sent SNMPv3 trap (linkUp, authNoPriv)\n");

    // Send an SNMPv3 Inform through a client that performs engine discovery.
    println!("--- Client: sending SNMPv3 Inform ---");
    let v3_priv_client = Client::builder(
        recv_addr.to_string(),
        async_snmp::UsmConfig::new("v3user").auth_priv(
            AuthProtocol::Sha256,
            "authpass12345678",
            PrivProtocol::Aes128,
            "privpass12345678",
        )?,
    )
    .connect()
    .await?;
    let auth_failure = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 5);
    v3_priv_client
        .send_inform(&auth_failure, 200_000, vec![])
        .await?;
    println!("Sent SNMPv3 Inform (authenticationFailure, authPriv) - acknowledged\n");

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
        "  Received from {}: {:?} trap_oid={} uptime={} variable_bindings={}",
        source,
        notification.version(),
        trap_oid,
        notification.uptime(),
        notification.varbinds().len(),
    );
}
