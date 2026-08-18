//! Receive SNMP notifications
//!
//! This example receives SNMPv1, SNMPv2c, and SNMPv3 traps and confirmed
//! Inform requests. The receiver attempts an Inform response before it delivers
//! the notification to the application.
//!
//! SNMPv1 and SNMPv2c communities and content use cleartext. Without a configured
//! community allowlist they are unverified; an allowlist adds no message
//! integrity. SNMPv3 usernames, contexts, and content are authenticated only at
//! authNoPriv/authPriv and are spoofable at noAuthNoPriv.
//!
//! Run `cargo run --example notification_receiver`.
//!
//! To send test notifications with net-snmp, run:
//!
//! ```text
//! snmptrap -v 2c -c public localhost:1162 '' SNMPv2-MIB::coldStart
//! snmpinform -v 2c -c public localhost:1162 '' SNMPv2-MIB::coldStart
//! snmptrap -v 3 -u trapuser -l authPriv -a SHA -A authpass123 \
//!     -x AES -X privpass123 localhost:1163 '' SNMPv2-MIB::warmStart
//! ```

use async_snmp::notification::{
    Notification, NotificationAcceptance, NotificationEnvelope, NotificationReceiver, oids,
};
use async_snmp::{AuthProtocol, AuthoritativeEngine, PrivProtocol, SecurityLevel};
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("async_snmp=debug".parse()?),
        )
        .init();

    // =========================================================================
    // Example 1: Simple SNMPv2c receiver
    // =========================================================================
    println!("--- Simple notification receiver ---\n");

    // Bind to unprivileged port 1162 instead of the standard port 162.
    let receiver = NotificationReceiver::bind("0.0.0.0:1162").await?;

    println!("Listening for notifications on {}", receiver.local_addr());
    println!("This receiver handles SNMPv1 and SNMPv2c only; SNMPv3 notifications are rejected");
    println!(
        "(use NotificationReceiver::builder() with authoritative_engine and usm_user to accept SNMPv3)\n"
    );

    // =========================================================================
    // Example 2: Receiver with SNMPv3 authentication
    // =========================================================================
    println!("--- Authenticated SNMPv3 receiver ---\n");

    // A receiver with USM users is authoritative for SNMPv3 Inform exchanges
    // and requires stable engine ID and engine boots state. This example uses a
    // no-op persistence callback. A deployed application must store both fields
    // durably and call AuthoritativeEngine::restart after later process starts.
    // Storage errors must implement Error + Send + Sync and remain downcastable
    // through AuthoritativeEnginePersistenceError.
    let engine = AuthoritativeEngine::install(b"example-receiver-engine".to_vec(), |_| {
        Ok::<(), std::convert::Infallible>(())
    })?;
    let authenticated_receiver = NotificationReceiver::builder()
        .bind("0.0.0.0:1163")
        .authoritative_engine(engine)
        // Configure authentication and privacy capabilities. A keyed user also
        // supports noAuthNoPriv, so the policy below enforces the minimum.
        .usm_user("trapuser", |u| {
            u.auth_priv(
                AuthProtocol::Sha1,
                b"authpass123",
                PrivProtocol::Aes128,
                b"privpass123",
            )
        })?
        // Add a second USM user.
        .usm_user("readonly", |u| {
            u.auth(AuthProtocol::Sha256, b"readonlypass")
        })?
        // This synchronous policy runs after applicable USM processing and
        // notification-prefix validation, but before any Inform response. It
        // can inspect all normalized content; keep it bounded and non-blocking.
        .acceptance_policy(|notification: &NotificationEnvelope<'_>| {
            if notification.security_level >= Some(SecurityLevel::AuthNoPriv)
                && notification
                    .trap_oid()
                    .is_ok_and(|oid| oid.starts_with(&oids::snmp_traps()))
            {
                NotificationAcceptance::Accept
            } else {
                NotificationAcceptance::Reject
            }
        })
        .build()
        .await?;

    println!(
        "SNMPv3 authenticated receiver on {}",
        authenticated_receiver.local_addr()
    );
    println!("Configured users: trapuser (authPriv), readonly (authNoPriv)\n");

    // =========================================================================
    // Example 3: Receiver with community filtering
    // =========================================================================
    println!("--- Community-filtered receiver ---\n");

    // Communities use cleartext and provide no message integrity. Filtering is
    // opt-in. After you configure one or more communities, the receiver drops
    // SNMPv1 and SNMPv2c notifications that do not match them and does not
    // acknowledge dropped Inform requests. Comparison is constant-time. The
    // filter does not affect SNMPv3, which USM controls.
    let filtered_receiver = NotificationReceiver::builder()
        .bind("0.0.0.0:1164")
        .communities(["public", "monitor"])
        .build()
        .await?;

    println!(
        "Community-filtered receiver on {} (accepts: public, monitor)\n",
        filtered_receiver.local_addr()
    );

    // =========================================================================
    // Example 4: Main receive loop
    // =========================================================================
    println!("--- Waiting for notifications ---\n");
    println!("Send test traps with:");
    println!("  snmptrap -v 2c -c public localhost:1162 '' SNMPv2-MIB::coldStart");
    println!("  snmpinform -v 2c -c public localhost:1162 '' SNMPv2-MIB::warmStart");
    println!("  snmptrap -v 3 -u trapuser -l authPriv -a SHA -A authpass123 \\");
    println!("      -x AES -X privpass123 localhost:1163 '' SNMPv2-MIB::warmStart\n");

    // Each receiver has its own socket, so run one receive loop per port. An
    // application can instead combine community filters, authoritative state,
    // and USM users on one receiver.
    let handles = [
        spawn_receiver("SNMPv1/SNMPv2c", receiver),
        spawn_receiver("SNMPv3", authenticated_receiver),
        spawn_receiver("filtered", filtered_receiver),
    ];

    // Wait 30 seconds, then stop each receive task.
    println!("Receiver running... (waiting 30 seconds for demo)\n");

    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    println!("\nDemo timeout reached");
    for handle in handles {
        handle.abort();
    }

    println!("\nExample complete!");
    Ok(())
}

fn spawn_receiver(
    label: &'static str,
    receiver: NotificationReceiver,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match receiver.recv().await {
                Ok(received) => {
                    println!("[{label} receiver]");
                    handle_notification(&received.notification, received.source);
                    if let Some(outcome) = received.inform_ack {
                        println!("  Inform acknowledgement: {outcome:?}");
                    }
                }
                Err(e) => eprintln!("{label} receive error: {e}"),
            }
        }
    })
}

/// Prints common and version-specific fields from a received notification.
fn handle_notification(notification: &Notification, source: SocketAddr) {
    println!("=== Notification from {source} ===");

    // Print fields that all notification types provide.
    println!("  Version: {:?}", notification.version());
    println!("  Confirmed: {}", notification.is_confirmed());
    let trap_oid = match notification.trap_oid() {
        Ok(oid) => oid,
        Err(err) => {
            println!("  Trap OID: <invalid: {err}>");
            return;
        }
    };

    println!("  Trap OID: {trap_oid}");
    println!("  Uptime: {} centiseconds", notification.uptime());

    // Identify selected standard notification types.
    let trap_name = if trap_oid == oids::cold_start() {
        "coldStart"
    } else if trap_oid == oids::warm_start() {
        "warmStart"
    } else if trap_oid == oids::link_down() {
        "linkDown"
    } else if trap_oid == oids::link_up() {
        "linkUp"
    } else if trap_oid == oids::auth_failure() {
        "authenticationFailure"
    } else {
        "enterprise-specific"
    };
    println!("  Trap type: {trap_name}");

    // Print fields that depend on the SNMP version.
    match notification {
        Notification::TrapV1 {
            community, trap, ..
        } => {
            println!("  Type: SNMPv1 Trap");
            println!(
                "  Community: {}",
                String::from_utf8_lossy(community.as_bytes())
            );
            println!("  Enterprise: {}", trap.enterprise());
            println!("  Generic trap: {:?}", trap.generic_trap());
            println!("  Specific trap: {}", trap.specific_trap());
            println!("  Agent address: {:?}", trap.agent_addr());
        }

        Notification::TrapV2c {
            community,
            request_id,
            ..
        } => {
            println!("  Type: SNMPv2c Trap");
            println!(
                "  Community: {}",
                String::from_utf8_lossy(community.as_bytes())
            );
            println!("  Request ID: {request_id}");
        }

        Notification::TrapV3 {
            username,
            context_engine_id,
            context_name,
            security_level,
            request_id,
            ..
        } => {
            println!("  Type: SNMPv3 Trap");
            println!("  Security level: {security_level:?}");
            println!("  Username: {username:?}");
            println!("  Context engine ID: {:?}", context_engine_id.as_ref());
            println!("  Context name: {}", String::from_utf8_lossy(context_name));
            println!("  Request ID: {request_id}");
        }

        Notification::InformV2c {
            community,
            request_id,
            ..
        } => {
            println!("  Type: SNMPv2c Inform (response attempted before delivery)");
            println!(
                "  Community: {}",
                String::from_utf8_lossy(community.as_bytes())
            );
            println!("  Request ID: {request_id}");
        }

        Notification::InformV3 {
            username,
            context_engine_id,
            context_name,
            security_level,
            request_id,
            ..
        } => {
            println!("  Type: SNMPv3 Inform (response attempted before delivery)");
            println!("  Security level: {security_level:?}");
            println!("  Username: {username:?}");
            println!("  Context engine ID: {:?}", context_engine_id.as_ref());
            println!("  Context name: {}", String::from_utf8_lossy(context_name));
            println!("  Request ID: {request_id}");
        }
    }

    // Print the notification's variable bindings.
    let varbinds = notification.varbinds();
    if !varbinds.is_empty() {
        println!("  Variable bindings ({}):", varbinds.len());
        for vb in varbinds {
            println!("    {}: {:?}", vb.oid, vb.value);
        }
    }

    println!();
}
