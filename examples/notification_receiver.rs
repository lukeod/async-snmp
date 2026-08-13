//! SNMP Notification Receiver Example
//!
//! This example demonstrates receiving SNMP notifications:
//! - TrapV1: SNMPv1 format traps
//! - TrapV2c/TrapV3: SNMPv2c and SNMPv3 traps
//! - InformRequest: Confirmed notifications (response attempted before delivery)
//!
//! V1/v2c communities and content are cleartext. Without a configured
//! community allowlist they are unverified; an allowlist adds no message
//! integrity. V3 username, context, and content are authenticated only at
//! authNoPriv/authPriv and are spoofable at noAuthNoPriv.
//!
//! Run with: cargo run --example notification_receiver
//!
//! Test with net-snmp:
//!   # v2c trap
//!   snmptrap -v 2c -c public localhost:1162 '' SNMPv2-MIB::coldStart
//!
//!   # v2c inform
//!   snmpinform -v 2c -c public localhost:1162 '' SNMPv2-MIB::coldStart
//!
//!   # v3 trap
//!   snmptrap -v 3 -u trapuser -l authPriv -a SHA -A authpass123 \
//!       -x AES -X privpass123 localhost:1163 '' SNMPv2-MIB::warmStart

use async_snmp::notification::{
    Notification, NotificationAcceptance, NotificationEnvelope, NotificationReceiver, oids,
};
use async_snmp::{AuthProtocol, AuthoritativeEngine, PrivProtocol, SecurityLevel};
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("async_snmp=debug".parse()?),
        )
        .init();

    // =========================================================================
    // Example 1: Simple v2c receiver
    // =========================================================================
    println!("--- Simple Notification Receiver ---\n");

    // Bind to port 1162 (unprivileged alternative to 162)
    // Use port 162 in production (requires root/admin)
    let receiver = NotificationReceiver::bind("0.0.0.0:1162").await?;

    println!("Listening for notifications on {}", receiver.local_addr());
    println!("This receiver handles v1 and v2c only; v3 notifications are rejected");
    println!(
        "(use NotificationReceiver::builder() with authoritative_engine and usm_user to accept v3)\n"
    );

    // =========================================================================
    // Example 2: Receiver with v3 authentication
    // =========================================================================
    println!("--- V3 Authenticated Receiver ---\n");

    // A receiver with USM users is authoritative for V3 Inform exchanges and
    // needs stable engine ID/boots state. This no-op callback is suitable only
    // for the example; deployed applications must store both fields durably
    // and call AuthoritativeEngine::restart on later process starts. Storage
    // errors must implement Error + Send + Sync and remain downcastable through
    // AuthoritativeEnginePersistenceError.
    let engine = AuthoritativeEngine::install(b"example-receiver-engine".to_vec(), |_| {
        Ok::<(), std::convert::Infallible>(())
    })?;
    let authenticated_receiver = NotificationReceiver::builder()
        .bind("0.0.0.0:1163")
        .authoritative_engine(engine)
        // Configure authentication/privacy capabilities. A keyed user also
        // supports noAuthNoPriv, so the policy below enforces the minimum.
        .usm_user("trapuser", |u| {
            u.auth_priv(
                AuthProtocol::Sha1,
                b"authpass123",
                PrivProtocol::Aes128,
                b"privpass123",
            )
        })
        // Can add multiple users
        .usm_user("readonly", |u| {
            u.auth(AuthProtocol::Sha256, b"readonlypass")
        })
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
        "V3 authenticated receiver on {}",
        authenticated_receiver.local_addr()
    );
    println!("Configured users: trapuser (authPriv), readonly (authNoPriv)\n");

    // =========================================================================
    // Example 3: Receiver with community filtering
    // =========================================================================
    println!("--- Community-Filtered Receiver ---\n");

    // Communities are cleartext and provide no message integrity. Filtering is
    // opt-in. Once one or more communities are
    // configured, v1/v2c notifications whose community matches none of them
    // are dropped (a dropped inform is not acknowledged). Comparison is
    // constant-time. This does not affect v3, which is gated by USM.
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
    println!("--- Waiting for Notifications ---\n");
    println!("Send test traps with:");
    println!("  snmptrap -v 2c -c public localhost:1162 '' SNMPv2-MIB::coldStart");
    println!("  snmpinform -v 2c -c public localhost:1162 '' SNMPv2-MIB::warmStart");
    println!("  snmptrap -v 3 -u trapuser -l authPriv -a SHA -A authpass123 \\");
    println!("      -x AES -X privpass123 localhost:1163 '' SNMPv2-MIB::warmStart\n");

    // Each configured receiver has its own socket, so run one receive loop per
    // port. A production application could instead combine community filters,
    // authoritative state, and USM users on one receiver.
    let handles = [
        spawn_receiver("v1/v2c", receiver),
        spawn_receiver("v3", authenticated_receiver),
        spawn_receiver("filtered", filtered_receiver),
    ];

    // In a real application, you would handle shutdown gracefully
    // For this demo, we'll wait a bit then exit
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
                Ok((notification, source)) => {
                    println!("[{label} receiver]");
                    handle_notification(&notification, source);
                }
                Err(e) => eprintln!("{label} receive error: {e}"),
            }
        }
    })
}

/// Handle a received notification.
///
/// This demonstrates extracting useful information from different notification types.
fn handle_notification(notification: &Notification, source: SocketAddr) {
    println!("=== Notification from {source} ===");

    // Common fields available on all notification types
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

    // Identify well-known trap types
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
    println!("  Trap Type: {trap_name}");

    // Version-specific handling
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
            println!("  Generic Trap: {:?}", trap.generic_trap());
            println!("  Specific Trap: {}", trap.specific_trap());
            println!("  Agent Address: {:?}", trap.agent_addr());
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
            println!("  Security Level: {security_level:?}");
            println!("  Username: {username:?}");
            println!("  Context Engine ID: {:?}", context_engine_id.as_ref());
            println!("  Context Name: {}", String::from_utf8_lossy(context_name));
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
            println!("  Security Level: {security_level:?}");
            println!("  Username: {username:?}");
            println!("  Context Engine ID: {:?}", context_engine_id.as_ref());
            println!("  Context Name: {}", String::from_utf8_lossy(context_name));
            println!("  Request ID: {request_id}");
        }
    }

    // Print varbinds
    let varbinds = notification.varbinds();
    if !varbinds.is_empty() {
        println!("  Varbinds ({}):", varbinds.len());
        for vb in varbinds {
            println!("    {}: {:?}", vb.oid, vb.value);
        }
    }

    println!();
}
