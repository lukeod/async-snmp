//! SNMP Notification Receiver Example
//!
//! This example demonstrates receiving SNMP notifications:
//! - TrapV1: SNMPv1 format traps
//! - TrapV2c/TrapV3: SNMPv2c and SNMPv3 traps
//! - InformRequest: Confirmed notifications (auto-response)
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
//!       -x AES -X privpass123 localhost:1162 '' SNMPv2-MIB::warmStart

use async_snmp::notification::{Notification, NotificationReceiver, oids};
use async_snmp::{AuthProtocol, PrivProtocol};
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
    println!("(use NotificationReceiver::builder() with usm_user to accept v3)\n");

    // =========================================================================
    // Example 2: Receiver with v3 authentication
    // =========================================================================
    println!("--- V3 Authenticated Receiver ---\n");

    let authenticated_receiver = NotificationReceiver::builder()
        .bind("0.0.0.0:1163")
        // Configure USM user for authenticated traps/informs
        .usm_user("trapuser", |u| {
            u.auth(AuthProtocol::Sha1, b"authpass123")
                .privacy(PrivProtocol::Aes128, b"privpass123")
        })
        // Can add multiple users
        .usm_user("readonly", |u| {
            u.auth(AuthProtocol::Sha256, b"readonlypass")
        })
        .build()
        .await?;

    println!(
        "V3 authenticated receiver on {}",
        authenticated_receiver.local_addr()
    );
    println!("Configured users: trapuser (authPriv), readonly (authNoPriv)\n");

    // =========================================================================
    // Example 3: Main receive loop
    // =========================================================================
    println!("--- Waiting for Notifications ---\n");
    println!("Send test traps with:");
    println!("  snmptrap -v 2c -c public localhost:1162 '' SNMPv2-MIB::coldStart");
    println!("  snmpinform -v 2c -c public localhost:1162 '' SNMPv2-MIB::warmStart\n");

    // Clone receiver for the loop (receivers are Arc internally)
    let receiver_clone = receiver.clone();

    // Spawn a task to receive notifications
    let handle = tokio::spawn(async move {
        loop {
            match receiver_clone.recv().await {
                Ok((notification, source)) => {
                    handle_notification(&notification, source);
                }
                Err(e) => {
                    eprintln!("Error receiving notification: {e}");
                }
            }
        }
    });

    // In a real application, you would handle shutdown gracefully
    // For this demo, we'll wait a bit then exit
    println!("Receiver running... (waiting 30 seconds for demo)\n");

    tokio::select! {
        _ = handle => {}
        () = tokio::time::sleep(std::time::Duration::from_secs(30)) => {
            println!("\nDemo timeout reached");
        }
    }

    println!("\nExample complete!");
    Ok(())
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
        Notification::TrapV1 { community, trap } => {
            println!("  Type: SNMPv1 Trap");
            println!("  Community: {}", String::from_utf8_lossy(community));
            println!("  Enterprise: {}", trap.enterprise);
            println!("  Generic Trap: {:?}", trap.generic_trap);
            println!("  Specific Trap: {}", trap.specific_trap);
            println!("  Agent Address: {:?}", trap.agent_addr);
        }

        Notification::TrapV2c {
            community,
            request_id,
            ..
        } => {
            println!("  Type: SNMPv2c Trap");
            println!("  Community: {}", String::from_utf8_lossy(community));
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
            println!("  Username: {}", String::from_utf8_lossy(username));
            println!("  Context Engine ID: {:?}", context_engine_id.as_ref());
            println!("  Context Name: {}", String::from_utf8_lossy(context_name));
            println!("  Request ID: {request_id}");
        }

        Notification::InformV2c {
            community,
            request_id,
            ..
        } => {
            println!("  Type: SNMPv2c Inform (response sent automatically)");
            println!("  Community: {}", String::from_utf8_lossy(community));
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
            println!("  Type: SNMPv3 Inform (response sent automatically)");
            println!("  Security Level: {security_level:?}");
            println!("  Username: {}", String::from_utf8_lossy(username));
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
