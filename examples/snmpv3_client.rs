//! SNMPv3 Client Example
//!
//! This example demonstrates SNMPv3 operations with authentication and privacy:
//! - authPriv security level (SHA-1 authentication + AES-128 encryption)
//! - Various security levels (noAuthNoPriv, authNoPriv, authPriv)
//! - Master key caching for high-throughput scenarios
//!
//! Run with: cargo run --example snmpv3_client
//!
//! Uses the async-snmp test container which has pre-configured users:
//!   docker build -t async-snmp-test:latest tests/containers/snmpd/
//!   docker run -d -p 11161:161/udp async-snmp-test:latest

use async_snmp::{Auth, AuthProtocol, Client, MasterKeys, PrivProtocol, oid};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for debug output
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("async_snmp=info".parse()?),
        )
        .init();

    let target = "127.0.0.1:11161";

    // =========================================================================
    // Example 1: authPriv (SHA-1 + AES-128) - Most secure
    // =========================================================================
    println!("--- SNMPv3 authPriv (SHA-1 + AES-128) ---\n");

    // Build authentication using the fluent builder API
    // Uses container user: privaes128_user (SHA + AES-128)
    let auth = Auth::usm("privaes128_user")
        .auth(AuthProtocol::Sha1, "authpass123")
        .privacy(PrivProtocol::Aes128, "privpass123");

    let client = Client::builder(target, auth)
        .timeout(Duration::from_secs(10))
        .retries(3)
        .connect()
        .await?;

    println!("Connected to {} with authPriv", client.peer_addr());

    // Perform a GET request
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await?;
    println!("sysDescr: {:?}\n", result.value);

    // =========================================================================
    // Example 2: authNoPriv (Authentication only, no encryption)
    // =========================================================================
    println!("--- SNMPv3 authNoPriv (SHA-256 only) ---\n");

    // Uses container user: authsha256_user (SHA-256 auth, no privacy)
    let auth_only = Auth::usm("authsha256_user").auth(AuthProtocol::Sha256, "authpass123");
    // Note: no .privacy() call

    let client_auth = Client::builder(target, auth_only)
        .timeout(Duration::from_secs(10))
        .connect()
        .await?;

    println!("Connected with authNoPriv");

    match client_auth.get(&oid!(1, 3, 6, 1, 2, 1, 1, 5, 0)).await {
        Ok(result) => println!("sysName: {:?}\n", result.value),
        Err(e) => println!("Error: {}\n", e),
    }

    // =========================================================================
    // Example 3: noAuthNoPriv (No security - use with caution!)
    // =========================================================================
    println!("--- SNMPv3 noAuthNoPriv ---\n");

    // Uses container user: noauth_user (no auth, no privacy)
    // Just specify username, no auth or privacy
    let no_auth = Auth::usm("noauth_user");

    let client_noauth = Client::builder(target, no_auth)
        .timeout(Duration::from_secs(10))
        .connect()
        .await?;

    println!("Connected with noAuthNoPriv");

    match client_noauth.get(&oid!(1, 3, 6, 1, 2, 1, 1, 3, 0)).await {
        Ok(result) => println!("sysUpTime: {:?}\n", result.value),
        Err(e) => println!("Error: {}\n", e),
    }

    // =========================================================================
    // Example 4: Master key caching for high-throughput polling
    // =========================================================================
    println!("--- Master Key Caching for High-Throughput ---\n");

    // For polling many devices with the same credentials, pre-compute master keys.
    // This avoids the expensive key derivation (~850us) on every connection.
    // Only the cheap localization (~1us) is done per engine.

    // Uses container user: privaes192_user (SHA-256 + AES-192)
    let master_keys = MasterKeys::new(AuthProtocol::Sha256, b"authpass123")
        .with_privacy(PrivProtocol::Aes192, b"privpass123");

    println!("Master keys derived once (expensive operation)");

    // Create multiple clients using the cached master keys
    // Note: These TEST-NET-1 addresses are for demonstration - they won't be reachable
    let targets = ["192.0.2.1:161", "192.0.2.2:161", "192.0.2.3:161"];

    for target_addr in &targets {
        // Clone master keys (cheap - just Arc increment)
        let auth = Auth::usm("privaes192_user").with_master_keys(master_keys.clone());

        // Each client reuses the master keys; only localization is performed
        match Client::builder(*target_addr, auth)
            .timeout(Duration::from_secs(2))
            .retries(1)
            .connect()
            .await
        {
            Ok(client) => {
                println!("Connected to {} (using cached master keys)", target_addr);
                // In a real scenario, you would poll OIDs here
                drop(client);
            }
            Err(e) => {
                // Expected to fail if hosts are not reachable
                println!("Could not connect to {}: {}", target_addr, e);
            }
        }
    }

    // =========================================================================
    // Example 5: Different authentication and privacy protocols
    // =========================================================================
    println!("\n--- Protocol Options ---\n");

    // Available authentication protocols:
    // - AuthProtocol::Md5      (legacy, not recommended)
    // - AuthProtocol::Sha1     (legacy)
    // - AuthProtocol::Sha224
    // - AuthProtocol::Sha256   (recommended)
    // - AuthProtocol::Sha384
    // - AuthProtocol::Sha512   (strongest)

    // Available privacy protocols:
    // - PrivProtocol::Des      (legacy, not recommended)
    // - PrivProtocol::Aes128   (recommended)
    // - PrivProtocol::Aes192
    // - PrivProtocol::Aes256   (strongest)

    let strong_auth = Auth::usm("admin")
        .auth(AuthProtocol::Sha512, "strongauthpass")
        .privacy(PrivProtocol::Aes256, "strongprivpass");

    println!("Created auth config: SHA-512 + AES-256");
    println!("Auth protocol: {:?}", AuthProtocol::Sha512);
    println!("Priv protocol: {:?}", PrivProtocol::Aes256);

    // Build but don't connect (just demonstrate configuration)
    let _builder = Client::builder(target, strong_auth).timeout(Duration::from_secs(10));

    // =========================================================================
    // Example 6: Context name for VACM
    // =========================================================================
    println!("\n--- Context Name (VACM) ---\n");

    // Some agents use context names for View-based Access Control (VACM)
    let auth_with_context = Auth::usm("snmpuser")
        .auth(AuthProtocol::Sha256, "authpass123")
        .privacy(PrivProtocol::Aes128, "privpass123")
        .context_name("vlan100");

    println!("Created auth config with context name 'vlan100'");

    let _builder = Client::builder(target, auth_with_context).timeout(Duration::from_secs(10));

    println!("\nExample complete!");
    Ok(())
}
