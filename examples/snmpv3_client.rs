//! Use an SNMPv3 client
//!
//! The client performs SNMPv3 operations at the noAuthNoPriv, authNoPriv, and
//! authPriv security levels. It also caches master keys when polling multiple
//! authoritative engines.
//!
//! Run `cargo run --example snmpv3_client`.
//!
//! To start the async-snmp test container with its preconfigured users, run:
//!
//! ```text
//! docker build -t async-snmp-test:latest tests/containers/snmpd/
//! docker run -d -p 11161:161/udp async-snmp-test:latest
//! ```

use async_snmp::{
    Auth, AuthProtocol, Client, MasterKeys, PrivProtocol, ResponseShapePolicy, Retry, oid,
};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for diagnostic output.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("async_snmp=info".parse()?),
        )
        .init();

    let target = ("127.0.0.1", 11161);

    // =========================================================================
    // Example 1: Legacy-compatible authPriv with SHA-1 and AES-128
    // =========================================================================
    println!("--- SNMPv3 authPriv (SHA-1 + AES-128) ---\n");

    // Configure the container's privaes128_user user with SHA-1 and AES-128.
    let auth = async_snmp::UsmConfig::new("privaes128_user").auth_priv(
        AuthProtocol::Sha1,
        "authpass123",
        PrivProtocol::Aes128,
        "privpass123",
    )?;

    let client = Client::builder(target, auth)
        .response_shape_policy(ResponseShapePolicy::Strict)
        .request_timeout(Duration::from_secs(10))
        .retry(Retry::fixed(3, Duration::ZERO).expect("valid retry count"))
        .connect()
        .await?;

    println!(
        "UDP client configured for {} with authPriv; the GET below tests reachability",
        client.peer_addr()
    );

    // Retrieve sysDescr.0.
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await?;
    println!(
        "sysDescr: {:?}\n",
        result
            .single()
            .expect("strict response policy returns a singleton")
            .value
    );

    // =========================================================================
    // Example 2: authNoPriv with authentication and no privacy
    // =========================================================================
    println!("--- SNMPv3 authNoPriv (SHA-256 only) ---\n");

    // Configure the container's authsha256_user user with SHA-256.
    let auth_only =
        async_snmp::UsmConfig::new("authsha256_user").auth(AuthProtocol::Sha256, "authpass123")?;
    // auth() selects authNoPriv.

    let client_auth = Client::builder(target, auth_only)
        .response_shape_policy(ResponseShapePolicy::Strict)
        .request_timeout(Duration::from_secs(10))
        .connect()
        .await?;

    println!("UDP authNoPriv client configured; the GET below tests reachability");

    match client_auth.get(&oid!(1, 3, 6, 1, 2, 1, 1, 5, 0)).await {
        Ok(result) => println!(
            "sysName: {:?}\n",
            result
                .single()
                .expect("strict response policy returns a singleton")
                .value
        ),
        Err(e) => println!("Error: {e}\n"),
    }

    // =========================================================================
    // Example 3: noAuthNoPriv without authentication or privacy
    // =========================================================================
    println!("--- SNMPv3 noAuthNoPriv ---\n");

    // Specify only the container's noauth_user username.
    let no_auth = Auth::usm("noauth_user");

    let client_noauth = Client::builder(target, no_auth)
        .response_shape_policy(ResponseShapePolicy::Strict)
        .request_timeout(Duration::from_secs(10))
        .connect()
        .await?;

    println!("UDP noAuthNoPriv client configured; the GET below tests reachability");

    match client_noauth.get(&oid!(1, 3, 6, 1, 2, 1, 1, 3, 0)).await {
        Ok(result) => println!(
            "sysUpTime: {:?}\n",
            result
                .single()
                .expect("strict response policy returns a singleton")
                .value
        ),
        Err(e) => println!("Error: {e}\n"),
    }

    // =========================================================================
    // Example 4: Master key caching for polling many engines
    // =========================================================================
    println!("--- Master key caching ---\n");

    // When polling many devices with the same credentials, precompute master
    // keys. This avoids repeating password-to-key derivation; only the much
    // cheaper per-engine localization remains for each target.

    // Uses container user: privaes192_user (SHA-256 + AES-192)
    let master_keys = MasterKeys::new(AuthProtocol::Sha256, b"authpass123")?
        .with_privacy(PrivProtocol::Aes192Blumenthal, b"privpass123")?;

    println!("Master keys derived once (expensive operation)");

    // Create clients that use the cached master keys. These TEST-NET-1
    // addresses demonstrate configuration only.
    // UDP `connect()` resolves/binds/configures a peer; it does not probe reachability.
    let targets = [("192.0.2.1", 161), ("192.0.2.2", 161), ("192.0.2.3", 161)];

    for target_addr in &targets {
        // Cloning copies only the small zeroizing key buffers and avoids
        // repeating password-to-key derivation.
        let auth =
            async_snmp::UsmConfig::new("privaes192_user").with_master_keys(master_keys.clone())?;

        // Each client reuses the master keys and performs only localization.
        match Client::builder(*target_addr, auth)
            .request_timeout(Duration::from_secs(2))
            .retry(Retry::fixed(1, Duration::ZERO).expect("valid retry count"))
            .connect()
            .await
        {
            Ok(client) => {
                println!(
                    "Configured UDP client for {} (using cached master keys)",
                    client.peer_addr()
                );
                // A polling application can issue requests through this client.
                drop(client);
            }
            Err(e) => {
                // This reports local resolution/bind/configuration failures, not
                // an agent reachability probe.
                println!(
                    "Could not configure client for {}:{}: {}",
                    target_addr.0, target_addr.1, e
                );
            }
        }
    }

    // =========================================================================
    // Example 5: Different authentication and privacy protocols
    // =========================================================================
    println!("\n--- Protocol options ---\n");

    // Supported authentication protocols:
    // - AuthProtocol::Md5      (legacy)
    // - AuthProtocol::Sha1     (legacy)
    // - AuthProtocol::Sha224
    // - AuthProtocol::Sha256
    // - AuthProtocol::Sha384
    // - AuthProtocol::Sha512

    // Supported privacy protocols:
    // - PrivProtocol::Des      (legacy)
    // - PrivProtocol::Des3     (legacy 3DES)
    // - PrivProtocol::Aes128   (RFC 3826)
    // - PrivProtocol::Aes192Blumenthal / Aes192Reeder (draft/vendor extensions)
    // - PrivProtocol::Aes256Blumenthal / Aes256Reeder (draft/vendor extensions)

    let strong_auth = async_snmp::UsmConfig::new("admin").auth_priv(
        AuthProtocol::Sha512,
        "strongauthpass",
        PrivProtocol::Aes256Blumenthal,
        "strongprivpass",
    )?;

    println!("Created auth config: SHA-512 + AES-256");
    println!("Auth protocol: {:?}", AuthProtocol::Sha512);
    println!("Priv protocol: {:?}", PrivProtocol::Aes256Blumenthal);

    // Create a builder without connecting.
    let _builder = Client::builder(target, strong_auth).request_timeout(Duration::from_secs(10));

    // =========================================================================
    // Example 6: Context name for VACM
    // =========================================================================
    println!("\n--- Context name (VACM) ---\n");

    // Some agents use context names for view-based access control (VACM).
    let auth_with_context = async_snmp::UsmConfig::new("snmpuser")
        .auth_priv(
            AuthProtocol::Sha256,
            "authpass123",
            PrivProtocol::Aes128,
            "privpass123",
        )?
        .context_name("vlan100");

    println!("Created auth config with context name 'vlan100'");

    let _builder =
        Client::builder(target, auth_with_context).request_timeout(Duration::from_secs(10));

    println!("\nExample complete!");
    Ok(())
}
