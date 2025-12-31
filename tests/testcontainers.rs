//! Integration tests using testcontainers.
//!
//! These tests use our custom `async-snmp-test` container image which provides full
//! SNMP protocol support including V2c SET, V3 SHA-2 auth, and AES-192/256 privacy.
//!
//! Requirements:
//!   - Docker running
//!   - Custom container image built locally:
//!     `docker build -t async-snmp-test:latest tests/containers/snmpd/`
//!
//! Container lifecycle:
//!   - A single container is shared across all tests in a run
//!   - Container is automatically cleaned up when tests complete (via atexit)
//!   - Stale containers from crashed runs are cleaned up at startup
//!
//! Environment variables:
//!   - SNMPD_IMAGE: Override the snmpd image (default: async-snmp-test:latest)
//!   - DOCKER_HOST: Override Docker socket location

mod common;

use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::Duration;

use async_snmp::{Auth, Client, SharedUdpTransport, Value, oid};
use common::{
    AUTH_PASSWORD, COMMUNITY_RW, PRIV_PASSWORD, collect_stream, parse_image, snmpd_image, users,
};
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
};
use tokio::sync::OnceCell;

// ============================================================================
// Container Runtime Detection
// ============================================================================

/// Check if Docker is available.
///
/// testcontainers-rs natively handles Docker socket detection via:
/// - `DOCKER_HOST` environment variable
/// - `/var/run/docker.sock` (standard Docker)
/// - `~/.docker/run/docker.sock`, `~/.docker/desktop/docker.sock` (rootless Docker)
fn is_docker_available() -> bool {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();

    *AVAILABLE.get_or_init(|| {
        // If DOCKER_HOST is set, assume Docker is available
        if std::env::var("DOCKER_HOST").is_ok() {
            return true;
        }

        // Check paths that testcontainers-rs will find natively
        let docker_paths = [
            "/var/run/docker.sock".to_string(),
            dirs::runtime_dir()
                .map(|d| format!("{}/.docker/run/docker.sock", d.display()))
                .unwrap_or_default(),
            dirs::home_dir()
                .map(|d| format!("{}/.docker/run/docker.sock", d.display()))
                .unwrap_or_default(),
            dirs::home_dir()
                .map(|d| format!("{}/.docker/desktop/docker.sock", d.display()))
                .unwrap_or_default(),
        ];

        docker_paths
            .iter()
            .any(|path| !path.is_empty() && std::path::Path::new(path).exists())
    })
}

/// Macro to skip test if Docker is not available
macro_rules! require_container_runtime {
    () => {
        if !is_docker_available() {
            eprintln!("Skipping test: Docker not available");
            return;
        }
    };
}

// ============================================================================
// Shared Container Infrastructure
// ============================================================================

/// Container info with host and port for connecting
struct ContainerInfo {
    _container: ContainerAsync<GenericImage>,
    host: String,
    port: u16,
}

/// Container name used for the test container.
const CONTAINER_NAME: &str = "async-snmp-test";

/// Shared container - reused across all tests within a single test run.
///
/// At startup, any existing container with this name is stopped and removed,
/// ensuring a clean state. The container is then shared across all tests
/// in this run for speed.
///
/// Our custom container (async-snmp-test) has all users pre-configured,
/// so a single container supports v2c, v3, and all security levels.
static SNMPD_CONTAINER: OnceCell<ContainerInfo> = OnceCell::const_new();

/// Stop and remove the test container.
fn cleanup_container() {
    let _ = std::process::Command::new("docker")
        .args(["stop", CONTAINER_NAME])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    let _ = std::process::Command::new("docker")
        .args(["rm", CONTAINER_NAME])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

/// Register cleanup to run when the process exits.
fn register_cleanup() {
    static REGISTERED: OnceLock<()> = OnceLock::new();
    REGISTERED.get_or_init(|| {
        extern "C" fn cleanup_on_exit() {
            cleanup_container();
        }
        // SAFETY: cleanup_on_exit is a valid C function that doesn't panic
        unsafe {
            libc::atexit(cleanup_on_exit);
        }
    });
}

/// Check if a container image exists locally.
/// Returns Ok(()) if the image exists, Err with a helpful message otherwise.
fn check_image_exists(image: &str) -> Result<(), String> {
    let output = std::process::Command::new("docker")
        .args(["image", "inspect", image])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    match output {
        Ok(status) if status.success() => Ok(()),
        _ => Err(format!(
            "Container image '{image}' not found locally.\n\n\
            Build it before running tests:\n\n    \
            docker build -t {image} tests/containers/snmpd/\n"
        )),
    }
}

async fn get_snmpd_container() -> &'static ContainerInfo {
    SNMPD_CONTAINER
        .get_or_init(|| async {
            // Clean up any stale container from previous (possibly crashed) runs
            cleanup_container();
            // Register cleanup to run when this process exits
            register_cleanup();

            let image_str = snmpd_image();
            let (name, tag) = parse_image(&image_str);

            // Check if image exists locally before trying to start.
            // This provides a fast, clear failure instead of waiting for pull timeout.
            if let Err(msg) = check_image_exists(&image_str) {
                panic!("{msg}");
            }

            let container = GenericImage::new(name, tag)
                .with_exposed_port(161.udp())
                .with_wait_for(WaitFor::seconds(2))
                .with_container_name(CONTAINER_NAME)
                .start()
                .await
                .expect("Failed to start snmpd container");

            let host = container.get_host().await.expect("Failed to get host");
            let port = container
                .get_host_port_ipv4(161.udp())
                .await
                .expect("Failed to get port");

            ContainerInfo {
                _container: container,
                host: host.to_string(),
                port,
            }
        })
        .await
}

// Backward compatibility aliases
async fn get_v2c_container() -> &'static ContainerInfo {
    get_snmpd_container().await
}

async fn get_v3_container() -> &'static ContainerInfo {
    get_snmpd_container().await
}

/// Create a v2c client connected to the shared container
async fn create_v2c_client() -> Client {
    let info = get_v2c_container().await;
    let target = format!("{}:{}", info.host, info.port);

    Client::builder(&target, Auth::v2c("public"))
        .timeout(Duration::from_secs(5))
        .retries(2)
        .connect()
        .await
        .expect("Failed to connect to SNMP agent")
}

// ============================================================================
// SNMPv2c Tests
// ============================================================================

#[tokio::test]
async fn test_get_sysdescr() {
    require_container_runtime!();

    let client = create_v2c_client().await;
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;

    match result {
        Ok(vb) => {
            println!("sysDescr: {:?}", vb.value);
            assert_eq!(vb.oid, oid!(1, 3, 6, 1, 2, 1, 1, 1, 0));
            assert!(matches!(vb.value, Value::OctetString(_)));
        }
        Err(e) => panic!("GET failed: {}", e),
    }
}

#[tokio::test]
async fn test_get_multiple() {
    require_container_runtime!();

    let client = create_v2c_client().await;
    let oids = [
        oid!(1, 3, 6, 1, 2, 1, 1, 1, 0), // sysDescr
        oid!(1, 3, 6, 1, 2, 1, 1, 3, 0), // sysUpTime
        oid!(1, 3, 6, 1, 2, 1, 1, 5, 0), // sysName
    ];

    let results = client.get_many(&oids).await.expect("GET failed");

    assert_eq!(results.len(), 3);
    println!("Got {} varbinds:", results.len());
    for (i, vb) in results.iter().enumerate() {
        println!("  {}: {:?}", vb.oid, vb.value);
        assert_eq!(vb.oid, oids[i], "OID mismatch at index {}", i);
    }
}

#[tokio::test]
async fn test_get_next() {
    require_container_runtime!();

    let client = create_v2c_client().await;
    let result = client.get_next(&oid!(1, 3, 6, 1, 2, 1, 1)).await;

    match result {
        Ok(vb) => {
            println!("Next OID: {}: {:?}", vb.oid, vb.value);
            // Should return something under system (1.3.6.1.2.1.1.*)
            assert!(vb.oid.starts_with(&oid!(1, 3, 6, 1, 2, 1, 1)));
            // GETNEXT should return lexicographically greater OID
            assert!(vb.oid > oid!(1, 3, 6, 1, 2, 1, 1));
        }
        Err(e) => panic!("GETNEXT failed: {}", e),
    }
}

#[tokio::test]
async fn test_get_bulk() {
    require_container_runtime!();

    let client = create_v2c_client().await;
    let results = client
        .get_bulk(&[oid!(1, 3, 6, 1, 2, 1, 1)], 0, 5)
        .await
        .expect("GETBULK failed");

    println!("GETBULK returned {} varbinds:", results.len());
    for vb in &results {
        println!("  {}: {:?}", vb.oid, vb.value);
    }

    assert!(!results.is_empty());
    assert!(results.len() <= 5);
}

#[tokio::test]
async fn test_walk_system() {
    require_container_runtime!();

    let client = create_v2c_client().await;
    let walk = client.walk(oid!(1, 3, 6, 1, 2, 1, 1));

    let mut pinned = Box::pin(walk);
    let results = collect_stream(pinned.as_mut(), 20).await;

    println!("Walk returned {} items:", results.len());
    let mut ok_count = 0;
    let mut prev_oid: Option<async_snmp::Oid> = None;
    for result in &results {
        match result {
            Ok(vb) => {
                println!("  {}: {:?}", vb.oid, vb.value);
                assert!(vb.oid.starts_with(&oid!(1, 3, 6, 1, 2, 1, 1)));
                // Verify lexicographic ordering
                if let Some(ref prev) = prev_oid {
                    assert!(
                        vb.oid > *prev,
                        "OIDs not in order: {} should be > {}",
                        vb.oid,
                        prev
                    );
                }
                prev_oid = Some(vb.oid.clone());
                ok_count += 1;
            }
            Err(e) => println!("  Error: {}", e),
        }
    }

    assert!(
        ok_count >= 5,
        "Expected at least 5 system OIDs, got {}",
        ok_count
    );
}

#[tokio::test]
async fn test_bulk_walk_system() {
    require_container_runtime!();

    let client = create_v2c_client().await;
    let walk = client.bulk_walk(oid!(1, 3, 6, 1, 2, 1, 1), 10);

    let mut pinned = Box::pin(walk);
    let results = collect_stream(pinned.as_mut(), 50).await;

    println!("BulkWalk returned {} items:", results.len());
    let mut ok_count = 0;
    for result in &results {
        match result {
            Ok(vb) => {
                println!("  {}: {:?}", vb.oid, vb.value);
                assert!(vb.oid.starts_with(&oid!(1, 3, 6, 1, 2, 1, 1)));
                ok_count += 1;
            }
            Err(e) => println!("  Error: {}", e),
        }
    }

    assert!(
        ok_count >= 5,
        "Expected at least 5 system OIDs, got {}",
        ok_count
    );
}

#[tokio::test]
async fn test_walk_interfaces() {
    require_container_runtime!();

    let client = create_v2c_client().await;
    let walk = client.bulk_walk(oid!(1, 3, 6, 1, 2, 1, 2), 25);

    let mut pinned = Box::pin(walk);
    let results = collect_stream(pinned.as_mut(), 100).await;

    println!("Interfaces walk returned {} items", results.len());

    let ok_count = results.iter().filter(|r| r.is_ok()).count();
    println!(
        "  {} successful, {} errors",
        ok_count,
        results.len() - ok_count
    );

    // Should have at least ifNumber and some interface entries
    assert!(ok_count >= 1);
}

#[tokio::test]
async fn test_nonexistent_oid() {
    require_container_runtime!();

    let client = create_v2c_client().await;
    let result = client.get(&oid!(1, 3, 6, 1, 99, 99, 99, 0)).await;

    match result {
        Ok(vb) => {
            println!("Result for nonexistent OID: {:?}", vb.value);
            assert!(
                matches!(vb.value, Value::NoSuchObject | Value::NoSuchInstance),
                "Expected NoSuchObject/NoSuchInstance, got {:?}",
                vb.value
            );
        }
        Err(e) => {
            // V1 agents may return NoSuchName error
            println!("Got error: {}", e);
            assert!(
                format!("{}", e).contains("NoSuchName")
                    || format!("{:?}", e).contains("NoSuchName"),
                "Unexpected error: {}",
                e
            );
        }
    }
}

#[tokio::test]
async fn test_get_many_batching() {
    require_container_runtime!();

    let info = get_v2c_container().await;
    let target = format!("{}:{}", info.host, info.port);

    // Create client with small max_oids_per_request to force batching
    let client = Client::builder(&target, Auth::v2c("public"))
        .timeout(Duration::from_secs(5))
        .retries(1)
        .max_oids_per_request(2) // Force batching at 2 OIDs
        .connect()
        .await
        .expect("Failed to connect to SNMP agent");

    // Request 5 OIDs - should trigger 3 batches (2, 2, 1)
    let oids = [
        oid!(1, 3, 6, 1, 2, 1, 1, 1, 0), // sysDescr
        oid!(1, 3, 6, 1, 2, 1, 1, 3, 0), // sysUpTime
        oid!(1, 3, 6, 1, 2, 1, 1, 4, 0), // sysContact
        oid!(1, 3, 6, 1, 2, 1, 1, 5, 0), // sysName
        oid!(1, 3, 6, 1, 2, 1, 1, 6, 0), // sysLocation
    ];

    let results = client.get_many(&oids).await.expect("GET_MANY failed");

    assert_eq!(
        results.len(),
        5,
        "Expected 5 results, got {}",
        results.len()
    );

    // Verify order matches input
    for (i, vb) in results.iter().enumerate() {
        assert_eq!(
            vb.oid, oids[i],
            "Result {} OID mismatch: expected {}, got {}",
            i, oids[i], vb.oid
        );
    }

    println!(
        "Batching test passed - got {} results in correct order",
        results.len()
    );
}

#[tokio::test]
async fn test_get_many_empty() {
    require_container_runtime!();

    let client = create_v2c_client().await;
    let results = client.get_many(&[]).await.expect("GET_MANY failed");
    assert!(results.is_empty(), "Expected empty results");
}

// ============================================================================
// Shared Transport Tests
// ============================================================================

#[tokio::test]
async fn test_shared_transport_single_client() {
    require_container_runtime!();

    let info = get_v2c_container().await;
    let target: SocketAddr = format!("127.0.0.1:{}", info.port).parse().unwrap();

    let shared = SharedUdpTransport::builder()
        .bind("0.0.0.0:0")
        .build()
        .await
        .expect("Failed to bind shared transport");

    let client = Client::builder(target.to_string(), Auth::v2c("public"))
        .timeout(Duration::from_secs(5))
        .retries(1)
        .build(shared.handle(target))
        .expect("Failed to build client");

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;
    match result {
        Ok(vb) => {
            println!("SharedTransport GET sysDescr: {:?}", vb.value);
            assert!(matches!(vb.value, Value::OctetString(_)));
        }
        Err(e) => panic!("SharedTransport GET failed: {}", e),
    }
}

#[tokio::test]
async fn test_shared_transport_multiple_clients() {
    require_container_runtime!();

    let info = get_v2c_container().await;
    let target: SocketAddr = format!("127.0.0.1:{}", info.port).parse().unwrap();

    let shared = SharedUdpTransport::builder()
        .bind("0.0.0.0:0")
        .build()
        .await
        .expect("Failed to bind shared transport");

    let client1 = Client::builder(target.to_string(), Auth::v2c("public"))
        .timeout(Duration::from_secs(5))
        .build(shared.handle(target))
        .expect("Failed to build client1");

    let client2 = Client::builder(target.to_string(), Auth::v2c("public"))
        .timeout(Duration::from_secs(5))
        .build(shared.handle(target))
        .expect("Failed to build client2");

    // Run concurrent requests
    let oid1 = oid!(1, 3, 6, 1, 2, 1, 1, 1, 0); // sysDescr
    let oid2 = oid!(1, 3, 6, 1, 2, 1, 1, 5, 0); // sysName
    let (result1, result2) = tokio::join!(client1.get(&oid1), client2.get(&oid2),);

    let vb1 = result1.expect("Client 1 GET failed");
    let vb2 = result2.expect("Client 2 GET failed");

    println!("Concurrent GET results:");
    println!("  sysDescr: {:?}", vb1.value);
    println!("  sysName: {:?}", vb2.value);

    assert!(matches!(vb1.value, Value::OctetString(_)));
    assert!(matches!(vb2.value, Value::OctetString(_)));
}

#[tokio::test]
async fn test_shared_transport_walk() {
    require_container_runtime!();

    let info = get_v2c_container().await;
    let target: SocketAddr = format!("127.0.0.1:{}", info.port).parse().unwrap();

    let shared = SharedUdpTransport::builder()
        .bind("0.0.0.0:0")
        .build()
        .await
        .expect("Failed to bind shared transport");

    let client = Client::builder(target.to_string(), Auth::v2c("public"))
        .timeout(Duration::from_secs(5))
        .build(shared.handle(target))
        .expect("Failed to build client");

    let walk = client.walk(oid!(1, 3, 6, 1, 2, 1, 1));
    let mut pinned = Box::pin(walk);
    let results = collect_stream(pinned.as_mut(), 20).await;

    let ok_count = results.iter().filter(|r| r.is_ok()).count();
    println!("SharedTransport walk returned {} items", ok_count);

    assert!(
        ok_count >= 5,
        "Expected at least 5 system OIDs, got {}",
        ok_count
    );
}

// ============================================================================
// SNMPv3 Tests
// ============================================================================

use async_snmp::{AuthProtocol, EngineCache, PrivProtocol};
use std::sync::Arc;

/// Create a v3 client with authPriv security level (SHA-1/AES-128)
/// Uses privaes128_user from our custom container.
async fn create_v3_client() -> Client {
    let info = get_v3_container().await;
    let target = format!("{}:{}", info.host, info.port);

    Client::builder(
        &target,
        Auth::usm(users::PRIVAES128_USER)
            .auth(AuthProtocol::Sha1, AUTH_PASSWORD)
            .privacy(PrivProtocol::Aes128, PRIV_PASSWORD),
    )
    .timeout(Duration::from_secs(5))
    .retries(1)
    .connect()
    .await
    .expect("Failed to connect V3 authPriv AES")
}

#[tokio::test]
async fn test_v3_auth_priv_aes() {
    require_container_runtime!();

    let client = create_v3_client().await;
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;

    match result {
        Ok(vb) => {
            println!("V3 authPriv (SHA1/AES128) GET sysDescr: {:?}", vb.value);
            assert!(matches!(vb.value, Value::OctetString(_)));
        }
        Err(e) => panic!("V3 GET failed: {}", e),
    }
}

#[tokio::test]
async fn test_v3_getbulk() {
    require_container_runtime!();

    let client = create_v3_client().await;
    let results = client
        .get_bulk(&[oid!(1, 3, 6, 1, 2, 1, 1)], 0, 5)
        .await
        .expect("V3 GETBULK failed");

    println!("V3 GETBULK returned {} varbinds:", results.len());
    for vb in &results {
        println!("  {}: {:?}", vb.oid, vb.value);
    }

    assert!(!results.is_empty());
}

#[tokio::test]
async fn test_v3_walk() {
    require_container_runtime!();

    let client = create_v3_client().await;
    let walk = client.walk(oid!(1, 3, 6, 1, 2, 1, 1));
    let mut pinned = Box::pin(walk);
    let results = collect_stream(pinned.as_mut(), 20).await;

    println!("V3 Walk returned {} items:", results.len());
    let mut ok_count = 0;
    for result in &results {
        match result {
            Ok(vb) => {
                println!("  {}: {:?}", vb.oid, vb.value);
                ok_count += 1;
            }
            Err(e) => println!("  Error: {}", e),
        }
    }

    assert!(
        ok_count >= 5,
        "Expected at least 5 system OIDs, got {}",
        ok_count
    );
}

#[tokio::test]
async fn test_v3_shared_engine_cache() {
    require_container_runtime!();

    let info = get_v3_container().await;
    let target = format!("{}:{}", info.host, info.port);

    // Create a shared engine cache
    let cache = Arc::new(EngineCache::new());

    // First client - will perform discovery
    let client1 = Client::builder(
        &target,
        Auth::usm(users::PRIVAES128_USER)
            .auth(AuthProtocol::Sha1, AUTH_PASSWORD)
            .privacy(PrivProtocol::Aes128, PRIV_PASSWORD),
    )
    .engine_cache(cache.clone())
    .timeout(Duration::from_secs(5))
    .retries(1)
    .connect()
    .await
    .expect("Failed to connect client 1");

    let result1 = client1.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;
    assert!(result1.is_ok(), "Client 1 GET failed: {:?}", result1);
    println!("Client 1 (with discovery): {:?}", result1.unwrap().value);

    // Second client - should use cached engine state
    let client2 = Client::builder(
        &target,
        Auth::usm(users::PRIVAES128_USER)
            .auth(AuthProtocol::Sha1, AUTH_PASSWORD)
            .privacy(PrivProtocol::Aes128, PRIV_PASSWORD),
    )
    .engine_cache(cache.clone())
    .timeout(Duration::from_secs(5))
    .retries(1)
    .connect()
    .await
    .expect("Failed to connect client 2");

    let result2 = client2.get(&oid!(1, 3, 6, 1, 2, 1, 1, 5, 0)).await;
    assert!(result2.is_ok(), "Client 2 GET failed: {:?}", result2);
    println!("Client 2 (from cache): {:?}", result2.unwrap().value);
}

// ============================================================================
// SNMPv3 Negative Security Tests
// ============================================================================

/// Test that wrong auth password is rejected by the agent.
///
/// The agent should return a Report PDU with usmStatsWrongDigests when the
/// HMAC doesn't match (wrong password), and our client should detect this
/// as an authentication failure.
#[tokio::test]
async fn test_v3_wrong_auth_password() {
    require_container_runtime!();

    let info = get_v3_container().await;
    let target = format!("{}:{}", info.host, info.port);

    // Use wrong auth password - should fail
    let result = Client::builder(
        &target,
        Auth::usm(users::PRIVAES128_USER)
            .auth(AuthProtocol::Sha1, "wrongpassword123")
            .privacy(PrivProtocol::Aes128, PRIV_PASSWORD),
    )
    .timeout(Duration::from_secs(3))
    .retries(0) // Don't retry on auth failure
    .connect()
    .await;

    match result {
        Ok(client) => {
            // Connection succeeded (discovery doesn't need auth), try a request
            let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;
            println!("Result with wrong auth password: {:?}", result);
            // Should fail with auth error or timeout (agent rejects our messages)
            assert!(
                result.is_err(),
                "Expected error with wrong auth password, got: {:?}",
                result
            );
            // The error should be auth-related or timeout
            let err = result.unwrap_err();
            let err_str = format!("{:?}", err);
            assert!(
                err_str.contains("Auth")
                    || err_str.contains("auth")
                    || err_str.contains("Hmac")
                    || err_str.contains("Timeout"),
                "Expected auth-related or timeout error, got: {}",
                err
            );
        }
        Err(e) => {
            // If connection itself fails due to auth, that's also valid
            println!("Connection failed with wrong auth password: {}", e);
        }
    }
}

/// Test that wrong privacy password is rejected.
///
/// The agent should be unable to decrypt our messages (or we unable to decrypt
/// the response) when using the wrong privacy password.
#[tokio::test]
async fn test_v3_wrong_priv_password() {
    require_container_runtime!();

    let info = get_v3_container().await;
    let target = format!("{}:{}", info.host, info.port);

    // Use correct auth but wrong priv password - should fail
    let result = Client::builder(
        &target,
        Auth::usm(users::PRIVAES128_USER)
            .auth(AuthProtocol::Sha1, AUTH_PASSWORD)
            .privacy(PrivProtocol::Aes128, "wrongprivpass99"),
    )
    .timeout(Duration::from_secs(3))
    .retries(0)
    .connect()
    .await;

    match result {
        Ok(client) => {
            let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;
            println!("Result with wrong priv password: {:?}", result);
            // Should fail - either decryption error or agent rejects
            assert!(
                result.is_err(),
                "Expected error with wrong priv password, got: {:?}",
                result
            );
            let err = result.unwrap_err();
            let err_str = format!("{:?}", err);
            // Could be decryption error, SNMP error (decryptionErrors), or timeout
            assert!(
                err_str.contains("Decrypt")
                    || err_str.contains("decrypt")
                    || err_str.contains("Timeout")
                    || err_str.contains("Snmp"),
                "Expected decrypt-related or timeout error, got: {}",
                err
            );
        }
        Err(e) => {
            println!("Connection failed with wrong priv password: {}", e);
        }
    }
}

/// Test that unknown username is rejected.
///
/// The agent should return a Report PDU with usmStatsUnknownUserNames.
#[tokio::test]
async fn test_v3_unknown_user() {
    require_container_runtime!();

    let info = get_v3_container().await;
    let target = format!("{}:{}", info.host, info.port);

    // Use non-existent username
    let result = Client::builder(
        &target,
        Auth::usm("nonexistentuser")
            .auth(AuthProtocol::Sha1, "somepassword123")
            .privacy(PrivProtocol::Aes128, "somepassword123"),
    )
    .timeout(Duration::from_secs(3))
    .retries(0)
    .connect()
    .await;

    match result {
        Ok(client) => {
            let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;
            println!("Result with unknown user: {:?}", result);
            // Should fail - agent doesn't know this user
            assert!(
                result.is_err(),
                "Expected error with unknown user, got: {:?}",
                result
            );
        }
        Err(e) => {
            // Connection failure due to unknown user is expected
            println!("Connection failed with unknown user: {}", e);
        }
    }
}

/// Test that wrong auth protocol fails.
///
/// If the agent expects SHA-1 but we use MD5 (or vice versa), authentication
/// should fail because the derived keys will be different.
#[tokio::test]
async fn test_v3_wrong_auth_protocol() {
    require_container_runtime!();

    let info = get_v3_container().await;
    let target = format!("{}:{}", info.host, info.port);

    // privaes128_user is configured with SHA-1, try with MD5
    let result = Client::builder(
        &target,
        Auth::usm(users::PRIVAES128_USER)
            .auth(AuthProtocol::Md5, AUTH_PASSWORD) // Wrong protocol
            .privacy(PrivProtocol::Aes128, PRIV_PASSWORD),
    )
    .timeout(Duration::from_secs(3))
    .retries(0)
    .connect()
    .await;

    match result {
        Ok(client) => {
            let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;
            println!("Result with wrong auth protocol: {:?}", result);
            // Should fail - HMAC will be wrong due to different key derivation
            assert!(
                result.is_err(),
                "Expected error with wrong auth protocol, got: {:?}",
                result
            );
        }
        Err(e) => {
            println!("Connection failed with wrong auth protocol: {}", e);
        }
    }
}

// ============================================================================
// SNMPv2c SET Operation Tests
// ============================================================================

/// Create a client for SET tests with write community.
/// Uses the shared container which supports rwcommunity "private".
async fn create_set_client() -> Client {
    let info = get_snmpd_container().await;
    let target = format!("{}:{}", info.host, info.port);

    Client::builder(
        &target,
        Auth::v2c(std::str::from_utf8(COMMUNITY_RW).unwrap()),
    )
    .timeout(Duration::from_secs(5))
    .retries(2)
    .connect()
    .await
    .expect("Failed to connect to SNMP agent for SET tests")
}

#[tokio::test]
async fn test_set_sys_contact() {
    require_container_runtime!();

    let client = create_set_client().await;
    let new_contact = Value::OctetString("admin@example.com".into());

    // SET sysContact
    let result = client
        .set(&oid!(1, 3, 6, 1, 2, 1, 1, 4, 0), new_contact.clone())
        .await;

    match result {
        Ok(vb) => {
            println!("SET sysContact result: {:?}", vb.value);
            assert_eq!(vb.oid, oid!(1, 3, 6, 1, 2, 1, 1, 4, 0));
            // Verify the value was set
            match &vb.value {
                Value::OctetString(s) => {
                    assert_eq!(s.as_ref(), b"admin@example.com");
                }
                _ => panic!("Expected OctetString, got {:?}", vb.value),
            }
        }
        Err(async_snmp::Error::Snmp { status, .. }) => {
            // NotWritable is acceptable if agent doesn't allow writes
            println!("SET rejected with SNMP error: {:?}", status);
        }
        Err(e) => panic!("SET failed unexpectedly: {}", e),
    }

    // Verify with GET
    let get_result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 4, 0)).await;
    println!("GET sysContact after SET: {:?}", get_result);
}

#[tokio::test]
async fn test_set_sys_name() {
    require_container_runtime!();

    let client = create_set_client().await;
    let new_name = Value::OctetString("test-device.local".into());

    // SET sysName
    let result = client
        .set(&oid!(1, 3, 6, 1, 2, 1, 1, 5, 0), new_name.clone())
        .await;

    match result {
        Ok(vb) => {
            println!("SET sysName result: {:?}", vb.value);
            assert_eq!(vb.oid, oid!(1, 3, 6, 1, 2, 1, 1, 5, 0));
        }
        Err(async_snmp::Error::Snmp { status, .. }) => {
            println!("SET rejected with SNMP error: {:?}", status);
        }
        Err(e) => panic!("SET failed unexpectedly: {}", e),
    }
}

#[tokio::test]
async fn test_set_sys_location() {
    require_container_runtime!();

    let client = create_set_client().await;
    let new_location = Value::OctetString("Server Room A, Rack 42".into());

    // SET sysLocation
    let result = client
        .set(&oid!(1, 3, 6, 1, 2, 1, 1, 6, 0), new_location.clone())
        .await;

    match result {
        Ok(vb) => {
            println!("SET sysLocation result: {:?}", vb.value);
            assert_eq!(vb.oid, oid!(1, 3, 6, 1, 2, 1, 1, 6, 0));
        }
        Err(async_snmp::Error::Snmp { status, .. }) => {
            println!("SET rejected with SNMP error: {:?}", status);
        }
        Err(e) => panic!("SET failed unexpectedly: {}", e),
    }
}

#[tokio::test]
async fn test_set_readonly_oid_rejected() {
    require_container_runtime!();

    let client = create_set_client().await;

    // Try to SET sysDescr which is read-only per RFC
    let result = client
        .set(
            &oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
            Value::OctetString("Hacked!".into()),
        )
        .await;

    // Should fail with NotWritable or similar error
    match result {
        Ok(vb) => {
            // Some agents may silently accept the SET but not apply it
            println!("SET returned: {:?} (may not have been applied)", vb.value);
        }
        Err(async_snmp::Error::Snmp { status, .. }) => {
            println!("SET correctly rejected with: {:?}", status);
            // NotWritable, NoAccess, or similar is expected
            assert!(
                matches!(
                    status,
                    async_snmp::ErrorStatus::NotWritable
                        | async_snmp::ErrorStatus::NoAccess
                        | async_snmp::ErrorStatus::ReadOnly
                        | async_snmp::ErrorStatus::NoSuchName
                ),
                "Expected NotWritable/NoAccess/ReadOnly error, got {:?}",
                status
            );
        }
        Err(e) => panic!("SET failed with unexpected error: {}", e),
    }
}

// ============================================================================
// GETBULK Edge Case Tests
// ============================================================================

#[tokio::test]
async fn test_getbulk_max_repetitions_zero() {
    require_container_runtime!();

    let client = create_v2c_client().await;

    // max_repetitions=0 should return no repeating variables
    let results = client
        .get_bulk(&[oid!(1, 3, 6, 1, 2, 1, 1)], 0, 0)
        .await
        .expect("GETBULK with max_repetitions=0 failed");

    println!(
        "GETBULK max_repetitions=0 returned {} varbinds",
        results.len()
    );
    // Should return empty or minimal results
    assert!(
        results.len() <= 1,
        "Expected at most 1 varbind with max_repetitions=0, got {}",
        results.len()
    );
}

#[tokio::test]
async fn test_getbulk_large_max_repetitions() {
    require_container_runtime!();

    let client = create_v2c_client().await;

    // Large max_repetitions - agent may truncate response
    let results = client
        .get_bulk(&[oid!(1, 3, 6, 1, 2, 1, 1)], 0, 100)
        .await
        .expect("GETBULK with large max_repetitions failed");

    println!(
        "GETBULK max_repetitions=100 returned {} varbinds",
        results.len()
    );
    // Should return something reasonable, agent will limit to available data
    assert!(!results.is_empty());
}

#[tokio::test]
async fn test_getbulk_non_repeaters_only() {
    require_container_runtime!();

    let client = create_v2c_client().await;

    // non_repeaters = 2, max_repetitions = 0 means just get 2 OIDs, no repetition
    let results = client
        .get_bulk(
            &[
                oid!(1, 3, 6, 1, 2, 1, 1, 1), // sysDescr branch
                oid!(1, 3, 6, 1, 2, 1, 1, 3), // sysUpTime branch
            ],
            2, // non_repeaters: treat first 2 as non-repeating
            0, // max_repetitions: no repeating variables
        )
        .await
        .expect("GETBULK with non_repeaters only failed");

    println!(
        "GETBULK non_repeaters only returned {} varbinds",
        results.len()
    );
    for vb in &results {
        println!("  {}: {:?}", vb.oid, vb.value);
    }
    // Should return exactly 2 GETNEXT results (one per non-repeater)
    assert_eq!(results.len(), 2, "Expected 2 varbinds for 2 non-repeaters");
}

#[tokio::test]
async fn test_getbulk_mixed_non_repeaters_and_repeaters() {
    require_container_runtime!();

    let client = create_v2c_client().await;

    // First OID is non-repeating, second is repeating
    let results = client
        .get_bulk(
            &[
                oid!(1, 3, 6, 1, 2, 1, 1, 1), // non-repeater
                oid!(1, 3, 6, 1, 2, 1, 1, 3), // repeater
            ],
            1, // non_repeaters: first OID only
            3, // max_repetitions: repeat second OID 3 times
        )
        .await
        .expect("GETBULK mixed failed");

    println!("GETBULK mixed returned {} varbinds:", results.len());
    for vb in &results {
        println!("  {}: {:?}", vb.oid, vb.value);
    }
    // Should return 1 non-repeater + up to 3 repetitions = up to 4 varbinds
    assert!(!results.is_empty(), "Expected at least 1 varbind");
    assert!(
        results.len() <= 4,
        "Expected at most 4 varbinds, got {}",
        results.len()
    );
}

#[tokio::test]
async fn test_getbulk_non_repeaters_exceeds_varbind_count() {
    require_container_runtime!();

    let client = create_v2c_client().await;

    // non_repeaters > number of OIDs - should treat all as non-repeating
    let results = client
        .get_bulk(
            &[oid!(1, 3, 6, 1, 2, 1, 1, 1)],
            10, // non_repeaters > 1 OID
            5,  // max_repetitions (should be ignored)
        )
        .await
        .expect("GETBULK with high non_repeaters failed");

    println!(
        "GETBULK high non_repeaters returned {} varbinds",
        results.len()
    );
    // Should return just 1 GETNEXT result
    assert_eq!(
        results.len(),
        1,
        "Expected 1 varbind when non_repeaters >= varbind count"
    );
}

// ============================================================================
// SNMPv3 noAuthNoPriv Tests
// ============================================================================

#[tokio::test]
async fn test_v3_noauthnopriv_get() {
    require_container_runtime!();

    let info = get_snmpd_container().await;
    let target = format!("{}:{}", info.host, info.port);

    // noAuthNoPriv user - no authentication or privacy
    let client = Client::builder(&target, Auth::usm(users::NOAUTH_USER))
        .timeout(Duration::from_secs(5))
        .retries(1)
        .connect()
        .await
        .expect("Failed to connect V3 noAuthNoPriv");

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;

    match result {
        Ok(vb) => {
            println!("V3 noAuthNoPriv GET sysDescr: {:?}", vb.value);
            assert!(matches!(vb.value, Value::OctetString(_)));
        }
        Err(e) => panic!("V3 noAuthNoPriv GET failed: {}", e),
    }
}

#[tokio::test]
async fn test_v3_noauthnopriv_walk() {
    require_container_runtime!();

    let info = get_snmpd_container().await;
    let target = format!("{}:{}", info.host, info.port);

    let client = Client::builder(&target, Auth::usm(users::NOAUTH_USER))
        .timeout(Duration::from_secs(5))
        .retries(1)
        .connect()
        .await
        .expect("Failed to connect V3 noAuthNoPriv");

    let walk = client.walk(oid!(1, 3, 6, 1, 2, 1, 1));
    let mut pinned = Box::pin(walk);
    let results = collect_stream(pinned.as_mut(), 20).await;

    println!("V3 noAuthNoPriv Walk returned {} items", results.len());
    let ok_count = results.iter().filter(|r| r.is_ok()).count();
    assert!(
        ok_count >= 5,
        "Expected at least 5 system OIDs, got {}",
        ok_count
    );
}

// ============================================================================
// SNMPv3 SHA-2 Authentication Tests (RFC 7860)
// ============================================================================

#[tokio::test]
async fn test_v3_auth_sha224() {
    require_container_runtime!();

    let info = get_snmpd_container().await;
    let target = format!("{}:{}", info.host, info.port);

    let client = Client::builder(
        &target,
        Auth::usm(users::AUTHSHA224_USER).auth(AuthProtocol::Sha224, AUTH_PASSWORD),
    )
    .timeout(Duration::from_secs(5))
    .retries(1)
    .connect()
    .await
    .expect("Failed to connect V3 SHA-224");

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;

    match result {
        Ok(vb) => {
            println!("V3 authNoPriv (SHA-224) GET sysDescr: {:?}", vb.value);
            assert!(matches!(vb.value, Value::OctetString(_)));
        }
        Err(e) => panic!("V3 SHA-224 GET failed: {}", e),
    }
}

#[tokio::test]
async fn test_v3_auth_sha256() {
    require_container_runtime!();

    let info = get_snmpd_container().await;
    let target = format!("{}:{}", info.host, info.port);

    let client = Client::builder(
        &target,
        Auth::usm(users::AUTHSHA256_USER).auth(AuthProtocol::Sha256, AUTH_PASSWORD),
    )
    .timeout(Duration::from_secs(5))
    .retries(1)
    .connect()
    .await
    .expect("Failed to connect V3 SHA-256");

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;

    match result {
        Ok(vb) => {
            println!("V3 authNoPriv (SHA-256) GET sysDescr: {:?}", vb.value);
            assert!(matches!(vb.value, Value::OctetString(_)));
        }
        Err(e) => panic!("V3 SHA-256 GET failed: {}", e),
    }
}

#[tokio::test]
async fn test_v3_auth_sha384() {
    require_container_runtime!();

    let info = get_snmpd_container().await;
    let target = format!("{}:{}", info.host, info.port);

    let client = Client::builder(
        &target,
        Auth::usm(users::AUTHSHA384_USER).auth(AuthProtocol::Sha384, AUTH_PASSWORD),
    )
    .timeout(Duration::from_secs(5))
    .retries(1)
    .connect()
    .await
    .expect("Failed to connect V3 SHA-384");

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;

    match result {
        Ok(vb) => {
            println!("V3 authNoPriv (SHA-384) GET sysDescr: {:?}", vb.value);
            assert!(matches!(vb.value, Value::OctetString(_)));
        }
        Err(e) => panic!("V3 SHA-384 GET failed: {}", e),
    }
}

#[tokio::test]
async fn test_v3_auth_sha512() {
    require_container_runtime!();

    let info = get_snmpd_container().await;
    let target = format!("{}:{}", info.host, info.port);

    let client = Client::builder(
        &target,
        Auth::usm(users::AUTHSHA512_USER).auth(AuthProtocol::Sha512, AUTH_PASSWORD),
    )
    .timeout(Duration::from_secs(5))
    .retries(1)
    .connect()
    .await
    .expect("Failed to connect V3 SHA-512");

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;

    match result {
        Ok(vb) => {
            println!("V3 authNoPriv (SHA-512) GET sysDescr: {:?}", vb.value);
            assert!(matches!(vb.value, Value::OctetString(_)));
        }
        Err(e) => panic!("V3 SHA-512 GET failed: {}", e),
    }
}

#[tokio::test]
async fn test_v3_auth_md5() {
    require_container_runtime!();

    let info = get_snmpd_container().await;
    let target = format!("{}:{}", info.host, info.port);

    let client = Client::builder(
        &target,
        Auth::usm(users::AUTHMD5_USER).auth(AuthProtocol::Md5, AUTH_PASSWORD),
    )
    .timeout(Duration::from_secs(5))
    .retries(1)
    .connect()
    .await
    .expect("Failed to connect V3 MD5");

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;

    match result {
        Ok(vb) => {
            println!("V3 authNoPriv (MD5) GET sysDescr: {:?}", vb.value);
            assert!(matches!(vb.value, Value::OctetString(_)));
        }
        Err(e) => panic!("V3 MD5 GET failed: {}", e),
    }
}

// ============================================================================
// SNMPv3 AES-192/256 Privacy Tests (Blumenthal)
// ============================================================================

#[tokio::test]
async fn test_v3_priv_aes192() {
    require_container_runtime!();

    let info = get_snmpd_container().await;
    let target = format!("{}:{}", info.host, info.port);

    // AES-192 user uses SHA-256 auth per container config
    let client = Client::builder(
        &target,
        Auth::usm(users::PRIVAES192_USER)
            .auth(AuthProtocol::Sha256, AUTH_PASSWORD)
            .privacy(PrivProtocol::Aes192, PRIV_PASSWORD),
    )
    .timeout(Duration::from_secs(5))
    .retries(1)
    .connect()
    .await
    .expect("Failed to connect V3 AES-192");

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;

    match result {
        Ok(vb) => {
            println!("V3 authPriv (SHA-256/AES-192) GET sysDescr: {:?}", vb.value);
            assert!(matches!(vb.value, Value::OctetString(_)));
        }
        Err(e) => panic!("V3 AES-192 GET failed: {}", e),
    }
}

#[tokio::test]
async fn test_v3_priv_aes256() {
    require_container_runtime!();

    let info = get_snmpd_container().await;
    let target = format!("{}:{}", info.host, info.port);

    // AES-256 user uses SHA-256 auth per container config
    let client = Client::builder(
        &target,
        Auth::usm(users::PRIVAES256_USER)
            .auth(AuthProtocol::Sha256, AUTH_PASSWORD)
            .privacy(PrivProtocol::Aes256, PRIV_PASSWORD),
    )
    .timeout(Duration::from_secs(5))
    .retries(1)
    .connect()
    .await
    .expect("Failed to connect V3 AES-256");

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;

    match result {
        Ok(vb) => {
            println!("V3 authPriv (SHA-256/AES-256) GET sysDescr: {:?}", vb.value);
            assert!(matches!(vb.value, Value::OctetString(_)));
        }
        Err(e) => panic!("V3 AES-256 GET failed: {}", e),
    }
}

#[tokio::test]
async fn test_v3_priv_des() {
    require_container_runtime!();

    let info = get_snmpd_container().await;
    let target = format!("{}:{}", info.host, info.port);

    // DES user uses SHA-1 auth per container config
    let client = Client::builder(
        &target,
        Auth::usm(users::PRIVDES_USER)
            .auth(AuthProtocol::Sha1, AUTH_PASSWORD)
            .privacy(PrivProtocol::Des, PRIV_PASSWORD),
    )
    .timeout(Duration::from_secs(5))
    .retries(1)
    .connect()
    .await
    .expect("Failed to connect V3 DES");

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;

    match result {
        Ok(vb) => {
            println!("V3 authPriv (SHA-1/DES) GET sysDescr: {:?}", vb.value);
            assert!(matches!(vb.value, Value::OctetString(_)));
        }
        Err(e) => panic!("V3 DES GET failed: {}", e),
    }
}

#[tokio::test]
async fn test_v3_priv_aes192_walk() {
    require_container_runtime!();

    let info = get_snmpd_container().await;
    let target = format!("{}:{}", info.host, info.port);

    let client = Client::builder(
        &target,
        Auth::usm(users::PRIVAES192_USER)
            .auth(AuthProtocol::Sha256, AUTH_PASSWORD)
            .privacy(PrivProtocol::Aes192, PRIV_PASSWORD),
    )
    .timeout(Duration::from_secs(5))
    .retries(1)
    .connect()
    .await
    .expect("Failed to connect V3 AES-192");

    let walk = client.walk(oid!(1, 3, 6, 1, 2, 1, 1));
    let mut pinned = Box::pin(walk);
    let results = collect_stream(pinned.as_mut(), 20).await;

    println!("V3 AES-192 Walk returned {} items", results.len());
    let ok_count = results.iter().filter(|r| r.is_ok()).count();
    assert!(
        ok_count >= 5,
        "Expected at least 5 system OIDs, got {}",
        ok_count
    );
}

#[tokio::test]
async fn test_v3_priv_aes256_walk() {
    require_container_runtime!();

    let info = get_snmpd_container().await;
    let target = format!("{}:{}", info.host, info.port);

    let client = Client::builder(
        &target,
        Auth::usm(users::PRIVAES256_USER)
            .auth(AuthProtocol::Sha256, AUTH_PASSWORD)
            .privacy(PrivProtocol::Aes256, PRIV_PASSWORD),
    )
    .timeout(Duration::from_secs(5))
    .retries(1)
    .connect()
    .await
    .expect("Failed to connect V3 AES-256");

    let walk = client.walk(oid!(1, 3, 6, 1, 2, 1, 1));
    let mut pinned = Box::pin(walk);
    let results = collect_stream(pinned.as_mut(), 20).await;

    println!("V3 AES-256 Walk returned {} items", results.len());
    let ok_count = results.iter().filter(|r| r.is_ok()).count();
    assert!(
        ok_count >= 5,
        "Expected at least 5 system OIDs, got {}",
        ok_count
    );
}
