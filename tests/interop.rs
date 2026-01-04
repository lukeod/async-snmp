//! Container-based interoperability tests.
//!
//! These tests verify Client works correctly against net-snmp,
//! serving as the firewall against correlated bugs where both
//! Client and Agent might have the same flaw.
//!
//! Run with: cargo test --test interop

use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::Duration;

use async_snmp::{Auth, AuthProtocol, Client, PrivProtocol, Retry, UdpTransport, Value, oid};
use testcontainers::{
    ContainerAsync, GenericImage,
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
};
use tokio::sync::OnceCell;

// ============================================================================
// Container Runtime Detection
// ============================================================================

/// Check if Docker is available.
fn is_docker_available() -> bool {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();

    *AVAILABLE.get_or_init(|| {
        if std::env::var("DOCKER_HOST").is_ok() {
            return true;
        }

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

struct ContainerInfo {
    _container: ContainerAsync<GenericImage>,
    host: String,
    udp_port: u16,
    tcp_port: u16,
}

static SNMPD_CONTAINER: OnceCell<ContainerInfo> = OnceCell::const_new();

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

fn snmpd_image() -> String {
    std::env::var("SNMPD_IMAGE").unwrap_or_else(|_| "async-snmp-test:latest".to_string())
}

fn parse_image(image: &str) -> (&str, &str) {
    if let Some(idx) = image.rfind(':') {
        let after_colon = &image[idx + 1..];
        if !after_colon.contains('/') {
            return (&image[..idx], after_colon);
        }
    }
    (image, "latest")
}

async fn get_snmpd_container() -> &'static ContainerInfo {
    SNMPD_CONTAINER
        .get_or_init(|| async {
            let image_str = snmpd_image();
            let (name, tag) = parse_image(&image_str);

            if let Err(msg) = check_image_exists(&image_str) {
                panic!("{msg}");
            }

            // Use log-based waiting: entrypoint.sh outputs "SNMPD_READY" when snmpd is responsive
            let container = GenericImage::new(name, tag)
                .with_exposed_port(161.udp())
                .with_exposed_port(161.tcp())
                .with_wait_for(WaitFor::message_on_stdout("SNMPD_READY"))
                .start()
                .await
                .expect("Failed to start snmpd container");

            let host = container.get_host().await.expect("Failed to get host");
            let udp_port = container
                .get_host_port_ipv4(161.udp())
                .await
                .expect("Failed to get UDP port");
            let tcp_port = container
                .get_host_port_ipv4(161.tcp())
                .await
                .expect("Failed to get TCP port");

            ContainerInfo {
                _container: container,
                host: host.to_string(),
                udp_port,
                tcp_port,
            }
        })
        .await
}

fn parse_target(info: &ContainerInfo) -> SocketAddr {
    use std::net::ToSocketAddrs;
    format!("{}:{}", info.host, info.udp_port)
        .to_socket_addrs()
        .expect("Failed to resolve target")
        .next()
        .expect("No addresses resolved")
}

// ============================================================================
// Test credentials (must match container configuration)
// ============================================================================

const COMMUNITY: &str = "public";
const AUTH_PASS: &str = "authpass123";
const PRIV_PASS: &str = "privpass123";

mod users {
    pub const NOAUTH_USER: &str = "noauth_user";
    pub const AUTHMD5_USER: &str = "authmd5_user";
    pub const AUTHSHA1_USER: &str = "authsha1_user";
    pub const AUTHSHA256_USER: &str = "authsha256_user";
    pub const PRIVDES_USER: &str = "privdes_user";
    pub const PRIVAES128_USER: &str = "privaes128_user";
}

// ============================================================================
// Basic Protocol Tests
// ============================================================================

#[tokio::test]
async fn v2c_get_returns_value() {
    require_container_runtime!();

    let info = get_snmpd_container().await;
    let target = format!("{}:{}", info.host, info.udp_port);

    let client = Client::builder(&target, Auth::v2c(COMMUNITY))
        .timeout(Duration::from_secs(5))
        .connect()
        .await
        .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();

    // sysDescr should be a non-empty string
    assert!(matches!(result.value, Value::OctetString(_)));
    if let Value::OctetString(s) = &result.value {
        assert!(!s.is_empty());
    }
}

#[tokio::test]
async fn v1_get_returns_value() {
    require_container_runtime!();

    let info = get_snmpd_container().await;
    let target = format!("{}:{}", info.host, info.udp_port);

    let client = Client::builder(&target, Auth::v1(COMMUNITY))
        .timeout(Duration::from_secs(5))
        .connect()
        .await
        .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();

    assert!(matches!(result.value, Value::OctetString(_)));
}

#[tokio::test]
async fn getnext_returns_next_oid() {
    require_container_runtime!();

    let info = get_snmpd_container().await;
    let target = format!("{}:{}", info.host, info.udp_port);

    let client = Client::builder(&target, Auth::v2c(COMMUNITY))
        .connect()
        .await
        .unwrap();

    let result = client
        .get_next(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))
        .await
        .unwrap();

    // Should return an OID greater than the request
    assert!(result.oid > oid!(1, 3, 6, 1, 2, 1, 1, 1, 0));
}

#[tokio::test]
async fn getbulk_returns_multiple() {
    require_container_runtime!();

    let info = get_snmpd_container().await;
    let target = format!("{}:{}", info.host, info.udp_port);

    let client = Client::builder(&target, Auth::v2c(COMMUNITY))
        .connect()
        .await
        .unwrap();

    let results = client
        .get_bulk(&[oid!(1, 3, 6, 1, 2, 1, 1)], 0, 5)
        .await
        .unwrap();

    assert!(results.len() >= 2);
}

// ============================================================================
// WALK Tests
// ============================================================================

#[tokio::test]
async fn walk_system_mib() {
    require_container_runtime!();

    let info = get_snmpd_container().await;
    let target = format!("{}:{}", info.host, info.udp_port);

    let client = Client::builder(&target, Auth::v2c(COMMUNITY))
        .connect()
        .await
        .unwrap();

    let results = client
        .walk(oid!(1, 3, 6, 1, 2, 1, 1))
        .expect("walk creation failed")
        .collect()
        .await
        .expect("walk failed");

    assert!(!results.is_empty());
    for vb in &results {
        assert!(vb.oid.starts_with(&oid!(1, 3, 6, 1, 2, 1, 1)));
    }
}

#[tokio::test]
async fn bulk_walk_interfaces() {
    require_container_runtime!();

    let info = get_snmpd_container().await;
    let target = format!("{}:{}", info.host, info.udp_port);

    let client = Client::builder(&target, Auth::v2c(COMMUNITY))
        .connect()
        .await
        .unwrap();

    let results = client
        .bulk_walk(oid!(1, 3, 6, 1, 2, 1, 2), 25)
        .collect()
        .await
        .expect("bulk_walk failed");

    assert!(!results.is_empty());
}

// ============================================================================
// V3 Security Level Tests
// ============================================================================

#[tokio::test]
async fn v3_no_auth_no_priv() {
    require_container_runtime!();

    let info = get_snmpd_container().await;
    let target = format!("{}:{}", info.host, info.udp_port);

    let client = Client::builder(&target, Auth::usm(users::NOAUTH_USER))
        .timeout(Duration::from_secs(5))
        .connect()
        .await
        .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert!(matches!(result.value, Value::OctetString(_)));
}

#[tokio::test]
async fn v3_auth_no_priv() {
    require_container_runtime!();

    let info = get_snmpd_container().await;
    let target = format!("{}:{}", info.host, info.udp_port);

    let client = Client::builder(
        &target,
        Auth::usm(users::AUTHSHA256_USER).auth(AuthProtocol::Sha256, AUTH_PASS),
    )
    .timeout(Duration::from_secs(5))
    .connect()
    .await
    .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert!(matches!(result.value, Value::OctetString(_)));
}

#[tokio::test]
async fn v3_auth_priv() {
    require_container_runtime!();

    let info = get_snmpd_container().await;
    let target = format!("{}:{}", info.host, info.udp_port);

    let client = Client::builder(
        &target,
        Auth::usm(users::PRIVAES128_USER)
            .auth(AuthProtocol::Sha1, AUTH_PASS)
            .privacy(PrivProtocol::Aes128, PRIV_PASS),
    )
    .timeout(Duration::from_secs(5))
    .connect()
    .await
    .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert!(matches!(result.value, Value::OctetString(_)));
}

// ============================================================================
// V3 Auth Protocol Tests
// ============================================================================

#[tokio::test]
async fn v3_auth_md5() {
    require_container_runtime!();

    let info = get_snmpd_container().await;
    let target = format!("{}:{}", info.host, info.udp_port);

    let client = Client::builder(
        &target,
        Auth::usm(users::AUTHMD5_USER).auth(AuthProtocol::Md5, AUTH_PASS),
    )
    .timeout(Duration::from_secs(5))
    .connect()
    .await
    .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert!(matches!(result.value, Value::OctetString(_)));
}

#[tokio::test]
async fn v3_auth_sha1() {
    require_container_runtime!();

    let info = get_snmpd_container().await;
    let target = format!("{}:{}", info.host, info.udp_port);

    let client = Client::builder(
        &target,
        Auth::usm(users::AUTHSHA1_USER).auth(AuthProtocol::Sha1, AUTH_PASS),
    )
    .timeout(Duration::from_secs(5))
    .connect()
    .await
    .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert!(matches!(result.value, Value::OctetString(_)));
}

#[tokio::test]
async fn v3_auth_sha256() {
    require_container_runtime!();

    let info = get_snmpd_container().await;
    let target = format!("{}:{}", info.host, info.udp_port);

    let client = Client::builder(
        &target,
        Auth::usm(users::AUTHSHA256_USER).auth(AuthProtocol::Sha256, AUTH_PASS),
    )
    .timeout(Duration::from_secs(5))
    .connect()
    .await
    .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert!(matches!(result.value, Value::OctetString(_)));
}

// ============================================================================
// V3 Priv Protocol Tests
// ============================================================================

#[tokio::test]
async fn v3_priv_des() {
    require_container_runtime!();

    let info = get_snmpd_container().await;
    let target = format!("{}:{}", info.host, info.udp_port);

    let client = Client::builder(
        &target,
        Auth::usm(users::PRIVDES_USER)
            .auth(AuthProtocol::Sha1, AUTH_PASS)
            .privacy(PrivProtocol::Des, PRIV_PASS),
    )
    .timeout(Duration::from_secs(5))
    .connect()
    .await
    .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert!(matches!(result.value, Value::OctetString(_)));
}

#[tokio::test]
async fn v3_priv_aes128() {
    require_container_runtime!();

    let info = get_snmpd_container().await;
    let target = format!("{}:{}", info.host, info.udp_port);

    let client = Client::builder(
        &target,
        Auth::usm(users::PRIVAES128_USER)
            .auth(AuthProtocol::Sha1, AUTH_PASS)
            .privacy(PrivProtocol::Aes128, PRIV_PASS),
    )
    .timeout(Duration::from_secs(5))
    .connect()
    .await
    .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert!(matches!(result.value, Value::OctetString(_)));
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[tokio::test]
async fn missing_oid_returns_no_such() {
    require_container_runtime!();

    let info = get_snmpd_container().await;
    let target = format!("{}:{}", info.host, info.udp_port);

    let client = Client::builder(&target, Auth::v2c(COMMUNITY))
        .connect()
        .await
        .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 99, 99, 99, 99)).await.unwrap();

    // Should be NoSuchObject or NoSuchInstance
    assert!(matches!(
        result.value,
        Value::NoSuchObject | Value::NoSuchInstance
    ));
}

#[tokio::test]
async fn wrong_community_fails() {
    require_container_runtime!();

    let info = get_snmpd_container().await;
    let target = format!("{}:{}", info.host, info.udp_port);

    let client = Client::builder(&target, Auth::v2c("wrongcommunity"))
        .timeout(Duration::from_secs(2))
        .retry(Retry::none())
        .connect()
        .await
        .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;

    // Should timeout (agent ignores bad community) or return error
    assert!(result.is_err());
}

// ============================================================================
// Value Type Tests (verify codec)
// ============================================================================

#[tokio::test]
async fn value_types_decode_correctly() {
    require_container_runtime!();

    let info = get_snmpd_container().await;
    let target = format!("{}:{}", info.host, info.udp_port);

    let client = Client::builder(&target, Auth::v2c(COMMUNITY))
        .connect()
        .await
        .unwrap();

    // Test various value types from standard MIBs
    let results = client
        .get_many(&[
            oid!(1, 3, 6, 1, 2, 1, 1, 1, 0), // OctetString (sysDescr)
            oid!(1, 3, 6, 1, 2, 1, 1, 2, 0), // OID (sysObjectID)
            oid!(1, 3, 6, 1, 2, 1, 1, 3, 0), // TimeTicks (sysUpTime)
            oid!(1, 3, 6, 1, 2, 1, 1, 7, 0), // Integer (sysServices)
        ])
        .await
        .unwrap();

    assert!(matches!(results[0].value, Value::OctetString(_)));
    assert!(matches!(results[1].value, Value::ObjectIdentifier(_)));
    assert!(matches!(results[2].value, Value::TimeTicks(_)));
    assert!(matches!(results[3].value, Value::Integer(_)));
}

// ============================================================================
// Transport Tests
// ============================================================================

#[tokio::test]
async fn tcp_transport_get() {
    require_container_runtime!();

    let info = get_snmpd_container().await;
    let target = format!("{}:{}", info.host, info.tcp_port);

    let client = Client::builder(&target, Auth::v2c(COMMUNITY))
        .timeout(Duration::from_secs(5))
        .connect_tcp()
        .await
        .expect("Failed to connect via TCP");

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;

    match result {
        Ok(vb) => {
            assert_eq!(vb.oid, oid!(1, 3, 6, 1, 2, 1, 1, 1, 0));
            assert!(matches!(vb.value, Value::OctetString(_)));
        }
        Err(e) => panic!("TCP GET failed: {}", e),
    }
}

#[tokio::test]
async fn shared_transport_multiple_clients() {
    require_container_runtime!();

    let info = get_snmpd_container().await;
    let target = parse_target(info);

    let shared = UdpTransport::builder()
        .bind("[::]:0")
        .build()
        .await
        .expect("Failed to bind shared transport");

    let client1 = Client::builder(target.to_string(), Auth::v2c(COMMUNITY))
        .timeout(Duration::from_secs(5))
        .build_with(&shared)
        .expect("Failed to build client1");

    let client2 = Client::builder(target.to_string(), Auth::v2c(COMMUNITY))
        .timeout(Duration::from_secs(5))
        .build_with(&shared)
        .expect("Failed to build client2");

    // Run concurrent requests
    let oid1 = oid!(1, 3, 6, 1, 2, 1, 1, 1, 0); // sysDescr
    let oid2 = oid!(1, 3, 6, 1, 2, 1, 1, 5, 0); // sysName
    let (result1, result2) = tokio::join!(client1.get(&oid1), client2.get(&oid2));

    let vb1 = result1.expect("Client 1 GET failed");
    let vb2 = result2.expect("Client 2 GET failed");

    assert!(matches!(vb1.value, Value::OctetString(_)));
    assert!(matches!(vb2.value, Value::OctetString(_)));
}

// ============================================================================
// V3 Engine Discovery Tests
// ============================================================================

#[tokio::test]
async fn v3_engine_discovery_and_request() {
    require_container_runtime!();

    let info = get_snmpd_container().await;
    let target = format!("{}:{}", info.host, info.udp_port);

    // This test verifies the full V3 flow: discovery + authenticated request
    let client = Client::builder(
        &target,
        Auth::usm(users::PRIVAES128_USER)
            .auth(AuthProtocol::Sha1, AUTH_PASS)
            .privacy(PrivProtocol::Aes128, PRIV_PASS),
    )
    .timeout(Duration::from_secs(5))
    .connect()
    .await
    .expect("V3 connection with discovery should succeed");

    // First request triggers engine discovery
    let result1 = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert!(matches!(result1.value, Value::OctetString(_)));

    // Second request uses cached engine state
    let result2 = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 5, 0)).await.unwrap();
    assert!(matches!(result2.value, Value::OctetString(_)));
}

// ============================================================================
// SET Operation Test
// ============================================================================

#[tokio::test]
async fn set_writable_oid() {
    require_container_runtime!();

    let info = get_snmpd_container().await;
    let target = format!("{}:{}", info.host, info.udp_port);

    let client = Client::builder(&target, Auth::v2c("private"))
        .timeout(Duration::from_secs(5))
        .connect()
        .await
        .unwrap();

    let new_contact = Value::OctetString("admin@example.com".into());

    // SET sysContact
    let result = client
        .set(&oid!(1, 3, 6, 1, 2, 1, 1, 4, 0), new_contact.clone())
        .await;

    match result {
        Ok(vb) => {
            assert_eq!(vb.oid, oid!(1, 3, 6, 1, 2, 1, 1, 4, 0));
            if let Value::OctetString(s) = &vb.value {
                assert_eq!(s.as_ref(), b"admin@example.com");
            }
        }
        Err(e) => match *e {
            async_snmp::Error::Snmp { .. } => {
                // NotWritable is acceptable if agent doesn't allow writes
            }
            _ => panic!("SET failed unexpectedly: {}", e),
        },
    }
}
