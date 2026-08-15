//! Container-based interoperability tests.
//!
//! These tests verify Client works correctly against net-snmp,
//! serving as the firewall against correlated bugs where both
//! Client and Agent might have the same flaw.
//!
//! Run with: cargo test --test interop --all-features -- --ignored

#[cfg(all(feature = "crypto-rustcrypto", unix))]
use std::fs::{self, File, OpenOptions};
#[cfg(feature = "crypto-rustcrypto")]
use std::io;
#[cfg(all(feature = "crypto-rustcrypto", unix))]
use std::io::Write;
use std::net::SocketAddr;
#[cfg(all(feature = "crypto-rustcrypto", unix))]
use std::path::{Path, PathBuf};
#[cfg(all(feature = "crypto-rustcrypto", unix))]
use std::sync::Mutex;
use std::sync::OnceLock;
use std::time::Duration;

#[cfg(feature = "crypto-rustcrypto")]
use async_snmp::DesSaltState;
#[cfg(all(feature = "crypto-rustcrypto", unix))]
use async_snmp::PersistedDesSaltState;
use async_snmp::{Auth, AuthProtocol, Client, PrivProtocol, Retry, UdpTransport, Value, oid};
#[cfg(all(feature = "crypto-rustcrypto", unix))]
use fs2::FileExt;
#[cfg(all(feature = "crypto-rustcrypto", unix))]
use tempfile::NamedTempFile;
use testcontainers::{
    ContainerAsync, GenericImage,
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
};

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
// Container Fixture
// ============================================================================

/// A per-test snmpd container.
///
/// Each test starts its own container and holds this guard for the test's
/// duration; dropping it removes the container. Keep it in a local so the
/// container is cleaned up when the test ends — storing it in a static would
/// leak the container, since statics are never dropped.
struct Snmpd {
    _container: ContainerAsync<GenericImage>,
    host: String,
    udp_port: u16,
    tcp_port: u16,
}

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

impl Snmpd {
    async fn start() -> Snmpd {
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

        #[cfg(not(target_os = "linux"))]
        tokio::time::sleep(Duration::from_millis(4000)).await; // Wait a moment for host port forwarding to be ready

        let host = container.get_host().await.expect("Failed to get host");
        let udp_port = container
            .get_host_port_ipv4(161.udp())
            .await
            .expect("Failed to get UDP port");
        let tcp_port = container
            .get_host_port_ipv4(161.tcp())
            .await
            .expect("Failed to get TCP port");

        Snmpd {
            _container: container,
            host: host.to_string(),
            udp_port,
            tcp_port,
        }
    }

    fn udp_target(&self) -> String {
        format!("{}:{}", self.host, self.udp_port)
    }

    fn tcp_target(&self) -> String {
        format!("{}:{}", self.host, self.tcp_port)
    }

    fn udp_socket_addr(&self) -> SocketAddr {
        use std::net::ToSocketAddrs;
        self.udp_target()
            .to_socket_addrs()
            .expect("Failed to resolve target")
            .next()
            .expect("No addresses resolved")
    }
}

// ============================================================================
// Test credentials (must match container configuration)
// ============================================================================

const COMMUNITY: &str = "public";
const AUTH_PASS: &str = "authpass123";
const PRIV_PASS: &str = "privpass123";

#[cfg(all(feature = "crypto-rustcrypto", unix))]
static DES_FIXTURE_PROCESS_LOCK: Mutex<()> = Mutex::new(());

#[cfg(all(feature = "crypto-rustcrypto", unix))]
fn des_fixture_state_path() -> PathBuf {
    let root = std::env::var_os("ASYNC_SNMP_INTEROP_STATE_DIR")
        .map(PathBuf::from)
        .or_else(dirs::state_dir)
        .or_else(dirs::data_local_dir)
        .unwrap_or_else(std::env::temp_dir);
    root.join("async-snmp")
        .join("interop")
        .join("net-snmp-privdes-sha1-des-v1.state")
}

#[cfg(all(feature = "crypto-rustcrypto", unix))]
fn read_des_fixture_record(path: &Path) -> io::Result<Option<PersistedDesSaltState>> {
    let encoded = match fs::read_to_string(path) {
        Ok(encoded) => encoded,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let engine_boots = encoded.trim().parse::<u32>().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid DES fixture epoch in {}: {error}", path.display()),
        )
    })?;
    PersistedDesSaltState::new(engine_boots)
        .map(Some)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

#[cfg(all(feature = "crypto-rustcrypto", unix))]
fn write_des_fixture_temp(path: &Path, state: &PersistedDesSaltState) -> io::Result<NamedTempFile> {
    let mut temp = NamedTempFile::new_in(path.parent().expect("DES fixture record has a parent"))?;
    writeln!(temp, "{}", state.engine_boots())?;
    temp.as_file().sync_all()?;
    Ok(temp)
}

#[cfg(all(feature = "crypto-rustcrypto", unix))]
fn sync_des_fixture_parent(path: &Path) -> io::Result<()> {
    File::open(path.parent().expect("DES fixture record has a parent"))?.sync_all()
}

#[cfg(all(feature = "crypto-rustcrypto", unix))]
fn install_des_fixture_record(path: &Path, state: &PersistedDesSaltState) -> io::Result<()> {
    let temp = write_des_fixture_temp(path, state)?;
    temp.persist_noclobber(path).map_err(|error| error.error)?;
    sync_des_fixture_parent(path)
}

#[cfg(all(feature = "crypto-rustcrypto", unix))]
fn restart_des_fixture_record(
    path: &Path,
    previous: PersistedDesSaltState,
    state: &PersistedDesSaltState,
) -> io::Result<()> {
    let current = read_des_fixture_record(path)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "DES fixture record disappeared during restart",
        )
    })?;
    if current != previous {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "stale DES fixture epoch: expected {}, found {}",
                previous.engine_boots(),
                current.engine_boots()
            ),
        ));
    }

    let temp = write_des_fixture_temp(path, state)?;
    temp.persist(path).map_err(|error| error.error)?;
    sync_des_fixture_parent(path)
}

#[cfg(all(feature = "crypto-rustcrypto", unix))]
fn open_des_fixture_state_at(
    path: &Path,
) -> Result<DesSaltState, Box<dyn std::error::Error + Send + Sync>> {
    let _process_guard = DES_FIXTURE_PROCESS_LOCK
        .lock()
        .map_err(|_| io::Error::other("DES fixture process lock poisoned"))?;
    fs::create_dir_all(path.parent().expect("DES fixture record has a parent"))?;

    let lock_path = path.with_extension("lock");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)?;
    FileExt::lock_exclusive(&lock)?;

    let result = match read_des_fixture_record(path)? {
        Some(previous) => DesSaltState::restart(previous, |attempted| {
            restart_des_fixture_record(path, previous, attempted)
        }),
        None => DesSaltState::install(|attempted| install_des_fixture_record(path, attempted)),
    };
    FileExt::unlock(&lock)?;
    result.map_err(Into::into)
}

#[cfg(all(feature = "crypto-rustcrypto", unix))]
fn open_des_fixture_state() -> Result<DesSaltState, Box<dyn std::error::Error + Send + Sync>> {
    open_des_fixture_state_at(&des_fixture_state_path())
}

#[cfg(all(feature = "crypto-rustcrypto", not(unix)))]
fn open_des_fixture_state() -> Result<DesSaltState, Box<dyn std::error::Error + Send + Sync>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "durable DES interoperability fixture requires Unix atomic rename semantics",
    )
    .into())
}

mod users {
    pub const NOAUTH_USER: &str = "noauth_user";
    #[cfg(feature = "crypto-rustcrypto")]
    pub const AUTHMD5_USER: &str = "authmd5_user";
    pub const AUTHSHA1_USER: &str = "authsha1_user";
    pub const AUTHSHA224_USER: &str = "authsha224_user";
    pub const AUTHSHA256_USER: &str = "authsha256_user";
    pub const AUTHSHA384_USER: &str = "authsha384_user";
    pub const AUTHSHA512_USER: &str = "authsha512_user";
    #[cfg(feature = "crypto-rustcrypto")]
    pub const PRIVDES_USER: &str = "privdes_user";
    pub const PRIVAES128_USER: &str = "privaes128_user";
}

// ============================================================================
// Basic Protocol Tests
// ============================================================================

#[tokio::test]
#[ignore = "requires the net-snmp interoperability container"]
async fn v2c_get_returns_value() {
    require_container_runtime!();

    let snmpd = Snmpd::start().await;
    let target = snmpd.udp_target();

    let client = Client::builder(&target, Auth::v2c(COMMUNITY))
        .request_timeout(Duration::from_secs(5))
        .connect()
        .await
        .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();

    // sysDescr should be a non-empty string
    assert!(result.anomalies.is_empty());
    let result = &result.varbinds[0];
    assert!(matches!(result.value, Value::OctetString(_)));
    if let Value::OctetString(s) = &result.value {
        assert!(!s.is_empty());
    }
}

#[tokio::test]
#[ignore = "requires the net-snmp interoperability container"]
async fn v1_get_returns_value() {
    require_container_runtime!();

    let snmpd = Snmpd::start().await;
    let target = snmpd.udp_target();

    let client = Client::builder(&target, Auth::v1(COMMUNITY))
        .request_timeout(Duration::from_secs(5))
        .connect()
        .await
        .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();

    assert!(result.anomalies.is_empty());
    assert!(matches!(result.varbinds[0].value, Value::OctetString(_)));
}

#[tokio::test]
#[ignore = "requires the net-snmp interoperability container"]
async fn getnext_returns_next_oid() {
    require_container_runtime!();

    let snmpd = Snmpd::start().await;
    let target = snmpd.udp_target();

    let client = Client::builder(&target, Auth::v2c(COMMUNITY))
        .connect()
        .await
        .unwrap();

    let result = client
        .get_next(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))
        .await
        .unwrap();

    // Should return an OID greater than the request
    assert!(result.anomalies.is_empty());
    assert!(result.varbinds[0].oid > oid!(1, 3, 6, 1, 2, 1, 1, 1, 0));
}

#[tokio::test]
#[ignore = "requires the net-snmp interoperability container"]
async fn getbulk_returns_multiple() {
    require_container_runtime!();

    let snmpd = Snmpd::start().await;
    let target = snmpd.udp_target();

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
#[ignore = "requires the net-snmp interoperability container"]
async fn walk_system_mib() {
    require_container_runtime!();

    let snmpd = Snmpd::start().await;
    let target = snmpd.udp_target();

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
#[ignore = "requires the net-snmp interoperability container"]
async fn bulk_walk_interfaces() {
    require_container_runtime!();

    let snmpd = Snmpd::start().await;
    let target = snmpd.udp_target();

    let client = Client::builder(&target, Auth::v2c(COMMUNITY))
        .connect()
        .await
        .unwrap();

    let results = client
        .bulk_walk(oid!(1, 3, 6, 1, 2, 1, 2), 25)
        .unwrap()
        .collect()
        .await
        .expect("bulk_walk failed");

    assert!(!results.is_empty());
}

// ============================================================================
// V3 Security Level Tests
// ============================================================================

#[tokio::test]
#[ignore = "requires the net-snmp interoperability container"]
async fn v3_no_auth_no_priv() {
    require_container_runtime!();

    let snmpd = Snmpd::start().await;
    let target = snmpd.udp_target();

    let client = Client::builder(&target, Auth::usm(users::NOAUTH_USER))
        .request_timeout(Duration::from_secs(5))
        .connect()
        .await
        .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert!(result.anomalies.is_empty());
    assert!(matches!(result.varbinds[0].value, Value::OctetString(_)));
}

#[tokio::test]
#[ignore = "requires the net-snmp interoperability container"]
async fn v3_auth_no_priv() {
    require_container_runtime!();

    let snmpd = Snmpd::start().await;
    let target = snmpd.udp_target();

    let client = Client::builder(
        &target,
        async_snmp::UsmConfig::new(users::AUTHSHA256_USER)
            .auth(AuthProtocol::Sha256, AUTH_PASS)
            .unwrap(),
    )
    .request_timeout(Duration::from_secs(5))
    .connect()
    .await
    .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert!(result.anomalies.is_empty());
    assert!(matches!(result.varbinds[0].value, Value::OctetString(_)));
}

#[tokio::test]
#[ignore = "requires the net-snmp interoperability container"]
async fn v3_auth_priv() {
    require_container_runtime!();

    let snmpd = Snmpd::start().await;
    let target = snmpd.udp_target();

    let client = Client::builder(
        &target,
        async_snmp::UsmConfig::new(users::PRIVAES128_USER)
            .auth_priv(
                AuthProtocol::Sha1,
                AUTH_PASS,
                PrivProtocol::Aes128,
                PRIV_PASS,
            )
            .unwrap(),
    )
    .request_timeout(Duration::from_secs(5))
    .connect()
    .await
    .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert!(result.anomalies.is_empty());
    assert!(matches!(result.varbinds[0].value, Value::OctetString(_)));
}

// ============================================================================
// V3 Auth Protocol Tests
// ============================================================================

#[cfg(feature = "crypto-rustcrypto")]
#[tokio::test]
#[ignore = "requires the net-snmp interoperability container"]
async fn v3_auth_md5() {
    require_container_runtime!();

    let snmpd = Snmpd::start().await;
    let target = snmpd.udp_target();

    let client = Client::builder(
        &target,
        async_snmp::UsmConfig::new(users::AUTHMD5_USER)
            .auth(AuthProtocol::Md5, AUTH_PASS)
            .unwrap(),
    )
    .request_timeout(Duration::from_secs(5))
    .connect()
    .await
    .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert!(result.anomalies.is_empty());
    assert!(matches!(result.varbinds[0].value, Value::OctetString(_)));
}

#[tokio::test]
#[ignore = "requires the net-snmp interoperability container"]
async fn v3_auth_sha1() {
    require_container_runtime!();

    let snmpd = Snmpd::start().await;
    let target = snmpd.udp_target();

    let client = Client::builder(
        &target,
        async_snmp::UsmConfig::new(users::AUTHSHA1_USER)
            .auth(AuthProtocol::Sha1, AUTH_PASS)
            .unwrap(),
    )
    .request_timeout(Duration::from_secs(5))
    .connect()
    .await
    .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert!(result.anomalies.is_empty());
    assert!(matches!(result.varbinds[0].value, Value::OctetString(_)));
}

#[tokio::test]
#[ignore = "requires the net-snmp interoperability container"]
async fn v3_auth_sha256() {
    require_container_runtime!();

    let snmpd = Snmpd::start().await;
    let target = snmpd.udp_target();

    let client = Client::builder(
        &target,
        async_snmp::UsmConfig::new(users::AUTHSHA256_USER)
            .auth(AuthProtocol::Sha256, AUTH_PASS)
            .unwrap(),
    )
    .request_timeout(Duration::from_secs(5))
    .connect()
    .await
    .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert!(result.anomalies.is_empty());
    assert!(matches!(result.varbinds[0].value, Value::OctetString(_)));
}

/// authNoPriv GET against net-snmp for a given RFC 7860 SHA-2 auth protocol.
async fn v3_auth_interop(user: &str, protocol: AuthProtocol) {
    let snmpd = Snmpd::start().await;
    let target = snmpd.udp_target();

    let client = Client::builder(
        &target,
        async_snmp::UsmConfig::new(bytes::Bytes::copy_from_slice(user.as_bytes()))
            .auth(protocol, AUTH_PASS)
            .unwrap(),
    )
    .request_timeout(Duration::from_secs(5))
    .connect()
    .await
    .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert!(result.anomalies.is_empty());
    assert!(matches!(result.varbinds[0].value, Value::OctetString(_)));
}

#[tokio::test]
#[ignore = "requires the net-snmp interoperability container"]
async fn v3_auth_sha224() {
    require_container_runtime!();
    v3_auth_interop(users::AUTHSHA224_USER, AuthProtocol::Sha224).await;
}

#[tokio::test]
#[ignore = "requires the net-snmp interoperability container"]
async fn v3_auth_sha384() {
    require_container_runtime!();
    v3_auth_interop(users::AUTHSHA384_USER, AuthProtocol::Sha384).await;
}

#[tokio::test]
#[ignore = "requires the net-snmp interoperability container"]
async fn v3_auth_sha512() {
    require_container_runtime!();
    v3_auth_interop(users::AUTHSHA512_USER, AuthProtocol::Sha512).await;
}

// ============================================================================
// V3 Priv Protocol Tests
// ============================================================================

#[cfg(feature = "crypto-rustcrypto")]
#[tokio::test]
#[ignore = "requires the net-snmp interoperability container"]
async fn v3_priv_des() {
    require_container_runtime!();

    let snmpd = Snmpd::start().await;
    let target = snmpd.udp_target();

    let client = Client::builder(
        &target,
        async_snmp::UsmConfig::new(users::PRIVDES_USER)
            .auth_priv(AuthProtocol::Sha1, AUTH_PASS, PrivProtocol::Des, PRIV_PASS)
            .unwrap(),
    )
    .request_timeout(Duration::from_secs(5))
    .des_salt_state(open_des_fixture_state().expect("open durable DES sender state"))
    .connect()
    .await
    .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert!(result.anomalies.is_empty());
    assert!(matches!(result.varbinds[0].value, Value::OctetString(_)));
}

#[cfg(all(feature = "crypto-rustcrypto", unix))]
#[test]
fn des_fixture_record_advances_across_restarts() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("des.state");

    let first = open_des_fixture_state_at(&path).unwrap();
    assert_eq!(first.engine_boots(), 1);
    drop(first);

    let restarted = open_des_fixture_state_at(&path).unwrap();
    assert_eq!(restarted.engine_boots(), 2);
    assert_eq!(
        read_des_fixture_record(&path)
            .unwrap()
            .unwrap()
            .engine_boots(),
        2
    );
}

#[cfg(all(feature = "crypto-rustcrypto", unix))]
#[test]
fn abandoned_restart_temp_does_not_replace_the_committed_epoch() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("des.state");

    let installed = open_des_fixture_state_at(&path).unwrap();
    let restarted = open_des_fixture_state_at(&path).unwrap();
    assert_eq!(installed.engine_boots(), 1);
    assert_eq!(restarted.engine_boots(), 2);

    let attempted = PersistedDesSaltState::new(3).unwrap();
    let abandoned = write_des_fixture_temp(&path, &attempted).unwrap();
    let abandoned_path = abandoned.path().to_owned();
    assert_eq!(
        read_des_fixture_record(&path)
            .unwrap()
            .unwrap()
            .engine_boots(),
        2
    );
    drop(abandoned);
    assert!(!abandoned_path.exists());

    let next = open_des_fixture_state_at(&path).unwrap();
    assert_eq!(next.engine_boots(), 3);
}

#[tokio::test]
#[ignore = "requires the net-snmp interoperability container"]
async fn v3_priv_aes128() {
    require_container_runtime!();

    let snmpd = Snmpd::start().await;
    let target = snmpd.udp_target();

    let client = Client::builder(
        &target,
        async_snmp::UsmConfig::new(users::PRIVAES128_USER)
            .auth_priv(
                AuthProtocol::Sha1,
                AUTH_PASS,
                PrivProtocol::Aes128,
                PRIV_PASS,
            )
            .unwrap(),
    )
    .request_timeout(Duration::from_secs(5))
    .connect()
    .await
    .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert!(result.anomalies.is_empty());
    assert!(matches!(result.varbinds[0].value, Value::OctetString(_)));
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[tokio::test]
#[ignore = "requires the net-snmp interoperability container"]
async fn missing_oid_returns_no_such() {
    require_container_runtime!();

    let snmpd = Snmpd::start().await;
    let target = snmpd.udp_target();

    let client = Client::builder(&target, Auth::v2c(COMMUNITY))
        .connect()
        .await
        .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 99, 99, 99, 99)).await.unwrap();

    // Should be NoSuchObject or NoSuchInstance
    assert!(result.anomalies.is_empty());
    assert!(matches!(
        result.varbinds[0].value,
        Value::NoSuchObject | Value::NoSuchInstance
    ));
}

#[tokio::test]
#[ignore = "requires the net-snmp interoperability container"]
async fn wrong_community_fails() {
    require_container_runtime!();

    let snmpd = Snmpd::start().await;
    let target = snmpd.udp_target();

    let client = Client::builder(&target, Auth::v2c("wrongcommunity"))
        .request_timeout(Duration::from_secs(2))
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
#[ignore = "requires the net-snmp interoperability container"]
async fn value_types_decode_correctly() {
    require_container_runtime!();

    let snmpd = Snmpd::start().await;
    let target = snmpd.udp_target();

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

    assert!(matches!(results.varbinds[0].value, Value::OctetString(_)));
    assert!(matches!(
        results.varbinds[1].value,
        Value::ObjectIdentifier(_)
    ));
    assert!(matches!(results.varbinds[2].value, Value::TimeTicks(_)));
    assert!(matches!(results.varbinds[3].value, Value::Integer(_)));
}

// ============================================================================
// Transport Tests
// ============================================================================

#[tokio::test]
#[ignore = "requires the net-snmp interoperability container"]
async fn tcp_transport_get() {
    require_container_runtime!();

    let snmpd = Snmpd::start().await;
    let target = snmpd.tcp_target();

    let client = Client::builder(&target, Auth::v2c(COMMUNITY))
        .request_timeout(Duration::from_secs(5))
        .connect_tcp()
        .await
        .expect("Failed to connect via TCP");

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;

    match result {
        Ok(response) => {
            assert!(response.anomalies.is_empty());
            assert_eq!(response.varbinds[0].oid, oid!(1, 3, 6, 1, 2, 1, 1, 1, 0));
            assert!(matches!(response.varbinds[0].value, Value::OctetString(_)));
        }
        Err(e) => panic!("TCP GET failed: {e}"),
    }
}

#[tokio::test]
#[ignore = "requires the net-snmp interoperability container"]
async fn shared_transport_multiple_clients() {
    require_container_runtime!();

    let snmpd = Snmpd::start().await;
    let target = snmpd.udp_socket_addr();

    let bind_addr = if target.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let shared = UdpTransport::builder()
        .bind(bind_addr)
        .build()
        .await
        .expect("Failed to bind shared transport");

    let client1 = Client::builder(target.to_string(), Auth::v2c(COMMUNITY))
        .request_timeout(Duration::from_secs(5))
        .build_with(&shared)
        .await
        .expect("Failed to build client1");

    let client2 = Client::builder(target.to_string(), Auth::v2c(COMMUNITY))
        .request_timeout(Duration::from_secs(5))
        .build_with(&shared)
        .await
        .expect("Failed to build client2");

    // Run concurrent requests
    let oid1 = oid!(1, 3, 6, 1, 2, 1, 1, 1, 0); // sysDescr
    let oid2 = oid!(1, 3, 6, 1, 2, 1, 1, 5, 0); // sysName
    let (result1, result2) = tokio::join!(client1.get(&oid1), client2.get(&oid2));

    let response1 = result1.expect("Client 1 GET failed");
    let response2 = result2.expect("Client 2 GET failed");

    assert!(response1.anomalies.is_empty());
    assert!(response2.anomalies.is_empty());
    assert!(matches!(response1.varbinds[0].value, Value::OctetString(_)));
    assert!(matches!(response2.varbinds[0].value, Value::OctetString(_)));
}

// ============================================================================
// V3 Engine Discovery Tests
// ============================================================================

#[tokio::test]
#[ignore = "requires the net-snmp interoperability container"]
async fn v3_engine_discovery_and_request() {
    require_container_runtime!();

    let snmpd = Snmpd::start().await;
    let target = snmpd.udp_target();

    // This test verifies the full V3 flow: discovery + authenticated request
    let client = Client::builder(
        &target,
        async_snmp::UsmConfig::new(users::PRIVAES128_USER)
            .auth_priv(
                AuthProtocol::Sha1,
                AUTH_PASS,
                PrivProtocol::Aes128,
                PRIV_PASS,
            )
            .unwrap(),
    )
    .request_timeout(Duration::from_secs(5))
    .connect()
    .await
    .expect("V3 connection with discovery should succeed");

    // First request triggers engine discovery
    let result1 = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert!(result1.anomalies.is_empty());
    assert!(matches!(result1.varbinds[0].value, Value::OctetString(_)));

    // Second request uses cached engine state
    let result2 = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 5, 0)).await.unwrap();
    assert!(result2.anomalies.is_empty());
    assert!(matches!(result2.varbinds[0].value, Value::OctetString(_)));
}

// ============================================================================
// SET Operation Test
// ============================================================================

#[tokio::test]
#[ignore = "requires the net-snmp interoperability container"]
async fn set_writable_oid() {
    require_container_runtime!();

    let snmpd = Snmpd::start().await;
    let target = snmpd.udp_target();

    let client = Client::builder(&target, Auth::v2c("private"))
        .request_timeout(Duration::from_secs(5))
        .connect()
        .await
        .unwrap();

    let new_contact = Value::OctetString("admin@example.com".into());

    // SET sysContact
    let result = client
        .set(&oid!(1, 3, 6, 1, 2, 1, 1, 4, 0), new_contact.clone())
        .await;

    match result {
        Ok(response) => {
            assert!(response.anomalies.is_empty());
            let vb = &response.varbinds[0];
            assert_eq!(vb.oid, oid!(1, 3, 6, 1, 2, 1, 1, 4, 0));
            if let Value::OctetString(s) = &vb.value {
                assert_eq!(s.as_ref(), b"admin@example.com");
            }
        }
        Err(e) => match *e {
            async_snmp::Error::Snmp { .. } => {
                // NotWritable is acceptable if agent doesn't allow writes
            }
            _ => panic!("SET failed unexpectedly: {e}"),
        },
    }
}
