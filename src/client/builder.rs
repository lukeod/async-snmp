//! New unified client builder.
//!
//! This module provides the [`ClientBuilder`] type, a single entry point for
//! constructing SNMP clients with any authentication mode (v1/v2c community
//! or v3 USM).

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;

use crate::client::retry::Retry;
use crate::client::walk::{OidOrdering, WalkMode};
use crate::client::{Auth, ClientConfig, CommunityVersion, V3SecurityConfig};
use crate::error::{Error, Result};
use crate::transport::{TcpTransport, Transport, UdpHandle, UdpTransport};
use crate::v3::EngineCache;
use crate::version::Version;

use super::Client;

/// Builder for constructing SNMP clients.
///
/// This is the single entry point for client construction. It supports all
/// SNMP versions (v1, v2c, v3) through the [`Auth`] enum.
///
/// # Example
///
/// ```rust,no_run
/// use async_snmp::{Auth, ClientBuilder, Retry};
/// use std::time::Duration;
///
/// # async fn example() -> async_snmp::Result<()> {
/// // Simple v2c client
/// let client = ClientBuilder::new("192.168.1.1:161", Auth::v2c("public"))
///     .connect().await?;
///
/// // v3 client with authentication
/// let client = ClientBuilder::new("192.168.1.1:161",
///     Auth::usm("admin").auth(async_snmp::AuthProtocol::Sha256, "password"))
///     .timeout(Duration::from_secs(10))
///     .retry(Retry::fixed(5, Duration::ZERO))
///     .connect().await?;
/// # Ok(())
/// # }
/// ```
pub struct ClientBuilder {
    target: String,
    auth: Auth,
    timeout: Duration,
    retry: Retry,
    max_oids_per_request: usize,
    max_repetitions: u32,
    walk_mode: WalkMode,
    oid_ordering: OidOrdering,
    max_walk_results: Option<usize>,
    engine_cache: Option<Arc<EngineCache>>,
    /// Override context engine ID (V3 only, for proxy/routing scenarios).
    context_engine_id: Option<Vec<u8>>,
}

impl ClientBuilder {
    /// Create a new client builder.
    ///
    /// # Arguments
    ///
    /// * `target` - The target address (e.g., "192.168.1.1:161")
    /// * `auth` - Authentication configuration (community or USM)
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use async_snmp::{Auth, ClientBuilder};
    ///
    /// // Using Auth::default() for v2c with "public" community
    /// let builder = ClientBuilder::new("192.168.1.1:161", Auth::default());
    ///
    /// // Using Auth::v1() for SNMPv1
    /// let builder = ClientBuilder::new("192.168.1.1:161", Auth::v1("private"));
    ///
    /// // Using Auth::usm() for SNMPv3
    /// let builder = ClientBuilder::new("192.168.1.1:161",
    ///     Auth::usm("admin").auth(async_snmp::AuthProtocol::Sha256, "password"));
    /// ```
    pub fn new(target: impl Into<String>, auth: impl Into<Auth>) -> Self {
        Self {
            target: target.into(),
            auth: auth.into(),
            timeout: Duration::from_secs(5),
            retry: Retry::default(),
            max_oids_per_request: 10,
            max_repetitions: 25,
            walk_mode: WalkMode::Auto,
            oid_ordering: OidOrdering::Strict,
            max_walk_results: None,
            engine_cache: None,
            context_engine_id: None,
        }
    }

    /// Set the request timeout (default: 5 seconds).
    ///
    /// This is the time to wait for a response before retrying or failing.
    /// The total time for a request may be `timeout * (retries + 1)`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_snmp::{Auth, ClientBuilder};
    /// use std::time::Duration;
    ///
    /// let builder = ClientBuilder::new("192.168.1.1:161", Auth::v2c("public"))
    ///     .timeout(Duration::from_secs(10));
    /// ```
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the retry configuration (default: 3 retries, no backoff).
    ///
    /// On timeout, the client resends the request up to this many times before
    /// returning an error. Retries are disabled for TCP (which handles
    /// reliability at the transport layer).
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_snmp::{Auth, ClientBuilder, Retry};
    /// use std::time::Duration;
    ///
    /// // No retries
    /// let builder = ClientBuilder::new("192.168.1.1:161", Auth::v2c("public"))
    ///     .retry(Retry::none());
    ///
    /// // 5 retries with no delay (immediate retry on timeout)
    /// let builder = ClientBuilder::new("192.168.1.1:161", Auth::v2c("public"))
    ///     .retry(Retry::fixed(5, Duration::ZERO));
    ///
    /// // Fixed delay between retries
    /// let builder = ClientBuilder::new("192.168.1.1:161", Auth::v2c("public"))
    ///     .retry(Retry::fixed(3, Duration::from_millis(200)));
    ///
    /// // Exponential backoff with jitter
    /// let builder = ClientBuilder::new("192.168.1.1:161", Auth::v2c("public"))
    ///     .retry(Retry::exponential(5)
    ///         .max_delay(Duration::from_secs(5))
    ///         .jitter(0.25));
    /// ```
    pub fn retry(mut self, retry: impl Into<Retry>) -> Self {
        self.retry = retry.into();
        self
    }

    /// Set the maximum OIDs per request (default: 10).
    ///
    /// Requests with more OIDs than this limit are automatically split
    /// into multiple batches. Some devices have lower limits on the number
    /// of OIDs they can handle in a single request.
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_snmp::{Auth, ClientBuilder};
    ///
    /// // For devices with limited request handling capacity
    /// let builder = ClientBuilder::new("192.168.1.1:161", Auth::v2c("public"))
    ///     .max_oids_per_request(5);
    ///
    /// // For high-capacity devices, increase to reduce round-trips
    /// let builder = ClientBuilder::new("192.168.1.1:161", Auth::v2c("public"))
    ///     .max_oids_per_request(50);
    /// ```
    pub fn max_oids_per_request(mut self, max: usize) -> Self {
        self.max_oids_per_request = max;
        self
    }

    /// Set max-repetitions for GETBULK operations (default: 25).
    ///
    /// Controls how many values are requested per GETBULK PDU during walks.
    /// This is a performance tuning parameter with trade-offs:
    ///
    /// - **Higher values**: Fewer network round-trips, faster walks on reliable
    ///   networks. But larger responses risk UDP fragmentation or may exceed
    ///   agent response buffer limits (causing truncation).
    /// - **Lower values**: More round-trips (higher latency), but smaller
    ///   responses that fit within MTU limits.
    ///
    /// The default of 25 is conservative. For local/reliable networks with
    /// capable agents, values of 50-100 can significantly speed up large walks.
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_snmp::{Auth, ClientBuilder};
    ///
    /// // Lower value for agents with small response buffers or lossy networks
    /// let builder = ClientBuilder::new("192.168.1.1:161", Auth::v2c("public"))
    ///     .max_repetitions(10);
    ///
    /// // Higher value for fast local network walks
    /// let builder = ClientBuilder::new("192.168.1.1:161", Auth::v2c("public"))
    ///     .max_repetitions(50);
    /// ```
    pub fn max_repetitions(mut self, max: u32) -> Self {
        self.max_repetitions = max;
        self
    }

    /// Override walk behavior for devices with buggy GETBULK (default: Auto).
    ///
    /// - `WalkMode::Auto`: Use GETNEXT for v1, GETBULK for v2c/v3
    /// - `WalkMode::GetNext`: Always use GETNEXT (slower but more compatible)
    /// - `WalkMode::GetBulk`: Always use GETBULK (faster, errors on v1)
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_snmp::{Auth, ClientBuilder, WalkMode};
    ///
    /// // Force GETNEXT for devices with broken GETBULK implementation
    /// let builder = ClientBuilder::new("192.168.1.1:161", Auth::v2c("public"))
    ///     .walk_mode(WalkMode::GetNext);
    ///
    /// // Force GETBULK for faster walks (only v2c/v3)
    /// let builder = ClientBuilder::new("192.168.1.1:161", Auth::v2c("public"))
    ///     .walk_mode(WalkMode::GetBulk);
    /// ```
    pub fn walk_mode(mut self, mode: WalkMode) -> Self {
        self.walk_mode = mode;
        self
    }

    /// Set OID ordering behavior for walk operations (default: Strict).
    ///
    /// - `OidOrdering::Strict`: Require strictly increasing OIDs. Most efficient.
    /// - `OidOrdering::AllowNonIncreasing`: Allow non-increasing OIDs with cycle
    ///   detection. Uses O(n) memory to track seen OIDs.
    ///
    /// Use `AllowNonIncreasing` for buggy agents that return OIDs out of order.
    ///
    /// **Warning**: `AllowNonIncreasing` uses O(n) memory. Always pair with
    /// [`max_walk_results`](Self::max_walk_results) to bound memory usage.
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_snmp::{Auth, ClientBuilder, OidOrdering};
    ///
    /// // Use relaxed ordering with a safety limit
    /// let builder = ClientBuilder::new("192.168.1.1:161", Auth::v2c("public"))
    ///     .oid_ordering(OidOrdering::AllowNonIncreasing)
    ///     .max_walk_results(10_000);
    /// ```
    pub fn oid_ordering(mut self, ordering: OidOrdering) -> Self {
        self.oid_ordering = ordering;
        self
    }

    /// Set maximum results from a single walk operation (default: unlimited).
    ///
    /// Safety limit to prevent runaway walks. Walk terminates normally when
    /// limit is reached.
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_snmp::{Auth, ClientBuilder};
    ///
    /// // Limit walks to at most 10,000 results
    /// let builder = ClientBuilder::new("192.168.1.1:161", Auth::v2c("public"))
    ///     .max_walk_results(10_000);
    /// ```
    pub fn max_walk_results(mut self, limit: usize) -> Self {
        self.max_walk_results = Some(limit);
        self
    }

    /// Set shared engine cache (V3 only, for polling many targets).
    ///
    /// Allows multiple clients to share discovered engine state, reducing
    /// the number of discovery requests. This is particularly useful when
    /// polling many devices with SNMPv3.
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_snmp::{Auth, AuthProtocol, ClientBuilder, EngineCache};
    /// use std::sync::Arc;
    ///
    /// // Create a shared engine cache
    /// let cache = Arc::new(EngineCache::new());
    ///
    /// // Multiple clients can share the same cache
    /// let builder1 = ClientBuilder::new("192.168.1.1:161",
    ///     Auth::usm("admin").auth(AuthProtocol::Sha256, "password"))
    ///     .engine_cache(cache.clone());
    ///
    /// let builder2 = ClientBuilder::new("192.168.1.2:161",
    ///     Auth::usm("admin").auth(AuthProtocol::Sha256, "password"))
    ///     .engine_cache(cache.clone());
    /// ```
    pub fn engine_cache(mut self, cache: Arc<EngineCache>) -> Self {
        self.engine_cache = Some(cache);
        self
    }

    /// Override the context engine ID (V3 only).
    ///
    /// By default, the context engine ID is the same as the authoritative
    /// engine ID discovered during engine discovery. Use this to override for:
    /// - Proxy scenarios where requests route through an intermediate agent
    /// - Devices that require a specific context engine ID
    /// - Pre-configured engine IDs from device documentation
    ///
    /// The engine ID should be provided as raw bytes (not hex-encoded).
    pub fn context_engine_id(mut self, engine_id: impl Into<Vec<u8>>) -> Self {
        self.context_engine_id = Some(engine_id.into());
        self
    }

    /// Validate the configuration.
    fn validate(&self) -> Result<()> {
        if let Auth::Usm(usm) = &self.auth {
            // Privacy requires authentication
            if usm.priv_protocol.is_some() && usm.auth_protocol.is_none() {
                return Err(Error::Config("privacy requires authentication".into()).boxed());
            }
            // Protocol requires password (unless using master keys)
            if usm.auth_protocol.is_some()
                && usm.auth_password.is_none()
                && usm.master_keys.is_none()
            {
                return Err(Error::Config("auth protocol requires password".into()).boxed());
            }
            if usm.priv_protocol.is_some()
                && usm.priv_password.is_none()
                && usm.master_keys.is_none()
            {
                return Err(Error::Config("priv protocol requires password".into()).boxed());
            }
        }

        // Validate walk mode for v1
        if let Auth::Community {
            version: CommunityVersion::V1,
            ..
        } = &self.auth
            && self.walk_mode == WalkMode::GetBulk
        {
            return Err(Error::Config("GETBULK not supported in SNMPv1".into()).boxed());
        }

        Ok(())
    }

    /// Resolve target address to SocketAddr.
    fn resolve_target(&self) -> Result<SocketAddr> {
        self.target
            .to_socket_addrs()
            .map_err(|e| {
                Error::Config(format!("could not resolve address '{}': {}", self.target, e).into())
                    .boxed()
            })?
            .next()
            .ok_or_else(|| {
                Error::Config(format!("could not resolve address '{}'", self.target).into()).boxed()
            })
    }

    /// Build ClientConfig from the builder settings.
    fn build_config(&self) -> ClientConfig {
        match &self.auth {
            Auth::Community { version, community } => {
                let snmp_version = match version {
                    CommunityVersion::V1 => Version::V1,
                    CommunityVersion::V2c => Version::V2c,
                };
                ClientConfig {
                    version: snmp_version,
                    community: Bytes::copy_from_slice(community.as_bytes()),
                    timeout: self.timeout,
                    retry: self.retry.clone(),
                    max_oids_per_request: self.max_oids_per_request,
                    v3_security: None,
                    walk_mode: self.walk_mode,
                    oid_ordering: self.oid_ordering,
                    max_walk_results: self.max_walk_results,
                    max_repetitions: self.max_repetitions,
                }
            }
            Auth::Usm(usm) => {
                let mut security =
                    V3SecurityConfig::new(Bytes::copy_from_slice(usm.username.as_bytes()));

                // Prefer master_keys over passwords if available
                if let Some(ref master_keys) = usm.master_keys {
                    security = security.with_master_keys(master_keys.clone());
                } else {
                    if let (Some(auth_proto), Some(auth_pass)) =
                        (usm.auth_protocol, &usm.auth_password)
                    {
                        security = security.auth(auth_proto, auth_pass.as_bytes());
                    }

                    if let (Some(priv_proto), Some(priv_pass)) =
                        (usm.priv_protocol, &usm.priv_password)
                    {
                        security = security.privacy(priv_proto, priv_pass.as_bytes());
                    }
                }

                ClientConfig {
                    version: Version::V3,
                    community: Bytes::new(),
                    timeout: self.timeout,
                    retry: self.retry.clone(),
                    max_oids_per_request: self.max_oids_per_request,
                    v3_security: Some(security),
                    walk_mode: self.walk_mode,
                    oid_ordering: self.oid_ordering,
                    max_walk_results: self.max_walk_results,
                    max_repetitions: self.max_repetitions,
                }
            }
        }
    }

    /// Build the client with the given transport.
    fn build_inner<T: Transport>(self, transport: T) -> Client<T> {
        let config = self.build_config();

        if let Some(cache) = self.engine_cache {
            Client::with_engine_cache(transport, config, cache)
        } else {
            Client::new(transport, config)
        }
    }

    /// Connect via UDP (default).
    ///
    /// Creates a new UDP socket and connects to the target address. This is the
    /// recommended connection method for most use cases due to UDP's lower
    /// overhead compared to TCP.
    ///
    /// For polling many targets, consider using a shared
    /// [`UdpTransport`](crate::transport::UdpTransport) with [`build_with()`](Self::build_with).
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid or the connection fails.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use async_snmp::{Auth, ClientBuilder};
    ///
    /// # async fn example() -> async_snmp::Result<()> {
    /// let client = ClientBuilder::new("192.168.1.1:161", Auth::v2c("public"))
    ///     .connect()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn connect(self) -> Result<Client<UdpHandle>> {
        self.validate()?;
        let addr = self.resolve_target()?;
        // Use dual-stack socket for both IPv4 and IPv6 targets
        let transport = UdpTransport::bind("[::]:0").await?;
        let handle = transport.handle(addr);
        Ok(self.build_inner(handle))
    }

    /// Build a client using a shared UDP transport.
    ///
    /// Creates a handle for the builder's target address from the given transport.
    /// This is the recommended way to create multiple clients that share a socket.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use async_snmp::{Auth, ClientBuilder};
    /// use async_snmp::transport::UdpTransport;
    ///
    /// # async fn example() -> async_snmp::Result<()> {
    /// let transport = UdpTransport::bind("0.0.0.0:0").await?;
    ///
    /// let client1 = ClientBuilder::new("192.168.1.1:161", Auth::v2c("public"))
    ///     .build_with(&transport)?;
    /// let client2 = ClientBuilder::new("192.168.1.2:161", Auth::v2c("public"))
    ///     .build_with(&transport)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn build_with(self, transport: &UdpTransport) -> Result<Client<UdpHandle>> {
        self.validate()?;
        let addr = self.resolve_target()?;
        let handle = transport.handle(addr);
        Ok(self.build_inner(handle))
    }

    /// Connect via TCP.
    ///
    /// Establishes a TCP connection to the target. Use this when:
    /// - UDP is blocked by firewalls
    /// - Messages exceed UDP's maximum datagram size
    /// - Reliable delivery is required
    ///
    /// Note that TCP has higher overhead than UDP due to connection setup
    /// and per-message framing.
    ///
    /// For advanced TCP configuration (connection timeout, keepalive, buffer
    /// sizes), construct a [`TcpTransport`] directly and use [`Client::new()`].
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid or the connection fails.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use async_snmp::{Auth, ClientBuilder};
    ///
    /// # async fn example() -> async_snmp::Result<()> {
    /// let client = ClientBuilder::new("192.168.1.1:161", Auth::v2c("public"))
    ///     .connect_tcp()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn connect_tcp(self) -> Result<Client<TcpTransport>> {
        self.validate()?;
        let addr = self.resolve_target()?;
        let transport = TcpTransport::connect(addr).await?;
        Ok(self.build_inner(transport))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v3::{AuthProtocol, MasterKeys, PrivProtocol};

    #[test]
    fn test_builder_defaults() {
        let builder = ClientBuilder::new("192.168.1.1:161", Auth::default());
        assert_eq!(builder.target, "192.168.1.1:161");
        assert_eq!(builder.timeout, Duration::from_secs(5));
        assert_eq!(builder.retry.max_attempts, 3);
        assert_eq!(builder.max_oids_per_request, 10);
        assert_eq!(builder.max_repetitions, 25);
        assert_eq!(builder.walk_mode, WalkMode::Auto);
        assert_eq!(builder.oid_ordering, OidOrdering::Strict);
        assert!(builder.max_walk_results.is_none());
        assert!(builder.engine_cache.is_none());
        assert!(builder.context_engine_id.is_none());
    }

    #[test]
    fn test_builder_with_options() {
        let cache = Arc::new(EngineCache::new());
        let builder = ClientBuilder::new("192.168.1.1:161", Auth::v2c("private"))
            .timeout(Duration::from_secs(10))
            .retry(Retry::fixed(5, Duration::ZERO))
            .max_oids_per_request(20)
            .max_repetitions(50)
            .walk_mode(WalkMode::GetNext)
            .oid_ordering(OidOrdering::AllowNonIncreasing)
            .max_walk_results(1000)
            .engine_cache(cache.clone())
            .context_engine_id(vec![0x80, 0x00, 0x01]);

        assert_eq!(builder.timeout, Duration::from_secs(10));
        assert_eq!(builder.retry.max_attempts, 5);
        assert_eq!(builder.max_oids_per_request, 20);
        assert_eq!(builder.max_repetitions, 50);
        assert_eq!(builder.walk_mode, WalkMode::GetNext);
        assert_eq!(builder.oid_ordering, OidOrdering::AllowNonIncreasing);
        assert_eq!(builder.max_walk_results, Some(1000));
        assert!(builder.engine_cache.is_some());
        assert_eq!(builder.context_engine_id, Some(vec![0x80, 0x00, 0x01]));
    }

    #[test]
    fn test_validate_community_ok() {
        let builder = ClientBuilder::new("192.168.1.1:161", Auth::v2c("public"));
        assert!(builder.validate().is_ok());
    }

    #[test]
    fn test_validate_usm_no_auth_no_priv_ok() {
        let builder = ClientBuilder::new("192.168.1.1:161", Auth::usm("readonly"));
        assert!(builder.validate().is_ok());
    }

    #[test]
    fn test_validate_usm_auth_no_priv_ok() {
        let builder = ClientBuilder::new(
            "192.168.1.1:161",
            Auth::usm("admin").auth(AuthProtocol::Sha256, "authpass"),
        );
        assert!(builder.validate().is_ok());
    }

    #[test]
    fn test_validate_usm_auth_priv_ok() {
        let builder = ClientBuilder::new(
            "192.168.1.1:161",
            Auth::usm("admin")
                .auth(AuthProtocol::Sha256, "authpass")
                .privacy(PrivProtocol::Aes128, "privpass"),
        );
        assert!(builder.validate().is_ok());
    }

    #[test]
    fn test_validate_priv_without_auth_error() {
        // Manually construct UsmAuth with priv but no auth
        let usm = crate::client::UsmAuth {
            username: "user".to_string(),
            auth_protocol: None,
            auth_password: None,
            priv_protocol: Some(PrivProtocol::Aes128),
            priv_password: Some("privpass".to_string()),
            context_name: None,
            master_keys: None,
        };
        let builder = ClientBuilder::new("192.168.1.1:161", Auth::Usm(usm));
        let err = builder.validate().unwrap_err();
        assert!(
            matches!(*err, Error::Config(ref msg) if msg.contains("privacy requires authentication"))
        );
    }

    #[test]
    fn test_validate_auth_protocol_without_password_error() {
        // Manually construct UsmAuth with auth protocol but no password
        let usm = crate::client::UsmAuth {
            username: "user".to_string(),
            auth_protocol: Some(AuthProtocol::Sha256),
            auth_password: None,
            priv_protocol: None,
            priv_password: None,
            context_name: None,
            master_keys: None,
        };
        let builder = ClientBuilder::new("192.168.1.1:161", Auth::Usm(usm));
        let err = builder.validate().unwrap_err();
        assert!(
            matches!(*err, Error::Config(ref msg) if msg.contains("auth protocol requires password"))
        );
    }

    #[test]
    fn test_validate_priv_protocol_without_password_error() {
        // Manually construct UsmAuth with priv protocol but no password
        let usm = crate::client::UsmAuth {
            username: "user".to_string(),
            auth_protocol: Some(AuthProtocol::Sha256),
            auth_password: Some("authpass".to_string()),
            priv_protocol: Some(PrivProtocol::Aes128),
            priv_password: None,
            context_name: None,
            master_keys: None,
        };
        let builder = ClientBuilder::new("192.168.1.1:161", Auth::Usm(usm));
        let err = builder.validate().unwrap_err();
        assert!(
            matches!(*err, Error::Config(ref msg) if msg.contains("priv protocol requires password"))
        );
    }

    #[test]
    fn test_builder_with_usm_builder() {
        // Test that UsmBuilder can be passed directly (via Into<Auth>)
        let builder = ClientBuilder::new(
            "192.168.1.1:161",
            Auth::usm("admin").auth(AuthProtocol::Sha256, "pass"),
        );
        assert!(builder.validate().is_ok());
    }

    #[test]
    fn test_validate_master_keys_bypass_auth_password() {
        // When master keys are set, auth password is not required
        let master_keys = MasterKeys::new(AuthProtocol::Sha256, b"authpass");
        let usm = crate::client::UsmAuth {
            username: "user".to_string(),
            auth_protocol: Some(AuthProtocol::Sha256),
            auth_password: None, // No password
            priv_protocol: None,
            priv_password: None,
            context_name: None,
            master_keys: Some(master_keys),
        };
        let builder = ClientBuilder::new("192.168.1.1:161", Auth::Usm(usm));
        assert!(builder.validate().is_ok());
    }

    #[test]
    fn test_validate_master_keys_bypass_priv_password() {
        // When master keys are set, priv password is not required
        let master_keys = MasterKeys::new(AuthProtocol::Sha256, b"authpass")
            .with_privacy(PrivProtocol::Aes128, b"privpass");
        let usm = crate::client::UsmAuth {
            username: "user".to_string(),
            auth_protocol: Some(AuthProtocol::Sha256),
            auth_password: None, // No password
            priv_protocol: Some(PrivProtocol::Aes128),
            priv_password: None, // No password
            context_name: None,
            master_keys: Some(master_keys),
        };
        let builder = ClientBuilder::new("192.168.1.1:161", Auth::Usm(usm));
        assert!(builder.validate().is_ok());
    }
}
