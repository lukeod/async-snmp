//! New unified client builder.
//!
//! This module provides the [`ClientBuilder`] type, a single entry point for
//! constructing SNMP clients with any authentication mode (v1/v2c community
//! or v3 USM).

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;

use crate::client::retry::Retry;
use crate::client::walk::{OidOrdering, WalkMode};
use crate::client::{
    Auth, ClientConfig, CommunityVersion, DEFAULT_MAX_OIDS_PER_REQUEST, DEFAULT_MAX_REPETITIONS,
    DEFAULT_TIMEOUT, UsmConfig,
};
use crate::error::{Error, Result};
use crate::transport::{TcpTransport, Transport, UdpHandle, UdpTransport};
use crate::v3::EngineCache;
use crate::version::Version;

use super::Client;

/// Target address for an SNMP client.
///
/// Specifies where to connect. Accepts either a combined address string
/// or a separate host and port, which is useful when host and port are
/// stored independently (avoids needing to format IPv6 bracket syntax).
///
/// # Examples
///
/// ```rust
/// use async_snmp::Target;
///
/// // From a string (port defaults to 161 if omitted)
/// let t: Target = "192.168.1.1:161".into();
/// let t: Target = "switch.local".into();
///
/// // From a (host, port) tuple - no bracket formatting needed for IPv6
/// let t: Target = ("fe80::1", 161).into();
/// let t: Target = ("switch.local".to_string(), 162).into();
///
/// // From a SocketAddr
/// let t: Target = "192.168.1.1:161".parse::<std::net::SocketAddr>().unwrap().into();
/// ```
#[derive(Debug, Clone)]
pub enum Target {
    /// A combined address string, e.g. `"192.168.1.1:161"` or `"[::1]:162"`.
    /// Port defaults to 161 if not specified.
    Address(String),
    /// A separate host and port, e.g. `("fe80::1", 161)`.
    HostPort(String, u16),
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Target::Address(addr) => f.write_str(addr),
            Target::HostPort(host, port) => {
                if host.contains(':') && !(host.starts_with('[') && host.ends_with(']')) {
                    write!(f, "[{}]:{}", host, port)
                } else {
                    write!(f, "{}:{}", host, port)
                }
            }
        }
    }
}

impl From<&str> for Target {
    fn from(s: &str) -> Self {
        Target::Address(s.to_string())
    }
}

impl From<String> for Target {
    fn from(s: String) -> Self {
        Target::Address(s)
    }
}

impl From<&String> for Target {
    fn from(s: &String) -> Self {
        Target::Address(s.clone())
    }
}

impl From<(&str, u16)> for Target {
    fn from((host, port): (&str, u16)) -> Self {
        Target::HostPort(host.to_string(), port)
    }
}

impl From<(String, u16)> for Target {
    fn from((host, port): (String, u16)) -> Self {
        Target::HostPort(host, port)
    }
}

impl From<SocketAddr> for Target {
    fn from(addr: SocketAddr) -> Self {
        Target::HostPort(addr.ip().to_string(), addr.port())
    }
}

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
/// // Using separate host and port (convenient for IPv6)
/// let client = ClientBuilder::new(("fe80::1", 161), Auth::v2c("public"))
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
    target: Target,
    auth: Auth,
    timeout: Duration,
    retry: Retry,
    max_oids_per_request: usize,
    max_repetitions: u32,
    walk_mode: WalkMode,
    oid_ordering: OidOrdering,
    max_walk_results: Option<usize>,
    engine_cache: Option<Arc<EngineCache>>,
}

impl ClientBuilder {
    /// Create a new client builder.
    ///
    /// # Arguments
    ///
    /// * `target` - The target address. Accepts a string (e.g., `"192.168.1.1"` or
    ///   `"192.168.1.1:161"`), a `(host, port)` tuple (e.g., `("fe80::1", 161)`),
    ///   or a [`SocketAddr`](std::net::SocketAddr). Port defaults to 161 if not
    ///   specified. IPv6 addresses are supported as bare (`::1`) or bracketed
    ///   (`[::1]:162`) forms.
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
    /// // Using separate host and port
    /// let builder = ClientBuilder::new(("192.168.1.1", 161), Auth::default());
    ///
    /// // Using Auth::v1() for SNMPv1
    /// let builder = ClientBuilder::new("192.168.1.1:161", Auth::v1("private"));
    ///
    /// // Using Auth::usm() for SNMPv3
    /// let builder = ClientBuilder::new("192.168.1.1:161",
    ///     Auth::usm("admin").auth(async_snmp::AuthProtocol::Sha256, "password"));
    /// ```
    pub fn new(target: impl Into<Target>, auth: impl Into<Auth>) -> Self {
        Self {
            target: target.into(),
            auth: auth.into(),
            timeout: DEFAULT_TIMEOUT,
            retry: Retry::default(),
            max_oids_per_request: DEFAULT_MAX_OIDS_PER_REQUEST,
            max_repetitions: DEFAULT_MAX_REPETITIONS,
            walk_mode: WalkMode::Auto,
            oid_ordering: OidOrdering::Strict,
            max_walk_results: None,
            engine_cache: None,
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

    /// Set the retry configuration (default: 3 retries, 1-second delay).
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
    /// of OIDs they can handle in a single request. Values must be greater
    /// than zero.
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

    /// Validate the configuration.
    fn validate(&self) -> Result<()> {
        if self.max_oids_per_request == 0 {
            return Err(
                Error::Config("max_oids_per_request must be greater than 0".into()).boxed(),
            );
        }

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

        // AllowNonIncreasing uses O(n) memory for cycle detection; require a bound
        if self.oid_ordering == OidOrdering::AllowNonIncreasing && self.max_walk_results.is_none() {
            return Err(Error::Config(
                "AllowNonIncreasing requires max_walk_results to bound memory usage".into(),
            )
            .boxed());
        }

        Ok(())
    }

    /// Resolve target address to SocketAddr, defaulting to port 161.
    ///
    /// Accepts IPv4 (`192.168.1.1`, `192.168.1.1:162`), IPv6 (`::1`,
    /// `[::1]:162`), hostnames (`switch.local`, `switch.local:162`), and
    /// `(host, port)` tuples. When no port is specified, SNMP port 161 is used.
    ///
    /// IP addresses are parsed directly without DNS. Hostnames are resolved
    /// asynchronously via `tokio::net::lookup_host`, bounded by the builder's
    /// configured timeout. To bypass DNS entirely, pass a resolved IP address.
    async fn resolve_target(&self) -> Result<SocketAddr> {
        let (host, port) = match &self.target {
            Target::Address(addr) => split_host_port(addr),
            Target::HostPort(host, port) => (host.as_str(), *port),
        };

        // Try direct parse first to avoid unnecessary async DNS lookup
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            return Ok(SocketAddr::new(ip, port));
        }

        let lookup = tokio::net::lookup_host((host, port));
        let mut addrs = tokio::time::timeout(self.timeout, lookup)
            .await
            .map_err(|_| {
                Error::Config(format!("DNS lookup timed out for '{}'", self.target).into()).boxed()
            })?
            .map_err(|e| {
                Error::Config(format!("could not resolve address '{}': {}", self.target, e).into())
                    .boxed()
            })?;

        addrs.next().ok_or_else(|| {
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
                let mut security = UsmConfig::new(Bytes::copy_from_slice(usm.username.as_bytes()));
                if let Some(context_name) = &usm.context_name {
                    security =
                        security.context_name(Bytes::copy_from_slice(context_name.as_bytes()));
                }

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
        let addr = self.resolve_target().await?;
        // Match bind address to target address family for cross-platform
        // compatibility. Dual-stack ([::]:0) only works reliably on Linux;
        // macOS/BSD default to IPV6_V6ONLY=1 and reject IPv4 targets.
        let bind_addr = if addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let transport = UdpTransport::bind(bind_addr).await?;
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
    ///     .build_with(&transport).await?;
    /// let client2 = ClientBuilder::new("192.168.1.2:161", Auth::v2c("public"))
    ///     .build_with(&transport).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn build_with(self, transport: &UdpTransport) -> Result<Client<UdpHandle>> {
        self.validate()?;
        let addr = self.resolve_target().await?;
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
        let addr = self.resolve_target().await?;
        let transport = TcpTransport::connect(addr).await?;
        Ok(self.build_inner(transport))
    }
}

/// Default SNMP port.
const DEFAULT_PORT: u16 = 161;

/// Split a target string into (host, port), defaulting to port 161.
///
/// Handles IPv4 (`192.168.1.1`), IPv4 with port (`192.168.1.1:162`),
/// bare IPv6 (`fe80::1`), bracketed IPv6 (`[::1]`, `[::1]:162`),
/// and hostnames (`switch.local`, `switch.local:162`).
fn split_host_port(target: &str) -> (&str, u16) {
    // Bracketed IPv6: [addr]:port or [addr]
    if let Some(rest) = target.strip_prefix('[') {
        if let Some((addr, port)) = rest.rsplit_once("]:")
            && let Ok(p) = port.parse()
        {
            return (addr, p);
        }
        return (rest.trim_end_matches(']'), DEFAULT_PORT);
    }

    // IPv4 or hostname: last colon is the port separator, but only if the
    // host part doesn't also contain colons (which would make it bare IPv6)
    if let Some((host, port)) = target.rsplit_once(':')
        && !host.contains(':')
        && let Ok(p) = port.parse::<u16>()
    {
        return (host, p);
    }

    // No port found (bare IPv4, IPv6, or hostname)
    (target, DEFAULT_PORT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v3::{AuthProtocol, MasterKeys, PrivProtocol};

    #[test]
    fn test_builder_defaults() {
        let builder = ClientBuilder::new("192.168.1.1:161", Auth::default());
        assert!(matches!(builder.target, Target::Address(ref s) if s == "192.168.1.1:161"));
        assert_eq!(builder.timeout, DEFAULT_TIMEOUT);
        assert_eq!(builder.retry.max_attempts, 3);
        assert_eq!(builder.max_oids_per_request, DEFAULT_MAX_OIDS_PER_REQUEST);
        assert_eq!(builder.max_repetitions, DEFAULT_MAX_REPETITIONS);
        assert_eq!(builder.walk_mode, WalkMode::Auto);
        assert_eq!(builder.oid_ordering, OidOrdering::Strict);
        assert!(builder.max_walk_results.is_none());
        assert!(builder.engine_cache.is_none());
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
            .engine_cache(cache.clone());

        assert_eq!(builder.timeout, Duration::from_secs(10));
        assert_eq!(builder.retry.max_attempts, 5);
        assert_eq!(builder.max_oids_per_request, 20);
        assert_eq!(builder.max_repetitions, 50);
        assert_eq!(builder.walk_mode, WalkMode::GetNext);
        assert_eq!(builder.oid_ordering, OidOrdering::AllowNonIncreasing);
        assert_eq!(builder.max_walk_results, Some(1000));
        assert!(builder.engine_cache.is_some());
    }

    #[test]
    fn test_validate_community_ok() {
        let builder = ClientBuilder::new("192.168.1.1:161", Auth::v2c("public"));
        assert!(builder.validate().is_ok());
    }

    #[test]
    fn test_validate_zero_max_oids_per_request_error() {
        let builder =
            ClientBuilder::new("192.168.1.1:161", Auth::v2c("public")).max_oids_per_request(0);
        let err = builder.validate().unwrap_err();
        assert!(matches!(
            *err,
            Error::Config(ref msg) if msg.contains("max_oids_per_request must be greater than 0")
        ));
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
        let master_keys = MasterKeys::new(AuthProtocol::Sha256, b"authpass").unwrap();
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
            .unwrap()
            .with_privacy(PrivProtocol::Aes128, b"privpass")
            .unwrap();
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

    #[test]
    fn test_build_config_preserves_v3_context_name() {
        let builder = ClientBuilder::new(
            "192.168.1.1:161",
            Auth::usm("admin")
                .auth(AuthProtocol::Sha256, "authpass")
                .context_name("vlan100"),
        );

        let config = builder.build_config();
        let security = config
            .v3_security
            .expect("expected v3 security config to be built");

        assert_eq!(security.context_name.as_ref(), b"vlan100");
    }

    #[test]
    fn test_builder_with_host_port_tuple() {
        let builder = ClientBuilder::new(("fe80::1", 161), Auth::default());
        assert!(matches!(
            builder.target,
            Target::HostPort(ref h, 161) if h == "fe80::1"
        ));
    }

    #[test]
    fn test_builder_with_string_host_port_tuple() {
        let builder = ClientBuilder::new(("switch.local".to_string(), 162), Auth::v2c("public"));
        assert!(matches!(
            builder.target,
            Target::HostPort(ref h, 162) if h == "switch.local"
        ));
    }

    #[test]
    fn test_target_from_str() {
        let t: Target = "192.168.1.1:161".into();
        assert!(matches!(t, Target::Address(ref s) if s == "192.168.1.1:161"));
    }

    #[test]
    fn test_target_from_tuple() {
        let t: Target = ("fe80::1", 161).into();
        assert!(matches!(t, Target::HostPort(ref h, 161) if h == "fe80::1"));
    }

    #[test]
    fn test_target_from_socket_addr() {
        let addr: SocketAddr = "192.168.1.1:162".parse().unwrap();
        let t: Target = addr.into();
        assert!(matches!(t, Target::HostPort(ref h, 162) if h == "192.168.1.1"));
    }

    #[test]
    fn test_target_display() {
        let t: Target = "192.168.1.1:161".into();
        assert_eq!(t.to_string(), "192.168.1.1:161");

        let t: Target = ("fe80::1", 161).into();
        assert_eq!(t.to_string(), "[fe80::1]:161");

        let addr: SocketAddr = "[::1]:162".parse().unwrap();
        let t: Target = addr.into();
        assert_eq!(t.to_string(), "[::1]:162");
    }

    #[tokio::test]
    async fn test_resolve_target_socket_addr() {
        let addr: SocketAddr = "10.0.0.1:162".parse().unwrap();
        let builder = ClientBuilder::new(addr, Auth::default());
        let resolved = builder.resolve_target().await.unwrap();
        assert_eq!(resolved, addr);
    }

    #[tokio::test]
    async fn test_resolve_target_host_port_ipv4() {
        let builder = ClientBuilder::new(("192.168.1.1", 162), Auth::default());
        let addr = builder.resolve_target().await.unwrap();
        assert_eq!(addr, "192.168.1.1:162".parse().unwrap());
    }

    #[tokio::test]
    async fn test_resolve_target_host_port_ipv6() {
        let builder = ClientBuilder::new(("::1", 161), Auth::default());
        let addr = builder.resolve_target().await.unwrap();
        assert_eq!(addr, "[::1]:161".parse().unwrap());
    }

    #[tokio::test]
    async fn test_resolve_target_string_still_works() {
        let builder = ClientBuilder::new("10.0.0.1:162", Auth::default());
        let addr = builder.resolve_target().await.unwrap();
        assert_eq!(addr, "10.0.0.1:162".parse().unwrap());
    }

    #[test]
    fn test_split_host_port_ipv4_with_port() {
        assert_eq!(split_host_port("192.168.1.1:162"), ("192.168.1.1", 162));
    }

    #[test]
    fn test_split_host_port_ipv4_default() {
        assert_eq!(split_host_port("192.168.1.1"), ("192.168.1.1", 161));
    }

    #[test]
    fn test_split_host_port_ipv6_bare() {
        assert_eq!(split_host_port("fe80::1"), ("fe80::1", 161));
    }

    #[test]
    fn test_split_host_port_ipv6_loopback() {
        assert_eq!(split_host_port("::1"), ("::1", 161));
    }

    #[test]
    fn test_split_host_port_ipv6_bracketed_with_port() {
        assert_eq!(split_host_port("[fe80::1]:162"), ("fe80::1", 162));
    }

    #[test]
    fn test_split_host_port_ipv6_bracketed_default() {
        assert_eq!(split_host_port("[::1]"), ("::1", 161));
    }

    #[test]
    fn test_split_host_port_hostname() {
        assert_eq!(split_host_port("switch.local"), ("switch.local", 161));
    }

    #[test]
    fn test_split_host_port_hostname_with_port() {
        assert_eq!(split_host_port("switch.local:162"), ("switch.local", 162));
    }
}
