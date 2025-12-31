//! New unified client builder.
//!
//! This module provides the [`ClientBuilder`] type, a single entry point for
//! constructing SNMP clients with any authentication mode (v1/v2c community
//! or v3 USM).

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;

use crate::client::walk::{OidOrdering, WalkMode};
use crate::client::{Auth, CommunityVersion, ClientConfig, V3SecurityConfig};
use crate::error::Error;
use crate::transport::{TcpTransport, Transport, UdpTransport};
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
/// use async_snmp::{Auth, ClientBuilder};
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
///     .retries(5)
///     .connect().await?;
/// # Ok(())
/// # }
/// ```
pub struct ClientBuilder {
    target: String,
    auth: Auth,
    timeout: Duration,
    retries: u32,
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
            retries: 3,
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
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the number of retries (default: 3).
    pub fn retries(mut self, retries: u32) -> Self {
        self.retries = retries;
        self
    }

    /// Set the maximum OIDs per request (default: 10).
    ///
    /// Requests with more OIDs than this limit are automatically split
    /// into multiple batches.
    pub fn max_oids_per_request(mut self, max: usize) -> Self {
        self.max_oids_per_request = max;
        self
    }

    /// Set max-repetitions for GETBULK operations (default: 25).
    ///
    /// Controls how many rows are requested per GETBULK PDU during walk
    /// operations. Higher values reduce round-trips but increase response size.
    pub fn max_repetitions(mut self, max: u32) -> Self {
        self.max_repetitions = max;
        self
    }

    /// Override walk behavior for devices with buggy GETBULK (default: Auto).
    ///
    /// - `WalkMode::Auto`: Use GETNEXT for v1, GETBULK for v2c/v3
    /// - `WalkMode::GetNext`: Always use GETNEXT (slower but more compatible)
    /// - `WalkMode::GetBulk`: Always use GETBULK (faster, errors on v1)
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
    pub fn oid_ordering(mut self, ordering: OidOrdering) -> Self {
        self.oid_ordering = ordering;
        self
    }

    /// Set maximum results from a single walk operation (default: unlimited).
    ///
    /// Safety limit to prevent runaway walks. Walk terminates normally when
    /// limit is reached.
    pub fn max_walk_results(mut self, limit: usize) -> Self {
        self.max_walk_results = Some(limit);
        self
    }

    /// Set shared engine cache (V3 only, for high-throughput polling).
    ///
    /// Allows multiple clients to share discovered engine state, reducing
    /// the number of discovery requests.
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
    fn validate(&self) -> Result<(), Error> {
        if let Auth::Usm(usm) = &self.auth {
            // Privacy requires authentication
            if usm.priv_protocol.is_some() && usm.auth_protocol.is_none() {
                return Err(Error::Config("privacy requires authentication".into()));
            }
            // Protocol requires password
            if usm.auth_protocol.is_some() && usm.auth_password.is_none() {
                return Err(Error::Config("auth protocol requires password".into()));
            }
            if usm.priv_protocol.is_some() && usm.priv_password.is_none() {
                return Err(Error::Config("priv protocol requires password".into()));
            }
        }

        // Validate walk mode for v1
        if let Auth::Community { version: CommunityVersion::V1, .. } = &self.auth
            && self.walk_mode == WalkMode::GetBulk
        {
            return Err(Error::Config("GETBULK not supported in SNMPv1".into()));
        }

        Ok(())
    }

    /// Resolve target address to SocketAddr.
    fn resolve_target(&self) -> Result<SocketAddr, Error> {
        self.target
            .to_socket_addrs()
            .map_err(|e| Error::Io {
                target: None,
                source: e,
            })?
            .next()
            .ok_or_else(|| Error::Io {
                target: None,
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "could not resolve address",
                ),
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
                    retries: self.retries,
                    max_oids_per_request: self.max_oids_per_request,
                    v3_security: None,
                    walk_mode: self.walk_mode,
                    oid_ordering: self.oid_ordering,
                    max_walk_results: self.max_walk_results,
                    max_repetitions: self.max_repetitions,
                }
            }
            Auth::Usm(usm) => {
                let mut security = V3SecurityConfig::new(Bytes::copy_from_slice(usm.username.as_bytes()));

                if let (Some(auth_proto), Some(auth_pass)) = (usm.auth_protocol, &usm.auth_password) {
                    security = security.auth(auth_proto, auth_pass.as_bytes().to_vec());
                }

                if let (Some(priv_proto), Some(priv_pass)) = (usm.priv_protocol, &usm.priv_password) {
                    security = security.privacy(priv_proto, priv_pass.as_bytes().to_vec());
                }

                ClientConfig {
                    version: Version::V3,
                    community: Bytes::new(),
                    timeout: self.timeout,
                    retries: self.retries,
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
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid or the connection fails.
    pub async fn connect(self) -> Result<Client<UdpTransport>, Error> {
        self.validate()?;
        let addr = self.resolve_target()?;
        let transport = UdpTransport::connect(addr).await?;
        Ok(self.build_inner(transport))
    }

    /// Connect via TCP.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid or the connection fails.
    pub async fn connect_tcp(self) -> Result<Client<TcpTransport>, Error> {
        self.validate()?;
        let addr = self.resolve_target()?;
        let transport = TcpTransport::connect(addr).await?;
        Ok(self.build_inner(transport))
    }

    /// Build with custom transport.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid.
    pub fn build<T: Transport>(self, transport: T) -> Result<Client<T>, Error> {
        self.validate()?;
        Ok(self.build_inner(transport))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v3::{AuthProtocol, PrivProtocol};

    #[test]
    fn test_builder_defaults() {
        let builder = ClientBuilder::new("192.168.1.1:161", Auth::default());
        assert_eq!(builder.target, "192.168.1.1:161");
        assert_eq!(builder.timeout, Duration::from_secs(5));
        assert_eq!(builder.retries, 3);
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
            .retries(5)
            .max_oids_per_request(20)
            .max_repetitions(50)
            .walk_mode(WalkMode::GetNext)
            .oid_ordering(OidOrdering::AllowNonIncreasing)
            .max_walk_results(1000)
            .engine_cache(cache.clone())
            .context_engine_id(vec![0x80, 0x00, 0x01]);

        assert_eq!(builder.timeout, Duration::from_secs(10));
        assert_eq!(builder.retries, 5);
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
        };
        let builder = ClientBuilder::new("192.168.1.1:161", Auth::Usm(usm));
        let err = builder.validate().unwrap_err();
        assert!(matches!(err, Error::Config(msg) if msg.contains("privacy requires authentication")));
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
        };
        let builder = ClientBuilder::new("192.168.1.1:161", Auth::Usm(usm));
        let err = builder.validate().unwrap_err();
        assert!(matches!(err, Error::Config(msg) if msg.contains("auth protocol requires password")));
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
        };
        let builder = ClientBuilder::new("192.168.1.1:161", Auth::Usm(usm));
        let err = builder.validate().unwrap_err();
        assert!(matches!(err, Error::Config(msg) if msg.contains("priv protocol requires password")));
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
}
