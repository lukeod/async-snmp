//! Typestate builders for SNMP clients.
//!
//! This module provides type-safe builders that prevent invalid configurations
//! at compile time. For example, calling `.privacy()` before `.auth()` is a
//! compile error, not a runtime panic.
//!
//! # Entry Points
//!
//! - [`Client::v1()`] - SNMPv1 with community string
//! - [`Client::v2c()`] - SNMPv2c with community string
//! - [`Client::v3()`] - SNMPv3 with username (starts as noAuthNoPriv)
//!
//! # Examples
//!
//! ```rust,no_run
//! # use async_snmp::Client;
//! # use std::time::Duration;
//! # async fn example() -> async_snmp::Result<()> {
//! // SNMPv2c
//! let client = Client::v2c("192.168.1.1:161")
//!     .community(b"public")
//!     .timeout(Duration::from_secs(5))
//!     .connect()
//!     .await?;
//!
//! // SNMPv3 with auth and privacy
//! let client = Client::v3("192.168.1.1:161", "admin")
//!     .auth(async_snmp::v3::AuthProtocol::Sha256, "authpass123")
//!     .privacy(async_snmp::v3::PrivProtocol::Aes128, "privpass123")
//!     .connect()
//!     .await?;
//! # Ok(())
//! # }
//! ```

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;

use crate::error::{Error, Result};
use crate::transport::{TcpTransport, Transport, UdpTransport};
use crate::v3::{AuthProtocol, EngineCache, PrivProtocol};
use crate::version::Version;

use super::{Client, ClientConfig, V3SecurityConfig};

/// Common configuration shared by all builder types.
struct BaseConfig {
    target: String,
    timeout: Duration,
    retries: u32,
    max_oids_per_request: usize,
    engine_cache: Option<Arc<EngineCache>>,
}

impl Default for BaseConfig {
    fn default() -> Self {
        Self {
            target: String::new(),
            timeout: Duration::from_secs(5),
            retries: 3,
            max_oids_per_request: 10,
            engine_cache: None,
        }
    }
}

impl BaseConfig {
    fn new(target: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            ..Default::default()
        }
    }

    fn resolve_target(&self) -> Result<SocketAddr> {
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
}

// Macro to implement common builder methods
macro_rules! impl_common_methods {
    ($builder:ty) => {
        impl $builder {
            /// Set the request timeout.
            pub fn timeout(mut self, timeout: Duration) -> Self {
                self.base.timeout = timeout;
                self
            }

            /// Set the number of retries (for UDP transport).
            pub fn retries(mut self, retries: u32) -> Self {
                self.base.retries = retries;
                self
            }

            /// Set the maximum OIDs per request.
            pub fn max_oids_per_request(mut self, max: usize) -> Self {
                self.base.max_oids_per_request = max;
                self
            }
        }
    };
}

// Macro to implement V3-specific engine cache method
macro_rules! impl_engine_cache {
    ($builder:ty) => {
        impl $builder {
            /// Set a shared engine cache for V3 clients.
            ///
            /// When polling many targets, sharing an engine cache allows reuse of
            /// discovered engine IDs across clients.
            pub fn engine_cache(mut self, cache: Arc<EngineCache>) -> Self {
                self.base.engine_cache = Some(cache);
                self
            }
        }
    };
}

// ============================================================================
// V1 Client Builder
// ============================================================================

/// Builder for SNMPv1 clients.
///
/// Created via [`Client::v1()`].
pub struct V1ClientBuilder {
    base: BaseConfig,
    community: Bytes,
}

impl V1ClientBuilder {
    pub(crate) fn new(target: impl Into<String>) -> Self {
        Self {
            base: BaseConfig::new(target),
            community: Bytes::from_static(b"public"),
        }
    }

    /// Set the community string.
    pub fn community(mut self, community: &[u8]) -> Self {
        self.community = Bytes::copy_from_slice(community);
        self
    }

    /// Connect and create the client with owned UDP transport.
    pub async fn connect(self) -> Result<Client<UdpTransport>> {
        let addr = self.base.resolve_target()?;
        let transport = UdpTransport::connect(addr).await?;
        Ok(self.build(transport))
    }

    /// Connect and create the client with TCP transport.
    ///
    /// Unlike UDP, TCP guarantees delivery or failure, so the client
    /// will not retry on timeout when using this transport.
    pub async fn connect_tcp(self) -> Result<Client<TcpTransport>> {
        let addr = self.base.resolve_target()?;
        let transport = TcpTransport::connect(addr).await?;
        Ok(self.build(transport))
    }

    /// Build client with a pre-supplied transport.
    pub fn build<T: Transport>(self, transport: T) -> Client<T> {
        let config = ClientConfig {
            version: Version::V1,
            community: self.community,
            timeout: self.base.timeout,
            retries: self.base.retries,
            max_oids_per_request: self.base.max_oids_per_request,
            v3_security: None,
        };
        Client::new(transport, config)
    }
}

impl_common_methods!(V1ClientBuilder);

// ============================================================================
// V2c Client Builder
// ============================================================================

/// Builder for SNMPv2c clients.
///
/// Created via [`Client::v2c()`].
pub struct V2cClientBuilder {
    base: BaseConfig,
    community: Bytes,
}

impl V2cClientBuilder {
    pub(crate) fn new(target: impl Into<String>) -> Self {
        Self {
            base: BaseConfig::new(target),
            community: Bytes::from_static(b"public"),
        }
    }

    /// Set the community string.
    pub fn community(mut self, community: &[u8]) -> Self {
        self.community = Bytes::copy_from_slice(community);
        self
    }

    /// Connect and create the client with owned UDP transport.
    pub async fn connect(self) -> Result<Client<UdpTransport>> {
        let addr = self.base.resolve_target()?;
        let transport = UdpTransport::connect(addr).await?;
        Ok(self.build(transport))
    }

    /// Connect and create the client with TCP transport.
    ///
    /// Unlike UDP, TCP guarantees delivery or failure, so the client
    /// will not retry on timeout when using this transport.
    pub async fn connect_tcp(self) -> Result<Client<TcpTransport>> {
        let addr = self.base.resolve_target()?;
        let transport = TcpTransport::connect(addr).await?;
        Ok(self.build(transport))
    }

    /// Build client with a pre-supplied transport.
    pub fn build<T: Transport>(self, transport: T) -> Client<T> {
        let config = ClientConfig {
            version: Version::V2c,
            community: self.community,
            timeout: self.base.timeout,
            retries: self.base.retries,
            max_oids_per_request: self.base.max_oids_per_request,
            v3_security: None,
        };
        Client::new(transport, config)
    }
}

impl_common_methods!(V2cClientBuilder);

// ============================================================================
// V3 Client Builders (typestate progression)
// ============================================================================

/// Builder for SNMPv3 clients with noAuthNoPriv security.
///
/// Created via [`Client::v3()`]. Call [`.auth()`](Self::auth) to add authentication.
pub struct V3ClientBuilder {
    base: BaseConfig,
    username: Bytes,
}

impl V3ClientBuilder {
    pub(crate) fn new(target: impl Into<String>, username: impl Into<Bytes>) -> Self {
        Self {
            base: BaseConfig::new(target),
            username: username.into(),
        }
    }

    /// Add authentication protocol and password.
    ///
    /// This transitions to [`V3AuthClientBuilder`] with authNoPriv security level.
    pub fn auth(self, protocol: AuthProtocol, password: impl Into<Vec<u8>>) -> V3AuthClientBuilder {
        V3AuthClientBuilder {
            base: self.base,
            username: self.username,
            auth_protocol: protocol,
            auth_password: password.into(),
        }
    }

    /// Connect and create the client with owned UDP transport.
    ///
    /// Creates a noAuthNoPriv client.
    pub async fn connect(self) -> Result<Client<UdpTransport>> {
        let addr = self.base.resolve_target()?;
        let transport = UdpTransport::connect(addr).await?;
        Ok(self.build(transport))
    }

    /// Connect and create the client with TCP transport.
    ///
    /// Unlike UDP, TCP guarantees delivery or failure, so the client
    /// will not retry on timeout when using this transport.
    ///
    /// Creates a noAuthNoPriv client.
    pub async fn connect_tcp(self) -> Result<Client<TcpTransport>> {
        let addr = self.base.resolve_target()?;
        let transport = TcpTransport::connect(addr).await?;
        Ok(self.build(transport))
    }

    /// Build client with a pre-supplied transport.
    ///
    /// Creates a noAuthNoPriv client.
    pub fn build<T: Transport>(self, transport: T) -> Client<T> {
        let security = V3SecurityConfig::new(self.username);
        let config = ClientConfig {
            version: Version::V3,
            community: Bytes::new(),
            timeout: self.base.timeout,
            retries: self.base.retries,
            max_oids_per_request: self.base.max_oids_per_request,
            v3_security: Some(security),
        };

        if let Some(cache) = self.base.engine_cache {
            Client::with_engine_cache(transport, config, cache)
        } else {
            Client::new(transport, config)
        }
    }
}

impl_common_methods!(V3ClientBuilder);
impl_engine_cache!(V3ClientBuilder);

/// Builder for SNMPv3 clients with authNoPriv security.
///
/// Created from [`V3ClientBuilder::auth()`]. Call [`.privacy()`](Self::privacy)
/// to add encryption.
pub struct V3AuthClientBuilder {
    base: BaseConfig,
    username: Bytes,
    auth_protocol: AuthProtocol,
    auth_password: Vec<u8>,
}

impl V3AuthClientBuilder {
    /// Add privacy (encryption) protocol and password.
    ///
    /// This transitions to [`V3AuthPrivClientBuilder`] with authPriv security level.
    pub fn privacy(
        self,
        protocol: PrivProtocol,
        password: impl Into<Vec<u8>>,
    ) -> V3AuthPrivClientBuilder {
        V3AuthPrivClientBuilder {
            base: self.base,
            username: self.username,
            auth_protocol: self.auth_protocol,
            auth_password: self.auth_password,
            priv_protocol: protocol,
            priv_password: password.into(),
        }
    }

    /// Connect and create the client with owned UDP transport.
    ///
    /// Creates an authNoPriv client.
    pub async fn connect(self) -> Result<Client<UdpTransport>> {
        let addr = self.base.resolve_target()?;
        let transport = UdpTransport::connect(addr).await?;
        Ok(self.build(transport))
    }

    /// Connect and create the client with TCP transport.
    ///
    /// Unlike UDP, TCP guarantees delivery or failure, so the client
    /// will not retry on timeout when using this transport.
    ///
    /// Creates an authNoPriv client.
    pub async fn connect_tcp(self) -> Result<Client<TcpTransport>> {
        let addr = self.base.resolve_target()?;
        let transport = TcpTransport::connect(addr).await?;
        Ok(self.build(transport))
    }

    /// Build client with a pre-supplied transport.
    ///
    /// Creates an authNoPriv client.
    pub fn build<T: Transport>(self, transport: T) -> Client<T> {
        let security =
            V3SecurityConfig::new(self.username).auth(self.auth_protocol, self.auth_password);
        let config = ClientConfig {
            version: Version::V3,
            community: Bytes::new(),
            timeout: self.base.timeout,
            retries: self.base.retries,
            max_oids_per_request: self.base.max_oids_per_request,
            v3_security: Some(security),
        };

        if let Some(cache) = self.base.engine_cache {
            Client::with_engine_cache(transport, config, cache)
        } else {
            Client::new(transport, config)
        }
    }
}

impl_common_methods!(V3AuthClientBuilder);
impl_engine_cache!(V3AuthClientBuilder);

/// Builder for SNMPv3 clients with authPriv security.
///
/// Created from [`V3AuthClientBuilder::privacy()`].
pub struct V3AuthPrivClientBuilder {
    base: BaseConfig,
    username: Bytes,
    auth_protocol: AuthProtocol,
    auth_password: Vec<u8>,
    priv_protocol: PrivProtocol,
    priv_password: Vec<u8>,
}

impl V3AuthPrivClientBuilder {
    /// Connect and create the client with owned UDP transport.
    ///
    /// Creates an authPriv client.
    pub async fn connect(self) -> Result<Client<UdpTransport>> {
        let addr = self.base.resolve_target()?;
        let transport = UdpTransport::connect(addr).await?;
        Ok(self.build(transport))
    }

    /// Connect and create the client with TCP transport.
    ///
    /// Unlike UDP, TCP guarantees delivery or failure, so the client
    /// will not retry on timeout when using this transport.
    ///
    /// Creates an authPriv client.
    pub async fn connect_tcp(self) -> Result<Client<TcpTransport>> {
        let addr = self.base.resolve_target()?;
        let transport = TcpTransport::connect(addr).await?;
        Ok(self.build(transport))
    }

    /// Build client with a pre-supplied transport.
    ///
    /// Creates an authPriv client.
    pub fn build<T: Transport>(self, transport: T) -> Client<T> {
        let security = V3SecurityConfig::new(self.username)
            .auth(self.auth_protocol, self.auth_password)
            .privacy(self.priv_protocol, self.priv_password);
        let config = ClientConfig {
            version: Version::V3,
            community: Bytes::new(),
            timeout: self.base.timeout,
            retries: self.base.retries,
            max_oids_per_request: self.base.max_oids_per_request,
            v3_security: Some(security),
        };

        if let Some(cache) = self.base.engine_cache {
            Client::with_engine_cache(transport, config, cache)
        } else {
            Client::new(transport, config)
        }
    }
}

impl_common_methods!(V3AuthPrivClientBuilder);
impl_engine_cache!(V3AuthPrivClientBuilder);

// ============================================================================
// Entry points on Client
// ============================================================================

impl Client<UdpTransport> {
    /// Create an SNMPv1 client builder.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use async_snmp::Client;
    /// # async fn example() -> async_snmp::Result<()> {
    /// let client = Client::v1("192.168.1.1:161")
    ///     .community(b"public")
    ///     .connect()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn v1(target: impl Into<String>) -> V1ClientBuilder {
        V1ClientBuilder::new(target)
    }

    /// Create an SNMPv2c client builder.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use async_snmp::Client;
    /// # async fn example() -> async_snmp::Result<()> {
    /// let client = Client::v2c("192.168.1.1:161")
    ///     .community(b"public")
    ///     .connect()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn v2c(target: impl Into<String>) -> V2cClientBuilder {
        V2cClientBuilder::new(target)
    }

    /// Create an SNMPv3 client builder.
    ///
    /// The client starts with noAuthNoPriv security level. Use [`.auth()`](V3ClientBuilder::auth)
    /// to add authentication, and [`.privacy()`](V3AuthClientBuilder::privacy) to add encryption.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use async_snmp::Client;
    /// # async fn example() -> async_snmp::Result<()> {
    /// // noAuthNoPriv
    /// let client = Client::v3("192.168.1.1:161", "noauth_user")
    ///     .connect()
    ///     .await?;
    ///
    /// // authNoPriv
    /// let client = Client::v3("192.168.1.1:161", "auth_user")
    ///     .auth(async_snmp::v3::AuthProtocol::Sha256, "authpass")
    ///     .connect()
    ///     .await?;
    ///
    /// // authPriv
    /// let client = Client::v3("192.168.1.1:161", "priv_user")
    ///     .auth(async_snmp::v3::AuthProtocol::Sha256, "authpass")
    ///     .privacy(async_snmp::v3::PrivProtocol::Aes128, "privpass")
    ///     .connect()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn v3(target: impl Into<String>, username: impl Into<Bytes>) -> V3ClientBuilder {
        V3ClientBuilder::new(target, username)
    }
}
