//! SNMP Agent (RFC 3413).
//!
//! This module provides SNMP agent functionality for responding to
//! GET, GETNEXT, GETBULK, and SET requests.
//!
//! # Features
//!
//! - **Async handlers**: All handler methods are async for database queries, network calls, etc.
//! - **Atomic SET**: Two-phase commit protocol (test/commit/undo) per RFC 3416
//! - **VACM support**: Optional View-based Access Control Model (RFC 3415)
//!
//! # Example
//!
//! ```rust,no_run
//! use async_snmp::agent::Agent;
//! use async_snmp::handler::{MibHandler, RequestContext, GetResult, GetNextResult, BoxFuture};
//! use async_snmp::{Oid, Value, VarBind, oid};
//! use std::sync::Arc;
//!
//! // Define a simple handler for the system MIB subtree
//! struct SystemMibHandler;
//!
//! impl MibHandler for SystemMibHandler {
//!     fn get<'a>(&'a self, _ctx: &'a RequestContext, oid: &'a Oid) -> BoxFuture<'a, GetResult> {
//!         Box::pin(async move {
//!             // sysDescr.0
//!             if oid == &oid!(1, 3, 6, 1, 2, 1, 1, 1, 0) {
//!                 return GetResult::Value(Value::OctetString("My SNMP Agent".into()));
//!             }
//!             // sysObjectID.0
//!             if oid == &oid!(1, 3, 6, 1, 2, 1, 1, 2, 0) {
//!                 return GetResult::Value(Value::ObjectIdentifier(oid!(1, 3, 6, 1, 4, 1, 99999)));
//!             }
//!             GetResult::NoSuchObject
//!         })
//!     }
//!
//!     fn get_next<'a>(&'a self, _ctx: &'a RequestContext, oid: &'a Oid) -> BoxFuture<'a, GetNextResult> {
//!         Box::pin(async move {
//!             // Return the lexicographically next OID after the given one
//!             let sys_descr = oid!(1, 3, 6, 1, 2, 1, 1, 1, 0);
//!             let sys_object_id = oid!(1, 3, 6, 1, 2, 1, 1, 2, 0);
//!
//!             if oid < &sys_descr {
//!                 return GetNextResult::Value(VarBind::new(sys_descr, Value::OctetString("My SNMP Agent".into())));
//!             }
//!             if oid < &sys_object_id {
//!                 return GetNextResult::Value(VarBind::new(sys_object_id, Value::ObjectIdentifier(oid!(1, 3, 6, 1, 4, 1, 99999))));
//!             }
//!             GetNextResult::EndOfMibView
//!         })
//!     }
//! }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), async_snmp::Error> {
//!     let agent = Agent::builder()
//!         .bind("0.0.0.0:161")
//!         .community(b"public")
//!         .handler(oid!(1, 3, 6, 1, 2, 1, 1), Arc::new(SystemMibHandler))
//!         .build()
//!         .await?;
//!
//!     agent.run().await
//! }
//! ```

mod request;
mod response;
mod set_handler;
pub mod vacm;

pub use vacm::{SecurityModel, VacmBuilder, VacmConfig, View, ViewCheckResult, ViewSubtree};

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;

use bytes::Bytes;
use subtle::ConstantTimeEq;
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tracing::instrument;

use crate::ber::Decoder;
use crate::error::{DecodeErrorKind, Error, ErrorStatus, Result};
use crate::handler::{GetNextResult, GetResult, MibHandler, RequestContext};
use crate::notification::UsmUserConfig;
use crate::oid::Oid;
use crate::pdu::{Pdu, PduType};
use crate::util::bind_udp_socket;
use crate::v3::SaltCounter;
use crate::value::Value;
use crate::varbind::VarBind;
use crate::version::Version;

/// Default maximum message size for UDP (RFC 3417 recommendation).
const DEFAULT_MAX_MESSAGE_SIZE: usize = 1472;

/// Overhead for SNMP message encoding (approximate conservative estimate).
/// This accounts for version, community/USM, PDU headers, etc.
const RESPONSE_OVERHEAD: usize = 100;

/// Registered handler with its OID prefix.
pub(crate) struct RegisteredHandler {
    pub(crate) prefix: Oid,
    pub(crate) handler: Arc<dyn MibHandler>,
}

/// Builder for [`Agent`].
///
/// Use this builder to configure and construct an SNMP agent. The builder
/// pattern allows you to chain configuration methods before calling
/// [`build()`](AgentBuilder::build) to create the agent.
///
/// # Minimal Example
///
/// ```rust,no_run
/// use async_snmp::agent::Agent;
/// use async_snmp::handler::{MibHandler, RequestContext, GetResult, GetNextResult, BoxFuture};
/// use async_snmp::{Oid, Value, VarBind, oid};
/// use std::sync::Arc;
///
/// struct MyHandler;
/// impl MibHandler for MyHandler {
///     fn get<'a>(&'a self, _: &'a RequestContext, _: &'a Oid) -> BoxFuture<'a, GetResult> {
///         Box::pin(async { GetResult::NoSuchObject })
///     }
///     fn get_next<'a>(&'a self, _: &'a RequestContext, _: &'a Oid) -> BoxFuture<'a, GetNextResult> {
///         Box::pin(async { GetNextResult::EndOfMibView })
///     }
/// }
///
/// # async fn example() -> Result<(), async_snmp::Error> {
/// let agent = Agent::builder()
///     .bind("0.0.0.0:1161")  // Use non-privileged port
///     .community(b"public")
///     .handler(oid!(1, 3, 6, 1, 4, 1, 99999), Arc::new(MyHandler))
///     .build()
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct AgentBuilder {
    bind_addr: String,
    communities: Vec<Vec<u8>>,
    usm_users: HashMap<Bytes, UsmUserConfig>,
    handlers: Vec<RegisteredHandler>,
    engine_id: Option<Vec<u8>>,
    max_message_size: usize,
    max_concurrent_requests: Option<usize>,
    recv_buffer_size: Option<usize>,
    vacm: Option<VacmConfig>,
    cancel: Option<CancellationToken>,
}

impl AgentBuilder {
    /// Create a new builder with default settings.
    ///
    /// Defaults:
    /// - Bind address: `0.0.0.0:161` (UDP)
    /// - Max message size: 1472 bytes (Ethernet MTU - IP/UDP headers)
    /// - Max concurrent requests: 1000
    /// - Receive buffer size: 4MB (requested from kernel)
    /// - No communities or USM users (all requests rejected)
    /// - No handlers registered
    pub fn new() -> Self {
        Self {
            bind_addr: "0.0.0.0:161".to_string(),
            communities: Vec::new(),
            usm_users: HashMap::new(),
            handlers: Vec::new(),
            engine_id: None,
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            max_concurrent_requests: Some(1000),
            recv_buffer_size: Some(4 * 1024 * 1024), // 4MB
            vacm: None,
            cancel: None,
        }
    }

    /// Set the UDP bind address.
    ///
    /// Default is `0.0.0.0:161` (standard SNMP agent port). Note that binding
    /// to UDP port 161 typically requires root/administrator privileges.
    ///
    /// # IPv4 Examples
    ///
    /// ```rust,no_run
    /// use async_snmp::agent::Agent;
    ///
    /// # async fn example() -> Result<(), async_snmp::Error> {
    /// // Bind to all IPv4 interfaces on standard port (requires privileges)
    /// let agent = Agent::builder().bind("0.0.0.0:161").community(b"public").build().await?;
    ///
    /// // Bind to localhost only on non-privileged port
    /// let agent = Agent::builder().bind("127.0.0.1:1161").community(b"public").build().await?;
    ///
    /// // Bind to specific interface
    /// let agent = Agent::builder().bind("192.168.1.100:161").community(b"public").build().await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # IPv6 / Dual-Stack Examples
    ///
    /// ```rust,no_run
    /// use async_snmp::agent::Agent;
    ///
    /// # async fn example() -> Result<(), async_snmp::Error> {
    /// // Bind to all interfaces via dual-stack (handles both IPv4 and IPv6)
    /// let agent = Agent::builder().bind("[::]:161").community(b"public").build().await?;
    ///
    /// // Bind to IPv6 localhost only
    /// let agent = Agent::builder().bind("[::1]:1161").community(b"public").build().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn bind(mut self, addr: impl Into<String>) -> Self {
        self.bind_addr = addr.into();
        self
    }

    /// Add an accepted community string for v1/v2c requests.
    ///
    /// Multiple communities can be added. If none are added,
    /// all v1/v2c requests are rejected.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use async_snmp::agent::Agent;
    ///
    /// # async fn example() -> Result<(), async_snmp::Error> {
    /// let agent = Agent::builder()
    ///     .bind("0.0.0.0:1161")
    ///     .community(b"public")   // Read-only access
    ///     .community(b"private")  // Read-write access (with VACM)
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn community(mut self, community: &[u8]) -> Self {
        self.communities.push(community.to_vec());
        self
    }

    /// Add multiple community strings.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use async_snmp::agent::Agent;
    ///
    /// # async fn example() -> Result<(), async_snmp::Error> {
    /// let communities = ["public", "private", "monitor"];
    /// let agent = Agent::builder()
    ///     .bind("0.0.0.0:1161")
    ///     .communities(communities)
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn communities<I, C>(mut self, communities: I) -> Self
    where
        I: IntoIterator<Item = C>,
        C: AsRef<[u8]>,
    {
        for c in communities {
            self.communities.push(c.as_ref().to_vec());
        }
        self
    }

    /// Add a USM user for SNMPv3 authentication.
    ///
    /// Configure authentication and privacy settings using the closure.
    /// Multiple users can be added with different security levels.
    ///
    /// # Security Levels
    ///
    /// - **noAuthNoPriv**: No authentication or encryption (not recommended)
    /// - **authNoPriv**: Authentication only (HMAC verification)
    /// - **authPriv**: Authentication and encryption (most secure)
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use async_snmp::agent::Agent;
    /// use async_snmp::{AuthProtocol, PrivProtocol};
    ///
    /// # async fn example() -> Result<(), async_snmp::Error> {
    /// let agent = Agent::builder()
    ///     .bind("0.0.0.0:1161")
    ///     // Read-only user with authentication only
    ///     .usm_user("monitor", |u| {
    ///         u.auth(AuthProtocol::Sha256, b"monitorpass123")
    ///     })
    ///     // Admin user with full encryption
    ///     .usm_user("admin", |u| {
    ///         u.auth(AuthProtocol::Sha256, b"adminauth123")
    ///          .privacy(PrivProtocol::Aes128, b"adminpriv123")
    ///     })
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn usm_user<F>(mut self, username: impl Into<Bytes>, configure: F) -> Self
    where
        F: FnOnce(UsmUserConfig) -> UsmUserConfig,
    {
        let username_bytes: Bytes = username.into();
        let config = configure(UsmUserConfig::new(username_bytes.clone()));
        self.usm_users.insert(username_bytes, config);
        self
    }

    /// Set the engine ID for SNMPv3.
    ///
    /// If not set, a default engine ID will be generated based on the
    /// RFC 3411 format using enterprise number and timestamp.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use async_snmp::agent::Agent;
    ///
    /// # async fn example() -> Result<(), async_snmp::Error> {
    /// let agent = Agent::builder()
    ///     .bind("0.0.0.0:1161")
    ///     .engine_id(b"\x80\x00\x00\x00\x01MyEngine".to_vec())
    ///     .community(b"public")
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn engine_id(mut self, engine_id: impl Into<Vec<u8>>) -> Self {
        self.engine_id = Some(engine_id.into());
        self
    }

    /// Set the maximum message size for responses.
    ///
    /// Default is 1472 octets (fits Ethernet MTU minus IP/UDP headers).
    /// GETBULK responses will be truncated to fit within this limit.
    ///
    /// For SNMPv3 requests, the agent uses the minimum of this value
    /// and the msgMaxSize from the request.
    pub fn max_message_size(mut self, size: usize) -> Self {
        self.max_message_size = size;
        self
    }

    /// Set the maximum number of concurrent requests the agent will process.
    ///
    /// Default is 1000. Requests beyond this limit will queue until a slot
    /// becomes available. Set to `None` for unbounded concurrency.
    ///
    /// This controls memory usage under high load while still allowing
    /// parallel request processing.
    pub fn max_concurrent_requests(mut self, limit: Option<usize>) -> Self {
        self.max_concurrent_requests = limit;
        self
    }

    /// Set the UDP socket receive buffer size.
    ///
    /// Default is 4MB. The kernel may cap this at `net.core.rmem_max`.
    /// A larger buffer prevents packet loss during request bursts.
    ///
    /// Set to `None` to use the kernel default.
    pub fn recv_buffer_size(mut self, size: Option<usize>) -> Self {
        self.recv_buffer_size = size;
        self
    }

    /// Register a MIB handler for an OID subtree.
    ///
    /// Handlers are matched by longest prefix. When a request comes in,
    /// the handler with the longest matching prefix is used.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use async_snmp::agent::Agent;
    /// use async_snmp::handler::{MibHandler, RequestContext, GetResult, GetNextResult, BoxFuture};
    /// use async_snmp::{Oid, Value, VarBind, oid};
    /// use std::sync::Arc;
    ///
    /// struct SystemHandler;
    /// impl MibHandler for SystemHandler {
    ///     fn get<'a>(&'a self, _: &'a RequestContext, oid: &'a Oid) -> BoxFuture<'a, GetResult> {
    ///         Box::pin(async move {
    ///             if oid == &oid!(1, 3, 6, 1, 2, 1, 1, 1, 0) {
    ///                 GetResult::Value(Value::OctetString("My Agent".into()))
    ///             } else {
    ///                 GetResult::NoSuchObject
    ///             }
    ///         })
    ///     }
    ///     fn get_next<'a>(&'a self, _: &'a RequestContext, _: &'a Oid) -> BoxFuture<'a, GetNextResult> {
    ///         Box::pin(async { GetNextResult::EndOfMibView })
    ///     }
    /// }
    ///
    /// # async fn example() -> Result<(), async_snmp::Error> {
    /// let agent = Agent::builder()
    ///     .bind("0.0.0.0:1161")
    ///     .community(b"public")
    ///     // Register handler for system MIB subtree
    ///     .handler(oid!(1, 3, 6, 1, 2, 1, 1), Arc::new(SystemHandler))
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn handler(mut self, prefix: Oid, handler: Arc<dyn MibHandler>) -> Self {
        self.handlers.push(RegisteredHandler { prefix, handler });
        self
    }

    /// Configure VACM (View-based Access Control Model) using a builder function.
    ///
    /// When VACM is enabled, all requests are checked against the configured
    /// access control rules. Requests that don't have proper access are rejected
    /// with `noAccess` error (v2c/v3) or `noSuchName` (v1).
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use async_snmp::agent::{Agent, SecurityModel, VacmBuilder};
    /// use async_snmp::message::SecurityLevel;
    /// use async_snmp::oid;
    ///
    /// # async fn example() -> Result<(), async_snmp::Error> {
    /// let agent = Agent::builder()
    ///     .bind("0.0.0.0:161")
    ///     .community(b"public")
    ///     .community(b"private")
    ///     .vacm(|v| v
    ///         .group("public", SecurityModel::V2c, "readonly_group")
    ///         .group("private", SecurityModel::V2c, "readwrite_group")
    ///         .access("readonly_group", |a| a
    ///             .read_view("full_view"))
    ///         .access("readwrite_group", |a| a
    ///             .read_view("full_view")
    ///             .write_view("write_view"))
    ///         .view("full_view", |v| v
    ///             .include(oid!(1, 3, 6, 1)))
    ///         .view("write_view", |v| v
    ///             .include(oid!(1, 3, 6, 1, 2, 1, 1))))
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn vacm<F>(mut self, configure: F) -> Self
    where
        F: FnOnce(VacmBuilder) -> VacmBuilder,
    {
        let builder = VacmBuilder::new();
        self.vacm = Some(configure(builder).build());
        self
    }

    /// Set a cancellation token for graceful shutdown.
    ///
    /// If not set, the agent creates its own token accessible via `Agent::cancel()`.
    pub fn cancel(mut self, token: CancellationToken) -> Self {
        self.cancel = Some(token);
        self
    }

    /// Build the agent.
    pub async fn build(mut self) -> Result<Agent> {
        let bind_addr: std::net::SocketAddr = self.bind_addr.parse().map_err(|_| Error::Io {
            target: None,
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid bind address: {}", self.bind_addr),
            ),
        })?;

        let socket = bind_udp_socket(bind_addr, self.recv_buffer_size)
            .await
            .map_err(|e| Error::Io {
                target: Some(bind_addr),
                source: e,
            })?;

        let local_addr = socket.local_addr().map_err(|e| Error::Io {
            target: Some(bind_addr),
            source: e,
        })?;

        // Generate default engine ID if not provided
        let engine_id = self.engine_id.unwrap_or_else(|| {
            // RFC 3411 format: enterprise number + format + local identifier
            // Use a simple format: 0x80 (local) + timestamp + random
            let mut id = vec![0x80, 0x00, 0x00, 0x00, 0x01]; // Enterprise format indicator
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            id.extend_from_slice(&timestamp.to_be_bytes());
            id
        });

        // Sort handlers by prefix length (longest first) for matching
        self.handlers
            .sort_by(|a, b| b.prefix.len().cmp(&a.prefix.len()));

        let cancel = self.cancel.unwrap_or_default();

        // Create concurrency limiter if configured
        let concurrency_limit = self
            .max_concurrent_requests
            .map(|n| Arc::new(Semaphore::new(n)));

        Ok(Agent {
            inner: Arc::new(AgentInner {
                socket: Arc::new(socket),
                local_addr,
                communities: self.communities,
                usm_users: self.usm_users,
                handlers: self.handlers,
                engine_id,
                engine_boots: AtomicU32::new(1),
                engine_time: AtomicU32::new(0),
                engine_start: Instant::now(),
                salt_counter: SaltCounter::new(),
                max_message_size: self.max_message_size,
                concurrency_limit,
                vacm: self.vacm,
                snmp_invalid_msgs: AtomicU32::new(0),
                snmp_unknown_security_models: AtomicU32::new(0),
                snmp_silent_drops: AtomicU32::new(0),
                cancel,
            }),
        })
    }
}

impl Default for AgentBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Inner state shared across agent clones.
pub(crate) struct AgentInner {
    pub(crate) socket: Arc<UdpSocket>,
    pub(crate) local_addr: SocketAddr,
    pub(crate) communities: Vec<Vec<u8>>,
    pub(crate) usm_users: HashMap<Bytes, UsmUserConfig>,
    pub(crate) handlers: Vec<RegisteredHandler>,
    pub(crate) engine_id: Vec<u8>,
    pub(crate) engine_boots: AtomicU32,
    pub(crate) engine_time: AtomicU32,
    pub(crate) engine_start: Instant,
    pub(crate) salt_counter: SaltCounter,
    pub(crate) max_message_size: usize,
    pub(crate) concurrency_limit: Option<Arc<Semaphore>>,
    pub(crate) vacm: Option<VacmConfig>,
    // RFC 3412 statistics counters
    /// snmpInvalidMsgs (1.3.6.1.6.3.11.2.1.2) - messages with invalid msgFlags
    /// (e.g., privacy without authentication)
    pub(crate) snmp_invalid_msgs: AtomicU32,
    /// snmpUnknownSecurityModels (1.3.6.1.6.3.11.2.1.1) - messages with
    /// unrecognized security model
    pub(crate) snmp_unknown_security_models: AtomicU32,
    /// snmpSilentDrops (1.3.6.1.6.3.11.2.1.3) - confirmed-class PDUs silently
    /// dropped because even an empty response would exceed max message size
    pub(crate) snmp_silent_drops: AtomicU32,
    /// Cancellation token for graceful shutdown.
    pub(crate) cancel: CancellationToken,
}

/// SNMP Agent.
///
/// Listens for and responds to SNMP requests (GET, GETNEXT, GETBULK, SET).
///
/// # Example
///
/// ```rust,no_run
/// use async_snmp::agent::Agent;
/// use async_snmp::oid;
///
/// # async fn example() -> Result<(), async_snmp::Error> {
/// let agent = Agent::builder()
///     .bind("0.0.0.0:161")
///     .community(b"public")
///     .build()
///     .await?;
///
/// agent.run().await
/// # }
/// ```
pub struct Agent {
    pub(crate) inner: Arc<AgentInner>,
}

impl Agent {
    /// Create a builder for configuring the agent.
    pub fn builder() -> AgentBuilder {
        AgentBuilder::new()
    }

    /// Get the local address the agent is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr
    }

    /// Get the engine ID.
    pub fn engine_id(&self) -> &[u8] {
        &self.inner.engine_id
    }

    /// Get the cancellation token for this agent.
    ///
    /// Call `token.cancel()` to initiate graceful shutdown.
    pub fn cancel(&self) -> CancellationToken {
        self.inner.cancel.clone()
    }

    /// Get the snmpInvalidMsgs counter value.
    ///
    /// This counter tracks messages with invalid msgFlags, such as
    /// privacy-without-authentication (RFC 3412 Section 7.2 Step 5d).
    ///
    /// OID: 1.3.6.1.6.3.11.2.1.2
    pub fn snmp_invalid_msgs(&self) -> u32 {
        self.inner.snmp_invalid_msgs.load(Ordering::Relaxed)
    }

    /// Get the snmpUnknownSecurityModels counter value.
    ///
    /// This counter tracks messages with unrecognized security models
    /// (RFC 3412 Section 7.2 Step 2).
    ///
    /// OID: 1.3.6.1.6.3.11.2.1.1
    pub fn snmp_unknown_security_models(&self) -> u32 {
        self.inner
            .snmp_unknown_security_models
            .load(Ordering::Relaxed)
    }

    /// Get the snmpSilentDrops counter value.
    ///
    /// This counter tracks confirmed-class PDUs (GetRequest, GetNextRequest,
    /// GetBulkRequest, SetRequest, InformRequest) that were silently dropped
    /// because even an empty Response-PDU would exceed the maximum message
    /// size constraint (RFC 3412 Section 7.1).
    ///
    /// OID: 1.3.6.1.6.3.11.2.1.3
    pub fn snmp_silent_drops(&self) -> u32 {
        self.inner.snmp_silent_drops.load(Ordering::Relaxed)
    }

    /// Run the agent, processing requests concurrently.
    ///
    /// Requests are processed in parallel up to the configured
    /// `max_concurrent_requests` limit (default: 1000). This method runs
    /// until the cancellation token is triggered.
    #[instrument(skip(self), err, fields(snmp.local_addr = %self.local_addr()))]
    pub async fn run(&self) -> Result<()> {
        let mut buf = vec![0u8; 65535];

        loop {
            let (len, source) = tokio::select! {
                result = self.inner.socket.recv_from(&mut buf) => {
                    result.map_err(|e| Error::Io {
                        target: Some(self.inner.local_addr),
                        source: e,
                    })?
                }
                _ = self.inner.cancel.cancelled() => {
                    tracing::info!("agent shutdown requested");
                    return Ok(());
                }
            };

            let data = Bytes::copy_from_slice(&buf[..len]);

            // Clone agent for the spawned task
            let agent = self.clone();

            // Acquire concurrency permit if configured
            let permit = if let Some(ref sem) = self.inner.concurrency_limit {
                Some(sem.clone().acquire_owned().await.expect("semaphore closed"))
            } else {
                None
            };

            // Spawn task to handle request concurrently
            tokio::spawn(async move {
                // Update engine time
                agent.update_engine_time();

                match agent.handle_request(data, source).await {
                    Ok(Some(response_bytes)) => {
                        if let Err(e) = agent.inner.socket.send_to(&response_bytes, source).await {
                            tracing::warn!(snmp.source = %source, error = %e, "failed to send response");
                        }
                    }
                    Ok(None) => {
                        // No response needed (e.g., invalid message)
                    }
                    Err(e) => {
                        tracing::warn!(snmp.source = %source, error = %e, "error handling request");
                    }
                }

                // Permit dropped here, releasing the slot
                drop(permit);
            });
        }
    }

    /// Process a single request and return the response bytes.
    ///
    /// Returns `None` if no response should be sent.
    async fn handle_request(&self, data: Bytes, source: SocketAddr) -> Result<Option<Bytes>> {
        // Peek at version
        let mut decoder = Decoder::new(data.clone());
        let mut seq = decoder.read_sequence()?;
        let version_num = seq.read_integer()?;
        let version = Version::from_i32(version_num).ok_or_else(|| {
            Error::decode(seq.offset(), DecodeErrorKind::UnknownVersion(version_num))
        })?;
        drop(seq);
        drop(decoder);

        match version {
            Version::V1 => self.handle_v1(data, source).await,
            Version::V2c => self.handle_v2c(data, source).await,
            Version::V3 => self.handle_v3(data, source).await,
        }
    }

    /// Update engine time based on elapsed time since start.
    fn update_engine_time(&self) {
        let elapsed = self.inner.engine_start.elapsed().as_secs() as u32;
        self.inner.engine_time.store(elapsed, Ordering::Relaxed);
    }

    /// Validate community string using constant-time comparison.
    ///
    /// Uses constant-time comparison to prevent timing attacks that could
    /// be used to guess valid community strings character by character.
    pub(crate) fn validate_community(&self, community: &[u8]) -> bool {
        if self.inner.communities.is_empty() {
            // No communities configured = reject all
            return false;
        }
        // Use constant-time comparison for each community string.
        // We compare against all configured communities regardless of
        // early matches to maintain constant-time behavior.
        let mut valid = false;
        for configured in &self.inner.communities {
            // ct_eq returns a Choice, which we convert to bool after comparison
            if configured.len() == community.len()
                && bool::from(configured.as_slice().ct_eq(community))
            {
                valid = true;
            }
        }
        valid
    }

    /// Dispatch a request to the appropriate handler.
    async fn dispatch_request(&self, ctx: &RequestContext, pdu: &Pdu) -> Result<Pdu> {
        match pdu.pdu_type {
            PduType::GetRequest => self.handle_get(ctx, pdu).await,
            PduType::GetNextRequest => self.handle_get_next(ctx, pdu).await,
            PduType::GetBulkRequest => self.handle_get_bulk(ctx, pdu).await,
            PduType::SetRequest => self.handle_set(ctx, pdu).await,
            PduType::InformRequest => self.handle_inform(pdu),
            _ => {
                // Should not happen - filtered earlier
                Ok(pdu.to_error_response(ErrorStatus::GenErr, 0))
            }
        }
    }

    /// Handle InformRequest PDU.
    ///
    /// Per RFC 3416 Section 4.2.7, an InformRequest is a confirmed-class PDU
    /// that the receiver acknowledges by returning a Response with the same
    /// request-id and varbind list.
    fn handle_inform(&self, pdu: &Pdu) -> Result<Pdu> {
        // Simply acknowledge by returning the same varbinds in a Response
        Ok(Pdu {
            pdu_type: PduType::Response,
            request_id: pdu.request_id,
            error_status: 0,
            error_index: 0,
            varbinds: pdu.varbinds.clone(),
        })
    }

    /// Handle GET request.
    async fn handle_get(&self, ctx: &RequestContext, pdu: &Pdu) -> Result<Pdu> {
        let mut response_varbinds = Vec::with_capacity(pdu.varbinds.len());

        for (index, vb) in pdu.varbinds.iter().enumerate() {
            // VACM read access check
            if let Some(ref vacm) = self.inner.vacm
                && !vacm.check_access(ctx.read_view.as_ref(), &vb.oid)
            {
                // v1: noSuchName, v2c/v3: noAccess or NoSuchObject
                if ctx.version == Version::V1 {
                    return Ok(Pdu {
                        pdu_type: PduType::Response,
                        request_id: pdu.request_id,
                        error_status: ErrorStatus::NoSuchName.as_i32(),
                        error_index: (index + 1) as i32,
                        varbinds: pdu.varbinds.clone(),
                    });
                } else {
                    // For GET, return NoSuchObject for inaccessible OIDs per RFC 3415
                    response_varbinds.push(VarBind::new(vb.oid.clone(), Value::NoSuchObject));
                    continue;
                }
            }

            let result = if let Some(handler) = self.find_handler(&vb.oid) {
                handler.handler.get(ctx, &vb.oid).await
            } else {
                GetResult::NoSuchObject
            };

            let response_value = match result {
                GetResult::Value(v) => v,
                GetResult::NoSuchObject => {
                    // v1 returns noSuchName error, v2c/v3 returns NoSuchObject exception
                    if ctx.version == Version::V1 {
                        return Ok(Pdu {
                            pdu_type: PduType::Response,
                            request_id: pdu.request_id,
                            error_status: ErrorStatus::NoSuchName.as_i32(),
                            error_index: (index + 1) as i32,
                            varbinds: pdu.varbinds.clone(),
                        });
                    } else {
                        Value::NoSuchObject
                    }
                }
                GetResult::NoSuchInstance => {
                    // v1 returns noSuchName error, v2c/v3 returns NoSuchInstance exception
                    if ctx.version == Version::V1 {
                        return Ok(Pdu {
                            pdu_type: PduType::Response,
                            request_id: pdu.request_id,
                            error_status: ErrorStatus::NoSuchName.as_i32(),
                            error_index: (index + 1) as i32,
                            varbinds: pdu.varbinds.clone(),
                        });
                    } else {
                        Value::NoSuchInstance
                    }
                }
            };

            response_varbinds.push(VarBind::new(vb.oid.clone(), response_value));
        }

        Ok(Pdu {
            pdu_type: PduType::Response,
            request_id: pdu.request_id,
            error_status: 0,
            error_index: 0,
            varbinds: response_varbinds,
        })
    }

    /// Handle GETNEXT request.
    async fn handle_get_next(&self, ctx: &RequestContext, pdu: &Pdu) -> Result<Pdu> {
        let mut response_varbinds = Vec::with_capacity(pdu.varbinds.len());

        for (index, vb) in pdu.varbinds.iter().enumerate() {
            // Try to find the next OID from any handler
            let next = self.get_next_oid(ctx, &vb.oid).await;

            // Check VACM access for the returned OID (if VACM enabled)
            let next = if let Some(ref next_vb) = next {
                if let Some(ref vacm) = self.inner.vacm {
                    if vacm.check_access(ctx.read_view.as_ref(), &next_vb.oid) {
                        next
                    } else {
                        // OID not accessible, continue searching
                        // For simplicity, we just return EndOfMibView here
                        // A more complete implementation would continue the search
                        None
                    }
                } else {
                    next
                }
            } else {
                next
            };

            match next {
                Some(next_vb) => {
                    response_varbinds.push(next_vb);
                }
                None => {
                    // v1 returns noSuchName, v2c/v3 returns endOfMibView
                    if ctx.version == Version::V1 {
                        return Ok(Pdu {
                            pdu_type: PduType::Response,
                            request_id: pdu.request_id,
                            error_status: ErrorStatus::NoSuchName.as_i32(),
                            error_index: (index + 1) as i32,
                            varbinds: pdu.varbinds.clone(),
                        });
                    } else {
                        response_varbinds.push(VarBind::new(vb.oid.clone(), Value::EndOfMibView));
                    }
                }
            }
        }

        Ok(Pdu {
            pdu_type: PduType::Response,
            request_id: pdu.request_id,
            error_status: 0,
            error_index: 0,
            varbinds: response_varbinds,
        })
    }

    /// Handle GETBULK request.
    ///
    /// Per RFC 3416 Section 4.2.3, if the response would exceed the message
    /// size limit, we return fewer variable bindings rather than all of them.
    async fn handle_get_bulk(&self, ctx: &RequestContext, pdu: &Pdu) -> Result<Pdu> {
        // For GETBULK, error_status is non_repeaters and error_index is max_repetitions
        let non_repeaters = pdu.error_status.max(0) as usize;
        let max_repetitions = pdu.error_index.max(0) as usize;

        let mut response_varbinds = Vec::new();
        let mut current_size: usize = RESPONSE_OVERHEAD;
        let max_size = self.inner.max_message_size;

        // Helper to check if we can add a varbind
        let can_add = |vb: &VarBind, current_size: usize| -> bool {
            current_size + vb.encoded_size() <= max_size
        };

        // Handle non-repeaters (first N varbinds get one GETNEXT each)
        for vb in pdu.varbinds.iter().take(non_repeaters) {
            let next_vb = match self.get_next_oid(ctx, &vb.oid).await {
                Some(next_vb) => next_vb,
                None => VarBind::new(vb.oid.clone(), Value::EndOfMibView),
            };

            if !can_add(&next_vb, current_size) {
                // Can't fit even non-repeaters, return tooBig if we have nothing
                if response_varbinds.is_empty() {
                    return Ok(Pdu {
                        pdu_type: PduType::Response,
                        request_id: pdu.request_id,
                        error_status: ErrorStatus::TooBig.as_i32(),
                        error_index: 0,
                        varbinds: pdu.varbinds.clone(),
                    });
                }
                // Otherwise return what we have
                break;
            }

            current_size += next_vb.encoded_size();
            response_varbinds.push(next_vb);
        }

        // Handle repeaters
        if non_repeaters < pdu.varbinds.len() {
            let repeaters = &pdu.varbinds[non_repeaters..];
            let mut current_oids: Vec<Oid> = repeaters.iter().map(|vb| vb.oid.clone()).collect();
            let mut all_done = vec![false; repeaters.len()];

            'outer: for _ in 0..max_repetitions {
                let mut row_complete = true;
                for (i, oid) in current_oids.iter_mut().enumerate() {
                    let next_vb = if all_done[i] {
                        VarBind::new(oid.clone(), Value::EndOfMibView)
                    } else {
                        match self.get_next_oid(ctx, oid).await {
                            Some(next_vb) => {
                                *oid = next_vb.oid.clone();
                                row_complete = false;
                                next_vb
                            }
                            None => {
                                all_done[i] = true;
                                VarBind::new(oid.clone(), Value::EndOfMibView)
                            }
                        }
                    };

                    // Check size before adding
                    if !can_add(&next_vb, current_size) {
                        // Can't fit more, return what we have
                        break 'outer;
                    }

                    current_size += next_vb.encoded_size();
                    response_varbinds.push(next_vb);
                }

                if row_complete {
                    break;
                }
            }
        }

        Ok(Pdu {
            pdu_type: PduType::Response,
            request_id: pdu.request_id,
            error_status: 0,
            error_index: 0,
            varbinds: response_varbinds,
        })
    }

    /// Find the handler for a given OID.
    pub(crate) fn find_handler(&self, oid: &Oid) -> Option<&RegisteredHandler> {
        // Handlers are sorted by prefix length (longest first)
        self.inner
            .handlers
            .iter()
            .find(|&handler| handler.handler.handles(&handler.prefix, oid))
            .map(|v| v as _)
    }

    /// Get the next OID from any handler.
    async fn get_next_oid(&self, ctx: &RequestContext, oid: &Oid) -> Option<VarBind> {
        // Find the first handler that can provide a next OID
        let mut best_result: Option<VarBind> = None;

        for handler in &self.inner.handlers {
            if let GetNextResult::Value(next) = handler.handler.get_next(ctx, oid).await {
                // Must be lexicographically greater than the request OID
                if next.oid > *oid {
                    match &best_result {
                        None => best_result = Some(next),
                        Some(current) if next.oid < current.oid => best_result = Some(next),
                        _ => {}
                    }
                }
            }
        }

        best_result
    }
}

impl Clone for Agent {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::{
        BoxFuture, GetNextResult, GetResult, MibHandler, RequestContext, SecurityModel, SetResult,
    };
    use crate::message::SecurityLevel;
    use crate::oid;

    struct TestHandler;

    impl MibHandler for TestHandler {
        fn get<'a>(&'a self, _ctx: &'a RequestContext, oid: &'a Oid) -> BoxFuture<'a, GetResult> {
            Box::pin(async move {
                if oid == &oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0) {
                    return GetResult::Value(Value::Integer(42));
                }
                if oid == &oid!(1, 3, 6, 1, 4, 1, 99999, 2, 0) {
                    return GetResult::Value(Value::OctetString(Bytes::from_static(b"test")));
                }
                GetResult::NoSuchObject
            })
        }

        fn get_next<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            oid: &'a Oid,
        ) -> BoxFuture<'a, GetNextResult> {
            Box::pin(async move {
                let oid1 = oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0);
                let oid2 = oid!(1, 3, 6, 1, 4, 1, 99999, 2, 0);

                if oid < &oid1 {
                    return GetNextResult::Value(VarBind::new(oid1, Value::Integer(42)));
                }
                if oid < &oid2 {
                    return GetNextResult::Value(VarBind::new(
                        oid2,
                        Value::OctetString(Bytes::from_static(b"test")),
                    ));
                }
                GetNextResult::EndOfMibView
            })
        }
    }

    fn test_ctx() -> RequestContext {
        RequestContext {
            source: "127.0.0.1:12345".parse().unwrap(),
            version: Version::V2c,
            security_model: SecurityModel::V2c,
            security_name: Bytes::from_static(b"public"),
            security_level: SecurityLevel::NoAuthNoPriv,
            context_name: Bytes::new(),
            request_id: 1,
            pdu_type: PduType::GetRequest,
            group_name: None,
            read_view: None,
            write_view: None,
        }
    }

    #[test]
    fn test_agent_builder_defaults() {
        let builder = AgentBuilder::new();
        assert_eq!(builder.bind_addr, "0.0.0.0:161");
        assert!(builder.communities.is_empty());
        assert!(builder.usm_users.is_empty());
        assert!(builder.handlers.is_empty());
    }

    #[test]
    fn test_agent_builder_community() {
        let builder = AgentBuilder::new()
            .community(b"public")
            .community(b"private");
        assert_eq!(builder.communities.len(), 2);
    }

    #[test]
    fn test_agent_builder_communities() {
        let builder = AgentBuilder::new().communities(["public", "private"]);
        assert_eq!(builder.communities.len(), 2);
    }

    #[test]
    fn test_agent_builder_handler() {
        let builder =
            AgentBuilder::new().handler(oid!(1, 3, 6, 1, 4, 1, 99999), Arc::new(TestHandler));
        assert_eq!(builder.handlers.len(), 1);
    }

    #[tokio::test]
    async fn test_mib_handler_default_set() {
        let handler = TestHandler;
        let mut ctx = test_ctx();
        ctx.pdu_type = PduType::SetRequest;

        let result = handler
            .test_set(&ctx, &oid!(1, 3, 6, 1), &Value::Integer(1))
            .await;
        assert_eq!(result, SetResult::NotWritable);
    }

    #[test]
    fn test_mib_handler_handles() {
        let handler = TestHandler;
        let prefix = oid!(1, 3, 6, 1, 4, 1, 99999);

        // OID within prefix
        assert!(handler.handles(&prefix, &oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0)));

        // OID before prefix (GETNEXT should still try)
        assert!(handler.handles(&prefix, &oid!(1, 3, 6, 1, 4, 1, 99998)));

        // OID after prefix (not handled)
        assert!(!handler.handles(&prefix, &oid!(1, 3, 6, 1, 4, 1, 100000)));
    }

    #[tokio::test]
    async fn test_test_handler_get() {
        let handler = TestHandler;
        let ctx = test_ctx();

        // Existing OID
        let result = handler
            .get(&ctx, &oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0))
            .await;
        assert!(matches!(result, GetResult::Value(Value::Integer(42))));

        // Non-existing OID
        let result = handler
            .get(&ctx, &oid!(1, 3, 6, 1, 4, 1, 99999, 99, 0))
            .await;
        assert!(matches!(result, GetResult::NoSuchObject));
    }

    #[tokio::test]
    async fn test_test_handler_get_next() {
        let handler = TestHandler;
        let mut ctx = test_ctx();
        ctx.pdu_type = PduType::GetNextRequest;

        // Before first OID
        let next = handler.get_next(&ctx, &oid!(1, 3, 6, 1, 4, 1, 99999)).await;
        assert!(next.is_value());
        if let GetNextResult::Value(vb) = next {
            assert_eq!(vb.oid, oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0));
        }

        // Between OIDs
        let next = handler
            .get_next(&ctx, &oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0))
            .await;
        assert!(next.is_value());
        if let GetNextResult::Value(vb) = next {
            assert_eq!(vb.oid, oid!(1, 3, 6, 1, 4, 1, 99999, 2, 0));
        }

        // After last OID
        let next = handler
            .get_next(&ctx, &oid!(1, 3, 6, 1, 4, 1, 99999, 2, 0))
            .await;
        assert!(next.is_end_of_mib_view());
    }
}
