//! SNMP Agent (RFC 3413).
//!
//! This module provides SNMP agent functionality for responding to
//! GET, GETNEXT, GETBULK, and SET requests, and for sending traps and informs.
//!
//! # Features
//!
//! - **Async handlers**: All handler methods are async for database queries, network calls, etc.
//! - **Atomic SET**: Two-phase commit protocol (test/commit/undo/free) per RFC 3416
//! - **VACM support**: Optional View-based Access Control Model (RFC 3415)
//! - **Trap/inform sending**: Send notifications to configured trap sinks via [`Agent::send_trap`] and [`Agent::send_inform`]
//! - **Built-in MIB handlers**: Automatic read-only handlers for snmpEngine, usmStats, and mpdStats groups (see [`BuiltinMib`])
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
//! async fn main() -> Result<(), Box<async_snmp::Error>> {
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

mod builtins;
mod notification;
mod request;
mod response;
mod set_handler;
pub mod vacm;

pub use vacm::{SecurityModel, VacmBuilder, VacmConfig, View, ViewCheckResult, ViewSubtree};

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use subtle::ConstantTimeEq;
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tracing::instrument;

use std::io::IoSliceMut;

use quinn_udp::{RecvMeta, Transmit, UdpSockRef, UdpSocketState};

use crate::error::{Error, ErrorStatus, Result};
use crate::handler::{GetNextResult, GetResult, MibHandler, RequestContext};
use crate::notification::UsmConfig;
use crate::oid;
use crate::oid::Oid;
use crate::pdu::{Pdu, PduType};
use crate::util::bind_udp_socket;
use crate::v3::process::UsmStats;
use crate::v3::{SaltCounter, compute_engine_boots_time};
use crate::value::Value;
use crate::varbind::VarBind;
use crate::version::Version;

/// Default maximum message size for UDP (RFC 3417 recommendation).
const DEFAULT_MAX_MESSAGE_SIZE: usize = 1472;

/// Overhead for SNMP message encoding (approximate conservative estimate).
/// This accounts for version, community/USM, PDU headers, etc.
const RESPONSE_OVERHEAD: usize = 100;

/// Built-in MIB handler groups that the agent registers automatically.
///
/// By default, the agent registers handlers for standard SNMP MIB objects
/// (engine parameters, USM statistics, MPD statistics). Use
/// [`AgentBuilder::without_builtin_handler`] to disable specific groups
/// or [`AgentBuilder::without_builtin_handlers`] to disable all of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BuiltinMib {
    /// snmpEngine scalars (1.3.6.1.6.3.10.2.1).
    ///
    /// Provides snmpEngineID, snmpEngineBoots, snmpEngineTime,
    /// and snmpEngineMaxMessageSize.
    SnmpEngine,
    /// USM statistics (1.3.6.1.6.3.15.1.1).
    ///
    /// Provides the six usmStats counters (unsupportedSecLevels,
    /// notInTimeWindows, unknownUserNames, unknownEngineIDs,
    /// wrongDigests, decryptionErrors).
    UsmStats,
    /// MPD statistics (1.3.6.1.6.3.11.2.1).
    ///
    /// Provides snmpUnknownSecurityModels and snmpInvalidMsgs.
    MpdStats,
}

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
/// # Access Control
///
/// By default, the agent operates in **permissive mode**: any authenticated
/// request (valid community string for v1/v2c, valid USM credentials for v3)
/// has full read and write access to all registered handlers.
///
/// For production deployments, use the [`vacm()`](AgentBuilder::vacm) method
/// to configure View-based Access Control (RFC 3415), which allows fine-grained
/// control over which security names can access which OID subtrees.
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
/// # async fn example() -> Result<(), Box<async_snmp::Error>> {
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
    usm_users: HashMap<Bytes, UsmConfig>,
    handlers: Vec<RegisteredHandler>,
    engine_id: Option<Vec<u8>>,
    engine_boots: u32,
    max_message_size: usize,
    max_concurrent_requests: Option<usize>,
    recv_buffer_size: Option<usize>,
    vacm: Option<VacmConfig>,
    cancel: Option<CancellationToken>,
    trap_sinks: Vec<(String, crate::client::Auth)>,
    inform_timeout: Duration,
    inform_retry: crate::client::Retry,
    disabled_builtins: HashSet<BuiltinMib>,
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
    #[must_use]
    pub fn new() -> Self {
        Self {
            bind_addr: "0.0.0.0:161".to_string(),
            communities: Vec::new(),
            usm_users: HashMap::new(),
            handlers: Vec::new(),
            engine_id: None,
            engine_boots: 1,
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            max_concurrent_requests: Some(1000),
            recv_buffer_size: Some(4 * 1024 * 1024), // 4MB
            vacm: None,
            cancel: None,
            trap_sinks: Vec::new(),
            inform_timeout: Duration::from_secs(5),
            inform_retry: crate::client::Retry::default(),
            disabled_builtins: HashSet::new(),
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
    /// # async fn example() -> Result<(), Box<async_snmp::Error>> {
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
    /// # async fn example() -> Result<(), Box<async_snmp::Error>> {
    /// // Bind to all interfaces (IPv6, with dual-stack on Linux)
    /// let agent = Agent::builder().bind("[::]:161").community(b"public").build().await?;
    ///
    /// // Bind to IPv6 localhost only
    /// let agent = Agent::builder().bind("[::1]:1161").community(b"public").build().await?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
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
    /// # async fn example() -> Result<(), Box<async_snmp::Error>> {
    /// let agent = Agent::builder()
    ///     .bind("0.0.0.0:1161")
    ///     .community(b"public")   // Read-only access
    ///     .community(b"private")  // Read-write access (with VACM)
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
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
    /// # async fn example() -> Result<(), Box<async_snmp::Error>> {
    /// let communities = ["public", "private", "monitor"];
    /// let agent = Agent::builder()
    ///     .bind("0.0.0.0:1161")
    ///     .communities(communities)
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
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

    /// Add a USM user for `SNMPv3` authentication.
    ///
    /// Configure authentication and privacy settings using the closure.
    /// Multiple users can be added with different security levels.
    ///
    /// # Security Levels
    ///
    /// - **noAuthNoPriv**: No authentication or encryption
    /// - **authNoPriv**: Authentication only (HMAC verification)
    /// - **authPriv**: Authentication and encryption
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use async_snmp::agent::Agent;
    /// use async_snmp::{AuthProtocol, PrivProtocol};
    ///
    /// # async fn example() -> Result<(), Box<async_snmp::Error>> {
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
    #[must_use]
    pub fn usm_user<F>(mut self, username: impl Into<Bytes>, configure: F) -> Self
    where
        F: FnOnce(UsmConfig) -> UsmConfig,
    {
        let username_bytes: Bytes = username.into();
        let config = configure(UsmConfig::new(username_bytes.clone()));
        self.usm_users.insert(username_bytes, config);
        self
    }

    /// Set the engine ID for `SNMPv3`.
    ///
    /// If not set, a default engine ID will be generated based on the
    /// RFC 3411 format using enterprise number and timestamp.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use async_snmp::agent::Agent;
    ///
    /// # async fn example() -> Result<(), Box<async_snmp::Error>> {
    /// let agent = Agent::builder()
    ///     .bind("0.0.0.0:1161")
    ///     .engine_id(b"\x80\x00\x00\x00\x01MyEngine".to_vec())
    ///     .community(b"public")
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn engine_id(mut self, engine_id: impl Into<Vec<u8>>) -> Self {
        self.engine_id = Some(engine_id.into());
        self
    }

    /// Set the initial engine boots value.
    ///
    /// Per RFC 3414 Section 2.3, snmpEngineBoots must be monotonically
    /// increasing across restarts. The application is responsible for
    /// persisting and restoring this value. If not set, defaults to 1.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use async_snmp::agent::Agent;
    ///
    /// # async fn example() -> Result<(), Box<async_snmp::Error>> {
    /// // Load persisted value (e.g. from file or database)
    /// let persisted_boots: u32 = 42;
    ///
    /// let agent = Agent::builder()
    ///     .bind("0.0.0.0:1161")
    ///     .engine_boots(persisted_boots)
    ///     .community(b"public")
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn engine_boots(mut self, boots: u32) -> Self {
        self.engine_boots = boots;
        self
    }

    /// Set the maximum message size for responses.
    ///
    /// Default is 1472 octets (fits Ethernet MTU minus IP/UDP headers).
    /// GETBULK responses will be truncated to fit within this limit.
    ///
    /// For `SNMPv3` requests, the agent uses the minimum of this value
    /// and the msgMaxSize from the request.
    #[must_use]
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
    #[must_use]
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
    #[must_use]
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
    /// # async fn example() -> Result<(), Box<async_snmp::Error>> {
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
    #[must_use]
    pub fn handler(mut self, prefix: Oid, handler: Arc<dyn MibHandler>) -> Self {
        self.handlers.push(RegisteredHandler { prefix, handler });
        self
    }

    /// Configure VACM (View-based Access Control Model) using a builder function.
    ///
    /// When VACM is configured, all requests are checked against the configured
    /// access control rules. Requests that don't have proper access are rejected
    /// with `noAccess` error (v2c/v3) or `noSuchName` (v1).
    ///
    /// **Without VACM configuration, the agent operates in permissive mode**:
    /// any authenticated request has full read/write access to all handlers.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use async_snmp::agent::{Agent, SecurityModel, VacmBuilder};
    /// use async_snmp::message::SecurityLevel;
    /// use async_snmp::oid;
    ///
    /// # async fn example() -> Result<(), Box<async_snmp::Error>> {
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
    #[must_use]
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
    #[must_use]
    pub fn cancel(mut self, token: CancellationToken) -> Self {
        self.cancel = Some(token);
        self
    }

    /// Add a trap/inform destination.
    ///
    /// The agent will send notifications to all configured trap sinks when
    /// [`Agent::send_trap()`] or [`Agent::send_inform()`] is called.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use async_snmp::agent::Agent;
    /// use async_snmp::{Auth, AuthProtocol, PrivProtocol};
    ///
    /// # async fn example() -> Result<(), Box<async_snmp::Error>> {
    /// let agent = Agent::builder()
    ///     .bind("0.0.0.0:1161")
    ///     .community(b"public")
    ///     .trap_sink("192.168.1.100:162", Auth::v2c("public"))
    ///     .trap_sink("10.0.0.1:162", Auth::usm("trapuser")
    ///         .auth(AuthProtocol::Sha256, "authpass")
    ///         .privacy(PrivProtocol::Aes128, "privpass"))
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn trap_sink(
        mut self,
        dest: impl Into<String>,
        auth: impl Into<crate::client::Auth>,
    ) -> Self {
        self.trap_sinks.push((dest.into(), auth.into()));
        self
    }

    /// Set the timeout for inform requests sent to trap sinks.
    ///
    /// Default is 5 seconds. Only affects `send_inform`, not `send_trap`.
    #[must_use]
    pub fn inform_timeout(mut self, timeout: Duration) -> Self {
        self.inform_timeout = timeout;
        self
    }

    /// Set the retry policy for inform requests sent to trap sinks.
    ///
    /// Default is `Retry::default()` (3 retries with 1-second delay).
    /// Only affects `send_inform`, not `send_trap`.
    #[must_use]
    pub fn inform_retry(mut self, retry: crate::client::Retry) -> Self {
        self.inform_retry = retry;
        self
    }

    /// Disable a specific built-in MIB handler group.
    ///
    /// By default, the agent registers handlers for snmpEngine, USM stats,
    /// and MPD stats. Call this to prevent registration of a specific group,
    /// e.g., if you want to provide your own handler for those OIDs.
    #[must_use]
    pub fn without_builtin_handler(mut self, mib: BuiltinMib) -> Self {
        self.disabled_builtins.insert(mib);
        self
    }

    /// Disable all built-in MIB handlers.
    ///
    /// The agent will not register any internal handlers for snmpEngine,
    /// USM stats, or MPD stats. You can still query the counter values
    /// via accessor methods like [`Agent::usm_unknown_engine_ids()`].
    #[must_use]
    pub fn without_builtin_handlers(mut self) -> Self {
        self.disabled_builtins.insert(BuiltinMib::SnmpEngine);
        self.disabled_builtins.insert(BuiltinMib::UsmStats);
        self.disabled_builtins.insert(BuiltinMib::MpdStats);
        self
    }

    /// Build the agent.
    pub async fn build(mut self) -> Result<Agent> {
        let bind_addr: std::net::SocketAddr = self.bind_addr.parse().map_err(|_| {
            Error::Config(format!("invalid bind address: {}", self.bind_addr).into())
        })?;

        let socket = bind_udp_socket(bind_addr, self.recv_buffer_size, None, false)
            .await
            .map_err(|e| Error::Network {
                target: bind_addr,
                source: e,
            })?;

        let local_addr = socket.local_addr().map_err(|e| Error::Network {
            target: bind_addr,
            source: e,
        })?;

        let socket_state =
            UdpSocketState::new(UdpSockRef::from(&socket)).map_err(|e| Error::Network {
                target: bind_addr,
                source: e,
            })?;

        // Generate default engine ID if not provided
        let engine_id: Bytes = self.engine_id.map_or_else(
            || {
                // RFC 3411 format: enterprise number + format + local identifier
                // Use a simple format: 0x80 (local) + timestamp + random
                let mut id = vec![0x80, 0x00, 0x00, 0x00, 0x01]; // Enterprise format indicator
                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                id.extend_from_slice(&timestamp.to_be_bytes());
                Bytes::from(id)
            },
            Bytes::from,
        );

        let cancel = self.cancel.unwrap_or_default();

        // Create concurrency limiter if configured
        let concurrency_limit = self
            .max_concurrent_requests
            .map(|n| Arc::new(Semaphore::new(n)));

        // Resolve trap sink addresses
        let mut trap_sinks = Vec::with_capacity(self.trap_sinks.len());
        for (dest_str, auth) in self.trap_sinks {
            let dest: SocketAddr = dest_str.parse().map_err(|_| {
                Error::Config(format!("invalid trap sink address: {dest_str}").into())
            })?;
            trap_sinks.push(notification::TrapSink::new(
                dest,
                auth,
                self.inform_timeout,
                self.inform_retry.clone(),
            ));
        }

        let state = Arc::new(AgentState {
            engine_id,
            engine_boots: AtomicU32::new(self.engine_boots),
            engine_time: AtomicU32::new(0),
            engine_start: Instant::now(),
            engine_boots_base: self.engine_boots,
            max_message_size: self.max_message_size,
            snmp_invalid_msgs: AtomicU32::new(0),
            snmp_unknown_security_models: AtomicU32::new(0),
            snmp_silent_drops: AtomicU32::new(0),
            usm_stats: UsmStats::default(),
        });

        // Register built-in handlers for any not disabled
        if !self.disabled_builtins.contains(&BuiltinMib::SnmpEngine) {
            self.handlers.push(RegisteredHandler {
                prefix: oid!(1, 3, 6, 1, 6, 3, 10, 2, 1),
                handler: Arc::new(builtins::SnmpEngineHandler {
                    state: Arc::clone(&state),
                }),
            });
        }
        if !self.disabled_builtins.contains(&BuiltinMib::UsmStats) {
            self.handlers.push(RegisteredHandler {
                prefix: oid!(1, 3, 6, 1, 6, 3, 15, 1, 1),
                handler: Arc::new(builtins::UsmStatsHandler {
                    state: Arc::clone(&state),
                }),
            });
        }
        if !self.disabled_builtins.contains(&BuiltinMib::MpdStats) {
            self.handlers.push(RegisteredHandler {
                prefix: oid!(1, 3, 6, 1, 6, 3, 11, 2, 1),
                handler: Arc::new(builtins::MpdStatsHandler {
                    state: Arc::clone(&state),
                }),
            });
        }

        // Sort handlers by prefix length (longest first) for matching
        self.handlers
            .sort_by_key(|h| std::cmp::Reverse(h.prefix.len()));

        Ok(Agent {
            inner: Arc::new(AgentInner {
                socket: Arc::new(socket),
                socket_state,
                local_addr,
                communities: self.communities,
                usm_users: self.usm_users,
                handlers: self.handlers,
                state,
                salt_counter: SaltCounter::new(),
                concurrency_limit,
                vacm: self.vacm,
                cancel,
                trap_sinks,
            }),
        })
    }
}

impl Default for AgentBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Engine state and counters shared across agent clones and (future) built-in handlers.
pub(crate) struct AgentState {
    pub(crate) engine_id: Bytes,
    pub(crate) engine_boots: AtomicU32,
    pub(crate) engine_time: AtomicU32,
    pub(crate) engine_start: Instant,
    /// Initial `engine_boots` value at startup, used to compute overflow-adjusted boots.
    pub(crate) engine_boots_base: u32,
    pub(crate) max_message_size: usize,
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
    /// RFC 3414 usmStats counters
    pub(crate) usm_stats: UsmStats,
}

/// Inner state shared across agent clones.
pub(crate) struct AgentInner {
    pub(crate) socket: Arc<UdpSocket>,
    pub(crate) socket_state: UdpSocketState,
    pub(crate) local_addr: SocketAddr,
    pub(crate) communities: Vec<Vec<u8>>,
    pub(crate) usm_users: HashMap<Bytes, UsmConfig>,
    pub(crate) handlers: Vec<RegisteredHandler>,
    pub(crate) state: Arc<AgentState>,
    pub(crate) salt_counter: SaltCounter,
    pub(crate) concurrency_limit: Option<Arc<Semaphore>>,
    pub(crate) vacm: Option<VacmConfig>,
    /// Cancellation token for graceful shutdown.
    pub(crate) cancel: CancellationToken,
    /// Configured trap/inform destinations.
    pub(crate) trap_sinks: Vec<notification::TrapSink>,
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
/// # async fn example() -> Result<(), Box<async_snmp::Error>> {
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
    #[must_use]
    pub fn builder() -> AgentBuilder {
        AgentBuilder::new()
    }

    /// Get the local address the agent is bound to.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr
    }

    /// Get the engine ID.
    #[must_use]
    pub fn engine_id(&self) -> &[u8] {
        &self.inner.state.engine_id
    }

    /// Get the current engine boots value.
    ///
    /// Useful for persisting across restarts per RFC 3414 Section 2.3.
    /// The persisted value should be passed to `AgentBuilder::engine_boots()`
    /// on the next startup.
    #[must_use]
    pub fn engine_boots(&self) -> u32 {
        self.inner.state.engine_boots.load(Ordering::Relaxed)
    }

    /// Get the current engine time value.
    #[must_use]
    pub fn engine_time(&self) -> u32 {
        self.inner.state.engine_time.load(Ordering::Relaxed)
    }

    /// Get the cancellation token for this agent.
    ///
    /// Call `token.cancel()` to initiate graceful shutdown.
    #[must_use]
    pub fn cancel(&self) -> CancellationToken {
        self.inner.cancel.clone()
    }

    /// Get the snmpInvalidMsgs counter value.
    ///
    /// This counter tracks messages with invalid msgFlags, such as
    /// privacy-without-authentication (RFC 3412 Section 7.2 Step 5d).
    ///
    /// OID: 1.3.6.1.6.3.11.2.1.2
    #[must_use]
    pub fn snmp_invalid_msgs(&self) -> u32 {
        self.inner.state.snmp_invalid_msgs.load(Ordering::Relaxed)
    }

    /// Get the snmpUnknownSecurityModels counter value.
    ///
    /// This counter tracks messages with unrecognized security models
    /// (RFC 3412 Section 7.2 Step 2).
    ///
    /// OID: 1.3.6.1.6.3.11.2.1.1
    #[must_use]
    pub fn snmp_unknown_security_models(&self) -> u32 {
        self.inner
            .state
            .snmp_unknown_security_models
            .load(Ordering::Relaxed)
    }

    /// Get the snmpSilentDrops counter value.
    ///
    /// This counter tracks confirmed-class PDUs (`GetRequest`, `GetNextRequest`,
    /// `GetBulkRequest`, `SetRequest`, `InformRequest`) that were silently dropped
    /// because even an empty Response-PDU would exceed the maximum message
    /// size constraint (RFC 3412 Section 7.1).
    ///
    /// OID: 1.3.6.1.6.3.11.2.1.3
    #[must_use]
    pub fn snmp_silent_drops(&self) -> u32 {
        self.inner.state.snmp_silent_drops.load(Ordering::Relaxed)
    }

    /// Get the usmStatsUnknownEngineIDs counter value.
    ///
    /// This counter tracks messages with unknown engine IDs.
    /// Incremented when a non-discovery request arrives with an engine ID that
    /// does not match the local engine (RFC 3414 Section 3.2 Step 3).
    ///
    /// OID: 1.3.6.1.6.3.15.1.1.4
    #[must_use]
    pub fn usm_unknown_engine_ids(&self) -> u32 {
        self.inner
            .state
            .usm_stats
            .unknown_engine_ids
            .load(Ordering::Relaxed)
    }

    /// Get the usmStatsUnknownUserNames counter value.
    ///
    /// This counter tracks messages with unknown user names.
    /// Incremented when a message arrives with a user name not in the local
    /// user database (RFC 3414 Section 3.2 Step 1).
    ///
    /// OID: 1.3.6.1.6.3.15.1.1.3
    #[must_use]
    pub fn usm_unknown_usernames(&self) -> u32 {
        self.inner
            .state
            .usm_stats
            .unknown_usernames
            .load(Ordering::Relaxed)
    }

    /// Get the usmStatsWrongDigests counter value.
    ///
    /// This counter tracks messages with incorrect authentication digests.
    /// (RFC 3414 Section 3.2 Step 6).
    ///
    /// OID: 1.3.6.1.6.3.15.1.1.5
    #[must_use]
    pub fn usm_wrong_digests(&self) -> u32 {
        self.inner
            .state
            .usm_stats
            .wrong_digests
            .load(Ordering::Relaxed)
    }

    /// Get the usmStatsNotInTimeWindows counter value.
    ///
    /// This counter tracks messages requesting an authenticated security
    /// level that fail the time window check (RFC 3414 Section 3.2 Step 7a):
    /// engine boots mismatch, boots latched at the maximum (checked before
    /// digest verification), or message time differing from the local time
    /// by more than 150 seconds.
    ///
    /// OID: 1.3.6.1.6.3.15.1.1.2
    #[must_use]
    pub fn usm_not_in_time_windows(&self) -> u32 {
        self.inner
            .state
            .usm_stats
            .not_in_time_windows
            .load(Ordering::Relaxed)
    }

    /// Get the usmStatsUnsupportedSecLevels counter value.
    ///
    /// This counter tracks messages where the user does not support
    /// the requested security level (e.g., auth required but user
    /// has no auth key configured). RFC 3414 Section 3.2.
    ///
    /// OID: 1.3.6.1.6.3.15.1.1.1
    #[must_use]
    pub fn usm_unsupported_sec_levels(&self) -> u32 {
        self.inner
            .state
            .usm_stats
            .unsupported_sec_levels
            .load(Ordering::Relaxed)
    }

    /// Get the usmStatsDecryptionErrors counter value.
    ///
    /// This counter tracks messages where decryption failed (the user
    /// has a privacy key but the decrypt operation returned an error).
    /// RFC 3414 Section 3.2.
    ///
    /// OID: 1.3.6.1.6.3.15.1.1.6
    #[must_use]
    pub fn usm_decryption_errors(&self) -> u32 {
        self.inner
            .state
            .usm_stats
            .decryption_errors
            .load(Ordering::Relaxed)
    }

    /// Returns agent uptime in hundredths of a second (centiseconds).
    ///
    /// Use this in your system MIB handler to provide sysUpTime.0
    /// (1.3.6.1.2.1.1.3.0) as a `Value::TimeTicks` value.
    #[must_use]
    pub fn uptime_hundredths(&self) -> u32 {
        let elapsed = self.inner.state.engine_start.elapsed();
        let centisecs = elapsed.as_millis() / 10;
        centisecs.min(u128::from(u32::MAX)) as u32
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
            let recv_meta = tokio::select! {
                result = self.recv_packet(&mut buf) => {
                    result?
                }
                () = self.inner.cancel.cancelled() => {
                    tracing::info!(target: "async_snmp::agent", "agent shutdown requested");
                    return Ok(());
                }
            };

            let data = Bytes::copy_from_slice(&buf[..recv_meta.len]);
            let agent = self.clone();

            let permit = if let Some(ref sem) = self.inner.concurrency_limit {
                Some(sem.clone().acquire_owned().await.expect("semaphore closed"))
            } else {
                None
            };

            tokio::spawn(async move {
                agent.update_engine_time();

                match agent.handle_request(data, recv_meta.addr).await {
                    Ok(Some(response_bytes)) => {
                        // Per RFC 3416 Section 4.2 the GET/GETNEXT/SET handlers
                        // already emit a tooBig Response when their result would
                        // not fit (and GETBULK Section 4.2.3 truncates or emits
                        // tooBig). This drop is the final fallback for when even
                        // that empty tooBig Response still exceeds the limit; the
                        // packet is then silently dropped (snmpSilentDrops).
                        if response_bytes.len() > agent.inner.state.max_message_size {
                            agent
                                .inner
                                .state
                                .snmp_silent_drops
                                .fetch_add(1, Ordering::Relaxed);
                            tracing::debug!(target: "async_snmp::agent", { snmp.source = %recv_meta.addr, response_size = response_bytes.len(), max_size = agent.inner.state.max_message_size }, "response exceeds max message size, silently dropped");
                        } else if let Err(e) =
                            agent.send_response(&response_bytes, &recv_meta).await
                        {
                            tracing::warn!(target: "async_snmp::agent", { snmp.source = %recv_meta.addr, error = %e }, "failed to send response");
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        tracing::warn!(target: "async_snmp::agent", { snmp.source = %recv_meta.addr, error = %e }, "error handling request");
                    }
                }

                drop(permit);
            });
        }
    }

    async fn recv_packet(&self, buf: &mut [u8]) -> Result<RecvMeta> {
        let mut iov = [IoSliceMut::new(buf)];
        let mut meta = [RecvMeta::default()];

        loop {
            self.inner
                .socket
                .readable()
                .await
                .map_err(|e| Error::Network {
                    target: self.inner.local_addr,
                    source: e,
                })?;

            let result = self.inner.socket.try_io(tokio::io::Interest::READABLE, || {
                let sref = UdpSockRef::from(&*self.inner.socket);
                self.inner.socket_state.recv(sref, &mut iov, &mut meta)
            });

            match result {
                Ok(n) if n > 0 => return Ok(meta[0]),
                Ok(_) => { /* fall thru to next `loop {}` iteration */ }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => { /* fall thru to next `loop {}` iteration */
                }
                Err(e) => {
                    return Err(Error::Network {
                        target: self.inner.local_addr,
                        source: e,
                    }
                    .boxed());
                }
            }
        }
    }

    async fn send_response(&self, data: &[u8], recv_meta: &RecvMeta) -> std::io::Result<()> {
        let transmit = Transmit {
            destination: recv_meta.addr,
            ecn: None,
            contents: data,
            segment_size: None,
            src_ip: recv_meta.dst_ip,
        };

        loop {
            self.inner.socket.writable().await?;

            let result = self.inner.socket.try_io(tokio::io::Interest::WRITABLE, || {
                let sref = UdpSockRef::from(&*self.inner.socket);
                self.inner.socket_state.try_send(sref, &transmit)
            });

            match result {
                Ok(()) => return Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => { /* fall thru to next `loop {}` iteration */
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Process a single request and return the response bytes.
    ///
    /// Returns `None` if no response should be sent.
    async fn handle_request(&self, data: Bytes, source: SocketAddr) -> Result<Option<Bytes>> {
        match crate::message::peek_version(data.clone(), source)? {
            Version::V1 => self.handle_v1(data, source).await,
            Version::V2c => self.handle_v2c(data, source).await,
            Version::V3 => self.handle_v3(data, source).await,
        }
    }

    /// Update engine boots and time based on elapsed time since start.
    ///
    /// Per RFC 3414 Section 2.3, when snmpEngineTime reaches `MAX_ENGINE_TIME`
    /// (2^31-1), snmpEngineBoots is incremented and snmpEngineTime resets to
    /// zero. The boots/time pair is derived from total elapsed seconds and
    /// the base boots value at startup, so no mutable state beyond the
    /// atomics is needed.
    fn update_engine_time(&self) {
        let total_secs = self.inner.state.engine_start.elapsed().as_secs();
        let (boots, time) =
            compute_engine_boots_time(self.inner.state.engine_boots_base, total_secs);

        if boots != self.inner.state.engine_boots.load(Ordering::Relaxed)
            && boots > self.inner.state.engine_boots_base
        {
            tracing::warn!(
                target: "async_snmp::agent",
                engine_boots = boots,
                "engine time wrapped past MAX_ENGINE_TIME, incrementing engine boots"
            );
        }

        self.inner
            .state
            .engine_boots
            .store(boots, Ordering::Relaxed);
        self.inner.state.engine_time.store(time, Ordering::Relaxed);
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
            PduType::GetBulkRequest => {
                // SNMPv1 does not support GETBULK
                if ctx.version == Version::V1 {
                    return Ok(pdu.to_error_response(ErrorStatus::GenErr, 0));
                }
                self.handle_get_bulk(ctx, pdu).await
            }
            PduType::SetRequest => self.handle_set(ctx, pdu).await,
            PduType::InformRequest => self.handle_inform(pdu),
            _ => {
                // Should not happen - filtered earlier
                Ok(pdu.to_error_response(ErrorStatus::GenErr, 0))
            }
        }
    }

    /// Handle `InformRequest` PDU.
    ///
    /// Per RFC 3416 Section 4.2.7, an `InformRequest` is a confirmed-class PDU
    /// that the receiver acknowledges by returning a Response with the same
    /// request-id and varbind list.
    #[allow(
        clippy::unnecessary_wraps,
        reason = "TODO store received informs, which may be a fallible operation"
    )]
    #[allow(
        clippy::unused_self,
        reason = "TODO store received informs, which may require self"
    )]
    fn handle_inform(&self, pdu: &Pdu) -> Result<Pdu> {
        // Simply acknowledge by returning the same varbinds in a Response
        Ok(pdu.to_response())
    }

    /// Effective maximum response message size for a request: the smaller of
    /// the agent's configured limit and the client's advertised `msgMaxSize`
    /// (v3). v1/v2c requests carry no `msg_max_size`, so the agent limit applies.
    fn effective_max_size(&self, ctx: &RequestContext) -> usize {
        let agent_max = self.inner.state.max_message_size;
        match ctx.msg_max_size {
            Some(client_max) => agent_max.min(client_max as usize),
            None => agent_max,
        }
    }

    /// Estimate whether a Response carrying `varbinds` fits within `max_size`,
    /// using the same estimate as GETBULK: `RESPONSE_OVERHEAD` plus the encoded
    /// size of each varbind.
    fn response_fits(varbinds: &[VarBind], max_size: usize) -> bool {
        let size = RESPONSE_OVERHEAD + varbinds.iter().map(VarBind::encoded_size).sum::<usize>();
        size <= max_size
    }

    /// Build the `tooBig` Response for `pdu`: error-status `tooBig`, error-index
    /// zero, and an empty variable-bindings field, per RFC 3416 Section 4.2.
    pub(super) fn too_big_response(pdu: &Pdu) -> Pdu {
        Pdu {
            pdu_type: PduType::Response,
            request_id: pdu.request_id,
            error_status: ErrorStatus::TooBig.as_i32(),
            error_index: 0,
            varbinds: Vec::new(),
        }
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
                    return Ok(pdu.to_error_response(ErrorStatus::NoSuchName, (index + 1) as i32));
                }
                // For GET, return NoSuchObject for inaccessible OIDs per RFC 3415
                response_varbinds.push(VarBind::new(vb.oid.clone(), Value::NoSuchObject));
                continue;
            }

            let result = if let Some(handler) = self.find_handler(&vb.oid) {
                handler.handler.get(ctx, &vb.oid).await
            } else {
                GetResult::NoSuchObject
            };

            let response_value = match result {
                GetResult::Value(v) => {
                    // RFC 2576 Section 4.1.2.3: Counter64 not valid in v1
                    if ctx.version == Version::V1 && matches!(v, Value::Counter64(_)) {
                        return Ok(
                            pdu.to_error_response(ErrorStatus::NoSuchName, (index + 1) as i32)
                        );
                    }
                    v
                }
                GetResult::NoSuchObject => {
                    // v1 returns noSuchName error, v2c/v3 returns NoSuchObject exception
                    if ctx.version == Version::V1 {
                        return Ok(
                            pdu.to_error_response(ErrorStatus::NoSuchName, (index + 1) as i32)
                        );
                    }
                    Value::NoSuchObject
                }
                GetResult::NoSuchInstance => {
                    // v1 returns noSuchName error, v2c/v3 returns NoSuchInstance exception
                    if ctx.version == Version::V1 {
                        return Ok(
                            pdu.to_error_response(ErrorStatus::NoSuchName, (index + 1) as i32)
                        );
                    }
                    Value::NoSuchInstance
                }
            };

            response_varbinds.push(VarBind::new(vb.oid.clone(), response_value));
        }

        // RFC 3416 Section 4.2.1: if the Response would exceed the message-size
        // limit, return a tooBig Response with an empty variable-bindings list.
        if !Self::response_fits(&response_varbinds, self.effective_max_size(ctx)) {
            return Ok(Self::too_big_response(pdu));
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
            // Try to find the next OID from any handler, skipping OIDs denied by
            // VACM. RFC 3413 classifies GETNEXT as Read-Class and requires
            // continuing the walk until an accessible OID is found.
            let next = self.get_next_accessible_oid(ctx, &vb.oid).await;

            if let Some(next_vb) = next {
                response_varbinds.push(next_vb);
            } else {
                // v1 returns noSuchName, v2c/v3 returns endOfMibView
                if ctx.version == Version::V1 {
                    return Ok(pdu.to_error_response(ErrorStatus::NoSuchName, (index + 1) as i32));
                }
                response_varbinds.push(VarBind::new(vb.oid.clone(), Value::EndOfMibView));
            }
        }

        // RFC 3416 Section 4.2.2: if the Response would exceed the message-size
        // limit, return a tooBig Response with an empty variable-bindings list.
        if !Self::response_fits(&response_varbinds, self.effective_max_size(ctx)) {
            return Ok(Self::too_big_response(pdu));
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
        let non_repeaters = pdu.error_status.try_into().unwrap_or(0);
        let max_repetitions = pdu.error_index.max(0);

        let mut response_varbinds = Vec::new();
        let mut current_size: usize = RESPONSE_OVERHEAD;
        let max_size = self.effective_max_size(ctx);

        // Helper to check if we can add a varbind
        let can_add = |vb: &VarBind, current_size: usize| -> bool {
            current_size + vb.encoded_size() <= max_size
        };

        // Handle non-repeaters (first N varbinds get one GETNEXT each)
        for vb in pdu.varbinds.iter().take(non_repeaters) {
            let next = self.get_next_accessible_oid(ctx, &vb.oid).await;

            let next_vb = match next {
                Some(next_vb) => next_vb,
                None => VarBind::new(vb.oid.clone(), Value::EndOfMibView),
            };

            if !can_add(&next_vb, current_size) {
                // Can't fit even non-repeaters, return tooBig if we have nothing
                if response_varbinds.is_empty() {
                    return Ok(Self::too_big_response(pdu));
                }
                // RFC 3416 Section 4.2.3: truncation removes variable bindings
                // from the END of the positional set. All repeaters are
                // positionally after every non-repeater, so once a non-repeater
                // is dropped, no later binding may appear. Return the
                // non-repeater prefix collected so far without running the
                // repeater loop (falling through would emit repeater varbinds
                // into the dropped non-repeater's slot).
                return Ok(Pdu {
                    pdu_type: PduType::Response,
                    request_id: pdu.request_id,
                    error_status: 0,
                    error_index: 0,
                    varbinds: response_varbinds,
                });
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
                        let next = self.get_next_accessible_oid(ctx, oid).await;

                        if let Some(next_vb) = next {
                            *oid = next_vb.oid.clone();
                            row_complete = false;
                            next_vb
                        } else {
                            all_done[i] = true;
                            VarBind::new(oid.clone(), Value::EndOfMibView)
                        }
                    };

                    // Check size before adding
                    if !can_add(&next_vb, current_size) {
                        // RFC 3416 Section 4.2.3 / net-snmp: if nothing has fit
                        // yet (common non_repeaters == 0 shape where the first
                        // repeater varbind is oversized), return tooBig with
                        // empty varbinds. Mirrors the non-repeater tooBig guard
                        // above; a bare noError+empty response is
                        // indistinguishable from end-of-MIB and silently ends a
                        // manager's walk instead of prompting a retry with a
                        // smaller max-repetitions.
                        if response_varbinds.is_empty() {
                            return Ok(Self::too_big_response(pdu));
                        }
                        // Some varbinds already fit: truncate (partial response).
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

    /// Find the next OID accessible under VACM, skipping denied OIDs by
    /// continuing the walk. Returns None when end-of-MIB is reached or all
    /// remaining candidates are denied.
    async fn get_next_accessible_oid(
        &self,
        ctx: &RequestContext,
        from_oid: &Oid,
    ) -> Option<VarBind> {
        let mut search_from = from_oid.clone();
        loop {
            let candidate = self.get_next_oid(ctx, &search_from).await;
            match candidate {
                None => return None,
                Some(ref next_vb) => {
                    if next_vb.oid <= search_from {
                        tracing::error!(
                            target: "async_snmp::agent",
                            from = %search_from,
                            got = %next_vb.oid,
                            "handler returned non-increasing OID in GETNEXT"
                        );
                        return None;
                    }
                    // RFC 2576 Section 4.1.2.3: skip Counter64 for v1
                    if ctx.version == Version::V1 && matches!(next_vb.value, Value::Counter64(_)) {
                        search_from = next_vb.oid.clone();
                        continue;
                    }
                    if let Some(ref vacm) = self.inner.vacm {
                        if vacm.check_access(ctx.read_view.as_ref(), &next_vb.oid) {
                            return candidate;
                        }
                        search_from = next_vb.oid.clone();
                    } else {
                        return candidate;
                    }
                }
            }
        }
    }

    /// Get the next OID from any handler.
    async fn get_next_oid(&self, ctx: &RequestContext, oid: &Oid) -> Option<VarBind> {
        // Find the first handler that can provide a next OID.
        //
        // A handler can only return an OID > oid if:
        //   - oid falls within the handler's subtree (oid starts with handler prefix), OR
        //   - the handler's entire subtree is after oid (handler prefix > oid)
        //
        // Handlers whose prefix is <= oid and whose subtree does not contain oid
        // cannot return anything useful and are skipped.
        let mut best_result: Option<VarBind> = None;

        for handler in &self.inner.handlers {
            let prefix = &handler.prefix;
            if prefix <= oid && !oid.starts_with(prefix) {
                continue;
            }
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
            msg_max_size: None,
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
        let prefix = oid!(1, 3, 6, 1, 4, 1, 99_999);

        // OID within prefix
        assert!(handler.handles(&prefix, &oid!(1, 3, 6, 1, 4, 1, 99_999, 1, 0)));

        // Exact prefix match
        assert!(handler.handles(&prefix, &oid!(1, 3, 6, 1, 4, 1, 99_999)));

        // OID before prefix - should NOT be handled (GET/SET routing must not claim
        // OIDs outside the registered subtree)
        assert!(!handler.handles(&prefix, &oid!(1, 3, 6, 1, 4, 1, 99_998)));

        // OID after prefix (not handled)
        assert!(!handler.handles(&prefix, &oid!(1, 3, 6, 1, 4, 1, 100_000)));
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

    // FiveOidHandler has OIDs at .99999.{1,2,3,4,5}.0 with integer values 1-5.
    struct FiveOidHandler;

    impl MibHandler for FiveOidHandler {
        fn get<'a>(&'a self, _ctx: &'a RequestContext, oid: &'a Oid) -> BoxFuture<'a, GetResult> {
            Box::pin(async move {
                for i in 1u16..=5 {
                    if oid == &oid!(1, 3, 6, 1, 4, 1, 99999, i.into(), 0) {
                        return GetResult::Value(Value::Integer(i.into()));
                    }
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
                for i in 1u32..=5 {
                    let candidate = oid!(1, 3, 6, 1, 4, 1, 99999, i, 0);
                    if oid < &candidate {
                        return GetNextResult::Value(VarBind::new(
                            candidate,
                            Value::Integer(i as i32),
                        ));
                    }
                }
                GetNextResult::EndOfMibView
            })
        }
    }

    /// Build an agent bound to a random port for testing, with a VACM view
    /// that only permits reading OIDs under .99999.2 and .99999.4 (odd OIDs
    /// 1, 3, 5 are denied). This exercises the VACM walk-past logic.
    async fn test_agent_with_restricted_vacm() -> Agent {
        Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), Arc::new(FiveOidHandler))
            .vacm(|v| {
                v.group("public", SecurityModel::V2c, "readers")
                    .access("readers", |a| a.read_view("restricted"))
                    .view("restricted", |v| {
                        v.include(oid!(1, 3, 6, 1, 4, 1, 99999, 2))
                            .include(oid!(1, 3, 6, 1, 4, 1, 99999, 4))
                    })
            })
            .build()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_getbulk_vacm_filters_inaccessible_oids() {
        let agent = test_agent_with_restricted_vacm().await;

        let mut ctx = test_ctx();
        ctx.pdu_type = PduType::GetBulkRequest;
        ctx.read_view = Some(Bytes::from_static(b"restricted"));

        // GETBULK starting before the handler prefix, requesting up to 10 repeats.
        // The handler has OIDs {1,2,3,4,5}.0 but only {2,4} are in the view.
        // The walk must skip denied OIDs and continue, returning both 2 and 4.
        let pdu = Pdu {
            pdu_type: PduType::GetBulkRequest,
            request_id: 1,
            error_status: 0, // non_repeaters
            error_index: 10, // max_repetitions
            varbinds: vec![VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999), Value::Null)],
        };

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();

        // Collect the OIDs returned (excluding EndOfMibView sentinels)
        let returned_oids: Vec<&Oid> = response
            .varbinds
            .iter()
            .filter(|vb| !matches!(vb.value, Value::EndOfMibView))
            .map(|vb| &vb.oid)
            .collect();

        // Both accessible OIDs must appear - the walk must not stop at the first one
        assert!(
            returned_oids.contains(&&oid!(1, 3, 6, 1, 4, 1, 99999, 2, 0)),
            "expected .99999.2.0 in response, got: {returned_oids:?}"
        );
        assert!(
            returned_oids.contains(&&oid!(1, 3, 6, 1, 4, 1, 99999, 4, 0)),
            "expected .99999.4.0 in response (walk must continue past denied OIDs), got: {returned_oids:?}"
        );

        // Denied OIDs must not appear
        for &oid in &[
            &oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0),
            &oid!(1, 3, 6, 1, 4, 1, 99999, 3, 0),
            &oid!(1, 3, 6, 1, 4, 1, 99999, 5, 0),
        ] {
            assert!(
                !returned_oids.contains(&oid),
                "GETBULK returned OID outside read view: {oid:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_getbulk_non_repeaters_vacm_filtered() {
        let agent = test_agent_with_restricted_vacm().await;

        let mut ctx = test_ctx();
        ctx.pdu_type = PduType::GetBulkRequest;
        ctx.read_view = Some(Bytes::from_static(b"restricted"));

        // GETBULK with non_repeaters=2, max_repetitions=0.
        // First varbind starts before the subtree: walks past denied .99999.1.0
        // and returns the first accessible .99999.2.0.
        // Second varbind starts at .99999.4.0 (the last accessible OID): walks
        // to .99999.5.0 (denied) and then hits end-of-MIB, returning EndOfMibView.
        let pdu = Pdu {
            pdu_type: PduType::GetBulkRequest,
            request_id: 2,
            error_status: 2, // non_repeaters
            error_index: 0,  // max_repetitions
            varbinds: vec![
                VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999), Value::Null),
                VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999, 4, 0), Value::Null),
            ],
        };

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();

        // First non-repeater skips denied .99999.1.0 and returns accessible .99999.2.0
        assert_eq!(
            response.varbinds[0].oid,
            oid!(1, 3, 6, 1, 4, 1, 99999, 2, 0)
        );
        assert!(matches!(response.varbinds[0].value, Value::Integer(2)));

        // Second non-repeater walks to .99999.5.0 (denied), then end-of-MIB
        assert_eq!(response.varbinds[1].value, Value::EndOfMibView);
    }

    // TestHandler with three OIDs: .99999.1.0, .99999.2.0, .99999.3.0
    struct ThreeOidHandler;

    impl MibHandler for ThreeOidHandler {
        fn get<'a>(&'a self, _ctx: &'a RequestContext, oid: &'a Oid) -> BoxFuture<'a, GetResult> {
            Box::pin(async move {
                if oid == &oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0) {
                    return GetResult::Value(Value::Integer(1));
                }
                if oid == &oid!(1, 3, 6, 1, 4, 1, 99999, 2, 0) {
                    return GetResult::Value(Value::Integer(2));
                }
                if oid == &oid!(1, 3, 6, 1, 4, 1, 99999, 3, 0) {
                    return GetResult::Value(Value::Integer(3));
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
                let oid3 = oid!(1, 3, 6, 1, 4, 1, 99999, 3, 0);

                if oid < &oid1 {
                    return GetNextResult::Value(VarBind::new(oid1, Value::Integer(1)));
                }
                if oid < &oid2 {
                    return GetNextResult::Value(VarBind::new(oid2, Value::Integer(2)));
                }
                if oid < &oid3 {
                    return GetNextResult::Value(VarBind::new(oid3, Value::Integer(3)));
                }
                GetNextResult::EndOfMibView
            })
        }
    }

    /// Build an agent with `ThreeOidHandler` and a VACM view that includes
    /// .99999.1 and .99999.3 but excludes .99999.2.
    async fn test_agent_with_gap_vacm() -> Agent {
        Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), Arc::new(ThreeOidHandler))
            .vacm(|v| {
                v.group("public", SecurityModel::V2c, "readers")
                    .access("readers", |a| a.read_view("gap"))
                    .view("gap", |v| {
                        v.include(oid!(1, 3, 6, 1, 4, 1, 99999, 1))
                            .include(oid!(1, 3, 6, 1, 4, 1, 99999, 3))
                    })
            })
            .build()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_getnext_vacm_skips_inaccessible_continues_walk() {
        // GETNEXT must continue past denied OIDs to find the next accessible one.
        // .99999.2.0 is excluded from the view; .99999.3.0 is included.
        // GETNEXT from .99999.1.0 should skip .99999.2.0 and return .99999.3.0.
        let agent = test_agent_with_gap_vacm().await;

        let mut ctx = test_ctx();
        ctx.pdu_type = PduType::GetNextRequest;
        ctx.read_view = Some(Bytes::from_static(b"gap"));

        let pdu = Pdu {
            pdu_type: PduType::GetNextRequest,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbinds: vec![VarBind::new(
                oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0),
                Value::Null,
            )],
        };

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();
        assert_eq!(response.varbinds.len(), 1);
        assert_eq!(
            response.varbinds[0].oid,
            oid!(1, 3, 6, 1, 4, 1, 99999, 3, 0),
            "GETNEXT should skip denied .99999.2.0 and return accessible .99999.3.0"
        );
        assert!(matches!(response.varbinds[0].value, Value::Integer(3)));
    }

    #[tokio::test]
    async fn test_getnext_vacm_all_remaining_denied_returns_end_of_mib() {
        // When all remaining OIDs are denied, GETNEXT should return EndOfMibView.
        // Start at .99999.4.0 (the last accessible OID). The only OID after it
        // is .99999.5.0 which is denied, so the walk reaches end-of-MIB.
        let agent = test_agent_with_restricted_vacm().await;

        let mut ctx = test_ctx();
        ctx.pdu_type = PduType::GetNextRequest;
        ctx.read_view = Some(Bytes::from_static(b"restricted"));

        let pdu = Pdu {
            pdu_type: PduType::GetNextRequest,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbinds: vec![VarBind::new(
                oid!(1, 3, 6, 1, 4, 1, 99999, 4, 0),
                Value::Null,
            )],
        };

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();
        assert_eq!(response.varbinds.len(), 1);
        assert_eq!(
            response.varbinds[0].value,
            Value::EndOfMibView,
            "GETNEXT should return EndOfMibView when all remaining OIDs are denied"
        );
    }

    #[tokio::test]
    async fn test_getbulk_without_vacm_returns_all_oids() {
        // Sanity check: without VACM, both OIDs should be returned
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), Arc::new(TestHandler))
            .build()
            .await
            .unwrap();

        let mut ctx = test_ctx();
        ctx.pdu_type = PduType::GetBulkRequest;

        let pdu = Pdu {
            pdu_type: PduType::GetBulkRequest,
            request_id: 1,
            error_status: 0,
            error_index: 10,
            varbinds: vec![VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999), Value::Null)],
        };

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();

        // Both OIDs should appear
        assert!(
            response
                .varbinds
                .iter()
                .any(|vb| vb.oid == oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0))
        );
        assert!(
            response
                .varbinds
                .iter()
                .any(|vb| vb.oid == oid!(1, 3, 6, 1, 4, 1, 99999, 2, 0))
        );
    }

    #[tokio::test]
    async fn test_v1_getbulk_rejected() {
        // SNMPv1 does not support GETBULK. Should return GenErr.
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), Arc::new(TestHandler))
            .build()
            .await
            .unwrap();

        let mut ctx = test_ctx();
        ctx.version = Version::V1;
        ctx.security_model = SecurityModel::V1;
        ctx.pdu_type = PduType::GetBulkRequest;

        let pdu = Pdu {
            pdu_type: PduType::GetBulkRequest,
            request_id: 1,
            error_status: 0,
            error_index: 10,
            varbinds: vec![VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999), Value::Null)],
        };

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();
        assert_eq!(
            ErrorStatus::from_i32(response.error_status),
            ErrorStatus::GenErr,
            "v1 GETBULK should be rejected"
        );
    }

    /// Handler returning Counter64 at .99999.1.0, Integer at .99999.2.0
    struct Counter64Handler;

    impl MibHandler for Counter64Handler {
        fn get<'a>(&'a self, _ctx: &'a RequestContext, oid: &'a Oid) -> BoxFuture<'a, GetResult> {
            Box::pin(async move {
                if oid == &oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0) {
                    return GetResult::Value(Value::Counter64(1_000_000_000_000));
                }
                if oid == &oid!(1, 3, 6, 1, 4, 1, 99999, 2, 0) {
                    return GetResult::Value(Value::Integer(42));
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
                    return GetNextResult::Value(VarBind::new(
                        oid1,
                        Value::Counter64(1_000_000_000_000),
                    ));
                }
                if oid < &oid2 {
                    return GetNextResult::Value(VarBind::new(oid2, Value::Integer(42)));
                }
                GetNextResult::EndOfMibView
            })
        }
    }

    async fn test_agent_with_counter64() -> Agent {
        Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), Arc::new(Counter64Handler))
            .build()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_v1_get_filters_counter64() {
        // RFC 2576 Section 4.1.2.3: Counter64 not valid in v1 GET responses.
        // Should return noSuchName for the Counter64 varbind.
        let agent = test_agent_with_counter64().await;

        let mut ctx = test_ctx();
        ctx.version = Version::V1;
        ctx.security_model = SecurityModel::V1;
        ctx.pdu_type = PduType::GetRequest;

        let pdu = Pdu {
            pdu_type: PduType::GetRequest,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbinds: vec![VarBind::new(
                oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0),
                Value::Null,
            )],
        };

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();
        assert_eq!(
            ErrorStatus::from_i32(response.error_status),
            ErrorStatus::NoSuchName,
            "v1 GET of Counter64 should return noSuchName"
        );
    }

    #[tokio::test]
    async fn test_v2c_get_allows_counter64() {
        // v2c should return Counter64 normally
        let agent = test_agent_with_counter64().await;

        let ctx = test_ctx(); // v2c by default

        let pdu = Pdu {
            pdu_type: PduType::GetRequest,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbinds: vec![VarBind::new(
                oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0),
                Value::Null,
            )],
        };

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();
        assert_eq!(response.error_status, 0);
        assert!(matches!(response.varbinds[0].value, Value::Counter64(_)));
    }

    #[tokio::test]
    async fn test_getbulk_respects_v3_msg_max_size() {
        // When msg_max_size is set (V3 request), GETBULK should limit the
        // response to fit within min(agent_max, client_msg_max_size).
        // The agent has a large max_message_size, but the client advertises
        // a small msgMaxSize that can only fit a few varbinds.
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .max_message_size(65507) // agent allows large responses
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), Arc::new(FiveOidHandler))
            .build()
            .await
            .unwrap();

        // First, get the full response without msg_max_size limit
        let mut ctx_unlimited = test_ctx();
        ctx_unlimited.pdu_type = PduType::GetBulkRequest;
        ctx_unlimited.msg_max_size = None;

        let pdu = Pdu {
            pdu_type: PduType::GetBulkRequest,
            request_id: 1,
            error_status: 0, // non_repeaters
            error_index: 10, // max_repetitions
            varbinds: vec![VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999), Value::Null)],
        };

        let full_response = agent.dispatch_request(&ctx_unlimited, &pdu).await.unwrap();
        let full_count = full_response
            .varbinds
            .iter()
            .filter(|vb| !matches!(vb.value, Value::EndOfMibView))
            .count();
        assert!(
            full_count >= 3,
            "expected at least 3 data varbinds without limit, got {full_count}"
        );

        // Now set a small msg_max_size that limits the response.
        // RESPONSE_OVERHEAD is 100, and each varbind for OIDs like
        // .1.3.6.1.4.1.99999.N.0 with Integer value is ~22 bytes.
        // Set msg_max_size to fit overhead + ~2 varbinds but not all 5.
        let mut ctx_limited = test_ctx();
        ctx_limited.pdu_type = PduType::GetBulkRequest;
        ctx_limited.msg_max_size = Some(150); // overhead(100) + room for ~2 varbinds

        let limited_response = agent.dispatch_request(&ctx_limited, &pdu).await.unwrap();
        let limited_count = limited_response
            .varbinds
            .iter()
            .filter(|vb| !matches!(vb.value, Value::EndOfMibView))
            .count();

        assert!(
            limited_count < full_count,
            "V3 msg_max_size should limit response: got {limited_count} varbinds (unlimited: {full_count})"
        );
        assert!(
            limited_count > 0,
            "should still return at least one varbind"
        );
    }

    // Handler with two large non-repeater values under .99999.1.0 and
    // .99999.2.0, and a small repeater value under .99999.9.0.
    struct MixedSizeHandler;

    impl MibHandler for MixedSizeHandler {
        fn get<'a>(&'a self, _ctx: &'a RequestContext, oid: &'a Oid) -> BoxFuture<'a, GetResult> {
            Box::pin(async move {
                if oid == &oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0)
                    || oid == &oid!(1, 3, 6, 1, 4, 1, 99999, 2, 0)
                {
                    return GetResult::Value(Value::OctetString(Bytes::from(vec![0xAB; 200])));
                }
                if oid == &oid!(1, 3, 6, 1, 4, 1, 99999, 9, 0) {
                    return GetResult::Value(Value::Integer(7));
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
                let big1 = oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0);
                let big2 = oid!(1, 3, 6, 1, 4, 1, 99999, 2, 0);
                let small = oid!(1, 3, 6, 1, 4, 1, 99999, 9, 0);
                if oid < &big1 {
                    return GetNextResult::Value(VarBind::new(
                        big1,
                        Value::OctetString(Bytes::from(vec![0xAB; 200])),
                    ));
                }
                if oid < &big2 {
                    return GetNextResult::Value(VarBind::new(
                        big2,
                        Value::OctetString(Bytes::from(vec![0xAB; 200])),
                    ));
                }
                if oid < &small {
                    return GetNextResult::Value(VarBind::new(small, Value::Integer(7)));
                }
                GetNextResult::EndOfMibView
            })
        }
    }

    #[tokio::test]
    async fn test_getbulk_dropped_non_repeater_omits_repeaters() {
        // RFC 3416 Section 4.2.3: truncation removes variable bindings from the
        // END of the positional set. Repeaters are positionally after all
        // non-repeaters, so if a non-repeater does not fit, no repeater binding
        // may appear in the response. Regression test for the fall-through bug
        // where a dropped non-repeater let repeater varbinds bleed into its slot.
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .max_message_size(65507)
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), Arc::new(MixedSizeHandler))
            .without_builtin_handlers()
            .build()
            .await
            .unwrap();

        // Size the limit so the first (big) non-repeater fits, the second (big)
        // does not, but a small repeater varbind WOULD fit if it were reached.
        let big_vb = VarBind::new(
            oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0),
            Value::OctetString(Bytes::from(vec![0xAB; 200])),
        );
        let small_vb = VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999, 9, 0), Value::Integer(7));
        let max = RESPONSE_OVERHEAD + big_vb.encoded_size() + small_vb.encoded_size();

        let mut ctx = test_ctx();
        ctx.pdu_type = PduType::GetBulkRequest;
        ctx.msg_max_size = Some(max as u32);

        let pdu = Pdu {
            pdu_type: PduType::GetBulkRequest,
            request_id: 1,
            error_status: 2, // non_repeaters
            error_index: 2,  // max_repetitions
            varbinds: vec![
                VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999, 1), Value::Null),
                VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999, 2), Value::Null),
                VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999, 9), Value::Null),
            ],
        };

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();

        // Only the first non-repeater fit; the response is exactly that prefix.
        assert_eq!(
            response.varbinds.len(),
            1,
            "expected exactly the non-repeater prefix, got {:?}",
            response
                .varbinds
                .iter()
                .map(|vb| &vb.oid)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            response.varbinds[0].oid,
            oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0)
        );
        // The repeater varbind must not have bled into the dropped slot.
        assert!(
            !response
                .varbinds
                .iter()
                .any(|vb| vb.oid == oid!(1, 3, 6, 1, 4, 1, 99999, 9, 0)),
            "repeater varbind leaked into response after a dropped non-repeater"
        );
    }

    #[tokio::test]
    async fn test_getbulk_too_big_has_empty_varbinds() {
        // RFC 3416 Section 4.2: a tooBig Response has an empty variable-bindings
        // field. When not even the first GETBULK varbind fits, respond tooBig.
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .max_message_size(65507)
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), Arc::new(MixedSizeHandler))
            .without_builtin_handlers()
            .build()
            .await
            .unwrap();

        let mut ctx = test_ctx();
        ctx.pdu_type = PduType::GetBulkRequest;
        // Below RESPONSE_OVERHEAD, so even the first varbind cannot fit.
        ctx.msg_max_size = Some((RESPONSE_OVERHEAD - 1) as u32);

        let pdu = Pdu {
            pdu_type: PduType::GetBulkRequest,
            request_id: 1,
            error_status: 2, // non_repeaters
            error_index: 2,  // max_repetitions
            varbinds: vec![
                VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999, 1), Value::Null),
                VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999, 2), Value::Null),
                VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999, 9), Value::Null),
            ],
        };

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();

        assert_eq!(response.error_status, ErrorStatus::TooBig.as_i32());
        assert!(
            response.varbinds.is_empty(),
            "tooBig Response must have empty varbinds, got {}",
            response.varbinds.len()
        );
    }

    #[tokio::test]
    async fn test_getbulk_too_big_zero_non_repeaters_first_repeater_oversized() {
        // RFC 3416 Section 4.2.3 / net-snmp: for the common GETBULK shape
        // non_repeaters == 0, when the FIRST repeater varbind does not fit the
        // size limit, respond tooBig with empty varbinds (not a bare
        // noError+empty response, which a manager cannot distinguish from
        // end-of-MIB). Regression test for the repeater-loop `break 'outer`
        // path that returned error_status 0 with empty varbinds.
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .max_message_size(65507)
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), Arc::new(MixedSizeHandler))
            .without_builtin_handlers()
            .build()
            .await
            .unwrap();

        // The first repeater get_next from .99999.1 returns big1 (200-byte
        // OctetString). Size the limit above RESPONSE_OVERHEAD (so this is not
        // the trivial below-overhead case) but below what big1 needs, so big1
        // is the first varbind and does not fit.
        let big_vb = VarBind::new(
            oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0),
            Value::OctetString(Bytes::from(vec![0xAB; 200])),
        );
        let max = RESPONSE_OVERHEAD + big_vb.encoded_size() - 1;

        let mut ctx = test_ctx();
        ctx.pdu_type = PduType::GetBulkRequest;
        ctx.msg_max_size = Some(max as u32);

        let pdu = Pdu {
            pdu_type: PduType::GetBulkRequest,
            request_id: 1,
            error_status: 0, // non_repeaters == 0
            error_index: 5,  // max_repetitions
            varbinds: vec![VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999, 1), Value::Null)],
        };

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();

        assert_eq!(
            response.error_status,
            ErrorStatus::TooBig.as_i32(),
            "first oversized repeater varbind (non_repeaters == 0) must yield tooBig"
        );
        assert!(
            response.varbinds.is_empty(),
            "tooBig Response must have empty varbinds, got {}",
            response.varbinds.len()
        );
    }

    #[tokio::test]
    async fn test_getbulk_msg_max_size_none_uses_agent_max() {
        // Without msg_max_size (v1/v2c), the agent's own max_message_size is used.
        // With a large agent max, all 5 OIDs should be returned.
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .max_message_size(65507)
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), Arc::new(FiveOidHandler))
            .without_builtin_handlers()
            .build()
            .await
            .unwrap();

        let mut ctx = test_ctx();
        ctx.pdu_type = PduType::GetBulkRequest;
        ctx.msg_max_size = None; // v2c, no client limit

        let pdu = Pdu {
            pdu_type: PduType::GetBulkRequest,
            request_id: 1,
            error_status: 0,
            error_index: 10,
            varbinds: vec![VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999), Value::Null)],
        };

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();
        let data_count = response
            .varbinds
            .iter()
            .filter(|vb| !matches!(vb.value, Value::EndOfMibView))
            .count();
        assert_eq!(
            data_count, 5,
            "all 5 OIDs should be returned without msg_max_size limit"
        );
    }

    #[tokio::test]
    async fn test_v1_getnext_skips_counter64() {
        // RFC 2576 Section 4.1.2.3: Counter64 skipped in v1 GETNEXT.
        // Walking from .99999 should skip the Counter64 at .99999.1.0
        // and return the Integer at .99999.2.0.
        let agent = test_agent_with_counter64().await;

        let mut ctx = test_ctx();
        ctx.version = Version::V1;
        ctx.security_model = SecurityModel::V1;
        ctx.pdu_type = PduType::GetNextRequest;

        let pdu = Pdu {
            pdu_type: PduType::GetNextRequest,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbinds: vec![VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999), Value::Null)],
        };

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();
        assert_eq!(response.error_status, 0, "should succeed");
        assert_eq!(
            response.varbinds[0].oid,
            oid!(1, 3, 6, 1, 4, 1, 99999, 2, 0),
            "should skip Counter64 and return next non-Counter64 OID"
        );
        assert!(matches!(response.varbinds[0].value, Value::Integer(42)));
    }

    #[test]
    fn test_engine_time_no_overflow() {
        // Normal operation: elapsed < MAX_ENGINE_TIME, boots stays at base
        let (boots, time) = crate::v3::compute_engine_boots_time(1, 1000);
        assert_eq!(boots, 1);
        assert_eq!(time, 1000);
    }

    #[test]
    fn test_engine_time_zero_elapsed() {
        let (boots, time) = crate::v3::compute_engine_boots_time(1, 0);
        assert_eq!(boots, 1);
        assert_eq!(time, 0);
    }

    #[test]
    fn test_engine_time_just_below_max() {
        let max = crate::v3::MAX_ENGINE_TIME;
        let (boots, time) = crate::v3::compute_engine_boots_time(1, u64::from(max) - 1);
        assert_eq!(boots, 1);
        assert_eq!(time, max - 1);
    }

    #[test]
    fn test_engine_time_at_max_wraps() {
        // Exactly at MAX_ENGINE_TIME seconds: boots increments, time resets to 0
        let max = crate::v3::MAX_ENGINE_TIME;
        let (boots, time) = crate::v3::compute_engine_boots_time(1, u64::from(max));
        assert_eq!(
            boots, 2,
            "boots should increment when elapsed reaches MAX_ENGINE_TIME"
        );
        assert_eq!(time, 0, "time should wrap to 0");
    }

    #[test]
    fn test_engine_time_past_max() {
        // 500 seconds past the first wrap
        let max = crate::v3::MAX_ENGINE_TIME;
        let (boots, time) = crate::v3::compute_engine_boots_time(1, u64::from(max) + 500);
        assert_eq!(boots, 2);
        assert_eq!(time, 500);
    }

    #[test]
    fn test_engine_time_multiple_wraps() {
        // Three full cycles
        let max = crate::v3::MAX_ENGINE_TIME;
        let elapsed = u64::from(max) * 3 + 42;
        let (boots, time) = crate::v3::compute_engine_boots_time(1, elapsed);
        assert_eq!(boots, 4, "base 1 + 3 wraps = 4");
        assert_eq!(time, 42);
    }

    #[test]
    fn test_engine_time_boots_capped_at_max() {
        // If enough wraps happen that boots would exceed MAX_ENGINE_TIME, cap it
        let max = crate::v3::MAX_ENGINE_TIME;
        let elapsed = u64::from(max) * u64::from(max); // way more wraps than max allows
        let (boots, _time) = crate::v3::compute_engine_boots_time(1, elapsed);
        assert_eq!(boots, max, "boots should be capped at MAX_ENGINE_TIME");
    }

    #[test]
    fn test_engine_time_base_boots_preserved() {
        // A non-1 base boots (e.g. from persistence) is respected
        let max = crate::v3::MAX_ENGINE_TIME;
        let (boots, time) = crate::v3::compute_engine_boots_time(5, u64::from(max) + 100);
        assert_eq!(boots, 6, "base 5 + 1 wrap = 6");
        assert_eq!(time, 100);
    }

    #[test]
    fn test_engine_time_high_base_boots_capped() {
        // Base boots near MAX_ENGINE_TIME with a wrap should cap
        let max = crate::v3::MAX_ENGINE_TIME;
        let (boots, _time) = crate::v3::compute_engine_boots_time(max - 1, u64::from(max) * 2);
        assert_eq!(boots, max, "should cap at MAX_ENGINE_TIME, not overflow");
    }

    #[tokio::test]
    async fn test_engine_boots_builder() {
        // engine_boots builder method sets the initial boots value
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .engine_boots(42)
            .build()
            .await
            .unwrap();

        assert_eq!(agent.engine_boots(), 42);
    }

    #[tokio::test]
    async fn test_engine_boots_default() {
        // Default engine_boots is 1
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .build()
            .await
            .unwrap();

        assert_eq!(agent.engine_boots(), 1);
    }

    #[tokio::test]
    async fn test_usm_counter_accessors_default_zero() {
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .build()
            .await
            .unwrap();

        assert_eq!(agent.usm_unsupported_sec_levels(), 0);
        assert_eq!(agent.usm_decryption_errors(), 0);
    }

    #[test]
    fn test_builtin_mib_without_single() {
        let builder = AgentBuilder::new().without_builtin_handler(BuiltinMib::UsmStats);
        assert!(builder.disabled_builtins.contains(&BuiltinMib::UsmStats));
        assert!(!builder.disabled_builtins.contains(&BuiltinMib::SnmpEngine));
        assert!(!builder.disabled_builtins.contains(&BuiltinMib::MpdStats));
    }

    #[test]
    fn test_builtin_mib_without_all() {
        let builder = AgentBuilder::new().without_builtin_handlers();
        assert!(builder.disabled_builtins.contains(&BuiltinMib::SnmpEngine));
        assert!(builder.disabled_builtins.contains(&BuiltinMib::UsmStats));
        assert!(builder.disabled_builtins.contains(&BuiltinMib::MpdStats));
    }

    #[tokio::test]
    async fn test_uptime_hundredths() {
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .build()
            .await
            .unwrap();

        let uptime = agent.uptime_hundredths();
        assert!(
            uptime < 100,
            "uptime should be less than 1 second, got {uptime}"
        );

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let uptime2 = agent.uptime_hundredths();
        assert!(uptime2 > uptime, "uptime should increase after delay");
    }

    #[tokio::test]
    async fn test_builtin_handlers_registered_by_default() {
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .build()
            .await
            .unwrap();

        let ctx = test_ctx();

        // snmpEngineMaxMessageSize.0 should be queryable
        let handler = agent
            .find_handler(&oid!(1, 3, 6, 1, 6, 3, 10, 2, 1, 4, 0))
            .expect("snmpEngine handler should be registered");
        let get_result = handler
            .handler
            .get(&ctx, &oid!(1, 3, 6, 1, 6, 3, 10, 2, 1, 4, 0))
            .await;
        assert!(matches!(get_result, GetResult::Value(Value::Integer(_))));

        // usmStatsWrongDigests.0 should be queryable
        let handler = agent
            .find_handler(&oid!(1, 3, 6, 1, 6, 3, 15, 1, 1, 5, 0))
            .expect("USM stats handler should be registered");
        let get_result = handler
            .handler
            .get(&ctx, &oid!(1, 3, 6, 1, 6, 3, 15, 1, 1, 5, 0))
            .await;
        assert!(matches!(get_result, GetResult::Value(Value::Counter32(0))));

        // snmpUnknownSecurityModels.0 should be queryable
        let handler = agent
            .find_handler(&oid!(1, 3, 6, 1, 6, 3, 11, 2, 1, 1, 0))
            .expect("MPD stats handler should be registered");
        let get_result = handler
            .handler
            .get(&ctx, &oid!(1, 3, 6, 1, 6, 3, 11, 2, 1, 1, 0))
            .await;
        assert!(matches!(get_result, GetResult::Value(Value::Counter32(0))));
    }

    #[tokio::test]
    async fn test_builtin_handlers_disabled() {
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .without_builtin_handlers()
            .build()
            .await
            .unwrap();

        assert!(
            agent
                .find_handler(&oid!(1, 3, 6, 1, 6, 3, 10, 2, 1, 1, 0))
                .is_none()
        );
        assert!(
            agent
                .find_handler(&oid!(1, 3, 6, 1, 6, 3, 15, 1, 1, 1, 0))
                .is_none()
        );
        assert!(
            agent
                .find_handler(&oid!(1, 3, 6, 1, 6, 3, 11, 2, 1, 1, 0))
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_builtin_handler_selective_disable() {
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .without_builtin_handler(BuiltinMib::UsmStats)
            .build()
            .await
            .unwrap();

        assert!(
            agent
                .find_handler(&oid!(1, 3, 6, 1, 6, 3, 10, 2, 1, 1, 0))
                .is_some()
        );
        assert!(
            agent
                .find_handler(&oid!(1, 3, 6, 1, 6, 3, 15, 1, 1, 1, 0))
                .is_none()
        );
        assert!(
            agent
                .find_handler(&oid!(1, 3, 6, 1, 6, 3, 11, 2, 1, 1, 0))
                .is_some()
        );
    }

    // Build an agent whose effective response size limit only fits a couple of
    // varbinds, used to exercise the RFC 3416 tooBig paths for GET/GETNEXT.
    async fn small_limit_agent() -> Agent {
        Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .max_message_size(150)
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), Arc::new(FiveOidHandler))
            .without_builtin_handlers()
            .build()
            .await
            .unwrap()
    }

    fn five_varbinds() -> Vec<VarBind> {
        (1u32..=5)
            .map(|i| VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999, i, 0), Value::Null))
            .collect()
    }

    #[tokio::test]
    async fn test_get_too_big_returns_toobig_response() {
        let agent = small_limit_agent().await;
        let ctx = test_ctx();

        // GET for all five OIDs; the response cannot fit within the 150-byte
        // effective limit, so RFC 3416 Section 4.2.1 requires a tooBig Response.
        let pdu = Pdu {
            pdu_type: PduType::GetRequest,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbinds: five_varbinds(),
        };

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();
        assert_eq!(response.error_status, ErrorStatus::TooBig.as_i32());
        assert_eq!(response.error_index, 0);
        assert!(response.varbinds.is_empty());
    }

    #[tokio::test]
    async fn test_get_within_limit_returns_response() {
        let agent = small_limit_agent().await;
        let ctx = test_ctx();

        // A single varbind fits comfortably; the tooBig check must not fire.
        let pdu = Pdu {
            pdu_type: PduType::GetRequest,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbinds: vec![VarBind::new(
                oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0),
                Value::Null,
            )],
        };

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();
        assert_eq!(response.error_status, 0);
        assert_eq!(response.varbinds.len(), 1);
        assert!(matches!(response.varbinds[0].value, Value::Integer(1)));
    }

    #[tokio::test]
    async fn test_getnext_too_big_returns_toobig_response() {
        let agent = small_limit_agent().await;
        let mut ctx = test_ctx();
        ctx.pdu_type = PduType::GetNextRequest;

        let pdu = Pdu {
            pdu_type: PduType::GetNextRequest,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbinds: five_varbinds(),
        };

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();
        assert_eq!(response.error_status, ErrorStatus::TooBig.as_i32());
        assert_eq!(response.error_index, 0);
        assert!(response.varbinds.is_empty());
    }

    #[tokio::test]
    async fn test_getnext_within_limit_returns_response() {
        let agent = small_limit_agent().await;
        let mut ctx = test_ctx();
        ctx.pdu_type = PduType::GetNextRequest;

        let pdu = Pdu {
            pdu_type: PduType::GetNextRequest,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbinds: vec![VarBind::new(
                oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0),
                Value::Null,
            )],
        };

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();
        assert_eq!(response.error_status, 0);
        assert_eq!(response.varbinds.len(), 1);
        assert_eq!(
            response.varbinds[0].oid,
            oid!(1, 3, 6, 1, 4, 1, 99999, 2, 0)
        );
    }
}
