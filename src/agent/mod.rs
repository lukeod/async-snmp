//! SNMP agent implementation (RFC 3413).
//!
//! [`Agent`] responds to GET, GETNEXT, GETBULK, and SET requests and can send
//! traps and informs to configured sinks.
//!
//! # Components
//!
//! - Async [`MibHandler`] methods
//! - Multi-phase SET processing (`test`/`commit`/`undo`/`free`) under RFC 3416
//! - Optional View-based Access Control Model (VACM, RFC 3415)
//! - Trap and inform delivery through [`Agent::send_trap`] and
//!   [`Agent::send_inform`]
//! - Read-only handlers for the snmpEngine, usmStats, and mpdStats groups; see
//!   [`BuiltinMib`]
//!
//! # Example
//!
//! ```rust,no_run
//! use async_snmp::agent::Agent;
//! use async_snmp::handler::{MibHandler, RequestContext, GetResult, GetNextResult, HandlerResult, BoxFuture};
//! use async_snmp::{Oid, Value, VarBind, oid};
//! use std::sync::Arc;
//!
//! // Define a simple handler for the system MIB subtree
//! struct SystemMibHandler;
//!
//! impl MibHandler for SystemMibHandler {
//!     fn get<'a>(&'a self, _ctx: &'a RequestContext, oid: &'a Oid) -> BoxFuture<'a, HandlerResult<GetResult>> {
//!         Box::pin(async move {
//!             // sysDescr.0
//!             if oid == &oid!(1, 3, 6, 1, 2, 1, 1, 1, 0) {
//!                 return Ok(GetResult::Value(Value::OctetString("My SNMP Agent".into())));
//!             }
//!             // sysObjectID.0
//!             if oid == &oid!(1, 3, 6, 1, 2, 1, 1, 2, 0) {
//!                 return Ok(GetResult::Value(Value::ObjectIdentifier(oid!(1, 3, 6, 1, 4, 1, 99999))));
//!             }
//!             Ok(GetResult::NoSuchObject)
//!         })
//!     }
//!
//!     fn get_next<'a>(&'a self, _ctx: &'a RequestContext, oid: &'a Oid) -> BoxFuture<'a, HandlerResult<GetNextResult>> {
//!         Box::pin(async move {
//!             // Return the lexicographically next OID after the given one
//!             let sys_descr = oid!(1, 3, 6, 1, 2, 1, 1, 1, 0);
//!             let sys_object_id = oid!(1, 3, 6, 1, 2, 1, 1, 2, 0);
//!
//!             if oid < &sys_descr {
//!                 return Ok(GetNextResult::Value(VarBind::new(sys_descr, Value::OctetString("My SNMP Agent".into()))));
//!             }
//!             if oid < &sys_object_id {
//!                 return Ok(GetNextResult::Value(VarBind::new(sys_object_id, Value::ObjectIdentifier(oid!(1, 3, 6, 1, 4, 1, 99999)))));
//!             }
//!             Ok(GetNextResult::EndOfMibView)
//!         })
//!     }
//! }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<async_snmp::Error>> {
//!     let agent = Agent::builder()
//!         .bind("0.0.0.0:1161")
//!         .community(b"public")
//!         .handler(oid!(1, 3, 6, 1, 2, 1, 1), Arc::new(SystemMibHandler))
//!         .allow_all_access()
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

pub use crate::handler::SecurityModel;
pub use notification::{
    NotificationOutcome, NotificationSendStream, NotificationSinkId, NotificationSinkSummary,
    SinkOutcome, SinkSkipReason, SinkStatus,
};
pub use vacm::{VacmBuilder, VacmConfig, VacmSecurityModel, View, ViewCheckResult, ViewSubtree};

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tokio::task::{JoinError, JoinSet};
use tokio_util::sync::CancellationToken;
use tracing::instrument;

use crate::error::{Error, ErrorStatus, Result};
use crate::handler::{GetNextResult, GetResult, HandlerResult, MibHandler, RequestContext};
use crate::message_size::{MessageSize, UDP_RECEIVE_BUFFER_SIZE, UDP_RECEIVE_LIMITS};
use crate::oid;
use crate::oid::Oid;
use crate::pdu::{Pdu, PduBody, PduType};
use crate::udp_responder::{ReceivedDatagram, UdpResponder};
use crate::util::{
    EmptyCommunityPolicy, PreparedAuthoritativeUsm, bind_udp_socket, community_matches,
    prepare_authoritative_usm,
};
use crate::v3::process::UsmStats;
use crate::v3::{AuthoritativeEngine, UsmUser};
use crate::v3::{SaltCounter, compute_engine_boots_time};
use crate::value::Value;
use crate::varbind::VarBind;
use crate::version::Version;

/// Default maximum message size for UDP (RFC 3417 recommendation).
const DEFAULT_MAX_MESSAGE_SIZE: usize = 1472;

/// Base overhead for SNMP message encoding: the v1/v2c community wrapper plus
/// the fixed BER framing shared by every response (message and PDU sequence
/// headers, request-id / error-status / error-index integers, and, for v3, the
/// msgGlobalData, USM, and scopedPDU framing). The variable-length community
/// string (v1/v2c), variable-length v3 fields, and the auth/priv material are
/// added on top in [`Agent::response_overhead`].
const RESPONSE_OVERHEAD: usize = 100;

/// Additional v3 overhead when the message is authenticated:
/// msgAuthenticationParameters carries up to a 48-octet HMAC (SHA-512).
const V3_AUTH_OVERHEAD: usize = 48;

/// Additional v3 overhead when the message is encrypted: the 8-octet salt in
/// msgPrivacyParameters, the OCTET STRING wrapper around the encrypted
/// scopedPDU, and up to a full DES/AES block of CBC padding.
const V3_PRIV_OVERHEAD: usize = 20;

/// Maximum number of inaccessible or version-incompatible OIDs skipped while
/// advancing one GETNEXT step. The bound covers both VACM-denied candidates and
/// `Counter64` candidates that cannot be returned to SNMPv1 requesters. Reaching
/// it is an internal processing failure rather than evidence of end-of-MIB.
const MAX_GETNEXT_SKIP_ITERATIONS: usize = 1000;

/// Clears the shared active-run flag whenever an [`Agent::run`] future exits or
/// is dropped.
struct RunGuard<'a> {
    active: &'a AtomicBool,
}

impl Drop for RunGuard<'_> {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
    }
}

/// Request tasks owned by one [`Agent::run`] invocation.
///
/// Tokio's [`JoinSet`] aborts its tasks when dropped. If the `run` future is
/// dropped or aborted, detach dispatched requests instead so their handler
/// lifecycles and response attempts can finish. The cancellation token only
/// stops tasks that have not crossed the pre-dispatch boundary.
struct RequestTasks {
    tasks: JoinSet<()>,
    cancel: CancellationToken,
}

impl RequestTasks {
    fn new(cancel: CancellationToken) -> Self {
        Self {
            tasks: JoinSet::new(),
            cancel,
        }
    }

    fn cancellation_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    fn cancel(&self) {
        self.cancel.cancel();
    }

    fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    fn spawn(&mut self, task: impl Future<Output = ()> + Send + 'static) {
        self.tasks.spawn(task);
    }

    async fn join_next(&mut self) -> Option<std::result::Result<(), JoinError>> {
        self.tasks.join_next().await
    }
}

impl Drop for RequestTasks {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.tasks.detach_all();
    }
}

/// RFC 2576 Section 4.1.2.3: SNMPv1 has no Counter64 type, so a Counter64
/// value cannot be carried in a v1 response varbind. GET responds with
/// noSuchName; GETNEXT/GETBULK skip the offending varbind.
fn v1_rejects_counter64(version: Version, value: &Value) -> bool {
    version == Version::V1 && matches!(value, Value::Counter64(_))
}

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

/// Agent authorization policy selected by the builder.
pub(crate) enum AgentAuthorization {
    Unset,
    Vacm(VacmConfig),
    AllowAll,
    Conflict,
}

impl AgentAuthorization {
    pub(crate) fn vacm(&self) -> Option<&VacmConfig> {
        match self {
            Self::Vacm(vacm) => Some(vacm),
            Self::Unset | Self::AllowAll | Self::Conflict => None,
        }
    }
}

/// Builder for [`Agent`].
///
/// Use this builder to configure and construct an SNMP agent. The builder
/// pattern allows you to chain configuration methods before calling
/// [`build()`](AgentBuilder::build) to create the agent.
///
/// # Access Control
///
/// An agent with an accepted community or USM user must explicitly select
/// [`vacm()`](AgentBuilder::vacm) or
/// [`allow_all_access()`](AgentBuilder::allow_all_access). USM authentication
/// and privacy protocols are capabilities and do not establish an inbound
/// minimum security level.
///
/// # Minimal Example
///
/// ```rust,no_run
/// use async_snmp::agent::Agent;
/// use async_snmp::handler::{MibHandler, RequestContext, GetResult, GetNextResult, HandlerResult, BoxFuture};
/// use async_snmp::{Oid, Value, VarBind, oid};
/// use std::sync::Arc;
///
/// struct MyHandler;
/// impl MibHandler for MyHandler {
///     fn get<'a>(&'a self, _: &'a RequestContext, _: &'a Oid) -> BoxFuture<'a, HandlerResult<GetResult>> {
///         Box::pin(async { Ok(GetResult::NoSuchObject) })
///     }
///     fn get_next<'a>(&'a self, _: &'a RequestContext, _: &'a Oid) -> BoxFuture<'a, HandlerResult<GetNextResult>> {
///         Box::pin(async { Ok(GetNextResult::EndOfMibView) })
///     }
/// }
///
/// # async fn example() -> Result<(), Box<async_snmp::Error>> {
/// let agent = Agent::builder()
///     .bind("0.0.0.0:1161")  // Use non-privileged port
///     .community(b"public")
///     .handler(oid!(1, 3, 6, 1, 4, 1, 99999), Arc::new(MyHandler))
///     .allow_all_access()
///     .build()
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct AgentBuilder {
    bind_addr: String,
    communities: Vec<crate::Community>,
    usm_users: HashMap<Bytes, UsmUser>,
    handlers: Vec<RegisteredHandler>,
    authoritative_engine: Option<AuthoritativeEngine>,
    max_message_size: usize,
    decode_policy: crate::message::DecodePolicy,
    compatibility_policy: crate::CompatibilityPolicy,
    max_concurrent_requests: Option<usize>,
    recv_buffer_size: Option<usize>,
    authorization: AgentAuthorization,
    cancel: Option<CancellationToken>,
    trap_sinks: Vec<(NotificationSinkId, String, crate::client::Auth)>,
    trap_send_timeout: Duration,
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
            authoritative_engine: None,
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            decode_policy: crate::message::DecodePolicy::Compatible,
            compatibility_policy: crate::CompatibilityPolicy::default(),
            max_concurrent_requests: Some(1000),
            recv_buffer_size: Some(4 * 1024 * 1024), // 4MB
            authorization: AgentAuthorization::Unset,
            cancel: None,
            trap_sinks: Vec::new(),
            trap_send_timeout: crate::client::DEFAULT_SEND_TIMEOUT,
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
    /// let agent = Agent::builder().bind("0.0.0.0:161").community(b"public").allow_all_access().build().await?;
    ///
    /// // Bind to localhost only on non-privileged port
    /// let agent = Agent::builder().bind("127.0.0.1:1161").community(b"public").allow_all_access().build().await?;
    ///
    /// // Bind to specific interface
    /// let agent = Agent::builder().bind("192.168.1.100:161").community(b"public").allow_all_access().build().await?;
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
    /// let agent = Agent::builder().bind("[::]:161").community(b"public").allow_all_access().build().await?;
    ///
    /// // Bind to IPv6 localhost only
    /// let agent = Agent::builder().bind("[::1]:1161").community(b"public").allow_all_access().build().await?;
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
    ///     .community(b"public")
    ///     .community(b"private")
    ///     .allow_all_access()
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn community(mut self, community: impl Into<crate::Community>) -> Self {
        self.communities.push(community.into());
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
    ///     .allow_all_access()
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn communities<I, C>(mut self, communities: I) -> Self
    where
        I: IntoIterator<Item = C>,
        C: Into<crate::Community>,
    {
        for c in communities {
            self.communities.push(c.into());
        }
        self
    }

    /// Add a USM user for `SNMPv3` authentication.
    ///
    /// Configure supported authentication and privacy mechanisms using the
    /// closure. The strongest configured mechanism is available through
    /// [`UsmUser::maximum_security_level`](crate::UsmUser::maximum_security_level),
    /// but it is not a minimum: lower-level packets naming the user remain
    /// valid USM input and are controlled by the Agent authorization policy.
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
    /// use async_snmp::{AuthProtocol, AuthoritativeEngine, PrivProtocol};
    /// use std::convert::Infallible;
    ///
    /// # async fn example() -> Result<(), Box<async_snmp::Error>> {
    /// # // Replace this no-op with durable storage in an application.
    /// let engine = AuthoritativeEngine::install(b"agent-engine".to_vec(), |_| {
    ///     Ok::<(), Infallible>(())
    /// })?;
    /// let agent = Agent::builder()
    ///     .bind("0.0.0.0:1161")
    ///     .authoritative_engine(engine)
    ///     // User capable of authentication
    ///     .usm_user("monitor", |u| {
    ///         u.auth(AuthProtocol::Sha256, b"monitorpass123")
    ///     })
    ///     // User capable of authentication and privacy
    ///     .usm_user("admin", |u| {
    ///         u.auth_priv(
    ///             AuthProtocol::Sha256,
    ///             b"adminauth123",
    ///             PrivProtocol::Aes128,
    ///             b"adminpriv123",
    ///         )
    ///     })
    ///     .allow_all_access()
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn usm_user<F>(mut self, username: impl Into<Bytes>, configure: F) -> Self
    where
        F: FnOnce(UsmUser) -> UsmUser,
    {
        let username_bytes: Bytes = username.into();
        let config = configure(UsmUser::new(username_bytes.clone()));
        self.usm_users.insert(username_bytes, config);
        self
    }

    /// Set the persisted local authoritative engine state for `SNMPv3`.
    ///
    /// An agent with USM users or V3 trap sinks requires this value. Construct
    /// it with [`AuthoritativeEngine::install`] on first installation or
    /// [`AuthoritativeEngine::restart`] on later process starts. Those
    /// constructors persist the stable engine ID and startup boots counter
    /// before returning: boots 1 for installation, or the incremented stored
    /// value on restart. The retained callback also persists runtime rollover
    /// increments before they are used.
    ///
    /// ```rust,no_run
    /// use async_snmp::agent::Agent;
    /// use async_snmp::v3::AuthoritativeEngine;
    /// use std::convert::Infallible;
    ///
    /// # async fn example() -> Result<(), Box<async_snmp::Error>> {
    /// # // Replace this no-op with durable storage in an application.
    /// let engine = AuthoritativeEngine::install(b"my-engine".to_vec(), |_| {
    ///     Ok::<(), Infallible>(())
    /// })?;
    /// let agent = Agent::builder()
    ///     .bind("0.0.0.0:1161")
    ///     .authoritative_engine(engine)
    ///     .community(b"public")
    ///     .allow_all_access()
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn authoritative_engine(mut self, engine: AuthoritativeEngine) -> Self {
        self.authoritative_engine = Some(engine);
        self
    }

    #[cfg(test)]
    pub(crate) fn engine_id(mut self, engine_id: impl Into<Vec<u8>>) -> Self {
        let boots = self
            .authoritative_engine
            .as_ref()
            .map_or(1, AuthoritativeEngine::engine_boots);
        self.authoritative_engine = Some(AuthoritativeEngine::for_test(engine_id.into(), boots));
        self
    }

    #[cfg(test)]
    pub(crate) fn engine_boots(mut self, boots: u32) -> Self {
        let engine_id = self
            .authoritative_engine
            .as_ref()
            .map(|engine| engine.engine_id().to_vec())
            .unwrap_or_else(|| {
                crate::v3::generate_engine_id()
                    .expect("test engine ID generation")
                    .to_vec()
            });
        self.authoritative_engine = Some(AuthoritativeEngine::for_test(engine_id, boots));
        self
    }

    /// Set the maximum message size for responses.
    ///
    /// Default is 1472 octets (fits Ethernet MTU minus IP/UDP headers).
    /// GETBULK responses will be truncated to fit within this limit.
    /// Values above the UDP receive capacity advertised by this agent (65507
    /// octets) are rejected by [`AgentBuilder::build`].
    ///
    /// For `SNMPv3` requests, the agent uses the minimum of this value
    /// and the msgMaxSize from the request. This outbound response limit is
    /// independent of the local receive capacity advertised in V3 messages.
    /// Values below the V3 advertisement minimum, including zero, are allowed:
    /// they are response/drop policy and are never copied into a V3 header.
    #[must_use]
    pub fn max_message_size(mut self, size: usize) -> Self {
        self.max_message_size = size;
        self
    }

    /// Set top-level request-envelope handling (default: compatible).
    ///
    /// Compatible mode accepts a bounded suffix after one declared SNMP
    /// message and reports it as a decode anomaly. Strict mode rejects it.
    #[must_use]
    pub fn decode_policy(mut self, policy: crate::message::DecodePolicy) -> Self {
        self.decode_policy = policy;
        self
    }

    /// Set BER/value interoperability handling (default: compatible).
    ///
    /// The policy applies to community requests and every staged v3 decode,
    /// including security parameters and plaintext or decrypted scoped PDUs.
    #[must_use]
    pub fn compatibility_policy(mut self, policy: crate::CompatibilityPolicy) -> Self {
        self.compatibility_policy = policy;
        self
    }

    /// Require canonical top-level envelopes and canonical BER/value input.
    #[must_use]
    pub fn strict_decoding(mut self) -> Self {
        self.decode_policy = crate::message::DecodePolicy::Strict;
        self.compatibility_policy = crate::CompatibilityPolicy::STRICT;
        self
    }

    /// Set the maximum number of concurrent requests the agent will process.
    ///
    /// Default is 1000. Requests beyond this limit will queue until a slot
    /// becomes available. Set to `None` for unbounded concurrency.
    ///
    /// This controls memory usage under high load while still allowing
    /// parallel request processing.
    ///
    /// A limit of `Some(0)` is invalid (it would permit no requests and wedge
    /// the agent) and is rejected by [`AgentBuilder::build`].
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
    /// use async_snmp::handler::{MibHandler, RequestContext, GetResult, GetNextResult, HandlerResult, BoxFuture};
    /// use async_snmp::{Oid, Value, VarBind, oid};
    /// use std::sync::Arc;
    ///
    /// struct SystemHandler;
    /// impl MibHandler for SystemHandler {
    ///     fn get<'a>(&'a self, _: &'a RequestContext, oid: &'a Oid) -> BoxFuture<'a, HandlerResult<GetResult>> {
    ///         Box::pin(async move {
    ///             if oid == &oid!(1, 3, 6, 1, 2, 1, 1, 1, 0) {
    ///                 Ok(GetResult::Value(Value::OctetString("My Agent".into())))
    ///             } else {
    ///                 Ok(GetResult::NoSuchObject)
    ///             }
    ///         })
    ///     }
    ///     fn get_next<'a>(&'a self, _: &'a RequestContext, _: &'a Oid) -> BoxFuture<'a, HandlerResult<GetNextResult>> {
    ///         Box::pin(async { Ok(GetNextResult::EndOfMibView) })
    ///     }
    /// }
    ///
    /// # async fn example() -> Result<(), Box<async_snmp::Error>> {
    /// let agent = Agent::builder()
    ///     .bind("0.0.0.0:1161")
    ///     .community(b"public")
    ///     // Register handler for system MIB subtree
    ///     .handler(oid!(1, 3, 6, 1, 2, 1, 1), Arc::new(SystemHandler))
    ///     .allow_all_access()
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
    /// access control rules. Missing groups, access rows, or views produce an
    /// `authorizationError` with error-index zero for v2c/v3. OIDs outside an
    /// existing view retain operation-specific `notInView` handling.
    ///
    /// VACM and [`allow_all_access`](Self::allow_all_access) are mutually
    /// exclusive. An explicitly empty VACM configuration is a valid deny-all
    /// policy.
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
    ///         .access("readonly_group", SecurityModel::V2c, SecurityLevel::NoAuthNoPriv, |a| a
    ///             .read_view("full_view"))
    ///         .access("readwrite_group", SecurityModel::V2c, SecurityLevel::NoAuthNoPriv, |a| a
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
        self.authorization = match self.authorization {
            AgentAuthorization::Unset | AgentAuthorization::Vacm(_) => {
                AgentAuthorization::Vacm(configure(builder).build())
            }
            AgentAuthorization::AllowAll | AgentAuthorization::Conflict => {
                AgentAuthorization::Conflict
            }
        };
        self
    }

    /// Explicitly allow every operation supported by an accepted identity.
    ///
    /// This escape hatch includes unauthenticated `noAuthNoPriv` requests that
    /// name a configured USM user. Use [`vacm`](Self::vacm) to require minimum
    /// security levels or restrict MIB views. The two selections are mutually
    /// exclusive.
    #[must_use]
    pub fn allow_all_access(mut self) -> Self {
        self.authorization = match self.authorization {
            AgentAuthorization::Unset | AgentAuthorization::AllowAll => {
                AgentAuthorization::AllowAll
            }
            AgentAuthorization::Vacm(_) | AgentAuthorization::Conflict => {
                AgentAuthorization::Conflict
            }
        };
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
    /// For V3 traps, the Agent is authoritative and uses its persisted
    /// [`AuthoritativeEngine`]. For V3 Informs, the receiving sink is
    /// authoritative and the Agent discovers the sink's engine. Configuring
    /// any V3 sink still requires local authoritative state because it may be
    /// used by [`Agent::send_trap()`].
    ///
    /// `id` must be unique within the agent and contain 1 to 32 UTF-8 octets.
    /// It is included in delivery outcomes and should remain stable across
    /// restarts when the application retains sink status.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use async_snmp::agent::Agent;
    /// use async_snmp::{Auth, AuthProtocol, AuthoritativeEngine, PrivProtocol};
    /// use std::convert::Infallible;
    ///
    /// # async fn example() -> Result<(), Box<async_snmp::Error>> {
    /// # // Replace this no-op with durable storage in an application.
    /// let engine = AuthoritativeEngine::install(b"agent-engine".to_vec(), |_| {
    ///     Ok::<(), Infallible>(())
    /// })?;
    /// let agent = Agent::builder()
    ///     .bind("0.0.0.0:1161")
    ///     .authoritative_engine(engine)
    ///     .community(b"public")
    ///     .trap_sink("primary", "192.168.1.100:162", Auth::v2c("public"))
    ///     .trap_sink("secure", "10.0.0.1:162", Auth::usm("trapuser").auth_priv(
    ///         AuthProtocol::Sha256,
    ///         "authpass",
    ///         PrivProtocol::Aes128,
    ///         "privpass",
    ///     ))
    ///     .allow_all_access()
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn trap_sink(
        mut self,
        id: impl Into<NotificationSinkId>,
        dest: impl Into<String>,
        auth: impl Into<crate::client::Auth>,
    ) -> Self {
        self.trap_sinks.push((id.into(), dest.into(), auth.into()));
        self
    }

    /// Set the timeout for each unconfirmed trap send to a configured sink.
    ///
    /// Default is [`crate::DEFAULT_SEND_TIMEOUT`] (5 seconds). The timeout
    /// includes local UDP socket queueing and send I/O for each sink. It only
    /// affects `send_trap`; confirmed informs use
    /// [`inform_timeout`](Self::inform_timeout) while waiting for a response.
    #[must_use]
    pub fn trap_send_timeout(mut self, timeout: Duration) -> Self {
        self.trap_send_timeout = timeout;
        self
    }

    /// Set the timeout for inform requests sent to trap sinks.
    ///
    /// Default is 5 seconds. This bounds each wait for an inform response and
    /// only affects `send_inform`; unconfirmed trap sends use
    /// [`trap_send_timeout`](Self::trap_send_timeout).
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
    ///
    /// Returns a configuration error when inbound identities do not have an
    /// explicit access policy, VACM and unrestricted access are both selected,
    /// notification sink IDs are empty, longer than 32 UTF-8 octets, or
    /// duplicated; USM credentials are invalid; USM users or V3 trap sinks are
    /// configured without a persisted [`AuthoritativeEngine`]; or the
    /// response-size limit exceeds the fixed UDP receive capacity. Returns
    /// [`Error::RandomSource`] when a generated engine ID or required privacy
    /// salt cannot be initialized.
    pub async fn build(mut self) -> Result<Agent> {
        crate::transport::checked_deadline(self.trap_send_timeout, "trap send timeout")?;

        if matches!(self.authorization, AgentAuthorization::Conflict) {
            return Err(Error::Config(
                "VACM and unrestricted Agent access are mutually exclusive".into(),
            )
            .boxed());
        }
        if (!self.communities.is_empty() || !self.usm_users.is_empty())
            && matches!(self.authorization, AgentAuthorization::Unset)
        {
            return Err(Error::Config(
                "an Agent with inbound identities requires vacm() or allow_all_access()".into(),
            )
            .boxed());
        }

        let mut sink_ids = HashSet::with_capacity(self.trap_sinks.len());
        for (id, _, _) in &self.trap_sinks {
            id.validate()?;
            if !sink_ids.insert(id.clone()) {
                return Err(
                    Error::Config(format!("duplicate notification sink ID: {id}").into()).boxed(),
                );
            }
        }

        let max_udp_message_size = UDP_RECEIVE_LIMITS.advertised().as_usize();
        if self.max_message_size > max_udp_message_size {
            return Err(Error::Config(
                format!("max_message_size must not exceed UDP capacity {max_udp_message_size}")
                    .into(),
            )
            .boxed());
        }
        let local_receive_capacity = UDP_RECEIVE_LIMITS.advertised();

        // Keep trap-sink credential validation local because outbound sinks
        // are agent-specific, but prepare inbound USM and engine state through
        // the same path used by notification receivers.
        for (_, _, auth) in &mut self.trap_sinks {
            if let crate::client::Auth::Usm(config) = auth {
                config.validate_and_precompute().map_err(|error| {
                    Error::Config(format!("invalid trap sink USM configuration: {error}").into())
                        .boxed()
                })?;
            }
        }
        let requires_privacy = self
            .usm_users
            .values()
            .any(|security| security.maximum_security_level().requires_priv())
            || self.trap_sinks.iter().any(|(_, _, auth)| {
                matches!(auth, crate::client::Auth::Usm(security) if security.security_level().requires_priv())
            });
        let requires_authoritative_engine = !self.usm_users.is_empty()
            || self
                .trap_sinks
                .iter()
                .any(|(_, _, auth)| matches!(auth, crate::client::Auth::Usm(_)));
        let PreparedAuthoritativeUsm {
            users: usm_users,
            authoritative_engine,
            engine_id,
            engine_boots,
        } = prepare_authoritative_usm(
            self.usm_users,
            self.authoritative_engine,
            requires_authoritative_engine,
            "invalid USM user configuration",
            "authoritative engine state is required for SNMPv3 agent roles",
        )?;
        let salt_counter = requires_privacy.then(SaltCounter::new).transpose()?;

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

        let udp_responder = UdpResponder::new(&socket);

        let cancel = self.cancel.unwrap_or_default();

        // Create concurrency limiter if configured. A zero-permit semaphore
        // would never grant a permit and wedge the agent, so reject it.
        if self.max_concurrent_requests == Some(0) {
            return Err(
                Error::Config("max_concurrent_requests must be greater than 0".into()).into(),
            );
        }
        let concurrency_limit = self
            .max_concurrent_requests
            .map(|n| Arc::new(Semaphore::new(n)));

        // Resolve trap sink addresses
        let mut trap_sinks = Vec::with_capacity(self.trap_sinks.len());
        for (index, (id, dest_str, auth)) in self.trap_sinks.into_iter().enumerate() {
            let dest: SocketAddr = dest_str.parse().map_err(|_| {
                Error::Config(format!("invalid trap sink address: {dest_str}").into())
            })?;
            trap_sinks.push(notification::TrapSink::new(
                index,
                id,
                dest,
                auth,
                self.trap_send_timeout,
                self.inform_timeout,
                self.inform_retry.clone(),
            ));
        }

        let state = Arc::new(AgentState {
            authoritative_engine,
            engine_id,
            engine_boots: AtomicU32::new(engine_boots),
            engine_time: AtomicU32::new(0),
            engine_start: Instant::now(),
            engine_boots_base: engine_boots,
            #[cfg(test)]
            authoritative_elapsed_override: std::sync::atomic::AtomicU64::new(u64::MAX),
            max_message_size: self.max_message_size,
            local_receive_capacity,
            decode_policy: self.decode_policy,
            compatibility_policy: self.compatibility_policy,
            snmp_in_asn_parse_errs: AtomicU32::new(0),
            snmp_invalid_msgs: AtomicU32::new(0),
            snmp_unknown_security_models: AtomicU32::new(0),
            snmp_silent_drops: AtomicU32::new(0),
            snmp_unknown_contexts: AtomicU32::new(0),
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
                udp_responder,
                local_addr,
                communities: self.communities,
                usm_users,
                handlers: self.handlers,
                state,
                salt_counter,
                concurrency_limit,
                authorization: self.authorization,
                cancel,
                trap_sinks,
                notification_id: std::sync::atomic::AtomicI32::new(1),
                run_active: AtomicBool::new(false),
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
    pub(crate) authoritative_engine: Option<AuthoritativeEngine>,
    pub(crate) engine_id: Bytes,
    pub(crate) engine_boots: AtomicU32,
    pub(crate) engine_time: AtomicU32,
    pub(crate) engine_start: Instant,
    /// Initial `engine_boots` value at startup, used to compute overflow-adjusted boots.
    pub(crate) engine_boots_base: u32,
    #[cfg(test)]
    authoritative_elapsed_override: std::sync::atomic::AtomicU64,
    /// Configured upper bound for outbound response messages.
    pub(crate) max_message_size: usize,
    /// Wire-valid `msgMaxSize` advertising this agent's UDP receive capacity.
    pub(crate) local_receive_capacity: MessageSize,
    /// Inbound top-level envelope consumption policy.
    pub(crate) decode_policy: crate::message::DecodePolicy,
    /// Inbound BER/value malformed-input compatibility policy.
    pub(crate) compatibility_policy: crate::CompatibilityPolicy,
    /// snmpInASNParseErrs (1.3.6.1.2.1.11.6.0) - messages rejected because
    /// their ASN.1 representation is invalid for the received SNMP version
    pub(crate) snmp_in_asn_parse_errs: AtomicU32,
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
    /// snmpUnknownContexts (1.3.6.1.6.3.12.1.5) - requests whose scopedPDU
    /// contextEngineID did not name a context served by this engine
    pub(crate) snmp_unknown_contexts: AtomicU32,
    /// RFC 3414 usmStats counters
    pub(crate) usm_stats: UsmStats,
}

impl AgentState {
    /// Return one coherent authoritative boots/time pair for the current instant.
    pub(crate) fn authoritative_boots_time(&self) -> Result<(u32, u32)> {
        #[cfg(test)]
        let override_elapsed = self.authoritative_elapsed_override.load(Ordering::Relaxed);
        #[cfg(test)]
        let pair = if override_elapsed != u64::MAX {
            compute_engine_boots_time(self.engine_boots_base, override_elapsed)
        } else {
            self.sample_authoritative_boots_time()?
        };
        #[cfg(not(test))]
        let pair = self.sample_authoritative_boots_time()?;

        self.engine_boots.store(pair.0, Ordering::Relaxed);
        self.engine_time.store(pair.1, Ordering::Relaxed);
        Ok(pair)
    }

    fn sample_authoritative_boots_time(&self) -> Result<(u32, u32)> {
        match &self.authoritative_engine {
            Some(engine) => engine.current_boots_time(),
            None => {
                let total_secs = self.engine_start.elapsed().as_secs();
                Ok(compute_engine_boots_time(
                    self.engine_boots_base,
                    total_secs,
                ))
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn set_authoritative_elapsed_for_test(&self, elapsed: u64) {
        self.authoritative_elapsed_override
            .store(elapsed, Ordering::Relaxed);
    }
}

/// Inner state shared across agent clones.
pub(crate) struct AgentInner {
    pub(crate) socket: Arc<UdpSocket>,
    pub(crate) udp_responder: UdpResponder,
    pub(crate) local_addr: SocketAddr,
    pub(crate) communities: Vec<crate::Community>,
    pub(crate) usm_users: HashMap<Bytes, UsmUser>,
    pub(crate) handlers: Vec<RegisteredHandler>,
    pub(crate) state: Arc<AgentState>,
    pub(crate) salt_counter: Option<SaltCounter>,
    pub(crate) concurrency_limit: Option<Arc<Semaphore>>,
    pub(crate) authorization: AgentAuthorization,
    /// Cancellation token for graceful shutdown.
    pub(crate) cancel: CancellationToken,
    /// Configured trap/inform destinations.
    pub(crate) trap_sinks: Vec<notification::TrapSink>,
    /// Per-agent monotonic counter for trap request-ids and v3 notification msgIDs.
    pub(crate) notification_id: std::sync::atomic::AtomicI32,
    /// Shared across clones to enforce one active service loop.
    pub(crate) run_active: AtomicBool,
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
///     .allow_all_access()
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

    /// Return the configured top-level request-envelope policy.
    #[must_use]
    pub fn decode_policy(&self) -> crate::message::DecodePolicy {
        self.inner.state.decode_policy
    }

    /// Return the configured BER/value compatibility policy.
    #[must_use]
    pub fn compatibility_policy(&self) -> crate::CompatibilityPolicy {
        self.inner.state.compatibility_policy
    }

    /// Iterate over credential-free notification sink summaries in configuration order.
    pub fn notification_sinks(
        &self,
    ) -> impl ExactSizeIterator<Item = &NotificationSinkSummary> + DoubleEndedIterator {
        self.inner.trap_sinks.iter().map(|sink| &sink.summary)
    }

    /// Get the local engine ID.
    ///
    /// With an [`AuthoritativeEngine`] this is the stable persisted V3
    /// identity. A community-only Agent instead has a generated process-local
    /// ID for its built-in engine objects.
    #[must_use]
    pub fn engine_id(&self) -> &[u8] {
        &self.inner.state.engine_id
    }

    /// Get the most recently sampled engine boots value.
    ///
    /// V3 processing samples the shared authoritative clock. Any rollover
    /// increment has already been stored through the retained persistence
    /// callback before this snapshot is published.
    #[must_use]
    pub fn engine_boots(&self) -> u32 {
        self.inner.state.engine_boots.load(Ordering::Relaxed)
    }

    /// Get the most recently sampled engine time value.
    ///
    /// This snapshot is refreshed during protocol processing rather than by a
    /// background timer, so it can remain unchanged while the Agent is idle.
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

    /// Get the snmpInASNParseErrs counter value.
    ///
    /// This counter tracks authenticated SNMPv1 requests rejected because a
    /// varbind carries the SNMPv2-only Counter64 type.
    ///
    /// OID: 1.3.6.1.2.1.11.6.0
    #[must_use]
    pub fn snmp_in_asn_parse_errs(&self) -> u32 {
        self.inner
            .state
            .snmp_in_asn_parse_errs
            .load(Ordering::Relaxed)
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

    /// Get the snmpUnknownContexts counter value.
    ///
    /// This counter tracks requests whose scopedPDU contextEngineID did not
    /// name a context served by this engine (RFC 3413 Section 3.2). Such
    /// requests are answered with a Report PDU rather than dispatched against
    /// the local MIB.
    ///
    /// OID: 1.3.6.1.6.3.12.1.5
    #[must_use]
    pub fn snmp_unknown_contexts(&self) -> u32 {
        self.inner
            .state
            .snmp_unknown_contexts
            .load(Ordering::Relaxed)
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
    ///
    /// Cancellation stops receiving datagrams and waiting for concurrency
    /// permits. A received request whose task has not started request handling
    /// may be dropped. Once request handling starts, including SET processing,
    /// it is allowed to finish through its response attempt before this method
    /// returns. There is no forced shutdown timeout, so a user handler that
    /// never returns can cause shutdown to wait indefinitely. Dropping or
    /// aborting the `run` future cannot provide that completion guarantee;
    /// already-dispatched requests are detached to finish in the background
    /// rather than being forcibly aborted. For orderly shutdown, cancel the
    /// configured token and await this method.
    ///
    /// Only one active call to `run` is supported for an agent. Cloned handles
    /// may still be used for other agent operations while that call is active.
    #[instrument(skip(self), err, fields(snmp.local_addr = %self.local_addr()))]
    pub async fn run(&self) -> Result<()> {
        self.inner
            .run_active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::AgentAlreadyRunning.boxed())?;
        let _run_guard = RunGuard {
            active: &self.inner.run_active,
        };

        let mut buf = vec![0u8; UDP_RECEIVE_BUFFER_SIZE];
        let mut request_tasks = RequestTasks::new(self.inner.cancel.child_token());

        let log_task_result = |result: std::result::Result<(), JoinError>| {
            if let Err(error) = result {
                tracing::error!(target: "async_snmp::agent", %error, "request task failed");
            }
        };

        let run_result = 'service: loop {
            let recv_meta = loop {
                tokio::select! {
                    biased;
                    () = self.inner.cancel.cancelled() => {
                        tracing::info!(target: "async_snmp::agent", "agent shutdown requested");
                        break 'service Ok(());
                    }
                    result = request_tasks.join_next(), if !request_tasks.is_empty() => {
                        if let Some(result) = result {
                            log_task_result(result);
                        }
                    }
                    result = self.recv_packet(&mut buf) => {
                        match result {
                            Ok(recv_meta) => break recv_meta,
                            Err(error) => break 'service Err(error),
                        }
                    }
                }
            };

            let data = Bytes::copy_from_slice(&buf[..recv_meta.len]);
            if data.len() > UDP_RECEIVE_LIMITS.advertised().as_usize() {
                tracing::debug!(target: "async_snmp::agent", { snmp.source = %recv_meta.source, received_size = data.len(), advertised_size = UDP_RECEIVE_LIMITS.advertised().as_usize() }, "accepted bounded UDP datagram above advertised capacity");
            }
            let agent = self.clone();

            let permit = if let Some(ref sem) = self.inner.concurrency_limit {
                loop {
                    tokio::select! {
                        biased;
                        () = self.inner.cancel.cancelled() => {
                            tracing::info!(target: "async_snmp::agent", "agent shutdown requested");
                            break 'service Ok(());
                        }
                        result = request_tasks.join_next(), if !request_tasks.is_empty() => {
                            if let Some(result) = result {
                                log_task_result(result);
                            }
                        }
                        result = sem.clone().acquire_owned() => {
                            break Some(result.expect("semaphore closed"));
                        }
                    }
                }
            } else {
                None
            };

            let task_cancel = request_tasks.cancellation_token();
            request_tasks.spawn(async move {
                let _permit = permit;

                // This is the only cooperative cancellation boundary. Once
                // handle_request is entered, its handler lifecycle and response
                // attempt must run to completion and must never be aborted.
                if task_cancel.is_cancelled() {
                    return;
                }

                if let Err(error) = agent.update_engine_time() {
                    tracing::warn!(target: "async_snmp::agent", %error, "could not persist authoritative engine time transition");
                }

                match agent.handle_request(data, recv_meta.source).await {
                    Ok(Some(response_bytes)) => {
                        if let Err(e) = agent.send_response(&response_bytes, &recv_meta).await {
                            tracing::warn!(target: "async_snmp::agent", { snmp.source = %recv_meta.source, error = %e }, "failed to send response");
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        tracing::warn!(target: "async_snmp::agent", { snmp.source = %recv_meta.source, error = %e }, "error handling request");
                    }
                }
            });
        };

        request_tasks.cancel();
        while let Some(result) = request_tasks.join_next().await {
            log_task_result(result);
        }

        run_result
    }

    async fn recv_packet(&self, buf: &mut [u8]) -> Result<ReceivedDatagram> {
        self.inner
            .udp_responder
            .recv(&self.inner.socket, buf)
            .await
            .map_err(|source| {
                Error::Network {
                    target: self.inner.local_addr,
                    source,
                }
                .boxed()
            })
    }

    async fn send_response(
        &self,
        data: &[u8],
        recv_meta: &ReceivedDatagram,
    ) -> std::io::Result<()> {
        self.inner
            .udp_responder
            .reply(&self.inner.socket, data, recv_meta)
            .await
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
    fn update_engine_time(&self) -> Result<()> {
        let previous_boots = self.inner.state.engine_boots.load(Ordering::Relaxed);
        let (boots, _) = self.inner.state.authoritative_boots_time()?;

        if boots != previous_boots && boots > self.inner.state.engine_boots_base {
            tracing::warn!(
                target: "async_snmp::agent",
                engine_boots = boots,
                "engine time wrapped past MAX_ENGINE_TIME, incrementing engine boots"
            );
        }

        Ok(())
    }

    /// Validate community string using constant-time comparison.
    ///
    /// Uses constant-time comparison to prevent timing attacks that could
    /// be used to guess valid community strings character by character.
    pub(crate) fn validate_community(&self, community: &[u8]) -> bool {
        community_matches(
            &self.inner.communities,
            community,
            EmptyCommunityPolicy::Deny,
        )
    }

    /// Dispatch a request to the appropriate handler.
    async fn dispatch_request(&self, ctx: &RequestContext, pdu: &Pdu) -> Result<Pdu> {
        match pdu.pdu_type() {
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
            PduType::InformRequest => Ok(self.handle_inform(ctx, pdu)),
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
    ///
    /// The agent only acknowledges the inform; its contents are discarded. In
    /// the RFC 3413 architecture informs are addressed to notification
    /// receivers, not command responders; applications that want to consume
    /// informs should use [`crate::notification::NotificationReceiver`].
    fn handle_inform(&self, _ctx: &RequestContext, pdu: &Pdu) -> Pdu {
        // Exact sizing and the empty-varbind tooBig fallback are applied at the
        // shared message-envelope finalizer after the response is encoded.
        pdu.to_response()
    }

    /// Effective maximum response message size for a request: the smaller of
    /// the agent's configured limit and the client's advertised `msgMaxSize`
    /// (v3). v1/v2c requests carry no `msg_max_size`, so the agent limit applies.
    fn effective_max_size(&self, ctx: &RequestContext) -> usize {
        let agent_max = self.inner.state.max_message_size;
        match ctx.msg_max_size {
            Some(client_max) => agent_max.min(client_max),
            None => agent_max,
        }
    }

    /// Upper-bound overhead (the non-varbind bytes) of the encoded Response for
    /// this request, used to budget how many varbinds fit within the size limit.
    ///
    /// For v1/v2c the fixed [`RESPONSE_OVERHEAD`] covers the community wrapper.
    /// The v3 USM/scopedPDU wrapper is materially larger and grows with the
    /// security level, so the v3 estimate adds the engine ID (carried twice, as
    /// the authoritative engine ID in the security parameters and the context
    /// engine ID in the scopedPDU), the user name, the context name, and the
    /// auth/priv material. The result is deliberately a conservative work
    /// budget that may trim later varbinds. It never selects `tooBig`: the first
    /// candidate and the final response are authoritatively decided by exact
    /// message-envelope encoding.
    fn response_overhead(&self, ctx: &RequestContext) -> usize {
        if ctx.version != Version::V3 {
            // v1/v2c echo the request's community string in the response
            // wrapper. A long, operator-configured community can otherwise
            // push the encoded Response past the size limit after
            // response_fits has already accepted it.
            return RESPONSE_OVERHEAD + ctx.security_name.len();
        }
        let mut overhead = RESPONSE_OVERHEAD
            + 2 * self.inner.state.engine_id.len()
            + ctx.security_name.len()
            + ctx.context_name.len();
        if ctx.security_level.requires_auth() {
            overhead += V3_AUTH_OVERHEAD;
        }
        if ctx.security_level.requires_priv() {
            overhead += V3_PRIV_OVERHEAD;
        }
        overhead
    }

    /// Handle GET request.
    async fn handle_get(&self, ctx: &RequestContext, pdu: &Pdu) -> Result<Pdu> {
        let mut response_varbinds = Vec::with_capacity(pdu.varbinds.len());

        for (index, vb) in pdu.varbinds.iter().enumerate() {
            // VACM read access check
            if let Some(vacm) = self.inner.authorization.vacm()
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
                match handler.handler.get(ctx, &vb.oid).await {
                    Ok(result) => result,
                    Err(err) => {
                        // RFC 3416 Section 4.2.1: a varbind whose processing
                        // fails yields a genErr Response naming its index.
                        tracing::warn!(
                            target: "async_snmp::agent",
                            oid = %vb.oid,
                            error = %err,
                            "handler GET failed; responding genErr"
                        );
                        return Ok(pdu.to_error_response(ErrorStatus::GenErr, (index + 1) as i32));
                    }
                }
            } else {
                GetResult::NoSuchObject
            };

            let response_value = match result {
                GetResult::Value(v) => {
                    if v1_rejects_counter64(ctx.version, &v) {
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

        Ok(Pdu::response(pdu.request_id, 0, 0, response_varbinds))
    }

    /// Handle GETNEXT request.
    async fn handle_get_next(&self, ctx: &RequestContext, pdu: &Pdu) -> Result<Pdu> {
        let mut response_varbinds = Vec::with_capacity(pdu.varbinds.len());

        for (index, vb) in pdu.varbinds.iter().enumerate() {
            // Try to find the next OID from any handler, skipping OIDs denied by
            // VACM. RFC 3413 classifies GETNEXT as Read-Class and requires
            // continuing the walk until an accessible OID is found.
            let next = match self.get_next_accessible_oid(ctx, &vb.oid).await {
                Ok(next) => next,
                Err(err) => {
                    tracing::warn!(
                        target: "async_snmp::agent",
                        oid = %vb.oid,
                        error = %err,
                        "handler GETNEXT failed; responding genErr"
                    );
                    return Ok(pdu.to_error_response(ErrorStatus::GenErr, (index + 1) as i32));
                }
            };

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

        Ok(Pdu::response(pdu.request_id, 0, 0, response_varbinds))
    }

    /// Handle GETBULK request.
    ///
    /// Per RFC 3416 Section 4.2.3, if the response would exceed the message
    /// size limit, we return fewer variable bindings rather than all of them.
    async fn handle_get_bulk(&self, ctx: &RequestContext, pdu: &Pdu) -> Result<Pdu> {
        let PduBody::GetBulk {
            non_repeaters,
            max_repetitions,
        } = &pdu.body
        else {
            unreachable!("GETBULK handler requires a typed GETBULK body");
        };
        let non_repeaters = usize::try_from(*non_repeaters).unwrap_or(0);
        let max_repetitions = *max_repetitions;

        let mut response_varbinds = Vec::new();
        let mut current_size: usize = self.response_overhead(ctx);
        let max_size = self.effective_max_size(ctx);

        // Helper to check if we can add a varbind
        let can_add = |vb: &VarBind, current_size: usize| -> bool {
            current_size + vb.encoded_size() <= max_size
        };

        // Handle non-repeaters (first N varbinds get one GETNEXT each)
        for (index, vb) in pdu.varbinds.iter().take(non_repeaters).enumerate() {
            let next = match self.get_next_accessible_oid(ctx, &vb.oid).await {
                Ok(next) => next,
                Err(err) => {
                    // RFC 3416 Section 4.2.3: error-index names the varbind in
                    // the received request.
                    tracing::warn!(
                        target: "async_snmp::agent",
                        oid = %vb.oid,
                        error = %err,
                        "handler GETBULK failed; responding genErr"
                    );
                    return Ok(pdu.to_error_response(ErrorStatus::GenErr, (index + 1) as i32));
                }
            };

            let next_vb = match next {
                Some(next_vb) => next_vb,
                None => VarBind::new(vb.oid.clone(), Value::EndOfMibView),
            };

            if !can_add(&next_vb, current_size) {
                if response_varbinds.is_empty() {
                    // The budget is deliberately conservative and therefore
                    // cannot authoritatively select tooBig. Return the first
                    // candidate to the message-envelope finalizer, which will
                    // encode it exactly before choosing the protocol fallback.
                    response_varbinds.push(next_vb);
                }
                // RFC 3416 Section 4.2.3: truncation removes variable bindings
                // from the END of the positional set. All repeaters are
                // positionally after every non-repeater, so once a non-repeater
                // is dropped, no later binding may appear. Return the
                // non-repeater prefix collected so far without running the
                // repeater loop (falling through would emit repeater varbinds
                // into the dropped non-repeater's slot).
                return Ok(Pdu::response(pdu.request_id, 0, 0, response_varbinds));
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
                        let next = match self.get_next_accessible_oid(ctx, oid).await {
                            Ok(next) => next,
                            Err(err) => {
                                // error-index refers to the repeater's position
                                // in the received request, whatever the
                                // repetition it failed on (RFC 3416
                                // Section 4.2.3).
                                tracing::warn!(
                                    target: "async_snmp::agent",
                                    oid = %oid,
                                    error = %err,
                                    "handler GETBULK failed; responding genErr"
                                );
                                return Ok(pdu.to_error_response(
                                    ErrorStatus::GenErr,
                                    (non_repeaters + i + 1) as i32,
                                ));
                            }
                        };

                        if let Some(next_vb) = next {
                            *oid = next_vb.oid.clone();
                            row_complete = false;
                            next_vb
                        } else {
                            all_done[i] = true;
                            VarBind::new(oid.clone(), Value::EndOfMibView)
                        }
                    };

                    // Check the conservative work budget before adding. If this
                    // is the first binding, retain it so the exact envelope
                    // finalizer—not this estimate—decides between the candidate,
                    // tooBig, and a silent drop.
                    if !can_add(&next_vb, current_size) {
                        if response_varbinds.is_empty() {
                            response_varbinds.push(next_vb);
                        }
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

        Ok(Pdu::response(pdu.request_id, 0, 0, response_varbinds))
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
    /// remaining candidates are denied. A handler processing failure
    /// propagates as Err (mapped to genErr by the caller).
    async fn get_next_accessible_oid(
        &self,
        ctx: &RequestContext,
        from_oid: &Oid,
    ) -> HandlerResult<Option<VarBind>> {
        let mut search_from = from_oid.clone();
        for _ in 0..MAX_GETNEXT_SKIP_ITERATIONS {
            let candidate = self.get_next_oid(ctx, &search_from).await?;
            match candidate {
                None => return Ok(None),
                Some(ref next_vb) => {
                    if next_vb.oid <= search_from {
                        tracing::error!(
                            target: "async_snmp::agent",
                            from = %search_from,
                            got = %next_vb.oid,
                            "handler returned non-increasing OID in GETNEXT"
                        );
                        return Ok(None);
                    }
                    if v1_rejects_counter64(ctx.version, &next_vb.value) {
                        search_from = next_vb.oid.clone();
                        continue;
                    }
                    if let Some(vacm) = self.inner.authorization.vacm() {
                        if vacm.check_access(ctx.read_view.as_ref(), &next_vb.oid) {
                            return Ok(candidate);
                        }
                        search_from = next_vb.oid.clone();
                    } else {
                        return Ok(candidate);
                    }
                }
            }
        }
        tracing::warn!(
            target: "async_snmp::agent",
            from = %from_oid,
            cap = MAX_GETNEXT_SKIP_ITERATIONS,
            "GETNEXT inaccessible/version-incompatible candidate skip cap reached"
        );
        Err(crate::handler::HandlerError::new(
            "GETNEXT candidate skip cap reached",
        ))
    }

    /// Get the next OID from any handler.
    async fn get_next_oid(
        &self,
        ctx: &RequestContext,
        oid: &Oid,
    ) -> HandlerResult<Option<VarBind>> {
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
            if let GetNextResult::Value(next) = handler.handler.get_next(ctx, oid).await? {
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

        Ok(best_result)
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
        BoxFuture, GetNextResult, GetResult, HandlerError, HandlerResult, MibHandler,
        RequestContext, SecurityModel, SetTestError,
    };
    use crate::message::SecurityLevel;
    use crate::oid;

    #[tokio::test]
    async fn decoding_policy_defaults_strict_preset_and_targeted_override() {
        let default = Agent::builder().bind("127.0.0.1:0").build().await.unwrap();
        assert_eq!(
            default.decode_policy(),
            crate::message::DecodePolicy::Compatible
        );
        assert_eq!(
            default.compatibility_policy(),
            crate::CompatibilityPolicy::DEFAULT
        );

        let mut targeted = crate::CompatibilityPolicy::STRICT;
        targeted.empty_counter64_as_zero = true;
        let configured = Agent::builder()
            .bind("127.0.0.1:0")
            .strict_decoding()
            .compatibility_policy(targeted)
            .build()
            .await
            .unwrap();
        assert_eq!(
            configured.decode_policy(),
            crate::message::DecodePolicy::Strict
        );
        assert_eq!(configured.compatibility_policy(), targeted);
    }

    struct TestHandler;

    impl MibHandler for TestHandler {
        fn get<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            oid: &'a Oid,
        ) -> BoxFuture<'a, HandlerResult<GetResult>> {
            Box::pin(async move {
                if oid == &oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0) {
                    return Ok(GetResult::Value(Value::Integer(42)));
                }
                if oid == &oid!(1, 3, 6, 1, 4, 1, 99999, 2, 0) {
                    return Ok(GetResult::Value(Value::OctetString(Bytes::from_static(
                        b"test",
                    ))));
                }
                Ok(GetResult::NoSuchObject)
            })
        }

        fn get_next<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            oid: &'a Oid,
        ) -> BoxFuture<'a, HandlerResult<GetNextResult>> {
            Box::pin(async move {
                let oid1 = oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0);
                let oid2 = oid!(1, 3, 6, 1, 4, 1, 99999, 2, 0);

                if oid < &oid1 {
                    return Ok(GetNextResult::Value(VarBind::new(oid1, Value::Integer(42))));
                }
                if oid < &oid2 {
                    return Ok(GetNextResult::Value(VarBind::new(
                        oid2,
                        Value::OctetString(Bytes::from_static(b"test")),
                    )));
                }
                Ok(GetNextResult::EndOfMibView)
            })
        }
    }

    fn test_ctx() -> RequestContext {
        RequestContext {
            source: "127.0.0.1:12345".parse().unwrap(),
            version: Version::V2c,
            security_model: SecurityModel::V2c,
            security_name: crate::SecurityName::Community(crate::Community::from("public")),
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

    async fn wait_for_run_state(agent: &Agent, expected: bool) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while agent.inner.run_active.load(Ordering::Acquire) != expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("agent run state did not change");
    }

    #[tokio::test]
    async fn cloned_concurrent_run_fails_while_first_stays_operational() {
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), Arc::new(TestHandler))
            .without_builtin_handlers()
            .allow_all_access()
            .build()
            .await
            .unwrap();
        let first_agent = agent.clone();
        let first = tokio::spawn(async move { first_agent.run().await });
        wait_for_run_state(&agent, true).await;

        let error = agent.clone().run().await.unwrap_err();
        assert!(matches!(*error, Error::AgentAlreadyRunning));
        assert!(!first.is_finished());

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let request = crate::message::CommunityMessage::new(
            Version::V2c,
            Bytes::from_static(b"public"),
            Pdu::get_request(7, &[oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0)]),
        )
        .unwrap()
        .encode()
        .unwrap();
        client.send_to(&request, agent.local_addr()).await.unwrap();
        let mut response = [0_u8; 2048];
        let (len, _) =
            tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut response))
                .await
                .expect("first run stopped receiving")
                .unwrap();
        let decoded =
            crate::message::CommunityMessage::decode(Bytes::copy_from_slice(&response[..len]))
                .unwrap();
        let response_pdu = decoded.pdu().standard().unwrap();
        assert_eq!(response_pdu.request_id, 7);
        assert_eq!(response_pdu.error_status(), 0);

        agent.cancel().cancel();
        first.await.unwrap().unwrap();
        wait_for_run_state(&agent, false).await;
        assert!(
            agent.run().await.is_ok(),
            "a later call must acquire the guard"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn wildcard_agent_reply_uses_received_destination_as_source() {
        let agent = Agent::builder()
            .bind("0.0.0.0:0")
            .community(b"public")
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), Arc::new(TestHandler))
            .without_builtin_handlers()
            .allow_all_access()
            .build()
            .await
            .unwrap();
        let destination = SocketAddr::from(([127, 0, 0, 2], agent.local_addr().port()));
        let run_agent = agent.clone();
        let run_task = tokio::spawn(async move { run_agent.run().await });
        wait_for_run_state(&agent, true).await;

        let request = crate::message::CommunityMessage::new(
            Version::V2c,
            Bytes::from_static(b"public"),
            Pdu::get_request(7, &[oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0)]),
        )
        .unwrap()
        .encode()
        .unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&request, destination).await.unwrap();

        let mut response = [0_u8; 2048];
        let (_, source) =
            tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut response))
                .await
                .expect("wildcard agent did not respond")
                .unwrap();
        assert_eq!(source.ip(), destination.ip());

        agent.cancel().cancel();
        run_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn dropped_run_future_releases_exclusivity() {
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .allow_all_access()
            .build()
            .await
            .unwrap();

        let timed_out = tokio::time::timeout(Duration::from_millis(10), agent.run()).await;
        assert!(timed_out.is_err());
        wait_for_run_state(&agent, false).await;

        agent.cancel().cancel();
        assert!(agent.run().await.is_ok());
    }

    #[tokio::test]
    async fn aborted_run_task_releases_exclusivity() {
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .allow_all_access()
            .build()
            .await
            .unwrap();
        let task_agent = agent.clone();
        let task = tokio::spawn(async move { task_agent.run().await });
        wait_for_run_state(&agent, true).await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        wait_for_run_state(&agent, false).await;

        agent.cancel().cancel();
        assert!(agent.run().await.is_ok());
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
        assert!(matches!(result, Err(SetTestError::NotWritable)));
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
            .await
            .unwrap();
        assert!(matches!(result, GetResult::Value(Value::Integer(42))));

        // Non-existing OID
        let result = handler
            .get(&ctx, &oid!(1, 3, 6, 1, 4, 1, 99999, 99, 0))
            .await
            .unwrap();
        assert!(matches!(result, GetResult::NoSuchObject));
    }

    #[tokio::test]
    async fn test_test_handler_get_next() {
        let handler = TestHandler;
        let mut ctx = test_ctx();
        ctx.pdu_type = PduType::GetNextRequest;

        // Before first OID
        let next = handler
            .get_next(&ctx, &oid!(1, 3, 6, 1, 4, 1, 99999))
            .await
            .unwrap();
        assert!(next.is_value());
        if let GetNextResult::Value(vb) = next {
            assert_eq!(vb.oid, oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0));
        }

        // Between OIDs
        let next = handler
            .get_next(&ctx, &oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0))
            .await
            .unwrap();
        assert!(next.is_value());
        if let GetNextResult::Value(vb) = next {
            assert_eq!(vb.oid, oid!(1, 3, 6, 1, 4, 1, 99999, 2, 0));
        }

        // After last OID
        let next = handler
            .get_next(&ctx, &oid!(1, 3, 6, 1, 4, 1, 99999, 2, 0))
            .await
            .unwrap();
        assert!(next.is_end_of_mib_view());
    }

    struct SerialProbeHandler {
        id: &'static str,
        candidates: Vec<Oid>,
        error: Option<&'static str>,
        calls: Arc<std::sync::atomic::AtomicUsize>,
        order: Arc<std::sync::Mutex<Vec<&'static str>>>,
        release: Option<Arc<tokio::sync::Notify>>,
        dropped: Option<Arc<std::sync::atomic::AtomicBool>>,
        handles: bool,
    }

    impl MibHandler for SerialProbeHandler {
        fn get<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
        ) -> BoxFuture<'a, HandlerResult<GetResult>> {
            Box::pin(async { Ok(GetResult::NoSuchObject) })
        }

        fn get_next<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            oid: &'a Oid,
        ) -> BoxFuture<'a, HandlerResult<GetNextResult>> {
            Box::pin(async move {
                struct DropSignal(Option<Arc<std::sync::atomic::AtomicBool>>);

                impl Drop for DropSignal {
                    fn drop(&mut self) {
                        if let Some(dropped) = &self.0 {
                            dropped.store(true, std::sync::atomic::Ordering::SeqCst);
                        }
                    }
                }

                self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                self.order.lock().unwrap().push(self.id);
                let _drop_signal = DropSignal(self.dropped.clone());
                if let Some(release) = &self.release {
                    release.notified().await;
                }
                if let Some(message) = self.error {
                    return Err(HandlerError::new(message));
                }
                Ok(self
                    .candidates
                    .iter()
                    .find(|candidate| *candidate > oid)
                    .cloned()
                    .map(|next| GetNextResult::Value(VarBind::new(next, Value::Integer(1))))
                    .unwrap_or(GetNextResult::EndOfMibView))
            })
        }

        fn handles(&self, _registered_prefix: &Oid, _oid: &Oid) -> bool {
            self.handles
        }
    }

    fn serial_probe(
        id: &'static str,
        candidates: Vec<Oid>,
        calls: Arc<std::sync::atomic::AtomicUsize>,
        order: Arc<std::sync::Mutex<Vec<&'static str>>>,
    ) -> SerialProbeHandler {
        SerialProbeHandler {
            id,
            candidates,
            error: None,
            calls,
            order,
            release: None,
            dropped: None,
            handles: true,
        }
    }

    #[tokio::test]
    async fn get_next_serial_probing_preserves_registration_contracts() {
        let cursor = oid!(1, 3, 6, 1, 4, 1, 100);
        for reverse_registration in [false, true] {
            let order = Arc::new(std::sync::Mutex::new(Vec::new()));
            let nested_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let containing_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let nested = (
                oid!(1, 3, 6, 1, 4, 1, 100, 2),
                Arc::new(SerialProbeHandler {
                    handles: false,
                    ..serial_probe(
                        "nested",
                        vec![oid!(1, 3, 6, 1, 4, 1, 100, 1)],
                        nested_calls.clone(),
                        order.clone(),
                    )
                }) as Arc<dyn MibHandler>,
            );
            let containing = (
                cursor.clone(),
                Arc::new(serial_probe(
                    "containing",
                    vec![oid!(1, 3, 6, 1, 4, 1, 100, 3)],
                    containing_calls.clone(),
                    order.clone(),
                )) as Arc<dyn MibHandler>,
            );
            let registrations = if reverse_registration {
                vec![containing, nested]
            } else {
                vec![nested, containing]
            };
            let mut builder = Agent::builder()
                .bind("127.0.0.1:0")
                .community(b"public")
                .without_builtin_handlers();
            for (prefix, handler) in registrations {
                builder = builder.handler(prefix, handler);
            }
            let agent = builder.allow_all_access().build().await.unwrap();

            let result = agent
                .get_next_oid(&test_ctx(), &cursor)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(result.oid, oid!(1, 3, 6, 1, 4, 1, 100, 1));
            assert_eq!(nested_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
            assert_eq!(
                containing_calls.load(std::sync::atomic::Ordering::SeqCst),
                1
            );
            assert_eq!(*order.lock().unwrap(), ["nested", "containing"]);
        }

        let order = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut builder = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .without_builtin_handlers();
        for (id, suffix) in [("first", 3), ("second", 2)] {
            builder = builder.handler(
                cursor.clone(),
                Arc::new(serial_probe(
                    id,
                    vec![cursor.child(suffix)],
                    Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                    order.clone(),
                )),
            );
        }
        let agent = builder.allow_all_access().build().await.unwrap();
        let result = agent
            .get_next_oid(&test_ctx(), &cursor)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result.oid, cursor.child(2));
        assert_eq!(*order.lock().unwrap(), ["first", "second"]);
    }

    #[tokio::test]
    async fn get_next_waits_for_each_probe_before_starting_the_next() {
        use std::sync::atomic::Ordering;

        let prefix = oid!(1, 3, 6, 1, 4, 1, 200);
        let order = Arc::new(std::sync::Mutex::new(Vec::new()));
        let first_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let later_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let release = Arc::new(tokio::sync::Notify::new());
        let first = SerialProbeHandler {
            release: Some(release.clone()),
            ..serial_probe(
                "first",
                vec![prefix.child(1)],
                first_calls.clone(),
                order.clone(),
            )
        };
        let later = SerialProbeHandler {
            error: Some("later failure"),
            ..serial_probe("later", Vec::new(), later_calls.clone(), order.clone())
        };
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .without_builtin_handlers()
            .handler(prefix.clone(), Arc::new(first))
            .handler(prefix.clone(), Arc::new(later))
            .allow_all_access()
            .build()
            .await
            .unwrap();
        let task = tokio::spawn(async move { agent.get_next_oid(&test_ctx(), &prefix).await });

        tokio::time::timeout(Duration::from_secs(1), async {
            while first_calls.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(later_calls.load(Ordering::SeqCst), 0);
        assert_eq!(*order.lock().unwrap(), ["first"]);

        release.notify_one();
        let error = task.await.unwrap().unwrap_err();
        assert_eq!(error.message(), "later failure");
        assert_eq!(later_calls.load(Ordering::SeqCst), 1);
        assert_eq!(*order.lock().unwrap(), ["first", "later"]);
    }

    #[tokio::test]
    async fn cancelled_get_bulk_drops_current_probe_without_starting_later_handlers() {
        use std::sync::atomic::Ordering;

        let prefix = oid!(1, 3, 6, 1, 4, 1, 300);
        let order = Arc::new(std::sync::Mutex::new(Vec::new()));
        let first_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let later_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let first = SerialProbeHandler {
            release: Some(Arc::new(tokio::sync::Notify::new())),
            dropped: Some(dropped.clone()),
            ..serial_probe("first", Vec::new(), first_calls.clone(), order.clone())
        };
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .without_builtin_handlers()
            .handler(prefix.clone(), Arc::new(first))
            .handler(
                prefix.clone(),
                Arc::new(serial_probe(
                    "later",
                    Vec::new(),
                    later_calls.clone(),
                    order.clone(),
                )),
            )
            .allow_all_access()
            .build()
            .await
            .unwrap();
        let mut ctx = test_ctx();
        ctx.pdu_type = PduType::GetBulkRequest;
        let pdu = Pdu::get_bulk(9, 0, 2, vec![VarBind::new(prefix, Value::Null)]).unwrap();

        assert!(
            tokio::time::timeout(
                Duration::from_millis(20),
                agent.dispatch_request(&ctx, &pdu)
            )
            .await
            .is_err()
        );
        assert_eq!(first_calls.load(Ordering::SeqCst), 1);
        assert_eq!(later_calls.load(Ordering::SeqCst), 0);
        assert!(dropped.load(Ordering::SeqCst));
        assert_eq!(*order.lock().unwrap(), ["first"]);
    }

    #[tokio::test]
    async fn get_bulk_repeats_serial_handler_order_for_each_step() {
        let prefix = oid!(1, 3, 6, 1, 4, 1, 400);
        let order = Arc::new(std::sync::Mutex::new(Vec::new()));
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .without_builtin_handlers()
            .handler(
                prefix.clone(),
                Arc::new(serial_probe(
                    "first",
                    vec![prefix.child(2), prefix.child(4)],
                    Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                    order.clone(),
                )),
            )
            .handler(
                prefix.clone(),
                Arc::new(serial_probe(
                    "second",
                    vec![prefix.child(1), prefix.child(3)],
                    Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                    order.clone(),
                )),
            )
            .allow_all_access()
            .build()
            .await
            .unwrap();
        let mut ctx = test_ctx();
        ctx.pdu_type = PduType::GetBulkRequest;
        let pdu = Pdu::get_bulk(10, 0, 3, vec![VarBind::new(prefix.clone(), Value::Null)]).unwrap();

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();
        assert_eq!(
            response
                .varbinds
                .iter()
                .map(|varbind| varbind.oid.clone())
                .collect::<Vec<_>>(),
            [prefix.child(1), prefix.child(2), prefix.child(3)]
        );
        assert_eq!(
            *order.lock().unwrap(),
            ["first", "second", "first", "second", "first", "second"]
        );
    }

    // Serves .99999.1.0 and fails everything past it, simulating a backing
    // store that is reachable for the first object and down for the rest.
    struct FailingBackendHandler;

    impl MibHandler for FailingBackendHandler {
        fn get<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            oid: &'a Oid,
        ) -> BoxFuture<'a, HandlerResult<GetResult>> {
            Box::pin(async move {
                if oid == &oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0) {
                    return Ok(GetResult::Value(Value::Integer(1)));
                }
                Err(HandlerError::new("backing store unavailable"))
            })
        }

        fn get_next<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            oid: &'a Oid,
        ) -> BoxFuture<'a, HandlerResult<GetNextResult>> {
            Box::pin(async move {
                let first = oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0);
                if oid < &first {
                    return Ok(GetNextResult::Value(VarBind::new(first, Value::Integer(1))));
                }
                Err(HandlerError::new("backing store unavailable"))
            })
        }
    }

    async fn failing_backend_agent() -> Agent {
        AgentBuilder::new()
            .bind("127.0.0.1:0")
            .community(b"public")
            .handler(
                oid!(1, 3, 6, 1, 4, 1, 99999),
                Arc::new(FailingBackendHandler),
            )
            .allow_all_access()
            .build()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_get_handler_error_maps_to_generr() {
        let agent = failing_backend_agent().await;
        let ctx = test_ctx();

        // First varbind succeeds, second hits the failing backend: RFC 3416
        // Section 4.2.1 requires genErr with error-index of the failing varbind
        // and the request varbinds echoed.
        let pdu = Pdu::standard(
            crate::pdu::StandardPduType::GetRequest,
            1,
            0,
            0,
            vec![
                VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0), Value::Null),
                VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999, 2, 0), Value::Null),
            ],
        );

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();
        assert_eq!(response.error_status(), ErrorStatus::GenErr.as_i32());
        assert_eq!(response.error_index(), 2);
        assert_eq!(response.varbinds.len(), 2);
        assert_eq!(response.varbinds[0].oid, pdu.varbinds[0].oid);
    }

    #[tokio::test]
    async fn test_get_v1_handler_error_maps_to_generr() {
        let agent = failing_backend_agent().await;
        let mut ctx = test_ctx();
        ctx.version = Version::V1;

        let pdu = Pdu::standard(
            crate::pdu::StandardPduType::GetRequest,
            2,
            0,
            0,
            vec![VarBind::new(
                oid!(1, 3, 6, 1, 4, 1, 99999, 2, 0),
                Value::Null,
            )],
        );

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();
        assert_eq!(response.error_status(), ErrorStatus::GenErr.as_i32());
        assert_eq!(response.error_index(), 1);
    }

    #[tokio::test]
    async fn test_getnext_handler_error_maps_to_generr() {
        let agent = failing_backend_agent().await;
        let mut ctx = test_ctx();
        ctx.pdu_type = PduType::GetNextRequest;

        let pdu = Pdu::standard(
            crate::pdu::StandardPduType::GetNextRequest,
            3,
            0,
            0,
            vec![VarBind::new(
                oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0),
                Value::Null,
            )],
        );

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();
        assert_eq!(response.error_status(), ErrorStatus::GenErr.as_i32());
        assert_eq!(response.error_index(), 1);
    }

    #[tokio::test]
    async fn test_getbulk_handler_error_maps_to_generr() {
        let agent = failing_backend_agent().await;
        let mut ctx = test_ctx();
        ctx.pdu_type = PduType::GetBulkRequest;

        // Non-repeater resolves to .1.0; the repeater's first GETNEXT fails.
        // error-index refers to the varbind position in the received request
        // (RFC 3416 Section 4.2.3), here 2, regardless of repetition count.
        let pdu = Pdu::get_bulk(
            4,
            1,
            5,
            vec![
                VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999), Value::Null),
                VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0), Value::Null),
            ],
        )
        .unwrap();

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();
        assert_eq!(response.error_status(), ErrorStatus::GenErr.as_i32());
        assert_eq!(response.error_index(), 2);
    }

    // FiveOidHandler has OIDs at .99999.{1,2,3,4,5}.0 with integer values 1-5.
    struct FiveOidHandler;

    impl MibHandler for FiveOidHandler {
        fn get<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            oid: &'a Oid,
        ) -> BoxFuture<'a, HandlerResult<GetResult>> {
            Box::pin(async move {
                for i in 1u16..=5 {
                    if oid == &oid!(1, 3, 6, 1, 4, 1, 99999, i.into(), 0) {
                        return Ok(GetResult::Value(Value::Integer(i.into())));
                    }
                }
                Ok(GetResult::NoSuchObject)
            })
        }

        fn get_next<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            oid: &'a Oid,
        ) -> BoxFuture<'a, HandlerResult<GetNextResult>> {
            Box::pin(async move {
                for i in 1u32..=5 {
                    let candidate = oid!(1, 3, 6, 1, 4, 1, 99999, i, 0);
                    if oid < &candidate {
                        return Ok(GetNextResult::Value(VarBind::new(
                            candidate,
                            Value::Integer(i as i32),
                        )));
                    }
                }
                Ok(GetNextResult::EndOfMibView)
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
                    .access(
                        "readers",
                        SecurityModel::V2c,
                        SecurityLevel::NoAuthNoPriv,
                        |a| a.read_view("restricted"),
                    )
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
        let pdu = Pdu::get_bulk(
            1,
            0,
            10,
            vec![VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999), Value::Null)],
        )
        .unwrap();

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
        let pdu = Pdu::get_bulk(
            2,
            2,
            0,
            vec![
                VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999), Value::Null),
                VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999, 4, 0), Value::Null),
            ],
        )
        .unwrap();

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

    /// Handler exposing an effectively unbounded range of OIDs under
    /// .99999.1.<n>, counting every `get_next` call. Used to exercise the
    /// GETNEXT candidate skip cap.
    struct CountingRangeHandler {
        calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl MibHandler for CountingRangeHandler {
        fn get<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
        ) -> BoxFuture<'a, HandlerResult<GetResult>> {
            Box::pin(async move { Ok(GetResult::NoSuchObject) })
        }

        fn get_next<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
        ) -> BoxFuture<'a, HandlerResult<GetNextResult>> {
            Box::pin(async move {
                // Nth call returns .99999.1.N; N strictly increases each call, so
                // the returned OID is always greater than the previous one (the
                // current search cursor), keeping the walk monotonically advancing.
                let n = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                let next = Oid::from_slice(&[1, 3, 6, 1, 4, 1, 99999, 1]).child(n as u32);
                Ok(GetNextResult::Value(VarBind::new(next, Value::Integer(1))))
            })
        }
    }

    // Regression: cap exhaustion is a processing failure, not end-of-MIB.
    #[tokio::test]
    async fn test_getnext_vacm_denied_range_is_capped() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .handler(
                oid!(1, 3, 6, 1, 4, 1, 99999),
                Arc::new(CountingRangeHandler {
                    calls: calls.clone(),
                }),
            )
            // View includes an unrelated subtree only, so every OID the handler
            // returns under .99999 is denied.
            .vacm(|v| {
                v.group("public", SecurityModel::V2c, "readers")
                    .access(
                        "readers",
                        SecurityModel::V2c,
                        SecurityLevel::NoAuthNoPriv,
                        |a| a.read_view("restricted"),
                    )
                    .view("restricted", |v| v.include(oid!(1, 3, 6, 1, 4, 1, 88888)))
            })
            .build()
            .await
            .unwrap();

        let mut ctx = test_ctx();
        ctx.pdu_type = PduType::GetNextRequest;
        ctx.read_view = Some(Bytes::from_static(b"restricted"));

        let pdu = Pdu::standard(
            crate::pdu::StandardPduType::GetNextRequest,
            1,
            0,
            0,
            vec![VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999), Value::Null)],
        );

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();

        assert_eq!(response.error_status(), ErrorStatus::GenErr.as_i32());
        assert_eq!(response.error_index(), 1);

        let total = calls.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(total, MAX_GETNEXT_SKIP_ITERATIONS);
    }

    struct Counter64RangeHandler {
        calls: Arc<std::sync::atomic::AtomicUsize>,
        unbounded: bool,
    }

    impl MibHandler for Counter64RangeHandler {
        fn get<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
        ) -> BoxFuture<'a, HandlerResult<GetResult>> {
            Box::pin(async { Ok(GetResult::NoSuchObject) })
        }

        fn get_next<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
        ) -> BoxFuture<'a, HandlerResult<GetNextResult>> {
            Box::pin(async move {
                let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
                if !self.unbounded && n > 1 {
                    return Ok(GetNextResult::EndOfMibView);
                }
                let next = Oid::from_slice(&[1, 3, 6, 1, 4, 1, 99999, 1]).child(n as u32);
                Ok(GetNextResult::Value(VarBind::new(
                    next,
                    Value::Counter64(n as u64),
                )))
            })
        }
    }

    async fn counter64_range_agent(
        unbounded: bool,
    ) -> (Agent, Arc<std::sync::atomic::AtomicUsize>) {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .handler(
                oid!(1, 3, 6, 1, 4, 1, 99999),
                Arc::new(Counter64RangeHandler {
                    calls: calls.clone(),
                    unbounded,
                }),
            )
            .without_builtin_handlers()
            .allow_all_access()
            .build()
            .await
            .unwrap();
        (agent, calls)
    }

    #[tokio::test]
    async fn test_v1_counter64_skip_cap_is_gen_err() {
        let (agent, calls) = counter64_range_agent(true).await;
        let mut ctx = test_ctx();
        ctx.version = Version::V1;
        ctx.security_model = SecurityModel::V1;
        ctx.pdu_type = PduType::GetNextRequest;
        let pdu = Pdu::get_next_request(1, &[oid!(1, 3, 6, 1, 4, 1, 99999)]);

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();
        assert_eq!(response.error_status(), ErrorStatus::GenErr.as_i32());
        assert_eq!(response.error_index(), 1);
        assert_eq!(calls.load(Ordering::SeqCst), MAX_GETNEXT_SKIP_ITERATIONS);
    }

    #[tokio::test]
    async fn test_v1_counter64_skip_reaching_actual_eom_is_not_cap_failure() {
        let (agent, calls) = counter64_range_agent(false).await;
        let mut ctx = test_ctx();
        ctx.version = Version::V1;
        ctx.security_model = SecurityModel::V1;
        ctx.pdu_type = PduType::GetNextRequest;
        let pdu = Pdu::get_next_request(1, &[oid!(1, 3, 6, 1, 4, 1, 99999)]);

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();
        assert_eq!(response.error_status(), ErrorStatus::NoSuchName.as_i32());
        assert_eq!(response.error_index(), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    // TestHandler with three OIDs: .99999.1.0, .99999.2.0, .99999.3.0
    struct ThreeOidHandler;

    impl MibHandler for ThreeOidHandler {
        fn get<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            oid: &'a Oid,
        ) -> BoxFuture<'a, HandlerResult<GetResult>> {
            Box::pin(async move {
                if oid == &oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0) {
                    return Ok(GetResult::Value(Value::Integer(1)));
                }
                if oid == &oid!(1, 3, 6, 1, 4, 1, 99999, 2, 0) {
                    return Ok(GetResult::Value(Value::Integer(2)));
                }
                if oid == &oid!(1, 3, 6, 1, 4, 1, 99999, 3, 0) {
                    return Ok(GetResult::Value(Value::Integer(3)));
                }
                Ok(GetResult::NoSuchObject)
            })
        }

        fn get_next<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            oid: &'a Oid,
        ) -> BoxFuture<'a, HandlerResult<GetNextResult>> {
            Box::pin(async move {
                let oid1 = oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0);
                let oid2 = oid!(1, 3, 6, 1, 4, 1, 99999, 2, 0);
                let oid3 = oid!(1, 3, 6, 1, 4, 1, 99999, 3, 0);

                if oid < &oid1 {
                    return Ok(GetNextResult::Value(VarBind::new(oid1, Value::Integer(1))));
                }
                if oid < &oid2 {
                    return Ok(GetNextResult::Value(VarBind::new(oid2, Value::Integer(2))));
                }
                if oid < &oid3 {
                    return Ok(GetNextResult::Value(VarBind::new(oid3, Value::Integer(3))));
                }
                Ok(GetNextResult::EndOfMibView)
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
                    .access(
                        "readers",
                        SecurityModel::V2c,
                        SecurityLevel::NoAuthNoPriv,
                        |a| a.read_view("gap"),
                    )
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

        let pdu = Pdu::standard(
            crate::pdu::StandardPduType::GetNextRequest,
            1,
            0,
            0,
            vec![VarBind::new(
                oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0),
                Value::Null,
            )],
        );

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

        let pdu = Pdu::standard(
            crate::pdu::StandardPduType::GetNextRequest,
            1,
            0,
            0,
            vec![VarBind::new(
                oid!(1, 3, 6, 1, 4, 1, 99999, 4, 0),
                Value::Null,
            )],
        );

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
            .allow_all_access()
            .build()
            .await
            .unwrap();

        let mut ctx = test_ctx();
        ctx.pdu_type = PduType::GetBulkRequest;

        let pdu = Pdu::get_bulk(
            1,
            0,
            10,
            vec![VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999), Value::Null)],
        )
        .unwrap();

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
            .allow_all_access()
            .build()
            .await
            .unwrap();

        let mut ctx = test_ctx();
        ctx.version = Version::V1;
        ctx.security_model = SecurityModel::V1;
        ctx.pdu_type = PduType::GetBulkRequest;

        let pdu = Pdu::get_bulk(
            1,
            0,
            10,
            vec![VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999), Value::Null)],
        )
        .unwrap();

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();
        assert_eq!(
            ErrorStatus::from_i32(response.error_status()),
            ErrorStatus::GenErr,
            "v1 GETBULK should be rejected"
        );
    }

    /// Handler returning Counter64 at .99999.1.0, Integer at .99999.2.0
    struct Counter64Handler;

    impl MibHandler for Counter64Handler {
        fn get<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            oid: &'a Oid,
        ) -> BoxFuture<'a, HandlerResult<GetResult>> {
            Box::pin(async move {
                if oid == &oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0) {
                    return Ok(GetResult::Value(Value::Counter64(1_000_000_000_000)));
                }
                if oid == &oid!(1, 3, 6, 1, 4, 1, 99999, 2, 0) {
                    return Ok(GetResult::Value(Value::Integer(42)));
                }
                Ok(GetResult::NoSuchObject)
            })
        }

        fn get_next<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            oid: &'a Oid,
        ) -> BoxFuture<'a, HandlerResult<GetNextResult>> {
            Box::pin(async move {
                let oid1 = oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0);
                let oid2 = oid!(1, 3, 6, 1, 4, 1, 99999, 2, 0);

                if oid < &oid1 {
                    return Ok(GetNextResult::Value(VarBind::new(
                        oid1,
                        Value::Counter64(1_000_000_000_000),
                    )));
                }
                if oid < &oid2 {
                    return Ok(GetNextResult::Value(VarBind::new(oid2, Value::Integer(42))));
                }
                Ok(GetNextResult::EndOfMibView)
            })
        }
    }

    async fn test_agent_with_counter64() -> Agent {
        Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), Arc::new(Counter64Handler))
            .allow_all_access()
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

        let pdu = Pdu::standard(
            crate::pdu::StandardPduType::GetRequest,
            1,
            0,
            0,
            vec![VarBind::new(
                oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0),
                Value::Null,
            )],
        );

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();
        assert_eq!(
            ErrorStatus::from_i32(response.error_status()),
            ErrorStatus::NoSuchName,
            "v1 GET of Counter64 should return noSuchName"
        );
    }

    #[tokio::test]
    async fn test_v2c_get_allows_counter64() {
        // v2c should return Counter64 normally
        let agent = test_agent_with_counter64().await;

        let ctx = test_ctx(); // v2c by default

        let pdu = Pdu::standard(
            crate::pdu::StandardPduType::GetRequest,
            1,
            0,
            0,
            vec![VarBind::new(
                oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0),
                Value::Null,
            )],
        );

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();
        assert_eq!(response.error_status(), 0);
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
            .allow_all_access()
            .build()
            .await
            .unwrap();

        // First, get the full response without msg_max_size limit
        let mut ctx_unlimited = test_ctx();
        ctx_unlimited.pdu_type = PduType::GetBulkRequest;
        ctx_unlimited.msg_max_size = None;

        let pdu = Pdu::get_bulk(
            1,
            0,
            10,
            vec![VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999), Value::Null)],
        )
        .unwrap();

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

    #[tokio::test]
    async fn test_response_overhead_scales_with_v3_security_level() {
        // A 17-octet engine ID is carried twice (authoritative + context).
        let engine_id = vec![0x11u8; 17];
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .engine_id(engine_id.clone())
            .allow_all_access()
            .build()
            .await
            .unwrap();

        // v1/v2c: base overhead plus the echoed community string, unaffected by
        // the security level field.
        let v2c = test_ctx();
        assert_eq!(
            agent.response_overhead(&v2c),
            RESPONSE_OVERHEAD + v2c.security_name.len()
        );

        let username = Bytes::from_static(b"user");
        let variable = 2 * engine_id.len() + username.len(); // context name empty

        let mut noauth = test_ctx();
        noauth.version = Version::V3;
        noauth.security_level = SecurityLevel::NoAuthNoPriv;
        noauth.security_name = crate::SecurityName::Usm(username.clone());
        assert_eq!(
            agent.response_overhead(&noauth),
            RESPONSE_OVERHEAD + variable
        );

        let mut authnopriv = noauth.clone();
        authnopriv.security_level = SecurityLevel::AuthNoPriv;
        assert_eq!(
            agent.response_overhead(&authnopriv),
            RESPONSE_OVERHEAD + variable + V3_AUTH_OVERHEAD
        );

        let mut authpriv = noauth.clone();
        authpriv.security_level = SecurityLevel::AuthPriv;
        assert_eq!(
            agent.response_overhead(&authpriv),
            RESPONSE_OVERHEAD + variable + V3_AUTH_OVERHEAD + V3_PRIV_OVERHEAD
        );

        // Overhead is monotonic in the wrapper cost.
        assert!(agent.response_overhead(&v2c) < agent.response_overhead(&noauth));
        assert!(agent.response_overhead(&noauth) < agent.response_overhead(&authnopriv));
        assert!(agent.response_overhead(&authnopriv) < agent.response_overhead(&authpriv));
    }

    #[tokio::test]
    async fn test_response_overhead_counts_community_length() {
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .allow_all_access()
            .build()
            .await
            .unwrap();

        // A long, operator-configured community is echoed in the v1/v2c
        // response wrapper and must be reflected in GETBULK's early budget.
        let short = test_ctx();
        let mut long = test_ctx();
        long.security_name = crate::SecurityName::Usm(Bytes::from(vec![b'x'; 200]));

        assert_eq!(
            agent.response_overhead(&long) - agent.response_overhead(&short),
            long.security_name.len() - short.security_name.len()
        );
    }

    #[tokio::test]
    async fn test_getbulk_authpriv_budgets_for_wrapper() {
        // For the same advertised msgMaxSize, an authPriv v3 request must
        // reserve more space for the USM/scopedPDU wrapper than a v2c request,
        // so it fits strictly fewer varbinds. Under the old fixed overhead both
        // budgeted identically and the authPriv Response could exceed the limit.
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .max_message_size(65507)
            .engine_id(vec![0x11u8; 17])
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), Arc::new(FiveOidHandler))
            .allow_all_access()
            .build()
            .await
            .unwrap();

        let pdu = Pdu::get_bulk(
            1,
            0,
            10,
            vec![VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999), Value::Null)],
        )
        .unwrap();

        // A limit large enough to expose the difference: v2c fits more varbinds
        // than authPriv because authPriv's overhead is larger.
        let limit = 200;

        let mut v2c = test_ctx();
        v2c.pdu_type = PduType::GetBulkRequest;
        v2c.msg_max_size = Some(limit);
        let v2c_count = agent
            .dispatch_request(&v2c, &pdu)
            .await
            .unwrap()
            .varbinds
            .iter()
            .filter(|vb| !matches!(vb.value, Value::EndOfMibView))
            .count();

        let mut authpriv = test_ctx();
        authpriv.version = Version::V3;
        authpriv.security_level = SecurityLevel::AuthPriv;
        authpriv.security_name = crate::SecurityName::Usm(Bytes::from_static(b"user"));
        authpriv.pdu_type = PduType::GetBulkRequest;
        authpriv.msg_max_size = Some(limit);
        let authpriv_count = agent
            .dispatch_request(&authpriv, &pdu)
            .await
            .unwrap()
            .varbinds
            .iter()
            .filter(|vb| !matches!(vb.value, Value::EndOfMibView))
            .count();

        assert!(
            authpriv_count < v2c_count,
            "authPriv should budget fewer varbinds than v2c for the same \
             msgMaxSize: authpriv={authpriv_count}, v2c={v2c_count}"
        );
    }

    // Handler with two large non-repeater values under .99999.1.0 and
    // .99999.2.0, and a small repeater value under .99999.9.0.
    struct MixedSizeHandler;

    impl MibHandler for MixedSizeHandler {
        fn get<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            oid: &'a Oid,
        ) -> BoxFuture<'a, HandlerResult<GetResult>> {
            Box::pin(async move {
                if oid == &oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0)
                    || oid == &oid!(1, 3, 6, 1, 4, 1, 99999, 2, 0)
                {
                    return Ok(GetResult::Value(Value::OctetString(Bytes::from(vec![
                        0xAB;
                        200
                    ]))));
                }
                if oid == &oid!(1, 3, 6, 1, 4, 1, 99999, 9, 0) {
                    return Ok(GetResult::Value(Value::Integer(7)));
                }
                Ok(GetResult::NoSuchObject)
            })
        }

        fn get_next<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            oid: &'a Oid,
        ) -> BoxFuture<'a, HandlerResult<GetNextResult>> {
            Box::pin(async move {
                let big1 = oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0);
                let big2 = oid!(1, 3, 6, 1, 4, 1, 99999, 2, 0);
                let small = oid!(1, 3, 6, 1, 4, 1, 99999, 9, 0);
                if oid < &big1 {
                    return Ok(GetNextResult::Value(VarBind::new(
                        big1,
                        Value::OctetString(Bytes::from(vec![0xAB; 200])),
                    )));
                }
                if oid < &big2 {
                    return Ok(GetNextResult::Value(VarBind::new(
                        big2,
                        Value::OctetString(Bytes::from(vec![0xAB; 200])),
                    )));
                }
                if oid < &small {
                    return Ok(GetNextResult::Value(VarBind::new(small, Value::Integer(7))));
                }
                Ok(GetNextResult::EndOfMibView)
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
            .allow_all_access()
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
        ctx.msg_max_size = Some(max);

        let pdu = Pdu::get_bulk(
            1,
            2,
            2,
            vec![
                VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999, 1), Value::Null),
                VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999, 2), Value::Null),
                VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999, 9), Value::Null),
            ],
        )
        .unwrap();

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
    async fn test_getbulk_first_non_repeater_survives_conservative_budget() {
        // The dispatch-layer budget is only an optimization. Its first
        // candidate must survive for exact message-envelope finalization.
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .max_message_size(65507)
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), Arc::new(MixedSizeHandler))
            .without_builtin_handlers()
            .allow_all_access()
            .build()
            .await
            .unwrap();

        let mut ctx = test_ctx();
        ctx.pdu_type = PduType::GetBulkRequest;
        // Below RESPONSE_OVERHEAD, so even the first varbind cannot fit.
        ctx.msg_max_size = Some(RESPONSE_OVERHEAD - 1);

        let pdu = Pdu::get_bulk(
            1,
            2,
            2,
            vec![
                VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999, 1), Value::Null),
                VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999, 2), Value::Null),
                VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999, 9), Value::Null),
            ],
        )
        .unwrap();

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();

        assert_eq!(response.error_status(), 0);
        assert_eq!(response.varbinds.len(), 1);
    }

    #[tokio::test]
    async fn test_getbulk_first_repeater_survives_conservative_budget() {
        // The first repeater candidate likewise reaches exact envelope
        // finalization rather than letting the estimate select tooBig.
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .max_message_size(65507)
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), Arc::new(MixedSizeHandler))
            .without_builtin_handlers()
            .allow_all_access()
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
        ctx.msg_max_size = Some(max);

        let pdu = Pdu::get_bulk(
            1,
            0,
            5,
            vec![VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999, 1), Value::Null)],
        )
        .unwrap();

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();

        assert_eq!(response.error_status(), 0);
        assert_eq!(response.varbinds.len(), 1);
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
            .allow_all_access()
            .build()
            .await
            .unwrap();

        let mut ctx = test_ctx();
        ctx.pdu_type = PduType::GetBulkRequest;
        ctx.msg_max_size = None; // v2c, no client limit

        let pdu = Pdu::get_bulk(
            1,
            0,
            10,
            vec![VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999), Value::Null)],
        )
        .unwrap();

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

        let pdu = Pdu::standard(
            crate::pdu::StandardPduType::GetNextRequest,
            1,
            0,
            0,
            vec![VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999), Value::Null)],
        );

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();
        assert_eq!(response.error_status(), 0, "should succeed");
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
    fn test_engine_time_at_max_is_representable() {
        let max = crate::v3::MAX_ENGINE_TIME;
        let (boots, time) = crate::v3::compute_engine_boots_time(1, u64::from(max));
        assert_eq!(boots, 1);
        assert_eq!(time, max);
    }

    #[test]
    fn test_engine_time_wraps_after_max() {
        let max = crate::v3::MAX_ENGINE_TIME;
        let (boots, time) = crate::v3::compute_engine_boots_time(1, u64::from(max) + 1);
        assert_eq!(boots, 2);
        assert_eq!(time, 0);
    }

    #[test]
    fn test_engine_time_past_max() {
        // 500 seconds into the second complete 31-bit cycle.
        let cycle = u64::from(crate::v3::MAX_ENGINE_TIME) + 1;
        let (boots, time) = crate::v3::compute_engine_boots_time(1, cycle + 500);
        assert_eq!(boots, 2);
        assert_eq!(time, 500);
    }

    #[test]
    fn test_engine_time_multiple_wraps() {
        // Three full cycles
        let cycle = u64::from(crate::v3::MAX_ENGINE_TIME) + 1;
        let elapsed = cycle * 3 + 42;
        let (boots, time) = crate::v3::compute_engine_boots_time(1, elapsed);
        assert_eq!(boots, 4, "base 1 + 3 wraps = 4");
        assert_eq!(time, 42);
    }

    #[test]
    fn test_engine_time_boots_capped_at_max() {
        // If enough wraps happen that boots would exceed MAX_ENGINE_TIME, cap it
        let max = crate::v3::MAX_ENGINE_TIME;
        let cycle = u64::from(max) + 1;
        let elapsed = cycle * u64::from(max); // way more wraps than max allows
        let (boots, _time) = crate::v3::compute_engine_boots_time(1, elapsed);
        assert_eq!(boots, max, "boots should be capped at MAX_ENGINE_TIME");
    }

    #[test]
    fn test_engine_time_base_boots_preserved() {
        // A non-1 base boots (e.g. from persistence) is respected
        let cycle = u64::from(crate::v3::MAX_ENGINE_TIME) + 1;
        let (boots, time) = crate::v3::compute_engine_boots_time(5, cycle + 100);
        assert_eq!(boots, 6, "base 5 + 1 wrap = 6");
        assert_eq!(time, 100);
    }

    #[test]
    fn test_engine_time_high_base_boots_capped() {
        // Base boots near MAX_ENGINE_TIME with a wrap should cap
        let max = crate::v3::MAX_ENGINE_TIME;
        let cycle = u64::from(max) + 1;
        let (boots, _time) = crate::v3::compute_engine_boots_time(max - 1, cycle * 2);
        assert_eq!(boots, max, "should cap at MAX_ENGINE_TIME, not overflow");
    }

    #[tokio::test]
    async fn test_authoritative_engine_builder() {
        let engine = AuthoritativeEngine::install(b"test-agent-engine".to_vec(), |_| {
            Ok::<(), std::convert::Infallible>(())
        })
        .unwrap();
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .authoritative_engine(engine)
            .allow_all_access()
            .build()
            .await
            .unwrap();

        assert_eq!(agent.engine_boots(), 1);
        assert_eq!(agent.engine_id(), b"test-agent-engine");
    }

    #[tokio::test]
    async fn inbound_identities_require_explicit_authorization_before_bind() {
        let result = Agent::builder()
            .bind("not a socket address")
            .community(b"public")
            .build()
            .await;
        let error = result.err().expect("missing Agent policy must fail");
        assert!(matches!(
            *error,
            Error::Config(ref message) if message.contains("requires vacm() or allow_all_access()")
        ));

        let result = Agent::builder()
            .bind("not a socket address")
            .usm_user("user", |user| user)
            .build()
            .await;
        let error = result.err().expect("missing Agent policy must fail");
        assert!(matches!(
            *error,
            Error::Config(ref message) if message.contains("requires vacm() or allow_all_access()")
        ));
    }

    #[tokio::test]
    async fn conflicting_agent_authorization_selections_are_rejected() {
        for result in [
            Agent::builder()
                .bind("not a socket address")
                .allow_all_access()
                .vacm(|vacm| vacm)
                .build()
                .await,
            Agent::builder()
                .bind("not a socket address")
                .vacm(|vacm| vacm)
                .allow_all_access()
                .build()
                .await,
        ] {
            let error = result.err().expect("conflicting policies must fail");
            assert!(matches!(
                *error,
                Error::Config(ref message) if message.contains("mutually exclusive")
            ));
        }
    }

    #[tokio::test]
    async fn empty_vacm_is_an_explicit_deny_all_policy() {
        Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .vacm(|vacm| vacm)
            .build()
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_v3_agent_requires_authoritative_engine_before_bind() {
        let result = Agent::builder()
            .bind("not a socket address")
            .usm_user("user", |user| user)
            .allow_all_access()
            .build()
            .await;

        let err = result.err().expect("expected build to fail");
        assert!(matches!(
            *err,
            Error::Config(ref message)
                if message.contains("authoritative engine state is required")
        ));
    }

    #[tokio::test]
    async fn test_v3_trap_sink_requires_authoritative_engine_before_bind() {
        let result = Agent::builder()
            .bind("not a socket address")
            .trap_sink("v3-sink", "127.0.0.1:162", crate::Auth::usm("trapuser"))
            .build()
            .await;

        let err = result.err().expect("expected build to fail");
        assert!(matches!(
            *err,
            Error::Config(ref message)
                if message.contains("authoritative engine state is required")
        ));
    }

    #[tokio::test]
    async fn test_authoritative_engine_persistence_failure_precedes_bind() {
        let engine = AuthoritativeEngine::with_rollover_persistence_failure_for_test(
            b"test-agent-engine".to_vec(),
        );
        let result = Agent::builder()
            .bind("not a socket address")
            .community(b"public")
            .authoritative_engine(engine)
            .allow_all_access()
            .build()
            .await;

        let err = result.err().expect("expected build to fail");
        assert!(err.to_string().contains("storage unavailable"));
    }

    #[tokio::test]
    async fn test_agent_community_matching_preserves_deny_empty_policy() {
        let empty = Agent::builder().bind("127.0.0.1:0").build().await.unwrap();
        assert!(!empty.validate_community(b"public"));
        assert!(!empty.validate_community(b""));
        assert!(empty.inner.salt_counter.is_none());

        let configured = Agent::builder()
            .bind("127.0.0.1:0")
            .communities([b"public".as_slice(), b"monitor"])
            .allow_all_access()
            .build()
            .await
            .unwrap();
        assert!(configured.validate_community(b"public"));
        assert!(configured.validate_community(b"monitor"));
        assert!(configured.inner.salt_counter.is_none());
        for community in [b"private".as_slice(), b"pub", b"publicx", b""] {
            assert!(!configured.validate_community(community));
        }
    }

    #[tokio::test]
    async fn test_invalid_usm_user_is_rejected_before_bind() {
        let result = Agent::builder()
            .bind("not a socket address")
            .usm_user("", |user| user)
            .allow_all_access()
            .build()
            .await;

        let err = result.err().expect("expected build to fail");
        assert!(matches!(
            *err,
            Error::Config(ref message) if message.contains("USM username")
        ));
    }

    #[tokio::test]
    async fn test_subminimum_response_cap_is_not_an_advertised_capacity() {
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .max_message_size(0)
            .without_builtin_handlers()
            .build()
            .await
            .unwrap();
        assert_eq!(agent.inner.state.max_message_size, 0);
        assert_eq!(
            agent.inner.state.local_receive_capacity,
            UDP_RECEIVE_LIMITS.advertised()
        );
    }

    #[tokio::test]
    async fn test_max_message_size_above_udp_capacity_rejected_before_bind() {
        let max_udp_message_size = crate::UDP_RECEIVE_LIMITS.advertised().as_usize();
        let result = Agent::builder()
            .bind("not a socket address")
            .max_message_size(max_udp_message_size + 1)
            .build()
            .await;

        let err = result.err().expect("expected build to fail");
        match *err {
            Error::Config(message) => assert!(message.contains("max_message_size")),
            other => panic!("expected max_message_size configuration error, got {other}"),
        }
    }

    #[tokio::test]
    async fn test_zero_max_concurrent_requests_rejected() {
        // A zero-permit concurrency limit would never grant a permit and wedge
        // the agent on the first packet, so the builder must reject it.
        let result = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .max_concurrent_requests(Some(0))
            .allow_all_access()
            .build()
            .await;

        let err = result.err().expect("expected build to fail");
        assert!(matches!(*err, Error::Config(_)));
    }

    #[tokio::test]
    async fn test_engine_boots_default() {
        // Default engine_boots is 1
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .allow_all_access()
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
            .allow_all_access()
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
            .allow_all_access()
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
            .allow_all_access()
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
            .await
            .unwrap();
        assert!(matches!(get_result, GetResult::Value(Value::Integer(_))));

        // usmStatsWrongDigests.0 should be queryable
        let handler = agent
            .find_handler(&oid!(1, 3, 6, 1, 6, 3, 15, 1, 1, 5, 0))
            .expect("USM stats handler should be registered");
        let get_result = handler
            .handler
            .get(&ctx, &oid!(1, 3, 6, 1, 6, 3, 15, 1, 1, 5, 0))
            .await
            .unwrap();
        assert!(matches!(get_result, GetResult::Value(Value::Counter32(0))));

        // snmpUnknownSecurityModels.0 should be queryable
        let handler = agent
            .find_handler(&oid!(1, 3, 6, 1, 6, 3, 11, 2, 1, 1, 0))
            .expect("MPD stats handler should be registered");
        let get_result = handler
            .handler
            .get(&ctx, &oid!(1, 3, 6, 1, 6, 3, 11, 2, 1, 1, 0))
            .await
            .unwrap();
        assert!(matches!(get_result, GetResult::Value(Value::Counter32(0))));
    }

    #[tokio::test]
    async fn test_builtin_handlers_disabled() {
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .without_builtin_handlers()
            .allow_all_access()
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
            .allow_all_access()
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
            .max_message_size(80)
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), Arc::new(FiveOidHandler))
            .without_builtin_handlers()
            .allow_all_access()
            .build()
            .await
            .unwrap()
    }

    fn five_varbinds() -> Vec<VarBind> {
        (1u32..=5)
            .map(|i| VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999, i, 0), Value::Null))
            .collect()
    }

    async fn finalized_community_response(agent: &Agent, version: Version, pdu: Pdu) -> Pdu {
        let request = crate::message::CommunityMessage::new(version, b"public".as_slice(), pdu)
            .unwrap()
            .encode()
            .unwrap();
        let bytes = match version {
            Version::V1 => {
                agent
                    .handle_v1(request, "127.0.0.1:161".parse().unwrap())
                    .await
            }
            Version::V2c => {
                agent
                    .handle_v2c(request, "127.0.0.1:161".parse().unwrap())
                    .await
            }
            Version::V3 => unreachable!(),
        }
        .unwrap()
        .unwrap();
        crate::message::CommunityMessage::decode(bytes)
            .unwrap()
            .pdu()
            .standard()
            .unwrap()
            .clone()
    }

    #[tokio::test]
    async fn test_get_too_big_returns_toobig_response() {
        let agent = small_limit_agent().await;

        // GET for all five OIDs; the response cannot fit within the 150-byte
        // effective limit, so RFC 3416 Section 4.2.1 requires a tooBig Response.
        let pdu = Pdu::standard(
            crate::pdu::StandardPduType::GetRequest,
            1,
            0,
            0,
            five_varbinds(),
        );

        let response = finalized_community_response(&agent, Version::V2c, pdu).await;
        assert_eq!(response.error_status(), ErrorStatus::TooBig.as_i32());
        assert_eq!(response.error_index(), 0);
        assert!(response.varbinds.is_empty());
    }

    #[tokio::test]
    async fn test_v1_exact_size_overrides_conservative_estimate() {
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .max_message_size(150)
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), Arc::new(FiveOidHandler))
            .without_builtin_handlers()
            .allow_all_access()
            .build()
            .await
            .unwrap();

        // The old conservative estimate selected tooBig here. Exact envelope
        // encoding shows that the normal response fits.
        let request_varbinds = five_varbinds();
        let pdu = Pdu::standard(
            crate::pdu::StandardPduType::GetRequest,
            1,
            0,
            0,
            request_varbinds.clone(),
        );

        let response = finalized_community_response(&agent, Version::V1, pdu.clone()).await;
        assert_eq!(response.error_status(), 0);
        assert_eq!(response.varbinds.len(), request_varbinds.len());

        let v2c_response = finalized_community_response(&agent, Version::V2c, pdu).await;
        assert_eq!(v2c_response.error_status(), 0);
        assert_eq!(v2c_response.varbinds.len(), request_varbinds.len());
    }

    #[tokio::test]
    async fn test_get_within_limit_returns_response() {
        let agent = small_limit_agent().await;
        let ctx = test_ctx();

        // A single varbind fits comfortably; the tooBig check must not fire.
        let pdu = Pdu::standard(
            crate::pdu::StandardPduType::GetRequest,
            1,
            0,
            0,
            vec![VarBind::new(
                oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0),
                Value::Null,
            )],
        );

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();
        assert_eq!(response.error_status(), 0);
        assert_eq!(response.varbinds.len(), 1);
        assert!(matches!(response.varbinds[0].value, Value::Integer(1)));
    }

    #[tokio::test]
    async fn test_getnext_too_big_returns_toobig_response() {
        let agent = small_limit_agent().await;

        let pdu = Pdu::standard(
            crate::pdu::StandardPduType::GetNextRequest,
            1,
            0,
            0,
            five_varbinds(),
        );

        let response = finalized_community_response(&agent, Version::V2c, pdu).await;
        assert_eq!(response.error_status(), ErrorStatus::TooBig.as_i32());
        assert_eq!(response.error_index(), 0);
        assert!(response.varbinds.is_empty());
    }

    #[tokio::test]
    async fn test_inform_too_big_returns_toobig_response() {
        let agent = small_limit_agent().await;

        // An InformRequest whose echoed Response would exceed the 150-byte
        // effective limit. RFC 3416 Section 4.2.7 (confirmed-class) requires a
        // fitting tooBig acknowledgement rather than silently dropping the
        // oversized echo, which would make a confirmed-class sender retry
        // indefinitely.
        let big = Value::OctetString(Bytes::from(vec![0xABu8; 256]));
        let pdu = Pdu::standard(
            crate::pdu::StandardPduType::InformRequest,
            1,
            0,
            0,
            vec![VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0), big)],
        );

        let response = finalized_community_response(&agent, Version::V2c, pdu).await;
        assert_eq!(response.error_status(), ErrorStatus::TooBig.as_i32());
        assert_eq!(response.error_index(), 0);
        assert!(response.varbinds.is_empty());
    }

    #[tokio::test]
    async fn test_inform_within_limit_echoes_varbinds() {
        let agent = small_limit_agent().await;
        let mut ctx = test_ctx();
        ctx.pdu_type = PduType::InformRequest;

        // A small Inform fits within the limit and is acknowledged by echoing
        // the same varbinds in a Response.
        let pdu = Pdu::standard(
            crate::pdu::StandardPduType::InformRequest,
            7,
            0,
            0,
            vec![VarBind::new(
                oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0),
                Value::Integer(42),
            )],
        );

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();
        assert_eq!(response.pdu_type(), PduType::Response);
        assert_eq!(response.error_status(), 0);
        assert_eq!(response.request_id, 7);
        assert_eq!(response.varbinds.len(), 1);
        assert!(matches!(response.varbinds[0].value, Value::Integer(42)));
    }

    #[tokio::test]
    async fn test_getnext_within_limit_returns_response() {
        let agent = small_limit_agent().await;
        let mut ctx = test_ctx();
        ctx.pdu_type = PduType::GetNextRequest;

        let pdu = Pdu::standard(
            crate::pdu::StandardPduType::GetNextRequest,
            1,
            0,
            0,
            vec![VarBind::new(
                oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0),
                Value::Null,
            )],
        );

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();
        assert_eq!(response.error_status(), 0);
        assert_eq!(response.varbinds.len(), 1);
        assert_eq!(
            response.varbinds[0].oid,
            oid!(1, 3, 6, 1, 4, 1, 99999, 2, 0)
        );
    }
}
