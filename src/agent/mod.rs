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
    NotificationOutcome, NotificationSendStream, NotificationSinkId, NotificationSinkIdError,
    NotificationSinkSummary, SinkOutcome, SinkSkipReason, SinkStatus,
};
pub use vacm::{
    DuplicateVacmAccessEntry, VacmAccessIndex, VacmBuilder, VacmConfig, VacmSecurityModel, View,
    ViewSubtree,
};

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_util::stream::{FuturesUnordered, StreamExt};
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tokio::task::{AbortHandle, JoinError, JoinSet};
use tokio_util::sync::CancellationToken;
use tracing::instrument;

use crate::error::{ConstructionStage, Error, ErrorStatus, Result};
use crate::handler::{
    GetNextResult, GetResult, HandlerResult, MibHandler, RequestContext, RequestLifecycle,
    RequestTaskPhase,
};
use crate::message_size::{MessageSize, UDP_RECEIVE_BUFFER_SIZE, UDP_RECEIVE_LIMITS};
use crate::oid;
use crate::oid::Oid;
#[cfg(test)]
use crate::pdu::NotificationPdu;
use crate::pdu::{Pdu, PduBody, PduType, ResponsePdu};
use crate::transport::normalize_udp_target;
use crate::transport::udp_error::{
    UdpRecvErrorBackoff, UdpRecvErrorClass, classify_udp_recv_error,
};
use crate::udp_responder::{ReceivedDatagram, UdpResponder};
use crate::util::{
    EmptyCommunityPolicy, PreparedAuthoritativeUsm, ValidatedAuthoritativeUsm, bind_udp_socket,
    community_matches, validate_authoritative_usm_deferred,
};
use crate::v3::process::UsmStats;
use crate::v3::{AuthoritativeEngine, DesSaltState, PrivProtocol, UsmUser};
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

/// Maximum number of independent handler GETNEXT probes in flight at once.
const MAX_CONCURRENT_GETNEXT_PROBES: usize = 16;

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "visionos",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "netbsd",
    target_os = "openbsd",
    windows,
)))]
fn transient_recv_errno(_code: i32) -> bool {
    false
}

/// Clears the shared active-run flag after orderly exit, or after the last
/// retained request exits when [`Agent::run`] is dropped.
struct RunGuard<'a> {
    inner: &'a AgentInner,
    completed: bool,
}

impl RunGuard<'_> {
    fn complete(&mut self) {
        self.completed = true;
        self.inner.run_active.store(false, Ordering::Release);
    }
}

impl Drop for RunGuard<'_> {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        self.inner.run_orphaned.store(true, Ordering::Release);
        if self.inner.active_request_tasks.load(Ordering::Acquire) == 0 {
            self.inner.run_active.store(false, Ordering::Release);
        }
    }
}

struct ActiveRequestGuard {
    inner: Arc<AgentInner>,
    task_id: u64,
}

impl Drop for ActiveRequestGuard {
    fn drop(&mut self) {
        self.inner
            .live_request_tasks
            .lock()
            .unwrap()
            .remove(&self.task_id);
        if self
            .inner
            .active_request_tasks
            .fetch_sub(1, Ordering::AcqRel)
            == 1
            && self.inner.run_orphaned.load(Ordering::Acquire)
        {
            self.inner.run_active.store(false, Ordering::Release);
        }
    }
}

struct RequestTaskControl {
    phase: Arc<AtomicU8>,
    abort: AbortHandle,
}

/// Request tasks owned by one [`Agent::run`] invocation.
///
/// Each task also has an entry in the Agent-owned registry. If `run` is
/// dropped, detaching the local join handles does not lose ownership or
/// observability; the shared entry remains until the task guard exits.
struct RequestTasks {
    tasks: JoinSet<()>,
    cancel: CancellationToken,
    inner: Arc<AgentInner>,
}

impl RequestTasks {
    fn new(cancel: CancellationToken, inner: Arc<AgentInner>) -> Self {
        Self {
            tasks: JoinSet::new(),
            cancel,
            inner,
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

    fn spawn(&mut self, phase: Arc<AtomicU8>, task: impl Future<Output = ()> + Send + 'static) {
        let task_id = self
            .inner
            .next_request_task_id
            .fetch_add(1, Ordering::Relaxed);
        let activity = ActiveRequestGuard {
            inner: Arc::clone(&self.inner),
            task_id,
        };
        let (start_tx, start_rx) = tokio::sync::oneshot::channel();
        self.inner
            .active_request_tasks
            .fetch_add(1, Ordering::AcqRel);
        let abort = self.tasks.spawn(async move {
            let _activity = activity;
            let _ = start_rx.await;
            task.await;
        });
        self.inner
            .live_request_tasks
            .lock()
            .unwrap()
            .insert(task_id, RequestTaskControl { phase, abort });
        let _ = start_tx.send(());
    }

    async fn join_next(&mut self) -> Option<std::result::Result<(), JoinError>> {
        self.tasks.join_next().await
    }

    fn abort_retrievals(&mut self) {
        let tasks = self.inner.live_request_tasks.lock().unwrap();
        for control in tasks.values() {
            if control.phase.load(Ordering::Acquire) == RequestTaskPhase::Retrieval as u8 {
                control.abort.abort();
            }
        }
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

/// Shutdown handling for already-dispatched agent requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum AgentShutdownPolicy {
    /// Signal every request and drain handlers and response attempts without a bound.
    #[default]
    Drain,
    /// After `grace`, abort only positively classified retrieval tasks.
    ///
    /// Selecting this variant is an affirmative contract that every registered
    /// handler's GET, GETNEXT, and GETBULK futures are cancellation-safe when
    /// dropped. SET, Inform, and unclassified tasks are always drained.
    AbortCancellationSafeRetrievalsAfter(Duration),
}

/// Current health of the Agent's local authoritative V3 state.
///
/// Health changes use a bounded, coalescing watch channel. Repeated packets
/// during one persistence outage increment `consecutive_failures` in the
/// current value instead of enqueueing an unbounded sequence. A later
/// successful authoritative-state publication restores `Healthy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AgentHealth {
    /// No unresolved authoritative-engine persistence failure is known.
    Healthy,
    /// Local-authoritative V3 processing is degraded until persistence
    /// succeeds on a later attempt.
    AuthoritativePersistenceDegraded {
        /// Failed publication attempts observed in this outage.
        consecutive_failures: u64,
        /// Durable transition that most recently failed.
        operation: crate::v3::AuthoritativeEnginePersistenceOperation,
        /// Last durable boots value before the attempted transition.
        previous_engine_boots: Option<u32>,
        /// Boots value passed to the persistence callback.
        attempted_engine_boots: u32,
    },
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
    InvalidVacm(DuplicateVacmAccessEntry),
    AllowAll,
    Conflict,
}

impl AgentAuthorization {
    pub(crate) fn vacm(&self) -> Option<&VacmConfig> {
        match self {
            Self::Vacm(vacm) => Some(vacm),
            Self::Unset | Self::InvalidVacm(_) | Self::AllowAll | Self::Conflict => None,
        }
    }
}

/// Builder for [`Agent`].
///
/// Configure an SNMP agent, then call [`build()`](AgentBuilder::build) to
/// create it.
///
/// # Access control
///
/// An agent with an accepted community or USM user must explicitly select
/// [`vacm()`](AgentBuilder::vacm) or
/// [`allow_all_access()`](AgentBuilder::allow_all_access). USM authentication
/// and privacy protocols are capabilities and do not establish an inbound
/// minimum security level.
///
/// # Minimal example
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
    des_salt_state: Option<DesSaltState>,
    max_message_size: usize,
    decode_config: crate::DecodeConfig,
    max_concurrent_requests: Option<usize>,
    recv_buffer_size: Option<usize>,
    authorization: AgentAuthorization,
    cancel: Option<CancellationToken>,
    trap_sinks: Vec<(NotificationSinkId, String, crate::client::Auth)>,
    trap_send_timeout: Duration,
    inform_timeout: Duration,
    inform_retry: crate::client::Retry,
    response_send_timeout: Duration,
    request_deadline: Option<Duration>,
    shutdown_policy: AgentShutdownPolicy,
    construction_timeout: Duration,
    notification_fanout_limit: usize,
    disabled_builtins: HashSet<BuiltinMib>,
}

enum TrapSinkTarget {
    Address(SocketAddr),
    HostPort {
        original: String,
        host: String,
        port: u16,
    },
}

struct ValidatedTrapSink {
    id: NotificationSinkId,
    target: TrapSinkTarget,
    auth: crate::client::Auth,
}

struct ValidatedAgentBuilder {
    bind_addr: SocketAddr,
    communities: Vec<crate::Community>,
    usm: ValidatedAuthoritativeUsm,
    handlers: Vec<RegisteredHandler>,
    max_message_size: usize,
    local_receive_capacity: MessageSize,
    decode_config: crate::DecodeConfig,
    concurrency_limit: Option<Arc<Semaphore>>,
    recv_buffer_size: Option<usize>,
    authorization: AgentAuthorization,
    cancel: CancellationToken,
    trap_sinks: Vec<ValidatedTrapSink>,
    trap_send_timeout: Duration,
    inform_timeout: Duration,
    inform_retry: crate::client::Retry,
    response_send_timeout: Duration,
    request_deadline: Option<Duration>,
    shutdown_policy: AgentShutdownPolicy,
    construction_timeout: Duration,
    notification_fanout_limit: usize,
    disabled_builtins: HashSet<BuiltinMib>,
    requires_privacy: bool,
    des_salt_state: Option<DesSaltState>,
}

impl AgentBuilder {
    /// Create a builder with the default settings.
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
            des_salt_state: None,
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            decode_config: crate::DecodeConfig::default(),
            max_concurrent_requests: Some(1000),
            recv_buffer_size: Some(4 * 1024 * 1024), // 4MB
            authorization: AgentAuthorization::Unset,
            cancel: None,
            trap_sinks: Vec::new(),
            trap_send_timeout: crate::client::DEFAULT_SEND_TIMEOUT,
            inform_timeout: Duration::from_secs(5),
            inform_retry: crate::client::Retry::default(),
            response_send_timeout: crate::client::DEFAULT_SEND_TIMEOUT,
            request_deadline: None,
            shutdown_policy: AgentShutdownPolicy::Drain,
            construction_timeout: crate::client::DEFAULT_CONSTRUCTION_TIMEOUT,
            notification_fanout_limit: 32,
            disabled_builtins: HashSet::new(),
        }
    }

    /// Set the UDP bind address.
    ///
    /// The default is `0.0.0.0:161`, the standard SNMP agent port. Binding to
    /// UDP port 161 typically requires root or administrator privileges.
    ///
    /// # IPv4 examples
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
    /// # IPv6 and dual-stack examples
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
    /// # Security levels
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
    ///     }).unwrap()
    ///     // User capable of authentication and privacy
    ///     .usm_user("admin", |u| {
    ///         u.auth_priv(
    ///             AuthProtocol::Sha256,
    ///             b"adminauth123",
    ///             PrivProtocol::Aes128,
    ///             b"adminpriv123",
    ///         )
    ///     }).unwrap()
    ///     .allow_all_access()
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn usm_user<F>(
        mut self,
        username: impl Into<Bytes>,
        configure: F,
    ) -> crate::CryptoResult<Self>
    where
        F: FnOnce(UsmUser) -> crate::CryptoResult<UsmUser>,
    {
        let username_bytes: Bytes = username.into();
        let config = configure(UsmUser::new(username_bytes.clone()))?;
        self.usm_users.insert(username_bytes, config);
        Ok(self)
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

    /// Set durable generating-engine state for every DES/3DES response and
    /// notification sent by this agent.
    #[must_use]
    pub fn des_salt_state(mut self, state: DesSaltState) -> Self {
        self.des_salt_state = Some(state);
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
    /// The default is 1472 octets, which fits an Ethernet MTU after IP and UDP
    /// headers. The agent truncates GETBULK responses to fit this limit.
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

    /// Set bounded request-decoding compatibility.
    ///
    /// The same snapshot applies to community requests and every staged V3
    /// decode. The default is [`crate::DecodeConfig::DEFAULT`].
    #[must_use]
    pub fn decode_config(mut self, config: crate::DecodeConfig) -> Self {
        self.decode_config = config;
        self
    }

    /// Set the maximum number of requests that the agent processes concurrently.
    ///
    /// The default is 1000. Requests beyond this limit wait until a slot
    /// becomes available. Use `None` for unbounded concurrency.
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
    /// The default is 4 MiB. The kernel may cap this at `net.core.rmem_max`.
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
            AgentAuthorization::Unset
            | AgentAuthorization::Vacm(_)
            | AgentAuthorization::InvalidVacm(_) => match configure(builder).build() {
                Ok(config) => AgentAuthorization::Vacm(config),
                Err(error) => AgentAuthorization::InvalidVacm(error),
            },
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
            AgentAuthorization::Vacm(_)
            | AgentAuthorization::InvalidVacm(_)
            | AgentAuthorization::Conflict => AgentAuthorization::Conflict,
        };
        self
    }

    /// Set a cancellation token for graceful shutdown.
    ///
    /// If not set, the agent creates its own token accessible via
    /// [`Agent::cancellation_token`].
    #[must_use]
    pub fn cancellation_token(mut self, token: CancellationToken) -> Self {
        self.cancel = Some(token);
        self
    }

    /// Add a trap/inform destination.
    ///
    /// [`Agent::send_trap()`] and [`Agent::send_inform()`] send notifications
    /// to all configured sinks.
    /// For V3 traps, the Agent is authoritative and uses its persisted
    /// [`AuthoritativeEngine`]. For V3 Informs, the receiving sink is
    /// authoritative and the Agent discovers the sink's engine. Configuring
    /// any V3 sink still requires local authoritative state because it may be
    /// used by [`Agent::send_trap()`].
    ///
    /// `id` must be unique within the agent. Its 1-to-32-octet length was
    /// validated when the [`NotificationSinkId`] was constructed.
    /// It is included in delivery outcomes and should remain stable across
    /// restarts when the application retains sink status. `dest` must include
    /// a port and may be an IPv4 address, bracketed IPv6 address, or hostname.
    /// IPv4 binds accept IPv4 and mapped-IPv6 destinations, normalizing the
    /// latter to IPv4, and reject native IPv6 destinations. IPv6 binds retain
    /// IPv6 destinations and map IPv4 destinations into the dual-stack address
    /// space. Hostname candidates are considered in resolver order under the
    /// same rules.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use async_snmp::agent::Agent;
    /// use async_snmp::{
    ///     Auth, AuthProtocol, AuthoritativeEngine, NotificationSinkId, PrivProtocol,
    /// };
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
    ///     .trap_sink(NotificationSinkId::new("primary").unwrap(), "192.168.1.100:162", Auth::v2c("public"))
    ///     .trap_sink(NotificationSinkId::new("secure").unwrap(), "10.0.0.1:162", async_snmp::UsmConfig::new("trapuser")
    ///         .auth_priv(
    ///             AuthProtocol::Sha256,
    ///             "authpass",
    ///             PrivProtocol::Aes128,
    ///             "privpass",
    ///         )
    ///         .unwrap())
    ///     .allow_all_access()
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn trap_sink(
        mut self,
        id: NotificationSinkId,
        dest: impl Into<String>,
        auth: impl Into<crate::client::Auth>,
    ) -> Self {
        self.trap_sinks.push((id, dest.into(), auth.into()));
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

    /// Set one total deadline for agent construction (default: 5 seconds).
    ///
    /// Pure configuration validation runs first. The deadline then spans UDP
    /// binding, every hostname sink lookup in configuration order, and local
    /// protocol-state setup. [`Duration::ZERO`] is an immediate deadline.
    #[must_use]
    pub fn construction_timeout(mut self, timeout: Duration) -> Self {
        self.construction_timeout = timeout;
        self
    }

    /// Set the maximum number of concurrent trap or Inform sink operations.
    ///
    /// A notification stream admits at most this many sink futures and admits
    /// the next configured sink after a prior outcome completes. Outcomes are
    /// still yielded in completion order.
    #[must_use]
    pub fn notification_fanout_limit(mut self, limit: usize) -> Self {
        self.notification_fanout_limit = limit;
        self
    }

    /// Set the deadline for each agent response send.
    ///
    /// The default is five seconds. Expiry releases the request concurrency
    /// permit so stalled socket writes cannot prevent graceful shutdown.
    #[must_use]
    pub fn response_send_timeout(mut self, timeout: Duration) -> Self {
        self.response_send_timeout = timeout;
        self
    }

    /// Set an optional cooperative deadline for each inbound request.
    ///
    /// The deadline is measured from receipt, before concurrency-permit
    /// queueing, and is exposed through [`RequestContext::deadline`]. Expiry
    /// signals the request cancellation token but does not drop the handler.
    #[must_use]
    pub fn request_deadline(mut self, deadline: Option<Duration>) -> Self {
        self.request_deadline = deadline;
        self
    }

    /// Configure shutdown handling for already-dispatched requests.
    ///
    /// The default is [`AgentShutdownPolicy::Drain`]. Selecting
    /// [`AgentShutdownPolicy::AbortCancellationSafeRetrievalsAfter`] affirms
    /// that every registered retrieval handler is cancellation-safe when its
    /// future is dropped.
    #[must_use]
    pub fn shutdown_policy(mut self, policy: AgentShutdownPolicy) -> Self {
        self.shutdown_policy = policy;
        self
    }

    /// Disable a specific built-in MIB handler group.
    ///
    /// By default, the agent registers handlers for snmpEngine, USM stats,
    /// and MPD stats. Disable a group when the application provides its own
    /// handler for those OIDs.
    #[must_use]
    pub fn without_builtin_handler(mut self, mib: BuiltinMib) -> Self {
        self.disabled_builtins.insert(mib);
        self
    }

    /// Disable all built-in MIB handlers.
    ///
    /// The agent does not register internal handlers for snmpEngine, USM
    /// stats, or MPD stats. Counter accessors such as
    /// [`Agent::usm_unknown_engine_ids()`] remain available.
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
    /// notification sink IDs are duplicated; trap sink destinations are
    /// invalid or cannot be resolved;
    /// USM credentials are invalid; USM users or V3 trap sinks are configured
    /// without a persisted [`AuthoritativeEngine`]; a timeout cannot be
    /// represented; or the response-size limit exceeds the fixed UDP receive
    /// capacity. Returns [`Error::RandomSource`] when a generated engine ID or
    /// required privacy salt cannot be initialized.
    ///
    /// Pure deterministic validation and normalization precedes socket I/O,
    /// DNS, entropy, and authoritative engine clock or persistence access.
    /// Checking whether configured durations can form deadlines observes the
    /// process monotonic clock during that validation phase.
    pub async fn build(self) -> Result<Agent> {
        self.build_with_dependencies(
            |addr, recv_buffer_size| bind_udp_socket(addr, recv_buffer_size, None, false),
            |host, port| async move {
                tokio::net::lookup_host((host.as_str(), port))
                    .await
                    .map(|addresses| addresses.collect())
                    .map_err(|error| {
                        Error::Config(
                            format!("could not resolve trap sink address '{host}': {error}").into(),
                        )
                        .boxed()
                    })
            },
            crate::v3::generate_engine_id,
            SaltCounter::new,
        )
        .await
    }

    async fn build_with_dependencies<B, BFut, R, RFut, G, S>(
        self,
        bind_socket: B,
        mut resolve_host: R,
        generate_engine_id: G,
        create_salt_counter: S,
    ) -> Result<Agent>
    where
        B: FnOnce(SocketAddr, Option<usize>) -> BFut,
        BFut: Future<Output = std::io::Result<UdpSocket>>,
        R: FnMut(String, u16) -> RFut,
        RFut: Future<Output = Result<Vec<SocketAddr>>>,
        G: FnOnce() -> Result<Bytes>,
        S: FnOnce() -> Result<SaltCounter>,
    {
        // Pure deterministic validation and normalization completes before
        // socket I/O, DNS, entropy, or authoritative clock/persistence access.
        // Deadline representability checks also observe the monotonic clock but
        // have no external effect. Environmental errors then have stable
        // precedence: bind, trap-sink resolution, authoritative engine
        // preparation, privacy salt.
        let mut config = self.validate_and_normalize()?;

        let construction =
            AgentConstructionDeadline::new(config.bind_addr, config.construction_timeout)?;

        let socket = construction
            .run(ConstructionStage::Bind, None, None, async {
                bind_socket(config.bind_addr, config.recv_buffer_size)
                    .await
                    .map_err(|source| {
                        Error::Network {
                            target: config.bind_addr,
                            source,
                        }
                        .boxed()
                    })
            })
            .await?;
        let local_addr = socket.local_addr().map_err(|source| Error::Network {
            target: config.bind_addr,
            source,
        })?;

        let mut trap_sinks = Vec::with_capacity(config.trap_sinks.len());
        for (index, sink) in config.trap_sinks.into_iter().enumerate() {
            let dest = match sink.target {
                TrapSinkTarget::Address(address) => address,
                TrapSinkTarget::HostPort {
                    original,
                    host,
                    port,
                } => {
                    let addresses = construction
                        .run(
                            ConstructionStage::Resolve,
                            Some(index),
                            Some(original.clone()),
                            resolve_host(host, port),
                        )
                        .await?;
                    addresses
                        .into_iter()
                        .find_map(|address| {
                            normalize_udp_target(config.bind_addr, address).ok()
                        })
                        .ok_or_else(|| {
                        Error::Config(
                            format!(
                                "no address resolved for trap sink '{original}' is compatible with Agent bind {}",
                                config.bind_addr
                            )
                            .into(),
                        )
                        .boxed()
                    })?
                }
            };
            trap_sinks.push(notification::TrapSink::new(
                index,
                sink.id,
                dest,
                sink.auth,
                config.trap_send_timeout,
                config.inform_timeout,
                config.inform_retry.clone(),
            ));
        }

        let PreparedAuthoritativeUsm {
            users: usm_users,
            authoritative_engine,
            engine_id,
            engine_boots,
        } = {
            construction.check(ConstructionStage::Prepare, None, None)?;
            config.usm.prepare(generate_engine_id)?
        };
        let salt_counter = config
            .requires_privacy
            .then(create_salt_counter)
            .transpose()?;
        construction.check(ConstructionStage::Prepare, None, None)?;
        let udp_responder = UdpResponder::new(&socket);

        let state = Arc::new(AgentState {
            authoritative_engine,
            engine_id,
            engine_start: Instant::now(),
            engine_boots_base: engine_boots,
            #[cfg(test)]
            authoritative_elapsed_override: std::sync::atomic::AtomicU64::new(u64::MAX),
            max_message_size: config.max_message_size,
            local_receive_capacity: config.local_receive_capacity,
            decode_config: config.decode_config,
            snmp_in_asn_parse_errs: AtomicU32::new(0),
            snmp_invalid_msgs: AtomicU32::new(0),
            snmp_unknown_security_models: AtomicU32::new(0),
            snmp_silent_drops: AtomicU32::new(0),
            snmp_unknown_contexts: AtomicU32::new(0),
            usm_stats: UsmStats::default(),
            health: tokio::sync::watch::channel(AgentHealth::Healthy).0,
        });

        // Register built-in handlers for any not disabled
        if !config.disabled_builtins.contains(&BuiltinMib::SnmpEngine) {
            config.handlers.push(RegisteredHandler {
                prefix: oid!(1, 3, 6, 1, 6, 3, 10, 2, 1),
                handler: Arc::new(builtins::SnmpEngineHandler {
                    state: Arc::clone(&state),
                }),
            });
        }
        if !config.disabled_builtins.contains(&BuiltinMib::UsmStats) {
            config.handlers.push(RegisteredHandler {
                prefix: oid!(1, 3, 6, 1, 6, 3, 15, 1, 1),
                handler: Arc::new(builtins::UsmStatsHandler {
                    state: Arc::clone(&state),
                }),
            });
        }
        if !config.disabled_builtins.contains(&BuiltinMib::MpdStats) {
            config.handlers.push(RegisteredHandler {
                prefix: oid!(1, 3, 6, 1, 6, 3, 11, 2, 1),
                handler: Arc::new(builtins::MpdStatsHandler {
                    state: Arc::clone(&state),
                }),
            });
        }

        // Sort handlers by prefix length (longest first) for matching
        config
            .handlers
            .sort_by_key(|h| std::cmp::Reverse(h.prefix.len()));

        let agent = Agent {
            inner: Arc::new(AgentInner {
                socket: Arc::new(socket),
                udp_responder,
                local_addr,
                communities: config.communities,
                usm_users,
                handlers: config.handlers,
                state,
                salt_counter,
                des_salt_state: config.des_salt_state,
                set_coordinator: tokio::sync::Mutex::new(()),
                concurrency_limit: config.concurrency_limit,
                authorization: config.authorization,
                cancel: config.cancel,
                trap_sinks,
                inform_transports: notification::InformTransportPool::new(),
                notification_id: std::sync::atomic::AtomicI32::new(1),
                run_active: AtomicBool::new(false),
                run_orphaned: AtomicBool::new(false),
                active_request_tasks: AtomicUsize::new(0),
                next_request_task_id: AtomicU64::new(1),
                live_request_tasks: std::sync::Mutex::new(HashMap::new()),
                response_send_timeout: config.response_send_timeout,
                request_deadline: config.request_deadline,
                shutdown_policy: config.shutdown_policy,
                notification_fanout_limit: config.notification_fanout_limit,
                #[cfg(test)]
                response_send_gate: std::sync::Mutex::new(None),
                #[cfg(test)]
                response_sends_started: AtomicU32::new(0),
                #[cfg(test)]
                received_datagrams: AtomicU32::new(0),
                #[cfg(test)]
                pre_permit_gate: std::sync::Mutex::new(None),
                #[cfg(test)]
                receive_errors: std::sync::Mutex::new(std::collections::VecDeque::new()),
                #[cfg(test)]
                receive_attempts: AtomicU32::new(0),
            }),
        };
        construction.check(ConstructionStage::Prepare, None, None)?;
        Ok(agent)
    }

    fn validate_and_normalize(mut self) -> Result<ValidatedAgentBuilder> {
        // Stable validation precedence: deadline representability (which reads
        // the monotonic clock), authorization, sink IDs, sizes/concurrency,
        // security configuration, then address syntax and family.
        crate::transport::checked_deadline(self.trap_send_timeout, "trap send timeout")?;
        crate::transport::checked_deadline(self.inform_timeout, "inform timeout")?;
        crate::transport::checked_deadline(self.response_send_timeout, "response send timeout")?;
        if let Some(deadline) = self.request_deadline {
            crate::transport::checked_deadline(deadline, "agent request deadline")?;
        }
        crate::transport::checked_deadline(
            self.construction_timeout,
            "agent construction timeout",
        )?;
        if let AgentShutdownPolicy::AbortCancellationSafeRetrievalsAfter(grace) =
            self.shutdown_policy
        {
            crate::transport::checked_deadline(grace, "agent shutdown grace")?;
        }

        if matches!(self.authorization, AgentAuthorization::Conflict) {
            return Err(Error::Config(
                "VACM and unrestricted Agent access are mutually exclusive".into(),
            )
            .boxed());
        }
        if let AgentAuthorization::InvalidVacm(error) = &self.authorization {
            return Err(Error::Config(error.to_string().into()).boxed());
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
            if !sink_ids.insert(id.clone()) {
                return Err(
                    Error::Config(format!("duplicate notification sink ID: {id}").into()).boxed(),
                );
            }
        }

        let local_receive_capacity = UDP_RECEIVE_LIMITS.advertised();
        if self.max_message_size > local_receive_capacity.as_usize() {
            return Err(Error::Config(
                format!("max_message_size must not exceed UDP capacity {local_receive_capacity}")
                    .into(),
            )
            .boxed());
        }
        if self.max_concurrent_requests == Some(0) {
            return Err(
                Error::Config("max_concurrent_requests must be greater than 0".into()).boxed(),
            );
        }
        if self.notification_fanout_limit == 0 {
            return Err(
                Error::Config("notification_fanout_limit must be greater than 0".into()).boxed(),
            );
        }

        let uses_des = self.usm_users.values().any(|security| {
            security
                .priv_protocol()
                .is_some_and(PrivProtocol::is_des_family)
        }) || self.trap_sinks.iter().any(|(_, _, auth)| {
            matches!(auth, crate::client::Auth::Usm(security)
                if security.priv_protocol().is_some_and(PrivProtocol::is_des_family))
        });
        let uses_aes = self.usm_users.values().any(|security| {
            security
                .priv_protocol()
                .is_some_and(|protocol| !protocol.is_des_family())
        }) || self.trap_sinks.iter().any(|(_, _, auth)| {
            matches!(auth, crate::client::Auth::Usm(security)
                if security.priv_protocol().is_some_and(|protocol| !protocol.is_des_family()))
        });
        if uses_des && self.des_salt_state.is_none() {
            return Err(Error::Config(
                "durable DES sender state is required for DES/3DES agent roles".into(),
            )
            .boxed());
        }
        if uses_des
            && let (Some(engine), Some(state)) = (&self.authoritative_engine, &self.des_salt_state)
            && engine.engine_boots() != state.engine_boots()
        {
            return Err(Error::Config(
                "DES sender boots must match the agent authoritative engine boots".into(),
            )
            .boxed());
        }
        let requires_authoritative_engine = !self.usm_users.is_empty()
            || self
                .trap_sinks
                .iter()
                .any(|(_, _, auth)| matches!(auth, crate::client::Auth::Usm(_)));

        for (_, _, auth) in &mut self.trap_sinks {
            if let crate::client::Auth::Usm(config) = auth {
                config.validate_and_precompute().map_err(|error| {
                    Error::Config(format!("invalid trap sink USM configuration: {error}").into())
                        .boxed()
                })?;
            }
        }
        let usm = validate_authoritative_usm_deferred(
            self.usm_users,
            self.authoritative_engine,
            requires_authoritative_engine,
            "invalid USM user configuration",
            "authoritative engine state is required for SNMPv3 agent roles",
        )?;

        let bind_addr = self.bind_addr.parse().map_err(|_| {
            Error::Config(format!("invalid bind address: {}", self.bind_addr).into()).boxed()
        })?;
        let trap_sinks = self
            .trap_sinks
            .into_iter()
            .map(|(id, destination, auth)| {
                let target = match parse_trap_sink_target(destination)? {
                    TrapSinkTarget::Address(address) => {
                        TrapSinkTarget::Address(normalize_udp_target(bind_addr, address)?)
                    }
                    target @ TrapSinkTarget::HostPort { .. } => target,
                };
                Ok(ValidatedTrapSink { id, target, auth })
            })
            .collect::<Result<Vec<_>>>()?;

        let concurrency_limit = self
            .max_concurrent_requests
            .map(|limit| Arc::new(Semaphore::new(limit)));

        Ok(ValidatedAgentBuilder {
            bind_addr,
            communities: self.communities,
            usm,
            handlers: self.handlers,
            max_message_size: self.max_message_size,
            local_receive_capacity,
            decode_config: self.decode_config,
            concurrency_limit,
            recv_buffer_size: self.recv_buffer_size,
            authorization: self.authorization,
            cancel: self.cancel.unwrap_or_default(),
            trap_sinks,
            trap_send_timeout: self.trap_send_timeout,
            inform_timeout: self.inform_timeout,
            inform_retry: self.inform_retry,
            response_send_timeout: self.response_send_timeout,
            request_deadline: self.request_deadline,
            shutdown_policy: self.shutdown_policy,
            construction_timeout: self.construction_timeout,
            notification_fanout_limit: self.notification_fanout_limit,
            disabled_builtins: self.disabled_builtins,
            requires_privacy: uses_aes,
            des_salt_state: self.des_salt_state,
        })
    }
}

struct AgentConstructionDeadline {
    bind_addr: SocketAddr,
    started: tokio::time::Instant,
    deadline: tokio::time::Instant,
}

impl AgentConstructionDeadline {
    fn new(bind_addr: SocketAddr, timeout: Duration) -> Result<Self> {
        let started = tokio::time::Instant::now();
        let deadline = started.checked_add(timeout).ok_or_else(|| {
            Error::Config("agent construction timeout exceeds the representable deadline".into())
                .boxed()
        })?;
        Ok(Self {
            bind_addr,
            started,
            deadline,
        })
    }

    async fn run<T, F>(
        &self,
        stage: ConstructionStage,
        sink_index: Option<usize>,
        sink_destination: Option<String>,
        future: F,
    ) -> Result<T>
    where
        F: Future<Output = Result<T>>,
    {
        self.check(stage, sink_index, sink_destination.clone())?;
        tokio::time::timeout_at(self.deadline, future)
            .await
            .map_err(|_| self.timeout_error(stage, sink_index, sink_destination))?
    }

    fn check(
        &self,
        stage: ConstructionStage,
        sink_index: Option<usize>,
        sink_destination: Option<String>,
    ) -> Result<()> {
        if tokio::time::Instant::now() >= self.deadline {
            return Err(self.timeout_error(stage, sink_index, sink_destination));
        }
        Ok(())
    }

    fn timeout_error(
        &self,
        stage: ConstructionStage,
        sink_index: Option<usize>,
        sink_destination: Option<String>,
    ) -> Box<Error> {
        Error::AgentConstructionTimeout {
            bind_addr: self.bind_addr,
            stage,
            sink_index,
            sink_destination,
            elapsed: self.started.elapsed(),
        }
        .boxed()
    }
}

fn parse_trap_sink_target(destination: String) -> Result<TrapSinkTarget> {
    if let Ok(address) = destination.parse() {
        return Ok(TrapSinkTarget::Address(address));
    }

    let (host, port) = if let Some(bracketed) = destination.strip_prefix('[') {
        let (host, remainder) = bracketed.split_once(']').ok_or_else(|| {
            Error::Config(format!("invalid trap sink address: {destination}").into()).boxed()
        })?;
        let port = remainder.strip_prefix(':').ok_or_else(|| {
            Error::Config(format!("invalid trap sink address: {destination}").into()).boxed()
        })?;
        (host, port)
    } else {
        let (host, port) = destination.rsplit_once(':').ok_or_else(|| {
            Error::Config(format!("invalid trap sink address: {destination}").into()).boxed()
        })?;
        if host.contains(':') {
            return Err(
                Error::Config(format!("invalid trap sink address: {destination}").into()).boxed(),
            );
        }
        (host, port)
    };

    if host.is_empty() || host.chars().any(char::is_whitespace) {
        return Err(
            Error::Config(format!("invalid trap sink address: {destination}").into()).boxed(),
        );
    }
    let port = port.parse::<u16>().map_err(|_| {
        Error::Config(format!("invalid trap sink address: {destination}").into()).boxed()
    })?;
    let host = host.to_owned();

    Ok(TrapSinkTarget::HostPort {
        original: destination,
        host,
        port,
    })
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
    pub(crate) engine_start: Instant,
    /// Initial `engine_boots` value at startup, used to compute overflow-adjusted boots.
    pub(crate) engine_boots_base: u32,
    #[cfg(test)]
    authoritative_elapsed_override: std::sync::atomic::AtomicU64,
    /// Configured upper bound for outbound response messages.
    pub(crate) max_message_size: usize,
    /// Wire-valid `msgMaxSize` advertising this agent's UDP receive capacity.
    pub(crate) local_receive_capacity: MessageSize,
    /// Inbound decode configuration snapshot.
    pub(crate) decode_config: crate::DecodeConfig,
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
    /// Bounded/coalescing current-health publication.
    health: tokio::sync::watch::Sender<AgentHealth>,
}

impl AgentState {
    /// Return one coherent authoritative boots/time pair for the current instant.
    pub(crate) fn authoritative_boots_time(&self) -> Result<(u32, u32)> {
        #[cfg(test)]
        let override_elapsed = self.authoritative_elapsed_override.load(Ordering::Relaxed);
        #[cfg(test)]
        let result = if override_elapsed != u64::MAX {
            Ok(compute_engine_boots_time(
                self.engine_boots_base,
                override_elapsed,
            ))
        } else {
            self.sample_authoritative_boots_time()
        };
        #[cfg(not(test))]
        let result = self.sample_authoritative_boots_time();

        self.observe_authoritative_result(&result);
        result
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

    fn observe_authoritative_result(&self, result: &Result<(u32, u32)>) {
        match result {
            Ok(_) => {
                self.health.send_if_modified(|health| {
                    if matches!(health, AgentHealth::Healthy) {
                        false
                    } else {
                        *health = AgentHealth::Healthy;
                        true
                    }
                });
            }
            Err(error) => {
                let Some(persistence) = error.authoritative_engine_persistence() else {
                    return;
                };
                self.health.send_modify(|health| {
                    let consecutive_failures = match *health {
                        AgentHealth::AuthoritativePersistenceDegraded {
                            consecutive_failures,
                            ..
                        } => consecutive_failures.saturating_add(1),
                        AgentHealth::Healthy => 1,
                    };
                    *health = AgentHealth::AuthoritativePersistenceDegraded {
                        consecutive_failures,
                        operation: persistence.operation(),
                        previous_engine_boots: persistence.previous_engine_boots(),
                        attempted_engine_boots: persistence.attempted_engine_boots(),
                    };
                });
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
    pub(crate) des_salt_state: Option<DesSaltState>,
    /// Serializes complete SET transactions without restricting retrieval.
    pub(crate) set_coordinator: tokio::sync::Mutex<()>,
    pub(crate) concurrency_limit: Option<Arc<Semaphore>>,
    pub(crate) authorization: AgentAuthorization,
    /// Cancellation token for graceful shutdown.
    pub(crate) cancel: CancellationToken,
    /// Configured trap/inform destinations.
    pub(crate) trap_sinks: Vec<notification::TrapSink>,
    /// Inform endpoints shared by all sinks of each destination family.
    pub(crate) inform_transports: notification::InformTransportPool,
    /// Per-agent monotonic counter for trap request-ids and v3 notification msgIDs.
    pub(crate) notification_id: std::sync::atomic::AtomicI32,
    /// Maximum sink futures admitted by one notification stream.
    pub(crate) notification_fanout_limit: usize,
    /// Shared across clones to enforce one active service loop.
    pub(crate) run_active: AtomicBool,
    /// True while a dropped run future still owns live request tasks.
    run_orphaned: AtomicBool,
    /// Dispatched request tasks, including work retained after `run` is dropped.
    active_request_tasks: AtomicUsize,
    next_request_task_id: AtomicU64,
    live_request_tasks: std::sync::Mutex<HashMap<u64, RequestTaskControl>>,
    pub(crate) response_send_timeout: Duration,
    request_deadline: Option<Duration>,
    shutdown_policy: AgentShutdownPolicy,
    #[cfg(test)]
    pub(crate) response_send_gate: std::sync::Mutex<Option<Arc<Semaphore>>>,
    #[cfg(test)]
    pub(crate) response_sends_started: AtomicU32,
    #[cfg(test)]
    received_datagrams: AtomicU32,
    #[cfg(test)]
    pre_permit_gate: std::sync::Mutex<Option<Arc<Semaphore>>>,
    #[cfg(test)]
    receive_errors: std::sync::Mutex<std::collections::VecDeque<std::io::Error>>,
    #[cfg(test)]
    receive_attempts: AtomicU32,
}

/// An SNMP agent.
///
/// Listens for and responds to GET, GETNEXT, GETBULK, and SET requests.
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

    /// Returns the local address that the agent is bound to.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr
    }

    /// Return the configured request decode configuration.
    #[must_use]
    pub fn decode_config(&self) -> crate::DecodeConfig {
        self.inner.state.decode_config
    }

    /// Iterate over credential-free notification sink summaries in configuration order.
    pub fn notification_sinks(
        &self,
    ) -> impl ExactSizeIterator<Item = &NotificationSinkSummary> + DoubleEndedIterator {
        self.inner.trap_sinks.iter().map(|sink| &sink.summary)
    }

    /// Returns the local engine ID.
    ///
    /// With an [`AuthoritativeEngine`] this is the stable persisted V3
    /// identity. A community-only Agent instead has a generated process-local
    /// ID for its built-in engine objects.
    #[must_use]
    pub fn engine_id(&self) -> &[u8] {
        &self.inner.state.engine_id
    }

    /// Return one coherent current engine boots/time pair.
    ///
    /// If engine time has wrapped, an [`AuthoritativeEngine`] persists the
    /// incremented boots value before this method returns it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AuthoritativeEnginePersistence`] if a rollover cannot
    /// be persisted. The previously durable pair remains authoritative.
    pub fn engine_boots_time(&self) -> Result<(u32, u32)> {
        self.inner.state.authoritative_boots_time()
    }

    /// Return the Agent's current local-authoritative persistence health.
    #[must_use]
    pub fn health(&self) -> AgentHealth {
        *self.inner.state.health.borrow()
    }

    /// Observe bounded, coalesced health changes.
    ///
    /// The returned watch receiver starts with the current value. Slow
    /// observers see the latest state instead of one queued item per failed
    /// packet. Recovery is published only after authoritative-state sampling
    /// succeeds on a later attempt.
    #[must_use]
    pub fn subscribe_health(&self) -> tokio::sync::watch::Receiver<AgentHealth> {
        self.inner.state.health.subscribe()
    }

    /// Initiate graceful shutdown.
    pub fn cancel(&self) {
        self.inner.cancel.cancel();
    }

    /// Returns a clone of the agent's cancellation token.
    #[must_use]
    pub fn cancellation_token(&self) -> CancellationToken {
        self.inner.cancel.clone()
    }

    /// Return the number of dispatched request tasks still owned by the agent.
    ///
    /// This includes protected SET work retained after a `run` future is
    /// dropped. A second `run` remains rejected until such orphaned work exits.
    #[must_use]
    pub fn active_request_count(&self) -> usize {
        self.inner.active_request_tasks.load(Ordering::Acquire)
    }

    /// Return whether a dropped `run` future left observable request work.
    #[must_use]
    pub fn has_orphaned_requests(&self) -> bool {
        self.inner.run_orphaned.load(Ordering::Acquire) && self.active_request_count() != 0
    }

    /// Returns the snmpInASNParseErrs counter value.
    ///
    /// This counter tracks ASN.1 or BER syntax errors encountered while
    /// decoding received SNMP messages. Authentication, authorization,
    /// message-processing, and version-specific semantic failures are not
    /// included.
    ///
    /// OID: 1.3.6.1.2.1.11.6.0
    #[must_use]
    pub fn snmp_in_asn_parse_errs(&self) -> u32 {
        self.inner
            .state
            .snmp_in_asn_parse_errs
            .load(Ordering::Relaxed)
    }

    /// Returns the snmpInvalidMsgs counter value.
    ///
    /// This counter tracks messages with invalid msgFlags, such as
    /// privacy-without-authentication (RFC 3412 Section 7.2 Step 5d).
    ///
    /// OID: 1.3.6.1.6.3.11.2.1.2
    #[must_use]
    pub fn snmp_invalid_msgs(&self) -> u32 {
        self.inner.state.snmp_invalid_msgs.load(Ordering::Relaxed)
    }

    /// Returns the snmpUnknownSecurityModels counter value.
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

    /// Returns the snmpSilentDrops counter value.
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

    /// Returns the snmpUnknownContexts counter value.
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

    /// Returns the usmStatsUnknownEngineIDs counter value.
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

    /// Returns the usmStatsUnknownUserNames counter value.
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

    /// Returns the usmStatsWrongDigests counter value.
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

    /// Returns the usmStatsNotInTimeWindows counter value.
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

    /// Returns the usmStatsUnsupportedSecLevels counter value.
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

    /// Returns the usmStatsDecryptionErrors counter value.
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
    /// permits, signals every dispatched request context, and by default drains
    /// handler work and response attempts without a forced timeout. A received
    /// request still waiting for admission may be dropped. Configure
    /// [`AgentShutdownPolicy::AbortCancellationSafeRetrievalsAfter`] only when
    /// every retrieval handler satisfies its cancellation-safety contract;
    /// SET and unclassified work always drain.
    ///
    /// Dropping or aborting `run` signals its request contexts but cannot await
    /// them. Live tasks remain in the Agent-owned registry and are observable
    /// through [`active_request_count`](Self::active_request_count); a second
    /// `run` is rejected until retained work finishes. For orderly shutdown,
    /// cancel the configured token and await this method.
    ///
    /// Only one active call to `run` is supported for an agent. Cloned handles
    /// may still be used for other agent operations while that call is active.
    /// Datagram-local receive metadata errors are discarded. Known transient
    /// socket errors are retried with bounded backoff; invalid or unknown
    /// socket-state errors terminate the service and are returned.
    #[instrument(skip(self), err, fields(snmp.local_addr = %self.local_addr()))]
    pub async fn run(&self) -> Result<()> {
        self.inner
            .run_active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::AgentAlreadyRunning.boxed())?;
        self.inner.run_orphaned.store(false, Ordering::Release);
        let mut run_guard = RunGuard {
            inner: &self.inner,
            completed: false,
        };

        let mut buf = vec![0u8; UDP_RECEIVE_BUFFER_SIZE];
        let mut request_tasks =
            RequestTasks::new(self.inner.cancel.child_token(), Arc::clone(&self.inner));
        let mut recv_error_backoff = UdpRecvErrorBackoff::default();

        let log_task_result = |result: std::result::Result<(), JoinError>| {
            if let Err(error) = result {
                if error.is_cancelled() {
                    tracing::debug!(target: "async_snmp::agent", "cancellation-safe retrieval task aborted by shutdown policy");
                } else {
                    tracing::error!(target: "async_snmp::agent", %error, "request task failed");
                }
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
                            Ok(recv_meta) => {
                                recv_error_backoff.reset();
                                break recv_meta;
                            }
                            Err(error) => match classify_udp_recv_error(&error) {
                                UdpRecvErrorClass::DatagramLocal => {
                                    recv_error_backoff.reset();
                                    tracing::warn!(target: "async_snmp::agent", %error, "discarding datagram with invalid receive metadata");
                                }
                                UdpRecvErrorClass::Transient => {
                                    let delay = recv_error_backoff.advance();
                                    tracing::warn!(target: "async_snmp::agent", %error, backoff = ?delay, "transient UDP receive error");
                                    tokio::select! {
                                        biased;
                                        () = self.inner.cancel.cancelled() => {
                                            tracing::info!(target: "async_snmp::agent", "agent shutdown requested");
                                            break 'service Ok(());
                                        }
                                        () = tokio::time::sleep(delay) => {}
                                    }
                                }
                                UdpRecvErrorClass::Fatal => {
                                    break 'service Err(Error::Network {
                                        target: self.inner.local_addr,
                                        source: error,
                                    }
                                    .boxed());
                                }
                            },
                        }
                    }
                }
            };

            // Capture receipt before copying the datagram or waiting for an
            // execution permit so queueing consumes the request budget.
            let received_at = tokio::time::Instant::now();
            let deadline = self.inner.request_deadline.map(|duration| {
                received_at
                    .checked_add(duration)
                    .expect("agent request deadline validated by builder")
            });
            #[cfg(test)]
            self.inner
                .received_datagrams
                .fetch_add(1, Ordering::Relaxed);
            #[cfg(test)]
            let pre_permit_gate = self.inner.pre_permit_gate.lock().unwrap().clone();
            #[cfg(test)]
            if let Some(gate) = pre_permit_gate {
                gate.acquire()
                    .await
                    .expect("test pre-permit gate remains open")
                    .forget();
            }

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
            let request_cancel = task_cancel.child_token();
            let phase = Arc::new(AtomicU8::new(RequestTaskPhase::Unclassified as u8));
            let lifecycle = RequestLifecycle::new(
                received_at,
                tokio::time::Instant::now(),
                deadline,
                request_cancel.clone(),
                phase.clone(),
            );
            request_tasks.spawn(phase, async move {
                let _permit = permit;

                let request = async {
                    match agent
                        .handle_request_with_lifecycle(data, recv_meta.source, lifecycle)
                        .await
                    {
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
                };
                tokio::pin!(request);
                if let Some(deadline) = deadline {
                    if tokio::time::Instant::now() >= deadline {
                        tracing::debug!(target: "async_snmp::agent", { snmp.source = %recv_meta.source }, "request deadline expired before admission");
                        request_cancel.cancel();
                        request.await;
                    } else {
                        tokio::select! {
                            () = tokio::time::sleep_until(deadline) => {
                                tracing::debug!(target: "async_snmp::agent", { snmp.source = %recv_meta.source }, "request deadline expired");
                                request_cancel.cancel();
                                request.await;
                            }
                            () = &mut request => {}
                        }
                    }
                } else {
                    request.await;
                }
            });
        };

        request_tasks.cancel();
        match self.inner.shutdown_policy {
            AgentShutdownPolicy::Drain => {
                while let Some(result) = request_tasks.join_next().await {
                    log_task_result(result);
                }
            }
            AgentShutdownPolicy::AbortCancellationSafeRetrievalsAfter(grace) => {
                let deadline = tokio::time::Instant::now()
                    .checked_add(grace)
                    .expect("agent shutdown grace validated by builder");
                loop {
                    if request_tasks.is_empty() {
                        break;
                    }
                    tokio::select! {
                        result = request_tasks.join_next() => {
                            if let Some(result) = result {
                                log_task_result(result);
                            }
                        }
                        () = tokio::time::sleep_until(deadline) => {
                            request_tasks.abort_retrievals();
                            break;
                        }
                    }
                }
                while let Some(result) = request_tasks.join_next().await {
                    log_task_result(result);
                }
            }
        }

        run_guard.complete();
        run_result
    }

    async fn recv_packet(&self, buf: &mut [u8]) -> std::io::Result<ReceivedDatagram> {
        #[cfg(test)]
        {
            self.inner.receive_attempts.fetch_add(1, Ordering::Relaxed);
            if let Some(error) = self.inner.receive_errors.lock().unwrap().pop_front() {
                return Err(error);
            }
        }
        self.inner.udp_responder.recv(&self.inner.socket, buf).await
    }

    async fn send_response(
        &self,
        data: &[u8],
        recv_meta: &ReceivedDatagram,
    ) -> std::io::Result<()> {
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.response_send_timeout)
            .expect("response send timeout validated by builder");
        let timeout_error =
            || std::io::Error::new(std::io::ErrorKind::TimedOut, "response send timed out");
        if tokio::time::Instant::now() >= deadline {
            return Err(timeout_error());
        }
        #[cfg(test)]
        let response_send_gate = self.inner.response_send_gate.lock().unwrap().clone();
        tokio::select! {
            biased;
            () = tokio::time::sleep_until(deadline) => Err(timeout_error()),
            result = async {
                #[cfg(test)]
                self.inner.response_sends_started.fetch_add(1, Ordering::Relaxed);
                #[cfg(test)]
                if let Some(gate) = &response_send_gate {
                    gate.acquire().await.expect("test send gate remains open").forget();
                }
                self.inner.udp_responder.reply(&self.inner.socket, data, recv_meta).await
            } => result,
        }
    }

    /// Process a single request and return the response bytes.
    ///
    /// Returns `None` if no response should be sent.
    #[cfg(test)]
    async fn handle_request(&self, data: Bytes, source: SocketAddr) -> Result<Option<Bytes>> {
        let now = tokio::time::Instant::now();
        self.handle_request_with_lifecycle(
            data,
            source,
            RequestLifecycle::new(
                now,
                now,
                None,
                CancellationToken::new(),
                Arc::new(AtomicU8::new(RequestTaskPhase::Unclassified as u8)),
            ),
        )
        .await
    }

    async fn handle_request_with_lifecycle(
        &self,
        data: Bytes,
        source: SocketAddr,
        lifecycle: RequestLifecycle,
    ) -> Result<Option<Bytes>> {
        let result = self.handle_request_inner(data, source, lifecycle).await;
        if matches!(
            &result,
            Err(error) if matches!(
                &**error,
                Error::Decode(error)
                    if !matches!(
                        error.kind,
                        crate::DecodeErrorKind::UnknownVersion(_)
                            | crate::DecodeErrorKind::InvalidMsgFlags
                            | crate::DecodeErrorKind::UnknownSecurityModel(_)
                    )
            )
        ) {
            self.inner
                .state
                .snmp_in_asn_parse_errs
                .fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    async fn handle_request_inner(
        &self,
        data: Bytes,
        source: SocketAddr,
        lifecycle: RequestLifecycle,
    ) -> Result<Option<Bytes>> {
        match crate::message::peek_version(data.clone(), source)? {
            Version::V1 => self.handle_v1_with_lifecycle(data, source, lifecycle).await,
            Version::V2c => {
                self.handle_v2c_with_lifecycle(data, source, lifecycle)
                    .await
            }
            Version::V3 => self.handle_v3_with_lifecycle(data, source, lifecycle).await,
        }
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
                if ctx.version() == Version::V1 {
                    return pdu.to_error_response(
                        ctx.version(),
                        ErrorStatus::GenErr,
                        usize::from(!pdu.varbinds.is_empty()),
                    );
                }
                self.handle_get_bulk(ctx, pdu).await
            }
            PduType::SetRequest => self.handle_set(ctx, pdu).await,
            PduType::InformRequest => self.handle_inform(ctx, pdu),
            _ => {
                // Should not happen - filtered earlier
                pdu.to_error_response(ctx.version(), ErrorStatus::GenErr, 0)
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
    fn handle_inform(&self, ctx: &RequestContext, pdu: &Pdu) -> Result<Pdu> {
        // Exact sizing and the empty-varbind tooBig fallback are applied at the
        // shared message-envelope finalizer after the response is encoded.
        pdu.to_response(ctx.version())
    }

    /// Effective maximum response message size for a request: the smaller of
    /// the agent's configured limit and the client's advertised `msgMaxSize`
    /// (v3). v1/v2c requests carry no `msg_max_size`, so the agent limit applies.
    fn effective_max_size(&self, ctx: &RequestContext) -> usize {
        let agent_max = self.inner.state.max_message_size;
        match ctx.msg_max_size() {
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
        if ctx.version() != Version::V3 {
            // v1/v2c echo the request's community string in the response
            // wrapper. A long, operator-configured community can otherwise
            // push the encoded Response past the size limit after
            // response_fits has already accepted it.
            return RESPONSE_OVERHEAD + ctx.security_name().len();
        }
        let mut overhead = RESPONSE_OVERHEAD
            + 2 * self.inner.state.engine_id.len()
            + ctx.security_name().len()
            + ctx.context_name().len();
        if ctx.security_level().requires_auth() {
            overhead += V3_AUTH_OVERHEAD;
        }
        if ctx.security_level().requires_priv() {
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
                && !vacm.check_access(ctx.read_view(), &vb.oid)
            {
                // v1: noSuchName, v2c/v3: noAccess or NoSuchObject
                if ctx.version() == Version::V1 {
                    return pdu.to_error_response(
                        ctx.version(),
                        ErrorStatus::NoSuchName,
                        index + 1,
                    );
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
                        return pdu.to_error_response(
                            ctx.version(),
                            ErrorStatus::GenErr,
                            index + 1,
                        );
                    }
                }
            } else {
                GetResult::NoSuchObject
            };

            let response_value = match result {
                GetResult::Value(v) => {
                    if v1_rejects_counter64(ctx.version(), &v) {
                        return pdu.to_error_response(
                            ctx.version(),
                            ErrorStatus::NoSuchName,
                            index + 1,
                        );
                    }
                    v
                }
                GetResult::NoSuchObject => {
                    // v1 returns noSuchName error, v2c/v3 returns NoSuchObject exception
                    if ctx.version() == Version::V1 {
                        return pdu.to_error_response(
                            ctx.version(),
                            ErrorStatus::NoSuchName,
                            index + 1,
                        );
                    }
                    Value::NoSuchObject
                }
                GetResult::NoSuchInstance => {
                    // v1 returns noSuchName error, v2c/v3 returns NoSuchInstance exception
                    if ctx.version() == Version::V1 {
                        return pdu.to_error_response(
                            ctx.version(),
                            ErrorStatus::NoSuchName,
                            index + 1,
                        );
                    }
                    Value::NoSuchInstance
                }
            };

            response_varbinds.push(VarBind::new(vb.oid.clone(), response_value));
        }

        Ok(ResponsePdu::success(ctx.version(), pdu.request_id, response_varbinds)?.into_raw())
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
                    return pdu.to_error_response(ctx.version(), ErrorStatus::GenErr, index + 1);
                }
            };

            if let Some(next_vb) = next {
                response_varbinds.push(next_vb);
            } else {
                // v1 returns noSuchName, v2c/v3 returns endOfMibView
                if ctx.version() == Version::V1 {
                    return pdu.to_error_response(
                        ctx.version(),
                        ErrorStatus::NoSuchName,
                        index + 1,
                    );
                }
                response_varbinds.push(VarBind::new(vb.oid.clone(), Value::EndOfMibView));
            }
        }

        Ok(ResponsePdu::success(ctx.version(), pdu.request_id, response_varbinds)?.into_raw())
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
                    return pdu.to_error_response(ctx.version(), ErrorStatus::GenErr, index + 1);
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
                return Ok(
                    ResponsePdu::success(ctx.version(), pdu.request_id, response_varbinds)?
                        .into_raw(),
                );
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
                                return pdu.to_error_response(
                                    ctx.version(),
                                    ErrorStatus::GenErr,
                                    non_repeaters + i + 1,
                                );
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

        Ok(ResponsePdu::success(ctx.version(), pdu.request_id, response_varbinds)?.into_raw())
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
                    if v1_rejects_counter64(ctx.version(), &next_vb.value) {
                        search_from = next_vb.oid.clone();
                        continue;
                    }
                    if let Some(vacm) = self.inner.authorization.vacm() {
                        if vacm.check_access(ctx.read_view(), &next_vb.oid) {
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
        // Custom `handles` implementations may establish non-prefix ownership,
        // so a registration prefix cannot safely prune this minimum scan.
        let handlers = &self.inner.handlers;
        let mut best_result: Option<VarBind> = None;
        let mut completed = std::iter::repeat_with(|| None)
            .take(handlers.len())
            .collect::<Vec<_>>();
        let mut next_to_start = 0;
        let mut next_to_process = 0;
        let mut probes = FuturesUnordered::new();
        let probe =
            |index: usize| async move { (index, handlers[index].handler.get_next(ctx, oid).await) };

        while next_to_start < handlers.len() && probes.len() < MAX_CONCURRENT_GETNEXT_PROBES {
            probes.push(probe(next_to_start));
            next_to_start += 1;
        }

        while let Some((index, result)) = probes.next().await {
            completed[index] = Some(result);

            while let Some(result) = completed[next_to_process].take() {
                let handler = &handlers[next_to_process];
                let prefix = &handler.prefix;
                if let GetNextResult::Value(next) = result? {
                    if next.oid <= *oid {
                        return Err(crate::handler::HandlerError::new(format!(
                            "GETNEXT handler registered at {prefix} returned non-increasing OID {} after {oid}",
                            next.oid
                        )));
                    }
                    if !handler.handler.handles(prefix, &next.oid) {
                        return Err(crate::handler::HandlerError::new(format!(
                            "GETNEXT handler registered at {prefix} returned unowned OID {}",
                            next.oid
                        )));
                    }
                    match &best_result {
                        None => best_result = Some(next),
                        Some(current) if next.oid < current.oid => best_result = Some(next),
                        _ => {}
                    }
                }
                next_to_process += 1;
                if next_to_process == handlers.len() {
                    break;
                }
            }

            while next_to_start < handlers.len() && probes.len() < MAX_CONCURRENT_GETNEXT_PROBES {
                probes.push(probe(next_to_start));
                next_to_start += 1;
            }
        }

        debug_assert_eq!(next_to_process, handlers.len());
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
    use std::sync::atomic::AtomicUsize;

    use crate::handler::{
        BoxFuture, GetNextResult, GetResult, HandlerError, HandlerResult, MibHandler, PreparedSet,
        RequestContext, SecurityModel, SetCommitError, SetCommitResult, SetTestError,
        SetTestResult, SetUndoResult,
    };
    use crate::message::SecurityLevel;
    use crate::oid;

    #[tokio::test]
    async fn decoding_policy_defaults_strict_preset_and_targeted_override() {
        let default = Agent::builder().bind("127.0.0.1:0").build().await.unwrap();
        assert_eq!(default.decode_config(), crate::DecodeConfig::DEFAULT);

        let mut targeted = crate::DecodeConfig::STRICT;
        targeted.empty_counter64_as_zero = true;
        let configured = Agent::builder()
            .bind("127.0.0.1:0")
            .decode_config(targeted)
            .build()
            .await
            .unwrap();
        assert_eq!(configured.decode_config(), targeted);
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

    type RequestObservation = (
        tokio::time::Instant,
        tokio::time::Instant,
        Option<tokio::time::Instant>,
        bool,
    );
    type RequestObservations = Arc<std::sync::Mutex<Vec<RequestObservation>>>;

    struct BlockingGetHandler {
        started: Arc<Semaphore>,
        release: Arc<Semaphore>,
        observe_cancellation: bool,
        observations: RequestObservations,
    }

    impl MibHandler for BlockingGetHandler {
        fn get<'a>(
            &'a self,
            ctx: &'a RequestContext,
            _oid: &'a Oid,
        ) -> BoxFuture<'a, HandlerResult<GetResult>> {
            Box::pin(async move {
                self.started.add_permits(1);
                if self.observe_cancellation {
                    ctx.cancelled().await;
                } else {
                    self.release
                        .acquire()
                        .await
                        .expect("blocking GET release remains open")
                        .forget();
                }
                self.observations.lock().unwrap().push((
                    ctx.received_at(),
                    ctx.admitted_at(),
                    ctx.deadline(),
                    ctx.is_cancelled(),
                ));
                Ok(GetResult::Value(Value::Integer(42)))
            })
        }

        fn get_next<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
        ) -> BoxFuture<'a, HandlerResult<GetNextResult>> {
            Box::pin(async { Ok(GetNextResult::EndOfMibView) })
        }
    }

    fn encoded_get(request_id: i32) -> Bytes {
        crate::message::CommunityMessage::new(
            crate::CommunityVersion::V2c,
            Bytes::from_static(b"public"),
            Pdu::get_request(request_id, &[oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0)]),
        )
        .unwrap()
        .encode()
        .unwrap()
    }

    #[derive(Clone, Copy)]
    enum ProtectedSetMode {
        Undo,
        Finalize,
    }

    struct ProtectedSetHandler {
        mode: ProtectedSetMode,
        cleanup_started: Arc<Semaphore>,
        release_cleanup: Arc<Semaphore>,
        calls: Arc<std::sync::Mutex<Vec<(&'static str, Oid)>>>,
    }

    struct ProtectedSetPrepared {
        mode: ProtectedSetMode,
        cleanup_started: Arc<Semaphore>,
        release_cleanup: Arc<Semaphore>,
        calls: Arc<std::sync::Mutex<Vec<(&'static str, Oid)>>>,
    }

    impl PreparedSet for ProtectedSetPrepared {
        fn commit<'a>(
            &'a mut self,
            _ctx: &'a RequestContext,
            oid: &'a Oid,
            _value: &'a Value,
        ) -> BoxFuture<'a, SetCommitResult> {
            Box::pin(async move {
                self.calls.lock().unwrap().push(("commit", oid.clone()));
                if matches!(self.mode, ProtectedSetMode::Undo) && oid == &protected_set_oid(2) {
                    Err(SetCommitError::Failed)
                } else {
                    Ok(())
                }
            })
        }

        fn undo<'a>(
            &'a mut self,
            _ctx: &'a RequestContext,
            oid: &'a Oid,
            _value: &'a Value,
        ) -> BoxFuture<'a, SetUndoResult> {
            Box::pin(async move {
                self.calls.lock().unwrap().push(("undo", oid.clone()));
                if matches!(self.mode, ProtectedSetMode::Undo) && oid == &protected_set_oid(2) {
                    self.cleanup_started.add_permits(1);
                    self.release_cleanup.acquire().await.unwrap().forget();
                }
                Ok(())
            })
        }

        fn finalize<'a>(
            &'a mut self,
            _ctx: &'a RequestContext,
            oid: &'a Oid,
            _value: &'a Value,
        ) -> BoxFuture<'a, ()> {
            Box::pin(async move {
                self.calls.lock().unwrap().push(("finalize", oid.clone()));
                if matches!(self.mode, ProtectedSetMode::Finalize) && oid == &protected_set_oid(2) {
                    self.cleanup_started.add_permits(1);
                    self.release_cleanup.acquire().await.unwrap().forget();
                }
            })
        }
    }

    impl MibHandler for ProtectedSetHandler {
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
            Box::pin(async { Ok(GetNextResult::EndOfMibView) })
        }

        fn test_set<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
            _value: &'a Value,
        ) -> BoxFuture<'a, SetTestResult> {
            Box::pin(async move {
                Ok(Box::new(ProtectedSetPrepared {
                    mode: self.mode,
                    cleanup_started: self.cleanup_started.clone(),
                    release_cleanup: self.release_cleanup.clone(),
                    calls: self.calls.clone(),
                }) as Box<dyn PreparedSet>)
            })
        }
    }

    fn protected_set_oid(index: u32) -> Oid {
        oid!(1, 3, 6, 1, 4, 1, 99999, index, 0)
    }

    fn encoded_set(request_id: i32) -> Bytes {
        crate::message::CommunityMessage::new(
            crate::CommunityVersion::V2c,
            Bytes::from_static(b"public"),
            Pdu::standard(
                crate::pdu::StandardPduType::SetRequest,
                request_id,
                0,
                0,
                vec![
                    VarBind::new(protected_set_oid(1), Value::Integer(1)),
                    VarBind::new(protected_set_oid(2), Value::Integer(2)),
                ],
            ),
        )
        .unwrap()
        .encode()
        .unwrap()
    }

    async fn run_protected_set_shutdown(mode: ProtectedSetMode) -> (i32, Vec<(&'static str, Oid)>) {
        let cleanup_started = Arc::new(Semaphore::new(0));
        let release_cleanup = Arc::new(Semaphore::new(0));
        let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let grace = Duration::from_millis(10);
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .handler(
                oid!(1, 3, 6, 1, 4, 1, 99999),
                Arc::new(ProtectedSetHandler {
                    mode,
                    cleanup_started: cleanup_started.clone(),
                    release_cleanup: release_cleanup.clone(),
                    calls: calls.clone(),
                }),
            )
            .without_builtin_handlers()
            .shutdown_policy(AgentShutdownPolicy::AbortCancellationSafeRetrievalsAfter(
                grace,
            ))
            .allow_all_access()
            .build()
            .await
            .unwrap();
        let run_agent = agent.clone();
        let run = tokio::spawn(async move { run_agent.run().await });
        wait_for_run_state(&agent, true).await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .send_to(&encoded_set(41), agent.local_addr())
            .await
            .unwrap();
        cleanup_started.acquire().await.unwrap().forget();

        agent.cancel();
        tokio::time::sleep(grace + Duration::from_millis(20)).await;
        assert!(!run.is_finished());
        assert_eq!(agent.active_request_count(), 1);
        assert_eq!(agent.inner.live_request_tasks.lock().unwrap().len(), 1);

        release_cleanup.add_permits(1);
        let mut response = [0_u8; 2048];
        let (len, _) =
            tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut response))
                .await
                .expect("protected SET response was not attempted")
                .unwrap();
        let response = crate::message::CommunityMessage::decode(
            Bytes::copy_from_slice(&response[..len]),
            crate::DecodeConfig::default(),
        )
        .unwrap()
        .value;
        let error_status = response.pdu().standard().unwrap().error_status();
        tokio::time::timeout(Duration::from_secs(1), run)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(agent.active_request_count(), 0);
        assert!(agent.inner.live_request_tasks.lock().unwrap().is_empty());
        wait_for_run_state(&agent, false).await;

        let calls = calls.lock().unwrap().clone();
        (error_status, calls)
    }

    fn test_ctx() -> RequestContext {
        crate::test_support::request_context(PduType::GetRequest)
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
            crate::CommunityVersion::V2c,
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
        let decoded = crate::message::CommunityMessage::decode(
            Bytes::copy_from_slice(&response[..len]),
            crate::DecodeConfig::default(),
        )
        .unwrap()
        .value;
        let response_pdu = decoded.pdu().standard().unwrap();
        assert_eq!(response_pdu.request_id, 7);
        assert_eq!(response_pdu.error_status(), 0);

        agent.cancel();
        first.await.unwrap().unwrap();
        wait_for_run_state(&agent, false).await;
        assert!(
            agent.run().await.is_ok(),
            "a later call must acquire the guard"
        );
    }

    #[test]
    fn receive_error_classification_and_backoff_are_bounded() {
        assert_eq!(
            classify_udp_recv_error(&std::io::Error::from(std::io::ErrorKind::InvalidData)),
            UdpRecvErrorClass::DatagramLocal
        );
        assert_eq!(
            classify_udp_recv_error(&std::io::Error::from(std::io::ErrorKind::ConnectionRefused)),
            UdpRecvErrorClass::Transient
        );
        assert_eq!(
            classify_udp_recv_error(&std::io::Error::from(std::io::ErrorKind::NetworkDown)),
            UdpRecvErrorClass::Transient
        );
        assert_eq!(
            classify_udp_recv_error(&std::io::Error::from(std::io::ErrorKind::InvalidInput)),
            UdpRecvErrorClass::Fatal
        );
        assert_eq!(
            classify_udp_recv_error(&std::io::Error::other("unclassified socket failure")),
            UdpRecvErrorClass::Fatal
        );

        let mut backoff = UdpRecvErrorBackoff::default();
        for _ in 0..16 {
            backoff.advance();
        }
        assert_eq!(backoff.current(), Duration::from_millis(100));
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos",
        target_os = "freebsd",
    ))]
    #[test]
    fn receive_error_classification_treats_enobufs_as_transient() {
        assert_eq!(
            classify_udp_recv_error(&std::io::Error::from_raw_os_error(nix::libc::ENOBUFS)),
            UdpRecvErrorClass::Transient
        );
    }

    #[tokio::test]
    async fn recoverable_receive_errors_do_not_stop_agent() {
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), Arc::new(TestHandler))
            .without_builtin_handlers()
            .allow_all_access()
            .build()
            .await
            .unwrap();
        {
            let mut errors = agent.inner.receive_errors.lock().unwrap();
            errors.push_back(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "injected datagram metadata failure",
            ));
            errors.push_back(std::io::Error::from(std::io::ErrorKind::ConnectionRefused));
        }
        let run_agent = agent.clone();
        let run = tokio::spawn(async move { run_agent.run().await });
        wait_for_run_state(&agent, true).await;

        let request = crate::message::CommunityMessage::new(
            crate::CommunityVersion::V2c,
            Bytes::from_static(b"public"),
            Pdu::get_request(17, &[oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0)]),
        )
        .unwrap()
        .encode()
        .unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&request, agent.local_addr()).await.unwrap();
        let mut response = [0_u8; 2048];
        let (len, _) =
            tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut response))
                .await
                .expect("agent stopped after a recoverable receive error")
                .unwrap();
        let response = crate::message::CommunityMessage::decode(
            Bytes::copy_from_slice(&response[..len]),
            crate::DecodeConfig::default(),
        )
        .unwrap()
        .value;
        assert_eq!(response.pdu().standard().unwrap().request_id, 17);

        agent.cancel();
        run.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn fatal_receive_error_stops_agent() {
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .allow_all_access()
            .build()
            .await
            .unwrap();
        agent
            .inner
            .receive_errors
            .lock()
            .unwrap()
            .push_back(std::io::Error::from(std::io::ErrorKind::InvalidInput));

        let error = agent.run().await.unwrap_err();
        let Error::Network { source, .. } = &*error else {
            panic!("fatal receive error lost its network classification");
        };
        assert_eq!(source.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_interrupts_receive_error_backoff() {
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .allow_all_access()
            .build()
            .await
            .unwrap();
        agent
            .inner
            .receive_errors
            .lock()
            .unwrap()
            .push_back(std::io::Error::from(std::io::ErrorKind::ConnectionRefused));
        let before = tokio::time::Instant::now();
        let run_agent = agent.clone();
        let run = tokio::spawn(async move { run_agent.run().await });
        while agent.inner.receive_attempts.load(Ordering::Relaxed) == 0 {
            tokio::task::yield_now().await;
        }

        agent.cancel();
        run.await.unwrap().unwrap();
        assert_eq!(tokio::time::Instant::now(), before);
    }

    #[tokio::test]
    async fn stalled_response_send_does_not_block_graceful_shutdown() {
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), Arc::new(TestHandler))
            .without_builtin_handlers()
            .max_concurrent_requests(Some(1))
            .response_send_timeout(Duration::from_millis(20))
            .allow_all_access()
            .build()
            .await
            .unwrap();
        *agent.inner.response_send_gate.lock().unwrap() = Some(Arc::new(Semaphore::new(0)));
        let run_agent = agent.clone();
        let run = tokio::spawn(async move { run_agent.run().await });
        wait_for_run_state(&agent, true).await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let request = crate::message::CommunityMessage::new(
            crate::CommunityVersion::V2c,
            Bytes::from_static(b"public"),
            Pdu::get_request(7, &[oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0)]),
        )
        .unwrap()
        .encode()
        .unwrap();
        client.send_to(&request, agent.local_addr()).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while agent.inner.response_sends_started.load(Ordering::Relaxed) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        agent.cancel();
        tokio::time::timeout(Duration::from_secs(1), run)
            .await
            .expect("graceful shutdown remained blocked on response send")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn cooperative_get_observes_shutdown_cancellation() {
        let started = Arc::new(Semaphore::new(0));
        let observations = Arc::new(std::sync::Mutex::new(Vec::new()));
        let handler = BlockingGetHandler {
            started: started.clone(),
            release: Arc::new(Semaphore::new(0)),
            observe_cancellation: true,
            observations: observations.clone(),
        };
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), Arc::new(handler))
            .without_builtin_handlers()
            .allow_all_access()
            .build()
            .await
            .unwrap();
        let run_agent = agent.clone();
        let run = tokio::spawn(async move { run_agent.run().await });
        wait_for_run_state(&agent, true).await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .send_to(&encoded_get(1), agent.local_addr())
            .await
            .unwrap();
        started.acquire().await.unwrap().forget();

        agent.cancel();
        run.await.unwrap().unwrap();
        let observations = observations.lock().unwrap();
        assert_eq!(observations.len(), 1);
        assert!(observations[0].3);
    }

    #[tokio::test(start_paused = true)]
    async fn request_deadline_includes_concurrency_permit_queueing() {
        let started = Arc::new(Semaphore::new(0));
        let release = Arc::new(Semaphore::new(0));
        let observations = Arc::new(std::sync::Mutex::new(Vec::new()));
        let handler = BlockingGetHandler {
            started: started.clone(),
            release: release.clone(),
            observe_cancellation: false,
            observations: observations.clone(),
        };
        let budget = Duration::from_millis(20);
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), Arc::new(handler))
            .without_builtin_handlers()
            .max_concurrent_requests(Some(1))
            .request_deadline(Some(budget))
            .allow_all_access()
            .build()
            .await
            .unwrap();
        let pre_permit_gate = Arc::new(Semaphore::new(1));
        *agent.inner.pre_permit_gate.lock().unwrap() = Some(pre_permit_gate.clone());
        let run_agent = agent.clone();
        let run = tokio::spawn(async move { run_agent.run().await });
        wait_for_run_state(&agent, true).await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .send_to(&encoded_get(1), agent.local_addr())
            .await
            .unwrap();
        started.acquire().await.unwrap().forget();
        client
            .send_to(&encoded_get(2), agent.local_addr())
            .await
            .unwrap();
        while agent.inner.received_datagrams.load(Ordering::Relaxed) < 2 {
            tokio::task::yield_now().await;
        }
        assert_eq!(agent.active_request_count(), 1);
        tokio::time::advance(budget + Duration::from_millis(1)).await;
        pre_permit_gate.add_permits(1);
        release.add_permits(2);
        tokio::time::timeout(Duration::from_secs(1), async {
            while observations.lock().unwrap().len() != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        let queued = {
            let observations = observations.lock().unwrap();
            observations[1]
        };
        assert_eq!(queued.2, queued.0.checked_add(budget));
        assert!(queued.1.duration_since(queued.0) >= budget);
        assert!(queued.3);
        agent.cancel();
        run.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn default_shutdown_drains_blocked_retrieval() {
        let started = Arc::new(Semaphore::new(0));
        let release = Arc::new(Semaphore::new(0));
        let handler = BlockingGetHandler {
            started: started.clone(),
            release: release.clone(),
            observe_cancellation: false,
            observations: Arc::new(std::sync::Mutex::new(Vec::new())),
        };
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), Arc::new(handler))
            .without_builtin_handlers()
            .allow_all_access()
            .build()
            .await
            .unwrap();
        let run_agent = agent.clone();
        let mut run = tokio::spawn(async move { run_agent.run().await });
        wait_for_run_state(&agent, true).await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .send_to(&encoded_get(1), agent.local_addr())
            .await
            .unwrap();
        started.acquire().await.unwrap().forget();
        agent.cancel();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut run)
                .await
                .is_err()
        );
        assert_eq!(agent.active_request_count(), 1);
        release.add_permits(1);
        run.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn bounded_retrieval_abort_releases_request_permit() {
        let started = Arc::new(Semaphore::new(0));
        let handler = BlockingGetHandler {
            started: started.clone(),
            release: Arc::new(Semaphore::new(0)),
            observe_cancellation: false,
            observations: Arc::new(std::sync::Mutex::new(Vec::new())),
        };
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), Arc::new(handler))
            .without_builtin_handlers()
            .max_concurrent_requests(Some(1))
            .shutdown_policy(AgentShutdownPolicy::AbortCancellationSafeRetrievalsAfter(
                Duration::from_millis(10),
            ))
            .allow_all_access()
            .build()
            .await
            .unwrap();
        let run_agent = agent.clone();
        let run = tokio::spawn(async move { run_agent.run().await });
        wait_for_run_state(&agent, true).await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .send_to(&encoded_get(1), agent.local_addr())
            .await
            .unwrap();
        started.acquire().await.unwrap().forget();
        agent.cancel();
        tokio::time::timeout(Duration::from_secs(1), run)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(agent.active_request_count(), 0);
        assert_eq!(
            agent
                .inner
                .concurrency_limit
                .as_ref()
                .unwrap()
                .available_permits(),
            1
        );
    }

    #[tokio::test]
    async fn bounded_retrieval_policy_drains_set_undo_after_shutdown_grace() {
        let (status, calls) = run_protected_set_shutdown(ProtectedSetMode::Undo).await;
        assert_eq!(status, ErrorStatus::CommitFailed.as_i32());
        assert_eq!(
            calls,
            vec![
                ("commit", protected_set_oid(1)),
                ("commit", protected_set_oid(2)),
                ("undo", protected_set_oid(2)),
                ("undo", protected_set_oid(1)),
            ]
        );
    }

    #[tokio::test]
    async fn bounded_retrieval_policy_drains_set_finalize_after_shutdown_grace() {
        let (status, calls) = run_protected_set_shutdown(ProtectedSetMode::Finalize).await;
        assert_eq!(status, ErrorStatus::NoError.as_i32());
        assert_eq!(
            calls,
            vec![
                ("commit", protected_set_oid(1)),
                ("commit", protected_set_oid(2)),
                ("finalize", protected_set_oid(2)),
                ("finalize", protected_set_oid(1)),
            ]
        );
    }

    #[tokio::test]
    async fn dropped_run_keeps_live_request_observable_and_blocks_second_run() {
        let started = Arc::new(Semaphore::new(0));
        let release = Arc::new(Semaphore::new(0));
        let handler = BlockingGetHandler {
            started: started.clone(),
            release: release.clone(),
            observe_cancellation: false,
            observations: Arc::new(std::sync::Mutex::new(Vec::new())),
        };
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), Arc::new(handler))
            .without_builtin_handlers()
            .allow_all_access()
            .build()
            .await
            .unwrap();
        let run_agent = agent.clone();
        let run = tokio::spawn(async move { run_agent.run().await });
        wait_for_run_state(&agent, true).await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .send_to(&encoded_get(1), agent.local_addr())
            .await
            .unwrap();
        started.acquire().await.unwrap().forget();
        run.abort();
        assert!(run.await.unwrap_err().is_cancelled());
        assert_eq!(agent.active_request_count(), 1);
        assert!(agent.has_orphaned_requests());
        assert!(matches!(
            &*agent.run().await.unwrap_err(),
            Error::AgentAlreadyRunning
        ));

        release.add_permits(1);
        tokio::time::timeout(Duration::from_secs(1), async {
            while agent.active_request_count() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        wait_for_run_state(&agent, false).await;
    }

    #[tokio::test]
    async fn zero_response_timeout_emits_no_agent_response() {
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), Arc::new(TestHandler))
            .without_builtin_handlers()
            .response_send_timeout(Duration::ZERO)
            .allow_all_access()
            .build()
            .await
            .unwrap();
        let run_agent = agent.clone();
        let run = tokio::spawn(async move { run_agent.run().await });
        wait_for_run_state(&agent, true).await;
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let request = crate::message::CommunityMessage::new(
            crate::CommunityVersion::V2c,
            Bytes::from_static(b"public"),
            Pdu::get_request(8, &[oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0)]),
        )
        .unwrap()
        .encode()
        .unwrap();
        client.send_to(&request, agent.local_addr()).await.unwrap();
        let mut response = [0u8; 64];
        assert!(
            tokio::time::timeout(Duration::from_millis(25), client.recv_from(&mut response))
                .await
                .is_err()
        );
        agent.cancel();
        run.await.unwrap().unwrap();
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
            crate::CommunityVersion::V2c,
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

        agent.cancel();
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

        agent.cancel();
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

        agent.cancel();
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
        let ctx = crate::test_support::request_context(PduType::SetRequest);

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
        let ctx = crate::test_support::request_context(PduType::GetNextRequest);

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

    struct FixedNextHandler {
        candidate: Oid,
    }

    impl MibHandler for FixedNextHandler {
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
                Ok(GetNextResult::Value(VarBind::new(
                    self.candidate.clone(),
                    Value::Integer(1),
                )))
            })
        }
    }

    #[tokio::test]
    async fn get_next_concurrent_probing_preserves_custom_ownership_contracts() {
        let cursor = oid!(1, 3, 6, 1, 4, 1, 100);
        for reverse_registration in [false, true] {
            let order = Arc::new(std::sync::Mutex::new(Vec::new()));
            let nested_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let containing_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let nested = (
                oid!(1, 3, 6, 1, 4, 1, 100, 2),
                // The candidate is outside the registered prefix, but this
                // handler's custom `handles` implementation owns it.
                Arc::new(serial_probe(
                    "nested",
                    vec![oid!(1, 3, 6, 1, 4, 1, 100, 1)],
                    nested_calls.clone(),
                    order.clone(),
                )) as Arc<dyn MibHandler>,
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
            assert_eq!(order.lock().unwrap().len(), 2);
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
        assert_eq!(order.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn get_next_rejects_non_increasing_and_unowned_candidates() {
        let ctx = crate::test_support::request_context(PduType::GetNextRequest);
        let cases = [
            (
                "non-increasing OID",
                oid!(1, 3, 6, 1, 4, 1, 500),
                oid!(1, 3, 6, 1, 4, 1, 500, 1),
                oid!(1, 3, 6, 1, 4, 1, 500, 1),
            ),
            (
                "unowned OID",
                oid!(1, 3, 6, 1, 4, 1, 500),
                oid!(1, 3, 6, 1, 4, 1, 500),
                oid!(1, 3, 6, 1, 4, 1, 600, 1),
            ),
        ];

        for (expected_error, prefix, cursor, candidate) in cases {
            let agent = Agent::builder()
                .bind("127.0.0.1:0")
                .community(b"public")
                .without_builtin_handlers()
                .handler(prefix, Arc::new(FixedNextHandler { candidate }))
                .allow_all_access()
                .build()
                .await
                .unwrap();

            let error = agent.get_next_oid(&ctx, &cursor).await.unwrap_err();
            assert!(error.message().contains(expected_error));

            let request = Pdu::standard(
                crate::pdu::StandardPduType::GetNextRequest,
                9,
                0,
                0,
                vec![VarBind::new(cursor, Value::Null)],
            );
            let response = agent.dispatch_request(&ctx, &request).await.unwrap();
            assert_eq!(response.error_status(), ErrorStatus::GenErr.as_i32());
            assert_eq!(response.error_index(), 1);
            assert_eq!(response.varbinds, request.varbinds);
        }
    }

    #[tokio::test]
    async fn get_bulk_preserves_non_prefix_ownership_after_crossing_registration_prefix() {
        let root = oid!(1, 3, 6, 1, 4, 1, 700);
        let order = Arc::new(std::sync::Mutex::new(Vec::new()));
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .without_builtin_handlers()
            .handler(
                root.child(2),
                Arc::new(serial_probe(
                    "custom",
                    vec![root.child(1), root.child(3), root.child(4)],
                    Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                    order.clone(),
                )),
            )
            .allow_all_access()
            .build()
            .await
            .unwrap();
        let ctx = crate::test_support::request_context(PduType::GetBulkRequest);
        let request =
            Pdu::get_bulk(11, 0, 2, vec![VarBind::new(root.child(1), Value::Null)]).unwrap();

        let response = agent.dispatch_request(&ctx, &request).await.unwrap();
        assert_eq!(
            response
                .varbinds
                .iter()
                .map(|varbind| varbind.oid.clone())
                .collect::<Vec<_>>(),
            [root.child(3), root.child(4)]
        );
        assert_eq!(*order.lock().unwrap(), ["custom", "custom"]);
    }

    #[tokio::test]
    async fn get_next_starts_independent_probes_and_selects_errors_in_handler_order() {
        use std::sync::atomic::Ordering;

        let prefix = oid!(1, 3, 6, 1, 4, 1, 200);
        let order = Arc::new(std::sync::Mutex::new(Vec::new()));
        let first_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let later_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let release = Arc::new(tokio::sync::Notify::new());
        let first = SerialProbeHandler {
            release: Some(release.clone()),
            error: Some("first failure"),
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
            while first_calls.load(Ordering::SeqCst) == 0 || later_calls.load(Ordering::SeqCst) == 0
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(first_calls.load(Ordering::SeqCst), 1);
        assert_eq!(later_calls.load(Ordering::SeqCst), 1);
        assert!(!task.is_finished());

        release.notify_waiters();
        let error = task.await.unwrap().unwrap_err();
        assert_eq!(error.message(), "first failure");
        assert_eq!(order.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn get_next_returns_deterministic_error_without_waiting_for_later_probe() {
        use std::sync::atomic::Ordering;

        let prefix = oid!(1, 3, 6, 1, 4, 1, 250);
        let order = Arc::new(std::sync::Mutex::new(Vec::new()));
        let first_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let later_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let first_release = Arc::new(tokio::sync::Notify::new());
        let later_release = Arc::new(tokio::sync::Notify::new());
        let later_dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let first = SerialProbeHandler {
            release: Some(first_release.clone()),
            error: Some("first failure"),
            ..serial_probe("first", Vec::new(), first_calls.clone(), order.clone())
        };
        let later = SerialProbeHandler {
            release: Some(later_release),
            dropped: Some(later_dropped.clone()),
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
            while first_calls.load(Ordering::SeqCst) == 0 || later_calls.load(Ordering::SeqCst) == 0
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        first_release.notify_waiters();

        let error = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(error.message(), "first failure");
        assert!(later_dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn cancelled_get_bulk_drops_all_in_flight_probes() {
        use std::sync::atomic::Ordering;

        let prefix = oid!(1, 3, 6, 1, 4, 1, 300);
        let order = Arc::new(std::sync::Mutex::new(Vec::new()));
        let first_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let later_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let first_dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let later_dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let release = Arc::new(tokio::sync::Notify::new());
        let first = SerialProbeHandler {
            release: Some(release.clone()),
            dropped: Some(first_dropped.clone()),
            ..serial_probe("first", Vec::new(), first_calls.clone(), order.clone())
        };
        let later = SerialProbeHandler {
            release: Some(release),
            dropped: Some(later_dropped.clone()),
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
        let ctx = crate::test_support::request_context(PduType::GetBulkRequest);
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
        assert_eq!(later_calls.load(Ordering::SeqCst), 1);
        assert!(first_dropped.load(Ordering::SeqCst));
        assert!(later_dropped.load(Ordering::SeqCst));
        assert_eq!(order.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn get_next_probe_concurrency_is_bounded() {
        use std::sync::atomic::Ordering;

        let prefix = oid!(1, 3, 6, 1, 4, 1, 350);
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let order = Arc::new(std::sync::Mutex::new(Vec::new()));
        let release = Arc::new(tokio::sync::Notify::new());
        let mut builder = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .without_builtin_handlers();
        for _ in 0..=MAX_CONCURRENT_GETNEXT_PROBES {
            builder = builder.handler(
                prefix.clone(),
                Arc::new(SerialProbeHandler {
                    release: Some(release.clone()),
                    ..serial_probe("probe", Vec::new(), calls.clone(), order.clone())
                }),
            );
        }
        let agent = builder.allow_all_access().build().await.unwrap();
        let task = tokio::spawn(async move { agent.get_next_oid(&test_ctx(), &prefix).await });

        tokio::time::timeout(Duration::from_secs(1), async {
            while calls.load(Ordering::SeqCst) < MAX_CONCURRENT_GETNEXT_PROBES {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), MAX_CONCURRENT_GETNEXT_PROBES);

        release.notify_waiters();
        tokio::time::timeout(Duration::from_secs(1), async {
            while calls.load(Ordering::SeqCst) <= MAX_CONCURRENT_GETNEXT_PROBES {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            calls.load(Ordering::SeqCst),
            MAX_CONCURRENT_GETNEXT_PROBES + 1
        );
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    }

    #[tokio::test]
    async fn get_next_refills_probe_window_without_batch_barriers() {
        use std::sync::atomic::Ordering;

        let prefix = oid!(1, 3, 6, 1, 4, 1, 375);
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let order = Arc::new(std::sync::Mutex::new(Vec::new()));
        let first_release = Arc::new(tokio::sync::Notify::new());
        let last_release = Arc::new(tokio::sync::Notify::new());
        let mut builder = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .without_builtin_handlers()
            .handler(
                prefix.clone(),
                Arc::new(SerialProbeHandler {
                    release: Some(first_release),
                    ..serial_probe("first", Vec::new(), calls.clone(), order.clone())
                }),
            );
        for _ in 1..MAX_CONCURRENT_GETNEXT_PROBES {
            builder = builder.handler(
                prefix.clone(),
                Arc::new(serial_probe(
                    "fast",
                    Vec::new(),
                    calls.clone(),
                    order.clone(),
                )),
            );
        }
        builder = builder.handler(
            prefix.clone(),
            Arc::new(SerialProbeHandler {
                release: Some(last_release),
                ..serial_probe("last", Vec::new(), calls.clone(), order.clone())
            }),
        );
        let agent = builder.allow_all_access().build().await.unwrap();
        let task = tokio::spawn(async move { agent.get_next_oid(&test_ctx(), &prefix).await });

        tokio::time::timeout(Duration::from_secs(1), async {
            while calls.load(Ordering::SeqCst) <= MAX_CONCURRENT_GETNEXT_PROBES {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            calls.load(Ordering::SeqCst),
            MAX_CONCURRENT_GETNEXT_PROBES + 1
        );
        assert!(!task.is_finished());

        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    }

    #[tokio::test]
    async fn get_bulk_repeats_bounded_handler_probes_for_each_step() {
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
        let ctx = crate::test_support::request_context(PduType::GetBulkRequest);
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
        assert_eq!(order.lock().unwrap().len(), 6);
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
        let ctx = crate::test_support::community_request_context(
            crate::CommunityVersion::V1,
            PduType::GetRequest,
        );

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
        let ctx = crate::test_support::request_context(PduType::GetNextRequest);

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
        let ctx = crate::test_support::request_context(PduType::GetBulkRequest);

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

        let ctx = crate::test_support::with_vacm_views(
            crate::test_support::request_context(PduType::GetBulkRequest),
            Bytes::from_static(b"restricted"),
            Bytes::new(),
        );

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

        let ctx = crate::test_support::with_vacm_views(
            crate::test_support::request_context(PduType::GetBulkRequest),
            Bytes::from_static(b"restricted"),
            Bytes::new(),
        );

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

        let ctx = crate::test_support::with_vacm_views(
            crate::test_support::request_context(PduType::GetNextRequest),
            Bytes::from_static(b"restricted"),
            Bytes::new(),
        );

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
        let ctx = crate::test_support::community_request_context(
            crate::CommunityVersion::V1,
            PduType::GetNextRequest,
        );
        let pdu = Pdu::get_next_request(1, &[oid!(1, 3, 6, 1, 4, 1, 99999)]);

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();
        assert_eq!(response.error_status(), ErrorStatus::GenErr.as_i32());
        assert_eq!(response.error_index(), 1);
        assert_eq!(calls.load(Ordering::SeqCst), MAX_GETNEXT_SKIP_ITERATIONS);
    }

    #[tokio::test]
    async fn test_v1_counter64_skip_reaching_actual_eom_is_not_cap_failure() {
        let (agent, calls) = counter64_range_agent(false).await;
        let ctx = crate::test_support::community_request_context(
            crate::CommunityVersion::V1,
            PduType::GetNextRequest,
        );
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

        let ctx = crate::test_support::with_vacm_views(
            crate::test_support::request_context(PduType::GetNextRequest),
            Bytes::from_static(b"gap"),
            Bytes::new(),
        );

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

        let ctx = crate::test_support::with_vacm_views(
            crate::test_support::request_context(PduType::GetNextRequest),
            Bytes::from_static(b"restricted"),
            Bytes::new(),
        );

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

        let ctx = crate::test_support::request_context(PduType::GetBulkRequest);

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

        let ctx = crate::test_support::community_request_context(
            crate::CommunityVersion::V1,
            PduType::GetBulkRequest,
        );

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

        let ctx = crate::test_support::community_request_context(
            crate::CommunityVersion::V1,
            PduType::GetRequest,
        );

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

        // First, get the full response with the largest UDP msgMaxSize.
        let ctx_unlimited = crate::test_support::usm_request_context_with(
            Bytes::from_static(b"user"),
            SecurityLevel::NoAuthNoPriv,
            Bytes::new(),
            "127.0.0.1:12345".parse().unwrap(),
            1,
            PduType::GetBulkRequest,
            65_507,
        );

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
        let ctx_limited = crate::test_support::usm_request_context_with(
            Bytes::from_static(b"user"),
            SecurityLevel::NoAuthNoPriv,
            Bytes::new(),
            "127.0.0.1:12345".parse().unwrap(),
            1,
            PduType::GetBulkRequest,
            150,
        );

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
            RESPONSE_OVERHEAD + v2c.security_name().len()
        );

        let username = Bytes::from_static(b"user");
        let variable = 2 * engine_id.len() + username.len(); // context name empty

        let noauth = crate::test_support::usm_request_context(
            SecurityLevel::NoAuthNoPriv,
            PduType::GetRequest,
        );
        assert_eq!(
            agent.response_overhead(&noauth),
            RESPONSE_OVERHEAD + variable
        );

        let authnopriv = crate::test_support::usm_request_context(
            SecurityLevel::AuthNoPriv,
            PduType::GetRequest,
        );
        assert_eq!(
            agent.response_overhead(&authnopriv),
            RESPONSE_OVERHEAD + variable + V3_AUTH_OVERHEAD
        );

        let authpriv =
            crate::test_support::usm_request_context(SecurityLevel::AuthPriv, PduType::GetRequest);
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
        let long = crate::test_support::community_request_context_with(
            crate::CommunityVersion::V2c,
            crate::Community::from(vec![b'x'; 200]),
            "127.0.0.1:12345".parse().unwrap(),
            1,
            PduType::GetRequest,
        );

        assert_eq!(
            agent.response_overhead(&long) - agent.response_overhead(&short),
            long.security_name().len() - short.security_name().len()
        );
    }

    #[tokio::test]
    async fn test_getbulk_authpriv_budgets_for_wrapper() {
        // For the same effective response limit, an authPriv v3 request must
        // reserve more space for the USM/scopedPDU wrapper than a v2c request,
        // so it fits strictly fewer varbinds. Under the old fixed overhead both
        // budgeted identically and the authPriv Response could exceed the limit.
        let limit = 200;
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .max_message_size(limit)
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
        let v2c = crate::test_support::request_context(PduType::GetBulkRequest);
        let v2c_count = agent
            .dispatch_request(&v2c, &pdu)
            .await
            .unwrap()
            .varbinds
            .iter()
            .filter(|vb| !matches!(vb.value, Value::EndOfMibView))
            .count();

        let authpriv = crate::test_support::usm_request_context_with(
            Bytes::from_static(b"user"),
            SecurityLevel::AuthPriv,
            Bytes::new(),
            "127.0.0.1:12345".parse().unwrap(),
            1,
            PduType::GetBulkRequest,
            limit,
        );
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

        let ctx = crate::test_support::usm_request_context_with(
            Bytes::from_static(b"user"),
            SecurityLevel::NoAuthNoPriv,
            Bytes::new(),
            "127.0.0.1:12345".parse().unwrap(),
            1,
            PduType::GetBulkRequest,
            max,
        );

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

        // Below RESPONSE_OVERHEAD, so even the first varbind cannot fit.
        let ctx = crate::test_support::usm_request_context_with(
            Bytes::from_static(b"user"),
            SecurityLevel::NoAuthNoPriv,
            Bytes::new(),
            "127.0.0.1:12345".parse().unwrap(),
            1,
            PduType::GetBulkRequest,
            RESPONSE_OVERHEAD - 1,
        );

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

        let ctx = crate::test_support::usm_request_context_with(
            Bytes::from_static(b"user"),
            SecurityLevel::NoAuthNoPriv,
            Bytes::new(),
            "127.0.0.1:12345".parse().unwrap(),
            1,
            PduType::GetBulkRequest,
            max,
        );

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

        let ctx = crate::test_support::request_context(PduType::GetBulkRequest);

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

        let ctx = crate::test_support::community_request_context(
            crate::CommunityVersion::V1,
            PduType::GetNextRequest,
        );

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

        assert_eq!(agent.engine_boots_time().unwrap().0, 1);
        assert_eq!(agent.engine_id(), b"test-agent-engine");
    }

    #[tokio::test]
    async fn authoritative_persistence_health_coalesces_failures_and_recovers() {
        let calls = Arc::new(AtomicUsize::new(0));
        let callback_calls = Arc::clone(&calls);
        let engine = AuthoritativeEngine::install(b"health-agent-engine".to_vec(), move |_| {
            match callback_calls.fetch_add(1, Ordering::Relaxed) {
                0 | 3.. => Ok(()),
                _ => Err(std::io::Error::other("persistence unavailable")),
            }
        })
        .unwrap();
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .authoritative_engine(engine.clone())
            .allow_all_access()
            .build()
            .await
            .unwrap();
        let mut health = agent.subscribe_health();
        engine.set_elapsed_for_test(u64::from(crate::v3::MAX_ENGINE_TIME) + 1);

        assert_eq!(agent.health(), AgentHealth::Healthy);
        assert_eq!(
            agent.engine_boots_time().unwrap_err().kind(),
            crate::ErrorKind::AuthoritativeEnginePersistence
        );
        assert_eq!(
            agent.engine_boots_time().unwrap_err().kind(),
            crate::ErrorKind::AuthoritativeEnginePersistence
        );
        assert!(health.has_changed().unwrap());
        assert!(matches!(
            agent.health(),
            AgentHealth::AuthoritativePersistenceDegraded {
                consecutive_failures: 2,
                operation: crate::AuthoritativeEnginePersistenceOperation::EngineTimeRollover,
                previous_engine_boots: Some(1),
                attempted_engine_boots: 2,
            }
        ));
        health.borrow_and_update();
        assert!(!health.has_changed().unwrap());

        assert_eq!(agent.engine_boots_time().unwrap(), (2, 0));
        health.changed().await.unwrap();
        assert_eq!(*health.borrow_and_update(), AgentHealth::Healthy);
        assert_eq!(agent.health(), AgentHealth::Healthy);
    }

    #[tokio::test]
    async fn persistence_outage_fails_v3_closed_while_community_requests_continue() {
        let calls = Arc::new(AtomicUsize::new(0));
        let callback_calls = Arc::clone(&calls);
        let engine = AuthoritativeEngine::install(b"mixed-agent-engine".to_vec(), move |_| {
            if callback_calls.fetch_add(1, Ordering::Relaxed) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::other("persistence unavailable"))
            }
        })
        .unwrap();
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .usm_user("user", Ok)
            .unwrap()
            .authoritative_engine(engine.clone())
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), Arc::new(TestHandler))
            .without_builtin_handlers()
            .allow_all_access()
            .build()
            .await
            .unwrap();
        engine.set_elapsed_for_test(u64::from(crate::v3::MAX_ENGINE_TIME) + 1);

        let discovery =
            crate::message::V3Message::discovery_request(9, crate::UDP_RECEIVE_LIMITS.advertised())
                .unwrap()
                .encode()
                .unwrap();
        let source = "127.0.0.1:9999".parse().unwrap();
        assert_eq!(
            agent
                .handle_request(discovery.clone(), source)
                .await
                .unwrap_err()
                .kind(),
            crate::ErrorKind::AuthoritativeEnginePersistence
        );

        for version in [Version::V1, Version::V2c] {
            let community_version = match version {
                Version::V1 => crate::CommunityVersion::V1,
                Version::V2c => crate::CommunityVersion::V2c,
                Version::V3 => unreachable!(),
            };
            let request = crate::message::CommunityMessage::new(
                community_version,
                Bytes::from_static(b"public"),
                Pdu::get_request(7, &[oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0)]),
            )
            .unwrap()
            .encode()
            .unwrap();
            assert!(
                agent
                    .handle_request(request, source)
                    .await
                    .unwrap()
                    .is_some(),
                "{version:?} service stopped during V3 persistence outage"
            );
        }

        assert_eq!(
            agent
                .handle_request(discovery, source)
                .await
                .unwrap_err()
                .kind(),
            crate::ErrorKind::AuthoritativeEnginePersistence
        );
        assert!(matches!(
            agent.health(),
            AgentHealth::AuthoritativePersistenceDegraded {
                consecutive_failures: 2,
                ..
            }
        ));
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
            .usm_user("user", Ok)
            .unwrap()
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
    async fn duplicate_vacm_access_rows_are_rejected_before_bind() {
        let result = Agent::builder()
            .bind("not a socket address")
            .community(b"public")
            .vacm(|vacm| {
                vacm.access(
                    "group",
                    SecurityModel::V2c,
                    SecurityLevel::NoAuthNoPriv,
                    |entry| entry.read_view("first"),
                )
                .access(
                    "group",
                    SecurityModel::V2c,
                    SecurityLevel::NoAuthNoPriv,
                    |entry| entry.context_match_prefix().read_view("duplicate"),
                )
            })
            .build()
            .await;
        let error = result.err().expect("duplicate access row must fail");
        assert!(matches!(
            *error,
            Error::Config(ref message) if message.contains("duplicate VACM access entry")
        ));
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
            .usm_user("user", Ok)
            .unwrap()
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
            .trap_sink(
                NotificationSinkId::new("v3-sink").unwrap(),
                "127.0.0.1:162",
                crate::Auth::usm("trapuser"),
            )
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
    async fn test_invalid_bind_precedes_authoritative_engine_persistence() {
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
        assert!(matches!(
            *err,
            Error::Config(ref message) if message.contains("invalid bind address")
        ));
    }

    #[tokio::test]
    async fn test_authoritative_engine_persistence_failure_releases_socket() {
        let reservation = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bind_addr = reservation.local_addr().unwrap();
        drop(reservation);
        let engine = AuthoritativeEngine::with_rollover_persistence_failure_for_test(
            b"test-agent-engine".to_vec(),
        );

        let error = Agent::builder()
            .bind(bind_addr.to_string())
            .community(b"public")
            .authoritative_engine(engine)
            .allow_all_access()
            .build()
            .await
            .err()
            .expect("authoritative persistence must fail");

        assert_eq!(
            error.kind(),
            crate::ErrorKind::AuthoritativeEnginePersistence
        );
        let persistence = error
            .authoritative_engine_persistence()
            .expect("Agent must preserve the persistence failure");
        assert_eq!(
            persistence.operation(),
            crate::AuthoritativeEnginePersistenceOperation::EngineTimeRollover
        );
        assert_eq!(persistence.previous_engine_boots(), Some(1));
        assert_eq!(persistence.attempted_engine_boots(), 2);
        assert_eq!(
            persistence
                .downcast_source_ref::<std::io::Error>()
                .expect("concrete callback error")
                .kind(),
            std::io::ErrorKind::Other
        );
        assert!(error.to_string().contains("storage unavailable"));
        let _rebound = UdpSocket::bind(bind_addr).await.unwrap();
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
            .usm_user("", Ok)
            .unwrap()
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
    async fn invalid_response_send_timeout_precedes_bind() {
        let error = Agent::builder()
            .bind("not a socket address")
            .response_send_timeout(Duration::MAX)
            .build()
            .await
            .err()
            .expect("invalid timeout must fail");
        assert!(matches!(
            *error,
            Error::Config(ref message) if message.contains("response send timeout")
        ));
    }

    #[tokio::test]
    async fn invalid_construction_timeout_precedes_bind_and_resolution() {
        let error = Agent::builder()
            .bind("not a socket address")
            .construction_timeout(Duration::MAX)
            .trap_sink(
                NotificationSinkId::new("never-resolved").unwrap(),
                "sink.example:162",
                crate::Auth::v2c("public"),
            )
            .build_with_dependencies(
                |_, _| async { panic!("socket binder must not run") },
                |_, _| async { panic!("resolver must not run") },
                || panic!("engine ID generator must not run"),
                || panic!("salt generator must not run"),
            )
            .await
            .err()
            .expect("invalid construction timeout must fail");

        assert!(matches!(
            *error,
            Error::Config(ref message) if message.contains("agent construction timeout")
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn one_agent_construction_deadline_spans_all_sink_dns() {
        let calls = Arc::new(AtomicUsize::new(0));
        let resolver_calls = Arc::clone(&calls);
        let error = Agent::builder()
            .bind("127.0.0.1:0")
            .construction_timeout(Duration::from_millis(100))
            .trap_sink(
                NotificationSinkId::new("first").unwrap(),
                "first.example:162",
                crate::Auth::v2c("public"),
            )
            .trap_sink(
                NotificationSinkId::new("second").unwrap(),
                "second.example:162",
                crate::Auth::v2c("public"),
            )
            .build_with_dependencies(
                |addr, recv_buffer_size| bind_udp_socket(addr, recv_buffer_size, None, false),
                move |_, _| {
                    let calls = Arc::clone(&resolver_calls);
                    async move {
                        calls.fetch_add(1, Ordering::Relaxed);
                        tokio::time::sleep(Duration::from_millis(60)).await;
                        Ok(vec!["127.0.0.1:162".parse().unwrap()])
                    }
                },
                || Ok(Bytes::from_static(b"generated-engine")),
                || panic!("privacy salt must not be created"),
            )
            .await
            .err()
            .expect("aggregate DNS deadline must expire");

        assert_eq!(calls.load(Ordering::Relaxed), 2);
        assert!(matches!(
            *error,
            Error::AgentConstructionTimeout {
                stage: ConstructionStage::Resolve,
                sink_index: Some(1),
                ref sink_destination,
                ..
            } if sink_destination.as_deref() == Some("second.example:162")
        ));
    }

    fn unavailable_engine_id() -> Result<Bytes> {
        Err(Error::RandomSource {
            source: getrandom::Error::UNEXPECTED,
        }
        .boxed())
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    fn unavailable_salt_counter() -> Result<SaltCounter> {
        Err(Error::RandomSource {
            source: getrandom::Error::UNEXPECTED,
        }
        .boxed())
    }

    #[tokio::test]
    async fn deterministic_validation_precedes_invalid_bind_and_dependencies() {
        let error = Agent::builder()
            .bind("not a socket address")
            .max_concurrent_requests(Some(0))
            .trap_sink(
                NotificationSinkId::new("resolver-must-not-run").unwrap(),
                "unresolvable.invalid:162",
                crate::Auth::v2c("public"),
            )
            .build_with_dependencies(
                |_, _| async { panic!("socket binder must not run") },
                |_, _| async { panic!("resolver must not run") },
                || panic!("engine ID generator must not run"),
                || panic!("salt generator must not run"),
            )
            .await
            .err()
            .expect("deterministic configuration must fail");

        assert!(matches!(
            *error,
            Error::Config(ref message)
                if message.as_ref() == "max_concurrent_requests must be greater than 0"
        ));
    }

    #[tokio::test]
    async fn invalid_inform_timeout_precedes_occupied_bind() {
        let occupied = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let occupied_addr = occupied.local_addr().unwrap();

        let error = Agent::builder()
            .bind(occupied_addr.to_string())
            .inform_timeout(Duration::MAX)
            .build()
            .await
            .err()
            .expect("unrepresentable inform timeout must fail");

        assert!(matches!(
            *error,
            Error::Config(ref message) if message.contains("inform timeout")
        ));
    }

    #[tokio::test]
    async fn invalid_sink_address_precedes_occupied_bind_without_socket_attempt() {
        let occupied = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let occupied_addr = occupied.local_addr().unwrap();
        let bind_calls = Arc::new(AtomicUsize::new(0));
        let bind_calls_for_builder = Arc::clone(&bind_calls);

        let error = Agent::builder()
            .bind(occupied_addr.to_string())
            .trap_sink(
                NotificationSinkId::new("invalid").unwrap(),
                "missing-port",
                crate::Auth::v2c("public"),
            )
            .build_with_dependencies(
                move |addr, recv_buffer_size| {
                    bind_calls_for_builder.fetch_add(1, Ordering::Relaxed);
                    bind_udp_socket(addr, recv_buffer_size, None, false)
                },
                |_, _| async { panic!("resolver must not run") },
                || panic!("engine ID generator must not run"),
                || panic!("salt generator must not run"),
            )
            .await
            .err()
            .expect("invalid sink address must fail");

        assert!(matches!(
            *error,
            Error::Config(ref message)
                if message.as_ref() == "invalid trap sink address: missing-port"
        ));
        assert_eq!(bind_calls.load(Ordering::Relaxed), 0);
    }

    #[cfg(not(any(feature = "crypto-rustcrypto", feature = "crypto-fips")))]
    #[test]
    fn unavailable_usm_backend_is_reported_by_user_configuration() {
        let error = Agent::builder()
            .bind("127.0.0.1:0")
            .authoritative_engine(AuthoritativeEngine::for_test(
                b"test-agent-engine".to_vec(),
                1,
            ))
            .usm_user("authenticated", |user| {
                user.auth(crate::AuthProtocol::Sha256, b"authentication-password")
            })
            .err()
            .expect("user configuration must reject the unavailable backend");

        assert_eq!(error, crate::CryptoError::BackendUnavailable);
    }

    #[tokio::test]
    async fn occupied_bind_precedes_dns_and_entropy() {
        let occupied = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let occupied_addr = occupied.local_addr().unwrap();

        let error = Agent::builder()
            .bind(occupied_addr.to_string())
            .trap_sink(
                NotificationSinkId::new("unresolved").unwrap(),
                "unresolvable.invalid:162",
                crate::Auth::v2c("public"),
            )
            .build_with_dependencies(
                |addr, recv_buffer_size| bind_udp_socket(addr, recv_buffer_size, None, false),
                |_, _| async { panic!("resolver must not run after bind failure") },
                || panic!("engine ID generator must not run after bind failure"),
                || panic!("salt generator must not run after bind failure"),
            )
            .await
            .err()
            .expect("occupied bind must fail");

        assert!(matches!(
            *error,
            Error::Network { target, ref source }
                if target == occupied_addr && source.kind() == std::io::ErrorKind::AddrInUse
        ));
    }

    #[tokio::test]
    async fn dns_failure_precedes_entropy_and_releases_socket() {
        let reservation = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bind_addr = reservation.local_addr().unwrap();
        drop(reservation);

        let error = Agent::builder()
            .bind(bind_addr.to_string())
            .trap_sink(
                NotificationSinkId::new("unresolved").unwrap(),
                "unresolvable.invalid:162",
                crate::Auth::v2c("public"),
            )
            .build_with_dependencies(
                |addr, recv_buffer_size| bind_udp_socket(addr, recv_buffer_size, None, false),
                |host, _| async move {
                    Err(Error::Config(format!("injected DNS failure for {host}").into()).boxed())
                },
                || panic!("engine ID generator must not run after DNS failure"),
                || panic!("salt generator must not run after DNS failure"),
            )
            .await
            .err()
            .expect("injected DNS resolution must fail");

        assert!(error.to_string().contains("injected DNS failure"));
        let _rebound = UdpSocket::bind(bind_addr).await.unwrap();
    }

    #[tokio::test]
    async fn engine_id_entropy_failure_releases_socket() {
        let reservation = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bind_addr = reservation.local_addr().unwrap();
        drop(reservation);

        let error = Agent::builder()
            .bind(bind_addr.to_string())
            .build_with_dependencies(
                |addr, recv_buffer_size| bind_udp_socket(addr, recv_buffer_size, None, false),
                |_, _| async { panic!("resolver must not run") },
                unavailable_engine_id,
                || panic!("salt generator must not run after engine entropy failure"),
            )
            .await
            .err()
            .expect("injected engine entropy must fail");

        assert_eq!(error.kind(), crate::ErrorKind::RandomSource);
        let _rebound = UdpSocket::bind(bind_addr).await.unwrap();
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[tokio::test]
    async fn privacy_salt_entropy_failure_releases_socket() {
        let reservation = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bind_addr = reservation.local_addr().unwrap();
        drop(reservation);

        let error = Agent::builder()
            .bind(bind_addr.to_string())
            .authoritative_engine(AuthoritativeEngine::for_test(
                b"test-agent-engine".to_vec(),
                1,
            ))
            .usm_user("private", |user| {
                user.auth_priv(
                    crate::AuthProtocol::Sha256,
                    b"authentication-password",
                    crate::PrivProtocol::Aes128,
                    b"privacy-password",
                )
            })
            .unwrap()
            .allow_all_access()
            .build_with_dependencies(
                |addr, recv_buffer_size| bind_udp_socket(addr, recv_buffer_size, None, false),
                |_, _| async { panic!("resolver must not run") },
                || panic!("configured engine must avoid engine ID generation"),
                unavailable_salt_counter,
            )
            .await
            .err()
            .expect("injected salt entropy must fail");

        assert_eq!(error.kind(), crate::ErrorKind::RandomSource);
        let _rebound = UdpSocket::bind(bind_addr).await.unwrap();
    }

    fn validated_numeric_trap_sink(bind: &str, destination: SocketAddr) -> Result<SocketAddr> {
        let config = Agent::builder()
            .bind(bind)
            .trap_sink(
                NotificationSinkId::new("numeric").unwrap(),
                destination.to_string(),
                crate::Auth::v2c("public"),
            )
            .validate_and_normalize()?;
        let target = &config.trap_sinks[0].target;
        let TrapSinkTarget::Address(address) = target else {
            panic!("numeric destination must remain an address");
        };
        Ok(*address)
    }

    #[test]
    fn numeric_trap_sinks_follow_udp_bind_family_normalization() {
        let ipv4: SocketAddr = "192.0.2.1:1161".parse().unwrap();
        let mapped: SocketAddr = "[::ffff:192.0.2.2]:1162".parse().unwrap();
        let native_v6 = SocketAddr::V6(std::net::SocketAddrV6::new(
            "fe80::1".parse().unwrap(),
            1163,
            0,
            7,
        ));

        assert_eq!(
            validated_numeric_trap_sink("127.0.0.1:0", ipv4).unwrap(),
            ipv4
        );
        assert_eq!(
            validated_numeric_trap_sink("127.0.0.1:0", mapped).unwrap(),
            "192.0.2.2:1162".parse().unwrap()
        );
        let error = validated_numeric_trap_sink("127.0.0.1:0", native_v6)
            .expect_err("native IPv6 sink must be rejected for an IPv4 bind");
        assert!(error.to_string().contains("incompatible with IPv4 socket"));

        assert_eq!(
            validated_numeric_trap_sink("[::]:0", ipv4).unwrap(),
            "[::ffff:192.0.2.1]:1161".parse().unwrap()
        );
        assert_eq!(
            validated_numeric_trap_sink("[::]:0", mapped).unwrap(),
            mapped
        );
        assert_eq!(
            validated_numeric_trap_sink("[::]:0", native_v6).unwrap(),
            native_v6,
            "native IPv6 scope must be preserved"
        );
    }

    async fn agent_with_resolved_trap_sink(
        bind: &str,
        candidates: Vec<SocketAddr>,
    ) -> Result<Agent> {
        Agent::builder()
            .bind(bind)
            .trap_sink(
                NotificationSinkId::new("hostname").unwrap(),
                "sink.example:162",
                crate::Auth::v2c("public"),
            )
            .build_with_dependencies(
                |addr, recv_buffer_size| bind_udp_socket(addr, recv_buffer_size, None, false),
                move |host, port| {
                    let candidates = candidates.clone();
                    async move {
                        assert_eq!(host, "sink.example");
                        assert_eq!(port, 162);
                        Ok(candidates)
                    }
                },
                || Ok(Bytes::from_static(b"generated-engine")),
                || panic!("privacy salt must not be created"),
            )
            .await
    }

    #[tokio::test]
    async fn resolved_trap_sinks_follow_udp_bind_family_normalization() {
        let ipv4: SocketAddr = "192.0.2.1:1161".parse().unwrap();
        let mapped: SocketAddr = "[::ffff:192.0.2.2]:1162".parse().unwrap();
        let native_v6 = SocketAddr::V6(std::net::SocketAddrV6::new(
            "fe80::1".parse().unwrap(),
            1163,
            9,
            7,
        ));

        let agent = agent_with_resolved_trap_sink("127.0.0.1:0", vec![ipv4])
            .await
            .unwrap();
        assert_eq!(agent.inner.trap_sinks[0].summary.dest(), ipv4);

        let agent = agent_with_resolved_trap_sink("127.0.0.1:0", vec![mapped])
            .await
            .unwrap();
        assert_eq!(
            agent.inner.trap_sinks[0].summary.dest(),
            "192.0.2.2:1162".parse().unwrap()
        );

        let error = agent_with_resolved_trap_sink("127.0.0.1:0", vec![native_v6])
            .await
            .err()
            .expect("native IPv6 sink must be rejected for an IPv4 bind");
        assert!(error.to_string().contains("no address resolved"));

        let agent = agent_with_resolved_trap_sink("[::]:0", vec![ipv4])
            .await
            .unwrap();
        assert_eq!(
            agent.inner.trap_sinks[0].summary.dest(),
            "[::ffff:192.0.2.1]:1161".parse().unwrap()
        );

        let agent = agent_with_resolved_trap_sink("[::]:0", vec![mapped])
            .await
            .unwrap();
        assert_eq!(agent.inner.trap_sinks[0].summary.dest(), mapped);

        let agent = agent_with_resolved_trap_sink("[::]:0", vec![native_v6])
            .await
            .unwrap();
        assert_eq!(
            agent.inner.trap_sinks[0].summary.dest(),
            native_v6,
            "native IPv6 flow information and scope must be preserved"
        );
    }

    #[tokio::test]
    async fn resolved_trap_sink_uses_first_normalizable_candidate_in_order() {
        let incompatible: SocketAddr = "[2001:db8::1]:1161".parse().unwrap();
        let first_compatible: SocketAddr = "[::ffff:192.0.2.2]:1162".parse().unwrap();
        let later_compatible: SocketAddr = "192.0.2.3:1163".parse().unwrap();

        let agent = agent_with_resolved_trap_sink(
            "127.0.0.1:0",
            vec![incompatible, first_compatible, later_compatible],
        )
        .await
        .unwrap();
        assert_eq!(
            agent.inner.trap_sinks[0].summary.dest(),
            "192.0.2.2:1162".parse().unwrap()
        );

        let agent = agent_with_resolved_trap_sink("[::]:0", vec![later_compatible, incompatible])
            .await
            .unwrap();
        assert_eq!(
            agent.inner.trap_sinks[0].summary.dest(),
            "[::ffff:192.0.2.3]:1163".parse().unwrap(),
            "IPv6 binds must retain resolver order even when a later native IPv6 candidate exists"
        );
    }

    #[tokio::test]
    async fn trap_sink_resolution_preserves_sink_vector_and_index_order() {
        let resolver_calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let resolver_calls_for_builder = Arc::clone(&resolver_calls);
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .trap_sink(
                NotificationSinkId::new("numeric-mapped").unwrap(),
                "[::ffff:192.0.2.10]:1162",
                crate::Auth::v2c("public"),
            )
            .trap_sink(
                NotificationSinkId::new("resolved").unwrap(),
                "first.example:162",
                crate::Auth::v2c("public"),
            )
            .trap_sink(
                NotificationSinkId::new("numeric-v4").unwrap(),
                "192.0.2.30:1162",
                crate::Auth::v2c("public"),
            )
            .trap_sink(
                NotificationSinkId::new("mapped").unwrap(),
                "second.example:162",
                crate::Auth::v2c("public"),
            )
            .build_with_dependencies(
                |addr, recv_buffer_size| bind_udp_socket(addr, recv_buffer_size, None, false),
                move |host, port| {
                    resolver_calls_for_builder
                        .lock()
                        .unwrap()
                        .push(host.clone());
                    async move {
                        assert_eq!(port, 162);
                        match host.as_str() {
                            "first.example" => Ok(vec![
                                "[2001:db8::1]:1162".parse().unwrap(),
                                "192.0.2.20:1162".parse().unwrap(),
                            ]),
                            "second.example" => {
                                Ok(vec!["[::ffff:192.0.2.40]:1162".parse().unwrap()])
                            }
                            _ => panic!("unexpected resolver host: {host}"),
                        }
                    }
                },
                || Ok(Bytes::from_static(b"generated-engine")),
                || panic!("privacy salt must not be created"),
            )
            .await
            .unwrap();

        assert_eq!(
            *resolver_calls.lock().unwrap(),
            ["first.example", "second.example"]
        );
        let summaries: Vec<_> = agent.notification_sinks().collect();
        assert_eq!(summaries.len(), 4);
        for (expected_index, summary) in summaries.iter().enumerate() {
            assert_eq!(summary.index(), expected_index);
        }
        assert_eq!(summaries[0].id().as_bytes(), b"numeric-mapped");
        assert_eq!(summaries[0].dest(), "192.0.2.10:1162".parse().unwrap());
        assert_eq!(summaries[1].id().as_bytes(), b"resolved");
        assert_eq!(summaries[1].dest(), "192.0.2.20:1162".parse().unwrap());
        assert_eq!(summaries[2].id().as_bytes(), b"numeric-v4");
        assert_eq!(summaries[2].dest(), "192.0.2.30:1162".parse().unwrap());
        assert_eq!(summaries[3].id().as_bytes(), b"mapped");
        assert_eq!(summaries[3].dest(), "192.0.2.40:1162".parse().unwrap());
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

        assert_eq!(agent.engine_boots_time().unwrap().0, 1);
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
        let community_version = match version {
            Version::V1 => crate::CommunityVersion::V1,
            Version::V2c => crate::CommunityVersion::V2c,
            Version::V3 => unreachable!(),
        };
        let request =
            crate::message::CommunityMessage::new(community_version, b"public".as_slice(), pdu)
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
        crate::message::CommunityMessage::decode(bytes, crate::DecodeConfig::default())
            .unwrap()
            .value
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
        let pdu = NotificationPdu::inform(
            Version::V2c,
            1,
            0,
            &oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1),
            vec![VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0), big)],
        )
        .unwrap()
        .into_raw();

        let response = finalized_community_response(&agent, Version::V2c, pdu).await;
        assert_eq!(response.error_status(), ErrorStatus::TooBig.as_i32());
        assert_eq!(response.error_index(), 0);
        assert!(response.varbinds.is_empty());
    }

    #[tokio::test]
    async fn test_inform_within_limit_echoes_varbinds() {
        let agent = small_limit_agent().await;
        let ctx = crate::test_support::request_context(PduType::InformRequest);

        // A small Inform fits within the limit and is acknowledged by echoing
        // the same varbinds in a Response.
        let pdu = NotificationPdu::inform(
            Version::V2c,
            7,
            0,
            &oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1),
            vec![VarBind::new(
                oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0),
                Value::Integer(42),
            )],
        )
        .unwrap()
        .into_raw();

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();
        assert_eq!(response.pdu_type(), PduType::Response);
        assert_eq!(response.error_status(), 0);
        assert_eq!(response.request_id, 7);
        assert_eq!(response.varbinds.len(), 3);
        assert!(matches!(response.varbinds[2].value, Value::Integer(42)));
    }

    #[tokio::test]
    async fn test_getnext_within_limit_returns_response() {
        let agent = small_limit_agent().await;
        let ctx = crate::test_support::request_context(PduType::GetNextRequest);

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
