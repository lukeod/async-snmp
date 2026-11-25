//! Agent notification sending (trap/inform).
//!
//! Provides notification sink configuration and methods for sending notifications
//! from an agent to configured destinations.

use std::fmt;
use std::fmt::Write;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use futures_core::stream::{FusedStream, Stream};
use futures_util::stream::FuturesUnordered;
use tokio::sync::Mutex as AsyncMutex;

use crate::Community;
use crate::RequestTransport;
use crate::client::{Auth, Client, ClientConfig, Retry};
use crate::error::{Error, Result};
use crate::handler::SecurityModel;
use crate::message::{CommunityMessage, SecurityLevel};
use crate::oid::Oid;
use crate::pdu::NotificationPdu;
use crate::transport::BuiltinTransport;
use crate::v3::{DerivedKeys, UsmConfig};
use crate::varbind::VarBind;
use crate::version::{CommunityVersion, Version};

/// Transport route for an [agent notification sink](super::AgentBuilder::notification_sink).
///
/// # Choose a route
///
/// | Use case | Constructor |
/// | --- | --- |
/// | Send through the UDP socket that serves commands. | [`Self::shared_udp`] |
/// | Use a separate UDP source address, port, or socket configuration. | [`Self::udp`] |
/// | Connect to a TCP receiver during agent preparation or hand over a connected stream. | [`Self::tcp`] |
/// | Reuse an already prepared UDP peer or TCP session. | [`Self::peer`] |
///
/// The agent prepares and drives dedicated UDP and TCP sinks. Shared UDP sinks
/// enable exchanges on the selected listener automatically. If you reuse a peer
/// from a shared application service, enable client exchanges on that service
/// before preparation to receive Inform acknowledgements.
///
/// For a TCP session accepted after startup, select it through
/// [`crate::Agent::notification_peer`] and send directly through the returned handle.
///
/// ```rust
/// use async_snmp::{NotificationTarget, TcpTransport, UdpEndpoint, UdpHandle};
///
/// fn routes(existing: UdpHandle) -> [NotificationTarget; 4] {
///     [
///         NotificationTarget::shared_udp(0, "192.0.2.10:162"),
///         NotificationTarget::udp(
///             UdpEndpoint::builder().bind("0.0.0.0:1162"),
///             "192.0.2.20:162",
///         ),
///         NotificationTarget::tcp(
///             TcpTransport::builder().target("192.0.2.30:162".parse().unwrap()),
///         ),
///         NotificationTarget::peer(existing),
///     ]
/// }
/// ```
pub enum NotificationTarget {
    /// Reuse the UDP listener at this zero-based position in configured listener order.
    /// With the default `bind` configuration its index is zero.
    SharedUdp {
        listener: usize,
        destination: String,
    },
    /// Prepare a separate UDP endpoint, supervised by the Agent runner.
    Udp {
        endpoint: crate::UdpEndpointBuilder,
        destination: String,
    },
    /// Prepare an originator-initiated or supplied connected TCP session.
    Tcp(crate::TcpTransportBuilder),
    /// Select this exact existing peer. Its owner accounts for receive capacity
    /// when the peer serves the Agent's engine.
    Peer(BuiltinTransport),
}
impl NotificationTarget {
    /// Select a UDP listener by its position in the Agent listener configuration.
    /// Index zero selects the default `bind` endpoint. Non-UDP or missing indices
    /// fail preparation. Hostname resolution uses the selected socket's
    /// address family. Both traps and Informs use its bound source port.
    pub fn shared_udp(listener: usize, destination: impl Into<String>) -> Self {
        Self::SharedUdp {
            listener,
            destination: destination.into(),
        }
    }
    /// Prepare a separate UDP endpoint from bind configuration or an owned socket.
    /// `destination` includes a port and may contain a hostname. The Agent runner
    /// drives this endpoint for client exchanges.
    pub fn udp(endpoint: crate::UdpEndpointBuilder, destination: impl Into<String>) -> Self {
        Self::Udp {
            endpoint,
            destination: destination.into(),
        }
    }
    /// Prepare one TCP session using the supplied target, socket or connected stream.
    /// Target configuration connects during preparation. The Agent runner drives
    /// the session. If it closes, the configured sink fails delivery. To send
    /// over a new session, use [`crate::Agent::notification_peer`] or prepare a new agent.
    pub fn tcp(session: crate::TcpTransportBuilder) -> Self {
        Self::Tcp(session)
    }
    /// Reuse an existing UDP peer or exact TCP session.
    /// The peer retains its own service lifetime and requires its runner to be driven.
    /// Shared application services must have client exchanges enabled for Informs.
    /// When using the Agent's [`crate::LocalEngine`], the endpoint owner declares
    /// the endpoint's receive capacity on that engine.
    /// Closed peers fail delivery without reconnection or transport fallback.
    pub fn peer(peer: impl Into<BuiltinTransport>) -> Self {
        Self::Peer(peer.into())
    }
}

const MAX_NOTIFICATION_SINK_ID_LEN: usize = 32;

/// Stable caller-supplied identifier for a notification sink.
///
/// The identifier is operational metadata and is never derived from sink
/// credentials. Keep it stable across agent restarts when retaining sink
/// delivery outcomes outside the library. Configured identifiers
/// contain 1 to 32 octets, matching the `snmpTargetAddrName` size defined by
/// RFC 3413. Identifiers are opaque octets and need not contain UTF-8.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NotificationSinkId(Arc<[u8]>);

/// Error returned when a notification sink identifier has an invalid length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("notification sink ID length {length} is outside 1..=32 octets")]
pub struct NotificationSinkIdError {
    length: usize,
}

impl NotificationSinkIdError {
    /// Return the rejected identifier length in octets.
    #[must_use]
    pub const fn length(&self) -> usize {
        self.length
    }
}

impl NotificationSinkId {
    /// Create a notification sink identifier from bytes or text.
    ///
    /// Returns [`NotificationSinkIdError`] unless `id` contains 1 to 32
    /// octets. Text inputs are measured by their UTF-8 encoding.
    pub fn new(id: impl AsRef<[u8]>) -> std::result::Result<Self, NotificationSinkIdError> {
        Self::try_from(id.as_ref())
    }

    /// Return the identifier octets.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn from_arc(id: Arc<[u8]>) -> std::result::Result<Self, NotificationSinkIdError> {
        let length = id.len();
        if !(1..=MAX_NOTIFICATION_SINK_ID_LEN).contains(&length) {
            return Err(NotificationSinkIdError { length });
        }
        Ok(Self(id))
    }
}

fn write_escaped_id(bytes: &[u8], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    for &byte in bytes {
        for escaped in std::ascii::escape_default(byte) {
            f.write_char(char::from(escaped))?;
        }
    }
    Ok(())
}

impl fmt::Debug for NotificationSinkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NotificationSinkId(b\"")?;
        write_escaped_id(self.as_bytes(), f)?;
        f.write_str("\")")
    }
}

impl fmt::Display for NotificationSinkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_escaped_id(self.as_bytes(), f)
    }
}

impl AsRef<[u8]> for NotificationSinkId {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl TryFrom<&[u8]> for NotificationSinkId {
    type Error = NotificationSinkIdError;

    fn try_from(id: &[u8]) -> std::result::Result<Self, Self::Error> {
        Self::from_arc(Arc::from(id))
    }
}

impl TryFrom<Vec<u8>> for NotificationSinkId {
    type Error = NotificationSinkIdError;

    fn try_from(id: Vec<u8>) -> std::result::Result<Self, Self::Error> {
        Self::from_arc(Arc::from(id))
    }
}

impl<const N: usize> TryFrom<&[u8; N]> for NotificationSinkId {
    type Error = NotificationSinkIdError;

    fn try_from(id: &[u8; N]) -> std::result::Result<Self, Self::Error> {
        Self::try_from(id.as_slice())
    }
}

impl<const N: usize> TryFrom<[u8; N]> for NotificationSinkId {
    type Error = NotificationSinkIdError;

    fn try_from(id: [u8; N]) -> std::result::Result<Self, Self::Error> {
        Self::try_from(Vec::from(id))
    }
}

impl TryFrom<&str> for NotificationSinkId {
    type Error = NotificationSinkIdError;

    fn try_from(id: &str) -> std::result::Result<Self, Self::Error> {
        Self::try_from(id.as_bytes())
    }
}

impl TryFrom<String> for NotificationSinkId {
    type Error = NotificationSinkIdError;

    fn try_from(id: String) -> std::result::Result<Self, Self::Error> {
        Self::try_from(id.into_bytes())
    }
}

/// Credential-free description of a configured notification sink.
///
/// This summary deliberately excludes community identifiers, USM usernames,
/// context names, keys, and the original authentication configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NotificationSinkSummary {
    index: usize,
    id: NotificationSinkId,
    dest: SocketAddr,
    transport: crate::TransportKind,
    endpoint_id: crate::EndpointId,
    session_id: Option<crate::SessionId>,
    local_addr: SocketAddr,
    receive_limits: crate::ReceiveLimits,
    send_capacity: usize,
    version: Version,
    security_level: Option<SecurityLevel>,
}

impl NotificationSinkSummary {
    /// Zero-based position in sink configuration order.
    #[must_use]
    pub fn index(&self) -> usize {
        self.index
    }

    /// Stable caller-supplied sink identifier.
    #[must_use]
    pub fn id(&self) -> &NotificationSinkId {
        &self.id
    }

    /// Sink destination address.
    #[must_use]
    pub fn dest(&self) -> SocketAddr {
        self.dest
    }

    /// Selected transport protocol.
    pub fn transport(&self) -> crate::TransportKind {
        self.transport
    }
    /// Identity of the selected endpoint.
    pub fn endpoint_id(&self) -> crate::EndpointId {
        self.endpoint_id
    }
    /// Exact selected TCP session, absent for UDP.
    pub fn session_id(&self) -> Option<crate::SessionId> {
        self.session_id
    }
    /// Bound UDP address or connected TCP local address.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
    /// Advertised and accepted receive capacities for Inform exchanges.
    pub fn receive_limits(&self) -> crate::ReceiveLimits {
        self.receive_limits
    }
    /// Maximum encoded outgoing SNMP message length.
    pub fn send_capacity(&self) -> usize {
        self.send_capacity
    }

    /// SNMP version used for this sink.
    #[must_use]
    pub fn version(&self) -> Version {
        self.version
    }

    /// Configured SNMPv3 security level, or `None` for community versions.
    #[must_use]
    pub fn security_level(&self) -> Option<SecurityLevel> {
        self.security_level
    }
}

/// A configured notification destination.
///
/// Stores resolved credentials and cached keys for sending traps and informs
/// to a specific target.
pub(crate) struct TrapSink {
    peer: BuiltinTransport,
    pub(crate) summary: NotificationSinkSummary,
    auth: Auth,
    pub(crate) community: Community,
    pub(crate) v3_security: Option<UsmConfig>,
    /// Keys derived against the agent's `engine_id` for V3 trap sending.
    /// Lazily populated on first use.
    pub(crate) derived_keys: RwLock<Option<DerivedKeys>>,
    /// Timeout for each unconfirmed trap message send.
    trap_send_timeout: Duration,
    /// Inform request timeout and retry policy.
    inform_timeout: Duration,
    inform_retry: Retry,
    /// Cached client for inform sending. Lazily created on first inform.
    inform_client: AsyncMutex<Option<Client<BuiltinTransport>>>,
}

impl TrapSink {
    /// Create from an Auth configuration and resolved destination address.
    pub(crate) fn new(
        index: usize,
        id: NotificationSinkId,
        peer: BuiltinTransport,
        auth: Auth,
        trap_send_timeout: Duration,
        inform_timeout: Duration,
        inform_retry: Retry,
    ) -> Self {
        let sink_auth = auth.clone();
        let summary = NotificationSinkSummary {
            index,
            id,
            dest: peer.peer_addr(),
            transport: peer.transport_kind(),
            endpoint_id: peer.endpoint_id(),
            session_id: peer.session_id(),
            local_addr: peer.local_addr(),
            receive_limits: peer.receive_limits(),
            send_capacity: peer.send_capacity(),
            version: auth.version(),
            security_level: match &auth {
                Auth::Community { .. } => None,
                Auth::Usm(security) => Some(security.security_level()),
            },
        };
        match auth {
            Auth::Community { community, .. } => TrapSink {
                summary,
                peer,
                auth: sink_auth,
                community: community.clone(),
                v3_security: None,
                derived_keys: RwLock::new(None),
                trap_send_timeout,
                inform_timeout,
                inform_retry,
                inform_client: AsyncMutex::new(None),
            },
            Auth::Usm(security) => TrapSink {
                summary,
                peer,
                auth: sink_auth,
                community: Community::default(),
                v3_security: Some(security),
                derived_keys: RwLock::new(None),
                trap_send_timeout,
                inform_timeout,
                inform_retry,
                inform_client: AsyncMutex::new(None),
            },
        }
    }

    fn local_ipv4_addr(&self) -> Option<[u8; 4]> {
        let local = self.summary.local_addr.ip().to_canonical();
        if let IpAddr::V4(address) = local
            && !address.is_unspecified()
        {
            return Some(address.octets());
        }
        if !local.is_unspecified() || self.summary.transport != crate::TransportKind::Udp {
            return None;
        }

        let IpAddr::V4(target) = self.summary.dest.ip().to_canonical() else {
            return None;
        };
        // Connecting a separate UDP socket selects a route without sending a
        // datagram or changing the originator endpoint's peer or source port.
        let probe = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
        let _ = probe.set_broadcast(true);
        probe.connect((target, self.summary.dest.port())).ok()?;
        match probe.local_addr().ok()?.ip() {
            IpAddr::V4(address) if !address.is_unspecified() => Some(address.octets()),
            _ => None,
        }
    }

    /// Ensure keys are derived against the given `engine_id` for V3 trap sending.
    fn ensure_keys_derived(&self, engine_id: &[u8]) -> Result<()> {
        {
            let keys = self.derived_keys.read().map_err(|_| {
                Error::Config("trap sink derived_keys lock poisoned".into()).boxed()
            })?;
            if keys.is_some() {
                return Ok(());
            }
        }

        let security = self.v3_security.as_ref().ok_or_else(|| {
            Error::Config("V3 security not configured for trap sink".into()).boxed()
        })?;

        let keys = security
            .derive_keys_inner(engine_id)
            .map_err(|e| Error::Config(e.to_string().into()).boxed())?;

        let mut derived = self
            .derived_keys
            .write()
            .map_err(|_| Error::Config("trap sink derived_keys lock poisoned".into()).boxed())?;
        *derived = Some(keys);

        Ok(())
    }

    /// Get or create the cached inform client for this sink.
    async fn get_or_create_inform_client(
        &self,
        local_engine: &crate::LocalEngine,
    ) -> Result<Client<BuiltinTransport>> {
        let mut guard = self.inform_client.lock().await;
        if let Some(ref client) = *guard {
            return Ok(client.clone());
        }

        if self.summary.version == Version::V1 {
            unreachable!("v1 does not support informs");
        }
        let config = ClientConfig {
            auth: self.auth.clone(),
            request_timeout: self.inform_timeout,
            retry: self.inform_retry.clone(),
            local_engine: Some(local_engine.clone()),
            ..ClientConfig::default()
        };

        let client = Client::for_notification_sink(self.peer.clone(), config)?;
        *guard = Some(client.clone());
        Ok(client)
    }
}

/// Reason that a configured notification sink was not attempted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SinkSkipReason {
    /// SNMPv1 does not support Inform requests.
    InformUnsupportedForV1,
    /// VACM did not resolve a notify view containing the notification.
    NotInNotifyView,
}

impl std::fmt::Display for SinkSkipReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InformUnsupportedForV1 => write!(f, "SNMPv1 does not support informs"),
            Self::NotInNotifyView => write!(f, "notification is not in the sink's notify view"),
        }
    }
}

/// Delivery status for a configured notification sink.
#[derive(Debug)]
pub enum SinkStatus {
    /// Encoding and the local socket write succeeded for a trap, or the Inform
    /// was acknowledged.
    Succeeded,
    /// The delivery attempt failed.
    Failed(Box<Error>),
    /// The configured sink could not be attempted for the stated reason.
    Skipped(SinkSkipReason),
}

/// Delivery outcome for a single configured notification sink.
///
/// For traps, success reflects encoding and the local socket write, not remote
/// receipt. For confirmed informs, success reflects the full request/response
/// exchange, including acknowledgement.
#[derive(Debug)]
pub struct SinkOutcome {
    /// Credential-free configured sink identity and protocol summary.
    pub sink: NotificationSinkSummary,
    /// The delivery status for this sink.
    pub status: SinkStatus,
    /// Accepted response deviations for an Inform exchange. Empty for traps,
    /// skipped sinks, and local failures that consumed no response.
    pub metadata: crate::client::ResponseMetadata,
}

type PendingSinkOutcome<'a> = Pin<Box<dyn Future<Output = SinkOutcome> + Send + 'a>>;

/// Lazy stream of notification sink completions.
///
/// Configured sink operations are driven concurrently as the stream is polled.
/// Each item is yielded as its operation reports completion, so stream order can
/// differ from sink configuration order. Dropping the stream cancels unfinished
/// sink futures, but does not undo network I/O or remote processing that already
/// occurred.
///
/// Use [`into_outcome`](Self::into_outcome) on a newly created stream to run
/// every sink operation and restore sink configuration order in the resulting
/// [`NotificationOutcome`].
#[must_use = "notification streams must be polled to send notifications"]
pub struct NotificationSendStream<'a> {
    agent: &'a super::Agent,
    operation: NotificationOperation,
    next_sink: usize,
    admission_limit: usize,
    pending: FuturesUnordered<PendingSinkOutcome<'a>>,
}

enum NotificationOperation {
    Trap {
        trap_oid: Arc<Oid>,
        uptime: u32,
        varbinds: Arc<[VarBind]>,
    },
    Inform {
        trap_oid: Arc<Oid>,
        uptime: u32,
        varbinds: Arc<[VarBind]>,
    },
}

impl NotificationSendStream<'_> {
    /// Return the next sink outcome in completion order.
    pub async fn next(&mut self) -> Option<SinkOutcome> {
        std::future::poll_fn(|context| Pin::new(&mut *self).poll_next(context)).await
    }

    /// Consume the stream and return its remaining outcomes in configuration order.
    ///
    /// Outcomes already yielded by [`next`](Self::next) are not included.
    pub async fn into_outcome(mut self) -> NotificationOutcome {
        let mut sinks = Vec::with_capacity(self.agent.sinks.len());
        while let Some(outcome) = self.next().await {
            sinks.push(outcome);
        }
        sinks.sort_unstable_by_key(|outcome| outcome.sink.index());
        NotificationOutcome { sinks }
    }
}

impl<'a> NotificationSendStream<'a> {
    fn admit(&mut self) {
        while self.pending.len() < self.admission_limit && self.next_sink < self.agent.sinks.len() {
            let sink = &self.agent.sinks[self.next_sink];
            let agent = self.agent;
            self.next_sink += 1;
            let future: PendingSinkOutcome<'a> = match &self.operation {
                NotificationOperation::Trap {
                    trap_oid,
                    uptime,
                    varbinds,
                } => {
                    let trap_oid = Arc::clone(trap_oid);
                    let varbinds = Arc::clone(varbinds);
                    let uptime = *uptime;
                    Box::pin(async move {
                        agent
                            .trap_sink_outcome(sink, &trap_oid, uptime, &varbinds)
                            .await
                    })
                }
                NotificationOperation::Inform {
                    trap_oid,
                    uptime,
                    varbinds,
                } => {
                    let trap_oid = Arc::clone(trap_oid);
                    let varbinds = Arc::clone(varbinds);
                    let uptime = *uptime;
                    Box::pin(async move {
                        agent
                            .inform_sink_outcome(sink, &trap_oid, uptime, &varbinds)
                            .await
                    })
                }
            };
            self.pending.push(future);
        }
    }
}

impl Stream for NotificationSendStream<'_> {
    type Item = SinkOutcome;

    fn poll_next(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        this.admit();
        Pin::new(&mut this.pending).poll_next(context)
    }
}

impl FusedStream for NotificationSendStream<'_> {
    fn is_terminated(&self) -> bool {
        self.next_sink == self.agent.sinks.len() && self.pending.is_empty()
    }
}

/// Aggregate outcome of sending a notification to all configured sinks.
///
/// Returned by [`Agent::send_trap`](super::Agent::send_trap) and
/// [`Agent::send_inform`](super::Agent::send_inform) so callers can observe
/// success, failure, or an explicit skip for every configured sink.
#[must_use = "inspect notification outcomes or use the explicit best-effort helper"]
#[derive(Debug)]
pub struct NotificationOutcome {
    sinks: Vec<SinkOutcome>,
}

impl NotificationOutcome {
    /// Per-sink outcomes, in sink configuration order.
    pub fn sinks(&self) -> &[SinkOutcome] {
        &self.sinks
    }

    /// Iterator over the sinks whose delivery failed.
    pub fn failures(&self) -> impl Iterator<Item = &SinkOutcome> {
        self.sinks
            .iter()
            .filter(|s| matches!(s.status, SinkStatus::Failed(_)))
    }

    /// Iterator over configured sinks that were not attempted.
    pub fn skipped(&self) -> impl Iterator<Item = &SinkOutcome> {
        self.sinks
            .iter()
            .filter(|s| matches!(s.status, SinkStatus::Skipped(_)))
    }

    /// `true` if every configured sink succeeded.
    ///
    /// This is also `true` when no sinks are configured, but is `false` when
    /// any configured sink failed or was skipped.
    pub fn all_succeeded(&self) -> bool {
        self.sinks
            .iter()
            .all(|s| matches!(s.status, SinkStatus::Succeeded))
    }

    /// Number of configured sinks represented in this outcome.
    pub fn len(&self) -> usize {
        self.sinks.len()
    }

    /// `true` if no sinks were configured.
    pub fn is_empty(&self) -> bool {
        self.sinks.is_empty()
    }

    /// Consume the outcome, returning the per-sink outcomes.
    pub fn into_sinks(self) -> Vec<SinkOutcome> {
        self.sinks
    }
}

impl super::Agent {
    async fn trap_sink_outcome(
        &self,
        sink: &TrapSink,
        trap_oid: &Oid,
        uptime: u32,
        varbinds: &[VarBind],
    ) -> SinkOutcome {
        let status = if !self.notification_allowed(sink, trap_oid, varbinds) {
            SinkStatus::Skipped(SinkSkipReason::NotInNotifyView)
        } else {
            match NotificationPdu::trap_v2(
                Version::V3,
                self.next_notification_id(),
                uptime,
                trap_oid,
                varbinds.to_vec(),
            ) {
                Ok(pdu) => match self.send_trap_to_sink(sink, &pdu).await {
                    Ok(()) => SinkStatus::Succeeded,
                    Err(error) => SinkStatus::Failed(error),
                },
                Err(error) => SinkStatus::Failed(error),
            }
        };
        SinkOutcome {
            sink: sink.summary.clone(),
            status,
            metadata: crate::client::ResponseMetadata::default(),
        }
    }

    async fn inform_sink_outcome(
        &self,
        sink: &TrapSink,
        trap_oid: &Oid,
        uptime: u32,
        varbinds: &[VarBind],
    ) -> SinkOutcome {
        let (status, metadata) = if sink.summary.version == Version::V1 {
            (
                SinkStatus::Skipped(SinkSkipReason::InformUnsupportedForV1),
                crate::client::ResponseMetadata::default(),
            )
        } else if !self.notification_allowed(sink, trap_oid, varbinds) {
            (
                SinkStatus::Skipped(SinkSkipReason::NotInNotifyView),
                crate::client::ResponseMetadata::default(),
            )
        } else {
            match self
                .send_inform_to_sink(sink, trap_oid, uptime, varbinds)
                .await
            {
                Ok(metadata) => (SinkStatus::Succeeded, metadata),
                Err(error) => {
                    let metadata = error.response_metadata().cloned().unwrap_or_default();
                    (SinkStatus::Failed(error), metadata)
                }
            }
        };
        SinkOutcome {
            sink: sink.summary.clone(),
            status,
            metadata,
        }
    }

    /// Lazily send a trap to all configured sinks.
    ///
    /// No sink operation or request-ID allocation occurs until the returned
    /// stream is polled. Sink operations are then driven concurrently and
    /// outcomes are yielded as they complete. Dropping the stream cancels
    /// unfinished operations but cannot undo a trap write that already occurred.
    /// Use [`NotificationSendStream::into_outcome`] when outcomes are needed in
    /// sink configuration order.
    pub fn send_trap_stream(
        &self,
        trap_oid: &Oid,
        uptime: u32,
        varbinds: Vec<VarBind>,
    ) -> NotificationSendStream<'_> {
        let trap_oid = Arc::new(trap_oid.clone());
        let varbinds: Arc<[VarBind]> = Arc::from(varbinds);
        NotificationSendStream {
            agent: self,
            operation: NotificationOperation::Trap {
                trap_oid,
                uptime,
                varbinds,
            },
            next_sink: 0,
            admission_limit: self.inner.notification_fanout_limit,
            pending: FuturesUnordered::new(),
        }
    }

    /// Send a trap to all configured trap sinks, reporting every outcome.
    ///
    /// Constructs a `TrapV2` PDU with the mandatory sysUpTime.0 and
    /// snmpTrapOID.0 prefix and sends it to each destination. Trap success
    /// means encoding and the local socket write succeeded; traps are
    /// fire-and-forget and remote receipt is not confirmed.
    ///
    /// V1 trap sinks receive a converted v1 trap (RFC 3584 Section 3.2).
    /// A valid `snmpTrapAddress.0` supplies `agent-addr`. Otherwise the agent
    /// uses the sink's concrete local IPv4 address, including mapped IPv4. A
    /// wildcard UDP sink targeting IPv4 does a best-effort lookup of the
    /// ordinary route on a separate socket and sends on its original endpoint.
    /// Socket-specific routing options can affect the actual source. If no IPv4
    /// address is available, the field is `0.0.0.0`.
    /// For a V3 sink, this Agent is authoritative and sends its persisted
    /// engine ID with the current boots/time tuple.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use async_snmp::agent::Agent;
    /// # use async_snmp::{Auth, NotificationSinkId, oid};
    /// # async fn example() -> Result<(), Box<async_snmp::Error>> {
    /// let agent = Agent::builder()
    ///     .bind("0.0.0.0:1161")
    ///     .community(b"public")
    ///     .notification_sink(NotificationSinkId::new("primary").unwrap(), async_snmp::NotificationTarget::shared_udp(0, "192.168.1.100:162"), Auth::v2c("public"))
    ///     .allow_all_access()
    ///     .spawn()
    ///     .await?;
    ///
    /// let outcome = agent
    ///     .send_trap(&oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1), 0, vec![])
    ///     .await;
    /// assert!(outcome.all_succeeded());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn send_trap(
        &self,
        trap_oid: &Oid,
        uptime: u32,
        varbinds: Vec<VarBind>,
    ) -> NotificationOutcome {
        self.send_trap_stream(trap_oid, uptime, varbinds)
            .into_outcome()
            .await
    }

    /// Send a trap to all configured sinks, warning and discarding outcomes.
    ///
    /// Use [`send_trap`](Self::send_trap) when the caller needs to observe
    /// per-sink success or failure. Warnings are emitted as each sink operation
    /// completes rather than after every sink has finished.
    pub async fn send_trap_best_effort(&self, trap_oid: &Oid, uptime: u32, varbinds: Vec<VarBind>) {
        let mut stream = self.send_trap_stream(trap_oid, uptime, varbinds);
        while let Some(sink) = stream.next().await {
            match &sink.status {
                SinkStatus::Failed(error) => {
                    tracing::warn!(target: "async_snmp::agent", { snmp.sink_id = %sink.sink.id(), snmp.dest = %sink.sink.dest(), error = %error }, "failed to send trap");
                }
                SinkStatus::Skipped(reason) => {
                    tracing::warn!(target: "async_snmp::agent", { snmp.sink_id = %sink.sink.id(), snmp.dest = %sink.sink.dest(), reason = %reason }, "skipped trap sink");
                }
                SinkStatus::Succeeded => {}
            }
        }
    }

    /// Lazily send an Inform to all configured sinks.
    ///
    /// No sink operation starts until the returned stream is polled. Sink
    /// operations are then driven concurrently and outcomes are yielded as they
    /// complete. Dropping the stream cancels unfinished local exchanges but
    /// cannot undo an Inform already processed by a remote receiver. Use
    /// [`NotificationSendStream::into_outcome`] when outcomes are needed in sink
    /// configuration order.
    pub fn send_inform_stream(
        &self,
        trap_oid: &Oid,
        uptime: u32,
        varbinds: Vec<VarBind>,
    ) -> NotificationSendStream<'_> {
        let trap_oid = Arc::new(trap_oid.clone());
        let varbinds: Arc<[VarBind]> = Arc::from(varbinds);
        NotificationSendStream {
            agent: self,
            operation: NotificationOperation::Inform {
                trap_oid,
                uptime,
                varbinds,
            },
            next_sink: 0,
            admission_limit: self.inner.notification_fanout_limit,
            pending: FuturesUnordered::new(),
        }
    }

    /// Send an inform to all configured notification sinks, reporting every outcome.
    ///
    /// Constructs an `InformRequest` PDU and sends it to each destination,
    /// waiting for acknowledgement from each. Sink exchanges run concurrently,
    /// and outcomes remain in sink configuration order. Reuses a cached client
    /// per sink over the same selected peer used for traps. Owned transport
    /// drivers run only while the Agent runner is driven.
    ///
    /// V1 notification sinks are explicitly reported as skipped because v1 does not
    /// support informs. For a V3 sink, the receiver is authoritative; the
    /// cached client discovers and uses the sink's engine identity and trusted
    /// time rather than the Agent's local authoritative state. Each
    /// [`SinkOutcome::metadata`] retains accepted deviations from that sink's
    /// complete Inform exchange.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use async_snmp::agent::Agent;
    /// # use async_snmp::{Auth, NotificationSinkId, oid};
    /// # async fn example() -> Result<(), Box<async_snmp::Error>> {
    /// let agent = Agent::builder()
    ///     .bind("0.0.0.0:1161")
    ///     .community(b"public")
    ///     .notification_sink(NotificationSinkId::new("primary").unwrap(), async_snmp::NotificationTarget::shared_udp(0, "192.168.1.100:162"), Auth::v2c("public"))
    ///     .allow_all_access()
    ///     .spawn()
    ///     .await?;
    ///
    /// let outcome = agent
    ///     .send_inform(&oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 2), 0, vec![])
    ///     .await;
    /// assert!(outcome.all_succeeded());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn send_inform(
        &self,
        trap_oid: &Oid,
        uptime: u32,
        varbinds: Vec<VarBind>,
    ) -> NotificationOutcome {
        self.send_inform_stream(trap_oid, uptime, varbinds)
            .into_outcome()
            .await
    }

    /// Send an inform to all configured sinks, warning and discarding outcomes.
    ///
    /// Use [`send_inform`](Self::send_inform) when the caller needs to observe
    /// per-sink acknowledgement, failure, or skip status. Warnings are emitted
    /// as each sink operation completes rather than after every sink has
    /// finished.
    pub async fn send_inform_best_effort(
        &self,
        trap_oid: &Oid,
        uptime: u32,
        varbinds: Vec<VarBind>,
    ) {
        let mut stream = self.send_inform_stream(trap_oid, uptime, varbinds);
        while let Some(sink) = stream.next().await {
            match &sink.status {
                SinkStatus::Failed(error) => {
                    tracing::warn!(target: "async_snmp::agent", { snmp.sink_id = %sink.sink.id(), snmp.dest = %sink.sink.dest(), error = %error }, "failed to send inform");
                }
                SinkStatus::Skipped(reason) => {
                    tracing::warn!(target: "async_snmp::agent", { snmp.sink_id = %sink.sink.id(), snmp.dest = %sink.sink.dest(), reason = %reason }, "skipped inform sink");
                }
                SinkStatus::Succeeded => {}
            }
        }
    }

    /// Resolve and apply the target sink's VACM notify view.
    fn notification_allowed(&self, sink: &TrapSink, trap_oid: &Oid, varbinds: &[VarBind]) -> bool {
        let Some(vacm) = self.inner.authorization.vacm() else {
            return true;
        };

        let (model, security_name, security_level, context_name) = match &sink.auth {
            Auth::Community { version, community } => {
                let model = match version {
                    CommunityVersion::V1 => SecurityModel::V1,
                    CommunityVersion::V2c => SecurityModel::V2c,
                };
                (
                    model,
                    community.as_bytes(),
                    SecurityLevel::NoAuthNoPriv,
                    &[][..],
                )
            }
            Auth::Usm(security) => (
                SecurityModel::Usm,
                security.username().as_ref(),
                security.security_level(),
                security.configured_context_name().as_ref(),
            ),
        };

        let Some(group) = vacm.get_group(model, security_name) else {
            return false;
        };
        let Some(access) = vacm.get_access(group, context_name, model, security_level) else {
            return false;
        };
        let notify_view = Some(&access.notify_view);

        if !vacm.check_access(notify_view, trap_oid)
            || varbinds
                .iter()
                .any(|varbind| !vacm.check_access(notify_view, &varbind.oid))
        {
            return false;
        }

        // SNMPv2c/v3 notifications carry these mandatory varbind names. In v1
        // they are represented by Trap-PDU fields instead.
        sink.summary.version == Version::V1
            || (vacm.check_access(notify_view, &crate::notification::oids::sys_uptime())
                && vacm.check_access(notify_view, &crate::notification::oids::snmp_trap_oid()))
    }

    /// Send a trap PDU to a single sink.
    async fn send_trap_to_sink(&self, sink: &TrapSink, pdu: &NotificationPdu) -> Result<()> {
        self.ensure_notification_active()?;
        let data = match sink.summary.version {
            Version::V1 => {
                let trap = pdu.to_v1_trap_with(|| sink.local_ipv4_addr().unwrap_or_default())?;
                let msg = CommunityMessage::v1_trap(sink.community.clone(), trap.into_raw())?;
                msg.encode()
            }
            Version::V2c => {
                let msg = CommunityMessage::new(
                    CommunityVersion::V2c,
                    sink.community.clone(),
                    pdu.as_raw().clone(),
                )?;
                msg.encode()
            }
            Version::V3 => {
                let security = sink.v3_security.as_ref().ok_or_else(|| {
                    Error::Config("V3 security not configured for trap sink".into()).boxed()
                })?;

                sink.ensure_keys_derived(&self.inner.state.engine_id)?;
                let derived = sink.derived_keys.read().map_err(|_| {
                    Error::Config("trap sink derived_keys lock poisoned".into()).boxed()
                })?;

                let (engine_boots, engine_time) = self.inner.state.authoritative_boots_time()?;

                let msg_id = self.next_notification_id();
                let encoded = crate::v3::encode::encode_v3_message(
                    pdu.as_raw(),
                    msg_id,
                    &self.inner.state.engine_id,
                    engine_boots,
                    engine_time,
                    security,
                    derived.as_ref(),
                    self.inner.state.local_engine.salt_counter().as_deref(),
                    self.inner.state.local_engine.des_salt_state().as_ref(),
                    Some(engine_boots),
                    false, // reportable=false for traps
                    sink.peer.receive_limits().advertised(),
                )?;
                Ok(Bytes::from(encoded))
            }
        }?;

        tracing::debug!(target: "async_snmp::agent", { snmp.sink_id = %sink.summary.id, snmp.dest = %sink.summary.dest, snmp.bytes = data.len() }, "sending trap");
        tokio::select! {
            biased;
            () = self.inner.cancel.cancelled() => return Err(Error::Config("agent notification originator stopped".into()).boxed()),
            result = sink.peer.send_with_timeout(data, sink.trap_send_timeout) => result?,
        }

        Ok(())
    }

    /// Send an inform to a single sink, reusing a cached client.
    async fn send_inform_to_sink(
        &self,
        sink: &TrapSink,
        trap_oid: &Oid,
        uptime: u32,
        varbinds: &[VarBind],
    ) -> Result<crate::client::ResponseMetadata> {
        self.ensure_notification_active()?;
        let client = sink
            .get_or_create_inform_client(&self.inner.state.local_engine)
            .await?;
        tokio::select! {
            biased;
            () = self.inner.cancel.cancelled() => Err(Error::Config("agent notification originator stopped".into()).boxed()),
            result = client.send_inform_with_metadata(trap_oid, uptime, varbinds.to_vec()) => result,
        }
    }

    fn ensure_notification_active(&self) -> Result<()> {
        if self.inner.cancel.is_cancelled() {
            return Err(Error::Config("agent notification originator stopped".into()).boxed());
        }
        Ok(())
    }

    /// Select an existing peer for runtime notifications, including accepted TCP sessions.
    /// No connection is opened or replaced. The returned handle retains this Agent and
    /// the selected peer's service lifetime. Its sink index is zero.
    ///
    /// Enable `client_exchanges(true)` when preparing a shared service used for
    /// Inform acknowledgements. The endpoint owner declares its receive capacity
    /// when it shares the Agent's [`crate::LocalEngine`]. SNMPv3 requires this
    /// Agent's prepared authoritative engine. AES privacy additionally requires an
    /// AES user or configured sink during preparation, and DES/3DES requires
    /// durable `des_salt_state`.
    /// Credentials are validated here; no transport I/O or background task starts.
    pub fn notification_peer(
        &self,
        id: NotificationSinkId,
        peer: impl Into<BuiltinTransport>,
        auth: impl Into<Auth>,
    ) -> Result<NotificationPeer> {
        self.ensure_notification_active()?;
        let mut auth = auth.into();
        if let Auth::Usm(security) = &mut auth {
            security
                .validate_and_precompute()
                .map_err(|e| Error::Config(e.to_string().into()).boxed())?;
            if self.inner.state.authoritative_engine.is_none() {
                return Err(Error::Config(
                    "authoritative engine state is required for SNMPv3 notification originators"
                        .into(),
                )
                .boxed());
            }
            if security
                .priv_protocol()
                .is_some_and(crate::PrivProtocol::is_des_family)
                && self.inner.state.local_engine.des_salt_state().is_none()
            {
                return Err(Error::Config(
                    "durable DES sender state is required for DES/3DES notifications".into(),
                )
                .boxed());
            }
            if security.priv_protocol().is_some_and(|p| !p.is_des_family())
                && self.inner.state.local_engine.salt_counter().is_none()
            {
                return Err(Error::Config(
                    "configure an AES USM role before preparing an AES notification originator"
                        .into(),
                )
                .boxed());
            }
        }
        Ok(NotificationPeer {
            agent: self.clone(),
            sink: TrapSink::new(
                0,
                id,
                peer.into(),
                auth,
                self.inner.trap_send_timeout,
                self.inner.inform_timeout,
                self.inner.inform_retry.clone(),
            ),
        })
    }

    /// Generate a notification request/message ID.
    // Atomic::try_update requires Rust 1.95; the MSRV is 1.88.
    #[allow(deprecated)]
    fn next_notification_id(&self) -> i32 {
        use std::sync::atomic::Ordering;
        self.inner
            .notification_id
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(if v == i32::MAX { 1 } else { v + 1 })
            })
            .unwrap_or(1)
    }
}

/// Runtime notification originator selecting one exact peer and Agent security context.
pub struct NotificationPeer {
    agent: super::Agent,
    sink: TrapSink,
}
impl NotificationPeer {
    /// Credential-free identity and limits of this selected peer.
    pub fn summary(&self) -> &NotificationSinkSummary {
        &self.sink.summary
    }
    /// Send an unconfirmed notification using the Agent's local authoritative state.
    /// The outcome includes VACM skips and encoding/write failures. Cancellation
    /// preserves TCP framing; a closed session fails without replacement.
    pub async fn send_trap(&self, oid: &Oid, uptime: u32, varbinds: Vec<VarBind>) -> SinkOutcome {
        self.agent
            .trap_sink_outcome(&self.sink, oid, uptime, &varbinds)
            .await
    }
    /// Exchange an Inform using the receiver's authoritative engine and the Agent's
    /// configured timeout/retry policy. The outcome retains accepted response metadata;
    /// v1 is skipped. Dropping this future cancels the exchange and further retries.
    pub async fn send_inform(&self, oid: &Oid, uptime: u32, varbinds: Vec<VarBind>) -> SinkOutcome {
        self.agent
            .inform_sink_outcome(&self.sink, oid, uptime, &varbinds)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::{
        NotificationOperation, NotificationSendStream, NotificationSinkId, PendingSinkOutcome,
        SinkOutcome, SinkSkipReason, SinkStatus, TrapSink,
    };
    use crate::agent::{Agent, VacmSecurityModel};
    use crate::handler::SecurityModel;
    use crate::{Auth, Error, SecurityLevel, Value, VarBind, oid};
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    use crate::{AuthProtocol, PrivProtocol};
    use bytes::Bytes;
    use futures_util::stream::FuturesUnordered;
    use std::sync::Arc;

    async fn test_sink(auth: impl Into<Auth>) -> TrapSink {
        TrapSink::new(
            0,
            NotificationSinkId::new("test-sink").unwrap(),
            crate::UdpEndpoint::builder()
                .bind("127.0.0.1:0")
                .prepare()
                .await
                .unwrap()
                .into_parts()
                .0
                .handle("127.0.0.1:9".parse().unwrap())
                .unwrap()
                .into(),
            auth.into(),
            crate::client::DEFAULT_SEND_TIMEOUT,
            std::time::Duration::from_millis(10),
            crate::client::Retry::default(),
        )
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn agent_trap_rejects_des_state_after_authoritative_rollover() {
        let engine = crate::v3::AuthoritativeEngine::for_test(&b"agent-engine"[..], 1);
        engine.set_elapsed_for_test(u64::from(crate::v3::MAX_ENGINE_TIME) + 1);
        let des_state =
            crate::v3::DesSaltState::install(|_| Ok::<(), std::convert::Infallible>(())).unwrap();
        let auth = crate::UsmConfig::new("trapuser")
            .auth_priv(
                crate::v3::AuthProtocol::Sha1,
                b"auth-password",
                crate::v3::PrivProtocol::Des,
                b"priv-password",
            )
            .unwrap();
        let (agent, _runner, _) = Agent::builder()
            .bind("127.0.0.1:0")
            .authoritative_engine(engine)
            .des_salt_state(des_state.clone())
            .notification_sink(
                NotificationSinkId::new("des-sink").unwrap(),
                crate::NotificationTarget::shared_udp(0, "127.0.0.1:9"),
                auth,
            )
            .allow_all_access()
            .prepare()
            .await
            .unwrap()
            .into_parts();

        let outcome = agent
            .send_trap(&oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1), 0, vec![])
            .await;
        let SinkStatus::Failed(error) = &outcome.sinks()[0].status else {
            panic!("stale DES state must fail the trap sink")
        };
        assert!(matches!(
            &**error,
            Error::Privacy(crate::v3::PrivacyError::DesEngineBootsMismatch {
                state_engine_boots: 1,
                generating_engine_boots: 2,
            })
        ));
        assert_eq!(des_state.reserve().unwrap().salt(), 1);
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn agent_des_inform_persistence_updates_health_and_recovers() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let receiver_engine =
            crate::v3::AuthoritativeEngine::for_test(&b"receiver-inform-health"[..], 5);
        let receiver_des_state = crate::v3::DesSaltState::restart(
            crate::v3::PersistedDesSaltState::new(4).unwrap(),
            |_| Ok::<(), std::convert::Infallible>(()),
        )
        .unwrap();
        let mut receiver = crate::NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .authoritative_engine(receiver_engine)
            .des_salt_state(receiver_des_state)
            .usm_user("informuser", |user| {
                user.auth_priv(
                    AuthProtocol::Sha1,
                    b"auth-password",
                    PrivProtocol::Des,
                    b"priv-password",
                )
            })
            .unwrap()
            .admit_all_notifications()
            .spawn()
            .await
            .unwrap();
        let receiver_addr = receiver.local_addr();
        let receiver_task = tokio::spawn(async move { receiver.recv().await });

        let persistence_calls = std::sync::Arc::new(AtomicUsize::new(0));
        let callback_calls = std::sync::Arc::clone(&persistence_calls);
        let engine =
            crate::v3::AuthoritativeEngine::install(b"agent-inform-health".to_vec(), move |_| {
                match callback_calls.fetch_add(1, Ordering::Relaxed) {
                    0 | 3.. => Ok(()),
                    _ => Err(std::io::Error::other("persistence unavailable")),
                }
            })
            .unwrap();
        let des_state =
            crate::v3::DesSaltState::install(|_| Ok::<(), std::convert::Infallible>(())).unwrap();
        let sink_auth = crate::UsmConfig::new("informuser")
            .auth_priv(
                AuthProtocol::Sha1,
                b"auth-password",
                PrivProtocol::Des,
                b"priv-password",
            )
            .unwrap();
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .authoritative_engine(engine.clone())
            .des_salt_state(des_state)
            .notification_sink(
                NotificationSinkId::new("des-inform").unwrap(),
                crate::NotificationTarget::shared_udp(0, receiver_addr.to_string()),
                sink_auth,
            )
            .inform_timeout(std::time::Duration::from_secs(1))
            .inform_retry(crate::Retry::none())
            .allow_all_access()
            .spawn()
            .await
            .unwrap();
        engine.set_elapsed_for_test(u64::from(crate::v3::MAX_ENGINE_TIME) + 1);
        let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1);

        for expected_failures in [1, 2] {
            let outcome = agent.send_inform(&trap_oid, 0, vec![]).await;
            assert!(matches!(
                &outcome.sinks()[0].status,
                SinkStatus::Failed(error)
                    if error.kind() == crate::ErrorKind::AuthoritativeEnginePersistence
            ));
            assert!(matches!(
                agent.health(),
                crate::v3::LocalEngineHealth::AuthoritativePersistenceDegraded {
                    consecutive_failures,
                    ..
                } if consecutive_failures == expected_failures
            ));
        }

        let recovered = agent.send_inform(&trap_oid, 0, vec![]).await;
        assert!(matches!(
            &recovered.sinks()[0].status,
            SinkStatus::Failed(error)
                if matches!(
                    &**error,
                    Error::Privacy(crate::v3::PrivacyError::DesEngineBootsMismatch {
                        state_engine_boots: 1,
                        generating_engine_boots: 2,
                    })
                )
        ));
        assert_eq!(agent.health(), crate::v3::LocalEngineHealth::Healthy);
        assert_eq!(persistence_calls.load(Ordering::Relaxed), 4);

        receiver_task.abort();
        let _ = receiver_task.await;
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn cached_inform_client_uses_current_shared_des_state() {
        use std::convert::Infallible;

        let receiver_engine =
            crate::AuthoritativeEngine::for_test(b"cached-inform-receiver".as_slice(), 5);
        let receiver_des =
            crate::DesSaltState::restart(crate::PersistedDesSaltState::new(4).unwrap(), |_| {
                Ok::<_, Infallible>(())
            })
            .unwrap();
        let mut receiver = crate::NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .authoritative_engine(receiver_engine)
            .des_salt_state(receiver_des)
            .usm_user("user", |user| {
                user.auth_priv(
                    AuthProtocol::Sha1,
                    b"authentication",
                    PrivProtocol::Des,
                    b"privacy-password",
                )
            })
            .unwrap()
            .admit_all_notifications()
            .spawn()
            .await
            .unwrap();
        let authoritative =
            crate::AuthoritativeEngine::for_test(b"cached-inform-sender".as_slice(), 1);
        let local = crate::LocalEngine::new(authoritative.clone()).unwrap();
        let first_state = crate::DesSaltState::install(|_| Ok::<_, Infallible>(())).unwrap();
        local.set_des_salt_state(Some(first_state.clone())).unwrap();
        let auth = crate::UsmConfig::new("user")
            .auth_priv(
                AuthProtocol::Sha1,
                b"authentication",
                PrivProtocol::Des,
                b"privacy-password",
            )
            .unwrap();
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .local_engine(local.clone())
            .notification_sink(
                NotificationSinkId::new("cached-des").unwrap(),
                crate::NotificationTarget::shared_udp(0, receiver.local_addr().to_string()),
                auth,
            )
            .inform_timeout(std::time::Duration::from_secs(1))
            .inform_retry(crate::Retry::none())
            .allow_all_access()
            .spawn()
            .await
            .unwrap();
        let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1);
        assert!(
            agent
                .send_inform(&trap_oid, 0, vec![])
                .await
                .all_succeeded()
        );
        let cached = agent.sinks[0].inform_client.lock().await.clone().unwrap();
        assert!(Arc::ptr_eq(
            &cached.local_engine().unwrap().inner,
            &local.inner,
        ));

        local.set_des_salt_state(None).unwrap();
        let removed = agent.send_inform(&trap_oid, 0, vec![]).await;
        assert!(matches!(
            &removed.sinks()[0].status,
            SinkStatus::Failed(error) if matches!(&**error, Error::Config(_))
        ));
        local.set_des_salt_state(Some(first_state.clone())).unwrap();
        assert!(
            agent
                .send_inform(&trap_oid, 0, vec![])
                .await
                .all_succeeded()
        );

        authoritative.set_elapsed_for_test(u64::from(crate::v3::MAX_ENGINE_TIME) + 1);
        let stale = agent.send_inform(&trap_oid, 0, vec![]).await;
        assert!(matches!(
            &stale.sinks()[0].status,
            SinkStatus::Failed(error) if matches!(
                &**error,
                Error::Privacy(crate::v3::PrivacyError::DesEngineBootsMismatch { .. })
            )
        ));
        let next_state =
            crate::DesSaltState::restart(
                first_state.persisted_state(),
                |_| Ok::<_, Infallible>(()),
            )
            .unwrap();
        local.set_des_salt_state(Some(next_state)).unwrap();
        assert!(
            agent
                .send_inform(&trap_oid, 0, vec![])
                .await
                .all_succeeded()
        );
        for _ in 0..3 {
            let notification = receiver.recv().await.unwrap();
            assert!(matches!(
                notification.inform_ack,
                crate::NotificationAcknowledgement::Completed(crate::InformAckOutcome::Sent)
            ));
        }
        agent.shutdown().await.unwrap();
        receiver.shutdown().await.unwrap();
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[tokio::test]
    async fn notify_view_uses_each_sink_identity_context_and_security_level() {
        let (agent, _runner, _) = Agent::builder()
            .bind("127.0.0.1:0")
            .vacm(|v| {
                v.group("v1-community", SecurityModel::V1, "v1")
                    .group("v2-community", SecurityModel::V2c, "v2")
                    .group("context-user", SecurityModel::Usm, "context")
                    .group("security-user", SecurityModel::Usm, "security")
                    .access("v1", SecurityModel::V1, SecurityLevel::NoAuthNoPriv, |a| {
                        a.notify_view("all")
                    })
                    .access("v2", SecurityModel::V2c, SecurityLevel::NoAuthNoPriv, |a| {
                        a.notify_view("all")
                    })
                    .access(
                        "context",
                        SecurityModel::Usm,
                        SecurityLevel::NoAuthNoPriv,
                        |a| {
                            a.context_prefix("tenant/")
                                .context_match_prefix()
                                .notify_view("empty")
                        },
                    )
                    .access(
                        "context",
                        SecurityModel::Usm,
                        SecurityLevel::NoAuthNoPriv,
                        |a| a.context_prefix("tenant/blue").notify_view("all"),
                    )
                    .access(
                        "security",
                        SecurityModel::Usm,
                        SecurityLevel::NoAuthNoPriv,
                        |a| a.context_prefix("secure").notify_view("empty"),
                    )
                    .access(
                        "security",
                        SecurityModel::Usm,
                        SecurityLevel::AuthPriv,
                        |a| a.context_prefix("secure").notify_view("all"),
                    )
                    .view("all", |view| view.include(oid!(1, 3, 6)))
                    .view("empty", |view| view)
            })
            .prepare()
            .await
            .unwrap()
            .into_parts();
        let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1);

        assert!(agent.notification_allowed(
            &test_sink(Auth::v1("v1-community")).await,
            &trap_oid,
            &[]
        ));
        assert!(agent.notification_allowed(
            &test_sink(Auth::v2c("v2-community")).await,
            &trap_oid,
            &[]
        ));
        assert!(agent.notification_allowed(
            &test_sink(crate::UsmConfig::new("context-user").context_name("tenant/blue"),).await,
            &trap_oid,
            &[]
        ));
        assert!(!agent.notification_allowed(
            &test_sink(crate::UsmConfig::new("context-user").context_name("tenant/red"),).await,
            &trap_oid,
            &[]
        ));
        assert!(
            !agent.notification_allowed(
                &test_sink(
                    crate::UsmConfig::new("security-user")
                        .auth(AuthProtocol::Sha256, "auth-password")
                        .unwrap()
                        .context_name("secure")
                )
                .await,
                &trap_oid,
                &[]
            )
        );
        assert!(
            agent.notification_allowed(
                &test_sink(
                    crate::UsmConfig::new("security-user")
                        .auth_priv(
                            AuthProtocol::Sha256,
                            "auth-password",
                            PrivProtocol::Aes128,
                            "privacy-password",
                        )
                        .unwrap()
                        .context_name("secure")
                )
                .await,
                &trap_oid,
                &[]
            )
        );
    }

    #[tokio::test]
    async fn notify_view_denies_trap_oid_extra_varbind_and_missing_views() {
        let denied_trap = oid!(1, 3, 6, 1, 4, 1, 9999, 1);
        let allowed_trap = oid!(1, 3, 6, 1, 4, 1, 9999, 2);
        let denied_extra = oid!(1, 3, 6, 1, 4, 1, 9999, 3);
        let (agent, _runner, _) = Agent::builder()
            .bind("127.0.0.1:0")
            .vacm(|v| {
                v.group("trap-denied", SecurityModel::V2c, "trap-denied")
                    .group("extra-denied", SecurityModel::V2c, "extra-denied")
                    .group("missing", SecurityModel::V2c, "missing")
                    .group("empty", SecurityModel::V2c, "empty")
                    .group("no-access", SecurityModel::V2c, "no-access")
                    .access(
                        "trap-denied",
                        SecurityModel::V2c,
                        SecurityLevel::NoAuthNoPriv,
                        |a| a.notify_view("trap-view"),
                    )
                    .access(
                        "extra-denied",
                        SecurityModel::V2c,
                        SecurityLevel::NoAuthNoPriv,
                        |a| a.notify_view("extra-view"),
                    )
                    .access(
                        "missing",
                        SecurityModel::V2c,
                        SecurityLevel::NoAuthNoPriv,
                        |a| a.notify_view("not-defined"),
                    )
                    .access(
                        "empty",
                        SecurityModel::V2c,
                        SecurityLevel::NoAuthNoPriv,
                        |a| a,
                    )
                    .view("trap-view", |view| {
                        view.include(oid!(1, 3, 6)).exclude(denied_trap.clone())
                    })
                    .view("extra-view", |view| {
                        view.include(oid!(1, 3, 6)).exclude(denied_extra.clone())
                    })
            })
            .prepare()
            .await
            .unwrap()
            .into_parts();
        let extra = VarBind::new(denied_extra, Value::Integer(1));

        assert!(!agent.notification_allowed(
            &test_sink(Auth::v2c("trap-denied")).await,
            &denied_trap,
            &[]
        ));
        assert!(!agent.notification_allowed(
            &test_sink(Auth::v2c("extra-denied")).await,
            &allowed_trap,
            &[extra]
        ));
        assert!(!agent.notification_allowed(
            &test_sink(Auth::v2c("missing")).await,
            &allowed_trap,
            &[]
        ));
        assert!(!agent.notification_allowed(
            &test_sink(Auth::v2c("empty")).await,
            &allowed_trap,
            &[]
        ));
        assert!(!agent.notification_allowed(
            &test_sink(Auth::v2c("no-access")).await,
            &allowed_trap,
            &[]
        ));
        assert!(!agent.notification_allowed(
            &test_sink(Auth::v2c("no-group")).await,
            &allowed_trap,
            &[]
        ));
    }

    #[tokio::test]
    async fn notify_view_checks_v2_mandatory_varbind_names_but_not_v1_fields() {
        let trap_oid = oid!(1, 3, 6, 1, 4, 1, 9999, 1);
        let extra_oid = oid!(1, 3, 6, 1, 4, 1, 9999, 2);
        let (agent, _runner, _) = Agent::builder()
            .bind("127.0.0.1:0")
            .vacm(|v| {
                v.group("v1", SecurityModel::V1, "group")
                    .group("v2", SecurityModel::V2c, "group")
                    .access(
                        "group",
                        VacmSecurityModel::Any,
                        SecurityLevel::NoAuthNoPriv,
                        |a| a.notify_view("notification-only"),
                    )
                    .view("notification-only", |view| {
                        view.include(trap_oid.clone()).include(extra_oid.clone())
                    })
            })
            .prepare()
            .await
            .unwrap()
            .into_parts();
        let extra = VarBind::new(extra_oid, Value::Integer(1));

        assert!(agent.notification_allowed(
            &test_sink(Auth::v1("v1")).await,
            &trap_oid,
            std::slice::from_ref(&extra)
        ));
        assert!(!agent.notification_allowed(
            &test_sink(Auth::v2c("v2")).await,
            &trap_oid,
            &[extra]
        ));
    }

    #[tokio::test]
    async fn notification_vacm_is_permissive_when_unconfigured_and_mixed_per_sink() {
        let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1);
        let (permissive, _runner, _) = Agent::builder()
            .bind("127.0.0.1:0")
            .prepare()
            .await
            .unwrap()
            .into_parts();
        assert!(permissive.notification_allowed(
            &test_sink(Auth::v2c("unmapped")).await,
            &trap_oid,
            &[VarBind::new(oid!(9, 9), Value::Integer(1))]
        ));

        let (mixed, _runner, _) = Agent::builder()
            .bind("127.0.0.1:0")
            .notification_sink(
                NotificationSinkId::new("allowed").unwrap(),
                crate::NotificationTarget::shared_udp(0, "127.0.0.1:9"),
                Auth::v2c("allowed"),
            )
            .notification_sink(
                NotificationSinkId::new("denied").unwrap(),
                crate::NotificationTarget::shared_udp(0, "127.0.0.1:9"),
                Auth::v2c("denied"),
            )
            .vacm(|v| {
                v.group("allowed", SecurityModel::V2c, "allowed")
                    .group("denied", SecurityModel::V2c, "denied")
                    .access(
                        "allowed",
                        SecurityModel::V2c,
                        SecurityLevel::NoAuthNoPriv,
                        |a| a.notify_view("all"),
                    )
                    .access(
                        "denied",
                        SecurityModel::V2c,
                        SecurityLevel::NoAuthNoPriv,
                        |a| a.notify_view("empty"),
                    )
                    .view("all", |view| view.include(oid!(1, 3, 6)))
                    .view("empty", |view| view)
            })
            .prepare()
            .await
            .unwrap()
            .into_parts();
        let outcome = mixed.send_trap(&trap_oid, 0, vec![]).await;
        assert!(matches!(outcome.sinks()[0].status, SinkStatus::Succeeded));
        assert!(matches!(
            outcome.sinks()[1].status,
            SinkStatus::Skipped(SinkSkipReason::NotInNotifyView)
        ));

        let (agent, _runner, _) = Agent::builder()
            .bind("127.0.0.1:0")
            .notification_sink(
                NotificationSinkId::new("denied").unwrap(),
                crate::NotificationTarget::shared_udp(0, "127.0.0.1:9"),
                Auth::v2c("denied"),
            )
            .vacm(|v| {
                v.group("denied", SecurityModel::V2c, "denied")
                    .access(
                        "denied",
                        SecurityModel::V2c,
                        SecurityLevel::NoAuthNoPriv,
                        |a| a.notify_view("empty"),
                    )
                    .view("empty", |view| view)
            })
            .prepare()
            .await
            .unwrap()
            .into_parts();
        let denied_inform = agent.send_inform(&trap_oid, 0, vec![]).await;
        assert!(matches!(
            denied_inform.sinks()[0].status,
            SinkStatus::Skipped(SinkSkipReason::NotInNotifyView)
        ));

        let (agent, _runner, _) = Agent::builder()
            .bind("127.0.0.1:0")
            .notification_sink(
                NotificationSinkId::new("denied-v1").unwrap(),
                crate::NotificationTarget::shared_udp(0, "127.0.0.1:9"),
                Auth::v1("denied"),
            )
            .vacm(|v| v)
            .prepare()
            .await
            .unwrap()
            .into_parts();
        let denied_v1_inform = agent.send_inform(&trap_oid, 0, vec![]).await;
        assert!(matches!(
            denied_v1_inform.sinks()[0].status,
            SinkStatus::Skipped(SinkSkipReason::InformUnsupportedForV1)
        ));
    }

    #[tokio::test]
    async fn public_agent_notification_path_rejects_receive_only_values() {
        let (agent, _runner, _) = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .notification_sink(
                NotificationSinkId::new("public").unwrap(),
                crate::NotificationTarget::shared_udp(0, "127.0.0.1:9"),
                Auth::v2c("public"),
            )
            .allow_all_access()
            .prepare()
            .await
            .unwrap()
            .into_parts();
        let malformed = VarBind::new(
            oid!(1, 3, 6, 1, 4, 1, 9999, 1),
            Value::Unknown {
                tag: 0x48,
                data: Bytes::from_static(b"raw"),
            },
        );

        let outcome = agent
            .send_trap(&oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1), 0, vec![malformed])
            .await;
        assert_eq!(outcome.len(), 1);
        match &outcome.sinks()[0].status {
            SinkStatus::Failed(error) => {
                assert!(matches!(&**error, Error::InvalidMessage(_)));
            }
            status => panic!("expected outbound validation failure, got {status:?}"),
        }
    }

    #[tokio::test]
    async fn unpolled_trap_stream_does_not_allocate_request_id() {
        let (agent, _runner, _) = Agent::builder()
            .bind("127.0.0.1:0")
            .notification_sink(
                NotificationSinkId::new("lazy").unwrap(),
                crate::NotificationTarget::shared_udp(0, "127.0.0.1:9"),
                Auth::v1("public"),
            )
            .prepare()
            .await
            .unwrap()
            .into_parts();
        let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1);

        let stream = agent.send_trap_stream(&trap_oid, 0, vec![]);
        drop(stream);

        let mut stream = agent.send_trap_stream(&trap_oid, 0, vec![]);
        assert!(matches!(
            stream.next().await.unwrap().status,
            SinkStatus::Succeeded
        ));
        assert_eq!(agent.next_notification_id(), 2);
    }

    #[tokio::test]
    async fn trap_stream_admits_at_most_the_configured_fanout_limit() {
        let mut builder = Agent::builder()
            .bind("127.0.0.1:0")
            .notification_fanout_limit(2);
        for index in 0..5 {
            builder = builder.notification_sink(
                NotificationSinkId::new(format!("sink-{index}")).unwrap(),
                crate::NotificationTarget::shared_udp(0, format!("127.0.0.1:{}", 20_000 + index)),
                Auth::v2c("public"),
            );
        }
        let (agent, _runner, _) = builder.prepare().await.unwrap().into_parts();
        let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1);
        let mut stream = agent.send_trap_stream(&trap_oid, 0, vec![]);

        assert_eq!(stream.pending.len(), 0);
        stream.admit();
        assert_eq!(stream.pending.len(), 2);
        assert_eq!(stream.next_sink, 2);

        let first = stream.next().await.unwrap();
        assert!(matches!(first.status, SinkStatus::Succeeded));
        assert!(stream.pending.len() <= 2);
        stream.admit();
        assert_eq!(stream.pending.len(), 2);
        assert_eq!(stream.next_sink, 3);

        let outcome = stream.into_outcome().await;
        assert_eq!(outcome.len(), 4);
        assert!(outcome.all_succeeded());
    }

    #[tokio::test(start_paused = true)]
    async fn notification_stream_yields_admitted_futures_in_completion_order() {
        let (agent, _runner, _) = Agent::builder()
            .bind("127.0.0.1:0")
            .prepare()
            .await
            .unwrap()
            .into_parts();
        let pending = FuturesUnordered::new();
        for (index, delay) in [(0, 20), (1, 1)] {
            let mut sink = test_sink(Auth::v2c("public")).await.summary;
            sink.index = index;
            pending.push(Box::pin(async move {
                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                SinkOutcome {
                    sink,
                    status: SinkStatus::Succeeded,
                    metadata: crate::client::ResponseMetadata::default(),
                }
            }) as PendingSinkOutcome<'_>);
        }
        let trap_oid = Arc::new(oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1));
        let mut stream = NotificationSendStream {
            agent: &agent,
            operation: NotificationOperation::Trap {
                trap_oid,
                uptime: 0,
                varbinds: Arc::from([]),
            },
            next_sink: 0,
            admission_limit: 2,
            pending,
        };

        assert_eq!(stream.next().await.unwrap().sink.index(), 1);
        assert_eq!(stream.next().await.unwrap().sink.index(), 0);
    }

    #[tokio::test]
    async fn test_notification_ids_are_per_agent() {
        // Each Agent must own its own notification id sequence; two independent
        // agents must not share a process-global counter.
        let (agent_a, _runner, _) = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .allow_all_access()
            .prepare()
            .await
            .unwrap()
            .into_parts();
        let (agent_b, _runner, _) = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .allow_all_access()
            .prepare()
            .await
            .unwrap()
            .into_parts();

        // Advance agent_a's sequence a few times.
        let a1 = agent_a.next_notification_id();
        let a2 = agent_a.next_notification_id();
        let a3 = agent_a.next_notification_id();
        assert_eq!((a1, a2, a3), (1, 2, 3));

        // agent_b is unaffected by agent_a's advancement and starts fresh.
        let b1 = agent_b.next_notification_id();
        let b2 = agent_b.next_notification_id();
        assert_eq!((b1, b2), (1, 2));

        // agent_a continues its own monotonic sequence.
        assert_eq!(agent_a.next_notification_id(), 4);
    }
}
