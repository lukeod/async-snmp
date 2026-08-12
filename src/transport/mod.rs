//! Transport layer abstraction for SNMP communication.
//!
//! This module provides the [`Transport`] trait and implementations:
//!
//! - [`UdpTransport`] + [`UdpHandle`] - UDP socket with per-target handles
//! - [`TcpTransport`] - TCP stream with BER framing
//! - [`BuiltinTransport`] - runtime selection between library-maintained transports
//!
//! # Choosing a Transport
//!
//! | Scenario | Approach |
//! |----------|---------|
//! | Single target or few targets | [`Client::builder().connect()`](crate::Client::builder) - each client gets its own socket |
//! | Many UDP targets from one process | Pass a preconstructed [`UdpTransport`] socket owner to [`TargetClientBuilder::build_with`](crate::TargetClientBuilder::build_with) - each target gets a handle on one socket and recv loop |
//! | UDP blocked or messages exceed MTU | [`Client::builder().connect_tcp()`](crate::TargetClientBuilder::connect_tcp) |
//! | Preconstruct or implement any client transport | Pass the [`Transport`] implementation to [`ClientBuilder::build_with_transport`](crate::ClientBuilder::build_with_transport) without a target |
//! | Choose UDP or TCP at runtime | Configure the concrete transport, convert it to [`BuiltinTransport`], then pass it to [`ClientBuilder::build_with_transport`](crate::ClientBuilder::build_with_transport) |

mod builtin;
mod tcp;
mod udp;
mod udp_core;

pub use builtin::*;
pub use tcp::*;
pub use udp::*;

use crate::Community;
use crate::ber::length::parse_ber_length;
use crate::error::Error;
use crate::error::Result;
use crate::message::DecodePolicy;
use crate::message_size::{ReceiveLimits, UDP_RECEIVE_LIMITS};
use crate::version::{CommunityVersion, Version};
use bytes::Bytes;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicI32, Ordering};
use std::task::Poll;
use std::time::{Duration, Instant};

/// Global request ID counter, initialized with a cryptographically random seed.
///
/// Using a global counter ensures request IDs are unique across all
/// transports within the process, preventing collisions when multiple
/// transports exist or when sockets are rapidly recreated.
static REQUEST_ID_COUNTER: LazyLock<AtomicI32> =
    LazyLock::new(|| AtomicI32::new(request_id_seed_with(getrandom::fill)));

fn request_id_seed_with(
    mut fill: impl FnMut(&mut [u8]) -> std::result::Result<(), getrandom::Error>,
) -> i32 {
    let mut buf = [0u8; 4];
    if let Err(error) = fill(&mut buf) {
        tracing::warn!(target: "async_snmp::transport", %error, "OS random source unavailable; using deterministic request ID seed");
        buf = 1_i32.to_ne_bytes();
    }
    i32::from_ne_bytes(buf)
}

/// Allocate a globally unique request ID.
///
/// Returns a positive non-zero i32 (range 1..=2,147,483,647) that is unique
/// within this process. Per RFC 1157/3412, request-id/msgID is defined as
/// INTEGER (0..2,147,483,647), and some implementations may not handle negative
/// values correctly.
///
/// The counter is seeded with random bytes to minimize collision risk across
/// process restarts.
pub fn alloc_request_id() -> i32 {
    loop {
        let id = REQUEST_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
        let id = id & 0x7FFF_FFFF;
        if id != 0 {
            return id;
        }
    }
}

/// Policy for correlating SNMPv1/v2c responses whose community was rewritten.
///
/// Response versions always have to match. UDP strict-source checking is an
/// independent control and, when enabled, rejects every off-target response.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CommunityResponsePolicy {
    /// Require byte-for-byte equality with the request community.
    #[default]
    Exact,
    /// Accept a rewritten community only from the configured target.
    ///
    /// An off-target response whose community matches exactly remains accepted
    /// when UDP strict-source checking is disabled.
    AllowMismatchFromTarget,
    /// Accept a rewritten community from any source.
    ///
    /// With permissive UDP source checking this explicitly accepts both peer
    /// and community mismatches and therefore weakens spoof resistance.
    AllowMismatchFromAnySource,
}

/// Protocol-specific response identity held inside a request registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ResponseCorrelation {
    /// SNMPv1/v2c responses must match this version and community policy.
    Community {
        /// Expected SNMP version.
        version: Version,
        /// Community sent in the request.
        community: Community,
        /// Policy for safely accepting a rewritten community.
        policy: CommunityResponsePolicy,
    },
    /// SNMPv3 correlation uses msgID and its existing authenticated checks.
    V3,
    #[cfg(test)]
    Unchecked,
}

/// Correlation metadata for an in-flight request.
///
/// Construct registrations with [`Self::community`] or [`Self::v3`]. Identity,
/// community, and deadline metadata is read-only after construction; aliases
/// are normalized by [`Self::with_aliases`].
///
/// ```compile_fail
/// use async_snmp::RequestRegistration;
/// use std::time::Duration;
///
/// let mut registration = RequestRegistration::v3(7, Duration::from_secs(1));
/// registration.request_id = 8;
/// ```
///
/// Protocol-specific correlation details are intentionally internal rather
/// than a separately constructible public enum:
///
/// ```compile_fail
/// use async_snmp::transport::ResponseCorrelation;
/// ```
///
/// Community registrations accept only [`CommunityVersion`], so an SNMPv3
/// registration cannot be constructed through the community API:
///
/// ```compile_fail
/// use async_snmp::{CommunityResponsePolicy, RequestRegistration, Version};
/// use bytes::Bytes;
/// use std::time::Duration;
///
/// RequestRegistration::community(
///     7,
///     Duration::from_secs(1),
///     Version::V3,
///     Bytes::from_static(b"public"),
///     CommunityResponsePolicy::Exact,
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestRegistration {
    /// Request ID (v1/v2c) or msgID (v3).
    request_id: i32,
    /// Overall response deadline duration.
    timeout: Duration,
    /// Protocol-specific response identity.
    correlation: ResponseCorrelation,
    /// Top-level SNMP message consumption policy used by correlation.
    decode_policy: DecodePolicy,
    /// Prior transmission IDs that may still receive a response for this operation.
    aliases: Vec<i32>,
}

impl RequestRegistration {
    /// Construct v1/v2c registration metadata.
    #[must_use]
    pub fn community(
        request_id: i32,
        timeout: Duration,
        version: CommunityVersion,
        community: impl Into<Community>,
        policy: CommunityResponsePolicy,
    ) -> Self {
        Self {
            request_id,
            timeout,
            correlation: ResponseCorrelation::Community {
                version: version.into(),
                community: community.into(),
                policy,
            },
            decode_policy: DecodePolicy::Compatible,
            aliases: Vec::new(),
        }
    }

    /// Construct SNMPv3 registration metadata.
    #[must_use]
    pub const fn v3(request_id: i32, timeout: Duration) -> Self {
        Self {
            request_id,
            timeout,
            correlation: ResponseCorrelation::V3,
            decode_policy: DecodePolicy::Compatible,
            aliases: Vec::new(),
        }
    }

    #[cfg(test)]
    pub(crate) const fn test_unchecked(request_id: i32, timeout: Duration) -> Self {
        Self {
            request_id,
            timeout,
            correlation: ResponseCorrelation::Unchecked,
            decode_policy: DecodePolicy::Compatible,
            aliases: Vec::new(),
        }
    }

    /// Attach prior transmission IDs to this registration.
    ///
    /// The primary ID and duplicate aliases are omitted so transports can
    /// reserve and correlate one coherent set of IDs.
    #[must_use]
    pub fn with_aliases(mut self, aliases: impl IntoIterator<Item = i32>) -> Self {
        self.aliases.clear();
        for alias in aliases {
            if alias != self.request_id && !self.aliases.contains(&alias) {
                self.aliases.push(alias);
            }
        }
        self
    }

    /// Select the top-level message consumption policy for correlation.
    ///
    /// The default is [`DecodePolicy::Compatible`], matching the client decode
    /// default. Compatible correlation accepts a bounded UDP datagram suffix
    /// after one complete declared SNMP message TLV as an explicit deviation
    /// from RFC 3417's one-message-per-datagram mapping. Strict correlation
    /// rejects such a suffix before invoking the response validator. In either
    /// mode, identity fields are read only from the declared top-level envelope.
    #[must_use]
    pub const fn with_decode_policy(mut self, policy: DecodePolicy) -> Self {
        self.decode_policy = policy;
        self
    }

    /// Top-level message consumption policy used by correlation.
    #[must_use]
    pub const fn decode_policy(&self) -> DecodePolicy {
        self.decode_policy
    }

    /// Primary request ID (v1/v2c) or message ID (v3).
    #[must_use]
    pub const fn request_id(&self) -> i32 {
        self.request_id
    }

    /// Duration from registration to the absolute response deadline.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Prior transmission IDs accepted for this operation.
    #[must_use]
    pub fn aliases(&self) -> &[i32] {
        &self.aliases
    }

    /// Evaluate transport-level response identity without consuming the exchange.
    ///
    /// This checks the outer request ID (or SNMPv3 `msgID`) against the primary
    /// ID and aliases, verifies the registered protocol version, and applies
    /// the configured community response policy. `source_is_target` must report
    /// whether the packet source equals the transport's configured target.
    ///
    /// A matching identity is only a candidate. Callers must still decode and
    /// validate the response PDU and, for SNMPv3, perform the required security
    /// and scoped-PDU checks before accepting it.
    #[must_use]
    pub fn evaluate_response_identity(
        &self,
        data: &[u8],
        source_is_target: bool,
    ) -> ResponseIdentity {
        #[cfg(test)]
        if matches!(self.correlation, ResponseCorrelation::Unchecked) {
            return ResponseIdentity::Match;
        }

        let Some(envelope) = CorrelationEnvelope::parse(data, self.decode_policy) else {
            return ResponseIdentity::Reject;
        };
        let Some(response_id) = envelope.request_id() else {
            return ResponseIdentity::Reject;
        };
        if response_id != self.request_id && !self.aliases.contains(&response_id) {
            return ResponseIdentity::Reject;
        }

        self.correlation.evaluate(envelope, source_is_target)
    }
}

/// Result of evaluating immutable transport-level response identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseIdentity {
    /// The registered outer ID, version, and community matched exactly.
    Match,
    /// The outer ID and version matched, and the community rewrite policy
    /// explicitly accepted a different community.
    AcceptedCommunityMismatch,
    /// The packet did not match the registered response identity.
    Reject,
}

impl ResponseCorrelation {
    fn evaluate(
        &self,
        envelope: CorrelationEnvelope<'_>,
        source_is_target: bool,
    ) -> ResponseIdentity {
        #[cfg(test)]
        if matches!(self, Self::Unchecked) {
            return ResponseIdentity::Match;
        }

        let Self::Community {
            version,
            community,
            policy,
        } = self
        else {
            return if envelope.version == Version::V3 {
                ResponseIdentity::Match
            } else {
                ResponseIdentity::Reject
            };
        };

        let Some((actual_version, actual_community)) = envelope.community_identity() else {
            return ResponseIdentity::Reject;
        };
        if actual_version != *version {
            return ResponseIdentity::Reject;
        }
        if actual_community == community.as_bytes() {
            return ResponseIdentity::Match;
        }
        match policy {
            CommunityResponsePolicy::Exact => ResponseIdentity::Reject,
            CommunityResponsePolicy::AllowMismatchFromTarget if source_is_target => {
                ResponseIdentity::AcceptedCommunityMismatch
            }
            CommunityResponsePolicy::AllowMismatchFromAnySource => {
                ResponseIdentity::AcceptedCommunityMismatch
            }
            CommunityResponsePolicy::AllowMismatchFromTarget => ResponseIdentity::Reject,
        }
    }
}

/// Result of validating a correlated response candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Candidate<T> {
    /// Accept this candidate and complete the exchange.
    Accept(T),
    /// Ignore this candidate and continue waiting under the original deadline.
    Reject,
}

/// Client-side transport abstraction.
///
/// All transports implement this trait uniformly. For shared transports,
/// handles (not the pool itself) implement Transport. A response that fails the
/// registered correlation metadata or the caller's validator must be ignored
/// without consuming the pending request or extending its deadline.
pub trait Transport: Send + Sync {
    /// Send request data to the target.
    ///
    /// Implementations that return a finite [`send_capacity`](Self::send_capacity)
    /// must reject larger data with
    /// [`Error::OutboundMessageTooLarge`]
    /// before performing transport I/O. This applies to direct `send` calls;
    /// the default [`request_with`](Self::request_with) implementation performs
    /// the same check for request/response exchanges.
    fn send(&self, data: &[u8]) -> impl Future<Output = Result<()>> + Send;

    /// Send data under one total timeout.
    ///
    /// The timeout starts when this future is first polled and includes any
    /// transport-internal queueing as well as the actual write. The default
    /// implementation preserves compatibility for custom transports by
    /// applying a deadline around [`send`](Self::send). Stream transports may
    /// override this to distinguish expiry before stream I/O from expiry after
    /// a partially completed write.
    fn send_with_timeout(
        &self,
        data: &[u8],
        timeout: Duration,
    ) -> impl Future<Output = Result<()>> + Send {
        async move {
            crate::message_size::enforce_outbound_size(data.len(), self.send_capacity())?;
            checked_deadline(timeout, "transport send timeout")?;
            let deadline = tokio::time::Instant::now()
                .checked_add(timeout)
                .ok_or_else(|| {
                    Error::Config(
                        "transport send timeout exceeds the representable deadline".into(),
                    )
                    .boxed()
                })?;
            if tokio::time::Instant::now() >= deadline {
                return Err(Error::Timeout {
                    target: self.peer_addr(),
                    elapsed: timeout,
                    retries: 0,
                }
                .boxed());
            }
            tokio::time::timeout_at(deadline, self.send(data))
                .await
                .map_err(|_| {
                    Error::Timeout {
                        target: self.peer_addr(),
                        elapsed: timeout,
                        retries: 0,
                    }
                    .boxed()
                })?
        }
    }

    /// Receive one correlated response without additional validation.
    ///
    /// This compatibility operation is implemented in terms of
    /// [`recv_with`](Self::recv_with); clients should use the validated boundary.
    fn recv(
        &self,
        registration: RequestRegistration,
    ) -> impl Future<Output = Result<(Bytes, SocketAddr)>> + Send {
        self.recv_with(registration, |data, source| {
            Ok(Candidate::Accept((data, source)))
        })
    }

    /// Wait until the validator accepts a response candidate.
    ///
    /// Transports with out-of-band demultiplexing must install the registration
    /// before this future first returns [`Poll::Pending`] and remove it whenever
    /// the future completes or is dropped. Implementors use
    /// [`RequestRegistration::evaluate_response_identity`] before invoking the
    /// caller's validator; [`ResponseIdentity::Reject`] and
    /// [`Candidate::Reject`] both retain that same registration and its original
    /// absolute deadline. Validator errors are fatal local errors.
    #[cfg(not(test))]
    fn recv_with<T, F>(
        &self,
        registration: RequestRegistration,
        validate: F,
    ) -> impl Future<Output = Result<T>> + Send
    where
        T: Send,
        F: FnMut(Bytes, SocketAddr) -> Result<Candidate<T>> + Send;

    #[cfg(test)]
    fn recv_with<T, F>(
        &self,
        registration: RequestRegistration,
        mut validate: F,
    ) -> impl Future<Output = Result<T>> + Send
    where
        T: Send,
        F: FnMut(Bytes, SocketAddr) -> Result<Candidate<T>> + Send,
    {
        async move {
            // Unit-test transport doubles may implement only `recv` and expect
            // its synchronous setup to run after `send`.
            tokio::task::yield_now().await;
            let (data, source) = self.recv(registration).await?;
            match validate(data, source)? {
                Candidate::Accept(value) => Ok(value),
                Candidate::Reject => Err(Error::MalformedResponse {
                    target: self.peer_addr(),
                }
                .boxed()),
            }
        }
    }

    /// Send request data and receive one correlated response without additional
    /// validation. This compatibility operation accepts the first candidate.
    fn request(
        &self,
        data: &[u8],
        registration: RequestRegistration,
    ) -> impl Future<Output = Result<(Bytes, SocketAddr)>> + Send {
        self.request_with(data, registration, |response, source| {
            Ok(Candidate::Accept((response, source)))
        })
    }

    /// Send request data and wait until the validator accepts a response.
    ///
    /// The default implementation polls [`recv_with`](Self::recv_with) once
    /// before sending, allowing an out-of-band demultiplexer to install its
    /// correlation state before a fast response can arrive. Transports that
    /// serialize an exchange by holding a lock (such as TCP) must override this
    /// so one future owns the lock across the write and every rejected
    /// candidate.
    fn request_with<T, F>(
        &self,
        data: &[u8],
        registration: RequestRegistration,
        validate: F,
    ) -> impl Future<Output = Result<T>> + Send
    where
        T: Send,
        F: FnMut(Bytes, SocketAddr) -> Result<Candidate<T>> + Send,
    {
        async move {
            crate::message_size::enforce_outbound_size(data.len(), self.send_capacity())?;
            checked_deadline(registration.timeout(), "transport timeout")?;

            let mut receive = std::pin::pin!(self.recv_with(registration, validate));
            let ready_response = std::future::poll_fn(|context| {
                Poll::Ready(match receive.as_mut().poll(context) {
                    Poll::Ready(result) => Some(result),
                    Poll::Pending => None,
                })
            })
            .await;

            self.send(data).await?;
            match ready_response {
                Some(result) => result,
                None => receive.await,
            }
        }
    }

    /// The peer address for this transport.
    fn peer_addr(&self) -> SocketAddr;

    /// Local bind address.
    fn local_addr(&self) -> SocketAddr;

    /// Allocate the next request ID.
    ///
    /// Default uses the global allocator for process-wide uniqueness.
    fn alloc_request_id(&self) -> i32 {
        alloc_request_id()
    }

    /// Whether this is a reliable transport (TCP/TLS).
    ///
    /// When true, Client skips retries (transport guarantees delivery or failure).
    /// When false (UDP/DTLS), Client retries on timeout.
    fn is_reliable(&self) -> bool;

    /// Validated local receive limits for this transport.
    ///
    /// The advertised value is wire-valid for SNMPv3. The accepted value is
    /// the hard total-input bound and may be slightly larger for bounded UDP
    /// receive-side tolerance.
    fn receive_limits(&self) -> ReceiveLimits {
        UDP_RECEIVE_LIMITS
    }

    /// Maximum exact encoded message size this transport will send.
    ///
    /// This is independent of [`receive_limits`](Self::receive_limits), whose
    /// advertised value describes what the local endpoint can receive. The
    /// effectively unbounded default preserves the behavior of existing custom
    /// transports. Implementors that override this with a finite limit must
    /// enforce it in direct [`send`](Self::send) calls; the default request
    /// helper enforces it before starting receive-side work.
    fn send_capacity(&self) -> usize {
        usize::MAX
    }
}

pub(crate) fn checked_deadline(timeout: Duration, description: &str) -> Result<Instant> {
    Instant::now().checked_add(timeout).ok_or_else(|| {
        crate::error::Error::Config(
            format!("{description} exceeds the representable deadline").into(),
        )
        .boxed()
    })
}

// ============================================================================
// Correlation envelope extraction (shared between transports)
// ============================================================================

/// One checked top-level SNMP message envelope used for shallow correlation.
///
/// `data` ends at the declared outer SEQUENCE boundary, even when the received
/// datagram contains a compatible suffix. Nested correlation parsing therefore
/// cannot inspect or match bytes outside that envelope.
#[derive(Clone, Copy)]
struct CorrelationEnvelope<'a> {
    data: &'a [u8],
    version: Version,
    after_version: usize,
}

impl<'a> CorrelationEnvelope<'a> {
    fn parse(data: &'a [u8], policy: DecodePolicy) -> Option<Self> {
        if data.first().copied()? != 0x30 {
            return None;
        }
        let (outer_len, outer_len_bytes) = parse_ber_length(data.get(1..)?)?;
        let content_start = 1usize.checked_add(outer_len_bytes)?;
        let content_end = content_start.checked_add(outer_len)?;
        if content_end > data.len() || (policy == DecodePolicy::Strict && content_end != data.len())
        {
            return None;
        }

        let data = data.get(..content_end)?;

        let mut pos = content_start;
        if *data.get(pos)? != 0x02 {
            return None;
        }
        pos = pos.checked_add(1)?;
        let (version_len, version_len_bytes) = parse_ber_length(data.get(pos..)?)?;
        pos = pos.checked_add(version_len_bytes)?;
        let version_end = pos.checked_add(version_len)?;
        if version_end > content_end || version_len == 0 || version_len > 4 {
            return None;
        }
        let version = Version::from_i32(decode_ber_signed_integer(data.get(pos..version_end)?))?;
        Some(Self {
            data,
            version,
            after_version: version_end,
        })
    }

    fn community_identity(self) -> Option<(Version, &'a [u8])> {
        if !matches!(self.version, Version::V1 | Version::V2c) {
            return None;
        }

        let data = self.data;
        let mut pos = self.after_version;
        if *data.get(pos)? != 0x04 {
            return None;
        }
        pos = pos.checked_add(1)?;
        let (community_len, community_len_bytes) = parse_ber_length(data.get(pos..)?)?;
        pos = pos.checked_add(community_len_bytes)?;
        let community_end = pos.checked_add(community_len)?;
        Some((self.version, data.get(pos..community_end)?))
    }

    fn request_id(self) -> Option<i32> {
        match self.version {
            Version::V1 | Version::V2c => extract_v1v2c_request_id(self.data, self.after_version),
            Version::V3 => extract_v3_msg_id(self.data, self.after_version),
        }
    }
}

/// Extract a checked v1/v2c version and borrowed community without allocating.
///
/// The default compatible policy mirrors [`extract_request_id`]. Returned
/// bytes are always borrowed from the declared top-level envelope, never from
/// a datagram suffix.
#[cfg(test)]
pub(crate) fn extract_community_identity(data: &[u8]) -> Option<(Version, &[u8])> {
    CorrelationEnvelope::parse(data, DecodePolicy::Compatible)?.community_identity()
}

// ============================================================================
// Request ID Extraction (shared between transports)
// ============================================================================

/// Extract `request_id` (or msgID for V3) from an SNMP response.
///
/// SNMP message structure differs by version:
///
/// V1/V2c:
/// - SEQUENCE { INTEGER version, OCTET STRING community, PDU }
/// - PDU contains `request_id` as first INTEGER
///
/// V3:
/// - SEQUENCE { INTEGER version(3), SEQUENCE msgGlobalData { INTEGER msgID, ... }, ... }
/// - msgID in msgGlobalData is used for correlation
///
/// We navigate only within the first complete declared top-level envelope to
/// find the appropriate ID. A bounded datagram suffix is ignored here so the
/// registered strict/compatible policy can decide whether to accept it.
pub(crate) fn extract_request_id(data: &[u8]) -> Option<i32> {
    CorrelationEnvelope::parse(data, DecodePolicy::Compatible)?.request_id()
}

/// Extract msgID from V3 message starting at msgGlobalData position.
fn extract_v3_msg_id(data: &[u8], mut pos: usize) -> Option<i32> {
    // msgGlobalData SEQUENCE
    if *data.get(pos)? != 0x30 {
        return None;
    }
    pos = pos.checked_add(1)?;
    let (global_len, consumed) = parse_ber_length(data.get(pos..)?)?;
    pos = pos.checked_add(consumed)?;
    let global_end = pos.checked_add(global_len)?;
    data.get(pos..global_end)?;

    // First INTEGER inside msgGlobalData is msgID. Its complete encoding must
    // be contained by msgGlobalData rather than merely appearing later in the
    // outer packet.
    if *data.get(pos)? != 0x02 {
        return None;
    }
    pos = pos.checked_add(1)?;
    let (id_len, consumed) = parse_ber_length(data.get(pos..)?)?;
    pos = pos.checked_add(consumed)?;
    let id_end = pos.checked_add(id_len)?;
    if id_len == 0 || id_len > 4 || id_end > global_end {
        return None;
    }

    Some(decode_ber_signed_integer(data.get(pos..id_end)?))
}

/// Extract `request_id` from V1/V2c message starting at community position.
fn extract_v1v2c_request_id(data: &[u8], mut pos: usize) -> Option<i32> {
    // Community (OCTET STRING)
    if *data.get(pos)? != 0x04 {
        return None;
    }
    pos = pos.checked_add(1)?;
    let (community_len, consumed) = parse_ber_length(data.get(pos..)?)?;
    pos = pos.checked_add(consumed)?;
    pos = pos.checked_add(community_len)?;
    data.get(..pos)?;

    // PDU (context-specific, e.g., 0xA2 for Response)
    let pdu_tag = *data.get(pos)?;
    if !(0xA0..=0xA8).contains(&pdu_tag) {
        return None;
    }
    pos = pos.checked_add(1)?;
    let (pdu_len, consumed) = parse_ber_length(data.get(pos..)?)?;
    pos = pos.checked_add(consumed)?;
    let pdu_end = pos.checked_add(pdu_len)?;
    data.get(pos..pdu_end)?;

    // The complete request-id INTEGER must be contained by the PDU. Structural
    // and security validation beyond this shallow identity stays in the caller
    // validator.
    if *data.get(pos)? != 0x02 {
        return None;
    }
    pos = pos.checked_add(1)?;
    let (id_len, consumed) = parse_ber_length(data.get(pos..)?)?;
    pos = pos.checked_add(consumed)?;
    let id_end = pos.checked_add(id_len)?;
    if id_len == 0 || id_len > 4 || id_end > pdu_end {
        return None;
    }

    Some(decode_ber_signed_integer(data.get(pos..id_end)?))
}

/// Decode a BER-encoded signed integer.
fn decode_ber_signed_integer(bytes: &[u8]) -> i32 {
    if bytes.is_empty() {
        return 0;
    }

    // Sign extend for negative numbers
    let mut value: i32 = if bytes[0] & 0x80 != 0 { -1 } else { 0 };

    for &byte in bytes {
        value = (value << 8) | i32::from(byte);
    }

    value
}

#[cfg(test)]
mod request_id_tests {
    use super::*;
    use std::sync::atomic::AtomicI32;

    /// RFC 1157 and RFC 3412 define request-id/msgID as INTEGER (0..2_147_483_647).
    #[test]
    fn request_id_is_always_positive() {
        for _ in 0..10_000 {
            let id = alloc_request_id();
            assert!(id > 0, "request ID must be positive, got {id}");
        }
    }

    /// Some SNMP implementations treat request-id 0 specially or reject it.
    #[test]
    fn request_id_zero_is_skipped() {
        for _ in 0..10_000 {
            let id = alloc_request_id();
            assert_ne!(id, 0, "request ID must not be zero");
        }
    }

    /// Validates wrap-around: counter going from `i32::MAX` to negative must
    /// still produce positive values via 31-bit masking (RFC 3412 range).
    #[test]
    fn request_id_wrap_around_stays_positive() {
        let counter = AtomicI32::new(i32::MAX - 100);

        let alloc_test_id = || -> i32 {
            loop {
                let id = counter.fetch_add(1, Ordering::Relaxed);
                let id = id & 0x7FFF_FFFF;
                if id != 0 {
                    return id;
                }
            }
        };

        for i in 0..200 {
            let id = alloc_test_id();
            assert!(
                id > 0,
                "request ID must be positive after wrap, iteration {i}, got {id}"
            );
        }
    }

    #[test]
    fn request_ids_are_unique() {
        use std::collections::HashSet;

        let mut seen = HashSet::new();
        for _ in 0..10_000 {
            let id = alloc_request_id();
            assert!(seen.insert(id), "request ID {id} was allocated twice");
        }
    }

    #[test]
    fn request_id_seed_falls_back_when_random_source_fails() {
        let seed = request_id_seed_with(|_| Err(getrandom::Error::UNEXPECTED));
        assert_eq!(seed, 1);
    }
}

#[cfg(test)]
mod extract_tests {
    use super::*;

    const V1_RESPONSE: &[u8] = &[
        0x30, 0x1b, 0x02, 0x01, 0x00, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa2, 0x0e,
        0x02, 0x01, 0x2a, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x03, 0x30, 0x01, 0x00,
    ];
    const V2C_RESPONSE: &[u8] = &[
        0x30, 0x1c, 0x02, 0x01, 0x01, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa2, 0x0f,
        0x02, 0x02, 0x30, 0x39, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x03, 0x30, 0x01, 0x00,
    ];
    const V3_RESPONSE: &[u8] = &[
        0x30, 0x33, 0x02, 0x01, 0x03, 0x30, 0x11, 0x02, 0x02, 0x30, 0x39, 0x02, 0x03, 0x00, 0xff,
        0xe3, 0x04, 0x01, 0x04, 0x02, 0x01, 0x03, 0x04, 0x00, 0x30, 0x1b, 0x04, 0x00, 0x04, 0x00,
        0xa2, 0x15, 0x02, 0x02, 0x30, 0x39, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x09, 0x30,
        0x07, 0x06, 0x03, 0x2b, 0x06, 0x01, 0x05, 0x00,
    ];

    fn registration_for(version: Version) -> RequestRegistration {
        match version {
            Version::V1 => RequestRegistration::community(
                42,
                Duration::from_secs(1),
                CommunityVersion::V1,
                Bytes::from_static(b"public"),
                CommunityResponsePolicy::Exact,
            ),
            Version::V2c => RequestRegistration::community(
                12345,
                Duration::from_secs(1),
                CommunityVersion::V2c,
                Bytes::from_static(b"public"),
                CommunityResponsePolicy::Exact,
            ),
            Version::V3 => RequestRegistration::v3(12345, Duration::from_secs(1)),
        }
    }

    #[test]
    fn test_extract_request_id_v2c() {
        // A minimal SNMP v2c GET response with request_id = 12345
        let response = [
            0x30, 0x1c, // SEQUENCE
            0x02, 0x01, 0x01, // INTEGER 1 (v2c)
            0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, // "public"
            0xa2, 0x0f, // Response PDU
            0x02, 0x02, 0x30, 0x39, // INTEGER 12345
            0x02, 0x01, 0x00, // error-status
            0x02, 0x01, 0x00, // error-index
            0x30, 0x03, 0x30, 0x01, 0x00, // varbinds
        ];

        assert_eq!(extract_request_id(&response), Some(12345));
    }

    #[test]
    fn test_extract_request_id_v3() {
        // A minimal SNMPv3 Response message with msgID = 12345
        let v3_response = [
            0x30, 0x33, // SEQUENCE
            0x02, 0x01, 0x03, // version = 3
            0x30, 0x11, // msgGlobalData SEQUENCE
            0x02, 0x02, 0x30, 0x39, // INTEGER 12345 (msgID)
            0x02, 0x03, 0x00, 0xff, 0xe3, // INTEGER 65507 (msgMaxSize)
            0x04, 0x01, 0x04, // OCTET STRING (msgFlags)
            0x02, 0x01, 0x03, // INTEGER 3 (msgSecurityModel)
            0x04, 0x00, // msgSecurityParameters
            0x30, 0x1b, // ScopedPDU SEQUENCE
            0x04, 0x00, // contextEngineID
            0x04, 0x00, // contextName
            0xa2, 0x15, // ResponsePDU
            0x02, 0x02, 0x30, 0x39, // request_id
            0x02, 0x01, 0x00, // error-status
            0x02, 0x01, 0x00, // error-index
            0x30, 0x09, // varbinds
            0x30, 0x07, // varbind
            0x06, 0x03, 0x2b, 0x06, 0x01, // OID
            0x05, 0x00, // NULL
        ];

        assert_eq!(extract_request_id(&v3_response), Some(12345));
    }

    #[test]
    fn test_extract_request_id_v1() {
        // A minimal SNMPv1 GET response with request_id = 42
        let v1_response = [
            0x30, 0x1b, // SEQUENCE
            0x02, 0x01, 0x00, // INTEGER 0 (v1)
            0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, // "public"
            0xa2, 0x0e, // Response PDU
            0x02, 0x01, 0x2a, // INTEGER 42 (request_id)
            0x02, 0x01, 0x00, // error-status
            0x02, 0x01, 0x00, // error-index
            0x30, 0x03, 0x30, 0x01, 0x00, // varbinds
        ];

        assert_eq!(extract_request_id(&v1_response), Some(42));
    }

    #[test]
    fn test_extract_request_id_negative() {
        // Request ID = -1
        let response = [
            0x30, 0x18, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa2,
            0x0b, 0x02, 0x01, 0xff, // INTEGER -1
            0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00,
        ];

        assert_eq!(extract_request_id(&response), Some(-1));
    }

    #[test]
    fn test_extract_request_id_malformed() {
        assert_eq!(extract_request_id(&[]), None);
        assert_eq!(extract_request_id(&[0x02, 0x01, 0x00]), None);
        assert_eq!(extract_request_id(&[0x30, 0x10]), None);
    }

    #[test]
    fn test_extract_request_id_huge_long_form_length() {
        // Regression: request-id INTEGER with long-form length 0x88 followed by
        // eight 0xFF octets decodes to usize::MAX. Without a cap in
        // parse_ber_length, `pos + id_len` overflows and slicing panics,
        // killing the recv task.
        let malicious = [
            0x30, 0x0c, // SEQUENCE
            0x02, 0x01, 0x01, // INTEGER 1 (v2c)
            0x04, 0x00, // empty community
            0xa2, 0x0b, // Response PDU
            0x02, 0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, // INTEGER, length usize::MAX
        ];

        assert_eq!(extract_request_id(&malicious), None);
    }

    #[test]
    fn correlation_policy_handles_suffixes_for_all_versions() {
        for (version, packet) in [
            (Version::V1, V1_RESPONSE),
            (Version::V2c, V2C_RESPONSE),
            (Version::V3, V3_RESPONSE),
        ] {
            let mut suffixed = packet.to_vec();
            suffixed.extend_from_slice(V2C_RESPONSE);

            assert_eq!(
                registration_for(version).evaluate_response_identity(&suffixed, true),
                ResponseIdentity::Match,
                "compatible {version:?} correlation rejected a declared envelope with a suffix"
            );
            assert_eq!(
                registration_for(version)
                    .with_decode_policy(DecodePolicy::Strict)
                    .evaluate_response_identity(&suffixed, true),
                ResponseIdentity::Reject,
                "strict {version:?} correlation accepted a datagram suffix"
            );
        }
    }

    #[test]
    fn correlation_never_uses_plausible_identity_from_suffix() {
        let mut first = V1_RESPONSE.to_vec();
        first.extend_from_slice(V2C_RESPONSE);

        assert_eq!(extract_request_id(&first), Some(42));
        assert_eq!(
            registration_for(Version::V2c).evaluate_response_identity(&first, true),
            ResponseIdentity::Reject,
            "the v2c ID in the suffix must not correlate"
        );

        let version_only_envelope = [0x30, 0x03, 0x02, 0x01, 0x01];
        let mut missing_identity = version_only_envelope.to_vec();
        missing_identity.extend_from_slice(V2C_RESPONSE);
        assert_eq!(extract_request_id(&missing_identity), None);
        assert_eq!(
            registration_for(Version::V2c).evaluate_response_identity(&missing_identity, true),
            ResponseIdentity::Reject,
            "correlation must not continue parsing beyond the declared envelope"
        );
    }

    #[test]
    fn malformed_truncated_and_oversized_envelopes_never_correlate() {
        let malformed_packets: &[&[u8]] = &[
            &[],
            &[0x31, 0x00],
            &[0x30, 0x80],
            &[0x30, 0x05, 0x02, 0x01, 0x01],
            &[0x30, 0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            &[0x30, 0x84, 0x7f, 0xff, 0xff, 0xff, 0x02, 0x01, 0x01],
        ];

        for packet in malformed_packets {
            assert_eq!(extract_request_id(packet), None);
            for version in [Version::V1, Version::V2c, Version::V3] {
                assert_eq!(
                    registration_for(version).evaluate_response_identity(packet, true),
                    ResponseIdentity::Reject
                );
            }
        }
    }
}
