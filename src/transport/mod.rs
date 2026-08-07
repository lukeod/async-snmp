//! Transport layer abstraction for SNMP communication.
//!
//! This module provides the [`Transport`] trait and implementations:
//!
//! - [`UdpTransport`] + [`UdpHandle`] - UDP socket with per-target handles
//! - [`TcpTransport`] - TCP stream with BER framing
//!
//! # Choosing a Transport
//!
//! | Scenario | Approach |
//! |----------|---------|
//! | Single target or few targets | [`Client::builder().connect()`](crate::Client::builder) - each client gets its own socket |
//! | Many targets from one process | Share a [`UdpTransport`] via [`build_with()`](crate::ClientBuilder::build_with) - one socket, one recv loop |
//! | UDP blocked or messages exceed MTU | [`Client::builder().connect_tcp()`](crate::ClientBuilder::connect_tcp) |

mod tcp;
mod udp;
mod udp_core;

pub use tcp::*;
pub use udp::*;

use crate::ber::length::parse_ber_length;
use crate::error::Result;
use crate::message_size::{ReceiveLimits, UDP_RECEIVE_LIMITS};
use crate::version::Version;
use bytes::Bytes;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::Duration;

/// Global request ID counter, initialized with a cryptographically random seed.
///
/// Using a global counter ensures request IDs are unique across all
/// transports within the process, preventing collisions when multiple
/// transports exist or when sockets are rapidly recreated.
static REQUEST_ID_COUNTER: LazyLock<AtomicI32> = LazyLock::new(|| {
    let mut buf = [0u8; 4];
    getrandom::fill(&mut buf).expect("getrandom failed");
    let seed = i32::from_ne_bytes(buf);
    AtomicI32::new(seed)
});

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

/// Response identity supplied when registering an in-flight request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseCorrelation {
    /// SNMPv1/v2c responses must match this version and community policy.
    Community {
        /// Expected SNMP version.
        version: Version,
        /// Community sent in the request.
        community: Bytes,
        /// Policy for safely accepting a rewritten community.
        policy: CommunityResponsePolicy,
    },
    /// SNMPv3 correlation uses msgID and its existing authenticated checks.
    V3,
}

/// Correlation metadata for an in-flight request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestRegistration {
    /// Request ID (v1/v2c) or msgID (v3).
    pub request_id: i32,
    /// Overall response deadline duration.
    pub timeout: Duration,
    /// Protocol-specific response identity.
    pub correlation: ResponseCorrelation,
}

impl RequestRegistration {
    /// Construct v1/v2c registration metadata.
    #[must_use]
    pub fn community(
        request_id: i32,
        timeout: Duration,
        version: Version,
        community: Bytes,
        policy: CommunityResponsePolicy,
    ) -> Self {
        Self {
            request_id,
            timeout,
            correlation: ResponseCorrelation::Community {
                version,
                community,
                policy,
            },
        }
    }

    /// Construct SNMPv3 registration metadata.
    #[must_use]
    pub const fn v3(request_id: i32, timeout: Duration) -> Self {
        Self {
            request_id,
            timeout,
            correlation: ResponseCorrelation::V3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CorrelationResult {
    Match,
    AcceptedCommunityMismatch,
    Reject,
}

impl ResponseCorrelation {
    pub(crate) fn evaluate(&self, data: &[u8], source_is_target: bool) -> CorrelationResult {
        let Self::Community {
            version,
            community,
            policy,
        } = self
        else {
            return CorrelationResult::Match;
        };

        let Some((actual_version, actual_community)) = extract_community_identity(data) else {
            return CorrelationResult::Reject;
        };
        if actual_version != *version {
            return CorrelationResult::Reject;
        }
        if actual_community == community.as_ref() {
            return CorrelationResult::Match;
        }
        match policy {
            CommunityResponsePolicy::Exact => CorrelationResult::Reject,
            CommunityResponsePolicy::AllowMismatchFromTarget if source_is_target => {
                CorrelationResult::AcceptedCommunityMismatch
            }
            CommunityResponsePolicy::AllowMismatchFromAnySource => {
                CorrelationResult::AcceptedCommunityMismatch
            }
            CommunityResponsePolicy::AllowMismatchFromTarget => CorrelationResult::Reject,
        }
    }
}

/// Client-side transport abstraction.
///
/// All transports implement this trait uniformly. For shared transports,
/// handles (not the pool itself) implement Transport. A response that fails the
/// registered correlation metadata must be ignored without consuming the
/// pending request or extending its deadline.
pub trait Transport: Send + Sync {
    /// Send request data to the target.
    fn send(&self, data: &[u8]) -> impl Future<Output = Result<()>> + Send;

    /// Wait for response. Uses deadline set by `register_request()`.
    ///
    /// UDP and TCP transports use the deadline stored during registration.
    fn recv(&self, request_id: i32) -> impl Future<Output = Result<(Bytes, SocketAddr)>> + Send;

    /// Send request data and wait for the correlated response as a single unit.
    ///
    /// The default implementation simply chains [`send`](Self::send) then
    /// [`recv`](Self::recv). Transports that serialize a request/response pair by
    /// holding a lock between the two steps (e.g. TCP holding its stream lock)
    /// must override this so the lock is owned by one future for the whole
    /// exchange. Otherwise, if the caller's future is dropped between `send` and
    /// `recv` (for example a `timeout()` wrapping the call), the lock is stashed
    /// across independent await points and leaks, permanently wedging later
    /// requests.
    ///
    /// Callers should invoke [`register_request`](Self::register_request) before
    /// this, exactly as they would before a bare `send`/`recv` pair.
    fn request(
        &self,
        data: &[u8],
        request_id: i32,
    ) -> impl Future<Output = Result<(Bytes, SocketAddr)>> + Send {
        async move {
            self.send(data).await?;
            self.recv(request_id).await
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

    /// Pre-register a request with its timeout and response identity.
    ///
    /// Transports must leave the request pending, under its original deadline,
    /// when a received packet fails the supplied correlation metadata.
    fn register_request(&self, registration: RequestRegistration);

    /// Route responses addressed to `alias_id` (a prior transmission of the
    /// same operation) to the pending request registered under `primary_id`.
    /// Transports without out-of-band demultiplexing ignore this; the client
    /// still accepts windowed IDs in its own correlation check.
    fn register_request_alias(&self, _alias_id: i32, _primary_id: i32, _timeout: Duration) {}

    /// Validated local receive limits for this transport.
    ///
    /// The advertised value is wire-valid for SNMPv3. The accepted value is
    /// the hard total-input bound and may be slightly larger for bounded UDP
    /// receive-side tolerance.
    fn receive_limits(&self) -> ReceiveLimits {
        UDP_RECEIVE_LIMITS
    }
}

/// Agent-side transport abstraction (listener mode).
///
/// This trait is for future agent functionality.
pub trait AgentTransport: Send + Sync {
    /// Receive data from any source.
    fn recv_from(&self, buf: &mut [u8])
    -> impl Future<Output = Result<(usize, SocketAddr)>> + Send;

    /// Send data to a specific target.
    fn send_to(&self, data: &[u8], target: SocketAddr) -> impl Future<Output = Result<()>> + Send;

    /// Local bind address.
    fn local_addr(&self) -> SocketAddr;
}

// ============================================================================
// Correlation envelope extraction (shared between transports)
// ============================================================================

/// Extract a checked v1/v2c version and borrowed community without allocating.
///
/// All length arithmetic is checked and the outer BER frame must exactly cover
/// the supplied packet. Malformed, truncated, v3, and overlong envelopes do not
/// produce an identity match.
pub(crate) fn extract_community_identity(data: &[u8]) -> Option<(Version, &[u8])> {
    if data.first().copied()? != 0x30 {
        return None;
    }
    let (outer_len, outer_len_bytes) = parse_ber_length(data.get(1..)?)?;
    let content_start = 1usize.checked_add(outer_len_bytes)?;
    let content_end = content_start.checked_add(outer_len)?;
    if content_end != data.len() {
        return None;
    }

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
    let version_num = decode_ber_signed_integer(data.get(pos..version_end)?);
    let version = Version::from_i32(version_num)?;
    if !matches!(version, Version::V1 | Version::V2c) {
        return None;
    }
    pos = version_end;

    if *data.get(pos)? != 0x04 {
        return None;
    }
    pos = pos.checked_add(1)?;
    let (community_len, community_len_bytes) = parse_ber_length(data.get(pos..)?)?;
    pos = pos.checked_add(community_len_bytes)?;
    let community_end = pos.checked_add(community_len)?;
    if community_end > content_end {
        return None;
    }
    Some((version, data.get(pos..community_end)?))
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
/// We need to navigate through BER encoding to find the appropriate ID.
pub(crate) fn extract_request_id(data: &[u8]) -> Option<i32> {
    let mut pos = 0;

    // Outer SEQUENCE
    if pos >= data.len() || data[pos] != 0x30 {
        return None;
    }
    pos += 1;

    // Skip outer SEQUENCE length
    let (_, consumed) = parse_ber_length(&data[pos..])?;
    pos += consumed;

    // Version (INTEGER)
    if pos >= data.len() || data[pos] != 0x02 {
        return None;
    }
    pos += 1;
    let (version_len, consumed) = parse_ber_length(&data[pos..])?;
    pos += consumed;

    // Read version value
    if pos + version_len > data.len() {
        return None;
    }
    let version = if version_len == 1 {
        i32::from(data[pos])
    } else {
        // Multi-byte version (unusual but handle it)
        let mut v: i32 = 0;
        for i in 0..version_len {
            v = (v << 8) | i32::from(data[pos + i]);
        }
        v
    };
    pos += version_len;

    // Check what comes next to determine V1/V2c vs V3
    if pos >= data.len() {
        return None;
    }

    let next_tag = data[pos];

    if version == 3 && next_tag == 0x30 {
        // V3: Next is msgGlobalData SEQUENCE, extract msgID from it
        extract_v3_msg_id(data, pos)
    } else if next_tag == 0x04 {
        // V1/V2c: Next is community OCTET STRING
        extract_v1v2c_request_id(data, pos)
    } else {
        None
    }
}

/// Extract msgID from V3 message starting at msgGlobalData position.
fn extract_v3_msg_id(data: &[u8], mut pos: usize) -> Option<i32> {
    // msgGlobalData SEQUENCE
    if pos >= data.len() || data[pos] != 0x30 {
        return None;
    }
    pos += 1;

    // Skip msgGlobalData SEQUENCE length
    let (_, consumed) = parse_ber_length(&data[pos..])?;
    pos += consumed;

    // First INTEGER inside msgGlobalData is msgID
    if pos >= data.len() || data[pos] != 0x02 {
        return None;
    }
    pos += 1;

    // Read msgID length
    let (id_len, consumed) = parse_ber_length(&data[pos..])?;
    pos += consumed;

    if pos + id_len > data.len() {
        return None;
    }

    // Decode msgID (signed integer, big-endian)
    Some(decode_ber_signed_integer(&data[pos..pos + id_len]))
}

/// Extract `request_id` from V1/V2c message starting at community position.
fn extract_v1v2c_request_id(data: &[u8], mut pos: usize) -> Option<i32> {
    // Community (OCTET STRING)
    if pos >= data.len() || data[pos] != 0x04 {
        return None;
    }
    pos += 1;
    let (community_len, consumed) = parse_ber_length(&data[pos..])?;
    pos += consumed + community_len;

    // PDU (context-specific, e.g., 0xA2 for Response)
    if pos >= data.len() {
        return None;
    }
    let pdu_tag = data[pos];
    // PDU tags are 0xA0-0xA8
    if !(0xA0..=0xA8).contains(&pdu_tag) {
        return None;
    }
    pos += 1;

    // Skip PDU length
    let (_, consumed) = parse_ber_length(&data[pos..])?;
    pos += consumed;

    // Request ID (INTEGER)
    if pos >= data.len() || data[pos] != 0x02 {
        return None;
    }
    pos += 1;

    // Read request_id length
    let (id_len, consumed) = parse_ber_length(&data[pos..])?;
    pos += consumed;

    if pos + id_len > data.len() {
        return None;
    }

    // Decode request_id (signed integer, big-endian)
    Some(decode_ber_signed_integer(&data[pos..pos + id_len]))
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
}

#[cfg(test)]
mod extract_tests {
    use super::*;

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
}
