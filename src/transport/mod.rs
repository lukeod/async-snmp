//! Transport layer abstraction for SNMP communication.
//!
//! This module provides the [`Transport`] trait and implementations:
//!
//! - [`UdpTransport`] + [`UdpHandle`] - UDP socket with per-target handles
//! - [`TcpTransport`] - TCP stream with BER framing
//!
//! # Choosing a Transport
//!
//! | Scenario | Recommended Approach |
//! |----------|---------------------|
//! | Simple use | [`Client::builder().connect()`](crate::Client::builder) |
//! | Multiple targets | Share a [`UdpTransport`] via [`build_with()`](crate::ClientBuilder::build_with) |
//! | Firewall/NAT | [`Client::builder().connect_tcp()`](crate::ClientBuilder::connect_tcp) |
//!
//! Most users should use [`Client::builder()`](crate::Client::builder) which creates
//! the appropriate transport automatically.

mod tcp;
mod udp;
mod udp_core;

pub use tcp::*;
pub use udp::*;

use crate::error::Result;
use bytes::Bytes;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::Duration;

/// Global request ID counter, initialized with random seed.
///
/// Using a global counter ensures request IDs are unique across all
/// transports within the process, preventing collisions when multiple
/// transports exist or when sockets are rapidly recreated.
static REQUEST_ID_COUNTER: LazyLock<AtomicI32> = LazyLock::new(|| {
    use std::time::{SystemTime, UNIX_EPOCH};
    let time_component = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i32)
        .unwrap_or(1);
    let pid_component = std::process::id() as i32;
    AtomicI32::new(time_component.wrapping_add(pid_component))
});

/// Allocate a globally unique request ID.
///
/// Returns a positive non-zero i32 (range 1..=2147483647) that is unique
/// within this process. Per RFC 1157/3412, request-id/msgID is defined as
/// INTEGER (0..2147483647), and some implementations may not handle negative
/// values correctly.
///
/// The counter is seeded with time + PID to minimize collision risk across
/// process restarts.
pub fn alloc_request_id() -> i32 {
    loop {
        let id = REQUEST_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
        let id = id & 0x7FFFFFFF;
        if id != 0 {
            return id;
        }
    }
}

/// Client-side transport abstraction.
///
/// All transports implement this trait uniformly. For shared transports,
/// handles (not the pool itself) implement Transport.
pub trait Transport: Send + Sync + Clone {
    /// Send request data to the target.
    fn send(&self, data: &[u8]) -> impl Future<Output = Result<()>> + Send;

    /// Wait for response. Uses deadline set by `register_request()`.
    ///
    /// For UDP transports, the deadline was stored during registration.
    /// For TCP transports, uses the timeout parameter.
    fn recv(&self, request_id: i32) -> impl Future<Output = Result<(Bytes, SocketAddr)>> + Send;

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

    /// Pre-register a request with timeout before sending.
    ///
    /// UDP transports use this to create the response slot with deadline.
    /// TCP transports ignore this (default no-op).
    fn register_request(&self, _request_id: i32, _timeout: Duration) {
        // Default: no-op for TCP and other transports that don't need pre-registration
    }

    /// Maximum message size this transport can handle.
    ///
    /// Used to cap agent-reported msgMaxSize values. Default is the maximum
    /// UDP datagram payload (65507 bytes).
    fn max_message_size(&self) -> u32 {
        65507
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
// Request ID Extraction (shared between transports)
// ============================================================================

/// Extract request_id (or msgID for V3) from an SNMP response.
///
/// SNMP message structure differs by version:
///
/// V1/V2c:
/// - SEQUENCE { INTEGER version, OCTET STRING community, PDU }
/// - PDU contains request_id as first INTEGER
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
    pos = skip_ber_length(data, pos)?;

    // Version (INTEGER)
    if pos >= data.len() || data[pos] != 0x02 {
        return None;
    }
    pos += 1;
    let (new_pos, version_len) = read_ber_length(data, pos)?;
    pos = new_pos;

    // Read version value
    if pos + version_len > data.len() {
        return None;
    }
    let version = if version_len == 1 {
        data[pos] as i32
    } else {
        // Multi-byte version (unusual but handle it)
        let mut v: i32 = 0;
        for i in 0..version_len {
            v = (v << 8) | (data[pos + i] as i32);
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
    pos = skip_ber_length(data, pos)?;

    // First INTEGER inside msgGlobalData is msgID
    if pos >= data.len() || data[pos] != 0x02 {
        return None;
    }
    pos += 1;

    // Read msgID length
    let (new_pos, id_len) = read_ber_length(data, pos)?;
    pos = new_pos;

    if pos + id_len > data.len() {
        return None;
    }

    // Decode msgID (signed integer, big-endian)
    decode_ber_signed_integer(&data[pos..pos + id_len])
}

/// Extract request_id from V1/V2c message starting at community position.
fn extract_v1v2c_request_id(data: &[u8], mut pos: usize) -> Option<i32> {
    // Community (OCTET STRING)
    if pos >= data.len() || data[pos] != 0x04 {
        return None;
    }
    pos += 1;
    let (new_pos, community_len) = read_ber_length(data, pos)?;
    pos = new_pos + community_len;

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
    pos = skip_ber_length(data, pos)?;

    // Request ID (INTEGER)
    if pos >= data.len() || data[pos] != 0x02 {
        return None;
    }
    pos += 1;

    // Read request_id length
    let (new_pos, id_len) = read_ber_length(data, pos)?;
    pos = new_pos;

    if pos + id_len > data.len() {
        return None;
    }

    // Decode request_id (signed integer, big-endian)
    decode_ber_signed_integer(&data[pos..pos + id_len])
}

/// Decode a BER-encoded signed integer.
fn decode_ber_signed_integer(bytes: &[u8]) -> Option<i32> {
    if bytes.is_empty() {
        return Some(0);
    }

    // Sign extend for negative numbers
    let mut value: i32 = if bytes[0] & 0x80 != 0 { -1 } else { 0 };

    for &byte in bytes {
        value = (value << 8) | (byte as i32);
    }

    Some(value)
}

/// Skip BER length field and return new position.
fn skip_ber_length(data: &[u8], pos: usize) -> Option<usize> {
    let (new_pos, _) = read_ber_length(data, pos)?;
    Some(new_pos)
}

/// Read BER length field.
/// Returns (new_position, length_value).
fn read_ber_length(data: &[u8], pos: usize) -> Option<(usize, usize)> {
    if pos >= data.len() {
        return None;
    }

    let first = data[pos];

    if first < 0x80 {
        // Short form
        Some((pos + 1, first as usize))
    } else if first == 0x80 {
        // Indefinite length - not supported
        None
    } else {
        // Long form
        let num_octets = (first & 0x7F) as usize;
        if pos + 1 + num_octets > data.len() {
            return None;
        }

        let mut length: usize = 0;
        for i in 0..num_octets {
            length = (length << 8) | (data[pos + 1 + i] as usize);
        }

        Some((pos + 1 + num_octets, length))
    }
}

#[cfg(test)]
mod request_id_tests {
    use super::*;
    use std::sync::atomic::AtomicI32;

    /// RFC 1157 and RFC 3412 define request-id/msgID as INTEGER (0..2147483647).
    #[test]
    fn request_id_is_always_positive() {
        for _ in 0..10_000 {
            let id = alloc_request_id();
            assert!(id > 0, "request ID must be positive, got {}", id);
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

    /// Validates wrap-around: counter going from i32::MAX to negative must
    /// still produce positive values via 31-bit masking (RFC 3412 range).
    #[test]
    fn request_id_wrap_around_stays_positive() {
        let counter = AtomicI32::new(i32::MAX - 100);

        let alloc_test_id = || -> i32 {
            loop {
                let id = counter.fetch_add(1, Ordering::Relaxed);
                let id = id & 0x7FFFFFFF;
                if id != 0 {
                    return id;
                }
            }
        };

        for i in 0..200 {
            let id = alloc_test_id();
            assert!(
                id > 0,
                "request ID must be positive after wrap, iteration {}, got {}",
                i,
                id
            );
        }
    }

    #[test]
    fn request_ids_are_unique() {
        use std::collections::HashSet;

        let mut seen = HashSet::new();
        for _ in 0..10_000 {
            let id = alloc_request_id();
            assert!(seen.insert(id), "request ID {} was allocated twice", id);
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
            0x30, 0x35, // SEQUENCE
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
            0x30, 0x19, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa2,
            0x0c, 0x02, 0x01, 0xff, // INTEGER -1
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
}
