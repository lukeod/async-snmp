//! Internal utilities.

use std::fmt;
use std::io;
use std::net::SocketAddr;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

/// Encode bytes as lowercase hex string.
pub fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Decode hex string to bytes.
///
/// Available in tests and when the `testing` feature is enabled.
/// Returns an error for invalid hex characters or odd-length strings.
#[cfg(any(test, feature = "testing"))]
pub fn decode_hex(s: &str) -> Result<Vec<u8>, HexDecodeError> {
    if !s.len().is_multiple_of(2) {
        return Err(HexDecodeError::OddLength);
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| HexDecodeError::InvalidChar))
        .collect()
}

/// Error type for hex decoding.
#[cfg(any(test, feature = "testing"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HexDecodeError {
    /// Input has odd length (must be pairs of hex digits)
    OddLength,
    /// Invalid hexadecimal character
    InvalidChar,
}

/// Lazy hex formatter - only formats when actually displayed.
///
/// This avoids allocation when logging at disabled levels.
pub(crate) struct HexBytes<'a>(pub &'a [u8]);

impl fmt::Debug for HexBytes<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl fmt::Display for HexBytes<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Create and bind a UDP socket with proper IPv6 configuration.
///
/// For IPv6 sockets, sets `IPV6_V6ONLY = true` to ensure the socket only
/// accepts IPv6 connections and does not use IPv4-mapped addresses.
///
/// # Arguments
///
/// * `addr` - The socket address to bind to. The domain (IPv4/IPv6) is
///   inferred from the address type.
///
/// # Returns
///
/// A tokio `UdpSocket` bound to the specified address.
pub(crate) async fn bind_udp_socket(addr: SocketAddr) -> io::Result<UdpSocket> {
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };

    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    // For IPv6 sockets, set IPV6_V6ONLY to true.
    // This ensures the socket only handles IPv6 traffic and doesn't accept
    // IPv4-mapped IPv6 addresses, providing cleaner and more predictable behavior.
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }

    // Allow address reuse for quick restarts
    socket.set_reuse_address(true)?;

    // Set non-blocking before converting to tokio socket
    socket.set_nonblocking(true)?;

    socket.bind(&addr.into())?;

    UdpSocket::from_std(socket.into())
}

/// Create an ephemeral UDP socket for connecting to a target.
///
/// Binds to `0.0.0.0:0` (IPv4) or `[::]:0` (IPv6) depending on the target
/// address family. For IPv6, sets `IPV6_V6ONLY = true`.
///
/// # Arguments
///
/// * `target` - The target address. Used to determine whether to create
///   an IPv4 or IPv6 socket.
///
/// # Returns
///
/// A tokio `UdpSocket` bound to an ephemeral port.
pub(crate) async fn bind_ephemeral_udp_socket(target: SocketAddr) -> io::Result<UdpSocket> {
    let bind_addr: SocketAddr = if target.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };

    bind_udp_socket(bind_addr).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_bytes_display() {
        let data = [0xde, 0xad, 0xbe, 0xef];
        let hex = HexBytes(&data);
        assert_eq!(format!("{}", hex), "deadbeef");
    }

    #[test]
    fn test_hex_bytes_debug() {
        let data = [0x00, 0xff, 0x42];
        let hex = HexBytes(&data);
        assert_eq!(format!("{:?}", hex), "00ff42");
    }

    #[test]
    fn test_hex_bytes_empty() {
        let data: [u8; 0] = [];
        let hex = HexBytes(&data);
        assert_eq!(format!("{}", hex), "");
    }

    #[tokio::test]
    async fn test_bind_udp_socket_ipv4() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let socket = bind_udp_socket(addr).await.unwrap();
        let local = socket.local_addr().unwrap();
        assert!(local.is_ipv4());
        assert_ne!(local.port(), 0);
    }

    #[tokio::test]
    async fn test_bind_udp_socket_ipv6() {
        let addr: SocketAddr = "[::1]:0".parse().unwrap();
        let socket = bind_udp_socket(addr).await.unwrap();
        let local = socket.local_addr().unwrap();
        assert!(local.is_ipv6());
        assert_ne!(local.port(), 0);
    }

    #[tokio::test]
    async fn test_bind_ephemeral_udp_socket_ipv4_target() {
        let target: SocketAddr = "192.168.1.1:161".parse().unwrap();
        let socket = bind_ephemeral_udp_socket(target).await.unwrap();
        let local = socket.local_addr().unwrap();
        assert!(local.is_ipv4());
        assert_ne!(local.port(), 0);
    }

    #[tokio::test]
    async fn test_bind_ephemeral_udp_socket_ipv6_target() {
        let target: SocketAddr = "[2001:db8::1]:161".parse().unwrap();
        let socket = bind_ephemeral_udp_socket(target).await.unwrap();
        let local = socket.local_addr().unwrap();
        assert!(local.is_ipv6());
        assert_ne!(local.port(), 0);
    }

    // ========================================================================
    // Hex Encode/Decode Tests
    // ========================================================================

    #[test]
    fn test_encode_hex_basic() {
        assert_eq!(encode_hex(b"Hello world!"), "48656c6c6f20776f726c6421");
        assert_eq!(encode_hex(&[0x01, 0x02, 0x03, 0x0f, 0x10]), "0102030f10");
    }

    #[test]
    fn test_encode_hex_empty() {
        assert_eq!(encode_hex(&[]), "");
    }

    #[test]
    fn test_encode_hex_all_bytes() {
        // Test boundary values
        assert_eq!(encode_hex(&[0x00]), "00");
        assert_eq!(encode_hex(&[0xff]), "ff");
        assert_eq!(encode_hex(&[0x00, 0xff]), "00ff");
    }

    #[test]
    fn test_decode_hex_basic() {
        assert_eq!(
            decode_hex("48656c6c6f20776f726c6421").unwrap(),
            b"Hello world!"
        );
        assert_eq!(
            decode_hex("0102030f10").unwrap(),
            vec![0x01, 0x02, 0x03, 0x0f, 0x10]
        );
    }

    #[test]
    fn test_decode_hex_empty() {
        assert_eq!(decode_hex("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn test_decode_hex_mixed_case() {
        // Both upper and lower case should work
        assert_eq!(
            decode_hex("deadbeef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(
            decode_hex("DEADBEEF").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(
            decode_hex("DeAdBeEf").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
    }

    #[test]
    fn test_decode_hex_odd_length_error() {
        assert_eq!(decode_hex("1"), Err(HexDecodeError::OddLength));
        assert_eq!(decode_hex("123"), Err(HexDecodeError::OddLength));
        assert_eq!(decode_hex("12345"), Err(HexDecodeError::OddLength));
    }

    #[test]
    fn test_decode_hex_invalid_char_error() {
        assert_eq!(decode_hex("gg"), Err(HexDecodeError::InvalidChar));
        assert_eq!(decode_hex("0g"), Err(HexDecodeError::InvalidChar));
        assert_eq!(decode_hex("g0"), Err(HexDecodeError::InvalidChar));
        assert_eq!(decode_hex("xx"), Err(HexDecodeError::InvalidChar));
        assert_eq!(decode_hex("  "), Err(HexDecodeError::InvalidChar)); // spaces
    }

    #[test]
    fn test_hex_roundtrip() {
        let original = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let encoded = encode_hex(&original);
        let decoded = decode_hex(&encoded).unwrap();
        assert_eq!(original, decoded);
    }
}
