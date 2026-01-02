//! Internal utilities.

use std::io;
use std::net::SocketAddr;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

/// Create and bind a UDP socket with optional receive buffer size.
///
/// For IPv6 addresses, sets `IPV6_V6ONLY = false` to enable dual-stack mode,
/// allowing both IPv4 and IPv6 traffic on a single socket.
///
/// # Arguments
///
/// * `addr` - The socket address to bind to. For dual-stack, use `[::]:port`.
/// * `recv_buffer_size` - Optional receive buffer size. The kernel may cap this
///   at `net.core.rmem_max`. Larger buffers prevent packet loss during bursts.
///
/// # Returns
///
/// A tokio `UdpSocket` bound to the specified address.
pub(crate) async fn bind_udp_socket(
    addr: SocketAddr,
    recv_buffer_size: Option<usize>,
) -> io::Result<UdpSocket> {
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };

    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    // For IPv6 sockets, set IPV6_V6ONLY to false for dual-stack support.
    // This allows a single socket to handle both IPv4 and IPv6 traffic.
    if addr.is_ipv6() {
        socket.set_only_v6(false)?;
    }

    // Allow address reuse for quick restarts
    socket.set_reuse_address(true)?;

    // Set receive buffer size if requested (kernel may cap at rmem_max)
    if let Some(size) = recv_buffer_size {
        // Ignore errors - kernel will cap at rmem_max
        let _ = socket.set_recv_buffer_size(size);
    }

    // Set non-blocking before converting to tokio socket
    socket.set_nonblocking(true)?;

    socket.bind(&addr.into())?;

    UdpSocket::from_std(socket.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_bind_udp_socket_ipv4() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let socket = bind_udp_socket(addr, None).await.unwrap();
        let local = socket.local_addr().unwrap();
        assert!(local.is_ipv4());
        assert_ne!(local.port(), 0);
    }

    #[tokio::test]
    async fn test_bind_udp_socket_ipv6() {
        let addr: SocketAddr = "[::1]:0".parse().unwrap();
        let socket = bind_udp_socket(addr, None).await.unwrap();
        let local = socket.local_addr().unwrap();
        assert!(local.is_ipv6());
        assert_ne!(local.port(), 0);
    }

    #[tokio::test]
    async fn test_bind_udp_socket_with_buffer_size() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let socket = bind_udp_socket(addr, Some(1024 * 1024)).await.unwrap();
        let local = socket.local_addr().unwrap();
        assert!(local.is_ipv4());
        assert_ne!(local.port(), 0);
    }
}
