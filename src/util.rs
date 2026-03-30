//! Internal utilities.

use std::io;
use std::net::SocketAddr;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

/// Create and bind a UDP socket with optional buffer sizes.
///
/// For IPv6 addresses, sets `IPV6_V6ONLY = false` to enable dual-stack mode
/// where supported (Linux). On macOS/BSD this flag may be ignored.
///
/// # Arguments
///
/// * `addr` - The socket address to bind to. Should match the target address family.
/// * `recv_buffer_size` - Optional receive buffer size (SO_RCVBUF). The kernel may cap
///   this at `net.core.rmem_max`. Larger buffers prevent packet loss during bursts.
/// * `send_buffer_size` - Optional send buffer size (SO_SNDBUF). The kernel may cap
///   this at `net.core.wmem_max`.
///
/// # Returns
///
/// A tokio `UdpSocket` bound to the specified address.
pub(crate) async fn bind_udp_socket(
    addr: SocketAddr,
    recv_buffer_size: Option<usize>,
    send_buffer_size: Option<usize>,
    reuse_address: bool,
) -> io::Result<UdpSocket> {
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };

    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    // For IPv6 sockets, attempt dual-stack mode. This works on Linux but
    // macOS/BSD may ignore it (IPV6_V6ONLY defaults to true on those platforms).
    if addr.is_ipv6() {
        socket.set_only_v6(false)?;
    }

    // SO_REUSEADDR allows another process to bind the same port and steal traffic.
    // Only enable for client sockets (ephemeral ports) where it helps with quick
    // restarts. Agent and notification listener sockets should not set this to
    // prevent port hijacking.
    if reuse_address {
        socket.set_reuse_address(true)?;
    }

    // Set buffer sizes if requested (kernel may cap at rmem_max/wmem_max)
    if let Some(size) = recv_buffer_size {
        let _ = socket.set_recv_buffer_size(size);
    }
    if let Some(size) = send_buffer_size {
        let _ = socket.set_send_buffer_size(size);
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
        let socket = bind_udp_socket(addr, None, None, true).await.unwrap();
        let local = socket.local_addr().unwrap();
        assert!(local.is_ipv4());
        assert_ne!(local.port(), 0);
    }

    #[tokio::test]
    async fn test_bind_udp_socket_ipv6() {
        let addr: SocketAddr = "[::1]:0".parse().unwrap();
        let socket = bind_udp_socket(addr, None, None, true).await.unwrap();
        let local = socket.local_addr().unwrap();
        assert!(local.is_ipv6());
        assert_ne!(local.port(), 0);
    }

    #[tokio::test]
    async fn test_bind_udp_socket_with_buffer_size() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let socket = bind_udp_socket(addr, Some(1024 * 1024), None, true)
            .await
            .unwrap();
        let local = socket.local_addr().unwrap();
        assert!(local.is_ipv4());
        assert_ne!(local.port(), 0);
    }
}
