//! UDP transport implementation.

use super::Transport;
use crate::error::{Error, Result};
use crate::util::bind_ephemeral_udp_socket;
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// UDP transport for a single target.
///
/// Each `UdpTransport` owns a connected UDP socket to a specific target.
/// For high-throughput scenarios with many targets, use `SharedUdpTransport` instead.
#[derive(Clone)]
pub struct UdpTransport {
    inner: Arc<UdpTransportInner>,
}

struct UdpTransportInner {
    socket: UdpSocket,
    target: SocketAddr,
    local_addr: SocketAddr,
}

impl UdpTransport {
    /// Connect to a target address.
    ///
    /// Creates an ephemeral UDP socket bound to the appropriate address family.
    /// For IPv6 targets, the socket has `IPV6_V6ONLY` set to true.
    pub async fn connect(target: SocketAddr) -> Result<Self> {
        let socket = bind_ephemeral_udp_socket(target)
            .await
            .map_err(|e| Error::Io {
                target: Some(target),
                source: e,
            })?;

        socket.connect(target).await.map_err(|e| Error::Io {
            target: Some(target),
            source: e,
        })?;

        let local_addr = socket.local_addr().map_err(|e| Error::Io {
            target: Some(target),
            source: e,
        })?;

        Ok(Self {
            inner: Arc::new(UdpTransportInner {
                socket,
                target,
                local_addr,
            }),
        })
    }

    /// Connect with a timeout.
    ///
    /// Creates an ephemeral UDP socket bound to the appropriate address family,
    /// with a timeout for the bind and connect operations.
    /// For IPv6 targets, the socket has `IPV6_V6ONLY` set to true.
    pub async fn connect_timeout(target: SocketAddr, connect_timeout: Duration) -> Result<Self> {
        let result = timeout(connect_timeout, Self::connect(target)).await;

        match result {
            Ok(inner) => inner,
            Err(_) => Err(Error::Timeout {
                target: Some(target),
                elapsed: connect_timeout,
                request_id: 0,
                retries: 0,
            }),
        }
    }
}

impl Transport for UdpTransport {
    async fn send(&self, data: &[u8]) -> Result<()> {
        self.inner.socket.send(data).await.map_err(|e| Error::Io {
            target: Some(self.inner.target),
            source: e,
        })?;
        Ok(())
    }

    async fn recv(&self, request_id: i32, recv_timeout: Duration) -> Result<(Bytes, SocketAddr)> {
        let mut buf = vec![0u8; 65535];

        let result = timeout(recv_timeout, self.inner.socket.recv(&mut buf)).await;

        match result {
            Ok(Ok(len)) => {
                buf.truncate(len);
                Ok((Bytes::from(buf), self.inner.target))
            }
            Ok(Err(e)) => Err(Error::Io {
                target: Some(self.inner.target),
                source: e,
            }),
            Err(_) => Err(Error::Timeout {
                target: Some(self.inner.target),
                elapsed: recv_timeout,
                request_id,
                retries: 0,
            }),
        }
    }

    fn peer_addr(&self) -> SocketAddr {
        self.inner.target
    }

    fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr
    }

    fn is_stream(&self) -> bool {
        false
    }
}
