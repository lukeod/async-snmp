//! UDP transport implementation for SNMP clients.
//!
//! This module provides [`UdpTransport`], a simple UDP-based transport for SNMP
//! communication. Each transport instance owns a "connected" UDP socket bound
//! to a specific target.
//!
//! # Connection Behavior
//!
//! Despite the term "connected", UDP sockets created by [`UdpTransport::connect()`]
//! do not establish a stateful connection like TCP. Instead, the kernel:
//!
//! 1. Associates the socket with the target address for `send()` calls
//! 2. Filters incoming packets to only accept those from the target
//! 3. Enables better error reporting (e.g., ICMP port unreachable)
//!
//! This is more efficient than unconnected UDP for single-target communication.
//!
//! # When to Use
//!
//! - **1-100 targets**: `UdpTransport` is simpler and sufficient
//! - **100+ targets**: Consider [`SharedUdpTransport`](super::SharedUdpTransport)
//!   to reduce socket overhead
//! - **Reliable delivery needed**: Use [`TcpTransport`](super::TcpTransport) instead
//!
//! # Example
//!
//! ```rust,no_run
//! use async_snmp::{Auth, Client};
//! use std::time::Duration;
//!
//! # async fn example() -> async_snmp::Result<()> {
//! // The standard way to create a UDP client
//! let client = Client::builder("192.168.1.1:161", Auth::v2c("public"))
//!     .timeout(Duration::from_secs(5))
//!     .retries(3)
//!     .connect()
//!     .await?;
//! # Ok(())
//! # }
//! ```
//!
//! For direct transport construction:
//!
//! ```rust,no_run
//! use async_snmp::transport::UdpTransport;
//! use async_snmp::{Client, ClientConfig};
//!
//! # async fn example() -> async_snmp::Result<()> {
//! let transport = UdpTransport::connect("192.168.1.1:161".parse().unwrap()).await?;
//! let client = Client::new(transport, ClientConfig::default());
//! # Ok(())
//! # }
//! ```

use super::{Transport, extract_request_id};
use crate::error::{Error, Result};
use crate::util::bind_ephemeral_udp_socket;
use bytes::Bytes;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// UDP transport for a single target.
///
/// Each `UdpTransport` owns a connected UDP socket to a specific target.
/// For high-throughput scenarios with many targets, consider using
/// [`SharedUdpTransport`](super::SharedUdpTransport) instead.
///
/// # Cloning
///
/// `UdpTransport` uses `Arc` internally, so cloning is cheap. Multiple clients
/// can share the same transport, though this is typically only useful for
/// different SNMP configurations to the same target.
///
/// # Concurrent Request Handling
///
/// When multiple concurrent requests are made through the same `UdpTransport`,
/// responses are properly correlated using request IDs. If a caller receives a
/// response for a different request, it buffers the response for the correct caller.
///
/// # Example
///
/// ```rust,no_run
/// use async_snmp::transport::UdpTransport;
/// use async_snmp::{Client, ClientConfig};
/// use std::time::Duration;
///
/// # async fn example() -> async_snmp::Result<()> {
/// // Connect with a timeout
/// let transport = UdpTransport::connect_timeout(
///     "192.168.1.1:161".parse().unwrap(),
///     Duration::from_secs(5)
/// ).await?;
///
/// let client = Client::new(transport, ClientConfig::default());
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct UdpTransport {
    inner: Arc<UdpTransportInner>,
}

struct UdpTransportInner {
    socket: UdpSocket,
    target: SocketAddr,
    local_addr: SocketAddr,
    /// Buffer for responses received by one caller but intended for another.
    pending: Mutex<HashMap<i32, Bytes>>,
}

impl UdpTransport {
    /// Connect to a target address.
    ///
    /// Creates an ephemeral UDP socket bound to the appropriate address family.
    /// For IPv6 targets, the socket has `IPV6_V6ONLY` set to true.
    pub async fn connect(target: SocketAddr) -> Result<Self> {
        tracing::debug!(snmp.target = %target, "connecting UDP transport");

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

        tracing::debug!(
            snmp.target = %target,
            snmp.local_addr = %local_addr,
            "UDP transport connected"
        );

        Ok(Self {
            inner: Arc::new(UdpTransportInner {
                socket,
                target,
                local_addr,
                pending: Mutex::new(HashMap::new()),
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
        tracing::trace!(
            snmp.target = %self.inner.target,
            snmp.bytes = data.len(),
            "UDP send"
        );
        self.inner.socket.send(data).await.map_err(|e| Error::Io {
            target: Some(self.inner.target),
            source: e,
        })?;
        Ok(())
    }

    async fn recv(&self, request_id: i32, recv_timeout: Duration) -> Result<(Bytes, SocketAddr)> {
        tracing::trace!(
            snmp.target = %self.inner.target,
            snmp.request_id = request_id,
            snmp.timeout_ms = recv_timeout.as_millis() as u64,
            "UDP recv waiting"
        );

        let deadline = Instant::now() + recv_timeout;

        loop {
            // Check pending buffer first
            {
                let mut pending = self.inner.pending.lock().unwrap();
                if let Some(data) = pending.remove(&request_id) {
                    tracing::trace!(
                        snmp.target = %self.inner.target,
                        snmp.request_id = request_id,
                        snmp.bytes = data.len(),
                        "UDP recv from pending buffer"
                    );
                    return Ok((data, self.inner.target));
                }
            }

            // Calculate remaining time
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                tracing::trace!(
                    snmp.target = %self.inner.target,
                    snmp.request_id = request_id,
                    "UDP recv timeout"
                );
                return Err(Error::Timeout {
                    target: Some(self.inner.target),
                    elapsed: recv_timeout,
                    request_id,
                    retries: 0,
                });
            }

            // Try to receive from socket
            let mut buf = vec![0u8; 65535];
            let result = timeout(remaining, self.inner.socket.recv(&mut buf)).await;

            match result {
                Ok(Ok(len)) => {
                    buf.truncate(len);
                    let data = Bytes::from(buf);

                    // Extract request_id from response
                    if let Some(recv_id) = extract_request_id(&data) {
                        if recv_id == request_id {
                            tracing::trace!(
                                snmp.target = %self.inner.target,
                                snmp.request_id = request_id,
                                snmp.bytes = len,
                                "UDP recv complete"
                            );
                            return Ok((data, self.inner.target));
                        } else {
                            // Buffer for another caller
                            tracing::trace!(
                                snmp.target = %self.inner.target,
                                snmp.expected_id = request_id,
                                snmp.received_id = recv_id,
                                snmp.bytes = len,
                                "UDP recv buffered for different request"
                            );
                            let mut pending = self.inner.pending.lock().unwrap();
                            pending.insert(recv_id, data);
                            // Continue loop to try again
                        }
                    } else {
                        // Could not extract request_id (malformed packet)
                        // Log and continue to try again
                        tracing::warn!(
                            snmp.target = %self.inner.target,
                            snmp.bytes = len,
                            "UDP recv could not extract request_id, discarding"
                        );
                    }
                }
                Ok(Err(e)) => {
                    tracing::trace!(
                        snmp.target = %self.inner.target,
                        error = %e,
                        "UDP recv error"
                    );
                    return Err(Error::Io {
                        target: Some(self.inner.target),
                        source: e,
                    });
                }
                Err(_) => {
                    tracing::trace!(
                        snmp.target = %self.inner.target,
                        snmp.request_id = request_id,
                        "UDP recv timeout"
                    );
                    return Err(Error::Timeout {
                        target: Some(self.inner.target),
                        elapsed: recv_timeout,
                        request_id,
                        retries: 0,
                    });
                }
            }
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
