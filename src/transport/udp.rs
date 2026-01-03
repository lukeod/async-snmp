//! Unified UDP transport for SNMP clients.
//!
//! This module provides [`UdpTransport`] (the socket owner) and [`UdpHandle`]
//! (per-target handles that implement [`Transport`]).
//!
//! # Architecture
//!
//! ```text
//! +------------------+
//! |   UdpTransport   |  (owns socket, runs recv loop, manages shutdown)
//! +------------------+
//!          |
//!          | Arc<UdpTransportInner>
//!          v
//! +------------------+     +------------------+     +------------------+
//! |    UdpHandle     |     |    UdpHandle     |     |    UdpHandle     |
//! |  target: 10.0.0.1|     |  target: 10.0.0.2|     |  target: 10.0.0.3|
//! +------------------+     +------------------+     +------------------+
//!          |                        |                        |
//!          v                        v                        v
//! +------------------+     +------------------+     +------------------+
//! | Client<UdpHandle>|     | Client<UdpHandle>|     | Client<UdpHandle>|
//! +------------------+     +------------------+     +------------------+
//! ```
//!
//! # Usage
//!
//! ```rust,no_run
//! use async_snmp::{Auth, Client};
//! use async_snmp::transport::UdpTransport;
//!
//! # async fn example() -> async_snmp::Result<()> {
//! // Simple: Client creates transport internally
//! let client = Client::builder("192.168.1.1:161", Auth::v2c("public"))
//!     .connect()
//!     .await?;
//!
//! // High-throughput: share transport across clients (IPv4 and IPv6)
//! let transport = UdpTransport::bind("[::]:0").await?;
//! let client1 = Client::builder("192.168.1.1:161", Auth::v2c("public"))
//!     .build_with(&transport)?;
//! let client2 = Client::builder("[::1]:161", Auth::v2c("public"))
//!     .build_with(&transport)?;  // Same transport handles both!
//! # Ok(())
//! # }
//! ```
//!
//! # Dual-Stack Support
//!
//! The default bind address `[::]:0` creates a dual-stack socket that handles
//! both IPv4 and IPv6 targets. IPv4 addresses are transparently mapped to
//! IPv4-mapped IPv6 addresses (`::ffff:x.x.x.x`).
//!
//! Note: Dual-stack behavior follows Linux conventions. Other platforms
//! (Windows, BSD) are untested and may require separate IPv4/IPv6 sockets.

use super::udp_core::UdpCore;
use super::{Transport, extract_request_id};
use crate::error::{Error, Result};
use crate::util::bind_udp_socket;
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

/// Maximum UDP datagram size for receiving.
///
/// This is the UDP payload limit: 65535 - 20 (IP header) - 8 (UDP header) = 65507.
/// We use 65535 to be safe with any potential header variations.
const UDP_RECV_BUFFER_SIZE: usize = 65535;

/// Configuration for UDP transport.
#[derive(Clone)]
pub struct UdpTransportConfig {
    /// Maximum message size for sending (default: 1472, fits Ethernet MTU).
    ///
    /// This affects the advertised msgMaxSize in SNMPv3 requests. The receive
    /// buffer is always sized to accept the maximum UDP datagram (65535 bytes).
    pub max_message_size: usize,
    /// Log warning when response source differs from target (default: true)
    pub warn_on_source_mismatch: bool,
}

impl Default for UdpTransportConfig {
    fn default() -> Self {
        Self {
            max_message_size: 1472,
            warn_on_source_mismatch: true,
        }
    }
}

/// UDP transport that can serve multiple targets.
///
/// Owns a single UDP socket and spawns a background receiver task.
/// Create [`UdpHandle`]s for each target via [`handle()`](Self::handle).
pub struct UdpTransport {
    inner: Arc<UdpTransportInner>,
}

struct UdpTransportInner {
    socket: UdpSocket,
    local_addr: SocketAddr,
    core: UdpCore,
    config: UdpTransportConfig,
    shutdown: CancellationToken,
}

impl UdpTransport {
    /// Bind to the given address with default configuration.
    ///
    /// For dual-stack support (both IPv4 and IPv6 targets), bind to `[::]:0`.
    pub async fn bind(addr: impl AsRef<str>) -> Result<Self> {
        Self::builder().bind(addr).build().await
    }

    /// Create a builder for custom configuration.
    pub fn builder() -> UdpTransportBuilder {
        UdpTransportBuilder::new()
    }

    /// Create a handle for a specific target.
    ///
    /// Handles implement [`Transport`] and can be used with [`Client`](crate::Client).
    pub fn handle(&self, target: SocketAddr) -> UdpHandle {
        UdpHandle {
            inner: self.inner.clone(),
            target,
        }
    }

    /// Get the local bind address.
    pub fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr
    }

    /// Shutdown the transport, stopping the background receiver.
    ///
    /// Pending requests will fail with timeout errors.
    pub fn shutdown(&self) {
        self.inner.shutdown.cancel();
    }

    fn start_recv_loop(inner: Arc<UdpTransportInner>) {
        tokio::spawn(async move {
            let mut buf = vec![0u8; UDP_RECV_BUFFER_SIZE];
            let mut cleanup_interval = tokio::time::interval(Duration::from_secs(1));

            loop {
                tokio::select! {
                    biased;

                    _ = inner.shutdown.cancelled() => {
                        tracing::debug!(
                            snmp.local_addr = %inner.local_addr,
                            "UDP transport shutdown"
                        );
                        break;
                    }

                    _ = cleanup_interval.tick() => {
                        inner.core.cleanup_expired();
                    }

                    result = inner.socket.recv_from(&mut buf) => {
                        match result {
                            Ok((len, source)) => {
                                let data = Bytes::copy_from_slice(&buf[..len]);

                                if let Some(request_id) = extract_request_id(&data) {
                                    if !inner.core.deliver(request_id, data, source) {
                                        tracing::debug!(
                                            snmp.request_id = request_id,
                                            snmp.source = %source,
                                            "response for unknown request"
                                        );
                                    }
                                } else {
                                    tracing::debug!(
                                        snmp.source = %source,
                                        snmp.bytes = len,
                                        "malformed response (no request_id)"
                                    );
                                }
                            }
                            Err(e) if inner.shutdown.is_cancelled() => break,
                            Err(e) => {
                                tracing::error!(error = %e, "UDP recv error");
                            }
                        }
                    }
                }
            }
        });
    }
}

/// Builder for [`UdpTransport`].
pub struct UdpTransportBuilder {
    bind_addr: String,
    config: UdpTransportConfig,
}

impl UdpTransportBuilder {
    /// Create a new builder with default settings.
    ///
    /// Default bind address is `[::]:0` for dual-stack support.
    pub fn new() -> Self {
        Self {
            bind_addr: "[::]:0".into(),
            config: UdpTransportConfig::default(),
        }
    }

    /// Set the local bind address.
    pub fn bind(mut self, addr: impl AsRef<str>) -> Self {
        self.bind_addr = addr.as_ref().to_string();
        self
    }

    /// Set maximum message size for sending (default: 1472 bytes).
    ///
    /// This affects the advertised msgMaxSize in SNMPv3 requests. The receive
    /// buffer is always sized to accept any valid UDP datagram (65535 bytes).
    pub fn max_message_size(mut self, size: usize) -> Self {
        self.config.max_message_size = size;
        self
    }

    /// Configure warning on source address mismatch (default: true).
    pub fn warn_on_source_mismatch(mut self, warn: bool) -> Self {
        self.config.warn_on_source_mismatch = warn;
        self
    }

    /// Build the transport.
    pub async fn build(self) -> Result<UdpTransport> {
        let bind_addr: SocketAddr = self.bind_addr.parse().map_err(|_| {
            Error::Config(format!("invalid bind address: {}", self.bind_addr).into())
        })?;

        let socket = bind_udp_socket(bind_addr, None)
            .await
            .map_err(|e| Error::Network {
                target: bind_addr,
                source: e,
            })?;

        let local_addr = socket.local_addr().map_err(|e| Error::Network {
            target: bind_addr,
            source: e,
        })?;

        tracing::debug!(
            snmp.local_addr = %local_addr,
            "UDP transport bound"
        );

        let inner = Arc::new(UdpTransportInner {
            socket,
            local_addr,
            core: UdpCore::new(),
            config: self.config,
            shutdown: CancellationToken::new(),
        });

        UdpTransport::start_recv_loop(inner.clone());

        Ok(UdpTransport { inner })
    }
}

impl Default for UdpTransportBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Handle to a UDP transport for a specific target.
///
/// Implements [`Transport`] and can be used with [`Client`](crate::Client).
/// Cheap to clone (Arc + SocketAddr).
#[derive(Clone)]
pub struct UdpHandle {
    inner: Arc<UdpTransportInner>,
    target: SocketAddr,
}

impl Transport for UdpHandle {
    async fn send(&self, data: &[u8]) -> Result<()> {
        tracing::trace!(
            snmp.target = %self.target,
            snmp.bytes = data.len(),
            "UDP send"
        );
        self.inner
            .socket
            .send_to(data, self.target)
            .await
            .map_err(|e| Error::Network {
                target: self.target,
                source: e,
            })?;
        Ok(())
    }

    async fn recv(&self, request_id: i32) -> Result<(Bytes, SocketAddr)> {
        tracing::trace!(
            snmp.target = %self.target,
            snmp.request_id = request_id,
            "UDP recv waiting"
        );

        let result = self
            .inner
            .core
            .wait_for_response(request_id, self.target)
            .await;

        match &result {
            Ok((data, source)) => {
                // Warn on source mismatch
                if self.inner.config.warn_on_source_mismatch && *source != self.target {
                    tracing::warn!(
                        snmp.request_id = request_id,
                        snmp.target = %self.target,
                        snmp.source = %source,
                        "response source address mismatch"
                    );
                }
                tracing::trace!(
                    snmp.target = %self.target,
                    snmp.source = %source,
                    snmp.bytes = data.len(),
                    "UDP recv complete"
                );
            }
            Err(_) => {
                tracing::trace!(
                    snmp.target = %self.target,
                    snmp.request_id = request_id,
                    "UDP recv failed"
                );
            }
        }

        result
    }

    fn peer_addr(&self) -> SocketAddr {
        self.target
    }

    fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr
    }

    fn is_reliable(&self) -> bool {
        false
    }

    fn register_request(&self, request_id: i32, timeout: Duration) {
        self.inner.core.register(request_id, timeout);
    }
}
