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
//! # Response Demultiplexing
//!
//! A single background task reads all datagrams from the socket. Each incoming
//! response is matched to its caller by extracting the request ID (or msgID for
//! SNMPv3) from the packet header and looking up the corresponding pending
//! request slot. The pending map is sharded (64 shards, keyed by request ID) to
//! reduce lock contention under high concurrency.
//!
//! `connect()` creates a dedicated `UdpTransport` per client. `build_with()`
//! shares one `UdpTransport` across many clients - the demux logic is the same
//! in both cases; sharing just avoids duplicating the socket and recv task.
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
//! // Shared: multiple clients on one socket
//! let transport = UdpTransport::bind("0.0.0.0:0").await?;
//! let client1 = Client::builder("192.168.1.1:161", Auth::v2c("public"))
//!     .build_with(&transport).await?;
//! let client2 = Client::builder("192.168.1.2:161", Auth::v2c("public"))
//!     .build_with(&transport).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Address Family
//!
//! Bind to `0.0.0.0:0` for IPv4-only targets, `[::]:0` for IPv6-only targets,
//! or `[::]:0` for mixed IPv4/IPv6 targets. When an IPv6 transport is given an
//! IPv4 target, the address is automatically mapped to an IPv4-mapped IPv6
//! address (`::ffff:x.x.x.x`), ensuring cross-platform compatibility with
//! macOS and BSD (which default to `IPV6_V6ONLY=true`).

pub use super::udp_core::TransportStats;
use super::udp_core::UdpCore;
use super::{Transport, extract_request_id};
use crate::error::{Error, Result};
use crate::util::bind_udp_socket;
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
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
#[derive(Clone)]
pub struct UdpTransport {
    inner: Arc<UdpTransportInner>,
}

struct UdpTransportInner {
    socket: UdpSocket,
    local_addr: SocketAddr,
    core: UdpCore,
    config: UdpTransportConfig,
    shutdown: CancellationToken,
    recv_task: tokio::sync::Mutex<Option<JoinHandle<()>>>,
}

impl Drop for UdpTransport {
    fn drop(&mut self) {
        // Cancel the background receiver task when the last UdpTransport handle is dropped.
        // Arc::get_mut succeeds only when this is the last reference.
        if Arc::get_mut(&mut self.inner).is_some() {
            self.inner.shutdown.cancel();
        }
    }
}

impl UdpTransport {
    /// Bind to the given address with default configuration.
    ///
    /// Use `0.0.0.0:0` for IPv4 targets or `[::]:0` for IPv6 targets.
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
    ///
    /// When the transport is bound to an IPv6 socket and the target is IPv4,
    /// the target is automatically mapped to an IPv4-mapped IPv6 address
    /// (`::ffff:x.x.x.x`) for cross-platform dual-stack compatibility.
    pub fn handle(&self, target: SocketAddr) -> UdpHandle {
        let target = self.map_to_socket_family(target);
        UdpHandle {
            inner: self.inner.clone(),
            target,
        }
    }

    /// Map a target address to match this transport's socket family.
    ///
    /// Converts IPv4 targets to IPv4-mapped IPv6 addresses when the socket
    /// is IPv6, enabling dual-stack usage on platforms where the kernel does
    /// not perform this mapping implicitly (macOS, BSD).
    fn map_to_socket_family(&self, target: SocketAddr) -> SocketAddr {
        if let SocketAddr::V4(v4) = target
            && self.inner.local_addr.is_ipv6()
        {
            return SocketAddr::new(std::net::IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port());
        }
        target
    }

    /// Get the local bind address.
    pub fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr
    }

    /// Snapshot transport statistics.
    ///
    /// Returns cumulative counters for delivered and expired requests.
    /// Useful for monitoring transport health under load.
    pub fn stats(&self) -> TransportStats {
        self.inner.core.stats()
    }

    /// Shutdown the transport, stopping the background receiver.
    ///
    /// Signals the background recv task to stop and waits for it to exit.
    /// Pending requests will fail with timeout errors.
    pub async fn shutdown(&self) {
        self.inner.shutdown.cancel();
        let handle = self.inner.recv_task.lock().await.take();
        if let Some(handle) = handle {
            let _ = handle.await;
        }
    }

    fn start_recv_loop(inner: &Arc<UdpTransportInner>) {
        let task_inner = inner.clone();
        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; UDP_RECV_BUFFER_SIZE];
            let mut cleanup_interval = tokio::time::interval(Duration::from_secs(1));

            loop {
                tokio::select! {
                    biased;

                    _ = task_inner.shutdown.cancelled() => {
                        tracing::debug!(target: "async_snmp::transport", { snmp.local_addr = %task_inner.local_addr }, "UDP transport shutdown");
                        break;
                    }

                    _ = cleanup_interval.tick() => {
                        task_inner.core.cleanup_expired();
                    }

                    result = task_inner.socket.recv_from(&mut buf) => {
                        match result {
                            Ok((len, source)) => {
                                let data = Bytes::copy_from_slice(&buf[..len]);

                                if let Some(request_id) = extract_request_id(&data) {
                                    if !task_inner.core.deliver(request_id, data, source) {
                                        tracing::debug!(target: "async_snmp::transport", { snmp.request_id = request_id, snmp.source = %source }, "response for unknown request");
                                    }
                                } else {
                                    tracing::debug!(target: "async_snmp::transport", { snmp.source = %source, snmp.bytes = len }, "malformed response (no request_id)");
                                }
                            }
                            Err(_) if task_inner.shutdown.is_cancelled() => break,
                            Err(e) => {
                                tracing::error!(target: "async_snmp::transport", { error = %e }, "UDP recv error");
                            }
                        }
                    }
                }
            }
        });
        // Safe: mutex was just created, no contention possible
        *inner
            .recv_task
            .try_lock()
            .expect("recv_task lock at startup") = Some(handle);
    }
}

/// Builder for [`UdpTransport`].
pub struct UdpTransportBuilder {
    bind_addr: String,
    config: UdpTransportConfig,
    recv_buffer_size: Option<usize>,
    send_buffer_size: Option<usize>,
}

impl UdpTransportBuilder {
    /// Create a new builder with default settings.
    ///
    /// Default bind address is `0.0.0.0:0` (IPv4).
    pub fn new() -> Self {
        Self {
            bind_addr: "0.0.0.0:0".into(),
            config: UdpTransportConfig::default(),
            recv_buffer_size: None,
            send_buffer_size: None,
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

    /// Set the socket receive buffer size (SO_RCVBUF).
    ///
    /// When left unset, the OS default applies (typically 212KB on Linux).
    /// With a shared transport handling many targets, the default may be
    /// too small - if responses arrive faster than the recv loop processes
    /// them, the kernel drops datagrams. A rough guide: estimate peak
    /// inbound packets/sec, multiply by average response size (~200-500
    /// bytes for typical SNMP), and size the buffer for at least 500ms of
    /// burst capacity.
    ///
    /// The kernel may cap this at `net.core.rmem_max`. If you see
    /// unexplained timeouts under load, check for UDP buffer overflows
    /// with `cat /proc/net/snmp | grep Udp` (the `RcvbufErrors` column).
    pub fn recv_buffer_size(mut self, size: usize) -> Self {
        self.recv_buffer_size = Some(size);
        self
    }

    /// Set the socket send buffer size (SO_SNDBUF).
    ///
    /// The kernel may cap this at `net.core.wmem_max`.
    pub fn send_buffer_size(mut self, size: usize) -> Self {
        self.send_buffer_size = Some(size);
        self
    }

    /// Build the transport.
    pub async fn build(self) -> Result<UdpTransport> {
        let bind_addr: SocketAddr = self.bind_addr.parse().map_err(|_| {
            Error::Config(format!("invalid bind address: {}", self.bind_addr).into())
        })?;

        let socket = bind_udp_socket(
            bind_addr,
            self.recv_buffer_size,
            self.send_buffer_size,
            true,
        )
        .await
        .map_err(|e| Error::Network {
            target: bind_addr,
            source: e,
        })?;

        let local_addr = socket.local_addr().map_err(|e| Error::Network {
            target: bind_addr,
            source: e,
        })?;

        tracing::debug!(target: "async_snmp::transport", { snmp.local_addr = %local_addr }, "UDP transport bound");

        let inner = Arc::new(UdpTransportInner {
            socket,
            local_addr,
            core: UdpCore::new(),
            config: self.config,
            shutdown: CancellationToken::new(),
            recv_task: tokio::sync::Mutex::new(None),
        });

        UdpTransport::start_recv_loop(&inner);

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
        tracing::trace!(target: "async_snmp::transport", { snmp.target = %self.target, snmp.bytes = data.len() }, "UDP send");
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
        tracing::trace!(target: "async_snmp::transport", { snmp.target = %self.target, snmp.request_id = request_id }, "UDP recv waiting");

        let result = self
            .inner
            .core
            .wait_for_response(request_id, self.target)
            .await;

        match &result {
            Ok((data, source)) => {
                // Warn on source mismatch
                if self.inner.config.warn_on_source_mismatch && *source != self.target {
                    tracing::warn!(target: "async_snmp::transport", { snmp.request_id = request_id, snmp.target = %self.target, snmp.source = %source }, "response source address mismatch");
                }
                tracing::trace!(target: "async_snmp::transport", { snmp.target = %self.target, snmp.source = %source, snmp.bytes = data.len() }, "UDP recv complete");
            }
            Err(_) => {
                tracing::trace!(target: "async_snmp::transport", { snmp.target = %self.target, snmp.request_id = request_id }, "UDP recv failed");
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

    fn max_message_size(&self) -> u32 {
        self.inner.config.max_message_size as u32
    }

    fn is_reliable(&self) -> bool {
        false
    }

    fn register_request(&self, request_id: i32, timeout: Duration) {
        self.inner.core.register(request_id, timeout);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ipv6_transport_maps_ipv4_target() {
        let transport = UdpTransport::bind("[::]:0").await.unwrap();
        let handle = transport.handle("127.0.0.1:161".parse().unwrap());
        let mapped: SocketAddr = "[::ffff:127.0.0.1]:161".parse().unwrap();
        assert_eq!(handle.peer_addr(), mapped);
    }

    #[tokio::test]
    async fn ipv4_transport_preserves_ipv4_target() {
        let transport = UdpTransport::bind("0.0.0.0:0").await.unwrap();
        let handle = transport.handle("127.0.0.1:161".parse().unwrap());
        let expected: SocketAddr = "127.0.0.1:161".parse().unwrap();
        assert_eq!(handle.peer_addr(), expected);
    }

    #[tokio::test]
    async fn ipv6_transport_preserves_ipv6_target() {
        let transport = UdpTransport::bind("[::]:0").await.unwrap();
        let handle = transport.handle("[::1]:161".parse().unwrap());
        let expected: SocketAddr = "[::1]:161".parse().unwrap();
        assert_eq!(handle.peer_addr(), expected);
    }

    #[tokio::test]
    async fn max_message_size_default() {
        let transport = UdpTransport::bind("0.0.0.0:0").await.unwrap();
        let handle = transport.handle("127.0.0.1:161".parse().unwrap());
        // Default config is 1472
        assert_eq!(handle.max_message_size(), 1472);
    }

    #[tokio::test]
    async fn max_message_size_custom() {
        let transport = UdpTransport::builder()
            .max_message_size(8192)
            .build()
            .await
            .unwrap();
        let handle = transport.handle("127.0.0.1:161".parse().unwrap());
        assert_eq!(handle.max_message_size(), 8192);
    }

    #[tokio::test]
    async fn recv_buffer_size_configurable() {
        // Should not panic or fail - kernel may cap the value
        let transport = UdpTransport::builder()
            .recv_buffer_size(2 * 1024 * 1024)
            .build()
            .await
            .unwrap();
        assert!(transport.local_addr().port() > 0);
    }

    #[tokio::test]
    async fn send_buffer_size_configurable() {
        let transport = UdpTransport::builder()
            .send_buffer_size(512 * 1024)
            .build()
            .await
            .unwrap();
        assert!(transport.local_addr().port() > 0);
    }
}
