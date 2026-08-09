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
//! `SNMPv3`) from the packet header and looking up the corresponding pending
//! request slot. V1/v2c slots additionally enforce the registered version and
//! community policy before consuming a response. The pending map is sharded (64 shards, keyed by request ID) to
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
//! address (`::ffff:x.x.x.x`). An IPv4 transport accepts IPv4 and mapped IPv6
//! targets, but rejects native IPv6 targets during handle construction.

pub use super::udp_core::TransportStats;
use super::udp_core::UdpCore;
use super::{Candidate, RequestRegistration, Transport, extract_request_id};
use crate::error::{Error, Result};
use crate::message_size::{ReceiveLimits, UDP_RECEIVE_BUFFER_SIZE};
use crate::util::bind_udp_socket;
use bytes::Bytes;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tokio_util::sync::{CancellationToken, DropGuard};

/// Initial backoff applied after a UDP recv error before retrying, doubling up
/// to [`UDP_RECV_ERROR_BACKOFF_MAX`] while errors persist.
const UDP_RECV_ERROR_BACKOFF_MIN: Duration = Duration::from_millis(1);

/// Upper bound for the recv-error backoff.
const UDP_RECV_ERROR_BACKOFF_MAX: Duration = Duration::from_millis(100);

/// Computes the next recv-error backoff from the current one: the first error
/// starts at [`UDP_RECV_ERROR_BACKOFF_MIN`], subsequent errors double up to
/// [`UDP_RECV_ERROR_BACKOFF_MAX`]. A zero input means no prior error.
fn next_recv_error_backoff(current: Duration) -> Duration {
    match current {
        Duration::ZERO => UDP_RECV_ERROR_BACKOFF_MIN,
        d => (d * 2).min(UDP_RECV_ERROR_BACKOFF_MAX),
    }
}

/// Configuration for UDP transport.
#[derive(Clone)]
struct UdpTransportConfig {
    /// Maximum message size for sending (default: 1472, fits Ethernet MTU).
    ///
    /// This affects the advertised msgMaxSize in `SNMPv3` requests. The receive
    /// buffer is always sized to accept the maximum UDP datagram (65535 bytes).
    max_message_size: usize,
    /// Log warning when response source differs from target (default: true)
    warn_on_source_mismatch: bool,
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
    socket: Arc<UdpSocket>,
    local_addr: SocketAddr,
    core: Arc<UdpCore>,
    config: UdpTransportConfig,
    receive_limits: ReceiveLimits,
    shutdown: CancellationToken,
    // Cancels the recv task when the last transport/handle reference drops.
    // The task itself must hold no strong reference to this struct, or the
    // guard would never fire.
    _shutdown_guard: DropGuard,
    recv_task: tokio::sync::Mutex<Option<JoinHandle<()>>>,
}

impl UdpTransport {
    /// Bind to the given address with default configuration.
    ///
    /// Use `0.0.0.0:0` for IPv4 targets or `[::]:0` for IPv6 targets.
    pub async fn bind(addr: impl AsRef<str>) -> Result<Self> {
        Self::builder().bind(addr).build().await
    }

    /// Create a builder for custom configuration.
    #[must_use]
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
    /// IPv4-mapped IPv6 targets are converted back to IPv4 for IPv4 sockets.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] when an IPv4 socket is paired with a native
    /// IPv6 target, because that target cannot be represented by the socket.
    pub fn handle(&self, target: SocketAddr) -> Result<UdpHandle> {
        let target = self.map_to_socket_family(target)?;
        Ok(UdpHandle {
            inner: self.inner.clone(),
            target,
            strict_source: false,
        })
    }

    /// Map a target address to match this transport's socket family.
    ///
    /// Converts IPv4 targets to IPv4-mapped IPv6 addresses when the socket
    /// is IPv6, enabling dual-stack usage on platforms where the kernel does
    /// not perform this mapping implicitly (macOS, BSD). For an IPv4 socket,
    /// mapped IPv6 targets are normalized to IPv4 and native IPv6 targets are
    /// rejected before any I/O.
    fn map_to_socket_family(&self, target: SocketAddr) -> Result<SocketAddr> {
        match (self.inner.local_addr, target) {
            (SocketAddr::V6(_), SocketAddr::V4(target)) => Ok(SocketAddr::new(
                IpAddr::V6(target.ip().to_ipv6_mapped()),
                target.port(),
            )),
            (SocketAddr::V4(_), SocketAddr::V6(target)) => {
                let Some(ip) = target.ip().to_ipv4_mapped() else {
                    return Err(Error::Config(
                        format!(
                            "UDP target {target} is incompatible with IPv4 socket {}",
                            self.inner.local_addr
                        )
                        .into(),
                    )
                    .boxed());
                };
                Ok(SocketAddr::new(IpAddr::V4(ip), target.port()))
            }
            (_, target) => Ok(target),
        }
    }

    /// Get the local bind address.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr
    }

    /// Snapshot transport statistics.
    ///
    /// Returns cumulative counters for delivered, expired, unmatched, and
    /// malformed datagrams. Useful for monitoring transport health under load.
    #[must_use]
    pub fn stats(&self) -> TransportStats {
        self.inner.core.stats()
    }

    /// Shutdown the transport, stopping the background receiver.
    ///
    /// Signals the background recv task to stop and waits for it to exit.
    /// Pending requests are woken and fail with [`crate::Error::Closed`].
    ///
    /// Calling this is optional: the recv task is also cancelled when the
    /// last `UdpTransport` clone and [`UdpHandle`] are dropped.
    pub async fn shutdown(&self) {
        self.inner.shutdown.cancel();
        let handle = self.inner.recv_task.lock().await.take();
        if let Some(handle) = handle {
            let _ = handle.await;
        }
    }

    fn start_recv_loop(inner: &Arc<UdpTransportInner>) {
        // The task captures only the pieces it needs, never the inner Arc:
        // Drop-based cancellation relies on the DropGuard firing when the
        // last transport/handle reference drops, which can only happen if
        // the task keeps no strong reference to the inner state.
        let socket = inner.socket.clone();
        let core = inner.core.clone();
        let shutdown = inner.shutdown.clone();
        let local_addr = inner.local_addr;
        let receive_limits = inner.receive_limits;
        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; UDP_RECEIVE_BUFFER_SIZE];
            let mut cleanup_interval = tokio::time::interval(Duration::from_secs(1));
            // Backoff applied after a recv error to avoid a hot spin when the
            // socket is in a persistent error state (e.g. ENOBUFS or a stream
            // of ICMP port-unreachable errors). Reset on any successful recv so
            // the normal success path is never delayed.
            let mut recv_error_backoff = Duration::ZERO;

            loop {
                tokio::select! {
                    biased;

                    () = shutdown.cancelled() => {
                        tracing::debug!(target: "async_snmp::transport", { snmp.local_addr = %local_addr }, "UDP transport shutdown");
                        break;
                    }

                    _ = cleanup_interval.tick() => {
                        core.cleanup_expired();
                    }

                    result = socket.recv_from(&mut buf) => {
                        match result {
                            Ok((len, source)) => {
                                recv_error_backoff = Duration::ZERO;
                                if len > receive_limits.advertised().as_usize() {
                                    tracing::debug!(target: "async_snmp::transport", { snmp.source = %source, received_size = len, advertised_size = receive_limits.advertised().as_usize() }, "accepted bounded UDP datagram above advertised capacity");
                                }
                                let data = Bytes::copy_from_slice(&buf[..len]);

                                if let Some(request_id) = extract_request_id(&data) {
                                    if !core.deliver(request_id, data, source) {
                                        tracing::debug!(target: "async_snmp::transport", { snmp.request_id = request_id, snmp.source = %source }, "response for unknown request");
                                    }
                                } else {
                                    core.note_malformed();
                                    tracing::debug!(target: "async_snmp::transport", { snmp.source = %source, snmp.bytes = len }, "malformed response (no request_id)");
                                }
                            }
                            Err(_) if shutdown.is_cancelled() => break,
                            Err(e) => {
                                tracing::error!(target: "async_snmp::transport", { error = %e }, "UDP recv error");
                                // Exponential backoff, capped, to keep a persistent
                                // error condition from spinning a CPU core and
                                // flooding logs. The sleep is interruptible by
                                // shutdown so cancellation stays responsive.
                                recv_error_backoff = next_recv_error_backoff(recv_error_backoff);
                                tokio::select! {
                                    biased;
                                    () = shutdown.cancelled() => break,
                                    () = tokio::time::sleep(recv_error_backoff) => {}
                                }
                            }
                        }
                    }
                }
            }

            // Wake pending waiters so they fail now rather than at their
            // individual deadlines.
            core.close();
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
    #[must_use]
    pub fn new() -> Self {
        Self {
            bind_addr: "0.0.0.0:0".into(),
            config: UdpTransportConfig::default(),
            recv_buffer_size: None,
            send_buffer_size: None,
        }
    }

    /// Set the local bind address.
    #[must_use]
    pub fn bind(mut self, addr: impl AsRef<str>) -> Self {
        self.bind_addr = addr.as_ref().to_string();
        self
    }

    /// Set maximum message size for sending (default: 1472 bytes).
    ///
    /// This affects the advertised msgMaxSize in `SNMPv3` requests. The receive
    /// buffer is always sized to accept any valid UDP datagram (65535 bytes).
    #[must_use]
    pub fn max_message_size(mut self, size: usize) -> Self {
        self.config.max_message_size = size;
        self
    }

    /// Configure warning on source address mismatch (default: true).
    #[must_use]
    pub fn warn_on_source_mismatch(mut self, warn: bool) -> Self {
        self.config.warn_on_source_mismatch = warn;
        self
    }

    /// Set the socket receive buffer size (`SO_RCVBUF`).
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
    #[must_use]
    pub fn recv_buffer_size(mut self, size: usize) -> Self {
        self.recv_buffer_size = Some(size);
        self
    }

    /// Set the socket send buffer size (`SO_SNDBUF`).
    ///
    /// The kernel may cap this at `net.core.wmem_max`.
    #[must_use]
    pub fn send_buffer_size(mut self, size: usize) -> Self {
        self.send_buffer_size = Some(size);
        self
    }

    /// Build the transport.
    pub async fn build(self) -> Result<UdpTransport> {
        // Validate before parsing or binding so invalid size configuration has
        // deterministic precedence and can never be narrowed on advertisement.
        let receive_limits = ReceiveLimits::udp(self.config.max_message_size)
            .map_err(|error| Error::Config(error.to_string().into()).boxed())?;
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

        let shutdown = CancellationToken::new();
        let inner = Arc::new(UdpTransportInner {
            socket: Arc::new(socket),
            local_addr,
            core: Arc::new(UdpCore::new()),
            config: self.config,
            receive_limits,
            _shutdown_guard: shutdown.clone().drop_guard(),
            shutdown,
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
/// Cheap to clone (Arc + `SocketAddr`).
#[derive(Clone)]
pub struct UdpHandle {
    inner: Arc<UdpTransportInner>,
    target: SocketAddr,
    strict_source: bool,
}

impl UdpHandle {
    /// Require responses to originate from this handle's target address.
    ///
    /// By default (false), a source mismatch does not reject a response (see
    /// [`warn_on_source_mismatch`](UdpTransportBuilder::warn_on_source_mismatch)),
    /// because multihomed agents may legitimately reply from a different
    /// address. When enabled, a response from any other address is dropped
    /// (counted as `unmatched` in [`TransportStats`]) and the request keeps
    /// waiting for a response from the target.
    #[must_use]
    pub fn strict_source(mut self, strict: bool) -> Self {
        self.strict_source = strict;
        self
    }
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

    async fn request_with<T, F>(
        &self,
        data: &[u8],
        registration: RequestRegistration,
        validate: F,
    ) -> Result<T>
    where
        T: Send,
        F: FnMut(Bytes, SocketAddr) -> Result<Candidate<T>> + Send,
    {
        // Registration is the first work performed when this future is polled,
        // before a datagram can be sent. The guard owns primary and alias cleanup
        // across both awaits, including cancellation and send failure.
        let registration =
            self.inner
                .core
                .register(registration, self.target, self.strict_source)?;
        self.send(data).await?;
        self.recv_registered_with(&registration, validate).await
    }

    async fn recv_with<T, F>(&self, registration: RequestRegistration, validate: F) -> Result<T>
    where
        T: Send,
        F: FnMut(Bytes, SocketAddr) -> Result<Candidate<T>> + Send,
    {
        let registration =
            self.inner
                .core
                .register(registration, self.target, self.strict_source)?;
        self.recv_registered_with(&registration, validate).await
    }

    fn peer_addr(&self) -> SocketAddr {
        self.target
    }

    fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr
    }

    fn receive_limits(&self) -> ReceiveLimits {
        self.inner.receive_limits
    }

    fn is_reliable(&self) -> bool {
        false
    }
}

impl UdpHandle {
    #[cfg(test)]
    async fn recv_registered(
        &self,
        registration: &super::udp_core::UdpRegistration,
    ) -> Result<(Bytes, SocketAddr)> {
        self.recv_registered_with(registration, |data, source| {
            Ok(Candidate::Accept((data, source)))
        })
        .await
    }

    async fn recv_registered_with<T, F>(
        &self,
        registration: &super::udp_core::UdpRegistration,
        mut validate: F,
    ) -> Result<T>
    where
        F: FnMut(Bytes, SocketAddr) -> Result<Candidate<T>>,
    {
        let request_id = registration.request_id();
        tracing::trace!(target: "async_snmp::transport", { snmp.target = %self.target, snmp.request_id = request_id }, "UDP recv waiting");

        let result = self
            .inner
            .core
            .wait_for_response_with(registration, self.target, |data, source| {
                if self.inner.config.warn_on_source_mismatch && source != self.target {
                    tracing::warn!(target: "async_snmp::transport", { snmp.request_id = request_id, snmp.target = %self.target, snmp.source = %source }, "response source address mismatch");
                }
                tracing::trace!(target: "async_snmp::transport", { snmp.target = %self.target, snmp.source = %source, snmp.bytes = data.len() }, "UDP recv candidate");
                validate(data, source)
            })
            .await;

        if result.is_err() {
            tracing::trace!(target: "async_snmp::transport", { snmp.target = %self.target, snmp.request_id = request_id }, "UDP recv failed");
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn register_v3(
        handle: &UdpHandle,
        request_id: i32,
        timeout: Duration,
    ) -> super::super::udp_core::UdpRegistration {
        handle
            .inner
            .core
            .register(
                RequestRegistration::test_unchecked(request_id, timeout),
                handle.target,
                handle.strict_source,
            )
            .unwrap()
    }

    #[test]
    fn recv_error_backoff_starts_at_min_and_grows() {
        // No prior error -> first backoff is the minimum, never zero, so a
        // persistent recv error cannot hot-spin the loop.
        let first = next_recv_error_backoff(Duration::ZERO);
        assert_eq!(first, UDP_RECV_ERROR_BACKOFF_MIN);
        assert!(first > Duration::ZERO);

        // Repeated errors double the backoff.
        let second = next_recv_error_backoff(first);
        assert_eq!(second, first * 2);
    }

    #[test]
    fn recv_error_backoff_is_capped() {
        // Growth saturates at the maximum rather than increasing unbounded.
        let capped = next_recv_error_backoff(UDP_RECV_ERROR_BACKOFF_MAX);
        assert_eq!(capped, UDP_RECV_ERROR_BACKOFF_MAX);

        let near_max =
            next_recv_error_backoff(UDP_RECV_ERROR_BACKOFF_MAX / 2 + Duration::from_millis(1));
        assert_eq!(near_max, UDP_RECV_ERROR_BACKOFF_MAX);
    }

    #[tokio::test]
    async fn ipv6_transport_maps_ipv4_target() {
        let transport = UdpTransport::bind("[::]:0").await.unwrap();
        let handle = transport.handle("127.0.0.1:161".parse().unwrap()).unwrap();
        let mapped: SocketAddr = "[::ffff:127.0.0.1]:161".parse().unwrap();
        assert_eq!(handle.peer_addr(), mapped);
    }

    #[tokio::test]
    async fn ipv4_transport_preserves_ipv4_target() {
        let transport = UdpTransport::bind("0.0.0.0:0").await.unwrap();
        let handle = transport.handle("127.0.0.1:161".parse().unwrap()).unwrap();
        let expected: SocketAddr = "127.0.0.1:161".parse().unwrap();
        assert_eq!(handle.peer_addr(), expected);
    }

    #[tokio::test]
    async fn ipv4_transport_normalizes_mapped_ipv6_target() {
        let transport = UdpTransport::bind("0.0.0.0:0").await.unwrap();
        let handle = transport
            .handle("[::ffff:127.0.0.1]:161".parse().unwrap())
            .unwrap();
        assert_eq!(handle.peer_addr(), "127.0.0.1:161".parse().unwrap());
    }

    #[tokio::test]
    async fn ipv4_transport_rejects_native_ipv6_target() {
        let transport = UdpTransport::bind("0.0.0.0:0").await.unwrap();
        let error = transport
            .handle("[::1]:161".parse().unwrap())
            .err()
            .expect("native IPv6 target must be rejected during handle construction");

        assert!(matches!(*error, Error::Config(_)));
        assert!(error.to_string().contains("incompatible with IPv4 socket"));
    }

    #[tokio::test]
    async fn ipv6_transport_preserves_ipv6_target() {
        let transport = UdpTransport::bind("[::]:0").await.unwrap();
        let handle = transport.handle("[::1]:161".parse().unwrap()).unwrap();
        let expected: SocketAddr = "[::1]:161".parse().unwrap();
        assert_eq!(handle.peer_addr(), expected);
    }

    #[tokio::test]
    async fn max_message_size_default() {
        let transport = UdpTransport::bind("0.0.0.0:0").await.unwrap();
        let handle = transport.handle("127.0.0.1:161".parse().unwrap()).unwrap();
        // Default config is 1472
        assert_eq!(handle.receive_limits().advertised().as_usize(), 1472);
    }

    #[tokio::test]
    async fn max_message_size_custom() {
        let transport = UdpTransport::builder()
            .max_message_size(8192)
            .build()
            .await
            .unwrap();
        let handle = transport.handle("127.0.0.1:161".parse().unwrap()).unwrap();
        assert_eq!(handle.receive_limits().advertised().as_usize(), 8192);
    }

    #[tokio::test]
    async fn invalid_message_sizes_are_rejected_before_bind_parsing() {
        for size in [0usize, 483, crate::MAX_UDP_PAYLOAD + 1, usize::MAX] {
            let error = UdpTransport::builder()
                .bind("not a socket address")
                .max_message_size(size)
                .build()
                .await
                .err()
                .expect("invalid size must fail");
            assert!(
                matches!(*error, Error::Config(_)),
                "unexpected error: {error}"
            );
            assert!(error.to_string().contains("message size"));
        }
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
    async fn drop_without_shutdown_stops_recv_task() {
        let transport = UdpTransport::bind("127.0.0.1:0").await.unwrap();
        let task = transport
            .inner
            .recv_task
            .try_lock()
            .unwrap()
            .take()
            .expect("recv task running");
        let weak = Arc::downgrade(&transport.inner);

        drop(transport);

        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("recv task did not exit after drop")
            .unwrap();
        assert_eq!(weak.strong_count(), 0, "transport state leaked after drop");
    }

    #[tokio::test]
    async fn shutdown_wakes_pending_waiters() {
        let transport = UdpTransport::bind("127.0.0.1:0").await.unwrap();
        // Target port 9 (discard): no response will ever arrive.
        let handle = transport.handle("127.0.0.1:9".parse().unwrap()).unwrap();
        let waiter = tokio::spawn(async move {
            handle
                .recv(RequestRegistration::v3(42, Duration::from_secs(30)))
                .await
        });
        // Let the waiter park on its notify before shutting down.
        tokio::time::sleep(Duration::from_millis(50)).await;

        transport.shutdown().await;

        let result = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("pending waiter not woken by shutdown")
            .unwrap();
        let err = result.expect_err("waiter should fail after shutdown");
        assert!(
            matches!(*err, Error::Closed { .. }),
            "expected Error::Closed, got {err:?}"
        );
    }

    #[tokio::test]
    async fn recv_after_shutdown_without_slot_returns_closed() {
        let transport = UdpTransport::bind("127.0.0.1:0").await.unwrap();
        let handle = transport.handle("127.0.0.1:9".parse().unwrap()).unwrap();

        transport.shutdown().await;

        let err = handle
            .recv(RequestRegistration::v3(42, Duration::from_secs(30)))
            .await
            .expect_err("recv on closed transport should fail");
        assert!(
            matches!(*err, Error::Closed { .. }),
            "expected Error::Closed, got {err:?}"
        );
    }

    #[tokio::test]
    async fn recv_zero_deadline_on_open_transport_returns_timeout() {
        let transport = UdpTransport::bind("127.0.0.1:0").await.unwrap();
        let handle = transport.handle("127.0.0.1:9".parse().unwrap()).unwrap();

        let err = handle
            .recv(RequestRegistration::v3(42, Duration::ZERO))
            .await
            .expect_err("zero-deadline receive should fail");
        assert!(
            matches!(*err, Error::Timeout { .. }),
            "expected Error::Timeout, got {err:?}"
        );
    }

    // A send failure after registration must reclaim the pending entries
    // immediately rather than leaving them to expire or be swept
    // by the periodic cleanup. An oversized datagram (larger than the maximum
    // UDP payload) makes send_to fail synchronously, exercising that path.
    #[tokio::test]
    async fn send_failure_unregisters_pending_slot() {
        let transport = UdpTransport::bind("127.0.0.1:0").await.unwrap();
        let handle = transport.handle("127.0.0.1:9".parse().unwrap()).unwrap();

        let request_id = 55;
        let registration =
            RequestRegistration::v3(request_id, Duration::from_secs(30)).with_aliases([53, 54]);

        // Payload beyond the maximum UDP datagram size; send_to returns EMSGSIZE.
        let oversized = vec![0u8; 70_000];
        let err = handle
            .request(&oversized, registration)
            .await
            .expect_err("oversized send should fail");
        assert!(
            matches!(*err, Error::Network { .. }),
            "expected Error::Network, got {err:?}"
        );

        // The slot must already be gone: a response for this id finds nothing.
        let packet = response_packet(request_id);
        assert!(
            !transport
                .inner
                .core
                .deliver(request_id, packet, handle.peer_addr()),
            "pending slot should have been reclaimed on send failure"
        );
        assert_eq!(transport.inner.core.pending_counts(), (0, 0));
    }

    #[tokio::test]
    async fn failed_registration_sends_no_datagram() {
        let listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let transport = UdpTransport::bind("127.0.0.1:0").await.unwrap();
        let handle = transport.handle(target).unwrap();
        let _owner = register_v3(&handle, 60, Duration::from_secs(30));

        let error = handle
            .request(
                b"must not be sent",
                RequestRegistration::v3(61, Duration::from_secs(30)).with_aliases([60]),
            )
            .await
            .unwrap_err();
        assert!(matches!(*error, Error::RequestIdInUse { request_id: 60 }));

        let mut datagram = [0u8; 32];
        assert!(
            tokio::time::timeout(Duration::from_millis(50), listener.recv_from(&mut datagram))
                .await
                .is_err(),
            "failed registration sent a datagram"
        );
        assert_eq!(transport.inner.core.pending_counts(), (1, 0));
    }

    #[tokio::test]
    async fn dropping_unpolled_request_does_not_register() {
        let transport = UdpTransport::bind("127.0.0.1:0").await.unwrap();
        let handle = transport.handle("127.0.0.1:9".parse().unwrap()).unwrap();
        let registration =
            RequestRegistration::v3(70, Duration::from_secs(300)).with_aliases([68, 69]);

        let request = handle.request(b"request", registration);
        assert_eq!(transport.inner.core.pending_counts(), (0, 0));
        drop(request);
        assert_eq!(transport.inner.core.pending_counts(), (0, 0));
    }

    #[tokio::test]
    async fn repeated_cancellation_after_send_cleans_primary_and_aliases() {
        let listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let transport = UdpTransport::bind("127.0.0.1:0").await.unwrap();
        let handle = transport.handle(target).unwrap();
        let mut datagram = [0u8; 16];

        for iteration in 0..20 {
            let request_id = 1_000 + iteration;
            let registration = RequestRegistration::v3(request_id, Duration::from_secs(300))
                .with_aliases([2_000 + iteration * 2, 2_001 + iteration * 2]);
            let request_handle = handle.clone();
            let task =
                tokio::spawn(async move { request_handle.request(b"request", registration).await });

            listener.recv_from(&mut datagram).await.unwrap();
            assert_eq!(transport.inner.core.pending_counts(), (1, 2));

            task.abort();
            let error = task.await.expect_err("request task should be cancelled");
            assert!(error.is_cancelled());
            assert_eq!(
                transport.inner.core.pending_counts(),
                (0, 0),
                "iteration {iteration} retained UDP correlation state"
            );
        }
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

    /// Build a valid v2c response packet carrying `request_id`, for injection
    /// into `UdpCore::deliver` in the source-mismatch tests below.
    fn response_packet(request_id: i32) -> Bytes {
        let pdu = crate::pdu::Pdu::get_request(request_id, &[]).to_response();
        let msg = crate::message::CommunityMessage::v2c(b"public".as_slice(), pdu).unwrap();
        msg.encode().unwrap()
    }

    // T9 (RFC 3417 3.1): a response whose datagram source differs from the
    // handle's target is still delivered by request-id (the recv loop keys
    // solely on request_id, udp.rs:235-238); `recv`'s source check only warns,
    // it never rejects. These tests inject directly into `UdpCore::deliver`
    // (bypassing the real socket) to exercise that exact accept path
    // deterministically, per the brief's preferred approach.

    #[tokio::test]
    async fn recv_accepts_mismatched_source_with_warn_enabled() {
        let transport = UdpTransport::bind("127.0.0.1:0").await.unwrap();
        let target: SocketAddr = "127.0.0.1:161".parse().unwrap();
        let mismatched: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        assert_ne!(target, mismatched);

        // Default config: warn_on_source_mismatch is true.
        let handle = transport.handle(target).unwrap();
        let registration = register_v3(&handle, 42, Duration::from_secs(5));

        let packet = response_packet(42);
        assert!(
            transport.inner.core.deliver(42, packet.clone(), mismatched),
            "deliver should find the registered request"
        );

        let (data, source) = tokio::time::timeout(
            Duration::from_secs(1),
            handle.recv_registered(&registration),
        )
        .await
        .expect("recv timed out")
        .expect("mismatched-source response must still be accepted");

        assert_eq!(data, packet);
        assert_eq!(source, mismatched);
        assert_ne!(source, handle.peer_addr());
    }

    #[tokio::test]
    async fn recv_accepts_mismatched_source_with_warn_disabled() {
        let transport = UdpTransport::builder()
            .bind("127.0.0.1:0")
            .warn_on_source_mismatch(false)
            .build()
            .await
            .unwrap();
        let target: SocketAddr = "127.0.0.1:161".parse().unwrap();
        let mismatched: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        assert_ne!(target, mismatched);

        let handle = transport.handle(target).unwrap();
        let registration = register_v3(&handle, 7, Duration::from_secs(5));

        let packet = response_packet(7);
        assert!(transport.inner.core.deliver(7, packet.clone(), mismatched));

        // Acceptance must not depend on warn_on_source_mismatch: the flag
        // only controls whether a warning is logged, never rejection.
        let (data, source) = tokio::time::timeout(
            Duration::from_secs(1),
            handle.recv_registered(&registration),
        )
        .await
        .expect("recv timed out")
        .expect("mismatched-source response must be accepted regardless of warn flag");

        assert_eq!(data, packet);
        assert_eq!(source, mismatched);
        assert_ne!(source, handle.peer_addr());
    }

    #[tokio::test]
    async fn deliver_to_unregistered_id_counts_unmatched() {
        let transport = UdpTransport::bind("127.0.0.1:0").await.unwrap();
        let source: SocketAddr = "127.0.0.1:161".parse().unwrap();

        assert!(
            !transport
                .inner
                .core
                .deliver(42, response_packet(42), source)
        );

        let stats = transport.stats();
        assert_eq!(stats.unmatched, 1);
        assert_eq!(stats.delivered, 0);
    }

    #[tokio::test]
    async fn second_deliver_after_recv_counts_unmatched() {
        let transport = UdpTransport::bind("127.0.0.1:0").await.unwrap();
        let target: SocketAddr = "127.0.0.1:161".parse().unwrap();
        let handle = transport.handle(target).unwrap();
        let registration = register_v3(&handle, 7, Duration::from_secs(5));

        let packet = response_packet(7);
        assert!(transport.inner.core.deliver(7, packet.clone(), target));
        tokio::time::timeout(
            Duration::from_secs(1),
            handle.recv_registered(&registration),
        )
        .await
        .expect("recv timed out")
        .expect("first response must be delivered");

        // Slot consumed by recv: a duplicate is unmatched.
        assert!(!transport.inner.core.deliver(7, packet, target));

        let stats = transport.stats();
        assert_eq!(stats.delivered, 1);
        assert_eq!(stats.unmatched, 1);
    }

    #[tokio::test]
    async fn garbage_datagram_counts_malformed() {
        let transport = UdpTransport::bind("127.0.0.1:0").await.unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender
            .send_to(b"not snmp", transport.local_addr())
            .await
            .unwrap();

        // The recv loop processes the datagram asynchronously; poll briefly.
        let mut malformed = 0;
        for _ in 0..100 {
            malformed = transport.stats().malformed;
            if malformed == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(malformed, 1);
    }

    #[tokio::test]
    async fn cleanup_expired_counts_expired() {
        let transport = UdpTransport::bind("127.0.0.1:0").await.unwrap();
        let handle = transport.handle("127.0.0.1:9".parse().unwrap()).unwrap();
        let _registration = register_v3(&handle, 13, Duration::ZERO);

        transport.inner.core.cleanup_expired();

        assert_eq!(transport.stats().expired, 1);
    }

    #[tokio::test]
    async fn strict_handle_rejects_mismatched_source_and_keeps_slot() {
        let transport = UdpTransport::bind("127.0.0.1:0").await.unwrap();
        let target: SocketAddr = "127.0.0.1:161".parse().unwrap();
        let mismatched: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let handle = transport.handle(target).unwrap().strict_source(true);
        let registration = register_v3(&handle, 21, Duration::from_secs(5));

        let packet = response_packet(21);
        assert!(
            !transport.inner.core.deliver(21, packet.clone(), mismatched),
            "strict handle must reject a mismatched source"
        );
        assert_eq!(transport.stats().unmatched, 1);

        // The slot must survive rejection so the genuine response still lands.
        assert!(transport.inner.core.deliver(21, packet.clone(), target));

        let (data, source) = tokio::time::timeout(
            Duration::from_secs(1),
            handle.recv_registered(&registration),
        )
        .await
        .expect("recv timed out")
        .expect("matching-source response must be delivered after a rejected one");

        assert_eq!(data, packet);
        assert_eq!(source, target);
    }

    #[tokio::test]
    async fn strict_handle_accepts_matching_source() {
        let transport = UdpTransport::bind("127.0.0.1:0").await.unwrap();
        let target: SocketAddr = "127.0.0.1:161".parse().unwrap();

        let handle = transport.handle(target).unwrap().strict_source(true);
        let registration = register_v3(&handle, 22, Duration::from_secs(5));

        let packet = response_packet(22);
        assert!(transport.inner.core.deliver(22, packet.clone(), target));

        let (data, source) = tokio::time::timeout(
            Duration::from_secs(1),
            handle.recv_registered(&registration),
        )
        .await
        .expect("recv timed out")
        .expect("matching-source response must be accepted by a strict handle");

        assert_eq!(data, packet);
        assert_eq!(source, target);
    }

    #[tokio::test]
    async fn recv_matching_source_is_not_a_mismatch() {
        let transport = UdpTransport::bind("127.0.0.1:0").await.unwrap();
        let target: SocketAddr = "127.0.0.1:161".parse().unwrap();

        let handle = transport.handle(target).unwrap();
        let registration = register_v3(&handle, 99, Duration::from_secs(5));

        let packet = response_packet(99);
        assert!(transport.inner.core.deliver(99, packet.clone(), target));

        let (data, source) = tokio::time::timeout(
            Duration::from_secs(1),
            handle.recv_registered(&registration),
        )
        .await
        .expect("recv timed out")
        .expect("matching-source response must be accepted");

        assert_eq!(data, packet);
        assert_eq!(source, target);
        assert_eq!(source, handle.peer_addr());
    }
}
