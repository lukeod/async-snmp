//! Shared UDP transport for high-throughput SNMP polling.
//!
//! When monitoring systems need to poll thousands of SNMP targets simultaneously,
//! creating a dedicated socket per target becomes inefficient. The shared transport
//! solves this by using a single UDP socket with request-ID correlation to route
//! responses to the correct client.
//!
//! # Architecture
//!
//! ```text
//! +-------------------+
//! |  SharedUdpTransport  |  (owns UDP socket, spawns recv loop)
//! +-------------------+
//!          |
//!          | Arc<Inner>
//!          v
//! +-------------------+     +-------------------+     +-------------------+
//! | SharedUdpHandle   |     | SharedUdpHandle   |     | SharedUdpHandle   |
//! | target: 10.0.0.1  |     | target: 10.0.0.2  |     | target: 10.0.0.3  |
//! +-------------------+     +-------------------+     +-------------------+
//!          |                         |                         |
//!          v                         v                         v
//! +-------------------+     +-------------------+     +-------------------+
//! |    Client<SH>     |     |    Client<SH>     |     |    Client<SH>     |
//! +-------------------+     +-------------------+     +-------------------+
//! ```
//!
//! - [`SharedUdpTransport`] binds a single UDP socket and spawns a background
//!   task that receives all incoming packets.
//! - Each [`SharedUdpHandle`] represents a logical connection to one target.
//! - Handles implement [`Transport`], so they work with [`Client`](crate::Client).
//! - Responses are routed by extracting the request ID from each packet.
//!
//! # When to Use Shared vs Owned Transport
//!
//! | Scenario | Recommended Transport |
//! |----------|----------------------|
//! | 1-100 targets | [`UdpTransport`](super::UdpTransport) (simpler, one socket per target) |
//! | 100-10,000+ targets | [`SharedUdpTransport`] (single socket, lower resource usage) |
//! | TCP required | [`TcpTransport`](super::TcpTransport) (stream-based, no retries) |
//!
//! The crossover point depends on your system's file descriptor limits and
//! memory constraints. Shared transport becomes advantageous when socket
//! overhead (kernel buffers, file descriptors) becomes significant.
//!
//! # Example: Polling Multiple Devices
//!
//! ```rust,no_run
//! use async_snmp::{Auth, Client, ClientConfig, oid};
//! use async_snmp::transport::SharedUdpTransport;
//! use std::net::SocketAddr;
//!
//! # async fn example() -> async_snmp::Result<()> {
//! // Create the shared transport (binds one UDP socket)
//! let shared = SharedUdpTransport::builder()
//!     .bind("0.0.0.0:0")
//!     .build()
//!     .await?;
//!
//! // Create clients for multiple targets
//! let targets: Vec<SocketAddr> = vec![
//!     "192.168.1.1:161".parse().unwrap(),
//!     "192.168.1.2:161".parse().unwrap(),
//!     "192.168.1.3:161".parse().unwrap(),
//! ];
//!
//! let clients: Vec<_> = targets
//!     .iter()
//!     .map(|&addr| {
//!         let handle = shared.handle(addr);
//!         let mut config = ClientConfig::default();
//!         config.community = "public".into();
//!         Client::new(handle, config)
//!     })
//!     .collect();
//!
//! // Poll all targets concurrently
//! let oid = oid!(1, 3, 6, 1, 2, 1, 1, 1, 0);
//! let futures: Vec<_> = clients
//!     .iter()
//!     .map(|client| client.get(&oid))
//!     .collect();
//!
//! let results = futures::future::join_all(futures).await;
//! for (i, result) in results.iter().enumerate() {
//!     match result {
//!         Ok(vb) => println!("{}: {:?}", targets[i], vb.value),
//!         Err(e) => println!("{}: error - {}", targets[i], e),
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Request ID Coordination
//!
//! The shared transport maintains a single request ID counter across all handles.
//! This prevents collisions when multiple clients send requests concurrently.
//! Each handle's [`alloc_request_id()`](Transport::alloc_request_id) draws from
//! this shared counter.

use super::Transport;
use crate::error::{Error, Result};
use crate::util::bind_udp_socket;
use bytes::Bytes;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::oneshot;

/// Shared UDP transport for high-throughput polling.
///
/// A single unconnected UDP socket shared across many clients. Each client
/// gets a [`SharedUdpHandle`] that implements [`Transport`].
///
/// # Construction
///
/// Use [`bind()`](Self::bind) for simple cases or [`builder()`](Self::builder)
/// for full configuration:
///
/// ```rust,no_run
/// use async_snmp::transport::SharedUdpTransport;
///
/// # async fn example() -> async_snmp::Result<()> {
/// // Simple: bind to any available port
/// let shared = SharedUdpTransport::bind("0.0.0.0:0").await?;
///
/// // With configuration
/// let shared = SharedUdpTransport::builder()
///     .bind("0.0.0.0:0")
///     .max_message_size(8192)
///     .build()
///     .await?;
/// # Ok(())
/// # }
/// ```
///
/// # Creating Clients
///
/// ```rust,no_run
/// use async_snmp::transport::SharedUdpTransport;
/// use async_snmp::{Client, ClientConfig};
/// use std::net::SocketAddr;
///
/// # async fn example() -> async_snmp::Result<()> {
/// let shared = SharedUdpTransport::bind("0.0.0.0:0").await?;
///
/// // Create handles for different targets
/// let target1: SocketAddr = "192.168.1.1:161".parse().unwrap();
/// let target2: SocketAddr = "192.168.1.2:161".parse().unwrap();
///
/// let handle1 = shared.handle(target1);
/// let handle2 = shared.handle(target2);
///
/// // Create clients using the handles
/// let client1 = Client::new(handle1, ClientConfig::default());
/// let client2 = Client::new(handle2, ClientConfig::default());
/// # Ok(())
/// # }
/// ```
///
/// # Lifetime
///
/// The transport spawns a background tokio task for receiving packets. This task
/// runs as long as the `SharedUdpTransport` (or any `SharedUdpHandle` cloned from it)
/// exists. The task terminates when all references are dropped.
pub struct SharedUdpTransport {
    inner: Arc<SharedUdpTransportInner>,
}

struct SharedUdpTransportInner {
    socket: UdpSocket,
    local_addr: SocketAddr,
    pending: Mutex<HashMap<i32, PendingRequest>>,
    config: SharedTransportConfig,
    /// Shared request ID counter for all clients using this transport.
    /// Prevents request ID collisions between concurrent clients.
    next_request_id: AtomicI32,
}

struct PendingRequest {
    target: SocketAddr,
    sender: oneshot::Sender<(Bytes, SocketAddr)>,
    deadline: Instant,
}

/// Configuration for shared UDP transport.
#[derive(Clone)]
pub struct SharedTransportConfig {
    /// Log warning when response source differs from target (default: true)
    pub warn_on_source_mismatch: bool,
    /// Maximum message size (default: 65535)
    pub max_message_size: usize,
}

impl Default for SharedTransportConfig {
    fn default() -> Self {
        Self {
            warn_on_source_mismatch: true,
            max_message_size: 65535,
        }
    }
}

impl SharedUdpTransport {
    /// Bind a shared UDP transport to the given address with default settings.
    ///
    /// This is a convenience method equivalent to
    /// `SharedUdpTransport::builder().bind(addr).build()`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use async_snmp::transport::SharedUdpTransport;
    ///
    /// # async fn example() -> async_snmp::Result<()> {
    /// // Bind to any available port on all interfaces
    /// let shared = SharedUdpTransport::bind("0.0.0.0:0").await?;
    /// println!("Bound to {}", shared.local_addr());
    ///
    /// // Bind to a specific port
    /// let shared = SharedUdpTransport::bind("0.0.0.0:16100").await?;
    ///
    /// // IPv6
    /// let shared = SharedUdpTransport::bind("[::]:0").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn bind(addr: impl Into<String>) -> Result<Self> {
        Self::builder().bind(addr).build().await
    }

    /// Create a builder for configuring the shared transport.
    ///
    /// Use the builder when you need to customize settings like message size
    /// or source address mismatch warnings.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use async_snmp::transport::SharedUdpTransport;
    ///
    /// # async fn example() -> async_snmp::Result<()> {
    /// let shared = SharedUdpTransport::builder()
    ///     .bind("0.0.0.0:0")
    ///     // Disable warnings when response comes from different IP than request
    ///     // (common with load balancers or NAT)
    ///     .warn_on_source_mismatch(false)
    ///     // Reduce buffer size for memory-constrained environments
    ///     .max_message_size(8192)
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn builder() -> SharedUdpTransportBuilder {
        SharedUdpTransportBuilder::new()
    }

    /// Create a handle for a specific target.
    ///
    /// The returned [`SharedUdpHandle`] implements [`Transport`] and can be used
    /// with [`Client`](crate::Client). Multiple handles can be created for the same
    /// target if needed (e.g., for different SNMP communities).
    ///
    /// Handles are cheap to create and clone (just an `Arc` reference and target address).
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use async_snmp::transport::SharedUdpTransport;
    /// use async_snmp::{Client, ClientConfig};
    /// use std::net::SocketAddr;
    ///
    /// # async fn example() -> async_snmp::Result<()> {
    /// let shared = SharedUdpTransport::bind("0.0.0.0:0").await?;
    ///
    /// let target: SocketAddr = "192.168.1.1:161".parse().unwrap();
    /// let handle = shared.handle(target);
    ///
    /// // The handle can be cloned for use with multiple clients
    /// let handle2 = handle.clone();
    ///
    /// let client = Client::new(handle, ClientConfig::default());
    /// # Ok(())
    /// # }
    /// ```
    pub fn handle(&self, target: SocketAddr) -> SharedUdpHandle {
        SharedUdpHandle {
            inner: self.inner.clone(),
            target,
        }
    }

    /// Get the local bind address.
    ///
    /// Returns the actual bound address, which is useful when binding to port 0
    /// (ephemeral port) to discover the assigned port.
    pub fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr
    }

    /// Start the background receive loop.
    ///
    /// This spawns a tokio task that receives responses and dispatches them
    /// to waiting handles based on request ID.
    fn start_recv_loop(inner: Arc<SharedUdpTransportInner>) {
        tokio::spawn(async move {
            let mut buf = vec![0u8; inner.config.max_message_size];

            loop {
                match inner.socket.recv_from(&mut buf).await {
                    Ok((len, source)) => {
                        tracing::trace!(
                            snmp.source = %source,
                            snmp.bytes = len,
                            "shared transport received packet"
                        );

                        let data = Bytes::copy_from_slice(&buf[..len]);

                        // Extract request_id from response
                        // SNMP response has request_id at a known offset after the header
                        if let Some(request_id) = extract_request_id(&data) {
                            tracing::trace!(
                                snmp.request_id = request_id,
                                snmp.source = %source,
                                "extracted request_id from response"
                            );
                            let pending_req = inner.pending.lock().unwrap().remove(&request_id);
                            if let Some(pending_req) = pending_req {
                                // Warn if source doesn't match target
                                if inner.config.warn_on_source_mismatch
                                    && source != pending_req.target
                                {
                                    tracing::warn!(
                                        snmp.request_id = request_id,
                                        snmp.target = %pending_req.target,
                                        snmp.source = %source,
                                        "response source address mismatch"
                                    );
                                }

                                // Send response to waiter (ignore if receiver dropped)
                                let _ = pending_req.sender.send((data, source));
                            } else {
                                tracing::debug!(
                                    snmp.request_id = request_id,
                                    snmp.source = %source,
                                    "received response for unknown request_id"
                                );
                            }
                        } else {
                            tracing::debug!(
                                snmp.source = %source,
                                len,
                                "received malformed response (couldn't extract request_id)"
                            );
                        }
                    }
                    Err(e) => {
                        // Socket errors on shared transport are logged but don't stop the loop
                        tracing::error!(error = %e, "shared transport recv error");
                    }
                }

                // Clean up expired pending requests periodically
                // This is done inline to avoid spawning another task
                let now = Instant::now();
                inner
                    .pending
                    .lock()
                    .unwrap()
                    .retain(|_, p| p.deadline > now);
            }
        });
    }
}

/// Builder for [`SharedUdpTransport`].
pub struct SharedUdpTransportBuilder {
    bind_addr: String,
    config: SharedTransportConfig,
}

impl SharedUdpTransportBuilder {
    /// Create a new builder with default settings.
    pub fn new() -> Self {
        Self {
            bind_addr: "0.0.0.0:0".into(),
            config: SharedTransportConfig::default(),
        }
    }

    /// Set the local bind address.
    pub fn bind(mut self, addr: impl Into<String>) -> Self {
        self.bind_addr = addr.into();
        self
    }

    /// Configure warning on source address mismatch (default: true).
    ///
    /// When enabled, logs a warning if a response arrives from a different
    /// IP address than the request target. This is common with load balancers,
    /// NAT, or multi-homed devices.
    pub fn warn_on_source_mismatch(mut self, warn: bool) -> Self {
        self.config.warn_on_source_mismatch = warn;
        self
    }

    /// Set maximum receive buffer size (default: 65535).
    ///
    /// This is the maximum size of incoming UDP datagrams. Messages larger
    /// than this will be truncated.
    pub fn max_message_size(mut self, size: usize) -> Self {
        self.config.max_message_size = size;
        self
    }

    /// Build the shared transport.
    ///
    /// For IPv6 bind addresses, the socket has `IPV6_V6ONLY` set to true.
    pub async fn build(self) -> Result<SharedUdpTransport> {
        tracing::debug!(bind_addr = %self.bind_addr, "building shared UDP transport");

        let bind_addr: SocketAddr = self.bind_addr.parse().map_err(|_| Error::Io {
            target: None,
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid bind address: {}", self.bind_addr),
            ),
        })?;

        let socket = bind_udp_socket(bind_addr).await.map_err(|e| Error::Io {
            target: Some(bind_addr),
            source: e,
        })?;

        let local_addr = socket.local_addr().map_err(|e| Error::Io {
            target: Some(bind_addr),
            source: e,
        })?;

        // Randomize initial request ID to avoid collisions with previous incarnation
        // after a quick restart (enabled by SO_REUSEADDR). Uses time-based entropy
        // which is sufficient for this purpose - we just need to differ from the
        // previous run, not be cryptographically random.
        let initial_request_id = {
            use std::time::{SystemTime, UNIX_EPOCH};
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as i32)
                .unwrap_or(1);
            // Use absolute value to avoid starting negative (though negative IDs are valid)
            nanos.wrapping_abs().max(1)
        };

        tracing::debug!(
            snmp.local_addr = %local_addr,
            snmp.initial_request_id = initial_request_id,
            "shared UDP transport bound"
        );

        let inner = Arc::new(SharedUdpTransportInner {
            socket,
            local_addr,
            pending: Mutex::new(HashMap::new()),
            config: self.config,
            next_request_id: AtomicI32::new(initial_request_id),
        });

        // Start background receive loop
        SharedUdpTransport::start_recv_loop(inner.clone());

        Ok(SharedUdpTransport { inner })
    }
}

impl Default for SharedUdpTransportBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Handle to a shared UDP transport for a specific target.
///
/// Created via [`SharedUdpTransport::handle()`]. Implements [`Transport`]
/// and can be used with [`Client`](crate::Client).
///
/// # Cloning and Sharing
///
/// Handles are cheap to clone (just an `Arc` increment and target address copy).
/// Multiple handles can exist for the same target, which is useful when you need
/// multiple clients with different configurations (e.g., different communities).
///
/// # Example
///
/// ```rust,no_run
/// use async_snmp::transport::SharedUdpTransport;
/// use async_snmp::{Client, ClientConfig, Version};
/// use std::net::SocketAddr;
///
/// # async fn example() -> async_snmp::Result<()> {
/// let shared = SharedUdpTransport::bind("0.0.0.0:0").await?;
/// let target: SocketAddr = "192.168.1.1:161".parse().unwrap();
///
/// // Create a handle and use it with a client
/// let handle = shared.handle(target);
/// let client = Client::new(handle, ClientConfig::default());
///
/// // Or create multiple handles for different configurations
/// let handle_v1 = shared.handle(target);
/// let handle_v2c = shared.handle(target);
///
/// let mut config_v1 = ClientConfig::default();
/// config_v1.version = Version::V1;
/// config_v1.community = "public".into();
///
/// let mut config_v2c = ClientConfig::default();
/// config_v2c.version = Version::V2c;
/// config_v2c.community = "private".into();
///
/// let client_v1 = Client::new(handle_v1, config_v1);
/// let client_v2c = Client::new(handle_v2c, config_v2c);
/// # Ok(())
/// # }
/// ```
///
/// # Request ID Allocation
///
/// Unlike [`UdpTransport`](super::UdpTransport), handles allocate request IDs from
/// a shared counter in the parent [`SharedUdpTransport`]. This prevents ID collisions
/// when multiple clients send concurrent requests.
#[derive(Clone)]
pub struct SharedUdpHandle {
    inner: Arc<SharedUdpTransportInner>,
    target: SocketAddr,
}

impl Transport for SharedUdpHandle {
    async fn send(&self, data: &[u8]) -> Result<()> {
        tracing::trace!(
            snmp.target = %self.target,
            snmp.bytes = data.len(),
            "shared UDP send"
        );
        self.inner
            .socket
            .send_to(data, self.target)
            .await
            .map_err(|e| Error::Io {
                target: Some(self.target),
                source: e,
            })?;
        Ok(())
    }

    async fn recv(&self, request_id: i32, timeout: Duration) -> Result<(Bytes, SocketAddr)> {
        tracing::trace!(
            snmp.target = %self.target,
            snmp.request_id = request_id,
            snmp.timeout_ms = timeout.as_millis() as u64,
            "shared UDP recv waiting"
        );

        let (tx, rx) = oneshot::channel();
        let deadline = Instant::now() + timeout;

        // Register pending request
        self.inner.pending.lock().unwrap().insert(
            request_id,
            PendingRequest {
                target: self.target,
                sender: tx,
                deadline,
            },
        );

        // Wait for response with timeout
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok((data, source))) => {
                tracing::trace!(
                    snmp.target = %self.target,
                    snmp.source = %source,
                    snmp.bytes = data.len(),
                    "shared UDP recv complete"
                );
                Ok((data, source))
            }
            Ok(Err(_)) => {
                // Channel closed (shouldn't happen normally)
                tracing::trace!(
                    snmp.target = %self.target,
                    snmp.request_id = request_id,
                    "shared UDP recv channel closed"
                );
                self.inner.pending.lock().unwrap().remove(&request_id);
                Err(Error::Timeout {
                    target: Some(self.target),
                    elapsed: timeout,
                    request_id,
                    retries: 0,
                })
            }
            Err(_) => {
                // Timeout
                tracing::trace!(
                    snmp.target = %self.target,
                    snmp.request_id = request_id,
                    "shared UDP recv timeout"
                );
                self.inner.pending.lock().unwrap().remove(&request_id);
                Err(Error::Timeout {
                    target: Some(self.target),
                    elapsed: timeout,
                    request_id,
                    retries: 0,
                })
            }
        }
    }

    fn peer_addr(&self) -> SocketAddr {
        self.target
    }

    fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr
    }

    fn is_stream(&self) -> bool {
        false
    }

    fn alloc_request_id(&self) -> Option<i32> {
        Some(self.inner.next_request_id.fetch_add(1, Ordering::Relaxed))
    }
}

// Re-export from transport mod for use in tests
use super::extract_request_id;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_initial_request_id_randomized() {
        // Create two SharedUdpTransports and verify they have different initial request IDs.
        // This protects against quick-restart collisions with SO_REUSEADDR.
        let transport1 = SharedUdpTransport::builder()
            .bind("127.0.0.1:0")
            .build()
            .await
            .unwrap();

        // Small delay to ensure different timestamp
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;

        let transport2 = SharedUdpTransport::builder()
            .bind("127.0.0.1:0")
            .build()
            .await
            .unwrap();

        let handle1 = transport1.handle("192.168.1.1:161".parse().unwrap());
        let handle2 = transport2.handle("192.168.1.1:161".parse().unwrap());

        let id1 = handle1.alloc_request_id().unwrap();
        let id2 = handle2.alloc_request_id().unwrap();

        // IDs should be different (randomized) and not both start at 1
        assert_ne!(id1, id2, "request IDs should be randomized");
        // At least one should not be 1 (extremely unlikely both hit exactly 1)
        assert!(id1 != 1 || id2 != 1, "at least one ID should not be 1");
    }
}
