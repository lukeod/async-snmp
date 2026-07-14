//! TCP transport implementation for SNMP clients.
//!
//! This module provides [`TcpTransport`], a TCP-based transport for SNMP
//! communication. TCP transport is useful when UDP is unreliable (firewalls,
//! lossy networks) or when larger message sizes are needed.
//!
//! # Message Framing
//!
//! Unlike UDP where each datagram is a complete message, TCP is a byte stream.
//! SNMP over TCP uses BER's self-describing length for framing:
//!
//! ```text
//! +------+--------+------------+
//! | 0x30 | Length |  Content   |
//! +------+--------+------------+
//!   Tag   1-5 bytes  N bytes
//! ```
//!
//! The receiver reads:
//! 1. Tag byte (0x30 for SEQUENCE)
//! 2. Length field (1-5 bytes, definite form only)
//! 3. Content bytes (length determined by step 2)
//!
//! This is the native BER encoding - no additional framing is needed.
//!
//! # When to Prefer TCP Over UDP
//!
//! | Use Case | Recommendation |
//! |----------|----------------|
//! | Standard polling | UDP (lower overhead, retries handle loss) |
//! | Firewalled networks | TCP (stateful connection may pass firewall) |
//! | Large responses (>64KB) | TCP (no UDP datagram size limit) |
//! | Unreliable networks | TCP (built-in retransmission) |
//! | Simple deployment | UDP (no connection state to manage) |
//!
//! # No Automatic Retries
//!
//! Since TCP guarantees delivery or connection failure, the client disables
//! automatic retries when using TCP transport. A timeout means the connection
//! is likely broken, and retry would require reconnection.
//!
//! # Example
//!
//! ```rust,no_run
//! use async_snmp::{Auth, Client};
//! use std::time::Duration;
//!
//! # async fn example() -> async_snmp::Result<()> {
//! // Create a TCP client via the builder
//! let client = Client::builder("192.168.1.1:161", Auth::v2c("public"))
//!     .timeout(Duration::from_secs(10))
//!     .connect_tcp()
//!     .await?;
//! # Ok(())
//! # }
//! ```
//!
//! For advanced TCP configuration (connection timeout, keepalive, buffer sizes),
//! construct the transport directly:
//!
//! ```rust,no_run
//! use async_snmp::transport::TcpTransport;
//! use async_snmp::{Client, ClientConfig};
//! use std::time::Duration;
//!
//! # async fn example() -> async_snmp::Result<()> {
//! let transport = TcpTransport::connect_timeout(
//!     "192.168.1.1:161".parse().unwrap(),
//!     Duration::from_secs(5)
//! ).await?;
//!
//! let client = Client::new(transport, ClientConfig::default());
//! # Ok(())
//! # }
//! ```

use super::Transport;
use crate::error::{Error, Result};
use bytes::{Bytes, BytesMut};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;

/// Protocol-level maximum SNMP message size for TCP (per RFC 3430).
///
/// This is the largest value that can be advertised in a v3 msgMaxSize field
/// (which is encoded as an i32). The advertised value is clamped to this
/// ceiling, but the effective advertisement is the transport's actual
/// acceptance limit (`max_allocation_size`) so that a peer honoring the
/// advertised size cannot send a response the reader would then reject.
const MAX_TCP_MESSAGE_SIZE: usize = 0x7FFF_FFFF;

/// Default allocation limit for incoming TCP messages.
///
/// While the protocol allows messages up to 2GB, we impose a practical limit
/// to prevent denial-of-service attacks where a malicious sender claims an
/// enormous message size. This limit is checked before allocating any buffers.
///
/// 10MB is generous for SNMP - even large table walks rarely exceed a few MB.
/// Real-world SNMP messages typically range from a few hundred bytes to a few KB.
const DEFAULT_MAX_ALLOCATION_SIZE: usize = 10 * 1024 * 1024; // 10 MB

/// Fallback receive timeout used when a request/recv is invoked without a
/// prior [`register_request`] (or after its per-request entry was already
/// consumed).
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Configuration options for [`TcpTransport`].
///
/// For advanced TCP socket configuration (`TCP_NODELAY`, keepalive, buffer sizes,
/// etc.), use [`TcpTransport::from_socket()`] with a pre-configured `TcpSocket`.
#[derive(Debug, Clone)]
pub struct TcpOptions {
    /// Maximum size of incoming messages to accept.
    ///
    /// Messages claiming to be larger than this are rejected before allocating
    /// any buffers, preventing denial-of-service attacks.
    ///
    /// Default: 10MB. Real SNMP messages rarely exceed a few KB.
    pub max_allocation_size: usize,
}

impl Default for TcpOptions {
    fn default() -> Self {
        Self {
            max_allocation_size: DEFAULT_MAX_ALLOCATION_SIZE,
        }
    }
}

/// Builder for [`TcpTransport`].
///
/// For advanced TCP socket configuration (`TCP_NODELAY`, keepalive, buffer sizes,
/// etc.), use [`TcpTransport::from_socket()`] with a pre-configured `TcpSocket`.
///
/// # Example
///
/// ```rust,no_run
/// use async_snmp::transport::TcpTransport;
/// use std::time::Duration;
///
/// # async fn example() -> async_snmp::Result<()> {
/// let transport = TcpTransport::builder()
///     .timeout(Duration::from_secs(10))
///     .max_allocation_size(1_000_000)  // 1MB limit
///     .connect("192.168.1.1:161".parse().unwrap())
///     .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct TcpTransportBuilder {
    timeout: Option<Duration>,
    options: TcpOptions,
}

impl TcpTransportBuilder {
    /// Create a new builder with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            timeout: None,
            options: TcpOptions::default(),
        }
    }

    /// Set connection timeout.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set maximum allocation size for incoming messages.
    ///
    /// Messages claiming to be larger than this are rejected before allocating
    /// any buffers, preventing denial-of-service attacks.
    ///
    /// Default: 10MB.
    #[must_use]
    pub fn max_allocation_size(mut self, size: usize) -> Self {
        self.options.max_allocation_size = size;
        self
    }

    /// Connect to the target address.
    pub async fn connect(self, target: SocketAddr) -> Result<TcpTransport> {
        let stream = match self.timeout {
            Some(t) => timeout(t, TcpStream::connect(target))
                .await
                .map_err(|_| {
                    Error::Timeout {
                        target,
                        elapsed: t,
                        retries: 0,
                    }
                    .boxed()
                })?
                .map_err(|e| Error::Network { target, source: e }.boxed())?,
            None => TcpStream::connect(target)
                .await
                .map_err(|e| Error::Network { target, source: e }.boxed())?,
        };

        let local_addr = stream
            .local_addr()
            .map_err(|e| Error::Network { target, source: e }.boxed())?;

        Ok(TcpTransport {
            inner: Arc::new(TcpTransportInner {
                stream: Arc::new(Mutex::new(stream)),
                pending_timeouts: StdMutex::new(HashMap::new()),
                target,
                local_addr,
                max_allocation_size: self.options.max_allocation_size,
                poisoned: AtomicBool::new(false),
            }),
        })
    }
}

impl Default for TcpTransportBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// TCP transport for a single target.
///
/// Each `TcpTransport` owns a TCP connection to a specific target.
/// Unlike UDP, TCP is stream-oriented so messages are framed using
/// BER's self-describing length encoding.
///
/// # Connection Lifecycle
///
/// The connection is established during construction and remains open
/// for the lifetime of the transport. If the connection fails, subsequent
/// operations return errors and a new transport must be created.
///
/// # No Retries
///
/// Since TCP guarantees delivery or failure, the client does not retry
/// on timeout when using TCP transport ([`is_reliable()`](Transport::is_reliable)
/// returns `true`). A timeout indicates the connection is likely broken.
///
/// # Serialized Operations
///
/// Request-response pairs are serialized to ensure correct correlation.
/// [`request()`](Transport::request) owns the stream lock for the whole
/// write-then-read exchange, preventing interleaving of concurrent requests.
/// Because the lock is held by a single future (not stashed across independent
/// await points), a dropped or cancelled request releases it instead of leaking
/// it.
///
/// # Example
///
/// ```rust,no_run
/// use async_snmp::transport::TcpTransport;
/// use async_snmp::{Client, ClientConfig};
/// use std::time::Duration;
///
/// # async fn example() -> async_snmp::Result<()> {
/// let transport = TcpTransport::connect_timeout(
///     "192.168.1.1:161".parse().unwrap(),
///     Duration::from_secs(5)
/// ).await?;
///
/// let client = Client::new(transport, ClientConfig::default());
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct TcpTransport {
    inner: Arc<TcpTransportInner>,
}

struct TcpTransportInner {
    /// The TCP stream, wrapped in Arc for owned guard pattern
    stream: Arc<Mutex<TcpStream>>,
    /// Per-request receive timeouts, keyed by request ID.
    ///
    /// [`register_request`](Transport::register_request) inserts the timeout for
    /// a request ID; the matching `request`/`recv` removes and uses it. Keeping
    /// the value keyed per request (rather than in a single shared field) means a
    /// second client sharing this cloned transport cannot overwrite the receive
    /// timeout of another client's in-flight request.
    pending_timeouts: StdMutex<HashMap<i32, Duration>>,
    target: SocketAddr,
    local_addr: SocketAddr,
    /// Maximum allocation size for incoming messages
    max_allocation_size: usize,
    /// Set once the stream framing is known to be lost.
    ///
    /// TCP is a byte stream framed by BER length prefixes. A read that times
    /// out, is truncated, or is rejected as malformed/oversized leaves an
    /// unknown number of bytes for the current frame still buffered in the
    /// kernel. Because the client does not retry on a reliable transport
    /// (`is_reliable() == true`), a subsequent read would parse those leftover
    /// bytes as the start of the next message. Once this flag is set the stream
    /// is treated as unusable and every later request/recv fails fast with
    /// [`Error::Closed`]; recovery requires constructing a new transport
    /// (RFC 3430 section 2: close the connection on lost framing).
    poisoned: AtomicBool,
}

impl TcpTransportInner {
    /// Report whether the stream framing has been marked lost.
    fn is_poisoned(&self) -> bool {
        self.poisoned.load(Ordering::Acquire)
    }

    /// Remove and return the receive timeout registered for `request_id`.
    ///
    /// Falls back to [`DEFAULT_REQUEST_TIMEOUT`] when no entry was registered
    /// (or it was already consumed). Taking the value here keeps it local to the
    /// request that owns the stream guard, so a concurrent registration for a
    /// different request cannot alter it.
    fn take_timeout(&self, request_id: i32) -> Duration {
        self.pending_timeouts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&request_id)
            .unwrap_or(DEFAULT_REQUEST_TIMEOUT)
    }

    /// Mark the stream unusable and best-effort close it.
    ///
    /// Called while holding the stream lock after any read that leaves the
    /// framing in an unknown state. The shutdown is best-effort; failures are
    /// ignored because the connection is already being abandoned.
    async fn poison(&self, stream: &mut TcpStream) {
        self.poisoned.store(true, Ordering::Release);
        let _ = stream.shutdown().await;
    }
}

impl TcpTransport {
    /// Connect to a target address with default options.
    ///
    /// For custom configuration, use [`builder()`](Self::builder) or
    /// [`from_socket()`](Self::from_socket).
    pub async fn connect(target: SocketAddr) -> Result<Self> {
        Self::builder().connect(target).await
    }

    /// Connect with a timeout.
    ///
    /// For additional configuration, use [`builder()`](Self::builder).
    pub async fn connect_timeout(target: SocketAddr, connect_timeout: Duration) -> Result<Self> {
        Self::builder()
            .timeout(connect_timeout)
            .connect(target)
            .await
    }

    /// Create a builder for custom configuration.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use async_snmp::transport::TcpTransport;
    /// use std::time::Duration;
    ///
    /// # async fn example() -> async_snmp::Result<()> {
    /// let transport = TcpTransport::builder()
    ///     .timeout(Duration::from_secs(10))
    ///     .max_allocation_size(1_000_000)
    ///     .connect("192.168.1.1:161".parse().unwrap())
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn builder() -> TcpTransportBuilder {
        TcpTransportBuilder::new()
    }

    /// Create a transport from a pre-configured TCP socket.
    ///
    /// Use this when you need fine-grained control over TCP socket options
    /// like `TCP_NODELAY`, keepalive, buffer sizes, etc.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use async_snmp::transport::{TcpTransport, TcpOptions};
    /// use tokio::net::TcpSocket;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let socket = TcpSocket::new_v4()?;
    /// socket.set_nodelay(true)?;
    /// // Configure other options as needed...
    ///
    /// let target = "192.168.1.1:161".parse()?;
    /// let transport = TcpTransport::from_socket(socket, target, TcpOptions::default()).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn from_socket(
        socket: tokio::net::TcpSocket,
        target: SocketAddr,
        options: TcpOptions,
    ) -> Result<Self> {
        let stream = socket
            .connect(target)
            .await
            .map_err(|e| Error::Network { target, source: e }.boxed())?;

        let local_addr = stream
            .local_addr()
            .map_err(|e| Error::Network { target, source: e }.boxed())?;

        Ok(Self {
            inner: Arc::new(TcpTransportInner {
                stream: Arc::new(Mutex::new(stream)),
                pending_timeouts: StdMutex::new(HashMap::new()),
                target,
                local_addr,
                max_allocation_size: options.max_allocation_size,
                poisoned: AtomicBool::new(false),
            }),
        })
    }
}

impl Transport for TcpTransport {
    async fn send(&self, data: &[u8]) -> Result<()> {
        // Fire-and-forget write (e.g. traps). The lock is held only for the
        // duration of this future; it is released on return or cancellation and
        // is never stashed across independent await points.
        let mut stream = self.inner.stream.clone().lock_owned().await;
        let target = self.inner.target;
        stream
            .write_all(data)
            .await
            .map_err(|e| Error::Network { target, source: e }.boxed())?;
        stream
            .flush()
            .await
            .map_err(|e| Error::Network { target, source: e }.boxed())?;
        Ok(())
    }

    fn register_request(&self, request_id: i32, timeout: Duration) {
        self.inner
            .pending_timeouts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(request_id, timeout);
    }

    async fn recv(&self, request_id: i32) -> Result<(Bytes, SocketAddr)> {
        let recv_timeout = self.inner.take_timeout(request_id);
        let target = self.inner.target;

        // Acquire the stream lock for the duration of this read only. The guard
        // is a local, so it is released on return or task cancellation.
        let mut stream = self.inner.stream.clone().lock_owned().await;

        // Refuse to read from a stream whose framing was previously lost; the
        // leftover bytes of the abandoned frame would be misparsed as a new
        // message.
        if self.inner.is_poisoned() {
            return Err(Error::Closed { target }.boxed());
        }

        // Read a complete BER-encoded message using the framing protocol.
        let max_alloc = self.inner.max_allocation_size;
        let result = timeout(
            recv_timeout,
            read_ber_message(&mut stream, target, max_alloc),
        )
        .await;

        match result {
            Ok(Ok(data)) => Ok((data, target)),
            Ok(Err(e)) => {
                // A malformed/oversized/truncated frame leaves the stream at an
                // unknown offset; abandon the connection.
                self.inner.poison(&mut stream).await;
                Err(e)
            }
            Err(_) => {
                tracing::debug!(target: "async_snmp::transport::tcp", { request_id, %target, elapsed = ?recv_timeout }, "transport timeout");
                // A timeout mid-frame leaves unread content bytes buffered;
                // abandon the connection.
                self.inner.poison(&mut stream).await;
                Err(Error::Timeout {
                    target,
                    elapsed: recv_timeout,
                    retries: 0,
                }
                .boxed())
            }
        }
    }

    async fn request(&self, data: &[u8], request_id: i32) -> Result<(Bytes, SocketAddr)> {
        let recv_timeout = self.inner.take_timeout(request_id);
        let target = self.inner.target;
        let max_alloc = self.inner.max_allocation_size;

        // Own the stream lock for the whole write+read exchange as a single
        // unit. The guard is a local held by one future, so it serializes
        // concurrent callers yet is released on return or cancellation. This
        // avoids stashing the guard across independent await points, which would
        // leak the lock (and permanently wedge later requests) if the caller's
        // future were dropped between the send and the recv.
        let mut stream = self.inner.stream.clone().lock_owned().await;

        // Refuse to reuse a stream whose framing was previously lost.
        if self.inner.is_poisoned() {
            return Err(Error::Closed { target }.boxed());
        }

        // A write failure may have left a partial request on the wire, so the
        // stream can no longer be trusted for framing; poison before returning.
        if let Err(e) = stream.write_all(data).await {
            self.inner.poison(&mut stream).await;
            return Err(Error::Network { target, source: e }.boxed());
        }
        if let Err(e) = stream.flush().await {
            self.inner.poison(&mut stream).await;
            return Err(Error::Network { target, source: e }.boxed());
        }

        let result = timeout(
            recv_timeout,
            read_ber_message(&mut stream, target, max_alloc),
        )
        .await;

        match result {
            Ok(Ok(response)) => Ok((response, target)),
            Ok(Err(e)) => {
                // A malformed/oversized/truncated frame leaves the stream at an
                // unknown offset; abandon the connection.
                self.inner.poison(&mut stream).await;
                Err(e)
            }
            Err(_) => {
                tracing::debug!(target: "async_snmp::transport::tcp", { request_id, %target, elapsed = ?recv_timeout }, "transport timeout");
                // A timeout mid-frame leaves unread content bytes buffered;
                // abandon the connection.
                self.inner.poison(&mut stream).await;
                Err(Error::Timeout {
                    target,
                    elapsed: recv_timeout,
                    retries: 0,
                }
                .boxed())
            }
        }
    }

    fn peer_addr(&self) -> SocketAddr {
        self.inner.target
    }

    fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr
    }

    fn is_reliable(&self) -> bool {
        true
    }

    fn max_message_size(&self) -> u32 {
        // Advertise the true acceptance limit rather than the protocol ceiling.
        // The reader rejects any frame whose claimed content length exceeds
        // `max_allocation_size`, so advertising a larger msgMaxSize would invite
        // a peer to send a legitimate-but-oversized response that then gets
        // rejected. Clamp to the i32-encodable protocol maximum.
        self.inner.max_allocation_size.min(MAX_TCP_MESSAGE_SIZE) as u32
    }
}

/// Read a complete BER-encoded SNMP message from a TCP stream.
///
/// SNMP messages are SEQUENCE types (tag 0x30). We read:
/// 1. Tag byte (must be 0x30)
/// 2. Length field (definite form only)
/// 3. Content bytes
async fn read_ber_message(
    stream: &mut TcpStream,
    target: SocketAddr,
    max_allocation_size: usize,
) -> Result<Bytes> {
    // Read tag byte
    let mut tag_buf = [0u8; 1];
    stream
        .read_exact(&mut tag_buf)
        .await
        .map_err(|e| Error::Network { target, source: e }.boxed())?;

    let tag = tag_buf[0];
    if tag != 0x30 {
        tracing::debug!(target: "async_snmp::transport::tcp", { expected_tag = 0x30, actual_tag = tag, %target }, "invalid SNMP message tag");
        return Err(Error::MalformedResponse { target }.boxed());
    }

    // Read length
    let mut first_len_byte = [0u8; 1];
    stream
        .read_exact(&mut first_len_byte)
        .await
        .map_err(|e| Error::Network { target, source: e }.boxed())?;

    let (content_len, len_bytes) = match first_len_byte[0].cmp(&0x80) {
        std::cmp::Ordering::Less => {
            // Short form: length is directly in this byte
            (first_len_byte[0] as usize, vec![first_len_byte[0]])
        }
        std::cmp::Ordering::Equal => {
            // Indefinite length - not supported
            tracing::debug!(target: "async_snmp::transport::tcp", { %target }, "indefinite length encoding not supported");
            return Err(Error::MalformedResponse { target }.boxed());
        }
        std::cmp::Ordering::Greater => {
            // Long form: first byte indicates number of following length bytes
            let num_len_bytes = (first_len_byte[0] & 0x7F) as usize;
            if num_len_bytes > 4 {
                tracing::debug!(target: "async_snmp::transport::tcp", { octets = num_len_bytes, %target }, "length encoding too long");
                return Err(Error::MalformedResponse { target }.boxed());
            }

            let mut len_bytes_buf = vec![0u8; num_len_bytes];
            stream
                .read_exact(&mut len_bytes_buf)
                .await
                .map_err(|e| Error::Network { target, source: e }.boxed())?;

            let mut length: usize = 0;
            for &b in &len_bytes_buf {
                length = (length << 8) | (b as usize);
            }

            // Build the complete length encoding for reconstruction
            let mut all_len_bytes = vec![first_len_byte[0]];
            all_len_bytes.extend_from_slice(&len_bytes_buf);

            (length, all_len_bytes)
        }
    };

    // Reject excessively large claimed sizes before allocating.
    // This prevents DoS attacks where a malicious sender claims a huge message
    // size without actually sending that much data.
    if content_len > max_allocation_size {
        tracing::warn!(target: "async_snmp::transport::tcp", { size = content_len, max = max_allocation_size, %target }, "message size exceeds limit");
        return Err(Error::MalformedResponse { target }.boxed());
    }

    // Read content
    let mut content = vec![0u8; content_len];
    stream
        .read_exact(&mut content)
        .await
        .map_err(|e| Error::Network { target, source: e }.boxed())?;

    // Reconstruct complete message: tag + length + content
    let total_len = 1 + len_bytes.len() + content_len;
    let mut message = BytesMut::with_capacity(total_len);
    message.extend_from_slice(&[tag]);
    message.extend_from_slice(&len_bytes);
    message.extend_from_slice(&content);

    Ok(message.freeze())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_tcp_send_recv() {
        // Start a mock server
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        // Server task
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();

            // Read incoming message using BER framing
            let mut buf = vec![0u8; 1024];
            let n = socket.read(&mut buf).await.unwrap();

            // Echo back a mock SNMP response
            // SEQUENCE { version=1, community="public", Response PDU { request_id=1, ... } }
            let response = [
                0x30, 0x1c, // SEQUENCE length 28
                0x02, 0x01, 0x01, // INTEGER 1 (v2c)
                0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, // "public"
                0xa2, 0x0f, // Response PDU
                0x02, 0x01, 0x01, // request_id = 1
                0x02, 0x01, 0x00, // error-status = 0
                0x02, 0x01, 0x00, // error-index = 0
                0x30, 0x04, 0x30, 0x02, 0x05, 0x00, // varbinds
            ];
            socket.write_all(&response).await.unwrap();
            n
        });

        // Client
        let transport = TcpTransport::connect(server_addr).await.unwrap();

        // Send a mock request
        let request = [
            0x30, 0x1a, // SEQUENCE
            0x02, 0x01, 0x01, // version
            0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, // community
            0xa0, 0x0d, // GET PDU
            0x02, 0x01, 0x01, // request_id = 1
            0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x02, 0x30, 0x00,
        ];
        transport.send(&request).await.unwrap();

        // Receive response
        transport.register_request(1, Duration::from_secs(5));
        let (response, source) = transport.recv(1).await.unwrap();

        assert_eq!(source, server_addr);
        assert_eq!(response[0], 0x30); // SEQUENCE tag
        assert!(response.len() > 10);

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_tcp_long_length_form() {
        // Test reading a message with long-form length encoding
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();

            // Wait for any data (client sends something)
            let mut buf = [0u8; 1];
            let _ = socket.read(&mut buf).await;

            // Send a response with 2-byte length field (length = 200)
            let mut response = vec![0x30, 0x81, 0xc8]; // SEQUENCE, long form length = 200
            response.extend(vec![0x00; 200]); // 200 bytes of content
            socket.write_all(&response).await.unwrap();
        });

        let transport = TcpTransport::connect(server_addr).await.unwrap();
        transport.send(&[0x00]).await.unwrap(); // Trigger server

        transport.register_request(1, Duration::from_secs(5));
        let (response, _) = transport.recv(1).await.unwrap();

        // Verify: tag (1) + length field (2) + content (200) = 203 bytes
        assert_eq!(response.len(), 203);
        assert_eq!(response[0], 0x30);
        assert_eq!(response[1], 0x81);
        assert_eq!(response[2], 0xc8); // 200 in hex

        server.await.unwrap();
    }

    /// Regression test: the advertised msgMaxSize must equal the transport's
    /// actual acceptance limit (`max_allocation_size`), not the protocol
    /// ceiling. Advertising more than the reader accepts would let a v3 peer
    /// honor the advertisement with a response the reader then rejects.
    #[tokio::test]
    async fn test_tcp_advertised_max_matches_accepted_limit() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut conns = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                conns.push(socket);
            }
        });

        // Default limit.
        let transport = TcpTransport::connect(server_addr).await.unwrap();
        assert_eq!(
            transport.max_message_size() as usize,
            transport.inner.max_allocation_size,
            "advertised msgMaxSize must equal the accepted allocation limit"
        );
        assert_eq!(
            transport.max_message_size() as usize,
            DEFAULT_MAX_ALLOCATION_SIZE
        );

        // Custom limit via the builder.
        let custom = 512 * 1024;
        let transport = TcpTransport::builder()
            .max_allocation_size(custom)
            .connect(server_addr)
            .await
            .unwrap();
        assert_eq!(transport.max_message_size() as usize, custom);
        assert_eq!(
            transport.max_message_size() as usize,
            transport.inner.max_allocation_size
        );
    }

    #[tokio::test]
    async fn test_tcp_is_reliable() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        // Accept connection in background
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let transport = TcpTransport::connect(server_addr).await.unwrap();
        assert!(transport.is_reliable());
    }

    /// Test concurrent requests through a single `TcpTransport`.
    ///
    /// TCP serializes request-response pairs via locking. Multiple concurrent
    /// callers queue up and execute one at a time. All should succeed.
    #[tokio::test]
    async fn test_tcp_concurrent_requests() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicI32, Ordering};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        // Track request_ids seen by server
        let request_counter = Arc::new(AtomicI32::new(0));
        let counter_clone = request_counter.clone();

        // Server that handles multiple sequential requests
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();

            // Handle 5 requests sequentially (TCP serializes them)
            for _ in 0..5 {
                // Read request using BER framing
                let mut tag = [0u8; 1];
                if socket.read_exact(&mut tag).await.is_err() {
                    break;
                }

                let mut len_byte = [0u8; 1];
                socket.read_exact(&mut len_byte).await.unwrap();
                let content_len = len_byte[0] as usize;

                let mut content = vec![0u8; content_len];
                socket.read_exact(&mut content).await.unwrap();

                // Extract request_id from the request (offset varies, just use counter)
                let request_id = counter_clone.fetch_add(1, Ordering::SeqCst) + 1;

                // Build response with matching request_id
                let response = build_response_with_id(request_id);
                socket.write_all(&response).await.unwrap();
            }
        });

        let transport = TcpTransport::connect(server_addr).await.unwrap();

        // Spawn 5 concurrent tasks that all try to use the transport
        let mut handles = vec![];
        for i in 0..5 {
            let transport = transport.clone();
            let handle = tokio::spawn(async move {
                let request_id = i + 1;
                let request = build_request_with_id(request_id);

                transport.register_request(request_id, Duration::from_secs(5));
                let (response, _) = transport.request(&request, request_id).await?;

                // Verify we got a valid response
                assert_eq!(response[0], 0x30, "Response should be SEQUENCE");
                Ok::<_, Box<Error>>(i)
            });
            handles.push(handle);
        }

        // Wait for all tasks to complete
        let results: Vec<_> = futures::future::join_all(handles).await;

        let success_count = results
            .iter()
            .filter(|r| r.as_ref().is_ok_and(std::result::Result::is_ok))
            .count();

        assert_eq!(
            success_count, 5,
            "All 5 concurrent requests should succeed (serialized)"
        );

        server.await.unwrap();
    }

    /// Build a minimal SNMP v2c request with a specific `request_id`.
    fn build_request_with_id(request_id: i32) -> Vec<u8> {
        let id_bytes = request_id.to_be_bytes();
        vec![
            0x30,
            0x1d, // SEQUENCE length 29
            0x02,
            0x01,
            0x01, // version = 1 (v2c)
            0x04,
            0x06,
            0x70,
            0x75,
            0x62,
            0x6c,
            0x69,
            0x63, // "public"
            0xa0,
            0x10, // GET PDU length 16
            0x02,
            0x04,
            id_bytes[0],
            id_bytes[1],
            id_bytes[2],
            id_bytes[3], // request_id
            0x02,
            0x01,
            0x00, // error-status = 0
            0x02,
            0x01,
            0x00, // error-index = 0
            0x30,
            0x02,
            0x30,
            0x00, // varbinds
        ]
    }

    /// Build a minimal SNMP v2c response with a specific `request_id`.
    fn build_response_with_id(request_id: i32) -> Vec<u8> {
        let id_bytes = request_id.to_be_bytes();
        vec![
            0x30,
            0x1d, // SEQUENCE length 29
            0x02,
            0x01,
            0x01, // version = 1 (v2c)
            0x04,
            0x06,
            0x70,
            0x75,
            0x62,
            0x6c,
            0x69,
            0x63, // "public"
            0xa2,
            0x10, // Response PDU length 16
            0x02,
            0x04,
            id_bytes[0],
            id_bytes[1],
            id_bytes[2],
            id_bytes[3], // request_id
            0x02,
            0x01,
            0x00, // error-status = 0
            0x02,
            0x01,
            0x00, // error-index = 0
            0x30,
            0x02,
            0x30,
            0x00, // varbinds
        ]
    }

    /// Test that excessively large claimed message sizes are rejected early.
    ///
    /// A malicious client could send a BER length field claiming the message is
    /// very large (e.g., 100MB) without actually sending that much data. Without
    /// proper limits, the receiver would allocate the full claimed size before
    /// reading any content, enabling a denial-of-service attack.
    #[tokio::test]
    async fn test_tcp_rejects_excessive_claimed_size() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        // Server that sends a message claiming to be 100MB
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();

            // Wait for any data (client sends something)
            let mut buf = [0u8; 64];
            let _ = socket.read(&mut buf).await;

            // Send a response claiming to be 100MB (0x06400000 = 104857600)
            // Format: tag (0x30) + long-form length (0x84 = 4 bytes follow)
            let malicious_response = [
                0x30, // SEQUENCE tag
                0x84, // Long form: 4 length bytes follow
                0x06, 0x40, 0x00,
                0x00, // Length = 104857600 (100MB)
                      // No actual content sent - attacker doesn't need to send anything
            ];
            let _ = socket.write_all(&malicious_response).await;

            // Keep connection open briefly
            tokio::time::sleep(Duration::from_millis(100)).await;
        });

        let transport = TcpTransport::connect(server_addr).await.unwrap();

        // Send a request to trigger the malicious response
        let request = build_request_with_id(1);
        transport.send(&request).await.unwrap();

        transport.register_request(1, Duration::from_secs(5));
        let result = transport.recv(1).await;

        // Should reject the message without allocating 100MB
        assert!(result.is_err(), "Should reject excessive claimed size");
        let err = result.unwrap_err();
        assert!(
            matches!(*err, Error::MalformedResponse { .. }),
            "Expected MalformedResponse error, got: {err:?}"
        );

        server.await.unwrap();
    }

    /// Test that `read_ber_message` rejects a non-SEQUENCE tag byte.
    #[tokio::test]
    async fn test_read_ber_message_rejects_bad_tag() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(&[0x31, 0x00]).await.unwrap();
        });

        let mut client = TcpStream::connect(server_addr).await.unwrap();
        let result = timeout(
            Duration::from_secs(5),
            read_ber_message(&mut client, server_addr, DEFAULT_MAX_ALLOCATION_SIZE),
        )
        .await
        .expect("read_ber_message should not hang");

        assert!(result.is_err(), "Should reject non-0x30 tag byte");
        let err = result.unwrap_err();
        assert!(
            matches!(*err, Error::MalformedResponse { .. }),
            "Expected MalformedResponse error, got: {err:?}"
        );

        server.await.unwrap();
    }

    /// Test that `read_ber_message` rejects the BER indefinite-length form (0x80).
    #[tokio::test]
    async fn test_read_ber_message_rejects_indefinite_length() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(&[0x30, 0x80]).await.unwrap();
        });

        let mut client = TcpStream::connect(server_addr).await.unwrap();
        let result = timeout(
            Duration::from_secs(5),
            read_ber_message(&mut client, server_addr, DEFAULT_MAX_ALLOCATION_SIZE),
        )
        .await
        .expect("read_ber_message should not hang");

        assert!(result.is_err(), "Should reject indefinite length encoding");
        let err = result.unwrap_err();
        assert!(
            matches!(*err, Error::MalformedResponse { .. }),
            "Expected MalformedResponse error, got: {err:?}"
        );

        server.await.unwrap();
    }

    /// Test that `read_ber_message` rejects a long-form length with more than
    /// the 4-octet cap of trailing length bytes.
    #[tokio::test]
    async fn test_read_ber_message_rejects_length_encoding_too_long() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            // 0x85 = long form, 5 trailing length octets (> 4-octet cap).
            socket
                .write_all(&[0x30, 0x85, 0x00, 0x00, 0x00, 0x00, 0x00])
                .await
                .unwrap();
        });

        let mut client = TcpStream::connect(server_addr).await.unwrap();
        let result = timeout(
            Duration::from_secs(5),
            read_ber_message(&mut client, server_addr, DEFAULT_MAX_ALLOCATION_SIZE),
        )
        .await
        .expect("read_ber_message should not hang");

        assert!(
            result.is_err(),
            "Should reject length encoding over 4 octets"
        );
        let err = result.unwrap_err();
        assert!(
            matches!(*err, Error::MalformedResponse { .. }),
            "Expected MalformedResponse error, got: {err:?}"
        );

        server.await.unwrap();
    }

    /// Test that `read_ber_message` reassembles content delivered across
    /// multiple separate TCP writes (segmented delivery), proving `read_exact`
    /// correctly spans multiple reads rather than assuming one full message
    /// arrives in a single `read`.
    #[tokio::test]
    async fn test_read_ber_message_reassembles_segmented_content() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();

            // Tag + length in the first segment.
            socket.write_all(&[0x30, 0x04]).await.unwrap();
            socket.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;

            // First half of content.
            socket.write_all(&[0x01, 0x02]).await.unwrap();
            socket.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;

            // Second half of content.
            socket.write_all(&[0x03, 0x04]).await.unwrap();
            socket.flush().await.unwrap();

            // Keep the connection open until the client has read everything.
            tokio::time::sleep(Duration::from_millis(100)).await;
        });

        let mut client = TcpStream::connect(server_addr).await.unwrap();
        let result = timeout(
            Duration::from_secs(5),
            read_ber_message(&mut client, server_addr, DEFAULT_MAX_ALLOCATION_SIZE),
        )
        .await
        .expect("read_ber_message should not hang");

        let bytes = result.expect("segmented message should reassemble successfully");
        assert_eq!(bytes.as_ref(), &[0x30, 0x04, 0x01, 0x02, 0x03, 0x04]);

        server.await.unwrap();
    }

    /// Test that a truncated stream (content promised but connection closed
    /// before it fully arrives) surfaces as a `Network` error from the
    /// content `read_exact` hitting `UnexpectedEof`.
    #[tokio::test]
    async fn test_read_ber_message_truncated_stream_is_network_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();

            // Claims 5 content octets but only ever sends 2, then drops the
            // connection.
            socket.write_all(&[0x30, 0x05]).await.unwrap();
            socket.write_all(&[0x01, 0x02]).await.unwrap();
            socket.flush().await.unwrap();
            drop(socket);
        });

        let mut client = TcpStream::connect(server_addr).await.unwrap();
        let result = timeout(
            Duration::from_secs(5),
            read_ber_message(&mut client, server_addr, DEFAULT_MAX_ALLOCATION_SIZE),
        )
        .await
        .expect("read_ber_message should not hang");

        assert!(result.is_err(), "Should error on truncated content stream");
        let err = result.unwrap_err();
        assert!(
            matches!(*err, Error::Network { .. }),
            "Expected Network error, got: {err:?}"
        );

        server.await.unwrap();
    }

    /// Test that a custom `max_allocation_size` via builder is respected.
    #[tokio::test]
    async fn test_tcp_builder_custom_allocation_limit() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        // Server that sends a message claiming to be 10KB (larger than our 1KB limit)
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();

            let mut buf = [0u8; 64];
            let _ = socket.read(&mut buf).await;

            // Send a response claiming to be 10KB (0x2800 = 10240)
            let response = [
                0x30, // SEQUENCE tag
                0x82, // Long form: 2 length bytes follow
                0x28, 0x00, // Length = 10240 (10KB)
            ];
            let _ = socket.write_all(&response).await;

            tokio::time::sleep(Duration::from_millis(100)).await;
        });

        // Use builder with 1KB limit
        let transport = TcpTransport::builder()
            .max_allocation_size(1024) // 1KB limit
            .connect(server_addr)
            .await
            .unwrap();

        let request = build_request_with_id(1);
        transport.send(&request).await.unwrap();

        transport.register_request(1, Duration::from_secs(5));
        let result = transport.recv(1).await;

        // Should reject 10KB message when limit is 1KB
        assert!(
            result.is_err(),
            "Should reject message exceeding custom limit"
        );
        let err = result.unwrap_err();
        assert!(
            matches!(*err, Error::MalformedResponse { .. }),
            "Expected MalformedResponse error, got: {err:?}"
        );

        server.await.unwrap();
    }

    /// Regression test: a dropped/cancelled request must not wedge the transport.
    ///
    /// Previously `send()` stashed the stream lock in a field for `recv()` to
    /// reclaim. If the caller's future was dropped between the two await points
    /// (e.g. a `timeout()` wrapping the request), the guard leaked and the stream
    /// lock was never released, deadlocking every later request. `request()` now
    /// owns the lock as a local for the whole exchange, so cancellation releases
    /// it and the next request proceeds.
    #[tokio::test]
    async fn test_tcp_cancelled_request_does_not_wedge_next() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();

            // Read the first request framing, then stall without responding so
            // the client's request future is cancelled by the outer timeout.
            let mut hdr = [0u8; 2];
            socket.read_exact(&mut hdr).await.unwrap();
            let mut body = vec![0u8; hdr[1] as usize];
            socket.read_exact(&mut body).await.unwrap();
            tokio::time::sleep(Duration::from_millis(300)).await;

            // Read the second request and answer it.
            socket.read_exact(&mut hdr).await.unwrap();
            let mut body2 = vec![0u8; hdr[1] as usize];
            socket.read_exact(&mut body2).await.unwrap();
            let response = build_response_with_id(2);
            socket.write_all(&response).await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
        });

        let transport = TcpTransport::connect(server_addr).await.unwrap();

        // First request: cancelled by the outer timeout before any response.
        let request = build_request_with_id(1);
        transport.register_request(1, Duration::from_secs(30));
        let cancelled = timeout(Duration::from_millis(50), transport.request(&request, 1)).await;
        assert!(cancelled.is_err(), "outer timeout should elapse (cancel)");

        // The stream lock must be free after the cancelled request.
        assert!(
            transport.inner.stream.clone().try_lock_owned().is_ok(),
            "stream lock leaked after a cancelled request"
        );

        // The next request must succeed rather than deadlock.
        let request2 = build_request_with_id(2);
        transport.register_request(2, Duration::from_secs(5));
        let result = timeout(Duration::from_secs(5), transport.request(&request2, 2))
            .await
            .expect("second request should not hang");
        let (response, _) = result.expect("second request should succeed");
        assert_eq!(response[0], 0x30);

        server.await.unwrap();
    }

    /// Regression test: a malformed frame must poison the stream so the next
    /// request fails fast instead of parsing leftover/misaligned bytes.
    ///
    /// With `is_reliable() == true` the client does not retry, so a desynced
    /// stream would otherwise have its next `request()` parse the tail of the
    /// abandoned frame as a fresh message. The transport now marks the stream
    /// poisoned after any malformed/oversized/truncated/timed-out read and
    /// rejects later requests with [`Error::Closed`].
    #[tokio::test]
    async fn test_tcp_malformed_frame_poisons_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();

            // Read the first request framing.
            let mut hdr = [0u8; 2];
            socket.read_exact(&mut hdr).await.unwrap();
            let mut body = vec![0u8; hdr[1] as usize];
            socket.read_exact(&mut body).await.unwrap();

            // Reply with a non-SEQUENCE tag (0x31) plus trailing bytes that, if
            // the stream were reused, could be misparsed as a following frame.
            socket
                .write_all(&[0x31, 0x02, 0xde, 0xad, 0x30, 0x00])
                .await
                .unwrap();
            socket.flush().await.unwrap();

            // Keep the connection open; the point is that the client must not
            // reuse it, not that the server closed it.
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        let transport = TcpTransport::connect(server_addr).await.unwrap();

        // First request: the malformed reply is rejected and poisons the stream.
        let request = build_request_with_id(1);
        transport.register_request(1, Duration::from_secs(5));
        let first = transport.request(&request, 1).await;
        let err = first.expect_err("malformed frame should error");
        assert!(
            matches!(*err, Error::MalformedResponse { .. }),
            "Expected MalformedResponse, got: {err:?}"
        );

        // The stream must now be flagged as poisoned.
        assert!(
            transport.inner.is_poisoned(),
            "stream should be poisoned after a malformed frame"
        );

        // The next request must fail fast with Closed rather than read the
        // leftover bytes of the abandoned frame.
        let request2 = build_request_with_id(2);
        transport.register_request(2, Duration::from_secs(5));
        let second = timeout(Duration::from_secs(5), transport.request(&request2, 2))
            .await
            .expect("second request should not hang");
        let err2 = second.expect_err("poisoned stream should reject the next request");
        assert!(
            matches!(*err2, Error::Closed { .. }),
            "Expected Closed on poisoned stream, got: {err2:?}"
        );

        server.await.unwrap();
    }

    /// Regression test: a second client sharing a cloned transport must not be
    /// able to overwrite the receive timeout of another client's request.
    ///
    /// Previously the timeout lived in a single shared `AtomicU64`, so client
    /// B's `register_request` (with a long timeout) would clobber the value
    /// client A registered (a short timeout) before A's `recv` read it. A's
    /// `recv` would then wait for B's long timeout. Timeouts are now keyed per
    /// request ID, so A's `recv` uses exactly the timeout A registered.
    #[tokio::test]
    async fn test_tcp_per_request_timeout_not_overwritten_by_clone() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        // Server accepts the connection but never responds.
        let server = tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
        });

        let transport_a = TcpTransport::connect(server_addr).await.unwrap();
        let transport_b = transport_a.clone();

        // Client A registers a short timeout for its request.
        transport_a.register_request(1, Duration::from_millis(150));
        // Client B, sharing the same cloned transport, registers a long timeout
        // for a different request. With the old shared atomic this overwrote A's
        // value; per-request keying keeps them independent.
        transport_b.register_request(2, Duration::from_secs(20));

        // A's recv must time out at ~150ms, not at B's 20s. Guard with a 5s
        // outer bound: if the bug regresses, A would wait 20s and this fails.
        let start = std::time::Instant::now();
        let result = timeout(Duration::from_secs(5), transport_a.recv(1))
            .await
            .expect("recv should honor A's short timeout, not B's long one");
        let elapsed = start.elapsed();

        let err = result.expect_err("recv should time out");
        assert!(
            matches!(*err, Error::Timeout { .. }),
            "Expected Timeout, got: {err:?}"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "recv honored the wrong timeout; elapsed {elapsed:?}"
        );

        server.abort();
    }

    /// Regression test: a read that times out mid-frame poisons the stream.
    ///
    /// The server sends a frame header claiming more content than it delivers
    /// and then stalls, so the client's content `read_exact` times out with
    /// bytes still buffered. `recv()` must poison the stream so a later `recv()`
    /// does not resume parsing at a misaligned offset.
    #[tokio::test]
    async fn test_tcp_timeout_mid_frame_poisons_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();

            let mut buf = [0u8; 64];
            let _ = socket.read(&mut buf).await;

            // Claim 8 content octets but send only 2, then stall without
            // closing so the client's content read times out.
            socket.write_all(&[0x30, 0x08, 0x01, 0x02]).await.unwrap();
            socket.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(500)).await;
        });

        let transport = TcpTransport::connect(server_addr).await.unwrap();

        let request = build_request_with_id(1);
        transport.send(&request).await.unwrap();

        transport.register_request(1, Duration::from_millis(100));
        let first = transport.recv(1).await;
        let err = first.expect_err("mid-frame read should time out");
        assert!(
            matches!(*err, Error::Timeout { .. }),
            "Expected Timeout, got: {err:?}"
        );

        assert!(
            transport.inner.is_poisoned(),
            "stream should be poisoned after a mid-frame timeout"
        );

        // A later recv must fail fast rather than parse leftover content bytes.
        transport.register_request(1, Duration::from_secs(5));
        let second = timeout(Duration::from_secs(5), transport.recv(1))
            .await
            .expect("second recv should not hang");
        let err2 = second.expect_err("poisoned stream should reject the next recv");
        assert!(
            matches!(*err2, Error::Closed { .. }),
            "Expected Closed on poisoned stream, got: {err2:?}"
        );

        server.await.unwrap();
    }
}
