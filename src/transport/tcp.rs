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
//! For direct transport construction:
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
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, OwnedMutexGuard};
use tokio::time::timeout;

/// Maximum SNMP message size for TCP (per RFC 3430).
///
/// This is the protocol-level maximum used for msgMaxSize advertisement.
const MAX_TCP_MESSAGE_SIZE: usize = 0x7fffffff;

/// Default allocation limit for incoming TCP messages.
///
/// While the protocol allows messages up to 2GB, we impose a practical limit
/// to prevent denial-of-service attacks where a malicious sender claims an
/// enormous message size. This limit is checked before allocating any buffers.
///
/// 10MB is generous for SNMP - even large table walks rarely exceed a few MB.
/// Real-world SNMP messages typically range from a few hundred bytes to a few KB.
const DEFAULT_MAX_ALLOCATION_SIZE: usize = 10 * 1024 * 1024; // 10 MB

/// Configuration options for [`TcpTransport`].
///
/// For advanced TCP socket configuration (TCP_NODELAY, keepalive, buffer sizes,
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
/// For advanced TCP socket configuration (TCP_NODELAY, keepalive, buffer sizes,
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
pub struct TcpTransportBuilder {
    timeout: Option<Duration>,
    options: TcpOptions,
}

impl TcpTransportBuilder {
    /// Create a new builder with default settings.
    pub fn new() -> Self {
        Self {
            timeout: None,
            options: TcpOptions::default(),
        }
    }

    /// Set connection timeout.
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
                active_guard: std::sync::Mutex::new(None),
                current_timeout: std::sync::Mutex::new(Duration::from_secs(30)),
                target,
                local_addr,
                max_allocation_size: self.options.max_allocation_size,
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
/// The stream lock is held from `send()` until `recv()` completes,
/// preventing interleaving of concurrent requests.
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
    /// Holds the stream lock between send() and recv() to serialize operations
    active_guard: std::sync::Mutex<Option<OwnedMutexGuard<TcpStream>>>,
    /// Timeout for current request (set by register_request)
    current_timeout: std::sync::Mutex<Duration>,
    target: SocketAddr,
    local_addr: SocketAddr,
    /// Maximum allocation size for incoming messages
    max_allocation_size: usize,
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
                active_guard: std::sync::Mutex::new(None),
                current_timeout: std::sync::Mutex::new(Duration::from_secs(30)),
                target,
                local_addr,
                max_allocation_size: options.max_allocation_size,
            }),
        })
    }
}

impl Transport for TcpTransport {
    async fn send(&self, data: &[u8]) -> Result<()> {
        // Acquire owned lock and hold it until recv() completes.
        // This serializes request-response pairs for concurrent callers.
        let mut stream = self.inner.stream.clone().lock_owned().await;
        let target = self.inner.target;

        let result = async {
            stream
                .write_all(data)
                .await
                .map_err(|e| Error::Network { target, source: e }.boxed())?;
            stream
                .flush()
                .await
                .map_err(|e| Error::Network { target, source: e }.boxed())?;
            Ok::<_, Box<Error>>(())
        }
        .await;

        match result {
            Ok(()) => {
                // Store the guard to hold the lock until recv()
                *self.inner.active_guard.lock().unwrap() = Some(stream);
                Ok(())
            }
            Err(e) => {
                // On error, guard is dropped and lock released
                Err(e)
            }
        }
    }

    fn register_request(&self, _request_id: i32, timeout: Duration) {
        *self.inner.current_timeout.lock().unwrap() = timeout;
    }

    async fn recv(&self, request_id: i32) -> Result<(Bytes, SocketAddr)> {
        let recv_timeout = *self.inner.current_timeout.lock().unwrap();
        let target = self.inner.target;

        // Take the guard that was stored by send().
        // This ensures we're reading the response for our request.
        let mut stream = self
            .inner
            .active_guard
            .lock()
            .unwrap()
            .take()
            .expect("recv() called without prior send() - this is a bug");

        // Read a complete BER-encoded message using the framing protocol.
        // The guard is dropped when this function returns, releasing the lock.
        let max_alloc = self.inner.max_allocation_size;
        let result = timeout(
            recv_timeout,
            read_ber_message(&mut stream, target, max_alloc),
        )
        .await;

        match result {
            Ok(Ok(data)) => Ok((data, target)),
            Ok(Err(e)) => Err(e),
            Err(_) => {
                tracing::debug!(
                    target: "async_snmp::transport::tcp",
                    request_id,
                    %target,
                    elapsed = ?recv_timeout,
                    "transport timeout"
                );
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
        MAX_TCP_MESSAGE_SIZE as u32
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
        tracing::debug!(
            target: "async_snmp::transport::tcp",
            expected_tag = 0x30,
            actual_tag = tag,
            %target,
            "invalid SNMP message tag"
        );
        return Err(Error::MalformedResponse { target }.boxed());
    }

    // Read length
    let mut first_len_byte = [0u8; 1];
    stream
        .read_exact(&mut first_len_byte)
        .await
        .map_err(|e| Error::Network { target, source: e }.boxed())?;

    let (content_len, len_bytes) = if first_len_byte[0] < 0x80 {
        // Short form: length is directly in this byte
        (first_len_byte[0] as usize, vec![first_len_byte[0]])
    } else if first_len_byte[0] == 0x80 {
        // Indefinite length - not supported
        tracing::debug!(
            target: "async_snmp::transport::tcp",
            %target,
            "indefinite length encoding not supported"
        );
        return Err(Error::MalformedResponse { target }.boxed());
    } else {
        // Long form: first byte indicates number of following length bytes
        let num_len_bytes = (first_len_byte[0] & 0x7F) as usize;
        if num_len_bytes > 4 {
            tracing::debug!(
                target: "async_snmp::transport::tcp",
                octets = num_len_bytes,
                %target,
                "length encoding too long"
            );
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
    };

    // Reject excessively large claimed sizes before allocating.
    // This prevents DoS attacks where a malicious sender claims a huge message
    // size without actually sending that much data.
    if content_len > max_allocation_size {
        tracing::warn!(
            target: "async_snmp::transport::tcp",
            size = content_len,
            max = max_allocation_size,
            %target,
            "message size exceeds limit"
        );
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

    /// Test concurrent requests through a single TcpTransport.
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
                transport.send(&request).await?;
                let (response, _) = transport.recv(request_id).await?;

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
            .filter(|r| r.as_ref().map(|r| r.is_ok()).unwrap_or(false))
            .count();

        assert_eq!(
            success_count, 5,
            "All 5 concurrent requests should succeed (serialized)"
        );

        server.await.unwrap();
    }

    /// Build a minimal SNMP v2c request with a specific request_id.
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

    /// Build a minimal SNMP v2c response with a specific request_id.
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
            "Expected MalformedResponse error, got: {:?}",
            err
        );

        server.await.unwrap();
    }

    /// Test that a custom max_allocation_size via builder is respected.
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
            "Expected MalformedResponse error, got: {:?}",
            err
        );

        server.await.unwrap();
    }
}
