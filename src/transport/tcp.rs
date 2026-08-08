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
//! let client = Client::new(transport, ClientConfig::default())?;
//! # Ok(())
//! # }
//! ```

use super::{Candidate, RequestRegistration, ResponseIdentity, Transport, extract_request_id};
use crate::error::{Error, Result};
use crate::message_size::ReceiveLimits;
use bytes::{Bytes, BytesMut};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
#[cfg(test)]
use tokio::time::timeout;

/// Default total-message limit for incoming TCP messages.
///
/// While the protocol allows messages up to 2GB, we impose a practical limit
/// to prevent denial-of-service attacks where a malicious sender claims an
/// enormous message size. This limit is checked before allocating any buffers.
///
/// 10MB is generous for SNMP - even large table walks rarely exceed a few MB.
/// Real-world SNMP messages typically range from a few hundred bytes to a few KB.
const DEFAULT_MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024; // 10 MB

/// Configuration options for [`TcpTransport`].
///
/// For advanced TCP socket configuration (`TCP_NODELAY`, keepalive, buffer sizes,
/// etc.), use [`TcpTransport::from_socket()`] with a pre-configured `TcpSocket`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct TcpOptions {
    /// Maximum size of incoming messages to accept.
    ///
    /// Messages claiming to be larger than this are rejected before allocating
    /// any buffers, preventing denial-of-service attacks.
    ///
    /// Default: 10MB. Real SNMP messages rarely exceed a few KB.
    pub max_message_size: usize,
}

impl Default for TcpOptions {
    fn default() -> Self {
        Self {
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
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
///     .max_message_size(1_000_000)  // 1MB limit
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

    /// Set the maximum total encoded size for incoming messages.
    ///
    /// Messages claiming to be larger than this are rejected before allocating
    /// any buffers, preventing denial-of-service attacks.
    ///
    /// Default: 10MB.
    #[must_use]
    pub fn max_message_size(mut self, size: usize) -> Self {
        self.options.max_message_size = size;
        self
    }

    /// Connect to the target address.
    pub async fn connect(self, target: SocketAddr) -> Result<TcpTransport> {
        // Validate the deadline before normalizing limits or starting connect
        // I/O so an unrepresentable duration has deterministic precedence.
        let connect_deadline = self
            .timeout
            .map(|timeout| tcp_deadline(timeout, "TCP connect timeout"))
            .transpose()?;
        let receive_limits = ReceiveLimits::tcp(self.options.max_message_size)
            .map_err(|error| Error::Config(error.to_string().into()).boxed())?;
        let stream = match (self.timeout, connect_deadline) {
            (Some(t), Some(deadline)) => {
                tokio::time::timeout_at(deadline, TcpStream::connect(target))
                    .await
                    .map_err(|_| {
                        Error::Timeout {
                            target,
                            elapsed: t,
                            retries: 0,
                        }
                        .boxed()
                    })?
                    .map_err(|e| Error::Network { target, source: e }.boxed())?
            }
            (None, None) => TcpStream::connect(target)
                .await
                .map_err(|e| Error::Network { target, source: e }.boxed())?,
            _ => unreachable!("deadline presence follows timeout presence"),
        };

        let local_addr = stream
            .local_addr()
            .map_err(|e| Error::Network { target, source: e }.boxed())?;

        Ok(TcpTransport {
            inner: Arc::new(TcpTransportInner {
                stream: Arc::new(Mutex::new(stream)),
                target,
                local_addr,
                receive_limits,
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
/// it. Cancellation after the lock is acquired also poisons the connection, so
/// later operations fail with [`Error::Closed`] rather than consuming ambiguous
/// stream state.
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
/// let client = Client::new(transport, ClientConfig::default())?;
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
    target: SocketAddr,
    local_addr: SocketAddr,
    /// One total-message bound shared by framing, decoding, and advertisement.
    receive_limits: ReceiveLimits,
    /// Set once framing or transaction state may be ambiguous.
    ///
    /// TCP is a byte stream framed by BER length prefixes. Partial I/O,
    /// cancellation, timeout, or malformed framing can leave an unknown number
    /// of bytes in flight or buffered. A subsequent exchange could then consume
    /// an abandoned request's response or parse leftover bytes as a fresh
    /// message. Once this flag is set every later operation fails fast with
    /// [`Error::Closed`]; recovery requires constructing a new transport.
    poisoned: AtomicBool,
}

impl TcpTransportInner {
    /// Report whether the stream framing has been marked lost.
    fn is_poisoned(&self) -> bool {
        self.poisoned.load(Ordering::Acquire)
    }
}

/// Marks a locked stream unusable unless its transaction completes cleanly.
///
/// The synchronous `Drop` implementation is essential: cancellation drops the
/// future at an arbitrary await point, where an asynchronous cleanup path
/// cannot be relied upon to run before another caller acquires the stream lock.
struct TcpTransactionGuard<'a> {
    poisoned: &'a AtomicBool,
    armed: bool,
}

impl<'a> TcpTransactionGuard<'a> {
    fn new(inner: &'a TcpTransportInner) -> Self {
        Self {
            poisoned: &inner.poisoned,
            armed: true,
        }
    }

    #[cfg(test)]
    fn for_test(poisoned: &'a AtomicBool) -> Self {
        Self {
            poisoned,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TcpTransactionGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.poisoned.store(true, Ordering::Release);
        }
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
    ///     .max_message_size(1_000_000)
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
        let receive_limits = ReceiveLimits::tcp(options.max_message_size)
            .map_err(|error| Error::Config(error.to_string().into()).boxed())?;
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
                target,
                local_addr,
                receive_limits,
                poisoned: AtomicBool::new(false),
            }),
        })
    }
}

impl Transport for TcpTransport {
    async fn send(&self, data: &[u8]) -> Result<()> {
        // Do not arm the transaction until the lock is acquired: cancellation
        // while queued has not touched stream state and must leave it reusable.
        let mut stream = self.inner.stream.clone().lock_owned().await;
        let target = self.inner.target;
        if self.inner.is_poisoned() {
            return Err(Error::Closed { target }.boxed());
        }

        let mut transaction = TcpTransactionGuard::new(&self.inner);
        write_message(&mut *stream, target, data).await?;
        transaction.disarm();
        Ok(())
    }

    async fn recv_with<T, F>(&self, registration: RequestRegistration, validate: F) -> Result<T>
    where
        T: Send,
        F: FnMut(Bytes, SocketAddr) -> Result<Candidate<T>> + Send,
    {
        let request_id = registration.request_id();
        let recv_timeout = registration.timeout();
        let target = self.inner.target;
        tcp_deadline(recv_timeout, "TCP timeout")?;
        let mut stream = self.inner.stream.clone().lock_owned().await;

        if self.inner.is_poisoned() {
            return Err(Error::Closed { target }.boxed());
        }
        let deadline = transaction_deadline(recv_timeout)?;
        let mut transaction = TcpTransactionGuard::new(&self.inner);
        let result = read_validated_message(
            &mut stream,
            target,
            self.inner.receive_limits.accepted(),
            &registration,
            deadline,
            validate,
        )
        .await;
        let value = finish_correlated_read(result, target, request_id, recv_timeout)?;
        transaction.disarm();
        Ok(value)
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
        let request_id = registration.request_id();
        let recv_timeout = registration.timeout();
        let target = self.inner.target;
        tcp_deadline(recv_timeout, "TCP timeout")?;
        let mut stream = self.inner.stream.clone().lock_owned().await;

        if self.inner.is_poisoned() {
            return Err(Error::Closed { target }.boxed());
        }
        let deadline = transaction_deadline(recv_timeout)?;
        let mut transaction = TcpTransactionGuard::new(&self.inner);

        tokio::time::timeout_at(deadline, write_message(&mut *stream, target, data))
            .await
            .map_err(|_| timeout_error(target, recv_timeout))??;

        let result = read_validated_message(
            &mut stream,
            target,
            self.inner.receive_limits.accepted(),
            &registration,
            deadline,
            validate,
        )
        .await;
        let value = finish_correlated_read(result, target, request_id, recv_timeout)?;
        transaction.disarm();
        Ok(value)
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

    fn receive_limits(&self) -> ReceiveLimits {
        self.inner.receive_limits
    }
}

enum CorrelatedReadError {
    Framing(Box<Error>),
    Validation(Box<Error>),
    Timeout,
}

fn tcp_deadline(timeout: Duration, description: &str) -> Result<tokio::time::Instant> {
    tokio::time::Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| {
            Error::Config(format!("{description} exceeds the representable deadline").into())
                .boxed()
        })
}

fn transaction_deadline(timeout: Duration) -> Result<tokio::time::Instant> {
    tcp_deadline(timeout, "TCP timeout")
}

fn timeout_error(target: SocketAddr, elapsed: Duration) -> Box<Error> {
    Error::Timeout {
        target,
        elapsed,
        retries: 0,
    }
    .boxed()
}

async fn write_message<W>(stream: &mut W, target: SocketAddr, data: &[u8]) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    stream
        .write_all(data)
        .await
        .map_err(|source| Error::Network { target, source }.boxed())?;
    stream
        .flush()
        .await
        .map_err(|source| Error::Network { target, source }.boxed())
}

async fn read_validated_message<T, F>(
    stream: &mut TcpStream,
    target: SocketAddr,
    max_message_size: usize,
    registration: &RequestRegistration,
    deadline: tokio::time::Instant,
    mut validate: F,
) -> std::result::Result<T, CorrelatedReadError>
where
    F: FnMut(Bytes, SocketAddr) -> Result<Candidate<T>>,
{
    let request_id = registration.request_id();
    loop {
        let frame =
            tokio::time::timeout_at(deadline, read_ber_message(stream, target, max_message_size))
                .await
                .map_err(|_| CorrelatedReadError::Timeout)?
                .map_err(CorrelatedReadError::Framing)?;

        let Some(frame_id) = extract_request_id(&frame) else {
            tracing::debug!(target: "async_snmp::transport::tcp", { request_id, %target }, "complete response frame has no extractable correlation ID");
            continue;
        };
        if frame_id != request_id && !registration.aliases().contains(&frame_id) {
            tracing::debug!(target: "async_snmp::transport::tcp", { request_id, frame_id, %target }, "stale response frame skipped");
            continue;
        }

        match registration.evaluate_response_identity(&frame, true) {
            ResponseIdentity::Match => {}
            ResponseIdentity::AcceptedCommunityMismatch => {
                tracing::warn!(target: "async_snmp::transport::tcp", { request_id, %target }, "accepted rewritten response community");
            }
            ResponseIdentity::Reject => {
                tracing::debug!(target: "async_snmp::transport::tcp", { request_id, %target }, "response rejected by registered identity correlation");
                continue;
            }
        }
        match validate(frame, target).map_err(CorrelatedReadError::Validation)? {
            Candidate::Accept(value) => return Ok(value),
            Candidate::Reject => {
                tracing::debug!(target: "async_snmp::transport::tcp", { request_id, %target }, "response rejected by client validation");
            }
        }
    }
}

fn finish_correlated_read<T>(
    result: std::result::Result<T, CorrelatedReadError>,
    target: SocketAddr,
    request_id: i32,
    recv_timeout: Duration,
) -> Result<T> {
    match result {
        Ok(value) => Ok(value),
        Err(CorrelatedReadError::Framing(error)) | Err(CorrelatedReadError::Validation(error)) => {
            Err(error)
        }
        Err(CorrelatedReadError::Timeout) => {
            tracing::debug!(target: "async_snmp::transport::tcp", { request_id, %target, elapsed = ?recv_timeout }, "transport timeout");
            Err(timeout_error(target, recv_timeout))
        }
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
    max_message_size: usize,
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

    // The configured quantity is total encoded message size, matching the V3
    // advertisement. Check it before allocating attacker-declared content.
    let total_len = 1usize
        .checked_add(len_bytes.len())
        .and_then(|header_len| header_len.checked_add(content_len))
        .ok_or_else(|| Error::MalformedResponse { target }.boxed())?;
    if total_len > max_message_size {
        tracing::warn!(target: "async_snmp::transport::tcp", { size = total_len, max = max_message_size, %target }, "message size exceeds limit");
        return Err(Error::MalformedResponse { target }.boxed());
    }

    // Read content
    let mut content = vec![0u8; content_len];
    stream
        .read_exact(&mut content)
        .await
        .map_err(|e| Error::Network { target, source: e }.boxed())?;

    // Reconstruct complete message: tag + length + content
    let mut message = BytesMut::with_capacity(total_len);
    message.extend_from_slice(&[tag]);
    message.extend_from_slice(&len_bytes);
    message.extend_from_slice(&content);

    Ok(message.freeze())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncWrite, AsyncWriteExt};
    use tokio::net::TcpListener;

    enum WriteFailure {
        Write,
        Flush,
    }

    struct FailingWriter(WriteFailure);

    impl AsyncWrite for FailingWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            match self.0 {
                WriteFailure::Write => Poll::Ready(Err(io::Error::other("write failed"))),
                WriteFailure::Flush => Poll::Ready(Ok(buf.len())),
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            match self.0 {
                WriteFailure::Write => Poll::Ready(Ok(())),
                WriteFailure::Flush => Poll::Ready(Err(io::Error::other("flush failed"))),
            }
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn guarded_write_and_flush_failures_poison() {
        let target = "127.0.0.1:161".parse().unwrap();
        for failure in [WriteFailure::Write, WriteFailure::Flush] {
            let poisoned = AtomicBool::new(false);
            let mut writer = FailingWriter(failure);
            {
                let _transaction = TcpTransactionGuard::for_test(&poisoned);
                let error = write_message(&mut writer, target, b"message")
                    .await
                    .unwrap_err();
                assert!(matches!(*error, Error::Network { .. }));
            }
            assert!(poisoned.load(Ordering::Acquire));
        }
    }

    #[tokio::test]
    async fn unrepresentable_direct_deadlines_fail_before_stream_io() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut byte = [0u8; 1];
            tokio::time::timeout(Duration::from_millis(50), socket.read_exact(&mut byte)).await
        });
        let transport = TcpTransport::connect(server_addr).await.unwrap();

        let request_error = transport
            .request(
                &build_request_with_id(1),
                RequestRegistration::v3(1, Duration::MAX),
            )
            .await
            .unwrap_err();
        assert!(matches!(*request_error, Error::Config(_)));
        let recv_error = transport
            .recv(RequestRegistration::v3(1, Duration::MAX))
            .await
            .unwrap_err();
        assert!(matches!(*recv_error, Error::Config(_)));
        assert!(!transport.inner.is_poisoned());
        assert!(
            server.await.unwrap().is_err(),
            "invalid deadline wrote bytes"
        );
    }

    #[tokio::test]
    async fn unrepresentable_connect_deadline_starts_no_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let error = TcpTransport::connect_timeout(server_addr, Duration::MAX)
            .await
            .err()
            .expect("unrepresentable connect deadline must fail");
        assert!(matches!(*error, Error::Config(_)));
        assert!(
            tokio::time::timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err(),
            "invalid connect deadline started stream I/O"
        );
    }

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
        let registration = RequestRegistration::test_unchecked(1, Duration::from_secs(5));
        let (response, source) = transport.recv(registration).await.unwrap();

        assert_eq!(source, server_addr);
        assert_eq!(response[0], 0x30); // SEQUENCE tag
        assert!(response.len() > 10);

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_tcp_long_length_form() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 31];
            socket.read_exact(&mut request).await.unwrap();

            // Encode the otherwise ordinary 29-byte response content using the
            // BER long form so correlation still sees a complete SNMP frame.
            let response = build_response_with_id(1);
            let mut long_form = vec![0x30, 0x81, response[1]];
            long_form.extend_from_slice(&response[2..]);
            socket.write_all(&long_form).await.unwrap();
        });

        let transport = TcpTransport::connect(server_addr).await.unwrap();
        let registration = RequestRegistration::test_unchecked(1, Duration::from_secs(5));
        let (response, _) = transport
            .request(&build_request_with_id(1), registration)
            .await
            .unwrap();

        assert_eq!(response.len(), 32);
        assert_eq!(&response[..3], &[0x30, 0x81, 0x1d]);
        server.await.unwrap();
    }

    /// Regression test: the advertised msgMaxSize must equal the transport's
    /// actual acceptance limit (`max_message_size`), not the protocol
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
            transport.receive_limits().advertised().as_usize(),
            transport.inner.receive_limits.accepted(),
            "advertised msgMaxSize must equal the accepted total-message limit"
        );
        assert_eq!(
            transport.receive_limits().advertised().as_usize(),
            DEFAULT_MAX_MESSAGE_SIZE
        );

        // Custom limit via the builder.
        let custom = 512 * 1024;
        let transport = TcpTransport::builder()
            .max_message_size(custom)
            .connect(server_addr)
            .await
            .unwrap();
        assert_eq!(transport.receive_limits().advertised().as_usize(), custom);
        assert_eq!(
            transport.receive_limits().advertised().as_usize(),
            transport.inner.receive_limits.accepted()
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
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

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

                let mut request = Vec::with_capacity(content_len + 2);
                request.extend_from_slice(&tag);
                request.extend_from_slice(&len_byte);
                request.extend_from_slice(&content);
                let request_id = extract_request_id(&request).unwrap();
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

                let registration =
                    RequestRegistration::test_unchecked(request_id, Duration::from_secs(5));
                let (response, _) = transport.request(&request, registration).await?;

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

    #[tokio::test]
    async fn tcp_skips_mismatched_community_frame_under_original_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 31];
            stream.read_exact(&mut request).await.unwrap();
            let mut wrong = build_response_with_id(77);
            wrong[7..13].copy_from_slice(b"other!");
            stream.write_all(&wrong).await.unwrap();
            stream.write_all(&build_response_with_id(77)).await.unwrap();
        });

        let transport = TcpTransport::connect(addr).await.unwrap();
        let registration = RequestRegistration::community(
            77,
            Duration::from_secs(2),
            crate::CommunityVersion::V2c,
            Bytes::from_static(b"public"),
            super::super::CommunityResponsePolicy::Exact,
        );
        let (response, _) = transport
            .request(&build_request_with_id(77), registration)
            .await
            .unwrap();
        assert_eq!(response.as_ref(), build_response_with_id(77));
        assert!(!transport.inner.is_poisoned());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn tcp_skips_stale_id_then_accepts_primary_id() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 31];
            stream.read_exact(&mut request).await.unwrap();
            stream.write_all(&build_response_with_id(90)).await.unwrap();
            stream.write_all(&build_response_with_id(91)).await.unwrap();
        });

        let transport = TcpTransport::connect(addr).await.unwrap();
        let (response, _) = transport
            .request(
                &build_request_with_id(91),
                RequestRegistration::test_unchecked(91, Duration::from_secs(2)),
            )
            .await
            .unwrap();
        assert_eq!(extract_request_id(&response), Some(91));
        assert!(!transport.inner.is_poisoned());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn tcp_accepts_each_registered_alias_id() {
        for accepted_alias in [101, 102] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0u8; 31];
                stream.read_exact(&mut request).await.unwrap();
                stream
                    .write_all(&build_response_with_id(accepted_alias))
                    .await
                    .unwrap();
            });

            let transport = TcpTransport::connect(addr).await.unwrap();
            let registration = RequestRegistration::test_unchecked(100, Duration::from_secs(2))
                .with_aliases([101, 102]);
            let (response, _) = transport
                .request(&build_request_with_id(100), registration)
                .await
                .unwrap();
            assert_eq!(extract_request_id(&response), Some(accepted_alias));
            assert!(!transport.inner.is_poisoned());
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn stale_frames_do_not_extend_deadline_and_timeout_poisons() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 31];
            stream.read_exact(&mut request).await.unwrap();
            for stale_id in 200..230 {
                if stream
                    .write_all(&build_response_with_id(stale_id))
                    .await
                    .is_err()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });

        let transport = TcpTransport::connect(addr).await.unwrap();
        let start = tokio::time::Instant::now();
        let error = transport
            .request(
                &build_request_with_id(300),
                RequestRegistration::v3(300, Duration::from_millis(100)),
            )
            .await
            .unwrap_err();
        let elapsed = start.elapsed();
        assert!(matches!(*error, Error::Timeout { .. }));
        assert!(elapsed < Duration::from_millis(250), "elapsed {elapsed:?}");
        assert!(transport.inner.is_poisoned());
        server.abort();
    }

    #[tokio::test]
    async fn tcp_validator_rejection_keeps_exchange_for_later_frame() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 31];
            stream.read_exact(&mut request).await.unwrap();
            stream.write_all(&build_response_with_id(78)).await.unwrap();
            stream.write_all(&build_response_with_id(78)).await.unwrap();
        });

        let transport = TcpTransport::connect(addr).await.unwrap();
        let registration = RequestRegistration::community(
            78,
            Duration::from_secs(2),
            crate::CommunityVersion::V2c,
            Bytes::from_static(b"public"),
            super::super::CommunityResponsePolicy::Exact,
        );
        let mut candidates = 0;
        let response = transport
            .request_with(&build_request_with_id(78), registration, |data, _| {
                candidates += 1;
                if candidates == 1 {
                    Ok(Candidate::Reject)
                } else {
                    Ok(Candidate::Accept(data))
                }
            })
            .await
            .unwrap();
        assert_eq!(response.as_ref(), build_response_with_id(78));
        assert_eq!(candidates, 2);
        assert!(!transport.inner.is_poisoned());
        server.await.unwrap();
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

        let registration = RequestRegistration::v3(1, Duration::from_secs(5));
        let result = transport.recv(registration).await;

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
            read_ber_message(&mut client, server_addr, DEFAULT_MAX_MESSAGE_SIZE),
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
            read_ber_message(&mut client, server_addr, DEFAULT_MAX_MESSAGE_SIZE),
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
            read_ber_message(&mut client, server_addr, DEFAULT_MAX_MESSAGE_SIZE),
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
            read_ber_message(&mut client, server_addr, DEFAULT_MAX_MESSAGE_SIZE),
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
            read_ber_message(&mut client, server_addr, DEFAULT_MAX_MESSAGE_SIZE),
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

    #[tokio::test]
    async fn invalid_tcp_message_sizes_are_rejected_before_connect() {
        let target = "127.0.0.1:9".parse().unwrap();
        for size in [0usize, 483, i32::MAX as usize + 1, usize::MAX] {
            let error = TcpTransport::builder()
                .max_message_size(size)
                .connect(target)
                .await
                .err()
                .expect("invalid size must fail before connect");
            assert!(
                matches!(*error, Error::Config(_)),
                "unexpected error: {error}"
            );
        }
    }

    #[tokio::test]
    async fn tcp_frame_limit_counts_total_encoded_size() {
        const CONTENT_LEN: usize = 481;
        // 0x82 + two length octets gives a four-byte tag/length header.
        const TOTAL_LEN: usize = 1 + 3 + CONTENT_LEN;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut frame = vec![0x30, 0x82, 0x01, 0xe1];
            frame.resize(TOTAL_LEN, 0);
            socket.write_all(&frame).await.unwrap();
        });
        let mut client = TcpStream::connect(server_addr).await.unwrap();
        let frame = read_ber_message(&mut client, server_addr, TOTAL_LEN)
            .await
            .expect("exact total-message limit should be accepted");
        assert_eq!(frame.len(), TOTAL_LEN);
        server.await.unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            // Only the header is needed: rejection must precede content allocation/read.
            socket.write_all(&[0x30, 0x82, 0x01, 0xe1]).await.unwrap();
        });
        let mut client = TcpStream::connect(server_addr).await.unwrap();
        let error = read_ber_message(&mut client, server_addr, TOTAL_LEN - 1)
            .await
            .expect_err("one byte over total-message limit must be rejected");
        assert!(matches!(*error, Error::MalformedResponse { .. }));
        server.await.unwrap();
    }

    /// Test that a custom `max_message_size` via builder is respected.
    #[tokio::test]
    async fn test_tcp_builder_custom_message_limit() {
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
            .max_message_size(1024) // 1KB limit
            .connect(server_addr)
            .await
            .unwrap();

        let request = build_request_with_id(1);
        transport.send(&request).await.unwrap();

        let registration = RequestRegistration::v3(1, Duration::from_secs(5));
        let result = transport.recv(registration).await;

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

    #[tokio::test]
    async fn cancellation_before_stream_lock_does_not_poison() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(1)).await;
        });
        let transport = TcpTransport::connect(server_addr).await.unwrap();
        let held_lock = transport.inner.stream.clone().lock_owned().await;

        let request = build_request_with_id(1);
        let registration = RequestRegistration::v3(1, Duration::from_secs(5));
        let cancelled = timeout(
            Duration::from_millis(30),
            transport.request(&request, registration),
        )
        .await;
        assert!(cancelled.is_err());
        assert!(!transport.inner.is_poisoned());

        drop(held_lock);
        server.abort();
    }

    #[tokio::test]
    async fn cancellation_after_complete_request_write_poisons() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let (written_tx, written_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 31];
            socket.read_exact(&mut request).await.unwrap();
            written_tx.send(()).unwrap();
            tokio::time::sleep(Duration::from_secs(1)).await;
        });
        let transport = TcpTransport::connect(server_addr).await.unwrap();
        let request_transport = transport.clone();
        let request = tokio::spawn(async move {
            request_transport
                .request(
                    &build_request_with_id(1),
                    RequestRegistration::v3(1, Duration::from_secs(30)),
                )
                .await
        });

        written_rx.await.unwrap();
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());
        assert!(transport.inner.is_poisoned());

        let error = transport
            .request(
                &build_request_with_id(2),
                RequestRegistration::v3(2, Duration::from_secs(1)),
            )
            .await
            .unwrap_err();
        assert!(matches!(*error, Error::Closed { .. }));
        server.abort();
    }

    #[tokio::test]
    async fn cancellation_during_partial_frame_read_poisons() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let (partial_tx, partial_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 31];
            socket.read_exact(&mut request).await.unwrap();
            socket.write_all(&[0x30, 0x08, 0x02]).await.unwrap();
            partial_tx.send(()).unwrap();
            tokio::time::sleep(Duration::from_secs(1)).await;
        });
        let transport = TcpTransport::connect(server_addr).await.unwrap();
        let request_transport = transport.clone();
        let request = tokio::spawn(async move {
            request_transport
                .request(
                    &build_request_with_id(1),
                    RequestRegistration::v3(1, Duration::from_secs(30)),
                )
                .await
        });

        partial_rx.await.unwrap();
        tokio::task::yield_now().await;
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());
        assert!(transport.inner.is_poisoned());
        server.abort();
    }

    #[tokio::test]
    async fn cancellation_during_partial_send_poisons() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.unwrap();
            accepted_tx.send(()).unwrap();
            tokio::time::sleep(Duration::from_secs(2)).await;
        });
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.set_send_buffer_size(1024).unwrap();
        let transport = TcpTransport::from_socket(socket, server_addr, TcpOptions::default())
            .await
            .unwrap();
        accepted_rx.await.unwrap();

        let send_transport = transport.clone();
        let send = tokio::spawn(async move {
            let data = vec![0xaa; 16 * 1024 * 1024];
            send_transport.send(&data).await
        });
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(!send.is_finished(), "test write must still be partial");
        send.abort();
        assert!(send.await.unwrap_err().is_cancelled());
        assert!(transport.inner.is_poisoned());
        server.abort();
    }

    #[tokio::test]
    async fn request_deadline_covers_partial_write() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(2)).await;
        });
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.set_send_buffer_size(1024).unwrap();
        let transport = TcpTransport::from_socket(socket, server_addr, TcpOptions::default())
            .await
            .unwrap();
        let data = vec![0xaa; 16 * 1024 * 1024];

        let start = tokio::time::Instant::now();
        let error = transport
            .request(&data, RequestRegistration::v3(1, Duration::from_millis(50)))
            .await
            .unwrap_err();
        assert!(matches!(*error, Error::Timeout { .. }));
        assert!(start.elapsed() < Duration::from_millis(500));
        assert!(transport.inner.is_poisoned());
        server.abort();
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
        let registration = RequestRegistration::v3(1, Duration::from_secs(5));
        let first = transport.request(&request, registration).await;
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
        let registration = RequestRegistration::v3(2, Duration::from_secs(5));
        let second = timeout(
            Duration::from_secs(5),
            transport.request(&request2, registration),
        )
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
    /// Registration metadata is owned by the receive future, so its timeout is
    /// used directly without shared mutable registration state.
    #[tokio::test]
    async fn test_tcp_receive_uses_owned_registration_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        // Server accepts the connection but never responds.
        let server = tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
        });

        let transport = TcpTransport::connect(server_addr).await.unwrap();
        let registration = RequestRegistration::v3(1, Duration::from_millis(150));

        let start = std::time::Instant::now();
        let result = timeout(Duration::from_secs(5), transport.recv(registration))
            .await
            .expect("recv should honor the owned short timeout");
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

        let registration = RequestRegistration::v3(1, Duration::from_millis(100));
        let first = transport.recv(registration).await;
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
        let registration = RequestRegistration::v3(1, Duration::from_secs(5));
        let second = timeout(Duration::from_secs(5), transport.recv(registration))
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
