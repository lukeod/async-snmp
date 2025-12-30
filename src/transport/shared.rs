//! Shared UDP transport for high-throughput polling.
//!
//! For monitoring systems polling thousands of targets, a shared transport
//! uses a single socket with request-ID correlation instead of one socket
//! per target.

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
/// # Example
///
/// ```rust,no_run
/// use async_snmp::transport::{SharedUdpTransport, SharedUdpHandle};
/// use async_snmp::{Client, ClientConfig};
/// use std::net::SocketAddr;
///
/// # async fn example() -> async_snmp::Result<()> {
/// let shared = SharedUdpTransport::builder().bind("0.0.0.0:0").build().await?;
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
    /// Create a builder for configuring the shared transport.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use async_snmp::transport::SharedUdpTransport;
    /// # async fn example() -> async_snmp::Result<()> {
    /// let shared = SharedUdpTransport::builder()
    ///     .bind("0.0.0.0:0")
    ///     .warn_on_source_mismatch(false)
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
    /// The handle implements [`Transport`] and can be used with [`Client`](crate::Client).
    pub fn handle(&self, target: SocketAddr) -> SharedUdpHandle {
        SharedUdpHandle {
            inner: self.inner.clone(),
            target,
        }
    }

    /// Get the local bind address.
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
                        let data = Bytes::copy_from_slice(&buf[..len]);

                        // Extract request_id from response
                        // SNMP response has request_id at a known offset after the header
                        if let Some(request_id) = extract_request_id(&data) {
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

    /// Configure warning on source address mismatch.
    pub fn warn_on_source_mismatch(mut self, warn: bool) -> Self {
        self.config.warn_on_source_mismatch = warn;
        self
    }

    /// Set maximum message size.
    pub fn max_message_size(mut self, size: usize) -> Self {
        self.config.max_message_size = size;
        self
    }

    /// Build the shared transport.
    ///
    /// For IPv6 bind addresses, the socket has `IPV6_V6ONLY` set to true.
    pub async fn build(self) -> Result<SharedUdpTransport> {
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
/// Implements [`Transport`] and can be used with [`Client`](crate::Client).
/// Multiple handles can be created for the same or different targets,
/// all sharing the same underlying socket.
#[derive(Clone)]
pub struct SharedUdpHandle {
    inner: Arc<SharedUdpTransportInner>,
    target: SocketAddr,
}

impl Transport for SharedUdpHandle {
    async fn send(&self, data: &[u8]) -> Result<()> {
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
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => {
                // Channel closed (shouldn't happen normally)
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

/// Extract request_id from an SNMP response.
///
/// SNMP message structure:
/// - SEQUENCE { version, community, PDU }
/// - PDU is SEQUENCE { request_id, error_status, error_index, varbinds }
///
/// We need to navigate through BER encoding to find the request_id.
fn extract_request_id(data: &[u8]) -> Option<i32> {
    let mut pos = 0;

    // Outer SEQUENCE
    if pos >= data.len() || data[pos] != 0x30 {
        return None;
    }
    pos += 1;

    // Skip length
    pos = skip_length(data, pos)?;

    // Version (INTEGER)
    if pos >= data.len() || data[pos] != 0x02 {
        return None;
    }
    pos += 1;
    let version_len = read_length(data, pos)?;
    pos = version_len.0;
    pos += version_len.1;

    // Community (OCTET STRING)
    if pos >= data.len() || data[pos] != 0x04 {
        return None;
    }
    pos += 1;
    let community_len = read_length(data, pos)?;
    pos = community_len.0;
    pos += community_len.1;

    // PDU (context-specific, e.g., 0xA2 for Response)
    if pos >= data.len() {
        return None;
    }
    let pdu_tag = data[pos];
    // PDU tags are 0xA0-0xA8
    if !(0xA0..=0xA8).contains(&pdu_tag) {
        return None;
    }
    pos += 1;

    // Skip PDU length
    pos = skip_length(data, pos)?;

    // Request ID (INTEGER)
    if pos >= data.len() || data[pos] != 0x02 {
        return None;
    }
    pos += 1;

    // Read request_id length
    let (new_pos, id_len) = read_length(data, pos)?;
    pos = new_pos;

    if pos + id_len > data.len() {
        return None;
    }

    // Decode request_id (signed integer, big-endian)
    let id_bytes = &data[pos..pos + id_len];
    let mut value: i32 = if !id_bytes.is_empty() && id_bytes[0] & 0x80 != 0 {
        -1 // Sign extend for negative numbers
    } else {
        0
    };

    for &byte in id_bytes {
        value = (value << 8) | (byte as i32);
    }

    Some(value)
}

/// Skip BER length field and return new position.
fn skip_length(data: &[u8], pos: usize) -> Option<usize> {
    let (new_pos, _) = read_length(data, pos)?;
    Some(new_pos)
}

/// Read BER length field.
/// Returns (new_position, length_value).
fn read_length(data: &[u8], pos: usize) -> Option<(usize, usize)> {
    if pos >= data.len() {
        return None;
    }

    let first = data[pos];

    if first < 0x80 {
        // Short form
        Some((pos + 1, first as usize))
    } else if first == 0x80 {
        // Indefinite length - not supported
        None
    } else {
        // Long form
        let num_octets = (first & 0x7F) as usize;
        if pos + 1 + num_octets > data.len() {
            return None;
        }

        let mut length: usize = 0;
        for i in 0..num_octets {
            length = (length << 8) | (data[pos + 1 + i] as usize);
        }

        Some((pos + 1 + num_octets, length))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_request_id() {
        // A minimal SNMP v2c GET response with request_id = 12345
        // 30 xx - SEQUENCE
        //   02 01 01 - INTEGER (version = 1 for v2c)
        //   04 06 70 75 62 6c 69 63 - OCTET STRING "public"
        //   a2 xx - Response PDU
        //     02 02 30 39 - INTEGER (request_id = 12345)
        //     ... rest of PDU
        let response = [
            0x30, 0x1c, // SEQUENCE
            0x02, 0x01, 0x01, // INTEGER 1 (v2c)
            0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, // "public"
            0xa2, 0x0f, // Response PDU
            0x02, 0x02, 0x30, 0x39, // INTEGER 12345
            0x02, 0x01, 0x00, // error-status
            0x02, 0x01, 0x00, // error-index
            0x30, 0x03, 0x30, 0x01, 0x00, // varbinds (empty-ish)
        ];

        let request_id = extract_request_id(&response);
        assert_eq!(request_id, Some(12345));
    }

    #[test]
    fn test_extract_request_id_negative() {
        // Request ID = -1 (0xFF FF FF FF in two's complement, or just 0xFF for BER)
        let response = [
            0x30, 0x19, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa2,
            0x0c, 0x02, 0x01, 0xff, // INTEGER -1
            0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00,
        ];

        let request_id = extract_request_id(&response);
        assert_eq!(request_id, Some(-1));
    }

    #[test]
    fn test_extract_request_id_malformed() {
        // Empty data
        assert_eq!(extract_request_id(&[]), None);

        // Not a sequence
        assert_eq!(extract_request_id(&[0x02, 0x01, 0x00]), None);

        // Truncated
        assert_eq!(extract_request_id(&[0x30, 0x10]), None);
    }

    #[test]
    fn test_read_length_short_form() {
        let data = [0x05, 0x00, 0x00];
        let (pos, len) = read_length(&data, 0).unwrap();
        assert_eq!(pos, 1);
        assert_eq!(len, 5);
    }

    #[test]
    fn test_read_length_long_form() {
        // Length = 256 (0x82 0x01 0x00)
        let data = [0x82, 0x01, 0x00];
        let (pos, len) = read_length(&data, 0).unwrap();
        assert_eq!(pos, 3);
        assert_eq!(len, 256);
    }

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
