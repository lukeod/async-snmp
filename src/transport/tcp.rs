//! TCP transport implementation.
//!
//! TCP transport uses BER self-describing length for message framing.
//! Each SNMP message is a BER-encoded SEQUENCE, so the receiver reads:
//! 1. Tag byte (0x30 for SEQUENCE)
//! 2. Length field (1-5 bytes, definite form only)
//! 3. Content bytes (length determined by step 2)

use super::Transport;
use crate::error::{DecodeErrorKind, Error, Result};
use bytes::{Bytes, BytesMut};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;

/// Maximum SNMP message size for TCP (per net-snmp SNMP_MAX_PACKET_LEN).
const MAX_TCP_MESSAGE_SIZE: usize = 0x7fffffff;

/// TCP transport for a single target.
///
/// Each `TcpTransport` owns a TCP connection to a specific target.
/// Unlike UDP, TCP is stream-oriented so messages are framed using
/// BER's self-describing length.
///
/// Since TCP guarantees delivery or failure, the client does not retry
/// on timeout when using TCP transport (`is_stream() = true`).
#[derive(Clone)]
pub struct TcpTransport {
    inner: Arc<TcpTransportInner>,
}

struct TcpTransportInner {
    /// The TCP stream, protected by mutex for concurrent access
    stream: Mutex<TcpStream>,
    target: SocketAddr,
    local_addr: SocketAddr,
}

impl TcpTransport {
    /// Connect to a target address.
    pub async fn connect(target: SocketAddr) -> Result<Self> {
        let stream = TcpStream::connect(target).await.map_err(|e| Error::Io {
            target: Some(target),
            source: e,
        })?;

        let local_addr = stream.local_addr().map_err(|e| Error::Io {
            target: Some(target),
            source: e,
        })?;

        Ok(Self {
            inner: Arc::new(TcpTransportInner {
                stream: Mutex::new(stream),
                target,
                local_addr,
            }),
        })
    }

    /// Connect with a timeout.
    pub async fn connect_timeout(target: SocketAddr, connect_timeout: Duration) -> Result<Self> {
        let stream = timeout(connect_timeout, TcpStream::connect(target))
            .await
            .map_err(|_| Error::Timeout {
                target: Some(target),
                elapsed: connect_timeout,
                request_id: 0,
                retries: 0,
            })?
            .map_err(|e| Error::Io {
                target: Some(target),
                source: e,
            })?;

        let local_addr = stream.local_addr().map_err(|e| Error::Io {
            target: Some(target),
            source: e,
        })?;

        Ok(Self {
            inner: Arc::new(TcpTransportInner {
                stream: Mutex::new(stream),
                target,
                local_addr,
            }),
        })
    }
}

impl Transport for TcpTransport {
    async fn send(&self, data: &[u8]) -> Result<()> {
        let mut stream = self.inner.stream.lock().await;
        stream.write_all(data).await.map_err(|e| Error::Io {
            target: Some(self.inner.target),
            source: e,
        })?;
        stream.flush().await.map_err(|e| Error::Io {
            target: Some(self.inner.target),
            source: e,
        })?;
        Ok(())
    }

    async fn recv(&self, request_id: i32, recv_timeout: Duration) -> Result<(Bytes, SocketAddr)> {
        let mut stream = self.inner.stream.lock().await;

        // Read a complete BER-encoded message using the framing protocol
        let result = timeout(recv_timeout, read_ber_message(&mut stream)).await;

        match result {
            Ok(Ok(data)) => Ok((data, self.inner.target)),
            Ok(Err(e)) => Err(e),
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
        true
    }
}

/// Read a complete BER-encoded SNMP message from a TCP stream.
///
/// SNMP messages are SEQUENCE types (tag 0x30). We read:
/// 1. Tag byte (must be 0x30)
/// 2. Length field (definite form only)
/// 3. Content bytes
async fn read_ber_message(stream: &mut TcpStream) -> Result<Bytes> {
    let target: SocketAddr = stream
        .peer_addr()
        .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());

    // Read tag byte
    let mut tag_buf = [0u8; 1];
    stream
        .read_exact(&mut tag_buf)
        .await
        .map_err(|e| Error::Io {
            target: Some(target),
            source: e,
        })?;

    let tag = tag_buf[0];
    if tag != 0x30 {
        return Err(Error::decode(
            0,
            DecodeErrorKind::UnexpectedTag {
                expected: 0x30,
                actual: tag,
            },
        ));
    }

    // Read length
    let mut first_len_byte = [0u8; 1];
    stream
        .read_exact(&mut first_len_byte)
        .await
        .map_err(|e| Error::Io {
            target: Some(target),
            source: e,
        })?;

    let (content_len, len_bytes) = if first_len_byte[0] < 0x80 {
        // Short form: length is directly in this byte
        (first_len_byte[0] as usize, vec![first_len_byte[0]])
    } else if first_len_byte[0] == 0x80 {
        // Indefinite length - not supported
        return Err(Error::decode(1, DecodeErrorKind::IndefiniteLength));
    } else {
        // Long form: first byte indicates number of following length bytes
        let num_len_bytes = (first_len_byte[0] & 0x7F) as usize;
        if num_len_bytes > 4 {
            return Err(Error::decode(
                1,
                DecodeErrorKind::LengthTooLong {
                    octets: num_len_bytes,
                },
            ));
        }

        let mut len_bytes_buf = vec![0u8; num_len_bytes];
        stream
            .read_exact(&mut len_bytes_buf)
            .await
            .map_err(|e| Error::Io {
                target: Some(target),
                source: e,
            })?;

        let mut length: usize = 0;
        for &b in &len_bytes_buf {
            length = (length << 8) | (b as usize);
        }

        // Build the complete length encoding for reconstruction
        let mut all_len_bytes = vec![first_len_byte[0]];
        all_len_bytes.extend_from_slice(&len_bytes_buf);

        (length, all_len_bytes)
    };

    // Sanity check on content length
    if content_len > MAX_TCP_MESSAGE_SIZE {
        return Err(Error::MessageTooLarge {
            size: content_len,
            max: MAX_TCP_MESSAGE_SIZE,
        });
    }

    // Read content
    let mut content = vec![0u8; content_len];
    stream
        .read_exact(&mut content)
        .await
        .map_err(|e| Error::Io {
            target: Some(target),
            source: e,
        })?;

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
        let (response, source) = transport.recv(1, Duration::from_secs(5)).await.unwrap();

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

        let (response, _) = transport.recv(1, Duration::from_secs(5)).await.unwrap();

        // Verify: tag (1) + length field (2) + content (200) = 203 bytes
        assert_eq!(response.len(), 203);
        assert_eq!(response[0], 0x30);
        assert_eq!(response[1], 0x81);
        assert_eq!(response[2], 0xc8); // 200 in hex

        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_tcp_is_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        // Accept connection in background
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let transport = TcpTransport::connect(server_addr).await.unwrap();
        assert!(transport.is_stream());
    }
}
