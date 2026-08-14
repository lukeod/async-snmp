use super::{Candidate, RequestRegistration, TcpTransport, Transport, UdpHandle};
use crate::error::Result;
use crate::message_size::ReceiveLimits;
use bytes::Bytes;
use std::net::SocketAddr;
use std::time::Duration;

/// A runtime-selected library-maintained transport.
///
/// This enum lets an application choose between the built-in UDP and TCP
/// transports at runtime while retaining the generic [`Client`](crate::Client)
/// API. Configure and construct the concrete transport first, convert it with
/// [`From`], and pass it to
/// [`ClientBuilder::build_with_transport`](crate::ClientBuilder::build_with_transport).
/// Custom transports should continue to use `Client<T>` directly.
///
/// ```rust,no_run
/// use async_snmp::{Auth, BuiltinTransport, ClientBuilder, RuntimeClient, TcpTransport};
///
/// # async fn example() -> async_snmp::Result<()> {
/// let target = "192.0.2.1:161".parse().unwrap();
/// let transport = TcpTransport::builder()
///     .max_message_size(256 * 1024)
///     .connect(target)
///     .await?;
/// let client: RuntimeClient = ClientBuilder::new(Auth::v2c("public"))
///     .build_with_transport(BuiltinTransport::from(transport))?;
/// # let _ = client;
/// # Ok(())
/// # }
/// ```
#[non_exhaustive]
pub enum BuiltinTransport {
    /// A target handle on a shared or dedicated UDP endpoint.
    Udp(UdpHandle),
    /// A TCP connection to one target.
    Tcp(TcpTransport),
}

impl From<UdpHandle> for BuiltinTransport {
    fn from(transport: UdpHandle) -> Self {
        Self::Udp(transport)
    }
}

impl From<TcpTransport> for BuiltinTransport {
    fn from(transport: TcpTransport) -> Self {
        Self::Tcp(transport)
    }
}

impl Transport for BuiltinTransport {
    async fn send(&self, data: &[u8]) -> Result<()> {
        match self {
            Self::Udp(transport) => transport.send(data).await,
            Self::Tcp(transport) => transport.send(data).await,
        }
    }

    async fn send_with_timeout(&self, data: &[u8], timeout: Duration) -> Result<()> {
        match self {
            Self::Udp(transport) => transport.send_with_timeout(data, timeout).await,
            Self::Tcp(transport) => transport.send_with_timeout(data, timeout).await,
        }
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
        match self {
            Self::Udp(transport) => transport.request_with(data, registration, validate).await,
            Self::Tcp(transport) => transport.request_with(data, registration, validate).await,
        }
    }

    fn peer_addr(&self) -> SocketAddr {
        match self {
            Self::Udp(transport) => transport.peer_addr(),
            Self::Tcp(transport) => transport.peer_addr(),
        }
    }

    fn local_addr(&self) -> SocketAddr {
        match self {
            Self::Udp(transport) => transport.local_addr(),
            Self::Tcp(transport) => transport.local_addr(),
        }
    }

    fn alloc_request_id(&self) -> i32 {
        match self {
            Self::Udp(transport) => transport.alloc_request_id(),
            Self::Tcp(transport) => transport.alloc_request_id(),
        }
    }

    fn is_reliable(&self) -> bool {
        match self {
            Self::Udp(transport) => transport.is_reliable(),
            Self::Tcp(transport) => transport.is_reliable(),
        }
    }

    fn receive_limits(&self) -> ReceiveLimits {
        match self {
            Self::Udp(transport) => transport.receive_limits(),
            Self::Tcp(transport) => transport.receive_limits(),
        }
    }

    fn send_capacity(&self) -> usize {
        match self {
            Self::Udp(transport) => transport.send_capacity(),
            Self::Tcp(transport) => transport.send_capacity(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{TcpOptions, UdpTransport};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UdpSocket};
    use tokio::time::timeout;

    const TEST_TIMEOUT: Duration = Duration::from_secs(2);

    #[tokio::test]
    async fn udp_delegates_every_transport_method() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let endpoint = UdpTransport::builder()
            .bind("127.0.0.1:0")
            .max_message_size(4096)
            .build()
            .await
            .unwrap();
        let handle = endpoint.handle(server_addr).unwrap();
        let expected_local = handle.local_addr();
        let transport = BuiltinTransport::from(handle);

        assert_eq!(transport.peer_addr(), server_addr);
        assert_eq!(transport.local_addr(), expected_local);
        assert!(!transport.is_reliable());
        assert_eq!(transport.receive_limits().advertised().as_usize(), 4096);
        assert!(transport.alloc_request_id() > 0);

        let sent = request(1);
        transport.send(&sent).await.unwrap();
        let mut buffer = [0; 64];
        let (length, source) = server.recv_from(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..length], sent);
        assert_eq!(source, expected_local);

        let server_exchange = async {
            let (length, source) = server.recv_from(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..length], request(4));
            server.send_to(&response(4), source).await.unwrap();
        };
        let request_data = request(4);
        let client_exchange =
            transport.request_with(&request_data, registration(4), |data, source| {
                Ok(Candidate::Accept((data, source)))
            });
        let ((), result) = tokio::join!(server_exchange, client_exchange);
        assert_eq!(result.unwrap().0.as_ref(), response(4));

        let server_exchange = async {
            let (length, source) = server.recv_from(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..length], request(5));
            server.send_to(&response(5), source).await.unwrap();
            server
                .send_to(&alternate_response(5), source)
                .await
                .unwrap();
        };
        let request_data = request(5);
        let client_exchange =
            transport.request_with(&request_data, registration(5), reject_first());
        let ((), result) = tokio::join!(server_exchange, client_exchange);
        assert_eq!(result.unwrap().as_ref(), alternate_response(5));
    }

    #[tokio::test]
    async fn tcp_delegates_every_transport_method() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let tcp = TcpTransport::builder()
            .max_message_size(8192)
            .connect(server_addr)
            .await
            .unwrap();
        let expected_local = tcp.local_addr();
        let transport = BuiltinTransport::from(tcp);
        let (mut server, _) = listener.accept().await.unwrap();

        assert_eq!(transport.peer_addr(), server_addr);
        assert_eq!(transport.local_addr(), expected_local);
        assert!(transport.is_reliable());
        assert_eq!(transport.receive_limits().advertised().as_usize(), 8192);
        assert!(transport.alloc_request_id() > 0);

        transport.send(&request(1)).await.unwrap();
        assert_eq!(read_frame(&mut server).await, request(1));

        let server_exchange = async {
            assert_eq!(read_frame(&mut server).await, request(4));
            server.write_all(&response(4)).await.unwrap();
        };
        let request_data = request(4);
        let client_exchange =
            transport.request_with(&request_data, registration(4), |data, source| {
                Ok(Candidate::Accept((data, source)))
            });
        let ((), result) = tokio::join!(server_exchange, client_exchange);
        assert_eq!(result.unwrap().0.as_ref(), response(4));

        let server_exchange = async {
            assert_eq!(read_frame(&mut server).await, request(5));
            server.write_all(&response(5)).await.unwrap();
            server.write_all(&alternate_response(5)).await.unwrap();
        };
        let request_data = request(5);
        let client_exchange =
            transport.request_with(&request_data, registration(5), reject_first());
        let ((), result) = tokio::join!(server_exchange, client_exchange);
        assert_eq!(result.unwrap().as_ref(), alternate_response(5));
    }

    #[tokio::test]
    async fn tcp_request_with_keeps_concurrent_exchanges_serialized_across_rejection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.set_send_buffer_size(1024).unwrap();
        let tcp = TcpTransport::from_socket(socket, server_addr, TcpOptions::default())
            .await
            .unwrap();
        let first = BuiltinTransport::from(tcp.clone());
        let second = BuiltinTransport::from(tcp);
        let (mut server, _) = listener.accept().await.unwrap();

        let first_task = tokio::spawn(async move {
            let request = large_frame(11);
            first
                .request_with(&request, registration(11), reject_first_matching(11))
                .await
        });
        tokio::task::yield_now().await;
        let second_task = tokio::spawn(async move {
            let request = large_frame(12);
            second
                .request_with(&request, registration(12), reject_first_matching(12))
                .await
        });

        for _ in 0..2 {
            let request = read_frame(&mut server).await;
            let marker = *request.last().unwrap();

            // The TCP implementation owns the connection lock from write
            // through every rejected candidate. Delegating to the trait's
            // send-then-recv default would allow the queued request to begin.
            let mut next = [0_u8; 1];
            assert!(
                timeout(Duration::from_millis(50), server.read_exact(&mut next))
                    .await
                    .is_err(),
                "a concurrent request was written before the active exchange completed"
            );

            server
                .write_all(&response(i32::from(marker)))
                .await
                .unwrap();
            server
                .write_all(&alternate_response(i32::from(marker)))
                .await
                .unwrap();
        }

        assert_eq!(first_task.await.unwrap().unwrap(), 11);
        assert_eq!(second_task.await.unwrap().unwrap(), 12);
    }

    fn registration(request_id: i32) -> RequestRegistration {
        RequestRegistration::test_unchecked(request_id, TEST_TIMEOUT)
    }

    fn reject_first() -> impl FnMut(Bytes, SocketAddr) -> Result<Candidate<Bytes>> + Send {
        let mut candidates = 0;
        move |data, _| {
            candidates += 1;
            if candidates == 1 {
                Ok(Candidate::Reject)
            } else {
                Ok(Candidate::Accept(data))
            }
        }
    }

    fn reject_first_matching(
        expected: u8,
    ) -> impl FnMut(Bytes, SocketAddr) -> Result<Candidate<u8>> + Send {
        let mut candidates = 0;
        move |_data, _| {
            candidates += 1;
            if candidates == 1 {
                Ok(Candidate::Reject)
            } else {
                Ok(Candidate::Accept(expected))
            }
        }
    }

    async fn read_frame(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
        let mut header = [0_u8; 2];
        stream.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0], 0x30);

        let (mut frame, length) = if header[1] & 0x80 == 0 {
            (header.to_vec(), usize::from(header[1]))
        } else {
            let length_octets = usize::from(header[1] & 0x7f);
            let mut encoded_length = vec![0; length_octets];
            stream.read_exact(&mut encoded_length).await.unwrap();
            let length = encoded_length
                .iter()
                .fold(0_usize, |length, octet| (length << 8) | usize::from(*octet));
            let mut frame = header.to_vec();
            frame.extend_from_slice(&encoded_length);
            (frame, length)
        };
        let header_length = frame.len();
        frame.resize(header_length + length, 0);
        stream
            .read_exact(&mut frame[header_length..])
            .await
            .unwrap();
        frame
    }

    fn large_frame(marker: u8) -> Vec<u8> {
        const CONTENT_LENGTH: usize = 512 * 1024;
        let mut frame = vec![0x30, 0x83, 0x08, 0x00, 0x00];
        frame.resize(frame.len() + CONTENT_LENGTH, 0);
        *frame.last_mut().unwrap() = marker;
        frame
    }

    fn request(request_id: i32) -> Vec<u8> {
        message(0xa0, request_id)
    }

    fn response(request_id: i32) -> Vec<u8> {
        message(0xa2, request_id)
    }

    fn alternate_response(request_id: i32) -> Vec<u8> {
        let mut response = response(request_id);
        let value_tag = response.len() - 2;
        response[value_tag] = 0x05;
        response
    }

    fn message(pdu_tag: u8, request_id: i32) -> Vec<u8> {
        let id = request_id.to_be_bytes();
        vec![
            0x30, 0x1d, 0x02, 0x01, 0x01, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', pdu_tag,
            0x10, 0x02, 0x04, id[0], id[1], id[2], id[3], 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30,
            0x02, 0x30, 0x00,
        ]
    }
}
