//! Complete-message transport metadata and internal response capabilities.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::time::Instant;

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Process-local endpoint identity, independent of its bound address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EndpointId(u64);

impl EndpointId {
    /// Allocate an identity for a newly created endpoint.
    pub fn new() -> Self {
        Self(NEXT_ID.fetch_add(1, Ordering::Relaxed))
    }
}
impl Default for EndpointId {
    fn default() -> Self {
        Self::new()
    }
}

/// Process-local connection identity; reconnects have distinct identities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(u64);
impl SessionId {
    /// Allocate an identity for a newly connected or accepted session.
    pub fn new() -> Self {
        Self(NEXT_ID.fetch_add(1, Ordering::Relaxed))
    }
}
impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

/// Process-local identity of one complete received SNMP input.
///
/// Each [`ReceivedMessageInfo`] constructor allocates a new identity. Copies
/// retain it, including a discovery result reused by several logical operations.
/// A retransmission received separately has a different identity, even when its
/// bytes match. This value is not an on-wire transaction or authenticated identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReceptionId(u64);

/// Transport mapping that delivered a complete SNMP input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TransportKind {
    /// One UDP datagram.
    Udp,
    /// One BER-framed message on a TCP connection.
    Tcp,
}

/// Metadata captured when one complete SNMP input is received.
///
/// Length includes the original encoded SNMP message (including USM ciphertext,
/// padding and accepted UDP suffixes). It excludes network and transport headers.
/// The timestamp is userspace receive completion, not kernel or network ingress.
/// Addresses and this metadata do not establish an authenticated identity.
/// Constructors preserve UDP/TCP session invariants; address, timestamp and length
/// values are asserted by the transport implementation, not independently verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceivedMessageInfo {
    reception_id: ReceptionId,
    endpoint_id: EndpointId,
    transport: TransportKind,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    datagram_destination: Option<IpAddr>,
    session_id: Option<SessionId>,
    received_at: Instant,
    received_len: usize,
}

impl ReceivedMessageInfo {
    /// Construct UDP metadata with a new reception identity. Call once per input.
    /// Supply a destination only when receive metadata
    /// identifies it; a wildcard bind address does not identify a destination.
    pub fn udp(
        endpoint_id: EndpointId,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        datagram_destination: Option<IpAddr>,
        received_at: Instant,
        received_len: usize,
    ) -> Self {
        Self {
            reception_id: ReceptionId(NEXT_ID.fetch_add(1, Ordering::Relaxed)),
            endpoint_id,
            transport: TransportKind::Udp,
            local_addr,
            peer_addr,
            datagram_destination,
            session_id: None,
            received_at,
            received_len,
        }
    }

    /// Construct metadata with a new reception identity for one complete TCP BER
    /// frame on a known session. Call once per frame, then preserve this value.
    pub fn tcp(
        endpoint_id: EndpointId,
        session_id: SessionId,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        received_at: Instant,
        received_len: usize,
    ) -> Self {
        Self {
            reception_id: ReceptionId(NEXT_ID.fetch_add(1, Ordering::Relaxed)),
            endpoint_id,
            transport: TransportKind::Tcp,
            local_addr,
            peer_addr,
            datagram_destination: None,
            session_id: Some(session_id),
            received_at,
            received_len,
        }
    }
    /// Identity allocated once at complete-input receipt, preserved by copying.
    pub const fn reception_id(self) -> ReceptionId {
        self.reception_id
    }
    /// Endpoint which received the input.
    pub const fn endpoint_id(self) -> EndpointId {
        self.endpoint_id
    }
    /// Transport mapping used for this input.
    pub const fn transport(self) -> TransportKind {
        self.transport
    }
    /// Bound socket address (UDP) or connected local address (TCP).
    pub const fn local_addr(self) -> SocketAddr {
        self.local_addr
    }
    /// Remote transport address, without an authentication claim.
    pub const fn peer_addr(self) -> SocketAddr {
        self.peer_addr
    }
    /// Actual UDP destination, when supplied by platform receive metadata.
    pub const fn datagram_destination(self) -> Option<IpAddr> {
        self.datagram_destination
    }
    /// TCP connection identity, absent for datagrams.
    pub const fn session_id(self) -> Option<SessionId> {
        self.session_id
    }
    /// Userspace receive-completion timestamp.
    pub const fn received_at(self) -> Instant {
        self.received_at
    }
    /// Byte length of the complete transport-delivered SNMP input.
    pub const fn received_len(self) -> usize {
        self.received_len
    }
}

/// Limits of the endpoint which received a message, independent of application
/// response policy and the peer's advertised receive size.
#[derive(Debug, Clone, Copy)]
pub(crate) struct EndpointLimits {
    pub(crate) receive: crate::ReceiveLimits,
    pub(crate) send: usize,
}
impl EndpointLimits {
    #[cfg(any(feature = "agent", test))]
    pub(crate) const UDP: Self = Self {
        receive: crate::UDP_RECEIVE_LIMITS,
        send: crate::MAX_UDP_PAYLOAD,
    };
}

/// A response capability bound to the exact receiving endpoint and destination.
#[derive(Clone)]
pub(crate) struct ReplyRoute {
    kind: ReplyKind,
    pub(crate) limits: EndpointLimits,
}

#[derive(Clone)]
enum ReplyKind {
    Udp {
        socket: std::sync::Arc<tokio::net::UdpSocket>,
        responder: std::sync::Arc<crate::udp_responder::UdpResponder>,
        received: crate::udp_responder::ReceivedDatagram,
        endpoint_id: EndpointId,
        local_addr: SocketAddr,
        admission: Option<(
            std::sync::Arc<std::sync::Mutex<bool>>,
            tokio_util::sync::CancellationToken,
        )>,
    },
    Tcp(super::TcpTransport),
}
impl ReplyRoute {
    pub(crate) fn observation(&self) -> &super::observation::Observation {
        match &self.kind {
            ReplyKind::Udp { responder, .. } => responder.observation(),
            ReplyKind::Tcp(transport) => transport.observation(),
        }
    }

    pub(crate) async fn send_before(&self, data: &[u8], deadline: Instant) -> std::io::Result<()> {
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "reply deadline expired",
            ));
        }
        if data.len() > self.limits.send {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "response exceeds endpoint send capacity",
            ));
        }
        match &self.kind {
            ReplyKind::Udp {
                socket,
                responder,
                received,
                endpoint_id,
                local_addr,
                admission,
            } => {
                let send = responder.send_to_admitted(
                    socket,
                    data,
                    received.source,
                    received.destination,
                    admission.as_ref().map(|(gate, _)| gate.as_ref()),
                );
                let result = tokio::select! { biased;
                    () = tokio::time::sleep_until(deadline) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "reply deadline expired")),
                    () = async { match admission { Some((_, cancel)) => cancel.cancelled().await, None => std::future::pending().await } } => Err(std::io::Error::new(std::io::ErrorKind::NotConnected, "UDP endpoint closed")),
                    result = send => result,
                };
                if result.is_ok() {
                    responder.observation().sent(super::SentMessageInfo {
                        endpoint_id: *endpoint_id,
                        session_id: None,
                        transport: TransportKind::Udp,
                        local_addr: *local_addr,
                        peer_addr: received.source,
                        sent_at: Instant::now(),
                        sent_len: data.len(),
                    });
                }
                result
            }
            ReplyKind::Tcp(transport) => transport
                .write_before(data, deadline)
                .await
                .map_err(std::io::Error::other),
        }
    }
}

/// Original bytes, receive metadata and a transport-owned response capability.
pub(crate) struct ReceivedMessage {
    pub(crate) bytes: bytes::Bytes,
    pub(crate) info: ReceivedMessageInfo,
    pub(crate) reply: ReplyRoute,
}
impl ReceivedMessage {
    pub(crate) fn observe(&self, disposition: super::MessageDisposition) {
        self.reply.observation().disposition(self.info, disposition);
    }

    pub(crate) fn with_udp_admission(
        mut self,
        gate: std::sync::Arc<std::sync::Mutex<bool>>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Self {
        if let ReplyKind::Udp { admission, .. } = &mut self.reply.kind {
            *admission = Some((gate, cancel));
        }
        self
    }

    pub(crate) fn tcp(
        bytes: bytes::Bytes,
        info: ReceivedMessageInfo,
        transport: super::TcpTransport,
    ) -> Self {
        use super::RequestTransport;
        let limits = EndpointLimits {
            receive: transport.receive_limits(),
            send: transport.send_capacity(),
        };
        Self {
            bytes,
            info,
            reply: ReplyRoute {
                kind: ReplyKind::Tcp(transport),
                limits,
            },
        }
    }

    pub(crate) fn udp(
        bytes: bytes::Bytes,
        info: ReceivedMessageInfo,
        socket: std::sync::Arc<tokio::net::UdpSocket>,
        responder: std::sync::Arc<crate::udp_responder::UdpResponder>,
        received: crate::udp_responder::ReceivedDatagram,
        limits: EndpointLimits,
    ) -> Self {
        debug_assert_eq!(info.received_len(), bytes.len());
        debug_assert_eq!(info.peer_addr(), received.source);
        Self {
            bytes,
            info,
            reply: ReplyRoute {
                kind: ReplyKind::Udp {
                    socket,
                    responder,
                    received,
                    endpoint_id: info.endpoint_id(),
                    local_addr: info.local_addr(),
                    admission: None,
                },
                limits,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn udp_reply_route_preserves_the_complete_input_identity() {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local = socket.local_addr().unwrap();
        let responder = Arc::new(crate::udp_responder::UdpResponder::new(&socket));
        let endpoint = EndpointId::new();
        let mut buffer = [0; 32];
        let mut previous = None;
        for _ in 0..2 {
            peer.send_to(b"same bytes", local).await.unwrap();
            let received = responder.recv(&socket, &mut buffer).await.unwrap();
            let info = ReceivedMessageInfo::udp(
                endpoint,
                local,
                received.source,
                received.destination.map(|destination| destination.ip),
                Instant::now(),
                received.len,
            );
            let message = ReceivedMessage::udp(
                bytes::Bytes::copy_from_slice(&buffer[..received.len]),
                info,
                socket.clone(),
                responder.clone(),
                received,
                EndpointLimits::UDP,
            );
            assert_eq!(message.info, info);
            assert_ne!(Some(info.reception_id()), previous);
            previous = Some(info.reception_id());
        }
    }
}
