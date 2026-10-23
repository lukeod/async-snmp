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
    /// Construct UDP metadata. Supply a destination only when receive metadata
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

    /// Construct TCP metadata for one complete BER frame on a known session.
    pub fn tcp(
        endpoint_id: EndpointId,
        session_id: SessionId,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        received_at: Instant,
        received_len: usize,
    ) -> Self {
        Self {
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
    pub(crate) const UDP: Self = Self {
        receive: crate::UDP_RECEIVE_LIMITS,
        send: crate::MAX_UDP_PAYLOAD,
    };
}

/// A response capability bound to the exact receiving endpoint and destination.
#[derive(Debug, Clone)]
pub(crate) struct ReplyRoute {
    socket: std::sync::Arc<tokio::net::UdpSocket>,
    responder: std::sync::Arc<crate::udp_responder::UdpResponder>,
    received: crate::udp_responder::ReceivedDatagram,
    pub(crate) limits: EndpointLimits,
}
impl ReplyRoute {
    pub(crate) async fn send(&self, data: &[u8]) -> std::io::Result<()> {
        if data.len() > self.limits.send {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "response exceeds endpoint send capacity",
            ));
        }
        self.responder
            .reply(&self.socket, data, &self.received)
            .await
    }
}

/// Original bytes, receive metadata and a transport-owned response capability.
pub(crate) struct ReceivedMessage {
    pub(crate) bytes: bytes::Bytes,
    pub(crate) info: ReceivedMessageInfo,
    pub(crate) reply: ReplyRoute,
}
impl ReceivedMessage {
    pub(crate) fn udp(
        bytes: bytes::Bytes,
        endpoint_id: EndpointId,
        socket: std::sync::Arc<tokio::net::UdpSocket>,
        responder: std::sync::Arc<crate::udp_responder::UdpResponder>,
        received: crate::udp_responder::ReceivedDatagram,
        received_at: Instant,
        limits: EndpointLimits,
    ) -> Self {
        let info = ReceivedMessageInfo::udp(
            endpoint_id,
            socket
                .local_addr()
                .expect("bound UDP endpoint has local address"),
            received.source,
            received.destination.map(|d| d.ip),
            received_at,
            bytes.len(),
        );
        Self {
            bytes,
            info,
            reply: ReplyRoute {
                socket,
                responder,
                received,
                limits,
            },
        }
    }
}
