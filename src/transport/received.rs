//! Complete-message transport metadata and internal response capabilities.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::time::Instant;

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// One original complete SNMP input and its receive metadata.
///
/// Custom transports construct this value once per message or response
/// candidate. Built-in transports may retain private parsing work alongside the
/// original bytes; consumers still perform their own security, policy and
/// exchange acceptance checks.
pub struct ReceivedPacket {
    bytes: bytes::Bytes,
    info: ReceivedMessageInfo,
    pub(crate) prepared: Option<Box<crate::v3::prepared::PreparedV3>>,
}
impl ReceivedPacket {
    /// Wrap original input bytes and metadata captured once at receipt.
    ///
    /// `info.received_len()` must equal `bytes.len()`. This constructor does not
    /// validate the length; [`ProcessingInput::new`] checks it together with the
    /// hard receive bound before protocol processing.
    pub fn new(bytes: bytes::Bytes, info: ReceivedMessageInfo) -> Self {
        Self {
            bytes,
            info,
            prepared: None,
        }
    }
    /// Borrow the complete original SNMP input, before decoding or decryption.
    pub fn bytes(&self) -> &bytes::Bytes {
        &self.bytes
    }
    /// Return the original complete-input metadata and reception identity.
    pub fn info(&self) -> ReceivedMessageInfo {
        self.info
    }
    /// Take the original bytes and metadata for custom validation.
    pub fn into_parts(self) -> (bytes::Bytes, ReceivedMessageInfo) {
        (self.bytes, self.info)
    }
    pub(crate) fn into_prepared(
        self,
    ) -> (
        bytes::Bytes,
        ReceivedMessageInfo,
        Option<Box<crate::v3::prepared::PreparedV3>>,
    ) {
        (self.bytes, self.info, self.prepared)
    }
}

/// A complete SNMP input checked against its receive metadata and local limits.
///
/// This envelope retains the original packet and reception identity without
/// decoding or reconstructing its bytes. Construction checks only byte length
/// and the hard input bound. The transport supplies a complete datagram or
/// frame; protocol and security validation still belong to the processor.
/// Caller-supplied metadata and limits do not establish an authenticated
/// identity or trusted transport-security state.
pub struct ProcessingInput {
    packet: ReceivedPacket,
    limits: ProcessingLimits,
}

impl ProcessingInput {
    /// Validate one packet before protocol processing.
    ///
    /// Returns [`crate::Error::InvalidMessage`] when metadata records a different
    /// length, or [`crate::Error::Decode`] with
    /// [`crate::DecodeErrorKind::MessageTooLarge`] when the full input exceeds
    /// the receive limit. The full length includes any tolerated UDP suffix.
    pub fn new(packet: ReceivedPacket, limits: ProcessingLimits) -> crate::Result<Self> {
        if packet.info.received_len() != packet.bytes.len() {
            return Err(crate::Error::InvalidMessage(
                "received length does not match the complete input".into(),
            )
            .boxed());
        }
        if packet.bytes.len() > limits.receive.accepted() {
            return Err(crate::Error::Decode(
                crate::DecodeError::new(
                    0,
                    crate::DecodeErrorKind::MessageTooLarge {
                        size: packet.bytes.len(),
                        maximum: limits.receive.accepted(),
                    },
                )
                .with_peer(packet.info.peer_addr()),
            )
            .boxed());
        }
        Ok(Self { packet, limits })
    }

    /// Borrow the original complete SNMP input, before decoding or decryption.
    pub fn bytes(&self) -> &bytes::Bytes {
        self.packet.bytes()
    }

    /// Return receive metadata with its original reception identity.
    pub fn info(&self) -> ReceivedMessageInfo {
        self.packet.info()
    }

    /// Return the local receive and encoded-send capacities for this input.
    pub fn limits(&self) -> ProcessingLimits {
        self.limits
    }

    /// Recover the original packet and processing limits.
    pub fn into_parts(self) -> (ReceivedPacket, ProcessingLimits) {
        (self.packet, self.limits)
    }
}

impl std::fmt::Debug for ProcessingInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProcessingInput")
            .field("info", &self.info())
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

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

/// Local capacities for complete-message protocol processing.
///
/// These limits are independent of application response policy and the peer's
/// advertised receive size. The receive limit distinguishes advertised capacity
/// from the hard accepted-input bound, including UDP tolerance. No UDP ceiling
/// is applied to stream inputs. Limits supplied by custom I/O describe that
/// implementation's capacities and are not independently verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessingLimits {
    pub(crate) receive: crate::ReceiveLimits,
    pub(crate) send: usize,
}
impl ProcessingLimits {
    /// Default full-capacity UDP receive and send limits.
    pub const UDP: Self = Self {
        receive: crate::UDP_RECEIVE_LIMITS,
        send: crate::MAX_UDP_PAYLOAD,
    };

    /// Combine validated receive limits with an exact encoded-send capacity.
    ///
    /// A send capacity below the minimum SNMP message size is allowed: response
    /// finalization may suppress responses that cannot fit. Returns a
    /// configuration error when `send` exceeds [`crate::MESSAGE_SIZE_MAXIMUM`].
    pub fn new(receive: crate::ReceiveLimits, send: usize) -> crate::Result<Self> {
        if send > crate::MESSAGE_SIZE_MAXIMUM {
            return Err(crate::Error::Config(
                "processing send capacity exceeds the SNMP size range".into(),
            )
            .boxed());
        }
        Ok(Self { receive, send })
    }

    /// Local advertised receive capacity and hard accepted-input bound.
    pub const fn receive(self) -> crate::ReceiveLimits {
        self.receive
    }

    /// Largest encoded response that the receiving endpoint can send.
    pub const fn send(self) -> usize {
        self.send
    }
}

/// A response capability bound to the exact receiving endpoint and destination.
#[derive(Clone)]
pub(crate) struct ReplyRoute {
    kind: ReplyKind,
    pub(crate) limits: ProcessingLimits,
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

    pub(crate) async fn send_before(
        &self,
        data: bytes::Bytes,
        deadline: Instant,
    ) -> std::io::Result<()> {
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
                    &data,
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
    pub(crate) prepared: Option<Box<crate::v3::prepared::PreparedV3>>,
}
impl ReceivedMessage {
    pub(crate) fn into_processing(self) -> crate::Result<(ProcessingInput, ReplyRoute)> {
        let Self {
            bytes,
            info,
            reply,
            prepared,
        } = self;
        let input = ProcessingInput::new(
            ReceivedPacket {
                bytes,
                info,
                prepared,
            },
            reply.limits,
        )?;
        Ok((input, reply))
    }

    pub(crate) fn discard_cached_plaintext(&mut self) {
        if let Some(crypto) = self.prepared.as_mut().and_then(|p| p.crypto.as_mut()) {
            crypto.plaintext = None;
        }
    }
    pub(crate) fn buffered_len(&self) -> usize {
        self.bytes.len() + self.prepared.as_ref().map_or(0, |p| p.plaintext_len())
    }
    pub(crate) fn into_packet(self) -> ReceivedPacket {
        ReceivedPacket {
            bytes: self.bytes,
            info: self.info,
            prepared: self.prepared,
        }
    }
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
        let limits = ProcessingLimits {
            receive: transport.receive_limits(),
            send: transport.send_capacity(),
        };
        Self {
            bytes,
            info,
            prepared: None,
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
        limits: ProcessingLimits,
    ) -> Self {
        debug_assert_eq!(info.received_len(), bytes.len());
        debug_assert_eq!(info.peer_addr(), received.source);
        Self {
            bytes,
            info,
            prepared: None,
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
                ProcessingLimits::UDP,
            );
            assert_eq!(message.info, info);
            let (input, reply) = message.into_processing().unwrap();
            assert_eq!(input.info(), info);
            assert_eq!(input.bytes().as_ref(), b"same bytes");
            assert_eq!(input.limits(), reply.limits);
            assert_ne!(Some(info.reception_id()), previous);
            previous = Some(info.reception_id());
        }
    }
}
