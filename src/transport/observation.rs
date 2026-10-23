//! Bounded transport observation without packet contents or user callbacks.

use super::{EndpointId, ReceivedMessageInfo, SessionId, TransportKind};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, ReadBuf};
use tokio::sync::mpsc;
use tokio::time::Instant;

/// Suggested event capacity. Full queues drop observations, never protocol work.
pub const DEFAULT_OBSERVATION_CAPACITY: usize = 256;

/// A completed outbound SNMP message, without its contents or credentials.
/// Completion means the socket accepted all bytes, not peer delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SentMessageInfo {
    pub endpoint_id: EndpointId,
    pub session_id: Option<SessionId>,
    pub transport: TransportKind,
    /// Bound UDP address or connected TCP local address. A wildcard remains wildcard.
    pub local_addr: SocketAddr,
    pub peer_addr: SocketAddr,
    pub sent_at: Instant,
    pub sent_len: usize,
}

/// Observed processing stages, independent of physical message/byte accounting.
/// A reception can have several stages or none, including when work is cancelled.
/// These are not an exhaustive terminal-outcome ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MessageDisposition {
    /// Structural parsing could not identify a response.
    Malformed,
    /// No pending exchange accepted correlation (including late/duplicate input).
    Unmatched,
    /// A correlated response was queued for client validation.
    CandidateQueued,
    /// The request transport's validator accepted a candidate. Later client
    /// timeliness publication, response-shape or operation checks can still fail.
    CandidateValidated,
    /// The request transport's validator rejected a candidate or returned an error.
    CandidateRejected,
    /// Command work entered the application queue; authorization/processing follows.
    ApplicationQueued,
    /// Notification processing published into its reserved delivery slot. A
    /// concurrently dropped consumer can discard it; consumption is not confirmed.
    NotificationDelivered,
    /// Notification policy, security or decoding rejected input.
    Rejected,
    /// The applicable application role was disabled.
    Disabled,
    /// Bounded processing or delivery capacity was unavailable.
    Overloaded,
}

/// Metadata-only events. Received precedes processing on that reception; concurrent
/// endpoints and asynchronous workers have no total causal ordering. Dropped
/// events create gaps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ObservationEvent {
    Received(ReceivedMessageInfo),
    Sent(SentMessageInfo),
    Disposition {
        info: ReceivedMessageInfo,
        disposition: MessageDisposition,
    },
}

/// Cumulative counters over all endpoints configured with one observer.
///
/// Complete input includes malformed UDP and complete BER frames before security
/// processing. Incomplete/oversized TCP frames contribute only socket bytes.
/// Socket bytes count successful syscall/read results, including partial I/O and
/// UDP input subsequently rejected for ancillary metadata. They exclude network
/// headers, TCP retransmissions and kernel-dropped input. Dispositions never add
/// message bytes. Atomic fields are sampled individually, not as one transaction.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ObservationStats {
    pub received_messages: u64,
    pub received_message_bytes: u64,
    pub sent_messages: u64,
    pub sent_message_bytes: u64,
    pub socket_read_bytes: u64,
    pub socket_written_bytes: u64,
    pub dispositions: u64,
    /// Events lost because the queue was full or the consumer was dropped.
    pub dropped_events: u64,
}
#[derive(Debug, Default)]
struct Counters {
    received_messages: AtomicU64,
    received_message_bytes: AtomicU64,
    sent_messages: AtomicU64,
    sent_message_bytes: AtomicU64,
    socket_read_bytes: AtomicU64,
    socket_written_bytes: AtomicU64,
    dispositions: AtomicU64,
    dropped_events: AtomicU64,
}
impl Counters {
    fn snapshot(&self) -> ObservationStats {
        ObservationStats {
            received_messages: self.received_messages.load(Ordering::Relaxed),
            received_message_bytes: self.received_message_bytes.load(Ordering::Relaxed),
            sent_messages: self.sent_messages.load(Ordering::Relaxed),
            sent_message_bytes: self.sent_message_bytes.load(Ordering::Relaxed),
            socket_read_bytes: self.socket_read_bytes.load(Ordering::Relaxed),
            socket_written_bytes: self.socket_written_bytes.load(Ordering::Relaxed),
            dispositions: self.dispositions.load(Ordering::Relaxed),
            dropped_events: self.dropped_events.load(Ordering::Relaxed),
        }
    }
}

/// Cloneable bounded observation sink. Configure it before preparing an endpoint.
/// No background task, callback, raw packet, or service lifetime lease is retained.
/// All clones aggregate counters and share one event queue. Keeping a clone keeps
/// the event stream open; use receiver.stats() to inspect counters after EOF.
#[derive(Clone, Debug)]
pub struct TransportObserver {
    sender: mpsc::Sender<ObservationEvent>,
    counters: Arc<Counters>,
}
impl TransportObserver {
    /// Create a channel with 1..=65,536 event slots. The suggested capacity is
    /// [`DEFAULT_OBSERVATION_CAPACITY`]. Queue saturation cannot block protocol I/O.
    pub fn channel(capacity: usize) -> crate::Result<(Self, ObservationReceiver)> {
        if !(1..=65_536).contains(&capacity) {
            return Err(crate::Error::Config(
                "observation capacity must be between 1 and 65536".into(),
            )
            .boxed());
        }
        let (sender, receiver) = mpsc::channel(capacity);
        let counters = Arc::new(Counters::default());
        Ok((
            Self {
                sender,
                counters: counters.clone(),
            },
            ObservationReceiver { receiver, counters },
        ))
    }
    /// Counters continue to advance when events are dropped.
    pub fn stats(&self) -> ObservationStats {
        self.counters.snapshot()
    }
    fn emit(&self, event: ObservationEvent) {
        if self.sender.try_send(event).is_err() {
            self.counters.dropped_events.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Single event consumer. Dropping it only disables event delivery; configured
/// endpoints continue processing and updating counters. Receiving is cancellation
/// safe. EOF means every sink/endpoint sender has been dropped, not service success.
pub struct ObservationReceiver {
    receiver: mpsc::Receiver<ObservationEvent>,
    counters: Arc<Counters>,
}
impl ObservationReceiver {
    pub async fn recv(&mut self) -> Option<ObservationEvent> {
        self.receiver.recv().await
    }
    pub fn try_recv(&mut self) -> Result<ObservationEvent, mpsc::error::TryRecvError> {
        self.receiver.try_recv()
    }
    pub fn stats(&self) -> ObservationStats {
        self.counters.snapshot()
    }
}

#[derive(Clone, Default, Debug)]
pub(crate) struct Observation(pub(crate) Option<TransportObserver>);
impl Observation {
    pub(crate) fn read(&self, length: usize) {
        if let Some(observer) = &self.0 {
            observer
                .counters
                .socket_read_bytes
                .fetch_add(length as u64, Ordering::Relaxed);
        }
    }
    pub(crate) fn written(&self, length: usize) {
        if let Some(observer) = &self.0 {
            observer
                .counters
                .socket_written_bytes
                .fetch_add(length as u64, Ordering::Relaxed);
        }
    }
    pub(crate) fn received(&self, info: ReceivedMessageInfo) {
        if let Some(observer) = &self.0 {
            observer
                .counters
                .received_messages
                .fetch_add(1, Ordering::Relaxed);
            observer
                .counters
                .received_message_bytes
                .fetch_add(info.received_len() as u64, Ordering::Relaxed);
            observer.emit(ObservationEvent::Received(info));
        }
    }
    pub(crate) fn sent(&self, info: SentMessageInfo) {
        if let Some(observer) = &self.0 {
            observer
                .counters
                .sent_messages
                .fetch_add(1, Ordering::Relaxed);
            observer
                .counters
                .sent_message_bytes
                .fetch_add(info.sent_len as u64, Ordering::Relaxed);
            observer.emit(ObservationEvent::Sent(info));
        }
    }
    pub(crate) fn disposition(&self, info: ReceivedMessageInfo, disposition: MessageDisposition) {
        if let Some(observer) = &self.0 {
            observer
                .counters
                .dispositions
                .fetch_add(1, Ordering::Relaxed);
            observer.emit(ObservationEvent::Disposition { info, disposition });
        }
    }
}

pub(crate) struct ObservedRead<R> {
    pub(crate) inner: R,
    pub(crate) observation: Observation,
}
impl<R: AsyncRead + Unpin> AsyncRead for ObservedRead<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buffer);
        self.observation.read(buffer.filled().len() - before);
        result
    }
}
