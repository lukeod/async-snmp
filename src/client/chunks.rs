//! Lazy streams for chunked fixed-cardinality operations.

use std::collections::VecDeque;
use std::future::Future;
use std::ops::Range;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_core::Stream;

use crate::error::{Error, ErrorStatus, Result};
use crate::oid::Oid;
use crate::pdu::{Pdu, PduType};
use crate::transport::Transport;

use super::response_shape::{RequestShape, classify};
use super::{Client, DecodedResponse, FixedCardinalityOperation, FixedCardinalityResponse};

/// One successful wire-level leaf of a chunked GET or GETNEXT operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedCardinalityChunk {
    /// Range of original request OIDs covered by this leaf.
    pub request_range: Range<usize>,
    /// Range occupied by this leaf in the concatenated successful responses.
    pub response_range: Range<usize>,
    /// Bindings and shape diagnostics for this leaf.
    ///
    /// Anomaly request and response indices are global to the original chunked
    /// operation rather than local to this response. Metadata also includes
    /// recovered ancestor `tooBig` responses observed since the preceding
    /// successful leaf, so each accepted response is represented once.
    pub response: FixedCardinalityResponse,
}

/// Terminal failure from a chunked GET or GETNEXT operation.
#[derive(Debug, thiserror::Error)]
#[error(
    "{operation:?} request range {failed_request_range:?} failed after completing {completed_request_count} request OIDs and {completed_response_count} response bindings: {source}"
)]
pub struct FixedCardinalityChunkError {
    /// Operation that was being performed.
    pub operation: FixedCardinalityOperation,
    /// Number of original request OIDs covered by successful leaves.
    pub completed_request_count: usize,
    /// Number of response bindings produced by successful leaves.
    pub completed_response_count: usize,
    /// Exact wire-level leaf range whose request failed.
    pub failed_request_range: Range<usize>,
    /// Original request, protocol, response-shape, or transport failure.
    #[source]
    pub source: Box<Error>,
}

type PendingResponse<'a> = Pin<Box<dyn Future<Output = Result<DecodedResponse>> + Send + 'a>>;

/// Lazy sequential stream of wire-level GET or GETNEXT response leaves.
///
/// A successful item is emitted for each request that reaches the wire and
/// succeeds. If an agent returns `tooBig` or local outbound-size enforcement
/// rejects a multi-OID request, the affected range is bisected and successful
/// child leaves are emitted independently. The corresponding error on a
/// single-OID range is terminal. The stream performs no prefetch: it starts at
/// most one request while being polled and does not start the next request until
/// the caller polls again after an item is yielded.
///
/// A terminal error is emitted once, after which the stream is fused. Its
/// source retains any recovered response metadata not already emitted with a
/// successful leaf.
#[must_use = "streams do nothing unless polled"]
pub struct FixedCardinalityChunkStream<'a, T: Transport> {
    client: &'a Client<T>,
    oids: Arc<[Oid]>,
    operation: FixedCardinalityOperation,
    ranges: VecDeque<Range<usize>>,
    active_range: Option<Range<usize>>,
    pending: Option<PendingResponse<'a>>,
    completed_request_count: usize,
    completed_response_count: usize,
    deferred_metadata: super::ResponseMetadata,
    done: bool,
}

impl<'a, T: Transport> FixedCardinalityChunkStream<'a, T> {
    pub(crate) fn new(
        client: &'a Client<T>,
        oids: &[Oid],
        operation: FixedCardinalityOperation,
    ) -> Result<Self> {
        for oid in oids {
            oid.validate_for_wire()?;
        }

        let max_per_request = client.inner.config.max_oids_per_request;
        let ranges = (0..oids.len())
            .step_by(max_per_request)
            .map(|start| start..(start + max_per_request).min(oids.len()))
            .collect();

        Ok(Self {
            client,
            oids: Arc::from(oids),
            operation,
            ranges,
            active_range: None,
            pending: None,
            completed_request_count: 0,
            completed_response_count: 0,
            deferred_metadata: super::ResponseMetadata::default(),
            done: false,
        })
    }

    /// Returns the next successful leaf or the single terminal error.
    pub async fn next(
        &mut self,
    ) -> Option<std::result::Result<FixedCardinalityChunk, FixedCardinalityChunkError>> {
        std::future::poll_fn(|cx| Pin::new(&mut *self).poll_next(cx)).await
    }

    pub(crate) async fn collect_response(mut self) -> Result<FixedCardinalityResponse> {
        let mut response = FixedCardinalityResponse::empty(self.operation);

        while let Some(item) = self.next().await {
            match item {
                Ok(chunk) => {
                    response.response_extend(chunk.response);
                }
                Err(error) => {
                    let mut source = error.source;
                    if let Error::ResponseShape {
                        response: failed_response,
                        ..
                    } = &mut *source
                    {
                        let mut complete_response = response;
                        complete_response.response_extend(std::mem::replace(
                            failed_response,
                            FixedCardinalityResponse::empty(self.operation),
                        ));
                        *failed_response = complete_response;
                    } else {
                        source = source.with_prior_response_metadata(&response.metadata);
                    }
                    return Err(source);
                }
            }
        }

        Ok(response)
    }

    fn start_next_request(&mut self) -> bool {
        let Some(range) = self.ranges.pop_front() else {
            self.done = true;
            return false;
        };
        let client = self.client;
        let oids = Arc::clone(&self.oids);
        let operation = self.operation;
        let request_range = range.clone();
        self.active_range = Some(range);
        self.pending = Some(Box::pin(async move {
            let request_id = client.next_request_id();
            let pdu = match operation {
                FixedCardinalityOperation::Get => {
                    Pdu::get_request(request_id, &oids[request_range])
                }
                FixedCardinalityOperation::GetNext => {
                    Pdu::get_next_request(request_id, &oids[request_range])
                }
                FixedCardinalityOperation::Set => {
                    unreachable!("SET does not use the chunk stream")
                }
            };
            client.send_request(pdu).await
        }));
        true
    }

    fn terminal_error(
        &mut self,
        failed_request_range: Range<usize>,
        mut source: Box<Error>,
    ) -> FixedCardinalityChunkError {
        source = source.with_prior_response_metadata(&self.deferred_metadata);
        self.deferred_metadata = super::ResponseMetadata::default();
        self.done = true;
        self.ranges.clear();
        FixedCardinalityChunkError {
            operation: self.operation,
            completed_request_count: self.completed_request_count,
            completed_response_count: self.completed_response_count,
            failed_request_range,
            source,
        }
    }
}

impl FixedCardinalityResponse {
    fn response_extend(&mut self, response: Self) {
        debug_assert_eq!(self.operation, response.operation);
        self.varbinds.extend(response.varbinds);
        self.anomalies.extend(response.anomalies);
        self.metadata
            .decode_anomalies
            .extend(response.metadata.decode_anomalies);
    }
}

impl<T: Transport> Stream for FixedCardinalityChunkStream<'_, T> {
    type Item = std::result::Result<FixedCardinalityChunk, FixedCardinalityChunkError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(None);
        }

        loop {
            if this.pending.is_none() && !this.start_next_request() {
                return Poll::Ready(None);
            }

            let result = match this.pending.as_mut() {
                Some(pending) => match pending.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(result) => result,
                },
                None => unreachable!("a request range must have a pending future"),
            };
            this.pending = None;
            let request_range = this
                .active_range
                .take()
                .expect("a pending request must have an active range");

            match result {
                Ok(decoded) => {
                    let pdu = decoded.pdu;
                    debug_assert_eq!(pdu.pdu_type(), PduType::Response);
                    let response_range = this.completed_response_count
                        ..this.completed_response_count + pdu.varbinds.len();
                    let request = match this.operation {
                        FixedCardinalityOperation::Get => {
                            RequestShape::Get(&this.oids[request_range.clone()])
                        }
                        FixedCardinalityOperation::GetNext => {
                            RequestShape::GetNext(&this.oids[request_range.clone()])
                        }
                        FixedCardinalityOperation::Set => {
                            unreachable!("SET does not use the chunk stream")
                        }
                    };
                    let mut response = classify(
                        request,
                        pdu.varbinds,
                        request_range.start,
                        response_range.start,
                    );
                    response.metadata = std::mem::take(&mut this.deferred_metadata);
                    response
                        .metadata
                        .decode_anomalies
                        .extend(decoded.decode_anomalies);

                    if this.client.inner.config.response_shape_policy
                        == super::ResponseShapePolicy::Strict
                        && !response.anomalies.is_empty()
                    {
                        let source = Error::ResponseShape {
                            target: this.client.peer_addr(),
                            response,
                        }
                        .boxed();
                        let error = this.terminal_error(request_range, source);
                        return Poll::Ready(Some(Err(error)));
                    }

                    this.completed_request_count += request_range.len();
                    this.completed_response_count = response_range.end;
                    return Poll::Ready(Some(Ok(FixedCardinalityChunk {
                        request_range,
                        response_range,
                        response,
                    })));
                }
                Err(source)
                    if request_range.len() > 1
                        && matches!(
                            &*source,
                            Error::Snmp {
                                status: ErrorStatus::TooBig,
                                ..
                            }
                        ) =>
                {
                    if let Some(metadata) = source.response_metadata().cloned() {
                        this.deferred_metadata.append(metadata);
                    }
                    let middle = request_range.start + request_range.len() / 2;
                    tracing::debug!(target: "async_snmp::client", { peer = %this.client.peer_addr(), snmp.batch_size = request_range.len(), snmp.split_at = middle, snmp.limit_source = "remote_too_big" }, "agent tooBig response, bisecting batch");
                    this.ranges.push_front(middle..request_range.end);
                    this.ranges.push_front(request_range.start..middle);
                }
                Err(source)
                    if request_range.len() > 1
                        && matches!(&*source, Error::OutboundMessageTooLarge { .. }) =>
                {
                    let Error::OutboundMessageTooLarge { size, limit } = &*source else {
                        unreachable!();
                    };
                    let middle = request_range.start + request_range.len() / 2;
                    tracing::debug!(target: "async_snmp::client", { peer = %this.client.peer_addr(), snmp.batch_size = request_range.len(), snmp.split_at = middle, snmp.encoded_size = size, snmp.outbound_limit = limit, snmp.limit_source = "local_outbound" }, "local outbound limit exceeded, bisecting batch");
                    this.ranges.push_front(middle..request_range.end);
                    this.ranges.push_front(request_range.start..middle);
                }
                Err(source)
                    if matches!(
                        &*source,
                        Error::Snmp {
                            status: ErrorStatus::TooBig,
                            ..
                        }
                    ) =>
                {
                    tracing::debug!(target: "async_snmp::client", { peer = %this.client.peer_addr(), snmp.batch_size = request_range.len(), snmp.limit_source = "remote_too_big" }, "agent tooBig response for indivisible batch");
                    let error = this.terminal_error(request_range, source);
                    return Poll::Ready(Some(Err(error)));
                }
                Err(source) if matches!(&*source, Error::OutboundMessageTooLarge { .. }) => {
                    let Error::OutboundMessageTooLarge { size, limit } = &*source else {
                        unreachable!();
                    };
                    tracing::debug!(target: "async_snmp::client", { peer = %this.client.peer_addr(), snmp.batch_size = request_range.len(), snmp.encoded_size = size, snmp.outbound_limit = limit, snmp.limit_source = "local_outbound" }, "local outbound limit exceeded for indivisible batch");
                    let error = this.terminal_error(request_range, source);
                    return Poll::Ready(Some(Err(error)));
                }
                Err(source) => {
                    let error = this.terminal_error(request_range, source);
                    return Poll::Ready(Some(Err(error)));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{ClientConfig, ResponseShapeAnomaly, ResponseShapePolicy, Retry};
    use crate::message::CommunityMessage;
    use crate::transport::RequestRegistration;
    use crate::value::Value;
    use crate::varbind::VarBind;
    use bytes::Bytes;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::AsyncReadExt;
    use tokio::time::{Duration, timeout};

    #[derive(Clone)]
    enum Action {
        Echo,
        EchoWithSuffix(usize),
        Response(Vec<VarBind>),
        TooBig,
        TooBigWithSuffix(usize),
        Fail,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct RequestRecord {
        pdu_type: PduType,
        oids: Vec<Oid>,
    }

    struct PendingRequest {
        request_id: i32,
        record: RequestRecord,
    }

    #[derive(Clone)]
    struct ScriptTransport {
        actions: Arc<Mutex<VecDeque<Action>>>,
        pending: Arc<Mutex<VecDeque<PendingRequest>>>,
        records: Arc<Mutex<Vec<RequestRecord>>>,
        sends: Arc<AtomicUsize>,
        allocations: Arc<AtomicUsize>,
        send_capacity: usize,
    }

    impl ScriptTransport {
        fn new(actions: impl IntoIterator<Item = Action>) -> Self {
            Self {
                actions: Arc::new(Mutex::new(actions.into_iter().collect())),
                pending: Arc::new(Mutex::new(VecDeque::new())),
                records: Arc::new(Mutex::new(Vec::new())),
                sends: Arc::new(AtomicUsize::new(0)),
                allocations: Arc::new(AtomicUsize::new(0)),
                send_capacity: crate::MAX_UDP_PAYLOAD,
            }
        }

        fn with_send_capacity(mut self, send_capacity: usize) -> Self {
            self.send_capacity = send_capacity;
            self
        }

        fn records(&self) -> Vec<RequestRecord> {
            self.records.lock().unwrap().clone()
        }
    }

    impl Transport for ScriptTransport {
        fn send(&self, data: &[u8]) -> impl Future<Output = Result<()>> + Send {
            self.sends.fetch_add(1, Ordering::Relaxed);
            let message = CommunityMessage::decode(Bytes::copy_from_slice(data)).unwrap();
            let pdu = message.pdu().standard().unwrap();
            let record = RequestRecord {
                pdu_type: pdu.pdu_type(),
                oids: pdu
                    .varbinds
                    .iter()
                    .map(|varbind| varbind.oid.clone())
                    .collect(),
            };
            self.records.lock().unwrap().push(record.clone());
            self.pending.lock().unwrap().push_back(PendingRequest {
                request_id: pdu.request_id,
                record,
            });
            async { Ok(()) }
        }

        fn recv(
            &self,
            _registration: RequestRegistration,
        ) -> impl Future<Output = Result<(Bytes, std::net::SocketAddr)>> + Send {
            let action = self
                .actions
                .lock()
                .unwrap()
                .pop_front()
                .expect("missing scripted action");
            let pending = self
                .pending
                .lock()
                .unwrap()
                .pop_front()
                .expect("missing pending request");
            let peer = self.peer_addr();

            async move {
                if matches!(action, Action::Fail) {
                    return Err(Error::Closed { target: peer }.boxed());
                }

                let suffix_length = match action {
                    Action::EchoWithSuffix(length) | Action::TooBigWithSuffix(length) => length,
                    _ => 0,
                };
                let pdu = match action {
                    Action::Echo | Action::EchoWithSuffix(_) => {
                        let varbinds = pending
                            .record
                            .oids
                            .into_iter()
                            .map(|oid| {
                                let response_oid = match pending.record.pdu_type {
                                    PduType::GetNextRequest => oid.child(0),
                                    _ => oid,
                                };
                                VarBind::new(response_oid, Value::Integer(1))
                            })
                            .collect();
                        Pdu::response(pending.request_id, 0, 0, varbinds)
                    }
                    Action::Response(varbinds) => Pdu::response(pending.request_id, 0, 0, varbinds),
                    Action::TooBig | Action::TooBigWithSuffix(_) => Pdu::response(
                        pending.request_id,
                        ErrorStatus::TooBig.as_i32(),
                        0,
                        Vec::new(),
                    ),
                    Action::Fail => unreachable!(),
                };
                let message = CommunityMessage::v2c(Bytes::from_static(b"public"), pdu).unwrap();
                let mut encoded = message.encode().unwrap().to_vec();
                encoded.extend(std::iter::repeat_n(0xa5, suffix_length));
                Ok((Bytes::from(encoded), peer))
            }
        }

        fn peer_addr(&self) -> std::net::SocketAddr {
            "127.0.0.1:161".parse().unwrap()
        }

        fn local_addr(&self) -> std::net::SocketAddr {
            "127.0.0.1:0".parse().unwrap()
        }

        fn alloc_request_id(&self) -> i32 {
            self.allocations.fetch_add(1, Ordering::Relaxed) as i32 + 1
        }

        fn is_reliable(&self) -> bool {
            true
        }

        fn send_capacity(&self) -> usize {
            self.send_capacity
        }
    }

    fn test_oids(count: u32) -> Vec<Oid> {
        (0..count)
            .map(|index| Oid::from_slice(&[1, 3, 6, 1, 4, 1, 999, index]))
            .collect()
    }

    fn trailing_lengths(metadata: &crate::client::ResponseMetadata) -> Vec<usize> {
        metadata
            .decode_anomalies
            .iter()
            .map(|anomaly| match anomaly {
                crate::DecodeAnomaly::TrailingBytes {
                    original_length, ..
                } => *original_length,
                other => panic!("expected trailing-byte anomaly, got {other:?}"),
            })
            .collect()
    }

    fn client(
        transport: ScriptTransport,
        max_oids_per_request: usize,
        response_shape_policy: ResponseShapePolicy,
    ) -> Client<ScriptTransport> {
        Client::new(
            transport,
            ClientConfig {
                auth: crate::Auth::v2c("public"),
                retry: Retry::none(),
                max_oids_per_request,
                response_shape_policy,
                ..Default::default()
            },
        )
        .unwrap()
    }

    #[tokio::test]
    async fn stream_is_lazy_and_applies_backpressure() {
        let transport = ScriptTransport::new([Action::Echo, Action::Echo]);
        let client = client(transport.clone(), 2, ResponseShapePolicy::Compatible);
        let oids = test_oids(4);
        let mut stream = client.get_many_chunks(&oids).unwrap();

        assert_eq!(transport.allocations.load(Ordering::Relaxed), 0);
        assert_eq!(transport.sends.load(Ordering::Relaxed), 0);

        let first = stream.next().await.unwrap().unwrap();
        assert_eq!(first.request_range, 0..2);
        assert_eq!(transport.sends.load(Ordering::Relaxed), 1);
        assert_eq!(transport.records().len(), 1);

        let second = stream.next().await.unwrap().unwrap();
        assert_eq!(second.request_range, 2..4);
        assert_eq!(transport.sends.load(Ordering::Relaxed), 2);
        assert!(stream.next().await.is_none());
    }

    #[test]
    fn every_oid_is_validated_before_any_request_can_start() {
        let transport = ScriptTransport::new([]);
        let client = client(transport.clone(), 1, ResponseShapePolicy::Compatible);
        let mut oids = test_oids(3);
        oids[2] = Oid::empty();

        let error = client
            .get_many_chunks(&oids)
            .err()
            .expect("invalid OID must reject stream construction");
        assert!(matches!(*error, Error::InvalidOid(_)));
        assert_eq!(transport.allocations.load(Ordering::Relaxed), 0);
        assert_eq!(transport.sends.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn later_chunk_failure_reports_progress_and_fuses() {
        let transport = ScriptTransport::new([Action::Echo, Action::Fail, Action::Echo]);
        let client = client(transport, 2, ResponseShapePolicy::Compatible);
        let mut stream = client.get_many_chunks(&test_oids(6)).unwrap();

        let first = stream.next().await.unwrap().unwrap();
        assert_eq!(first.request_range, 0..2);
        let error = stream.next().await.unwrap().unwrap_err();
        assert_eq!(error.operation, FixedCardinalityOperation::Get);
        assert_eq!(error.completed_request_count, 2);
        assert_eq!(error.completed_response_count, 2);
        assert_eq!(error.failed_request_range, 2..4);
        assert!(matches!(*error.source, Error::Closed { .. }));
        assert!(stream.next().await.is_none());
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn too_big_emits_successful_leaves_and_reports_right_child_failure() {
        let transport = ScriptTransport::new([Action::TooBig, Action::Echo, Action::Fail]);
        let client = client(transport.clone(), 4, ResponseShapePolicy::Compatible);
        let mut stream = client.get_next_many_chunks(&test_oids(4)).unwrap();

        let left = stream.next().await.unwrap().unwrap();
        assert_eq!(left.request_range, 0..2);
        assert_eq!(left.response_range, 0..2);
        assert_eq!(left.response.operation, FixedCardinalityOperation::GetNext);

        let error = stream.next().await.unwrap().unwrap_err();
        assert_eq!(error.operation, FixedCardinalityOperation::GetNext);
        assert_eq!(error.completed_request_count, 2);
        assert_eq!(error.completed_response_count, 2);
        assert_eq!(error.failed_request_range, 2..4);
        assert!(matches!(*error.source, Error::Closed { .. }));
        assert_eq!(
            transport
                .records()
                .into_iter()
                .map(|record| record.oids.len())
                .collect::<Vec<_>>(),
            [4, 2, 2]
        );
    }

    #[tokio::test]
    async fn too_big_metadata_is_carried_once_into_successful_children_and_aggregate() {
        let actions = [
            Action::TooBigWithSuffix(1),
            Action::EchoWithSuffix(2),
            Action::EchoWithSuffix(3),
        ];
        let stream_client = client(
            ScriptTransport::new(actions.clone()),
            4,
            ResponseShapePolicy::Compatible,
        );
        let mut stream = stream_client.get_many_chunks(&test_oids(4)).unwrap();

        let left = stream.next().await.unwrap().unwrap();
        assert_eq!(trailing_lengths(&left.response.metadata), [1, 2]);
        let right = stream.next().await.unwrap().unwrap();
        assert_eq!(trailing_lengths(&right.response.metadata), [3]);

        let aggregate_client = client(
            ScriptTransport::new(actions),
            4,
            ResponseShapePolicy::Compatible,
        );
        let aggregate = aggregate_client.get_many(&test_oids(4)).await.unwrap();
        assert_eq!(trailing_lengths(&aggregate.metadata), [1, 2, 3]);
    }

    #[tokio::test]
    async fn too_big_metadata_is_carried_once_into_terminal_child_failure() {
        let transport = ScriptTransport::new([Action::TooBigWithSuffix(1), Action::Fail]);
        let client = client(transport, 4, ResponseShapePolicy::Compatible);
        let mut stream = client.get_many_chunks(&test_oids(4)).unwrap();

        let error = stream.next().await.unwrap().unwrap_err();
        assert_eq!(error.source.kind(), crate::ErrorKind::Closed);
        assert!(matches!(
            error.source.exchange_source(),
            Error::Closed { .. }
        ));
        assert_eq!(
            trailing_lengths(error.source.response_metadata().unwrap()),
            [1]
        );
    }

    #[tokio::test]
    async fn too_big_metadata_merges_into_terminal_snmp_error_without_wrapper() {
        let transport =
            ScriptTransport::new([Action::TooBigWithSuffix(1), Action::TooBigWithSuffix(2)]);
        let client = client(transport, 2, ResponseShapePolicy::Compatible);
        let mut stream = client.get_many_chunks(&test_oids(2)).unwrap();

        let error = stream.next().await.unwrap().unwrap_err();
        assert!(matches!(
            error.source.as_ref(),
            Error::Snmp {
                status: ErrorStatus::TooBig,
                ..
            }
        ));
        assert_eq!(
            trailing_lengths(error.source.response_metadata().unwrap()),
            [1, 2]
        );
    }

    #[tokio::test]
    async fn local_outbound_limit_bisects_splittable_get_before_send() {
        let oids = test_oids(4);
        let two_oid_size = CommunityMessage::v2c(
            Bytes::from_static(b"public"),
            Pdu::get_request(1, &oids[..2]),
        )
        .unwrap()
        .encode()
        .unwrap()
        .len();
        let four_oid_size =
            CommunityMessage::v2c(Bytes::from_static(b"public"), Pdu::get_request(1, &oids))
                .unwrap()
                .encode()
                .unwrap()
                .len();
        assert!(four_oid_size > two_oid_size);

        let transport =
            ScriptTransport::new([Action::Echo, Action::Echo]).with_send_capacity(two_oid_size);
        let client = client(transport.clone(), 4, ResponseShapePolicy::Compatible);
        let response = client.get_many(&oids).await.unwrap();

        assert_eq!(response.varbinds.len(), 4);
        assert_eq!(transport.sends.load(Ordering::Relaxed), 2);
        assert_eq!(
            transport
                .records()
                .into_iter()
                .map(|record| record.oids.len())
                .collect::<Vec<_>>(),
            [2, 2],
            "the oversized four-OID parent must not reach transport send"
        );
    }

    #[tokio::test]
    async fn local_outbound_limit_bisects_splittable_get_next_before_send() {
        let oids = test_oids(4);
        let two_oid_size = CommunityMessage::v2c(
            Bytes::from_static(b"public"),
            Pdu::get_next_request(1, &oids[..2]),
        )
        .unwrap()
        .encode()
        .unwrap()
        .len();

        let transport =
            ScriptTransport::new([Action::Echo, Action::Echo]).with_send_capacity(two_oid_size);
        let client = client(transport.clone(), 4, ResponseShapePolicy::Compatible);
        let response = client.get_next_many(&oids).await.unwrap();

        assert_eq!(response.operation, FixedCardinalityOperation::GetNext);
        assert_eq!(response.varbinds.len(), 4);
        assert_eq!(transport.sends.load(Ordering::Relaxed), 2);
        assert!(
            transport
                .records()
                .iter()
                .all(|record| record.pdu_type == PduType::GetNextRequest)
        );
        assert_eq!(
            transport
                .records()
                .into_iter()
                .map(|record| record.oids.len())
                .collect::<Vec<_>>(),
            [2, 2]
        );
    }

    #[tokio::test]
    async fn remote_too_big_on_singleton_is_terminal() {
        let transport = ScriptTransport::new([Action::TooBig]);
        let client = client(transport.clone(), 1, ResponseShapePolicy::Compatible);
        let mut stream = client.get_many_chunks(&test_oids(1)).unwrap();

        let error = stream.next().await.unwrap().unwrap_err();
        assert_eq!(error.failed_request_range, 0..1);
        assert!(matches!(
            *error.source,
            Error::Snmp {
                status: ErrorStatus::TooBig,
                ..
            }
        ));
        assert_eq!(transport.sends.load(Ordering::Relaxed), 1);
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn local_outbound_limit_on_singleton_is_terminal_before_send() {
        let oids = test_oids(1);
        let encoded_size =
            CommunityMessage::v2c(Bytes::from_static(b"public"), Pdu::get_request(1, &oids))
                .unwrap()
                .encode()
                .unwrap()
                .len();
        let transport = ScriptTransport::new([]).with_send_capacity(encoded_size - 1);
        let client = client(transport.clone(), 1, ResponseShapePolicy::Compatible);
        let mut stream = client.get_many_chunks(&oids).unwrap();

        let error = stream.next().await.unwrap().unwrap_err();
        assert_eq!(error.failed_request_range, 0..1);
        assert!(matches!(
            *error.source,
            Error::OutboundMessageTooLarge { size, limit }
                if size == encoded_size && limit == encoded_size - 1
        ));
        assert_eq!(transport.sends.load(Ordering::Relaxed), 0);
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn compatible_chunks_retain_anomalies_with_global_indices() {
        let oids = test_oids(4);
        let renamed = VarBind::new(Oid::from_slice(&[1, 3, 6, 1, 9]), Value::Integer(9));
        let transport = ScriptTransport::new([
            Action::Response(vec![VarBind::new(oids[0].clone(), Value::Integer(1))]),
            Action::Response(vec![renamed]),
        ]);
        let client = client(transport, 2, ResponseShapePolicy::Compatible);
        let mut stream = client.get_many_chunks(&oids).unwrap();

        let first = stream.next().await.unwrap().unwrap();
        assert_eq!(first.request_range, 0..2);
        assert_eq!(first.response_range, 0..1);
        assert!(matches!(
            first.response.anomalies.as_slice(),
            [ResponseShapeAnomaly::Truncated {
                request_range,
                response_range,
                expected: 2,
                actual: 1,
            }] if request_range == &(0..2) && response_range == &(0..1)
        ));

        let second = stream.next().await.unwrap().unwrap();
        assert_eq!(second.request_range, 2..4);
        assert_eq!(second.response_range, 1..2);
        assert!(matches!(
            second.response.anomalies.as_slice(),
            [ResponseShapeAnomaly::Truncated {
                request_range,
                response_range,
                expected: 2,
                actual: 1,
            }] if request_range == &(2..4) && response_range == &(1..2)
        ));
    }

    #[tokio::test]
    async fn strict_anomaly_is_a_terminal_leaf_error_with_global_indices() {
        let oids = test_oids(4);
        let second_response = vec![
            VarBind::new(Oid::from_slice(&[1, 3, 6, 1, 9]), Value::Integer(9)),
            VarBind::new(oids[3].clone(), Value::Integer(3)),
        ];
        let transport = ScriptTransport::new([Action::Echo, Action::Response(second_response)]);
        let client = client(transport, 2, ResponseShapePolicy::Strict);
        let mut stream = client.get_many_chunks(&oids).unwrap();

        stream.next().await.unwrap().unwrap();
        let error = stream.next().await.unwrap().unwrap_err();
        assert_eq!(error.completed_request_count, 2);
        assert_eq!(error.completed_response_count, 2);
        assert_eq!(error.failed_request_range, 2..4);
        let Error::ResponseShape { response, .. } = *error.source else {
            panic!("strict anomaly must retain its response");
        };
        assert_eq!(response.varbinds.len(), 2);
        assert!(matches!(
            response.anomalies.as_slice(),
            [ResponseShapeAnomaly::OidMismatch {
                request_index: 2,
                response_index: 2,
                ..
            }]
        ));
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn empty_input_finishes_without_io() {
        let transport = ScriptTransport::new([]);
        let client = client(transport.clone(), 2, ResponseShapePolicy::Compatible);

        let mut get = client.get_many_chunks(&[]).unwrap();
        assert!(get.next().await.is_none());
        let mut get_next = client.get_next_many_chunks(&[]).unwrap();
        assert!(get_next.next().await.is_none());
        assert_eq!(transport.sends.load(Ordering::Relaxed), 0);

        let aggregate = client.get_many(&[]).await.unwrap();
        assert_eq!(aggregate.operation, FixedCardinalityOperation::Get);
        assert!(aggregate.varbinds.is_empty());
        assert!(aggregate.anomalies.is_empty());
    }

    #[tokio::test]
    async fn aggregate_methods_collect_the_same_engine_results() {
        let oids = test_oids(4);
        let streamed_get_transport = ScriptTransport::new([Action::Echo, Action::Echo]);
        let streamed_get_client =
            client(streamed_get_transport, 2, ResponseShapePolicy::Compatible);
        let mut get_stream = streamed_get_client.get_many_chunks(&oids).unwrap();
        let mut streamed_get_response =
            FixedCardinalityResponse::empty(FixedCardinalityOperation::Get);
        while let Some(chunk) = get_stream.next().await {
            streamed_get_response.response_extend(chunk.unwrap().response);
        }
        let aggregate_get_transport = ScriptTransport::new([Action::Echo, Action::Echo]);
        let aggregate_get_client =
            client(aggregate_get_transport, 2, ResponseShapePolicy::Compatible);
        assert_eq!(
            aggregate_get_client.get_many(&oids).await.unwrap(),
            streamed_get_response
        );

        let streamed_transport = ScriptTransport::new([Action::Echo, Action::Echo]);
        let streamed_client = client(streamed_transport, 2, ResponseShapePolicy::Compatible);
        let mut stream = streamed_client.get_next_many_chunks(&oids).unwrap();
        let mut streamed_response =
            FixedCardinalityResponse::empty(FixedCardinalityOperation::GetNext);
        while let Some(chunk) = stream.next().await {
            streamed_response.response_extend(chunk.unwrap().response);
        }

        let aggregate_transport = ScriptTransport::new([Action::Echo, Action::Echo]);
        let aggregate_client = client(aggregate_transport, 2, ResponseShapePolicy::Compatible);
        assert_eq!(
            aggregate_client.get_next_many(&oids).await.unwrap(),
            streamed_response
        );

        let failing_transport = ScriptTransport::new([Action::Echo, Action::Fail]);
        let failing_client = client(failing_transport, 2, ResponseShapePolicy::Compatible);
        let error = failing_client.get_many(&oids).await.unwrap_err();
        assert!(matches!(*error, Error::Closed { .. }));
    }

    #[tokio::test]
    async fn aggregate_strict_error_retains_completed_and_failed_responses() {
        let oids = test_oids(4);
        let second_response = vec![
            VarBind::new(Oid::from_slice(&[1, 3, 6, 1, 9]), Value::Integer(9)),
            VarBind::new(oids[3].clone(), Value::Integer(3)),
        ];
        let transport = ScriptTransport::new([Action::Echo, Action::Response(second_response)]);
        let client = client(transport, 2, ResponseShapePolicy::Strict);

        let error = client.get_many(&oids).await.unwrap_err();
        let Error::ResponseShape { response, .. } = *error else {
            panic!("strict aggregate must return the shape source error");
        };
        assert_eq!(response.varbinds.len(), 4);
        assert!(matches!(
            response.anomalies.as_slice(),
            [ResponseShapeAnomaly::OidMismatch {
                request_index: 2,
                response_index: 2,
                ..
            }]
        ));
    }

    #[tokio::test]
    async fn dropping_in_flight_tcp_chunk_poisons_the_connection() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let transport = crate::TcpTransport::connect(target).await.unwrap();
        let client = Client::new(
            transport,
            ClientConfig {
                auth: crate::Auth::v2c("public"),
                retry: Retry::none(),
                request_timeout: Duration::from_secs(2),
                ..Default::default()
            },
        )
        .unwrap();
        let (request_seen, seen) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut first_byte = [0];
            socket.read_exact(&mut first_byte).await.unwrap();
            request_seen.send(()).unwrap();
            std::future::pending::<()>().await;
        });

        let oid = test_oids(1).remove(0);
        let mut stream = client.get_many_chunks(std::slice::from_ref(&oid)).unwrap();
        let mut next = Box::pin(stream.next());
        tokio::select! {
            result = &mut next => panic!("request unexpectedly completed: {result:?}"),
            result = timeout(Duration::from_secs(2), seen) => result.unwrap().unwrap(),
        }
        drop(next);
        drop(stream);

        let error = timeout(Duration::from_secs(2), client.get(&oid))
            .await
            .unwrap()
            .unwrap_err();
        assert!(matches!(*error, Error::Closed { .. }));
        server.abort();
    }
}
