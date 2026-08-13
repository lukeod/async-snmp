//! Walk stream implementations.

// Allow complex types for boxed futures in manual Stream implementations.
// The `pending` fields require `Option<Pin<Box<dyn Future<Output = ...> + Send>>>`
// which triggers this lint but is the standard pattern for storing futures.
#![allow(clippy::type_complexity)]

/// Implement `next()` and `collect()` for a Stream type that implements `poll_next`.
macro_rules! impl_stream_helpers {
    ($type:ident < $($gen:tt),+ >) => {
        impl<$($gen),+> $type<$($gen),+>
        where
            $($gen: crate::transport::Transport + 'static,)+
        {
            /// Get the next varbind, or None when complete.
            pub async fn next(&mut self) -> Option<crate::error::Result<crate::varbind::VarBind>> {
                std::future::poll_fn(|cx| std::pin::Pin::new(&mut *self).poll_next(cx)).await
            }

            /// Collect all remaining varbinds from the walk stream.
            ///
            /// Definite result-limit truncation is returned as an error. Consume
            /// the stream manually when partial bindings need to be retained.
            pub async fn collect(mut self) -> crate::error::Result<Vec<crate::varbind::VarBind>> {
                let mut results = Vec::new();
                while let Some(result) = self.next().await {
                    results.push(result?);
                }
                Ok(results)
            }
        }
    };
}

use std::collections::{HashSet, VecDeque};
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_core::Stream;

use crate::error::{Error, Result, WalkAbortReason};
use crate::oid::Oid;
use crate::pdu::Pdu;
use crate::transport::Transport;
use crate::varbind::VarBind;
use crate::version::Version;

use super::Client;
use super::response_shape::{BulkResponse, ResponseMetadata};

/// One walked binding plus anomalies accepted since the preceding item.
///
/// GETNEXT associates one response with one item. GETBULK associates response
/// metadata with the first yielded binding from that response, so flattening a
/// walk never duplicates anomalies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalkItem {
    pub varbind: VarBind,
    pub metadata: ResponseMetadata,
}

/// A collected walk and the anomaly aggregate for every accepted response,
/// including responses that terminate without yielding a binding.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WalkCollection {
    pub varbinds: Vec<VarBind>,
    pub metadata: ResponseMetadata,
}

/// Terminal failure from a metadata-preserving walk.
#[derive(Debug, thiserror::Error)]
#[error("walk failed: {source}")]
pub struct WalkError {
    /// The protocol, response-shape, walk-policy, or transport failure.
    #[source]
    pub source: Box<Error>,
    /// Every accepted response anomaly observed before termination.
    pub metadata: ResponseMetadata,
}

/// Walk operation mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum WalkMode {
    /// Auto-select based on version (default).
    /// V1 uses GETNEXT, V2c/V3 uses GETBULK.
    #[default]
    Auto,
    /// Always use GETNEXT (slower but more compatible).
    GetNext,
    /// Always use GETBULK (faster, errors on v1).
    GetBulk,
}

/// OID ordering behavior during walk operations.
///
/// SNMP walks rely on agents returning OIDs in strictly increasing
/// lexicographic order. However, some buggy agents violate this requirement,
/// returning OIDs out of order or even repeating OIDs (which would cause
/// infinite loops).
///
/// This enum controls how the library handles ordering violations:
///
/// - [`Strict`](Self::Strict) (default): Terminates immediately with
///   [`Error::WalkAborted`](crate::Error::WalkAborted) on any violation.
///   Use this unless you know the agent has ordering bugs.
///
/// - [`AllowNonIncreasing`](Self::AllowNonIncreasing): Tolerates out-of-order
///   OIDs but tracks all seen OIDs to detect cycles. Returns
///   [`Error::WalkAborted`](crate::Error::WalkAborted) if the same OID appears twice.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OidOrdering {
    /// Require strictly increasing OIDs (default).
    ///
    /// Walk terminates with [`Error::WalkAborted`](crate::Error::WalkAborted)
    /// on first violation. Most efficient: O(1) memory, O(1) per-item check.
    #[default]
    Strict,

    /// Allow non-increasing OIDs, with cycle detection.
    ///
    /// Some buggy agents return OIDs out of order. This mode tracks all seen
    /// OIDs in a `HashSet` to detect cycles, terminating with an error if the
    /// same OID is returned twice.
    ///
    /// **Warning**: This uses O(n) memory where n = number of walk results.
    /// Always pair with [`ClientBuilder::max_walk_results`] to bound memory
    /// usage. Cycle detection only catches duplicate OIDs; a pathological
    /// agent could still return an infinite sequence of unique OIDs within
    /// the subtree.
    ///
    /// [`ClientBuilder::max_walk_results`]: crate::ClientBuilder::max_walk_results
    AllowNonIncreasing,
}

enum OidTracker {
    Strict { last: Option<Oid> },
    Relaxed { seen: HashSet<Oid> },
}

/// Outcome of validating a single varbind from a walk response.
enum VarbindOutcome {
    /// Varbind is valid and within the subtree; emit it.
    Yield,
    /// Walk is complete (end-of-MIB or out-of-subtree).
    Done,
    /// Walk should abort with the given error.
    Abort(Box<Error>),
}

/// Validate a varbind received during a walk.
///
/// Checks end-of-MIB, subtree containment, and OID ordering.
/// Returns the outcome, updating `oid_tracker` on success.
fn validate_walk_varbind(
    vb: &VarBind,
    base_oid: &Oid,
    oid_tracker: &mut OidTracker,
    target: std::net::SocketAddr,
) -> VarbindOutcome {
    if vb.value.is_exception() {
        return VarbindOutcome::Done;
    }
    if !vb.oid.starts_with(base_oid) {
        return VarbindOutcome::Done;
    }
    match oid_tracker.check(&vb.oid, target) {
        Ok(()) => VarbindOutcome::Yield,
        Err(e) => VarbindOutcome::Abort(e),
    }
}

impl OidTracker {
    fn new(ordering: OidOrdering, cursor: &Oid) -> Self {
        match ordering {
            OidOrdering::Strict => OidTracker::Strict {
                last: Some(cursor.clone()),
            },
            OidOrdering::AllowNonIncreasing => OidTracker::Relaxed {
                seen: HashSet::new(),
            },
        }
    }

    fn check(&mut self, oid: &Oid, target: std::net::SocketAddr) -> Result<()> {
        match self {
            OidTracker::Strict { last } => {
                if let Some(prev) = last
                    && oid <= prev
                {
                    tracing::debug!(target: "async_snmp::walk", { previous_oid = %prev, current_oid = %oid, %target }, "non-increasing OID detected");
                    return Err(Error::WalkAborted {
                        target,
                        reason: WalkAbortReason::NonIncreasing,
                    }
                    .boxed());
                }
                *last = Some(oid.clone());
                Ok(())
            }
            OidTracker::Relaxed { seen } => {
                if !seen.insert(oid.clone()) {
                    tracing::debug!(target: "async_snmp::walk", { %oid, %target }, "duplicate OID detected (cycle)");
                    return Err(Error::WalkAborted {
                        target,
                        reason: WalkAbortReason::Cycle,
                    }
                    .boxed());
                }
                Ok(())
            }
        }
    }
}

/// Async stream for walking an OID subtree using GETNEXT.
///
/// Created by [`Client::walk_getnext()`].
pub struct Walk<T: Transport> {
    client: Client<T>,
    base_oid: Oid,
    current_oid: Oid,
    /// OID tracker for ordering validation.
    oid_tracker: OidTracker,
    /// Maximum number of results to return (None = unlimited).
    max_results: Option<usize>,
    /// Count of results returned so far.
    count: usize,
    done: bool,
    metadata: ResponseMetadata,
    pending: Option<
        Pin<
            Box<
                dyn std::future::Future<Output = Result<crate::client::FixedCardinalityResponse>>
                    + Send,
            >,
        >,
    >,
}

impl<T: Transport> Walk<T> {
    pub(crate) fn new(
        client: Client<T>,
        oid: Oid,
        ordering: OidOrdering,
        max_results: Option<usize>,
    ) -> Self {
        let oid_tracker = OidTracker::new(ordering, &oid);
        Self {
            client,
            base_oid: oid.clone(),
            current_oid: oid,
            oid_tracker,
            max_results,
            count: 0,
            done: false,
            metadata: ResponseMetadata::default(),
            pending: None,
        }
    }
}

impl_stream_helpers!(Walk<T>);

impl<T: Transport + 'static> Walk<T> {
    fn poll_next_with_metadata(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<WalkItem>>> {
        if self.done {
            return Poll::Ready(None);
        }

        let result_limit = self.max_results.filter(|limit| self.count >= *limit);

        // Check if we have a pending request
        if self.pending.is_none() {
            // Start a new GETNEXT request
            let client = self.client.clone();
            let oid = self.current_oid.clone();

            let fut = Box::pin(async move { client.get_next(&oid).await });
            self.pending = Some(fut);
        }

        // Poll the pending future
        let pending = self.pending.as_mut().unwrap();
        match pending.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.pending = None;

                match result {
                    Ok(response) if result_limit.is_some() && response.varbinds.is_empty() => {
                        self.metadata.append(response.metadata);
                        self.done = true;
                        Poll::Ready(None)
                    }
                    Ok(mut response)
                        if response.anomalies.is_empty() && response.varbinds.len() == 1 =>
                    {
                        let item_metadata = std::mem::take(&mut response.metadata);
                        self.metadata.append(item_metadata.clone());
                        let vb = response.varbinds.into_iter().next().unwrap();
                        let target = self.client.peer_addr();
                        let base_oid = self.base_oid.clone();
                        match validate_walk_varbind(&vb, &base_oid, &mut self.oid_tracker, target) {
                            VarbindOutcome::Done => {
                                self.done = true;
                                return Poll::Ready(None);
                            }
                            VarbindOutcome::Abort(e) => {
                                self.done = true;
                                return Poll::Ready(Some(Err(e)));
                            }
                            VarbindOutcome::Yield => {}
                        }

                        if let Some(limit) = result_limit {
                            self.done = true;
                            return Poll::Ready(Some(Err(Error::WalkAborted {
                                target,
                                reason: WalkAbortReason::ResultLimitExceeded { limit },
                            }
                            .boxed())));
                        }

                        // Update current OID for next iteration
                        self.current_oid = vb.oid.clone();
                        self.count += 1;

                        Poll::Ready(Some(Ok(WalkItem {
                            varbind: vb,
                            metadata: item_metadata,
                        })))
                    }
                    Ok(response) => {
                        self.metadata.append(response.metadata.clone());
                        self.done = true;
                        Poll::Ready(Some(Err(Error::ResponseShape {
                            target: self.client.peer_addr(),
                            response,
                        }
                        .boxed())))
                    }
                    Err(e) => {
                        if let Some(metadata) = e.response_metadata().cloned() {
                            self.metadata.append(metadata);
                        }
                        if self.client.inner.config.version() == Version::V1
                            && matches!(
                                &*e,
                                Error::Snmp {
                                    status: crate::error::ErrorStatus::NoSuchName,
                                    ..
                                }
                            )
                        {
                            self.done = true;
                            return Poll::Ready(None);
                        }

                        self.done = true;
                        Poll::Ready(Some(Err(e)))
                    }
                }
            }
        }
    }
}

impl<T: Transport + 'static> Stream for Walk<T> {
    type Item = Result<VarBind>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.poll_next_with_metadata(cx) {
            Poll::Ready(Some(Ok(item))) => Poll::Ready(Some(Ok(item.varbind))),
            Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(error))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Async stream for walking an OID subtree using GETBULK.
///
/// Created by [`Client::bulk_walk()`].
pub struct BulkWalk<T: Transport> {
    client: Client<T>,
    base_oid: Oid,
    current_oid: Oid,
    max_repetitions: u32,
    /// OID tracker for ordering validation.
    oid_tracker: OidTracker,
    /// Maximum number of results to return (None = unlimited).
    max_results: Option<usize>,
    /// Count of results returned so far.
    count: usize,
    done: bool,
    metadata: ResponseMetadata,
    deferred_item_metadata: ResponseMetadata,
    /// Buffered results from the last GETBULK response
    buffer: VecDeque<VarBind>,
    pending: Option<Pin<Box<dyn std::future::Future<Output = Result<BulkResponse>> + Send>>>,
}

impl<T: Transport> BulkWalk<T> {
    pub(crate) fn new(
        client: Client<T>,
        oid: Oid,
        max_repetitions: u32,
        ordering: OidOrdering,
        max_results: Option<usize>,
    ) -> Result<Self> {
        Pdu::checked_get_bulk_fields(0, max_repetitions)?;
        let oid_tracker = OidTracker::new(ordering, &oid);
        Ok(Self {
            client,
            base_oid: oid.clone(),
            current_oid: oid,
            max_repetitions,
            oid_tracker,
            max_results,
            count: 0,
            done: false,
            metadata: ResponseMetadata::default(),
            deferred_item_metadata: ResponseMetadata::default(),
            buffer: VecDeque::new(),
            pending: None,
        })
    }
}

impl_stream_helpers!(BulkWalk<T>);

impl<T: Transport + 'static> BulkWalk<T> {
    fn poll_next_with_metadata(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<WalkItem>>> {
        loop {
            if self.done {
                return Poll::Ready(None);
            }

            let result_limit = self.max_results.filter(|limit| self.count >= *limit);

            // Check if we have buffered results to return, including the single
            // look-ahead candidate after the configured limit is yielded.
            if let Some(vb) = self.buffer.pop_front() {
                let target = self.client.peer_addr();
                let base_oid = self.base_oid.clone();
                match validate_walk_varbind(&vb, &base_oid, &mut self.oid_tracker, target) {
                    VarbindOutcome::Done => {
                        self.done = true;
                        return Poll::Ready(None);
                    }
                    VarbindOutcome::Abort(e) => {
                        self.done = true;
                        return Poll::Ready(Some(Err(e)));
                    }
                    VarbindOutcome::Yield => {}
                }

                if let Some(limit) = result_limit {
                    self.done = true;
                    return Poll::Ready(Some(Err(Error::WalkAborted {
                        target,
                        reason: WalkAbortReason::ResultLimitExceeded { limit },
                    }
                    .boxed())));
                }

                // Update current OID for next request
                self.current_oid = vb.oid.clone();
                self.count += 1;

                return Poll::Ready(Some(Ok(WalkItem {
                    varbind: vb,
                    metadata: std::mem::take(&mut self.deferred_item_metadata),
                })));
            }

            // Buffer exhausted, need to fetch more
            if self.pending.is_none() {
                let client = self.client.clone();
                let oid = self.current_oid.clone();
                let max_rep = if result_limit.is_some() {
                    1
                } else {
                    self.max_repetitions
                };

                let fut =
                    Box::pin(
                        async move { client.get_bulk_with_metadata(&[oid], 0, max_rep).await },
                    );
                self.pending = Some(fut);
            }

            // Poll the pending future
            let pending = self.pending.as_mut().unwrap();
            match pending.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => {
                    self.pending = None;

                    match result {
                        Ok(response) => {
                            self.metadata.append(response.metadata.clone());
                            self.deferred_item_metadata.append(response.metadata);
                            if response.varbinds.is_empty() {
                                self.done = true;
                                return Poll::Ready(None);
                            }

                            self.buffer = response.varbinds.into();
                            // Continue loop to process buffer
                        }
                        Err(mut e) => {
                            let accepted_metadata =
                                e.response_metadata().cloned().unwrap_or_default();
                            self.metadata.append(accepted_metadata.clone());
                            // On tooBig, degrade instead of aborting (RFC 3416
                            // 4.2.3): halve max-repetitions down to a floor of 1
                            // and retry the same position. Only surface the error
                            // if it still fails at max-repetitions = 1.
                            if result_limit.is_none()
                                && self.max_repetitions > 1
                                && matches!(
                                    &*e,
                                    Error::Snmp {
                                        status: crate::error::ErrorStatus::TooBig,
                                        ..
                                    }
                                )
                            {
                                self.deferred_item_metadata.append(accepted_metadata);
                                let reduced = (self.max_repetitions / 2).max(1);
                                tracing::debug!(target: "async_snmp::client", { peer = %self.client.peer_addr(), snmp.max_repetitions = self.max_repetitions, snmp.reduced_max_repetitions = reduced }, "tooBig response, reducing max-repetitions and retrying");
                                self.max_repetitions = reduced;
                                // Retry the same position with fewer repetitions.
                                continue;
                            }

                            e = e.with_prior_response_metadata(&self.deferred_item_metadata);
                            self.done = true;
                            return Poll::Ready(Some(Err(e)));
                        }
                    }
                }
            }
        }
    }
}

impl<T: Transport + 'static> Stream for BulkWalk<T> {
    type Item = Result<VarBind>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.poll_next_with_metadata(cx) {
            Poll::Ready(Some(Ok(item))) => Poll::Ready(Some(Ok(item.varbind))),
            Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(error))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// GETNEXT walk stream that retains decode metadata.
/// Terminal items use [`WalkError`] so both the source error and the cumulative
/// accepted-response metadata remain available.
#[must_use = "streams do nothing unless polled"]
pub struct WalkWithMetadata<T: Transport> {
    inner: Walk<T>,
}

impl<T: Transport> WalkWithMetadata<T> {
    pub(crate) fn new(inner: Walk<T>) -> Self {
        Self { inner }
    }

    /// Aggregate metadata observed so far, including non-yielding terminal responses.
    pub fn metadata(&self) -> &ResponseMetadata {
        &self.inner.metadata
    }
}

impl<T: Transport + 'static> WalkWithMetadata<T> {
    pub async fn next(&mut self) -> Option<std::result::Result<WalkItem, WalkError>> {
        std::future::poll_fn(|cx| Pin::new(&mut *self).poll_next(cx)).await
    }

    pub async fn collect(mut self) -> std::result::Result<WalkCollection, WalkError> {
        let mut varbinds = Vec::new();
        while let Some(item) = self.next().await {
            varbinds.push(item?.varbind);
        }
        Ok(WalkCollection {
            varbinds,
            metadata: self.inner.metadata,
        })
    }
}

impl<T: Transport + 'static> Stream for WalkWithMetadata<T> {
    type Item = std::result::Result<WalkItem, WalkError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.inner.poll_next_with_metadata(cx) {
            Poll::Ready(Some(Err(source))) => Poll::Ready(Some(Err(WalkError {
                source,
                metadata: self.inner.metadata.clone(),
            }))),
            Poll::Ready(Some(Ok(item))) => Poll::Ready(Some(Ok(item))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// GETBULK walk stream that retains decode metadata without duplicating it
/// across bindings returned by the same response.
#[must_use = "streams do nothing unless polled"]
pub struct BulkWalkWithMetadata<T: Transport> {
    inner: BulkWalk<T>,
}

impl<T: Transport> BulkWalkWithMetadata<T> {
    pub(crate) fn new(inner: BulkWalk<T>) -> Self {
        Self { inner }
    }

    /// Aggregate metadata observed so far, including non-yielding terminal responses.
    pub fn metadata(&self) -> &ResponseMetadata {
        &self.inner.metadata
    }
}

impl<T: Transport + 'static> BulkWalkWithMetadata<T> {
    pub async fn next(&mut self) -> Option<std::result::Result<WalkItem, WalkError>> {
        std::future::poll_fn(|cx| Pin::new(&mut *self).poll_next(cx)).await
    }

    pub async fn collect(mut self) -> std::result::Result<WalkCollection, WalkError> {
        let mut varbinds = Vec::new();
        while let Some(item) = self.next().await {
            varbinds.push(item?.varbind);
        }
        Ok(WalkCollection {
            varbinds,
            metadata: self.inner.metadata,
        })
    }
}

impl<T: Transport + 'static> Stream for BulkWalkWithMetadata<T> {
    type Item = std::result::Result<WalkItem, WalkError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.inner.poll_next_with_metadata(cx) {
            Poll::Ready(Some(Err(source))) => Poll::Ready(Some(Err(WalkError {
                source,
                metadata: self.inner.metadata.clone(),
            }))),
            Poll::Ready(Some(Ok(item))) => Poll::Ready(Some(Ok(item))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

// ============================================================================
// Unified WalkStream - auto-selects GETNEXT or GETBULK based on WalkMode
// ============================================================================

/// Unified walk stream that auto-selects between GETNEXT and GETBULK.
///
/// Created by [`Client::walk()`] when using `WalkMode::Auto` or explicit mode selection.
/// This type wraps either a [`Walk`] or [`BulkWalk`] internally based on:
/// - `WalkMode::Auto`: Uses GETNEXT for V1, GETBULK for V2c/V3
/// - `WalkMode::GetNext`: Always uses GETNEXT
/// - `WalkMode::GetBulk`: Always uses GETBULK (fails on V1)
pub enum WalkStream<T: Transport> {
    /// GETNEXT-based walk (used for V1 or when explicitly requested)
    GetNext(Walk<T>),
    /// GETBULK-based walk (used for V2c/V3 or when explicitly requested)
    GetBulk(BulkWalk<T>),
}

impl<T: Transport> WalkStream<T> {
    /// Create a new walk stream with auto-selection based on version and walk mode.
    pub(crate) fn new(
        client: Client<T>,
        oid: Oid,
        version: Version,
        walk_mode: WalkMode,
        ordering: OidOrdering,
        max_results: Option<usize>,
        max_repetitions: u32,
    ) -> Result<Self> {
        let use_bulk = match walk_mode {
            WalkMode::Auto => version != Version::V1,
            WalkMode::GetNext => false,
            WalkMode::GetBulk => {
                if version == Version::V1 {
                    return Err(Error::Config("GETBULK is not supported in SNMPv1".into()).boxed());
                }
                true
            }
        };

        Ok(if use_bulk {
            WalkStream::GetBulk(BulkWalk::new(
                client,
                oid,
                max_repetitions,
                ordering,
                max_results,
            )?)
        } else {
            WalkStream::GetNext(Walk::new(client, oid, ordering, max_results))
        })
    }
}

impl<T: Transport + 'static> WalkStream<T> {
    /// Get the next varbind, or None when complete.
    pub async fn next(&mut self) -> Option<Result<VarBind>> {
        std::future::poll_fn(|cx| Pin::new(&mut *self).poll_next(cx)).await
    }

    /// Collect all remaining varbinds from the walk stream.
    ///
    /// Definite result-limit truncation is returned as an error. Consume the
    /// stream manually when partial bindings need to be retained.
    pub async fn collect(mut self) -> Result<Vec<VarBind>> {
        let mut results = Vec::new();
        while let Some(result) = self.next().await {
            results.push(result?);
        }
        Ok(results)
    }
}

impl<T: Transport + 'static> Stream for WalkStream<T> {
    type Item = Result<VarBind>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // SAFETY: We're just projecting the pin to the inner enum variant
        match self.get_mut() {
            WalkStream::GetNext(walk) => Pin::new(walk).poll_next(cx),
            WalkStream::GetBulk(bulk_walk) => Pin::new(bulk_walk).poll_next(cx),
        }
    }
}

/// Auto-selected GETNEXT/GETBULK walk stream with decode metadata.
pub enum WalkStreamWithMetadata<T: Transport> {
    GetNext(WalkWithMetadata<T>),
    GetBulk(BulkWalkWithMetadata<T>),
}

impl<T: Transport> WalkStreamWithMetadata<T> {
    pub(crate) fn new(inner: WalkStream<T>) -> Self {
        match inner {
            WalkStream::GetNext(walk) => Self::GetNext(WalkWithMetadata::new(walk)),
            WalkStream::GetBulk(walk) => Self::GetBulk(BulkWalkWithMetadata::new(walk)),
        }
    }

    /// Aggregate metadata observed so far.
    pub fn metadata(&self) -> &ResponseMetadata {
        match self {
            Self::GetNext(walk) => walk.metadata(),
            Self::GetBulk(walk) => walk.metadata(),
        }
    }
}

impl<T: Transport + 'static> WalkStreamWithMetadata<T> {
    pub async fn next(&mut self) -> Option<std::result::Result<WalkItem, WalkError>> {
        std::future::poll_fn(|cx| Pin::new(&mut *self).poll_next(cx)).await
    }

    pub async fn collect(mut self) -> std::result::Result<WalkCollection, WalkError> {
        let mut varbinds = Vec::new();
        while let Some(item) = self.next().await {
            varbinds.push(item?.varbind);
        }
        Ok(WalkCollection {
            varbinds,
            metadata: self.metadata().clone(),
        })
    }
}

impl<T: Transport + 'static> Stream for WalkStreamWithMetadata<T> {
    type Item = std::result::Result<WalkItem, WalkError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.get_mut() {
            Self::GetNext(walk) => Pin::new(walk).poll_next(cx),
            Self::GetBulk(walk) => Pin::new(walk).poll_next(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oid;
    use crate::value::Value;

    fn target_addr() -> std::net::SocketAddr {
        "127.0.0.1:161".parse().unwrap()
    }

    #[test]
    fn test_walk_terminates_on_no_such_object() {
        let base = oid!(1, 3, 6, 1, 2, 1, 1);
        let mut tracker = OidTracker::new(OidOrdering::Strict, &base);
        let vb = VarBind::new(oid!(1, 3, 6, 1, 2, 1, 1, 1, 0), Value::NoSuchObject);
        assert!(matches!(
            validate_walk_varbind(&vb, &base, &mut tracker, target_addr()),
            VarbindOutcome::Done
        ));
    }

    #[test]
    fn test_walk_terminates_on_no_such_instance() {
        let base = oid!(1, 3, 6, 1, 2, 1, 1);
        let mut tracker = OidTracker::new(OidOrdering::Strict, &base);
        let vb = VarBind::new(oid!(1, 3, 6, 1, 2, 1, 1, 1, 0), Value::NoSuchInstance);
        assert!(matches!(
            validate_walk_varbind(&vb, &base, &mut tracker, target_addr()),
            VarbindOutcome::Done
        ));
    }

    #[test]
    fn test_walk_terminates_on_end_of_mib_view() {
        let base = oid!(1, 3, 6, 1, 2, 1, 1);
        let mut tracker = OidTracker::new(OidOrdering::Strict, &base);
        let vb = VarBind::new(oid!(1, 3, 6, 1, 2, 1, 1, 1, 0), Value::EndOfMibView);
        assert!(matches!(
            validate_walk_varbind(&vb, &base, &mut tracker, target_addr()),
            VarbindOutcome::Done
        ));
    }

    #[test]
    fn test_walk_yields_normal_value() {
        let base = oid!(1, 3, 6, 1, 2, 1, 1);
        let mut tracker = OidTracker::new(OidOrdering::Strict, &base);
        let vb = VarBind::new(oid!(1, 3, 6, 1, 2, 1, 1, 1, 0), Value::Integer(42));
        assert!(matches!(
            validate_walk_varbind(&vb, &base, &mut tracker, target_addr()),
            VarbindOutcome::Yield
        ));
    }

    #[test]
    fn test_walk_strict_rejects_equal_first_result() {
        let base = oid!(1, 3, 6, 1, 2, 1, 1);
        let mut tracker = OidTracker::new(OidOrdering::Strict, &base);
        let vb = VarBind::new(base.clone(), Value::Integer(1));

        match validate_walk_varbind(&vb, &base, &mut tracker, target_addr()) {
            VarbindOutcome::Abort(e) => match *e {
                Error::WalkAborted { reason, .. } => {
                    assert_eq!(reason, WalkAbortReason::NonIncreasing);
                }
                other => panic!("expected WalkAborted, got {other:?}"),
            },
            _ => panic!("expected Abort outcome"),
        }
    }

    #[test]
    fn test_walk_relaxed_allows_equal_first_result_then_detects_cycle() {
        let base = oid!(1, 3, 6, 1, 2, 1, 1);
        let mut tracker = OidTracker::new(OidOrdering::AllowNonIncreasing, &base);
        let vb = VarBind::new(base.clone(), Value::Integer(1));

        assert!(matches!(
            validate_walk_varbind(&vb, &base, &mut tracker, target_addr()),
            VarbindOutcome::Yield
        ));

        match validate_walk_varbind(&vb, &base, &mut tracker, target_addr()) {
            VarbindOutcome::Abort(e) => match *e {
                Error::WalkAborted { reason, .. } => {
                    assert_eq!(reason, WalkAbortReason::Cycle);
                }
                other => panic!("expected WalkAborted, got {other:?}"),
            },
            _ => panic!("expected Abort outcome"),
        }
    }

    #[test]
    fn test_walk_strict_aborts_on_non_increasing_oid() {
        let base = oid!(1, 3, 6, 1, 2, 1, 1);
        let mut tracker = OidTracker::new(OidOrdering::Strict, &base);

        let vb1 = VarBind::new(oid!(1, 3, 6, 1, 2, 1, 1, 2, 0), Value::Integer(1));
        assert!(matches!(
            validate_walk_varbind(&vb1, &base, &mut tracker, target_addr()),
            VarbindOutcome::Yield
        ));

        // A lower in-subtree OID must abort with NonIncreasing.
        let vb2 = VarBind::new(oid!(1, 3, 6, 1, 2, 1, 1, 1, 0), Value::Integer(2));
        match validate_walk_varbind(&vb2, &base, &mut tracker, target_addr()) {
            VarbindOutcome::Abort(e) => match *e {
                Error::WalkAborted { reason, .. } => {
                    assert_eq!(reason, WalkAbortReason::NonIncreasing);
                }
                other => panic!("expected WalkAborted, got {other:?}"),
            },
            _ => panic!("expected Abort outcome"),
        }
    }

    #[test]
    fn test_walk_strict_aborts_on_equal_oid() {
        let base = oid!(1, 3, 6, 1, 2, 1, 1);
        let mut tracker = OidTracker::new(OidOrdering::Strict, &base);

        let vb1 = VarBind::new(oid!(1, 3, 6, 1, 2, 1, 1, 2, 0), Value::Integer(1));
        assert!(matches!(
            validate_walk_varbind(&vb1, &base, &mut tracker, target_addr()),
            VarbindOutcome::Yield
        ));

        // Same OID again (the `<=` boundary) must also abort with NonIncreasing.
        let vb2 = VarBind::new(oid!(1, 3, 6, 1, 2, 1, 1, 2, 0), Value::Integer(1));
        match validate_walk_varbind(&vb2, &base, &mut tracker, target_addr()) {
            VarbindOutcome::Abort(e) => match *e {
                Error::WalkAborted { reason, .. } => {
                    assert_eq!(reason, WalkAbortReason::NonIncreasing);
                }
                other => panic!("expected WalkAborted, got {other:?}"),
            },
            _ => panic!("expected Abort outcome"),
        }
    }

    #[test]
    fn test_walk_relaxed_aborts_on_duplicate_oid_cycle() {
        let base = oid!(1, 3, 6, 1, 2, 1, 1);
        let mut tracker = OidTracker::new(OidOrdering::AllowNonIncreasing, &base);

        let vb1 = VarBind::new(oid!(1, 3, 6, 1, 2, 1, 1, 2, 0), Value::Integer(1));
        assert!(matches!(
            validate_walk_varbind(&vb1, &base, &mut tracker, target_addr()),
            VarbindOutcome::Yield
        ));

        // Same OID again must abort with Cycle (not NonIncreasing).
        let vb2 = VarBind::new(oid!(1, 3, 6, 1, 2, 1, 1, 2, 0), Value::Integer(1));
        match validate_walk_varbind(&vb2, &base, &mut tracker, target_addr()) {
            VarbindOutcome::Abort(e) => match *e {
                Error::WalkAborted { reason, .. } => {
                    assert_eq!(reason, WalkAbortReason::Cycle);
                }
                other => panic!("expected WalkAborted, got {other:?}"),
            },
            _ => panic!("expected Abort outcome"),
        }
    }

    #[test]
    fn test_walk_relaxed_allows_non_increasing_distinct_oid() {
        let base = oid!(1, 3, 6, 1, 2, 1, 1);
        let mut tracker = OidTracker::new(OidOrdering::AllowNonIncreasing, &base);

        // Higher OID first.
        let vb1 = VarBind::new(oid!(1, 3, 6, 1, 2, 1, 1, 3, 0), Value::Integer(1));
        assert!(matches!(
            validate_walk_varbind(&vb1, &base, &mut tracker, target_addr()),
            VarbindOutcome::Yield
        ));

        // Lower, but distinct, in-subtree OID: relaxed mode tolerates this (no abort).
        let vb2 = VarBind::new(oid!(1, 3, 6, 1, 2, 1, 1, 1, 0), Value::Integer(2));
        assert!(matches!(
            validate_walk_varbind(&vb2, &base, &mut tracker, target_addr()),
            VarbindOutcome::Yield
        ));
    }

    // -------------------------------------------------------------------------
    // Mock transport that returns tooBig for GETBULK when max-repetitions
    // exceeds a threshold, otherwise returns a terminating response. Used to
    // exercise BulkWalk degradation (RFC 3416 4.2.3): on tooBig the walk halves
    // max-repetitions and retries the same position instead of aborting.
    // -------------------------------------------------------------------------

    use crate::client::ClientConfig;
    use crate::error::ErrorStatus;
    use crate::message::CommunityMessage;
    use crate::pdu::{Pdu, PduType};
    use bytes::Bytes;
    use std::collections::VecDeque;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct BulkTooBigTransport {
        /// Highest max-repetitions the agent will accept; larger requests return tooBig.
        max_repetitions: u32,
        /// Records (request_id, max_repetitions) seen by `send`, drained by `recv`.
        pending: Arc<Mutex<VecDeque<(i32, u32)>>>,
        /// Total number of tooBig responses emitted.
        too_big_count: Arc<Mutex<usize>>,
    }

    impl BulkTooBigTransport {
        fn new(max_repetitions: u32) -> Self {
            Self {
                max_repetitions,
                pending: Arc::new(Mutex::new(VecDeque::new())),
                too_big_count: Arc::new(Mutex::new(0)),
            }
        }
    }

    impl Transport for BulkTooBigTransport {
        fn send(&self, data: &[u8]) -> impl std::future::Future<Output = Result<()>> + Send {
            let request_id = crate::transport::extract_request_id(data).unwrap_or(1);
            let msg = CommunityMessage::decode(Bytes::copy_from_slice(data)).unwrap();
            let pdu = msg.pdu().standard().unwrap();
            let (_, max_rep) = pdu
                .get_bulk_fields()
                .expect("walk request must contain typed GETBULK fields");
            self.pending
                .lock()
                .unwrap()
                .push_back((request_id, max_rep));
            async { Ok(()) }
        }

        fn recv(
            &self,
            _registration: crate::transport::RequestRegistration,
        ) -> impl std::future::Future<Output = Result<(Bytes, SocketAddr)>> + Send {
            let (request_id, max_rep) = self.pending.lock().unwrap().pop_front().unwrap_or((1, 0));
            let threshold = self.max_repetitions;
            let too_big_count = self.too_big_count.clone();
            let peer: SocketAddr = "127.0.0.1:161".parse().unwrap();

            async move {
                let pdu = if max_rep > threshold {
                    *too_big_count.lock().unwrap() += 1;
                    Pdu::response(request_id, ErrorStatus::TooBig.as_i32(), 0, vec![])
                } else {
                    // One in-subtree value, then EndOfMibView to terminate the walk.
                    let varbinds = vec![
                        VarBind::new(oid!(1, 3, 6, 1, 2, 1, 2, 1, 0), Value::Integer(1)),
                        VarBind::new(oid!(1, 3, 6, 1, 2, 1, 2, 2, 0), Value::EndOfMibView),
                    ];
                    Pdu::response(request_id, 0, 0, varbinds)
                };

                let msg = CommunityMessage::v2c(Bytes::from_static(b"public"), pdu).unwrap();
                Ok((msg.encode().unwrap(), peer))
            }
        }

        fn recv_with<T, F>(
            &self,
            registration: crate::transport::RequestRegistration,
            validate: F,
        ) -> impl std::future::Future<Output = Result<T>> + Send
        where
            T: Send,
            F: FnMut(Bytes, SocketAddr) -> Result<crate::transport::Candidate<T>> + Send,
        {
            crate::transport::recv_with_scripted(
                registration,
                self.peer_addr(),
                move |registration| {
                    futures_util::stream::once(async move { self.recv(registration).await })
                },
                validate,
            )
        }

        fn peer_addr(&self) -> SocketAddr {
            "127.0.0.1:161".parse().unwrap()
        }

        fn local_addr(&self) -> SocketAddr {
            "127.0.0.1:0".parse().unwrap()
        }

        fn is_reliable(&self) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn bulk_walk_degrades_max_repetitions_on_too_big() {
        // Agent accepts at most max-repetitions=4. Starting at 25, the walk must
        // halve (25 -> 12 -> 6 -> 3) and retry the same position until it fits,
        // rather than surfacing the tooBig error.
        let transport = BulkTooBigTransport::new(4);
        let too_big_count = transport.too_big_count.clone();
        let config = ClientConfig {
            auth: crate::Auth::v2c("public"),
            retry: crate::client::retry::Retry::none(),
            ..Default::default()
        };
        let client = Client::new(transport, config).expect("valid client config");

        let results = client
            .bulk_walk(oid!(1, 3, 6, 1, 2, 1, 2), 25)
            .unwrap()
            .collect()
            .await
            .unwrap();

        // The reduced request succeeded and yielded the in-subtree varbind.
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].oid, oid!(1, 3, 6, 1, 2, 1, 2, 1, 0));
        // At least one tooBig was observed and recovered from.
        assert!(*too_big_count.lock().unwrap() >= 1);
    }

    #[tokio::test]
    async fn bulk_walk_too_big_at_min_repetitions_is_unrecoverable() {
        // Agent returns tooBig even at max-repetitions=1: degradation bottoms out
        // and the error is surfaced.
        let transport = BulkTooBigTransport::new(0);
        let config = ClientConfig {
            auth: crate::Auth::v2c("public"),
            retry: crate::client::retry::Retry::none(),
            ..Default::default()
        };
        let client = Client::new(transport, config).expect("valid client config");

        let err = client
            .bulk_walk(oid!(1, 3, 6, 1, 2, 1, 2), 8)
            .unwrap()
            .collect()
            .await
            .unwrap_err();

        assert!(
            matches!(
                &*err,
                Error::Snmp {
                    status: ErrorStatus::TooBig,
                    ..
                }
            ),
            "expected TooBig, got: {err}"
        );
    }

    // -------------------------------------------------------------------------
    // Mock transport for empty-walk consumption tests. Every walk request gets
    // an EndOfMibView response, and all request PDU types are recorded so tests
    // can detect any hidden GET issued by a consumer.
    // -------------------------------------------------------------------------

    type RequestLog = Arc<Mutex<Vec<PduType>>>;

    #[derive(Clone)]
    struct EmptyWalkTransport {
        pending: Arc<Mutex<VecDeque<(i32, PduType)>>>,
        requests: RequestLog,
    }

    impl EmptyWalkTransport {
        fn new() -> (Self, RequestLog) {
            let requests = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    pending: Arc::new(Mutex::new(VecDeque::new())),
                    requests: requests.clone(),
                },
                requests,
            )
        }
    }

    impl Transport for EmptyWalkTransport {
        fn send(&self, data: &[u8]) -> impl std::future::Future<Output = Result<()>> + Send {
            let request_id = crate::transport::extract_request_id(data).unwrap_or(1);
            let msg = CommunityMessage::decode(Bytes::copy_from_slice(data)).unwrap();
            let pdu_type = msg.pdu().standard().unwrap().pdu_type();
            self.pending
                .lock()
                .unwrap()
                .push_back((request_id, pdu_type));
            self.requests.lock().unwrap().push(pdu_type);
            async { Ok(()) }
        }

        fn recv(
            &self,
            _registration: crate::transport::RequestRegistration,
        ) -> impl std::future::Future<Output = Result<(Bytes, SocketAddr)>> + Send {
            let (request_id, _) = self.pending.lock().unwrap().pop_front().unwrap();
            let peer: SocketAddr = "127.0.0.1:161".parse().unwrap();

            async move {
                let pdu = Pdu::response(
                    request_id,
                    0,
                    0,
                    vec![VarBind::new(
                        oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
                        Value::EndOfMibView,
                    )],
                );
                let msg = CommunityMessage::v2c(Bytes::from_static(b"public"), pdu).unwrap();
                Ok((msg.encode().unwrap(), peer))
            }
        }

        fn recv_with<T, F>(
            &self,
            registration: crate::transport::RequestRegistration,
            validate: F,
        ) -> impl std::future::Future<Output = Result<T>> + Send
        where
            T: Send,
            F: FnMut(Bytes, SocketAddr) -> Result<crate::transport::Candidate<T>> + Send,
        {
            crate::transport::recv_with_scripted(
                registration,
                self.peer_addr(),
                move |registration| {
                    futures_util::stream::once(async move { self.recv(registration).await })
                },
                validate,
            )
        }

        fn peer_addr(&self) -> SocketAddr {
            "127.0.0.1:161".parse().unwrap()
        }

        fn local_addr(&self) -> SocketAddr {
            "127.0.0.1:0".parse().unwrap()
        }

        fn is_reliable(&self) -> bool {
            true
        }
    }

    fn empty_walk_client(
        max_walk_results: Option<usize>,
    ) -> (Client<EmptyWalkTransport>, RequestLog) {
        let (transport, requests) = EmptyWalkTransport::new();
        let config = ClientConfig {
            auth: crate::Auth::v2c("public"),
            retry: crate::client::retry::Retry::none(),
            max_walk_results,
            ..Default::default()
        };
        (
            Client::new(transport, config).expect("valid client config"),
            requests,
        )
    }

    fn assert_requests(requests: &RequestLog, expected: &[PduType]) {
        assert_eq!(requests.lock().unwrap().as_slice(), expected);
    }

    fn normalize(items: Vec<Result<VarBind>>) -> Result<Vec<VarBind>> {
        items.into_iter().collect()
    }

    #[test]
    fn bulk_walk_constructor_checks_max_repetitions_before_stream_creation() {
        let base = oid!(1, 3, 6, 1);

        for max_repetitions in [0, crate::pdu::MAX_GET_BULK_VALUE] {
            let (client, requests) = empty_walk_client(None);
            assert!(
                BulkWalk::new(
                    client,
                    base.clone(),
                    max_repetitions,
                    OidOrdering::Strict,
                    None,
                )
                .is_ok()
            );
            assert_requests(&requests, &[]);
        }

        let (client, requests) = empty_walk_client(None);
        let error = BulkWalk::new(
            client,
            base,
            crate::pdu::MAX_GET_BULK_VALUE + 1,
            OidOrdering::Strict,
            None,
        )
        .err()
        .expect("out-of-range value must not construct a stream");
        assert!(matches!(*error, Error::InvalidMessage(_)));
        assert_requests(&requests, &[]);
    }

    #[tokio::test]
    async fn walk_consumers_share_empty_sequence_and_request_pattern() {
        let base = oid!(1, 3, 6, 1, 2, 1, 1, 1, 0);

        let (client, requests) = empty_walk_client(None);
        let mut walk = client.walk_getnext(base.clone());
        assert!(walk.next().await.is_none());
        assert_requests(&requests, &[PduType::GetNextRequest]);

        let (client, requests) = empty_walk_client(None);
        let results = client.walk_getnext(base.clone()).collect().await.unwrap();
        assert!(results.is_empty());
        assert_requests(&requests, &[PduType::GetNextRequest]);

        let (client, requests) = empty_walk_client(None);
        let mut walk = client.walk_getnext(base.clone());
        assert!(futures::StreamExt::next(&mut walk).await.is_none());
        assert_requests(&requests, &[PduType::GetNextRequest]);

        let (client, requests) = empty_walk_client(None);
        let walk = client.walk_getnext(base.clone());
        let items: Vec<Result<VarBind>> = futures::StreamExt::collect(walk).await;
        assert!(normalize(items).unwrap().is_empty());
        assert_requests(&requests, &[PduType::GetNextRequest]);

        let (client, requests) = empty_walk_client(None);
        let mut walk = client.walk_getnext(base);
        let item = std::future::poll_fn(|cx| Stream::poll_next(Pin::new(&mut walk), cx)).await;
        assert!(item.is_none());
        assert_requests(&requests, &[PduType::GetNextRequest]);
    }

    #[tokio::test]
    async fn bulk_walk_consumers_share_empty_sequence_and_request_pattern() {
        let base = oid!(1, 3, 6, 1, 2, 1, 1, 1, 0);

        let (client, requests) = empty_walk_client(None);
        let mut walk = client.bulk_walk(base.clone(), 10).unwrap();
        assert!(walk.next().await.is_none());
        assert_requests(&requests, &[PduType::GetBulkRequest]);

        let (client, requests) = empty_walk_client(None);
        let results = client
            .bulk_walk(base.clone(), 10)
            .unwrap()
            .collect()
            .await
            .unwrap();
        assert!(results.is_empty());
        assert_requests(&requests, &[PduType::GetBulkRequest]);

        let (client, requests) = empty_walk_client(None);
        let mut walk = client.bulk_walk(base.clone(), 10).unwrap();
        assert!(futures::StreamExt::next(&mut walk).await.is_none());
        assert_requests(&requests, &[PduType::GetBulkRequest]);

        let (client, requests) = empty_walk_client(None);
        let walk = client.bulk_walk(base.clone(), 10).unwrap();
        let items: Vec<Result<VarBind>> = futures::StreamExt::collect(walk).await;
        assert!(normalize(items).unwrap().is_empty());
        assert_requests(&requests, &[PduType::GetBulkRequest]);

        let (client, requests) = empty_walk_client(None);
        let mut walk = client.bulk_walk(base, 10).unwrap();
        let item = std::future::poll_fn(|cx| Stream::poll_next(Pin::new(&mut walk), cx)).await;
        assert!(item.is_none());
        assert_requests(&requests, &[PduType::GetBulkRequest]);
    }

    #[tokio::test]
    async fn walk_stream_consumers_share_empty_sequence_and_request_pattern() {
        let base = oid!(1, 3, 6, 1, 2, 1, 1, 1, 0);

        let (client, requests) = empty_walk_client(None);
        let mut walk = client.walk(base.clone()).unwrap();
        assert!(walk.next().await.is_none());
        assert_requests(&requests, &[PduType::GetBulkRequest]);

        let (client, requests) = empty_walk_client(None);
        let results = client.walk(base.clone()).unwrap().collect().await.unwrap();
        assert!(results.is_empty());
        assert_requests(&requests, &[PduType::GetBulkRequest]);

        let (client, requests) = empty_walk_client(None);
        let mut walk = client.walk(base.clone()).unwrap();
        assert!(futures::StreamExt::next(&mut walk).await.is_none());
        assert_requests(&requests, &[PduType::GetBulkRequest]);

        let (client, requests) = empty_walk_client(None);
        let walk = client.walk(base.clone()).unwrap();
        let items: Vec<Result<VarBind>> = futures::StreamExt::collect(walk).await;
        assert!(normalize(items).unwrap().is_empty());
        assert_requests(&requests, &[PduType::GetBulkRequest]);

        let (client, requests) = empty_walk_client(None);
        let mut walk = client.walk(base).unwrap();
        let item = std::future::poll_fn(|cx| Stream::poll_next(Pin::new(&mut walk), cx)).await;
        assert!(item.is_none());
        assert_requests(&requests, &[PduType::GetBulkRequest]);
    }

    #[derive(Debug)]
    enum WalkReply {
        Response(Vec<VarBind>),
        ResponseWithSuffix(Vec<VarBind>, usize),
        Status(ErrorStatus),
        StatusWithSuffix(ErrorStatus, usize),
        Timeout,
        Closed,
    }

    type DetailedRequestLog = Arc<Mutex<Vec<(PduType, Option<u32>)>>>;

    #[derive(Clone)]
    struct ScriptedWalkTransport {
        version: Version,
        replies: Arc<Mutex<VecDeque<WalkReply>>>,
        pending: Arc<Mutex<VecDeque<i32>>>,
        requests: DetailedRequestLog,
    }

    impl ScriptedWalkTransport {
        fn new(version: Version, replies: Vec<WalkReply>) -> (Self, DetailedRequestLog) {
            let requests = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    version,
                    replies: Arc::new(Mutex::new(replies.into())),
                    pending: Arc::new(Mutex::new(VecDeque::new())),
                    requests: requests.clone(),
                },
                requests,
            )
        }
    }

    impl Transport for ScriptedWalkTransport {
        fn send(&self, data: &[u8]) -> impl std::future::Future<Output = Result<()>> + Send {
            let message = CommunityMessage::decode(Bytes::copy_from_slice(data)).unwrap();
            let pdu = message.pdu().standard().unwrap();
            let request = (
                pdu.pdu_type(),
                pdu.get_bulk_fields()
                    .map(|(_, max_repetitions)| max_repetitions),
            );
            self.pending.lock().unwrap().push_back(pdu.request_id);
            self.requests.lock().unwrap().push(request);
            async { Ok(()) }
        }

        fn recv(
            &self,
            _registration: crate::transport::RequestRegistration,
        ) -> impl std::future::Future<Output = Result<(Bytes, SocketAddr)>> + Send {
            let request_id = self.pending.lock().unwrap().pop_front().unwrap();
            let reply = self.replies.lock().unwrap().pop_front().unwrap();
            let version = self.version;
            let peer = target_addr();

            async move {
                let encode_response = |varbinds, suffix_len| {
                    let pdu = Pdu::response(request_id, 0, 0, varbinds);
                    let message = match version {
                        Version::V1 => CommunityMessage::v1(Bytes::from_static(b"public"), pdu),
                        Version::V2c => CommunityMessage::v2c(Bytes::from_static(b"public"), pdu),
                        Version::V3 => unreachable!("scripted walk uses community versions"),
                    }
                    .unwrap();
                    let mut encoded = message.encode().unwrap().to_vec();
                    encoded.extend(std::iter::repeat_n(0xa5, suffix_len));
                    Ok((Bytes::from(encoded), peer))
                };
                let encode_status = |status: ErrorStatus, suffix_len| {
                    let (error_index, varbinds) = if status == ErrorStatus::TooBig {
                        (0, vec![])
                    } else {
                        (1, vec![VarBind::null(walk_base())])
                    };
                    let pdu = Pdu::response(request_id, status.as_i32(), error_index, varbinds);
                    let message = match version {
                        Version::V1 => CommunityMessage::v1(Bytes::from_static(b"public"), pdu),
                        Version::V2c => CommunityMessage::v2c(Bytes::from_static(b"public"), pdu),
                        Version::V3 => unreachable!("scripted walk uses community versions"),
                    }
                    .unwrap();
                    let mut encoded = message.encode().unwrap().to_vec();
                    encoded.extend(std::iter::repeat_n(0xa5, suffix_len));
                    Ok((Bytes::from(encoded), peer))
                };
                match reply {
                    WalkReply::Response(varbinds) => encode_response(varbinds, 0),
                    WalkReply::ResponseWithSuffix(varbinds, suffix_len) => {
                        encode_response(varbinds, suffix_len)
                    }
                    WalkReply::Status(status) => encode_status(status, 0),
                    WalkReply::StatusWithSuffix(status, suffix_len) => {
                        encode_status(status, suffix_len)
                    }
                    WalkReply::Timeout => Err(Error::Timeout {
                        target: peer,
                        elapsed: std::time::Duration::from_secs(3),
                        retries: 2,
                    }
                    .boxed()),
                    WalkReply::Closed => Err(Error::Closed { target: peer }.boxed()),
                }
            }
        }

        fn recv_with<T, F>(
            &self,
            registration: crate::transport::RequestRegistration,
            validate: F,
        ) -> impl std::future::Future<Output = Result<T>> + Send
        where
            T: Send,
            F: FnMut(Bytes, SocketAddr) -> Result<crate::transport::Candidate<T>> + Send,
        {
            crate::transport::recv_with_scripted(
                registration,
                self.peer_addr(),
                move |registration| {
                    futures_util::stream::once(async move { self.recv(registration).await })
                },
                validate,
            )
        }

        fn peer_addr(&self) -> SocketAddr {
            target_addr()
        }

        fn local_addr(&self) -> SocketAddr {
            "127.0.0.1:0".parse().unwrap()
        }

        fn is_reliable(&self) -> bool {
            true
        }
    }

    fn scripted_walk_client(
        version: Version,
        max_walk_results: usize,
        replies: Vec<WalkReply>,
    ) -> (Client<ScriptedWalkTransport>, DetailedRequestLog) {
        let (transport, requests) = ScriptedWalkTransport::new(version, replies);
        let auth = match version {
            Version::V1 => crate::Auth::v1("public"),
            Version::V2c => crate::Auth::v2c("public"),
            Version::V3 => unreachable!("scripted walk uses community versions"),
        };
        let config = ClientConfig {
            auth,
            retry: crate::client::retry::Retry::none(),
            max_walk_results: Some(max_walk_results),
            ..Default::default()
        };
        (
            Client::new(transport, config).expect("valid client config"),
            requests,
        )
    }

    fn walk_base() -> Oid {
        oid!(1, 3, 6, 1, 2, 1, 1)
    }

    fn walk_binding(index: u32) -> VarBind {
        VarBind::new(walk_base().child(index), Value::Integer(index as i32))
    }

    fn out_of_subtree_binding() -> VarBind {
        VarBind::new(oid!(1, 3, 6, 1, 2, 2, 1), Value::Integer(99))
    }

    fn assert_result_limit(error: &Error, expected_limit: usize) {
        assert!(matches!(
            error,
            Error::WalkAborted {
                reason: WalkAbortReason::ResultLimitExceeded { limit },
                ..
            } if *limit == expected_limit
        ));
    }

    fn detailed_requests(requests: &DetailedRequestLog) -> Vec<(PduType, Option<u32>)> {
        requests.lock().unwrap().clone()
    }

    fn trailing(length: usize) -> crate::DecodeAnomaly {
        crate::DecodeAnomaly::TrailingBytes {
            original_length: length,
            canonical_length: 0,
        }
    }

    #[tokio::test]
    async fn getnext_metadata_items_and_aggregate_include_terminal_response() {
        let (client, _) = scripted_walk_client(
            Version::V2c,
            10,
            vec![
                WalkReply::ResponseWithSuffix(vec![walk_binding(1)], 1),
                WalkReply::ResponseWithSuffix(vec![out_of_subtree_binding()], 2),
            ],
        );
        let mut walk = client.walk_getnext_with_metadata(walk_base());
        let item = walk.next().await.unwrap().unwrap();
        assert_eq!(item.varbind, walk_binding(1));
        assert_eq!(item.metadata.decode_anomalies, vec![trailing(1)]);
        assert!(walk.next().await.is_none());
        assert_eq!(
            walk.metadata().decode_anomalies,
            vec![trailing(1), trailing(2)]
        );
    }

    #[tokio::test]
    async fn bulk_walk_metadata_is_not_duplicated_across_one_response() {
        let (client, _) = scripted_walk_client(
            Version::V2c,
            10,
            vec![
                WalkReply::ResponseWithSuffix(vec![walk_binding(1), walk_binding(2)], 1),
                WalkReply::ResponseWithSuffix(vec![out_of_subtree_binding()], 2),
            ],
        );
        let mut walk = client.bulk_walk_with_metadata(walk_base(), 8).unwrap();
        let first = walk.next().await.unwrap().unwrap();
        let second = walk.next().await.unwrap().unwrap();
        assert_eq!(first.metadata.decode_anomalies, vec![trailing(1)]);
        assert!(second.metadata.decode_anomalies.is_empty());
        assert!(walk.next().await.is_none());
        assert_eq!(
            walk.metadata().decode_anomalies,
            vec![trailing(1), trailing(2)]
        );
    }

    #[tokio::test]
    async fn terminal_walk_protocol_error_retains_response_metadata() {
        let (client, _) = scripted_walk_client(
            Version::V2c,
            10,
            vec![WalkReply::StatusWithSuffix(ErrorStatus::GenErr, 3)],
        );
        let error = client
            .walk_getnext_with_metadata(walk_base())
            .next()
            .await
            .unwrap()
            .unwrap_err();
        assert!(matches!(
            &*error.source,
            Error::Snmp { metadata, .. }
                if metadata.decode_anomalies == vec![trailing(3)]
        ));
        assert_eq!(error.metadata.decode_anomalies, vec![trailing(3)]);
    }

    #[tokio::test]
    async fn getnext_zero_exact_and_plus_one_limit_semantics_are_truthful() {
        let (client, requests) = scripted_walk_client(
            Version::V2c,
            0,
            vec![WalkReply::Response(vec![walk_binding(1)])],
        );
        let mut walk = client.walk_getnext(walk_base());
        let error = walk.next().await.unwrap().unwrap_err();
        assert_result_limit(&error, 0);
        assert!(walk.next().await.is_none());
        assert_eq!(
            detailed_requests(&requests),
            vec![(PduType::GetNextRequest, None)]
        );

        let (client, requests) = scripted_walk_client(
            Version::V2c,
            2,
            vec![
                WalkReply::Response(vec![walk_binding(1)]),
                WalkReply::Response(vec![walk_binding(2)]),
                WalkReply::Response(vec![out_of_subtree_binding()]),
            ],
        );
        let results = client.walk_getnext(walk_base()).collect().await.unwrap();
        assert_eq!(results, vec![walk_binding(1), walk_binding(2)]);
        assert_eq!(detailed_requests(&requests).len(), 3);

        let (client, requests) = scripted_walk_client(
            Version::V2c,
            2,
            vec![
                WalkReply::Response(vec![walk_binding(1)]),
                WalkReply::Response(vec![walk_binding(2)]),
                WalkReply::Response(vec![walk_binding(3)]),
            ],
        );
        let mut walk = client.walk_getnext(walk_base());
        assert_eq!(walk.next().await.unwrap().unwrap(), walk_binding(1));
        assert_eq!(walk.next().await.unwrap().unwrap(), walk_binding(2));
        let error = walk.next().await.unwrap().unwrap_err();
        assert_result_limit(&error, 2);
        assert!(walk.next().await.is_none());
        assert_eq!(detailed_requests(&requests).len(), 3);
    }

    #[tokio::test]
    async fn getbulk_zero_exact_and_plus_one_use_buffered_probe_candidates() {
        let (client, requests) = scripted_walk_client(
            Version::V2c,
            0,
            vec![WalkReply::Response(vec![walk_binding(1)])],
        );
        let error = client
            .bulk_walk(walk_base(), 9)
            .unwrap()
            .next()
            .await
            .unwrap()
            .unwrap_err();
        assert_result_limit(&error, 0);
        assert_eq!(
            detailed_requests(&requests),
            vec![(PduType::GetBulkRequest, Some(1))]
        );

        let (client, requests) = scripted_walk_client(
            Version::V2c,
            2,
            vec![WalkReply::Response(vec![
                walk_binding(1),
                walk_binding(2),
                out_of_subtree_binding(),
            ])],
        );
        let results = client
            .bulk_walk(walk_base(), 9)
            .unwrap()
            .collect()
            .await
            .unwrap();
        assert_eq!(results, vec![walk_binding(1), walk_binding(2)]);
        assert_eq!(
            detailed_requests(&requests),
            vec![(PduType::GetBulkRequest, Some(9))]
        );

        let (client, requests) = scripted_walk_client(
            Version::V2c,
            2,
            vec![WalkReply::Response(vec![
                walk_binding(1),
                walk_binding(2),
                walk_binding(3),
                walk_binding(4),
            ])],
        );
        let mut walk = client.bulk_walk(walk_base(), 9).unwrap();
        assert_eq!(walk.next().await.unwrap().unwrap(), walk_binding(1));
        assert_eq!(walk.next().await.unwrap().unwrap(), walk_binding(2));
        let error = walk.next().await.unwrap().unwrap_err();
        assert_result_limit(&error, 2);
        assert!(walk.next().await.is_none());
        assert_eq!(
            detailed_requests(&requests),
            vec![(PduType::GetBulkRequest, Some(9))]
        );
    }

    #[tokio::test]
    async fn getbulk_additional_probe_uses_one_max_repetition() {
        let (client, requests) = scripted_walk_client(
            Version::V2c,
            2,
            vec![
                WalkReply::Response(vec![walk_binding(1), walk_binding(2)]),
                WalkReply::Response(vec![]),
            ],
        );
        let results = client
            .bulk_walk(walk_base(), 8)
            .unwrap()
            .collect()
            .await
            .unwrap();
        assert_eq!(results, vec![walk_binding(1), walk_binding(2)]);
        assert_eq!(
            detailed_requests(&requests),
            vec![
                (PduType::GetBulkRequest, Some(8)),
                (PduType::GetBulkRequest, Some(1)),
            ]
        );

        let (client, requests) = scripted_walk_client(
            Version::V2c,
            2,
            vec![
                WalkReply::Response(vec![walk_binding(1), walk_binding(2)]),
                WalkReply::Response(vec![walk_binding(3), walk_binding(4)]),
            ],
        );
        let error = client
            .bulk_walk(walk_base(), 8)
            .unwrap()
            .collect()
            .await
            .unwrap_err();
        assert_result_limit(&error, 2);
        assert_eq!(
            detailed_requests(&requests),
            vec![
                (PduType::GetBulkRequest, Some(8)),
                (PduType::GetBulkRequest, Some(1)),
            ]
        );
    }

    #[tokio::test]
    async fn getbulk_additional_empty_out_of_subtree_and_exception_probes_complete() {
        let completion_replies = [
            vec![],
            vec![out_of_subtree_binding()],
            vec![VarBind::new(walk_base().child(1), Value::EndOfMibView)],
        ];

        for reply in completion_replies {
            let (client, requests) = scripted_walk_client(
                Version::V2c,
                1,
                vec![
                    WalkReply::Response(vec![walk_binding(1)]),
                    WalkReply::Response(reply),
                ],
            );
            let results = client
                .bulk_walk(walk_base(), 6)
                .unwrap()
                .collect()
                .await
                .unwrap();
            assert_eq!(results, vec![walk_binding(1)]);
            assert_eq!(
                detailed_requests(&requests),
                vec![
                    (PduType::GetBulkRequest, Some(6)),
                    (PduType::GetBulkRequest, Some(1)),
                ]
            );
        }
    }

    #[tokio::test]
    async fn empty_out_of_subtree_exception_and_v1_no_such_name_probes_complete() {
        let completion_replies = [
            vec![],
            vec![out_of_subtree_binding()],
            vec![VarBind::new(walk_base(), Value::EndOfMibView)],
        ];

        for reply in completion_replies {
            let (client, _) =
                scripted_walk_client(Version::V2c, 0, vec![WalkReply::Response(reply)]);
            assert!(
                client
                    .walk_getnext(walk_base())
                    .collect()
                    .await
                    .unwrap()
                    .is_empty()
            );
        }

        let (client, requests) = scripted_walk_client(
            Version::V1,
            0,
            vec![WalkReply::Status(ErrorStatus::NoSuchName)],
        );
        assert!(
            client
                .walk_getnext(walk_base())
                .collect()
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            detailed_requests(&requests),
            vec![(PduType::GetNextRequest, None)]
        );
    }

    #[tokio::test]
    async fn probe_failures_preserve_timeout_protocol_shape_ordering_and_transport_errors() {
        let (client, _) = scripted_walk_client(Version::V2c, 0, vec![WalkReply::Timeout]);
        let error = client
            .walk_getnext(walk_base())
            .collect()
            .await
            .unwrap_err();
        assert!(matches!(*error, Error::Timeout { .. }));

        let (client, _) = scripted_walk_client(
            Version::V2c,
            0,
            vec![WalkReply::Status(ErrorStatus::TooBig)],
        );
        let error = client
            .walk_getnext(walk_base())
            .collect()
            .await
            .unwrap_err();
        assert!(matches!(
            *error,
            Error::Snmp {
                status: ErrorStatus::TooBig,
                ..
            }
        ));

        let (client, _) = scripted_walk_client(
            Version::V2c,
            0,
            vec![WalkReply::Response(vec![walk_binding(1), walk_binding(2)])],
        );
        let error = client
            .walk_getnext(walk_base())
            .collect()
            .await
            .unwrap_err();
        assert!(matches!(*error, Error::ResponseShape { .. }));

        let (client, _) = scripted_walk_client(
            Version::V2c,
            1,
            vec![
                WalkReply::Response(vec![walk_binding(2)]),
                WalkReply::Response(vec![walk_binding(1)]),
            ],
        );
        let error = client
            .bulk_walk(walk_base(), 1)
            .unwrap()
            .collect()
            .await
            .unwrap_err();
        assert!(matches!(
            *error,
            Error::WalkAborted {
                reason: WalkAbortReason::NonIncreasing,
                ..
            }
        ));

        let (client, _) = scripted_walk_client(Version::V2c, 0, vec![WalkReply::Closed]);
        let error = client
            .walk_getnext(walk_base())
            .collect()
            .await
            .unwrap_err();
        assert!(matches!(*error, Error::Closed { .. }));
    }

    #[tokio::test]
    async fn getbulk_probe_too_big_is_not_degraded_or_retried() {
        let (client, requests) = scripted_walk_client(
            Version::V2c,
            1,
            vec![
                WalkReply::Response(vec![walk_binding(1)]),
                WalkReply::Status(ErrorStatus::TooBig),
            ],
        );
        let error = client
            .bulk_walk(walk_base(), 7)
            .unwrap()
            .collect()
            .await
            .unwrap_err();
        assert!(matches!(
            *error,
            Error::Snmp {
                status: ErrorStatus::TooBig,
                ..
            }
        ));
        assert_eq!(
            detailed_requests(&requests),
            vec![
                (PduType::GetBulkRequest, Some(7)),
                (PduType::GetBulkRequest, Some(1)),
            ]
        );
    }

    #[tokio::test]
    async fn getbulk_additional_probe_failure_is_original_and_stream_is_fused() {
        let (client, requests) = scripted_walk_client(
            Version::V2c,
            1,
            vec![
                WalkReply::Response(vec![walk_binding(1)]),
                WalkReply::Timeout,
            ],
        );
        let mut walk = client.bulk_walk(walk_base(), 7).unwrap();
        assert_eq!(walk.next().await.unwrap().unwrap(), walk_binding(1));
        let error = walk.next().await.unwrap().unwrap_err();
        assert!(matches!(*error, Error::Timeout { .. }));
        assert!(walk.next().await.is_none());
        assert_eq!(
            detailed_requests(&requests),
            vec![
                (PduType::GetBulkRequest, Some(7)),
                (PduType::GetBulkRequest, Some(1)),
            ]
        );
    }

    #[tokio::test]
    async fn collect_rejects_truncation_while_manual_streaming_retains_yielded_values() {
        let replies = || {
            vec![
                WalkReply::Response(vec![walk_binding(1)]),
                WalkReply::Response(vec![walk_binding(2)]),
            ]
        };

        let (client, _) = scripted_walk_client(Version::V2c, 1, replies());
        let error = client
            .walk_getnext(walk_base())
            .collect()
            .await
            .unwrap_err();
        assert_result_limit(&error, 1);

        let (client, _) = scripted_walk_client(Version::V2c, 1, replies());
        let mut walk = client.walk_getnext(walk_base());
        let mut retained = Vec::new();
        let terminal_error = loop {
            match walk.next().await {
                Some(Ok(varbind)) => retained.push(varbind),
                Some(Err(error)) => break error,
                None => panic!("definite truncation must emit a terminal error"),
            }
        };
        assert_eq!(retained, vec![walk_binding(1)]);
        assert_result_limit(&terminal_error, 1);
        assert!(walk.next().await.is_none());
    }

    #[tokio::test]
    async fn max_results_zero_probes_and_exception_completes_normally() {
        let base = oid!(1, 3, 6, 1, 2, 1, 1, 1, 0);

        let (client, requests) = empty_walk_client(Some(0));
        assert!(
            client
                .walk_getnext(base.clone())
                .collect()
                .await
                .unwrap()
                .is_empty()
        );
        assert_requests(&requests, &[PduType::GetNextRequest]);

        let (client, requests) = empty_walk_client(Some(0));
        assert!(
            client
                .bulk_walk(base.clone(), 10)
                .unwrap()
                .collect()
                .await
                .unwrap()
                .is_empty()
        );
        assert_requests(&requests, &[PduType::GetBulkRequest]);

        let (client, requests) = empty_walk_client(Some(0));
        assert!(
            client
                .walk(base)
                .unwrap()
                .collect()
                .await
                .unwrap()
                .is_empty()
        );
        assert_requests(&requests, &[PduType::GetBulkRequest]);
    }
}
