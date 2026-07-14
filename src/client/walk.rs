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

            /// Collect all remaining varbinds.
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
use crate::transport::Transport;
use crate::varbind::VarBind;
use crate::version::Version;

use super::Client;

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
    fn new(ordering: OidOrdering) -> Self {
        match ordering {
            OidOrdering::Strict => OidTracker::Strict { last: None },
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
    pending: Option<Pin<Box<dyn std::future::Future<Output = Result<VarBind>> + Send>>>,
}

impl<T: Transport> Walk<T> {
    pub(crate) fn new(
        client: Client<T>,
        oid: Oid,
        ordering: OidOrdering,
        max_results: Option<usize>,
    ) -> Self {
        Self {
            client,
            base_oid: oid.clone(),
            current_oid: oid,
            oid_tracker: OidTracker::new(ordering),
            max_results,
            count: 0,
            done: false,
            pending: None,
        }
    }
}

impl_stream_helpers!(Walk<T>);

impl<T: Transport + 'static> Stream for Walk<T> {
    type Item = Result<VarBind>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.done {
            return Poll::Ready(None);
        }

        // Check max_results limit
        if let Some(max) = self.max_results
            && self.count >= max
        {
            self.done = true;
            return Poll::Ready(None);
        }

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
                    Ok(vb) => {
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

                        // Update current OID for next iteration
                        self.current_oid = vb.oid.clone();
                        self.count += 1;

                        Poll::Ready(Some(Ok(vb)))
                    }
                    Err(e) => {
                        if self.client.inner.config.version == Version::V1
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

/// Async stream for walking an OID subtree using GETBULK.
///
/// Created by [`Client::bulk_walk()`].
pub struct BulkWalk<T: Transport> {
    client: Client<T>,
    base_oid: Oid,
    current_oid: Oid,
    max_repetitions: i32,
    /// OID tracker for ordering validation.
    oid_tracker: OidTracker,
    /// Maximum number of results to return (None = unlimited).
    max_results: Option<usize>,
    /// Count of results returned so far.
    count: usize,
    done: bool,
    /// Buffered results from the last GETBULK response
    buffer: VecDeque<VarBind>,
    pending: Option<Pin<Box<dyn std::future::Future<Output = Result<Vec<VarBind>>> + Send>>>,
}

impl<T: Transport> BulkWalk<T> {
    pub(crate) fn new(
        client: Client<T>,
        oid: Oid,
        max_repetitions: i32,
        ordering: OidOrdering,
        max_results: Option<usize>,
    ) -> Self {
        Self {
            client,
            base_oid: oid.clone(),
            current_oid: oid,
            max_repetitions,
            oid_tracker: OidTracker::new(ordering),
            max_results,
            count: 0,
            done: false,
            buffer: VecDeque::new(),
            pending: None,
        }
    }
}

impl_stream_helpers!(BulkWalk<T>);

impl<T: Transport + 'static> Stream for BulkWalk<T> {
    type Item = Result<VarBind>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            if self.done {
                return Poll::Ready(None);
            }

            // Check max_results limit
            if let Some(max) = self.max_results
                && self.count >= max
            {
                self.done = true;
                return Poll::Ready(None);
            }

            // Check if we have buffered results to return
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

                // Update current OID for next request
                self.current_oid = vb.oid.clone();
                self.count += 1;

                return Poll::Ready(Some(Ok(vb)));
            }

            // Buffer exhausted, need to fetch more
            if self.pending.is_none() {
                let client = self.client.clone();
                let oid = self.current_oid.clone();
                let max_rep = self.max_repetitions;

                let fut = Box::pin(async move { client.get_bulk(&[oid], 0, max_rep).await });
                self.pending = Some(fut);
            }

            // Poll the pending future
            let pending = self.pending.as_mut().unwrap();
            match pending.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => {
                    self.pending = None;

                    match result {
                        Ok(varbinds) => {
                            if varbinds.is_empty() {
                                self.done = true;
                                return Poll::Ready(None);
                            }

                            self.buffer = varbinds.into();
                            // Continue loop to process buffer
                        }
                        Err(e) => {
                            // On tooBig, degrade instead of aborting (RFC 3416
                            // 4.2.3): halve max-repetitions down to a floor of 1
                            // and retry the same position. Only surface the error
                            // if it still fails at max-repetitions = 1.
                            if self.max_repetitions > 1
                                && matches!(
                                    &*e,
                                    Error::Snmp {
                                        status: crate::error::ErrorStatus::TooBig,
                                        ..
                                    }
                                )
                            {
                                let reduced = (self.max_repetitions / 2).max(1);
                                tracing::debug!(target: "async_snmp::client", { peer = %self.client.peer_addr(), snmp.max_repetitions = self.max_repetitions, snmp.reduced_max_repetitions = reduced }, "tooBig response, reducing max-repetitions and retrying");
                                self.max_repetitions = reduced;
                                // Retry the same position with fewer repetitions.
                                continue;
                            }

                            self.done = true;
                            return Poll::Ready(Some(Err(e)));
                        }
                    }
                }
            }
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
        max_repetitions: i32,
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
            ))
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

    /// Collect all remaining varbinds.
    ///
    /// If the walk completes with no results, a fallback GET is attempted on the
    /// base OID. This handles scalar OIDs (e.g. `sysDescr.0`) where GETNEXT would
    /// walk past the value. The GET result is only returned if it contains a real
    /// value (not `NoSuchObject`, `NoSuchInstance`, or `EndOfMibView`).
    pub async fn collect(mut self) -> Result<Vec<VarBind>> {
        let mut results = Vec::new();
        while let Some(result) = self.next().await {
            results.push(result?);
        }
        if results.is_empty() {
            let (client, base_oid) = match &self {
                WalkStream::GetNext(w) => (&w.client, &w.base_oid),
                WalkStream::GetBulk(bw) => (&bw.client, &bw.base_oid),
            };
            match client.get(base_oid).await {
                Ok(vb) if !vb.value.is_exception() => {
                    results.push(vb);
                }
                _ => {}
            }
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
        let mut tracker = OidTracker::new(OidOrdering::Strict);
        let vb = VarBind::new(oid!(1, 3, 6, 1, 2, 1, 1, 1, 0), Value::NoSuchObject);
        assert!(matches!(
            validate_walk_varbind(&vb, &base, &mut tracker, target_addr()),
            VarbindOutcome::Done
        ));
    }

    #[test]
    fn test_walk_terminates_on_no_such_instance() {
        let base = oid!(1, 3, 6, 1, 2, 1, 1);
        let mut tracker = OidTracker::new(OidOrdering::Strict);
        let vb = VarBind::new(oid!(1, 3, 6, 1, 2, 1, 1, 1, 0), Value::NoSuchInstance);
        assert!(matches!(
            validate_walk_varbind(&vb, &base, &mut tracker, target_addr()),
            VarbindOutcome::Done
        ));
    }

    #[test]
    fn test_walk_terminates_on_end_of_mib_view() {
        let base = oid!(1, 3, 6, 1, 2, 1, 1);
        let mut tracker = OidTracker::new(OidOrdering::Strict);
        let vb = VarBind::new(oid!(1, 3, 6, 1, 2, 1, 1, 1, 0), Value::EndOfMibView);
        assert!(matches!(
            validate_walk_varbind(&vb, &base, &mut tracker, target_addr()),
            VarbindOutcome::Done
        ));
    }

    #[test]
    fn test_walk_yields_normal_value() {
        let base = oid!(1, 3, 6, 1, 2, 1, 1);
        let mut tracker = OidTracker::new(OidOrdering::Strict);
        let vb = VarBind::new(oid!(1, 3, 6, 1, 2, 1, 1, 1, 0), Value::Integer(42));
        assert!(matches!(
            validate_walk_varbind(&vb, &base, &mut tracker, target_addr()),
            VarbindOutcome::Yield
        ));
    }

    #[test]
    fn test_walk_strict_aborts_on_non_increasing_oid() {
        let base = oid!(1, 3, 6, 1, 2, 1, 1);
        let mut tracker = OidTracker::new(OidOrdering::Strict);

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
        let mut tracker = OidTracker::new(OidOrdering::Strict);

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
        let mut tracker = OidTracker::new(OidOrdering::AllowNonIncreasing);

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
        let mut tracker = OidTracker::new(OidOrdering::AllowNonIncreasing);

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
        max_repetitions: i32,
        /// Records (request_id, max_repetitions) seen by `send`, drained by `recv`.
        pending: Arc<Mutex<VecDeque<(i32, i32)>>>,
        /// Total number of tooBig responses emitted.
        too_big_count: Arc<Mutex<usize>>,
    }

    impl BulkTooBigTransport {
        fn new(max_repetitions: i32) -> Self {
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
            let pdu = msg.pdu.standard().unwrap();
            // For GETBULK, error_index carries max-repetitions.
            let max_rep = pdu.error_index;
            self.pending
                .lock()
                .unwrap()
                .push_back((request_id, max_rep));
            async { Ok(()) }
        }

        fn recv(
            &self,
            _request_id: i32,
        ) -> impl std::future::Future<Output = Result<(Bytes, SocketAddr)>> + Send {
            let (request_id, max_rep) = self.pending.lock().unwrap().pop_front().unwrap_or((1, 0));
            let threshold = self.max_repetitions;
            let too_big_count = self.too_big_count.clone();
            let peer: SocketAddr = "127.0.0.1:161".parse().unwrap();

            async move {
                let pdu = if max_rep > threshold {
                    *too_big_count.lock().unwrap() += 1;
                    Pdu {
                        pdu_type: PduType::Response,
                        request_id,
                        error_status: ErrorStatus::TooBig.as_i32(),
                        error_index: 0,
                        varbinds: vec![],
                    }
                } else {
                    // One in-subtree value, then EndOfMibView to terminate the walk.
                    let varbinds = vec![
                        VarBind::new(oid!(1, 3, 6, 1, 2, 1, 2, 1, 0), Value::Integer(1)),
                        VarBind::new(oid!(1, 3, 6, 1, 2, 1, 2, 2, 0), Value::EndOfMibView),
                    ];
                    Pdu {
                        pdu_type: PduType::Response,
                        request_id,
                        error_status: 0,
                        error_index: 0,
                        varbinds,
                    }
                };

                let msg = CommunityMessage::v2c(Bytes::from_static(b"public"), pdu);
                Ok((msg.encode(), peer))
            }
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
            version: Version::V2c,
            retry: crate::client::retry::Retry::none(),
            ..Default::default()
        };
        let client = Client::new(transport, config);

        let results = client
            .bulk_walk(oid!(1, 3, 6, 1, 2, 1, 2), 25)
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
            version: Version::V2c,
            retry: crate::client::retry::Retry::none(),
            ..Default::default()
        };
        let client = Client::new(transport, config);

        let err = client
            .bulk_walk(oid!(1, 3, 6, 1, 2, 1, 2), 8)
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
}
