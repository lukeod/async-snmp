//! Walk stream implementations.

#![allow(clippy::type_complexity)]

use std::collections::HashSet;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_core::Stream;

use crate::error::{Error, Result, WalkAbortReason};
use crate::oid::Oid;
use crate::transport::Transport;
use crate::value::Value;
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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
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
    /// OIDs in a HashSet to detect cycles, terminating with an error if the
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

impl<T: Transport + 'static> Walk<T> {
    /// Get the next varbind, or None when complete.
    pub async fn next(&mut self) -> Option<Result<VarBind>> {
        std::future::poll_fn(|cx| Pin::new(&mut *self).poll_next(cx)).await
    }

    /// Collect all remaining varbinds.
    pub async fn collect(mut self) -> Result<Vec<VarBind>> {
        let mut results = Vec::new();
        while let Some(result) = self.next().await {
            results.push(result?);
        }
        Ok(results)
    }
}

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
                        // Check for end conditions
                        if matches!(vb.value, Value::EndOfMibView) {
                            self.done = true;
                            return Poll::Ready(None);
                        }

                        // Check if OID left the subtree
                        if !vb.oid.starts_with(&self.base_oid) {
                            self.done = true;
                            return Poll::Ready(None);
                        }

                        // Check OID ordering using the tracker
                        let target = self.client.peer_addr();
                        if let Err(e) = self.oid_tracker.check(&vb.oid, target) {
                            self.done = true;
                            return Poll::Ready(Some(Err(e)));
                        }

                        // Update current OID for next iteration
                        self.current_oid = vb.oid.clone();
                        self.count += 1;

                        Poll::Ready(Some(Ok(vb)))
                    }
                    Err(e) => {
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
    buffer: Vec<VarBind>,
    /// Index into the buffer
    buffer_idx: usize,
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
            buffer: Vec::new(),
            buffer_idx: 0,
            pending: None,
        }
    }
}

impl<T: Transport + 'static> BulkWalk<T> {
    /// Get the next varbind, or None when complete.
    pub async fn next(&mut self) -> Option<Result<VarBind>> {
        std::future::poll_fn(|cx| Pin::new(&mut *self).poll_next(cx)).await
    }

    /// Collect all remaining varbinds.
    pub async fn collect(mut self) -> Result<Vec<VarBind>> {
        let mut results = Vec::new();
        while let Some(result) = self.next().await {
            results.push(result?);
        }
        Ok(results)
    }
}

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
            if self.buffer_idx < self.buffer.len() {
                let vb = self.buffer[self.buffer_idx].clone();
                self.buffer_idx += 1;

                // Check for end conditions
                if matches!(vb.value, Value::EndOfMibView) {
                    self.done = true;
                    return Poll::Ready(None);
                }

                // Check if OID left the subtree
                if !vb.oid.starts_with(&self.base_oid) {
                    self.done = true;
                    return Poll::Ready(None);
                }

                // Check OID ordering using the tracker
                let target = self.client.peer_addr();
                if let Err(e) = self.oid_tracker.check(&vb.oid, target) {
                    self.done = true;
                    return Poll::Ready(Some(Err(e)));
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

                            self.buffer = varbinds;
                            self.buffer_idx = 0;
                            // Continue loop to process buffer
                        }
                        Err(e) => {
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
