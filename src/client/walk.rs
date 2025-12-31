//! Walk stream implementations.

#![allow(clippy::type_complexity)]

use std::collections::HashSet;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_core::Stream;

use crate::error::{Error, Result};
use crate::oid::Oid;
use crate::transport::Transport;
use crate::value::Value;
use crate::varbind::VarBind;

use super::Client;

/// Walk operation mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum OidOrdering {
    /// Require strictly increasing OIDs (default).
    /// Walk terminates with error on first violation.
    /// Most efficient: O(1) memory, O(1) per-item check.
    #[default]
    Strict,

    /// Allow non-increasing OIDs, with cycle detection.
    /// Some buggy agents return OIDs out of order.
    /// Walk tracks all seen OIDs in a HashSet to detect cycles.
    /// Terminates with error if same OID returned twice.
    /// Memory: O(n) where n = number of walk results.
    AllowNonIncreasing,
}

/// Internal OID tracking for walk operations.
///
/// This enum implements two strategies for detecting walk termination
/// conditions due to agent misbehavior:
/// - `Strict`: O(1) memory, compares against previous OID
/// - `Relaxed`: O(n) memory, tracks all seen OIDs in a HashSet
enum OidTracker {
    /// O(1) memory: stores only the previous OID for comparison.
    /// Used by default Strict mode.
    Strict { last: Option<Oid> },

    /// O(n) memory: HashSet of all seen OIDs for cycle detection.
    /// Only allocated when AllowNonIncreasing is configured.
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

    /// Check if OID is valid according to ordering rules.
    /// Returns Ok(()) if valid, Err if violation detected.
    fn check(&mut self, oid: &Oid) -> Result<()> {
        match self {
            OidTracker::Strict { last } => {
                if let Some(prev) = last
                    && oid <= prev
                {
                    return Err(Error::NonIncreasingOid {
                        previous: prev.clone(),
                        current: oid.clone(),
                    });
                }
                *last = Some(oid.clone());
                Ok(())
            }
            OidTracker::Relaxed { seen } => {
                if !seen.insert(oid.clone()) {
                    return Err(Error::DuplicateOid { oid: oid.clone() });
                }
                Ok(())
            }
        }
    }
}

/// Async stream for walking an OID subtree using GETNEXT.
///
/// Created by [`Client::walk()`].
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
                        if let Err(e) = self.oid_tracker.check(&vb.oid) {
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
                if let Err(e) = self.oid_tracker.check(&vb.oid) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{MockTransport, ResponseBuilder};
    use crate::{ClientConfig, Version};
    use bytes::Bytes;
    use futures_core::Stream;
    use std::pin::Pin;
    use std::task::Context;
    use std::time::Duration;

    fn mock_client(mock: MockTransport) -> Client<MockTransport> {
        let config = ClientConfig {
            version: Version::V2c,
            community: Bytes::from_static(b"public"),
            timeout: Duration::from_secs(1),
            retries: 0,
            max_oids_per_request: 10,
            v3_security: None,
            walk_mode: WalkMode::Auto,
            oid_ordering: OidOrdering::Strict,
            max_walk_results: None,
            max_repetitions: 25,
        };
        Client::new(mock, config)
    }

    async fn collect_walk<T: Transport + 'static>(
        mut walk: Pin<&mut Walk<T>>,
        limit: usize,
    ) -> Vec<Result<VarBind>> {
        use std::future::poll_fn;

        let mut results = Vec::new();
        while results.len() < limit {
            let item = poll_fn(|cx: &mut Context<'_>| walk.as_mut().poll_next(cx)).await;
            match item {
                Some(result) => results.push(result),
                None => break,
            }
        }
        results
    }

    async fn collect_bulk_walk<T: Transport + 'static>(
        mut walk: Pin<&mut BulkWalk<T>>,
        limit: usize,
    ) -> Vec<Result<VarBind>> {
        use std::future::poll_fn;

        let mut results = Vec::new();
        while results.len() < limit {
            let item = poll_fn(|cx: &mut Context<'_>| walk.as_mut().poll_next(cx)).await;
            match item {
                Some(result) => results.push(result),
                None => break,
            }
        }
        results
    }

    #[tokio::test]
    async fn test_walk_terminates_on_end_of_mib_view() {
        let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

        // First response: valid OID in subtree
        mock.queue_response(
            ResponseBuilder::new(1)
                .varbind(
                    Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 1, 0]),
                    Value::OctetString("test".into()),
                )
                .build_v2c(b"public"),
        );

        // Second response: EndOfMibView
        mock.queue_response(
            ResponseBuilder::new(2)
                .varbind(
                    Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 1, 0]),
                    Value::EndOfMibView,
                )
                .build_v2c(b"public"),
        );

        let client = mock_client(mock);
        let walk = client.walk(Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1]));

        let mut pinned = Box::pin(walk);
        let results = collect_walk(pinned.as_mut(), 10).await;

        assert_eq!(results.len(), 1);
        assert!(results[0].is_ok());
    }

    #[tokio::test]
    async fn test_walk_terminates_when_leaving_subtree() {
        let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

        // Response with OID outside the walked subtree (interfaces, not system)
        mock.queue_response(
            ResponseBuilder::new(1)
                .varbind(
                    Oid::from_slice(&[1, 3, 6, 1, 2, 1, 2, 1, 0]), // interfaces subtree
                    Value::Integer(1),
                )
                .build_v2c(b"public"),
        );

        let client = mock_client(mock);
        let walk = client.walk(Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1])); // system subtree

        let mut pinned = Box::pin(walk);
        let results = collect_walk(pinned.as_mut(), 10).await;

        // Should terminate immediately with no results
        assert_eq!(results.len(), 0);
    }

    #[tokio::test]
    async fn test_walk_returns_oids_in_sequence() {
        let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

        // Queue three responses in lexicographic order
        mock.queue_response(
            ResponseBuilder::new(1)
                .varbind(
                    Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 1, 0]),
                    Value::OctetString("desc".into()),
                )
                .build_v2c(b"public"),
        );
        mock.queue_response(
            ResponseBuilder::new(2)
                .varbind(
                    Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 2, 0]),
                    Value::ObjectIdentifier(Oid::from_slice(&[1, 3, 6, 1, 4, 1, 99])),
                )
                .build_v2c(b"public"),
        );
        mock.queue_response(
            ResponseBuilder::new(3)
                .varbind(
                    Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 3, 0]),
                    Value::TimeTicks(12345),
                )
                .build_v2c(b"public"),
        );
        // Fourth response leaves subtree
        mock.queue_response(
            ResponseBuilder::new(4)
                .varbind(
                    Oid::from_slice(&[1, 3, 6, 1, 2, 1, 2, 1, 0]),
                    Value::Integer(1),
                )
                .build_v2c(b"public"),
        );

        let client = mock_client(mock);
        let walk = client.walk(Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1]));

        let mut pinned = Box::pin(walk);
        let results = collect_walk(pinned.as_mut(), 10).await;

        assert_eq!(results.len(), 3);

        // Verify lexicographic ordering
        let oids: Vec<_> = results
            .iter()
            .filter_map(|r| r.as_ref().ok())
            .map(|vb| &vb.oid)
            .collect();
        for i in 1..oids.len() {
            assert!(oids[i] > oids[i - 1], "OIDs should be strictly increasing");
        }
    }

    #[tokio::test]
    async fn test_walk_propagates_errors() {
        let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

        // First response succeeds
        mock.queue_response(
            ResponseBuilder::new(1)
                .varbind(
                    Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 1, 0]),
                    Value::OctetString("test".into()),
                )
                .build_v2c(b"public"),
        );

        // Second request times out
        mock.queue_timeout();

        let client = mock_client(mock);
        let walk = client.walk(Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1]));

        let mut pinned = Box::pin(walk);
        let results = collect_walk(pinned.as_mut(), 10).await;

        assert_eq!(results.len(), 2);
        assert!(results[0].is_ok());
        assert!(results[1].is_err());
    }

    #[tokio::test]
    async fn test_bulk_walk_terminates_on_end_of_mib_view() {
        let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

        // GETBULK response with multiple varbinds, last one is EndOfMibView
        mock.queue_response(
            ResponseBuilder::new(1)
                .varbind(
                    Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 1, 0]),
                    Value::OctetString("desc".into()),
                )
                .varbind(
                    Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 2, 0]),
                    Value::ObjectIdentifier(Oid::from_slice(&[1, 3, 6, 1, 4, 1, 99])),
                )
                .varbind(
                    Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 3, 0]),
                    Value::EndOfMibView,
                )
                .build_v2c(b"public"),
        );

        let client = mock_client(mock);
        let walk = client.bulk_walk(Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1]), 10);

        let mut pinned = Box::pin(walk);
        let results = collect_bulk_walk(pinned.as_mut(), 20).await;

        // Should return 2 valid results before EndOfMibView terminates
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.is_ok()));
    }

    #[tokio::test]
    async fn test_bulk_walk_terminates_when_leaving_subtree() {
        let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

        // GETBULK returns varbinds, some in subtree, one outside
        mock.queue_response(
            ResponseBuilder::new(1)
                .varbind(
                    Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 1, 0]),
                    Value::OctetString("desc".into()),
                )
                .varbind(
                    Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 2, 0]),
                    Value::ObjectIdentifier(Oid::from_slice(&[1, 3, 6, 1, 4, 1, 99])),
                )
                .varbind(
                    Oid::from_slice(&[1, 3, 6, 1, 2, 1, 2, 1, 0]), // interfaces - outside system
                    Value::Integer(1),
                )
                .build_v2c(b"public"),
        );

        let client = mock_client(mock);
        let walk = client.bulk_walk(Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1]), 10);

        let mut pinned = Box::pin(walk);
        let results = collect_bulk_walk(pinned.as_mut(), 20).await;

        // Should return 2 results (third OID is outside subtree)
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn test_bulk_walk_handles_empty_response() {
        let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

        // Empty GETBULK response (no varbinds)
        mock.queue_response(ResponseBuilder::new(1).build_v2c(b"public"));

        let client = mock_client(mock);
        let walk = client.bulk_walk(Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1]), 10);

        let mut pinned = Box::pin(walk);
        let results = collect_bulk_walk(pinned.as_mut(), 20).await;

        // Should return empty
        assert_eq!(results.len(), 0);
    }

    // Tests for non-increasing OID detection.
    // These prevent infinite loops on non-conformant SNMP agents.

    #[tokio::test]
    async fn test_walk_errors_on_decreasing_oid() {
        use crate::error::Error;

        let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

        // First response: .1.3.6.1.2.1.1.5.0
        mock.queue_response(
            ResponseBuilder::new(1)
                .varbind(
                    Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 5, 0]),
                    Value::OctetString("host1".into()),
                )
                .build_v2c(b"public"),
        );

        // Second response: .1.3.6.1.2.1.1.4.0 (DECREASING - goes backwards!)
        mock.queue_response(
            ResponseBuilder::new(2)
                .varbind(
                    Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 4, 0]),
                    Value::OctetString("admin".into()),
                )
                .build_v2c(b"public"),
        );

        let client = mock_client(mock);
        let walk = client.walk(Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1]));

        let mut pinned = Box::pin(walk);
        let results = collect_walk(pinned.as_mut(), 10).await;

        // Should get first result OK, then error on second
        assert_eq!(results.len(), 2);
        assert!(results[0].is_ok());
        assert!(matches!(
            &results[1],
            Err(Error::NonIncreasingOid { previous, current })
            if previous == &Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 5, 0])
               && current == &Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 4, 0])
        ));
    }

    #[tokio::test]
    async fn test_walk_errors_on_same_oid_returned_twice() {
        use crate::error::Error;

        let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

        // First response: .1.3.6.1.2.1.1.1.0
        mock.queue_response(
            ResponseBuilder::new(1)
                .varbind(
                    Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 1, 0]),
                    Value::OctetString("desc".into()),
                )
                .build_v2c(b"public"),
        );

        // Second response: same OID again! (would cause infinite loop)
        mock.queue_response(
            ResponseBuilder::new(2)
                .varbind(
                    Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 1, 0]),
                    Value::OctetString("desc".into()),
                )
                .build_v2c(b"public"),
        );

        let client = mock_client(mock);
        let walk = client.walk(Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1]));

        let mut pinned = Box::pin(walk);
        let results = collect_walk(pinned.as_mut(), 10).await;

        // Should get first result OK, then error on second
        assert_eq!(results.len(), 2);
        assert!(results[0].is_ok());
        assert!(matches!(
            &results[1],
            Err(Error::NonIncreasingOid { previous, current })
            if previous == current
        ));
    }

    #[tokio::test]
    async fn test_bulk_walk_errors_on_non_increasing_oid() {
        use crate::error::Error;

        let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

        // First GETBULK response with non-increasing OID in the batch
        mock.queue_response(
            ResponseBuilder::new(1)
                .varbind(
                    Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 1, 0]),
                    Value::OctetString("desc".into()),
                )
                .varbind(
                    Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 3, 0]),
                    Value::TimeTicks(12345),
                )
                .varbind(
                    // Non-increasing: .1.2.0 < .3.0 (goes backwards)
                    Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 2, 0]),
                    Value::ObjectIdentifier(Oid::from_slice(&[1, 3, 6, 1, 4, 1, 99])),
                )
                .build_v2c(b"public"),
        );

        let client = mock_client(mock);
        let walk = client.bulk_walk(Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1]), 10);

        let mut pinned = Box::pin(walk);
        let results = collect_bulk_walk(pinned.as_mut(), 20).await;

        // Should get first two results OK, then error on third
        assert_eq!(results.len(), 3);
        assert!(results[0].is_ok());
        assert!(results[1].is_ok());
        assert!(matches!(
            &results[2],
            Err(Error::NonIncreasingOid { previous, current })
            if previous == &Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 3, 0])
               && current == &Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 2, 0])
        ));
    }

    // Tests for AllowNonIncreasing OID ordering mode

    #[tokio::test]
    async fn test_walk_allow_non_increasing_accepts_out_of_order() {
        let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

        // Three OIDs out of order, but no duplicates
        mock.queue_response(
            ResponseBuilder::new(1)
                .varbind(
                    Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 5, 0]),
                    Value::OctetString("five".into()),
                )
                .build_v2c(b"public"),
        );
        mock.queue_response(
            ResponseBuilder::new(2)
                .varbind(
                    Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 3, 0]), // out of order
                    Value::OctetString("three".into()),
                )
                .build_v2c(b"public"),
        );
        mock.queue_response(
            ResponseBuilder::new(3)
                .varbind(
                    Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 7, 0]),
                    Value::OctetString("seven".into()),
                )
                .build_v2c(b"public"),
        );
        // Fourth response leaves subtree
        mock.queue_response(
            ResponseBuilder::new(4)
                .varbind(
                    Oid::from_slice(&[1, 3, 6, 1, 2, 1, 2, 1, 0]),
                    Value::Integer(1),
                )
                .build_v2c(b"public"),
        );

        let client = mock_client(mock);
        let walk = Walk::new(
            client,
            Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1]),
            OidOrdering::AllowNonIncreasing,
            None,
        );

        let mut pinned = Box::pin(walk);
        let results = collect_walk(pinned.as_mut(), 10).await;

        // Should get all three results successfully
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|r| r.is_ok()));
    }

    #[tokio::test]
    async fn test_walk_allow_non_increasing_detects_cycle() {
        use crate::error::Error;

        let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

        // First OID
        mock.queue_response(
            ResponseBuilder::new(1)
                .varbind(
                    Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 1, 0]),
                    Value::OctetString("first".into()),
                )
                .build_v2c(b"public"),
        );
        // Second OID
        mock.queue_response(
            ResponseBuilder::new(2)
                .varbind(
                    Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 2, 0]),
                    Value::OctetString("second".into()),
                )
                .build_v2c(b"public"),
        );
        // Same as first - cycle!
        mock.queue_response(
            ResponseBuilder::new(3)
                .varbind(
                    Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 1, 0]),
                    Value::OctetString("first-again".into()),
                )
                .build_v2c(b"public"),
        );

        let client = mock_client(mock);
        let walk = Walk::new(
            client,
            Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1]),
            OidOrdering::AllowNonIncreasing,
            None,
        );

        let mut pinned = Box::pin(walk);
        let results = collect_walk(pinned.as_mut(), 10).await;

        // Should get first two OK, then DuplicateOid error
        assert_eq!(results.len(), 3);
        assert!(results[0].is_ok());
        assert!(results[1].is_ok());
        assert!(matches!(
            &results[2],
            Err(Error::DuplicateOid { oid })
            if oid == &Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 1, 0])
        ));
    }

    // Tests for max_results limit

    #[tokio::test]
    async fn test_walk_respects_max_results() {
        let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

        // Queue many responses
        for i in 1..=10 {
            mock.queue_response(
                ResponseBuilder::new(i)
                    .varbind(
                        Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, i as u32, 0]),
                        Value::Integer(i as i32),
                    )
                    .build_v2c(b"public"),
            );
        }

        let client = mock_client(mock);
        let walk = Walk::new(
            client,
            Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1]),
            OidOrdering::Strict,
            Some(3), // Limit to 3 results
        );

        let mut pinned = Box::pin(walk);
        let results = collect_walk(pinned.as_mut(), 20).await;

        // Should stop after 3 results
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|r| r.is_ok()));
    }

    #[tokio::test]
    async fn test_bulk_walk_respects_max_results() {
        let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

        // GETBULK returns many varbinds at once
        mock.queue_response(
            ResponseBuilder::new(1)
                .varbind(
                    Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 1, 0]),
                    Value::Integer(1),
                )
                .varbind(
                    Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 2, 0]),
                    Value::Integer(2),
                )
                .varbind(
                    Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 3, 0]),
                    Value::Integer(3),
                )
                .varbind(
                    Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 4, 0]),
                    Value::Integer(4),
                )
                .varbind(
                    Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 5, 0]),
                    Value::Integer(5),
                )
                .build_v2c(b"public"),
        );

        let client = mock_client(mock);
        let walk = BulkWalk::new(
            client,
            Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1]),
            10,
            OidOrdering::Strict,
            Some(3), // Limit to 3 results
        );

        let mut pinned = Box::pin(walk);
        let results = collect_bulk_walk(pinned.as_mut(), 20).await;

        // Should stop after 3 results even though buffer has more
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|r| r.is_ok()));
    }

    // Tests for inherent next() and collect() methods

    #[tokio::test]
    async fn test_walk_inherent_next() {
        let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

        mock.queue_response(
            ResponseBuilder::new(1)
                .varbind(
                    Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 1, 0]),
                    Value::OctetString("test".into()),
                )
                .build_v2c(b"public"),
        );
        mock.queue_response(
            ResponseBuilder::new(2)
                .varbind(
                    Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 2, 0]),
                    Value::Integer(42),
                )
                .build_v2c(b"public"),
        );
        mock.queue_response(
            ResponseBuilder::new(3)
                .varbind(
                    Oid::from_slice(&[1, 3, 6, 1, 2, 1, 2, 1, 0]), // leaves subtree
                    Value::Integer(1),
                )
                .build_v2c(b"public"),
        );

        let client = mock_client(mock);
        let mut walk = client.walk(Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1]));

        // Use inherent next() method
        let first = walk.next().await;
        assert!(first.is_some());
        assert!(first.unwrap().is_ok());

        let second = walk.next().await;
        assert!(second.is_some());
        assert!(second.unwrap().is_ok());

        let third = walk.next().await;
        assert!(third.is_none()); // Walk ended
    }

    #[tokio::test]
    async fn test_walk_inherent_collect() {
        let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

        mock.queue_response(
            ResponseBuilder::new(1)
                .varbind(
                    Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 1, 0]),
                    Value::OctetString("test".into()),
                )
                .build_v2c(b"public"),
        );
        mock.queue_response(
            ResponseBuilder::new(2)
                .varbind(
                    Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 2, 0]),
                    Value::Integer(42),
                )
                .build_v2c(b"public"),
        );
        mock.queue_response(
            ResponseBuilder::new(3)
                .varbind(
                    Oid::from_slice(&[1, 3, 6, 1, 2, 1, 2, 1, 0]), // leaves subtree
                    Value::Integer(1),
                )
                .build_v2c(b"public"),
        );

        let client = mock_client(mock);
        let walk = client.walk(Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1]));

        // Use inherent collect() method
        let results = walk.collect().await.unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn test_bulk_walk_inherent_collect() {
        let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

        mock.queue_response(
            ResponseBuilder::new(1)
                .varbind(
                    Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 1, 0]),
                    Value::OctetString("desc".into()),
                )
                .varbind(
                    Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 2, 0]),
                    Value::ObjectIdentifier(Oid::from_slice(&[1, 3, 6, 1, 4, 1, 99])),
                )
                .varbind(
                    Oid::from_slice(&[1, 3, 6, 1, 2, 1, 2, 1, 0]), // outside system
                    Value::Integer(1),
                )
                .build_v2c(b"public"),
        );

        let client = mock_client(mock);
        let walk = client.bulk_walk(Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1]), 10);

        // Use inherent collect() method
        let results = walk.collect().await.unwrap();
        assert_eq!(results.len(), 2);
    }
}
