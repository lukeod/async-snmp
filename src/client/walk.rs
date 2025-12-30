//! Walk stream implementations.

use std::pin::Pin;
use std::task::{Context, Poll};

use futures_core::Stream;

use crate::error::{Error, Result};
use crate::oid::Oid;
use crate::transport::Transport;
use crate::value::Value;
use crate::varbind::VarBind;

use super::Client;

/// Async stream for walking an OID subtree using GETNEXT.
///
/// Created by [`Client::walk()`].
pub struct Walk<T: Transport> {
    client: Client<T>,
    base_oid: Oid,
    current_oid: Oid,
    /// Last OID that was successfully returned to the caller.
    /// Used to detect non-increasing OIDs (agent misbehavior).
    last_returned_oid: Option<Oid>,
    done: bool,
    pending: Option<Pin<Box<dyn std::future::Future<Output = Result<VarBind>> + Send>>>,
}

impl<T: Transport> Walk<T> {
    pub(crate) fn new(client: Client<T>, oid: Oid) -> Self {
        Self {
            client,
            base_oid: oid.clone(),
            current_oid: oid,
            last_returned_oid: None,
            done: false,
            pending: None,
        }
    }
}

impl<T: Transport + 'static> Stream for Walk<T> {
    type Item = Result<VarBind>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.done {
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

                        // Check for non-increasing OID (agent misbehavior).
                        // This prevents infinite loops on non-conformant devices.
                        if let Some(last_oid) = self.last_returned_oid.take()
                            && vb.oid <= last_oid
                        {
                            self.done = true;
                            return Poll::Ready(Some(Err(Error::NonIncreasingOid {
                                previous: last_oid,
                                current: vb.oid,
                            })));
                        }

                        // Update current OID for next iteration
                        self.current_oid = vb.oid.clone();
                        self.last_returned_oid = Some(vb.oid.clone());

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
    /// Last OID that was successfully returned to the caller.
    /// Used to detect non-increasing OIDs (agent misbehavior).
    last_returned_oid: Option<Oid>,
    done: bool,
    /// Buffered results from the last GETBULK response
    buffer: Vec<VarBind>,
    /// Index into the buffer
    buffer_idx: usize,
    pending: Option<Pin<Box<dyn std::future::Future<Output = Result<Vec<VarBind>>> + Send>>>,
}

impl<T: Transport> BulkWalk<T> {
    pub(crate) fn new(client: Client<T>, oid: Oid, max_repetitions: i32) -> Self {
        Self {
            client,
            base_oid: oid.clone(),
            current_oid: oid,
            max_repetitions,
            last_returned_oid: None,
            done: false,
            buffer: Vec::new(),
            buffer_idx: 0,
            pending: None,
        }
    }
}

impl<T: Transport + 'static> Stream for BulkWalk<T> {
    type Item = Result<VarBind>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            if self.done {
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

                // Check for non-increasing OID (agent misbehavior).
                // This prevents infinite loops on non-conformant devices.
                if let Some(last_oid) = self.last_returned_oid.take()
                    && vb.oid <= last_oid
                {
                    self.done = true;
                    return Poll::Ready(Some(Err(Error::NonIncreasingOid {
                        previous: last_oid,
                        current: vb.oid,
                    })));
                }

                // Update current OID for next request
                self.current_oid = vb.oid.clone();
                self.last_returned_oid = Some(vb.oid.clone());

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
}
