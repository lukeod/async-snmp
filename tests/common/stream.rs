//! Stream collection utilities for testing walks.

use futures_core::Stream;
use std::future::poll_fn;
use std::pin::Pin;
use std::task::Context;

/// Collect items from a stream up to a limit.
pub async fn collect_stream<S, T, E>(mut stream: Pin<&mut S>, limit: usize) -> Vec<Result<T, E>>
where
    S: Stream<Item = Result<T, E>> + Unpin,
{
    let mut results = Vec::new();
    while results.len() < limit {
        let item = poll_fn(|cx: &mut Context<'_>| Pin::new(&mut stream).poll_next(cx)).await;

        match item {
            Some(result) => results.push(result),
            None => break,
        }
    }
    results
}
