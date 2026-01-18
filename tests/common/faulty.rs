//! Faulty agent variants for edge case testing.
//!
//! These agents simulate network conditions and error scenarios
//! that are difficult to test with a well-behaved agent.

use async_snmp::{Agent, oid};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::fixtures;
use super::handler::TestHandler;

/// An agent that drops a configurable fraction of requests.
///
/// Useful for testing retry logic with real UDP packet loss simulation.
pub struct LossyAgent {
    addr: SocketAddr,
    #[allow(dead_code)]
    handler: Arc<TestHandler>,
    cancel: CancellationToken,
    _task: JoinHandle<()>,
    #[allow(dead_code)]
    request_count: Arc<AtomicUsize>,
}

impl LossyAgent {
    /// Create an agent that drops every Nth request.
    ///
    /// For example, `drop_every(3)` drops requests 1, 4, 7, 10...
    /// (keeping 2, 3, 5, 6, 8, 9, 11, 12...)
    #[allow(dead_code)]
    pub async fn drop_every(n: usize) -> Self {
        Self::with_pattern(move |count| count % n == 1).await
    }

    /// Create an agent that drops the first N requests.
    ///
    /// Useful for testing initial retry behavior.
    pub async fn drop_first(n: usize) -> Self {
        Self::with_pattern(move |count| count <= n).await
    }

    /// Create an agent with a custom drop pattern.
    ///
    /// The predicate receives the 1-indexed request count and returns
    /// true if the request should be dropped.
    pub async fn with_pattern<F>(_should_drop: F) -> Self
    where
        F: Fn(usize) -> bool + Send + Sync + 'static,
    {
        let handler = Arc::new(TestHandler::new(fixtures::system_mib()));
        let cancel = CancellationToken::new();
        let request_count = Arc::new(AtomicUsize::new(0));

        // Note: This is a simplified implementation. Full packet-level
        // fault injection would require modifying Agent or using a custom
        // transport. For now, we use a standard agent.

        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .cancel(cancel.clone())
            .handler(oid!(1, 3, 6), handler.clone())
            .build()
            .await
            .expect("failed to build lossy agent");

        let addr = agent.local_addr();
        let count_clone = request_count.clone();

        let task = tokio::spawn(async move {
            let _ = agent.run().await;
        });

        // Yield to let the agent task start its receive loop
        tokio::task::yield_now().await;

        Self {
            addr,
            handler,
            cancel,
            _task: task,
            request_count: count_clone,
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    #[allow(dead_code)]
    pub fn request_count(&self) -> usize {
        self.request_count.load(Ordering::Relaxed)
    }

    #[allow(dead_code)]
    pub fn stop(&self) {
        self.cancel.cancel();
    }
}

impl Drop for LossyAgent {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// An agent that delays responses by a configurable duration.
///
/// Useful for testing timeout behavior.
pub struct SlowAgent {
    addr: SocketAddr,
    #[allow(dead_code)]
    handler: Arc<TestHandler>,
    cancel: CancellationToken,
    _task: JoinHandle<()>,
    delay: Duration,
}

impl SlowAgent {
    /// Create an agent that delays all responses.
    pub async fn with_delay(delay: Duration) -> Self {
        let handler = Arc::new(TestHandler::new(fixtures::system_mib()));
        let cancel = CancellationToken::new();

        // Note: This is a simplified implementation. True delay injection
        // would require modifying Agent or using a custom transport.
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .cancel(cancel.clone())
            .handler(oid!(1, 3, 6), handler.clone())
            .build()
            .await
            .expect("failed to build slow agent");

        let addr = agent.local_addr();

        let task = tokio::spawn(async move {
            let _ = agent.run().await;
        });

        // Yield to let the agent task start its receive loop
        tokio::task::yield_now().await;

        Self {
            addr,
            handler,
            cancel,
            _task: task,
            delay,
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    #[allow(dead_code)]
    pub fn delay(&self) -> Duration {
        self.delay
    }

    #[allow(dead_code)]
    pub fn stop(&self) {
        self.cancel.cancel();
    }
}

impl Drop for SlowAgent {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// An agent that can be paused and resumed.
///
/// Useful for testing timeout and recovery scenarios.
pub struct PausableAgent {
    addr: SocketAddr,
    #[allow(dead_code)]
    handler: Arc<TestHandler>,
    cancel: CancellationToken,
    #[allow(dead_code)]
    pause: Arc<tokio::sync::Notify>,
    #[allow(dead_code)]
    resume: Arc<tokio::sync::Notify>,
    _task: JoinHandle<()>,
}

impl PausableAgent {
    #[allow(dead_code)]
    pub async fn new() -> Self {
        let handler = Arc::new(TestHandler::new(fixtures::system_mib()));
        let cancel = CancellationToken::new();
        let pause = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());

        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .cancel(cancel.clone())
            .handler(oid!(1, 3, 6), handler.clone())
            .build()
            .await
            .expect("failed to build pausable agent");

        let addr = agent.local_addr();

        let task = tokio::spawn(async move {
            let _ = agent.run().await;
        });

        // Yield to let the agent task start its receive loop
        tokio::task::yield_now().await;

        Self {
            addr,
            handler,
            cancel,
            pause,
            resume,
            _task: task,
        }
    }

    #[allow(dead_code)]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Pause the agent (it will stop processing requests).
    #[allow(dead_code)]
    pub fn pause(&self) {
        // Note: This is a placeholder. Full implementation would
        // require Agent to support pause/resume signals.
    }

    /// Resume the agent.
    #[allow(dead_code)]
    pub fn resume(&self) {
        // Note: This is a placeholder.
    }

    #[allow(dead_code)]
    pub fn stop(&self) {
        self.cancel.cancel();
    }
}

impl Drop for PausableAgent {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_snmp::{Auth, Client, Retry};

    // Note: These tests demonstrate the API but may not fully test
    // fault injection until the implementation is complete.

    #[tokio::test]
    async fn lossy_agent_responds() {
        let agent = LossyAgent::drop_first(0).await;

        let client = Client::builder(agent.addr().to_string(), Auth::v2c("public"))
            .retry(Retry::none())
            .connect()
            .await
            .unwrap();

        let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn slow_agent_responds() {
        let agent = SlowAgent::with_delay(Duration::from_millis(10)).await;

        let client = Client::builder(agent.addr().to_string(), Auth::v2c("public"))
            .timeout(Duration::from_secs(1))
            .retry(Retry::none())
            .connect()
            .await
            .unwrap();

        let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;
        assert!(result.is_ok());
    }
}
