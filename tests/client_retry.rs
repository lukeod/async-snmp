#![cfg(feature = "agent")]
//! Retry and timeout behavior tests.

mod common;

use async_snmp::{Auth, Client, Retry, oid};
use common::TestAgent;
use std::time::{Duration, Instant};

/// Client retries on timeout (UDP).
#[tokio::test]
async fn client_retries_on_timeout() {
    // Use a regular agent but with very short timeout
    let agent = TestAgent::new().await;

    let client = Client::builder(agent.addr().to_string(), Auth::v2c("public"))
        .timeout(Duration::from_millis(100))
        .retry(Retry::fixed(2, Duration::ZERO))
        .connect()
        .await
        .unwrap();

    // Should succeed even with short timeout since agent responds quickly
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;
    assert!(result.is_ok());
}

/// Client gives up after max retries.
#[tokio::test]
async fn client_fails_after_max_retries() {
    let agent = TestAgent::new().await;
    let addr = agent.addr().to_string();

    // Stop agent so requests will timeout
    agent.stop();
    tokio::time::sleep(Duration::from_millis(10)).await;

    let start = Instant::now();

    let client = Client::builder(addr, Auth::v2c("public"))
        .timeout(Duration::from_millis(50))
        .retry(Retry::fixed(2, Duration::ZERO)) // 3 total attempts
        .connect()
        .await
        .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;

    assert!(result.is_err());

    // Should have taken ~150ms (3 attempts * 50ms timeout)
    let elapsed = start.elapsed();
    assert!(elapsed >= Duration::from_millis(100));
    assert!(elapsed < Duration::from_millis(500));
}

/// Zero retries means single attempt.
#[tokio::test]
async fn zero_retries_single_attempt() {
    let agent = TestAgent::new().await;
    let addr = agent.addr().to_string();

    agent.stop();
    tokio::time::sleep(Duration::from_millis(10)).await;

    let start = Instant::now();

    let client = Client::builder(addr, Auth::v2c("public"))
        .timeout(Duration::from_millis(50))
        .retry(Retry::none()) // No retries
        .connect()
        .await
        .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;

    assert!(result.is_err());

    // Should have taken ~50ms (single attempt)
    let elapsed = start.elapsed();
    assert!(elapsed >= Duration::from_millis(30));
    assert!(elapsed < Duration::from_millis(200));
}

/// TCP transport doesn't retry (is_reliable = true).
#[tokio::test]
async fn tcp_no_retry() {
    // This test requires TCP support in TestAgent.
    // For now, just document the expected behavior:
    //
    // When using TCP:
    // - is_reliable() returns true
    // - Client skips retries
    // - Connection errors fail immediately
}
