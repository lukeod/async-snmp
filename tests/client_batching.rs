#![cfg(feature = "agent")]
//! Request batching tests using TestAgent.

mod common;

use async_snmp::{Auth, Client, Oid, Value, oid};
use common::{TestAgent, fixtures};

/// GET_MANY with more OIDs than max_oids_per_request batches automatically.
#[tokio::test]
async fn get_many_batches_large_requests() {
    // Create agent with many OIDs
    let mut data = fixtures::system_mib();
    for i in 0..50 {
        data.insert(
            oid!(1, 3, 6, 1, 4, 1, 99999, 1, i as u32),
            Value::Integer(i),
        );
    }
    let agent = TestAgent::with_data(data).await;

    let client = Client::builder(agent.addr().to_string(), Auth::v2c("public"))
        .max_oids_per_request(10) // Force batching
        .connect()
        .await
        .unwrap();

    // Request 50 OIDs
    let oids: Vec<Oid> = (0..50)
        .map(|i| oid!(1, 3, 6, 1, 4, 1, 99999, 1, i as u32))
        .collect();

    let results = client.get_many(&oids).await.unwrap();

    // Should get all 50 results
    assert_eq!(results.len(), 50);

    for (i, result) in results.iter().enumerate() {
        assert_eq!(result.value, Value::Integer(i as i32));
    }
}

/// Batching preserves order.
#[tokio::test]
async fn batching_preserves_order() {
    let mut data = fixtures::system_mib();
    for i in 0..20 {
        data.insert(
            oid!(1, 3, 6, 1, 4, 1, 99999, 2, i as u32),
            Value::Integer(i * 10),
        );
    }
    let agent = TestAgent::with_data(data).await;

    let client = Client::builder(agent.addr().to_string(), Auth::v2c("public"))
        .max_oids_per_request(5)
        .connect()
        .await
        .unwrap();

    let oids: Vec<Oid> = (0..20)
        .map(|i| oid!(1, 3, 6, 1, 4, 1, 99999, 2, i as u32))
        .collect();

    let results = client.get_many(&oids).await.unwrap();

    // Results should be in request order
    for (i, result) in results.iter().enumerate() {
        assert_eq!(result.oid, oids[i]);
        assert_eq!(result.value, Value::Integer((i * 10) as i32));
    }
}

/// Single OID request doesn't batch.
#[tokio::test]
async fn single_oid_no_batching() {
    let agent = TestAgent::new().await;

    let client = Client::builder(agent.addr().to_string(), Auth::v2c("public"))
        .max_oids_per_request(10)
        .connect()
        .await
        .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();

    assert_eq!(result.value.as_str(), Some("Test SNMP Agent"));
}

/// Empty request returns empty result.
#[tokio::test]
async fn empty_request_returns_empty() {
    let agent = TestAgent::new().await;

    let client = Client::builder(agent.addr().to_string(), Auth::v2c("public"))
        .connect()
        .await
        .unwrap();

    let results = client.get_many(&[]).await.unwrap();

    assert!(results.is_empty());
}
