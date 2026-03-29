#![cfg(feature = "agent")]
//! WALK and BULKWALK operation tests using TestAgent.

mod common;

use async_snmp::{Auth, Client, Value, oid};
use common::{TestAgent, fixtures};

/// WALK iterates through subtree.
#[tokio::test]
async fn walk_iterates_subtree() {
    let agent = TestAgent::new().await;

    let client = Client::builder(agent.addr().to_string(), Auth::v2c("public"))
        .connect()
        .await
        .unwrap();

    let results = client
        .walk(oid!(1, 3, 6, 1, 2, 1, 1))
        .unwrap()
        .collect()
        .await
        .unwrap();

    // Should get all 7 system MIB entries
    assert_eq!(results.len(), 7);

    // First should be sysDescr
    assert_eq!(results[0].oid, oid!(1, 3, 6, 1, 2, 1, 1, 1, 0));
}

/// SNMPv1 WALK iterates through subtree and stops cleanly on noSuchName.
#[tokio::test]
async fn v1_walk_iterates_subtree() {
    let agent = TestAgent::new().await;

    let client = Client::builder(agent.addr().to_string(), Auth::v1("public"))
        .connect()
        .await
        .unwrap();

    let results = client
        .walk(oid!(1, 3, 6, 1, 2, 1, 1))
        .unwrap()
        .collect()
        .await
        .unwrap();

    assert_eq!(results.len(), 7);
    assert_eq!(results[0].oid, oid!(1, 3, 6, 1, 2, 1, 1, 1, 0));
}

/// WALK stops at subtree boundary.
#[tokio::test]
async fn walk_stops_at_boundary() {
    // Create agent with data in two subtrees
    let mut data = fixtures::system_mib();
    data.insert(oid!(1, 3, 6, 1, 4, 1, 1, 0), Value::Integer(99));

    let agent = TestAgent::with_data(data).await;

    let client = Client::builder(agent.addr().to_string(), Auth::v2c("public"))
        .connect()
        .await
        .unwrap();

    // Walk only the system subtree
    let results = client
        .walk(oid!(1, 3, 6, 1, 2, 1, 1))
        .unwrap()
        .collect()
        .await
        .unwrap();

    // Should only get system MIB entries, not enterprise data
    assert_eq!(results.len(), 7);

    for vb in results {
        assert!(vb.oid.starts_with(&oid!(1, 3, 6, 1, 2, 1, 1)));
    }
}

/// WALK on empty subtree returns nothing.
#[tokio::test]
async fn walk_empty_subtree_returns_nothing() {
    let agent = TestAgent::new().await;

    let client = Client::builder(agent.addr().to_string(), Auth::v2c("public"))
        .connect()
        .await
        .unwrap();

    let results = client
        .walk(oid!(1, 3, 6, 1, 99))
        .unwrap()
        .collect()
        .await
        .unwrap();

    assert!(results.is_empty());
}

/// SNMPv1 WALK on empty subtree returns nothing instead of noSuchName.
#[tokio::test]
async fn v1_walk_empty_subtree_returns_nothing() {
    let agent = TestAgent::new().await;

    let client = Client::builder(agent.addr().to_string(), Auth::v1("public"))
        .connect()
        .await
        .unwrap();

    let results = client
        .walk(oid!(1, 3, 6, 1, 99))
        .unwrap()
        .collect()
        .await
        .unwrap();

    assert!(results.is_empty());
}

/// BULKWALK is more efficient than WALK.
#[tokio::test]
async fn bulkwalk_iterates_subtree() {
    // Use interface table for more data
    let data = fixtures::combined([fixtures::system_mib(), fixtures::interface_table(10)]);
    let agent = TestAgent::with_data(data).await;

    let client = Client::builder(agent.addr().to_string(), Auth::v2c("public"))
        .connect()
        .await
        .unwrap();

    let results = client
        .bulk_walk(oid!(1, 3, 6, 1, 2, 1, 2), 25)
        .collect()
        .await
        .unwrap();

    // Should get all interface entries
    // 10 interfaces * 8 columns + ifNumber = 81 entries
    assert!(results.len() > 80);

    for vb in results {
        assert!(vb.oid.starts_with(&oid!(1, 3, 6, 1, 2, 1, 2)));
    }
}

/// BULKWALK respects max_repetitions.
#[tokio::test]
async fn bulkwalk_respects_max_repetitions() {
    let data = fixtures::combined([fixtures::system_mib(), fixtures::interface_table(5)]);
    let agent = TestAgent::with_data(data).await;

    let client = Client::builder(agent.addr().to_string(), Auth::v2c("public"))
        .max_repetitions(10)
        .connect()
        .await
        .unwrap();

    // This should still work, just with smaller batches
    let results = client
        .bulk_walk_default(oid!(1, 3, 6, 1, 2, 1, 2))
        .collect()
        .await
        .unwrap();

    assert!(!results.is_empty());
}

/// GETBULK returns multiple varbinds.
#[tokio::test]
async fn getbulk_returns_multiple_varbinds() {
    let agent = TestAgent::new().await;

    let client = Client::builder(agent.addr().to_string(), Auth::v2c("public"))
        .connect()
        .await
        .unwrap();

    let results = client
        .get_bulk(&[oid!(1, 3, 6, 1, 2, 1, 1)], 0, 5)
        .await
        .unwrap();

    // Should get up to 5 entries
    assert!(results.len() <= 5);
    assert!(!results.is_empty());
}
