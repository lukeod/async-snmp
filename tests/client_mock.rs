//! Client protocol tests using MockTransport.
//!
//! These tests verify client behavior without network dependencies by using
//! a programmable mock transport that simulates SNMP agent responses.
//!
//! Run with: `cargo test --test client_mock`

mod common;

use async_snmp::{
    Client, ClientConfig, Error, ErrorStatus, OidOrdering, Value, Version, WalkMode, oid,
    transport::{MockTransport, ResponseBuilder},
};
use bytes::Bytes;
use std::time::Duration;

// ============================================================================
// Helper functions
// ============================================================================

fn create_mock_client(mock: MockTransport) -> Client<MockTransport> {
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

fn create_mock_client_v1(mock: MockTransport) -> Client<MockTransport> {
    let config = ClientConfig {
        version: Version::V1,
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

// ============================================================================
// GET Operation Tests
// ============================================================================

#[tokio::test]
async fn test_get_single_oid_octet_string() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(
            oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
            Value::OctetString("Test Device".into()),
        )
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock.clone());
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();

    assert_eq!(result.oid, oid!(1, 3, 6, 1, 2, 1, 1, 1, 0));
    assert!(matches!(result.value, Value::OctetString(ref s) if s.as_ref() == b"Test Device"));

    // Verify request was sent
    let requests = mock.requests();
    assert_eq!(requests.len(), 1);
}

#[tokio::test]
async fn test_get_single_oid_integer() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(oid!(1, 3, 6, 1, 2, 1, 1, 7, 0), Value::Integer(72))
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock);
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 7, 0)).await.unwrap();

    assert_eq!(result.value, Value::Integer(72));
}

#[tokio::test]
async fn test_get_single_oid_timeticks() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(oid!(1, 3, 6, 1, 2, 1, 1, 3, 0), Value::TimeTicks(123456))
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock);
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 3, 0)).await.unwrap();

    assert_eq!(result.value, Value::TimeTicks(123456));
}

#[tokio::test]
async fn test_get_single_oid_counter32() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(
            oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 10, 1),
            Value::Counter32(999999),
        )
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock);
    let result = client
        .get(&oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 10, 1))
        .await
        .unwrap();

    assert_eq!(result.value, Value::Counter32(999999));
}

#[tokio::test]
async fn test_get_single_oid_counter64() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(
            oid!(1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 6, 1),
            Value::Counter64(123456789012345),
        )
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock);
    let result = client
        .get(&oid!(1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 6, 1))
        .await
        .unwrap();

    assert_eq!(result.value, Value::Counter64(123456789012345));
}

#[tokio::test]
async fn test_get_single_oid_gauge32() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(
            oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 5, 1),
            Value::Gauge32(1000000000),
        )
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock);
    let result = client
        .get(&oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 5, 1))
        .await
        .unwrap();

    assert_eq!(result.value, Value::Gauge32(1000000000));
}

#[tokio::test]
async fn test_get_single_oid_ip_address() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(
            oid!(1, 3, 6, 1, 2, 1, 4, 20, 1, 1, 192, 168, 1, 1),
            Value::IpAddress([192, 168, 1, 1]),
        )
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock);
    let result = client
        .get(&oid!(1, 3, 6, 1, 2, 1, 4, 20, 1, 1, 192, 168, 1, 1))
        .await
        .unwrap();

    assert_eq!(result.value, Value::IpAddress([192, 168, 1, 1]));
}

#[tokio::test]
async fn test_get_single_oid_object_identifier() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(
            oid!(1, 3, 6, 1, 2, 1, 1, 2, 0),
            Value::ObjectIdentifier(oid!(1, 3, 6, 1, 4, 1, 99999)),
        )
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock);
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 2, 0)).await.unwrap();

    assert_eq!(
        result.value,
        Value::ObjectIdentifier(oid!(1, 3, 6, 1, 4, 1, 99999))
    );
}

// ============================================================================
// GET NoSuchObject/NoSuchInstance Tests
// ============================================================================

#[tokio::test]
async fn test_get_no_such_object() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(oid!(1, 3, 6, 1, 99, 99, 99, 0), Value::NoSuchObject)
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock);
    let result = client.get(&oid!(1, 3, 6, 1, 99, 99, 99, 0)).await.unwrap();

    assert_eq!(result.value, Value::NoSuchObject);
}

#[tokio::test]
async fn test_get_no_such_instance() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(oid!(1, 3, 6, 1, 2, 1, 1, 1, 99), Value::NoSuchInstance)
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock);
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 99)).await.unwrap();

    assert_eq!(result.value, Value::NoSuchInstance);
}

#[tokio::test]
async fn test_get_end_of_mib_view() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(oid!(1, 3, 6, 1, 2, 1, 99999), Value::EndOfMibView)
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock);
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 99999)).await.unwrap();

    assert_eq!(result.value, Value::EndOfMibView);
}

// ============================================================================
// GET Multiple OIDs Tests
// ============================================================================

#[tokio::test]
async fn test_get_many_three_oids() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(
            oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
            Value::OctetString("Test".into()),
        )
        .varbind(oid!(1, 3, 6, 1, 2, 1, 1, 3, 0), Value::TimeTicks(12345))
        .varbind(
            oid!(1, 3, 6, 1, 2, 1, 1, 5, 0),
            Value::OctetString("hostname".into()),
        )
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock);
    let oids = [
        oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
        oid!(1, 3, 6, 1, 2, 1, 1, 3, 0),
        oid!(1, 3, 6, 1, 2, 1, 1, 5, 0),
    ];
    let results = client.get_many(&oids).await.unwrap();

    assert_eq!(results.len(), 3);
    assert_eq!(results[0].oid, oid!(1, 3, 6, 1, 2, 1, 1, 1, 0));
    assert_eq!(results[1].oid, oid!(1, 3, 6, 1, 2, 1, 1, 3, 0));
    assert_eq!(results[2].oid, oid!(1, 3, 6, 1, 2, 1, 1, 5, 0));
}

#[tokio::test]
async fn test_get_many_empty_list() {
    let mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let client = create_mock_client(mock.clone());
    let results = client.get_many(&[]).await.unwrap();

    assert!(results.is_empty());
    // No requests should be sent for empty list
    assert!(mock.requests().is_empty());
}

#[tokio::test]
async fn test_get_many_batching() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    // First batch response (2 OIDs)
    let response1 = ResponseBuilder::new(1)
        .varbind(
            oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
            Value::OctetString("desc".into()),
        )
        .varbind(oid!(1, 3, 6, 1, 2, 1, 1, 3, 0), Value::TimeTicks(100))
        .build_v2c(b"public");
    mock.queue_response(response1);

    // Second batch response (2 OIDs)
    let response2 = ResponseBuilder::new(2)
        .varbind(
            oid!(1, 3, 6, 1, 2, 1, 1, 5, 0),
            Value::OctetString("name".into()),
        )
        .varbind(
            oid!(1, 3, 6, 1, 2, 1, 1, 6, 0),
            Value::OctetString("loc".into()),
        )
        .build_v2c(b"public");
    mock.queue_response(response2);

    // Third batch response (1 OID)
    let response3 = ResponseBuilder::new(3)
        .varbind(oid!(1, 3, 6, 1, 2, 1, 1, 7, 0), Value::Integer(72))
        .build_v2c(b"public");
    mock.queue_response(response3);

    // Create client with max_oids_per_request = 2
    let config = ClientConfig {
        version: Version::V2c,
        community: Bytes::from_static(b"public"),
        timeout: Duration::from_secs(1),
        retries: 0,
        max_oids_per_request: 2,
        v3_security: None,
        walk_mode: WalkMode::Auto,
        oid_ordering: OidOrdering::Strict,
        max_walk_results: None,
        max_repetitions: 25,
    };
    let client = Client::new(mock.clone(), config);

    let oids = [
        oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
        oid!(1, 3, 6, 1, 2, 1, 1, 3, 0),
        oid!(1, 3, 6, 1, 2, 1, 1, 5, 0),
        oid!(1, 3, 6, 1, 2, 1, 1, 6, 0),
        oid!(1, 3, 6, 1, 2, 1, 1, 7, 0),
    ];
    let results = client.get_many(&oids).await.unwrap();

    assert_eq!(results.len(), 5);
    // Verify 3 requests were sent (batches of 2, 2, 1)
    assert_eq!(mock.requests().len(), 3);
}

// ============================================================================
// GETNEXT Tests
// ============================================================================

#[tokio::test]
async fn test_getnext_returns_next_oid() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(
            oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
            Value::OctetString("Test".into()),
        )
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock);
    let result = client.get_next(&oid!(1, 3, 6, 1, 2, 1, 1)).await.unwrap();

    // GETNEXT should return the next OID after the requested one
    assert_eq!(result.oid, oid!(1, 3, 6, 1, 2, 1, 1, 1, 0));
}

#[tokio::test]
async fn test_getnext_end_of_mib() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(oid!(1, 3, 6, 1, 2, 1, 99999), Value::EndOfMibView)
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock);
    let result = client
        .get_next(&oid!(1, 3, 6, 1, 2, 1, 99999))
        .await
        .unwrap();

    assert_eq!(result.value, Value::EndOfMibView);
}

// ============================================================================
// SET Tests
// ============================================================================

#[tokio::test]
async fn test_set_integer_value() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0), Value::Integer(42))
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock);
    let result = client
        .set(&oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0), Value::Integer(42))
        .await
        .unwrap();

    assert_eq!(result.value, Value::Integer(42));
}

#[tokio::test]
async fn test_set_octet_string_value() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(
            oid!(1, 3, 6, 1, 2, 1, 1, 5, 0),
            Value::OctetString("NewHostname".into()),
        )
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock);
    let result = client
        .set(
            &oid!(1, 3, 6, 1, 2, 1, 1, 5, 0),
            Value::OctetString("NewHostname".into()),
        )
        .await
        .unwrap();

    assert!(matches!(result.value, Value::OctetString(ref s) if s.as_ref() == b"NewHostname"));
}

// ============================================================================
// GETBULK Tests
// ============================================================================

#[tokio::test]
async fn test_getbulk_returns_multiple_varbinds() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(
            oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
            Value::OctetString("desc".into()),
        )
        .varbind(
            oid!(1, 3, 6, 1, 2, 1, 1, 2, 0),
            Value::ObjectIdentifier(oid!(1, 3, 6, 1, 4, 1, 9999)),
        )
        .varbind(oid!(1, 3, 6, 1, 2, 1, 1, 3, 0), Value::TimeTicks(12345))
        .varbind(
            oid!(1, 3, 6, 1, 2, 1, 1, 4, 0),
            Value::OctetString("admin".into()),
        )
        .varbind(
            oid!(1, 3, 6, 1, 2, 1, 1, 5, 0),
            Value::OctetString("hostname".into()),
        )
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock);
    let results = client
        .get_bulk(&[oid!(1, 3, 6, 1, 2, 1, 1)], 0, 5)
        .await
        .unwrap();

    assert_eq!(results.len(), 5);
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[tokio::test]
async fn test_timeout_error() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());
    mock.queue_timeout();

    let client = create_mock_client(mock);
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;

    assert!(matches!(result, Err(Error::Timeout { .. })));
}

#[tokio::test]
async fn test_snmp_error_no_such_name() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(oid!(1, 3, 6, 1, 99, 99), Value::Null)
        .error_status(ErrorStatus::NoSuchName.as_i32())
        .error_index(1)
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock);
    let result = client.get(&oid!(1, 3, 6, 1, 99, 99)).await;

    match result {
        Err(Error::Snmp { status, index, .. }) => {
            assert_eq!(status, ErrorStatus::NoSuchName);
            assert_eq!(index, 1);
        }
        _ => panic!("Expected Snmp error"),
    }
}

#[tokio::test]
async fn test_snmp_error_not_writable() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(
            oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
            Value::OctetString("test".into()),
        )
        .error_status(ErrorStatus::NotWritable.as_i32())
        .error_index(1)
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock);
    let result = client
        .set(
            &oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
            Value::OctetString("test".into()),
        )
        .await;

    match result {
        Err(Error::Snmp { status, .. }) => {
            assert_eq!(status, ErrorStatus::NotWritable);
        }
        _ => panic!("Expected Snmp error"),
    }
}

#[tokio::test]
async fn test_snmp_error_gen_err() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(oid!(1, 3, 6, 1, 2, 1, 1, 1, 0), Value::Null)
        .error_status(ErrorStatus::GenErr.as_i32())
        .error_index(1)
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock);
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;

    match result {
        Err(Error::Snmp { status, .. }) => {
            assert_eq!(status, ErrorStatus::GenErr);
        }
        _ => panic!("Expected Snmp error"),
    }
}

// ============================================================================
// V1 Specific Tests
// ============================================================================

#[tokio::test]
async fn test_v1_get_single_oid() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(
            oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
            Value::OctetString("Test Device".into()),
        )
        .build_v1(b"public");
    mock.queue_response(response);

    let client = create_mock_client_v1(mock);
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();

    assert_eq!(result.oid, oid!(1, 3, 6, 1, 2, 1, 1, 1, 0));
    assert!(matches!(result.value, Value::OctetString(_)));
}

// ============================================================================
// Retry Logic Tests
// ============================================================================

#[tokio::test]
async fn test_retry_on_timeout_success_on_retry() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    // First attempt times out
    mock.queue_timeout();

    // Second attempt succeeds
    let response = ResponseBuilder::new(1)
        .varbind(
            oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
            Value::OctetString("Success".into()),
        )
        .build_v2c(b"public");
    mock.queue_response(response);

    // Create client with 1 retry
    let config = ClientConfig {
        version: Version::V2c,
        community: Bytes::from_static(b"public"),
        timeout: Duration::from_secs(1),
        retries: 1,
        max_oids_per_request: 10,
        v3_security: None,
        walk_mode: WalkMode::Auto,
        oid_ordering: OidOrdering::Strict,
        max_walk_results: None,
        max_repetitions: 25,
    };
    let client = Client::new(mock.clone(), config);

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert!(matches!(result.value, Value::OctetString(_)));

    // Should have sent 2 requests (original + 1 retry)
    assert_eq!(mock.requests().len(), 2);
}

#[tokio::test]
async fn test_retry_exhaustion() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    // All attempts time out
    mock.queue_timeout();
    mock.queue_timeout();
    mock.queue_timeout();

    // Create client with 2 retries
    let config = ClientConfig {
        version: Version::V2c,
        community: Bytes::from_static(b"public"),
        timeout: Duration::from_millis(10),
        retries: 2,
        max_oids_per_request: 10,
        v3_security: None,
        walk_mode: WalkMode::Auto,
        oid_ordering: OidOrdering::Strict,
        max_walk_results: None,
        max_repetitions: 25,
    };
    let client = Client::new(mock.clone(), config);

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;
    assert!(result.is_err());

    // Should have sent 3 requests (original + 2 retries)
    assert_eq!(mock.requests().len(), 3);
}

// ============================================================================
// Edge Cases
// ============================================================================

#[tokio::test]
async fn test_large_oid() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    // OID with 20+ arcs (tests SmallVec heap allocation)
    let large_oid = oid!(
        1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10
    );

    let response = ResponseBuilder::new(1)
        .varbind(large_oid.clone(), Value::Integer(42))
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock);
    let result = client.get(&large_oid).await.unwrap();

    assert_eq!(result.oid, large_oid);
}

#[tokio::test]
async fn test_large_counter64_value() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let large_value = u64::MAX;
    let response = ResponseBuilder::new(1)
        .varbind(
            oid!(1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 6, 1),
            Value::Counter64(large_value),
        )
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock);
    let result = client
        .get(&oid!(1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 6, 1))
        .await
        .unwrap();

    assert_eq!(result.value, Value::Counter64(large_value));
}

#[tokio::test]
async fn test_empty_octet_string() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(
            oid!(1, 3, 6, 1, 2, 1, 1, 4, 0),
            Value::OctetString(Bytes::new()),
        )
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock);
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 4, 0)).await.unwrap();

    assert!(matches!(result.value, Value::OctetString(ref s) if s.is_empty()));
}

#[tokio::test]
async fn test_null_value() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(oid!(1, 3, 6, 1, 2, 1, 1, 8, 0), Value::Null)
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock);
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 8, 0)).await.unwrap();

    assert_eq!(result.value, Value::Null);
}

// ============================================================================
// Request ID Mismatch Tests (CRIT-001)
// ============================================================================

#[tokio::test]
async fn test_request_id_mismatch_rejected() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    // Queue a response with a DIFFERENT request ID than what the client will send
    // The client starts with request_id=1, so we send a response with request_id=9999
    let response = ResponseBuilder::new(9999) // Wrong request ID
        .varbind(
            oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
            Value::OctetString("Test".into()),
        )
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock);
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;

    // Should fail with RequestIdMismatch error
    match result {
        Err(Error::RequestIdMismatch { expected, actual }) => {
            // Expected is what the client sent (starts at 1), actual is 9999
            assert_ne!(expected, actual);
            assert_eq!(actual, 9999);
        }
        Err(Error::Timeout { .. }) => {
            // Also acceptable - client may time out waiting for correct response
        }
        other => panic!(
            "Expected RequestIdMismatch or Timeout error, got {:?}",
            other
        ),
    }
}

#[tokio::test]
async fn test_request_id_correct_accepted() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    // Queue a response with matching request ID
    let response = ResponseBuilder::new(1) // Correct request ID
        .varbind(
            oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
            Value::OctetString("Test".into()),
        )
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock);
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;

    // Should succeed
    assert!(
        result.is_ok(),
        "Expected success with matching request ID, got {:?}",
        result
    );
}

// ============================================================================
// ErrorStatus Handling Tests (RFC 3416 error codes)
// ============================================================================

#[tokio::test]
async fn test_error_status_too_big() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(oid!(1, 3, 6, 1, 2, 1, 1, 1, 0), Value::Null)
        .error_status(ErrorStatus::TooBig.as_i32())
        .error_index(0) // TooBig typically has index 0
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock);
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;

    match result {
        Err(Error::Snmp { status, index, .. }) => {
            assert_eq!(status, ErrorStatus::TooBig);
            assert_eq!(index, 0);
        }
        _ => panic!("Expected TooBig error, got {:?}", result),
    }
}

#[tokio::test]
async fn test_error_status_bad_value() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0), Value::Integer(42))
        .error_status(ErrorStatus::BadValue.as_i32())
        .error_index(1)
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock);
    let result = client
        .set(&oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0), Value::Integer(42))
        .await;

    match result {
        Err(Error::Snmp { status, index, .. }) => {
            assert_eq!(status, ErrorStatus::BadValue);
            assert_eq!(index, 1);
        }
        _ => panic!("Expected BadValue error, got {:?}", result),
    }
}

#[tokio::test]
async fn test_error_status_read_only() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(
            oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
            Value::OctetString("test".into()),
        )
        .error_status(ErrorStatus::ReadOnly.as_i32())
        .error_index(1)
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock);
    let result = client
        .set(
            &oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
            Value::OctetString("test".into()),
        )
        .await;

    match result {
        Err(Error::Snmp { status, .. }) => {
            assert_eq!(status, ErrorStatus::ReadOnly);
        }
        _ => panic!("Expected ReadOnly error, got {:?}", result),
    }
}

#[tokio::test]
async fn test_error_status_no_access() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(oid!(1, 3, 6, 1, 2, 1, 1, 1, 0), Value::Null)
        .error_status(ErrorStatus::NoAccess.as_i32())
        .error_index(1)
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock);
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;

    match result {
        Err(Error::Snmp { status, .. }) => {
            assert_eq!(status, ErrorStatus::NoAccess);
        }
        _ => panic!("Expected NoAccess error, got {:?}", result),
    }
}

#[tokio::test]
async fn test_error_status_wrong_type() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(oid!(1, 3, 6, 1, 2, 1, 1, 5, 0), Value::Integer(42))
        .error_status(ErrorStatus::WrongType.as_i32())
        .error_index(1)
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock);
    // Try to set an Integer where OctetString is expected
    let result = client
        .set(&oid!(1, 3, 6, 1, 2, 1, 1, 5, 0), Value::Integer(42))
        .await;

    match result {
        Err(Error::Snmp { status, .. }) => {
            assert_eq!(status, ErrorStatus::WrongType);
        }
        _ => panic!("Expected WrongType error, got {:?}", result),
    }
}

#[tokio::test]
async fn test_error_status_wrong_length() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(
            oid!(1, 3, 6, 1, 2, 1, 1, 5, 0),
            Value::OctetString("x".repeat(1000).into()),
        )
        .error_status(ErrorStatus::WrongLength.as_i32())
        .error_index(1)
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock);
    let result = client
        .set(
            &oid!(1, 3, 6, 1, 2, 1, 1, 5, 0),
            Value::OctetString("x".repeat(1000).into()),
        )
        .await;

    match result {
        Err(Error::Snmp { status, .. }) => {
            assert_eq!(status, ErrorStatus::WrongLength);
        }
        _ => panic!("Expected WrongLength error, got {:?}", result),
    }
}

#[tokio::test]
async fn test_error_status_wrong_value() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0), Value::Integer(-1))
        .error_status(ErrorStatus::WrongValue.as_i32())
        .error_index(1)
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock);
    let result = client
        .set(&oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0), Value::Integer(-1))
        .await;

    match result {
        Err(Error::Snmp { status, .. }) => {
            assert_eq!(status, ErrorStatus::WrongValue);
        }
        _ => panic!("Expected WrongValue error, got {:?}", result),
    }
}

#[tokio::test]
async fn test_error_status_no_creation() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(oid!(1, 3, 6, 1, 4, 1, 99999, 1, 999), Value::Integer(1))
        .error_status(ErrorStatus::NoCreation.as_i32())
        .error_index(1)
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock);
    let result = client
        .set(&oid!(1, 3, 6, 1, 4, 1, 99999, 1, 999), Value::Integer(1))
        .await;

    match result {
        Err(Error::Snmp { status, .. }) => {
            assert_eq!(status, ErrorStatus::NoCreation);
        }
        _ => panic!("Expected NoCreation error, got {:?}", result),
    }
}

#[tokio::test]
async fn test_error_status_inconsistent_value() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0), Value::Integer(42))
        .error_status(ErrorStatus::InconsistentValue.as_i32())
        .error_index(1)
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock);
    let result = client
        .set(&oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0), Value::Integer(42))
        .await;

    match result {
        Err(Error::Snmp { status, .. }) => {
            assert_eq!(status, ErrorStatus::InconsistentValue);
        }
        _ => panic!("Expected InconsistentValue error, got {:?}", result),
    }
}

#[tokio::test]
async fn test_error_status_resource_unavailable() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0), Value::Integer(42))
        .error_status(ErrorStatus::ResourceUnavailable.as_i32())
        .error_index(1)
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock);
    let result = client
        .set(&oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0), Value::Integer(42))
        .await;

    match result {
        Err(Error::Snmp { status, .. }) => {
            assert_eq!(status, ErrorStatus::ResourceUnavailable);
        }
        _ => panic!("Expected ResourceUnavailable error, got {:?}", result),
    }
}

#[tokio::test]
async fn test_error_status_commit_failed() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0), Value::Integer(42))
        .error_status(ErrorStatus::CommitFailed.as_i32())
        .error_index(1)
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock);
    let result = client
        .set(&oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0), Value::Integer(42))
        .await;

    match result {
        Err(Error::Snmp { status, .. }) => {
            assert_eq!(status, ErrorStatus::CommitFailed);
        }
        _ => panic!("Expected CommitFailed error, got {:?}", result),
    }
}

#[tokio::test]
async fn test_error_status_undo_failed() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0), Value::Integer(42))
        .error_status(ErrorStatus::UndoFailed.as_i32())
        .error_index(1)
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock);
    let result = client
        .set(&oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0), Value::Integer(42))
        .await;

    match result {
        Err(Error::Snmp { status, .. }) => {
            assert_eq!(status, ErrorStatus::UndoFailed);
        }
        _ => panic!("Expected UndoFailed error, got {:?}", result),
    }
}

#[tokio::test]
async fn test_error_status_authorization_error() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(oid!(1, 3, 6, 1, 2, 1, 1, 1, 0), Value::Null)
        .error_status(ErrorStatus::AuthorizationError.as_i32())
        .error_index(1)
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock);
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;

    match result {
        Err(Error::Snmp { status, .. }) => {
            assert_eq!(status, ErrorStatus::AuthorizationError);
        }
        _ => panic!("Expected AuthorizationError error, got {:?}", result),
    }
}

#[tokio::test]
async fn test_error_status_inconsistent_name() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(oid!(1, 3, 6, 1, 4, 1, 99999, 1, 999), Value::Integer(1))
        .error_status(ErrorStatus::InconsistentName.as_i32())
        .error_index(1)
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock);
    let result = client
        .set(&oid!(1, 3, 6, 1, 4, 1, 99999, 1, 999), Value::Integer(1))
        .await;

    match result {
        Err(Error::Snmp { status, .. }) => {
            assert_eq!(status, ErrorStatus::InconsistentName);
        }
        _ => panic!("Expected InconsistentName error, got {:?}", result),
    }
}

#[tokio::test]
async fn test_error_status_wrong_encoding() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(
            oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0),
            Value::OctetString("test".into()),
        )
        .error_status(ErrorStatus::WrongEncoding.as_i32())
        .error_index(1)
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock);
    let result = client
        .set(
            &oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0),
            Value::OctetString("test".into()),
        )
        .await;

    match result {
        Err(Error::Snmp { status, .. }) => {
            assert_eq!(status, ErrorStatus::WrongEncoding);
        }
        _ => panic!("Expected WrongEncoding error, got {:?}", result),
    }
}

#[tokio::test]
async fn test_error_index_zero_on_general_error() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    // Some errors like TooBig use index 0 to indicate no specific varbind
    let response = ResponseBuilder::new(1)
        .varbind(oid!(1, 3, 6, 1, 2, 1, 1, 1, 0), Value::Null)
        .error_status(ErrorStatus::GenErr.as_i32())
        .error_index(0) // index 0 means "general error, no specific varbind"
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock);
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;

    match result {
        Err(Error::Snmp { status, index, .. }) => {
            assert_eq!(status, ErrorStatus::GenErr);
            assert_eq!(index, 0, "Error index 0 should be preserved");
        }
        _ => panic!("Expected GenErr error, got {:?}", result),
    }
}

#[tokio::test]
async fn test_error_index_points_to_correct_varbind() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    // Error on the third varbind in a multi-varbind request
    let response = ResponseBuilder::new(1)
        .varbind(
            oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
            Value::OctetString("ok".into()),
        )
        .varbind(oid!(1, 3, 6, 1, 2, 1, 1, 3, 0), Value::TimeTicks(100))
        .varbind(oid!(1, 3, 6, 1, 99, 99, 99, 0), Value::Null) // This one causes error
        .error_status(ErrorStatus::NoSuchName.as_i32())
        .error_index(3) // Points to third varbind
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock);
    let oids = [
        oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
        oid!(1, 3, 6, 1, 2, 1, 1, 3, 0),
        oid!(1, 3, 6, 1, 99, 99, 99, 0),
    ];
    let result = client.get_many(&oids).await;

    match result {
        Err(Error::Snmp {
            status, index, oid, ..
        }) => {
            assert_eq!(status, ErrorStatus::NoSuchName);
            assert_eq!(index, 3, "Error index should point to third varbind");
            // The error should include the problematic OID
            assert!(oid.is_some(), "Error should include the OID");
            assert_eq!(oid.unwrap(), oid!(1, 3, 6, 1, 99, 99, 99, 0));
        }
        _ => panic!("Expected NoSuchName error, got {:?}", result),
    }
}

// ============================================================================
// Negative Integer Tests
// ============================================================================

#[tokio::test]
async fn test_negative_integer_value() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0), Value::Integer(-42))
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock);
    let result = client
        .get(&oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0))
        .await
        .unwrap();

    assert_eq!(result.value, Value::Integer(-42));
}

#[tokio::test]
async fn test_integer_min_value() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(
            oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0),
            Value::Integer(i32::MIN),
        )
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock);
    let result = client
        .get(&oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0))
        .await
        .unwrap();

    assert_eq!(result.value, Value::Integer(i32::MIN));
}

#[tokio::test]
async fn test_integer_max_value() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(
            oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0),
            Value::Integer(i32::MAX),
        )
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock);
    let result = client
        .get(&oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0))
        .await
        .unwrap();

    assert_eq!(result.value, Value::Integer(i32::MAX));
}

#[tokio::test]
async fn test_counter32_max_value() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(
            oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 10, 1),
            Value::Counter32(u32::MAX),
        )
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock);
    let result = client
        .get(&oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 10, 1))
        .await
        .unwrap();

    assert_eq!(result.value, Value::Counter32(u32::MAX));
}

#[tokio::test]
async fn test_gauge32_max_value() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(
            oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 5, 1),
            Value::Gauge32(u32::MAX),
        )
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock);
    let result = client
        .get(&oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 5, 1))
        .await
        .unwrap();

    assert_eq!(result.value, Value::Gauge32(u32::MAX));
}

// ============================================================================
// V1 Protocol Coverage Tests
// ============================================================================

#[tokio::test]
async fn test_v1_getnext() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(
            oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
            Value::OctetString("System Description".into()),
        )
        .build_v1(b"public");
    mock.queue_response(response);

    let client = create_mock_client_v1(mock);
    let result = client.get_next(&oid!(1, 3, 6, 1, 2, 1, 1)).await.unwrap();

    assert_eq!(result.oid, oid!(1, 3, 6, 1, 2, 1, 1, 1, 0));
    assert!(matches!(result.value, Value::OctetString(_)));
}

#[tokio::test]
async fn test_v1_set_integer() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0), Value::Integer(42))
        .build_v1(b"public");
    mock.queue_response(response);

    let client = create_mock_client_v1(mock);
    let result = client
        .set(&oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0), Value::Integer(42))
        .await
        .unwrap();

    assert_eq!(result.value, Value::Integer(42));
}

#[tokio::test]
async fn test_v1_set_octet_string() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(
            oid!(1, 3, 6, 1, 2, 1, 1, 5, 0),
            Value::OctetString("NewHostname".into()),
        )
        .build_v1(b"public");
    mock.queue_response(response);

    let client = create_mock_client_v1(mock);
    let result = client
        .set(
            &oid!(1, 3, 6, 1, 2, 1, 1, 5, 0),
            Value::OctetString("NewHostname".into()),
        )
        .await
        .unwrap();

    assert!(matches!(result.value, Value::OctetString(ref s) if s.as_ref() == b"NewHostname"));
}

#[tokio::test]
async fn test_v1_get_many() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(
            oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
            Value::OctetString("Device".into()),
        )
        .varbind(oid!(1, 3, 6, 1, 2, 1, 1, 3, 0), Value::TimeTicks(12345))
        .varbind(
            oid!(1, 3, 6, 1, 2, 1, 1, 5, 0),
            Value::OctetString("hostname".into()),
        )
        .build_v1(b"public");
    mock.queue_response(response);

    let client = create_mock_client_v1(mock);
    let oids = [
        oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
        oid!(1, 3, 6, 1, 2, 1, 1, 3, 0),
        oid!(1, 3, 6, 1, 2, 1, 1, 5, 0),
    ];
    let results = client.get_many(&oids).await.unwrap();

    assert_eq!(results.len(), 3);
    assert_eq!(results[0].oid, oid!(1, 3, 6, 1, 2, 1, 1, 1, 0));
    assert_eq!(results[1].oid, oid!(1, 3, 6, 1, 2, 1, 1, 3, 0));
    assert_eq!(results[2].oid, oid!(1, 3, 6, 1, 2, 1, 1, 5, 0));
}

#[tokio::test]
async fn test_v1_error_no_such_name() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    // V1 uses NoSuchName error instead of NoSuchObject exception value
    let response = ResponseBuilder::new(1)
        .varbind(oid!(1, 3, 6, 1, 99, 99, 99), Value::Null)
        .error_status(ErrorStatus::NoSuchName.as_i32())
        .error_index(1)
        .build_v1(b"public");
    mock.queue_response(response);

    let client = create_mock_client_v1(mock);
    let result = client.get(&oid!(1, 3, 6, 1, 99, 99, 99)).await;

    match result {
        Err(Error::Snmp { status, index, .. }) => {
            assert_eq!(status, ErrorStatus::NoSuchName);
            assert_eq!(index, 1);
        }
        _ => panic!("Expected NoSuchName error, got {:?}", result),
    }
}

#[tokio::test]
async fn test_v1_error_too_big() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(oid!(1, 3, 6, 1, 2, 1, 1, 1, 0), Value::Null)
        .error_status(ErrorStatus::TooBig.as_i32())
        .error_index(0)
        .build_v1(b"public");
    mock.queue_response(response);

    let client = create_mock_client_v1(mock);
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;

    match result {
        Err(Error::Snmp { status, .. }) => {
            assert_eq!(status, ErrorStatus::TooBig);
        }
        _ => panic!("Expected TooBig error, got {:?}", result),
    }
}

#[tokio::test]
async fn test_v1_error_bad_value() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0), Value::Integer(-1))
        .error_status(ErrorStatus::BadValue.as_i32())
        .error_index(1)
        .build_v1(b"public");
    mock.queue_response(response);

    let client = create_mock_client_v1(mock);
    let result = client
        .set(&oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0), Value::Integer(-1))
        .await;

    match result {
        Err(Error::Snmp { status, index, .. }) => {
            assert_eq!(status, ErrorStatus::BadValue);
            assert_eq!(index, 1);
        }
        _ => panic!("Expected BadValue error, got {:?}", result),
    }
}

#[tokio::test]
async fn test_v1_error_read_only() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(
            oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
            Value::OctetString("test".into()),
        )
        .error_status(ErrorStatus::ReadOnly.as_i32())
        .error_index(1)
        .build_v1(b"public");
    mock.queue_response(response);

    let client = create_mock_client_v1(mock);
    let result = client
        .set(
            &oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
            Value::OctetString("test".into()),
        )
        .await;

    match result {
        Err(Error::Snmp { status, .. }) => {
            assert_eq!(status, ErrorStatus::ReadOnly);
        }
        _ => panic!("Expected ReadOnly error, got {:?}", result),
    }
}

#[tokio::test]
async fn test_v1_error_gen_err() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(oid!(1, 3, 6, 1, 2, 1, 1, 1, 0), Value::Null)
        .error_status(ErrorStatus::GenErr.as_i32())
        .error_index(1)
        .build_v1(b"public");
    mock.queue_response(response);

    let client = create_mock_client_v1(mock);
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;

    match result {
        Err(Error::Snmp { status, .. }) => {
            assert_eq!(status, ErrorStatus::GenErr);
        }
        _ => panic!("Expected GenErr error, got {:?}", result),
    }
}

#[tokio::test]
async fn test_v1_get_integer() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(oid!(1, 3, 6, 1, 2, 1, 1, 7, 0), Value::Integer(72))
        .build_v1(b"public");
    mock.queue_response(response);

    let client = create_mock_client_v1(mock);
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 7, 0)).await.unwrap();

    assert_eq!(result.value, Value::Integer(72));
}

#[tokio::test]
async fn test_v1_get_timeticks() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(oid!(1, 3, 6, 1, 2, 1, 1, 3, 0), Value::TimeTicks(123456))
        .build_v1(b"public");
    mock.queue_response(response);

    let client = create_mock_client_v1(mock);
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 3, 0)).await.unwrap();

    assert_eq!(result.value, Value::TimeTicks(123456));
}

#[tokio::test]
async fn test_v1_get_counter32() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(
            oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 10, 1),
            Value::Counter32(999999),
        )
        .build_v1(b"public");
    mock.queue_response(response);

    let client = create_mock_client_v1(mock);
    let result = client
        .get(&oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 10, 1))
        .await
        .unwrap();

    assert_eq!(result.value, Value::Counter32(999999));
}

#[tokio::test]
async fn test_v1_get_gauge32() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(
            oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 5, 1),
            Value::Gauge32(1000000000),
        )
        .build_v1(b"public");
    mock.queue_response(response);

    let client = create_mock_client_v1(mock);
    let result = client
        .get(&oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 5, 1))
        .await
        .unwrap();

    assert_eq!(result.value, Value::Gauge32(1000000000));
}

#[tokio::test]
async fn test_v1_get_ip_address() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(
            oid!(1, 3, 6, 1, 2, 1, 4, 20, 1, 1, 192, 168, 1, 1),
            Value::IpAddress([192, 168, 1, 1]),
        )
        .build_v1(b"public");
    mock.queue_response(response);

    let client = create_mock_client_v1(mock);
    let result = client
        .get(&oid!(1, 3, 6, 1, 2, 1, 4, 20, 1, 1, 192, 168, 1, 1))
        .await
        .unwrap();

    assert_eq!(result.value, Value::IpAddress([192, 168, 1, 1]));
}

#[tokio::test]
async fn test_v1_get_object_identifier() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(
            oid!(1, 3, 6, 1, 2, 1, 1, 2, 0),
            Value::ObjectIdentifier(oid!(1, 3, 6, 1, 4, 1, 99999)),
        )
        .build_v1(b"public");
    mock.queue_response(response);

    let client = create_mock_client_v1(mock);
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 2, 0)).await.unwrap();

    assert_eq!(
        result.value,
        Value::ObjectIdentifier(oid!(1, 3, 6, 1, 4, 1, 99999))
    );
}

#[tokio::test]
async fn test_v1_retry_on_timeout() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    // First attempt times out
    mock.queue_timeout();

    // Second attempt succeeds
    let response = ResponseBuilder::new(1)
        .varbind(
            oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
            Value::OctetString("Success".into()),
        )
        .build_v1(b"public");
    mock.queue_response(response);

    // Create V1 client with 1 retry
    let config = ClientConfig {
        version: Version::V1,
        community: Bytes::from_static(b"public"),
        timeout: Duration::from_secs(1),
        retries: 1,
        max_oids_per_request: 10,
        v3_security: None,
        walk_mode: WalkMode::Auto,
        oid_ordering: OidOrdering::Strict,
        max_walk_results: None,
        max_repetitions: 25,
    };
    let client = Client::new(mock.clone(), config);

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert!(matches!(result.value, Value::OctetString(_)));

    // Should have sent 2 requests (original + 1 retry)
    assert_eq!(mock.requests().len(), 2);
}

#[tokio::test]
async fn test_v1_null_value() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(oid!(1, 3, 6, 1, 2, 1, 1, 8, 0), Value::Null)
        .build_v1(b"public");
    mock.queue_response(response);

    let client = create_mock_client_v1(mock);
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 8, 0)).await.unwrap();

    assert_eq!(result.value, Value::Null);
}

#[tokio::test]
async fn test_v1_opaque_value() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    let response = ResponseBuilder::new(1)
        .varbind(
            oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0),
            Value::Opaque(Bytes::from_static(&[0xDE, 0xAD, 0xBE, 0xEF])),
        )
        .build_v1(b"public");
    mock.queue_response(response);

    let client = create_mock_client_v1(mock);
    let result = client
        .get(&oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0))
        .await
        .unwrap();

    assert!(
        matches!(result.value, Value::Opaque(ref data) if data.as_ref() == [0xDE, 0xAD, 0xBE, 0xEF])
    );
}

// ============================================================================
// Version Mismatch Tests
//
// These tests verify that the client detects and rejects responses where the
// SNMP version doesn't match what was requested (RFC compliance).
// ============================================================================

#[tokio::test]
async fn test_v2c_client_receives_v1_response_rejected() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    // V2c client sends request, but receives V1 response (version mismatch)
    let response = ResponseBuilder::new(1)
        .varbind(
            oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
            Value::OctetString("Test".into()),
        )
        .build_v1(b"public"); // V1 response to V2c client
    mock.queue_response(response);

    let client = create_mock_client(mock); // V2c client
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;

    match result {
        Err(Error::VersionMismatch { expected, actual }) => {
            assert_eq!(expected, Version::V2c);
            assert_eq!(actual, Version::V1);
        }
        _ => panic!("Expected VersionMismatch error, got {:?}", result),
    }
}

#[tokio::test]
async fn test_v1_client_receives_v2c_response_rejected() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    // V1 client sends request, but receives V2c response (version mismatch)
    let response = ResponseBuilder::new(1)
        .varbind(
            oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
            Value::OctetString("Test".into()),
        )
        .build_v2c(b"public"); // V2c response to V1 client
    mock.queue_response(response);

    let client = create_mock_client_v1(mock); // V1 client
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;

    match result {
        Err(Error::VersionMismatch { expected, actual }) => {
            assert_eq!(expected, Version::V1);
            assert_eq!(actual, Version::V2c);
        }
        _ => panic!("Expected VersionMismatch error, got {:?}", result),
    }
}

#[tokio::test]
async fn test_v2c_client_receives_v2c_response_accepted() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    // V2c client sends request and receives matching V2c response (OK)
    let response = ResponseBuilder::new(1)
        .varbind(
            oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
            Value::OctetString("Test".into()),
        )
        .build_v2c(b"public");
    mock.queue_response(response);

    let client = create_mock_client(mock); // V2c client
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;

    assert!(
        result.is_ok(),
        "Matching version should succeed, got {:?}",
        result
    );
}

#[tokio::test]
async fn test_v1_client_receives_v1_response_accepted() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    // V1 client sends request and receives matching V1 response (OK)
    let response = ResponseBuilder::new(1)
        .varbind(
            oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
            Value::OctetString("Test".into()),
        )
        .build_v1(b"public");
    mock.queue_response(response);

    let client = create_mock_client_v1(mock); // V1 client
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;

    assert!(
        result.is_ok(),
        "Matching version should succeed, got {:?}",
        result
    );
}

#[tokio::test]
async fn test_v2c_getnext_version_mismatch() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    // Test version mismatch on GETNEXT operation
    let response = ResponseBuilder::new(1)
        .varbind(
            oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
            Value::OctetString("Test".into()),
        )
        .build_v1(b"public"); // V1 response to V2c client
    mock.queue_response(response);

    let client = create_mock_client(mock); // V2c client
    let result = client.get_next(&oid!(1, 3, 6, 1, 2, 1, 1)).await;

    assert!(matches!(result, Err(Error::VersionMismatch { .. })));
}

#[tokio::test]
async fn test_v2c_set_version_mismatch() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    // Test version mismatch on SET operation
    let response = ResponseBuilder::new(1)
        .varbind(
            oid!(1, 3, 6, 1, 2, 1, 1, 5, 0),
            Value::OctetString("NewName".into()),
        )
        .build_v1(b"public"); // V1 response to V2c client
    mock.queue_response(response);

    let client = create_mock_client(mock); // V2c client
    let result = client
        .set(
            &oid!(1, 3, 6, 1, 2, 1, 1, 5, 0),
            Value::OctetString("NewName".into()),
        )
        .await;

    assert!(matches!(result, Err(Error::VersionMismatch { .. })));
}

#[tokio::test]
async fn test_v2c_get_many_version_mismatch() {
    let mut mock = MockTransport::new("127.0.0.1:161".parse().unwrap());

    // Test version mismatch on GET_MANY operation
    let response = ResponseBuilder::new(1)
        .varbind(
            oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
            Value::OctetString("Test".into()),
        )
        .varbind(oid!(1, 3, 6, 1, 2, 1, 1, 3, 0), Value::TimeTicks(12345))
        .build_v1(b"public"); // V1 response to V2c client
    mock.queue_response(response);

    let client = create_mock_client(mock); // V2c client
    let oids = [
        oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
        oid!(1, 3, 6, 1, 2, 1, 1, 3, 0),
    ];
    let result = client.get_many(&oids).await;

    assert!(matches!(result, Err(Error::VersionMismatch { .. })));
}
