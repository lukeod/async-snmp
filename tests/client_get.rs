//! GET and SET operation tests using TestAgent.

mod common;

use async_snmp::transport::UdpTransport;
use async_snmp::{Auth, Client, Retry, Value, oid};
use common::TestAgent;
use std::time::Duration;

/// Basic GET returns expected value.
#[tokio::test]
async fn get_returns_value() {
    let agent = TestAgent::new().await;

    let client = Client::builder(agent.addr().to_string(), Auth::v2c("public"))
        .connect()
        .await
        .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();

    assert_eq!(result.value.as_str(), Some("Test SNMP Agent"));
}

/// GET on missing OID returns NoSuchInstance.
#[tokio::test]
async fn get_missing_oid_returns_no_such_instance() {
    let agent = TestAgent::new().await;

    let client = Client::builder(agent.addr().to_string(), Auth::v2c("public"))
        .connect()
        .await
        .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 99, 99, 99)).await.unwrap();

    assert_eq!(result.value, Value::NoSuchInstance);
}

/// GET multiple OIDs in single request.
#[tokio::test]
async fn get_many_returns_all_values() {
    let agent = TestAgent::new().await;

    let client = Client::builder(agent.addr().to_string(), Auth::v2c("public"))
        .connect()
        .await
        .unwrap();

    let oids = [
        oid!(1, 3, 6, 1, 2, 1, 1, 1, 0), // sysDescr
        oid!(1, 3, 6, 1, 2, 1, 1, 3, 0), // sysUpTime
        oid!(1, 3, 6, 1, 2, 1, 1, 5, 0), // sysName
    ];

    let results = client.get_many(&oids).await.unwrap();

    assert_eq!(results.len(), 3);
    assert_eq!(results[0].value.as_str(), Some("Test SNMP Agent"));
    assert!(matches!(results[1].value, Value::TimeTicks(_)));
    assert_eq!(results[2].value.as_str(), Some("test-agent"));
}

/// GET with timeout when agent doesn't respond.
#[tokio::test]
async fn get_timeout_when_agent_stopped() {
    let agent = TestAgent::new().await;
    let addr = agent.addr();

    // Stop the agent before sending request
    agent.stop();
    tokio::time::sleep(Duration::from_millis(10)).await;

    let client = Client::builder(addr.to_string(), Auth::v2c("public"))
        .timeout(Duration::from_millis(100))
        .retry(Retry::none()) // No retries for faster test
        .connect()
        .await
        .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("timeout"));
}

/// SET modifies value.
#[tokio::test]
async fn set_modifies_value() {
    let agent = TestAgent::new().await;

    let client = Client::builder(agent.addr().to_string(), Auth::v2c("public"))
        .connect()
        .await
        .unwrap();

    let new_value = Value::OctetString("Modified Name".into());
    let result = client
        .set(&oid!(1, 3, 6, 1, 2, 1, 1, 5, 0), new_value.clone())
        .await
        .unwrap();

    assert_eq!(result.value, new_value);

    // Verify the change persisted
    let get_result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 5, 0)).await.unwrap();
    assert_eq!(get_result.value, new_value);
}

/// SET multiple values.
#[tokio::test]
async fn set_many_modifies_values() {
    let agent = TestAgent::new().await;

    let client = Client::builder(agent.addr().to_string(), Auth::v2c("public"))
        .connect()
        .await
        .unwrap();

    let varbinds = [
        (
            oid!(1, 3, 6, 1, 2, 1, 1, 4, 0),
            Value::OctetString("new-contact".into()),
        ),
        (
            oid!(1, 3, 6, 1, 2, 1, 1, 6, 0),
            Value::OctetString("new-location".into()),
        ),
    ];

    for (oid, value) in &varbinds {
        client.set(oid, value.clone()).await.unwrap();
    }

    // Verify changes
    for (oid, expected) in &varbinds {
        let result = client.get(oid).await.unwrap();
        assert_eq!(&result.value, expected);
    }
}

/// V1 GET works (if supported).
#[tokio::test]
async fn v1_get_works() {
    let agent = TestAgent::new().await;

    let client = Client::builder(agent.addr().to_string(), Auth::v1("public"))
        .connect()
        .await
        .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();

    assert_eq!(result.value.as_str(), Some("Test SNMP Agent"));
}

/// GETNEXT returns lexicographically next OID.
#[tokio::test]
async fn getnext_returns_next_oid() {
    let agent = TestAgent::new().await;

    let client = Client::builder(agent.addr().to_string(), Auth::v2c("public"))
        .connect()
        .await
        .unwrap();

    // GETNEXT on sysDescr should return sysObjectID
    let result = client
        .get_next(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))
        .await
        .unwrap();

    assert_eq!(result.oid, oid!(1, 3, 6, 1, 2, 1, 1, 2, 0));
}

/// GETNEXT past end of MIB returns EndOfMibView.
#[tokio::test]
async fn getnext_past_end_returns_end_of_mib_view() {
    let agent = TestAgent::new().await;

    let client = Client::builder(agent.addr().to_string(), Auth::v2c("public"))
        .connect()
        .await
        .unwrap();

    // GETNEXT on last OID in system MIB
    let result = client
        .get_next(&oid!(1, 3, 6, 1, 2, 1, 1, 7, 0))
        .await
        .unwrap();

    assert_eq!(result.value, Value::EndOfMibView);
}

/// IPv6 shared transport can reach an IPv4 agent via address mapping.
#[tokio::test]
async fn ipv6_transport_reaches_ipv4_agent() {
    let agent = TestAgent::new().await;
    assert!(agent.addr().is_ipv4(), "TestAgent should bind to IPv4");

    // Bind an IPv6 transport and use it to reach the IPv4 agent.
    // UdpTransport::handle() maps the IPv4 target to ::ffff:x.x.x.x.
    let transport = UdpTransport::bind("[::]:0").await.unwrap();
    let client = Client::builder(agent.addr().to_string(), Auth::v2c("public"))
        .timeout(Duration::from_secs(2))
        .build_with(&transport)
        .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert_eq!(result.value.as_str(), Some("Test SNMP Agent"));
}
