//! SNMPv3 security tests using TestAgent.

mod common;

use async_snmp::v3::{AuthProtocol, PrivProtocol};
use async_snmp::{Auth, Client, Retry, oid};
use common::{TestAgentBuilder, V3User};
use std::time::Duration;

const AUTH_PASS: &str = "authpassword123";
const PRIV_PASS: &str = "privpassword123";

/// V3 noAuthNoPriv works.
#[tokio::test]
async fn v3_no_auth_no_priv() {
    let agent = TestAgentBuilder::new()
        .usm_user(V3User::no_auth(b"noauthuser".to_vec()))
        .build()
        .await;

    let client = Client::builder(agent.addr().to_string(), Auth::usm("noauthuser"))
        .connect()
        .await
        .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();

    assert_eq!(result.value.as_str(), Some("Test SNMP Agent"));
}

/// V3 authNoPriv with SHA-256.
#[tokio::test]
async fn v3_auth_sha256() {
    let agent = TestAgentBuilder::new()
        .usm_user(V3User::auth_only(
            b"authuser".to_vec(),
            AuthProtocol::Sha256,
            AUTH_PASS.as_bytes().to_vec(),
        ))
        .build()
        .await;

    let client = Client::builder(
        agent.addr().to_string(),
        Auth::usm("authuser").auth(AuthProtocol::Sha256, AUTH_PASS),
    )
    .connect()
    .await
    .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();

    assert_eq!(result.value.as_str(), Some("Test SNMP Agent"));
}

/// V3 authPriv with SHA-256 and AES-128.
#[tokio::test]
async fn v3_auth_priv_sha256_aes128() {
    let agent = TestAgentBuilder::new()
        .usm_user(V3User::auth_priv(
            b"authprivuser".to_vec(),
            AuthProtocol::Sha256,
            AUTH_PASS.as_bytes().to_vec(),
            PrivProtocol::Aes128,
            PRIV_PASS.as_bytes().to_vec(),
        ))
        .build()
        .await;

    let client = Client::builder(
        agent.addr().to_string(),
        Auth::usm("authprivuser")
            .auth(AuthProtocol::Sha256, AUTH_PASS)
            .privacy(PrivProtocol::Aes128, PRIV_PASS),
    )
    .connect()
    .await
    .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();

    assert_eq!(result.value.as_str(), Some("Test SNMP Agent"));
}

/// V3 with MD5 auth (legacy support).
#[tokio::test]
async fn v3_auth_md5() {
    let agent = TestAgentBuilder::new()
        .usm_user(V3User::auth_only(
            b"md5user".to_vec(),
            AuthProtocol::Md5,
            AUTH_PASS.as_bytes().to_vec(),
        ))
        .build()
        .await;

    let client = Client::builder(
        agent.addr().to_string(),
        Auth::usm("md5user").auth(AuthProtocol::Md5, AUTH_PASS),
    )
    .connect()
    .await
    .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();

    assert_eq!(result.value.as_str(), Some("Test SNMP Agent"));
}

/// V3 with DES privacy (legacy support).
#[tokio::test]
async fn v3_auth_priv_sha1_des() {
    let agent = TestAgentBuilder::new()
        .usm_user(V3User::auth_priv(
            b"desuser".to_vec(),
            AuthProtocol::Sha1,
            AUTH_PASS.as_bytes().to_vec(),
            PrivProtocol::Des,
            PRIV_PASS.as_bytes().to_vec(),
        ))
        .build()
        .await;

    let client = Client::builder(
        agent.addr().to_string(),
        Auth::usm("desuser")
            .auth(AuthProtocol::Sha1, AUTH_PASS)
            .privacy(PrivProtocol::Des, PRIV_PASS),
    )
    .connect()
    .await
    .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();

    assert_eq!(result.value.as_str(), Some("Test SNMP Agent"));
}

/// Wrong password fails authentication.
#[tokio::test]
async fn v3_wrong_password_fails() {
    let agent = TestAgentBuilder::new()
        .usm_user(V3User::auth_only(
            b"authuser".to_vec(),
            AuthProtocol::Sha256,
            AUTH_PASS.as_bytes().to_vec(),
        ))
        .build()
        .await;

    let client = Client::builder(
        agent.addr().to_string(),
        Auth::usm("authuser").auth(AuthProtocol::Sha256, "wrongpassword"),
    )
    .timeout(Duration::from_millis(500))
    .retry(Retry::none())
    .connect()
    .await
    .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;

    assert!(result.is_err());
}

/// Unknown user with authentication fails.
///
/// When authentication is required, the agent rejects unknown users.
#[tokio::test]
async fn v3_unknown_user_auth_fails() {
    let agent = TestAgentBuilder::new()
        .usm_user(V3User::auth_only(
            b"validuser".to_vec(),
            AuthProtocol::Sha256,
            AUTH_PASS.as_bytes().to_vec(),
        ))
        .build()
        .await;

    // Try to use unknown user with authentication - should fail
    let client = Client::builder(
        agent.addr().to_string(),
        Auth::usm("unknownuser").auth(AuthProtocol::Sha256, AUTH_PASS),
    )
    .timeout(Duration::from_millis(500))
    .retry(Retry::none())
    .connect()
    .await
    .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;

    assert!(result.is_err());
}

/// Unknown user with noAuthNoPriv fails (RFC 3414 section 3.2 step 1).
///
/// Non-discovery messages with an unknown username must be rejected with
/// usmStatsUnknownUserNames even when security level is noAuthNoPriv.
/// Only discovery messages (empty msgUserName) are exempt.
#[tokio::test]
async fn v3_unknown_user_no_auth_fails() {
    let agent = TestAgentBuilder::new()
        .usm_user(V3User::no_auth(b"knownuser".to_vec()))
        .build()
        .await;

    // Try to use unknown user with noAuthNoPriv - must fail per RFC 3414
    let client = Client::builder(agent.addr().to_string(), Auth::usm("unknownuser"))
        .timeout(Duration::from_millis(500))
        .retry(Retry::none())
        .connect()
        .await
        .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;

    assert!(
        result.is_err(),
        "unknown noAuthNoPriv user should be rejected"
    );
}

/// Engine discovery works.
#[tokio::test]
async fn v3_engine_discovery() {
    let agent = TestAgentBuilder::new()
        .usm_user(V3User::auth_only(
            b"authuser".to_vec(),
            AuthProtocol::Sha256,
            AUTH_PASS.as_bytes().to_vec(),
        ))
        .build()
        .await;

    let client = Client::builder(
        agent.addr().to_string(),
        Auth::usm("authuser").auth(AuthProtocol::Sha256, AUTH_PASS),
    )
    .connect()
    .await
    .unwrap();

    // First request triggers discovery
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    assert_eq!(result.value.as_str(), Some("Test SNMP Agent"));

    // Subsequent request should use cached engine info
    let result2 = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 3, 0)).await.unwrap();
    assert!(matches!(result2.value, async_snmp::Value::TimeTicks(_)));
}
