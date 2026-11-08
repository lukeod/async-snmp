#![cfg(feature = "agent")]

use std::convert::Infallible;
use std::time::Duration;

use async_snmp::{
    Agent, Auth, AuthoritativeEngine, Client, Error, InformAckOutcome, NotificationReceiver, Retry,
    UsmSecurityContext, UsmUser, UsmUserEntry, oid,
};

const WAIT: Duration = Duration::from_secs(3);

fn engine(id: &[u8]) -> AuthoritativeEngine {
    AuthoritativeEngine::install(bytes::Bytes::copy_from_slice(id), |_| {
        Ok::<_, Infallible>(())
    })
    .unwrap()
}

#[tokio::test]
async fn explicit_empty_contexts_require_engine_and_application_policy() {
    let context = UsmSecurityContext::default();
    let error = Agent::builder()
        .bind("not an address")
        .security_context(context.clone())
        .allow_all_access()
        .prepare()
        .await
        .err()
        .unwrap();
    assert!(
        matches!(*error, Error::Config(ref message) if message.contains("authoritative engine"))
    );
    let error = Agent::builder()
        .bind("not an address")
        .security_context(context.clone())
        .authoritative_engine(engine(b"context-engine"))
        .prepare()
        .await
        .err()
        .unwrap();
    assert!(
        matches!(*error, Error::Config(ref message) if message.contains("vacm() or allow_all_access()"))
    );
    let error = NotificationReceiver::builder()
        .bind("not an address")
        .security_context(context.clone())
        .authoritative_engine(engine(b"context-engine"))
        .prepare()
        .await
        .err()
        .unwrap();
    assert!(matches!(*error, Error::Config(ref message) if message.contains("acceptance policy")));
    let error = NotificationReceiver::builder()
        .bind("not an address")
        .security_context(context.clone())
        .accept_all_notifications()
        .prepare()
        .await
        .err()
        .unwrap();
    assert!(
        matches!(*error, Error::Config(ref message) if message.contains("authoritative engine"))
    );
    let error = Agent::builder()
        .security_context(context.clone())
        .usm_user("user", Ok)
        .unwrap()
        .prepare()
        .await
        .err()
        .unwrap();
    assert!(
        matches!(*error, Error::Config(ref message) if message.contains("security_context conflicts"))
    );
    let error = NotificationReceiver::builder()
        .security_context(context)
        .usm_user("user", Ok)
        .unwrap()
        .prepare()
        .await
        .err()
        .unwrap();
    assert!(
        matches!(*error, Error::Config(ref message) if message.contains("security_context conflicts"))
    );
}

#[tokio::test]
async fn replacement_reaches_shared_command_and_notification_roles_without_crypto() {
    let context = UsmSecurityContext::default();
    let mut agent = Agent::builder()
        .bind("127.0.0.1:0")
        .authoritative_engine(engine(b"shared-context-engine"))
        .security_context(context.clone())
        .allow_all_access()
        .notifications(NotificationReceiver::builder().accept_all_notifications())
        .spawn()
        .await
        .unwrap();
    let mut notifications = agent.take_notifications().unwrap();
    context
        .replace_users([UsmUserEntry::new(UsmUser::new("dynamic-user"))])
        .unwrap();
    let client = Client::builder(
        agent.bound_addresses()[0].local_addr.to_string(),
        Auth::usm("dynamic-user"),
    )
    .retry(Retry::none())
    .request_timeout(WAIT)
    .connect()
    .await
    .unwrap();
    client
        .get(&oid!(1, 3, 6, 1, 6, 3, 10, 2, 1, 1, 0))
        .await
        .unwrap();
    client
        .send_inform(&oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1), 0, vec![])
        .await
        .unwrap();
    let event = tokio::time::timeout(WAIT, notifications.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        event.inform_ack,
        async_snmp::NotificationAcknowledgement::Completed(InformAckOutcome::Sent)
    ));
    assert!(
        context
            .replace_users([UsmUserEntry::new(UsmUser::new(""))])
            .is_err()
    );
    client
        .get(&oid!(1, 3, 6, 1, 6, 3, 10, 2, 1, 1, 0))
        .await
        .unwrap();
    agent.shutdown().await.unwrap();
}

#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
fn user(password: &[u8]) -> UsmUser {
    UsmUser::new("same-user")
        .auth(async_snmp::AuthProtocol::Sha256, password)
        .unwrap()
}

#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
#[tokio::test]
async fn one_context_selects_overlapping_usernames_by_authoritative_engine() {
    let first = engine(b"context-engine-one");
    let second = engine(b"context-engine-two");
    let context = UsmSecurityContext::new([
        UsmUserEntry::for_engine(
            bytes::Bytes::copy_from_slice(first.engine_id()),
            user(b"first-authentication"),
        )
        .unwrap(),
        UsmUserEntry::for_engine(
            bytes::Bytes::copy_from_slice(second.engine_id()),
            user(b"second-authentication"),
        )
        .unwrap(),
    ])
    .unwrap();
    let first = Agent::builder()
        .bind("127.0.0.1:0")
        .authoritative_engine(first)
        .security_context(context.clone())
        .allow_all_access()
        .spawn()
        .await
        .unwrap();
    let second = Agent::builder()
        .bind("127.0.0.1:0")
        .authoritative_engine(second)
        .security_context(context)
        .allow_all_access()
        .spawn()
        .await
        .unwrap();
    for (agent, password) in [
        (&first, b"first-authentication".as_slice()),
        (&second, b"second-authentication".as_slice()),
    ] {
        let auth = async_snmp::UsmConfig::new("same-user")
            .auth(async_snmp::AuthProtocol::Sha256, password)
            .unwrap();
        let client = Client::builder(agent.bound_addresses()[0].local_addr.to_string(), auth)
            .retry(Retry::none())
            .request_timeout(WAIT)
            .connect()
            .await
            .unwrap();
        let response = client
            .get(&oid!(1, 3, 6, 1, 6, 3, 10, 2, 1, 1, 0))
            .await
            .unwrap();
        assert_eq!(
            response.varbinds[0].value.as_bytes().unwrap(),
            agent.engine_id()
        );
    }
    first.shutdown().await.unwrap();
    second.shutdown().await.unwrap();
}

#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
#[tokio::test]
async fn replacement_can_add_aes_after_empty_context_preparation() {
    let context = UsmSecurityContext::default();
    let mut agent = Agent::builder()
        .bind("127.0.0.1:0")
        .authoritative_engine(engine(b"dynamic-privacy-engine"))
        .security_context(context.clone())
        .allow_all_access()
        .notifications(NotificationReceiver::builder().accept_all_notifications())
        .spawn()
        .await
        .unwrap();
    let mut notifications = agent.take_notifications().unwrap();
    let auth = async_snmp::UsmConfig::new("dynamic-user")
        .auth_priv(
            async_snmp::AuthProtocol::Sha256,
            b"authentication-password",
            async_snmp::PrivProtocol::Aes128,
            b"privacy-password",
        )
        .unwrap();
    context
        .replace_users([UsmUserEntry::new(
            UsmUser::new("dynamic-user")
                .auth_priv(
                    async_snmp::AuthProtocol::Sha256,
                    b"authentication-password",
                    async_snmp::PrivProtocol::Aes128,
                    b"privacy-password",
                )
                .unwrap(),
        )])
        .unwrap();
    let client = Client::builder(agent.bound_addresses()[0].local_addr.to_string(), auth)
        .retry(Retry::none())
        .request_timeout(WAIT)
        .connect()
        .await
        .unwrap();
    client
        .get(&oid!(1, 3, 6, 1, 6, 3, 10, 2, 1, 1, 0))
        .await
        .unwrap();
    client
        .send_inform(&oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1), 0, vec![])
        .await
        .unwrap();
    assert!(matches!(
        tokio::time::timeout(WAIT, notifications.recv())
            .await
            .unwrap()
            .unwrap()
            .inform_ack,
        async_snmp::NotificationAcknowledgement::Completed(InformAckOutcome::Sent)
    ));
    agent.shutdown().await.unwrap();
}

#[cfg(feature = "crypto-rustcrypto")]
#[tokio::test]
async fn runtime_des_credentials_require_durable_sender_state_before_acknowledgement() {
    let context = UsmSecurityContext::default();
    let mut receiver = NotificationReceiver::builder()
        .bind("127.0.0.1:0")
        .authoritative_engine(engine(b"dynamic-des-receiver"))
        .security_context(context.clone())
        .accept_all_notifications()
        .spawn()
        .await
        .unwrap();
    let user = UsmUser::new("des-user")
        .auth_priv(
            async_snmp::AuthProtocol::Sha256,
            b"authentication-password",
            async_snmp::PrivProtocol::Des,
            b"privacy-password",
        )
        .unwrap();
    context.replace_users([UsmUserEntry::new(user)]).unwrap();
    let sender = async_snmp::LocalEngine::new(engine(b"dynamic-des-sender")).unwrap();
    sender
        .set_des_salt_state(Some(
            async_snmp::DesSaltState::install(|_| Ok::<_, Infallible>(())).unwrap(),
        ))
        .unwrap();
    let auth = async_snmp::UsmConfig::new("des-user")
        .auth_priv(
            async_snmp::AuthProtocol::Sha256,
            b"authentication-password",
            async_snmp::PrivProtocol::Des,
            b"privacy-password",
        )
        .unwrap();
    let client = Client::builder(receiver.bound_addresses()[0].local_addr.to_string(), auth)
        .local_engine(sender)
        .retry(Retry::none())
        .request_timeout(Duration::from_millis(200))
        .connect()
        .await
        .unwrap();
    let trap = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1);
    assert!(client.send_inform(&trap, 0, vec![]).await.is_err());
    let failed = tokio::time::timeout(WAIT, receiver.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        failed.inform_ack,
        async_snmp::NotificationAcknowledgement::Completed(InformAckOutcome::Failed(_))
    ));
    receiver
        .local_engine()
        .set_des_salt_state(Some(
            async_snmp::DesSaltState::install(|_| Ok::<_, Infallible>(())).unwrap(),
        ))
        .unwrap();
    client.send_inform(&trap, 0, vec![]).await.unwrap();
    let completed = tokio::time::timeout(WAIT, receiver.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        completed.inform_ack,
        async_snmp::NotificationAcknowledgement::Completed(InformAckOutcome::Sent)
    ));
    receiver.shutdown().await.unwrap();
}
