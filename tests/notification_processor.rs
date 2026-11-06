//! Integration tests for socketless notification processing.

#![cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]

use std::sync::Arc;
use std::time::Duration;

use async_snmp::notification::{
    InformResponse, Notification, NotificationEngine, NotificationProcessor,
    NotificationVarbindValidation, V3Processed,
};
use async_snmp::v3::{AuthProtocol, PrivProtocol};
use async_snmp::{AuthoritativeEngine, Client, UsmConfig, oid};
use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// A Client Inform to a caller-owned socket resolves once the caller sends the
/// processor's deferred acknowledgement.
#[tokio::test]
async fn v3_inform_to_caller_owned_socket_with_deferred_ack() {
    let engine = AuthoritativeEngine::install(b"processor-engine".to_vec(), |_| {
        Ok::<(), std::convert::Infallible>(())
    })
    .unwrap();
    let processor = NotificationProcessor::builder(NotificationEngine::new(engine).unwrap())
        .usm_user("informuser", |u| {
            u.auth_priv(
                AuthProtocol::Sha256,
                b"authpass12345678",
                PrivProtocol::Aes128,
                b"privpass12345678",
            )
        })
        .unwrap()
        .build()
        .unwrap();
    let processor = Arc::new(processor);
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = socket.local_addr().unwrap();
    let (notifications, mut received) = mpsc::unbounded_channel();

    let listener = tokio::spawn({
        let processor = Arc::clone(&processor);
        let socket = Arc::clone(&socket);
        async move {
            let mut buf = vec![0; async_snmp::UDP_RECEIVE_BUFFER_SIZE];
            loop {
                let (len, source) = socket.recv_from(&mut buf).await.unwrap();
                let datagram = Bytes::copy_from_slice(&buf[..len]);
                match processor.process(datagram, source).unwrap() {
                    V3Processed::Authenticated(message) => {
                        let notification = message
                            .to_notification(NotificationVarbindValidation::Strict)
                            .unwrap()
                            .unwrap();
                        notifications.send(notification).unwrap();
                        let ack = message.inform_ack().unwrap();
                        let processor = Arc::clone(&processor);
                        let socket = Arc::clone(&socket);
                        tokio::spawn(async move {
                            tokio::time::sleep(Duration::from_millis(200)).await;
                            let InformResponse::Response(response) =
                                processor.encode_inform_response(&ack).unwrap()
                            else {
                                panic!("expected a Response");
                            };
                            socket.send_to(&response, source).await.unwrap();
                        });
                    }
                    V3Processed::UsmFailed {
                        report: Some(report),
                        ..
                    } => {
                        socket.send_to(&report, source).await.unwrap();
                    }
                    other => panic!("unexpected processing outcome: {other:?}"),
                }
            }
        }
    });

    let client = Client::builder(
        addr.to_string(),
        UsmConfig::new("informuser")
            .auth_priv(
                AuthProtocol::Sha256,
                "authpass12345678",
                PrivProtocol::Aes128,
                "privpass12345678",
            )
            .unwrap(),
    )
    .connect()
    .await
    .unwrap();

    let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 4);
    tokio::time::timeout(
        Duration::from_secs(5),
        client.send_inform(&trap_oid, 7777, vec![]),
    )
    .await
    .expect("Inform should resolve after the deferred acknowledgement")
    .unwrap();

    match received.recv().await.unwrap() {
        Notification::InformV3 {
            username,
            uptime,
            trap_oid: received_oid,
            ..
        } => {
            assert_eq!(username.as_ref(), b"informuser");
            assert_eq!(uptime, 7777);
            assert_eq!(received_oid, trap_oid);
        }
        other => panic!("expected InformV3, got {other:?}"),
    }
    assert_eq!(processor.engine().usm_stats().unknown_engine_ids, 1);
    listener.abort();
}
