use async_snmp::message::{CommunityMessage, Message};
use async_snmp::{Auth, Client, Oid, Pdu, PduType, Retry, Value, VarBind};
use bytes::Bytes;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;

#[tokio::test]
async fn wrong_community_does_not_consume_pending_udp_request() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer = socket.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let server_requests = Arc::clone(&requests);

    let server = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        let (len, source) = socket.recv_from(&mut buf).await.unwrap();
        server_requests.fetch_add(1, Ordering::Relaxed);
        let request = Message::decode(Bytes::copy_from_slice(&buf[..len])).unwrap();
        let request_id = request.into_pdu().unwrap().request_id;
        let oid = Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 1, 0]);

        let response = |community: &'static [u8], value: &'static [u8]| {
            CommunityMessage::v2c(
                Bytes::from_static(community),
                Pdu {
                    pdu_type: PduType::Response,
                    request_id,
                    error_status: 0,
                    error_index: 0,
                    varbinds: vec![VarBind::new(
                        oid.clone(),
                        Value::OctetString(Bytes::from_static(value)),
                    )],
                },
            )
            .unwrap()
            .encode()
            .unwrap()
        };

        socket
            .send_to(&response(b"spoofed", b"spoof"), source)
            .await
            .unwrap();
        socket
            .send_to(&response(b"public", b"legitimate"), source)
            .await
            .unwrap();
    });

    let client = Client::builder(peer, Auth::v2c("public"))
        .timeout(Duration::from_secs(2))
        .retry(Retry::none())
        .connect()
        .await
        .unwrap();
    let result = client
        .get(&Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 1, 0]))
        .await
        .unwrap();

    assert!(result.anomalies.is_empty());
    assert_eq!(
        result.varbinds[0].value,
        Value::OctetString(Bytes::from_static(b"legitimate"))
    );
    server.await.unwrap();
    assert_eq!(requests.load(Ordering::Relaxed), 1, "request was retried");
}

#[tokio::test]
async fn non_utf8_community_correlates_udp_response() {
    let community = Bytes::from_static(b"public\xff");
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer = socket.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        let (len, source) = socket.recv_from(&mut buf).await.unwrap();
        let Message::Community(request) =
            Message::decode(Bytes::copy_from_slice(&buf[..len])).unwrap()
        else {
            panic!("expected community request");
        };
        assert_eq!(request.community(), &community);

        let request_id = request.into_pdu().unwrap().request_id;
        let response = CommunityMessage::v2c(
            community,
            Pdu {
                pdu_type: PduType::Response,
                request_id,
                error_status: 0,
                error_index: 0,
                varbinds: vec![VarBind::new(
                    Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 1, 0]),
                    Value::OctetString(Bytes::from_static(b"matched")),
                )],
            },
        )
        .unwrap()
        .encode()
        .unwrap();
        socket.send_to(&response, source).await.unwrap();
    });

    let client = Client::builder(peer, Auth::v2c(Bytes::from_static(b"public\xff")))
        .timeout(Duration::from_secs(2))
        .retry(Retry::none())
        .connect()
        .await
        .unwrap();
    let result = client
        .get(&Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 1, 0]))
        .await
        .unwrap();

    assert!(result.anomalies.is_empty());
    assert_eq!(
        result.varbinds[0].value,
        Value::OctetString(Bytes::from_static(b"matched"))
    );
    server.await.unwrap();
}
