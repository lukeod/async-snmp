use async_snmp::DecodeConfig;
use async_snmp::message::{CommunityMessage, Message};
use async_snmp::{Auth, Client, Oid, RequestPdu, ResponsePdu, Retry, Value, VarBind, Version};
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
        let request = Message::decode(Bytes::copy_from_slice(&buf[..len]), DecodeConfig::default())
            .unwrap()
            .value;
        let request_id = request.into_pdu().unwrap().request_id();
        let oid = Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 1, 0]);

        let response = |community: &'static [u8], value: &'static [u8]| {
            CommunityMessage::v2c(
                Bytes::from_static(community),
                ResponsePdu::success(
                    Version::V2c,
                    request_id,
                    vec![VarBind::new(
                        oid.clone(),
                        Value::OctetString(Bytes::from_static(value)),
                    )],
                )
                .unwrap(),
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
        .request_timeout(Duration::from_secs(2))
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
async fn malformed_and_wrong_pdu_candidates_do_not_consume_udp_exchange() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer = socket.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        let (len, source) = socket.recv_from(&mut buf).await.unwrap();
        let request = Message::decode(Bytes::copy_from_slice(&buf[..len]), DecodeConfig::default())
            .unwrap()
            .value;
        let request_id = request.into_pdu().unwrap().request_id();
        let oid = Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 1, 0]);

        let wrong_pdu = CommunityMessage::v2c(
            "public",
            RequestPdu::get(Version::V2c, request_id, std::slice::from_ref(&oid)).unwrap(),
        )
        .unwrap()
        .encode()
        .unwrap();
        socket.send_to(&wrong_pdu, source).await.unwrap();

        let mut malformed = CommunityMessage::v2c(
            "public",
            ResponsePdu::success(
                Version::V2c,
                request_id,
                vec![VarBind::new(
                    oid.clone(),
                    Value::ObjectIdentifier(Oid::from_slice(&[1, 3, 6, 1])),
                )],
            )
            .unwrap(),
        )
        .unwrap()
        .encode()
        .unwrap()
        .to_vec();
        *malformed.last_mut().unwrap() = 0x80;
        socket.send_to(&malformed, source).await.unwrap();

        let genuine = CommunityMessage::v2c(
            "public",
            ResponsePdu::success(
                Version::V2c,
                request_id,
                vec![VarBind::new(
                    oid,
                    Value::OctetString(Bytes::from_static(b"genuine")),
                )],
            )
            .unwrap(),
        )
        .unwrap()
        .encode()
        .unwrap();
        socket.send_to(&genuine, source).await.unwrap();
    });

    let client = Client::builder(peer, Auth::v2c("public"))
        .request_timeout(Duration::from_secs(2))
        .retry(Retry::none())
        .connect()
        .await
        .unwrap();
    let result = client
        .get(&Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 1, 0]))
        .await
        .unwrap();

    assert_eq!(
        result.varbinds[0].value,
        Value::OctetString(Bytes::from_static(b"genuine"))
    );
    server.await.unwrap();
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
            Message::decode(Bytes::copy_from_slice(&buf[..len]), DecodeConfig::default())
                .unwrap()
                .value
        else {
            panic!("expected community request");
        };
        assert!(request.community().matches(&community));

        let request_id = request.into_pdu().unwrap().request_id();
        let response = CommunityMessage::v2c(
            community,
            ResponsePdu::success(
                Version::V2c,
                request_id,
                vec![VarBind::new(
                    Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 1, 0]),
                    Value::OctetString(Bytes::from_static(b"matched")),
                )],
            )
            .unwrap(),
        )
        .unwrap()
        .encode()
        .unwrap();
        socket.send_to(&response, source).await.unwrap();
    });

    let client = Client::builder(peer, Auth::v2c(Bytes::from_static(b"public\xff")))
        .request_timeout(Duration::from_secs(2))
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

async fn udp_suffix_policy(version: async_snmp::CommunityVersion, config: DecodeConfig) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer = socket.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        let (len, source) = socket.recv_from(&mut buf).await.unwrap();
        let request = Message::decode(Bytes::copy_from_slice(&buf[..len]), DecodeConfig::default())
            .unwrap()
            .value;
        let request_id = request.into_pdu().unwrap().request_id();
        let oid = Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 1, 0]);
        let response = CommunityMessage::new(
            version.into(),
            "public",
            ResponsePdu::success(
                version.into(),
                request_id,
                vec![VarBind::new(
                    oid,
                    Value::OctetString(Bytes::from_static(b"suffix policy")),
                )],
            )
            .unwrap(),
        )
        .unwrap()
        .encode()
        .unwrap();
        let mut suffixed = response.to_vec();
        // This is itself a plausible SNMP message carrying another ID. It must
        // remain opaque suffix data during correlation.
        suffixed.extend_from_slice(
            CommunityMessage::new(
                version.into(),
                "public",
                ResponsePdu::success(version.into(), request_id.wrapping_add(1), Vec::new())
                    .unwrap(),
            )
            .unwrap()
            .encode()
            .unwrap()
            .as_ref(),
        );
        socket.send_to(&suffixed, source).await.unwrap();
        if !config.trailing_bytes {
            socket.send_to(&response, source).await.unwrap();
        }
    });

    let auth = match version {
        async_snmp::CommunityVersion::V1 => Auth::v1("public"),
        async_snmp::CommunityVersion::V2c => Auth::v2c("public"),
    };
    let result = Client::builder(peer, auth)
        .decode_config(config)
        .request_timeout(Duration::from_secs(2))
        .retry(Retry::none())
        .connect()
        .await
        .unwrap()
        .get(&Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 1, 0]))
        .await
        .unwrap();
    assert_eq!(
        result.varbinds[0].value,
        Value::OctetString(Bytes::from_static(b"suffix policy"))
    );
    if config.trailing_bytes {
        assert!(matches!(
            result.metadata.decode_anomalies.as_slice(),
            [async_snmp::DecodeAnomaly::TrailingBytes {
                original_length: 1..,
                canonical_length: 0,
            }]
        ));
    } else {
        assert!(result.metadata.decode_anomalies.is_empty());
    }
    server.await.unwrap();
}

#[tokio::test]
async fn udp_client_suffix_policy_is_coherent_for_v1_and_v2c() {
    for version in [
        async_snmp::CommunityVersion::V1,
        async_snmp::CommunityVersion::V2c,
    ] {
        udp_suffix_policy(version, DecodeConfig::default()).await;
        udp_suffix_policy(version, DecodeConfig::STRICT).await;
    }
}
