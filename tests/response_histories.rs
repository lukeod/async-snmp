//! Histories retain complete accepted inputs independently of operation aggregation.

use async_snmp::message::{CommunityMessage, Message};
use async_snmp::{
    Auth, Client, DecodeConfig, PduType, ResponsePdu, Retry, TransportKind, Value, Version, oid,
};
use bytes::Bytes;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

fn response(data: Bytes, too_big: bool) -> Bytes {
    let message = Message::decode(data, DecodeConfig::default())
        .unwrap()
        .value;
    let request = message.into_pdu().unwrap();
    let mut bindings = request.varbinds().to_vec();
    if request.pdu_type() != PduType::InformRequest {
        for binding in &mut bindings {
            binding.value = Value::Integer(7);
        }
    }
    let pdu = if too_big {
        ResponsePdu::too_big(Version::V2c, request.request_id(), vec![])
    } else {
        ResponsePdu::success(Version::V2c, request.request_id(), bindings)
    }
    .unwrap();
    CommunityMessage::v2c("public", pdu)
        .unwrap()
        .encode()
        .unwrap()
}

#[tokio::test]
async fn udp_batch_error_and_inform_histories_keep_each_input_length() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut buffer = [0; 4096];
        let mut lengths = Vec::new();
        for index in 0..6 {
            let (length, source) = socket.recv_from(&mut buffer).await.unwrap();
            if index == 5 {
                // This operation has no accepted input, unlike the preceding five.
                break;
            }
            let mut reply =
                response(Bytes::copy_from_slice(&buffer[..length]), index == 3).to_vec();
            if index == 0 {
                reply.extend_from_slice(&[0xaa; 700]);
            }
            lengths.push(reply.len());
            socket.send_to(b"malformed", source).await.unwrap();
            socket.send_to(&reply, source).await.unwrap();
        }
        lengths
    });
    let client = Client::builder(address, Auth::v2c("public"))
        .max_oids_per_request(1)
        .request_timeout(Duration::from_millis(200))
        .retry(Retry::none())
        .connect()
        .await
        .unwrap();
    let oids = [
        oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
        oid!(1, 3, 6, 1, 2, 1, 1, 2, 0),
        oid!(1, 3, 6, 1, 2, 1, 1, 3, 0),
    ];
    let batch = client.get_many(&oids).await.unwrap();
    let error = client.get(&oids[0]).await.unwrap_err();
    assert!(matches!(
        error.exchange_source(),
        async_snmp::Error::Snmp { .. }
    ));
    let inform = client
        .send_inform_with_metadata(&oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1), 123, vec![])
        .await
        .unwrap();
    let no_response = client.get(&oids[0]).await.unwrap_err();
    assert!(no_response.response_metadata().is_none());
    let lengths = server.await.unwrap();
    assert_eq!(batch.metadata.received_messages.len(), 3);
    assert_eq!(
        error.response_metadata().unwrap().received_messages.len(),
        1
    );
    assert_eq!(inform.received_messages.len(), 1);
    let records: Vec<_> = batch
        .metadata
        .received_messages
        .iter()
        .chain(&error.response_metadata().unwrap().received_messages)
        .chain(&inform.received_messages)
        .collect();
    assert_eq!(
        records
            .iter()
            .map(|record| record.info.received_len())
            .collect::<Vec<_>>(),
        lengths
    );
    for (index, record) in records.iter().enumerate() {
        assert_eq!(record.pdu_type, PduType::Response);
        assert_eq!(record.info.transport(), TransportKind::Udp);
        assert_eq!(record.info.peer_addr(), address);
        assert_eq!(record.info.endpoint_id(), records[0].info.endpoint_id());
        assert!(
            records[..index]
                .iter()
                .all(|earlier| earlier.info.reception_id() != record.info.reception_id())
        );
    }
    assert_eq!(batch.metadata.decode_anomalies().count(), 1);
    assert!(
        records[1].decode_anomalies.is_empty(),
        "short input must not inherit prior buffer suffix"
    );
    assert!(records[0].info.received_len() > records[1].info.received_len() + 600);
}

async fn read_frame(stream: &mut TcpStream) -> Bytes {
    let mut bytes = vec![0; 2];
    stream.read_exact(&mut bytes).await.unwrap();
    let length = if bytes[1] & 0x80 == 0 {
        usize::from(bytes[1])
    } else {
        let octets = usize::from(bytes[1] & 0x7f);
        bytes.resize(2 + octets, 0);
        stream.read_exact(&mut bytes[2..]).await.unwrap();
        bytes[2..]
            .iter()
            .fold(0, |length, byte| length * 256 + usize::from(*byte))
    };
    let start = bytes.len();
    bytes.resize(start + length, 0);
    stream.read_exact(&mut bytes[start..]).await.unwrap();
    Bytes::from(bytes)
}

#[tokio::test]
async fn tcp_history_counts_one_frame_despite_segmentation_and_adjacent_rejections() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_frame(&mut stream).await;
        let reply = response(request.clone(), false);
        let id = Message::decode(request, DecodeConfig::default())
            .unwrap()
            .value
            .into_pdu()
            .unwrap()
            .request_id();
        let decoy = CommunityMessage::v2c(
            "public",
            ResponsePdu::success(Version::V2c, id.wrapping_add(1), vec![]).unwrap(),
        )
        .unwrap()
        .encode()
        .unwrap();
        let mut combined = vec![0x30, 0]; // Complete framing, invalid SNMP message.
        combined.extend_from_slice(&decoy);
        combined.extend_from_slice(&reply);
        stream.write_all(&combined[..1]).await.unwrap();
        tokio::task::yield_now().await;
        stream.write_all(&combined[1..]).await.unwrap();
        // Keep the connection until the client finishes validation.
        let mut byte = [0];
        let _ = stream.read(&mut byte).await;
        reply.len()
    });
    let client = Client::builder(address, Auth::v2c("public"))
        .request_timeout(Duration::from_secs(2))
        .retry(Retry::none())
        .connect_tcp()
        .await
        .unwrap();
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    drop(client);
    let length = server.await.unwrap();
    let [record] = result.metadata.received_messages.as_slice() else {
        panic!("one accepted frame")
    };
    assert_eq!(record.info.received_len(), length);
    assert_eq!(record.info.transport(), TransportKind::Tcp);
    assert!(record.info.session_id().is_some());
    assert_eq!(record.pdu_type, PduType::Response);
    assert!(record.decode_anomalies.is_empty());
}
