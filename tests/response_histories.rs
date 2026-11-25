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
    let (observer, mut events) = async_snmp::TransportObserver::channel(64).unwrap();
    let endpoint = async_snmp::UdpEndpoint::builder()
        .observer(observer.clone())
        .spawn()
        .await
        .unwrap();
    let client = Client::builder(address, Auth::v2c("public"))
        .max_oids_per_request(1)
        .request_timeout(Duration::from_millis(200))
        .retry(Retry::none())
        .build_with(&endpoint)
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
        .send_inform(&oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1), 123, vec![])
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
    let stats = observer.stats();
    assert_eq!(stats.received_messages, 10);
    assert_eq!(stats.sent_messages, 6);
    assert_eq!(
        stats.socket_read_bytes,
        lengths.iter().sum::<usize>() as u64 + 5 * 9
    );
    assert_eq!(stats.received_message_bytes, stats.socket_read_bytes);
    assert_eq!(stats.sent_message_bytes, stats.socket_written_bytes);
    let mut receipts = Vec::new();
    while let Ok(event) = events.try_recv() {
        if let async_snmp::ObservationEvent::Received(info) = event {
            receipts.push(info);
        }
    }
    for record in records {
        assert_eq!(
            receipts.iter().filter(|&&info| info == record.info).count(),
            1
        );
    }
    endpoint.shutdown().await.unwrap();
}

#[cfg(feature = "agent")]
mod v3_batch {
    use super::*;
    use async_snmp::{
        Agent, AuthoritativeEngine, Error, FixedCardinalityOperation, ListenerSource, RunningAgent,
        UdpEndpoint,
    };

    const RECEIVE_CAPACITY: usize = 484;

    async fn start_agent() -> RunningAgent {
        let engine = AuthoritativeEngine::install(b"batch-history".as_slice(), |_| {
            Ok::<_, std::convert::Infallible>(())
        })
        .unwrap();
        Agent::builder()
            .listener(ListenerSource::Udp(
                UdpEndpoint::builder()
                    .bind("127.0.0.1:0")
                    .receive_capacity(RECEIVE_CAPACITY),
            ))
            .authoritative_engine(engine)
            .usm_user("monitor", Ok)
            .unwrap()
            .allow_all_access()
            .spawn()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn cold_v3_batches_split_and_keep_discovery_once() {
        let running = start_agent().await;
        for operation in [
            FixedCardinalityOperation::Get,
            FixedCardinalityOperation::GetNext,
        ] {
            let client = Client::builder(
                running.agent().bound_addresses()[0].local_addr,
                Auth::usm("monitor"),
            )
            .max_oids_per_request(80)
            .retry(Retry::none())
            .connect()
            .await
            .unwrap();
            let engine_boots_oid = oid!(1, 3, 6, 1, 6, 3, 10, 2, 1, 2, 0);
            let response = if operation == FixedCardinalityOperation::Get {
                client.get_many(&vec![engine_boots_oid.clone(); 80]).await
            } else {
                let engine_boots_prefix = oid!(1, 3, 6, 1, 6, 3, 10, 2, 1, 2);
                client.get_next_many(&vec![engine_boots_prefix; 80]).await
            }
            .unwrap();
            assert_eq!(response.operation, operation);
            assert_eq!(response.varbinds.len(), 80);
            assert!(
                response
                    .varbinds
                    .iter()
                    .all(|vb| vb.oid == engine_boots_oid)
            );
            let (discovery, responses) = response.metadata.received_messages.split_first().unwrap();
            assert_eq!(discovery.pdu_type, PduType::Report);
            assert!(responses.len() > 1);
            assert!(
                responses
                    .iter()
                    .all(|record| record.pdu_type == PduType::Response)
            );
        }
        running.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn cold_v3_batch_keeps_discovery_on_a_failed_singleton() {
        let running = start_agent().await;
        let client = Client::builder(
            running.agent().bound_addresses()[0].local_addr,
            Auth::usm("monitor"),
        )
        .retry(Retry::none())
        .connect()
        .await
        .unwrap();
        let mut arcs = [u32::MAX; async_snmp::oid::MAX_OID_LEN];
        arcs[..2].copy_from_slice(&[1, 3]);
        let oids = [
            async_snmp::Oid::from_slice(&arcs),
            oid!(1, 3, 6, 1, 6, 3, 10, 2, 1, 2, 0),
        ];
        let mut chunks = client.get_many_chunks(&oids).unwrap();

        let error = chunks.next().await.unwrap().unwrap_err();
        assert_eq!(error.failed_request_range, 0..1);
        assert!(matches!(
            error.source.exchange_source(),
            Error::OutboundMessageTooLarge {
                limit: RECEIVE_CAPACITY,
                ..
            }
        ));
        let [discovery] = error
            .source
            .response_metadata()
            .unwrap()
            .received_messages
            .as_slice()
        else {
            panic!("expected only the discovery Report");
        };
        assert_eq!(discovery.pdu_type, PduType::Report);
        assert!(chunks.next().await.is_none());
        running.shutdown().await.unwrap();
    }
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
        (reply.len(), combined.len())
    });
    let (observer, mut events) = async_snmp::TransportObserver::channel(32).unwrap();
    let transport = async_snmp::TcpTransport::builder()
        .observer(observer.clone())
        .connect(address)
        .await
        .unwrap();
    let client = async_snmp::ClientBuilder::new(Auth::v2c("public"))
        .request_timeout(Duration::from_secs(2))
        .retry(Retry::none())
        .build_with_transport(transport)
        .unwrap();
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.unwrap();
    drop(client);
    let (length, input_bytes) = server.await.unwrap();
    let [record] = result.metadata.received_messages.as_slice() else {
        panic!("one accepted frame")
    };
    assert_eq!(record.info.received_len(), length);
    assert_eq!(record.info.transport(), TransportKind::Tcp);
    assert!(record.info.session_id().is_some());
    assert_eq!(record.pdu_type, PduType::Response);
    assert!(record.decode_anomalies.is_empty());
    let stats = observer.stats();
    assert_eq!(stats.received_messages, 3);
    assert_eq!(stats.socket_read_bytes, input_bytes as u64);
    assert_eq!(stats.received_message_bytes, input_bytes as u64);
    assert_eq!(stats.sent_messages, 1);
    let mut matched = 0;
    while let Ok(event) = events.try_recv() {
        if let async_snmp::ObservationEvent::Received(info) = event
            && info == record.info
        {
            matched += 1;
        }
    }
    assert_eq!(matched, 1);
}
