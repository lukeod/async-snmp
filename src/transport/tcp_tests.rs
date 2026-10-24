use super::*;
use crate::transport::extract_request_id;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;

fn deadline_after(timeout: Duration) -> Instant {
    Instant::now() + timeout
}
async fn read_ber_message(
    stream: &mut TcpStream,
    target: SocketAddr,
    maximum: usize,
) -> Result<Bytes> {
    BerFramer::new(
        maximum,
        Duration::from_secs(5),
        Duration::from_secs(5),
        Arc::new(Semaphore::new(maximum)),
    )
    .next(stream, target)
    .await?
    .map(|frame| frame.bytes)
    .ok_or_else(|| Error::Closed { target }.boxed())
}
impl TcpTransport {
    async fn request(
        &self,
        data: &[u8],
        registration: RequestRegistration,
    ) -> Result<(Bytes, SocketAddr)> {
        self.request_with(Bytes::copy_from_slice(data), registration, |packet| {
            let (bytes, info) = packet.into_parts();
            Ok(Candidate::Accept((bytes, info.peer_addr())))
        })
        .await
    }
}

#[tokio::test]
async fn unrepresentable_connect_deadline_starts_no_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    let error = TcpTransport::connect_timeout(server_addr, Duration::MAX)
        .await
        .err()
        .expect("unrepresentable connect deadline must fail");
    assert!(matches!(*error, Error::Config(_)));
    assert!(
        tokio::time::timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err(),
        "invalid connect deadline started stream I/O"
    );
}

#[tokio::test]
async fn test_tcp_long_length_form() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 31];
        socket.read_exact(&mut request).await.unwrap();

        // Encode the otherwise ordinary 29-byte response content using the
        // BER long form so correlation still sees a complete SNMP frame.
        let response = build_response_with_id(1);
        let mut long_form = vec![0x30, 0x81, response[1]];
        long_form.extend_from_slice(&response[2..]);
        socket.write_all(&long_form).await.unwrap();
    });

    let transport = TcpTransport::connect(server_addr).await.unwrap();
    let registration = RequestRegistration::test_unchecked(1, Duration::from_secs(5));
    let (response, _) = transport
        .request(&build_request_with_id(1), registration)
        .await
        .unwrap();

    assert_eq!(response.len(), 32);
    assert_eq!(&response[..3], &[0x30, 0x81, 0x1d]);
    server.await.unwrap();
}

#[tokio::test]
async fn test_tcp_advertised_max_matches_accepted_limit() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut conns = Vec::new();
        while let Ok((socket, _)) = listener.accept().await {
            conns.push(socket);
        }
    });

    // Default limit.
    let transport = TcpTransport::connect(server_addr).await.unwrap();
    assert_eq!(
        transport.receive_limits().advertised().as_usize(),
        transport.inner.state.receive_limits.accepted(),
        "advertised msgMaxSize must equal the accepted total-message limit"
    );
    assert_eq!(
        transport.receive_limits().advertised().as_usize(),
        DEFAULT_MAX_MESSAGE_SIZE
    );

    // Custom limit via the builder.
    let custom = 512 * 1024;
    let transport = TcpTransport::builder()
        .max_message_size(custom)
        .connect(server_addr)
        .await
        .unwrap();
    assert_eq!(transport.receive_limits().advertised().as_usize(), custom);
    assert_eq!(
        transport.receive_limits().advertised().as_usize(),
        transport.inner.state.receive_limits.accepted()
    );
}

#[tokio::test]
async fn receive_advertisement_and_send_capacity_are_independent() {
    let request = build_request_with_id(1);
    let exact_limit = request.len();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    let (inspect_tx, inspect_rx) = tokio::sync::oneshot::channel();
    let (inspected_tx, inspected_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        inspect_rx.await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), socket.read_u8())
                .await
                .is_err(),
            "oversized rejection must leave the TCP stream empty"
        );
        inspected_tx.send(()).unwrap();
        let mut received = vec![0; exact_limit];
        socket.read_exact(&mut received).await.unwrap();
        received
    });

    let transport = TcpTransport::builder()
        .max_message_size(4096)
        .send_capacity(exact_limit)
        .connect(server_addr)
        .await
        .unwrap();
    assert_eq!(transport.receive_limits().advertised().as_usize(), 4096);
    assert_eq!(transport.send_capacity(), exact_limit);

    let mut oversized = request.clone();
    oversized.push(0);
    let error = transport.send(oversized.clone().into()).await.unwrap_err();
    assert!(matches!(
        *error,
        Error::OutboundMessageTooLarge { size, limit }
            if size == exact_limit + 1 && limit == exact_limit
    ));
    inspect_tx.send(()).unwrap();
    inspected_rx.await.unwrap();

    transport.send(request.clone().into()).await.unwrap();
    assert_eq!(server.await.unwrap(), request);
}

#[tokio::test]
async fn test_tcp_is_reliable() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    // Accept connection in background
    tokio::spawn(async move {
        let _ = listener.accept().await;
    });

    let transport = TcpTransport::connect(server_addr).await.unwrap();
    assert!(transport.is_reliable());
}

#[tokio::test]
async fn test_tcp_concurrent_requests() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    // Server that handles multiple sequential requests
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();

        // Respond to five complete frames
        for _ in 0..5 {
            // Read request using BER framing
            let mut tag = [0u8; 1];
            if socket.read_exact(&mut tag).await.is_err() {
                break;
            }

            let mut len_byte = [0u8; 1];
            socket.read_exact(&mut len_byte).await.unwrap();
            let content_len = len_byte[0] as usize;

            let mut content = vec![0u8; content_len];
            socket.read_exact(&mut content).await.unwrap();

            let mut request = Vec::with_capacity(content_len + 2);
            request.extend_from_slice(&tag);
            request.extend_from_slice(&len_byte);
            request.extend_from_slice(&content);
            let request_id = extract_request_id(&request).unwrap();
            let response = build_response_with_id(request_id);
            socket.write_all(&response).await.unwrap();
        }
    });

    let transport = TcpTransport::connect(server_addr).await.unwrap();

    // Spawn 5 concurrent tasks that all try to use the transport
    let mut handles = vec![];
    for i in 0..5 {
        let transport = transport.clone();
        let handle = tokio::spawn(async move {
            let request_id = i + 1;
            let request = build_request_with_id(request_id);

            let registration =
                RequestRegistration::test_unchecked(request_id, Duration::from_secs(5));
            let (response, _) = transport.request(&request, registration).await?;

            // Verify we got a valid response
            assert_eq!(response[0], 0x30, "Response should be SEQUENCE");
            Ok::<_, Box<Error>>(i)
        });
        handles.push(handle);
    }

    // Wait for all tasks to complete
    let results: Vec<_> = futures::future::join_all(handles).await;

    let success_count = results
        .iter()
        .filter(|r| r.as_ref().is_ok_and(std::result::Result::is_ok))
        .count();

    assert_eq!(success_count, 5, "All concurrent requests should succeed");

    server.await.unwrap();
}
fn build_request_with_id(request_id: i32) -> Vec<u8> {
    let id_bytes = request_id.to_be_bytes();
    vec![
        0x30,
        0x1d, // SEQUENCE length 29
        0x02,
        0x01,
        0x01, // version = 1 (v2c)
        0x04,
        0x06,
        0x70,
        0x75,
        0x62,
        0x6c,
        0x69,
        0x63, // "public"
        0xa0,
        0x10, // GET PDU length 16
        0x02,
        0x04,
        id_bytes[0],
        id_bytes[1],
        id_bytes[2],
        id_bytes[3], // request_id
        0x02,
        0x01,
        0x00, // error-status = 0
        0x02,
        0x01,
        0x00, // error-index = 0
        0x30,
        0x02,
        0x30,
        0x00, // varbinds
    ]
}
fn build_response_with_id(request_id: i32) -> Vec<u8> {
    let id_bytes = request_id.to_be_bytes();
    vec![
        0x30,
        0x1d, // SEQUENCE length 29
        0x02,
        0x01,
        0x01, // version = 1 (v2c)
        0x04,
        0x06,
        0x70,
        0x75,
        0x62,
        0x6c,
        0x69,
        0x63, // "public"
        0xa2,
        0x10, // Response PDU length 16
        0x02,
        0x04,
        id_bytes[0],
        id_bytes[1],
        id_bytes[2],
        id_bytes[3], // request_id
        0x02,
        0x01,
        0x00, // error-status = 0
        0x02,
        0x01,
        0x00, // error-index = 0
        0x30,
        0x02,
        0x30,
        0x00, // varbinds
    ]
}

#[tokio::test]
async fn tcp_skips_mismatched_community_frame_under_original_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 31];
        stream.read_exact(&mut request).await.unwrap();
        let mut wrong = build_response_with_id(77);
        wrong[7..13].copy_from_slice(b"other!");
        stream.write_all(&wrong).await.unwrap();
        stream.write_all(&build_response_with_id(77)).await.unwrap();
    });

    let transport = TcpTransport::connect(addr).await.unwrap();
    let registration = RequestRegistration::community(
        77,
        deadline_after(Duration::from_secs(2)),
        crate::CommunityVersion::V2c,
        Bytes::from_static(b"public"),
        super::super::CommunityResponsePolicy::Exact,
    );
    let (response, _) = transport
        .request(&build_request_with_id(77), registration)
        .await
        .unwrap();
    assert_eq!(response.as_ref(), build_response_with_id(77));
    server.await.unwrap();
}

#[tokio::test]
async fn tcp_strict_envelope_policy_applies_to_each_framed_message() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 31];
        stream.read_exact(&mut request).await.unwrap();
        // Back-to-back top-level TLVs are two TCP frames, not one message
        // with a suffix. Strict policy accepts the first framed response.
        stream.write_all(&build_response_with_id(77)).await.unwrap();
        stream.write_all(&build_response_with_id(78)).await.unwrap();
    });

    let transport = TcpTransport::connect(addr).await.unwrap();
    let registration = RequestRegistration::community(
        77,
        deadline_after(Duration::from_secs(2)),
        crate::CommunityVersion::V2c,
        Bytes::from_static(b"public"),
        super::super::CommunityResponsePolicy::Exact,
    )
    .with_decode_config(crate::DecodeConfig::STRICT);
    let (response, _) = transport
        .request(&build_request_with_id(77), registration)
        .await
        .unwrap();
    assert_eq!(response.as_ref(), build_response_with_id(77));
    server.await.unwrap();
}

#[tokio::test]
async fn tcp_skips_stale_id_then_accepts_primary_id() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 31];
        stream.read_exact(&mut request).await.unwrap();
        stream.write_all(&build_response_with_id(90)).await.unwrap();
        stream.write_all(&build_response_with_id(91)).await.unwrap();
    });

    let transport = TcpTransport::connect(addr).await.unwrap();
    let (response, _) = transport
        .request(
            &build_request_with_id(91),
            RequestRegistration::test_unchecked(91, Duration::from_secs(2)),
        )
        .await
        .unwrap();
    assert_eq!(extract_request_id(&response), Some(91));
    server.await.unwrap();
}

#[tokio::test]
async fn tcp_accepts_each_registered_alias_id() {
    for accepted_alias in [101, 102] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 31];
            stream.read_exact(&mut request).await.unwrap();
            stream
                .write_all(&build_response_with_id(accepted_alias))
                .await
                .unwrap();
        });

        let transport = TcpTransport::connect(addr).await.unwrap();
        let registration = RequestRegistration::test_unchecked(100, Duration::from_secs(2))
            .with_aliases([101, 102])
            .unwrap();
        let (response, _) = transport
            .request(&build_request_with_id(100), registration)
            .await
            .unwrap();
        assert_eq!(extract_request_id(&response), Some(accepted_alias));
        server.await.unwrap();
    }
}

#[tokio::test]
async fn stale_frames_do_not_extend_deadline_or_close_session() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 31];
        stream.read_exact(&mut request).await.unwrap();
        for stale_id in 200..230 {
            if stream
                .write_all(&build_response_with_id(stale_id))
                .await
                .is_err()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });

    let transport = TcpTransport::connect(addr).await.unwrap();
    let start = tokio::time::Instant::now();
    let error = transport
        .request(
            &build_request_with_id(300),
            RequestRegistration::v3(300, deadline_after(Duration::from_millis(100))),
        )
        .await
        .unwrap_err();
    let elapsed = start.elapsed();
    assert!(matches!(*error, Error::Timeout { .. }));
    assert!(elapsed < Duration::from_millis(250), "elapsed {elapsed:?}");
    assert!(!transport.control().is_shutdown());
    server.abort();
}

#[tokio::test]
async fn tcp_validator_rejection_keeps_exchange_for_later_frame() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 31];
        stream.read_exact(&mut request).await.unwrap();
        stream.write_all(&build_response_with_id(78)).await.unwrap();
        stream.write_all(&build_response_with_id(78)).await.unwrap();
    });

    let transport = TcpTransport::connect(addr).await.unwrap();
    let registration = RequestRegistration::community(
        78,
        deadline_after(Duration::from_secs(2)),
        crate::CommunityVersion::V2c,
        Bytes::from_static(b"public"),
        super::super::CommunityResponsePolicy::Exact,
    );
    let mut candidates = 0;
    let response = transport
        .request_with((build_request_with_id(78)).into(), registration, |packet| {
            let (data, _) = packet.into_parts();
            candidates += 1;
            if candidates == 1 {
                Ok(Candidate::Reject)
            } else {
                Ok(Candidate::Accept(data))
            }
        })
        .await
        .unwrap();
    assert_eq!(response.as_ref(), build_response_with_id(78));
    assert_eq!(candidates, 2);
    server.await.unwrap();
}

#[tokio::test]
async fn test_read_ber_message_rejects_bad_tag() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        socket.write_all(&[0x31, 0x00]).await.unwrap();
    });

    let mut client = TcpStream::connect(server_addr).await.unwrap();
    let result = timeout(
        Duration::from_secs(5),
        read_ber_message(&mut client, server_addr, DEFAULT_MAX_MESSAGE_SIZE),
    )
    .await
    .expect("read_ber_message should not hang");

    assert!(result.is_err(), "Should reject non-0x30 tag byte");
    let err = result.unwrap_err();
    assert!(
        matches!(&*err, Error::Decode(error)
                if error.offset == 0
                    && error.kind == crate::DecodeErrorKind::UnexpectedTag { expected: 0x30, actual: 0x31 }
                    && error.peer == Some(server_addr)),
        "Expected Decode error, got: {err:?}"
    );

    server.await.unwrap();
}

#[tokio::test]
async fn test_read_ber_message_rejects_indefinite_length() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        socket.write_all(&[0x30, 0x80]).await.unwrap();
    });

    let mut client = TcpStream::connect(server_addr).await.unwrap();
    let result = timeout(
        Duration::from_secs(5),
        read_ber_message(&mut client, server_addr, DEFAULT_MAX_MESSAGE_SIZE),
    )
    .await
    .expect("read_ber_message should not hang");

    assert!(result.is_err(), "Should reject indefinite length encoding");
    let err = result.unwrap_err();
    assert!(
        matches!(*err, Error::Decode(_)),
        "Expected Decode error, got: {err:?}"
    );

    server.await.unwrap();
}

#[tokio::test]
async fn test_read_ber_message_rejects_length_encoding_too_long() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        // 0x85 = long form, 5 trailing length octets (> 4-octet cap).
        socket
            .write_all(&[0x30, 0x85, 0x00, 0x00, 0x00, 0x00, 0x00])
            .await
            .unwrap();
    });

    let mut client = TcpStream::connect(server_addr).await.unwrap();
    let result = timeout(
        Duration::from_secs(5),
        read_ber_message(&mut client, server_addr, DEFAULT_MAX_MESSAGE_SIZE),
    )
    .await
    .expect("read_ber_message should not hang");

    assert!(
        result.is_err(),
        "Should reject length encoding over 4 octets"
    );
    let err = result.unwrap_err();
    assert!(
        matches!(*err, Error::Decode(_)),
        "Expected Decode error, got: {err:?}"
    );

    server.await.unwrap();
}

#[tokio::test]
async fn test_read_ber_message_reassembles_segmented_content() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();

        // Tag + length in the first segment.
        socket.write_all(&[0x30, 0x04]).await.unwrap();
        socket.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;

        // First half of content.
        socket.write_all(&[0x01, 0x02]).await.unwrap();
        socket.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Second half of content.
        socket.write_all(&[0x03, 0x04]).await.unwrap();
        socket.flush().await.unwrap();

        // Keep the connection open until the client has read everything.
        tokio::time::sleep(Duration::from_millis(100)).await;
    });

    let mut client = TcpStream::connect(server_addr).await.unwrap();
    let result = timeout(
        Duration::from_secs(5),
        read_ber_message(&mut client, server_addr, DEFAULT_MAX_MESSAGE_SIZE),
    )
    .await
    .expect("read_ber_message should not hang");

    let bytes = result.expect("segmented message should reassemble successfully");
    assert_eq!(bytes.as_ref(), &[0x30, 0x04, 0x01, 0x02, 0x03, 0x04]);

    server.await.unwrap();
}

#[tokio::test]
async fn test_read_ber_message_truncated_stream_is_network_error() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();

        // Claims 5 content octets but only ever sends 2, then drops the
        // connection.
        socket.write_all(&[0x30, 0x05]).await.unwrap();
        socket.write_all(&[0x01, 0x02]).await.unwrap();
        socket.flush().await.unwrap();
        drop(socket);
    });

    let mut client = TcpStream::connect(server_addr).await.unwrap();
    let result = timeout(
        Duration::from_secs(5),
        read_ber_message(&mut client, server_addr, DEFAULT_MAX_MESSAGE_SIZE),
    )
    .await
    .expect("read_ber_message should not hang");

    assert!(result.is_err(), "Should error on truncated content stream");
    let err = result.unwrap_err();
    assert!(
        matches!(*err, Error::Network { .. }),
        "Expected Network error, got: {err:?}"
    );

    server.await.unwrap();
}

#[tokio::test]
async fn invalid_tcp_message_sizes_are_rejected_before_connect() {
    let target = "127.0.0.1:9".parse().unwrap();
    for size in [0usize, 483, i32::MAX as usize + 1, usize::MAX] {
        let error = TcpTransport::builder()
            .max_message_size(size)
            .connect(target)
            .await
            .err()
            .expect("invalid size must fail before connect");
        assert!(
            matches!(*error, Error::Config(_)),
            "unexpected error: {error}"
        );
    }
}

#[tokio::test]
async fn tcp_frame_limit_counts_total_encoded_size() {
    const CONTENT_LEN: usize = 481;
    // 0x82 + two length octets gives a four-byte tag/length header.
    const TOTAL_LEN: usize = 1 + 3 + CONTENT_LEN;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut frame = vec![0x30, 0x82, 0x01, 0xe1];
        frame.resize(TOTAL_LEN, 0);
        socket.write_all(&frame).await.unwrap();
    });
    let mut client = TcpStream::connect(server_addr).await.unwrap();
    let frame = read_ber_message(&mut client, server_addr, TOTAL_LEN)
        .await
        .expect("exact total-message limit should be accepted");
    assert_eq!(frame.len(), TOTAL_LEN);
    server.await.unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        // Only the header is needed: rejection must precede content allocation/read.
        socket.write_all(&[0x30, 0x82, 0x01, 0xe1]).await.unwrap();
    });
    let mut client = TcpStream::connect(server_addr).await.unwrap();
    let error = read_ber_message(&mut client, server_addr, TOTAL_LEN - 1)
        .await
        .expect_err("one byte over total-message limit must be rejected");
    assert!(matches!(*error, Error::Decode(_)));
    server.await.unwrap();
}

async fn pair(builder: TcpTransportBuilder) -> (PreparedTcpSession, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (prepared, accepted) = tokio::join!(builder.target(address).prepare(), listener.accept());
    (prepared.unwrap(), accepted.unwrap().0)
}
fn registration(id: i32) -> RequestRegistration {
    RequestRegistration::test_unchecked(id, Duration::from_secs(2))
}

#[tokio::test]
async fn concurrent_requests_are_written_before_any_response_and_correlated_out_of_order() {
    let (prepared, mut peer) = pair(TcpTransport::builder()).await;
    let running = prepared.spawn();
    let session = running.session_id();
    let endpoint = running.endpoint_id();
    let peer_task = tokio::spawn(async move {
        let address = peer.peer_addr().unwrap();
        let mut ids = Vec::new();
        for _ in 0..8 {
            ids.push(
                extract_request_id(&read_ber_message(&mut peer, address, 4096).await.unwrap())
                    .unwrap(),
            );
        }
        for id in ids.into_iter().rev() {
            peer.write_all(&build_response_with_id(id)).await.unwrap();
        }
    });
    let requests = (1..=8).map(|id| {
        let transport = running.transport();
        async move {
            let response = transport
                .request_with(
                    (build_request_with_id(id)).into(),
                    registration(id),
                    |packet| {
                        let (bytes, info) = packet.into_parts();
                        assert_eq!(info.session_id(), Some(session));
                        assert_eq!(info.endpoint_id(), endpoint);
                        assert_eq!(info.received_len(), bytes.len());
                        Ok(Candidate::Accept(bytes))
                    },
                )
                .await
                .unwrap();
            assert_eq!(extract_request_id(&response), Some(id));
        }
    });
    timeout(Duration::from_secs(3), futures::future::join_all(requests))
        .await
        .unwrap();
    peer_task.await.unwrap();
    running.join().await.unwrap();
}

#[tokio::test]
async fn cancellation_after_write_preserves_partial_read_and_late_response_is_discarded() {
    let (prepared, mut peer) = pair(TcpTransport::builder()).await;
    let running = prepared.spawn();
    let first = running.transport();
    let task = tokio::spawn(async move {
        first
            .request(&build_request_with_id(1), registration(1))
            .await
    });
    let address = peer.peer_addr().unwrap();
    read_ber_message(&mut peer, address, 4096).await.unwrap();
    let late = build_response_with_id(1);
    peer.write_all(&late[..8]).await.unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let second = running.transport();
    let task = tokio::spawn(async move {
        second
            .request(&build_request_with_id(2), registration(2))
            .await
    });
    read_ber_message(&mut peer, address, 4096).await.unwrap();
    peer.write_all(&late[8..]).await.unwrap();
    peer.write_all(&build_response_with_id(2)).await.unwrap();
    assert_eq!(extract_request_id(&task.await.unwrap().unwrap().0), Some(2));
    assert!(!running.control().is_shutdown());
    running.shutdown().await.unwrap();
}

#[tokio::test]
async fn exchange_timeout_does_not_close_idle_or_framing_session() {
    let (prepared, mut peer) = pair(TcpTransport::builder()).await;
    let running = prepared.spawn();
    let transport = running.transport();
    let task = tokio::spawn(async move {
        transport
            .request(
                &build_request_with_id(1),
                RequestRegistration::test_unchecked(1, Duration::from_millis(20)),
            )
            .await
    });
    let address = peer.peer_addr().unwrap();
    read_ber_message(&mut peer, address, 4096).await.unwrap();
    assert_eq!(
        task.await.unwrap().unwrap_err().kind(),
        crate::ErrorKind::Timeout
    );
    let transport = running.transport();
    let task = tokio::spawn(async move {
        transport
            .request(&build_request_with_id(2), registration(2))
            .await
    });
    read_ber_message(&mut peer, address, 4096).await.unwrap();
    peer.write_all(&build_response_with_id(1)).await.unwrap();
    peer.write_all(&build_response_with_id(2)).await.unwrap();
    assert_eq!(extract_request_id(&task.await.unwrap().unwrap().0), Some(2));
    running.shutdown().await.unwrap();
}

#[tokio::test]
async fn in_flight_bound_queues_under_absolute_deadline_without_sending() {
    let (prepared, mut peer) = pair(TcpTransport::builder().max_in_flight(1)).await;
    let running = prepared.spawn();
    let first = running.transport();
    let first = tokio::spawn(async move {
        first
            .request(&build_request_with_id(1), registration(1))
            .await
    });
    let address = peer.peer_addr().unwrap();
    read_ber_message(&mut peer, address, 4096).await.unwrap();
    let error = running
        .request(
            &build_request_with_id(2),
            RequestRegistration::test_unchecked(2, Duration::from_millis(10)),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), crate::ErrorKind::Timeout);
    assert!(
        timeout(Duration::from_millis(10), peer.read_u8())
            .await
            .is_err()
    );
    first.abort();
    let _ = first.await;
    let next = running.transport();
    let next = tokio::spawn(async move {
        next.request(&build_request_with_id(3), registration(3))
            .await
    });
    assert_eq!(
        extract_request_id(&read_ber_message(&mut peer, address, 4096).await.unwrap()),
        Some(3)
    );
    peer.write_all(&build_response_with_id(3)).await.unwrap();
    next.await.unwrap().unwrap();
    running.shutdown().await.unwrap();
}

#[tokio::test]
async fn queued_write_retains_encoded_allocation_and_output_admission() {
    for shared in [false, true] {
        let (sender, _receiver) = mpsc::channel(1);
        let service_budget = Arc::new(BufferBudget::new(1508));
        let mut builder = TcpTransport::builder()
            .max_message_size(484)
            .send_capacity(1024)
            .max_buffered_bytes(1508);
        if shared {
            builder = builder.ingress(
                super::super::ingress::ApplicationIngress {
                    admission_hook: None,
                    sender,
                    disabled: CancellationToken::new(),
                    capacity: Arc::new(Semaphore::new(1)),
                    budget: service_budget.clone(),
                    overload_timeout: Duration::from_secs(1),
                    drops: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                    session: None,
                },
                crate::EndpointId::new(),
            );
        }
        let (prepared, _peer) = pair(builder).await;
        let (transport, mut runner) = prepared.into_parts();
        let encoded = Bytes::from(vec![0x42; 128]);
        let allocation = encoded.as_ptr();
        let mut send = Box::pin(transport.send(encoded));
        assert!(futures::poll!(send.as_mut()).is_pending());
        let command = runner.writes.try_recv().unwrap();
        assert_eq!(command.bytes.as_ptr(), allocation);
        assert_eq!(
            transport.inner.state.budget.outbound.available_permits(),
            896
        );
        if shared {
            assert_eq!(service_budget.outbound.available_permits(), 896);
        }
        drop(send);
        assert!(command.cancelled.is_cancelled());
        // The queued frame owns its admission even after the caller cancels.
        assert_eq!(
            transport.inner.state.budget.outbound.available_permits(),
            896
        );
        drop(command);
        assert_eq!(
            transport.inner.state.budget.outbound.available_permits(),
            1024
        );
        if shared {
            assert_eq!(service_budget.outbound.available_permits(), 1024);
        }
    }
}

#[tokio::test]
async fn queued_cancellation_and_prestart_deadline_write_nothing() {
    let (prepared, mut peer) = pair(TcpTransport::builder().write_queue_capacity(1)).await;
    let (transport, runner) = prepared.into_parts();
    let first = transport.clone();
    let pending = tokio::spawn(async move {
        first
            .send_with_timeout(
                bytes::Bytes::from_static(b"cancelled"),
                Duration::from_secs(1),
            )
            .await
    });
    while transport.inner.writes.capacity() != 0 {
        tokio::task::yield_now().await;
    }
    pending.abort();
    let _ = pending.await;
    let error = transport
        .send_with_timeout(
            bytes::Bytes::from_static(b"expired"),
            Duration::from_millis(10),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), crate::ErrorKind::Timeout);
    let task = tokio::spawn(runner.run());
    transport
        .send(bytes::Bytes::from_static(b"ok"))
        .await
        .unwrap();
    let mut bytes = [0; 2];
    peer.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"ok");
    assert!(
        timeout(Duration::from_millis(10), peer.read_u8())
            .await
            .is_err()
    );
    transport.control().shutdown().await;
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn cleanup_on_unpolled_runner_future_and_task_abort() {
    for mode in 0..3 {
        let (prepared, _peer) = pair(TcpTransport::builder()).await;
        let (transport, runner) = prepared.into_parts();
        match mode {
            0 => drop(runner),
            1 => drop(runner.run()),
            _ => {
                let task = tokio::spawn(runner.run());
                task.abort();
                assert!(task.await.is_err());
            }
        }
        timeout(Duration::from_secs(1), transport.control().wait_closed())
            .await
            .unwrap();
        assert_eq!(
            transport
                .send(bytes::Bytes::from_static(b"closed"))
                .await
                .unwrap_err()
                .kind(),
            crate::ErrorKind::Closed
        );
        assert_eq!(
            transport
                .request(&build_request_with_id(1), registration(1))
                .await
                .unwrap_err()
                .kind(),
            crate::ErrorKind::Closed
        );
    }
}

#[tokio::test]
async fn abort_wakes_pending_and_owner_drop_closes_retained_peers() {
    let (prepared, mut peer) = pair(TcpTransport::builder()).await;
    let running = prepared.spawn();
    let handle = running.transport();
    let pending_handle = handle.clone();
    let pending = tokio::spawn(async move {
        pending_handle
            .request(&build_request_with_id(1), registration(1))
            .await
    });
    let address = peer.peer_addr().unwrap();
    read_ber_message(&mut peer, address, 4096).await.unwrap();
    running.task().abort();
    running.control().wait_closed().await;
    assert_eq!(
        pending.await.unwrap().unwrap_err().kind(),
        crate::ErrorKind::Closed
    );
    assert!(running.join().await.is_err());
    let (prepared, _peer) = pair(TcpTransport::builder()).await;
    let running = prepared.spawn();
    let control = running.control();
    drop(running);
    timeout(Duration::from_secs(1), control.wait_closed())
        .await
        .unwrap();
    assert!(control.is_shutdown());
}

#[tokio::test]
async fn retained_control_and_final_public_handle_have_distinct_lifetimes() {
    let (prepared, mut peer) = pair(TcpTransport::builder()).await;
    let (transport, runner) = prepared.into_parts();
    let control = transport.control();
    let task = tokio::spawn(runner.run());
    drop(transport);
    assert!(
        timeout(Duration::from_millis(10), peer.read_u8())
            .await
            .is_err()
    );
    drop(control);
    task.await.unwrap().unwrap();
    assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
}

#[tokio::test]
async fn shutdown_before_start_waits_until_runner_is_dropped() {
    let (prepared, _peer) = pair(TcpTransport::builder()).await;
    let (transport, runner) = prepared.into_parts();
    let control = transport.control();
    control.request_shutdown();
    assert!(
        timeout(Duration::from_millis(10), control.wait_closed())
            .await
            .is_err()
    );
    drop(runner);
    control.wait_closed().await;
}

#[tokio::test]
async fn invalid_complete_message_is_skipped_and_framing_failure_is_terminal() {
    let (prepared, mut peer) = pair(TcpTransport::builder()).await;
    let running = prepared.spawn();
    let handle = running.transport();
    let pending = tokio::spawn(async move {
        handle
            .request(&build_request_with_id(1), registration(1))
            .await
    });
    let address = peer.peer_addr().unwrap();
    read_ber_message(&mut peer, address, 4096).await.unwrap();
    peer.write_all(&[0x30, 0x01, 0xff]).await.unwrap();
    peer.write_all(&build_response_with_id(1)).await.unwrap();
    pending.await.unwrap().unwrap();
    peer.write_all(&[0x30, 0x80]).await.unwrap();
    running.control().wait_closed().await;
    assert!(matches!(running.control().status(), TcpStatus::Failed(_)));
    assert_eq!(
        running
            .send(bytes::Bytes::from_static(b"closed"))
            .await
            .unwrap_err()
            .kind(),
        crate::ErrorKind::Decode
    );
    assert!(running.join().await.is_err());
}

#[tokio::test]
async fn idle_has_no_timeout_but_partial_header_and_body_do() {
    for partial in [vec![0x30], vec![0x30, 0x03, 0x01]] {
        let (prepared, mut peer) = pair(
            TcpTransport::builder()
                .header_timeout(Duration::from_millis(20))
                .body_timeout(Duration::from_millis(20)),
        )
        .await;
        let running = prepared.spawn();
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(!running.control().is_shutdown());
        peer.write_all(&partial).await.unwrap();
        timeout(Duration::from_secs(1), running.control().wait_closed())
            .await
            .unwrap();
        assert!(matches!(running.control().status(), TcpStatus::Failed(_)));
        assert!(running.join().await.is_err());
    }
}

#[tokio::test]
async fn aggregate_budget_follows_pending_frames_and_bounds_allocation() {
    let budget = Arc::new(Semaphore::new(8));
    let mut framer = BerFramer::new(
        8,
        Duration::from_secs(1),
        Duration::from_secs(1),
        budget.clone(),
    );
    let mut input: &[u8] = &[0x30, 0x02, 1, 2, 0x30, 0x02, 3, 4, 0x30, 0x02, 5, 6];
    let address = "127.0.0.1:161".parse().unwrap();
    let first = framer.next(&mut input, address).await.unwrap().unwrap();
    let retained = first;
    assert_eq!(budget.available_permits(), 4);
    let second = framer.next(&mut input, address).await.unwrap().unwrap();
    assert_eq!(budget.available_permits(), 0);
    assert!(framer.next(&mut input, address).await.is_err());
    drop(retained);
    drop(second);
    assert_eq!(budget.available_permits(), 8);
}

#[tokio::test]
async fn framing_clean_eof_and_partial_eof_are_distinct() {
    let address = "127.0.0.1:161".parse().unwrap();
    for partial in [vec![], vec![0x30], vec![0x30, 0x82, 0], vec![0x30, 0x02, 1]] {
        let mut input = partial.as_slice();
        let mut framer = BerFramer::new(
            1024,
            Duration::from_secs(1),
            Duration::from_secs(1),
            Arc::new(Semaphore::new(1024)),
        );
        let result = framer.next(&mut input, address).await;
        if partial.is_empty() {
            assert!(result.unwrap().is_none());
        } else {
            assert_eq!(result.err().unwrap().kind(), crate::ErrorKind::Network);
        }
    }
}

#[tokio::test]
async fn oversized_declared_body_is_rejected_before_allocation() {
    let (prepared, mut peer) = pair(TcpTransport::builder().max_message_size(484)).await;
    let running = prepared.spawn();
    let initial = running.inner.state.budget.inbound.available_permits();
    peer.write_all(&[0x30, 0x84, 0x06, 0x40, 0, 0])
        .await
        .unwrap();
    running.control().wait_closed().await;
    assert_eq!(
        running.inner.state.budget.inbound.available_permits(),
        initial
    );
    assert_eq!(
        running.join().await.unwrap_err().kind(),
        crate::ErrorKind::Decode
    );
}

#[tokio::test]
async fn supplied_stream_preserves_options_and_rejects_conflicts() {
    let (_prepared, stream) = pair(TcpTransport::builder()).await;
    stream.set_nodelay(true).unwrap();
    stream.set_ttl(41).unwrap();
    let local = stream.local_addr().unwrap();
    let prepared = TcpTransport::builder()
        .from_stream(stream)
        .prepare()
        .await
        .unwrap();
    assert!(prepared.runner.stream.nodelay().unwrap());
    assert_eq!(prepared.runner.stream.ttl().unwrap(), 41);
    assert_eq!(prepared.transport.local_addr(), local);
    for conflict in 0..3 {
        let (_other, stream) = pair(TcpTransport::builder()).await;
        let builder = TcpTransport::builder().from_stream(stream);
        let builder = match conflict {
            0 => builder.target("127.0.0.1:161".parse().unwrap()),
            1 => builder.connect_timeout(Duration::from_secs(1)),
            _ => builder.from_socket(TcpSocket::new_v4().unwrap()),
        };
        assert_eq!(
            builder.prepare().await.err().unwrap().kind(),
            crate::ErrorKind::Config
        );
    }
}

#[tokio::test]
async fn accepted_session_can_initiate_an_exchange_and_closed_handle_is_not_replaced() {
    let (outbound, accepted) = pair(TcpTransport::builder()).await;
    let accepted = TcpTransport::builder()
        .from_stream(accepted)
        .prepare()
        .await
        .unwrap()
        .spawn();
    let first_id = accepted.session_id();
    let mut outbound_stream = outbound.runner.stream;
    let handle = accepted.transport();
    let pending = tokio::spawn(async move {
        handle
            .request(&build_request_with_id(7), registration(7))
            .await
    });
    let address = outbound_stream.peer_addr().unwrap();
    assert_eq!(
        extract_request_id(
            &read_ber_message(&mut outbound_stream, address, 4096)
                .await
                .unwrap()
        ),
        Some(7)
    );
    outbound_stream
        .write_all(&build_response_with_id(7))
        .await
        .unwrap();
    pending.await.unwrap().unwrap();
    let old = accepted.transport();
    accepted.shutdown().await.unwrap();
    let (replacement, _peer) = pair(TcpTransport::builder()).await;
    assert_ne!(first_id, replacement.transport.session_id());
    assert_eq!(
        old.send(bytes::Bytes::from_static(b"closed"))
            .await
            .unwrap_err()
            .kind(),
        crate::ErrorKind::Closed
    );
}

#[tokio::test]
async fn validation_error_and_rejected_candidates_leave_session_aligned() {
    let (prepared, mut peer) = pair(TcpTransport::builder()).await;
    let running = prepared.spawn();
    let peer_task = tokio::spawn(async move {
        let address = peer.peer_addr().unwrap();
        for id in 1..=2 {
            read_ber_message(&mut peer, address, 4096).await.unwrap();
            peer.write_all(&build_response_with_id(id)).await.unwrap();
        }
    });
    let error = running
        .request_with(
            (build_request_with_id(1)).into(),
            registration(1),
            |packet| {
                let (_, _) = packet.into_parts();
                Err::<Candidate<()>, _>(Error::Config("validator error".into()).boxed())
            },
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), crate::ErrorKind::Config);
    running
        .request(&build_request_with_id(2), registration(2))
        .await
        .unwrap();
    peer_task.await.unwrap();
    running.join().await.unwrap();
}

#[tokio::test]
async fn frame_larger_than_udp_capacity_is_received_with_exact_length() {
    let (prepared, mut peer) = pair(TcpTransport::builder()).await;
    let running = prepared.spawn();
    let handle = running.transport();
    let pending = tokio::spawn(async move {
        handle
            .request_with(
                (build_request_with_id(1)).into(),
                registration(1),
                |packet| {
                    let (data, info) = packet.into_parts();
                    assert_eq!(info.received_len(), data.len());
                    Ok(Candidate::Accept(data.len()))
                },
            )
            .await
    });
    let address = peer.peer_addr().unwrap();
    read_ber_message(&mut peer, address, 4096).await.unwrap();
    let message = crate::message::CommunityMessage::v2c(
        "public",
        crate::Pdu::response(
            1,
            0,
            0,
            vec![crate::VarBind::new(
                crate::oid!(1, 3, 6, 1),
                crate::Value::OctetString(Bytes::from(vec![1; 70_000])),
            )],
        ),
    )
    .unwrap()
    .encode()
    .unwrap();
    peer.write_all(&message).await.unwrap();
    assert_eq!(pending.await.unwrap().unwrap(), message.len());
    running.shutdown().await.unwrap();
}

#[tokio::test]
async fn cancelling_started_write_finishes_frame_before_next_message() {
    let (observer, _events) = crate::TransportObserver::channel(8).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let socket = TcpSocket::new_v4().unwrap();
    socket.set_send_buffer_size(4096).unwrap();
    let (prepared, accepted) = tokio::join!(
        TcpTransport::builder()
            .observer(observer.clone())
            .from_socket(socket)
            .target(address)
            .prepare(),
        listener.accept()
    );
    let running = prepared.unwrap().spawn();
    let mut peer = accepted.unwrap().0;
    let payload = vec![b'X'; 1024 * 1024];
    let sender = running.transport();
    let sending = tokio::spawn(async move { sender.send(payload.clone().into()).await });
    let mut first = [0; 1024];
    peer.read_exact(&mut first).await.unwrap();
    assert!(first.iter().all(|&byte| byte == b'X'));
    sending.abort();
    let _ = sending.await;
    let sender = running.transport();
    let next = tokio::spawn(async move { sender.send(bytes::Bytes::from_static(b"END")).await });
    let mut remainder = vec![0; 1024 * 1024 - first.len() + 3];
    timeout(Duration::from_secs(4), peer.read_exact(&mut remainder))
        .await
        .unwrap()
        .unwrap();
    assert!(
        remainder[..remainder.len() - 3]
            .iter()
            .all(|&byte| byte == b'X')
    );
    assert_eq!(&remainder[remainder.len() - 3..], b"END");
    next.await.unwrap().unwrap();
    assert_eq!(observer.stats().sent_messages, 2);
    assert_eq!(
        observer.stats().socket_written_bytes,
        (1024 * 1024 + 3) as u64
    );
    assert_eq!(
        observer.stats().sent_message_bytes,
        observer.stats().socket_written_bytes
    );
    assert!(!running.control().is_shutdown());
    running.shutdown().await.unwrap();
}

#[tokio::test]
async fn partial_write_uses_original_exchange_deadline_and_closes_session() {
    let (observer, mut events) = crate::TransportObserver::channel(8).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let socket = TcpSocket::new_v4().unwrap();
    socket.set_send_buffer_size(4096).unwrap();
    let (prepared, accepted) = tokio::join!(
        TcpTransport::builder()
            .observer(observer.clone())
            .from_socket(socket)
            .target(address)
            .prepare(),
        listener.accept()
    );
    let running = prepared.unwrap().spawn();
    let mut peer = accepted.unwrap().0;
    let payload = vec![b'X'; 4 * 1024 * 1024];
    let error = running
        .request(
            &payload,
            RequestRegistration::test_unchecked(1, Duration::from_millis(30)),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind(), crate::ErrorKind::Timeout);
    assert!(
        matches!(error.exchange_source(), Error::Timeout { elapsed, retries: 0, .. } if *elapsed >= Duration::from_millis(20))
    );
    timeout(Duration::from_secs(1), running.control().wait_closed())
        .await
        .unwrap();
    let mut written = Vec::new();
    peer.read_to_end(&mut written).await.unwrap();
    assert!(!written.is_empty());
    assert!(written.len() < payload.len());
    assert_eq!(observer.stats().socket_written_bytes, written.len() as u64);
    assert_eq!(observer.stats().sent_messages, 0);
    assert_eq!(observer.stats().sent_message_bytes, 0);
    assert!(events.try_recv().is_err());
    assert!(running.join().await.is_err());
}

#[tokio::test]
async fn retained_candidates_exhaust_session_budget_without_unbounded_allocation() {
    let (prepared, mut peer) = pair(
        TcpTransport::builder()
            .max_message_size(484)
            .send_capacity(484)
            .max_buffered_bytes(968),
    )
    .await;
    let running = prepared.spawn();
    let _registration = running
        .inner
        .state
        .core
        .register(registration(1), running.peer_addr(), true)
        .unwrap();
    let mut frames = Vec::new();
    for _ in 0..20 {
        frames.extend(build_response_with_id(1));
    }
    peer.write_all(&frames).await.unwrap();
    timeout(Duration::from_secs(1), running.control().wait_closed())
        .await
        .unwrap();
    assert!(matches!(running.control().status(), TcpStatus::Failed(_)));
    assert!(running.join().await.is_err());
}

#[test]
fn supplied_stream_prepares_outside_runtime_and_runs_on_another_runtime() {
    let origin = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let (prepared, peer) = origin.block_on(pair(TcpTransport::builder()));
    let stream = prepared.runner.stream;
    let prepared =
        futures::executor::block_on(TcpTransport::builder().from_stream(stream).prepare()).unwrap();
    let execution = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let running = prepared.spawn_on(execution.handle());
    execution.block_on(async {
        let mut peer = peer;
        let send = running.send(bytes::Bytes::from_static(b"hello"));
        let receive = async {
            let mut bytes = [0; 5];
            peer.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"hello");
        };
        let (sent, ()) = tokio::join!(send, receive);
        sent.unwrap();
        running.shutdown().await.unwrap();
    });
}

#[tokio::test]
async fn accepted_decoded_values_outlive_transport_buffer_accounting() {
    let (prepared, mut peer) = pair(
        TcpTransport::builder()
            .max_message_size(484)
            .send_capacity(484)
            .max_buffered_bytes(968),
    )
    .await;
    let running = prepared.spawn();
    let client = crate::ClientBuilder::new(crate::Auth::v2c("public"))
        .build_with_transport(running.transport())
        .unwrap();
    let server = tokio::spawn(async move {
        let address = peer.peer_addr().unwrap();
        for _ in 0..20 {
            let frame = read_ber_message(&mut peer, address, 484).await.unwrap();
            let decoded =
                crate::message::CommunityMessage::decode(frame, crate::DecodeConfig::DEFAULT)
                    .unwrap();
            let request = decoded.value.pdu().standard().unwrap();
            let values = request
                .varbinds
                .iter()
                .map(|vb| {
                    crate::VarBind::new(
                        vb.oid.clone(),
                        crate::Value::OctetString(Bytes::from(vec![7; 100])),
                    )
                })
                .collect();
            let response = crate::message::CommunityMessage::v2c(
                "public",
                crate::Pdu::response(request.request_id, 0, 0, values),
            )
            .unwrap()
            .encode()
            .unwrap();
            peer.write_all(&response).await.unwrap();
        }
    });
    let mut retained = Vec::new();
    for _ in 0..20 {
        retained.push(client.get(&crate::oid!(1, 3, 6, 1)).await.unwrap());
    }
    assert!(
        retained
            .iter()
            .all(|response| response.varbinds[0].value.as_bytes() == Some(&[7; 100]))
    );
    server.await.unwrap();
    assert_eq!(running.inner.state.budget.inbound.available_permits(), 484);
    running.join().await.unwrap();
}

#[tokio::test]
async fn receive_permit_is_held_during_validation_and_released_on_acceptance() {
    let (prepared, mut peer) = pair(
        TcpTransport::builder()
            .max_message_size(484)
            .send_capacity(484)
            .max_buffered_bytes(968),
    )
    .await;
    let running = prepared.spawn();
    let budget = running.inner.state.budget.inbound.clone();
    let server = tokio::spawn(async move {
        let address = peer.peer_addr().unwrap();
        read_ber_message(&mut peer, address, 484).await.unwrap();
        peer.write_all(&build_response_with_id(1)).await.unwrap();
    });
    let bytes = running
        .request_with(
            (build_request_with_id(1)).into(),
            registration(1),
            |packet| {
                let (data, _) = packet.into_parts();
                assert!(budget.available_permits() <= 484 - data.len());
                Ok(Candidate::Accept(data))
            },
        )
        .await
        .unwrap();
    server.await.unwrap();
    assert_eq!(budget.available_permits(), 484);
    assert!(!bytes.is_empty());
    running.join().await.unwrap();
}

#[tokio::test]
async fn framing_failure_wakes_exchange_with_structured_packet_error() {
    let (prepared, mut peer) = pair(TcpTransport::builder()).await;
    let running = prepared.spawn();
    let handle = running.transport();
    let pending = tokio::spawn(async move {
        handle
            .request(&build_request_with_id(1), registration(1))
            .await
    });
    let address = peer.peer_addr().unwrap();
    read_ber_message(&mut peer, address, 484).await.unwrap();
    peer.write_all(&[0xbf]).await.unwrap();
    let error = pending.await.unwrap().unwrap_err();
    assert!(matches!(error.exchange_source(), Error::Decode(error)
        if error.offset == 0 && error.peer == Some(running.peer_addr())
        && error.kind == crate::DecodeErrorKind::UnsupportedMultiOctetTag { first_octet: 0xbf }));
    assert!(running.join().await.is_err());
}

#[tokio::test]
async fn zero_deadline_and_invalid_duration_do_not_send_or_close_session() {
    let (prepared, mut peer) = pair(TcpTransport::builder()).await;
    let running = prepared.spawn();
    assert_eq!(
        running
            .send_with_timeout(bytes::Bytes::from_static(b"invalid"), Duration::MAX)
            .await
            .unwrap_err()
            .kind(),
        crate::ErrorKind::Config
    );
    assert_eq!(
        running
            .send_with_timeout(bytes::Bytes::from_static(b"zero"), Duration::ZERO)
            .await
            .unwrap_err()
            .kind(),
        crate::ErrorKind::Timeout
    );
    assert_eq!(
        running
            .request(
                &build_request_with_id(1),
                RequestRegistration::test_unchecked(1, Duration::ZERO)
            )
            .await
            .unwrap_err()
            .kind(),
        crate::ErrorKind::Timeout
    );
    assert!(
        timeout(Duration::from_millis(10), peer.read_u8())
            .await
            .is_err()
    );
    assert!(!running.control().is_shutdown());
    running.shutdown().await.unwrap();
}
