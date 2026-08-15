#![cfg(feature = "agent")]
//! Retry and timeout behavior tests.

mod common;

use async_snmp::{Auth, Client, Error, MAX_RETRIES, Retry, oid};
use common::TestAgent;
use std::io;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn read_ber_frame(stream: &mut TcpStream) -> io::Result<Option<usize>> {
    let mut first = [0u8; 1];
    if stream.read(&mut first).await? == 0 {
        return Ok(None);
    }
    let mut second = [0u8; 1];
    stream.read_exact(&mut second).await?;
    let header = [first[0], second[0]];
    if header[0] != 0x30 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SNMP message is not a BER sequence",
        ));
    }

    let mut header_len = 2;
    let content_len = if header[1] & 0x80 == 0 {
        usize::from(header[1])
    } else {
        let length_octets = usize::from(header[1] & 0x7f);
        if length_octets == 0 || length_octets > std::mem::size_of::<usize>() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid BER length-of-length",
            ));
        }
        let mut encoded_length = vec![0u8; length_octets];
        stream.read_exact(&mut encoded_length).await?;
        header_len += length_octets;
        encoded_length
            .into_iter()
            .try_fold(0usize, |length, octet| {
                length
                    .checked_mul(256)
                    .and_then(|length| length.checked_add(usize::from(octet)))
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "BER length overflow")
                    })
            })?
    };
    let mut content = vec![0u8; content_len];
    stream.read_exact(&mut content).await?;
    Ok(Some(header_len + content_len))
}

#[tokio::test]
async fn ber_frame_reader_rejects_a_partial_header() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let error = read_ber_frame(&mut stream).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    });

    let mut peer = TcpStream::connect(target).await.unwrap();
    peer.write_all(&[0x30]).await.unwrap();
    peer.shutdown().await.unwrap();
    server.await.unwrap();
}

/// Client retries on timeout (UDP).
#[tokio::test]
async fn client_retries_on_timeout() {
    // Use a regular agent but with very short timeout
    let agent = TestAgent::new().await;

    let client = Client::builder(agent.addr().to_string(), Auth::v2c("public"))
        .request_timeout(Duration::from_millis(100))
        .retry(Retry::fixed(2, Duration::ZERO).unwrap())
        .connect()
        .await
        .unwrap();

    // Should succeed even with short timeout since agent responds quickly
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;
    assert!(result.is_ok());
}

/// Client gives up after max retries.
#[tokio::test]
async fn client_fails_after_max_retries() {
    let agent = TestAgent::new().await;
    let addr = agent.addr().to_string();

    // Stop agent so requests will timeout
    agent.stop();
    tokio::time::sleep(Duration::from_millis(10)).await;

    let start = Instant::now();

    let client = Client::builder(addr, Auth::v2c("public"))
        .request_timeout(Duration::from_millis(50))
        .retry(Retry::fixed(2, Duration::ZERO).unwrap()) // 3 total attempts
        .connect()
        .await
        .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;

    assert!(result.is_err());

    // Should have taken ~150ms (3 attempts * 50ms timeout)
    let elapsed = start.elapsed();
    assert!(elapsed >= Duration::from_millis(100));
    assert!(elapsed < Duration::from_millis(500));
}

/// Zero retries means single attempt.
#[tokio::test]
async fn zero_retries_single_attempt() {
    let agent = TestAgent::new().await;
    let addr = agent.addr().to_string();

    agent.stop();
    tokio::time::sleep(Duration::from_millis(10)).await;

    let start = Instant::now();

    let client = Client::builder(addr, Auth::v2c("public"))
        .request_timeout(Duration::from_millis(50))
        .retry(Retry::none()) // No retries
        .connect()
        .await
        .unwrap();

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;

    assert!(result.is_err());

    // Should have taken ~50ms (single attempt)
    let elapsed = start.elapsed();
    assert!(elapsed >= Duration::from_millis(30));
    assert!(elapsed < Duration::from_millis(200));
}

/// TCP transport doesn't retry (`is_reliable` = true).
#[tokio::test]
async fn tcp_no_retry() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut frames = Vec::new();
        while let Some(frame_len) = read_ber_frame(&mut stream).await.unwrap() {
            frames.push(frame_len);
        }
        frames
    });

    let client = Client::builder(target.to_string(), Auth::v2c("public"))
        .request_timeout(Duration::from_millis(50))
        .retry(Retry::fixed(MAX_RETRIES, Duration::ZERO).unwrap())
        .connect_tcp()
        .await
        .unwrap();
    let error = client
        .get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))
        .await
        .unwrap_err();
    assert!(matches!(*error, Error::Timeout { retries: 0, .. }));

    drop(client);
    let frames = server.await.unwrap();
    assert_eq!(frames.len(), 1, "reliable TCP exchange was retransmitted");
    assert!(
        frames[0] > 2,
        "test peer did not receive a complete request"
    );
}
