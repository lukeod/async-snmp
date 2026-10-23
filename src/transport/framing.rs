//! Bounded incremental BER framing shared by connected and accepted sessions.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

use crate::{DecodeError, DecodeErrorKind, Error, Result};

/// Outbound owned storage retains byte admission until write completion.
pub(super) struct BufferedFrame {
    pub(super) bytes: Vec<u8>,
    pub(super) _permit: OwnedSemaphorePermit,
}
impl AsRef<[u8]> for BufferedFrame {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// Inbound budget transfers to the dispatcher/candidate queue and lasts through
/// protocol validation. Successful application values may borrow `bytes` after
/// admission accounting ends; caller-retained results are not transport buffers.
#[derive(Debug)]
pub(super) struct ReceivedFrame {
    pub(super) bytes: Bytes,
    pub(super) permit: OwnedSemaphorePermit,
}

pub(super) struct BerFramer {
    maximum: usize,
    header_timeout: Duration,
    body_timeout: Duration,
    budget: Arc<Semaphore>,
}

impl BerFramer {
    pub(super) fn new(
        maximum: usize,
        header_timeout: Duration,
        body_timeout: Duration,
        budget: Arc<Semaphore>,
    ) -> Self {
        Self {
            maximum,
            header_timeout,
            body_timeout,
            budget,
        }
    }

    /// Read exactly one frame without consuming bytes from the following frame.
    /// Idle connections have no read deadline. Once the first byte arrives the
    /// header must complete within `header_timeout`, and then the body within
    /// `body_timeout`. All declared sizes are checked before body allocation.
    /// A cancelled call ends its owning session; caller cancellation never drops
    /// this future because requests do not own the reader.
    pub(super) async fn next<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
        peer: SocketAddr,
    ) -> Result<Option<ReceivedFrame>> {
        let mut header = [0u8; 6];
        if reader
            .read(&mut header[..1])
            .await
            .map_err(|source| network(peer, source))?
            == 0
        {
            return Ok(None);
        }
        if header[0] & 0x1f == 0x1f {
            return Err(decode(
                peer,
                0,
                DecodeErrorKind::UnsupportedMultiOctetTag {
                    first_octet: header[0],
                },
            ));
        }
        if header[0] != 0x30 {
            return Err(decode(
                peer,
                0,
                DecodeErrorKind::UnexpectedTag {
                    expected: 0x30,
                    actual: header[0],
                },
            ));
        }
        let header_deadline = Instant::now() + self.header_timeout;
        read_until(reader, &mut header[1..2], peer, header_deadline).await?;
        let (header_len, content_len) = if header[1] < 0x80 {
            (2, header[1] as usize)
        } else if header[1] == 0x80 {
            return Err(decode(peer, 1, DecodeErrorKind::IndefiniteLength));
        } else {
            let octets = (header[1] & 0x7f) as usize;
            if octets > 4 {
                return Err(decode(peer, 1, DecodeErrorKind::LengthTooLong { octets }));
            }
            read_until(reader, &mut header[2..2 + octets], peer, header_deadline).await?;
            let content = header[2..2 + octets]
                .iter()
                .try_fold(0usize, |length, &byte| {
                    length
                        .checked_mul(256)
                        .and_then(|v| v.checked_add(byte as usize))
                })
                .ok_or_else(|| decode(peer, 1, DecodeErrorKind::IntegerOverflow))?;
            (2 + octets, content)
        };
        let total = header_len
            .checked_add(content_len)
            .ok_or_else(|| decode(peer, 1, DecodeErrorKind::IntegerOverflow))?;
        if total > self.maximum {
            return Err(decode(
                peer,
                0,
                DecodeErrorKind::MessageTooLarge {
                    size: total,
                    maximum: self.maximum,
                },
            ));
        }
        // Client-capable sessions must not pause their reader behind application
        // or candidate buffering. Budget exhaustion closes this session.
        let permit = self
            .budget
            .clone()
            .try_acquire_many_owned(total as u32)
            .map_err(|_| {
                network(
                    peer,
                    std::io::Error::other("TCP buffered-byte limit exhausted"),
                )
            })?;
        let mut bytes = vec![0; total];
        bytes[..header_len].copy_from_slice(&header[..header_len]);
        let body_deadline = Instant::now() + self.body_timeout;
        read_until(reader, &mut bytes[header_len..], peer, body_deadline).await?;
        Ok(Some(ReceivedFrame {
            bytes: Bytes::from(bytes),
            permit,
        }))
    }
}

async fn read_until<R: AsyncRead + Unpin>(
    reader: &mut R,
    mut remaining: &mut [u8],
    peer: SocketAddr,
    deadline: Instant,
) -> Result<()> {
    while !remaining.is_empty() {
        if Instant::now() >= deadline {
            return Err(progress_timeout(peer));
        }
        let length = tokio::time::timeout_at(deadline, reader.read(remaining))
            .await
            .map_err(|_| progress_timeout(peer))?
            .map_err(|source| network(peer, source))?;
        if length == 0 {
            return Err(network(
                peer,
                std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "partial TCP BER frame"),
            ));
        }
        remaining = &mut remaining[length..];
    }
    Ok(())
}
fn progress_timeout(peer: SocketAddr) -> Box<Error> {
    network(
        peer,
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "TCP BER frame progress deadline expired",
        ),
    )
}
fn network(target: SocketAddr, source: std::io::Error) -> Box<Error> {
    Error::Network { target, source }.boxed()
}
fn decode(peer: SocketAddr, offset: usize, kind: DecodeErrorKind) -> Box<Error> {
    Error::Decode(DecodeError::new(offset, kind).with_peer(peer)).boxed()
}
