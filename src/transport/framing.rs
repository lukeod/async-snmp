//! Bounded incremental BER framing shared by connected and accepted sessions.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

use crate::{DecodeError, DecodeErrorKind, Error, Result};

/// Partition a fixed total during preparation. Input retention must never consume
/// the space needed to send a reply. The service reserves the largest configured
/// TCP send capacity, shared by all writers, rather than one reserve per session.
pub(crate) struct BufferBudget {
    pub(crate) inbound: Arc<Semaphore>,
    pub(crate) outbound: Arc<Semaphore>,
    total: usize,
    capacities: Mutex<(usize, usize)>, // minimum inbound, reserved outbound
}
impl BufferBudget {
    pub(crate) fn new(total: usize) -> Self {
        Self {
            inbound: Arc::new(Semaphore::new(total)),
            outbound: Arc::new(Semaphore::new(0)),
            total,
            capacities: Mutex::new((0, 0)),
        }
    }

    /// Called for every configured listener before execution. Accepted sessions
    /// repeat the same reservation without changing the partition.
    pub(crate) fn reserve(&self, inbound: usize, outbound: usize) -> Result<()> {
        let mut capacities = self.capacities.lock().unwrap();
        let required = (capacities.0.max(inbound), capacities.1.max(outbound));
        if required
            .0
            .checked_add(required.1)
            .is_none_or(|sum| sum > self.total)
        {
            return Err(Error::Config(
                "buffer budget must accommodate inbound capacity and reserved TCP output".into(),
            )
            .boxed());
        }
        let extra = required.1 - capacities.1;
        if extra != 0 {
            self.inbound
                .clone()
                .try_acquire_many_owned(extra as u32)
                .map_err(|_| {
                    Error::Config("buffer reservation must precede execution".into()).boxed()
                })?
                .forget();
            self.outbound.add_permits(extra);
        }
        *capacities = required;
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct BufferPermits {
    pub(crate) _local: OwnedSemaphorePermit,
    pub(crate) _shared: Option<OwnedSemaphorePermit>,
}
impl BufferPermits {
    /// Best-effort retention never waits for a second input-sized reservation.
    pub(crate) fn try_extend(&mut self, bytes: usize) -> bool {
        let Ok(local) = self
            ._local
            .semaphore()
            .clone()
            .try_acquire_many_owned(bytes as u32)
        else {
            return false;
        };
        let shared = if let Some(current) = &self._shared {
            let Ok(extra) = current
                .semaphore()
                .clone()
                .try_acquire_many_owned(bytes as u32)
            else {
                return false;
            };
            Some(extra)
        } else {
            None
        };
        self._local.merge(local);
        if let Some(extra) = shared {
            self._shared.as_mut().unwrap().merge(extra);
        }
        true
    }
}
impl From<OwnedSemaphorePermit> for BufferPermits {
    fn from(permit: OwnedSemaphorePermit) -> Self {
        Self {
            _local: permit,
            _shared: None,
        }
    }
}

/// Inbound budget transfers to the dispatcher/candidate queue and lasts through
/// protocol validation. Successful application values may borrow `bytes` after
/// admission accounting ends; caller-retained results are not transport buffers.
#[derive(Debug)]
pub(super) struct ReceivedFrame {
    pub(super) bytes: Bytes,
    pub(super) permit: BufferPermits,
}

pub(super) struct BerFramer {
    maximum: usize,
    header_timeout: Duration,
    body_timeout: Duration,
    budget: Arc<Semaphore>,
    shared: Option<(Arc<Semaphore>, Duration)>,
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
            shared: None,
        }
    }

    pub(super) fn with_shared_budget(mut self, budget: Arc<Semaphore>, overload: Duration) -> Self {
        self.shared = Some((budget, overload));
        self
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
        // Inbound-only sessions may pause at a validated frame boundary. This
        // bounded admission wait is separate from the body progress deadline.
        let admission_deadline = self
            .shared
            .as_ref()
            .map(|(_, overload)| Instant::now() + *overload);
        let permit = if let Some(deadline) = admission_deadline {
            tokio::time::timeout_at(
                deadline,
                self.budget.clone().acquire_many_owned(total as u32),
            )
            .await
            .map_err(|_| {
                network(
                    peer,
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "TCP session buffer overload",
                    ),
                )
            })?
            .map_err(|_| network(peer, std::io::Error::other("TCP session buffer closed")))?
        } else {
            self.budget
                .clone()
                .try_acquire_many_owned(total as u32)
                .map_err(|_| {
                    network(
                        peer,
                        std::io::Error::other("TCP buffered-byte limit exhausted"),
                    )
                })?
        };
        let shared = if let Some((budget, _)) = &self.shared {
            Some(
                tokio::time::timeout_at(
                    admission_deadline.expect("shared budget deadline"),
                    budget.clone().acquire_many_owned(total as u32),
                )
                .await
                .map_err(|_| {
                    network(
                        peer,
                        std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "TCP aggregate buffer overload",
                        ),
                    )
                })?
                .map_err(|_| network(peer, std::io::Error::other("TCP aggregate buffer closed")))?,
            )
        } else {
            None
        };
        let permit = BufferPermits {
            _local: permit,
            _shared: shared,
        };
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test(start_paused = true)]
    async fn inbound_budget_pause_does_not_consume_body_progress_deadline() {
        let local = Arc::new(Semaphore::new(4));
        let busy = local.clone().acquire_many_owned(4).await.unwrap();
        let shared = Arc::new(Semaphore::new(4));
        let (mut reader, mut writer) = tokio::io::duplex(16);
        let task = tokio::spawn(async move {
            BerFramer::new(4, Duration::from_secs(1), Duration::from_secs(1), local)
                .with_shared_budget(shared, Duration::from_secs(5))
                .next(&mut reader, "127.0.0.1:161".parse().unwrap())
                .await
        });
        writer.write_all(&[0x30, 2, 5, 0]).await.unwrap();
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(!task.is_finished());
        drop(busy);
        assert_eq!(
            task.await.unwrap().unwrap().unwrap().bytes.as_ref(),
            &[0x30, 2, 5, 0]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn session_and_aggregate_admission_share_one_overload_deadline() {
        let local = Arc::new(Semaphore::new(4));
        let local_busy = local.clone().acquire_many_owned(4).await.unwrap();
        let shared = Arc::new(Semaphore::new(4));
        let _shared_busy = shared.clone().acquire_many_owned(4).await.unwrap();
        let (mut reader, mut writer) = tokio::io::duplex(16);
        let task = tokio::spawn(async move {
            BerFramer::new(4, Duration::from_secs(1), Duration::from_secs(1), local)
                .with_shared_budget(shared, Duration::from_secs(5))
                .next(&mut reader, "127.0.0.1:161".parse().unwrap())
                .await
        });
        writer.write_all(&[0x30, 2, 5, 0]).await.unwrap();
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(3)).await;
        drop(local_busy);
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(2)).await;
        tokio::task::yield_now().await;
        assert!(task.is_finished());
        assert!(task.await.unwrap().is_err());
    }
}
