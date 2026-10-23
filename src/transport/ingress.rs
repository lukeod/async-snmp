//! Bounded application admission shared by concrete endpoint readers.
use super::{ReceivedMessage, framing::BufferPermits};
use crate::{Error, Result};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

pub(crate) struct InboundWork {
    #[cfg_attr(not(feature = "agent"), allow(dead_code))]
    pub(crate) message: ReceivedMessage,
    pub(crate) _admission: OwnedSemaphorePermit,
    pub(crate) _session: Option<OwnedSemaphorePermit>,
    pub(crate) _buffers: Option<BufferPermits>,
}
#[derive(Clone)]
pub(crate) struct ApplicationIngress {
    pub(crate) sender: mpsc::Sender<InboundWork>,
    pub(crate) enabled: Arc<std::sync::atomic::AtomicBool>,
    pub(crate) capacity: Arc<Semaphore>,
    pub(crate) budget: Arc<Semaphore>,
    pub(crate) overload_timeout: Duration,
    pub(crate) drops: Arc<std::sync::atomic::AtomicU64>,
    pub(crate) session: Option<Arc<Semaphore>>,
}
impl std::fmt::Debug for ApplicationIngress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApplicationIngress").finish_non_exhaustive()
    }
}
impl ApplicationIngress {
    pub(crate) fn is_enabled(&self) -> bool {
        self.enabled.load(std::sync::atomic::Ordering::Acquire) && !self.sender.is_closed()
    }
    pub(crate) fn deliver_udp(&self, message: ReceivedMessage) {
        if !self.is_enabled() {
            return;
        }
        let Ok(admission) = self.capacity.clone().try_acquire_owned() else {
            self.drops
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return;
        };
        let Ok(buffer) = self
            .budget
            .clone()
            .try_acquire_many_owned(message.bytes.len() as u32)
        else {
            self.drops
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return;
        };
        let _ = self.sender.try_send(InboundWork {
            message,
            _admission: admission,
            _session: None,
            _buffers: Some(buffer.into()),
        });
    }
    pub(crate) async fn deliver_tcp(
        &self,
        message: ReceivedMessage,
        buffers: BufferPermits,
    ) -> Result<()> {
        let target = message.info.peer_addr();
        tokio::time::timeout(self.overload_timeout, async {
            let session = if let Some(limit) = &self.session {
                Some(tokio::select! { biased;
                    () = self.sender.closed() => return Ok(()),
                    permit = limit.clone().acquire_owned() => permit.map_err(|_| Error::Closed { target }.boxed())?,
                })
            } else { None };
            let admission = tokio::select! { biased;
                () = self.sender.closed() => return Ok(()),
                permit = self.capacity.clone().acquire_owned() => permit.map_err(|_| Error::Closed { target }.boxed())?,
            };
            let _ = self.sender.send(InboundWork { message, _admission: admission, _session: session, _buffers: Some(buffers) }).await; Ok(())
        }).await.map_err(|_| Error::Network { target, source: std::io::Error::new(std::io::ErrorKind::TimedOut, "TCP application admission overload") }.boxed())?
    }
}
