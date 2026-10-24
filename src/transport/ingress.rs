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
#[cfg(test)]
type AdmissionHook = Arc<dyn Fn(&ApplicationIngress, bool) + Send + Sync>;

#[derive(Clone)]
pub(crate) struct ApplicationIngress {
    #[cfg(test)]
    pub(crate) admission_hook: Option<AdmissionHook>,
    pub(crate) sender: mpsc::Sender<InboundWork>,
    pub(crate) disabled: tokio_util::sync::CancellationToken,
    pub(crate) capacity: Arc<Semaphore>,
    pub(crate) budget: Arc<super::framing::BufferBudget>,
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
        !self.disabled.is_cancelled() && !self.sender.is_closed()
    }
    pub(crate) fn deliver_udp(&self, message: ReceivedMessage) {
        if !self.is_enabled() {
            message.observe(super::MessageDisposition::Disabled);
            return;
        }
        let Ok(admission) = self.capacity.clone().try_acquire_owned() else {
            message.observe(super::MessageDisposition::Overloaded);
            self.drops
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return;
        };
        let Ok(buffer) = self
            .budget
            .inbound
            .clone()
            .try_acquire_many_owned(message.bytes.len() as u32)
        else {
            message.observe(super::MessageDisposition::Overloaded);
            self.drops
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return;
        };
        let observation = message.reply.observation().clone();
        let info = message.info;
        let result = self.sender.try_send(InboundWork {
            message,
            _admission: admission,
            _session: None,
            _buffers: Some(buffer.into()),
        });
        observation.disposition(
            info,
            match result {
                Ok(()) => super::MessageDisposition::ApplicationQueued,
                Err(mpsc::error::TrySendError::Closed(_)) => super::MessageDisposition::Disabled,
                Err(_) => super::MessageDisposition::Overloaded,
            },
        );
    }
    pub(crate) async fn deliver_tcp(
        &self,
        message: ReceivedMessage,
        buffers: BufferPermits,
        fail_fast: bool,
    ) -> Result<()> {
        let observation = message.reply.observation().clone();
        let info = message.info;
        let result = self.deliver_tcp_inner(message, buffers, fail_fast).await;
        if result.is_err() {
            // Decide overload only while the role is still enabled. Closing a
            // role can race with semaphore/channel admission on a mixed session.
            // That closure must not terminate the other roles or exchanges.
            if !self.is_enabled() {
                observation.disposition(info, super::MessageDisposition::Disabled);
                return Ok(());
            }
            observation.disposition(info, super::MessageDisposition::Overloaded);
        }
        result
    }
    async fn deliver_tcp_inner(
        &self,
        message: ReceivedMessage,
        buffers: BufferPermits,
        fail_fast: bool,
    ) -> Result<()> {
        if !self.is_enabled() {
            message.observe(super::MessageDisposition::Disabled);
            return Ok(());
        }
        #[cfg(test)]
        if let Some(hook) = &self.admission_hook {
            hook(self, false);
        }
        let target = message.info.peer_addr();
        let info = message.info;
        let observation = message.reply.observation().clone();
        if fail_fast {
            let overload = || {
                Error::Network {
                    target,
                    source: std::io::Error::other(format!(
                        "TCP session {:?} application admission overload",
                        message.info.session_id()
                    )),
                }
                .boxed()
            };
            let session = self
                .session
                .as_ref()
                .map(|limit| limit.clone().try_acquire_owned())
                .transpose()
                .map_err(|_| overload())?;
            let admission = self
                .capacity
                .clone()
                .try_acquire_owned()
                .map_err(|_| overload())?;
            if !self.is_enabled() {
                observation.disposition(info, super::MessageDisposition::Disabled);
                return Ok(());
            }
            #[cfg(test)]
            if let Some(hook) = &self.admission_hook {
                hook(self, true);
            }
            let work = InboundWork {
                message,
                _admission: admission,
                _session: session,
                _buffers: Some(buffers),
            };
            return self
                .sender
                .try_send(work)
                .map(|()| {
                    observation.disposition(info, super::MessageDisposition::ApplicationQueued)
                })
                .map_err(|error| {
                    Error::Network {
                        target,
                        source: std::io::Error::other(format!(
                            "TCP application admission overload: {error}"
                        )),
                    }
                    .boxed()
                });
        }
        tokio::select! { biased;
        () = self.disabled.cancelled() => { observation.disposition(info, super::MessageDisposition::Disabled); Ok(()) },
        result = tokio::time::timeout(self.overload_timeout, async {
            let session = if let Some(limit) = &self.session {
                Some(tokio::select! { biased;
                    () = self.sender.closed() => { observation.disposition(info, super::MessageDisposition::Disabled); return Ok(()); },
                    permit = limit.clone().acquire_owned() => permit.map_err(|_| Error::Closed { target }.boxed())?,
                })
            } else { None };
            let admission = tokio::select! { biased;
                () = self.sender.closed() => { observation.disposition(info, super::MessageDisposition::Disabled); return Ok(()); },
                permit = self.capacity.clone().acquire_owned() => permit.map_err(|_| Error::Closed { target }.boxed())?,
            };
            let result = self.sender.send(InboundWork { message, _admission: admission, _session: session, _buffers: Some(buffers) }).await;
            observation.disposition(info, if result.is_ok() { super::MessageDisposition::ApplicationQueued } else { super::MessageDisposition::Disabled }); Ok(())
        }) => result.map_err(|_| Error::Network { target, source: std::io::Error::new(std::io::ErrorKind::TimedOut, "TCP application admission overload") }.boxed())?,
        }
    }
}
