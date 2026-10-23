//! Notification admission, delivery and supervised I/O.

use super::*;
use crate::transport::udp_error::{
    UdpRecvErrorBackoff, UdpRecvErrorClass, classify_udp_recv_error,
};
use tokio::sync::mpsc::{OwnedPermit, Sender};
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::{CancellationToken, DropGuard};

struct DeliveryState {
    open: bool,
    sender: Option<Sender<ReceivedNotification>>,
}

pub(super) struct Delivery {
    state: Mutex<DeliveryState>,
    overloaded: AtomicU64,
}
impl Delivery {
    pub(super) fn new(sender: Sender<ReceivedNotification>) -> Self {
        Self {
            state: Mutex::new(DeliveryState {
                open: true,
                sender: Some(sender),
            }),
            overloaded: AtomicU64::new(0),
        }
    }
    fn close_admission(&self) {
        self.state.lock().unwrap().open = false;
    }
    fn finish(&self) {
        let mut state = self.state.lock().unwrap();
        state.open = false;
        state.sender.take();
    }
    fn is_open(&self) -> bool {
        self.state.lock().unwrap().open
    }
}

#[derive(Default)]
pub(super) struct NotificationAdmission {
    failure: Option<NotificationDisposition>,
    permit: Option<OwnedPermit<ReceivedNotification>>,
}
impl NotificationAdmission {
    pub(super) fn reserve(&mut self, delivery: &Delivery) -> bool {
        let state = delivery.state.lock().unwrap();
        if !state.open {
            self.failure = Some(NotificationDisposition::Disabled);
            return false;
        }
        let Some(sender) = &state.sender else {
            self.failure = Some(NotificationDisposition::Disabled);
            return false;
        };
        match sender.clone().try_reserve_owned() {
            Ok(permit) => {
                self.permit = Some(permit);
                true
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                delivery.overloaded.fetch_add(1, Ordering::Relaxed);
                self.failure = Some(NotificationDisposition::Overloaded);
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.failure = Some(NotificationDisposition::Disabled);
                false
            }
        }
    }
    fn publish(mut self, notification: ReceivedNotification) {
        self.permit
            .take()
            .expect("accepted notification reserves delivery before acknowledgement")
            .send(notification);
    }
}

/// Health of the notification role's local authoritative engine. Changes are
/// coalesced; a later successful authoritative acquisition restores health.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum NotificationHealth {
    /// No unresolved authoritative persistence failure.
    Healthy,
    /// Traffic requiring unavailable local authoritative state is withheld.
    AuthoritativePersistenceDegraded {
        /// Failed acquisitions during the current outage.
        consecutive_failures: u64,
        /// Durable transition whose publication failed.
        operation: crate::v3::AuthoritativeEnginePersistenceOperation,
        /// Last durable boots value.
        previous_engine_boots: Option<u32>,
        /// Boots value passed to the persistence callback.
        attempted_engine_boots: u32,
    },
}

/// Network runner state. Queue EOF does not distinguish normal termination
/// from failure; inspect this state or join the runner.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum NotificationStatus {
    /// Prepared, but not yet driven.
    Prepared,
    /// Network receive and protocol processing are active.
    Running,
    /// The runner completed normally.
    Stopped,
    /// The runner or its future was dropped before completing, including task abort.
    Interrupted,
    /// A fatal receive or processing-task failure ended execution.
    Failed(Arc<str>),
}

pub(super) struct ServiceState {
    pub(super) shutdown: CancellationToken,
    complete: CancellationToken,
    status: Mutex<NotificationStatus>,
}
impl ServiceState {
    pub(super) fn new() -> Self {
        Self {
            shutdown: CancellationToken::new(),
            complete: CancellationToken::new(),
            status: Mutex::new(NotificationStatus::Prepared),
        }
    }
}

pub(super) struct NotificationLease {
    _guard: DropGuard,
}
impl NotificationLease {
    pub(super) fn new(shutdown: CancellationToken) -> Self {
        Self {
            _guard: shutdown.drop_guard(),
        }
    }
}

pub(super) struct RunnerCleanup {
    pub(super) delivery: Arc<Delivery>,
    pub(super) state: Arc<ServiceState>,
}
impl Drop for RunnerCleanup {
    fn drop(&mut self) {
        self.delivery.finish();
        self.state.shutdown.cancel();
        let mut status = self.state.status.lock().unwrap();
        if !matches!(
            *status,
            NotificationStatus::Failed(_) | NotificationStatus::Stopped
        ) {
            *status = NotificationStatus::Interrupted;
        }
        self.state.complete.cancel();
    }
}

/// Cloneable service control. Keeping it alive retains network execution, but
/// never retains the consumer or enables notification admission after its drop.
#[derive(Clone)]
pub struct NotificationControl {
    inner: Arc<ReceiverInner>,
    state: Arc<ServiceState>,
    _lease: Arc<NotificationLease>,
}
impl NotificationControl {
    /// Request service shutdown without waiting. Admitted work is drained while
    /// the runner is driven; queued events need not be consumed for it to finish.
    pub fn request_shutdown(&self) {
        self.inner.delivery.close_admission();
        self.state.shutdown.cancel();
    }
    /// Wait for termination. An unstarted runner must be driven or dropped.
    pub async fn wait_closed(&self) {
        self.state.complete.cancelled().await;
    }
    /// Request shutdown and wait under the same runner-start precondition.
    pub async fn shutdown(&self) {
        self.request_shutdown();
        self.wait_closed().await;
    }
    /// Whether shutdown has been requested or execution ended.
    pub fn is_shutdown(&self) -> bool {
        self.state.shutdown.is_cancelled()
    }
    /// Current network execution status.
    pub fn status(&self) -> NotificationStatus {
        self.state.status.lock().unwrap().clone()
    }
    /// Current authoritative persistence health.
    pub fn health(&self) -> NotificationHealth {
        *self.inner.health.borrow()
    }
    /// Subscribe to bounded, coalesced persistence-health changes.
    pub fn subscribe_health(&self) -> watch::Receiver<NotificationHealth> {
        self.inner.health.subscribe()
    }
    /// Inputs dropped because delivery or protocol work was full. Disabled-role
    /// drops are not overload and do not increment this counter.
    pub fn overload_drops(&self) -> u64 {
        self.inner.delivery.overloaded.load(Ordering::Relaxed)
    }
}

impl NotificationReceiver {
    /// Receive one accepted event. Cancellation does not consume an event or
    /// close admission. The runner receives and acknowledges independently of
    /// this method. `None` means the queue and all admitted producers finished;
    /// inspect control status or the runner result to distinguish failure.
    pub async fn recv(&mut self) -> Option<ReceivedNotification> {
        self.events.recv().await
    }
    /// Stop new notification admission and drain queued/admitted events. An
    /// already reserved Inform still completes its bounded acknowledgement and
    /// publishes its outcome. This disables only the notification role.
    pub fn close(&mut self) {
        self.inner.delivery.close_admission();
        self.events.close();
    }
    /// Acquire service lifecycle and health observation without retaining the consumer.
    pub fn control(&self) -> NotificationControl {
        NotificationControl {
            inner: self.inner.clone(),
            state: self.state.clone(),
            _lease: self.lease.clone(),
        }
    }
    #[cfg(test)]
    fn processor(&self) -> NotificationProcessor {
        NotificationProcessor {
            inner: self.inner.clone(),
        }
    }
}
impl Drop for NotificationReceiver {
    fn drop(&mut self) {
        self.close();
    }
}

/// Prepared receiver and single-use runner. Preparation creates no tasks.
#[must_use = "drive or drop the notification runner"]
pub struct PreparedNotificationReceiver {
    pub(super) receiver: NotificationReceiver,
    pub(super) runner: NotificationRunner,
}
impl PreparedNotificationReceiver {
    /// Separate the single consumer from network execution.
    pub fn into_parts(self) -> (NotificationReceiver, NotificationRunner) {
        (self.receiver, self.runner)
    }
    /// Spawn on the current runtime and retain the task result.
    pub fn spawn(self) -> RunningNotificationReceiver {
        self.spawn_on(&tokio::runtime::Handle::current())
    }
    /// Spawn without migrating the socket's original Tokio registration.
    pub fn spawn_on(self, runtime: &tokio::runtime::Handle) -> RunningNotificationReceiver {
        let (receiver, runner) = self.into_parts();
        RunningNotificationReceiver {
            receiver,
            task: Some(runtime.spawn(runner.run())),
        }
    }
}

/// Owns the single consumer and spawned runner. Drop requests service shutdown;
/// use a prepared pair when consumer and runner need separate owners.
#[must_use = "dropping the running owner requests shutdown"]
pub struct RunningNotificationReceiver {
    receiver: NotificationReceiver,
    task: Option<JoinHandle<Result<()>>>,
}
impl std::ops::Deref for RunningNotificationReceiver {
    type Target = NotificationReceiver;
    fn deref(&self) -> &Self::Target {
        &self.receiver
    }
}
impl std::ops::DerefMut for RunningNotificationReceiver {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.receiver
    }
}
impl Drop for RunningNotificationReceiver {
    fn drop(&mut self) {
        if self.task.is_some() {
            self.receiver.control().request_shutdown();
        }
    }
}
impl RunningNotificationReceiver {
    /// Access task status or abort execution.
    pub fn task(&self) -> &JoinHandle<Result<()>> {
        self.task.as_ref().expect("running task retained")
    }
    /// Join while retaining the consumer for queued events. This does not request shutdown.
    pub async fn join(&mut self) -> Result<()> {
        let Some(task) = self.task.as_mut() else {
            return match self.control().status() {
                NotificationStatus::Failed(message) => Err(Error::Network {
                    target: self.local_addr(),
                    source: std::io::Error::other(message.to_string()),
                }
                .boxed()),
                NotificationStatus::Interrupted => Err(Error::Network {
                    target: self.local_addr(),
                    source: std::io::Error::other("notification runner interrupted"),
                }
                .boxed()),
                _ => Ok(()),
            };
        };
        let result = task.await;
        self.task.take();
        result.map_err(|source| {
            *self.receiver.state.status.lock().unwrap() =
                NotificationStatus::Failed(Arc::from(source.to_string()));
            Error::Network {
                target: self.local_addr(),
                source: std::io::Error::other(source),
            }
            .boxed()
        })?
    }
    /// Request shutdown, drain admitted processing and join; events remain available.
    pub async fn shutdown(&mut self) -> Result<()> {
        self.control().request_shutdown();
        self.join().await
    }
}

/// Owned UDP execution. A single reader dispatches bounded protocol tasks;
/// delivery capacity is reserved before application acceptance and responses.
#[must_use = "drive or drop the notification runner"]
pub struct NotificationRunner {
    socket: Arc<UdpSocket>,
    responder: Arc<UdpResponder>,
    endpoint_id: crate::EndpointId,
    local_addr: SocketAddr,
    processor: NotificationProcessor,
    max_processing: usize,
    cleanup: RunnerCleanup,
}
impl NotificationRunner {
    pub(super) fn new(
        socket: Arc<UdpSocket>,
        responder: Arc<UdpResponder>,
        endpoint_id: crate::EndpointId,
        local_addr: SocketAddr,
        processor: NotificationProcessor,
        max_processing: usize,
        cleanup: RunnerCleanup,
    ) -> Self {
        Self {
            socket,
            responder,
            endpoint_id,
            local_addr,
            processor,
            max_processing,
            cleanup,
        }
    }
    async fn receive(&self, buffer: &mut [u8]) -> std::io::Result<ReceivedDatagram> {
        #[cfg(test)]
        loop {
            if let Some(error) = self
                .processor
                .inner
                .receive_errors
                .lock()
                .unwrap()
                .pop_front()
            {
                return Err(error);
            }
            tokio::select! {
                result = self.responder.recv(&self.socket, buffer) => return result,
                () = self.processor.inner.receive_error_ready.notified() => {},
            }
        }
        #[cfg(not(test))]
        self.responder.recv(&self.socket, buffer).await
    }
    /// Drive receive/protocol work until shutdown or fatal failure. The socket's
    /// registration runtime must remain alive and driven. Graceful completion
    /// drains admitted work into its reserved slots without waiting for consumers.
    pub async fn run(self) -> Result<()> {
        *self.cleanup.state.status.lock().unwrap() = NotificationStatus::Running;
        let mut buffer = vec![0; crate::UDP_RECEIVE_BUFFER_SIZE];
        let mut tasks = JoinSet::new();
        let mut backoff = UdpRecvErrorBackoff::default();
        let mut result = loop {
            tokio::select! {
                biased;
                () = self.cleanup.state.shutdown.cancelled() => break Ok(()),
                joined = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(Err(error)) = joined {
                        break Err(Error::Network { target: self.local_addr, source: std::io::Error::other(error) }.boxed());
                    }
                }
                received = self.receive(&mut buffer) => {
                    match received {
                        Ok(received) => {
                            backoff.reset();
                            let received_at = tokio::time::Instant::now();
                            if !self.processor.is_enabled() { continue; }
                            if tasks.len() >= self.max_processing {
                                self.processor.inner.delivery.overloaded.fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                            let message = crate::transport::ReceivedMessage::udp(Bytes::copy_from_slice(&buffer[..received.len]),
                                self.endpoint_id, self.socket.clone(), self.responder.clone(), received, received_at, crate::transport::EndpointLimits::UDP);
                            let processor = self.processor.clone();
                            tasks.spawn(async move { processor.process(message).await; });
                        }
                        Err(error) => match classify_udp_recv_error(&error) {
                            UdpRecvErrorClass::DatagramLocal => { backoff.reset(); },
                            UdpRecvErrorClass::Transient => {
                                let delay = backoff.advance();
                                tokio::select! {
                                    biased;
                                    () = self.cleanup.state.shutdown.cancelled() => break Ok(()),
                                    () = tokio::time::sleep(delay) => {},
                                }
                            }
                            UdpRecvErrorClass::Fatal => break Err(Error::Network { target: self.local_addr, source: error }.boxed()),
                        }
                    }
                }
            }
        };
        self.processor.inner.delivery.close_admission();
        while let Some(joined) = tasks.join_next().await {
            if let Err(error) = joined {
                result = Err(Error::Network {
                    target: self.local_addr,
                    source: std::io::Error::other(error),
                }
                .boxed());
            }
        }
        *self.cleanup.state.status.lock().unwrap() = match &result {
            Err(error) => NotificationStatus::Failed(Arc::from(error.to_string())),
            Ok(()) => NotificationStatus::Stopped,
        };
        result
    }
}

/// The dispatcher distinguishes a disabled role from admission overload; a
/// shared TCP session closes for overload but keeps other roles after closure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NotificationDisposition {
    Delivered,
    Rejected,
    Disabled,
    Overloaded,
}

impl NotificationProcessor {
    pub(crate) fn is_enabled(&self) -> bool {
        self.inner.delivery.is_open()
    }

    pub(crate) async fn process(
        &self,
        message: crate::transport::ReceivedMessage,
    ) -> NotificationDisposition {
        if !self.is_enabled() {
            return NotificationDisposition::Disabled;
        }
        let source = message.info.peer_addr();
        let mut admission = NotificationAdmission::default();
        match self.parse_and_respond(message, &mut admission).await {
            Ok(Some(notification)) => {
                admission.publish(notification);
                NotificationDisposition::Delivered
            }
            Ok(None) => admission
                .failure
                .unwrap_or(NotificationDisposition::Rejected),
            Err(error) => {
                tracing::debug!(target: "async_snmp::notification", %source, %error, "notification rejected before admission");
                NotificationDisposition::Rejected
            }
        }
    }
}

#[cfg(test)]
impl NotificationReceiver {
    pub(super) async fn handle_v1(
        &self,
        data: Bytes,
        source: SocketAddr,
    ) -> Result<Option<ReceivedNotification>> {
        self.processor().handle_v1(data, source).await
    }
    pub(super) async fn handle_v2c(
        &self,
        data: Bytes,
        source: SocketAddr,
    ) -> Result<Option<ReceivedNotification>> {
        self.processor().handle_v2c(data, source).await
    }
    pub(super) async fn handle_v3(
        &self,
        data: Bytes,
        source: SocketAddr,
    ) -> Result<Option<ReceivedNotification>> {
        self.processor().handle_v3(data, source).await
    }
}
