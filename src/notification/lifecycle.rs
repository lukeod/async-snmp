//! Notification admission, delivery and supervised I/O.

use super::*;
use tokio::sync::mpsc::{OwnedPermit, Sender};
use tokio::task::JoinHandle;
use tokio_util::sync::{CancellationToken, DropGuard};

struct DeliveryState {
    open: bool,
    sender: Option<Sender<ReceivedNotification>>,
}

pub(super) struct Delivery {
    state: Mutex<DeliveryState>,
    overloaded: AtomicU64,
    closed: CancellationToken,
}
impl Delivery {
    pub(super) fn new(sender: Sender<ReceivedNotification>) -> Self {
        Self {
            state: Mutex::new(DeliveryState {
                open: true,
                sender: Some(sender),
            }),
            overloaded: AtomicU64::new(0),
            closed: CancellationToken::new(),
        }
    }
    fn close_admission(&self) {
        self.state.lock().unwrap().open = false;
        self.closed.cancel();
    }
    fn finish(&self) {
        let mut state = self.state.lock().unwrap();
        state.open = false;
        state.sender.take();
        self.closed.cancel();
    }
    fn is_open(&self) -> bool {
        self.state.lock().unwrap().open
    }
}

#[derive(Default)]
pub(crate) struct NotificationAdmission {
    failure: Option<NotificationDisposition>,
    permit: Option<OwnedPermit<ReceivedNotification>>,
}
impl NotificationAdmission {
    pub(super) fn reserve(&mut self, delivery: &Delivery) -> bool {
        if self.permit.is_some() {
            return true;
        }
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
    attached: std::sync::atomic::AtomicBool,
}
impl ServiceState {
    pub(super) fn new() -> Self {
        Self {
            shutdown: CancellationToken::new(),
            complete: CancellationToken::new(),
            status: Mutex::new(NotificationStatus::Prepared),
            attached: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

pub(crate) struct NotificationLease {
    _guard: DropGuard,
    _service_lease: Option<Arc<dyn Send + Sync>>,
}
impl NotificationLease {
    pub(super) fn new(shutdown: CancellationToken) -> Self {
        Self {
            _guard: shutdown.drop_guard(),
            _service_lease: None,
        }
    }
}

pub(crate) struct RunnerCleanup {
    pub(super) delivery: Arc<Delivery>,
    pub(super) state: Arc<ServiceState>,
}
impl RunnerCleanup {
    pub(crate) fn stop_admission(&self) {
        self.delivery.close_admission();
    }
    pub(crate) fn started(&self) {
        if !self.state.shutdown.is_cancelled() {
            *self.state.status.lock().unwrap() = NotificationStatus::Running;
        }
    }
    pub(crate) fn finished(&self, result: &Result<()>) {
        self.delivery.finish();
        *self.state.status.lock().unwrap() = match result {
            Ok(()) => NotificationStatus::Stopped,
            Err(error) => NotificationStatus::Failed(error.to_string().into()),
        };
        self.state.complete.cancel();
    }
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

/// Cloneable notification control. For a standalone receiver, shutdown stops
/// its endpoint service. For an attached agent role, shutdown closes only that
/// notification role; agent or endpoint control owns network shutdown. Keeping
/// control alive retains the service, but never retains the consumer or enables
/// notification admission after its drop.
#[derive(Clone)]
pub struct NotificationControl {
    inner: Arc<ReceiverInner>,
    state: Arc<ServiceState>,
    _lease: Arc<NotificationLease>,
}
impl NotificationControl {
    /// Request standalone-service or attached-role shutdown. Admitted work is drained while
    /// the runner is driven; queued events need not be consumed for it to finish.
    pub fn request_shutdown(&self) {
        self.inner.delivery.close_admission();
        self.state.shutdown.cancel();
        if self.state.attached.load(Ordering::Acquire) {
            self.inner.delivery.finish();
        }
    }
    /// Wait for termination. An unstarted runner must be driven or dropped.
    pub async fn wait_closed(&self) {
        if self.state.attached.load(Ordering::Acquire) {
            self.state.shutdown.cancelled().await;
            NotificationProcessor {
                inner: self.inner.clone(),
            }
            .drain()
            .await;
            let mut status = self.state.status.lock().unwrap();
            if matches!(
                *status,
                NotificationStatus::Prepared | NotificationStatus::Running
            ) {
                *status = NotificationStatus::Stopped;
            }
            self.state.complete.cancel();
        }
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
    /// Identified addresses used by this notification role.
    pub fn bound_addresses(&self) -> &[crate::transport::BoundListener] {
        &self.network.bound
    }
    /// Select a shared endpoint prepared with client exchanges enabled.
    pub fn udp_endpoint(&self, id: crate::EndpointId) -> Option<crate::UdpEndpoint> {
        self.network
            .udp
            .iter()
            .find(|endpoint| endpoint.endpoint_id() == id)
            .cloned()
            .map(|endpoint| endpoint.with_service_lease(self.lease.clone()))
    }
    /// Snapshot exact accepted or configured TCP sessions, retaining service lifetime.
    pub fn tcp_sessions(&self) -> Vec<crate::TcpTransport> {
        self.network
            .sessions
            .lock()
            .unwrap()
            .values()
            .cloned()
            .map(|session| session.with_service_lease(self.lease.clone()))
            .collect()
    }
    #[cfg(feature = "agent")]
    pub(crate) fn attach_lifetime(&mut self, lease: Arc<dyn Send + Sync>) {
        Arc::get_mut(&mut self.lease)
            .expect("new role lease is unique")
            ._service_lease = Some(lease);
        self.state.attached.store(true, Ordering::Release);
    }
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
    pub(crate) fn processor(&self) -> NotificationProcessor {
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
                    target: self.bound_addresses()[0].local_addr,
                    source: std::io::Error::other(message.to_string()),
                }
                .boxed()),
                NotificationStatus::Interrupted => Err(Error::Network {
                    target: self.bound_addresses()[0].local_addr,
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
                target: self.bound_addresses()[0].local_addr,
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

/// Owned listener and session execution. Graceful shutdown drains admitted replies.
#[must_use = "drive or drop the notification runner"]
pub struct NotificationRunner {
    network: crate::transport::network::NetworkCleanup,
    listeners: Vec<crate::transport::listener::PreparedListener>,
    processor: NotificationProcessor,
    cleanup: RunnerCleanup,
}
impl NotificationRunner {
    pub(super) fn from_network(
        network: Arc<crate::transport::network::NetworkState>,
        #[allow(unused_mut)] mut listeners: Vec<crate::transport::listener::PreparedListener>,
        processor: NotificationProcessor,
        cleanup: RunnerCleanup,
    ) -> Self {
        #[cfg(test)]
        for listener in &mut listeners {
            if let crate::transport::listener::PreparedListener::Udp { runner, .. } = listener {
                runner.test_receive_faults(
                    processor.inner.receive_errors.clone(),
                    processor.inner.receive_error_ready.clone(),
                );
            }
        }
        Self {
            network: crate::transport::network::NetworkCleanup(network),
            listeners,
            processor,
            cleanup,
        }
    }
    /// Run all prepared sources. Graceful shutdown finishes admitted acknowledgements
    /// before terminating session writers; queue consumption is not required.
    pub async fn run(self) -> Result<()> {
        let Self {
            network,
            listeners,
            processor,
            cleanup,
        } = self;
        cleanup.started();
        let mut children = tokio::task::JoinSet::new();
        let (failures, mut failure_rx) = mpsc::channel(listeners.len());
        for source in listeners {
            let state = network.0.clone();
            let cancel = cleanup.state.shutdown.clone();
            let failures = failures.clone();
            children.spawn(state.run_source(source, cancel, failures));
        }
        let result = tokio::select! {
            biased;
            () = cleanup.state.shutdown.cancelled() => Ok(()),
            Some(error) = failure_rx.recv() => Err(error),
            joined = children.join_next() => match joined {
                Some(Ok(result)) => result,
                Some(Err(error)) => Err(Error::Config(format!("notification network task failed: {error}").into()).boxed()),
                None => Ok(()),
            }
        };
        cleanup.stop_admission();
        cleanup.state.shutdown.cancel();
        processor.drain().await;
        network.0.close_endpoints();
        children.abort_all();
        while children.join_next().await.is_some() {}
        cleanup.finished(&result);
        result
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NotificationDisposition {
    Delivered,
    Rejected,
    Disabled,
    Overloaded,
}

impl NotificationProcessor {
    pub(crate) fn processing_limit(&self) -> usize {
        self.inner.max_processing
    }
    pub(crate) fn is_enabled(&self) -> bool {
        self.inner.delivery.is_open()
    }

    pub(crate) fn note_overload(&self) {
        if self.is_enabled() {
            self.inner
                .delivery
                .overloaded
                .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub(crate) async fn drain(&self) {
        loop {
            let notified = self.inner.idle.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.inner.active.load(Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }
    pub(crate) async fn admission_closed(&self) {
        self.inner.delivery.closed.cancelled().await;
    }
    pub(crate) async fn reserve_tcp(
        &self,
        fail_fast: bool,
    ) -> Result<Option<NotificationAdmission>> {
        let delivery = &self.inner.delivery;
        let sender = {
            let state = delivery.state.lock().unwrap();
            if !state.open {
                return Ok(None);
            }
            let Some(sender) = state.sender.clone() else {
                return Ok(None);
            };
            sender
        };
        let permit = if fail_fast {
            match sender.try_reserve_owned() {
                Ok(permit) => permit,
                Err(mpsc::error::TrySendError::Closed(_)) => return Ok(None),
                Err(mpsc::error::TrySendError::Full(_)) => {
                    self.note_overload();
                    return Err(Error::Config("TCP notification delivery overload".into()).boxed());
                }
            }
        } else {
            tokio::select! { biased;
                () = delivery.closed.cancelled() => return Ok(None),
                permit = sender.reserve_owned() => match permit { Ok(permit) => permit, Err(_) => return Ok(None) },
            }
        };
        let state = delivery.state.lock().unwrap();
        if !state.open {
            return Ok(None);
        }
        Ok(Some(NotificationAdmission {
            failure: None,
            permit: Some(permit),
        }))
    }
    pub(crate) async fn process(
        &self,
        message: crate::transport::ReceivedMessage,
    ) -> NotificationDisposition {
        if !self.is_enabled() {
            message.observe(crate::MessageDisposition::Disabled);
            return NotificationDisposition::Disabled;
        }
        self.process_admitted(message, NotificationAdmission::default())
            .await
    }
    pub(crate) fn process_admitted(
        &self,
        message: crate::transport::ReceivedMessage,
        mut admission: NotificationAdmission,
    ) -> impl std::future::Future<Output = NotificationDisposition> + Send + 'static {
        struct Active(Arc<ReceiverInner>);
        impl Drop for Active {
            fn drop(&mut self) {
                self.0.active.fetch_sub(1, Ordering::AcqRel);
                self.0.idle.notify_waiters();
            }
        }
        self.inner.active.fetch_add(1, Ordering::AcqRel);
        let active = Active(self.inner.clone());
        let processor = self.clone();
        async move {
            let _active = active;
            let source = message.info.peer_addr();
            let info = message.info;
            let observation = message.reply.observation().clone();
            let disposition = match processor.parse_and_respond(message, &mut admission).await {
                Ok(Some(notification)) => {
                    admission.publish(notification);
                    NotificationDisposition::Delivered
                }
                Ok(None) => admission
                    .failure
                    .unwrap_or(NotificationDisposition::Rejected),
                Err(error) => {
                    if matches!(&*error, Error::Decode(error) if !matches!(error.kind,
                    crate::DecodeErrorKind::UnknownVersion(_) | crate::DecodeErrorKind::InvalidMsgFlags | crate::DecodeErrorKind::UnknownSecurityModel(_)))
                    {
                        processor
                            .inner
                            .snmp_in_asn_parse_errs
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    tracing::debug!(target: "async_snmp::notification", %source, %error, "notification rejected before admission");
                    NotificationDisposition::Rejected
                }
            };
            observation.disposition(
                info,
                match disposition {
                    NotificationDisposition::Delivered => {
                        crate::MessageDisposition::NotificationDelivered
                    }
                    NotificationDisposition::Disabled => crate::MessageDisposition::Disabled,
                    NotificationDisposition::Overloaded => crate::MessageDisposition::Overloaded,
                    NotificationDisposition::Rejected => crate::MessageDisposition::Rejected,
                },
            );
            disposition
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
