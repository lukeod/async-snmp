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
pub(super) struct NotificationAdmission {
    failure: Option<NotificationDisposition>,
    permit: Option<OwnedPermit<ReceivedNotification>>,
    pub(super) pending_permit: Option<tokio::sync::OwnedSemaphorePermit>,
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
    pub(super) fn reserve_delivery(&mut self, inner: &ReceiverInner, inform: bool) -> bool {
        if !self.reserve(&inner.delivery) {
            return false;
        }
        if !inform
            || inner.acknowledgement_mode == InformAcknowledgementMode::Automatic
            || self.pending_permit.is_some()
        {
            return true;
        }
        match inner.pending.slots.clone().try_acquire_owned() {
            Ok(permit) => {
                self.pending_permit = Some(permit);
                true
            }
            Err(tokio::sync::TryAcquireError::Closed) => {
                self.failure = Some(NotificationDisposition::Disabled);
                false
            }
            Err(tokio::sync::TryAcquireError::NoPermits) => {
                inner.delivery.overloaded.fetch_add(1, Ordering::Relaxed);
                self.failure = Some(NotificationDisposition::Overloaded);
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

/// Shared local authoritative-engine persistence health.
pub use crate::v3::LocalEngineHealth as NotificationHealth;

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

    fn request_shutdown(&self, delivery: &Delivery, pending: &pending::PendingRegistry) {
        delivery.close_admission();
        pending.shutdown();
        self.shutdown.cancel();
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
    pub(super) pending: Arc<pending::PendingRegistry>,
    pub(super) capacity_registration: Option<crate::ReceiveCapacityRegistration>,
}
impl RunnerCleanup {
    pub(crate) fn request_shutdown(&self) {
        self.state.request_shutdown(&self.delivery, &self.pending);
    }
    #[cfg(feature = "agent")]
    pub(crate) fn shutdown_token(&self) -> &CancellationToken {
        &self.state.shutdown
    }
    pub(crate) fn started(&self) {
        if !self.state.shutdown.is_cancelled() {
            *self.state.status.lock().unwrap() = NotificationStatus::Running;
        }
    }
    pub(crate) fn finished(mut self, result: &Result<()>) {
        self.finish(match result {
            Ok(()) => NotificationStatus::Stopped,
            Err(error) => NotificationStatus::Failed(error.to_string().into()),
        });
    }
    fn finish(&mut self, status: NotificationStatus) {
        if self.state.complete.is_cancelled() {
            return;
        }
        self.request_shutdown();
        drop(self.capacity_registration.take());
        *self.state.status.lock().unwrap() = status;
        // Publish status before dropping the last sender can wake the consumer.
        self.delivery.finish();
        self.state.complete.cancel();
    }
}
impl Drop for RunnerCleanup {
    fn drop(&mut self) {
        self.finish(NotificationStatus::Interrupted);
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
    /// Request standalone-service or attached-role shutdown.
    ///
    /// This invalidates pending manual acknowledgements. A driven runner
    /// drains admitted automatic response attempts. Queued events remain
    /// available to the consumer.
    pub fn request_shutdown(&self) {
        self.state
            .request_shutdown(&self.inner.delivery, &self.inner.pending);
    }
    /// Wait for termination. An unstarted runner must be driven or dropped.
    pub async fn wait_closed(&self) {
        self.state.complete.cancelled().await;
    }
    /// [`Request shutdown`](Self::request_shutdown) and
    /// [`wait for termination`](Self::wait_closed).
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
    /// Overload drops charged to notification processing, TCP admission or delivery.
    /// Shared UDP dispatch charges its drops to active commands first. With
    /// commands absent or disabled, an active notification role counts those drops.
    pub fn overload_drops(&self) -> u64 {
        self.inner.delivery.overloaded.load(Ordering::Relaxed)
    }
}

impl NotificationReceiver {
    /// Identified addresses used by this notification role.
    pub fn bound_addresses(&self) -> &[crate::transport::BoundListener] {
        &self.network.bound
    }
    /// Return the UDP endpoint with the matching ID, regardless of its client
    /// exchange capability.
    ///
    /// To initiate requests on a standalone receiver's endpoint, configure
    /// [`client_exchanges(true)`](NotificationReceiverBuilder::client_exchanges)
    /// during preparation. An attached receiver uses the selected agent
    /// endpoint's exchange capability.
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
    }
    /// Receive one accepted event with a cancellation-safe wait.
    ///
    /// Automatic mode attempts acknowledgement before delivery. Manual mode
    /// requires explicit completion. `None` means the queue and all admitted
    /// producers have finished. Check the runner result or control status for
    /// its terminal outcome.
    pub async fn recv(&mut self) -> Option<ReceivedNotification> {
        self.events.recv().await
    }
    /// Stop admission for this notification role.
    ///
    /// Use [`Self::recv`] to drain queued and admitted events. Admitted automatic
    /// Inform response attempts continue. Admitted manual tokens remain usable
    /// until their deadlines while the runner stays active.
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
    pub(crate) fn processor(&self) -> NotificationRole {
        NotificationRole {
            inner: self.inner.clone(),
        }
    }
}
impl Drop for NotificationReceiver {
    fn drop(&mut self) {
        self.close();
        self.inner.pending.shutdown();
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
impl Drop for RunningNotificationReceiver {
    fn drop(&mut self) {
        if self.task.is_some() {
            self.receiver.control().request_shutdown();
        }
    }
}
impl RunningNotificationReceiver {
    /// Receive the next event. See [`NotificationReceiver::recv`] for delivery and
    /// cancellation semantics.
    pub async fn recv(&mut self) -> Option<ReceivedNotification> {
        self.receiver.recv().await
    }

    /// Stop admission and keep admitted events available through [`Self::recv`].
    /// See [`NotificationReceiver::close`] for acknowledgement behavior.
    pub fn close(&mut self) {
        self.receiver.close();
    }

    /// Access the retained runner handle for status or aborting execution.
    /// Returns `None` after [`Self::join`] or [`Self::shutdown`] finishes.
    pub fn task(&self) -> Option<&JoinHandle<Result<()>>> {
        self.task.as_ref()
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
            if source.is_panic() {
                *self.receiver.state.status.lock().unwrap() =
                    NotificationStatus::Failed(Arc::from(source.to_string()));
            }
            Error::Network {
                target: self.bound_addresses()[0].local_addr,
                source: std::io::Error::other(source),
            }
            .boxed()
        })?
    }
    /// Request shutdown and join the runner. Queued events remain available.
    ///
    /// Shutdown invalidates pending manual acknowledgements and drains
    /// admitted automatic response attempts.
    pub async fn shutdown(&mut self) -> Result<()> {
        self.control().request_shutdown();
        self.join().await
    }
}

/// Owned listener and session execution for a notification receiver.
#[must_use = "drive or drop the notification runner"]
pub struct NotificationRunner {
    network: crate::transport::network::NetworkCleanup,
    listeners: Vec<crate::transport::listener::PreparedListener>,
    processor: NotificationRole,
    cleanup: RunnerCleanup,
}
impl NotificationRunner {
    pub(super) fn from_network(
        network: Arc<crate::transport::network::NetworkState>,
        #[allow(unused_mut)] mut listeners: Vec<crate::transport::listener::PreparedListener>,
        processor: NotificationRole,
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
    /// Drive the receiver until service shutdown or a fatal listener failure.
    /// Individual endpoints can stop while the service remains active.
    /// Graceful shutdown invalidates pending manual acknowledgements and drains
    /// admitted automatic response attempts before closing session writers.
    /// Queued events remain available after shutdown.
    pub async fn run(self) -> Result<()> {
        // On cancellation, drop the network before publishing runner completion.
        let Self {
            cleanup,
            network,
            listeners,
            processor,
        } = self;
        cleanup.started();
        let mut children = tokio::task::JoinSet::new();
        if processor.has_pending_worker() {
            children.spawn(
                processor
                    .clone()
                    .run_pending(cleanup.state.shutdown.clone()),
            );
        }
        let (failures, mut failure_rx) = mpsc::channel(listeners.len());
        for source in listeners {
            let state = network.0.clone();
            let cancel = cleanup.state.shutdown.clone();
            let failures = failures.clone();
            children.spawn(state.run_source(source, cancel, failures));
        }
        let result = loop {
            tokio::select! {
                biased;
                () = cleanup.state.shutdown.cancelled() => break Ok(()),
                Some(error) = failure_rx.recv() => break Err(error),
                joined = children.join_next(), if !children.is_empty() => match joined {
                    Some(Ok(Err(error))) => break Err(error),
                    Some(Err(error)) => break Err(Error::Config(format!("notification network task failed: {error}").into()).boxed()),
                    Some(Ok(Ok(()))) | None => {},
                }
            }
        };
        cleanup.request_shutdown();
        processor.drain().await;
        network.0.close_endpoints();
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

struct ActiveNotification(NotificationRole);
impl Drop for ActiveNotification {
    fn drop(&mut self) {
        self.0.inner.active.fetch_sub(1, Ordering::AcqRel);
        self.0.inner.idle.notify_waiters();
    }
}

pub(crate) struct NotificationWork {
    active: ActiveNotification,
    info: crate::ReceivedMessageInfo,
    observation: crate::transport::observation::Observation,
    result: Result<(NotificationProcessResult, crate::transport::ReplyRoute)>,
    pub(super) admission: NotificationAdmission,
}
impl NotificationWork {
    pub(crate) async fn run(mut self) -> NotificationDisposition {
        let source = self.info.peer_addr();
        let result = match self.result {
            Ok((result, route)) => {
                self.active
                    .0
                    .respond(result, route, source, &mut self.admission)
                    .await
            }
            Err(error) => Err(error),
        };
        let disposition = match result {
            Ok(Some(notification)) => {
                self.admission.publish(notification);
                NotificationDisposition::Delivered
            }
            Ok(None) => self
                .admission
                .failure
                .unwrap_or(NotificationDisposition::Rejected),
            Err(error) => {
                tracing::debug!(target: "async_snmp::notification", %source, %error, "notification rejected before admission");
                NotificationDisposition::Rejected
            }
        };
        self.observation.disposition(
            self.info,
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

impl NotificationRole {
    pub(crate) fn has_pending_worker(&self) -> bool {
        self.inner.acknowledgement_mode == InformAcknowledgementMode::ApplicationControlled
    }

    pub(crate) fn processing_limit(&self) -> usize {
        self.inner.max_processing
    }
    pub(crate) fn is_enabled(&self) -> bool {
        self.inner.delivery.is_open()
    }

    pub(crate) fn note_overload(&self) -> bool {
        let delivery = &self.inner.delivery;
        let state = delivery.state.lock().unwrap();
        if !state.open {
            return false;
        }
        delivery.overloaded.fetch_add(1, Ordering::Relaxed);
        true
    }
    pub(crate) async fn drain(&self) {
        loop {
            let notified = self.inner.idle.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.inner.active.load(Ordering::Acquire) == 0 {
                self.inner.pending.drain().await;
                return;
            }
            notified.await;
        }
    }
    pub(crate) async fn admission_closed(&self) {
        self.inner.delivery.closed.cancelled().await;
    }
    async fn reserve_tcp(&self, fail_fast: bool) -> Result<Option<NotificationAdmission>> {
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
            pending_permit: None,
        }))
    }
    pub(crate) async fn process(
        &self,
        message: crate::transport::ReceivedMessage,
    ) -> NotificationDisposition {
        match self.prepare(message) {
            Some(work) => work.run().await,
            None => NotificationDisposition::Disabled,
        }
    }

    pub(crate) async fn admit_tcp(
        &self,
        message: crate::transport::ReceivedMessage,
        fail_fast: bool,
    ) -> Result<Option<NotificationWork>> {
        let Some(mut work) = self.prepare(message) else {
            return Ok(None);
        };
        // Reports and Inform tooBig replies terminate before event delivery.
        if matches!(work.result, Ok((NotificationProcessResult::Accepted(_), _))) {
            let Some(admission) = self.reserve_tcp(fail_fast).await? else {
                work.observation
                    .disposition(work.info, crate::MessageDisposition::Disabled);
                return Ok(None);
            };
            work.admission = admission;
        }
        Ok(Some(work))
    }

    pub(super) fn prepare(
        &self,
        message: crate::transport::ReceivedMessage,
    ) -> Option<NotificationWork> {
        // Register active work before shutdown can close admission and drain it.
        let active = {
            let state = self.inner.delivery.state.lock().unwrap();
            if !state.open {
                message.observe(crate::MessageDisposition::Disabled);
                return None;
            }
            self.inner.active.fetch_add(1, Ordering::AcqRel);
            ActiveNotification(self.clone())
        };
        let info = message.info;
        let observation = message.reply.observation().clone();
        let result = message.into_processing().and_then(|(input, route)| {
            self.inner
                .protocol
                .process(input)
                .map(|result| (result, route))
        });
        Some(NotificationWork {
            active,
            info,
            observation,
            result,
            admission: NotificationAdmission::default(),
        })
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
