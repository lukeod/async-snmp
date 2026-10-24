//! Agent execution and network ownership, separate from retained mutation work.
use super::*;
use crate::transport::ingress::InboundWork;
use crate::transport::listener::PreparedListener;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::DropGuard;

/// Observable root execution state. Interrupted execution does not imply that
/// admitted mutation cleanup has finished; observe/drain it through control.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AgentStatus {
    Prepared,
    Running,
    Stopped,
    Interrupted,
    Failed(Arc<str>),
}

pub(crate) struct AgentNetwork {
    pub(crate) io: Arc<crate::transport::network::NetworkState>,
    drops: Arc<AtomicU64>,
    status: std::sync::Mutex<AgentStatus>,
    complete: CancellationToken,
}
impl AgentNetwork {
    pub(super) fn new(
        listeners: &[PreparedListener],
        max_connections: usize,
        drops: Arc<AtomicU64>,
    ) -> Result<Self> {
        Ok(Self {
            io: Arc::new(crate::transport::network::NetworkState::new(
                listeners,
                max_connections,
            )?),
            drops,
            status: std::sync::Mutex::new(AgentStatus::Prepared),
            complete: CancellationToken::new(),
        })
    }
    fn close_endpoints(&self) {
        self.io.close_endpoints();
    }
}

impl std::ops::Deref for AgentNetwork {
    type Target = crate::transport::network::NetworkState;
    fn deref(&self) -> &Self::Target {
        &self.io
    }
}

pub(super) struct AgentLease {
    _guard: DropGuard,
}
impl AgentLease {
    pub(super) fn new(cancel: CancellationToken) -> Self {
        Self {
            _guard: cancel.drop_guard(),
        }
    }
}

/// Cloneable service control; it retains public network lifetime independently
/// of application-owned mutation tasks.
#[derive(Clone)]
pub struct AgentControl {
    pub(super) agent: Agent,
}
impl AgentControl {
    /// Disable only the command role, leaving notifications and exchanges active.
    pub fn close_commands(&self) {
        self.agent.close_commands();
    }
    pub fn request_shutdown(&self) {
        self.agent.inner.cancel.cancel();
    }
    pub fn status(&self) -> AgentStatus {
        self.agent.network.status.lock().unwrap().clone()
    }
    /// UDP inputs dropped during dispatch or application admission because work or memory was full.
    pub fn overload_drops(&self) -> u64 {
        self.agent.network.drops.load(Ordering::Relaxed)
    }
    pub fn is_shutdown(&self) -> bool {
        self.agent.inner.cancel.is_cancelled()
    }
    /// Wait for the network runner. An unstarted runner must be driven or dropped.
    /// Forced network termination does not establish mutation cleanup completion.
    pub async fn wait_closed(&self) {
        self.agent.network.complete.cancelled().await;
    }
    pub async fn shutdown(&self) {
        self.request_shutdown();
        self.wait_closed().await;
    }
    /// Number of positively classified mutation tasks still retained by the application.
    pub fn outstanding_mutations(&self) -> usize {
        self.agent
            .inner
            .live_request_tasks
            .lock()
            .unwrap()
            .values()
            .filter(|task| {
                let phase = task.phase.load(Ordering::Acquire);
                phase == RequestTaskPhase::SetPreCommit as u8
                    || phase == RequestTaskPhase::SetProtected as u8
            })
            .count()
    }
    /// Wait for mutation and unclassified tasks after network admission stopped.
    /// A timeout or retained task panic is reported without aborting cleanup.
    pub async fn drain_mutations(&self, timeout: Duration) -> Result<()> {
        if !self.is_shutdown() {
            return Err(
                Error::Config("stop network admission before draining mutations".into()).boxed(),
            );
        }
        let deadline = crate::transport::checked_deadline(timeout, "mutation drain timeout")?;
        tokio::time::timeout_at(deadline.into(), self.wait_closed())
            .await
            .map_err(|_| {
                Error::Config(
                    "network admission has not stopped before mutation drain deadline".into(),
                )
                .boxed()
            })?;
        let inner = &self.agent.inner;
        loop {
            let notified = inner.task_changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let outstanding = inner
                .live_request_tasks
                .lock()
                .unwrap()
                .values()
                .any(|task| {
                    task.phase.load(Ordering::Acquire) != RequestTaskPhase::Retrieval as u8
                });
            if !outstanding {
                if inner.mutation_failures.load(Ordering::Acquire) != 0 {
                    return Err(Error::Config("retained mutation cleanup failed".into()).boxed());
                }
                return Ok(());
            }
            tokio::time::timeout_at(deadline.into(), notified)
                .await
                .map_err(|_| {
                    Error::Config(
                        "mutation drain deadline expired; cleanup remains retained".into(),
                    )
                    .boxed()
                })?;
        }
    }
}

/// Prepared public handle and one unstarted runner. No task is spawned by preparation.
#[must_use = "drive or drop the agent runner"]
pub struct PreparedAgent {
    pub(super) agent: Agent,
    pub(super) runner: AgentRunner,
    pub(super) notifications: Option<crate::NotificationReceiver>,
}
impl PreparedAgent {
    /// Take the unique attached consumer before splitting or spawning the runner.
    pub fn take_notifications(&mut self) -> Option<crate::NotificationReceiver> {
        self.notifications.take()
    }
    pub fn into_parts(self) -> (Agent, AgentRunner) {
        (self.agent, self.runner)
    }
    pub fn spawn(self) -> RunningAgent {
        self.spawn_on(&tokio::runtime::Handle::current())
    }
    /// Existing listener/socket registrations remain on their original runtime.
    pub fn spawn_on(self, runtime: &tokio::runtime::Handle) -> RunningAgent {
        let Self {
            agent,
            runner,
            notifications,
        } = self;
        RunningAgent {
            agent,
            notifications,
            task: Some(runtime.spawn(runner.run())),
        }
    }
    #[cfg(test)]
    fn into_test_agent(self) -> Agent {
        let (agent, runner) = self.into_parts();
        *agent.test_runner.lock().unwrap() = Some(runner);
        agent
    }
}
/// Owner of a spawned service. Drop requests shutdown; retain it to observe the result.
#[must_use = "dropping the running owner requests shutdown"]
pub struct RunningAgent {
    agent: Agent,
    notifications: Option<crate::NotificationReceiver>,
    task: Option<JoinHandle<Result<()>>>,
}
impl std::ops::Deref for RunningAgent {
    type Target = Agent;
    fn deref(&self) -> &Agent {
        &self.agent
    }
}
impl Drop for RunningAgent {
    fn drop(&mut self) {
        if self.task.is_some() {
            self.agent.control().request_shutdown();
        }
    }
}
impl RunningAgent {
    /// Take the one attached notification consumer.
    pub fn take_notifications(&mut self) -> Option<crate::NotificationReceiver> {
        self.notifications.take()
    }
    pub fn agent(&self) -> Agent {
        self.agent.clone()
    }
    pub fn task(&self) -> &JoinHandle<Result<()>> {
        self.task.as_ref().expect("running task retained")
    }
    pub async fn join(mut self) -> Result<()> {
        let result = self.task.as_mut().expect("running task retained").await;
        self.task.take();
        result.map_err(|error| {
            Error::Config(format!("agent runner failed: {error}").into()).boxed()
        })?
    }
    pub async fn shutdown(self) -> Result<()> {
        self.control().request_shutdown();
        self.join().await
    }
}

struct AgentRunCleanup {
    inner: Arc<AgentInner>,
    network: Arc<AgentNetwork>,
    completed: bool,
}
impl Drop for AgentRunCleanup {
    fn drop(&mut self) {
        self.inner.cancel.cancel();
        self.network.close_endpoints();
        self.inner
            .run_orphaned
            .store(!self.completed, Ordering::Release);
        if self.inner.active_request_tasks.load(Ordering::Acquire) == 0 {
            self.inner.run_active.store(false, Ordering::Release);
        }
        if !self.completed {
            *self.network.status.lock().unwrap() = AgentStatus::Interrupted;
        }
        self.network.complete.cancel();
        self.inner.task_changed.notify_waiters();
    }
}

/// Owned root runner. Network children abort with it; admitted mutation tasks
/// stay in the independently retained application registry through commit/undo/free.
#[must_use = "drive or drop the agent runner"]
pub struct AgentRunner {
    processor: AgentProcessor,
    listeners: Vec<PreparedListener>,
    incoming: mpsc::Receiver<InboundWork>,
    cleanup: AgentRunCleanup,
    pub(super) notification_role: Option<(
        crate::notification::NotificationProcessor,
        crate::notification::RunnerCleanup,
    )>,
}
impl AgentRunner {
    pub(super) fn new(
        inner: Arc<AgentInner>,
        network: Arc<AgentNetwork>,
        listeners: Vec<PreparedListener>,
        incoming: mpsc::Receiver<InboundWork>,
    ) -> Self {
        Self {
            notification_role: None,
            processor: AgentProcessor {
                inner: inner.clone(),
            },
            listeners,
            incoming,
            cleanup: AgentRunCleanup {
                inner,
                network,
                completed: false,
            },
        }
    }
    pub async fn run(mut self) -> Result<()> {
        self.processor
            .inner
            .run_active
            .store(true, Ordering::Release);
        *self.cleanup.network.status.lock().unwrap() = AgentStatus::Running;
        if let Some((_, role)) = &self.notification_role {
            role.started();
        }
        let mut children: JoinSet<Result<()>> = JoinSet::new();
        let (failures, mut failure_rx) = mpsc::channel(self.listeners.len());
        let mut requests = RequestTasks::new(
            self.processor.inner.cancel.child_token(),
            self.processor.inner.clone(),
        );
        for listener in self.listeners.drain(..) {
            let network = self.cleanup.network.clone();
            let cancel = self.processor.inner.cancel.clone();
            let failures = failures.clone();
            #[cfg(test)]
            let test_inner = self.processor.inner.clone();
            #[allow(unused_mut)]
            let mut listener = listener;
            #[cfg(test)]
            if let PreparedListener::Udp { runner, .. } = &mut listener {
                runner.test_receive_state(
                    test_inner.receive_errors.clone(),
                    test_inner.receive_attempts.clone(),
                );
            }
            children.spawn(network.io.clone().run_source(listener, cancel, failures));
        }
        let result = loop {
            tokio::select! {
                biased;
                () = self.processor.inner.cancel.cancelled() => break Ok(()),
                Some(error) = failure_rx.recv() => break Err(error),
                joined = children.join_next(), if !children.is_empty() => match joined {
                    Some(Ok(Err(error))) => break Err(error),
                    Some(Err(error)) => break Err(Error::Config(format!("agent listener task failed: {error}").into()).boxed()),
                    Some(Ok(Ok(()))) => break Err(Error::Config("agent listener stopped unexpectedly".into()).boxed()),
                    None => {},
                },
                joined = requests.join_next(), if !requests.is_empty() => { log_request_result(joined); },
                work = self.incoming.recv() => {
                    let Some(work) = work else { break Ok(()); };
                    self.dispatch(&mut requests, work);
                }
            }
        };
        if let Some((_, role)) = &self.notification_role {
            role.stop_admission();
        }
        self.incoming.close();
        self.processor.inner.cancel.cancel();
        requests.cancel();
        // Keep endpoints writable while admitted handlers finalize responses.
        if let AgentShutdownPolicy::AbortCancellationSafeRetrievalsAfter(grace) =
            self.processor.inner.shutdown_policy
        {
            let drain = async {
                while let Some(joined) = requests.join_next().await {
                    log_request_result(Some(joined));
                }
            };
            if tokio::time::timeout(grace, drain).await.is_err() {
                requests.abort_retrievals();
            }
        }
        while let Some(joined) = requests.join_next().await {
            log_request_result(Some(joined));
        }
        if let Some((processor, role)) = &self.notification_role {
            processor.drain().await;
            role.finished(&result);
        }
        self.cleanup.network.close_endpoints();
        children.abort_all();
        while children.join_next().await.is_some() {}
        self.cleanup.completed = true;
        self.processor
            .inner
            .run_active
            .store(false, Ordering::Release);
        *self.cleanup.network.status.lock().unwrap() = match &result {
            Ok(()) => AgentStatus::Stopped,
            Err(error) => AgentStatus::Failed(error.to_string().into()),
        };
        result
    }
    fn dispatch(&self, requests: &mut RequestTasks, work: InboundWork) {
        if self.processor.inner.command_stop.is_cancelled() {
            return;
        }
        let received_at = work.message.info.received_at();
        let deadline = self
            .processor
            .inner
            .request_deadline
            .map(|timeout| received_at + timeout);
        let cancel = requests.cancellation_token().child_token();
        let phase = Arc::new(AtomicU8::new(RequestTaskPhase::Unclassified as u8));
        let lifecycle = RequestLifecycle::new(
            received_at,
            tokio::time::Instant::now(),
            deadline,
            cancel.clone(),
            phase.clone(),
        )
        .with_message(work.message.info, work.message.reply.limits);
        let processor = self.processor.clone();
        #[cfg(test)]
        self.processor
            .inner
            .received_datagrams
            .fetch_add(1, Ordering::Relaxed);
        requests.spawn(phase, async move {
            let InboundWork { message, _admission, _session, _buffers } = work;
            let request = async {
                match processor.handle_prepared_request_with_lifecycle(message.bytes, message.info.peer_addr(), lifecycle, message.prepared).await {
                    Ok(Some(bytes)) => { let _ = processor.send_response(&bytes, &message.reply).await; },
                    Ok(None) => {},
                    Err(error) => tracing::debug!(%error, "agent request rejected"),
                }
            };
            tokio::pin!(request);
            if let Some(deadline) = deadline {
                tokio::select! { biased; () = tokio::time::sleep_until(deadline) => { cancel.cancel(); request.await; }, () = &mut request => {} }
            } else { request.await; }
        });
    }
}

fn log_request_result(result: Option<std::result::Result<(), JoinError>>) {
    if let Some(Err(error)) = result {
        tracing::debug!(%error, "agent request task terminated");
    }
}

#[cfg(test)]
impl AgentBuilder {
    // Existing protocol tests deliberately retain an unstarted runner. Public
    // callers use the explicit prepared pair; this helper is test-only.
    pub(super) async fn build(self) -> Result<Agent> {
        Ok(self
            .discard_notifications()
            .prepare()
            .await?
            .into_test_agent())
    }
    pub(super) async fn build_with_dependencies<B, BFut, R, RFut, G, S>(
        self,
        bind: B,
        resolve: R,
        generate: G,
        salt: S,
    ) -> Result<Agent>
    where
        B: FnOnce(SocketAddr, Option<usize>) -> BFut,
        BFut: Future<Output = std::io::Result<UdpSocket>>,
        R: FnMut(String, u16) -> RFut,
        RFut: Future<Output = Result<Vec<SocketAddr>>>,
        G: FnOnce() -> Result<Bytes>,
        S: FnOnce() -> Result<SaltCounter>,
    {
        Ok(self
            .prepare_with_dependencies(bind, resolve, generate, salt)
            .await?
            .into_test_agent())
    }
}
#[cfg(test)]
impl Agent {
    pub(super) async fn run(&self) -> Result<()> {
        let runner = self
            .test_runner
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| Error::Config("agent runner already consumed".into()).boxed())?;
        runner.run().await
    }
}
