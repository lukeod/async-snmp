//! Caller-owned command I/O and retained request ownership.

use super::*;

/// Application-only configuration for a [`CommandProcessor`].
/// Building creates no sockets, DNS requests, workers or background tasks and
/// does not require a Tokio runtime. Processing uses owned Tokio request tasks.
pub struct CommandProcessorBuilder {
    local_engine: Option<crate::LocalEngine>,
    security_context: Option<crate::UsmSecurityContext>,
    communities: Vec<crate::Community>,
    handlers: Vec<RegisteredHandler>,
    authorization: AgentAuthorization,
    max_message_size: usize,
    decode_config: crate::DecodeConfig,
    max_concurrent_requests: usize,
    request_deadline: Option<Duration>,
    disabled_builtins: HashSet<BuiltinMib>,
}

impl Default for CommandProcessorBuilder {
    fn default() -> Self {
        Self {
            local_engine: None,
            security_context: None,
            communities: Vec::new(),
            handlers: Vec::new(),
            authorization: AgentAuthorization::Unset,
            max_message_size: crate::MESSAGE_SIZE_MAXIMUM,
            decode_config: crate::DecodeConfig::DEFAULT,
            max_concurrent_requests: 64,
            request_deadline: None,
            disabled_builtins: HashSet::new(),
        }
    }
}

impl CommandProcessorBuilder {
    /// Share authoritative identity, clock, counters and privacy sender state.
    pub fn local_engine(mut self, engine: crate::LocalEngine) -> Self {
        self.local_engine = Some(engine);
        self
    }

    /// Select inbound credentials and their atomic runtime replacements.
    /// Even an initially empty explicit context requires a persisted local
    /// engine and an explicit access policy.
    pub fn security_context(mut self, context: crate::UsmSecurityContext) -> Self {
        self.security_context = Some(context);
        self
    }

    /// Accept this v1/v2c cleartext community. With no communities configured,
    /// community requests are rejected.
    pub fn community(mut self, community: impl Into<crate::Community>) -> Self {
        self.communities.push(community.into());
        self
    }

    /// Register a handler, selected by longest matching OID prefix.
    pub fn handler(mut self, prefix: Oid, handler: Arc<dyn MibHandler>) -> Self {
        self.handlers.push(RegisteredHandler { prefix, handler });
        self
    }

    /// Configure VACM; it conflicts with unrestricted access.
    pub fn vacm(mut self, configure: impl FnOnce(VacmBuilder) -> VacmBuilder) -> Self {
        self.authorization = configure_vacm(self.authorization, configure);
        self
    }

    /// Explicitly allow operations from accepted identities, including
    /// unauthenticated USM messages. Conflicts with VACM.
    pub fn allow_all_access(mut self) -> Self {
        self.authorization = allow_all_access(self.authorization);
        self
    }

    /// Local encoded-response policy; input and peer limits still apply.
    pub fn max_message_size(mut self, size: usize) -> Self {
        self.max_message_size = size;
        self
    }

    /// Select bounded request-decoding compatibility.
    pub fn decode_config(mut self, config: crate::DecodeConfig) -> Self {
        self.decode_config = config;
        self
    }

    /// Bound admitted owned requests across clones (default: 64). Callers wait
    /// for capacity before admission; cancellation before admission starts no work.
    pub fn max_concurrent_requests(mut self, limit: usize) -> Self {
        self.max_concurrent_requests = limit;
        self
    }

    /// Absolute request budget from input receipt, including admission wait.
    /// Expiry returns a timeout and signals cooperative cancellation without
    /// aborting admitted mutation cleanup.
    pub fn request_deadline(mut self, timeout: Option<Duration>) -> Self {
        self.request_deadline = timeout;
        self
    }

    /// Omit one built-in engine/statistics MIB handler.
    pub fn without_builtin_handler(mut self, mib: BuiltinMib) -> Self {
        self.disabled_builtins.insert(mib);
        self
    }

    /// Omit every built-in engine/statistics MIB handler.
    pub fn without_builtin_handlers(mut self) -> Self {
        self.disabled_builtins.extend([
            BuiltinMib::SnmpEngine,
            BuiltinMib::UsmStats,
            BuiltinMib::MpdStats,
        ]);
        self
    }

    /// Prepare shared command application state without network or task creation.
    /// Register caller-owned endpoint capacities on [`crate::LocalEngine`] before
    /// processing; no UDP capacity is inferred for a socketless application.
    pub fn build(self) -> Result<CommandProcessor> {
        let has_security_context = self.security_context.is_some();
        validate_authorization(
            &self.authorization,
            !self.communities.is_empty() || has_security_context,
        )?;
        if self.max_message_size > crate::MESSAGE_SIZE_MAXIMUM {
            return Err(
                Error::Config("max_message_size exceeds the SNMP size range".into()).boxed(),
            );
        }
        if self.max_concurrent_requests == 0
            || self.max_concurrent_requests > Semaphore::MAX_PERMITS
        {
            return Err(Error::Config(
                "max_concurrent_requests must be nonzero and representable".into(),
            )
            .boxed());
        }
        if let Some(timeout) = self.request_deadline {
            crate::transport::checked_deadline(timeout, "command request deadline")?;
        }
        if has_security_context
            && self
                .local_engine
                .as_ref()
                .and_then(crate::LocalEngine::authoritative_engine)
                .is_none()
        {
            return Err(Error::Config(
                "persisted local engine state is required for a USM command processor".into(),
            )
            .boxed());
        }
        let local_engine = match self.local_engine {
            Some(engine) => engine,
            None => crate::LocalEngine::from_prepared(
                None,
                crate::v3::generate_engine_id()?,
                1,
                None,
                None,
            ),
        };
        let inner = prepare_application(ApplicationConfig {
            local_engine,
            security_context: self.security_context.unwrap_or_default(),
            security_context_required: has_security_context,
            communities: self.communities,
            handlers: self.handlers,
            authorization: self.authorization,
            max_message_size: self.max_message_size,
            decode_config: self.decode_config,
            concurrency_limit: Arc::new(Semaphore::new(self.max_concurrent_requests)),
            command_stop: CancellationToken::new(),
            cancel: CancellationToken::new(),
            request_deadline: self.request_deadline,
            disabled_builtins: self.disabled_builtins,
            discard_notifications: false,
            trap_send_timeout: crate::client::DEFAULT_SEND_TIMEOUT,
            inform_timeout: crate::client::DEFAULT_REQUEST_TIMEOUT,
            inform_retry: crate::Retry::default(),
            response_send_timeout: crate::client::DEFAULT_SEND_TIMEOUT,
            shutdown_policy: AgentShutdownPolicy::Drain,
            notification_fanout_limit: 32,
        });
        let lease = Arc::new(ApplicationLease {
            inner: inner.clone(),
        });
        Ok(CommandProcessor {
            core: AgentProcessor { inner },
            lease,
        })
    }
}

/// Socketless v1/v2c/v3 command responder sharing the managed Agent's handlers,
/// VACM, security processing and exact response finalization.
///
/// Clones share one SET coordinator, admission limit and tracked request registry.
/// Each admitted request runs in an owned Tokio task. Dropping its caller future,
/// reaching a deadline or requesting shutdown signals cancellation but retains
/// commit/undo/free work until it exits while the runtime remains alive/driven.
/// Runtime teardown or process failure cannot guarantee asynchronous cleanup.
/// Use [`CommandControl::request_shutdown`] before bounded
/// [`CommandControl::drain_mutations`] or [`CommandControl::drain_requests`].
/// The first waits for SET/unclassified work; the second also waits for retrievals.
/// Neither timeout aborts retained work. Processing does not deduplicate retries
/// or promise exactly-once SET execution. Returned bytes still require caller I/O.
#[derive(Clone)]
pub struct CommandProcessor {
    core: AgentProcessor,
    lease: Arc<ApplicationLease>,
}

struct ApplicationLease {
    inner: Arc<AgentInner>,
}
impl Drop for ApplicationLease {
    fn drop(&mut self) {
        close_application(&self.inner);
    }
}

/// One encoded Response or Report and its original input metadata.
/// Bytes have not been sent; the caller owns reply routing and transport I/O.
pub struct CommandResponse {
    /// Exactly finalized complete encoded SNMP Response or Report.
    pub bytes: Bytes,
    /// Original input metadata and reception identity.
    pub receive_info: crate::ReceivedMessageInfo,
}
impl std::fmt::Debug for CommandResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommandResponse")
            .field("encoded_len", &self.bytes.len())
            .field("receive_info", &self.receive_info)
            .finish()
    }
}

impl CommandProcessor {
    /// Configure a command application independently of any transport.
    pub fn builder() -> CommandProcessorBuilder {
        CommandProcessorBuilder::default()
    }

    /// Shared local engine. Keep one receive-capacity registration per
    /// caller-owned endpoint while it serves this application.
    pub fn local_engine(&self) -> crate::LocalEngine {
        self.core.inner.state.local_engine.clone()
    }

    /// Observe application admission and retained work without owning network I/O.
    pub fn control(&self) -> CommandControl {
        CommandControl {
            inner: self.core.inner.clone(),
            _lease: self.lease.clone(),
        }
    }

    /// Process one input on the current Tokio runtime, returning a Response or
    /// Report when applicable. Requires an active runtime; build does not.
    ///
    /// Register each custom endpoint with [`crate::LocalEngine::register_receive_capacity`].
    /// Missing declaration, or an input advertisement below the minimum of
    /// live endpoint declarations, is rejected before admission. Each admitted request keeps
    /// its input capacity registered through completion even if the endpoint's
    /// public registration is dropped meanwhile.
    ///
    /// `None` means the input did not require a response or was rejected.
    /// Caller cancellation/deadline/shutdown can return before owned cleanup
    /// completes. Use control's drain methods to observe completion separately.
    pub async fn process(&self, input: crate::ProcessingInput) -> Result<Option<CommandResponse>> {
        tokio::runtime::Handle::try_current().map_err(|_| {
            Error::Config("command processing requires an active Tokio runtime".into()).boxed()
        })?;
        let info = input.info();
        let limits = input.limits();
        let engine = self.local_engine();
        if engine
            .declared_receive_capacity()
            .is_none_or(|registered| registered > limits.receive().advertised())
        {
            return Err(Error::Config(
                "register the caller-owned endpoint receive capacity before command processing"
                    .into(),
            )
            .boxed());
        }
        let deadline = self
            .core
            .inner
            .request_deadline
            .map(|timeout| {
                info.received_at().checked_add(timeout).ok_or_else(|| {
                    Error::Config("command deadline exceeds the input clock range".into()).boxed()
                })
            })
            .transpose()?;
        let timeout = || {
            Error::Timeout {
                target: info.peer_addr(),
                elapsed: info.received_at().elapsed(),
                retries: 0,
            }
            .boxed()
        };
        let closed = || Error::Config("command application admission is closed".into()).boxed();
        let permit = if let Some(deadline) = deadline {
            tokio::select! { biased;
                () = self.core.inner.command_stop.cancelled() => return Err(closed()),
                () = tokio::time::sleep_until(deadline) => return Err(timeout()),
                permit = self.core.inner.concurrency_limit.clone().acquire_owned() => permit.map_err(|_| closed())?,
            }
        } else {
            tokio::select! { biased;
                () = self.core.inner.command_stop.cancelled() => return Err(closed()),
                permit = self.core.inner.concurrency_limit.clone().acquire_owned() => permit.map_err(|_| closed())?,
            }
        };
        let cancellation = self.core.inner.cancel.child_token();
        let mut tasks = RequestTasks::new(cancellation.clone(), self.core.inner.clone());
        let (sender, result) = tokio::sync::oneshot::channel();
        {
            let _admission = self.core.inner.command_admission_gate.lock().unwrap();
            if self.core.inner.command_stop.is_cancelled() {
                return Err(closed());
            }
            if deadline.is_some_and(|deadline| tokio::time::Instant::now() >= deadline) {
                return Err(timeout());
            }
            let capacity = engine.register_processing_capacity(limits.receive().advertised())?;
            let phase = Arc::new(AtomicU8::new(RequestTaskPhase::Unclassified as u8));
            let lifecycle = RequestLifecycle::new(
                info.received_at(),
                tokio::time::Instant::now(),
                deadline,
                cancellation.clone(),
                phase.clone(),
            );
            let core = self.core.clone();
            let task_cancel = cancellation.clone();
            tasks.spawn(phase, async move {
                let (_permit, _capacity) = (permit, capacity);
                let request = core.handle_processing_input_with_lifecycle(input, lifecycle);
                tokio::pin!(request);
                let outcome = if let Some(deadline) = deadline {
                    tokio::select! { biased;
                        () = tokio::time::sleep_until(deadline) => { task_cancel.cancel(); request.await },
                        result = &mut request => result,
                    }
                } else { request.await };
                let _ = sender.send(outcome.map(|bytes| bytes.map(|bytes| CommandResponse { bytes, receive_info: info })));
            });
        }
        let result = if let Some(deadline) = deadline {
            tokio::select! { biased;
                () = self.core.inner.command_stop.cancelled() => return Err(closed()),
                () = tokio::time::sleep_until(deadline) => return Err(timeout()),
                result = result => result,
            }
        } else {
            tokio::select! { biased;
                () = self.core.inner.command_stop.cancelled() => return Err(closed()),
                result = result => result,
            }
        };
        match tasks.join_next().await {
            Some(Ok(())) => result
                .map_err(|_| Error::Config("command task ended without a result".into()).boxed())?,
            Some(Err(error)) => {
                Err(Error::Config(format!("command task failed: {error}").into()).boxed())
            }
            None => Err(Error::Config("command task ownership was lost".into()).boxed()),
        }
    }
}

/// Application control independent of caller futures and network lifetimes.
/// `is_shutdown` reports closed admission; it does not establish cleanup completion.
#[derive(Clone)]
pub struct CommandControl {
    inner: Arc<AgentInner>,
    _lease: Arc<ApplicationLease>,
}
impl CommandControl {
    /// Close admission and signal cancellation; retained work remains owned.
    pub fn request_shutdown(&self) {
        close_application(&self.inner);
    }
    /// Whether admission has been closed, including last-public-handle shutdown.
    pub fn is_shutdown(&self) -> bool {
        self.inner.command_stop.is_cancelled()
    }
    /// Registered requests, including work not yet classified as retrieval or SET.
    pub fn outstanding_requests(&self) -> usize {
        self.inner.request_registry.lock().unwrap().tasks.len()
    }
    /// Positively classified SET work; unclassified requests are also included
    /// by drain methods even though this statistic does not count them.
    pub fn outstanding_mutations(&self) -> usize {
        outstanding_mutations(&self.inner)
    }
    /// Wait for SET/unclassified work after closing admission. Timeout never
    /// aborts cleanup. A classified mutation task that panics or is interrupted
    /// before completion causes the drain to return an error.
    pub async fn drain_mutations(&self, timeout: Duration) -> Result<()> {
        self.drain(timeout, false).await
    }
    /// Wait for every registered request after closing admission, including
    /// retrieval handlers that have not cooperatively completed. An interrupted
    /// or panicking classified mutation causes the drain to return an error.
    pub async fn drain_requests(&self, timeout: Duration) -> Result<()> {
        self.drain(timeout, true).await
    }
    /// Close admission, then perform a bounded full request drain.
    pub async fn shutdown(&self, timeout: Duration) -> Result<()> {
        self.request_shutdown();
        self.drain_requests(timeout).await
    }
    async fn drain(&self, timeout: Duration, all: bool) -> Result<()> {
        if !self.is_shutdown() {
            return Err(
                Error::Config("close command admission before draining requests".into()).boxed(),
            );
        }
        let deadline = crate::transport::checked_deadline(timeout, "command drain timeout")?;
        drain_retained(&self.inner, deadline, all).await
    }
}

fn close_application(inner: &AgentInner) {
    let _admission = inner.command_admission_gate.lock().unwrap();
    inner.command_stop.cancel();
    inner.cancel.cancel();
}

pub(super) fn outstanding_mutations(inner: &AgentInner) -> usize {
    inner
        .request_registry
        .lock()
        .unwrap()
        .tasks
        .values()
        .filter(|task| task.is_mutation())
        .count()
}

pub(super) async fn drain_retained(
    inner: &AgentInner,
    deadline: std::time::Instant,
    all: bool,
) -> Result<()> {
    loop {
        let notified = inner.task_changed.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        let (outstanding, mutation_failed) = {
            let registry = inner.request_registry.lock().unwrap();
            (
                registry
                    .tasks
                    .values()
                    .any(|task| all || !task.is_retrieval()),
                registry.mutation_failed,
            )
        };
        if !outstanding {
            if mutation_failed {
                return Err(Error::Config("retained mutation cleanup failed".into()).boxed());
            }
            return Ok(());
        }
        tokio::time::timeout_at(deadline.into(), notified)
            .await
            .map_err(|_| {
                Error::Config("mutation drain deadline expired; cleanup remains retained".into())
                    .boxed()
            })?;
    }
}

pub(super) fn validate_authorization(
    authorization: &AgentAuthorization,
    has_identities: bool,
) -> Result<()> {
    if matches!(authorization, AgentAuthorization::Conflict) {
        return Err(Error::Config(
            "VACM and unrestricted Agent access are mutually exclusive".into(),
        )
        .boxed());
    }
    if let AgentAuthorization::InvalidVacm(error) = authorization {
        return Err(Error::Config(error.to_string().into()).boxed());
    }
    if has_identities && matches!(authorization, AgentAuthorization::Unset) {
        return Err(Error::Config(
            "an Agent with inbound identities requires vacm() or allow_all_access()".into(),
        )
        .boxed());
    }
    Ok(())
}

pub(super) fn configure_vacm(
    authorization: AgentAuthorization,
    configure: impl FnOnce(VacmBuilder) -> VacmBuilder,
) -> AgentAuthorization {
    match authorization {
        AgentAuthorization::Unset
        | AgentAuthorization::Vacm(_)
        | AgentAuthorization::InvalidVacm(_) => match configure(VacmBuilder::new()).build() {
            Ok(config) => AgentAuthorization::Vacm(config),
            Err(error) => AgentAuthorization::InvalidVacm(error),
        },
        AgentAuthorization::AllowAll | AgentAuthorization::Conflict => AgentAuthorization::Conflict,
    }
}

pub(super) fn allow_all_access(authorization: AgentAuthorization) -> AgentAuthorization {
    match authorization {
        AgentAuthorization::Unset | AgentAuthorization::AllowAll => AgentAuthorization::AllowAll,
        _ => AgentAuthorization::Conflict,
    }
}

pub(super) struct ApplicationConfig {
    pub local_engine: crate::LocalEngine,
    pub security_context: crate::UsmSecurityContext,
    pub security_context_required: bool,
    pub communities: Vec<crate::Community>,
    pub handlers: Vec<RegisteredHandler>,
    pub authorization: AgentAuthorization,
    pub max_message_size: usize,
    pub decode_config: crate::DecodeConfig,
    pub concurrency_limit: Arc<Semaphore>,
    pub command_stop: CancellationToken,
    pub cancel: CancellationToken,
    pub request_deadline: Option<Duration>,
    pub disabled_builtins: HashSet<BuiltinMib>,
    pub discard_notifications: bool,
    pub trap_send_timeout: Duration,
    pub inform_timeout: Duration,
    pub inform_retry: crate::Retry,
    pub response_send_timeout: Duration,
    pub shutdown_policy: AgentShutdownPolicy,
    pub notification_fanout_limit: usize,
}

pub(super) fn prepare_application(mut config: ApplicationConfig) -> Arc<AgentInner> {
    let local_engine = config.local_engine;
    let security_context = config.security_context;
    let state = Arc::new(AgentState {
        local_engine,
        max_message_size: config.max_message_size,
        decode_config: config.decode_config,
    });

    // Register built-in handlers for any not disabled
    if !config.disabled_builtins.contains(&BuiltinMib::SnmpEngine) {
        config.handlers.push(RegisteredHandler {
            prefix: oid!(1, 3, 6, 1, 6, 3, 10, 2, 1),
            handler: Arc::new(builtins::SnmpEngineHandler {
                state: Arc::clone(&state),
            }),
        });
    }
    if !config.disabled_builtins.contains(&BuiltinMib::UsmStats) {
        config.handlers.push(RegisteredHandler {
            prefix: oid!(1, 3, 6, 1, 6, 3, 15, 1, 1),
            handler: Arc::new(builtins::UsmStatsHandler {
                state: Arc::clone(&state),
            }),
        });
    }
    if !config.disabled_builtins.contains(&BuiltinMib::MpdStats) {
        config.handlers.push(RegisteredHandler {
            prefix: oid!(1, 3, 6, 1, 6, 3, 11, 2, 1),
            handler: Arc::new(builtins::MpdStatsHandler {
                state: Arc::clone(&state),
            }),
        });
    }

    // Sort handlers by prefix length (longest first) for matching
    config
        .handlers
        .sort_by_key(|h| std::cmp::Reverse(h.prefix.len()));

    Arc::new(AgentInner {
        discard_notifications: config.discard_notifications,
        command_stop: config.command_stop,
        command_admission_gate: std::sync::Mutex::new(()),
        task_changed: Arc::new(tokio::sync::Notify::new()),
        communities: config.communities,
        security_context,
        security_context_required: config.security_context_required,
        handlers: config.handlers,
        state,
        set_coordinator: tokio::sync::Mutex::new(()),
        concurrency_limit: config.concurrency_limit,
        authorization: config.authorization,
        cancel: config.cancel,
        trap_send_timeout: config.trap_send_timeout,
        inform_timeout: config.inform_timeout,
        inform_retry: config.inform_retry,
        notification_id: std::sync::atomic::AtomicI32::new(1),
        run_active: AtomicBool::new(false),
        run_orphaned: AtomicBool::new(false),
        active_request_tasks: AtomicUsize::new(0),
        next_request_task_id: AtomicU64::new(1),
        request_registry: std::sync::Mutex::new(RequestRegistry::default()),
        response_send_timeout: config.response_send_timeout,
        request_deadline: config.request_deadline,
        shutdown_policy: config.shutdown_policy,
        notification_fanout_limit: config.notification_fanout_limit,
        #[cfg(test)]
        response_send_gate: std::sync::Mutex::new(None),
        #[cfg(test)]
        response_sends_started: AtomicU32::new(0),
        #[cfg(test)]
        received_datagrams: AtomicU32::new(0),
        #[cfg(test)]
        receive_errors: Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new())),
        #[cfg(test)]
        receive_attempts: Arc::new(AtomicU32::new(0)),
    })
}
