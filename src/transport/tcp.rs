//! Session-owned TCP framing, correlation and serialized complete-message writes.
//!
//! A session has one reader and one writer, driven by its owned [`TcpRunner`].
//! Requests register before entering the bounded write queue and validate
//! responses in their own futures. Cancellation removes a registration without
//! dropping the reader. Started writes finish under their original deadline or
//! close the session; messages never interleave. There is no reconnect or replay.
//!
//! [`TcpTransportBuilder::prepare`] performs setup without spawning. Supplied
//! streams retain their original Tokio registration and socket options. Explicit
//! spawn conveniences return a [`RunningTcpSession`] owner. `connect` conveniences
//! retain their task with the public session lifetime and expose [`TcpControl`].
//!
//! ```rust,no_run
//! use async_snmp::{Auth, ClientBuilder, TcpTransport};
//! # async fn example() -> async_snmp::Result<()> {
//! let prepared = TcpTransport::builder()
//!     .target("192.0.2.1:161".parse().unwrap()).prepare().await?;
//! let (session, runner) = prepared.into_parts();
//! let client = ClientBuilder::new(Auth::v2c("public")).build_with_transport(session)?;
//! let driver = tokio::spawn(runner.run());
//! # let _ = (client, driver);
//! # Ok(())
//! # }
//! ```

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::{Semaphore, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::{CancellationToken, DropGuard};

use super::framing::{BerFramer, BufferedFrame};
use super::udp_core::UdpCore;
use super::{Candidate, CorrelationEnvelope, RequestRegistration, RequestTransport};
use crate::error::{ConstructionStage, Error, Result};
use crate::message_size::ReceiveLimits;

const DEFAULT_MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

/// TCP frame, queue and execution limits. Limits are per session; listener
/// supervisors additionally bound the number and aggregate capacity of sessions.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct TcpOptions {
    /// Maximum complete incoming frame and advertised receive size; default 10 MiB.
    pub max_message_size: usize,
    /// Maximum exact outgoing message size; default 10 MiB.
    pub send_capacity: usize,
    /// Concurrent locally initiated exchanges; default 64. Waiting consumes the
    /// exchange's ordinary absolute deadline.
    pub max_in_flight: usize,
    /// Complete writes waiting for the writer; default 32.
    pub write_queue_capacity: usize,
    /// Aggregate buffered inbound/outbound bytes, including parked and validating
    /// candidates; default 32 MiB. Accepted caller-owned results are excluded.
    /// Must accommodate each configured message limit.
    pub max_buffered_bytes: usize,
    /// Complete a started BER header within this duration; default 5 seconds.
    pub header_timeout: Duration,
    /// Complete a declared BER body within this duration; default 30 seconds.
    pub body_timeout: Duration,
    /// Total queue/write budget for send-only operations, and upper bound for
    /// individual writes; default 5 seconds. Exchange deadlines may be shorter.
    pub write_timeout: Duration,
}
impl Default for TcpOptions {
    fn default() -> Self {
        Self {
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            send_capacity: DEFAULT_MAX_MESSAGE_SIZE,
            max_in_flight: 64,
            write_queue_capacity: 32,
            max_buffered_bytes: 32 * 1024 * 1024,
            header_timeout: Duration::from_secs(5),
            body_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(5),
        }
    }
}
impl TcpOptions {
    fn validate(&self) -> Result<ReceiveLimits> {
        let limits = ReceiveLimits::tcp(self.max_message_size)
            .map_err(|error| Error::Config(error.to_string().into()).boxed())?;
        if self.max_in_flight == 0
            || self.max_in_flight > Semaphore::MAX_PERMITS
            || self.write_queue_capacity == 0
            || self.write_queue_capacity > Semaphore::MAX_PERMITS
        {
            return Err(Error::Config(
                "TCP concurrency and queue capacities must be nonzero and representable".into(),
            )
            .boxed());
        }
        if self.max_buffered_bytes > u32::MAX as usize
            || self.max_buffered_bytes > Semaphore::MAX_PERMITS
            || self.max_buffered_bytes < self.max_message_size.max(self.send_capacity)
        {
            return Err(Error::Config(
                "TCP buffered-byte capacity must fit semaphore accounting and every message limit"
                    .into(),
            )
            .boxed());
        }
        for (duration, name) in [
            (self.header_timeout, "TCP header timeout"),
            (self.body_timeout, "TCP body timeout"),
            (self.write_timeout, "TCP write timeout"),
        ] {
            if duration.is_zero() {
                return Err(Error::Config(format!("{name} must be nonzero").into()).boxed());
            }
            tcp_deadline(duration, name)?;
        }
        Ok(limits)
    }
}

/// Prepare a connected or accepted TCP session. A supplied stream conflicts
/// with target, connect timeout and pre-connect socket configuration.
#[derive(Debug, Default)]
pub struct TcpTransportBuilder {
    target: Option<SocketAddr>,
    stream: Option<TcpStream>,
    socket: Option<TcpSocket>,
    connect_timeout: Option<Duration>,
    options: TcpOptions,
}
impl TcpTransportBuilder {
    /// Create default configuration.
    pub fn new() -> Self {
        Self::default()
    }
    /// Configure an outbound connection target.
    #[must_use]
    pub fn target(mut self, target: SocketAddr) -> Self {
        self.target = Some(target);
        self
    }
    /// Supply an owned connected or accepted stream without modifying its options.
    #[must_use]
    pub fn from_stream(mut self, stream: TcpStream) -> Self {
        self.stream = Some(stream);
        self
    }
    /// Supply a configured pre-connect socket. Also configure a target.
    #[must_use]
    pub fn from_socket(mut self, socket: TcpSocket) -> Self {
        self.socket = Some(socket);
        self
    }
    /// Configure all session limits.
    #[must_use]
    pub fn options(mut self, options: TcpOptions) -> Self {
        self.options = options;
        self
    }
    /// Bound initial connection establishment.
    #[must_use]
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = Some(timeout);
        self
    }
    /// Set complete incoming frame size and SNMPv3 receive advertisement.
    #[must_use]
    pub fn max_message_size(mut self, size: usize) -> Self {
        self.options.max_message_size = size;
        self
    }
    /// Set exact outgoing message capacity.
    #[must_use]
    pub fn send_capacity(mut self, size: usize) -> Self {
        self.options.send_capacity = size;
        self
    }
    /// Bound concurrent exchanges.
    #[must_use]
    pub fn max_in_flight(mut self, count: usize) -> Self {
        self.options.max_in_flight = count;
        self
    }
    /// Bound the writer queue.
    #[must_use]
    pub fn write_queue_capacity(mut self, count: usize) -> Self {
        self.options.write_queue_capacity = count;
        self
    }
    /// Bound owned message bytes across reads, candidates and writes.
    #[must_use]
    pub fn max_buffered_bytes(mut self, bytes: usize) -> Self {
        self.options.max_buffered_bytes = bytes;
        self
    }
    /// Bound completion of a started BER header.
    #[must_use]
    pub fn header_timeout(mut self, timeout: Duration) -> Self {
        self.options.header_timeout = timeout;
        self
    }
    /// Bound completion of a declared BER body.
    #[must_use]
    pub fn body_timeout(mut self, timeout: Duration) -> Self {
        self.options.body_timeout = timeout;
        self
    }
    /// Bound individual writes and default send-only operations.
    #[must_use]
    pub fn write_timeout(mut self, timeout: Duration) -> Self {
        self.options.write_timeout = timeout;
        self
    }

    /// Validate and establish initial resources, without creating background tasks.
    /// Packaging a registered supplied stream requires no entered Tokio runtime.
    pub async fn prepare(self) -> Result<PreparedTcpSession> {
        let started = Instant::now();
        let connect_deadline = self
            .connect_timeout
            .map(|duration| tcp_deadline(duration, "TCP connect timeout"))
            .transpose()?;
        let limits = self.options.validate()?;
        let stream = if let Some(stream) = self.stream {
            if self.target.is_some() || self.socket.is_some() || self.connect_timeout.is_some() {
                return Err(Error::Config(
                    "supplied TCP stream conflicts with target, socket or connect timeout".into(),
                )
                .boxed());
            }
            stream
        } else {
            let target = self.target.ok_or_else(|| {
                Error::Config("TCP target or connected stream is required".into()).boxed()
            })?;
            let connect = async {
                match self.socket {
                    Some(socket) => socket.connect(target).await,
                    None => TcpStream::connect(target).await,
                }
                .map_err(|source| Error::Network { target, source }.boxed())
            };
            if let Some(deadline) = connect_deadline {
                if Instant::now() >= deadline {
                    return Err(construction_timeout(target, started));
                }
                tokio::time::timeout_at(deadline, connect)
                    .await
                    .map_err(|_| construction_timeout(target, started))??
            } else {
                connect.await?
            }
        };
        let unknown = "0.0.0.0:0".parse().unwrap();
        let target = stream.peer_addr().map_err(|source| {
            Error::Network {
                target: unknown,
                source,
            }
            .boxed()
        })?;
        let local_addr = stream
            .local_addr()
            .map_err(|source| Error::Network { target, source }.boxed())?;
        let (writes, receiver) = mpsc::channel(self.options.write_queue_capacity);
        let state = Arc::new(SessionState {
            endpoint_id: crate::EndpointId::new(),
            session_id: crate::SessionId::new(),
            target,
            local_addr,
            receive_limits: limits,
            options: self.options.clone(),
            core: Arc::new(UdpCore::for_stream()),
            shutdown: CancellationToken::new(),
            complete: CancellationToken::new(),
            admission: Mutex::new(true),
            status: Mutex::new(TcpStatus::Prepared),
            terminal_error: Mutex::new(None),
            in_flight: Arc::new(Semaphore::new(self.options.max_in_flight)),
            budget: Arc::new(Semaphore::new(self.options.max_buffered_bytes)),
        });
        let transport = TcpTransport {
            inner: Arc::new(TcpTransportInner {
                _lease: state.shutdown.clone().drop_guard(),
                state: state.clone(),
                writes,
                task: tokio::sync::Mutex::new(None),
            }),
        };
        Ok(PreparedTcpSession {
            transport,
            runner: TcpRunner {
                stream,
                writes: receiver,
                cleanup: SessionCleanup(state),
            },
        })
    }
    /// Prepare and explicitly spawn the session on the current runtime.
    pub async fn spawn(self) -> Result<RunningTcpSession> {
        Ok(self.prepare().await?.spawn())
    }
    /// Prepare and spawn without migrating existing I/O registration.
    pub async fn spawn_on(self, runtime: &tokio::runtime::Handle) -> Result<RunningTcpSession> {
        Ok(self.prepare().await?.spawn_on(runtime))
    }
    /// Connect and retain the driver with the public session lifetime. Its result
    /// is observable through the returned handle's control.
    pub async fn connect(self, target: SocketAddr) -> Result<TcpTransport> {
        Ok(self.target(target).spawn().await?.into_managed())
    }
}

/// Cloneable handle to exactly one TCP session, whether accepted or connected.
/// A closed handle never connects again or selects another session by address.
#[derive(Clone)]
pub struct TcpTransport {
    inner: Arc<TcpTransportInner>,
}
struct TcpTransportInner {
    state: Arc<SessionState>,
    writes: mpsc::Sender<WriteCommand>,
    task: tokio::sync::Mutex<Option<JoinHandle<Result<()>>>>,
    _lease: DropGuard,
}
struct SessionState {
    endpoint_id: crate::EndpointId,
    session_id: crate::SessionId,
    target: SocketAddr,
    local_addr: SocketAddr,
    receive_limits: ReceiveLimits,
    options: TcpOptions,
    core: Arc<UdpCore>,
    shutdown: CancellationToken,
    complete: CancellationToken,
    admission: Mutex<bool>,
    status: Mutex<TcpStatus>,
    terminal_error: Mutex<Option<Arc<Error>>>,
    in_flight: Arc<Semaphore>,
    budget: Arc<Semaphore>,
}
impl SessionState {
    fn close(&self) {
        *self.admission.lock().unwrap() = false;
        self.shutdown.cancel();
        self.core.close();
    }
    fn closed_error(&self) -> Box<Error> {
        self.terminal_error.lock().unwrap().as_ref().map_or_else(
            || {
                Error::Closed {
                    target: self.target,
                }
                .boxed()
            },
            |source| {
                Error::SharedOperation {
                    source: source.clone(),
                }
                .boxed()
            },
        )
    }
    fn fail(&self, error: Box<Error>) -> Box<Error> {
        let error: Arc<Error> = error.into();
        *self.status.lock().unwrap() = TcpStatus::Failed(Arc::from(error.to_string()));
        *self.terminal_error.lock().unwrap() = Some(error.clone());
        self.close();
        Error::SharedOperation { source: error }.boxed()
    }
}
struct SessionCleanup(Arc<SessionState>);
impl Drop for SessionCleanup {
    fn drop(&mut self) {
        self.0.close();
        let mut status = self.0.status.lock().unwrap();
        if !matches!(*status, TcpStatus::Failed(_)) {
            *status = TcpStatus::Stopped;
        }
        self.0.complete.cancel();
    }
}

/// Coalesced session status, independent of response consumption.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TcpStatus {
    /// Prepared, with an unpolled runner.
    Prepared,
    /// Reader and writer are being driven.
    Running,
    /// Terminal, including runner drop or clean peer EOF.
    Stopped,
    /// Terminal framing or socket failure.
    Failed(Arc<str>),
}

/// Prepared session and its unstarted, single-use runner.
#[must_use = "drive or drop the runner"]
pub struct PreparedTcpSession {
    transport: TcpTransport,
    runner: TcpRunner,
}
impl PreparedTcpSession {
    /// Separate public lifetime ownership from driver ownership.
    pub fn into_parts(self) -> (TcpTransport, TcpRunner) {
        (self.transport, self.runner)
    }
    /// Spawn and retain a running owner.
    pub fn spawn(self) -> RunningTcpSession {
        self.spawn_on(&tokio::runtime::Handle::current())
    }
    /// Spawn without migrating the supplied stream's Tokio registration.
    pub fn spawn_on(self, runtime: &tokio::runtime::Handle) -> RunningTcpSession {
        let (transport, runner) = self.into_parts();
        RunningTcpSession {
            transport,
            task: Some(runtime.spawn(runner.run())),
        }
    }
}

/// Owned session driver. Its reader and writer are polled concurrently by one
/// supervisor future; there are no detached child tasks. Cleanup is owned before
/// `run` is polled, so abort or unpolled drop wakes pending exchanges.
#[must_use = "drive or drop the runner"]
pub struct TcpRunner {
    stream: TcpStream,
    writes: mpsc::Receiver<WriteCommand>,
    cleanup: SessionCleanup,
}
impl TcpRunner {
    /// Drive complete-message reads and serialized writes until terminal shutdown.
    /// The runtime owning the socket registration must remain alive and driven.
    pub async fn run(self) -> Result<()> {
        let Self {
            stream,
            writes,
            cleanup,
        } = self;
        let state = &cleanup.0;
        *state.status.lock().unwrap() = TcpStatus::Running;
        let (read, write) = stream.into_split();
        let result = tokio::select! {
            biased;
            () = state.shutdown.cancelled() => Ok(()),
            result = read_loop(read, state) => result,
            result = write_loop(write, writes, state) => result,
        };
        result.map_err(|error| state.fail(error))
    }
}

/// Running session owner. Drop requests shutdown; join observes its result.
#[must_use = "dropping the running owner requests shutdown"]
pub struct RunningTcpSession {
    transport: TcpTransport,
    task: Option<JoinHandle<Result<()>>>,
}
impl std::ops::Deref for RunningTcpSession {
    type Target = TcpTransport;
    fn deref(&self) -> &TcpTransport {
        &self.transport
    }
}
impl Drop for RunningTcpSession {
    fn drop(&mut self) {
        if self.task.is_some() {
            self.transport.control().request_shutdown();
        }
    }
}
impl RunningTcpSession {
    /// Clone a handle selecting this exact session.
    pub fn transport(&self) -> TcpTransport {
        self.transport.clone()
    }
    /// Access retained task status or abort it.
    pub fn task(&self) -> &JoinHandle<Result<()>> {
        self.task.as_ref().expect("running task retained")
    }
    /// Join without initiating shutdown.
    pub async fn join(mut self) -> Result<()> {
        let result = self.task.as_mut().expect("running task retained").await;
        self.task.take();
        join_result(result, self.peer_addr())
    }
    /// Request shutdown and join the driver.
    pub async fn shutdown(self) -> Result<()> {
        self.control().request_shutdown();
        self.join().await
    }
    fn into_managed(mut self) -> TcpTransport {
        *self
            .transport
            .inner
            .task
            .try_lock()
            .expect("new session task slot") = self.task.take();
        self.transport.clone()
    }
}

/// Cloneable lifecycle authority for one session.
#[derive(Clone)]
pub struct TcpControl {
    transport: TcpTransport,
}
impl TcpControl {
    /// Request terminal shutdown without waiting for an unpolled runner.
    pub fn request_shutdown(&self) {
        self.transport.inner.state.close();
    }
    /// Whether shutdown has been requested or the driver terminated.
    pub fn is_shutdown(&self) -> bool {
        self.transport.inner.state.shutdown.is_cancelled()
    }
    /// Observe current driver state.
    pub fn status(&self) -> TcpStatus {
        self.transport.inner.state.status.lock().unwrap().clone()
    }
    /// Wait for driver completion. An unstarted runner must be driven or dropped.
    pub async fn wait_closed(&self) {
        self.transport.inner.state.complete.cancelled().await;
    }
    /// Request shutdown and wait for completion.
    pub async fn shutdown(&self) {
        self.request_shutdown();
        self.wait_closed().await;
    }
    /// Join a driver retained by a connect convenience; explicit owners expose
    /// their own `join`. Errors remain visible in status after a previous join.
    pub async fn join(&self) -> Result<()> {
        let mut task = self.transport.inner.task.lock().await;
        if let Some(join) = task.as_mut() {
            let result = join.await;
            task.take();
            join_result(result, self.transport.peer_addr())
        } else {
            drop(task);
            self.wait_closed().await;
            let state = &self.transport.inner.state;
            if state.terminal_error.lock().unwrap().is_some() {
                Err(state.closed_error())
            } else {
                Ok(())
            }
        }
    }
}

impl TcpTransport {
    /// Configure a session from an outbound target or an owned stream.
    pub fn builder() -> TcpTransportBuilder {
        TcpTransportBuilder::new()
    }
    /// Connect with a driver retained for the public session lifetime.
    pub async fn connect(target: SocketAddr) -> Result<Self> {
        Self::builder().connect(target).await
    }
    /// Connect under a construction deadline.
    pub async fn connect_timeout(target: SocketAddr, timeout: Duration) -> Result<Self> {
        Self::builder()
            .connect_timeout(timeout)
            .connect(target)
            .await
    }
    /// Connect a configured socket and retain its driver. To drive it yourself,
    /// use `builder().from_socket(socket).target(target).prepare()`.
    pub async fn from_socket(
        socket: TcpSocket,
        target: SocketAddr,
        options: TcpOptions,
    ) -> Result<Self> {
        Self::builder()
            .from_socket(socket)
            .target(target)
            .options(options)
            .spawn()
            .await
            .map(RunningTcpSession::into_managed)
    }
    /// Identity of this connection; reconnects always have a different identity.
    pub fn session_id(&self) -> crate::SessionId {
        self.inner.state.session_id
    }
    /// Identity of the owning transport endpoint.
    pub fn endpoint_id(&self) -> crate::EndpointId {
        self.inner.state.endpoint_id
    }
    /// Acquire session-wide shutdown and result observation authority.
    pub fn control(&self) -> TcpControl {
        TcpControl {
            transport: self.clone(),
        }
    }

    async fn before<T>(
        &self,
        deadline: Instant,
        future: impl std::future::Future<Output = Result<T>>,
    ) -> Result<T> {
        let state = &self.inner.state;
        let started = Instant::now();
        if state.shutdown.is_cancelled() {
            return Err(state.closed_error());
        }
        if Instant::now() >= deadline {
            return Err(timeout_error(state.target, started.elapsed()));
        }
        tokio::select! {
            biased;
            result = future => result,
            () = state.shutdown.cancelled() => Err(state.closed_error()),
            () = tokio::time::sleep_until(deadline) => Err(timeout_error(state.target, started.elapsed())),
        }
    }

    async fn write_before(&self, data: &[u8], deadline: Instant) -> Result<()> {
        let state = &self.inner.state;
        let started = Instant::now();
        crate::message_size::enforce_outbound_size(data.len(), state.options.send_capacity)?;
        let cancelled = CancellationToken::new();
        let _cancel_on_drop = cancelled.clone().drop_guard();
        self.before(deadline, async {
            // Reserve a queue slot and byte budget before copying caller data.
            let slot = self
                .inner
                .writes
                .clone()
                .reserve_owned()
                .await
                .map_err(|_| state.closed_error())?;
            let budget = state
                .budget
                .clone()
                .acquire_many_owned(data.len() as u32)
                .await
                .map_err(|_| state.closed_error())?;
            let bytes = Bytes::from_owner(BufferedFrame {
                bytes: data.to_vec(),
                _permit: budget,
            });
            let (complete, result) = oneshot::channel();
            {
                let admission = state.admission.lock().unwrap();
                if !*admission || state.shutdown.is_cancelled() {
                    return Err(state.closed_error());
                }
                if Instant::now() >= deadline {
                    return Err(timeout_error(state.target, started.elapsed()));
                }
                slot.send(WriteCommand {
                    bytes,
                    started,
                    deadline,
                    cancelled,
                    complete,
                });
            }
            match result.await {
                Ok(result) => result,
                Err(_) => {
                    state.shutdown.cancelled().await;
                    Err(state.closed_error())
                }
            }
        })
        .await
    }
}

impl RequestTransport for TcpTransport {
    async fn send(&self, data: &[u8]) -> Result<()> {
        self.send_with_timeout(data, self.inner.state.options.write_timeout)
            .await
    }
    async fn send_with_timeout(&self, data: &[u8], duration: Duration) -> Result<()> {
        let deadline = tcp_deadline(duration, "TCP send timeout")?;
        self.write_before(data, deadline).await
    }
    async fn request_with<T, F>(
        &self,
        data: &[u8],
        registration: RequestRegistration,
        validate: F,
    ) -> Result<T>
    where
        T: Send,
        F: FnMut(Bytes, crate::ReceivedMessageInfo) -> Result<Candidate<T>> + Send,
    {
        let started = Instant::now();
        let result = async {
            let state = &self.inner.state;
            crate::message_size::enforce_outbound_size(data.len(), state.options.send_capacity)?;
            let deadline = registration.deadline();
            let _permit = self
                .before(deadline, async {
                    state
                        .in_flight
                        .clone()
                        .acquire_owned()
                        .await
                        .map_err(|_| state.closed_error())
                })
                .await?;
            let registration = {
                let admission = state.admission.lock().unwrap();
                if !*admission || state.shutdown.is_cancelled() {
                    return Err(state.closed_error());
                }
                state.core.register(registration, state.target, true)?
            };
            self.write_before(data, deadline).await?;
            // The core offers queued complete responses before closure, permitting a
            // final response followed immediately by peer EOF to complete normally.
            let result = state
                .core
                .wait_for_response_with(&registration, state.target, validate)
                .await;
            result.map_err(|error| {
                if matches!(*error, Error::Closed { .. }) {
                    state.closed_error()
                } else {
                    error
                }
            })
        }
        .await;
        result.map_err(|error| {
            if error.kind() == crate::ErrorKind::Timeout {
                timeout_error(self.peer_addr(), started.elapsed())
            } else {
                error
            }
        })
    }

    fn peer_addr(&self) -> SocketAddr {
        self.inner.state.target
    }
    fn local_addr(&self) -> SocketAddr {
        self.inner.state.local_addr
    }
    fn is_reliable(&self) -> bool {
        true
    }
    fn receive_limits(&self) -> ReceiveLimits {
        self.inner.state.receive_limits
    }
    fn send_capacity(&self) -> usize {
        self.inner.state.options.send_capacity
    }
}

struct WriteCommand {
    bytes: Bytes,
    started: Instant,
    deadline: Instant,
    cancelled: CancellationToken,
    complete: oneshot::Sender<Result<()>>,
}

async fn read_loop(mut read: tokio::net::tcp::OwnedReadHalf, state: &SessionState) -> Result<()> {
    let mut framer = BerFramer::new(
        state.receive_limits.accepted(),
        state.options.header_timeout,
        state.options.body_timeout,
        state.budget.clone(),
    );
    while let Some(frame) = framer.next(&mut read, state.target).await? {
        let super::framing::ReceivedFrame {
            bytes: frame,
            permit,
        } = frame;
        let info = crate::ReceivedMessageInfo::tcp(
            state.endpoint_id,
            state.session_id,
            state.local_addr,
            state.target,
            Instant::now(),
            frame.len(),
        );
        if let Some(envelope) = CorrelationEnvelope::parse(&frame)
            && let Some(id) = envelope.request_id(&frame)
        {
            state
                .core
                .deliver_parsed_buffered(id, envelope, frame, info, permit);
        } else {
            state.core.note_malformed();
        }
    }
    Ok(())
}

async fn write_loop(
    write: tokio::net::tcp::OwnedWriteHalf,
    mut receiver: mpsc::Receiver<WriteCommand>,
    state: &SessionState,
) -> Result<()> {
    'commands: while let Some(command) = receiver.recv().await {
        if command.cancelled.is_cancelled() {
            continue;
        }
        let deadline = command
            .deadline
            .min(Instant::now() + state.options.write_timeout);
        if Instant::now() >= deadline {
            let _ = command
                .complete
                .send(Err(timeout_error(state.target, command.started.elapsed())));
            continue;
        }
        let mut offset = 0;
        while offset < command.bytes.len() {
            let ready = tokio::select! {
                biased;
                () = command.cancelled.cancelled(), if offset == 0 => continue 'commands,
                result = tokio::time::timeout_at(deadline, write.writable()) => result,
            };
            match ready {
                Ok(Ok(())) => {}
                Ok(Err(source)) => {
                    return Err(Error::Network {
                        target: state.target,
                        source,
                    }
                    .boxed());
                }
                Err(_) if offset == 0 => {
                    let _ = command.complete.send(Err(timeout_error(
                        state.target,
                        state.options.write_timeout,
                    )));
                    continue 'commands;
                }
                Err(_) => return Err(timeout_error(state.target, command.started.elapsed())),
            }
            let admission = state.admission.lock().unwrap();
            if !*admission || state.shutdown.is_cancelled() {
                return Ok(());
            }
            if offset == 0 && command.cancelled.is_cancelled() {
                break;
            }
            if Instant::now() >= deadline {
                if offset == 0 {
                    let _ = command.complete.send(Err(timeout_error(
                        state.target,
                        state.options.write_timeout,
                    )));
                    continue 'commands;
                }
                return Err(timeout_error(state.target, command.started.elapsed()));
            }
            match write.try_write(&command.bytes[offset..]) {
                Ok(0) => {
                    return Err(Error::Network {
                        target: state.target,
                        source: std::io::Error::new(
                            std::io::ErrorKind::WriteZero,
                            "TCP frame write returned zero",
                        ),
                    }
                    .boxed());
                }
                Ok(written) => offset += written,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(source) => {
                    return Err(Error::Network {
                        target: state.target,
                        source,
                    }
                    .boxed());
                }
            }
        }
        if offset == command.bytes.len() {
            let _ = command.complete.send(Ok(()));
        }
    }
    Ok(())
}

fn tcp_deadline(duration: Duration, description: &str) -> Result<Instant> {
    Instant::now().checked_add(duration).ok_or_else(|| {
        Error::Config(format!("{description} exceeds the representable deadline").into()).boxed()
    })
}
fn timeout_error(target: SocketAddr, elapsed: Duration) -> Box<Error> {
    Error::Timeout {
        target,
        elapsed,
        retries: 0,
    }
    .boxed()
}
fn construction_timeout(target: SocketAddr, started: Instant) -> Box<Error> {
    Error::ConstructionTimeout {
        target: target.into(),
        stage: ConstructionStage::Connect,
        elapsed: started.elapsed(),
    }
    .boxed()
}
fn join_result(
    result: std::result::Result<Result<()>, tokio::task::JoinError>,
    target: SocketAddr,
) -> Result<()> {
    result.map_err(|source| {
        Error::Network {
            target,
            source: std::io::Error::other(source),
        }
        .boxed()
    })?
}

#[cfg(test)]
#[path = "tcp_tests.rs"]
mod tests;
