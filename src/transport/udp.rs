//! UDP transport for SNMP clients.
//!
//! Provides [`UdpEndpoint`] as the socket owner, [`UdpHandle`] as a per-target
//! [`RequestTransport`], and [`UdpControl`] as the explicit endpoint-wide lifecycle
//! authority.
//!
//! Preparation binds or accepts an owned socket without spawning. A prepared
//! endpoint separates into cloneable public handles and one owned [`UdpRunner`].
//! [`PreparedUdpEndpoint::spawn`] retains the runner's task in a
//! [`RunningUdpEndpoint`]; dropping that owner requests shutdown. The detached
//! runner path lets an application's supervisor own and join the task directly.
//!
//! ```rust,no_run
//! use async_snmp::{Auth, ClientBuilder, UdpEndpoint};
//! # async fn example() -> async_snmp::Result<()> {
//! let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
//! let (endpoint, runner) = UdpEndpoint::builder()
//!     .from_socket(socket).prepare().await?.into_parts();
//! let control = endpoint.control();
//! let client = ClientBuilder::new(Auth::v2c("public"))
//!     .build_with_transport(endpoint.handle("192.0.2.1:161".parse().unwrap())?)?;
//! let task = tokio::spawn(runner.run());
//! // Use client, then stop admission and observe completion.
//! control.request_shutdown();
//! task.await.expect("UDP driver task panicked")?;
//! # let _ = client;
//! # Ok(())
//! # }
//! ```
//!
//! # Response demultiplexing
//!
//! A single background task reads all datagrams from the socket. Each incoming
//! response is matched to its caller by extracting the request ID (or msgID for
//! `SNMPv3`) from the packet header and looking up the corresponding pending
//! request slot. V1/v2c slots additionally enforce the registered version and
//! community policy before consuming a response. The pending map is sharded by
//! request ID.
//!
//! `connect()` creates a dedicated UDP endpoint per client.
//! [`TargetClientBuilder::build_with`](crate::TargetClientBuilder::build_with)
//! instead accepts a preconstructed `UdpEndpoint` socket owner and derives a
//! per-target `UdpHandle`; it is distinct from target-free
//! [`ClientBuilder::build_with_transport`](crate::ClientBuilder::build_with_transport),
//! which accepts an arbitrary type that already implements `RequestTransport`. The
//! demultiplexing logic is the same in both UDP cases; sharing avoids
//! duplicating the socket and recv task.
//! Dedicated endpoints are drop-managed by default. Call
//! [`TargetClientBuilder::connect_with_control`](crate::TargetClientBuilder::connect_with_control)
//! or [`UdpEndpoint::control`] only when orderly endpoint-wide shutdown is
//! required.
//!
//! # Usage
//!
//! ```rust,no_run
//! use async_snmp::{Auth, Client};
//! use async_snmp::transport::UdpEndpoint;
//!
//! # async fn example() -> async_snmp::Result<()> {
//! // Simple: Client creates transport internally
//! let client = Client::builder("192.168.1.1:161", Auth::v2c("public"))
//!     .connect()
//!     .await?;
//!
//! // Shared: multiple clients on one socket
//! let transport = UdpEndpoint::spawn("0.0.0.0:0").await?;
//! let client1 = Client::builder("192.168.1.1:161", Auth::v2c("public"))
//!     .build_with(&transport).await?;
//! let client2 = Client::builder("192.168.1.2:161", Auth::v2c("public"))
//!     .build_with(&transport).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Address family
//!
//! Bind to `0.0.0.0:0` for IPv4-only targets, `[::]:0` for IPv6-only targets,
//! or `[::]:0` for mixed IPv4/IPv6 targets. When an IPv6 transport is given an
//! IPv4 target, the address is automatically mapped to an IPv4-mapped IPv6
//! address (`::ffff:x.x.x.x`). An IPv4 transport accepts IPv4 and mapped IPv6
//! targets, but rejects native IPv6 targets during handle construction. An
//! externally supplied IPv6-only socket also rejects IPv4 and mapped targets.

use super::udp_core::UdpCore;
pub use super::udp_core::UdpStats;
use super::udp_error::{UdpRecvErrorBackoff, UdpRecvErrorClass, classify_udp_recv_error};
use super::{
    Candidate, CorrelationEnvelope, RequestRegistration, RequestTransport, normalize_udp_target,
};
use crate::error::{Error, Result};
use crate::message_size::{ReceiveLimits, UDP_RECEIVE_BUFFER_SIZE};
use crate::util::bind_udp_socket;
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tokio_util::sync::{CancellationToken, DropGuard};

/// Configuration for UDP transport.
#[derive(Clone)]
struct UdpEndpointConfig {
    /// Local receive capacity advertised in SNMPv3 messages.
    local_receive_capacity: usize,
    max_inflight_requests: usize,
    /// Maximum exact encoded datagram size sent by this transport.
    send_capacity: usize,
    /// Log warning when response source differs from target (default: true)
    warn_on_source_mismatch: bool,
}

impl Default for UdpEndpointConfig {
    fn default() -> Self {
        Self {
            local_receive_capacity: 1472,
            max_inflight_requests: 1024,
            send_capacity: 1472,
            warn_on_source_mismatch: true,
        }
    }
}

/// UDP transport that can serve multiple targets.
///
/// Owns a single UDP socket. Its receiver is driven by a separate [`UdpRunner`].
/// Create [`UdpHandle`]s for each target via [`handle()`](Self::handle).
#[derive(Clone)]
pub struct UdpEndpoint {
    _service_lease: Option<Arc<dyn Send + Sync>>,
    inner: Arc<UdpEndpointInner>,
}

struct UdpEndpointInner {
    endpoint_id: crate::EndpointId,
    responder: Arc<crate::udp_responder::UdpResponder>,
    socket: Arc<UdpSocket>,
    local_addr: SocketAddr,
    core: Arc<UdpCore>,
    config: UdpEndpointConfig,
    receive_limits: ReceiveLimits,
    shutdown: CancellationToken,
    shutdown_complete: CancellationToken,
    operations: tokio::sync::RwLock<()>,
    request_admission: Arc<tokio::sync::Semaphore>,
    // Cancels the recv task when the last transport/handle reference drops.
    // The task itself must hold no strong reference to this struct, or the
    // guard would never fire.
    _shutdown_guard: DropGuard,
    recv_task: tokio::sync::Mutex<Option<JoinHandle<Result<()>>>>,
    admission: Arc<Mutex<bool>>,
    status: Arc<Mutex<UdpStatus>>,
    ipv6_only: bool,
    ingress: Option<super::ingress::ApplicationIngress>,
    dispatch: Arc<std::sync::OnceLock<Arc<super::dispatch::DispatchRoles>>>,
    #[cfg(test)]
    receive_errors: Arc<std::sync::Mutex<std::collections::VecDeque<std::io::Error>>>,
    #[cfg(test)]
    receive_error_ready: Arc<tokio::sync::Notify>,
}

#[cfg(not(test))]
async fn recv_datagram(
    socket: &UdpSocket,
    responder: &crate::udp_responder::UdpResponder,
    buf: &mut [u8],
) -> std::io::Result<crate::udp_responder::ReceivedDatagram> {
    responder.recv(socket, buf).await
}

#[cfg(test)]
async fn recv_datagram(
    socket: &UdpSocket,
    responder: &crate::udp_responder::UdpResponder,
    receive_errors: &std::sync::Mutex<std::collections::VecDeque<std::io::Error>>,
    receive_error_ready: &tokio::sync::Notify,
    buf: &mut [u8],
) -> std::io::Result<crate::udp_responder::ReceivedDatagram> {
    loop {
        if let Some(error) = receive_errors.lock().unwrap().pop_front() {
            return Err(error);
        }
        tokio::select! {
            result = responder.recv(socket, buf) => return result,
            () = receive_error_ready.notified() => {}
        }
    }
}

struct UdpRecvTaskCleanup {
    core: Arc<UdpCore>,
    shutdown_complete: CancellationToken,
    shutdown: CancellationToken,
    admission: Arc<Mutex<bool>>,
    status: Arc<Mutex<UdpStatus>>,
}

impl Drop for UdpRecvTaskCleanup {
    fn drop(&mut self) {
        *self.admission.lock().unwrap() = false;
        self.shutdown.cancel();
        self.core.close();
        let mut status = self.status.lock().unwrap();
        if !matches!(*status, UdpStatus::Failed(_)) {
            *status = UdpStatus::Stopped;
        }
        self.shutdown_complete.cancel();
    }
}

impl UdpEndpoint {
    /// Process-local identity of this bound endpoint.
    pub fn endpoint_id(&self) -> crate::EndpointId {
        self.inner.endpoint_id
    }
    #[cfg_attr(not(feature = "agent"), allow(dead_code))]
    pub(crate) fn with_service_lease(mut self, lease: Arc<dyn Send + Sync>) -> Self {
        self._service_lease = Some(lease);
        self
    }
    pub(crate) fn configure_dispatch(&self, roles: Arc<super::dispatch::DispatchRoles>) {
        assert!(
            self.inner.dispatch.set(roles).is_ok(),
            "endpoint roles configured once during preparation"
        );
    }
    #[cfg(test)]
    pub(crate) fn test_socket(&self) -> Arc<UdpSocket> {
        self.inner.socket.clone()
    }
    #[cfg(test)]
    pub(crate) fn test_responder(&self) -> Arc<crate::udp_responder::UdpResponder> {
        self.inner.responder.clone()
    }
    pub(crate) fn limits(&self) -> super::EndpointLimits {
        super::EndpointLimits {
            receive: self.inner.receive_limits,
            send: self.inner.config.send_capacity,
        }
    }

    /// Bind and explicitly start a receiver with default configuration.
    ///
    /// Use `0.0.0.0:0` for IPv4 targets or `[::]:0` for IPv6 targets.
    pub async fn spawn(addr: impl AsRef<str>) -> Result<RunningUdpEndpoint> {
        Self::builder().bind(addr).spawn().await
    }

    /// Create a builder for custom configuration.
    #[must_use]
    pub fn builder() -> UdpEndpointBuilder {
        UdpEndpointBuilder::new()
    }

    /// Create a handle for a specific target.
    ///
    /// Handles implement [`RequestTransport`] and can be used with [`Client`](crate::Client).
    ///
    /// When the transport is bound to an IPv6 socket and the target is IPv4,
    /// the target is automatically mapped to an IPv4-mapped IPv6 address
    /// (`::ffff:x.x.x.x`) for cross-platform dual-stack compatibility.
    /// IPv4-mapped IPv6 targets are converted back to IPv4 for IPv4 sockets.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] when an IPv4 socket is paired with a native
    /// IPv6 target, or an IPv6-only socket is paired with an IPv4/mapped target.
    pub fn handle(&self, target: SocketAddr) -> Result<UdpHandle> {
        let target = normalize_udp_target(self.inner.local_addr, target)?;
        if self.inner.ipv6_only && target.ip().to_canonical().is_ipv4() {
            return Err(
                Error::Config("IPv6-only UDP socket cannot address an IPv4 target".into()).boxed(),
            );
        }
        Ok(UdpHandle {
            _service_lease: self._service_lease.clone(),
            inner: self.inner.clone(),
            target,
            strict_source: false,
            #[cfg(test)]
            send_gate: None,
        })
    }

    /// Returns the local bind address.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr
    }

    /// Snapshot transport statistics.
    ///
    /// Returns cumulative counters for correlated, discarded, and malformed
    /// datagrams plus expired registrations.
    #[must_use]
    pub fn stats(&self) -> UdpStats {
        self.inner.core.stats()
    }

    /// Acquire endpoint-wide lifecycle authority.
    ///
    /// Shutdown through the returned [`UdpControl`] affects every transport,
    /// handle, and client sharing this socket. Per-target handles intentionally
    /// cannot acquire lifecycle authority.
    #[must_use]
    pub fn control(&self) -> UdpControl {
        UdpControl {
            _service_lease: self._service_lease.clone(),
            inner: Arc::clone(&self.inner),
        }
    }

    #[cfg(test)]
    fn inject_receive_error(&self, error: std::io::Error) {
        self.inner.receive_errors.lock().unwrap().push_back(error);
        self.inner.receive_error_ready.notify_one();
    }
}
/// Prepared endpoint with its single, unstarted receiver.
#[must_use = "the runner must be driven or dropped"]
pub struct PreparedUdpEndpoint {
    endpoint: UdpEndpoint,
    runner: UdpRunner,
}
impl PreparedUdpEndpoint {
    /// Separate public handles from the single-use I/O runner.
    pub fn into_parts(self) -> (UdpEndpoint, UdpRunner) {
        (self.endpoint, self.runner)
    }
    /// Start on the current runtime and retain the task result.
    pub fn spawn(self) -> RunningUdpEndpoint {
        self.spawn_on(&tokio::runtime::Handle::current())
    }
    /// Start on a runtime without moving the socket's original I/O registration.
    pub fn spawn_on(self, runtime: &tokio::runtime::Handle) -> RunningUdpEndpoint {
        let (endpoint, runner) = self.into_parts();
        RunningUdpEndpoint {
            endpoint,
            task: Some(runtime.spawn(runner.run())),
        }
    }
}

/// Coalesced UDP driver state, observable independently of a task join.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UdpStatus {
    /// Prepared; the runner has not been polled.
    Prepared,
    /// The receiver is running.
    Running,
    /// The receiver is terminal, including forced runner drop.
    Stopped,
    /// A fatal receive error terminated the receiver.
    Failed(Arc<str>),
}

/// Owned, single-use UDP receive driver. Dropping it closes the endpoint even
/// when `run()` has never been polled. Timers are created only when it runs.
#[must_use = "the runner must be driven or dropped"]
pub struct UdpRunner {
    socket: Arc<UdpSocket>,
    responder: Arc<crate::udp_responder::UdpResponder>,
    endpoint_id: crate::EndpointId,
    local_addr: SocketAddr,
    receive_limits: ReceiveLimits,
    cleanup: UdpRecvTaskCleanup,
    ingress: Option<super::ingress::ApplicationIngress>,
    dispatch: Arc<std::sync::OnceLock<Arc<super::dispatch::DispatchRoles>>>,
    send_capacity: usize,
    #[cfg(test)]
    receive_attempts: Option<Arc<std::sync::atomic::AtomicU32>>,
    #[cfg(test)]
    receive_errors: Arc<Mutex<std::collections::VecDeque<std::io::Error>>>,
    #[cfg(test)]
    receive_error_ready: Arc<tokio::sync::Notify>,
}
impl UdpRunner {
    #[cfg(test)]
    pub(crate) fn test_receive_faults(
        &mut self,
        errors: Arc<Mutex<std::collections::VecDeque<std::io::Error>>>,
        ready: Arc<tokio::sync::Notify>,
    ) {
        self.receive_errors = errors;
        self.receive_error_ready = ready;
    }
    #[cfg(test)]
    pub(crate) fn test_receive_state(
        &mut self,
        errors: Arc<Mutex<std::collections::VecDeque<std::io::Error>>>,
        attempts: Arc<std::sync::atomic::AtomicU32>,
    ) {
        self.receive_errors = errors;
        self.receive_attempts = Some(attempts);
    }

    fn new(inner: &UdpEndpointInner) -> Self {
        Self {
            socket: inner.socket.clone(),
            responder: inner.responder.clone(),
            endpoint_id: inner.endpoint_id,
            local_addr: inner.local_addr,
            receive_limits: inner.receive_limits,
            ingress: inner.ingress.clone(),
            dispatch: inner.dispatch.clone(),
            send_capacity: inner.config.send_capacity,
            #[cfg(test)]
            receive_attempts: None,
            cleanup: UdpRecvTaskCleanup {
                core: inner.core.clone(),
                shutdown_complete: inner.shutdown_complete.clone(),
                shutdown: inner.shutdown.clone(),
                admission: inner.admission.clone(),
                status: inner.status.clone(),
            },
            #[cfg(test)]
            receive_errors: inner.receive_errors.clone(),
            #[cfg(test)]
            receive_error_ready: inner.receive_error_ready.clone(),
        }
    }
    /// Run until shutdown or fatal endpoint failure. The socket remains registered
    /// with the runtime on which it was originally constructed; that runtime must
    /// remain alive and driven even if this future runs elsewhere.
    pub async fn run(self) -> Result<()> {
        *self.cleanup.status.lock().unwrap() = UdpStatus::Running;
        let result = self.receive().await;
        if let Err(error) = &result {
            *self.cleanup.status.lock().unwrap() = UdpStatus::Failed(error.to_string().into());
        }
        result
    }
    async fn receive(&self) -> Result<()> {
        let socket = &self.socket;
        let responder = &self.responder;
        let endpoint_id = self.endpoint_id;
        let local_addr = self.local_addr;
        let receive_limits = self.receive_limits;
        let core = &self.cleanup.core;
        let shutdown = &self.cleanup.shutdown;
        #[cfg(test)]
        let receive_errors = &self.receive_errors;
        #[cfg(test)]
        let receive_error_ready = &self.receive_error_ready;
        let mut buf = vec![0u8; UDP_RECEIVE_BUFFER_SIZE];
        let mut cleanup_interval = tokio::time::interval(Duration::from_secs(1));
        // Backoff applied after a recv error to avoid a hot spin when the
        // socket is in a persistent error state (e.g. ENOBUFS or a stream
        // of ICMP port-unreachable errors). Reset on any successful recv so
        // the normal success path is never delayed.
        let mut recv_error_backoff = UdpRecvErrorBackoff::default();
        let mut dispatch_tasks = tokio::task::JoinSet::new();

        loop {
            #[cfg(test)]
            if let Some(attempts) = &self.receive_attempts {
                attempts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            tokio::select! {
                biased;

                () = shutdown.cancelled() => {
                    tracing::debug!(target: "async_snmp::transport", { snmp.local_addr = %local_addr }, "UDP transport shutdown");
                    break;
                }

                joined = dispatch_tasks.join_next(), if !dispatch_tasks.is_empty() => {
                    if let Some(Err(error)) = joined { return Err(Error::Config(format!("UDP processing task failed: {error}").into()).boxed()); }
                },

                _ = cleanup_interval.tick() => {
                    core.cleanup_expired();
                }

                result = recv_datagram(
                    socket,
                    responder,
                    #[cfg(test)] receive_errors.as_ref(),
                    #[cfg(test)] receive_error_ready.as_ref(),
                    &mut buf,
                ) => {
                    match result {
                        Ok(received) => {
                            let len = received.len;
                            let source = received.source;
                            let info = crate::ReceivedMessageInfo::udp(endpoint_id, local_addr, source, received.destination.map(|d| d.ip), tokio::time::Instant::now(), len);
                            recv_error_backoff.reset();
                            if len > receive_limits.advertised().as_usize() {
                                tracing::debug!(target: "async_snmp::transport", { snmp.source = %source, received_size = len, advertised_size = receive_limits.advertised().as_usize() }, "accepted bounded UDP datagram above advertised capacity");
                            }
                            let data = Bytes::copy_from_slice(&buf[..len]);

                            if let Some(roles) = self.dispatch.get() {
                                let message = super::ReceivedMessage::udp(data, info, self.socket.clone(), self.responder.clone(), received, super::EndpointLimits { receive: receive_limits, send: self.send_capacity }).with_udp_admission(self.cleanup.admission.clone(), self.cleanup.shutdown.clone());
                                roles.dispatch(message, core.clone(), &mut dispatch_tasks);
                                continue;
                            }
                            if let Some(ingress) = &self.ingress {
                                ingress.deliver_udp(super::ReceivedMessage::udp(data, info, self.socket.clone(), self.responder.clone(), received, super::EndpointLimits { receive: receive_limits, send: self.send_capacity }).with_udp_admission(self.cleanup.admission.clone(), self.cleanup.shutdown.clone()));
                                continue;
                            }
                            if let Some(envelope) = CorrelationEnvelope::parse(&data)
                                && let Some(request_id) = envelope.request_id(&data)
                            {
                                if !core.deliver_parsed(request_id, envelope, data, info) {
                                    tracing::debug!(target: "async_snmp::transport", { snmp.request_id = request_id, snmp.source = %source }, "response for unknown request");
                                }
                            } else {
                                core.note_malformed();
                                tracing::debug!(target: "async_snmp::transport", { snmp.source = %source, snmp.bytes = len }, "malformed response (no request_id)");
                            }
                        }
                        Err(_) if shutdown.is_cancelled() => break,
                        Err(e) => match classify_udp_recv_error(&e) {
                            UdpRecvErrorClass::DatagramLocal => {
                                recv_error_backoff.reset();
                                tracing::warn!(target: "async_snmp::transport", { error = %e }, "discarding datagram with invalid receive metadata");
                            }
                            UdpRecvErrorClass::Transient => {
                                let delay = recv_error_backoff.advance();
                                tracing::warn!(target: "async_snmp::transport", { error = %e, backoff = ?delay }, "transient UDP recv error");
                                tokio::select! {
                                    biased;
                                    () = shutdown.cancelled() => break,
                                    () = tokio::time::sleep(delay) => {}
                                }
                            }
                            UdpRecvErrorClass::Fatal => {
                                tracing::error!(target: "async_snmp::transport", { error = %e }, "fatal UDP recv error");
                                return Err(Error::Network { target: local_addr, source: e }.boxed());
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

/// Running endpoint owner. Dropping it requests endpoint-wide shutdown.
/// Clone an endpoint/peer/control handle for use in other tasks; retain this
/// owner to observe the driver result with `join` or `shutdown`.
#[must_use = "dropping the running owner requests shutdown"]
pub struct RunningUdpEndpoint {
    endpoint: UdpEndpoint,
    task: Option<JoinHandle<Result<()>>>,
}
impl std::ops::Deref for RunningUdpEndpoint {
    type Target = UdpEndpoint;
    fn deref(&self) -> &Self::Target {
        &self.endpoint
    }
}
impl Drop for RunningUdpEndpoint {
    fn drop(&mut self) {
        if self.task.is_some() {
            self.endpoint.control().request_shutdown();
        }
    }
}
impl RunningUdpEndpoint {
    /// Clone the public endpoint handle without creating another reader.
    pub fn endpoint(&self) -> UdpEndpoint {
        self.endpoint.clone()
    }
    /// Access the retained task for abort and completion inspection.
    pub fn task(&self) -> &JoinHandle<Result<()>> {
        self.task.as_ref().expect("running task retained")
    }
    /// Join without requesting shutdown. Other handles may keep the service alive.
    pub async fn join(mut self) -> Result<()> {
        let result = self.task.as_mut().expect("running task retained").await;
        self.task.take();
        result.map_err(|error| {
            Error::Network {
                target: self.endpoint.local_addr(),
                source: std::io::Error::other(error),
            }
            .boxed()
        })?
    }
    /// Request shutdown and observe the terminal driver result.
    pub async fn shutdown(self) -> Result<()> {
        let control = self.control();
        control.request_shutdown();
        let result = self.join().await;
        control.wait_closed().await;
        result
    }
    // Dedicated client conveniences keep task ownership in the public lifetime
    // state, never in the driver. Controls can join it and the final public
    // handle still requests cancellation.
    pub(crate) fn into_managed(mut self) -> UdpEndpoint {
        *self
            .endpoint
            .inner
            .recv_task
            .try_lock()
            .expect("new endpoint task slot") = self.task.take();
        self.endpoint.clone()
    }
}

/// Builder for [`UdpEndpoint`].
pub struct UdpEndpointBuilder {
    bind_addr: Option<String>,
    socket: Option<UdpSocket>,
    config: UdpEndpointConfig,
    recv_buffer_size: Option<usize>,
    send_buffer_size: Option<usize>,
    ingress: Option<super::ingress::ApplicationIngress>,
}

impl UdpEndpointBuilder {
    #[cfg_attr(not(feature = "agent"), allow(dead_code))]
    pub(crate) fn ingress(mut self, ingress: super::ingress::ApplicationIngress) -> Self {
        self.ingress = Some(ingress);
        self
    }

    /// Create a builder with the default settings.
    ///
    /// Default bind address is `0.0.0.0:0` (IPv4).
    #[must_use]
    pub fn new() -> Self {
        Self {
            bind_addr: None,
            socket: None,
            config: UdpEndpointConfig::default(),
            recv_buffer_size: None,
            send_buffer_size: None,
            ingress: None,
        }
    }

    /// Bound concurrently registered exchanges (default 1024). Admission waits
    /// within the request's absolute deadline. Retries retain one permit until
    /// their correlation window ends, including between transmission attempts.
    #[must_use]
    pub fn max_inflight_requests(mut self, limit: usize) -> Self {
        self.config.max_inflight_requests = limit;
        self
    }

    /// Set the local bind address.
    #[must_use]
    pub fn bind(mut self, addr: impl AsRef<str>) -> Self {
        self.bind_addr = Some(addr.as_ref().to_string());
        self
    }

    /// Supply an owned, bound, unconnected Tokio socket. Its runtime registration
    /// and socket options are retained. Explicit bind/buffer options conflict.
    /// Destination-metadata collection is enabled where supported by the platform.
    #[must_use]
    pub fn from_socket(mut self, socket: UdpSocket) -> Self {
        self.socket = Some(socket);
        self
    }

    /// Set both local receive advertisement and outbound send capacity.
    ///
    /// The default for both is 1472 bytes. Prefer [`receive_capacity`](Self::receive_capacity)
    /// and [`send_capacity`](Self::send_capacity) when the two limits differ.
    #[must_use]
    pub fn max_message_size(mut self, size: usize) -> Self {
        self.config.local_receive_capacity = size;
        self.config.send_capacity = size;
        self
    }

    /// Set the local receive capacity advertised as SNMPv3 `msgMaxSize`.
    ///
    /// UDP still uses a bounded full-size receive buffer for compatibility, but
    /// does not advertise that additional tolerance.
    #[must_use]
    pub fn receive_capacity(mut self, size: usize) -> Self {
        self.config.local_receive_capacity = size;
        self
    }

    /// Set the maximum exact encoded datagram size sent by the transport.
    #[must_use]
    pub fn send_capacity(mut self, size: usize) -> Self {
        self.config.send_capacity = size;
        self
    }

    /// Configure warning on source address mismatch (default: true).
    #[must_use]
    pub fn warn_on_source_mismatch(mut self, warn: bool) -> Self {
        self.config.warn_on_source_mismatch = warn;
        self
    }

    /// Set the socket receive buffer size (`SO_RCVBUF`).
    ///
    /// When left unset, the OS default applies (typically 212KB on Linux).
    /// With a shared transport handling many targets, the default may be
    /// too small - if responses arrive faster than the recv loop processes
    /// them, the kernel drops datagrams. A rough guide: estimate peak
    /// inbound packets/sec, multiply by average response size (~200-500
    /// bytes for typical SNMP), and size the buffer for at least 500ms of
    /// burst capacity.
    ///
    /// The kernel may cap this at `net.core.rmem_max`. If you see
    /// unexplained timeouts under load, check for UDP buffer overflows
    /// with `cat /proc/net/snmp | grep Udp` (the `RcvbufErrors` column).
    #[must_use]
    pub fn recv_buffer_size(mut self, size: usize) -> Self {
        self.recv_buffer_size = Some(size);
        self
    }

    /// Set the socket send buffer size (`SO_SNDBUF`).
    ///
    /// The kernel may cap this at `net.core.wmem_max`.
    #[must_use]
    pub fn send_buffer_size(mut self, size: usize) -> Self {
        self.send_buffer_size = Some(size);
        self
    }

    /// Prepare resources without starting any background task. Supplied sockets
    /// can be packaged without an entered runtime. Binding a new socket requires
    /// an entered Tokio runtime and preserves that runtime's I/O registration.
    pub async fn prepare(self) -> Result<PreparedUdpEndpoint> {
        if self.config.max_inflight_requests == 0
            || self.config.max_inflight_requests > tokio::sync::Semaphore::MAX_PERMITS
        {
            return Err(Error::Config(
                "UDP max_inflight_requests must be nonzero and representable".into(),
            )
            .boxed());
        }
        // Validate before parsing or binding so invalid size configuration has
        // deterministic precedence and can never be narrowed on advertisement.
        let receive_limits = ReceiveLimits::udp(self.config.local_receive_capacity)
            .map_err(|error| Error::Config(error.to_string().into()).boxed())?;
        if self.config.send_capacity > crate::MAX_UDP_PAYLOAD {
            return Err(Error::Config(
                format!(
                    "UDP send capacity {} exceeds maximum payload {}",
                    self.config.send_capacity,
                    crate::MAX_UDP_PAYLOAD
                )
                .into(),
            )
            .boxed());
        }
        if self.socket.is_some()
            && (self.bind_addr.is_some()
                || self.recv_buffer_size.is_some()
                || self.send_buffer_size.is_some())
        {
            return Err(Error::Config(
                "supplied UDP socket conflicts with bind or kernel buffer options".into(),
            )
            .boxed());
        }
        let socket = match self.socket {
            Some(socket) => {
                if socket.peer_addr().is_ok() {
                    return Err(Error::Config(
                        "shared UDP endpoint requires an unconnected socket".into(),
                    )
                    .boxed());
                }
                socket
            }
            None => {
                let bind = self.bind_addr.as_deref().unwrap_or("0.0.0.0:0");
                let bind_addr: SocketAddr = bind
                    .parse()
                    .map_err(|_| Error::Config(format!("invalid bind address: {bind}").into()))?;
                bind_udp_socket(
                    bind_addr,
                    self.recv_buffer_size,
                    self.send_buffer_size,
                    true,
                )
                .await
                .map_err(|source| Error::Network {
                    target: bind_addr,
                    source,
                })?
            }
        };
        let local_addr = socket.local_addr().map_err(|source| Error::Network {
            target: "0.0.0.0:0".parse().unwrap(),
            source,
        })?;
        if local_addr.port() == 0 {
            return Err(Error::Config("UDP endpoint requires a bound socket".into()).boxed());
        }
        let ipv6_only = local_addr.is_ipv6()
            && socket2::SockRef::from(&socket)
                .only_v6()
                .map_err(|source| Error::Network {
                    target: local_addr,
                    source,
                })?;

        tracing::debug!(target: "async_snmp::transport", { snmp.local_addr = %local_addr }, "UDP transport bound");

        let shutdown = CancellationToken::new();
        let shutdown_complete = CancellationToken::new();
        let inner = Arc::new(UdpEndpointInner {
            endpoint_id: crate::EndpointId::new(),
            responder: Arc::new(crate::udp_responder::UdpResponder::new(&socket)),
            socket: Arc::new(socket),
            local_addr,
            core: Arc::new(UdpCore::new()),
            request_admission: Arc::new(tokio::sync::Semaphore::new(
                self.config.max_inflight_requests,
            )),
            config: self.config,
            receive_limits,
            _shutdown_guard: shutdown.clone().drop_guard(),
            shutdown,
            shutdown_complete,
            operations: tokio::sync::RwLock::new(()),
            recv_task: tokio::sync::Mutex::new(None),
            admission: Arc::new(Mutex::new(true)),
            status: Arc::new(Mutex::new(UdpStatus::Prepared)),
            ipv6_only,
            ingress: self.ingress,
            dispatch: Arc::new(std::sync::OnceLock::new()),
            #[cfg(test)]
            receive_errors: Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new())),
            #[cfg(test)]
            receive_error_ready: Arc::new(tokio::sync::Notify::new()),
        });

        let runner = UdpRunner::new(&inner);
        Ok(PreparedUdpEndpoint {
            endpoint: UdpEndpoint {
                inner,
                _service_lease: None,
            },
            runner,
        })
    }
    /// Prepare and start the same runner on the current runtime.
    pub async fn spawn(self) -> Result<RunningUdpEndpoint> {
        Ok(self.prepare().await?.spawn())
    }
    /// Prepare and start on `runtime`. Supplied socket registrations do not migrate.
    pub async fn spawn_on(self, runtime: &tokio::runtime::Handle) -> Result<RunningUdpEndpoint> {
        Ok(self.prepare().await?.spawn_on(runtime))
    }
}

/// Endpoint-wide UDP lifecycle authority.
///
/// This capability is cloneable. Every clone controls the same socket, and
/// shutdown is irreversible and idempotent. It affects all clients and handles
/// that share the endpoint, including clients for other targets.
#[derive(Clone)]
pub struct UdpControl {
    _service_lease: Option<Arc<dyn Send + Sync>>,
    inner: Arc<UdpEndpointInner>,
}

impl UdpControl {
    /// Snapshot cumulative endpoint statistics.
    ///
    /// Statistics remain readable after shutdown.
    #[must_use]
    pub fn stats(&self) -> UdpStats {
        self.inner.core.stats()
    }

    /// Return whether endpoint shutdown has been requested.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.inner.shutdown.is_cancelled()
    }

    /// Observe driver state, including fatal endpoint errors.
    pub fn status(&self) -> UdpStatus {
        self.inner.status.lock().unwrap().clone()
    }

    /// Stop new operations and request receiver termination without waiting.
    pub fn request_shutdown(&self) {
        *self.inner.admission.lock().unwrap() = false;
        self.inner.shutdown.cancel();
        self.inner.core.close();
    }

    /// Wait for driver termination and operations to leave. An unpolled runner
    /// must be driven or dropped; requesting shutdown alone cannot drop it.
    pub async fn wait_closed(&self) {
        self.inner.shutdown_complete.cancelled().await;
        let _operations = self.inner.operations.write().await;
    }

    /// Join the retained driver of a dedicated client convenience. Explicitly
    /// spawned services retain their result in `RunningUdpEndpoint::join`.
    pub async fn join(&self) -> Result<()> {
        let mut task = self.inner.recv_task.lock().await;
        if let Some(join) = task.as_mut() {
            let result = join.await;
            task.take();
            result.map_err(|error| {
                Error::Network {
                    target: self.inner.local_addr,
                    source: std::io::Error::other(error),
                }
                .boxed()
            })?
        } else {
            drop(task);
            self.wait_closed().await;
            match self.status() {
                UdpStatus::Failed(message) => Err(Error::Network {
                    target: self.inner.local_addr,
                    source: std::io::Error::other(message.to_string()),
                }
                .boxed()),
                _ => Ok(()),
            }
        }
    }

    /// Irreversibly shut down the entire UDP endpoint.
    ///
    /// The runner must be driven or dropped for this wait to complete.
    ///
    /// Pending operations on every client are woken. When this method returns,
    /// no operation that began before cancellation remains active, and future
    /// sends, requests, and receives fail with [`Error::Closed`] before request
    /// registration or socket I/O. Concurrent and repeated calls are safe.
    pub async fn shutdown(&self) {
        self.request_shutdown();
        self.wait_closed().await;
    }
}

impl Default for UdpEndpointBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Handle to a UDP transport for a specific target.
///
/// Implements [`RequestTransport`] and can be used with [`Client`](crate::Client).
/// Cheap to clone (Arc + `SocketAddr`).
///
/// Handles expose endpoint observation but not lifecycle authority:
///
/// ```compile_fail
/// async fn invalid(handle: async_snmp::UdpHandle) {
///     let _control = handle.control();
///     handle.shutdown().await;
/// }
/// ```
#[derive(Clone)]
pub struct UdpHandle {
    _service_lease: Option<Arc<dyn Send + Sync>>,
    inner: Arc<UdpEndpointInner>,
    target: SocketAddr,
    strict_source: bool,
    #[cfg(test)]
    send_gate: Option<Arc<tokio::sync::Semaphore>>,
}

impl UdpHandle {
    /// Identity of the owning UDP endpoint.
    pub fn endpoint_id(&self) -> crate::EndpointId {
        self.inner.endpoint_id
    }
    /// Snapshot cumulative statistics for this handle's UDP endpoint.
    ///
    /// The counters are shared by all handles and clients using the socket and
    /// remain readable after endpoint shutdown.
    #[must_use]
    pub fn stats(&self) -> UdpStats {
        self.inner.core.stats()
    }

    /// Require responses to originate from this handle's target address.
    ///
    /// By default (false), a source mismatch does not reject a response (see
    /// [`warn_on_source_mismatch`](UdpEndpointBuilder::warn_on_source_mismatch)),
    /// because multihomed agents may legitimately reply from a different
    /// address. When enabled, a response from any other address is dropped
    /// (counted as `discarded_datagrams` in [`UdpStats`]) and the request keeps
    /// waiting for a response from the target.
    #[must_use]
    pub fn strict_source(mut self, strict: bool) -> Self {
        self.strict_source = strict;
        self
    }
}

impl RequestTransport for UdpHandle {
    async fn send(&self, data: &[u8]) -> Result<()> {
        crate::message_size::enforce_outbound_size(data.len(), self.send_capacity())?;
        let _operation = self.inner.operations.read().await;
        self.ensure_open()?;
        self.send_datagram(data).await
    }

    async fn request_with<T, F>(
        &self,
        data: &[u8],
        mut registration: RequestRegistration,
        validate: F,
    ) -> Result<T>
    where
        T: Send,
        F: FnMut(Bytes, crate::ReceivedMessageInfo) -> Result<Candidate<T>> + Send,
    {
        crate::message_size::enforce_outbound_size(data.len(), self.send_capacity())?;
        let _operation = self.inner.operations.read().await;
        self.ensure_open()?;

        if let Some(roles) = self.inner.dispatch.get() {
            roles.validate_registration(&registration)?;
        } else if self.inner.ingress.is_some() {
            return Err(Error::Config(
                "client exchanges were not enabled during endpoint preparation".into(),
            )
            .boxed());
        }

        // Admission is owned by the registration/window, not this attempt's
        // future, so retry retention cannot grow the pending map beyond its bound.
        let admitted_at = tokio::time::Instant::now();
        let acquire = async {
            if let Some(window) = registration.correlation_window() {
                let mut admission = window.udp_admission.lock().await;
                if let Some(permit) = admission.get(&self.inner.endpoint_id) {
                    return permit.clone();
                }
                let permit = Arc::new(
                    self.inner
                        .request_admission
                        .clone()
                        .acquire_owned()
                        .await
                        .expect("request admission is never closed"),
                );
                admission.insert(self.inner.endpoint_id, permit.clone());
                permit
            } else {
                Arc::new(
                    self.inner
                        .request_admission
                        .clone()
                        .acquire_owned()
                        .await
                        .expect("request admission is never closed"),
                )
            }
        };
        registration.udp_admission = Some(tokio::select! {
            biased;
            () = self.inner.shutdown.cancelled() => return Err(Error::Closed { target: self.target }.boxed()),
            () = tokio::time::sleep_until(registration.deadline()) => return Err(Error::Timeout { target: self.target, elapsed: admitted_at.elapsed(), retries: 0 }.boxed()),
            permit = acquire => permit,
        });
        let registration =
            self.inner
                .core
                .register(registration, self.target, self.strict_source)?;
        let deadline = registration.deadline();
        if tokio::time::Instant::now() >= deadline {
            return Err(registration.timeout_error(self.target));
        }
        tokio::select! {
            biased;
            () = tokio::time::sleep_until(deadline) => {
                tracing::debug!(target: "async_snmp::transport::udp", { request_id = registration.request_id(), target = %self.target }, "transport timeout during UDP send");
                return Err(registration.timeout_error(self.target));
            }
            result = self.send_datagram(data) => result?,
        }
        self.recv_registered_with(&registration, validate).await
    }

    fn peer_addr(&self) -> SocketAddr {
        self.target
    }

    fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr
    }

    fn receive_limits(&self) -> ReceiveLimits {
        self.inner.receive_limits
    }

    fn send_capacity(&self) -> usize {
        self.inner.config.send_capacity
    }

    fn is_reliable(&self) -> bool {
        false
    }
}

impl UdpHandle {
    fn ensure_open(&self) -> Result<()> {
        if self.inner.shutdown.is_cancelled() {
            return Err(Error::Closed {
                target: self.target,
            }
            .boxed());
        }
        Ok(())
    }

    async fn send_datagram(&self, data: &[u8]) -> Result<()> {
        crate::message_size::enforce_outbound_size(data.len(), self.send_capacity())?;
        #[cfg(test)]
        if let Some(gate) = &self.send_gate {
            tokio::select! {
                biased;
                () = self.inner.shutdown.cancelled() => return Err(Error::Closed { target: self.target }.boxed()),
                permit = gate.acquire() => permit.expect("test send gate remains open").forget(),
            }
        }
        loop {
            tokio::select! {
                biased;
                () = self.inner.shutdown.cancelled() => return Err(Error::Closed { target: self.target }.boxed()),
                result = self.inner.socket.writable() => result.map_err(|source| Error::Network { target: self.target, source })?,
            }
            let admission = self.inner.admission.lock().unwrap();
            if !*admission {
                return Err(Error::Closed {
                    target: self.target,
                }
                .boxed());
            }
            match self.inner.socket.try_send_to(data, self.target) {
                Ok(_) => break,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(source) => {
                    return Err(Error::Network {
                        target: self.target,
                        source,
                    }
                    .boxed());
                }
            }
        }
        Ok(())
    }
    #[cfg(test)]
    async fn recv_registered(
        &self,
        registration: &super::udp_core::UdpRegistration,
    ) -> Result<(Bytes, SocketAddr)> {
        self.recv_registered_with(registration, |data, source| {
            Ok(Candidate::Accept((data, source.peer_addr())))
        })
        .await
    }

    async fn recv_registered_with<T, F>(
        &self,
        registration: &super::udp_core::UdpRegistration,
        mut validate: F,
    ) -> Result<T>
    where
        F: FnMut(Bytes, crate::ReceivedMessageInfo) -> Result<Candidate<T>>,
    {
        let request_id = registration.request_id();
        tracing::trace!(target: "async_snmp::transport", { snmp.target = %self.target, snmp.request_id = request_id }, "UDP recv waiting");

        let result = self
            .inner
            .core
            .wait_for_response_with(registration, self.target, |data, info| {
                let source = info.peer_addr();
                if self.inner.config.warn_on_source_mismatch && source != self.target {
                    tracing::warn!(target: "async_snmp::transport", { snmp.request_id = request_id, snmp.target = %self.target, snmp.source = %source }, "response source address mismatch");
                }
                tracing::trace!(target: "async_snmp::transport", { snmp.target = %self.target, snmp.source = %source, snmp.bytes = data.len() }, "UDP recv candidate");
                validate(data, info)
            })
            .await;

        if result.is_err() {
            tracing::trace!(target: "async_snmp::transport", { snmp.target = %self.target, snmp.request_id = request_id }, "UDP recv failed");
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Auth, Client, Retry, oid};

    #[tokio::test]
    async fn bounded_registration_admission_retains_retry_window_and_honors_deadline() {
        let service = UdpEndpoint::builder()
            .bind("127.0.0.1:0")
            .max_inflight_requests(1)
            .spawn()
            .await
            .unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let handle = service.handle(peer.local_addr().unwrap()).unwrap();
        let window = super::super::CorrelationWindow::new();
        let first = RequestRegistration::v3(1, deadline_after(Duration::from_secs(3)))
            .with_correlation_window(window.clone());
        let mut pending =
            Box::pin(handle.request_with(b"first", first, |_, _| Ok(Candidate::Accept(()))));
        let mut buffer = [0; 64];
        tokio::select! {
            result = &mut pending => panic!("request completed before peer received it: {result:?}"),
            result = tokio::time::timeout(Duration::from_secs(1), peer.recv(&mut buffer)) => { result.unwrap().unwrap(); }
        }
        drop(pending);
        assert_eq!(service.inner.request_admission.available_permits(), 0);
        let error = handle
            .request_with(
                b"blocked",
                RequestRegistration::v3(2, deadline_after(Duration::from_millis(20))),
                |_, _| Ok(Candidate::Accept(())),
            )
            .await
            .unwrap_err();
        assert!(matches!(*error, Error::Timeout { .. }));
        assert_eq!(service.inner.core.pending_counts(), (1, 0));
        let retry = RequestRegistration::v3(3, deadline_after(Duration::from_secs(3)))
            .with_correlation_window(window.clone())
            .with_aliases([1])
            .unwrap();
        let mut retrying =
            Box::pin(handle.request_with(b"retry", retry, |_, _| Ok(Candidate::Accept(()))));
        let n = tokio::select! {
            result = &mut retrying => panic!("retry completed before peer received it: {result:?}"),
            result = tokio::time::timeout(Duration::from_secs(1), peer.recv(&mut buffer)) => result.unwrap().unwrap(),
        };
        assert_eq!(&buffer[..n], b"retry");
        drop(retrying);
        drop(window);
        assert_eq!(service.inner.request_admission.available_permits(), 1);
        assert_eq!(service.inner.core.pending_counts(), (0, 0));
        service.shutdown().await.unwrap();
    }

    fn deadline_after(timeout: Duration) -> tokio::time::Instant {
        tokio::time::Instant::now() + timeout
    }

    fn v3_identity(msg_id: u8) -> Bytes {
        Bytes::from(vec![
            0x30, 0x08, 0x02, 0x01, 0x03, 0x30, 0x03, 0x02, 0x01, msg_id,
        ])
    }

    fn register_v3(
        handle: &UdpHandle,
        request_id: i32,
        timeout: Duration,
    ) -> super::super::udp_core::UdpRegistration {
        handle
            .inner
            .core
            .register(
                RequestRegistration::test_unchecked(request_id, timeout),
                handle.target,
                handle.strict_source,
            )
            .unwrap()
    }

    static_assertions::assert_impl_all!(UdpRunner: Send);
    static_assertions::assert_not_impl_any!(UdpRunner: Clone);

    #[tokio::test]
    async fn abort_before_first_poll_and_task_panic_release_runner_ownership() {
        for panic_task in [false, true] {
            let (endpoint, runner) = UdpEndpoint::builder().prepare().await.unwrap().into_parts();
            let control = endpoint.control();
            let task = if panic_task {
                tokio::spawn(async move {
                    let _runner = runner;
                    panic!("injected task panic");
                    #[allow(unreachable_code)]
                    Ok::<(), Box<Error>>(())
                })
            } else {
                let task = tokio::spawn(runner.run());
                task.abort();
                task
            };
            assert!(task.await.is_err());
            tokio::time::timeout(Duration::from_secs(1), control.wait_closed())
                .await
                .unwrap();
            assert!(control.is_shutdown());
        }
    }

    #[tokio::test]
    async fn retained_control_keeps_detached_endpoint_alive() {
        let (endpoint, runner) = UdpEndpoint::builder().prepare().await.unwrap().into_parts();
        let control = endpoint.control();
        let task = tokio::spawn(runner.run());
        drop(endpoint);
        tokio::task::yield_now().await;
        assert!(!task.is_finished());
        drop(control);
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[test]
    fn spawning_elsewhere_does_not_migrate_socket_registration() {
        let origin = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let socket = origin.block_on(UdpSocket::bind("127.0.0.1:0")).unwrap();
        let prepared =
            futures::executor::block_on(UdpEndpoint::builder().from_socket(socket).prepare())
                .unwrap();
        drop(origin);
        let execution = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let service = prepared.spawn_on(execution.handle());
        let control = service.control();
        execution.block_on(async {
            let error = tokio::time::timeout(Duration::from_secs(1), service.join())
                .await
                .unwrap()
                .unwrap_err();
            assert!(matches!(*error, Error::Network { .. }));
            assert!(control.is_shutdown());
        });
    }

    #[tokio::test]
    async fn preparation_does_not_receive_until_runner_starts() {
        let (endpoint, runner) = UdpEndpoint::builder()
            .bind("127.0.0.1:0")
            .prepare()
            .await
            .unwrap()
            .into_parts();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender
            .send_to(b"malformed", endpoint.local_addr())
            .await
            .unwrap();
        tokio::task::yield_now().await;
        assert_eq!(endpoint.control().status(), UdpStatus::Prepared);
        assert_eq!(endpoint.stats().malformed_datagrams, 0);
        let task = tokio::spawn(runner.run());
        tokio::time::timeout(Duration::from_secs(1), async {
            while endpoint.stats().malformed_datagrams == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        endpoint.control().shutdown().await;
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn unpolled_runner_and_unpolled_run_future_close_sends() {
        for as_future in [false, true] {
            let (endpoint, runner) = UdpEndpoint::builder().prepare().await.unwrap().into_parts();
            let handle = endpoint.handle("127.0.0.1:161".parse().unwrap()).unwrap();
            if as_future {
                drop(runner.run());
            } else {
                drop(runner);
            }
            endpoint.control().wait_closed().await;
            assert!(endpoint.control().is_shutdown());
            assert!(matches!(
                *handle.send(b"data").await.unwrap_err(),
                Error::Closed { .. }
            ));
            assert!(matches!(
                *handle
                    .request_with(
                        b"data",
                        RequestRegistration::v3(1, deadline_after(Duration::from_secs(1))),
                        |_, _| Ok(Candidate::Accept(()))
                    )
                    .await
                    .unwrap_err(),
                Error::Closed { .. }
            ));
        }
    }

    #[tokio::test]
    async fn shutdown_before_start_requires_runner_drop_or_execution() {
        let (endpoint, runner) = UdpEndpoint::builder().prepare().await.unwrap().into_parts();
        let control = endpoint.control();
        control.request_shutdown();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), control.wait_closed())
                .await
                .is_err()
        );
        drop(runner);
        control.wait_closed().await;
        assert_eq!(control.status(), UdpStatus::Stopped);
        let (endpoint, runner) = UdpEndpoint::builder().prepare().await.unwrap().into_parts();
        endpoint.control().request_shutdown();
        runner.run().await.unwrap();
        endpoint.control().wait_closed().await;
    }

    #[tokio::test]
    async fn pending_prestart_request_uses_ordinary_deadline() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (endpoint, runner) = UdpEndpoint::builder().prepare().await.unwrap().into_parts();
        let handle = endpoint.handle(peer.local_addr().unwrap()).unwrap();
        let error = handle
            .request_with(
                b"data",
                RequestRegistration::v3(1, deadline_after(Duration::from_millis(10))),
                |_, _| Ok(Candidate::Accept(())),
            )
            .await
            .unwrap_err();
        assert!(matches!(*error, Error::Timeout { .. }));
        let mut bytes = [0; 16];
        assert_eq!(peer.recv_from(&mut bytes).await.unwrap().0, 4);
        drop(runner);
    }

    #[tokio::test]
    async fn task_abort_wakes_pending_request_and_stops_plain_sends() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let service = UdpEndpoint::spawn("127.0.0.1:0").await.unwrap();
        let handle = service.handle(peer.local_addr().unwrap()).unwrap();
        let pending_handle = handle.clone();
        let pending = tokio::spawn(async move {
            pending_handle
                .request_with(
                    b"request",
                    RequestRegistration::v3(1, deadline_after(Duration::from_secs(30))),
                    |_, _| Ok(Candidate::Accept(())),
                )
                .await
        });
        let mut bytes = [0; 32];
        peer.recv_from(&mut bytes).await.unwrap();
        service.task().abort();
        service.control().wait_closed().await;
        assert!(matches!(
            *pending.await.unwrap().unwrap_err(),
            Error::Closed { .. }
        ));
        assert!(matches!(
            *handle.send(b"after abort").await.unwrap_err(),
            Error::Closed { .. }
        ));
        assert!(service.join().await.is_err());
        assert!(
            tokio::time::timeout(Duration::from_millis(10), peer.recv_from(&mut bytes))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn running_owner_drop_requests_shutdown_with_retained_control() {
        let service = UdpEndpoint::spawn("127.0.0.1:0").await.unwrap();
        let control = service.control();
        let handle = service.handle("127.0.0.1:161".parse().unwrap()).unwrap();
        drop(service);
        assert!(control.is_shutdown());
        control.wait_closed().await;
        assert!(matches!(
            *handle.send(b"data").await.unwrap_err(),
            Error::Closed { .. }
        ));
    }

    #[tokio::test]
    async fn fatal_receive_returns_error_and_closes_plain_send_admission() {
        let service = UdpEndpoint::spawn("127.0.0.1:0").await.unwrap();
        let control = service.control();
        let handle = service.handle("127.0.0.1:161".parse().unwrap()).unwrap();
        service.inject_receive_error(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "injected fatal receive",
        ));
        let error = service.join().await.unwrap_err();
        assert!(matches!(*error, Error::Network { .. }));
        assert!(matches!(control.status(), UdpStatus::Failed(_)));
        assert!(matches!(
            *handle.send(b"data").await.unwrap_err(),
            Error::Closed { .. }
        ));
    }

    #[tokio::test]
    async fn supplied_socket_preserves_options_and_rejects_conflicting_configuration() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.set_ttl(37).unwrap();
        socket.set_broadcast(true).unwrap();
        let bound = socket.local_addr().unwrap();
        let (endpoint, runner) = UdpEndpoint::builder()
            .from_socket(socket)
            .prepare()
            .await
            .unwrap()
            .into_parts();
        assert_eq!(endpoint.local_addr(), bound);
        assert_eq!(endpoint.inner.socket.ttl().unwrap(), 37);
        assert!(endpoint.inner.socket.broadcast().unwrap());
        drop(runner);
        for option in 0..3 {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let builder = UdpEndpoint::builder().from_socket(socket);
            let builder = match option {
                0 => builder.bind("127.0.0.1:0"),
                1 => builder.recv_buffer_size(4096),
                _ => builder.send_buffer_size(4096),
            };
            assert!(matches!(
                *builder.prepare().await.err().unwrap(),
                Error::Config(_)
            ));
        }
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.connect("127.0.0.1:161").await.unwrap();
        assert!(matches!(
            *UdpEndpoint::builder()
                .from_socket(socket)
                .prepare()
                .await
                .err()
                .unwrap(),
            Error::Config(_)
        ));
    }

    #[tokio::test]
    async fn supplied_unbound_socket_is_rejected_before_execution() {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .unwrap();
        socket.set_nonblocking(true).unwrap();
        let socket = UdpSocket::from_std(socket.into()).unwrap();
        assert_eq!(socket.local_addr().unwrap().port(), 0);
        let error = UdpEndpoint::builder()
            .from_socket(socket)
            .prepare()
            .await
            .err()
            .unwrap();
        assert!(matches!(*error, Error::Config(_)));
        assert!(error.to_string().contains("bound socket"));
    }

    #[tokio::test]
    async fn supplied_ipv6_only_socket_rejects_ipv4_targets() {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .unwrap();
        socket.set_only_v6(true).unwrap();
        socket.set_nonblocking(true).unwrap();
        socket
            .bind(&"[::]:0".parse::<SocketAddr>().unwrap().into())
            .unwrap();
        let socket = UdpSocket::from_std(socket.into()).unwrap();
        let (endpoint, _runner) = UdpEndpoint::builder()
            .from_socket(socket)
            .prepare()
            .await
            .unwrap()
            .into_parts();
        assert!(endpoint.handle("127.0.0.1:161".parse().unwrap()).is_err());
        assert!(
            endpoint
                .handle("[::ffff:127.0.0.1]:161".parse().unwrap())
                .is_err()
        );
        assert!(endpoint.handle("[::1]:161".parse().unwrap()).is_ok());
    }

    #[test]
    fn supplied_socket_preparation_outside_runtime_and_execution_on_other_runtime() {
        let origin = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let socket = origin.block_on(UdpSocket::bind("127.0.0.1:0")).unwrap();
        // Packaging a registered socket requires no entered runtime.
        let prepared =
            futures::executor::block_on(UdpEndpoint::builder().from_socket(socket).prepare())
                .unwrap();
        let execution = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let service = prepared.spawn_on(execution.handle());
        execution.block_on(async {
            let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            sender
                .send_to(b"malformed", service.local_addr())
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(1), async {
                while service.stats().malformed_datagrams == 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            service.shutdown().await.unwrap();
        });
    }

    #[tokio::test]
    async fn ipv6_transport_maps_ipv4_target() {
        let transport = UdpEndpoint::spawn("[::]:0").await.unwrap();
        let handle = transport.handle("127.0.0.1:161".parse().unwrap()).unwrap();
        let mapped: SocketAddr = "[::ffff:127.0.0.1]:161".parse().unwrap();
        assert_eq!(handle.peer_addr(), mapped);
    }

    #[tokio::test]
    async fn ipv4_transport_preserves_ipv4_target() {
        let transport = UdpEndpoint::spawn("0.0.0.0:0").await.unwrap();
        let handle = transport.handle("127.0.0.1:161".parse().unwrap()).unwrap();
        let expected: SocketAddr = "127.0.0.1:161".parse().unwrap();
        assert_eq!(handle.peer_addr(), expected);
    }

    #[tokio::test]
    async fn ipv4_transport_normalizes_mapped_ipv6_target() {
        let transport = UdpEndpoint::spawn("0.0.0.0:0").await.unwrap();
        let handle = transport
            .handle("[::ffff:127.0.0.1]:161".parse().unwrap())
            .unwrap();
        assert_eq!(handle.peer_addr(), "127.0.0.1:161".parse().unwrap());
    }

    #[tokio::test]
    async fn ipv4_transport_rejects_native_ipv6_target() {
        let transport = UdpEndpoint::spawn("0.0.0.0:0").await.unwrap();
        let error = transport
            .handle("[::1]:161".parse().unwrap())
            .err()
            .expect("native IPv6 target must be rejected during handle construction");

        assert!(matches!(*error, Error::Config(_)));
        assert!(error.to_string().contains("incompatible with IPv4 socket"));
    }

    #[tokio::test]
    async fn ipv6_transport_preserves_ipv6_target() {
        let transport = UdpEndpoint::spawn("[::]:0").await.unwrap();
        let handle = transport.handle("[::1]:161".parse().unwrap()).unwrap();
        let expected: SocketAddr = "[::1]:161".parse().unwrap();
        assert_eq!(handle.peer_addr(), expected);
    }

    #[tokio::test]
    async fn max_message_size_default() {
        let transport = UdpEndpoint::spawn("0.0.0.0:0").await.unwrap();
        let handle = transport.handle("127.0.0.1:161".parse().unwrap()).unwrap();
        // Default config is 1472
        assert_eq!(handle.receive_limits().advertised().as_usize(), 1472);
    }

    #[tokio::test]
    async fn max_message_size_custom() {
        let transport = UdpEndpoint::builder()
            .max_message_size(8192)
            .spawn()
            .await
            .unwrap();
        let handle = transport.handle("127.0.0.1:161".parse().unwrap()).unwrap();
        assert_eq!(handle.receive_limits().advertised().as_usize(), 8192);
        assert_eq!(handle.send_capacity(), 8192);
    }

    #[tokio::test]
    async fn receive_advertisement_and_send_capacity_are_independent() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let transport = UdpEndpoint::builder()
            .bind("127.0.0.1:0")
            .receive_capacity(4096)
            .send_capacity(4)
            .spawn()
            .await
            .unwrap();
        let handle = transport.handle(server.local_addr().unwrap()).unwrap();

        assert_eq!(handle.receive_limits().advertised().as_usize(), 4096);
        assert_eq!(handle.send_capacity(), 4);

        handle.send(&[1, 2, 3, 4]).await.unwrap();
        let mut received = [0; 8];
        let (length, _) = server.recv_from(&mut received).await.unwrap();
        assert_eq!(&received[..length], &[1, 2, 3, 4]);

        let error = handle.send(&[1, 2, 3, 4, 5]).await.unwrap_err();
        assert!(matches!(
            *error,
            Error::OutboundMessageTooLarge { size: 5, limit: 4 }
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(25), server.recv_from(&mut received))
                .await
                .is_err(),
            "oversized datagram must not reach the socket"
        );
    }

    #[tokio::test]
    async fn invalid_message_sizes_are_rejected_before_bind_parsing() {
        for size in [0usize, 483, crate::MAX_UDP_PAYLOAD + 1, usize::MAX] {
            let error = UdpEndpoint::builder()
                .bind("not a socket address")
                .max_message_size(size)
                .spawn()
                .await
                .err()
                .expect("invalid size must fail");
            assert!(
                matches!(*error, Error::Config(_)),
                "unexpected error: {error}"
            );
            assert!(error.to_string().contains("message size"));
        }
    }

    #[tokio::test]
    async fn invalid_send_capacity_is_rejected_before_bind_parsing() {
        let error = UdpEndpoint::builder()
            .bind("not a socket address")
            .send_capacity(crate::MAX_UDP_PAYLOAD + 1)
            .spawn()
            .await
            .err()
            .expect("invalid send capacity must fail");
        assert!(matches!(*error, Error::Config(_)));
        assert!(error.to_string().contains("send capacity"));
    }

    #[tokio::test]
    async fn recv_buffer_size_configurable() {
        // Should not panic or fail - kernel may cap the value
        let transport = UdpEndpoint::builder()
            .recv_buffer_size(2 * 1024 * 1024)
            .spawn()
            .await
            .unwrap();
        assert!(transport.local_addr().port() > 0);
    }

    #[tokio::test]
    async fn final_endpoint_reference_drop_stops_recv_task() {
        let (transport, runner) = UdpEndpoint::builder()
            .bind("127.0.0.1:0")
            .prepare()
            .await
            .unwrap()
            .into_parts();
        let handle = transport.handle("127.0.0.1:161".parse().unwrap()).unwrap();
        let task = tokio::spawn(runner.run());
        let weak = Arc::downgrade(&transport.inner);

        drop(transport);
        tokio::task::yield_now().await;
        assert!(
            !task.is_finished(),
            "recv task stopped while a handle still held the endpoint"
        );

        drop(handle);

        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("recv task did not exit after drop")
            .unwrap()
            .unwrap();
        assert_eq!(weak.strong_count(), 0, "transport state leaked after drop");
    }

    #[tokio::test]
    async fn dedicated_client_and_control_observe_same_counters() {
        let listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (client, control) =
            Client::builder(listener.local_addr().unwrap(), Auth::v2c("public"))
                .request_timeout(Duration::from_millis(20))
                .retry(Retry::none())
                .connect_with_control()
                .await
                .unwrap();

        let error = client
            .get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))
            .await
            .expect_err("silent endpoint should time out");
        assert!(matches!(*error, Error::Timeout { .. }));

        assert_eq!(client.stats(), control.stats());
        assert_eq!(client.stats().expired_registrations, 1);
    }

    #[tokio::test]
    async fn request_send_uses_exchange_deadline_and_releases_registration() {
        let listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let transport = UdpEndpoint::spawn("127.0.0.1:0").await.unwrap();
        let mut handle = transport.handle(listener.local_addr().unwrap()).unwrap();
        handle.send_gate = Some(Arc::new(tokio::sync::Semaphore::new(0)));

        let started = std::time::Instant::now();
        let error = handle
            .request_with(
                b"request",
                RequestRegistration::test_unchecked(42, Duration::from_millis(20)),
                |_, _| Ok(Candidate::Accept(())),
            )
            .await
            .expect_err("stalled send must time out");

        assert!(matches!(*error, Error::Timeout { .. }));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(handle.stats().expired_registrations, 1);

        // The timed-out future dropped its registration guard, so the same ID
        // can be registered immediately instead of remaining pinned until the
        // endpoint's periodic cleanup pass.
        drop(register_v3(&handle, 42, Duration::from_secs(1)));
    }

    #[tokio::test]
    async fn zero_timeout_request_does_not_send_datagram() {
        let listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let transport = UdpEndpoint::spawn("127.0.0.1:0").await.unwrap();
        let handle = transport.handle(listener.local_addr().unwrap()).unwrap();

        let error = handle
            .request_with(
                b"request",
                RequestRegistration::test_unchecked(43, Duration::ZERO),
                |_, _| Ok(Candidate::Accept(())),
            )
            .await
            .expect_err("zero-timeout request must time out");

        assert!(matches!(*error, Error::Timeout { .. }));
        let mut received = [0u8; 16];
        assert!(
            tokio::time::timeout(Duration::from_millis(25), listener.recv_from(&mut received))
                .await
                .is_err(),
            "expired request emitted a datagram"
        );
    }

    #[tokio::test]
    async fn shared_udp_receive_error_policy_recovers_or_closes_by_class() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let transport = UdpEndpoint::spawn("127.0.0.1:0").await.unwrap();
        let handle = transport.handle(server.local_addr().unwrap()).unwrap();
        transport.inject_receive_error(std::io::Error::from(std::io::ErrorKind::InvalidData));
        transport.inject_receive_error(std::io::Error::from(std::io::ErrorKind::ConnectionRefused));

        let request = async {
            handle
                .request_with(
                    b"request",
                    RequestRegistration::v3(44, deadline_after(Duration::from_secs(2))),
                    |data, source| Ok(Candidate::Accept((data, source.peer_addr()))),
                )
                .await
        };
        let response = async {
            let mut data = [0; 64];
            let (_, source) = server.recv_from(&mut data).await.unwrap();
            server.send_to(&v3_identity(44), source).await.unwrap();
        };
        let (result, ()) = tokio::join!(request, response);
        assert_eq!(result.unwrap().1, server.local_addr().unwrap());

        let fatal_handle = transport.handle(server.local_addr().unwrap()).unwrap();
        let pending = tokio::spawn(async move {
            fatal_handle
                .request_with(
                    b"request",
                    RequestRegistration::v3(45, deadline_after(Duration::from_secs(30))),
                    |data, source| Ok(Candidate::Accept((data, source.peer_addr()))),
                )
                .await
        });
        let mut sent = [0; 64];
        server.recv_from(&mut sent).await.unwrap();
        transport.inject_receive_error(std::io::Error::from(std::io::ErrorKind::InvalidInput));
        let error = pending.await.unwrap().unwrap_err();
        assert!(matches!(*error, Error::Closed { .. }));
    }

    #[tokio::test]
    async fn shared_clients_handles_and_control_observe_same_counters() {
        let transport = UdpEndpoint::spawn("127.0.0.1:0").await.unwrap();
        let control = transport.control();
        let target: SocketAddr = "127.0.0.1:161".parse().unwrap();
        let handle = transport.handle(target).unwrap();
        let client1 = Client::builder(target, Auth::v2c("public"))
            .build_with(&transport)
            .await
            .unwrap();
        let client2 = Client::builder(target, Auth::v2c("private"))
            .build_with(&transport)
            .await
            .unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        sender
            .send_to(b"not snmp", transport.local_addr())
            .await
            .unwrap();
        for _ in 0..100 {
            if control.stats().malformed_datagrams == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let expected = transport.stats();
        assert_eq!(expected.malformed_datagrams, 1);
        assert_eq!(handle.stats(), expected);
        assert_eq!(client1.stats(), expected);
        assert_eq!(client2.stats(), expected);
        assert_eq!(control.stats(), expected);
    }

    #[tokio::test]
    async fn shutdown_wakes_pending_waiters() {
        let transport = UdpEndpoint::spawn("127.0.0.1:0").await.unwrap();
        // Target port 9 (discard): no response will ever arrive.
        let handle = transport.handle("127.0.0.1:9".parse().unwrap()).unwrap();
        let waiter = tokio::spawn(async move {
            handle
                .request_with(
                    b"request",
                    RequestRegistration::v3(42, deadline_after(Duration::from_secs(30))),
                    |data, source| Ok(Candidate::Accept((data, source.peer_addr()))),
                )
                .await
        });
        // Let the waiter park on its notify before shutting down.
        tokio::time::sleep(Duration::from_millis(50)).await;

        transport.control().shutdown().await;

        let result = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("pending waiter not woken by shutdown")
            .unwrap();
        let err = result.expect_err("waiter should fail after shutdown");
        assert!(
            matches!(*err, Error::Closed { .. }),
            "expected Error::Closed, got {err:?}"
        );
    }

    #[test]
    fn shutdown_completes_after_originating_runtime_is_dropped() {
        let runtime_a = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let control = runtime_a.block_on(async {
            let transport = UdpEndpoint::spawn("127.0.0.1:0")
                .await
                .unwrap()
                .into_managed();
            transport.control()
        });

        drop(runtime_a);

        let runtime_b = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime_b.block_on(async {
            tokio::time::timeout(Duration::from_secs(1), control.shutdown())
                .await
                .expect("shutdown hung after originating runtime teardown");
        });
        assert!(control.is_shutdown());
    }

    #[tokio::test]
    async fn concurrent_cloned_control_shutdown_wakes_all_shared_clients() {
        let listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let transport = UdpEndpoint::spawn("127.0.0.1:0").await.unwrap();
        let control = transport.control();
        let client1 = Client::builder(target, Auth::v2c("public"))
            .request_timeout(Duration::from_secs(30))
            .retry(Retry::none())
            .build_with(&transport)
            .await
            .unwrap();
        let client2 = Client::builder(target, Auth::v2c("private"))
            .request_timeout(Duration::from_secs(30))
            .retry(Retry::none())
            .build_with(&transport)
            .await
            .unwrap();

        let request1 =
            tokio::spawn(async move { client1.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await });
        let request2 =
            tokio::spawn(async move { client2.get(&oid!(1, 3, 6, 1, 2, 1, 1, 3, 0)).await });

        let mut datagram = [0u8; 2048];
        for _ in 0..2 {
            tokio::time::timeout(Duration::from_secs(1), listener.recv_from(&mut datagram))
                .await
                .expect("client did not send request")
                .unwrap();
        }

        let other_control = control.clone();
        tokio::join!(control.shutdown(), other_control.shutdown());
        assert!(control.is_shutdown());
        assert!(other_control.is_shutdown());

        for request in [request1, request2] {
            let error = request
                .await
                .unwrap()
                .expect_err("shared client request should be closed");
            assert!(matches!(*error, Error::Closed { .. }));
        }

        let stats = control.stats();
        control.shutdown().await;
        other_control.shutdown().await;
        assert_eq!(control.stats(), stats);
    }

    #[tokio::test]
    async fn post_shutdown_operations_do_not_register_or_send() {
        let listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let transport = UdpEndpoint::spawn("127.0.0.1:0").await.unwrap();
        let handle = transport.handle(target).unwrap();
        let control = transport.control();

        control.shutdown().await;
        let stats = control.stats();

        let send_error = handle.send(b"must not be sent").await.unwrap_err();
        assert!(matches!(*send_error, Error::Closed { .. }));
        let request_error = handle
            .request_with(
                b"must not be sent",
                RequestRegistration::v3(101, deadline_after(Duration::from_secs(30))),
                |data, source| Ok(Candidate::Accept((data, source.peer_addr()))),
            )
            .await
            .unwrap_err();
        assert!(matches!(*request_error, Error::Closed { .. }));

        assert_eq!(transport.inner.core.pending_counts(), (0, 0));
        let mut datagram = [0u8; 32];
        assert!(
            tokio::time::timeout(Duration::from_millis(50), listener.recv_from(&mut datagram))
                .await
                .is_err(),
            "post-shutdown operation sent a datagram"
        );

        control.shutdown().await;
        assert_eq!(control.stats(), stats);
        assert_eq!(handle.stats(), stats);
    }

    #[tokio::test]
    async fn request_after_shutdown_without_slot_returns_closed() {
        let transport = UdpEndpoint::spawn("127.0.0.1:0").await.unwrap();
        let handle = transport.handle("127.0.0.1:9".parse().unwrap()).unwrap();

        transport.control().shutdown().await;

        let err = handle
            .request_with(
                b"request",
                RequestRegistration::v3(42, deadline_after(Duration::from_secs(30))),
                |data, source| Ok(Candidate::Accept((data, source.peer_addr()))),
            )
            .await
            .expect_err("recv on closed transport should fail");
        assert!(
            matches!(*err, Error::Closed { .. }),
            "expected Error::Closed, got {err:?}"
        );
    }

    #[tokio::test]
    async fn request_zero_deadline_on_open_transport_returns_timeout() {
        let transport = UdpEndpoint::spawn("127.0.0.1:0").await.unwrap();
        let handle = transport.handle("127.0.0.1:9".parse().unwrap()).unwrap();

        let err = handle
            .request_with(
                b"request",
                RequestRegistration::v3(42, tokio::time::Instant::now()),
                |data, source| Ok(Candidate::Accept((data, source.peer_addr()))),
            )
            .await
            .expect_err("zero-deadline receive should fail");
        assert!(
            matches!(*err, Error::Timeout { .. }),
            "expected Error::Timeout, got {err:?}"
        );
    }

    // A local size failure after registration must reclaim the pending entries
    // immediately rather than leaving them to expire or be swept by the
    // periodic cleanup.
    #[tokio::test]
    async fn outbound_size_failure_unregisters_pending_slot() {
        let transport = UdpEndpoint::spawn("127.0.0.1:0").await.unwrap();
        let handle = transport.handle("127.0.0.1:9".parse().unwrap()).unwrap();

        let request_id = 55;
        let registration =
            RequestRegistration::v3(request_id, deadline_after(Duration::from_secs(30)))
                .with_aliases([53, 54])
                .unwrap();

        let oversized = vec![0u8; 1473];
        let err = handle
            .request_with(&oversized, registration, |data, source| {
                Ok(Candidate::Accept((data, source.peer_addr())))
            })
            .await
            .expect_err("oversized send should fail");
        assert!(
            matches!(
                *err,
                Error::OutboundMessageTooLarge {
                    size: 1473,
                    limit: 1472
                }
            ),
            "expected local outbound-size error, got {err:?}"
        );

        // The slot must already be gone: a response for this id finds nothing.
        let packet = response_packet(request_id);
        assert!(
            !transport
                .inner
                .core
                .deliver(request_id, packet, handle.peer_addr()),
            "pending slot should have been reclaimed on send failure"
        );
        assert_eq!(transport.inner.core.pending_counts(), (0, 0));
    }

    #[tokio::test]
    async fn failed_registration_sends_no_datagram() {
        let listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let transport = UdpEndpoint::spawn("127.0.0.1:0").await.unwrap();
        let handle = transport.handle(target).unwrap();
        let _owner = register_v3(&handle, 60, Duration::from_secs(30));

        let error = handle
            .request_with(
                b"must not be sent",
                RequestRegistration::v3(61, deadline_after(Duration::from_secs(30)))
                    .with_aliases([60])
                    .unwrap(),
                |data, source| Ok(Candidate::Accept((data, source.peer_addr()))),
            )
            .await
            .unwrap_err();
        assert!(matches!(*error, Error::RequestIdInUse { request_id: 60 }));

        let mut datagram = [0u8; 32];
        assert!(
            tokio::time::timeout(Duration::from_millis(50), listener.recv_from(&mut datagram))
                .await
                .is_err(),
            "failed registration sent a datagram"
        );
        assert_eq!(transport.inner.core.pending_counts(), (1, 0));
    }

    #[tokio::test]
    async fn dropping_unpolled_request_does_not_register() {
        let transport = UdpEndpoint::spawn("127.0.0.1:0").await.unwrap();
        let handle = transport.handle("127.0.0.1:9".parse().unwrap()).unwrap();
        let registration = RequestRegistration::v3(70, deadline_after(Duration::from_secs(300)))
            .with_aliases([68, 69])
            .unwrap();

        let request = handle.request_with(b"request", registration, |data, source| {
            Ok(Candidate::Accept((data, source.peer_addr())))
        });
        assert_eq!(transport.inner.core.pending_counts(), (0, 0));
        drop(request);
        assert_eq!(transport.inner.core.pending_counts(), (0, 0));
    }

    #[tokio::test]
    async fn repeated_cancellation_after_send_cleans_primary_and_aliases() {
        let listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let transport = UdpEndpoint::spawn("127.0.0.1:0").await.unwrap();
        let handle = transport.handle(target).unwrap();
        let mut datagram = [0u8; 16];

        for iteration in 0..20 {
            let request_id = 1_000 + iteration;
            let registration =
                RequestRegistration::v3(request_id, deadline_after(Duration::from_secs(300)))
                    .with_aliases([2_000 + iteration * 2, 2_001 + iteration * 2])
                    .unwrap();
            let request_handle = handle.clone();
            let task = tokio::spawn(async move {
                request_handle
                    .request_with(b"request", registration, |data, source| {
                        Ok(Candidate::Accept((data, source.peer_addr())))
                    })
                    .await
            });

            listener.recv_from(&mut datagram).await.unwrap();
            assert_eq!(transport.inner.core.pending_counts(), (1, 2));

            task.abort();
            let error = task.await.expect_err("request task should be cancelled");
            assert!(error.is_cancelled());
            assert_eq!(
                transport.inner.core.pending_counts(),
                (0, 0),
                "iteration {iteration} retained UDP correlation state"
            );
        }
    }

    #[tokio::test]
    async fn send_buffer_size_configurable() {
        let transport = UdpEndpoint::builder()
            .send_buffer_size(512 * 1024)
            .spawn()
            .await
            .unwrap();
        assert!(transport.local_addr().port() > 0);
    }

    /// Build a valid v2c response packet carrying `request_id`, for injection
    /// into `UdpCore::deliver` in the source-mismatch tests below.
    fn response_packet(request_id: i32) -> Bytes {
        let pdu =
            crate::pdu::ResponsePdu::success(crate::Version::V2c, request_id, vec![]).unwrap();
        let msg = crate::message::CommunityMessage::v2c(b"public".as_slice(), pdu).unwrap();
        msg.encode().unwrap()
    }

    // T9 (RFC 3417 3.1): a response whose datagram source differs from the
    // handle's target is still delivered by request-id (the recv loop keys
    // solely on request_id, udp.rs:235-238); `recv`'s source check only warns,
    // it never rejects. These tests inject directly into `UdpCore::deliver`
    // (bypassing the real socket) to exercise that exact accept path
    // deterministically, per the brief's preferred approach.

    #[tokio::test]
    async fn recv_accepts_mismatched_source_with_warn_enabled() {
        let transport = UdpEndpoint::spawn("127.0.0.1:0").await.unwrap();
        let target: SocketAddr = "127.0.0.1:161".parse().unwrap();
        let mismatched: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        assert_ne!(target, mismatched);

        // Default config: warn_on_source_mismatch is true.
        let handle = transport.handle(target).unwrap();
        let registration = register_v3(&handle, 42, Duration::from_secs(5));

        let packet = response_packet(42);
        assert!(
            transport.inner.core.deliver(42, packet.clone(), mismatched),
            "deliver should find the registered request"
        );

        let (data, source) = tokio::time::timeout(
            Duration::from_secs(1),
            handle.recv_registered(&registration),
        )
        .await
        .expect("recv timed out")
        .expect("mismatched-source response must still be accepted");

        assert_eq!(data, packet);
        assert_eq!(source, mismatched);
        assert_ne!(source, handle.peer_addr());
    }

    #[tokio::test]
    async fn recv_accepts_mismatched_source_with_warn_disabled() {
        let transport = UdpEndpoint::builder()
            .bind("127.0.0.1:0")
            .warn_on_source_mismatch(false)
            .spawn()
            .await
            .unwrap();
        let target: SocketAddr = "127.0.0.1:161".parse().unwrap();
        let mismatched: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        assert_ne!(target, mismatched);

        let handle = transport.handle(target).unwrap();
        let registration = register_v3(&handle, 7, Duration::from_secs(5));

        let packet = response_packet(7);
        assert!(transport.inner.core.deliver(7, packet.clone(), mismatched));

        // Acceptance must not depend on warn_on_source_mismatch: the flag
        // only controls whether a warning is logged, never rejection.
        let (data, source) = tokio::time::timeout(
            Duration::from_secs(1),
            handle.recv_registered(&registration),
        )
        .await
        .expect("recv timed out")
        .expect("mismatched-source response must be accepted regardless of warn flag");

        assert_eq!(data, packet);
        assert_eq!(source, mismatched);
        assert_ne!(source, handle.peer_addr());
    }

    #[tokio::test]
    async fn deliver_to_unregistered_id_counts_unmatched() {
        let transport = UdpEndpoint::spawn("127.0.0.1:0").await.unwrap();
        let source: SocketAddr = "127.0.0.1:161".parse().unwrap();

        assert!(
            !transport
                .inner
                .core
                .deliver(42, response_packet(42), source)
        );

        let stats = transport.stats();
        assert_eq!(stats.discarded_datagrams, 1);
        assert_eq!(stats.correlated_datagrams, 0);
    }

    #[tokio::test]
    async fn second_deliver_after_recv_counts_unmatched() {
        let transport = UdpEndpoint::spawn("127.0.0.1:0").await.unwrap();
        let target: SocketAddr = "127.0.0.1:161".parse().unwrap();
        let handle = transport.handle(target).unwrap();
        let registration = register_v3(&handle, 7, Duration::from_secs(5));

        let packet = response_packet(7);
        assert!(transport.inner.core.deliver(7, packet.clone(), target));
        tokio::time::timeout(
            Duration::from_secs(1),
            handle.recv_registered(&registration),
        )
        .await
        .expect("recv timed out")
        .expect("first response must be delivered");

        // Slot consumed by recv: a duplicate is unmatched.
        assert!(!transport.inner.core.deliver(7, packet, target));

        let stats = transport.stats();
        assert_eq!(stats.correlated_datagrams, 1);
        assert_eq!(stats.discarded_datagrams, 1);
    }

    #[tokio::test]
    async fn garbage_datagram_counts_malformed() {
        let transport = UdpEndpoint::spawn("127.0.0.1:0").await.unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender
            .send_to(b"not snmp", transport.local_addr())
            .await
            .unwrap();

        // The recv loop processes the datagram asynchronously; poll briefly.
        let mut malformed = 0;
        for _ in 0..100 {
            malformed = transport.stats().malformed_datagrams;
            if malformed == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(malformed, 1);
    }

    #[tokio::test]
    async fn cleanup_expired_counts_expired() {
        let transport = UdpEndpoint::spawn("127.0.0.1:0").await.unwrap();
        let handle = transport.handle("127.0.0.1:9".parse().unwrap()).unwrap();
        let _registration = register_v3(&handle, 13, Duration::ZERO);

        transport.inner.core.cleanup_expired();

        assert_eq!(transport.stats().expired_registrations, 1);
    }

    #[tokio::test]
    async fn strict_handle_rejects_mismatched_source_and_keeps_slot() {
        let transport = UdpEndpoint::spawn("127.0.0.1:0").await.unwrap();
        let target: SocketAddr = "127.0.0.1:161".parse().unwrap();
        let mismatched: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let handle = transport.handle(target).unwrap().strict_source(true);
        let registration = register_v3(&handle, 21, Duration::from_secs(5));

        let packet = response_packet(21);
        assert!(
            !transport.inner.core.deliver(21, packet.clone(), mismatched),
            "strict handle must reject a mismatched source"
        );
        assert_eq!(transport.stats().discarded_datagrams, 1);

        // The slot must survive rejection so the genuine response still lands.
        assert!(transport.inner.core.deliver(21, packet.clone(), target));

        let (data, source) = tokio::time::timeout(
            Duration::from_secs(1),
            handle.recv_registered(&registration),
        )
        .await
        .expect("recv timed out")
        .expect("matching-source response must be delivered after a rejected one");

        assert_eq!(data, packet);
        assert_eq!(source, target);
    }

    #[tokio::test]
    async fn strict_handle_accepts_matching_source() {
        let transport = UdpEndpoint::spawn("127.0.0.1:0").await.unwrap();
        let target: SocketAddr = "127.0.0.1:161".parse().unwrap();

        let handle = transport.handle(target).unwrap().strict_source(true);
        let registration = register_v3(&handle, 22, Duration::from_secs(5));

        let packet = response_packet(22);
        assert!(transport.inner.core.deliver(22, packet.clone(), target));

        let (data, source) = tokio::time::timeout(
            Duration::from_secs(1),
            handle.recv_registered(&registration),
        )
        .await
        .expect("recv timed out")
        .expect("matching-source response must be accepted by a strict handle");

        assert_eq!(data, packet);
        assert_eq!(source, target);
    }

    #[tokio::test]
    async fn recv_matching_source_is_not_a_mismatch() {
        let transport = UdpEndpoint::spawn("127.0.0.1:0").await.unwrap();
        let target: SocketAddr = "127.0.0.1:161".parse().unwrap();

        let handle = transport.handle(target).unwrap();
        let registration = register_v3(&handle, 99, Duration::from_secs(5));

        let packet = response_packet(99);
        assert!(transport.inner.core.deliver(99, packet.clone(), target));

        let (data, source) = tokio::time::timeout(
            Duration::from_secs(1),
            handle.recv_registered(&registration),
        )
        .await
        .expect("recv timed out")
        .expect("matching-source response must be accepted");

        assert_eq!(data, packet);
        assert_eq!(source, target);
        assert_eq!(source, handle.peer_addr());
    }
}
