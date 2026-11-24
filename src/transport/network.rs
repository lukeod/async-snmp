//! Shared ownership and supervision of concrete application endpoints.
use super::udp_error::UdpRecvErrorBackoff;
use super::{BoundListener, TcpTransport, UdpEndpoint, listener::PreparedListener};
use crate::{Error, Result};
use std::{
    collections::HashMap,
    io,
    sync::{Arc, Mutex},
};
use tokio::{
    sync::{Semaphore, mpsc},
    task::JoinSet,
    time::{Instant, sleep_until},
};
use tokio_util::sync::CancellationToken;

pub(crate) struct NetworkState {
    pub(crate) bound: Vec<BoundListener>,
    pub(crate) udp: Vec<UdpEndpoint>,
    pub(crate) sessions: Mutex<HashMap<crate::SessionId, TcpTransport>>,
    connections: Arc<Semaphore>,
    pub(crate) stop: CancellationToken,
}
impl NetworkState {
    pub(crate) fn new(listeners: &[PreparedListener], max_connections: usize) -> Result<Self> {
        let configured = listeners
            .iter()
            .filter(|source| matches!(source, PreparedListener::Session { .. }))
            .count();
        if configured > max_connections {
            return Err(
                Error::Config("configured TCP sessions exceed connection limit".into()).boxed(),
            );
        }
        Ok(Self {
            bound: listeners.iter().map(PreparedListener::bound).collect(),
            udp: listeners
                .iter()
                .filter_map(|source| match source {
                    PreparedListener::Udp { endpoint, .. } => Some(endpoint.clone()),
                    _ => None,
                })
                .collect(),
            sessions: Mutex::new(
                listeners
                    .iter()
                    .filter_map(|source| match source {
                        PreparedListener::Session { transport, .. } => {
                            Some((transport.session_id(), transport.clone()))
                        }
                        _ => None,
                    })
                    .collect(),
            ),
            connections: Arc::new(Semaphore::new(max_connections - configured)),
            stop: CancellationToken::new(),
        })
    }
    pub(crate) fn close_endpoints(&self) {
        self.stop.cancel();
        for endpoint in &self.udp {
            endpoint.control().request_shutdown();
        }
        for (_, session) in self.sessions.lock().unwrap().drain() {
            session.control().request_shutdown();
        }
    }
    pub(crate) fn run_source(
        self: Arc<Self>,
        source: PreparedListener,
        cancel: CancellationToken,
        failures: mpsc::Sender<Box<Error>>,
    ) -> impl std::future::Future<Output = Result<()>> + Send + 'static {
        let configured_guard = if let PreparedListener::Session { transport, .. } = &source {
            Some(SessionGuard {
                network: self.clone(),
                id: transport.session_id(),
                configured: true,
            })
        } else {
            None
        };
        async move {
            match source {
                PreparedListener::Udp { bound, runner, .. } => match runner.run().await {
                    Ok(()) => Err(listener_error(
                        bound,
                        Error::Config("UDP listener stopped unexpectedly".into()).boxed(),
                    )),
                    Err(error) => Err(listener_error(bound, error)),
                },
                source @ PreparedListener::Tcp { .. } => {
                    run_tcp_listener(source, self, cancel, failures).await
                }
                PreparedListener::Session { runner, .. } => {
                    if let Err(error) = runner.run().await {
                        tracing::debug!(%error, "configured TCP session terminated");
                    }
                    drop(configured_guard);
                    // A configured connection failure is scoped to that session.
                    self.stop.cancelled().await;
                    Ok(())
                }
            }
        }
    }
}
struct SessionGuard {
    network: Arc<NetworkState>,
    id: crate::SessionId,
    configured: bool,
}
impl Drop for SessionGuard {
    fn drop(&mut self) {
        if self.configured {
            self.network.connections.add_permits(1);
        }
        if let Some(session) = self.network.sessions.lock().unwrap().remove(&self.id) {
            session.control().request_shutdown();
        }
    }
}

async fn run_tcp_listener(
    source: PreparedListener,
    network: Arc<NetworkState>,
    cancel: CancellationToken,
    failures: mpsc::Sender<Box<Error>>,
) -> Result<()> {
    let PreparedListener::Tcp {
        bound,
        listener,
        #[cfg(test)]
        accept_hook,
        options,
        ingress,
        roles,
        observation,
    } = source
    else {
        unreachable!("TCP acceptor source")
    };
    let mut sessions = JoinSet::new();
    let mut backoff = UdpRecvErrorBackoff::default();
    let mut accepting = true;
    let mut retry_at = None;
    loop {
        tokio::select! {
            biased;
            () = network.stop.cancelled() => break,
            () = cancel.cancelled(), if accepting => { accepting = false; },
            _ = sessions.join_next(), if !sessions.is_empty() => {},
            accepted = async {
                if let Some(deadline) = retry_at {
                    sleep_until(deadline).await;
                }
                #[cfg(test)]
                if let Some(hook) = &accept_hook {
                    hook()?;
                }
                listener.accept().await
            }, if accepting => match accepted {
                Ok((stream, _)) => {
                    backoff.reset();
                    retry_at = None;
                    let Ok(permit) = network.connections.clone().try_acquire_owned() else { drop(stream); continue; };
                    let prepared = match TcpTransport::builder().from_stream(stream).observation(observation.clone()).options(options.clone()).ingress(ingress.clone(), bound.endpoint_id).prepare().await {
                        Ok(prepared) => prepared,
                        Err(error) => { tracing::debug!(%error, "accepted TCP session preparation failed"); continue; }
                    };
                    let (transport, runner) = prepared.into_parts();
                    if let Some(roles) = &roles { transport.configure_dispatch(roles.clone()); }
                    let id = transport.session_id();
                    {
                        let mut active = network.sessions.lock().unwrap();
                        if network.stop.is_cancelled() {
                            continue;
                        }
                        active.insert(id, transport);
                    }
                    let network = network.clone();
                    let guard = SessionGuard { network, id, configured: false };
                    sessions.spawn(async move {
                        let _guard = guard;
                        let _permit = permit;
                        if let Err(error) = runner.run().await { tracing::debug!(%error, "agent TCP session terminated"); }
                    });
                }
                Err(error) if retryable_accept_error(&error) => {
                    let delay = backoff.advance();
                    tracing::debug!(%error, local_addr = %bound.local_addr, ?delay, "retrying TCP accept");
                    retry_at = Some(Instant::now() + delay);
                }
                Err(source) => {
                    let _ = failures.try_send(listener_error(bound, Error::Network { target: bound.local_addr, source }.boxed()));
                    accepting = false;
                },
            }
        }
    }
    while sessions.join_next().await.is_some() {}
    Ok(())
}

fn retryable_accept_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::OutOfMemory
    ) || error.raw_os_error().is_some_and(accept_resource_errno)
}

#[cfg(unix)]
fn accept_resource_errno(code: i32) -> bool {
    matches!(
        code,
        libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM
    )
}

#[cfg(windows)]
fn accept_resource_errno(code: i32) -> bool {
    use windows_sys::Win32::Networking::WinSock;

    matches!(code, WinSock::WSAEMFILE | WinSock::WSAENOBUFS)
}

#[cfg(not(any(unix, windows)))]
const fn accept_resource_errno(_code: i32) -> bool {
    false
}

pub(crate) fn listener_error(bound: BoundListener, source: Box<Error>) -> Box<Error> {
    Error::Listener {
        endpoint_id: bound.endpoint_id,
        transport: bound.transport,
        local_addr: bound.local_addr,
        source,
    }
    .boxed()
}

pub(crate) struct NetworkCleanup(pub(crate) Arc<NetworkState>);
impl Drop for NetworkCleanup {
    fn drop(&mut self) {
        self.0.close_endpoints();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ListenerSource, NotificationReceiver, TcpListenerSource, TransportKind};
    use std::time::Duration;

    const WAIT: Duration = Duration::from_secs(2);

    #[cfg(any(unix, windows))]
    #[test]
    fn accept_retries_resource_errors() {
        #[cfg(unix)]
        let codes = [libc::EMFILE, libc::ENFILE, libc::ENOBUFS, libc::ENOMEM];
        #[cfg(windows)]
        let codes = {
            use windows_sys::Win32::Networking::WinSock;
            [WinSock::WSAEMFILE, WinSock::WSAENOBUFS]
        };
        for code in codes {
            assert!(retryable_accept_error(&io::Error::from_raw_os_error(code)));
        }
    }

    #[cfg(feature = "agent")]
    #[tokio::test]
    async fn tcp_accept_recovers_while_udp_keeps_serving() {
        use crate::{Agent, Auth, Client, Retry, Value, oid};
        use std::sync::atomic::{AtomicBool, Ordering};
        use tokio::sync::Notify;

        let resource_limited = Arc::new(AtomicBool::new(true));
        let failed = Arc::new(Notify::new());
        let accept = {
            let resource_limited = resource_limited.clone();
            let failed = failed.clone();
            move || {
                if resource_limited.load(Ordering::Acquire) {
                    failed.notify_one();
                    #[cfg(unix)]
                    return Err(io::Error::from_raw_os_error(libc::EMFILE));
                    #[cfg(windows)]
                    return Err(io::Error::from_raw_os_error(
                        windows_sys::Win32::Networking::WinSock::WSAEMFILE,
                    ));
                    #[cfg(not(any(unix, windows)))]
                    return Err(io::ErrorKind::OutOfMemory.into());
                }
                Ok(())
            }
        };
        let agent = Agent::builder()
            .community("public")
            .allow_all_access()
            .listener(ListenerSource::udp("127.0.0.1:0"))
            .listener(ListenerSource::Tcp(
                TcpListenerSource::bind("127.0.0.1:0").test_accept_hook(accept),
            ))
            .spawn()
            .await
            .unwrap();
        tokio::time::timeout(WAIT, failed.notified()).await.unwrap();
        let oid = oid!(1, 3, 6, 1, 6, 3, 10, 2, 1, 1, 0);
        let client = |transport| {
            let bound = agent
                .bound_addresses()
                .iter()
                .find(|bound| bound.transport == transport)
                .unwrap();
            Client::builder(bound.local_addr.to_string(), Auth::v2c("public"))
                .retry(Retry::none())
                .request_timeout(WAIT)
        };
        let udp = client(TransportKind::Udp).connect().await.unwrap();
        let response = udp.get(&oid).await.unwrap();
        assert!(matches!(response.varbinds[0].value, Value::OctetString(_)));

        resource_limited.store(false, Ordering::Release);
        let tcp = client(TransportKind::Tcp).connect_tcp().await.unwrap();
        assert_eq!(tcp.get(&oid).await.unwrap().varbinds, response.varbinds);
        agent.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn fatal_accept_failure_retains_listener_identity() {
        let source = TcpListenerSource::bind("127.0.0.1:0")
            .test_accept_hook(|| Err(io::ErrorKind::InvalidInput.into()));
        let mut receiver = NotificationReceiver::builder()
            .listener(ListenerSource::Tcp(source))
            .spawn()
            .await
            .unwrap();
        let expected = receiver.bound_addresses()[0];
        let error = tokio::time::timeout(WAIT, receiver.join())
            .await
            .unwrap()
            .unwrap_err();
        match *error {
            Error::Listener {
                endpoint_id,
                transport,
                local_addr,
                source,
            } => {
                assert_eq!(endpoint_id, expected.endpoint_id);
                assert_eq!(transport, TransportKind::Tcp);
                assert_eq!(local_addr, expected.local_addr);
                assert!(matches!(
                    *source,
                    Error::Network { source, .. }
                        if source.kind() == io::ErrorKind::InvalidInput
                ));
            }
            other => panic!("unexpected listener failure: {other}"),
        }
    }
}
