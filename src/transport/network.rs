//! Shared ownership and supervision of concrete application endpoints.
use super::udp_error::UdpRecvErrorBackoff;
use super::{BoundListener, TcpTransport, UdpEndpoint, listener::PreparedListener};
use crate::{Error, Result};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::{
    sync::{Semaphore, mpsc},
    task::JoinSet,
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
        options,
        ingress,
        roles,
    } = source
    else {
        unreachable!("TCP acceptor source")
    };
    let mut sessions = JoinSet::new();
    let mut backoff = UdpRecvErrorBackoff::default();
    let mut accepting = true;
    loop {
        tokio::select! {
            biased;
            () = network.stop.cancelled() => return Ok(()),
            () = cancel.cancelled(), if accepting => { accepting = false; },
            _ = sessions.join_next(), if !sessions.is_empty() => {},
            accepted = listener.accept(), if accepting => match accepted {
                Ok((stream, _)) => {
                    backoff.reset();
                    let Ok(permit) = network.connections.clone().try_acquire_owned() else { drop(stream); continue; };
                    let prepared = match TcpTransport::builder().from_stream(stream).options(options.clone()).ingress(ingress.clone(), bound.endpoint_id).prepare().await {
                        Ok(prepared) => prepared,
                        Err(error) => { tracing::debug!(%error, "accepted TCP session preparation failed"); continue; }
                    };
                    let (transport, runner) = prepared.into_parts();
                    if let Some(roles) = &roles { transport.configure_dispatch(roles.clone()); }
                    let id = transport.session_id();
                    network.sessions.lock().unwrap().insert(id, transport);
                    let network = network.clone();
                    let guard = SessionGuard { network, id, configured: false };
                    sessions.spawn(async move {
                        let _guard = guard;
                        let _permit = permit;
                        if let Err(error) = runner.run().await { tracing::debug!(%error, "agent TCP session terminated"); }
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted || error.kind() == std::io::ErrorKind::WouldBlock || error.kind() == std::io::ErrorKind::ConnectionAborted => {
                    tokio::select! { () = cancel.cancelled() => { accepting = false; }, () = tokio::time::sleep(backoff.advance()) => {} }
                }
                Err(source) => {
                    let _ = failures.try_send(listener_error(bound, Error::Network { target: bound.local_addr, source }.boxed()));
                    accepting = false;
                },
            }
        }
    }
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
