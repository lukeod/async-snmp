//! Concrete listener sources, with preparation independent of execution.
use super::framing::BufferBudget;
use super::{TcpOptions, TransportKind, UdpEndpoint, UdpEndpointBuilder, UdpRunner};
use crate::{EndpointId, Error, RequestTransport, Result};
use std::net::SocketAddr;
use tokio::net::{TcpListener, UdpSocket};

/// Identified bound endpoint address, including a configured connection. Accepted sessions retain the listener identity while
/// receiving distinct session identities and connected local addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundListener {
    pub endpoint_id: EndpointId,
    pub transport: TransportKind,
    pub local_addr: SocketAddr,
}

/// A UDP endpoint, TCP acceptor or explicit connected session configured before execution.
pub enum ListenerSource {
    Udp(UdpEndpointBuilder),
    Tcp(TcpListenerSource),
    /// An explicitly connected session, prepared before execution.
    Session(super::TcpTransportBuilder),
}
impl ListenerSource {
    /// Configure UDP with full datagram receive/send capacities.
    pub fn udp(address: impl AsRef<str>) -> Self {
        Self::Udp(
            UdpEndpoint::builder()
                .bind(address)
                .max_message_size(crate::MAX_UDP_PAYLOAD),
        )
    }
    /// Supply an owned bound, unconnected UDP socket without changing its options.
    pub fn udp_socket(socket: UdpSocket) -> Self {
        Self::Udp(
            UdpEndpoint::builder()
                .from_socket(socket)
                .max_message_size(crate::MAX_UDP_PAYLOAD),
        )
    }
    /// Configure a TCP listener with default session limits.
    pub fn tcp(address: impl AsRef<str>) -> Self {
        Self::Tcp(TcpListenerSource::bind(address))
    }
    /// Supply an owned TCP listener.
    pub fn tcp_listener(listener: TcpListener) -> Self {
        Self::Tcp(TcpListenerSource::from_listener(listener))
    }

    /// Validate authored settings and return the UDP bind address when one was configured.
    #[cfg(feature = "agent")]
    pub(crate) fn validate_config(&self, budget: &BufferBudget) -> Result<Option<SocketAddr>> {
        match self {
            Self::Udp(builder) => Ok(builder.validate_config()?.1),
            Self::Tcp(source) => {
                source.validate_config(budget)?;
                Ok(None)
            }
            Self::Session(builder) => {
                builder.validate_config(Some(budget))?;
                Ok(None)
            }
        }
    }

    pub(crate) async fn prepare(
        self,
        ingress: super::ingress::ApplicationIngress,
    ) -> Result<PreparedListener> {
        match self {
            Self::Udp(builder) => {
                let (endpoint, runner) = builder.prepare().await?.into_parts();
                let bound = BoundListener {
                    endpoint_id: endpoint.endpoint_id(),
                    transport: TransportKind::Udp,
                    local_addr: endpoint.local_addr(),
                };
                Ok(PreparedListener::Udp {
                    bound,
                    endpoint,
                    runner,
                })
            }
            Self::Session(builder) => {
                let id = EndpointId::new();
                let (transport, runner) =
                    builder.ingress(ingress, id).prepare().await?.into_parts();
                let bound = BoundListener {
                    endpoint_id: id,
                    transport: TransportKind::Tcp,
                    local_addr: transport.local_addr(),
                };
                Ok(PreparedListener::Session {
                    bound,
                    transport,
                    runner,
                })
            }
            Self::Tcp(source) => {
                let address = source.validate_config(&ingress.budget)?;
                let listener = match source.listener {
                    Some(listener) => listener,
                    None => {
                        let address = address.expect("validated TCP listener address");
                        TcpListener::bind(address).await.map_err(|source| {
                            Error::Network {
                                target: address,
                                source,
                            }
                            .boxed()
                        })?
                    }
                };
                let local_addr = listener.local_addr().map_err(|source| {
                    Error::Network {
                        target: "0.0.0.0:0".parse().unwrap(),
                        source,
                    }
                    .boxed()
                })?;
                if local_addr.port() == 0 {
                    return Err(Error::Config("supplied TCP listener must be bound".into()).boxed());
                }
                let bound = BoundListener {
                    endpoint_id: EndpointId::new(),
                    transport: TransportKind::Tcp,
                    local_addr,
                };
                Ok(PreparedListener::Tcp {
                    bound,
                    listener,
                    #[cfg(test)]
                    accept_hook: source.accept_hook,
                    options: source.options,
                    observation: source.observation,
                    ingress,
                    roles: None,
                })
            }
        }
    }
}

#[cfg(test)]
pub(crate) type TcpAcceptHook = Box<dyn Fn() -> std::io::Result<()> + Send + Sync>;

/// TCP acceptor source and limits applied independently to each accepted session.
pub struct TcpListenerSource {
    observation: super::observation::Observation,
    address: Option<String>,
    listener: Option<TcpListener>,
    #[cfg(test)]
    accept_hook: Option<TcpAcceptHook>,
    options: TcpOptions,
}
impl TcpListenerSource {
    /// Observe every accepted session; events retain listener and session identities.
    #[must_use]
    pub fn observer(mut self, observer: super::TransportObserver) -> Self {
        self.observation = super::observation::Observation(Some(observer));
        self
    }

    pub fn bind(address: impl AsRef<str>) -> Self {
        Self {
            observation: Default::default(),
            address: Some(address.as_ref().into()),
            listener: None,
            #[cfg(test)]
            accept_hook: None,
            options: TcpOptions::default(),
        }
    }
    pub fn from_listener(listener: TcpListener) -> Self {
        Self {
            observation: Default::default(),
            address: None,
            listener: Some(listener),
            #[cfg(test)]
            accept_hook: None,
            options: TcpOptions::default(),
        }
    }
    #[must_use]
    pub fn session_options(mut self, options: TcpOptions) -> Self {
        self.options = options;
        self
    }

    fn validate_config(&self, budget: &BufferBudget) -> Result<Option<SocketAddr>> {
        self.options.validate()?;
        self.options.reserve_buffer_budget(budget)?;
        match (self.address.as_deref(), self.listener.as_ref()) {
            (Some(address), None) => address
                .parse()
                .map(Some)
                .map_err(|_| Error::Config("invalid TCP listener address".into()).boxed()),
            (None, Some(_)) => Ok(None),
            (Some(_), Some(_)) => Err(Error::Config(
                "TCP bind address conflicts with supplied listener".into(),
            )
            .boxed()),
            (None, None) => Err(Error::Config("TCP listener source is required".into()).boxed()),
        }
    }

    #[cfg(test)]
    pub(crate) fn test_accept_hook(
        mut self,
        hook: impl Fn() -> std::io::Result<()> + Send + Sync + 'static,
    ) -> Self {
        self.accept_hook = Some(Box::new(hook));
        self
    }
}

pub(crate) enum PreparedListener {
    Session {
        bound: BoundListener,
        transport: super::TcpTransport,
        runner: super::TcpRunner,
    },
    Udp {
        bound: BoundListener,
        endpoint: UdpEndpoint,
        runner: UdpRunner,
    },
    Tcp {
        observation: super::observation::Observation,
        bound: BoundListener,
        listener: TcpListener,
        #[cfg(test)]
        accept_hook: Option<TcpAcceptHook>,
        options: TcpOptions,
        ingress: super::ingress::ApplicationIngress,
        roles: Option<std::sync::Arc<super::dispatch::DispatchRoles>>,
    },
}
impl PreparedListener {
    pub(crate) fn configure_dispatch(
        &mut self,
        dispatch: std::sync::Arc<super::dispatch::DispatchRoles>,
    ) {
        match self {
            Self::Udp { endpoint, .. } => endpoint.configure_dispatch(dispatch),
            Self::Session { transport, .. } => transport.configure_dispatch(dispatch),
            Self::Tcp { roles, .. } => *roles = Some(dispatch),
        }
    }

    pub(crate) fn bound(&self) -> BoundListener {
        match self {
            Self::Udp { bound, .. } | Self::Tcp { bound, .. } | Self::Session { bound, .. } => {
                *bound
            }
        }
    }
    /// UDP endpoints and configured TCP sessions unregister when they close.
    /// The root runner retains the TCP listener minimum through service drain.
    pub(crate) fn register_receive_capacities(
        listeners: &mut [Self],
        engine: &crate::LocalEngine,
    ) -> Option<crate::ReceiveCapacityRegistration> {
        listeners
            .iter_mut()
            .filter_map(|listener| match listener {
                Self::Udp { runner, .. } => {
                    runner.register_receive_capacity(engine);
                    None
                }
                Self::Tcp { options, .. } => Some(
                    crate::ReceiveLimits::tcp(options.max_message_size)
                        .expect("validated")
                        .advertised(),
                ),
                Self::Session { runner, .. } => {
                    runner.register_receive_capacity(engine);
                    None
                }
            })
            .min()
            .map(|capacity| engine.register_receive_capacity(capacity))
    }
}
