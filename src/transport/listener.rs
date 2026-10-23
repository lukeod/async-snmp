//! Concrete listener sources, with preparation independent of execution.
use super::{
    EndpointLimits, TcpOptions, TransportKind, UdpEndpoint, UdpEndpointBuilder, UdpRunner,
};
use crate::{EndpointId, Error, Result};
use std::net::SocketAddr;
use tokio::net::{TcpListener, UdpSocket};

/// Identified bound address. TCP sessions retain this listener identity while
/// receiving distinct session identities and connected local addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundListener {
    pub endpoint_id: EndpointId,
    pub transport: TransportKind,
    pub local_addr: SocketAddr,
}

/// A UDP endpoint or TCP acceptor configured before application execution.
pub enum ListenerSource {
    Udp(UdpEndpointBuilder),
    Tcp(TcpListenerSource),
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
    pub(crate) async fn prepare(
        self,
        ingress: super::ingress::ApplicationIngress,
    ) -> Result<PreparedListener> {
        match self {
            Self::Udp(builder) => {
                let (endpoint, runner) = builder.ingress(ingress).prepare().await?.into_parts();
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
            Self::Tcp(source) => {
                source.options.validate()?;
                if source.options.max_buffered_bytes > ingress.budget.available_permits() {
                    return Err(Error::Config(
                        "listener aggregate buffer limit must accommodate one TCP session budget"
                            .into(),
                    )
                    .boxed());
                }
                let listener = match (source.address, source.listener) {
                    (Some(_), Some(_)) => {
                        return Err(Error::Config(
                            "TCP bind address conflicts with supplied listener".into(),
                        )
                        .boxed());
                    }
                    (None, Some(listener)) => listener,
                    (Some(address), None) => {
                        let address: SocketAddr = address.parse().map_err(|_| {
                            Error::Config("invalid TCP listener address".into()).boxed()
                        })?;
                        TcpListener::bind(address).await.map_err(|source| {
                            Error::Network {
                                target: address,
                                source,
                            }
                            .boxed()
                        })?
                    }
                    _ => {
                        return Err(Error::Config("TCP listener source is required".into()).boxed());
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
                    options: source.options,
                    ingress,
                })
            }
        }
    }
}

/// TCP acceptor source and limits applied independently to each accepted session.
pub struct TcpListenerSource {
    address: Option<String>,
    listener: Option<TcpListener>,
    options: TcpOptions,
}
impl TcpListenerSource {
    pub fn bind(address: impl AsRef<str>) -> Self {
        Self {
            address: Some(address.as_ref().into()),
            listener: None,
            options: TcpOptions::default(),
        }
    }
    pub fn from_listener(listener: TcpListener) -> Self {
        Self {
            address: None,
            listener: Some(listener),
            options: TcpOptions::default(),
        }
    }
    #[must_use]
    pub fn session_options(mut self, options: TcpOptions) -> Self {
        self.options = options;
        self
    }
}

pub(crate) enum PreparedListener {
    Udp {
        bound: BoundListener,
        endpoint: UdpEndpoint,
        runner: UdpRunner,
    },
    Tcp {
        bound: BoundListener,
        listener: TcpListener,
        options: TcpOptions,
        ingress: super::ingress::ApplicationIngress,
    },
}
impl PreparedListener {
    pub(crate) fn bound(&self) -> BoundListener {
        match self {
            Self::Udp { bound, .. } | Self::Tcp { bound, .. } => *bound,
        }
    }
    pub(crate) fn limits(&self) -> EndpointLimits {
        match self {
            Self::Udp { endpoint, .. } => endpoint.limits(),
            Self::Tcp { options, .. } => EndpointLimits {
                receive: crate::ReceiveLimits::tcp(options.max_message_size).expect("validated"),
                send: options.send_capacity,
            },
        }
    }
}
