//! Destination-aware UDP receive and response support.
//!
//! Packet-info ancillary data is used on Linux, Android, Apple platforms,
//! Windows, FreeBSD, NetBSD, OpenBSD, and DragonFly BSD when the socket accepts
//! the relevant option. Other platforms do not provide an implementation here.
//! If metadata setup is unavailable or fails, construction emits a warning and
//! receive and send use Tokio's ordinary UDP operations, allowing the kernel to
//! select the response source address.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[cfg(any(
    test,
    windows,
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "netbsd",
    target_os = "openbsd",
))]
use std::sync::Arc;

use tokio::net::UdpSocket;

/// Metadata needed to reply to a received datagram.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ReceivedDatagram {
    pub(crate) len: usize,
    pub(crate) source: SocketAddr,
    pub(crate) destination: Option<DestinationMetadata>,
}

/// Ancillary metadata identifying the local destination of a datagram.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DestinationMetadata {
    pub(crate) ip: IpAddr,
    /// Zero means that the platform did not identify an incoming interface.
    pub(crate) interface_index: u32,
    /// The ordinary local IPv4 address supplied by packet-info, when the
    /// platform provides it independently of the datagram destination.
    ipv4_ordinary_local: Option<Ipv4Addr>,
}

impl DestinationMetadata {
    fn new(ip: IpAddr, interface_index: u32) -> Self {
        Self {
            ip,
            interface_index,
            ipv4_ordinary_local: None,
        }
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos",
    ))]
    fn from_ipv4_packet_info(
        destination: Ipv4Addr,
        interface_index: u32,
        ordinary_local: Ipv4Addr,
    ) -> Self {
        Self {
            ip: IpAddr::V4(destination),
            interface_index,
            ipv4_ordinary_local: Some(ordinary_local),
        }
    }

    fn direct_classification(self) -> DestinationClassification {
        if intrinsically_non_unicast(self.ip) {
            return DestinationClassification::NonUnicast;
        }
        match (self.ip, self.ipv4_ordinary_local) {
            (IpAddr::V4(destination), Some(ordinary_local)) => {
                if destination == ordinary_local {
                    DestinationClassification::Unicast
                } else {
                    DestinationClassification::NonUnicast
                }
            }
            (IpAddr::V6(_), _) => DestinationClassification::Unicast,
            (IpAddr::V4(_), None) => DestinationClassification::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DestinationClassification {
    Unicast,
    NonUnicast,
    Unknown,
}

#[cfg(any(
    test,
    windows,
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "netbsd",
    target_os = "openbsd",
))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Ipv4InterfaceAddress {
    interface_index: u32,
    address: Ipv4Addr,
    broadcast: Option<Ipv4Addr>,
}

#[cfg(any(
    windows,
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "netbsd",
    target_os = "openbsd",
))]
const MAX_IPV4_INTERFACE_ADDRESSES: usize = 4096;

#[cfg(any(
    test,
    windows,
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "netbsd",
    target_os = "openbsd",
))]
const INTERFACE_SNAPSHOT_TTL: std::time::Duration = std::time::Duration::from_secs(30);

#[cfg(any(
    test,
    windows,
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "netbsd",
    target_os = "openbsd",
))]
fn classify_from_ipv4_interfaces(
    destination: Ipv4Addr,
    interface_index: u32,
    interfaces: &[Ipv4InterfaceAddress],
) -> DestinationClassification {
    // An exact address on the received interface wins over another address's
    // broadcast calculation. This preserves unicast semantics for aliases and
    // point-to-point-sized prefixes.
    if interface_index == 0
        || interfaces.iter().any(|interface| {
            interface.interface_index == interface_index && interface.address == destination
        })
    {
        return if interface_index == 0 {
            DestinationClassification::Unknown
        } else {
            DestinationClassification::Unicast
        };
    }
    if interfaces.iter().any(|interface| {
        interface.interface_index == interface_index && interface.broadcast == Some(destination)
    }) {
        DestinationClassification::NonUnicast
    } else {
        DestinationClassification::Unknown
    }
}

#[cfg(any(test, windows))]
fn ipv4_directed_broadcast(address: Ipv4Addr, netmask: Ipv4Addr) -> Option<Ipv4Addr> {
    let address = u32::from(address);
    let netmask = u32::from(netmask);
    let prefix = netmask.leading_ones();
    let canonical_mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    if netmask != canonical_mask || prefix >= 31 {
        return None;
    }
    Some(Ipv4Addr::from((address & netmask) | !netmask))
}

fn intrinsically_non_unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast(),
        IpAddr::V6(ip) => ip.is_unspecified() || ip.is_multicast(),
    }
}

/// Per-socket capability for destination-aware datagram receives and replies.
#[derive(Debug)]
pub(crate) struct UdpResponder {
    packet_info: bool,
    #[cfg(any(
        test,
        windows,
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "netbsd",
        target_os = "openbsd",
    ))]
    ipv4_interfaces: Arc<InterfaceSnapshotState>,
}

#[cfg(any(
    test,
    windows,
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "netbsd",
    target_os = "openbsd",
))]
#[derive(Debug, Default)]
struct InterfaceSnapshotCache {
    last_good: Option<Arc<[Ipv4InterfaceAddress]>>,
    last_attempt: Option<std::time::Instant>,
    refresh_in_flight: bool,
}

#[cfg(any(
    test,
    windows,
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "netbsd",
    target_os = "openbsd",
))]
#[derive(Debug)]
struct InterfaceSnapshotState {
    cache: std::sync::Mutex<InterfaceSnapshotCache>,
    generation: tokio::sync::watch::Sender<u64>,
}

#[cfg(any(
    test,
    windows,
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "netbsd",
    target_os = "openbsd",
))]
impl Default for InterfaceSnapshotState {
    fn default() -> Self {
        let (generation, _) = tokio::sync::watch::channel(0);
        Self {
            cache: std::sync::Mutex::new(InterfaceSnapshotCache::default()),
            generation,
        }
    }
}

#[cfg(any(
    test,
    windows,
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "netbsd",
    target_os = "openbsd",
))]
impl InterfaceSnapshotState {
    fn cache(&self) -> std::sync::MutexGuard<'_, InterfaceSnapshotCache> {
        self.cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn publish(&self, result: io::Result<Vec<Ipv4InterfaceAddress>>) {
        let (addresses, error) = self.cache().record(result);
        if let Some(error) = error {
            tracing::debug!(
                target: "async_snmp::udp",
                %error,
                retained_last_good = addresses.is_some(),
                "could not refresh IPv4 interface-address snapshot"
            );
        }
        self.generation
            .send_modify(|generation| *generation = generation.wrapping_add(1));
    }
}

#[cfg(any(
    test,
    windows,
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "netbsd",
    target_os = "openbsd",
))]
impl InterfaceSnapshotCache {
    fn current_if_fresh(
        &self,
        now: std::time::Instant,
    ) -> Option<Option<Arc<[Ipv4InterfaceAddress]>>> {
        self.last_attempt
            .filter(|attempt| now.saturating_duration_since(*attempt) < INTERFACE_SNAPSHOT_TTL)
            .map(|_| self.last_good.clone())
    }

    fn begin_refresh(&mut self, now: std::time::Instant) {
        self.last_attempt = Some(now);
        self.refresh_in_flight = true;
    }

    fn record(
        &mut self,
        result: io::Result<Vec<Ipv4InterfaceAddress>>,
    ) -> (Option<Arc<[Ipv4InterfaceAddress]>>, Option<io::Error>) {
        self.refresh_in_flight = false;
        match result {
            Ok(addresses) => {
                let addresses = Arc::from(addresses);
                self.last_good = Some(Arc::clone(&addresses));
                (Some(addresses), None)
            }
            Err(error) => (self.last_good.clone(), Some(error)),
        }
    }
}

impl UdpResponder {
    pub(crate) fn new(socket: &UdpSocket) -> Self {
        Self::from_setup_result(socket, platform::enable_packet_info(socket))
    }

    fn from_setup_result(socket: &UdpSocket, result: io::Result<()>) -> Self {
        match result {
            Ok(()) => Self {
                packet_info: true,
                #[cfg(any(
                    test,
                    windows,
                    target_os = "freebsd",
                    target_os = "dragonfly",
                    target_os = "netbsd",
                    target_os = "openbsd",
                ))]
                ipv4_interfaces: Arc::new(InterfaceSnapshotState::default()),
            },
            Err(error) => {
                tracing::warn!(
                    target: "async_snmp::udp",
                    %error,
                    local_addr = ?socket.local_addr().ok(),
                    "UDP destination metadata unavailable; replies will use kernel source selection"
                );
                Self {
                    packet_info: false,
                    #[cfg(any(
                        test,
                        windows,
                        target_os = "freebsd",
                        target_os = "dragonfly",
                        target_os = "netbsd",
                        target_os = "openbsd",
                    ))]
                    ipv4_interfaces: Arc::new(InterfaceSnapshotState::default()),
                }
            }
        }
    }

    #[cfg(test)]
    fn without_packet_info() -> Self {
        Self {
            packet_info: false,
            #[cfg(any(
                test,
                windows,
                target_os = "freebsd",
                target_os = "dragonfly",
                target_os = "netbsd",
                target_os = "openbsd",
            ))]
            ipv4_interfaces: Arc::new(InterfaceSnapshotState::default()),
        }
    }

    /// Receive one datagram and, when available, its destination address.
    pub(crate) async fn recv(
        &self,
        socket: &UdpSocket,
        buf: &mut [u8],
    ) -> io::Result<ReceivedDatagram> {
        if !self.packet_info {
            let (len, source) = socket.recv_from(buf).await?;
            return Ok(ReceivedDatagram {
                len,
                source,
                destination: None,
            });
        }

        loop {
            socket.readable().await?;
            match socket.try_io(tokio::io::Interest::READABLE, || {
                platform::recv_with_packet_info(socket, buf)
            }) {
                Ok(received) => return Ok(received),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
    }

    /// Reply using the received destination as the source when packet info was
    /// available, or ordinary kernel source selection otherwise.
    #[cfg(feature = "agent")]
    pub(crate) async fn reply(
        &self,
        socket: &UdpSocket,
        data: &[u8],
        received: &ReceivedDatagram,
    ) -> io::Result<()> {
        self.send_to(socket, data, received.source, received.destination)
            .await
    }

    pub(crate) async fn send_to(
        &self,
        socket: &UdpSocket,
        data: &[u8],
        destination: SocketAddr,
        source: Option<DestinationMetadata>,
    ) -> io::Result<()> {
        let Some(source) = source.filter(|_| self.packet_info) else {
            socket.send_to(data, destination).await?;
            return Ok(());
        };

        let exact_result = self
            .send_with_metadata(socket, data, destination, source, false)
            .await;
        let exact_error = match exact_result {
            Ok(()) => return Ok(()),
            Err(error) => error,
        };

        // Only synchronous source-selection failures prove that the exact send
        // did not emit a datagram. Ambiguous errors must never be retried.
        if !source_selection_failure(&exact_error) {
            return Err(exact_error);
        }

        let classification = self.classify_destination(source).await;
        let recovery = recovery_after_exact_failure(classification, source.interface_index);
        if matches!(recovery, SendRecovery::None) {
            return Err(exact_error);
        }

        if matches!(
            recovery,
            SendRecovery::InterfaceOnly | SendRecovery::InterfaceThenKernel
        ) {
            tracing::debug!(
                target: "async_snmp::udp",
                source_ip = %source.ip,
                interface_index = source.interface_index,
                ?classification,
                %exact_error,
                "UDP exact-source reply failed; retrying on the received interface"
            );
            match self
                .send_with_metadata(socket, data, destination, source, true)
                .await
            {
                Ok(()) => return Ok(()),
                Err(error) if source_selection_failure(&error) => {
                    if !matches!(recovery, SendRecovery::InterfaceThenKernel) {
                        return Err(error);
                    }
                    tracing::debug!(
                        target: "async_snmp::udp",
                        source_ip = %source.ip,
                        interface_index = source.interface_index,
                        ?classification,
                        %error,
                        "UDP reply interface selection failed; retrying with kernel source selection"
                    );
                }
                Err(error) => return Err(error),
            }
        } else if matches!(recovery, SendRecovery::KernelOnly) {
            tracing::debug!(
                target: "async_snmp::udp",
                source_ip = %source.ip,
                ?classification,
                %exact_error,
                "UDP reply source was non-unicast and no interface was reported; retrying with kernel source selection"
            );
        }

        socket.send_to(data, destination).await?;
        Ok(())
    }

    async fn classify_destination(&self, source: DestinationMetadata) -> DestinationClassification {
        let direct = source.direct_classification();
        if direct != DestinationClassification::Unknown {
            return direct;
        }

        #[cfg(any(
            windows,
            target_os = "freebsd",
            target_os = "dragonfly",
            target_os = "netbsd",
            target_os = "openbsd",
        ))]
        if let IpAddr::V4(destination) = source.ip
            && let Some(interfaces) = self.ipv4_interface_snapshot().await
        {
            return classify_from_ipv4_interfaces(destination, source.interface_index, &interfaces);
        }

        DestinationClassification::Unknown
    }

    #[cfg(any(
        windows,
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "netbsd",
        target_os = "openbsd",
    ))]
    async fn ipv4_interface_snapshot(&self) -> Option<Arc<[Ipv4InterfaceAddress]>> {
        self.ipv4_interface_snapshot_with(platform::ipv4_interface_addresses)
            .await
    }

    #[cfg(any(
        test,
        windows,
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "netbsd",
        target_os = "openbsd",
    ))]
    async fn ipv4_interface_snapshot_with<F>(
        &self,
        enumerate: F,
    ) -> Option<Arc<[Ipv4InterfaceAddress]>>
    where
        F: FnOnce() -> io::Result<Vec<Ipv4InterfaceAddress>> + Send + 'static,
    {
        let mut enumerate = Some(enumerate);
        let mut generation = self.ipv4_interfaces.generation.subscribe();

        loop {
            let start_refresh = {
                let now = std::time::Instant::now();
                let mut cache = self.ipv4_interfaces.cache();
                if cache.refresh_in_flight {
                    false
                } else if let Some(addresses) = cache.current_if_fresh(now) {
                    return addresses;
                } else {
                    cache.begin_refresh(now);
                    true
                }
            };

            if start_refresh {
                let state = Arc::clone(&self.ipv4_interfaces);
                let enumerate = enumerate
                    .take()
                    .expect("an interface refresh is started at most once per caller");

                // Enumeration and publication must outlive both the initiating
                // waiter and its Tokio runtime. At most one bounded enumeration
                // thread exists for this shared snapshot state.
                let worker_state = Arc::clone(&state);
                if let Err(error) = std::thread::Builder::new()
                    .name("async-snmp-ipv4-interfaces".into())
                    .spawn(move || {
                        let result =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(enumerate))
                                .unwrap_or_else(|_| {
                                    Err(io::Error::other(
                                        "IPv4 interface-address enumeration panicked",
                                    ))
                                });
                        worker_state.publish(result);
                    })
                {
                    state.publish(Err(error));
                }
            }

            // A watch receiver observes completion even when publication races
            // with this await, without keeping the cache mutex locked.
            generation
                .changed()
                .await
                .expect("the interface snapshot state owns its generation sender");
        }
    }

    async fn send_with_metadata(
        &self,
        socket: &UdpSocket,
        data: &[u8],
        destination: SocketAddr,
        source: DestinationMetadata,
        unspecified_source: bool,
    ) -> io::Result<()> {
        loop {
            socket.writable().await?;
            match socket.try_io(tokio::io::Interest::WRITABLE, || {
                platform::send_with_source(socket, data, destination, source, unspecified_source)
            }) {
                Ok(()) => return Ok(()),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SendRecovery {
    None,
    InterfaceOnly,
    KernelOnly,
    InterfaceThenKernel,
}

fn recovery_after_exact_failure(
    classification: DestinationClassification,
    interface_index: u32,
) -> SendRecovery {
    match (classification, interface_index == 0) {
        (DestinationClassification::Unicast, _) => SendRecovery::None,
        (DestinationClassification::Unknown, true) => SendRecovery::None,
        (DestinationClassification::Unknown, false) => SendRecovery::InterfaceOnly,
        (DestinationClassification::NonUnicast, true) => SendRecovery::KernelOnly,
        (DestinationClassification::NonUnicast, false) => SendRecovery::InterfaceThenKernel,
    }
}

fn source_selection_failure(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::InvalidInput
            | io::ErrorKind::AddrNotAvailable
            | io::ErrorKind::NetworkUnreachable
    )
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "visionos",
    target_os = "freebsd",
))]
mod platform {
    use std::io::{IoSlice, IoSliceMut};
    use std::os::fd::AsRawFd;

    use nix::libc;
    use nix::sys::socket::{
        ControlMessage, ControlMessageOwned, MsgFlags, SockaddrStorage, recvmsg, sendmsg,
        setsockopt, sockopt::Ipv6RecvPacketInfo,
    };

    use super::*;

    pub(super) fn enable_packet_info(socket: &UdpSocket) -> io::Result<()> {
        if socket.local_addr()?.is_ipv4() {
            enable_ipv4_packet_info(socket)
        } else {
            setsockopt(socket, Ipv6RecvPacketInfo, &true).map_err(io::Error::from)
        }
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos",
    ))]
    fn enable_ipv4_packet_info(socket: &UdpSocket) -> io::Result<()> {
        setsockopt(socket, nix::sys::socket::sockopt::Ipv4PacketInfo, &true)
            .map_err(io::Error::from)
    }

    #[cfg(target_os = "freebsd")]
    fn enable_ipv4_packet_info(socket: &UdpSocket) -> io::Result<()> {
        setsockopt(socket, nix::sys::socket::sockopt::Ipv4RecvDstAddr, &true)
            .map_err(io::Error::from)?;
        setsockopt(socket, nix::sys::socket::sockopt::Ipv4RecvIf, &true).map_err(io::Error::from)
    }

    pub(super) fn recv_with_packet_info(
        socket: &UdpSocket,
        buf: &mut [u8],
    ) -> io::Result<ReceivedDatagram> {
        let mut iov = [IoSliceMut::new(buf)];
        // Space for packet-info representations and, on FreeBSD, the separate
        // IPv4 destination and receive-interface messages.
        #[cfg(not(target_os = "freebsd"))]
        let mut control = nix::cmsg_space!(libc::in6_pktinfo, libc::in_addr);
        #[cfg(target_os = "freebsd")]
        let mut control = nix::cmsg_space!(libc::in6_pktinfo, libc::in_addr, libc::sockaddr_dl);
        let message = recvmsg::<SockaddrStorage>(
            socket.as_raw_fd(),
            &mut iov,
            Some(&mut control),
            MsgFlags::empty(),
        )
        .map_err(io::Error::from)?;
        if message
            .flags
            .intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "UDP datagram or packet metadata exceeded its receive buffer",
            ));
        }

        let source = message
            .address
            .as_ref()
            .and_then(decode_socket_addr)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "received a non-IP UDP address")
            })?;
        let mut destination_ip = None;
        let mut interface_index = 0;
        #[cfg(not(target_os = "freebsd"))]
        let mut ordinary_ipv4_local = None;
        for control in message
            .cmsgs()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
        {
            match control {
                #[cfg(any(
                    target_os = "linux",
                    target_os = "android",
                    target_os = "macos",
                    target_os = "ios",
                    target_os = "tvos",
                    target_os = "watchos",
                    target_os = "visionos",
                ))]
                ControlMessageOwned::Ipv4PacketInfo(info) => {
                    let ip = std::net::Ipv4Addr::from(info.ipi_addr.s_addr.to_ne_bytes());
                    let ordinary_local =
                        std::net::Ipv4Addr::from(info.ipi_spec_dst.s_addr.to_ne_bytes());
                    destination_ip = Some(IpAddr::V4(ip));
                    interface_index = normalize_interface_index(info.ipi_ifindex);
                    ordinary_ipv4_local = Some(ordinary_local);
                }
                ControlMessageOwned::Ipv6PacketInfo(info) => {
                    destination_ip =
                        Some(IpAddr::V6(std::net::Ipv6Addr::from(info.ipi6_addr.s6_addr)));
                    interface_index = normalize_interface_index(info.ipi6_ifindex);
                }
                #[cfg(any(
                    target_os = "macos",
                    target_os = "ios",
                    target_os = "tvos",
                    target_os = "watchos",
                    target_os = "visionos",
                    target_os = "freebsd",
                ))]
                ControlMessageOwned::Ipv4RecvDstAddr(addr) => {
                    destination_ip = Some(IpAddr::V4(std::net::Ipv4Addr::from(
                        addr.s_addr.to_ne_bytes(),
                    )));
                }
                #[cfg(target_os = "freebsd")]
                ControlMessageOwned::Ipv4RecvIf(address) => {
                    interface_index = u32::from(address.sdl_index);
                }
                _ => {}
            }
        }
        Ok(ReceivedDatagram {
            len: message.bytes,
            source,
            destination: destination_ip.map(|ip| match ip {
                #[cfg(not(target_os = "freebsd"))]
                IpAddr::V4(ip) if ordinary_ipv4_local.is_some() => {
                    DestinationMetadata::from_ipv4_packet_info(
                        ip,
                        interface_index,
                        ordinary_ipv4_local.expect("checked above"),
                    )
                }
                #[cfg(target_os = "freebsd")]
                IpAddr::V4(ip) => DestinationMetadata::new(IpAddr::V4(ip), interface_index),
                _ => DestinationMetadata::new(ip, interface_index),
            }),
        })
    }

    #[cfg(target_os = "freebsd")]
    pub(super) fn ipv4_interface_addresses() -> io::Result<Vec<Ipv4InterfaceAddress>> {
        use nix::ifaddrs::getifaddrs;
        use nix::net::if_::{InterfaceFlags, if_nametoindex};

        let mut addresses = Vec::new();
        for interface in getifaddrs().map_err(io::Error::from)? {
            if !interface
                .flags
                .contains(InterfaceFlags::IFF_UP | InterfaceFlags::IFF_BROADCAST)
            {
                continue;
            }
            let Some(address) = interface
                .address
                .and_then(|address| address.as_sockaddr_in().map(|address| address.ip()))
            else {
                continue;
            };
            let Some(broadcast) = interface
                .broadcast
                .and_then(|address| address.as_sockaddr_in().map(|address| address.ip()))
            else {
                continue;
            };
            let Ok(interface_index) = if_nametoindex(interface.interface_name.as_str()) else {
                continue;
            };
            if addresses.len() == MAX_IPV4_INTERFACE_ADDRESSES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "IPv4 interface address snapshot exceeded its limit",
                ));
            }
            addresses.push(Ipv4InterfaceAddress {
                interface_index,
                address,
                broadcast: Some(broadcast),
            });
        }
        Ok(addresses)
    }

    pub(super) fn send_with_source(
        socket: &UdpSocket,
        data: &[u8],
        destination: SocketAddr,
        source: DestinationMetadata,
        unspecified_source: bool,
    ) -> io::Result<()> {
        let destination = SockaddrStorage::from(destination);
        let iov = [IoSlice::new(data)];
        let sent = match source.ip {
            IpAddr::V4(ip) => send_ipv4(
                socket,
                &iov,
                &destination,
                ip,
                source.interface_index,
                unspecified_source,
            ),
            IpAddr::V6(ip) => {
                let info = libc::in6_pktinfo {
                    ipi6_ifindex: c_interface_index(source.interface_index),
                    ipi6_addr: libc::in6_addr {
                        s6_addr: if unspecified_source {
                            std::net::Ipv6Addr::UNSPECIFIED.octets()
                        } else {
                            ip.octets()
                        },
                    },
                };
                sendmsg(
                    socket.as_raw_fd(),
                    &iov,
                    &[ControlMessage::Ipv6PacketInfo(&info)],
                    MsgFlags::empty(),
                    Some(&destination),
                )
            }
        }
        .map_err(io::Error::from)?;
        if sent != data.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "UDP send wrote a partial datagram",
            ));
        }
        Ok(())
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos",
    ))]
    fn send_ipv4(
        socket: &UdpSocket,
        iov: &[IoSlice<'_>],
        destination: &SockaddrStorage,
        ip: std::net::Ipv4Addr,
        interface_index: u32,
        unspecified_source: bool,
    ) -> nix::Result<usize> {
        let info = libc::in_pktinfo {
            ipi_ifindex: interface_index as _,
            ipi_spec_dst: libc::in_addr {
                s_addr: if unspecified_source {
                    0
                } else {
                    u32::from_ne_bytes(ip.octets())
                },
            },
            ipi_addr: libc::in_addr { s_addr: 0 },
        };
        sendmsg(
            socket.as_raw_fd(),
            iov,
            &[ControlMessage::Ipv4PacketInfo(&info)],
            MsgFlags::empty(),
            Some(destination),
        )
    }

    #[cfg(target_os = "freebsd")]
    fn send_ipv4(
        socket: &UdpSocket,
        iov: &[IoSlice<'_>],
        destination: &SockaddrStorage,
        ip: std::net::Ipv4Addr,
        _interface_index: u32,
        unspecified_source: bool,
    ) -> nix::Result<usize> {
        let addr = libc::in_addr {
            s_addr: if unspecified_source {
                0
            } else {
                u32::from_ne_bytes(ip.octets())
            },
        };
        sendmsg(
            socket.as_raw_fd(),
            iov,
            &[ControlMessage::Ipv4SendSrcAddr(&addr)],
            MsgFlags::empty(),
            Some(destination),
        )
    }

    fn decode_socket_addr(storage: &SockaddrStorage) -> Option<SocketAddr> {
        storage
            .as_sockaddr_in()
            .copied()
            .map(SocketAddr::from)
            .or_else(|| storage.as_sockaddr_in6().copied().map(SocketAddr::from))
    }

    fn normalize_interface_index<T>(index: T) -> u32
    where
        u32: TryFrom<T>,
    {
        u32::try_from(index).unwrap_or(0)
    }

    fn c_interface_index<T>(index: u32) -> T
    where
        T: TryFrom<u32> + Default,
    {
        T::try_from(index).unwrap_or_default()
    }
}

#[cfg(any(target_os = "dragonfly", target_os = "netbsd", target_os = "openbsd"))]
// These BSDs expose the required ancillary ABI through libc, while nix's
// `net` feature is not currently portable to all three targets.
mod platform {
    use std::mem;
    use std::os::fd::AsRawFd;
    use std::ptr;

    use super::*;

    const CONTROL_LEN: usize = 128;
    const OPTION_ON: libc::c_int = 1;

    #[derive(Clone, Copy)]
    #[repr(align(8))]
    struct Aligned<T>(T);

    pub(super) fn enable_packet_info(socket: &UdpSocket) -> io::Result<()> {
        if socket.local_addr()?.is_ipv4() {
            enable_ipv4_packet_info(socket)
        } else {
            set_socket_option(socket, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO)
        }
    }

    #[cfg(target_os = "netbsd")]
    fn enable_ipv4_packet_info(socket: &UdpSocket) -> io::Result<()> {
        set_socket_option(socket, libc::IPPROTO_IP, libc::IP_PKTINFO)
    }

    #[cfg(any(target_os = "dragonfly", target_os = "openbsd"))]
    fn enable_ipv4_packet_info(socket: &UdpSocket) -> io::Result<()> {
        set_socket_option(socket, libc::IPPROTO_IP, libc::IP_RECVDSTADDR)?;
        set_socket_option(socket, libc::IPPROTO_IP, libc::IP_RECVIF)
    }

    #[allow(unsafe_code)]
    pub(super) fn recv_with_packet_info(
        socket: &UdpSocket,
        buf: &mut [u8],
    ) -> io::Result<ReceivedDatagram> {
        // SAFETY: `sockaddr_storage` is a plain C storage type for which the
        // all-zero bit pattern is valid initialization.
        let mut source: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let mut control = Aligned([0_u8; CONTROL_LEN]);
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        // SAFETY: an all-zero `msghdr` is valid before its pointer/length
        // fields are initialized below.
        let mut message: libc::msghdr = unsafe { mem::zeroed() };
        message.msg_name = (&mut source as *mut libc::sockaddr_storage).cast();
        message.msg_namelen = mem::size_of_val(&source) as _;
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.0.as_mut_ptr().cast();
        message.msg_controllen = CONTROL_LEN as _;

        // SAFETY: every pointer in `message` refers to live writable storage
        // with the matching length for the duration of the call.
        let len = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut message, 0) };
        if len < 0 {
            return Err(io::Error::last_os_error());
        }
        if message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "UDP datagram or packet metadata exceeded its receive buffer",
            ));
        }

        // SAFETY: `recvmsg` initialized `source` and bounded `msg_namelen` by
        // the supplied `sockaddr_storage`; the destination storage is at least
        // as large and does not overlap it.
        let source = unsafe {
            let (_, address) = socket2::SockAddr::try_init(|storage, storage_len| {
                *storage_len = message.msg_namelen as _;
                ptr::copy_nonoverlapping(
                    (&source as *const libc::sockaddr_storage).cast::<u8>(),
                    storage.cast::<u8>(),
                    message.msg_namelen as usize,
                );
                Ok(())
            })?;
            address.as_socket()
        }
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "received a non-IP UDP address")
        })?;

        Ok(ReceivedDatagram {
            len: len as usize,
            source,
            destination: decode_destination(&message),
        })
    }

    #[allow(unsafe_code)]
    pub(super) fn send_with_source(
        socket: &UdpSocket,
        data: &[u8],
        destination: SocketAddr,
        source: DestinationMetadata,
        unspecified_source: bool,
    ) -> io::Result<()> {
        let destination = socket2::SockAddr::from(destination);
        let mut control = Aligned([0_u8; CONTROL_LEN]);
        let mut iov = libc::iovec {
            iov_base: data.as_ptr().cast_mut().cast(),
            iov_len: data.len(),
        };
        // SAFETY: an all-zero `msghdr` is valid before its pointer/length
        // fields are initialized below.
        let mut message: libc::msghdr = unsafe { mem::zeroed() };
        message.msg_name = destination.as_ptr().cast_mut().cast();
        message.msg_namelen = destination.len();
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.0.as_mut_ptr().cast();
        message.msg_controllen = CONTROL_LEN as _;

        match source.ip {
            #[cfg(target_os = "netbsd")]
            IpAddr::V4(ip) => encode_control(
                &mut message,
                libc::IPPROTO_IP,
                libc::IP_PKTINFO,
                libc::in_pktinfo {
                    ipi_addr: libc::in_addr {
                        s_addr: if unspecified_source {
                            0
                        } else {
                            u32::from_ne_bytes(ip.octets())
                        },
                    },
                    ipi_ifindex: source.interface_index,
                },
            ),
            #[cfg(any(target_os = "dragonfly", target_os = "openbsd"))]
            IpAddr::V4(ip) => encode_control(
                &mut message,
                libc::IPPROTO_IP,
                libc::IP_SENDSRCADDR,
                libc::in_addr {
                    s_addr: if unspecified_source {
                        0
                    } else {
                        u32::from_ne_bytes(ip.octets())
                    },
                },
            ),
            IpAddr::V6(ip) => encode_control(
                &mut message,
                libc::IPPROTO_IPV6,
                libc::IPV6_PKTINFO,
                libc::in6_pktinfo {
                    ipi6_addr: libc::in6_addr {
                        s6_addr: if unspecified_source {
                            std::net::Ipv6Addr::UNSPECIFIED.octets()
                        } else {
                            ip.octets()
                        },
                    },
                    ipi6_ifindex: source.interface_index,
                },
            ),
        }?;

        // SAFETY: the message's address, iovec, and control pointers all refer
        // to live immutable storage with matching lengths during the call.
        let sent = unsafe { libc::sendmsg(socket.as_raw_fd(), &message, 0) };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        if sent as usize != data.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "UDP send wrote a partial datagram",
            ));
        }
        Ok(())
    }

    #[allow(unsafe_code)]
    fn set_socket_option(socket: &UdpSocket, level: i32, name: i32) -> io::Result<()> {
        // SAFETY: `OPTION_ON` is live for the call and its pointer and length
        // describe one `c_int`, as required by these socket options.
        let result = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                level,
                name,
                (&OPTION_ON as *const libc::c_int).cast(),
                mem::size_of_val(&OPTION_ON) as libc::socklen_t,
            )
        };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    #[allow(unsafe_code)]
    fn decode_destination(message: &libc::msghdr) -> Option<DestinationMetadata> {
        // This private helper is called only while `message` references the
        // aligned control buffer just populated by `recvmsg`.
        // SAFETY: the private caller preserves that control-buffer invariant.
        let mut control = unsafe { libc::CMSG_FIRSTHDR(message) };
        let mut destination_ip = None;
        let mut interface_index = 0;
        while !control.is_null() {
            // SAFETY: CMSG_FIRSTHDR/CMSG_NXTHDR returned this non-null header
            // within the caller-validated control buffer.
            let header = unsafe { &*control };
            // SAFETY: CMSG_LEN performs only the platform alignment calculation.
            let empty_len = unsafe { libc::CMSG_LEN(0) as usize };
            if header.cmsg_len as usize >= empty_len {
                match (header.cmsg_level, header.cmsg_type) {
                    #[cfg(target_os = "netbsd")]
                    (libc::IPPROTO_IP, libc::IP_PKTINFO)
                        if header.cmsg_len as usize >= {
                            // SAFETY: CMSG_LEN performs only the platform
                            // alignment calculation for this payload size.
                            unsafe {
                                libc::CMSG_LEN(mem::size_of::<libc::in_pktinfo>() as _) as usize
                            }
                        } =>
                    {
                        // SAFETY: the checked cmsg length contains an
                        // `in_pktinfo`; ancillary payload may be unaligned.
                        let info = unsafe {
                            ptr::read_unaligned(libc::CMSG_DATA(control).cast::<libc::in_pktinfo>())
                        };
                        destination_ip = Some(IpAddr::V4(std::net::Ipv4Addr::from(
                            info.ipi_addr.s_addr.to_ne_bytes(),
                        )));
                        interface_index = info.ipi_ifindex;
                    }
                    #[cfg(any(target_os = "dragonfly", target_os = "openbsd"))]
                    (libc::IPPROTO_IP, libc::IP_RECVDSTADDR)
                        if header.cmsg_len as usize >= {
                            // SAFETY: CMSG_LEN performs only the platform
                            // alignment calculation for this payload size.
                            unsafe { libc::CMSG_LEN(mem::size_of::<libc::in_addr>() as _) as usize }
                        } =>
                    {
                        // SAFETY: the checked cmsg length contains an `in_addr`;
                        // unaligned read is required because ancillary payload
                        // alignment is not represented by the pointer type.
                        let addr = unsafe {
                            ptr::read_unaligned(libc::CMSG_DATA(control).cast::<libc::in_addr>())
                        };
                        destination_ip = Some(IpAddr::V4(std::net::Ipv4Addr::from(
                            addr.s_addr.to_ne_bytes(),
                        )));
                    }
                    #[cfg(any(target_os = "dragonfly", target_os = "openbsd"))]
                    (libc::IPPROTO_IP, libc::IP_RECVIF)
                        if header.cmsg_len as usize >= {
                            // SAFETY: CMSG_LEN performs only the platform
                            // alignment calculation for this payload size.
                            unsafe {
                                libc::CMSG_LEN(mem::size_of::<libc::sockaddr_dl>() as _) as usize
                            }
                        } =>
                    {
                        // SAFETY: the checked cmsg length contains a
                        // `sockaddr_dl`; ancillary payload may be unaligned.
                        let address = unsafe {
                            ptr::read_unaligned(
                                libc::CMSG_DATA(control).cast::<libc::sockaddr_dl>(),
                            )
                        };
                        interface_index = u32::from(address.sdl_index);
                    }
                    (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO)
                        if header.cmsg_len as usize >= {
                            // SAFETY: CMSG_LEN performs only the platform
                            // alignment calculation for this payload size.
                            unsafe {
                                libc::CMSG_LEN(mem::size_of::<libc::in6_pktinfo>() as _) as usize
                            }
                        } =>
                    {
                        // SAFETY: the checked cmsg length contains an
                        // `in6_pktinfo`; ancillary payload may be unaligned.
                        let info = unsafe {
                            ptr::read_unaligned(
                                libc::CMSG_DATA(control).cast::<libc::in6_pktinfo>(),
                            )
                        };
                        destination_ip =
                            Some(IpAddr::V6(std::net::Ipv6Addr::from(info.ipi6_addr.s6_addr)));
                        interface_index = info.ipi6_ifindex;
                    }
                    _ => {}
                }
            }
            // SAFETY: `control` is the current header in the live control
            // buffer and `message` retains the length returned by `recvmsg`.
            control = unsafe { libc::CMSG_NXTHDR(message, control) };
        }
        destination_ip.map(|ip| DestinationMetadata::new(ip, interface_index))
    }

    #[allow(unsafe_code)]
    pub(super) fn ipv4_interface_addresses() -> io::Result<Vec<Ipv4InterfaceAddress>> {
        struct InterfaceList(*mut libc::ifaddrs);

        impl Drop for InterfaceList {
            fn drop(&mut self) {
                // SAFETY: the pointer was returned by `getifaddrs` and is
                // released exactly once after traversal finishes.
                if !self.0.is_null() {
                    unsafe { libc::freeifaddrs(self.0) };
                }
            }
        }

        let mut head = ptr::null_mut();
        // SAFETY: `head` is a live output pointer populated by `getifaddrs`.
        if unsafe { libc::getifaddrs(&mut head) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let interfaces = InterfaceList(head);
        let mut addresses = Vec::new();
        let mut current = interfaces.0;
        while !current.is_null() {
            // SAFETY: every node in the getifaddrs-owned linked list remains
            // live until `interfaces` is dropped after this traversal.
            let interface = unsafe { &*current };
            let required_flags = (libc::IFF_UP | libc::IFF_BROADCAST) as libc::c_uint;
            if interface.ifa_flags & required_flags == required_flags
                && !interface.ifa_name.is_null()
            {
                // SAFETY: non-null AF_INET pointers in an `ifaddrs` entry
                // reference live `sockaddr_in` values for the list lifetime.
                let address = unsafe { ipv4_sockaddr(interface.ifa_addr) };
                // BSD exposes the broadcast/destination union as ifa_dstaddr;
                // IFF_BROADCAST establishes which union member is active.
                let broadcast = unsafe { ipv4_sockaddr(interface.ifa_dstaddr) };
                if let (Some(address), Some(broadcast)) = (address, broadcast) {
                    // SAFETY: getifaddrs supplies a NUL-terminated interface
                    // name that remains live for the list lifetime.
                    let interface_index = unsafe { libc::if_nametoindex(interface.ifa_name) };
                    if interface_index != 0 {
                        if addresses.len() == MAX_IPV4_INTERFACE_ADDRESSES {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "IPv4 interface address snapshot exceeded its limit",
                            ));
                        }
                        addresses.push(Ipv4InterfaceAddress {
                            interface_index,
                            address,
                            broadcast: Some(broadcast),
                        });
                    }
                }
            }
            current = interface.ifa_next;
        }
        Ok(addresses)
    }

    #[allow(unsafe_code)]
    unsafe fn ipv4_sockaddr(address: *const libc::sockaddr) -> Option<Ipv4Addr> {
        if address.is_null() {
            return None;
        }
        // SAFETY: the caller guarantees a live sockaddr; reading its family is
        // valid before deciding whether the larger IPv4 representation applies.
        if unsafe { (*address).sa_family as i32 } != libc::AF_INET {
            return None;
        }
        // SAFETY: AF_INET identifies this live sockaddr as `sockaddr_in`.
        let address = unsafe { &*address.cast::<libc::sockaddr_in>() };
        Some(Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()))
    }

    #[allow(unsafe_code)]
    fn encode_control<T: Copy>(
        message: &mut libc::msghdr,
        level: i32,
        kind: i32,
        value: T,
    ) -> io::Result<()> {
        // This private helper receives only messages backed by the aligned,
        // writable control buffer allocated in `send_with_source`.
        // SAFETY: CMSG_SPACE performs only the platform alignment calculation.
        let required = unsafe { libc::CMSG_SPACE(mem::size_of::<T>() as _) as usize };
        if (message.msg_controllen as usize) < required {
            return Err(io::Error::other("packet-info control buffer is too small"));
        }
        // SAFETY: `message` was initialized with a live aligned control buffer
        // and its capacity was checked above.
        let control = unsafe { libc::CMSG_FIRSTHDR(message) };
        if control.is_null() {
            return Err(io::Error::other("packet-info control buffer is invalid"));
        }
        // SAFETY: `control` is non-null and the capacity check guarantees room
        // for both the header and a `T`; unaligned write handles ABI padding.
        unsafe {
            (*control).cmsg_level = level;
            (*control).cmsg_type = kind;
            (*control).cmsg_len = libc::CMSG_LEN(mem::size_of::<T>() as _) as _;
            ptr::write_unaligned(libc::CMSG_DATA(control).cast::<T>(), value);
        }
        message.msg_controllen = required as _;
        Ok(())
    }
}

#[cfg(windows)]
// Winsock exposes WSARecvMsg only as a provider extension function pointer.
// Keep the required FFI and ancillary-buffer handling confined to this module.
mod platform {
    use std::mem;
    use std::os::windows::io::AsRawSocket;
    use std::ptr;
    use std::sync::LazyLock;

    use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper;
    use windows_sys::Win32::Networking::WinSock;

    use super::*;

    const CONTROL_LEN: usize = 64;
    const OPTION_ON: u32 = 1;

    #[derive(Clone, Copy)]
    #[repr(align(8))]
    struct Aligned<T>(T);

    pub(super) fn enable_packet_info(socket: &UdpSocket) -> io::Result<()> {
        let recv_msg_available = RECV_MSG
            .as_ref()
            .map_err(|error| winsock_error(*error))?
            .is_some();
        if !recv_msg_available {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Winsock provider does not expose WSARecvMsg",
            ));
        }

        if socket.local_addr()?.is_ipv4() {
            set_socket_option(socket, WinSock::IPPROTO_IP, WinSock::IP_PKTINFO)?;
        } else {
            set_socket_option(socket, WinSock::IPPROTO_IPV6, WinSock::IPV6_PKTINFO)?;
            if !socket2::SockRef::from(socket).only_v6()? {
                set_socket_option(socket, WinSock::IPPROTO_IP, WinSock::IP_PKTINFO)?;
            }
        }
        Ok(())
    }

    #[allow(unsafe_code)]
    pub(super) fn recv_with_packet_info(
        socket: &UdpSocket,
        buf: &mut [u8],
    ) -> io::Result<ReceivedDatagram> {
        let recv_msg = RECV_MSG
            .as_ref()
            .map_err(|error| winsock_error(*error))?
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::Unsupported, "WSARecvMsg is unavailable")
            })?;
        let mut control = Aligned([0_u8; CONTROL_LEN]);
        // SAFETY: `SOCKADDR_INET` is a C address union for which zero is a
        // valid initial state before WSARecvMsg fills it.
        let mut source: WinSock::SOCKADDR_INET = unsafe { mem::zeroed() };
        let mut data = WinSock::WSABUF {
            buf: buf.as_mut_ptr(),
            len: buf.len().try_into().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "UDP receive buffer is too large",
                )
            })?,
        };
        let mut message = WinSock::WSAMSG {
            name: (&mut source as *mut WinSock::SOCKADDR_INET).cast(),
            namelen: mem::size_of_val(&source) as i32,
            lpBuffers: &mut data,
            dwBufferCount: 1,
            Control: WinSock::WSABUF {
                buf: control.0.as_mut_ptr(),
                len: CONTROL_LEN as u32,
            },
            dwFlags: 0,
        };
        let mut len = 0_u32;
        // SAFETY: the provider-supplied function pointer is present, and every
        // pointer in `message` and `len` refers to live writable storage with
        // the corresponding Winsock length for the duration of the call.
        let result = unsafe {
            recv_msg(
                socket.as_raw_socket() as usize,
                &mut message,
                &mut len,
                ptr::null_mut(),
                None,
            )
        };
        if result == WinSock::SOCKET_ERROR {
            // WSAGetLastError must immediately follow the failing Winsock call;
            // GetLastError/last_os_error uses a different thread-local slot.
            return Err(winsock_error(unsafe { WinSock::WSAGetLastError() }));
        }
        if message.dwFlags & (WinSock::MSG_TRUNC | WinSock::MSG_CTRUNC) != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "UDP datagram or packet metadata exceeded its receive buffer",
            ));
        }

        // SAFETY: WSARecvMsg initialized `source` and bounded `namelen` by the
        // supplied `SOCKADDR_INET`; the destination does not overlap it.
        let source = unsafe {
            let (_, address) = socket2::SockAddr::try_init(|storage, storage_len| {
                *storage_len = message.namelen as _;
                ptr::copy_nonoverlapping(
                    (&source as *const WinSock::SOCKADDR_INET).cast::<u8>(),
                    storage.cast::<u8>(),
                    message.namelen as usize,
                );
                Ok(())
            })?;
            address.as_socket()
        }
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "received a non-IP UDP address")
        })?;

        Ok(ReceivedDatagram {
            len: len as usize,
            source,
            destination: decode_destination(&message),
        })
    }

    #[allow(unsafe_code)]
    pub(super) fn send_with_source(
        socket: &UdpSocket,
        data: &[u8],
        destination: SocketAddr,
        source: DestinationMetadata,
        unspecified_source: bool,
    ) -> io::Result<()> {
        let destination = socket2::SockAddr::from(destination);
        let mut control = Aligned([0_u8; CONTROL_LEN]);
        let control_len = match source.ip {
            IpAddr::V4(ip) => {
                let ip = if unspecified_source {
                    std::net::Ipv4Addr::UNSPECIFIED
                } else {
                    ip
                };
                let source_address = socket2::SockAddr::from(SocketAddr::new(IpAddr::V4(ip), 0));
                // SAFETY: socket2 constructed an AF_INET address at least as
                // large and aligned as `SOCKADDR_IN`; the value is copied.
                let source_address =
                    unsafe { ptr::read(source_address.as_ptr().cast::<WinSock::SOCKADDR_IN>()) };
                encode_control(
                    &mut control.0,
                    WinSock::IPPROTO_IP,
                    WinSock::IP_PKTINFO,
                    WinSock::IN_PKTINFO {
                        ipi_addr: source_address.sin_addr,
                        ipi_ifindex: source.interface_index,
                    },
                )
            }
            IpAddr::V6(ip) => {
                let ip = if unspecified_source {
                    std::net::Ipv6Addr::UNSPECIFIED
                } else {
                    ip
                };
                let source_address = socket2::SockAddr::from(SocketAddr::new(IpAddr::V6(ip), 0));
                // SAFETY: socket2 constructed an AF_INET6 address at least as
                // large and aligned as `SOCKADDR_IN6`; the value is copied.
                let source_address =
                    unsafe { ptr::read(source_address.as_ptr().cast::<WinSock::SOCKADDR_IN6>()) };
                encode_control(
                    &mut control.0,
                    WinSock::IPPROTO_IPV6,
                    WinSock::IPV6_PKTINFO,
                    WinSock::IN6_PKTINFO {
                        ipi6_addr: source_address.sin6_addr,
                        ipi6_ifindex: source.interface_index,
                    },
                )
            }
        }?;
        let mut buffer = WinSock::WSABUF {
            buf: data.as_ptr().cast_mut(),
            len: data.len().try_into().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "UDP datagram is too large")
            })?,
        };
        let message = WinSock::WSAMSG {
            name: destination.as_ptr().cast_mut().cast(),
            namelen: destination.len(),
            lpBuffers: &mut buffer,
            dwBufferCount: 1,
            Control: WinSock::WSABUF {
                buf: control.0.as_mut_ptr(),
                len: control_len as u32,
            },
            dwFlags: 0,
        };
        let mut sent = 0_u32;
        // SAFETY: the message address, data buffer, control buffer, and sent
        // count all refer to live storage with their exact Winsock lengths.
        let result = unsafe {
            WinSock::WSASendMsg(
                socket.as_raw_socket() as usize,
                &message,
                0,
                &mut sent,
                ptr::null_mut(),
                None,
            )
        };
        if result == WinSock::SOCKET_ERROR {
            // SAFETY: this is the immediate error query for WSASendMsg above.
            return Err(winsock_error(unsafe { WinSock::WSAGetLastError() }));
        }
        if sent as usize != data.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "UDP send wrote a partial datagram",
            ));
        }
        Ok(())
    }

    #[allow(unsafe_code)]
    fn set_socket_option(socket: &UdpSocket, level: i32, name: i32) -> io::Result<()> {
        // SAFETY: `OPTION_ON` is live for the call and its pointer and length
        // describe the DWORD required by IP_PKTINFO/IPV6_PKTINFO.
        let result = unsafe {
            WinSock::setsockopt(
                socket.as_raw_socket() as usize,
                level,
                name,
                (&OPTION_ON as *const u32).cast(),
                mem::size_of_val(&OPTION_ON) as i32,
            )
        };
        if result == WinSock::SOCKET_ERROR {
            // SAFETY: this is the immediate error query for setsockopt above.
            Err(winsock_error(unsafe { WinSock::WSAGetLastError() }))
        } else {
            Ok(())
        }
    }

    #[allow(unsafe_code)]
    fn decode_destination(message: &WinSock::WSAMSG) -> Option<DestinationMetadata> {
        let header_size = data_align(mem::size_of::<WinSock::CMSGHDR>());
        let mut offset = 0_usize;
        while offset.checked_add(header_size)? <= message.Control.len as usize {
            // SAFETY: the checked offset leaves a complete CMSGHDR in the live
            // control buffer; an unaligned read avoids an alignment assumption.
            let header = unsafe {
                ptr::read_unaligned(message.Control.buf.add(offset).cast::<WinSock::CMSGHDR>())
            };
            let message_len = header.cmsg_len as usize;
            if message_len < header_size
                || offset.checked_add(message_len)? > message.Control.len as usize
            {
                return None;
            }
            // SAFETY: the bounds check above proves this payload pointer lies
            // within the live control buffer.
            let payload = unsafe { message.Control.buf.add(offset + header_size) };
            match (header.cmsg_level, header.cmsg_type) {
                (WinSock::IPPROTO_IP, WinSock::IP_PKTINFO)
                    if message_len >= header_size + mem::size_of::<WinSock::IN_PKTINFO>() =>
                {
                    // SAFETY: the checked message length contains IN_PKTINFO;
                    // ancillary payload is not assumed to be aligned.
                    let info =
                        unsafe { ptr::read_unaligned(payload.cast::<WinSock::IN_PKTINFO>()) };
                    // SAFETY: the active union representation is the IPv4
                    // address written by Winsock for an IP_PKTINFO message.
                    let octets = unsafe { info.ipi_addr.S_un.S_addr }.to_ne_bytes();
                    return Some(DestinationMetadata::new(
                        IpAddr::V4(Ipv4Addr::from(octets)),
                        info.ipi_ifindex,
                    ));
                }
                (WinSock::IPPROTO_IPV6, WinSock::IPV6_PKTINFO)
                    if message_len >= header_size + mem::size_of::<WinSock::IN6_PKTINFO>() =>
                {
                    // SAFETY: the checked message length contains IN6_PKTINFO;
                    // ancillary payload is not assumed to be aligned.
                    let info =
                        unsafe { ptr::read_unaligned(payload.cast::<WinSock::IN6_PKTINFO>()) };
                    // SAFETY: the active union representation is the byte array
                    // written by Winsock for an IPV6_PKTINFO message.
                    let address = unsafe { info.ipi6_addr.u.Byte };
                    return Some(DestinationMetadata::new(
                        IpAddr::V6(std::net::Ipv6Addr::from(address)),
                        info.ipi6_ifindex,
                    ));
                }
                _ => {}
            }
            offset = offset.checked_add(header_align(message_len))?;
        }
        None
    }

    #[allow(unsafe_code)]
    pub(super) fn ipv4_interface_addresses() -> io::Result<Vec<Ipv4InterfaceAddress>> {
        const MAX_TABLE_ATTEMPTS: usize = 3;

        let mut required = 0_u32;
        // SAFETY: a null table is the documented size-query form, and
        // `required` is a live output pointer.
        let result =
            unsafe { IpHelper::GetIpAddrTable(ptr::null_mut(), &mut required, false.into()) };
        if result != ERROR_INSUFFICIENT_BUFFER && result != NO_ERROR {
            return Err(io::Error::from_raw_os_error(result as i32));
        }
        let (storage, required) = load_ipv4_table(required, MAX_TABLE_ATTEMPTS, |table, size| {
            // SAFETY: `load_ipv4_table` provides a live, aligned allocation of
            // exactly the capacity reported through `size`.
            unsafe { IpHelper::GetIpAddrTable(table, size, false.into()) }
        })?;
        if storage.is_empty() {
            return Ok(Vec::new());
        }
        let capacity = storage.len() * mem::size_of::<u32>();
        let table = storage.as_ptr().cast::<IpHelper::MIB_IPADDRTABLE>();

        let rows_offset = mem::offset_of!(IpHelper::MIB_IPADDRTABLE, table);
        if required as usize > capacity || (required as usize) < rows_offset {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Winsock returned an invalid IPv4 interface table size",
            ));
        }
        // SAFETY: the successful API call initialized the fixed header inside
        // the validated table buffer.
        let count = unsafe { (*table).dwNumEntries as usize };
        let available_rows =
            (required as usize - rows_offset) / mem::size_of::<IpHelper::MIB_IPADDRROW_XP>();
        if count > available_rows || count > MAX_IPV4_INTERFACE_ADDRESSES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Windows returned an invalid or oversized IPv4 interface table",
            ));
        }
        // SAFETY: `count` was bounded by the initialized table size and the
        // first row starts at the ABI-defined `table` field offset.
        let rows: &[IpHelper::MIB_IPADDRROW_XP] = unsafe {
            std::slice::from_raw_parts(storage.as_ptr().cast::<u8>().add(rows_offset).cast(), count)
        };
        Ok(rows
            .iter()
            .filter(|row| {
                let inactive =
                    (IpHelper::MIB_IPADDR_DELETED | IpHelper::MIB_IPADDR_DISCONNECTED) as u16;
                row.wType & inactive == 0
            })
            .map(|row| {
                let address = Ipv4Addr::from(row.dwAddr.to_ne_bytes());
                let netmask = Ipv4Addr::from(row.dwMask.to_ne_bytes());
                // GetIpAddrTable does not populate dwBCastAddr reliably. Its
                // address and mask fields provide the interface prefix needed
                // to derive the subnet-directed all-ones broadcast address.
                let broadcast = ipv4_directed_broadcast(address, netmask);
                Ipv4InterfaceAddress {
                    interface_index: row.dwIndex,
                    address,
                    broadcast,
                }
            })
            .collect())
    }

    fn load_ipv4_table<F>(
        mut required: u32,
        max_attempts: usize,
        mut get_table: F,
    ) -> io::Result<(Vec<u32>, u32)>
    where
        F: FnMut(*mut IpHelper::MIB_IPADDRTABLE, &mut u32) -> u32,
    {
        const MAX_TABLE_SIZE: u32 = 1024 * 1024;

        for _ in 0..max_attempts {
            if required == 0 {
                return Ok((Vec::new(), 0));
            }
            if required > MAX_TABLE_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "IPv4 interface table exceeded its bounded buffer",
                ));
            }
            let word_count = (required as usize).div_ceil(mem::size_of::<u32>());
            let mut storage = vec![0_u32; word_count];
            let capacity = (storage.len() * mem::size_of::<u32>()) as u32;
            let mut returned_size = capacity;
            let result = get_table(
                storage.as_mut_ptr().cast::<IpHelper::MIB_IPADDRTABLE>(),
                &mut returned_size,
            );
            if result == NO_ERROR {
                return Ok((storage, returned_size));
            }
            if result != ERROR_INSUFFICIENT_BUFFER {
                return Err(io::Error::from_raw_os_error(result as i32));
            }
            required = returned_size;
        }
        Err(io::Error::other(
            "IPv4 interface table kept growing during bounded retries",
        ))
    }

    fn winsock_error(code: i32) -> io::Error {
        io::Error::from_raw_os_error(code)
    }

    #[allow(unsafe_code)]
    fn encode_control<T: Copy>(
        buffer: &mut [u8],
        level: i32,
        kind: i32,
        value: T,
    ) -> io::Result<usize> {
        let header_size = data_align(mem::size_of::<WinSock::CMSGHDR>());
        let message_len = header_size + mem::size_of::<T>();
        let space =
            data_align(mem::size_of::<WinSock::CMSGHDR>() + header_align(mem::size_of::<T>()));
        if buffer.len() < space {
            return Err(io::Error::other("packet-info control buffer is too small"));
        }
        let header = WinSock::CMSGHDR {
            cmsg_len: message_len,
            cmsg_level: level,
            cmsg_type: kind,
        };
        // SAFETY: the capacity check guarantees space for the CMSGHDR and `T`;
        // unaligned writes account for the byte buffer's represented alignment.
        unsafe {
            ptr::write_unaligned(buffer.as_mut_ptr().cast::<WinSock::CMSGHDR>(), header);
            ptr::write_unaligned(buffer.as_mut_ptr().add(header_size).cast::<T>(), value);
        }
        Ok(space)
    }

    const fn header_align(length: usize) -> usize {
        (length + mem::align_of::<WinSock::CMSGHDR>() - 1)
            & !(mem::align_of::<WinSock::CMSGHDR>() - 1)
    }

    const fn data_align(length: usize) -> usize {
        (length + mem::align_of::<usize>() - 1) & !(mem::align_of::<usize>() - 1)
    }

    #[allow(unsafe_code)]
    static RECV_MSG: LazyLock<Result<WinSock::LPFN_WSARECVMSG, i32>> = LazyLock::new(|| {
        // SAFETY: the arguments request an ordinary IPv4 datagram socket and
        // the returned handle is checked before use.
        let socket = unsafe { WinSock::socket(WinSock::AF_INET as i32, WinSock::SOCK_DGRAM, 0) };
        if socket == WinSock::INVALID_SOCKET {
            // SAFETY: this is the immediate error query for socket above.
            return Err(unsafe { WinSock::WSAGetLastError() });
        }
        let guid = WinSock::WSAID_WSARECVMSG;
        let mut function: WinSock::LPFN_WSARECVMSG = None;
        let mut returned = 0_u32;
        // SAFETY: all pointers reference live objects of the exact sizes passed;
        // Winsock writes only the extension function pointer and byte count.
        let result = unsafe {
            WinSock::WSAIoctl(
                socket,
                WinSock::SIO_GET_EXTENSION_FUNCTION_POINTER,
                (&guid as *const windows_sys::core::GUID).cast(),
                mem::size_of_val(&guid) as u32,
                (&mut function as *mut WinSock::LPFN_WSARECVMSG).cast(),
                mem::size_of_val(&function) as u32,
                &mut returned,
                ptr::null_mut(),
                None,
            )
        };
        let ioctl_error = if result == WinSock::SOCKET_ERROR {
            // SAFETY: this is the immediate error query for WSAIoctl above.
            Some(unsafe { WinSock::WSAGetLastError() })
        } else {
            None
        };
        // SAFETY: `socket` is a valid owned Winsock handle and is closed once
        // after the extension-function query completes.
        let close_result = unsafe { WinSock::closesocket(socket) };
        let close_error = if close_result == WinSock::SOCKET_ERROR {
            // SAFETY: this is the immediate error query for closesocket above.
            Some(unsafe { WinSock::WSAGetLastError() })
        } else {
            None
        };
        if let Some(error) = ioctl_error.or(close_error) {
            Err(error)
        } else if returned as usize != mem::size_of::<WinSock::LPFN_WSARECVMSG>() {
            Ok(None)
        } else {
            Ok(function)
        }
    });

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn winsock_codes_map_to_source_selection_and_readiness_kinds() {
            assert_eq!(
                winsock_error(WinSock::WSAEWOULDBLOCK).kind(),
                io::ErrorKind::WouldBlock
            );
            assert_eq!(
                winsock_error(WinSock::WSAEADDRNOTAVAIL).kind(),
                io::ErrorKind::AddrNotAvailable
            );
            assert_eq!(
                winsock_error(WinSock::WSAEINVAL).kind(),
                io::ErrorKind::InvalidInput
            );
            assert_eq!(
                winsock_error(WinSock::WSAENETUNREACH).kind(),
                io::ErrorKind::NetworkUnreachable
            );
            for code in [
                WinSock::WSAEADDRNOTAVAIL,
                WinSock::WSAEINVAL,
                WinSock::WSAENETUNREACH,
            ] {
                assert!(source_selection_failure(&winsock_error(code)));
            }
        }

        #[test]
        fn ipv4_table_growth_retries_are_bounded() {
            let header_size = mem::size_of::<IpHelper::MIB_IPADDRTABLE>() as u32;
            let grown_size = header_size + mem::size_of::<IpHelper::MIB_IPADDRROW_XP>() as u32;
            let mut calls = 0;
            let (storage, returned) = load_ipv4_table(header_size, 3, |table, size| {
                calls += 1;
                if calls == 1 {
                    *size = grown_size;
                    return ERROR_INSUFFICIENT_BUFFER;
                }
                let _ = table;
                NO_ERROR
            })
            .unwrap();
            assert_eq!(calls, 2);
            assert!(storage.len() * mem::size_of::<u32>() >= grown_size as usize);
            assert_eq!(returned, grown_size);

            let mut calls = 0;
            let error = load_ipv4_table(header_size, 3, |_table, size| {
                calls += 1;
                *size = size.saturating_add(4);
                ERROR_INSUFFICIENT_BUFFER
            })
            .unwrap_err();
            assert_eq!(calls, 3);
            assert!(error.to_string().contains("kept growing"));
        }
    }
}

#[cfg(not(any(
    windows,
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "visionos",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "netbsd",
    target_os = "openbsd",
)))]
mod platform {
    use super::*;

    pub(super) fn enable_packet_info(_socket: &UdpSocket) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "packet info is unavailable on this platform",
        ))
    }

    pub(super) fn recv_with_packet_info(
        _socket: &UdpSocket,
        _buf: &mut [u8],
    ) -> io::Result<ReceivedDatagram> {
        unreachable!("packet info cannot be enabled on this platform")
    }

    pub(super) fn send_with_source(
        _socket: &UdpSocket,
        _data: &[u8],
        _destination: SocketAddr,
        _source: DestinationMetadata,
        _unspecified_source: bool,
    ) -> io::Result<()> {
        unreachable!("packet info cannot be enabled on this platform")
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Clone)]
    struct TraceBuffer(Arc<Mutex<Vec<u8>>>);

    impl io::Write for TraceBuffer {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn setup_failure_selects_fallback_and_emits_warning() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let output = Arc::new(Mutex::new(Vec::new()));
        let make_writer = {
            let output = Arc::clone(&output);
            move || TraceBuffer(Arc::clone(&output))
        };
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(make_writer)
            .finish();

        let responder = tracing::subscriber::with_default(subscriber, || {
            UdpResponder::from_setup_result(
                &socket,
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "injected packet-info setup failure",
                )),
            )
        });

        assert!(!responder.packet_info);
        let output = output.lock().unwrap();
        let output = String::from_utf8_lossy(&output);
        assert!(output.contains("UDP destination metadata unavailable"));
        assert!(output.contains("injected packet-info setup failure"));
    }

    #[tokio::test]
    async fn setup_success_selects_destination_metadata() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let responder = UdpResponder::from_setup_result(&socket, Ok(()));
        assert!(responder.packet_info);
    }

    #[tokio::test]
    async fn ordinary_udp_fallback_receives_and_sends() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let responder = UdpResponder::without_packet_info();
        client
            .send_to(b"request", server.local_addr().unwrap())
            .await
            .unwrap();

        let mut request = [0_u8; 64];
        let received = responder.recv(&server, &mut request).await.unwrap();
        assert_eq!(&request[..received.len], b"request");
        assert_eq!(received.destination, None);

        responder
            .send_to(&server, b"response", received.source, None)
            .await
            .unwrap();
        let mut response = [0_u8; 64];
        let (len, source) = client.recv_from(&mut response).await.unwrap();
        assert_eq!(&response[..len], b"response");
        assert_eq!(source, server.local_addr().unwrap());
    }

    #[tokio::test]
    async fn large_response_is_sent_as_an_ordinary_udp_datagram() {
        let server = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let responder = UdpResponder::new(&server);
        let payload = vec![0x5a; 32 * 1024];

        responder
            .send_to(
                &server,
                &payload,
                client.local_addr().unwrap(),
                Some(DestinationMetadata::new("127.0.0.1".parse().unwrap(), 0)),
            )
            .await
            .unwrap();

        let mut received = vec![0_u8; payload.len()];
        let (len, source) = client.recv_from(&mut received).await.unwrap();
        assert_eq!(len, payload.len());
        assert_eq!(received, payload);
        assert_eq!(source.ip(), "127.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn destination_metadata_classifies_from_interface_evidence() {
        let interfaces = [Ipv4InterfaceAddress {
            interface_index: 23,
            address: "192.0.2.10".parse().unwrap(),
            broadcast: ipv4_directed_broadcast(
                "192.0.2.10".parse().unwrap(),
                "255.255.255.0".parse().unwrap(),
            ),
        }];

        assert_eq!(
            classify_from_ipv4_interfaces("192.0.2.10".parse().unwrap(), 23, &interfaces),
            DestinationClassification::Unicast
        );

        assert_eq!(
            classify_from_ipv4_interfaces("192.0.2.255".parse().unwrap(), 23, &interfaces),
            DestinationClassification::NonUnicast
        );

        assert_eq!(
            classify_from_ipv4_interfaces("198.51.100.255".parse().unwrap(), 23, &interfaces),
            DestinationClassification::Unknown
        );

        assert_eq!(
            classify_from_ipv4_interfaces("192.0.2.255".parse().unwrap(), 24, &interfaces),
            DestinationClassification::Unknown
        );

        let aliased_interface = [
            interfaces[0],
            Ipv4InterfaceAddress {
                interface_index: 23,
                address: "192.0.2.255".parse().unwrap(),
                broadcast: ipv4_directed_broadcast(
                    "192.0.2.255".parse().unwrap(),
                    "255.255.255.255".parse().unwrap(),
                ),
            },
        ];
        assert_eq!(
            classify_from_ipv4_interfaces("192.0.2.255".parse().unwrap(), 23, &aliased_interface),
            DestinationClassification::Unicast
        );

        let multicast = DestinationMetadata::new("ff02::1".parse().unwrap(), 29);
        assert_eq!(multicast.interface_index, 29);
        assert_eq!(
            multicast.direct_classification(),
            DestinationClassification::NonUnicast
        );
    }

    #[test]
    fn directed_broadcast_handles_zero_point_to_point_and_host_prefixes() {
        assert_eq!(
            ipv4_directed_broadcast(
                "198.51.100.7".parse().unwrap(),
                "255.255.255.192".parse().unwrap(),
            ),
            Some("198.51.100.63".parse().unwrap())
        );
        assert_eq!(
            ipv4_directed_broadcast("198.51.100.7".parse().unwrap(), "0.0.0.0".parse().unwrap()),
            Some(Ipv4Addr::BROADCAST)
        );
        assert_eq!(
            ipv4_directed_broadcast(
                "198.51.100.6".parse().unwrap(),
                "255.255.255.254".parse().unwrap(),
            ),
            None
        );
        assert_eq!(
            ipv4_directed_broadcast(
                "198.51.100.7".parse().unwrap(),
                "255.255.255.255".parse().unwrap(),
            ),
            None
        );
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos",
    ))]
    #[test]
    fn packet_info_difference_is_non_unicast_evidence() {
        let exact = DestinationMetadata::from_ipv4_packet_info(
            "192.0.2.10".parse().unwrap(),
            17,
            "192.0.2.10".parse().unwrap(),
        );
        assert_eq!(
            exact.direct_classification(),
            DestinationClassification::Unicast
        );

        let broadcast = DestinationMetadata::from_ipv4_packet_info(
            "192.0.2.255".parse().unwrap(),
            17,
            "192.0.2.10".parse().unwrap(),
        );
        assert_eq!(
            broadcast.direct_classification(),
            DestinationClassification::NonUnicast
        );
    }

    #[test]
    fn unknown_destination_recovery_is_interface_only() {
        assert_eq!(
            recovery_after_exact_failure(DestinationClassification::Unknown, 17),
            SendRecovery::InterfaceOnly
        );
        assert_eq!(
            recovery_after_exact_failure(DestinationClassification::Unknown, 0),
            SendRecovery::None
        );
        assert_eq!(
            recovery_after_exact_failure(DestinationClassification::NonUnicast, 17),
            SendRecovery::InterfaceThenKernel
        );
        assert_eq!(
            recovery_after_exact_failure(DestinationClassification::NonUnicast, 0),
            SendRecovery::KernelOnly
        );
        assert_eq!(
            recovery_after_exact_failure(DestinationClassification::Unicast, 17),
            SendRecovery::None
        );
    }

    #[test]
    fn snapshot_failure_preserves_last_known_good_addresses() {
        let now = std::time::Instant::now();
        let address = Ipv4InterfaceAddress {
            interface_index: 17,
            address: "192.0.2.10".parse().unwrap(),
            broadcast: Some("192.0.2.255".parse().unwrap()),
        };
        let mut cache = InterfaceSnapshotCache::default();
        cache.begin_refresh(now);
        let (first, error) = cache.record(Ok(vec![address]));
        assert!(error.is_none());
        assert_eq!(first.as_deref(), Some([address].as_slice()));

        cache.begin_refresh(now + INTERFACE_SNAPSHOT_TTL);
        let (retained, error) = cache.record(Err(io::Error::other("injected refresh failure")));
        assert_eq!(retained.as_deref(), Some([address].as_slice()));
        assert_eq!(error.unwrap().to_string(), "injected refresh failure");
        assert_eq!(
            cache.current_if_fresh(now + INTERFACE_SNAPSHOT_TTL),
            Some(retained),
            "a failed refresh is throttled while preserving the last-known snapshot"
        );

        let mut empty_cache = InterfaceSnapshotCache::default();
        empty_cache.begin_refresh(now);
        let (addresses, error) =
            empty_cache.record(Err(io::Error::other("injected initial failure")));
        assert!(addresses.is_none());
        assert!(error.is_some());
        assert_eq!(empty_cache.current_if_fresh(now), Some(None));
    }

    #[tokio::test]
    async fn cancelled_snapshot_waiter_does_not_orphan_refresh() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let responder = Arc::new(UdpResponder::without_packet_info());
        let retained = Ipv4InterfaceAddress {
            interface_index: 17,
            address: "192.0.2.10".parse().unwrap(),
            broadcast: Some("192.0.2.255".parse().unwrap()),
        };
        {
            let mut cache = responder.ipv4_interfaces.cache();
            cache.last_good = Some(Arc::from([retained]));
        }

        let calls = Arc::new(AtomicUsize::new(0));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let initiating_waiter = {
            let responder = Arc::clone(&responder);
            let calls = Arc::clone(&calls);
            tokio::spawn(async move {
                responder
                    .ipv4_interface_snapshot_with(move || {
                        calls.fetch_add(1, Ordering::SeqCst);
                        started_tx.send(()).unwrap();
                        release_rx.recv().unwrap();
                        Err(io::Error::other("injected detached refresh failure"))
                    })
                    .await
            })
        };

        started_rx.await.unwrap();
        initiating_waiter.abort();
        assert!(initiating_waiter.await.unwrap_err().is_cancelled());

        let second_calls = Arc::clone(&calls);
        let second_waiter = responder.ipv4_interface_snapshot_with(move || {
            second_calls.fetch_add(1, Ordering::SeqCst);
            panic!("an in-flight snapshot refresh must be shared")
        });
        tokio::pin!(second_waiter);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), &mut second_waiter)
                .await
                .is_err(),
            "the second waiter must remain pending on the first enumeration"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        release_tx.send(()).unwrap();
        let snapshot = second_waiter.await;
        assert_eq!(snapshot.as_deref(), Some([retained].as_slice()));

        let final_calls = Arc::clone(&calls);
        let throttled = responder
            .ipv4_interface_snapshot_with(move || {
                final_calls.fetch_add(1, Ordering::SeqCst);
                panic!("a completed failed refresh must be throttled")
            })
            .await;
        assert_eq!(throttled.as_deref(), Some([retained].as_slice()));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn runtime_shutdown_does_not_orphan_snapshot_refresh() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let responder = Arc::new(UdpResponder::without_packet_info());
        let address = Ipv4InterfaceAddress {
            interface_index: 17,
            address: "192.0.2.10".parse().unwrap(),
            broadcast: Some("192.0.2.255".parse().unwrap()),
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let mut completion = responder.ipv4_interfaces.generation.subscribe();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();

        let runtime_a = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime_a.block_on({
            let responder = Arc::clone(&responder);
            let calls = Arc::clone(&calls);
            async move {
                tokio::spawn(async move {
                    responder
                        .ipv4_interface_snapshot_with(move || {
                            calls.fetch_add(1, Ordering::SeqCst);
                            started_tx.send(()).unwrap();
                            release_rx.recv().unwrap();
                            Ok(vec![address])
                        })
                        .await
                });
                started_rx.await.unwrap();
            }
        });

        drop(runtime_a);
        release_tx.send(()).unwrap();

        let runtime_b = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime_b.block_on(async {
            tokio::time::timeout(std::time::Duration::from_secs(1), completion.changed())
                .await
                .expect("refresh publication must survive shutdown of its originating runtime")
                .unwrap();

            let later_calls = Arc::clone(&calls);
            let snapshot = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                responder.ipv4_interface_snapshot_with(move || {
                    later_calls.fetch_add(1, Ordering::SeqCst);
                    panic!("a published refresh must remain throttled in a later runtime")
                }),
            )
            .await
            .expect("a later runtime must not wait on an orphaned refresh");
            assert_eq!(snapshot.as_deref(), Some([address].as_slice()));
        });
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn panicked_snapshot_refresh_clears_in_flight_state() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let responder = UdpResponder::without_packet_info();
        let calls = Arc::new(AtomicUsize::new(0));
        let first_calls = Arc::clone(&calls);
        let snapshot = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            responder.ipv4_interface_snapshot_with(move || {
                first_calls.fetch_add(1, Ordering::SeqCst);
                panic!("injected interface enumeration panic")
            }),
        )
        .await
        .expect("a panicked enumeration must notify its waiter");
        assert!(snapshot.is_none());
        assert!(!responder.ipv4_interfaces.cache().refresh_in_flight);

        let later_calls = Arc::clone(&calls);
        let throttled = responder
            .ipv4_interface_snapshot_with(move || {
                later_calls.fetch_add(1, Ordering::SeqCst);
                panic!("a panicked refresh must still be throttled")
            })
            .await;
        assert!(throttled.is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn fallback_is_limited_to_synchronous_source_selection_failures() {
        for kind in [
            io::ErrorKind::InvalidInput,
            io::ErrorKind::AddrNotAvailable,
            io::ErrorKind::NetworkUnreachable,
        ] {
            assert!(source_selection_failure(&io::Error::from(kind)));
        }
        for kind in [
            io::ErrorKind::WouldBlock,
            io::ErrorKind::Interrupted,
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::Other,
        ] {
            assert!(!source_selection_failure(&io::Error::from(kind)));
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn broadcast_reply_uses_received_interface_without_duplicates() {
        let server = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let responder = UdpResponder::new(&server);
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.set_broadcast(true).unwrap();
        let destination =
            SocketAddr::from(([127, 255, 255, 255], server.local_addr().unwrap().port()));

        client.send_to(b"request", destination).await.unwrap();
        let mut request = [0_u8; 64];
        let received = responder.recv(&server, &mut request).await.unwrap();
        assert_eq!(&request[..received.len], b"request");
        let metadata = received.destination.expect("missing IP_PKTINFO metadata");
        assert_eq!(metadata.ip, destination.ip());
        assert_ne!(metadata.interface_index, 0);
        assert_eq!(
            metadata.direct_classification(),
            DestinationClassification::NonUnicast
        );

        responder
            .send_to(&server, b"response", received.source, received.destination)
            .await
            .unwrap();
        let mut response = [0_u8; 64];
        let (len, source) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.recv_from(&mut response),
        )
        .await
        .expect("broadcast request did not receive a reply")
        .unwrap();
        assert_eq!(&response[..len], b"response");
        assert_eq!(source.ip(), "127.0.0.1".parse::<IpAddr>().unwrap());

        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(50),
                client.recv_from(&mut response),
            )
            .await
            .is_err(),
            "broadcast fallback emitted a duplicate reply"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn ipv6_receive_retains_interface_scope() {
        let server = UdpSocket::bind("[::]:0").await.unwrap();
        let responder = UdpResponder::new(&server);
        let client = UdpSocket::bind("[::1]:0").await.unwrap();
        let destination = SocketAddr::new(
            std::net::Ipv6Addr::LOCALHOST.into(),
            server.local_addr().unwrap().port(),
        );

        client.send_to(b"request", destination).await.unwrap();
        let mut request = [0_u8; 64];
        let received = responder.recv(&server, &mut request).await.unwrap();
        let metadata = received.destination.expect("missing IPV6_PKTINFO metadata");
        assert_eq!(metadata.ip, destination.ip());
        assert_ne!(metadata.interface_index, 0);
        assert_eq!(
            metadata.direct_classification(),
            DestinationClassification::Unicast
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn packet_info_does_not_enable_udp_gro() {
        use nix::sys::socket::{getsockopt, sockopt::UdpGroSegment};

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let _responder = UdpResponder::new(&socket);

        assert!(!getsockopt(&socket, UdpGroSegment).unwrap());
    }
}
