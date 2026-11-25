use std::net::SocketAddr;

pub(crate) fn wildcard_udp_destination(port: u16) -> SocketAddr {
    // Linux routes the alternate loopback address without an interface alias.
    let ip = if cfg!(target_os = "linux") {
        [127, 0, 0, 2]
    } else {
        [127, 0, 0, 1]
    };
    SocketAddr::from((ip, port))
}
