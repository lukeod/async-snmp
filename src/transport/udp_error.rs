//! Shared UDP receive-error classification and bounded backoff.

use std::time::Duration;

const BACKOFF_MIN: Duration = Duration::from_millis(1);
const BACKOFF_MAX: Duration = Duration::from_millis(100);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UdpRecvErrorClass {
    /// The socket received one unusable datagram or ancillary record.
    DatagramLocal,
    /// The socket may recover and the receive operation can be retried.
    Transient,
    /// The receive service cannot safely continue on this socket.
    Fatal,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct UdpRecvErrorBackoff(Duration);

impl UdpRecvErrorBackoff {
    pub(crate) fn reset(&mut self) {
        self.0 = Duration::ZERO;
    }

    pub(crate) fn advance(&mut self) -> Duration {
        self.0 = match self.0 {
            Duration::ZERO => BACKOFF_MIN,
            duration => (duration * 2).min(BACKOFF_MAX),
        };
        self.0
    }

    #[cfg(test)]
    pub(crate) const fn current(self) -> Duration {
        self.0
    }
}

pub(crate) fn classify_udp_recv_error(error: &std::io::Error) -> UdpRecvErrorClass {
    if error.kind() == std::io::ErrorKind::InvalidData {
        return UdpRecvErrorClass::DatagramLocal;
    }
    if matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::Interrupted
            | std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::NetworkDown
            | std::io::ErrorKind::NetworkUnreachable
            | std::io::ErrorKind::HostUnreachable
            | std::io::ErrorKind::AddrNotAvailable
            | std::io::ErrorKind::OutOfMemory
    ) || error.raw_os_error().is_some_and(transient_recv_errno)
    {
        return UdpRecvErrorClass::Transient;
    }
    UdpRecvErrorClass::Fatal
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
    target_os = "dragonfly",
    target_os = "netbsd",
    target_os = "openbsd",
))]
fn transient_recv_errno(code: i32) -> bool {
    use nix::libc;

    matches!(
        code,
        libc::EAGAIN
            | libc::EINTR
            | libc::ENOBUFS
            | libc::ENOMEM
            | libc::ECONNREFUSED
            | libc::ECONNRESET
            | libc::ENETDOWN
            | libc::ENETUNREACH
            | libc::EHOSTUNREACH
    )
}

#[cfg(windows)]
fn transient_recv_errno(code: i32) -> bool {
    use windows_sys::Win32::Networking::WinSock;

    matches!(
        code,
        WinSock::WSAEINTR
            | WinSock::WSAEWOULDBLOCK
            | WinSock::WSAENOBUFS
            | WinSock::WSAECONNREFUSED
            | WinSock::WSAECONNRESET
            | WinSock::WSAENETDOWN
            | WinSock::WSAENETUNREACH
            | WinSock::WSAEHOSTUNREACH
    )
}

#[cfg(not(any(
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
    windows,
)))]
const fn transient_recv_errno(_code: i32) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification_covers_each_service_policy_class() {
        assert_eq!(
            classify_udp_recv_error(&std::io::Error::from(std::io::ErrorKind::InvalidData)),
            UdpRecvErrorClass::DatagramLocal
        );
        assert_eq!(
            classify_udp_recv_error(&std::io::Error::from(std::io::ErrorKind::ConnectionRefused)),
            UdpRecvErrorClass::Transient
        );
        assert_eq!(
            classify_udp_recv_error(&std::io::Error::other("unclassified socket failure")),
            UdpRecvErrorClass::Fatal
        );
    }

    #[test]
    fn backoff_starts_nonzero_doubles_and_caps() {
        let mut backoff = UdpRecvErrorBackoff::default();
        assert_eq!(backoff.advance(), BACKOFF_MIN);
        assert_eq!(backoff.advance(), BACKOFF_MIN * 2);
        for _ in 0..16 {
            backoff.advance();
        }
        assert_eq!(backoff.current(), BACKOFF_MAX);
        backoff.reset();
        assert_eq!(backoff.current(), Duration::ZERO);
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
        target_os = "dragonfly",
        target_os = "netbsd",
        target_os = "openbsd",
    ))]
    #[test]
    fn enobufs_is_transient() {
        assert_eq!(
            classify_udp_recv_error(&std::io::Error::from_raw_os_error(nix::libc::ENOBUFS)),
            UdpRecvErrorClass::Transient
        );
    }
}
