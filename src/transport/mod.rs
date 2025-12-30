//! Transport layer abstraction.
//!
//! Provides the `Transport` trait and implementations for UDP, shared UDP, and TCP.

mod shared;
mod tcp;
mod udp;

#[cfg(any(test, feature = "testing"))]
mod mock;

pub use shared::*;
pub use tcp::*;
pub use udp::*;

#[cfg(any(test, feature = "testing"))]
pub use mock::*;

use crate::error::Result;
use bytes::Bytes;
use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

/// Client-side transport abstraction.
///
/// All transports implement this trait uniformly. For shared transports,
/// handles (not the pool itself) implement Transport.
///
/// # Clone Requirement
///
/// The `Clone` bound is required because walk streams own a clone of the client
/// (and thus the transport). This enables concurrent walks without borrow conflicts.
/// All implementations use `Arc` internally, making clone cheap (reference count increment).
pub trait Transport: Send + Sync + Clone {
    /// Send request data to the target.
    fn send(&self, data: &[u8]) -> impl Future<Output = Result<()>> + Send;

    /// Receive response with correlation and timeout.
    ///
    /// - `request_id`: Used for response correlation (required for shared transports,
    ///   can be used for validation on owned transports)
    /// - `timeout`: Maximum time to wait for response
    ///
    /// Returns (response_data, actual_source_address)
    fn recv(
        &self,
        request_id: i32,
        timeout: Duration,
    ) -> impl Future<Output = Result<(Bytes, SocketAddr)>> + Send;

    /// The peer address for this transport.
    ///
    /// Returns the remote address that this transport sends to and receives from.
    /// Named to match [`std::net::TcpStream::peer_addr()`].
    fn peer_addr(&self) -> SocketAddr;

    /// Local bind address.
    fn local_addr(&self) -> SocketAddr;

    /// Whether this is a stream transport (TCP/TLS).
    ///
    /// When true, Client skips retries (stream guarantees delivery or failure).
    /// When false (UDP/DTLS), Client retries on timeout.
    fn is_stream(&self) -> bool;

    /// Allocate a request ID from the transport's shared counter.
    ///
    /// For shared transports (e.g., `SharedUdpHandle`), this returns a unique
    /// request ID from a shared counter to prevent collisions between clients.
    /// For owned transports, returns `None` and the client uses its own counter.
    fn alloc_request_id(&self) -> Option<i32> {
        None
    }
}

/// Agent-side transport abstraction (listener mode).
///
/// This trait is for future agent functionality.
pub trait AgentTransport: Send + Sync {
    /// Receive data from any source.
    fn recv_from(&self, buf: &mut [u8])
    -> impl Future<Output = Result<(usize, SocketAddr)>> + Send;

    /// Send data to a specific target.
    fn send_to(&self, data: &[u8], target: SocketAddr) -> impl Future<Output = Result<()>> + Send;

    /// Local bind address.
    fn local_addr(&self) -> SocketAddr;
}
