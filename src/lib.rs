// Allow large error types - the Error enum includes OIDs inline for debugging convenience.
// Boxing them would add complexity and allocations for a marginal size reduction.
#![allow(clippy::result_large_err)]

//! # async-snmp
//!
//! Modern, async-first SNMP client library for Rust.
//!
//! ## Features
//!
//! - Full SNMPv1, v2c, and v3 support
//! - Async-first API built on Tokio
//! - Zero-copy BER encoding/decoding
//! - Type-safe OID and value handling
//! - Config-driven client construction
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use async_snmp::{Auth, Client, oid};
//! use std::time::Duration;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), async_snmp::Error> {
//!     // SNMPv2c client
//!     let client = Client::builder("192.168.1.1:161", Auth::v2c("public"))
//!         .timeout(Duration::from_secs(5))
//!         .connect()
//!         .await?;
//!
//!     let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await?;
//!     println!("sysDescr: {:?}", result.value);
//!
//!     Ok(())
//! }
//! ```
//!
//! ## SNMPv3 Example
//!
//! ```rust,no_run
//! use async_snmp::{Auth, Client, oid, v3::{AuthProtocol, PrivProtocol}};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), async_snmp::Error> {
//!     let client = Client::builder("192.168.1.1:161",
//!         Auth::usm("admin")
//!             .auth(AuthProtocol::Sha256, "authpass123")
//!             .privacy(PrivProtocol::Aes128, "privpass123"))
//!         .connect()
//!         .await?;
//!
//!     let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await?;
//!     println!("sysDescr: {:?}", result.value);
//!
//!     Ok(())
//! }
//! ```
//!
//! # Advanced Topics
//!
//! ## Error Handling Patterns
//!
//! The library provides detailed error information for debugging and recovery.
//! See the [`error`] module for complete documentation.
//!
//! ```rust,no_run
//! use async_snmp::{Auth, Client, Error, ErrorStatus, oid};
//! use std::time::Duration;
//!
//! async fn poll_device(addr: &str) -> Result<String, String> {
//!     let client = Client::builder(addr, Auth::v2c("public"))
//!         .timeout(Duration::from_secs(5))
//!         .retries(2)
//!         .connect()
//!         .await
//!         .map_err(|e| format!("Failed to connect: {}", e))?;
//!
//!     match client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await {
//!         Ok(vb) => Ok(vb.value.as_str().unwrap_or("(non-string)").to_string()),
//!         Err(Error::Timeout { retries, .. }) => {
//!             Err(format!("Device unreachable after {} retries", retries))
//!         }
//!         Err(Error::Snmp { status: ErrorStatus::NoSuchName, .. }) => {
//!             Err("OID not supported by device".to_string())
//!         }
//!         Err(e) => Err(format!("SNMP error: {}", e)),
//!     }
//! }
//! ```
//!
//! ## Concurrent Operations
//!
//! Use standard async patterns to poll multiple devices concurrently.
//! The [`SharedUdpTransport`] is recommended for polling many targets.
//!
//! ```rust,no_run
//! use async_snmp::{Auth, Client, SharedUdpTransport, oid};
//! use futures::future::join_all;
//!
//! async fn poll_many_devices(targets: Vec<String>) -> Vec<(String, Result<String, String>)> {
//!     // Create a shared transport for efficient socket usage
//!     let transport = SharedUdpTransport::bind("0.0.0.0:0")
//!         .await
//!         .expect("failed to bind");
//!
//!     let sys_descr = oid!(1, 3, 6, 1, 2, 1, 1, 1, 0);
//!
//!     // Spawn concurrent requests
//!     let futures: Vec<_> = targets.iter().map(|target| {
//!         let handle = transport.handle(target.parse().expect("invalid addr"));
//!         let oid = sys_descr.clone();
//!         let target = target.clone();
//!         async move {
//!             let client = match Client::builder(target.clone(), Auth::v2c("public"))
//!                 .build(handle) {
//!                 Ok(c) => c,
//!                 Err(e) => return (target, Err(e.to_string())),
//!             };
//!             let result: Result<String, String> = match client.get(&oid).await {
//!                 Ok(vb) => Ok(vb.value.to_string()),
//!                 Err(e) => Err(e.to_string()),
//!             };
//!             (target, result)
//!         }
//!     }).collect();
//!
//!     join_all(futures).await
//! }
//! ```
//!
//! ## Graceful Shutdown
//!
//! Use `tokio::select!` or cancellation tokens for clean shutdown.
//!
//! ```rust,no_run
//! use async_snmp::{Auth, Client, oid};
//! use std::time::Duration;
//! use tokio::time::interval;
//!
//! async fn poll_with_shutdown(
//!     addr: &str,
//!     mut shutdown: tokio::sync::oneshot::Receiver<()>,
//! ) {
//!     let client = Client::builder(addr, Auth::v2c("public"))
//!         .connect()
//!         .await
//!         .expect("failed to connect");
//!
//!     let sys_uptime = oid!(1, 3, 6, 1, 2, 1, 1, 3, 0);
//!     let mut poll_interval = interval(Duration::from_secs(30));
//!
//!     loop {
//!         tokio::select! {
//!             _ = &mut shutdown => {
//!                 println!("Shutdown signal received");
//!                 break;
//!             }
//!             _ = poll_interval.tick() => {
//!                 match client.get(&sys_uptime).await {
//!                     Ok(vb) => println!("Uptime: {:?}", vb.value),
//!                     Err(e) => eprintln!("Poll failed: {}", e),
//!                 }
//!             }
//!         }
//!     }
//! }
//! ```
//!
//! ## Tracing Integration
//!
//! The library uses the `tracing` crate for structured logging. All SNMP
//! operations emit spans and events with relevant context.
//!
//! ```rust,no_run
//! use async_snmp::{Auth, Client, oid};
//! use tracing_subscriber::{fmt, EnvFilter};
//!
//! #[tokio::main]
//! async fn main() {
//!     // Initialize tracing subscriber
//!     tracing_subscriber::fmt()
//!         .with_env_filter(
//!             EnvFilter::from_default_env()
//!                 .add_directive("async_snmp=debug".parse().unwrap())
//!         )
//!         .init();
//!
//!     // Operations now emit structured logs
//!     let client = Client::builder("192.168.1.1:161", Auth::v2c("public"))
//!         .connect()
//!         .await
//!         .expect("failed to connect");
//!
//!     // This will log: DEBUG async_snmp::client: snmp.target=192.168.1.1:161 snmp.oid=1.3.6.1.2.1.1.1.0
//!     let _ = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;
//! }
//! ```
//!
//! Key tracing fields include:
//! - `snmp.target` - The target address for client operations
//! - `snmp.oid` - The OID being requested
//! - `snmp.source` - The source address for agent/receiver operations
//! - `snmp.security_model` - SNMPv3 security model in use

pub mod agent;
pub mod ber;
pub mod client;
pub mod error;
pub mod format;
pub mod handler;
pub mod message;
pub mod notification;
pub mod oid;
pub mod pdu;
pub mod prelude;
pub mod transport;
pub mod v3;
pub mod value;
pub mod varbind;
pub mod version;

pub(crate) mod util;

#[cfg(feature = "cli")]
pub mod cli;

// Re-exports for convenience
pub use agent::{Agent, AgentBuilder, VacmBuilder, VacmConfig, View};
pub use client::{
    Auth, BulkWalk, Client, ClientBuilder, ClientConfig, CommunityVersion, OidOrdering, UsmAuth,
    UsmBuilder, V3SecurityConfig, Walk, WalkMode, WalkStream,
};
pub use error::{
    AuthErrorKind, CryptoErrorKind, DecodeErrorKind, EncodeErrorKind, Error, ErrorStatus,
    OidErrorKind, Result,
};
pub use handler::{
    BoxFuture, GetNextResult, GetResult, MibHandler, OidTable, RequestContext, Response,
    SecurityModel, SetResult,
};
pub use message::SecurityLevel;
pub use notification::{
    Notification, NotificationReceiver, NotificationReceiverBuilder, UsmUserConfig,
    validate_notification_varbinds,
};
pub use oid::Oid;
pub use pdu::{GenericTrap, Pdu, PduType, TrapV1Pdu};
pub use transport::{SharedUdpHandle, SharedUdpTransport, TcpTransport, Transport, UdpTransport};
pub use v3::{
    AuthProtocol, EngineCache, LocalizedKey, MasterKey, MasterKeys, ParseProtocolError,
    PrivProtocol,
};
pub use value::Value;
pub use varbind::VarBind;
pub use version::Version;

/// Type alias for a client using the shared UDP transport.
///
/// This is useful for high-throughput scenarios where many clients share
/// a single UDP socket via [`SharedUdpTransport`].
pub type SharedClient = Client<SharedUdpHandle>;

/// Type alias for a client using a dedicated UDP socket.
///
/// This is the default transport type, suitable for most use cases
/// with up to ~100 concurrent targets.
pub type UdpClient = Client<UdpTransport>;

/// Type alias for a client using a TCP connection.
pub type TcpClient = Client<TcpTransport>;

/// Testing utilities exposed via the `testing` feature.
#[cfg(feature = "testing")]
pub mod testing {
    pub use crate::format::hex::{Bytes as HexBytes, DecodeError, decode, encode};
}
