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
//! async fn main() -> Result<(), Box<async_snmp::Error>> {
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
//! async fn main() -> Result<(), Box<async_snmp::Error>> {
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
//! use async_snmp::{Auth, Client, Error, ErrorStatus, Retry, oid};
//! use std::time::Duration;
//!
//! async fn poll_device(addr: &str) -> Result<String, String> {
//!     let client = Client::builder(addr, Auth::v2c("public"))
//!         .timeout(Duration::from_secs(5))
//!         .retry(Retry::fixed(2, Duration::ZERO))
//!         .connect()
//!         .await
//!         .map_err(|e| format!("Failed to connect: {}", e))?;
//!
//!     match client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await {
//!         Ok(vb) => Ok(vb.value.as_str().unwrap_or("(non-string)").to_string()),
//!         Err(e) => match *e {
//!             Error::Timeout { retries, .. } => {
//!                 Err(format!("Device unreachable after {} retries", retries))
//!             }
//!             Error::Snmp { status: ErrorStatus::NoSuchName, .. } => {
//!                 Err("OID not supported by device".to_string())
//!             }
//!             _ => Err(format!("SNMP error: {}", e)),
//!         },
//!     }
//! }
//! ```
//!
//! ## Retry Configuration
//!
//! UDP transports retry on timeout with configurable backoff strategies.
//! TCP transports ignore retry configuration (the transport layer handles reliability).
//!
//! ```rust
//! use async_snmp::{Auth, Client, Retry};
//! use std::time::Duration;
//!
//! # async fn example() -> async_snmp::Result<()> {
//! // No retries (fail immediately on timeout)
//! let client = Client::builder("192.168.1.1:161", Auth::v2c("public"))
//!     .retry(Retry::none())
//!     .connect().await?;
//!
//! // 3 retries with no delay (default behavior)
//! let client = Client::builder("192.168.1.1:161", Auth::v2c("public"))
//!     .retry(Retry::fixed(3, Duration::ZERO))
//!     .connect().await?;
//!
//! // Exponential backoff with jitter (1s, 2s, 4s, 5s, 5s)
//! let client = Client::builder("192.168.1.1:161", Auth::v2c("public"))
//!     .retry(Retry::exponential(5)
//!         .max_delay(Duration::from_secs(5))
//!         .jitter(0.25))  // ±25% randomization
//!     .connect().await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Scalable Polling (Shared Transport)
//!
//! For monitoring systems polling many targets, share a single [`UdpTransport`]
//! across all clients:
//!
//! - **1 file descriptor** for all targets (vs 1 per target)
//! - **Firewall session reuse** between polls to the same target
//! - **Lower memory** from shared socket buffers
//! - **No per-poll socket creation** overhead
//!
//! **Scaling guidance:**
//! - **Most use cases**: Single shared [`UdpTransport`] recommended
//! - **~100,000s+ targets**: Multiple [`UdpTransport`] instances, sharded by target
//! - **Scrape isolation**: Per-client via [`.connect()`](ClientBuilder::connect) (FD + syscall overhead)
//!
//! ```rust,no_run
//! use async_snmp::{Auth, Client, oid};
//! use async_snmp::transport::UdpTransport;
//! use futures::future::join_all;
//!
//! async fn poll_many_devices(targets: Vec<String>) -> Vec<(String, Result<String, String>)> {
//!     // Single socket shared across all clients
//!     let transport = UdpTransport::bind("0.0.0.0:0")
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
//! ## High-Throughput SNMPv3 Polling
//!
//! SNMPv3 has two expensive per-connection operations:
//! - **Password derivation**: ~850μs to derive keys from passwords (SHA-256)
//! - **Engine discovery**: Round-trip to learn the agent's engine ID and time
//!
//! For polling many targets with shared credentials, cache both:
//!
//! ```rust,no_run
//! use async_snmp::{Auth, AuthProtocol, Client, EngineCache, MasterKeys, PrivProtocol, oid};
//! use async_snmp::transport::UdpTransport;
//! use std::sync::Arc;
//!
//! # async fn example() -> async_snmp::Result<()> {
//! // 1. Derive master keys once (expensive: ~850μs)
//! let master_keys = MasterKeys::new(AuthProtocol::Sha256, b"authpassword")
//!     .with_privacy(PrivProtocol::Aes128, b"privpassword");
//!
//! // 2. Share engine discovery results across clients
//! let engine_cache = Arc::new(EngineCache::new());
//!
//! // 3. Use shared transport for socket efficiency
//! let transport = UdpTransport::bind("0.0.0.0:0").await?;
//!
//! // Poll multiple targets - only ~1μs key localization per engine
//! for target in ["192.0.2.1:161", "192.0.2.2:161"] {
//!     let handle = transport.handle(target.parse().unwrap());
//!     let auth = Auth::usm("snmpuser").with_master_keys(master_keys.clone());
//!
//!     let client = Client::builder(target, auth)
//!         .engine_cache(engine_cache.clone())
//!         .build(handle)?;
//!
//!     let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await?;
//!     println!("{}: {:?}", target, result.value);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! | Optimization | Without | With | Savings |
//! |--------------|---------|------|---------|
//! | `MasterKeys` | 850μs/engine | 1μs/engine | ~99.9% |
//! | `EngineCache` | 1 RTT/engine | 0 RTT (cached) | 1 RTT |
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
//! ### Basic Setup
//!
//! ```rust,no_run
//! use async_snmp::{Auth, Client, oid};
//! use tracing_subscriber::EnvFilter;
//!
//! #[tokio::main]
//! async fn main() {
//!     tracing_subscriber::fmt()
//!         .with_env_filter(
//!             EnvFilter::from_default_env()
//!                 .add_directive("async_snmp=debug".parse().unwrap())
//!         )
//!         .init();
//!
//!     let client = Client::builder("192.168.1.1:161", Auth::v2c("public"))
//!         .connect()
//!         .await
//!         .expect("failed to connect");
//!
//!     // Logs: DEBUG async_snmp::client snmp.target=192.168.1.1:161 snmp.request_id=12345
//!     let _ = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;
//! }
//! ```
//!
//! ### Log Levels
//!
//! | Level | What's Logged |
//! |-------|---------------|
//! | ERROR | Socket errors, fatal transport failures |
//! | WARN | Auth failures, parse errors, source address mismatches |
//! | INFO | Connect/disconnect, walk completion |
//! | DEBUG | Request/response flow, engine discovery, retries |
//! | TRACE | Auth verification, raw packet data |
//!
//! ### Structured Fields
//!
//! All fields use the `snmp.` prefix for easy filtering:
//!
//! | Field | Description |
//! |-------|-------------|
//! | `snmp.target` | Target address for outgoing requests |
//! | `snmp.source` | Source address of incoming messages |
//! | `snmp.request_id` | SNMP request identifier |
//! | `snmp.retries` | Current retry attempt number |
//! | `snmp.elapsed_ms` | Request duration in milliseconds |
//! | `snmp.pdu_type` | PDU type (Get, GetNext, etc.) |
//! | `snmp.varbind_count` | Number of varbinds in request/response |
//! | `snmp.error_status` | SNMP error status from response |
//! | `snmp.error_index` | Index of problematic varbind |
//! | `snmp.non_repeaters` | GETBULK non-repeaters parameter |
//! | `snmp.max_repetitions` | GETBULK max-repetitions parameter |
//! | `snmp.username` | SNMPv3 USM username |
//! | `snmp.security_level` | SNMPv3 security level |
//! | `snmp.engine_id` | SNMPv3 engine identifier (hex) |
//! | `snmp.local_addr` | Local bind address |
//!
//! ### Filtering by Target
//!
//! Tracing targets follow a stable naming scheme (not tied to internal module paths):
//!
//! | Target Prefix | What's Included |
//! |---------------|-----------------|
//! | `async_snmp` | Everything |
//! | `async_snmp::client` | Client operations, requests, retries |
//! | `async_snmp::agent` | Agent request/response handling |
//! | `async_snmp::ber` | BER encoding/decoding |
//! | `async_snmp::v3` | SNMPv3 message processing |
//! | `async_snmp::transport` | UDP/TCP transport layer |
//! | `async_snmp::notification` | Trap/inform receiver |
//!
//! ```bash
//! # All library logs at debug level
//! RUST_LOG=async_snmp=debug cargo run
//!
//! # Only warnings and errors
//! RUST_LOG=async_snmp=warn cargo run
//!
//! # Trace client operations, debug everything else
//! RUST_LOG=async_snmp=debug,async_snmp::client=trace cargo run
//!
//! # Debug just BER decoding issues
//! RUST_LOG=async_snmp::ber=debug cargo run
//! ```
//!
//! ## Agent Compatibility
//!
//! Real-world SNMP agents often have quirks. This library provides several
//! options to handle non-conformant implementations.
//!
//! ### Walk Issues
//!
//! | Problem | Solution |
//! |---------|----------|
//! | GETBULK returns errors or garbage | Use [`WalkMode::GetNext`] |
//! | OIDs returned out of order | Use [`OidOrdering::AllowNonIncreasing`] |
//! | Walk never terminates | Set [`ClientBuilder::max_walk_results`] |
//! | Slow responses cause timeouts | Reduce [`ClientBuilder::max_repetitions`] |
//!
//! **Warning**: [`OidOrdering::AllowNonIncreasing`] uses O(n) memory to track
//! seen OIDs for cycle detection. Always pair it with [`ClientBuilder::max_walk_results`]
//! to bound memory usage. The cycle detection catches duplicate OIDs, but a
//! pathological agent could still return an infinite sequence of unique OIDs.
//!
//! ```rust,no_run
//! use async_snmp::{Auth, Client, WalkMode, OidOrdering};
//!
//! # async fn example() -> async_snmp::Result<()> {
//! // Configure for a problematic agent
//! let client = Client::builder("192.168.1.1:161", Auth::v2c("public"))
//!     .walk_mode(WalkMode::GetNext)           // Avoid buggy GETBULK
//!     .oid_ordering(OidOrdering::AllowNonIncreasing)  // Handle out-of-order OIDs
//!     .max_walk_results(10_000)               // IMPORTANT: bound memory usage
//!     .max_repetitions(10)                    // Smaller responses
//!     .connect()
//!     .await?;
//! # Ok(())
//! # }
//! ```
//!
//! ### Permissive Parsing
//!
//! The BER decoder accepts non-conformant encodings that some agents produce:
//! - Non-minimal integer encodings (extra leading bytes)
//! - Non-minimal OID subidentifier encodings
//! - Truncated values (logged as warnings)
//!
//! This matches net-snmp's permissive behavior.
//!
//! ### Unknown Value Types
//!
//! Unrecognized BER tags are preserved as [`Value::Unknown`] rather than
//! causing decode errors. This provides forward compatibility with new
//! SNMP types or vendor extensions.

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
    Auth, Backoff, BulkWalk, Client, ClientBuilder, ClientConfig, CommunityVersion, OidOrdering,
    Retry, RetryBuilder, UsmAuth, UsmBuilder, V3SecurityConfig, Walk, WalkMode, WalkStream,
};
pub use error::{Error, ErrorStatus, Result, WalkAbortReason};
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
pub use transport::{TcpTransport, Transport, UdpHandle, UdpTransport};
pub use v3::{
    AuthProtocol, EngineCache, LocalizedKey, MasterKey, MasterKeys, ParseProtocolError,
    PrivProtocol,
};
pub use value::Value;
pub use varbind::VarBind;
pub use version::Version;

/// Type alias for a client using UDP transport.
///
/// This is the default and most common client type.
pub type UdpClient = Client<UdpHandle>;

/// Type alias for a client using a TCP connection.
pub type TcpClient = Client<TcpTransport>;
