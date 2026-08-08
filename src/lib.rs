//! # async-snmp
//!
//! Modern, async-first SNMP client library for Rust.
//!
//! ## Features
//!
//! - Full `SNMPv1`, v2c, and v3 support
//! - Async-first API built on Tokio
//! - Zero-copy BER encoding/decoding
//! - Permissive OID tree/receive representation with checked outbound wire encoding
//! - Config-driven client construction
//! - Trap and inform sending (agent-based multi-sink or client-based)
//! - Trap and inform receiving with optional community filtering and per-notification
//!   security-level reporting
//! - SNMP agent with async handlers, two-phase SET, VACM, and built-in MIB handlers
//! - Automatic tooBig recovery (GET/GETNEXT batches bisect on oversized responses)
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use async_snmp::{Auth, Client, oid};
//! use std::time::Duration;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<async_snmp::Error>> {
//!     // SNMPv2c client - target accepts (host, port), a string, or a SocketAddr
//!     let client = Client::builder(("192.168.1.1", 161), Auth::v2c("public"))
//!         .response_shape_policy(async_snmp::ResponseShapePolicy::Strict)
//!         .timeout(Duration::from_secs(5))
//!         .connect()
//!         .await?;
//!
//!     let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await?;
//!     println!("sysDescr: {:?}", result.varbinds[0].value);
//!
//!     Ok(())
//! }
//! ```
//!
//! ## `SNMPv3` Example
//!
//! ```rust,no_run
//! use async_snmp::{Auth, Client, oid, v3::{AuthProtocol, PrivProtocol}};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<async_snmp::Error>> {
//!     let client = Client::builder(("192.168.1.1", 161),
//!         Auth::usm("admin").auth_priv(
//!             AuthProtocol::Sha256,
//!             "authpass123",
//!             PrivProtocol::Aes128,
//!             "privpass123",
//!         ))
//!         .response_shape_policy(async_snmp::ResponseShapePolicy::Strict)
//!         .connect()
//!         .await?;
//!
//!     let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await?;
//!     println!("sysDescr: {:?}", result.varbinds[0].value);
//!
//!     Ok(())
//! }
//! ```
//!
//! ## `SNMPv3` Trust, Corrections, and Roles
//!
//! Engine discovery is unauthenticated. A client accepts only a correlated,
//! standard `usmStatsUnknownEngineIDs.0` Report and learns an engine identity
//! candidate and message-size limit; it discards the Report's boots/time tuple.
//! Trusted time is established and advanced only after HMAC verification and
//! RFC 3414 Step 7(b) processing.
//!
//! Incoming auth/privacy flags select the received security level. HMAC and
//! timeliness processing precede decryption, scoped-PDU parsing, and msgID
//! correlation. Ordinary Responses then require exact identity, security,
//! context, PDU type, and request-id matches. Reports also require a current
//! exchange msgID and exact shape; terminal statuses are returned as
//! [`Error::Report`].
//!
//! On an SNMPv3 timeout, each transmission uses a fresh outer msgID while the
//! PDU request-id remains stable, and any msgID in the current exchange can
//! correlate. Stable request-id reuse is a deliberate RFC 3414 Section 11.1
//! interoperability deviation. One authenticated time-window Report may cause
//! a corrected request with fresh message and PDU IDs independently of timeout
//! retry policy. Other or repeated Reports are terminal.
//!
//! [`EngineCache`] maps target addresses to discovered identities while sharing
//! trusted time by authoritative engine ID. Cache TTL expiry affects future
//! lookups, not a live client's established identity; use
//! [`Client::rediscover_engine`] after an intentional device replacement.
//!
//! The default-off
//! [`ClientBuilder::allow_unauthenticated_v3_time_correction`] option supports
//! devices that emit an unauthenticated time-window Report. Its tuple is used
//! for one authenticated packet and never installed as trusted state, but an
//! injector can choose that packet's time fields; enable strict UDP source
//! checking where possible.
//!
//! Agents with USM users or V3 trap sinks, notification receivers with USM
//! users, and clients originating V3 traps are locally authoritative and need
//! a persisted [`AuthoritativeEngine`]. Polling and V3 Inform originators use
//! the remote responder as authoritative and do not need local engine state.
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
//!         .response_shape_policy(async_snmp::ResponseShapePolicy::Strict)
//!         .timeout(Duration::from_secs(5))
//!         .retry(Retry::fixed(2, Duration::ZERO))
//!         .connect()
//!         .await
//!         .map_err(|e| format!("Failed to connect: {}", e))?;
//!
//!     match client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await {
//!         Ok(response) => Ok(response.varbinds[0].value.as_str().unwrap_or("(non-string)").to_string()),
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
//! // 3 retries with no delay between attempts
//! let client = Client::builder("192.168.1.1:161", Auth::v2c("public"))
//!     .retry(Retry::fixed(3, Duration::ZERO))
//!     .connect().await?;
//!
//! // Exponential backoff with jitter (1s, 2s, 4s, 5s, 5s)
//! let client = Client::builder("192.168.1.1:161", Auth::v2c("public"))
//!     .retry(Retry::exponential(5)
//!         .max_delay(Duration::from_secs(5))
//!         .jitter(0.25)
//!         .build()
//!         .expect("valid retry configuration"))  // ±25% randomization
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
//! use async_snmp::{Auth, Client, oid, UdpTransport};
//! use futures::future::join_all;
//!
//! async fn poll_many_devices(targets: Vec<&str>) -> Vec<(&str, Result<String, String>)> {
//!     // Single socket shared across all clients
//!     let transport = UdpTransport::bind("0.0.0.0:0")
//!         .await
//!         .expect("failed to bind");
//!
//!     let sys_descr = oid!(1, 3, 6, 1, 2, 1, 1, 1, 0);
//!
//!     // Create clients for each target - (host, port) tuples work naturally
//!     let mut clients = Vec::new();
//!     for t in &targets {
//!         let client = Client::builder((*t, 161), Auth::v2c("public"))
//!             .response_shape_policy(async_snmp::ResponseShapePolicy::Strict)
//!             .build_with(&transport)
//!             .await
//!             .expect("failed to build client");
//!         clients.push(client);
//!     }
//!
//!     // Poll all targets concurrently
//!     let results = join_all(
//!         clients.iter().map(|c| async {
//!             match c.get(&sys_descr).await {
//!                 Ok(response) => Ok(response.varbinds[0].value.to_string()),
//!                 Err(e) => Err(e.to_string()),
//!             }
//!         })
//!     ).await;
//!
//!     targets.into_iter().zip(results).collect()
//! }
//! ```
//!
//! ## High-Throughput `SNMPv3` Polling
//!
//! `SNMPv3` has two expensive per-connection operations:
//! - **Password derivation**: ~850μs to derive keys from passwords (SHA-256)
//! - **Engine discovery**: Round-trip to learn the agent's engine ID and message-size limit
//!
//! For polling many targets with shared credentials, cache both:
//!
//! ```rust,no_run
//! use async_snmp::{Auth, AuthProtocol, Client, EngineCache, MasterKeys, PrivProtocol, oid, UdpTransport};
//! use std::sync::Arc;
//!
//! # async fn example() -> async_snmp::Result<()> {
//! // 1. Derive master keys once (expensive: ~850μs)
//! let master_keys = MasterKeys::new(AuthProtocol::Sha256, b"authpassword").unwrap()
//!     .with_privacy(PrivProtocol::Aes128, b"privpassword").unwrap();
//!
//! // 2. Share engine discovery results across clients
//! let engine_cache = Arc::new(EngineCache::new());
//!
//! // 3. Use shared transport for socket efficiency
//! let transport = UdpTransport::bind("0.0.0.0:0").await?;
//!
//! // Poll multiple targets - only ~1μs key localization per engine
//! for target in ["192.0.2.1:161", "192.0.2.2:161"] {
//!     let auth = Auth::usm("snmpuser").with_master_keys(master_keys.clone());
//!
//!     let client = Client::builder(target, auth)
//!         .response_shape_policy(async_snmp::ResponseShapePolicy::Strict)
//!         .engine_cache(engine_cache.clone())
//!         .build_with(&transport).await?;
//!
//!     let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await?;
//!     println!("{}: {:?}", target, result.varbinds[0].value);
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
//!         .response_shape_policy(async_snmp::ResponseShapePolicy::Strict)
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
//!                     Ok(response) => println!("Uptime: {:?}", response.varbinds[0].value),
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
//! | `snmp.pdu_type` | PDU type (Get, `GetNext`, etc.) |
//! | `snmp.varbind_count` | Number of varbinds in request/response |
//! | `snmp.error_status` | SNMP error status from response |
//! | `snmp.error_index` | Index of problematic varbind |
//! | `snmp.non_repeaters` | GETBULK non-repeaters parameter |
//! | `snmp.max_repetitions` | GETBULK max-repetitions parameter |
//! | `snmp.username` | `SNMPv3` USM username |
//! | `snmp.security_level` | `SNMPv3` security level |
//! | `snmp.engine_id` | `SNMPv3` engine identifier (hex) |
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
//! | `async_snmp::v3` | `SNMPv3` message processing |
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
//!
//! ## Cargo Features
//!
//! - `agent` - SNMP agent (enabled by default)
//! - `v3` - SNMPv3 protocol and USM surfaces (enabled by default)
//! - `crypto-rustcrypto` - RustCrypto backend (enabled by default). Supports all auth and privacy protocols.
//! - `crypto-fips` - FIPS backend via aws-lc-rs. Rejects MD5, DES, and 3DES.
//! - `cli` - Builds command-line utilities (`asnmp-get`, `asnmp-walk`, `asnmp-set`)
//! - `mib` - MIB integration via mib-rs (OID conversions, value formatting helpers)
//! - `rt-multi-thread` - Multi-threaded tokio runtime
//!
//! Crypto backend features are additive. Each USM configuration selects one
//! available backend with [`CryptoBackend`]. When both are compiled,
//! RustCrypto remains the default; FIPS operation must be selected explicitly.

#[cfg(feature = "agent")]
pub mod agent;
pub mod ber;
pub mod client;
pub mod compatibility;
pub mod error;
pub mod format;
#[cfg(feature = "agent")]
pub mod handler;
pub mod message;
pub mod message_size;
pub mod notification;
pub mod oid;
pub mod pdu;
pub mod prelude;
pub mod transport;
#[cfg(not(feature = "v3"))]
mod v3;
#[cfg(feature = "v3")]
pub mod v3;
pub mod value;
pub mod varbind;
pub mod version;

pub(crate) mod util;

#[cfg(feature = "cli")]
pub mod cli;

#[cfg(feature = "mib")]
pub mod mib_support;

// Re-exports for convenience
#[cfg(feature = "agent")]
pub use agent::{
    Agent, AgentBuilder, BuiltinMib, VacmBuilder, VacmConfig, VacmSecurityModel, View,
};
pub use client::{
    Auth, BulkWalk, Client, ClientBuilder, ClientConfig, CommunityVersion,
    DEFAULT_MAX_OIDS_PER_REQUEST, DEFAULT_MAX_REPETITIONS, DEFAULT_TIMEOUT,
    FixedCardinalityOperation, FixedCardinalityResponse, OidOrdering, ResponseShapeAnomaly,
    ResponseShapePolicy, Retry, RetryBuilder, RetryConfigError, Target, Walk, WalkMode, WalkStream,
};
pub use compatibility::CompatibilityPolicy;
pub use error::{Error, ErrorStatus, Result, WalkAbortReason};
#[cfg(feature = "agent")]
pub use handler::{
    BoxFuture, GetNextResult, GetResult, HandlerError, HandlerResult, MibHandler, OidTable,
    RequestContext, Response, SecurityModel, SetResult,
};
pub use message::SecurityLevel;
pub use message_size::{
    MAX_UDP_PAYLOAD, MESSAGE_SIZE_MAXIMUM, MESSAGE_SIZE_MINIMUM, MessageSize, MessageSizeError,
    ReceiveLimits, UDP_RECEIVE_BUFFER_SIZE, UDP_RECEIVE_LIMITS,
};
pub use notification::{
    Notification, NotificationReceiver, NotificationReceiverBuilder, NotificationVarbindValidation,
    validate_notification_varbinds,
};
pub use oid::Oid;
pub use pdu::{GenericTrap, Pdu, PduBody, PduType, StandardPduType, TrapV1Pdu};
pub use transport::{
    CommunityResponsePolicy, RequestRegistration, ResponseCorrelation, TcpTransport, Transport,
    UdpHandle, UdpTransport,
};
#[cfg(feature = "v3")]
pub use v3::{
    AuthProtocol, AuthoritativeEngine, EngineCache, ParseProtocolError,
    PersistedAuthoritativeEngine, PrivProtocol, UsmConfig, generate_engine_id,
};
#[cfg(all(
    feature = "v3",
    any(feature = "crypto-rustcrypto", feature = "crypto-fips")
))]
pub use v3::{CryptoBackend, CryptoError, CryptoResult, LocalizedKey, MasterKey, MasterKeys};
pub use value::{RowStatus, StorageType, Value};
pub use varbind::VarBind;
pub use version::Version;

/// Type alias for a client using UDP transport.
///
/// This is the default and most common client type.
pub type UdpClient = Client<UdpHandle>;

/// Type alias for a client using a TCP connection.
pub type TcpClient = Client<TcpTransport>;
