#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, doc(auto_cfg))]

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
//!         .request_timeout(Duration::from_secs(5))
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
//!         .request_timeout(Duration::from_secs(5))
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
//! # #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
//! # {
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
//! The library uses the `tracing` crate for structured logging. Client
//! operations are instrumented with spans, and protocol/transport paths emit
//! events with relevant context.
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
//! | ERROR | UDP receive failures and agent request-task/handler-contract failures |
//! | WARN | Authentication, correlation, compatibility, parse, and source-policy anomalies |
//! | INFO | Agent shutdown requests |
//! | DEBUG | Request/response flow, engine discovery, retries, and walk progress |
//! | TRACE | Detailed BER, value, USM, crypto, and packet-processing state |
//!
//! ### Structured Fields
//!
//! Stable operation fields use the `snmp.` prefix for easy filtering:
//!
//! | Field | Description |
//! |-------|-------------|
//! | `snmp.target` | Target address for outgoing requests |
//! | `snmp.source` | Source address of incoming messages |
//! | `snmp.request_id` | SNMP request identifier |
//! | `snmp.attempt` | Current retry attempt number |
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
//! | `async_snmp::notification` | Trap/inform sending and receiving |
//! | `async_snmp::message`, `async_snmp::pdu` | SNMP message and PDU processing |
//! | `async_snmp::ber`, `async_snmp::oid`, `async_snmp::value` | BER and SMI value processing |
//! | `async_snmp::v3`, `async_snmp::usm`, `async_snmp::crypto`, `async_snmp::engine` | `SNMPv3`/USM processing |
//! | `async_snmp::transport`, `async_snmp::transport::udp`, `async_snmp::transport::tcp` | Transport processing |
//! | `async_snmp::walk`, `async_snmp::error` | Walk and error processing |
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
//! ## Interoperability policy
//!
//! Interoperability deviations are independent controls, not a global
//! "permissive" mode. Defaults either preserve a bounded, unambiguous value or
//! narrowly accommodate common agent behavior. Security-sensitive relaxations
//! are off by default. [`CompatibilityPolicy`] is supplied to low-level message
//! decode calls; it is **not** a client-wide or receiver-wide setting. Outbound
//! structured encoders always require canonical protocol data.
//!
//! ### Malformed BER and value normalization
//!
//! [`CompatibilityPolicy::DEFAULT`] enables five normalizations. Every accepted
//! deviation emits a tracing warning with a stable `anomaly` field.
//! [`CompatibilityPolicy::STRICT`] disables all six behaviors.
//!
//! | `CompatibilityPolicy` field | Default | Scope and boundary |
//! |---|:---:|---|
//! | `truncate_numeric_values` | on | Decode out-of-range generic INTEGER and Unsigned32 values into their public 32-bit representation. |
//! | `empty_counter64_as_zero` | on | Decode a zero-length Counter64 as zero. |
//! | `empty_object_identifier` | on | Decode a zero-length OBJECT IDENTIFIER as [`Oid::empty`]. |
//! | `clamp_bounded_strings` | on | Clamp an over-declared OCTET STRING or Opaque length to its enclosing varbind; it cannot consume the next varbind. |
//! | `normalize_negative_get_bulk_fields` | on | Normalize negative GETBULK non-repeaters and max-repetitions to zero while decoding; strict receive policy rejects them. Canonical fields are unsigned. |
//! | `malformed_exception_payloads` | **off** | When enabled, discard non-empty payloads on exception values; the default rejects them. |
//!
//! These controls do not govern bytes after a complete top-level message. That
//! separate envelope policy is described below. Unknown BER value tags remain
//! preserved as [`Value::Unknown`] for receive compatibility, but structured
//! encoders reject that receive-only variant.
//!
//! ### Other policy layers
//!
//! | Control | Default | Scope, tradeoff, and observation |
//! |---|---|---|
//! | [`message::DecodePolicy`] | `Compatible` | Accepts only bytes after a fully consumed top-level message TLV. The outcome records their count and a stable `trailing_bytes` warning is emitted; `Strict` rejects them. Both modes reject unconsumed fields inside the declared envelope. |
//! | [`ResponseShapePolicy`] | `Compatible` | Fixed-cardinality operations preserve all received varbinds and return bounded anomalies for count, OID, successor, or SET-echo problems. `Strict` returns [`Error::ResponseShape`] with the same data and diagnostics. |
//! | [`NotificationVarbindValidation`] | `Tolerant` | V2c/v3 TrapV2 and Inform prefixes may use non-standard names, but still require `TimeTicks` then `ObjectIdentifier` values. `Strict` also requires the RFC names and order. Rejected notifications are dropped, rejected Informs are not acknowledged, and validation failures are traced. |
//! | [`WalkMode`], [`OidOrdering`], and walk limits | `Auto`, `Strict`, no result limit, 25 max-repetitions | `GetNext` avoids broken GETBULK. `AllowNonIncreasing` tracks all seen OIDs to detect cycles and therefore requires [`ClientBuilder::max_walk_results`] to bound O(n) memory; abort reasons and tracing identify ordering failures. Smaller max-repetitions reduce datagram size at the cost of more round trips. |
//! | UDP source correlation | off-target replies accepted with a warning | [`ClientBuilder::strict_source`] drops off-target datagrams while leaving the request pending; drops increment [`UdpStats::discarded_datagrams`]. Permissive source handling supports multihomed agents but weakens peer identity. TCP remains bound to its connected peer. |
//! | [`CommunityResponsePolicy`] | `Exact` | V1/v2c response communities match byte-for-byte. Rewrite policies emit warnings when used; accepting rewrites from any source weakens spoof resistance, especially with permissive UDP source handling. |
//! | [`ClientBuilder::allow_unauthenticated_v3_time_correction`] | off | Allows one correlated, packet-local correction from an unauthenticated time-window Report. The tuple is never trusted globally, but an injector can choose one packet's time fields. Use strict UDP source correlation where possible; tracing records protocol correction. |
//! | [`ClientBuilder::request_timeout`] / [`ClientBuilder::construction_timeout`] | 5 seconds / 5 seconds | Request waiting and client construction are independent. Construction uses one absolute deadline across resolution and built-in transport creation; [`Error::Timeout`] remains request-only. Preconfigured transports and [`ClientBuilder::build_with_transport`] allow application-owned deadline policy. |
//!
//! [`UdpStats`] exposes UDP `correlated_datagrams`, `expired_registrations`,
//! `discarded_datagrams`, and `malformed_datagrams` counters for endpoint
//! health. It is not an
//! anomaly counter for every policy above; malformed-input acceptance,
//! correlation decisions, and protocol corrections are observed through their
//! tracing events or returned diagnostics as documented.
//!
//! ### Strict low-level inspection and client controls
//!
//! Low-level strict decoding requires both exact envelope consumption and the
//! strict malformed-input policy. Client controls must be selected separately;
//! setting [`CompatibilityPolicy::STRICT`] does not make ordinary network
//! clients globally BER-strict.
//!
//! ```rust,no_run
//! use async_snmp::{
//!     Auth, Client, CommunityResponsePolicy, CompatibilityPolicy,
//!     ResponseShapePolicy,
//!     message::{DecodePolicy, Message},
//! };
//! use bytes::Bytes;
//!
//! fn inspect_strictly(packet: Bytes) -> async_snmp::Result<Message> {
//!     Ok(Message::decode_with_policies(
//!         packet,
//!         DecodePolicy::Strict,
//!         CompatibilityPolicy::STRICT,
//!     )?.value)
//! }
//!
//! let _client = Client::builder("192.0.2.1:161", Auth::v2c("public"))
//!     .response_shape_policy(ResponseShapePolicy::Strict)
//!     .strict_source(true)
//!     .community_response_policy(CommunityResponsePolicy::Exact)
//!     .allow_unauthenticated_v3_time_correction(false);
//! ```
//!
//! ### Targeted workarounds
//!
//! Start from strict low-level behavior and enable only deviations confirmed for
//! a specific agent. Configure client behavior independently rather than using
//! a broad compatibility preset.
//!
//! ```rust,no_run
//! use async_snmp::{Auth, Client, CompatibilityPolicy, WalkMode, message::Message};
//! use bytes::Bytes;
//!
//! // This agent over-declares bounded string lengths and has broken GETBULK.
//! let mut value_policy = CompatibilityPolicy::STRICT;
//! value_policy.clamp_bounded_strings = true;
//!
//! fn decode_agent_packet(
//!     packet: Bytes,
//!     policy: CompatibilityPolicy,
//! ) -> async_snmp::Result<Message> {
//!     Message::decode_with_compatibility_policy(packet, policy)
//! }
//!
//! let _client = Client::builder("192.0.2.2:161", Auth::v2c("public"))
//!     .walk_mode(WalkMode::GetNext);
//! # let _ = (value_policy, decode_agent_packet);
//! ```
//!
//! ## Cargo Features
//!
//! - `agent` - SNMP agent (not enabled by default)
//! - `crypto-rustcrypto` - RustCrypto backend (the only default feature). Supports all auth and privacy protocols.
//! - `crypto-fips` - FIPS backend via aws-lc-rs. Rejects MD5, DES, and 3DES.
//! - `cli` - Builds command-line utilities (`asnmp-get`, `asnmp-walk`, `asnmp-set`)
//! - `mib` - MIB integration via mib-rs (OID conversions, value formatting helpers)
//! - `rt-multi-thread` - Multi-threaded tokio runtime
//!
//! Client, protocol, transport, notification, and noAuthNoPriv APIs are always
//! available. The agent and crypto backend features are independent and
//! additive. Backend-free builds support SNMPv1/v2c and SNMPv3 noAuthNoPriv.

#[cfg(feature = "agent")]
pub mod agent;
pub mod ber;
pub mod client;
mod community;
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
mod response_finalizer;
pub mod transport;
#[cfg_attr(
    not(any(feature = "crypto-rustcrypto", feature = "crypto-fips")),
    allow(dead_code, unused_imports, unused_mut, unused_variables)
)]
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
    DEFAULT_CONSTRUCTION_TIMEOUT, DEFAULT_MAX_OIDS_PER_REQUEST, DEFAULT_MAX_REPETITIONS,
    DEFAULT_REQUEST_TIMEOUT, FixedCardinalityChunk, FixedCardinalityChunkError,
    FixedCardinalityChunkStream, FixedCardinalityOperation, FixedCardinalityResponse, OidOrdering,
    ResponseShapeAnomaly, ResponseShapePolicy, Retry, RetryBuilder, RetryConfigError, Target, Walk,
    WalkMode, WalkStream,
};
pub use community::Community;
pub use compatibility::CompatibilityPolicy;
pub use error::{ConstructionStage, Error, ErrorKind, ErrorStatus, Result, WalkAbortReason};
#[cfg(feature = "agent")]
pub use handler::{
    BoxFuture, GetNextResult, GetResult, HandlerError, HandlerResult, MibHandler, OidTable,
    RequestContext, SecurityModel, SecurityName, SetResult,
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
    BuiltinTransport, Candidate, CommunityResponsePolicy, RequestRegistration, ResponseIdentity,
    TcpTransport, Transport, UdpControl, UdpHandle, UdpStats, UdpTransport,
};
pub use v3::{
    AuthProtocol, AuthoritativeEngine, EngineCache, ParseProtocolError,
    PersistedAuthoritativeEngine, PrivProtocol, UsmConfig, generate_engine_id,
};
#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
pub use v3::{CryptoBackend, CryptoError, CryptoResult, LocalizedKey, MasterKey, MasterKeys};
pub use value::{RowStatus, StorageType, Value, ValueKind};
pub use varbind::VarBind;
pub use version::Version;

/// Type alias for a client using UDP transport.
///
/// This is the default and most common client type.
pub type UdpClient = Client<UdpHandle>;

/// Type alias for a client using a TCP connection.
pub type TcpClient = Client<TcpTransport>;

/// Type alias for a client whose built-in transport is selected at runtime.
///
/// Configure a [`UdpHandle`] or [`TcpTransport`] before converting it to
/// [`BuiltinTransport`] and passing it to [`ClientBuilder::build_with_transport`].
pub type RuntimeClient = Client<BuiltinTransport>;
