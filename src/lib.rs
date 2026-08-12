#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, doc(auto_cfg))]
#![forbid(unsafe_code)]

//! # async-snmp
//!
//! An asynchronous SNMP library built on Tokio.
//!
//! ## Protocol and API coverage
//!
//! - `SNMPv1`, v2c, and v3 USM clients
//! - GET, GETNEXT, GETBULK, SET, WALK, and BULKWALK operations
//! - Trap and inform sending and receiving through [`notification`]
//! - Per-client UDP, shared UDP, and TCP transports
//! - An SNMP agent with async handlers, two-phase SET processing, VACM, and
//!   built-in engine/USM/MPD objects when the `agent` feature is enabled
//! - Automatic `tooBig` recovery for GET and GETNEXT batches
//!
//! GETBULK, BULKWALK, and informs require SNMPv2c or SNMPv3. Structured
//! outbound encoding rejects values that cannot be represented on the wire;
//! receive-side compatibility behavior is described under
//! [Interoperability](#interoperability-policy).
//!
//! ## Client setup
//!
//! [`Client::builder`] accepts a `(host, port)` tuple, a combined address
//! string, or a [`std::net::SocketAddr`]. [`ClientBuilder::connect`] constructs
//! a UDP transport; [`ClientBuilder::connect_tcp`] constructs a TCP transport.
//! Request and construction timeouts are independent and default to five
//! seconds. The construction timeout is one deadline covering name resolution
//! and built-in transport creation.
//!
//! ### SNMPv2c
//!
//! ```rust,no_run
//! use async_snmp::{Auth, Client, oid};
//!
//! #[tokio::main(flavor = "current_thread")]
//! async fn main() -> async_snmp::Result<()> {
//!     let client = Client::builder(("192.168.1.1", 161), Auth::v2c("public"))
//!         .connect()
//!         .await?;
//!
//!     let response = client
//!         .get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))
//!         .await?;
//!
//!     match response.single() {
//!         Some(varbind) => println!("sysDescr: {:?}", varbind.value),
//!         None => eprintln!("unexpected response shape: {:?}", response.anomalies),
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! Fixed-cardinality GET, GETNEXT, and SET methods return a
//! [`FixedCardinalityResponse`]. The default [`ResponseShapePolicy::Compatible`]
//! preserves every decoded binding in `varbinds` and records bounded shape
//! problems in `anomalies`. [`FixedCardinalityResponse::single`] returns the
//! binding only when a singleton response is unambiguous. Applications that
//! want anomalous responses returned as errors can configure
//! [`ResponseShapePolicy::Strict`].
//!
//! ### SNMPv3 authentication and privacy
//!
//! ```rust,no_run
//! use async_snmp::{Auth, AuthProtocol, Client, PrivProtocol, oid};
//!
//! #[tokio::main(flavor = "current_thread")]
//! async fn main() -> async_snmp::Result<()> {
//!     let auth = Auth::usm("admin").auth_priv(
//!         AuthProtocol::Sha256,
//!         "authpass123",
//!         PrivProtocol::Aes128,
//!         "privpass123",
//!     );
//!
//!     let client = Client::builder(("192.168.1.1", 161), auth)
//!         .connect()
//!         .await?;
//!
//!     let response = client
//!         .get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))
//!         .await?;
//!
//!     match response.single() {
//!         Some(varbind) => println!("sysDescr: {:?}", varbind.value),
//!         None => eprintln!("unexpected response shape: {:?}", response.anomalies),
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! Plaintext authentication and privacy passwords must contain at least eight
//! octets. See [`v3`] for supported algorithms, backend selection, key
//! handling, and authoritative-engine requirements.
//!
//! ### Errors and retries
//!
//! Client operations use the boxed [`Error`] type. Match on variants when an
//! application needs to distinguish transport, protocol, authentication, or
//! response-shape failures. The [`error`] module documents every variant.
//!
//! ```rust,no_run
//! use async_snmp::{Auth, Client, Error, ErrorStatus, Retry, oid};
//! use std::time::Duration;
//!
//! async fn poll_device(addr: &str) -> Result<String, String> {
//!     let client = Client::builder(addr, Auth::v2c("public"))
//!         .request_timeout(Duration::from_secs(5))
//!         .retry(Retry::fixed(2, Duration::ZERO))
//!         .connect()
//!         .await
//!         .map_err(|error| format!("client construction failed: {error}"))?;
//!
//!     match client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await {
//!         Ok(response) => response
//!             .single()
//!             .and_then(|varbind| varbind.value.as_str())
//!             .map(str::to_owned)
//!             .ok_or_else(|| format!("unexpected response shape: {:?}", response.anomalies)),
//!         Err(error) => match *error {
//!             Error::Timeout { retries, .. } => {
//!                 Err(format!("device did not respond after {retries} retries"))
//!             }
//!             Error::Snmp { status: ErrorStatus::NoSuchName, .. } => {
//!                 Err("OID is not supported by the device".to_owned())
//!             }
//!             _ => Err(format!("SNMP request failed: {error}")),
//!         },
//!     }
//! }
//! ```
//!
//! UDP requests can retry on timeout with a fixed or exponential delay. TCP
//! requests do not use this retry policy because retransmission is handled by
//! the transport.
//!
//! ```rust
//! use async_snmp::{Auth, Client, Retry};
//! use std::time::Duration;
//!
//! # async fn example() -> async_snmp::Result<()> {
//! let no_retries = Client::builder("192.168.1.1:161", Auth::v2c("public"))
//!     .retry(Retry::none())
//!     .connect()
//!     .await?;
//!
//! let fixed = Client::builder("192.168.1.1:161", Auth::v2c("public"))
//!     .retry(Retry::fixed(3, Duration::ZERO))
//!     .connect()
//!     .await?;
//!
//! let exponential = Client::builder("192.168.1.1:161", Auth::v2c("public"))
//!     .retry(
//!         Retry::exponential(5)
//!             .max_delay(Duration::from_secs(5))
//!             .jitter(0.25)
//!             .build()
//!             .expect("valid retry configuration"),
//!     )
//!     .connect()
//!     .await?;
//! # let _ = (no_retries, fixed, exponential);
//! # Ok(())
//! # }
//! ```
//!
//! ### Shared UDP transport
//!
//! [`ClientBuilder::connect`] gives each client its own UDP endpoint.
//! [`ClientBuilder::build_with`] instead creates a per-target client handle on
//! an existing [`UdpTransport`]. Clients built from the same transport share
//! its socket, receive task, statistics, and lifecycle. Responses are
//! correlated by request identity; v1/v2c also applies version and community
//! checks, while v3 performs its authenticated client checks.
//!
//! ```rust,no_run
//! use async_snmp::{Auth, Client, UdpTransport, oid};
//! use futures::future::join_all;
//!
//! async fn poll_many_devices(
//!     targets: Vec<&str>,
//! ) -> Vec<(&str, Result<String, String>)> {
//!     let transport = UdpTransport::bind("0.0.0.0:0")
//!         .await
//!         .expect("failed to bind UDP transport");
//!     let sys_descr = oid!(1, 3, 6, 1, 2, 1, 1, 1, 0);
//!
//!     let mut clients = Vec::with_capacity(targets.len());
//!     for target in &targets {
//!         let client = Client::builder((*target, 161), Auth::v2c("public"))
//!             .build_with(&transport)
//!             .await
//!             .expect("failed to build client");
//!         clients.push(client);
//!     }
//!
//!     let results = join_all(clients.iter().map(|client| async {
//!         match client.get(&sys_descr).await {
//!             Ok(response) => response
//!                 .single()
//!                 .map(|varbind| varbind.value.to_string())
//!                 .ok_or_else(|| format!("unexpected response shape: {:?}", response.anomalies)),
//!             Err(error) => Err(error.to_string()),
//!         }
//!     }))
//!     .await;
//!
//!     targets.into_iter().zip(results).collect()
//! }
//! ```
//!
//! Multiple transports can be used when separate sockets, buffer policies, or
//! failure domains are required. See [`transport`] for correlation,
//! address-family, statistics, and shutdown details.
//!
//! ### Reusing SNMPv3 key and discovery state
//!
//! Password-to-key derivation expands the password to one megabyte before
//! hashing it. `MasterKeys` allows that result to be reused across engines
//! that share credentials. [`EngineCache`] shares discovered engine identities,
//! remote message-size limits, and trusted engine time between clients.
//!
//! ```rust,no_run
//! # #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
//! # {
//! use async_snmp::{
//!     Auth, AuthProtocol, Client, EngineCache, MasterKeys, PrivProtocol,
//!     UdpTransport, oid,
//! };
//! use std::sync::Arc;
//!
//! # async fn example() -> async_snmp::Result<()> {
//! let master_keys = MasterKeys::new(AuthProtocol::Sha256, b"authpassword")
//!     .expect("valid authentication configuration")
//!     .with_privacy(PrivProtocol::Aes128, b"privpassword")
//!     .expect("valid privacy configuration");
//! let engine_cache = Arc::new(EngineCache::new());
//! let transport = UdpTransport::bind("0.0.0.0:0").await?;
//!
//! for target in ["192.0.2.1:161", "192.0.2.2:161"] {
//!     let auth = Auth::usm("snmpuser").with_master_keys(master_keys.clone());
//!     let client = Client::builder(target, auth)
//!         .engine_cache(engine_cache.clone())
//!         .build_with(&transport)
//!         .await?;
//!
//!     let response = client
//!         .get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))
//!         .await?;
//!     if let Some(varbind) = response.single() {
//!         println!("{target}: {:?}", varbind.value);
//!     }
//! }
//! # Ok(())
//! # }
//! # }
//! ```
//!
//! ## SNMPv3 trust, correction, and authoritative roles
//!
//! Engine discovery is unauthenticated. A client accepts only a correlated,
//! standard `usmStatsUnknownEngineIDs.0` Report and learns an engine identity
//! candidate and message-size limit; it discards the Report's boots/time tuple.
//! Trusted time is established and advanced only after HMAC verification and
//! RFC 3414 Step 7(b) processing.
//!
//! Incoming authentication/privacy flags select the received security level.
//! HMAC and timeliness processing precede decryption, scoped-PDU parsing, and
//! msgID correlation. Ordinary Responses then require exact identity,
//! security, context, PDU type, and request-id matches. Reports also require a
//! current-exchange msgID and exact shape; terminal statuses are returned as
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
//! Agents with USM users or v3 trap sinks, notification receivers with USM
//! users, and clients originating v3 traps are locally authoritative and need
//! a persisted [`AuthoritativeEngine`]. Polling clients and v3 Inform
//! originators use the remote responder as authoritative and do not need local
//! engine state.
//!
//! ## Tracing
//!
//! The library uses the `tracing` crate for structured logging. Client
//! operations are instrumented with spans, and protocol/transport paths emit
//! events with relevant context.
//!
//! ### Subscriber setup
//!
//! ```rust,no_run
//! use async_snmp::{Auth, Client, oid};
//! use tracing_subscriber::EnvFilter;
//!
//! #[tokio::main(flavor = "current_thread")]
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
//!     let _ = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await;
//! }
//! ```
//!
//! ### Log levels
//!
//! | Level | Typical events |
//! |-------|---------------|
//! | ERROR | UDP receive failures and agent request-task/handler-contract failures |
//! | WARN | Authentication, correlation, compatibility, parse, and source-policy anomalies |
//! | INFO | Agent shutdown requests |
//! | DEBUG | Request/response flow, engine discovery, retries, and walk progress |
//! | TRACE | Detailed BER, value, USM, crypto, and packet-processing state |
//!
//! ### Structured fields
//!
//! Operation fields use the `snmp.` prefix:
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
//! ### Tracing targets and filters
//!
//! Tracing targets are grouped by subsystem:
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
//! Interoperability deviations are independent controls rather than a global
//! "permissive" mode. Defaults either preserve a bounded, unambiguous value or
//! narrowly accommodate common agent behavior. Security-sensitive relaxations
//! are off by default. [`CompatibilityPolicy`] is supplied to low-level message
//! decode calls; it is **not** a client-wide or receiver-wide setting. Outbound
//! structured encoders always require canonical protocol data.
//!
//! ### Malformed BER and value normalization
//!
//! [`CompatibilityPolicy`] contains six controls.
//! [`CompatibilityPolicy::DEFAULT`] enables the first five listed below and
//! leaves malformed exception payloads disabled. Every accepted deviation emits
//! a tracing warning with a stable `anomaly` field.
//! [`CompatibilityPolicy::STRICT`] disables all six controls.
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
//! ## Cargo features
//!
//! - `agent`: SNMP agent support.
//! - `crypto-rustcrypto` (default): RustCrypto authentication and privacy
//!   backend; supports MD5, SHA-1/SHA-2, DES/3DES, and AES.
//! - `crypto-fips`: AWS-LC FIPS backend; rejects MD5, DES, and 3DES.
//! - `cli`: Builds `asnmp-get`, `asnmp-walk`, and `asnmp-set`.
//! - `mib`: MIB integration through mib-rs.
//! - `rt-multi-thread`: Tokio's multi-threaded runtime.
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
    Agent, AgentBuilder, BuiltinMib, NotificationOutcome, NotificationSendStream,
    NotificationSinkId, NotificationSinkSummary, SinkOutcome, SinkSkipReason, SinkStatus,
    VacmBuilder, VacmConfig, VacmSecurityModel, View,
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
    Notification, NotificationMetadata, NotificationPduClass, NotificationReceiver,
    NotificationReceiverBuilder, NotificationVarbindValidation, validate_notification_varbinds,
};
pub use oid::Oid;
pub use pdu::{GenericTrap, Pdu, PduBody, PduType, StandardPduType, TrapV1Pdu};
pub use transport::{
    BuiltinTransport, Candidate, CommunityResponsePolicy, RequestRegistration, ResponseIdentity,
    TcpTransport, Transport, UdpControl, UdpHandle, UdpStats, UdpTransport,
};
pub use v3::{
    AuthProtocol, AuthoritativeEngine, EngineCache, ParseProtocolError,
    PersistedAuthoritativeEngine, PrivProtocol, UsmConfig, UsmUser, generate_engine_id,
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
