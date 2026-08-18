#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, doc(auto_cfg))]
#![deny(unsafe_code)]

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
//! string, or a [`std::net::SocketAddr`]. [`TargetClientBuilder::connect`] constructs
//! a UDP transport; [`TargetClientBuilder::connect_tcp`] constructs a TCP transport.
//! Request, standalone send, and construction timeouts are independent and
//! default to five seconds. The standalone send timeout bounds unconfirmed
//! traps, while informs use the request timeout while awaiting a response. The
//! construction timeout is one deadline covering name resolution and built-in
//! transport creation. For a preconfigured transport, use
//! [`ClientBuilder::new`] with authentication and client policy only, then call
//! [`ClientBuilder::build_with_transport`], which accepts any type implementing
//! [`Transport`]; transport construction and its deadline remain
//! application-owned. A preconstructed shared [`UdpTransport`] is a socket
//! owner rather than a per-target transport, so pair it with a target through
//! [`TargetClientBuilder::build_with`] to derive a [`UdpHandle`].
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
//! use async_snmp::{AuthProtocol, Client, PrivProtocol, UsmConfig, oid};
//!
//! #[tokio::main(flavor = "current_thread")]
//! async fn main() -> async_snmp::Result<()> {
//!     let auth = UsmConfig::new("admin")
//!         .auth_priv(
//!             AuthProtocol::Sha256,
//!             "authpass123",
//!             PrivProtocol::Aes128,
//!             "privpass123",
//!         )
//!         .unwrap();
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
//!         .retry(Retry::fixed(2, Duration::ZERO).expect("valid retry count"))
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
//!     .retry(Retry::fixed(3, Duration::ZERO).expect("valid retry count"))
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
//! [`TargetClientBuilder::connect`] gives each client its own UDP endpoint.
//! [`TargetClientBuilder::build_with`] instead creates a per-target client handle on
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
//! remote message-size limits, and trusted engine time between clients. It also
//! coalesces simultaneous ordinary discovery by independently constructed
//! clients for the same resolved address.
//!
//! ```rust,no_run
//! # #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
//! # {
//! use async_snmp::{
//!     Auth, AuthProtocol, Client, EngineCache, MasterKeys, PrivProtocol,
//!     UdpTransport, UsmConfig, oid,
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
//!     let auth = UsmConfig::new("snmpuser")
//!         .with_master_keys(master_keys.clone())
//!         .unwrap();
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
//! Notification trust depends on the wire security level. V1/v2c community
//! strings and content are cleartext; a receiver without a configured
//! community allowlist reports them as unverified claims, while an allowlist
//! checks only the cleartext value and adds no message integrity. V3 username,
//! scoped context, and notification content are authenticated only at
//! [`SecurityLevel::AuthNoPriv`] or [`SecurityLevel::AuthPriv`]; they are
//! spoofable at [`SecurityLevel::NoAuthNoPriv`].
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
//! # Debug only BER decoding issues
//! RUST_LOG=async_snmp::ber=debug cargo run
//! ```
//!
//! ## Interoperability policy
//!
//! Interoperability deviations are independent controls rather than a global
//! "permissive" mode. Defaults either preserve a bounded, unambiguous value or
//! narrowly accommodate common agent behavior. Security-sensitive relaxations
//! are off by default. [`DecodeConfig`] is supplied to low-level decode calls
//! or configured per network role. Outbound structured encoders
//! always require canonical protocol data.
//!
//! ### Malformed BER and value normalization
//!
//! [`DecodeConfig`] contains the top-level suffix choice and six targeted
//! BER/value controls. [`DecodeConfig::DEFAULT`] enables the first six listed below and
//! leaves malformed exception payloads disabled. Every accepted deviation is
//! returned as a typed [`DecodeAnomaly`] in [`message::DecodeOutcome::anomalies`]
//! and emits a tracing warning with a stable `anomaly` field.
//! [`DecodeConfig::STRICT`] disables all seven controls.
//!
//! | `DecodeConfig` field | Default | Scope and boundary |
//! |---|:---:|---|
//! | `trailing_bytes` | on | Accept bytes after one fully consumed top-level message TLV. Both settings reject extra fields inside the declared envelope. |
//! | `truncate_numeric_values` | on | Decode out-of-range generic INTEGER and Unsigned32 values into their public 32-bit representation. |
//! | `empty_counter64_as_zero` | on | Decode a zero-length Counter64 as zero. |
//! | `empty_object_identifier` | on | Decode a zero-length OBJECT IDENTIFIER as [`Oid::empty`]. |
//! | `clamp_bounded_strings` | on | Clamp an over-declared OCTET STRING or Opaque length to its enclosing varbind; it cannot consume the next varbind. |
//! | `normalize_negative_get_bulk_fields` | on | Normalize negative GETBULK non-repeaters and max-repetitions to zero while decoding; strict receive policy rejects them. Canonical fields are unsigned. |
//! | `malformed_exception_payloads` | **off** | When enabled, discard non-empty payloads on exception values; the default rejects them. |
//!
//! Unknown BER value tags remain preserved as [`Value::Unknown`] for receive
//! compatibility, but structured encoders reject that receive-only variant.
//!
//! ### Other policy layers
//!
//! | Control | Default | Scope, tradeoff, and observation |
//! |---|---|---|
//! | [`DecodeConfig`] | `DEFAULT` | Applies one immutable snapshot to correlation and every decode stage. TCP frames one declared TLV at a time, so adjacent stream messages are not suffixes. |
//! | [`ResponseShapePolicy`] | `Compatible` | Fixed-cardinality operations preserve all received varbinds and return bounded anomalies for count, OID, successor, or SET-echo problems. `Strict` returns [`Error::ResponseShape`] with the same data and diagnostics. |
//! | [`NotificationVarbindValidation`] | `Tolerant` | V2c/v3 TrapV2 and Inform prefixes may use non-standard names, but still require `TimeTicks` then `ObjectIdentifier` values. `Strict` also requires the RFC names and order. Rejected notifications are dropped, rejected Informs are not acknowledged, and validation failures are traced. |
//! | [`WalkOptions`] | `Auto`, `Strict`, no result limit, 25 max-repetitions | `GetNext` avoids broken GETBULK. `AllowNonIncreasing` tracks all seen OIDs to detect cycles and therefore requires a result limit to bound O(n) memory; abort reasons and tracing identify ordering failures. Smaller max-repetitions reduce datagram size at the cost of more round trips. |
//! | UDP source correlation | off-target replies accepted with a warning | [`TargetClientBuilder::strict_source`] drops off-target datagrams while leaving the request pending; drops increment [`UdpStats::discarded_datagrams`]. Permissive source handling supports multihomed agents but weakens peer identity. TCP remains bound to its connected peer. |
//! | [`CommunityResponsePolicy`] | `Exact` | V1/v2c response communities match byte-for-byte. Rewrite policies emit warnings when used; accepting rewrites from any source weakens spoof resistance, especially with permissive UDP source handling. |
//! | [`ClientBuilder::allow_unauthenticated_v3_time_correction`] | off | Allows one correlated, packet-local correction from an unauthenticated time-window Report. The tuple is never trusted globally, but an injector can choose one packet's time fields. Use strict UDP source correlation where possible; tracing records protocol correction. |
//! | Request, send, and construction timeouts | 5 seconds each | [`ClientBuilder::request_timeout`] and [`ClientBuilder::send_timeout`] configure client I/O. [`TargetClientBuilder::construction_timeout`] uses one absolute deadline across resolution and built-in transport creation. `AgentBuilder::construction_timeout` spans bind, every configured sink lookup, and Agent setup when the `agent` feature is enabled. Preconfigured transports and [`ClientBuilder::build_with_transport`] leave construction deadlines to the application. |
//!
//! [`UdpStats`] exposes UDP `correlated_datagrams`, `expired_registrations`,
//! `discarded_datagrams`, and `malformed_datagrams` counters for endpoint
//! health. It is not an
//! anomaly counter for every policy above; malformed-input acceptance,
//! correlation decisions, and protocol corrections are observed through their
//! tracing events or returned diagnostics as documented.
//!
//! Network clients retain decode anomalies in [`ResponseMetadata`], ordered by
//! accepted message within an exchange (v3 discovery, correction Reports, then
//! the final response). Within a v3 message the deterministic logical order is
//! outer header/security fields, plaintext or decrypted scoped-PDU fields, and
//! finally a top-level datagram suffix. Response-derived [`Error::Snmp`] and
//! [`Error::Report`] carry the same metadata; local transport, configuration,
//! and construction errors do not synthesize response metadata.
//!
//! Fixed GET/GETNEXT/SET responses expose metadata through
//! [`FixedCardinalityResponse::metadata`]; GETBULK and Inform callers use
//! [`Client::get_bulk_with_metadata`] and [`Client::send_inform_with_metadata`].
//! Metadata-preserving walk streams expose per-item anomalies exactly once and
//! a cumulative [`WalkCollection::metadata`] that also includes non-yielding
//! terminal responses. The shorter Inform and walk methods intentionally
//! discard this metadata. Notification acceptance policies receive
//! it through [`NotificationEnvelope::decode_anomalies`], and delivered
//! notifications retain it through [`Notification::decode_anomalies`].
//!
//! ### Strict low-level inspection and network-role controls
//!
//! Low-level and role decoding use the same configuration type. Start from
//! [`DecodeConfig::STRICT`] and enable only confirmed peer-specific deviations.
//!
//! ```rust,no_run
//! use async_snmp::{
//!     Auth, Client, CommunityResponsePolicy, DecodeConfig, ResponseShapePolicy,
//!     message::Message,
//! };
//! use bytes::Bytes;
//!
//! fn inspect_strictly(packet: Bytes) -> async_snmp::Result<Message> {
//!     Ok(Message::decode(packet, DecodeConfig::STRICT)?.value)
//! }
//!
//! let _client = Client::builder("192.0.2.1:161", Auth::v2c("public"))
//!     .decode_config(DecodeConfig::STRICT)
//!     .response_shape_policy(ResponseShapePolicy::Strict)
//!     .strict_source(true)
//!     .community_response_policy(CommunityResponsePolicy::Exact)
//!     .allow_unauthenticated_v3_time_correction(false);
//! ```
//!
//! ### Targeted workarounds
//!
//! Start from strict behavior and enable only deviations confirmed for a
//! specific peer.
//!
//! ```rust,no_run
//! use async_snmp::{Auth, Client, DecodeConfig, WalkMethod, WalkOptions, message::Message};
//! use bytes::Bytes;
//!
//! // This agent over-declares bounded string lengths and has broken GETBULK.
//! let mut decode_config = DecodeConfig::STRICT;
//! decode_config.clamp_bounded_strings = true;
//!
//! fn decode_agent_packet(
//!     packet: Bytes,
//!     config: DecodeConfig,
//! ) -> async_snmp::Result<Message> {
//!     Ok(Message::decode(packet, config)?.value)
//! }
//!
//! let _client = Client::builder("192.0.2.2:161", Auth::v2c("public"))
//!     .decode_config(decode_config)
//!     .walk_options(WalkOptions {
//!         method: WalkMethod::GetNext,
//!         ..WalkOptions::default()
//!     });
//! # let _ = (decode_config, decode_agent_packet);
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
mod udp_responder;
pub mod v3;
pub mod value;
pub mod varbind;
pub mod version;

pub(crate) mod util;

#[cfg(all(test, feature = "agent"))]
pub(crate) mod test_support;

#[cfg(feature = "cli")]
pub mod cli;

#[cfg(feature = "mib")]
pub mod mib_support;

// Re-exports for convenience
#[cfg(feature = "agent")]
pub use agent::{
    Agent, AgentBuilder, AgentShutdownPolicy, BuiltinMib, DuplicateVacmAccessEntry,
    NotificationOutcome, NotificationSendStream, NotificationSinkId, NotificationSinkIdError,
    NotificationSinkSummary, SinkOutcome, SinkSkipReason, SinkStatus, VacmAccessIndex, VacmBuilder,
    VacmConfig, VacmSecurityModel, View,
};
pub use client::{
    Auth, BulkResponse, Client, ClientBuilder, ClientConfig, CommunityVersion,
    DEFAULT_CONSTRUCTION_TIMEOUT, DEFAULT_MAX_OIDS_PER_REQUEST, DEFAULT_MAX_REPETITIONS,
    DEFAULT_REQUEST_TIMEOUT, DEFAULT_SEND_TIMEOUT, FixedCardinalityChunk,
    FixedCardinalityChunkError, FixedCardinalityChunkStream, FixedCardinalityOperation,
    FixedCardinalityResponse, MAX_RETRIES, OidOrdering, ResponseMetadata, ResponseShapeAnomaly,
    ResponseShapePolicy, Retry, RetryBuilder, RetryConfigError, Target, TargetClientBuilder,
    WalkCollection, WalkError, WalkItem, WalkMetadataStream, WalkMethod, WalkOptions, WalkStream,
};
pub use community::Community;
pub use compatibility::{
    BoundedStringKind, DecodeAnomaly, DecodeConfig, ExceptionKind, GetBulkField,
};
pub use error::{
    ConstructionStage, DecodeError, DecodeErrorKind, DecodeErrorOrigin, Error, ErrorKind,
    ErrorStatus, Result, WalkAbortReason,
};
#[cfg(feature = "agent")]
pub use handler::{
    BoxFuture, GetNextResult, GetResult, HandlerError, HandlerResult, MibHandler, OidTable,
    PreparedSet, RequestContext, SecurityModel, SecurityName, SetCommitError, SetCommitResult,
    SetTestError, SetTestResult, SetUndoError, SetUndoResult,
};
pub use message::SecurityLevel;
pub use message_size::{
    MAX_UDP_PAYLOAD, MESSAGE_SIZE_MAXIMUM, MESSAGE_SIZE_MINIMUM, MessageSize, MessageSizeError,
    ReceiveLimits, UDP_RECEIVE_BUFFER_SIZE, UDP_RECEIVE_LIMITS,
};
pub use notification::{
    InformAckOutcome, Notification, NotificationAcceptance, NotificationAcceptanceError,
    NotificationAcceptancePolicy, NotificationAcceptanceResult, NotificationEnvelope,
    NotificationPduClass, NotificationReceiver, NotificationReceiverBuilder,
    NotificationVarbindValidation, NotificationWireIdentity, ReceivedNotification,
    V3NotificationWireIdentity, validate_notification_varbinds,
};
pub use oid::Oid;
pub use pdu::{
    ErrorIndex, GenericTrap, GetBulkPdu, NotificationPdu, OutboundErrorStatus, OutboundPdu, Pdu,
    PduBody, PduType, RequestPdu, ResponsePdu, StandardPduType, TrapV1Notification, TrapV1Pdu,
};
pub use transport::{
    BuiltinTransport, Candidate, CommunityResponsePolicy, RequestRegistration, ResponseIdentity,
    TcpTransport, Transport, UdpControl, UdpHandle, UdpStats, UdpTransport,
};
pub use v3::{
    AuthProtocol, AuthoritativeEngine, AuthoritativeEnginePersistenceError,
    AuthoritativeEnginePersistenceOperation, CryptoBackend, CryptoError, CryptoResult,
    DesSaltPersistenceError, DesSaltPersistenceOperation, DesSaltState, DesSaltStateError,
    DiscoveredEngine, EngineCache, ParseProtocolError, PersistedAuthoritativeEngine,
    PersistedDesSaltState, PrivProtocol, UsmConfig, UsmUser, generate_engine_id,
};
#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
pub use v3::{LocalizedKey, MasterKey, MasterKeys};
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
