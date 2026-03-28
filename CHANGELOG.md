# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.11.0] - 2026-03-28

### Added

- `GenericTrap` enum with `Unknown(i32)` variant for wire values outside the standard 0-6 range
- `Display` impl for `GenericTrap`
- `PartialEq`, `Eq` for `Pdu`
- `ErrorStatus::as_str()` returning `Option<&'static str>`
- USM stats counters (`usmStatsUnknownEngineIDs`, `usmStatsUnknownUserNames`, `usmStatsWrongDigests`, `usmStatsNotInTimeWindows`) on `AgentInner`; public accessors on `Agent`
- `CommunityPdu` enum wrapping either a standard `Pdu` or `TrapV1Pdu` in community message decoding
- Error kinds `IntegerTooLong`, `Unsigned32TooLong`, `Integer64MissingLeadingZero`
- V3 outbound messages now use the negotiated `msgMaxSize` from engine discovery instead of a hardcoded value
- Retry policy applied to V3 engine discovery; previously a single unreliable discovery probe caused all subsequent V3 operations to fail on packet loss
- Discovery lock prevents redundant concurrent discovery attempts from multiple tasks racing on the same client

### Changed

- **Breaking:** `TrapV1Pdu.generic_trap` field type changed from `i32` to `GenericTrap`; `generic_trap_enum()` removed - use the field directly
- **Breaking:** `Notification::trap_oid()` return type changed from `&Oid` to `Result<Oid>`; RFC 3584 OID conversion for TrapV1 enterprise-specific traps is fallible
- **Breaking:** `MibHandler::undo_set` return type changed from `BoxFuture<'a, ()>` to `BoxFuture<'a, SetResult>`
- **Breaking:** `set_many` now returns `Error::Config` when the varbind count exceeds the per-request OID limit; SET must be atomic per RFC 3416 and silent batching across PDUs violates that guarantee
- **Breaking:** `UsmUserConfig` type alias removed; use `UsmConfig` directly
- **Breaking:** `EngineCache::Clone` removed; share instances via `Arc<EngineCache>`
- **Breaking:** `--level` flag removed from V3 CLI tools; security level is inferred from auth/priv configuration
- `error_index` in response PDUs is no longer bounds-checked at parse time; negative values and values exceeding the varbind count are now accepted, matching net-snmp behavior
- INTEGER values 5-8 bytes are now accepted and sign-extended to i32, matching net-snmp `CHECK_OVERFLOW_S`; values longer than 8 bytes are rejected
- Unsigned32 values up to 9 bytes (with leading zero) are now truncated to u32, matching net-snmp `CHECK_OVERFLOW_U`
- `Counter64` zero-length encoding now accepted with a warning instead of an error
- Long-form BER length limited to 8 octets (was 4), matching net-snmp's `sizeof(long)` threshold on 64-bit
- `PrivKey` clones now start with an independent salt counter instead of sharing the same atomic

### Fixed

- Salt counter race in `PrivKey::encrypt` could produce duplicate IVs under concurrent use; counter now uses `compare_exchange` and skips zero atomically
- Bounds checks on USM auth parameter offset were missing; malformed messages could panic
- Lock poison in V3 client and TCP transport caused panics; both now return `Error::Config`
- TCP `active_guard` held a sync `Mutex` guard across `.await` points; replaced with `tokio::sync::Mutex`
- SNMPv1 Trap PDUs (tag `0xA4`) were rejected instead of decoded through the community message path
- V3 concurrent discovery race where multiple callers could all run discovery simultaneously; callers now wait on a lock and reuse the result
- Unknown USM users for non-discovery `noAuthNoPriv` messages were not rejected per RFC 3414 Section 3.2; they now are
- GETNEXT did not advance past VACM-denied OIDs per RFC 3413 read-class semantics
- GETBULK did not apply VACM access checks; GETBULK also stopped at the first denied OID instead of continuing
- `handles()` default impl matched OIDs below the registered prefix, causing incorrect GET/SET routing; now only matches OIDs within the subtree
- SNMPv3 context names not forwarded from client config to scoped PDU
- `Pdu::is_error` incorrectly matched non-response PDUs (e.g. GETBULK requests)
- SNMPv1 `noSuchName` was not treated as normal walk termination
- Multi-byte BER tags were incorrectly accepted; now rejected (only single-byte tags are valid for SNMP)
- DES padding calculation was incorrect; simplified to `next_multiple_of(8)` matching the 3DES path
- OctetString/Opaque BER length clamped to enclosing SEQUENCE boundary for devices that send inflated lengths (e.g. MikroTik)
- IPv6 targets were not bracketed in display output
- `UdpTransport` background receiver task was not cancelled when the last clone was dropped
- Request ID counter seeded with time+PID; now uses `getrandom`
- `Retry::default()` used zero delay; now 1s fixed delay
- `GenericTrap::Unknown` displayed as `enterpriseSpecific`; now displays as `unknown`
- `TimeTicks` verbose display used inconsistent format
- Display hint `"1b"` (RFC 2579 OCTET STRING format) was not a valid format character; removed
- Display hint `"t"` (UTF-8) format incorrectly cast each byte to `char` instead of decoding UTF-8; invalid sequences are now replaced with U+FFFD per RFC 2579
- Inflated varbind count responses (more varbinds than requested) now return `MalformedResponse`; truncated responses warn and return partial results

### Removed

- `TrapV1Pdu::generic_trap_enum()` - use the `generic_trap` field directly
- `UsmUserConfig` type alias
- `EngineCache::Clone`

## [0.10.0] - 2026-03-27

### Added

- `Target` enum for specifying client target addresses. `ClientBuilder::new()` and `Client::builder()` now accept `(host, port)` tuples and `SocketAddr` in addition to combined address strings. This avoids IPv6 bracket formatting when host and port are stored separately - requested by @sjthomason (#17)
- `Target` implements `Display`
- `From<SocketAddr>` for `Target`, for use when the address is already resolved

### Changed

- **Breaking:** `ClientBuilder::new()` and `Client::builder()` now accept `impl Into<Target>` instead of `impl Into<String>`. `Target` converts from `&str`, `String`, `(&str, u16)`, `(String, u16)`, and `SocketAddr`. All existing `&str` and `String` callers work unchanged, but code relying on other `Into<String>` types may need adjustment

## [0.9.0] - 2026-03-27

### Added

- `UdpTransport` now implements `Clone` (cheap `Arc` increment) - thanks @sjthomason (#16)

### Changed

- **Breaking:** `ClientBuilder::build_with()` is now `async` and must be `.await`ed
- **Breaking:** `ClientBuilder::resolve_target()` uses async DNS resolution (`tokio::net::lookup_host`) instead of blocking `std::net::ToSocketAddrs`, preventing worker threads from stalling on slow or failing DNS - reported by @sjthomason (#17)
- DNS resolution is bounded by the builder's configured timeout
- Target address now defaults to port 161 when no port is specified, matching standard SNMP behavior. Accepts bare IPv4 (`192.168.1.1`), bare IPv6 (`::1`, `fe80::1`), bracketed IPv6 (`[::1]:162`), and hostnames (`switch.local`)
- CLI tools pass the raw target string to the builder instead of pre-resolving, removing redundant DNS resolution

### Fixed

- Bare IPv6 addresses (e.g., `fe80::1`) were incorrectly parsed as having a port due to colon detection

## [0.8.0] - 2026-03-21

### Added

- `mib` feature flag for optional mib-rs integration
- `mib_support` module with OID name resolution, symbolic formatting, type-aware value rendering (enum labels, display hints), and structured varbind metadata
- `VarBindFormatter` trait for pluggable output formatting in CLI tools
- OID conversions between async-snmp and mib-rs types
- Re-export core mib-rs types from `mib_support` so users don't need a direct mib-rs dependency
- MIB CLI args (`--mib-dir`, `--load-mibs`, `--system-mibs`) for asnmp-get, asnmp-walk, asnmp-set
- Examples: `mib_get`, `mib_walk`, `mib_table`

## [0.7.0] - 2026-03-19

### Added

- `agent` feature flag to gate SNMP agent module and `quinn-udp` dependency (default-on)
- `rt-multi-thread` feature flag for opt-in multi-threaded tokio runtime

### Changed

- Default tokio runtime is now single-threaded (`current_thread`); enable `rt-multi-thread` for multi-threaded runtime
- `SecurityModel` enum moved from `agent::vacm` to `handler` module (re-exported from `agent::vacm` for compatibility)
- Bumped `quinn-udp` from 0.5 to 0.6

## [0.6.0] - 2026-03-13

### Fixed

- `Client::connect` binding to IPv6 socket for IPv4 targets on macOS
- Cross-platform socket binding: default `UdpTransportBuilder` bind address changed from `[::]:0` to `0.0.0.0:0` to avoid assuming Linux dual-stack behavior

### Changed

- `UdpTransport::handle()` auto-maps IPv4 targets to IPv4-mapped IPv6 addresses (`::ffff:x.x.x.x`) when the socket is IPv6, enabling dual-stack shared transports without caller-managed address families
- Added macOS and Windows to CI test matrix

## [0.5.0] - 2026-01-18

### Added

- INTEGER DISPLAY-HINT formatting with `format::hints` constants module
- OID suffix extraction methods (`suffix_from`, `try_suffix_from`) for table index handling
- `RowStatus` and `StorageType` enum exports for USM table handling
- Value type improvements for NMS use cases
- `value_extraction` example

### Changed

- Use `VecDeque` in `BulkWalk` to avoid cloning varbinds on yield

### Removed

- `V3SecurityConfig` type alias (use `UsmConfig` directly)
- `context_engine_id` field from `ClientBuilder`
- Standalone `serde` feature flag
- `ClientBuilder::build()` method (use `Client::new()` or `build_with()`)

### Documentation

- Document VACM permissive mode default in `AgentBuilder`
- Clarify when to use `Client::new()` vs builder pattern
- Improved examples and README

## [0.4.0] - 2026-01-04

### Added

- `TcpTransportBuilder` with configurable allocation limit for DoS protection
- Automatic key extension for AES-192/256 and 3DES privacy protocols

### Changed

- **Breaking:** Redesigned error types around caller actions and boxed `Error` for smaller `Result`s
- **Breaking:** `TrapV1Pdu::v2_trap_oid()` now returns `Result` to handle invalid trap values
- Use explicit tracing targets with brace syntax for stable log filtering
- Reduced BER `MAX_LENGTH` from 16MB to 2MB
- Use `getrandom` for salt initialization and skip zero on wraparound
- Compute `VarBind::encoded_size()` arithmetically instead of allocating

### Fixed

- `Pdu::decode` rejecting valid GETBULK requests
- OID first subidentifier overflow during BER encoding
- Enforce `MAX_OID_LEN` during BER decode per RFC 2578 Section 3.5
- PDU `error_index` and GETBULK parameter validation during decode
- Integer overflow in BER decoder bounds checks
- USM `engine_boots`/`engine_time` validation per RFC 3414
- Cap `estimated_time()` at `MAX_ENGINE_TIME` per RFC 3414 Section 2.2.1
- Broken doc links

## [0.3.0] - 2026-01-02

### Added

- Agent concurrent request processing with semaphore-based limiting and graceful shutdown via `CancellationToken`
- `View::check_subtree()` for 3-state access detection (included/excluded/ambiguous)
- Blumenthal key extension (`KeyExtension::Blumenthal`) for AES-192/256 interoperability with net-snmp
- `Transport::max_message_size()` for transport-aware msgMaxSize capping
- IP_PKTINFO support via `quinn-udp` for correct source IP on multi-homed agents

### Changed

- VACM access selection implements full RFC 3415 preference order (securityModel, contextMatch, contextPrefix length, securityLevel)
- SNMPv3 generates fresh msgID on each retry attempt per RFC 3412 Section 6.2
- Request IDs masked to 31 bits for RFC 1157/3412 compliance
- Agent-reported msgMaxSize capped to transport limit

### Fixed

- msgID and msgMaxSize bounds validation per RFC 3412 HeaderData definition

### Removed

- Unused dependencies and dead code

## [0.2.0] - 2026-01-01

### Changed

- **Breaking:** Unified `UdpTransport` and `SharedUdpTransport` into a single
  `UdpTransport` with `UdpHandle` pattern. The new design uses a background
  receiver task with sharded pending maps for correct concurrent request handling.
- **Breaking:** `Transport` trait changes:
  - Renamed `target()` to `peer_addr()` for consistency with std
  - Added `register_request(request_id, timeout)` for pre-send slot registration
  - `recv()` no longer takes a timeout parameter (uses registered deadline)
- Request IDs are now allocated from a global counter for process-wide uniqueness,
  preventing collisions when multiple transports exist

### Added

- Configurable retry strategies with backoff support:
  - `RetryStrategy::Fixed` - constant delay between retries (default)
  - `RetryStrategy::Exponential` - exponential backoff with configurable base and max
  - `RetryStrategy::None` - disable retries entirely
- `UdpTransport::shutdown()` for graceful termination of background receiver
- `ClientBuilder::build_with(&UdpTransport)` for convenient shared transport usage

### Fixed

- Concurrent UDP requests no longer cause false timeouts due to race conditions
  in response routing
- Memory leak from orphaned pending responses now prevented via periodic cleanup

### Removed

- `SharedUdpTransport` and `SharedUdpHandle` (functionality merged into `UdpTransport`)

## [0.1.2] - 2026-01-01

### Fixed

- `MasterKeys` can now be used without also specifying passwords. Previously,
  using `Auth::usm().with_master_keys()` would fail validation requiring
  `auth_password` even though keys were already derived.

### Documentation

- Significantly expanded rustdoc coverage across all modules with examples
- Added crate-level documentation sections for error handling, tracing,
  agent compatibility, and scalable SNMPv3 polling
- Improved examples to use test container credentials and RFC 5737 TEST-NET
  addresses

## [0.1.1] - 2025-12-31

### Added

- SNMPv1, v2c, and v3 client support
- GET, GETNEXT, GETBULK, SET operations
- WALK and BULKWALK streaming iterators
- SNMPv3 USM security:
  - Authentication: MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512
  - Privacy: DES, AES-128, AES-192, AES-256
- Transport implementations:
  - `UdpTransport` for single-target clients
  - `TcpTransport` for stream-based connections
  - `SharedUdpTransport` for scalable polling (many targets, single FD)
- `NotificationReceiver` for trap/inform handling
- `Agent` with `MibHandler` trait for building SNMP agents
- VACM (View-Based Access Control Model) support
- Two-phase SET commit per RFC 3416
- `oid!` macro for compile-time OID parsing
- Zero-copy BER encoding/decoding
- CLI utilities: `asnmp-get`, `asnmp-walk`, `asnmp-set`

[0.11.0]: https://github.com/async-snmp/async-snmp/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/async-snmp/async-snmp/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/async-snmp/async-snmp/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/async-snmp/async-snmp/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/async-snmp/async-snmp/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/async-snmp/async-snmp/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/async-snmp/async-snmp/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/async-snmp/async-snmp/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/async-snmp/async-snmp/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/async-snmp/async-snmp/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/async-snmp/async-snmp/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/async-snmp/async-snmp/releases/tag/v0.1.1
