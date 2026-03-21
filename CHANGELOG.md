# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/async-snmp/async-snmp/compare/v0.8.0...HEAD
[0.8.0]: https://github.com/async-snmp/async-snmp/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/async-snmp/async-snmp/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/async-snmp/async-snmp/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/async-snmp/async-snmp/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/async-snmp/async-snmp/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/async-snmp/async-snmp/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/async-snmp/async-snmp/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/async-snmp/async-snmp/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/async-snmp/async-snmp/releases/tag/v0.1.1
