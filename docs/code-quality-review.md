# Code Quality Review

Review of ~30k lines of Rust across 62 source files, covering error handling/safety,
public API design, async/transport, crypto/SNMPv3, BER codec, and agent/handler subsystem.

## High severity

### ~~Unbounded memory in AllowNonIncreasing walk mode~~ (fixed)

`ClientBuilder::validate()` now rejects `AllowNonIncreasing` without `max_walk_results`.

### ~~Panics on valid API call paths~~ (fixed)

`Message::pdu()`, `Message::into_pdu()`, and `CommunityMessage::into_pdu()` now return
`Option` instead of panicking. Removed redundant `try_pdu()`/`try_into_pdu()`.

## Medium severity

### ~~GETNEXT loop can run forever with buggy handlers~~ (fixed)

`get_next_accessible_oid()` now checks OID monotonicity and returns `None` on violation.

### ~~Engine time truncation in agent~~ (fixed)

`update_engine_time()` now uses a saturating cast via `.min(u32::MAX as u64)`.

### ~~getrandom panics~~ (fixed)

`random_nonzero_u64()` now returns `CryptoResult` and propagates through `PrivKey::from_bytes()`
and `PrivKey::from_master_key()`. `SaltCounter::new()` (construction-time only) retains a panic
with a descriptive message.

### ~~std::sync::Mutex for TCP timeout~~ (fixed)

`current_timeout` replaced with `AtomicU64` storing milliseconds, eliminating poisoning risk.

### ~~VACM misconfiguration is silent~~ (fixed)

`resolve_vacm()` now logs a warning when a group exists but has no matching access entry.

### ~~Response auth key unwrap~~ (fixed)

`extract_auth_key()` now returns `&DerivedKeys` alongside the auth key, eliminating the
fragile `derived_keys.unwrap()` in the `AuthPriv` path.

### ~~EngineCache grows without bound~~ (fixed)

`EngineCache` is now unbounded by default (each entry is ~100-150 bytes, so memory
is negligible for typical deployments). `EngineCache::with_max_capacity()` is available
for users who need a hard limit, with oldest-synced eviction when full.

### ~~UDP pending requests HashMap unbounded~~ (fixed)

The UDP recv loop runs `cleanup_expired()` every second via a `tokio::time::interval`,
and `wait_for_response()` removes its own slot on completion or timeout.

### ~~SET undo failure leaves agent in inconsistent state~~ (fixed)

When `undo_set()` fails during rollback, the response now returns `UndoFailed` (per RFC 3416)
instead of `CommitFailed`, so the client knows the rollback was incomplete.

### ~~VACM misconfiguration is silent~~ (fixed)

`resolve_vacm()` now logs a warning when a group exists but has no matching access entry.


## Low severity

### Missing Debug on builder types

`src/client/builder.rs`, `src/client/auth.rs`, `src/client/retry.rs`,
`src/transport/tcp.rs`

`ClientBuilder`, `UsmBuilder`, `RetryBuilder`, `TcpTransportBuilder` lack
`#[derive(Debug)]`.

### Prelude missing key types

`src/prelude.rs`

Missing `Auth`, `ClientBuilder`, `Retry` which are commonly needed for basic client
construction. These types are available via normal crate paths (`async_snmp::Auth`, etc.)
but not re-exported from the prelude.

### Naming inconsistency: ber_encoded_len vs encoded_size

`src/oid.rs:490` vs `src/varbind.rs:45`

Internal methods use one name, public API uses another. Standardize to one.

### Builder types missing Clone

`src/client/auth.rs`, `src/client/retry.rs`, `src/transport/tcp.rs`

`UsmBuilder`, `RetryBuilder`, and `TcpTransportBuilder` lack `Clone`. Users can't clone a
partially-configured builder to create variants. (`ClientBuilder` already derives Clone.)

### CryptoProvider trait lacks documented security requirements

`src/v3/crypto/mod.rs:83-153`

No explicit constraints on implementation correctness (constant-time comparison, IV
uniqueness, etc.).

### UDP recv task has no JoinHandle

`src/transport/udp.rs:175-215`

Spawned task cannot be explicitly awaited for clean shutdown. The `CancellationToken`
provides a shutdown signal but no completion notification, so callers cannot confirm the
task has actually exited.

### Missing snmpSilentDrops counter increment

`src/agent/mod.rs:1059-1065`

GETBULK TooBig responses don't increment the counter per RFC 3412. The counter is defined
but never incremented anywhere in the codebase.

## Positive findings

- **BER codec is solid** - proper overflow prevention, MAX_LENGTH enforcement, bounds
  checking, well-documented permissive parsing for device compatibility
- **Crypto fundamentals are correct** - constant-time HMAC comparison, proper key zeroization
  (Zeroize + ZeroizeOnDrop), quality salt generation, correct HMAC truncation per
  RFC 3414/7860
- **Replay protection is comprehensive** - engine time window enforcement, boot counter
  overflow handling
- **No unsafe code** - entire codebase relies on safe Rust
- **Value/Oid types are well-designed** - comprehensive accessor methods, good Display impls,
  thorough validation
- **Agent implements RFC 3413/3415/3416 correctly** - two-phase SET semantics, VACM
  integration, constant-time community comparison
- **Good test coverage** - edge cases for BER non-minimal encodings, firmware bugs, concurrent
  salt generation
