# Trait Audit

Audit of trait implementations across the codebase: problematic Clone semantics, missing standard
traits, missing conversions, and ergonomic gaps.

## Problematic Clone Impls

### `EngineState` - `v3/engine.rs`

- [x] ~~Audit callers of `EngineCache::get()` for mutation of cloned `EngineState`~~

Not a real problem. All callers use the cloned `EngineState` as a read-only snapshot. The cache is
write-once at discovery time; per-client state is maintained in its own `RwLock<Option<EngineState>>`
and updated via `update_time()` on that local copy, never on the cached value. No action needed.

### `TcpTransport` - `transport/tcp.rs`

- [x] Remove `Clone` from the `Transport` trait

`Transport` trait requires `Clone` as a supertrait bound (`Transport: Send + Sync + Clone`). PR #16
added `#[derive(Clone)]` to `UdpTransport` to satisfy it. For UDP (shared connectionless socket via
`Arc<UdpTransportInner>`) Clone is semantically clean. For TCP (serialized access to a single stream
through a mutex) it's surprising - clones share one connection, not independent connections.

Investigation confirms nothing actually depends on `Transport: Clone`:

- `Client<T>` wraps transport in `Arc<ClientInner<T>>`. `Client::clone()` bumps the Arc, never
  clones the transport. The `#[derive(Clone)]` on `Client<T>` generates a spurious `T: Clone` bound
  that `Transport: Clone` happens to satisfy.
- `build_with(&transport)` takes a reference, `connect()`/`connect_tcp()` move the transport in.
  No builder path clones a transport.
- `Walk`, `BulkWalk`, `WalkStream` don't derive Clone. They clone `Client` (Arc bump) internally.
- Agent and notification receiver use `UdpSocket` directly, not the Transport trait.
- Test transports derive Clone to satisfy the trait but are never actually cloned.
- The only transport `.clone()` in the codebase is in a TCP test (`tcp.rs:703`), which works because
  `TcpTransport` independently derives Clone, not because the trait requires it.

Fix: remove `Clone` from `Transport: Send + Sync + Clone`, replace `#[derive(Clone)]` on
`Client<T>` with a manual impl that clones the Arc. All concrete transports keep their independent
`#[derive(Clone)]`. PR #16's change stays, still works, just no longer mandatory. Custom Transport
implementors no longer need to add Clone, which is a simplification.

---

## Methods That Should Be `TryFrom`/`From`

| Type | Current | Should Be | File | Status |
|------|---------|-----------|------|--------|
| `RowStatus` | `from_i32(i32) -> Option<Self>` | `TryFrom<i32>` | `value.rs` | [x] |
| `StorageType` | `from_i32(i32) -> Option<Self>` | `TryFrom<i32>` | `value.rs` | [x] |
| `Version` | `from_i32(i32) -> Option<Self>` | `TryFrom<i32>` | `version.rs` | [x] |
| `SecurityLevel` | `from_flags(u8)` / `to_flags()` | `TryFrom<u8>` / `Into<u8>` | `message/v3.rs` | [x] |

`MsgFlags` already returns `Result` from `from_byte()`, which is essentially the `TryFrom`
signature. Could formalize as `impl TryFrom<u8>` for consistency with `SecurityLevel`, but low
priority.

### `Value` - `From` impls (`value.rs`)

~~Missing `From<Bytes>`, `From<&[u8]>`, `From<Oid>`, `From<i32>`.~~

- [x] Already implemented (`value.rs:1170-1227`). All four conversions exist.

### `Oid` - conversions (`oid.rs`)

- [x] `From<Vec<u32>>` - missing. `From<&[u32]>` and `From<[u32; N]>` exist but not `From<Vec<u32>>`.
- [x] ~~`TryFrom<&str>`~~ - covered by existing `FromStr` impl (`oid.rs:640-646`), which provides
  the blanket `TryFrom<&str>`.

---

## Missing `Hash` on Equality Types

These types derive `PartialEq + Eq` but not `Hash`, making them unusable as `HashMap`/`HashSet` keys.
All are small Copy enums where adding Hash is trivial and zero-cost.

| Type | File | Status |
|------|------|--------|
| `PduType` | `pdu/mod.rs` | [x] |
| `GenericTrap` | `pdu/mod.rs` | [x] |
| `ErrorStatus` | `error/mod.rs` | [x] |
| `WalkAbortReason` | `error/mod.rs` | [x] also added `std::error::Error` |

`ErrorStatus` has an `Unknown(i32)` variant but `i32` is `Hash`, so deriving works fine.

`WalkAbortReason` already has `Display`; adding `impl Error for WalkAbortReason {}` is a one-liner.

### `UsmSecurityParams` - `v3/usm.rs`

- [x] Missing `PartialEq`/`Eq` entirely (currently only `Debug, Clone`). Fields are `Bytes`, which
  supports equality. Useful for testing.

---

## Missing `PartialEq`/`Eq` on Message Types

These are data containers where equality is testable but not derived, making unit tests awkward.
All fields already implement `PartialEq`/`Eq`.

| Type | File | Status |
|------|------|--------|
| `CommunityPdu` | `message/community.rs` | [x] |
| `ScopedPdu` | `message/v3.rs` | [x] |
| `V3Message` | `message/v3.rs` | [x] |
| `V3MessageData` | `message/v3.rs` | [x] |
| `MsgGlobalData` | `message/v3.rs` | [x] |
| `OidTable<V>` | `handler/oid_table.rs` | [x] bounded on `V: PartialEq` |

---

## Missing `AsRef` / `Borrow`

| Type | File | Missing | Status |
|------|------|---------|--------|
| `Oid` | `oid.rs` | `AsRef<[u32]>` | [x] delegates to `.arcs()` |
| `MasterKey` | `v3/auth.rs` | `AsRef<[u8]>` | [x] delegates to `.as_bytes()` |
| `LocalizedKey` | `v3/auth.rs` | `AsRef<[u8]>` | [x] delegates to `.as_bytes()` |

---

## Missing `Display`

- [x] ~~`Value` (`value.rs`)~~ - already implemented (`value.rs:1090-1127`).
- [x] ~~`ParseProtocolError` (`v3/mod.rs`)~~ - both `Display` and `std::error::Error` already
  implemented (`v3/mod.rs:59-76`).

---

## Missing `IntoIterator` on Collection Types

| Type | File | Form | Status |
|------|------|------|--------|
| `Oid` | `oid.rs` | `IntoIterator for &Oid` and `IntoIterator for Oid` | [x] |
| `OidTable<V>` | `handler/oid_table.rs` | `IntoIterator for &OidTable<V>` | [x] delegates to `.iter()` |

Consuming `IntoIterator for Oid` could also be added, delegating to `SmallVec`'s `IntoIterator`.

---

## Should Be `Copy`

| Type | File | Notes | Status |
|------|------|-------|--------|
| `Backoff` | `client/retry.rs` | All fields are `Duration` (Copy) and `f64` (Copy) | [x] |
| `format::hex::DecodeError` | `format/hex.rs` | Two unit variants | [x] |

---

## Unnecessary Allocation

**`verify_message`** in `v3/auth.rs` calls `message.to_vec()` to zero out the auth params region
before computing the HMAC, allocating a full copy of the message on every inbound authenticated
response.

- [x] Refactor HMAC computation to accept split ranges (before auth, zeros, after auth) using
  incremental `update()` calls on the HMAC context, avoiding the full message copy.

Low priority - SNMP message sizes are small and this isn't a high-throughput hot path.

---

## Missing `Debug`

| Type | File | Notes | Status |
|------|------|-------|--------|
| `DerivedKeys` | `notification/types.rs` | No derives at all. Safe to derive - inner types (`LocalizedKey`, `PrivKey`) already have custom Debug impls that print `[REDACTED]`. | [x] |
| `VarBindInfo` | `mib_support.rs` | Public struct, all fields support Debug. | [x] |
