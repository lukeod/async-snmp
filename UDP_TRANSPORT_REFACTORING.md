# UDP Transport Refactoring: Analysis and Recommendation

## Executive Summary

The current `UdpTransport` implementation has critical race conditions that can cause false timeouts and response misdelivery when used with concurrent requests. This document analyzes the issues, evaluates design options, and recommends a unified architecture that fixes all correctness issues while maintaining high performance.

**Recommendation:** Implement a shared `UdpCore` component with sharded pending request tracking, used by both `UdpTransport` and `SharedUdpTransport`.

---

## Current Architecture

### UdpTransport (`src/transport/udp.rs`)

- **Model:** Each caller directly awaits `socket.recv()` in a loop
- **Pending buffer:** `Mutex<HashMap<i32, Bytes>>` for mismatched responses
- **Request IDs:** Each `Client` has its own `AtomicI32` counter starting at 1
- **Socket:** Connected UDP socket (efficient for single target)

### SharedUdpTransport (`src/transport/shared.rs`)

- **Model:** Background task receives all packets, delivers via oneshot channels
- **Pending buffer:** `Mutex<HashMap<i32, PendingRequest>>` with deadlines
- **Request IDs:** Shared `AtomicI32` counter across all handles
- **Socket:** Unconnected UDP socket (supports multiple targets)

---

## Identified Issues

### 1. Race Condition: False Timeouts (UdpTransport) — CRITICAL

**Location:** `src/transport/udp.rs:200-298`

When multiple callers use the same `UdpTransport` concurrently:

```
Caller A (request_id=1)              Caller B (request_id=2)
─────────────────────────────────────────────────────────────
Check pending: empty                 Check pending: empty
Await socket.recv() ──────────┐      Await socket.recv() ──────┐
                              │                                 │
                              │      Response for ID=1 arrives  │
                              │      B receives it              │
                              │      B buffers: pending[1]=data │
                              │      B continues loop           │
                              │                                 │
A still blocked on recv()     │                                 │
A's response is in pending!   │                                 │
                              │                                 │
A times out (FALSE TIMEOUT) ──┘                                 │
```

**Impact:** Caller times out despite response being available in pending buffer.

### 2. Memory Leak: No Cleanup of Pending Buffer (UdpTransport) — MEDIUM

**Location:** `src/transport/udp.rs:112`

The `pending: Mutex<HashMap<i32, Bytes>>` has no expiration or cleanup mechanism.

**Leak scenarios:**
- Caller times out before response arrives → response buffered, never claimed
- Duplicate/spurious responses → permanently stored
- Caller errors out → buffered response becomes orphan

**Impact:** Unbounded memory growth over long-running connections.

### 3. Request ID Collision (UdpTransport + Client) — MEDIUM

**Location:** `src/client/mod.rs:134`, `src/transport/udp.rs` (no `alloc_request_id`)

When multiple `Client` instances share the same `UdpTransport`:
- Each client has its own counter starting at 1
- `UdpTransport::alloc_request_id()` returns `None` (default trait impl)
- Clients generate overlapping request IDs

**Impact:** Response delivered to wrong client; data corruption.

### 4. TOCTOU Window (UdpTransport) — LOW

**Location:** `src/transport/udp.rs:202-233`

Gap between checking pending buffer and awaiting socket:

```rust
{
    let mut pending = self.inner.pending.lock();
    if let Some(data) = pending.remove(&request_id) { return Ok(…); }
}  // Lock released

// ← Window: another caller could insert our response here

let result = socket.recv().await;  // We miss it until next iteration
```

**Impact:** Slight added latency in race scenarios.

---

## Performance Considerations

### Hot Path Operations

| Operation | Frequency | Cost |
|-----------|-----------|------|
| Socket send/recv | Per request | Syscall (~1-10μs) |
| Request ID allocation | Per request | `AtomicI32::fetch_add` (~1ns) |
| Pending map insert | Per request | Mutex lock + HashMap insert (~50-200ns) |
| Pending map remove | Per request | Mutex lock + HashMap remove (~50-200ns) |
| Response delivery | Per request | Channel send or notify (~10-50ns) |

**Observation:** Syscall cost dominates. In-memory operations are 10-100x cheaper.

### Scalability Targets

| Metric | Target |
|--------|--------|
| Request rate | 10,000+ req/s |
| Concurrent pending | 50,000+ (10k/s × 5s timeout) |
| Targets (SharedUdp) | 10,000+ |

### Contention Analysis

With 50k concurrent requests and a single `Mutex<HashMap>`:
- Every insert/remove/lookup contends on the same lock
- Under high load, threads spin waiting for lock
- Sharding reduces contention proportionally

---

## Design Options

### Option A: Sharded Notify + Shared Core

Extract common infrastructure with sharded locks to reduce contention.

```rust
// src/transport/udp_core.rs
const SHARDS: usize = 64;

pub struct UdpCore {
    shards: [Shard; SHARDS],
    next_request_id: AtomicI32,
}

struct Shard {
    pending: Mutex<HashMap<i32, ResponseSlot>>,
    notify: Notify,
}

struct ResponseSlot {
    response: Option<(Bytes, SocketAddr)>,
    deadline: Instant,
    target: SocketAddr,  // For source validation
}
```

**Pros:**
- No per-request allocation (unlike oneshot channels)
- Contention reduced by 64x via sharding
- Single `Notify` per shard (bounded thundering herd)
- No external dependencies

**Cons:**
- Slightly more complex than current SharedUdpTransport
- Waiters in same shard wake together (acceptable with 64 shards)

### Option B: Per-Request Oneshot Channels (Current SharedUdp Pattern)

Keep the current `SharedUdpTransport` pattern, apply to both transports.

```rust
struct PendingRequest {
    sender: oneshot::Sender<(Bytes, SocketAddr)>,
    deadline: Instant,
    target: SocketAddr,
}
```

**Pros:**
- Simple, proven pattern
- Direct delivery (no thundering herd)

**Cons:**
- Per-request channel allocation (~64 bytes + Arc overhead)
- At 10k req/s = 640KB/s allocation churn
- GC pressure from short-lived allocations

### Option C: Lock-Free with DashMap

Use `dashmap` crate for lock-free concurrent HashMap.

```rust
pending: DashMap<i32, ResponseSlot>
```

**Pros:**
- Lock-free reads and writes
- Well-tested, production-ready
- Simple API

**Cons:**
- External dependency
- Still need notification mechanism
- May have higher constant overhead than sharded Mutex

### Option D: Slot-Based Pre-allocation

Pre-allocate fixed slots, reuse across requests.

```rust
struct RequestSlot {
    state: AtomicU8,  // Free=0, Pending=1, Complete=2
    request_id: AtomicI32,
    response: UnsafeCell<MaybeUninit<(Bytes, SocketAddr)>>,
    waker: AtomicWaker,
}

slots: Box<[RequestSlot; 65536]>  // Fixed capacity
```

**Pros:**
- Zero allocation after startup
- Lock-free with atomic state machine
- Cache-friendly (slots are contiguous)

**Cons:**
- Fixed capacity (must handle overflow)
- Complex implementation (unsafe code)
- Slot lookup requires scan or secondary index

---

## Recommendation: Option A — Sharded Notify + Shared Core

### Rationale

1. **Correctness:** Fixes all identified race conditions and memory leaks
2. **Performance:**
   - No per-request allocation (unlike Option B)
   - Sharding reduces contention to negligible levels
   - No external dependencies (unlike Option C)
   - Simpler than lock-free slot management (unlike Option D)
3. **Maintainability:** Single implementation for both transport types
4. **Flexibility:** Easy to tune shard count based on benchmarks

### Architecture

```
src/transport/
├── mod.rs              # Transport trait, extract_request_id, re-exports
├── udp_core.rs         # NEW: UdpCore, Shard, ResponseSlot
├── udp.rs              # UdpTransport (connected socket + UdpCore)
├── shared.rs           # SharedUdpTransport (unconnected socket + UdpCore)
└── tcp.rs              # Unchanged
```

### Detailed Design

#### `UdpCore` — Central Request Tracking

```rust
// src/transport/udp_core.rs

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::Notify;

use crate::error::{Error, Result};

/// Number of shards for pending request map.
/// Higher values reduce contention but increase memory overhead.
/// 64 shards = 64 Mutexes + 64 Notifys ≈ 2-4KB overhead.
const SHARDS: usize = 64;

/// Core request tracking for UDP transports.
///
/// Provides sharded pending request storage with efficient wakeup
/// notification. Used by both `UdpTransport` and `SharedUdpTransport`.
pub struct UdpCore {
    shards: Box<[Shard; SHARDS]>,
    next_request_id: AtomicI32,
}

struct Shard {
    pending: Mutex<HashMap<i32, ResponseSlot>>,
    notify: Notify,
}

struct ResponseSlot {
    /// Filled by receiver task when response arrives.
    response: Option<(Bytes, SocketAddr)>,
    /// Request expiration time for cleanup.
    deadline: Instant,
    /// Expected source address (for validation/logging).
    expected_target: SocketAddr,
}

impl UdpCore {
    /// Create a new UdpCore with randomized initial request ID.
    pub fn new() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};

        let initial_id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| (d.as_nanos() as i32).wrapping_abs().max(1))
            .unwrap_or(1);

        Self {
            shards: Box::new(std::array::from_fn(|_| Shard {
                pending: Mutex::new(HashMap::new()),
                notify: Notify::new(),
            })),
            next_request_id: AtomicI32::new(initial_id),
        }
    }

    /// Allocate the next request ID.
    pub fn alloc_request_id(&self) -> i32 {
        self.next_request_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Register a pending request. Must be called before sending.
    pub fn register(&self, request_id: i32, target: SocketAddr, timeout: Duration) {
        let shard = self.shard(request_id);
        let deadline = Instant::now() + timeout;

        shard.pending.lock().unwrap().insert(request_id, ResponseSlot {
            response: None,
            deadline,
            expected_target: target,
        });
    }

    /// Deliver a response. Called by receiver task.
    /// Returns true if a waiter was found, false if response was unexpected.
    pub fn deliver(&self, request_id: i32, data: Bytes, source: SocketAddr) -> bool {
        let shard = self.shard(request_id);

        let found = {
            let mut pending = shard.pending.lock().unwrap();
            if let Some(slot) = pending.get_mut(&request_id) {
                slot.response = Some((data, source));
                true
            } else {
                false
            }
        };

        if found {
            shard.notify.notify_waiters();
        }

        found
    }

    /// Wait for a response with timeout.
    /// The request must have been registered with `register()` first.
    pub async fn wait_for_response(
        &self,
        request_id: i32,
        timeout: Duration,
    ) -> Result<(Bytes, SocketAddr)> {
        let shard = self.shard(request_id);
        let deadline = Instant::now() + timeout;

        loop {
            // Check for response
            {
                let mut pending = shard.pending.lock().unwrap();
                if let Some(slot) = pending.get_mut(&request_id) {
                    if let Some(response) = slot.response.take() {
                        pending.remove(&request_id);
                        return Ok(response);
                    }
                } else {
                    // Slot was removed (shouldn't happen in normal flow)
                    return Err(Error::Timeout {
                        target: None,
                        elapsed: timeout,
                        request_id,
                        retries: 0,
                    });
                }
            }

            // Calculate remaining time
            let now = Instant::now();
            if now >= deadline {
                self.unregister(request_id);
                return Err(Error::Timeout {
                    target: None,
                    elapsed: timeout,
                    request_id,
                    retries: 0,
                });
            }
            let remaining = deadline - now;

            // Wait for notification or timeout
            tokio::select! {
                biased;
                _ = shard.notify.notified() => continue,
                _ = tokio::time::sleep(remaining) => {
                    self.unregister(request_id);
                    return Err(Error::Timeout {
                        target: None,
                        elapsed: timeout,
                        request_id,
                        retries: 0,
                    });
                }
            }
        }
    }

    /// Unregister a pending request (e.g., on timeout or cancel).
    pub fn unregister(&self, request_id: i32) {
        let shard = self.shard(request_id);
        shard.pending.lock().unwrap().remove(&request_id);
    }

    /// Clean up expired requests across all shards.
    /// Should be called periodically by receiver tasks.
    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        for shard in self.shards.iter() {
            let mut pending = shard.pending.lock().unwrap();
            pending.retain(|_, slot| slot.deadline > now);
        }
    }

    /// Get the shard for a request ID.
    fn shard(&self, request_id: i32) -> &Shard {
        let index = (request_id as u32 as usize) % SHARDS;
        &self.shards[index]
    }
}

impl Default for UdpCore {
    fn default() -> Self {
        Self::new()
    }
}
```

#### Updated `UdpTransport`

```rust
// src/transport/udp.rs (updated)

use super::{Transport, UdpCore, extract_request_id};
use crate::error::{Error, Result};
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

pub struct UdpTransport {
    inner: Arc<UdpTransportInner>,
}

struct UdpTransportInner {
    socket: UdpSocket,
    target: SocketAddr,
    local_addr: SocketAddr,
    core: UdpCore,
}

impl UdpTransport {
    pub async fn connect(target: SocketAddr) -> Result<Self> {
        let socket = bind_ephemeral_udp_socket(target).await?;
        socket.connect(target).await?;
        let local_addr = socket.local_addr()?;

        let inner = Arc::new(UdpTransportInner {
            socket,
            target,
            local_addr,
            core: UdpCore::new(),
        });

        // Spawn background receiver
        Self::start_recv_loop(inner.clone());

        Ok(Self { inner })
    }

    fn start_recv_loop(inner: Arc<UdpTransportInner>) {
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            let mut cleanup_counter = 0u32;

            loop {
                match inner.socket.recv(&mut buf).await {
                    Ok(len) => {
                        let data = Bytes::copy_from_slice(&buf[..len]);

                        if let Some(request_id) = extract_request_id(&data) {
                            if !inner.core.deliver(request_id, data, inner.target) {
                                tracing::debug!(
                                    request_id,
                                    "received response for unknown request"
                                );
                            }
                        } else {
                            tracing::warn!(len, "malformed response, couldn't extract request_id");
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "UDP recv error");
                    }
                }

                // Periodic cleanup (every 100 packets)
                cleanup_counter += 1;
                if cleanup_counter >= 100 {
                    cleanup_counter = 0;
                    inner.core.cleanup_expired();
                }
            }
        });
    }
}

impl Clone for UdpTransport {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone() }
    }
}

impl Transport for UdpTransport {
    async fn send(&self, data: &[u8]) -> Result<()> {
        self.inner.socket.send(data).await.map_err(|e| Error::Io {
            target: Some(self.inner.target),
            source: e,
        })?;
        Ok(())
    }

    async fn recv(&self, request_id: i32, timeout: Duration) -> Result<(Bytes, SocketAddr)> {
        // Note: register() is called by the caller before send()
        // We just wait here
        self.inner.core.wait_for_response(request_id, timeout).await
    }

    fn peer_addr(&self) -> SocketAddr {
        self.inner.target
    }

    fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr
    }

    fn is_stream(&self) -> bool {
        false
    }

    fn alloc_request_id(&self) -> Option<i32> {
        Some(self.inner.core.alloc_request_id())
    }
}
```

#### Updated `SharedUdpTransport`

```rust
// src/transport/shared.rs (updated)

use super::{Transport, UdpCore, extract_request_id};
use crate::error::{Error, Result};
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

pub struct SharedUdpTransport {
    inner: Arc<SharedUdpTransportInner>,
}

struct SharedUdpTransportInner {
    socket: UdpSocket,
    local_addr: SocketAddr,
    core: UdpCore,
    config: SharedTransportConfig,
}

impl SharedUdpTransport {
    pub async fn bind(addr: &str) -> Result<Self> {
        let bind_addr: SocketAddr = addr.parse()?;
        let socket = bind_udp_socket(bind_addr).await?;
        let local_addr = socket.local_addr()?;

        let inner = Arc::new(SharedUdpTransportInner {
            socket,
            local_addr,
            core: UdpCore::new(),
            config: SharedTransportConfig::default(),
        });

        Self::start_recv_loop(inner.clone());

        Ok(Self { inner })
    }

    pub fn handle(&self, target: SocketAddr) -> SharedUdpHandle {
        SharedUdpHandle {
            inner: self.inner.clone(),
            target,
        }
    }

    fn start_recv_loop(inner: Arc<SharedUdpTransportInner>) {
        tokio::spawn(async move {
            let mut buf = vec![0u8; inner.config.max_message_size];
            let mut cleanup_counter = 0u32;

            loop {
                match inner.socket.recv_from(&mut buf).await {
                    Ok((len, source)) => {
                        let data = Bytes::copy_from_slice(&buf[..len]);

                        if let Some(request_id) = extract_request_id(&data) {
                            if !inner.core.deliver(request_id, data, source) {
                                tracing::debug!(
                                    request_id,
                                    %source,
                                    "received response for unknown request"
                                );
                            }
                        } else {
                            tracing::warn!(len, %source, "malformed response");
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "shared UDP recv error");
                    }
                }

                cleanup_counter += 1;
                if cleanup_counter >= 100 {
                    cleanup_counter = 0;
                    inner.core.cleanup_expired();
                }
            }
        });
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr
    }
}

#[derive(Clone)]
pub struct SharedUdpHandle {
    inner: Arc<SharedUdpTransportInner>,
    target: SocketAddr,
}

impl Transport for SharedUdpHandle {
    async fn send(&self, data: &[u8]) -> Result<()> {
        self.inner.socket.send_to(data, self.target).await.map_err(|e| Error::Io {
            target: Some(self.target),
            source: e,
        })?;
        Ok(())
    }

    async fn recv(&self, request_id: i32, timeout: Duration) -> Result<(Bytes, SocketAddr)> {
        self.inner.core.wait_for_response(request_id, timeout).await
    }

    fn peer_addr(&self) -> SocketAddr {
        self.target
    }

    fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr
    }

    fn is_stream(&self) -> bool {
        false
    }

    fn alloc_request_id(&self) -> Option<i32> {
        Some(self.inner.core.alloc_request_id())
    }
}
```

#### Transport Trait Update

The `Transport` trait needs a new method for pre-registration:

```rust
// src/transport/mod.rs

pub trait Transport: Send + Sync + Clone {
    // ... existing methods ...

    /// Pre-register a request before sending.
    /// Required for UDP transports to ensure the response slot exists
    /// before the packet is sent.
    fn register_request(&self, request_id: i32, target: SocketAddr, timeout: Duration) {
        // Default no-op for TCP (doesn't need pre-registration)
        let _ = (request_id, target, timeout);
    }
}
```

#### Client Integration

Update `Client::send_and_recv` to pre-register:

```rust
// src/client/mod.rs

async fn send_and_recv(&self, request_id: i32, data: &[u8]) -> Result<Pdu> {
    // Pre-register before sending
    self.inner.transport.register_request(
        request_id,
        self.peer_addr(),
        self.inner.config.timeout,
    );

    // ... rest unchanged ...
}
```

---

## Migration Plan

### Phase 1: Add UdpCore
1. Create `src/transport/udp_core.rs` with `UdpCore` implementation
2. Add comprehensive unit tests for `UdpCore`
3. Add `register_request` to `Transport` trait with default no-op

### Phase 2: Migrate UdpTransport
1. Update `UdpTransport` to use `UdpCore`
2. Spawn background receiver task
3. Update tests, ensure existing behavior preserved
4. Remove old `pending: HashMap<i32, Bytes>` field

### Phase 3: Migrate SharedUdpTransport
1. Update `SharedUdpTransport` to use `UdpCore`
2. Remove `PendingRequest` struct and oneshot channels
3. Update tests

### Phase 4: Client Integration
1. Update `Client::send_and_recv` to call `register_request`
2. Remove client-level `request_id: AtomicI32` (now handled by transport)
3. Update tests for new behavior

### Phase 5: Cleanup
1. Remove dead code
2. Update documentation
3. Add integration tests for concurrent request scenarios
4. Benchmark and tune shard count if needed

---

## Testing Strategy

### Unit Tests (UdpCore)

```rust
#[tokio::test]
async fn test_register_and_deliver() { ... }

#[tokio::test]
async fn test_timeout() { ... }

#[tokio::test]
async fn test_concurrent_requests() { ... }

#[tokio::test]
async fn test_cleanup_expired() { ... }

#[tokio::test]
async fn test_request_id_uniqueness() { ... }

#[tokio::test]
async fn test_sharding_distribution() { ... }
```

### Integration Tests

```rust
#[tokio::test]
async fn test_concurrent_requests_no_false_timeout() {
    // Spawn 100 concurrent requests
    // Verify all complete successfully (no false timeouts)
}

#[tokio::test]
async fn test_response_ordering_stress() {
    // Send requests, have mock agent respond out of order
    // Verify correct request-response matching
}

#[tokio::test]
async fn test_memory_stability() {
    // Run for extended period with timeouts
    // Verify no memory growth
}
```

### Benchmarks

```rust
#[bench]
fn bench_request_id_allocation(b: &mut Bencher) { ... }

#[bench]
fn bench_register_deliver_cycle(b: &mut Bencher) { ... }

#[bench]
fn bench_concurrent_requests(b: &mut Bencher) { ... }
```

---

## Performance Expectations

| Metric | Current | After Refactor |
|--------|---------|----------------|
| Request ID allocation | ~1ns | ~1ns (unchanged) |
| Per-request allocation | 64+ bytes (oneshot) | 0 bytes |
| Mutex contention (50k concurrent) | High (1 lock) | Low (64 locks) |
| False timeout rate | >0% (race condition) | 0% |
| Memory leak rate | >0 bytes/hour | 0 bytes/hour |

---

## Open Questions

1. **Shard count:** 64 is a reasonable default. Should this be configurable?
2. **Cleanup frequency:** Every 100 packets. Should this be time-based instead?
3. **Graceful shutdown:** Should `UdpCore` support cancellation of pending requests?
4. **Metrics:** Should we expose pending request count for monitoring?

---

## Conclusion

The recommended refactoring addresses all identified correctness issues while maintaining high performance through sharded locking. The shared `UdpCore` component reduces code duplication and ensures consistent behavior across both transport types. The migration can be done incrementally with comprehensive testing at each phase.
