# async-snmp

[![CI](https://github.com/lukeod/async-snmp/actions/workflows/ci.yml/badge.svg)](https://github.com/lukeod/async-snmp/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/async-snmp.svg)](https://crates.io/crates/async-snmp)
[![Documentation](https://docs.rs/async-snmp/badge.svg)](https://docs.rs/async-snmp)
[![MSRV](https://img.shields.io/badge/MSRV-1.88-blue.svg)](https://blog.rust-lang.org/)
[![License](https://img.shields.io/crates/l/async-snmp.svg)](#license)

Async-first SNMP client library for Rust.

## Note

This library is not currently stable. While pre v1.0, breaking changes are likely to occur frequently, no attempt will be made to maintain backward compatibility pre-1.0.

MIB parsing is handled by [mib-rs](https://github.com/lukeod/mib-rs). Enable the `mib` feature flag for integrated OID name resolution, symbolic formatting, and type-aware value rendering.

## Features

- **Full protocol support**: SNMPv1, v2c, and v3 (USM)
- **Async-first**: Built on Tokio
- **All operations**: GET, GETNEXT, GETBULK, SET, WALK, BULKWALK
- **Trap and inform sending**: Agent-based (multi-sink) and client-based notification sending with V1/V2c/V3 support
- **Trap and inform receiving**: V1/V2c/V3 notification receiver with optional community filtering and per-notification security-level reporting
- **SNMP agent**: Async handler framework with two-phase SET commit, VACM access control, and built-in MIB handlers for engine/USM/MPD statistics
- **SNMPv3 security**: MD5/SHA-1/SHA-2 authentication, DES/3DES/AES-128/192/256 privacy, with compile-time RustCrypto or FIPS 140-3 backend selection
- **Automatic tooBig recovery**: GET/GETNEXT batches are automatically bisected when an agent returns a tooBig error
- **Multiple transports**: UDP (per-client or shared), TCP
- **Zero-copy decoding**: Minimal allocations using `bytes` crate
- **Checked OID encoding**: `oid!` constructs OIDs conveniently; outbound encoding rejects malformed or non-wire-valid values

### Protocol Support Matrix

| Feature | v1 | v2c | v3 |
|---------|:--:|:---:|:--:|
| GET / GETNEXT | Y | Y | Y |
| GETBULK | - | Y | Y |
| SET | Y | Y | Y |
| WALK / BULKWALK | Y | Y | Y |
| Receive Traps | Y | Y | Y |
| Receive Informs | - | Y | Y |
| Send Traps | Y | Y | Y |
| Send Informs | - | Y | Y |

### Interoperability Policy

Compatibility is controlled by separate, narrowly scoped policies rather than a
global permissive mode. Bounded BER/value normalizations and anomaly-preserving
response-shape handling are enabled by default; exact community matching and
rejection of unauthenticated SNMPv3 time correction remain the default security
boundary. Relaxed UDP source matching supports multihomed agents but warns on
off-target replies. Enable only workarounds required by a known agent, and pair
relaxed walk ordering with a result limit.

See the crate documentation's
[interoperability policy](https://docs.rs/async-snmp/latest/async_snmp/#interoperability-policy)
for the full control inventory, defaults, tradeoffs, observability, and compiling
configuration examples.

### SNMPv3 Security

**Authentication:** MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512

**Privacy:** DES, 3DES, AES-128, AES-192, AES-256

**Crypto backends:** Backend Cargo features are additive. Each USM configuration
selects one compiled backend; when both are enabled, RustCrypto remains the
non-FIPS default:
- `crypto-rustcrypto` (default) - RustCrypto crates, supports all protocols
- `crypto-fips` - aws-lc-rs (rejects MD5, DES, 3DES); select
  `CryptoBackend::AwsLcFips` explicitly for FIPS operations

Plaintext authentication and privacy passwords shorter than 8 octets are
rejected with `CryptoError::PasswordTooShort`. Constructors that accept
pre-derived key material are unaffected.

### Authoritative Engine Persistence

An Agent with USM users or V3 trap sinks, a V3 notification receiver, and a
client sending V3 traps can be authoritative for an exchange. RFC 3414 requires
each such engine to retain one stable engine ID and its boots counter in
non-volatile storage. On restart, load both values, increment boots, and persist
the new pair before sending or accepting V3 traffic.

`AuthoritativeEngine` enforces that startup order. Its clones share one clock,
and it retains the persistence callback so a boots increment caused by engine
time wrapping is stored before the new value is used. On first installation,
use `install`; on later starts, validate the loaded record and use `restart`:

```rust,ignore
use async_snmp::{
    AuthoritativeEngine, PersistedAuthoritativeEngine, generate_engine_id,
};

let engine = match load_engine_state()? {
    Some((engine_id, previous_boots)) => {
        let previous = PersistedAuthoritativeEngine::new(engine_id, previous_boots)?;
        AuthoritativeEngine::restart(previous, |current| {
            store_engine_state(current.engine_id(), current.engine_boots())
        })?
    }
    None => AuthoritativeEngine::install(generate_engine_id(), |current| {
        store_engine_state(current.engine_id(), current.engine_boots())
    })?,
};

let agent = Agent::builder()
    .authoritative_engine(engine)
    // configure USM users, handlers, and transport
    .build()
    .await?;
```

The persistence callback must be safe to call for the lifetime of the engine
and durably store both fields. If a startup or rollover write fails, the new
boots value is not used. Polling clients and V3 Inform senders do not need local
authoritative state because the remote responder is authoritative for those
exchanges.

## Installation

```bash
cargo add async-snmp@0.17.0
```

## Quick Start

### SNMPv2c

```rust
use async_snmp::{Auth, Client, oid};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<async_snmp::Error>> {
    let client = Client::builder(("192.168.1.1", 161), Auth::v2c("public"))
        .response_shape_policy(async_snmp::ResponseShapePolicy::Strict)
        .timeout(Duration::from_secs(5))
        .connect()
        .await?;

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await?;
    println!("sysDescr: {:?}", result.varbinds[0].value);

    Ok(())
}
```

Fixed-cardinality `get`, `get_next`, and `set` operations (including their
`*_many` forms) return a `FixedCardinalityResponse`. Its `varbinds` field keeps
every decoded binding in received order. By default, bounded response-shape
problems are returned in `anomalies` rather than discarding data. Applications
that require rejection can configure
`.response_shape_policy(ResponseShapePolicy::Strict)`; the resulting
`Error::ResponseShape` retains the same bindings and diagnostics. Count
anomalies do not imply a positional request/response mapping.

The target accepts a `(host, port)` tuple, a combined string, or a `SocketAddr`:

```rust
// (host, port) tuple - no bracket formatting needed for IPv6
let client = Client::builder(("fe80::1", 161), Auth::v2c("public"))
    .connect().await?;

// Combined string (port defaults to 161 if omitted)
let client = Client::builder("192.168.1.1:161", Auth::v2c("public"))
    .connect().await?;

// SocketAddr - useful when the address is already resolved
let addr: SocketAddr = "192.168.1.1:161".parse().unwrap();
let client = Client::builder(addr, Auth::v2c("public"))
    .connect().await?;
```

### SNMPv3 with Authentication and Privacy

```rust
use async_snmp::{Auth, Client, oid, v3::{AuthProtocol, PrivProtocol}};

#[tokio::main]
async fn main() -> Result<(), Box<async_snmp::Error>> {
    let client = Client::builder(("192.168.1.1", 161),
        Auth::usm("admin").auth_priv(
            AuthProtocol::Sha256,
            "authpass123",
            PrivProtocol::Aes128,
            "privpass123",
        ))
        .response_shape_policy(async_snmp::ResponseShapePolicy::Strict)
        .connect()
        .await?;

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await?;
    println!("sysDescr: {:?}", result.varbinds[0].value);

    Ok(())
}
```

### Walking a Subtree

```rust
use async_snmp::{Auth, Client, oid};

#[tokio::main]
async fn main() -> Result<(), Box<async_snmp::Error>> {
    let client = Client::builder(("192.168.1.1", 161), Auth::v2c("public"))
        .connect()
        .await?;

    // Walk the system subtree
    let mut walk = client.walk(oid!(1, 3, 6, 1, 2, 1, 1))?;
    while let Some(result) = walk.next().await {
        let vb = result?;
        println!("{}: {:?}", vb.oid, vb.value);
    }

    Ok(())
}
```

### Shared Transport

For monitoring systems polling many targets, share a single UDP socket across all clients:

```rust
use async_snmp::{Auth, Client, UdpTransport, oid};

#[tokio::main]
async fn main() -> Result<(), Box<async_snmp::Error>> {
    // Single socket shared across all clients
    let shared = UdpTransport::bind("0.0.0.0:0").await?;

    let targets = vec![("192.168.1.1", 161), ("192.168.1.2", 161), ("192.168.1.3", 161)];

    let mut clients = Vec::new();
    for t in &targets {
        let client = Client::builder(*t, Auth::v2c("public"))
            .response_shape_policy(async_snmp::ResponseShapePolicy::Strict)
            .build_with(&shared)
            .await?;
        clients.push(client);
    }

    // Poll all targets concurrently - sharing one UDP socket
    let sys_uptime = oid!(1, 3, 6, 1, 2, 1, 1, 3, 0);
    let results = futures::future::join_all(
        clients.iter().map(|c| c.get(&sys_uptime))
    ).await;

    for (client, result) in clients.iter().zip(results) {
        match result {
            Ok(response) => println!("{}: {:?}", client.peer_addr(), response.varbinds[0].value),
            Err(e) => eprintln!("{}: {}", client.peer_addr(), e),
        }
    }

    Ok(())
}
```

A shared socket uses one file descriptor and one recv loop for all targets, instead of one per target. Repeated polls to the same target reuse the same source port, which avoids creating new firewall/NAT sessions each time.

| Approach | When to use |
|----------|-------------|
| Shared socket (`build_with()`) | Multiple targets from one process. One FD, one recv loop. V1/v2c responses are correlated by request ID, version, and community; v3 uses msgID plus authenticated client checks. |
| Multiple shared sockets | High target counts (100k+), sharded by subnet or target group |
| Per-client socket (`.connect()`) | Default for simple use. Each client gets its own socket and OS buffer. |

UDP source checking is permissive by default for multihomed agents and proxy
paths, while v1/v2c community matching remains exact. Proxies that rewrite the
community can opt into `CommunityResponsePolicy::AllowMismatchFromTarget`.
`AllowMismatchFromAnySource` also accepts an off-target rewritten response and
therefore weakens spoof resistance. `strict_source(true)` is independent and
always rejects off-target responses. Rejected packets increment the transport
`unmatched` counter; accepted source or community anomalies emit warnings.

### Using from Synchronous Code

async-snmp doesn't require your whole application to be async. For CLI tools, scripts, or sync codebases, use a lightweight single-threaded runtime:

```rust
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<async_snmp::Error>> {
    let client = Client::builder(("192.168.1.1", 161), Auth::v2c("public"))
        .response_shape_policy(async_snmp::ResponseShapePolicy::Strict)
        .connect().await?;
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await?;
    println!("{:?}", result.varbinds[0].value);
    Ok(())
}
```

Or wrap async-snmp for use in a fully synchronous call chain with `block_on()`:

```rust
fn snmp_get(
    target: (&str, u16),
    community: &str,
) -> Result<async_snmp::FixedCardinalityResponse, Box<async_snmp::Error>> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime");

    rt.block_on(async {
        let client = Client::builder(target, Auth::v2c(community))
            .response_shape_policy(async_snmp::ResponseShapePolicy::Strict)
            .connect().await?;
        client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await
    })
}
```

See [examples/lightweight_runtime.rs](examples/lightweight_runtime.rs) and [examples/sync_wrapper.rs](examples/sync_wrapper.rs) for complete examples, including a persistent wrapper struct that reuses the runtime and client across calls.

### Sending Traps and Informs

Traps and informs can be sent from an agent (recommended for devices that also handle requests) or directly from a client (for standalone tools like `snmptrap`):

```rust
use async_snmp::agent::{Agent, SinkStatus};
use async_snmp::{Auth, oid};

#[tokio::main]
async fn main() -> Result<(), Box<async_snmp::Error>> {
    let agent = Agent::builder()
        .bind("0.0.0.0:161")
        .community(b"public")
        .trap_sink("192.168.1.100:162", Auth::v2c("public"))
        .build()
        .await?;

    // Trap success means encoding and the local socket write succeeded; traps
    // do not confirm remote receipt.
    let cold_start = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1);
    let trap_outcome = agent.send_trap(&cold_start, 0, vec![]).await;

    // Inform success means the sink acknowledged the request.
    let inform_outcome = agent.send_inform(&cold_start, 0, vec![]).await;

    for sink in trap_outcome.sinks().iter().chain(inform_outcome.sinks()) {
        match &sink.status {
            SinkStatus::Succeeded => println!("{} succeeded", sink.dest),
            SinkStatus::Failed(error) => eprintln!("{} failed: {error}", sink.dest),
            SinkStatus::Skipped(reason) => eprintln!("{} skipped: {reason}", sink.dest),
        }
    }

    Ok(())
}
```

When outcomes are intentionally not needed, use the explicitly lossy
`send_trap_best_effort` and `send_inform_best_effort` helpers; they warn for
failed or skipped sinks and discard the aggregate outcome.

Client-based sending is useful for one-shot notifications without running an agent. See [examples/notification_sender.rs](examples/notification_sender.rs) for both approaches with V2c and V3 examples.

### Tracing

The library uses the `tracing` crate for structured logging. Filter by target:

```bash
# All library logs at debug level
RUST_LOG=async_snmp=debug cargo run

# Trace client operations only
RUST_LOG=async_snmp::client=trace cargo run

# Debug transport layer
RUST_LOG=async_snmp::transport=debug cargo run
```

Available targets:
- **Core**: `async_snmp::client`, `async_snmp::agent`, `async_snmp::notification`
- **Protocol**: `async_snmp::ber`, `async_snmp::pdu`, `async_snmp::oid`, `async_snmp::value`
- **SNMPv3**: `async_snmp::v3`, `async_snmp::usm`, `async_snmp::crypto`, `async_snmp::engine`
- **Transport**: `async_snmp::transport`, `async_snmp::transport::tcp`, `async_snmp::transport::udp`
- **Operations**: `async_snmp::walk`, `async_snmp::error`

## Documentation

Full API documentation is available on [docs.rs](https://docs.rs/async-snmp).

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `agent` | Yes | SNMP agent support (includes `quinn-udp`) |
| `v3` | Yes | SNMPv3 protocol and USM surfaces (implied by either crypto backend) |
| `crypto-rustcrypto` | Yes | RustCrypto-based crypto backend (all auth/priv protocols) |
| `crypto-fips` | No | FIPS 140-3 crypto via aws-lc-rs (rejects MD5, DES, 3DES) |
| `rt-multi-thread` | No | Multi-threaded tokio runtime |
| `cli` | No | CLI utilities (`asnmp-get`, `asnmp-walk`, `asnmp-set`) |
| `mib` | No | MIB integration via [mib-rs](https://github.com/lukeod/mib-rs) (OID name resolution, value formatting) |

The backend features can be enabled together. To use only the FIPS backend:

```bash
cargo add async-snmp --no-default-features --features agent,crypto-fips
```

When both are compiled, select FIPS explicitly on the shared USM configuration
with `.with_crypto_backend(CryptoBackend::AwsLcFips)`. Enabling the Cargo feature
alone is not a runtime FIPS-compliance selection.

## Minimum Supported Rust Version

This crate requires Rust 1.88 or later. The MSRV may be increased in minor version releases.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
