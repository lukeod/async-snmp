# async-snmp

[![CI](https://github.com/lukeod/async-snmp/actions/workflows/ci.yml/badge.svg)](https://github.com/lukeod/async-snmp/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/async-snmp.svg)](https://crates.io/crates/async-snmp)
[![Documentation](https://docs.rs/async-snmp/badge.svg)](https://docs.rs/async-snmp)
[![MSRV](https://img.shields.io/badge/MSRV-1.88-blue.svg)](https://blog.rust-lang.org/)
[![License](https://img.shields.io/crates/l/async-snmp.svg)](#license)

Modern, async-first SNMP client library for Rust.

## Note

This library is not currently stable. While pre v1.0, breaking changes are likely to occur frequently, no attempt will be made to maintain backward compatibility pre-1.0.

MIB parsing is handled by [mib-rs](https://github.com/lukeod/mib-rs). Enable the `mib` feature flag for integrated OID name resolution, symbolic formatting, and type-aware value rendering.

## Features

- **Full protocol support**: SNMPv1, v2c, and v3 (USM)
- **Async-first**: Built on Tokio for high-performance async I/O
- **All operations**: GET, GETNEXT, GETBULK, SET, WALK, BULKWALK
- **Trap and inform sending**: Agent-based (multi-sink) and client-based notification sending with V1/V2c/V3 support
- **SNMP agent**: Async handler framework with two-phase SET commit, VACM access control, and built-in MIB handlers for engine/USM/MPD statistics
- **SNMPv3 security**: MD5/SHA-1/SHA-2 authentication, DES/3DES/AES-128/192/256 privacy, with pluggable crypto backends including a FIPS 140-3 option
- **Automatic tooBig recovery**: GET/GETNEXT batches are automatically bisected when an agent returns a tooBig error
- **Multiple transports**: UDP, TCP, and shared UDP for scalable polling
- **Zero-copy decoding**: Minimal allocations using `bytes` crate
- **Type-safe**: Compile-time OID validation with `oid!` macro

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

### SNMPv3 Security

**Authentication:** MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512

**Privacy:** DES, 3DES, AES-128, AES-192, AES-256

**Crypto backends:** Pluggable via the `CryptoProvider` trait. Two built-in providers:
- `crypto-rustcrypto` (default) - RustCrypto crates, supports all protocols
- `crypto-fips` - aws-lc-rs for FIPS 140-3 compliance (rejects MD5, DES, 3DES)

## Installation

```bash
cargo add async-snmp
```

## Quick Start

### SNMPv2c

```rust
use async_snmp::{Auth, Client, oid};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), async_snmp::Error> {
    let client = Client::builder(("192.168.1.1", 161), Auth::v2c("public"))
        .timeout(Duration::from_secs(5))
        .connect()
        .await?;

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await?;
    println!("sysDescr: {:?}", result.value);

    Ok(())
}
```

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
async fn main() -> Result<(), async_snmp::Error> {
    let client = Client::builder(("192.168.1.1", 161),
        Auth::usm("admin")
            .auth(AuthProtocol::Sha256, "authpass123")
            .privacy(PrivProtocol::Aes128, "privpass123"))
        .connect()
        .await?;

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await?;
    println!("sysDescr: {:?}", result.value);

    Ok(())
}
```

### Walking a Subtree

```rust
use async_snmp::{Auth, Client, oid};
use futures::StreamExt;

#[tokio::main]
async fn main() -> Result<(), async_snmp::Error> {
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

### Scalable Polling (Shared Transport)

For monitoring systems polling thousands of targets, share a single UDP socket across all clients. This provides significant resource efficiency without sacrificing throughput:

```rust
use async_snmp::{Auth, Client, UdpTransport, oid};

#[tokio::main]
async fn main() -> Result<(), async_snmp::Error> {
    // Single socket shared across all clients
    let shared = UdpTransport::bind("0.0.0.0:0").await?;

    let targets = vec![("192.168.1.1", 161), ("192.168.1.2", 161), ("192.168.1.3", 161)];

    let mut clients = Vec::new();
    for t in &targets {
        let client = Client::builder(*t, Auth::v2c("public"))
            .build_with(&shared)
            .await?;
        clients.push(client);
    }

    // Poll all targets concurrently - sharing one UDP socket
    let results = futures::future::join_all(
        clients.iter().map(|c| c.get(&oid!(1, 3, 6, 1, 2, 1, 1, 3, 0)))
    ).await;

    for (client, result) in clients.iter().zip(results) {
        match result {
            Ok(vb) => println!("{}: {:?}", client.peer_addr(), vb.value),
            Err(e) => eprintln!("{}: {}", client.peer_addr(), e),
        }
    }

    Ok(())
}
```

**Benefits of shared transport:**
- **1 file descriptor** for all targets (vs 1 per target with separate sockets)
- **Firewall session reuse** between polls to the same target
- **Lower memory** from shared socket buffers
- **No per-poll socket creation** overhead

**Scaling guidance:**

| Approach | When to use |
|----------|-------------|
| Single shared socket | Recommended for most use cases |
| Multiple shared sockets | Extreme scale (~100,000s+ targets), shard by target |
| Per-client socket (`.connect()`) | When scrape isolation is required (has FD and syscall overhead) |

### Using from Synchronous Code

async-snmp doesn't require your whole application to be async. For CLI tools, scripts, or sync codebases, use a lightweight single-threaded runtime:

```rust
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), async_snmp::Error> {
    let client = Client::builder(("192.168.1.1", 161), Auth::v2c("public"))
        .connect().await?;
    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await?;
    println!("{:?}", result.value);
    Ok(())
}
```

Or wrap async-snmp for use in a fully synchronous call chain with `block_on()`:

```rust
fn snmp_get(target: (&str, u16), community: &str) -> Result<VarBind, async_snmp::Error> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime");

    rt.block_on(async {
        let client = Client::builder(target, Auth::v2c(community))
            .connect().await?;
        client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await
    })
}
```

See [examples/lightweight_runtime.rs](examples/lightweight_runtime.rs) and [examples/sync_wrapper.rs](examples/sync_wrapper.rs) for complete examples, including a persistent wrapper struct that reuses the runtime and client across calls.

### Sending Traps and Informs

Traps and informs can be sent from an agent (recommended for devices that also handle requests) or directly from a client (for standalone tools like `snmptrap`):

```rust
use async_snmp::agent::Agent;
use async_snmp::{Auth, oid};

#[tokio::main]
async fn main() -> Result<(), async_snmp::Error> {
    let agent = Agent::builder()
        .bind("0.0.0.0:161")
        .community(b"public")
        .engine_id(b"my-engine".to_vec())
        .trap_sink("192.168.1.100:162", Auth::v2c("public"))
        .build()
        .await?;

    // Send a coldStart trap to all configured sinks
    let cold_start = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1);
    agent.send_trap(&cold_start, 0, vec![]).await?;

    // Send an inform (waits for acknowledgement)
    agent.send_inform(&cold_start, 0, vec![]).await?;

    Ok(())
}
```

Client-based sending is useful for one-shot notifications without running an agent. See [examples/notification_sender.rs](examples/notification_sender.rs) for both approaches with V1, V2c, and V3 examples.

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
| `crypto-rustcrypto` | Yes | RustCrypto-based crypto backend (all auth/priv protocols) |
| `crypto-fips` | No | FIPS 140-3 crypto via aws-lc-rs (rejects MD5, DES, 3DES) |
| `rt-multi-thread` | No | Multi-threaded tokio runtime |
| `cli` | No | CLI utilities (`asnmp-get`, `asnmp-walk`, `asnmp-set`) |
| `mib` | No | MIB integration via [mib-rs](https://github.com/lukeod/mib-rs) (OID name resolution, value formatting) |

`crypto-rustcrypto` and `crypto-fips` are mutually exclusive. Exactly one must be enabled. To use the FIPS backend:

```bash
cargo add async-snmp --no-default-features --features agent,crypto-fips
```

## Minimum Supported Rust Version

This crate requires Rust 1.88 or later. The MSRV may be increased in minor version releases.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
