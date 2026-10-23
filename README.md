# async-snmp

[![CI](https://github.com/lukeod/async-snmp/actions/workflows/ci.yml/badge.svg)](https://github.com/lukeod/async-snmp/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/async-snmp.svg)](https://crates.io/crates/async-snmp)
[![Documentation](https://docs.rs/async-snmp/badge.svg)](https://docs.rs/async-snmp)
[![MSRV](https://img.shields.io/badge/MSRV-1.88-blue.svg)](https://blog.rust-lang.org/)
[![License](https://img.shields.io/crates/l/async-snmp.svg)](#license)

An asynchronous SNMP library for Rust that uses Tokio.

## Status

This crate is pre-1.0, so its API can change between releases. This README
describes the `main` branch, which can differ from published crate versions.
For version-specific API documentation, see
[async-snmp on docs.rs](https://docs.rs/async-snmp/latest/async_snmp/).

## Supported operations

- SNMPv1, SNMPv2c, and SNMPv3 USM clients
- GET, GETNEXT, GETBULK, SET, WALK, and BULKWALK
- Trap and inform sending and receiving
- UDP, shared UDP, and TCP transports
- An optional SNMP agent with UDP/TCP listener sets, explicit runners, asynchronous
  handlers, two-phase SET processing, and View-based Access Control Model (VACM) support
- Optional MIB parsing, OID resolution, and value formatting through
  [mib-rs](https://github.com/lukeod/mib-rs)
- Automatic `tooBig` recovery for GET and GETNEXT batches

GETBULK, BULKWALK, and informs require SNMPv2c or SNMPv3. SNMPv3 supports
MD5, SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512 authentication. It supports
DES, 3DES, and AES-128/192/256 privacy. The available algorithms depend on the
enabled cryptographic backend.

## Installation

Install the published release:

```bash
cargo add async-snmp
cargo add tokio --features macros,rt
```

To use the API documented in this README, install the main branch:

```bash
cargo add async-snmp --git https://github.com/lukeod/async-snmp
cargo add tokio --features macros,rt
```

## Example

```rust
use async_snmp::{Auth, Client, oid};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::builder(("192.168.1.1", 161), Auth::v2c("public"))
        .connect()
        .await?;

    let response = client
        .get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))
        .await?;

    for varbind in response.varbinds {
        println!("{}: {:?}", varbind.oid, varbind.value);
    }

    Ok(())
}
```

`get`, `get_next`, and `set` preserve received bindings in `varbinds` and
report response-shape issues in `anomalies`. Use `single()` when one
unambiguous binding is required.

The repository contains these examples:

- [basic client operations](examples/basic_client.rs)
- [walking a subtree](examples/walk_subtree.rs)
- [SNMPv3](examples/snmpv3_client.rs)
- [shared UDP transport](examples/shared_transport.rs)
- [TCP](examples/tcp_client.rs)
- [runtime transport selection](examples/runtime_transport.rs)
- [a lightweight single-threaded runtime](examples/lightweight_runtime.rs)
- [value extraction](examples/value_extraction.rs)
- [trap and inform sending](examples/notification_sender.rs) and
  [receiving](examples/notification_receiver.rs)
- [an agent with writable objects](examples/agent_with_set.rs)
- [calling the library from synchronous code](examples/sync_wrapper.rs)
- [MIB-backed queries](examples/mib_get.rs),
  [walks](examples/mib_walk.rs), and
  [table index decoding](examples/mib_table.rs)

## Transport and service lifecycle

Built-in services use `prepare().await?` followed by `into_parts()` to obtain
public handles and an owned runner. Preparation binds/connects and validates
configuration without starting tasks. Drive `runner.run()` or use the explicit
`spawn()`/`spawn_on()` conveniences; retain the running owner to observe shutdown
and failures. Supplied Tokio sockets keep their original runtime registration.
Dropping the last public handle requests shutdown; controls also retain lifetime.
Dropping an unpolled runner closes its endpoints. Sends and exchanges use their
ordinary deadlines before startup and fail after termination.

| API migration | Current API |
| --- | --- |
| Custom client transport contract | `RequestTransport` |
| Shared UDP transport | `UdpEndpoint`, target-specific `UdpHandle` |
| Agent/receiver startup | `prepare` plus runner, or explicit `spawn` |
| Single service local address | Identified `bound_addresses()` |
| Notification consumer | Non-Clone receiver; `recv(&mut self)` and separate control |
| Agent notification destinations | `notification_sink(id, NotificationTarget, auth)` |
| Client response history | `ResponseMetadata::received_messages` |
| Aggregate decode anomalies | `ResponseMetadata::decode_anomalies()` iterator |

Notification targets explicitly select `shared_udp(listener_index, destination)`,
`udp(endpoint_builder, destination)`, `tcp(session_builder)`, or `peer(existing)`.
The shared index follows configured listener order; index zero selects the default
UDP bind. Shared traps and Informs use the same source endpoint as commands.
Separate UDP/TCP resources prepare with the Agent and run under its supervisor.
TCP targets connect during preparation; selected existing sessions never reconnect,
replay, or fall back to UDP. Use `Agent::notification_peer` for accepted sessions
obtained after startup, enabling client exchanges on the selected service first.
Sink outcomes include endpoint/session identity, transport and limits without credentials.

See [shared UDP roles](examples/shared_udp_roles.rs) and
[shared TCP roles](examples/shared_tcp_roles.rs) for command handling alongside
Agent notification sends. SNMPv3 traps use the originating Agent's persisted engine;
Informs discover the receiver's authoritative engine. Runtime v3 originators require
prepared authoritative state, an AES role for AES privacy, or durable DES sender
state for DES/3DES. Closing a notification consumer disables that role while other
roles continue; root shutdown terminates all owned endpoints and pending exchanges.

Response histories contain each accepted message's PDU kind, decode anomalies and
`ReceivedMessageInfo`, including discovery/correction Reports and error Responses.
`received_len()` counts the original UDP payload or TCP BER frame before USM
decryption, including ciphertext, padding and accepted UDP suffixes. Batched
operations retain individual records. Shared discovery retains the same
`reception_id()` in every operation using it; histories describe provenance rather
than unique endpoint traffic. Rejected candidates do not create history records.

## Command-line tools

The `cli` feature provides the `asnmp-get`, `asnmp-walk`, and `asnmp-set`
commands:

```bash
cargo install --locked --git https://github.com/lukeod/async-snmp --features cli
asnmp-get -v 2c -c public 192.0.2.10 sysDescr.0
asnmp-walk -v 2c -c public 192.0.2.10 1.3.6.1.2.1.1
asnmp-set -v 2c -c private 192.0.2.10 sysLocation.0 s rack-7
```

Run each command with `--help` for its options.

## Feature flags

| Feature | Default | Description |
|---------|:-------:|-------------|
| `agent` | No | SNMP agent support |
| `crypto-rustcrypto` | Yes | RustCrypto authentication and privacy backend |
| `crypto-fips` | No | AWS-LC FIPS backend; excludes MD5, DES, and 3DES |
| `rt-multi-thread` | No | Tokio multithreaded runtime support |
| `cli` | No | `asnmp-get`, `asnmp-walk`, and `asnmp-set` commands |
| `mib` | No | MIB parsing, OID resolution, and value formatting through mib-rs |

SNMPv1, SNMPv2c, and SNMPv3 `noAuthNoPriv` work without a cryptographic
backend. Cargo features are additive. When you enable both backends,
RustCrypto is the default unless you select AWS-LC FIPS in the USM
configuration.

## Documentation

[Docs.rs](https://docs.rs/async-snmp/latest/async_snmp/) hosts API
documentation for published versions. To build and open documentation for the
`main` branch, run:

```bash
cargo doc --all-features --open
```

## Minimum supported Rust version

Rust 1.88 or later is required.

## License

You can use async-snmp under either the
[Apache License 2.0](LICENSE-APACHE) or the [MIT License](LICENSE-MIT).

## Contributing

See the [contribution guide](CONTRIBUTING.md).

Transport observation uses a bounded metadata channel:

```rust,no_run
# async fn example() -> async_snmp::Result<()> {
use async_snmp::{TransportObserver, UdpEndpoint, DEFAULT_OBSERVATION_CAPACITY};
let (observer, mut events) = TransportObserver::channel(DEFAULT_OBSERVATION_CAPACITY)?;
let running = UdpEndpoint::builder().observer(observer.clone()).spawn().await?;
// Consume events in application-owned work, or poll them with try_recv().
while let Ok(event) = events.try_recv() {
    println!("{event:?}");
}
println!("{:?}", observer.stats());
running.shutdown().await?;
# Ok(()) }
```

Configure the same observer on selected UDP/TCP builders or a `TcpListenerSource`
to aggregate their counters. Agent and notification listeners accept those sources.
`Received` events retain the same reception identity as response histories and
notification metadata. Shared discovery can appear in several operation histories,
while observation records the physical input once. `Sent` means a completed local
socket write; it does not confirm peer receipt. Events contain no packets or credentials.

Complete-message counters include malformed UDP input and complete TCP frames before
security processing. Socket-byte counters also include partial TCP I/O and UDP input
rejected after ancillary-metadata validation. They exclude network headers, TCP
retransmissions and kernel drops. Processing dispositions are separate stage events,
not complete terminal outcomes; candidate validation can precede a later operation
failure. Full or dropped event consumers do not slow protocol work: counters continue
and `dropped_events` increases. See [the observation example](examples/transport_observation.rs).
