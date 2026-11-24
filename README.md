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
- [caller-owned notification I/O and USM context selection](examples/notification_socketless.rs)
- [persisting notifications before Inform acknowledgement](examples/notification_durable.rs)
- [caller-owned command I/O and bounded shutdown](examples/command_socketless.rs)
- [calling the library from synchronous code](examples/sync_wrapper.rs)
- [MIB-backed queries](examples/mib_get.rs),
  [walks](examples/mib_walk.rs), and
  [table index decoding](examples/mib_table.rs)

## Choose the application and I/O layer

| Use case | API | Execution ownership |
| --- | --- | --- |
| Queries and outgoing notifications | `Client` with a built-in or custom `RequestTransport` | Transport implementation owns I/O; client validates exchange results |
| Managed command listeners | `Agent` (`agent` feature) | Owned runner supervises listeners, requests and attached roles |
| Managed notification listeners | `NotificationReceiver` | Owned runner supervises reception, delivery and acknowledgements |
| Caller-owned notification I/O | `NotificationProcessor` | Synchronous complete-message processing; caller owns I/O, concurrency and retained-response bounds |
| Caller-owned command I/O | `CommandProcessor` (`agent` feature) | Caller owns I/O; processor retains bounded Tokio request tasks and SET cleanup |

Processor `build()` creates no sockets, readers or background tasks and requires
no Tokio runtime. `NotificationProcessor::process` is synchronous and runtime-free;
`CommandProcessor::process` requires a running Tokio runtime for its owned tasks.
Supply original complete-message bytes and `ReceivedMessageInfo` through
`ProcessingInput`, with explicit receive/send `ProcessingLimits`. Metadata records
provenance; peer addresses, context names and unauthenticated wire fields do not
establish identity. Custom UDP/TCP endpoints also retain a
`LocalEngine::register_receive_capacity` registration for their serving lifetime.
The engine MIB reports the minimum registered capacity; per-message limits remain
specific to the receiving endpoint.

`LocalEngine` shares persisted authoritative identity/boots/time, counters,
persistence health and privacy sender state across roles. Prepare persisted
engine state once and pass clones to builders. `UsmSecurityContext` independently
shares inbound credentials and bounded remote-engine timeliness; separate contexts
isolate those tables even on one socket and one local engine. An exact
`UsmUserEntry::for_engine` engine-ID/username binding precedes an explicit
`UsmUserEntry::new` default. A failed exact entry never retries a default.
`replace_users` validates the complete replacement before atomic publication;
invalid replacements leave the current table intact, and remote timeliness is
retained. Each input keeps one selected credential snapshot, including its
deferred Inform response. Managed attached roles share their configured context.
Caller-owned I/O may select a logical processor explicitly, using untrusted routing
hints before security processing. Pass each message once to the selected
`NotificationProcessor::process`, including SNMPv3 discovery probes. If the
endpoint selects no listener, it can answer discovery using its designated
`LocalEngine::report_unknown_engine(input, decode_config)`.

Receivers use the SNMPv3 PDU type to distinguish an Inform naming a stale
receiver engine ID from a trap using the sender's engine ID. When the type is
unavailable, `reportableFlag` supplies the fallback. Only a recognized,
authenticated trap advances the remote engine clock. Send any Report from
`NotificationProcessResult::UsmFailed` or the endpoint discovery helper on the
original UDP route or exact TCP session. The originator decides whether to
rediscover after a stale-engine Report. An established async-snmp `Client`
can explicitly call `rediscover_engine()`.

`NotificationProcessor` returns accepted content and an optional owned
`InformResponse`. Encode it after application processing to use the current engine
time and sender state with the original validated credentials. The result is an
`EncodedInformResponse`. If updated SNMPv3 boots or time push the ordinary response
over the limit, encoding returns a fitting empty-varbind `tooBig` reply or counts a
silent drop. Use `into_bytes()` to get the reply if one fit.
Send the reply on the original route and set any deadline for deferred responses.

Use `admission_policy` on either notification builder to restrict validated
notifications by source, identity, security level, context, class, or OID.
Admission runs before Inform sizing, delivery, and any Inform Response. Inspect
the application payload after delivery and use deferred acknowledgement when
processing must finish before the ordinary Response is sent.

For admitted Informs, the processor checks the ordinary Response size before
delivery. An oversized response yields
`NotificationProcessResult::InformTooBig`. Send the empty-varbind `tooBig` reply
when `response` contains bytes. `response: None` indicates a counted silent drop.
[RFC 3416 §4.2.7](https://www.rfc-editor.org/rfc/rfc3416.html#section-4.2.7)

## Transport and service lifecycle

Built-in services use `prepare().await?` followed by `into_parts()` to obtain
public handles and an owned runner. Preparation binds/connects and validates
configuration without starting tasks. Drive `runner.run()` or use the explicit
`spawn()`/`spawn_on()` conveniences; retain the running owner to observe shutdown
and failures. Supplied Tokio sockets keep their original runtime registration.
Dropping the last public handle requests shutdown; controls also retain lifetime.
Dropping an unpolled runner closes its endpoints. Sends and exchanges use their
ordinary deadlines before startup and fail after termination.

`PreparedAgent::into_parts()` returns `(agent, runner, notifications)`, with an
optional notification receiver. Keep the receiver alive to admit notifications.
If you use `spawn()` or `spawn_on()`, call `RunningAgent::take_notifications()`
to receive events.

| API migration | Current API |
| --- | --- |
| Custom client transport contract | `RequestTransport` |
| Shared UDP transport | `UdpEndpoint`, target-specific `UdpHandle` |
| Agent/receiver startup | `prepare` plus runner, or explicit `spawn` |
| Notification `acceptance_policy` | `admission_policy` with `NotificationAdmissionInfo`. Inspect payloads in delivered events and use manual acknowledgement when needed. |
| Single service local address | Identified `bound_addresses()` |
| Notification consumer | Non-Clone receiver; `recv(&mut self)` and separate control |
| Managed `ReceivedNotification::inform_ack` | `NotificationAcknowledgement::{NotRequired, Completed, Pending}` |
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
prepared authoritative state and the applicable shared AES or durable DES sender
state. Closing a notification consumer disables that role while other
roles continue; root shutdown terminates all owned endpoints and pending exchanges.

Managed Inform acknowledgement defaults to `Automatic`: the local attempt
finishes before delivery. `inform_ack` is an enum, replacing the former optional
outcome: traps are `NotRequired`, finished attempts are `Completed(InformAckOutcome)`,
and application-controlled Informs carry `Pending(PendingInformAck)`. A completed
state can also report failure to install manual completion work. Select
`ApplicationControlled`, persist/process the event, then consume the pending token
with `acknowledge().await`. Drop or `reject()` sends nothing. Retransmissions remain
independent events; acknowledgement provides no exactly-once guarantee.

In either mode, the receiver handles oversized Informs before delivery and
attempts to send the `tooBig` alternate when it fits. For a delivered Inform,
`InformAckOutcome::Sent` records successful local transmission of the ordinary
response. If that response grows beyond the limit at completion, `SentTooBig`
records transmission of the alternate and `SuppressedBySize` records a counted
silent drop. `Failed` carries a completion error.

Manual mode defaults to 256 outstanding Informs and a 30-second deadline from
acceptance, including encoding and sending. These bounds survive dequeue. Tokens
hold weak references; expiry frees service-owned request/key memory and permits
even if the application retains a token. First polling `acknowledge()` commits a
supervised attempt that continues under its deadline if its waiter is abandoned.
It uses the original UDP destination/source route or exact TCP session, without
replacement. `receiver.close()` stops admission. Admitted tokens remain usable
until their deadlines while the runner stays active. Graceful shutdown drains
admitted automatic response attempts. Shutdown, consumer drop and runner abort
invalidate pending manual acknowledgements. Pending-slot saturation rejects
new Informs without closing TCP or blocking traps and shared roles. Delivery-queue
overload keeps its configured transport policy.

Command cancellation, deadline or shutdown can return before SET undo/free
finishes. Keep the Tokio runtime driven and close admission with
`CommandControl::request_shutdown()` before a bounded drain. `drain_mutations`
waits for SET and unclassified work; `drain_requests` also waits for retrievals.
A drain timeout reports incomplete work without aborting retained cleanup.
`shutdown(timeout)` combines closing admission and full request drain. Dropping
the last processor/control also closes admission. A drain returns an error if a
classified SET task panics or runtime teardown interrupts it before completion.
The caller sends each encoded command response and sets its send deadline.

Response histories contain each accepted message's PDU kind, decode anomalies and
`ReceivedMessageInfo`, including discovery/correction Reports and error Responses.
`received_len()` counts the original UDP payload or TCP BER frame before USM
decryption, including ciphertext, padding and accepted UDP suffixes. Batched
operations retain individual records. Shared discovery retains the same
`reception_id()` in every operation using it; histories describe provenance rather
than unique endpoint traffic. Rejected candidates do not create history records.

### Transport observation

`TransportObserver::channel` creates a bounded metadata channel. The runnable
example queries `sysDescr.0` over SNMPv2c and prints send and receive events,
processing dispositions, and counters. Run it against an agent that accepts the
`public` community. [Transport observation example](examples/transport_observation.rs)

```bash
cargo run --locked --example transport_observation -- 127.0.0.1:161
```

Configure the same observer on selected UDP/TCP builders or a `TcpListenerSource`
to aggregate their counters. Agent and notification listeners accept those sources.
`Received` events retain the same reception identity as response histories and
notification metadata. Shared discovery can appear in several operation histories,
while observation records the physical input once. `Sent` records a completed local
socket write. Events contain metadata only.

Complete-message counters include malformed UDP input and complete TCP frames before
security processing. Socket-byte counters also include partial TCP I/O and UDP input
rejected after ancillary-metadata validation. They exclude network headers, TCP
retransmissions and kernel drops. Processing dispositions record individual stages,
including candidate validation before an operation's final result. Full or dropped
event consumers increase `dropped_events` while protocol work and counters continue.

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
