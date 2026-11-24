//! One caller-owned socket, two explicitly selected logical USM contexts.
//!
//! Run `cargo run --example notification_socketless -- ./receiver.state ./received.log`.
//! Once the receiver is listening, send an Inform from a second shell using
//! Net-SNMP. This command uses the loopback source and demo password for tenant A.
//!
//! ```sh
//! (
//!     set -e
//!     snmp_config=$(mktemp -d)
//!     trap 'rm -rf -- "$snmp_config"' EXIT
//!     printf 'clientaddr 127.0.0.2\n' > "$snmp_config/snmp.conf"
//!     SNMPCONFPATH="$snmp_config" MIBS='' snmpinform -v3 -l authNoPriv \
//!         -u collector -a SHA-256 -A tenant-a-password \
//!         127.0.0.1:1162 '' .1.3.6.1.6.3.1.1.5.1
//! )
//! ```
//!
//! The receiver exits after one accepted notification. To try tenant B, restart
//! it with the same state and log paths, then use `127.0.0.3` in `clientaddr`
//! and `tenant-b-password` with `-A`. Both loopback source addresses must be
//! available on the host.
//!
//! Each tenant's processor handles notifications, discovery, and stale Inform
//! engine IDs. Other peers use the shared local engine for discovery. The
//! receiver atomically persists the engine ID and boots counter under a lock.
//! It appends and syncs the log before encoding the deferred Inform response.
//! The platform and filesystem must support opening and syncing the parent
//! directories of the engine state and log files.

#[path = "support/engine.rs"]
mod engine;
#[path = "support/notification_log.rs"]
mod notification_log;

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use async_snmp::{
    AuthProtocol, DecodeConfig, EncodedInformResponse, EndpointId, NotificationAdmissionDecision,
    NotificationProcessResult, NotificationProcessor, ProcessingInput, ProcessingLimits,
    ReceivedMessageInfo, ReceivedPacket, SecurityLevel, UsmSecurityContext, UsmUser, UsmUserEntry,
};
use bytes::Bytes;
use tokio::net::UdpSocket;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let state = PathBuf::from(args.next().unwrap_or_else(|| "receiver.state".into()));
    let log = PathBuf::from(args.next().unwrap_or_else(|| "received.log".into()));
    let engine = engine::load(&state)?;
    let make_context = |password: &[u8]| -> Result<UsmSecurityContext, Box<dyn std::error::Error>> {
        let user = UsmUser::new("collector").auth(AuthProtocol::Sha256, password)?;
        Ok(UsmSecurityContext::new([
            // Exact local binding for Informs; explicit default for remote traps.
            UsmUserEntry::for_engine(engine.engine_id().to_vec(), user.clone())?,
            UsmUserEntry::new(user),
        ])?)
    };
    let make_processor = |context| {
        NotificationProcessor::builder()
            .local_engine(engine.clone())
            .security_context(context)
            .admission_policy(|notification| {
                if notification.security_level >= Some(SecurityLevel::AuthNoPriv) {
                    NotificationAdmissionDecision::Admit
                } else {
                    NotificationAdmissionDecision::Reject
                }
            })
            .build()
    };
    let tenant_a = make_processor(make_context(b"tenant-a-password")?)?;
    let tenant_b = make_processor(make_context(b"tenant-b-password")?)?;
    // Construction above starts no readers or tasks. The application owns I/O.
    let socket = UdpSocket::bind("127.0.0.1:1162").await?;
    let local = socket.local_addr()?;
    let endpoint = EndpointId::new();
    let limits = ProcessingLimits::UDP;
    let _capacity = engine.register_receive_capacity(limits.receive().advertised());
    let mut buffer = vec![0; limits.receive().accepted()];
    println!(
        "Engine ID: {:02x?}; listening on {local}",
        engine.engine_id()
    );
    loop {
        let (len, peer) = socket.recv_from(&mut buffer).await?;
        // Original metadata is provenance, not authenticated identity. recv_from
        // provides no destination ancillary data; this socket binds a concrete IP.
        let info = ReceivedMessageInfo::udp(
            endpoint,
            local,
            peer,
            None,
            tokio::time::Instant::now(),
            len,
        );
        let input = ProcessingInput::new(
            ReceivedPacket::new(Bytes::copy_from_slice(&buffer[..len]), info),
            limits,
        )?;
        // Use the source address to select one context. Admission requires USM authentication.
        let selected = match peer.ip() {
            IpAddr::V4(ip) if ip == Ipv4Addr::new(127, 0, 0, 2) => Some(&tenant_a),
            IpAddr::V4(ip) if ip == Ipv4Addr::new(127, 0, 0, 3) => Some(&tenant_b),
            _ => None,
        };
        let mut accepted_one = false;
        let response = if let Some(processor) = selected {
            match processor.process(input) {
                Ok(NotificationProcessResult::Accepted(accepted)) => {
                    accepted_one = true;
                    // Dropping inform_response after persistence failure sends nothing.
                    notification_log::append(log.clone(), format!("{:?}", accepted.notification))
                        .await?;
                    accepted
                        .inform_response
                        .map(|response| response.encode())
                        .transpose()?
                        .and_then(EncodedInformResponse::into_bytes)
                }
                Ok(NotificationProcessResult::InformTooBig { response }) => response,
                Ok(NotificationProcessResult::UsmFailed { failure, report }) => {
                    eprintln!("USM failure: {failure:?}");
                    report // Reports are protocol results, independent of persistence.
                }
                Ok(_) => None,
                Err(error) => {
                    eprintln!("Invalid input: {error}");
                    None
                }
            }
        } else {
            // With no selected tenant, this endpoint advertises its shared engine.
            match engine.report_unknown_engine(input, DecodeConfig::DEFAULT) {
                Ok(report) => report,
                Err(error) => {
                    eprintln!("Invalid discovery input: {error}");
                    None
                }
            }
        };
        if let Some(response) = response {
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                socket.send_to(&response, peer),
            )
            .await??;
        }
        if accepted_one {
            break;
        }
    }
    Ok(())
}
