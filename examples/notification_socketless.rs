//! One caller-owned socket, two explicitly selected logical USM contexts.
//! Run `cargo run --example notification_socketless -- ./receiver.state ./received.log`.
//! Receives one accepted notification on 127.0.0.1:1162 and answers engine discovery.
//! Peer 127.0.0.2 selects tenant A and 127.0.0.3 selects tenant B. Each selected
//! processor handles notifications, discovery, and stale Inform engine IDs in one
//! call. Other peers use the shared local engine for discovery.
//! Both tenants use username "collector", SHA-256 and distinct demo passwords.
//! Engine ID/boots are atomically persisted and locked; retain the state file
//! between runs. The append-and-sync log precedes deferred Inform encoding.

#[path = "support/engine.rs"]
mod engine;
#[path = "support/notification_log.rs"]
mod notification_log;

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

use async_snmp::{
    AuthProtocol, DecodeConfig, EncodedInformResponse, EndpointId, NotificationAdmissionDecision,
    NotificationProcessResult, NotificationProcessor, ProcessingInput, ProcessingLimits,
    ReceivedMessageInfo, ReceivedPacket, SecurityLevel, UsmSecurityContext, UsmUser, UsmUserEntry,
};
use bytes::Bytes;
use tokio::net::UdpSocket;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    let engine = engine::load(Path::new(
        args.get(1).map_or("receiver.state", String::as_str),
    ))?;
    let log = PathBuf::from(args.get(2).map_or("received.log", String::as_str));
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
