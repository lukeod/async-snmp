//! SNMP notification receiver (RFC 3413).
//!
//! [`NotificationReceiver`] receives:
//! - `TrapV1` (SNMP v1 format, different PDU structure)
//! - `TrapV2`/`SNMPv2-Trap` (SNMP v2c/v3 format)
//! - `InformRequest` (confirmed notification, requires response)
//!
//! # Execution and delivery
//!
//! Preparation returns a single consumer and an owned runner. Drive the runner
//! independently to receive notifications even while the consumer is unpolled.
//! Automatic acknowledgement is the default and occurs before delivery:
//!
//! ```rust,no_run
//! use async_snmp::NotificationReceiver;
//! # async fn example() -> async_snmp::Result<()> {
//! let (mut receiver, runner) = NotificationReceiver::builder()
//!     .bind("127.0.0.1:1162").queue_capacity(256).prepare().await?.into_parts();
//! let control = receiver.control();
//! let task = tokio::spawn(runner.run());
//! if let Some(notification) = receiver.recv().await {
//!     println!("{} bytes", notification.receive_info.received_len());
//! }
//! control.request_shutdown();
//! task.await.expect("notification task panicked")?;
//! while receiver.recv().await.is_some() {}
//! # Ok(())
//! # }
//! ```
//!
//! `spawn()` and `spawn_on()` provide an owner retaining both the consumer and
//! task. Their owner requests shutdown on drop. Delivery is bounded (256 events
//! by default), with at most 64 concurrent protocol tasks and bounded
//! UDP input. A full queue drops deliverable Informs before acknowledgement.
//! In application-controlled mode, events carry [`PendingInformAck`]. Persist or
//! process the event, then call its `acknowledge()` method. At most 256 Informs
//! remain outstanding by default, including dequeued events; their default
//! lifetime is 30 seconds. Saturation rejects new Informs without affecting traps
//! or shared roles and does not close TCP; delivery-queue overload retains its
//! transport policy. The deadline starts at acceptance and includes encoding/send.
//! Expiry releases service-owned request/key memory and permits even if the weak
//! token is retained. Drop/reject sends nothing. First polling `acknowledge()`
//! commits a supervised attempt that survives abandoning its waiter, bounded by
//! the original deadline and service shutdown. Replies retain the original UDP
//! destination/source route or exact TCP session; closed routes are not replaced.
//! Protocol Reports are independent of application completion.
//!
//! [`NotificationReceiver::close`] stops admission. Admitted manual tokens
//! remain usable until their deadlines while the runner stays active.
//! Graceful shutdown drains admitted automatic response attempts. Shutdown,
//! consumer drop and runner abort invalidate pending manual acknowledgements.
//! Cancelling `recv()` leaves the event queue intact. Dropping the consumer or
//! aborting the runner can lose volatile events, including acknowledged events.
//! Acknowledgement is not a durability guarantee. Queue EOF does not report the
//! runner's terminal result; join the runner or inspect its control status.
//! Retransmitted Informs are independent events, with no exactly-once promise.
//!
//! # Caller-owned I/O
//!
//! [`NotificationProcessor::builder`] prepares runtime-free protocol state without
//! sockets or tasks. Feed original complete bytes and receive metadata through
//! [`crate::ProcessingInput`] with explicit limits; register custom endpoint
//! capacity on [`crate::LocalEngine`]. Metadata and pre-authentication selectors
//! are untrusted routing hints. Select a logical [`crate::UsmSecurityContext`]
//! once, then apply security; do not retry contexts on failure.
//!
//! [`NotificationProcessResult`] separates accepted notifications, rejection and
//! USM failures with optional Report bytes. Accepted Informs carry an owned
//! [`InformResponse`]; persist/process before `encode()`, then send on the original
//! route. Encoding retains validated keys across credential replacement and
//! samples current engine time/sender state. Caller-owned I/O must bound retained
//! capabilities, deadlines and sends; managed pending-ack bounds do not apply.
//!
//! # SNMPv1 and SNMPv2c
//!
//! Receive v1/v2c notifications. A receiver constructed with `spawn` has no
//! USM user table, so v3 notifications are rejected; see below for v3.
//! V1/v2c community strings are carried in cleartext and provide no message
//! integrity. With no configured community allowlist, the reported community
//! and notification content are unverified and spoofable. An allowlist proves
//! only that the cleartext value matched a configured entry; it does not make
//! the message cryptographically authenticated.
//!
//! ```rust,no_run
//! use async_snmp::notification::{NotificationReceiver, Notification};
//! use std::net::SocketAddr;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<async_snmp::Error>> {
//!     let mut receiver = NotificationReceiver::spawn("0.0.0.0:1162").await?;
//!
//!     loop {
//!         match receiver.recv().await {
//!             Some(received) => {
//!                 println!("Received notification from {}: {:?}", received.receive_info.peer_addr(), received.notification);
//!                 println!("Inform acknowledgement: {:?}", received.inform_ack);
//!             }
//!             None => return receiver.join().await,
//!         }
//!     }
//! }
//! ```
//!
//! # SNMPv3
//!
//! To receive V3 traps and `InformRequests`, configure USM credentials via
//! the builder. Configured mechanisms are capabilities, so a keyed user also
//! supports lower levels including `noAuthNoPriv`. Select an explicit
//! admission policy before preparation. Only `authNoPriv` and `authPriv`
//! authenticate the USM username, scoped context, and notification content;
//! every such field in a `noAuthNoPriv` message is an unverified, spoofable
//! claim.
//!
//! ```rust,no_run
//! use async_snmp::notification::{NotificationAdmissionDecision, NotificationReceiver};
//! use async_snmp::{AuthProtocol, AuthoritativeEngine, PrivProtocol, SecurityLevel};
//! use std::convert::Infallible;
//!
//! # async fn example() -> Result<(), Box<async_snmp::Error>> {
//! # // Replace this no-op with durable storage in an application.
//! let engine = AuthoritativeEngine::install(b"receiver-engine".to_vec(), |_| {
//!     Ok::<(), Infallible>(())
//! })?;
//! let mut receiver = NotificationReceiver::builder()
//!     .bind("0.0.0.0:1162")
//!     .authoritative_engine(engine)
//!     .usm_user("informuser", |u| {
//!         u.auth_priv(
//!             AuthProtocol::Sha1,
//!             b"authpass123",
//!             PrivProtocol::Aes128,
//!             b"privpass123",
//!         )
//!     }).unwrap()
//!     .admission_policy(|notification| {
//!         if notification.security_level >= Some(SecurityLevel::AuthNoPriv) {
//!             NotificationAdmissionDecision::Admit
//!         } else {
//!             NotificationAdmissionDecision::Reject
//!         }
//!     })
//!     .spawn()
//!     .await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Shared endpoint client exchanges
//!
//! Set [`NotificationReceiverBuilder::client_exchanges`] before preparation to
//! enable follow-up polling or Informs through `receiver.udp_endpoint(id)` and
//! its per-target handles. The receiver's existing runner owns all reception;
//! a full event queue does not consume the response-processing allowance.
//! The dispatcher reserves 64 response classifiers and 4 MiB of response input
//! buffers (at most 1 MiB per peer, 1,024 tracked peers) independently of
//! notification `max_processing` (default 64) and its
//! input budget (at most 4 MiB). Delivery retains at most `queue_capacity` decoded
//! events (default 256). Each pending exchange parks at most 16 candidates.
//! UDP admits at most 1,024 exchanges including retry retention; waiting for
//! admission uses the exchange deadline and is cancelled by endpoint shutdown.
//!
//! With the agent feature, `AgentBuilder::notifications` attaches this consumer
//! to all of the agent's configured endpoints and sessions. Configure engine/users/client capability on the
//! agent; attached notification configuration must omit those independent fields.
//! Attached control shutdown closes only notifications; standalone control
//! shutdown stops its endpoint service. Consumer closure never enables itself
//! again through a retained control or client handle.
//!
//! Configure `.listener(ListenerSource::udp(...))` and
//! `.listener(ListenerSource::tcp(...))` for multiple sources, or
//! `.session(TcpTransport::builder().target(peer))` for an explicitly connected
//! session. A supplied `TcpStream` uses the same builder's `from_stream` method.
//! Explicit sources replace the default UDP bind. `bound_addresses()` identifies
//! each endpoint; `tcp_sessions()` snapshots exact live sessions without reconnecting.
//! Both accepted and connected sessions support the configured roles. Starting
//! transactions over a reverse-direction connection requires explicit peer support.
//!
//! TCP defaults to 128 service connections, 64 MiB aggregate transport buffering,
//! 32 MiB per session and 10 MiB frame/send capacity. One frame may be queued for
//! classification per session, in addition to the active classifier and framer.
//! Each budget reserves the largest applicable send capacity for output. Frame,
//! dispatch and parked-candidate input use only the remainder, so input saturation
//! cannot block replies. Writes retain their output permits through completion;
//! UDP response reserves remain separate. Session application concurrency defaults
//! to 16, with service notification processing limited by `max_processing`.
//! Decoded delivery retains at most `queue_capacity` events and is separate from
//! the transport byte budgets. Each event is bounded by its receiving frame limit.
//! Inbound-only TCP sessions pause for capacity for at most five seconds; this
//! local pause excludes header/body progress deadlines. Sessions configured with
//! client exchanges close on application/delivery exhaustion even with no pending
//! exchange. Separate endpoints/sessions continue independently. TCP ordering still
//! permits head-of-line blocking; shared connections do not promise response isolation.
//!
//! # Mixed versions on one port
//!
//! A single receiver on one UDP port handles v1, v2c, and v3 concurrently;
//! each datagram is dispatched by its version field. Community filtering
//! (v1/v2c) and USM users (v3) are independent and can be configured
//! together — configuring one does not disable the other:
//!
//! ```rust,no_run
//! use async_snmp::notification::{NotificationAdmissionDecision, NotificationReceiver};
//! use async_snmp::{AuthProtocol, AuthoritativeEngine, PrivProtocol, SecurityLevel};
//! use std::convert::Infallible;
//!
//! # async fn example() -> Result<(), Box<async_snmp::Error>> {
//! # // Replace this no-op with durable storage in an application.
//! let engine = AuthoritativeEngine::install(b"receiver-engine".to_vec(), |_| {
//!     Ok::<(), Infallible>(())
//! })?;
//! let mut receiver = NotificationReceiver::builder()
//!     .bind("0.0.0.0:1162")
//!     .authoritative_engine(engine)
//!     .communities(["public", "monitor"]) // gates v1/v2c
//!     .usm_user("trapuser", |u| {          // gates v3
//!         u.auth_priv(
//!             AuthProtocol::Sha1,
//!             b"authpass123",
//!             PrivProtocol::Aes128,
//!             b"privpass123",
//!         )
//!     })
//!     .unwrap()
//!     .admission_policy(|notification| match notification.security_level {
//!         None => NotificationAdmissionDecision::Admit, // community allowlist matched
//!         Some(level) if level >= SecurityLevel::AuthNoPriv => {
//!             NotificationAdmissionDecision::Admit
//!         }
//!         Some(_) => NotificationAdmissionDecision::Reject,
//!     })
//!     .spawn()
//!     .await?;
//! # Ok(())
//! # }
//! ```
//!
//! The two mechanisms confer very different assurance. V1/v2c community and
//! content are cleartext; without an allowlist they are unverified, while a
//! match checks only the cleartext community value. V3 username, context, and
//! declared envelope content are authenticated at `authNoPriv` or `authPriv`,
//! but remain spoofable at `noAuthNoPriv`. Top-level bytes following the
//! declared V3 envelope are not covered by USM authentication. Each
//! [`Notification`] carries the community or
//! username and [`security_level`](Notification::security_level), so branch on
//! those fields when applying per-version policy.
//!
//! # SNMPv3 authoritative roles
//!
//! The sender of an unconfirmed V3 trap is authoritative. The receiver applies
//! per-sender engine processing and reports the received security level to the
//! application; authentication of identity and declared envelope content
//! occurs only at `authNoPriv` or `authPriv`. For a V3 Inform, this receiver is
//! authoritative:
//! the Inform must be localized to its stable engine ID, and any generated
//! Response uses its current coherent boots/time rather than echoing the
//! incoming tuple. Configuring any USM user therefore requires a persisted
//! [`AuthoritativeEngine`].
//!
//! # Notification varbind validation
//!
//! SNMPv2c and SNMPv3 TrapV2 and Inform PDUs start with an uptime value and a
//! trap OID value. By default, [`NotificationVarbindValidation::Tolerant`]
//! accepts non-standard names for those two varbinds, but still requires at
//! least two varbinds with `TimeTicks` then `ObjectIdentifier` values.
//! [`NotificationVarbindValidation::Strict`] additionally requires the exact
//! `sysUpTime.0` then `snmpTrapOID.0` names and order. Configure strict mode with
//! [`NotificationReceiverBuilder::varbind_validation`].
//!
//! A notification that fails the selected validation is dropped and not
//! returned by [`NotificationReceiver::recv`]. A rejected Inform is not
//! acknowledged. This policy does not affect SNMPv1 traps, community or USM
//! checks, SNMPv3 engine correlation, or outbound PDU construction.
//!
//! # Receiver admission and Inform acknowledgement
//!
//! [`NotificationReceiverBuilder::admission_policy`] receives one borrowed
//! [`NotificationAdmissionInfo`] after community or USM processing and
//! notification-prefix validation. The policy can use receive metadata, identity,
//! security level, scoped context, class, and notification OID. A rejection, error,
//! or panic discards the notification without an Inform Response. Discovery and
//! USM failure Reports follow their protocol rules.
//!
//! The processor checks the ordinary Response size for an admitted Inform before
//! delivery. The managed receiver attempts to send a fitting empty-varbind
//! `tooBig` Response in either acknowledgement mode. If the alternate also
//! exceeds the limit, the receiver counts a silent drop. Both outcomes end
//! processing before delivery.
//! [RFC 3416 §4.2.7](https://www.rfc-editor.org/rfc/rfc3416.html#section-4.2.7)
//!
//! Automatic mode attempts the ordinary Response before
//! [`NotificationReceiver::recv`] delivers the notification. Application-controlled
//! and socketless processing expose the payload so the application can inspect and
//! persist it before encoding the Response.
//!
//! [`NotificationReceiverBuilder::admit_all_notifications`] also admits
//! unverified `noAuthNoPriv` notifications that pass USM. Use an admission policy
//! that requires at least [`SecurityLevel::AuthNoPriv`] when authenticated
//! input is required.
//!
//! # Caller-owned I/O
//!
//! [`NotificationProcessor`] accepts complete [`crate::ProcessingInput`] values
//! without owning sockets, tasks or delivery queues. It uses the same protocol,
//! admission and response encoding as managed receivers for v1/v2c/v3. Select
//! a logical listener, then call [`NotificationProcessor::process`] once for
//! each message, including SNMPv3 discovery probes. For a message with no
//! selected listener, the endpoint can answer discovery using its designated
//! [`crate::LocalEngine::report_unknown_engine`].
//!
//! Receivers use the PDU type when readable to distinguish a stale Inform from
//! a remote-authoritative trap. For an encrypted PDU, classification uses
//! authenticated decryption with the selected credentials when available. If
//! the type remains unknown, a foreign engine ID with `reportableFlag` set
//! takes the local unknown-engine path. The flag also determines Report
//! eligibility when the PDU type is unknown. Remote timeliness advances only
//! for recognized, authenticated traps. [`NotificationProcessResult::UsmFailed`]
//! retains any encoded Report. Send Reports on the original route as protocol replies.
//!
//! An accepted Inform includes an owned [`InformResponse`]. Applications can persist
//! the notification before consuming that capability with [`InformResponse::encode`]
//! and sending the resulting reply on the original route. Encoding can
//! return a `tooBig` reply if the current engine clock pushes the ordinary
//! response over the limit. Dropping the capability skips acknowledgement.
//! [`NotificationProcessResult::InformTooBig`] contains an optional protocol
//! reply to send independently of persistence.

mod handlers;
mod lifecycle;
mod pending;
pub use pending::{InformAcknowledgementMode, NotificationAcknowledgement, PendingInformAck};
mod processor;
#[cfg(test)]
mod processor_tests;
pub use processor::{
    EncodedInformResponse, InformResponse, NotificationProcessResult, NotificationProcessor,
    NotificationProcessorBuilder, ProcessedNotification,
};
#[cfg(test)]
mod lifecycle_tests;
mod varbind;
pub(crate) use lifecycle::RunnerCleanup;
use lifecycle::{Delivery, NotificationLease};
pub use lifecycle::{
    NotificationControl, NotificationHealth, NotificationRunner, NotificationStatus,
    PreparedNotificationReceiver, RunningNotificationReceiver,
};

use std::collections::HashMap;
#[cfg(test)]
use std::net::SocketAddr;
#[cfg(test)]
use std::sync::atomic::AtomicU32;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::Community;
use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};

use crate::error::{Error, Result};
use crate::message::SecurityLevel;
use crate::oid::Oid;
use crate::pdu::TrapV1Pdu;
#[cfg(test)]
use crate::udp_responder::{ReceivedDatagram, UdpResponder};
use crate::util::{PreparedAuthoritativeUsm, validate_authoritative_usm};
use crate::v3::{AuthoritativeEngine, DesSaltState, PrivProtocol, SaltCounter};
use crate::varbind::VarBind;
use crate::version::Version;

use crate::v3::UsmUser;
pub use varbind::{NotificationVarbindValidation, validate_notification_varbinds};

/// Maximum number of distinct remote authoritative engines whose timeliness
/// state is retained for trap senders. A peer holding one USM credential can
/// authenticate under arbitrarily many fabricated engine IDs (keys are
/// localized per engine ID), so the table is bounded and the
/// least-recently-updated engine is evicted when full.
#[cfg(all(test, any(feature = "crypto-rustcrypto", feature = "crypto-fips")))]
const MAX_REMOTE_ENGINES: usize = crate::v3::security::DEFAULT_REMOTE_ENGINE_LIMIT;

/// Notification PDU class presented to an admission policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NotificationPduClass {
    /// An unconfirmed v1 or v2-style trap.
    Trap,
    /// A confirmed Inform request.
    Inform,
}

/// Wire identity retained for one received notification.
///
/// These fields identify one protocol transmission, not one semantic event.
/// In particular, an Inform retry can carry a different V3 message ID and is
/// delivered as another application event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationWireIdentity {
    /// Protocol version decoded from the datagram.
    pub version: Version,
    /// PDU request ID, absent only for an SNMPv1 Trap-PDU.
    pub request_id: Option<i32>,
    /// V3 message and USM identity, or `None` for v1/v2c.
    pub v3: Option<V3NotificationWireIdentity>,
}

/// V3 message and USM identity retained from a received notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V3NotificationWireIdentity {
    /// V3 message ID from msgGlobalData.
    pub msg_id: i32,
    /// Authoritative engine ID carried in the USM security parameters.
    pub authoritative_engine_id: Bytes,
    /// USM username carried on the wire.
    pub username: Bytes,
    /// Actual security level carried on the wire.
    pub security_level: SecurityLevel,
}

/// Local acknowledgement result for a delivered Inform.
#[derive(Debug)]
pub enum InformAckOutcome {
    /// The local socket send completed with the ordinary response.
    Sent,
    /// The local socket sent a `tooBig` response after the ordinary response
    /// grew beyond the size limit at completion.
    SentTooBig,
    /// Neither response fit at completion and the silent drop was counted.
    SuppressedBySize,
    /// Failure to complete the acknowledgement.
    ///
    /// Reply attempts preserve their transport error and any TCP session
    /// context. Use [`Error::kind`] to classify the failure.
    Failed(Box<Error>),
}

/// One delivered notification and its local acknowledgement result.
///
/// Traps use [`NotificationAcknowledgement::NotRequired`]. Automatic Informs
/// carry a completed local outcome; application-controlled Informs carry an
/// owned pending capability. Persistence is the application's responsibility.
/// The source and wire identity are transmission metadata and must not be
/// treated as a semantic-event deduplication key.
#[derive(Debug)]
pub struct ReceivedNotification {
    /// Delivered notification value.
    pub notification: Notification,
    /// Complete-message receive metadata, without a source authentication claim.
    pub receive_info: crate::ReceivedMessageInfo,
    /// Version, request ID, and V3 message/security identity from the wire.
    pub wire_identity: NotificationWireIdentity,
    /// Distinguishes traps, completed attempts and application-controlled Informs.
    pub inform_ack: NotificationAcknowledgement,
}

impl ReceivedNotification {
    fn trap(
        notification: Notification,
        receive_info: crate::ReceivedMessageInfo,
        wire_identity: NotificationWireIdentity,
    ) -> Self {
        Self {
            notification,
            receive_info,
            wire_identity,
            inform_ack: NotificationAcknowledgement::NotRequired,
        }
    }

    fn inform(
        notification: Notification,
        receive_info: crate::ReceivedMessageInfo,
        wire_identity: NotificationWireIdentity,
        outcome: InformAckOutcome,
    ) -> Self {
        Self {
            notification,
            receive_info,
            wire_identity,
            inform_ack: NotificationAcknowledgement::Completed(outcome),
        }
    }
}

/// Decision returned by a [`NotificationAdmissionPolicy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NotificationAdmissionDecision {
    /// Admit the notification for response sizing and delivery.
    Admit,
    /// Discard the notification without an Inform Response.
    Reject,
}

/// Application-policy failure while evaluating a notification.
///
/// Policy failures reject the notification and are emitted through tracing;
/// they are not returned from [`NotificationReceiver::recv`] because that
/// method continues waiting for the next acceptable datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationAdmissionError {
    message: Box<str>,
}

impl NotificationAdmissionError {
    /// Create an application-policy error with a diagnostic message.
    pub fn new(message: impl Into<Box<str>>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Return the diagnostic message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for NotificationAdmissionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for NotificationAdmissionError {}

/// Result returned by a fallible [`NotificationAdmissionPolicy`].
pub type NotificationAdmissionResult =
    std::result::Result<NotificationAdmissionDecision, NotificationAdmissionError>;

/// Identity and receive metadata used for notification admission.
///
/// This view is available after community filtering or USM processing and
/// notification-prefix validation. V1 and v2c communities are cleartext. V3
/// identity, context, and notification OID are authenticated at `AuthNoPriv`
/// or `AuthPriv`. At `NoAuthNoPriv` they are unverified claims. Application
/// varbinds are available on delivered [`Notification`] values.
#[derive(Clone, Copy)]
pub struct NotificationAdmissionInfo<'a> {
    /// Complete-message receive metadata. The source address is transport metadata.
    pub receive_info: crate::ReceivedMessageInfo,
    /// Protocol version.
    pub version: Version,
    /// Cleartext community for v1/v2c, or `None` for v3.
    pub community: Option<&'a Community>,
    /// USM authoritative engine ID for v3, or `None` for v1/v2c.
    pub authoritative_engine_id: Option<&'a [u8]>,
    /// USM username for v3, or `None` for v1/v2c.
    pub username: Option<&'a [u8]>,
    /// Actual v3 wire security level, or `None` for v1/v2c.
    pub security_level: Option<SecurityLevel>,
    /// Trap or Inform classification.
    pub pdu_class: NotificationPduClass,
    /// Scoped-PDU context engine ID for v3, or `None` for v1/v2c.
    pub context_engine_id: Option<&'a [u8]>,
    /// Scoped-PDU context name for v3, or `None` for v1/v2c.
    pub context_name: Option<&'a [u8]>,
    notification: &'a Notification,
}

impl std::fmt::Debug for NotificationAdmissionInfo<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NotificationAdmissionInfo")
            .field("receive_info", &self.receive_info)
            .field("version", &self.version)
            .field("community", &self.community)
            .field("authoritative_engine_id", &self.authoritative_engine_id)
            .field("username", &self.username)
            .field("security_level", &self.security_level)
            .field("pdu_class", &self.pdu_class)
            .field("context_engine_id", &self.context_engine_id)
            .field("context_name", &self.context_name)
            .finish_non_exhaustive()
    }
}

impl<'a> NotificationAdmissionInfo<'a> {
    fn new(
        receive_info: crate::ReceivedMessageInfo,
        notification: &'a Notification,
        identity: &'a NotificationWireIdentity,
        pdu_class: NotificationPduClass,
    ) -> Self {
        let (community, context_engine_id, context_name) = match notification {
            Notification::TrapV1 { community, .. }
            | Notification::TrapV2c { community, .. }
            | Notification::InformV2c { community, .. } => (Some(community), None, None),
            Notification::TrapV3 {
                context_engine_id,
                context_name,
                ..
            }
            | Notification::InformV3 {
                context_engine_id,
                context_name,
                ..
            } => (
                None,
                Some(context_engine_id.as_ref()),
                Some(context_name.as_ref()),
            ),
        };
        let usm = identity.v3.as_ref();
        Self {
            receive_info,
            version: identity.version,
            community,
            authoritative_engine_id: usm.map(|usm| usm.authoritative_engine_id.as_ref()),
            username: usm.map(|usm| usm.username.as_ref()),
            security_level: usm.map(|usm| usm.security_level),
            pdu_class,
            context_engine_id,
            context_name,
            notification,
        }
    }

    /// Return the normalized notification OID.
    ///
    /// V1 trap OIDs are derived from the generic and specific trap fields.
    /// Returns an error if an enterprise-specific trap cannot form a valid OID.
    pub fn trap_oid(&self) -> Result<Oid> {
        self.notification.trap_oid()
    }
}

/// Synchronous admission policy evaluated before Inform sizing and delivery.
///
/// A policy error or panic is contained and treated as
/// [`NotificationAdmissionDecision::Reject`]. Keep evaluation bounded and use
/// in-memory policy state. Use manual acknowledgement or caller-owned I/O for
/// application processing that must finish before an Inform Response is sent.
pub trait NotificationAdmissionPolicy: Send + Sync + 'static {
    /// Decide whether the receiver will service this validated notification.
    fn evaluate(&self, notification: &NotificationAdmissionInfo<'_>)
    -> NotificationAdmissionResult;
}

impl<F> NotificationAdmissionPolicy for F
where
    F: Fn(&NotificationAdmissionInfo<'_>) -> NotificationAdmissionResult + Send + Sync + 'static,
{
    fn evaluate(
        &self,
        notification: &NotificationAdmissionInfo<'_>,
    ) -> NotificationAdmissionResult {
        self(notification)
    }
}

struct AdmitAllNotifications;

impl NotificationAdmissionPolicy for AdmitAllNotifications {
    fn evaluate(
        &self,
        _notification: &NotificationAdmissionInfo<'_>,
    ) -> NotificationAdmissionResult {
        Ok(NotificationAdmissionDecision::Admit)
    }
}

struct InfallibleAdmissionPolicy<F>(F);

impl<F> NotificationAdmissionPolicy for InfallibleAdmissionPolicy<F>
where
    F: Fn(&NotificationAdmissionInfo<'_>) -> NotificationAdmissionDecision + Send + Sync + 'static,
{
    fn evaluate(
        &self,
        notification: &NotificationAdmissionInfo<'_>,
    ) -> NotificationAdmissionResult {
        Ok(self.0(notification))
    }
}

/// Well-known OIDs for notification varbinds.
pub mod oids {
    use crate::oid;

    /// sysUpTime.0 - first varbind in v2c/v3 notifications
    #[must_use]
    pub fn sys_uptime() -> crate::Oid {
        oid!(1, 3, 6, 1, 2, 1, 1, 3, 0)
    }

    /// snmpTrapOID.0 - second varbind in v2c/v3 notifications (contains trap type)
    #[must_use]
    pub fn snmp_trap_oid() -> crate::Oid {
        oid!(1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0)
    }

    /// snmpTrapEnterprise.0 - optional, enterprise OID for enterprise-specific traps
    #[must_use]
    pub fn snmp_trap_enterprise() -> crate::Oid {
        oid!(1, 3, 6, 1, 6, 3, 1, 1, 4, 3, 0)
    }

    /// snmpTrapAddress.0 - agent address from v1 trap (RFC 3584 Section 3)
    #[must_use]
    pub fn snmp_trap_address() -> crate::Oid {
        oid!(1, 3, 6, 1, 6, 3, 18, 1, 3, 0)
    }

    /// Standard trap OID prefix (snmpTraps)
    #[must_use]
    pub fn snmp_traps() -> crate::Oid {
        oid!(1, 3, 6, 1, 6, 3, 1, 1, 5)
    }

    /// coldStart trap OID (snmpTraps.1)
    #[must_use]
    pub fn cold_start() -> crate::Oid {
        oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1)
    }

    /// warmStart trap OID (snmpTraps.2)
    #[must_use]
    pub fn warm_start() -> crate::Oid {
        oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 2)
    }

    /// linkDown trap OID (snmpTraps.3)
    #[must_use]
    pub fn link_down() -> crate::Oid {
        oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 3)
    }

    /// linkUp trap OID (snmpTraps.4)
    #[must_use]
    pub fn link_up() -> crate::Oid {
        oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 4)
    }

    /// authenticationFailure trap OID (snmpTraps.5)
    #[must_use]
    pub fn auth_failure() -> crate::Oid {
        oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 5)
    }

    /// egpNeighborLoss trap OID (snmpTraps.6)
    #[must_use]
    pub fn egp_neighbor_loss() -> crate::Oid {
        oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 6)
    }
}

/// Builder for `NotificationReceiver`.
///
/// Configures the bind address, optional community filtering for v1/v2c, the
/// standard notification varbind validation policy, and USM credentials for
/// v3. Community filtering and USM users are independent and may be combined;
/// a single receiver then handles all versions on one port. Any USM user also
/// requires a persisted [`AuthoritativeEngine`] and an explicit notification
/// admission policy. See the
/// [module docs](crate::notification#mixed-versions-on-one-port).
pub struct NotificationReceiverBuilder {
    listeners: Vec<crate::ListenerSource>,
    network_explicit: bool,
    max_connections: usize,
    tcp_buffered_bytes: usize,
    overload_timeout: Duration,
    client_exchanges: bool,
    bind_addr: String,
    bind_explicit: bool,
    socket: Option<UdpSocket>,
    queue_capacity: usize,
    max_processing: usize,
    usm_users: HashMap<Bytes, UsmUser>,
    security_context: Option<crate::UsmSecurityContext>,
    communities: Vec<Community>,
    local_engine: Option<crate::LocalEngine>,
    authoritative_engine: Option<AuthoritativeEngine>,
    des_salt_state: Option<DesSaltState>,
    varbind_validation: NotificationVarbindValidation,
    max_message_size: usize,
    decode_config: crate::DecodeConfig,
    admission_policy: Option<Arc<dyn NotificationAdmissionPolicy>>,
    response_send_timeout: Duration,
    acknowledgement_mode: InformAcknowledgementMode,
    max_pending_informs: usize,
    pending_inform_timeout: Duration,
}

impl NotificationReceiverBuilder {
    /// Choose automatic (default) or application-controlled Inform responses.
    #[must_use]
    pub fn acknowledgement_mode(mut self, mode: InformAcknowledgementMode) -> Self {
        self.acknowledgement_mode = mode;
        self
    }

    /// Bound outstanding manual Informs, including events already dequeued.
    /// Defaults to 256. The permit remains service-owned through completion.
    /// Saturation rejects new deliverable Informs on UDP/TCP,
    /// without disabling traps or other roles on shared transports.
    #[must_use]
    pub fn max_pending_informs(mut self, limit: usize) -> Self {
        self.max_pending_informs = limit;
        self
    }

    /// Absolute lifetime of a manual Inform from acceptance (default 30 seconds).
    /// Expiry releases request/keys and permits even if its token is retained.
    #[must_use]
    pub fn pending_inform_timeout(mut self, timeout: Duration) -> Self {
        self.pending_inform_timeout = timeout;
        self
    }

    fn validate_acknowledgement(&self) -> Result<()> {
        if self.max_pending_informs == 0
            || self.max_pending_informs > tokio::sync::Semaphore::MAX_PERMITS
        {
            return Err(Error::Config(
                "max_pending_informs must be nonzero and representable".into(),
            )
            .boxed());
        }
        if self.pending_inform_timeout.is_zero() {
            return Err(Error::Config("pending_inform_timeout must be nonzero".into()).boxed());
        }
        crate::transport::checked_deadline(self.pending_inform_timeout, "pending Inform timeout")?;
        Ok(())
    }

    /// Create a builder with the default settings.
    ///
    /// Defaults:
    /// - Bind address: `0.0.0.0:162` (UDP, standard SNMP trap port)
    /// - No USM users (v3 notifications rejected until users are added)
    /// - No authoritative engine (required when adding a USM user)
    /// - Tolerant notification varbind validation
    /// - No explicit admission policy (required when adding a USM user)
    #[must_use]
    pub fn new() -> Self {
        Self {
            listeners: Vec::new(),
            network_explicit: false,
            max_connections: 128,
            tcp_buffered_bytes: 64 * 1024 * 1024,
            overload_timeout: Duration::from_secs(5),
            client_exchanges: false,
            bind_addr: "0.0.0.0:162".to_string(),
            bind_explicit: false,
            socket: None,
            queue_capacity: 256,
            max_processing: 64,
            usm_users: HashMap::new(),
            security_context: None,
            communities: Vec::new(),
            local_engine: None,
            authoritative_engine: None,
            des_salt_state: None,
            varbind_validation: NotificationVarbindValidation::Tolerant,
            max_message_size: crate::UDP_RECEIVE_LIMITS.advertised().as_usize(),
            decode_config: crate::DecodeConfig::default(),
            admission_policy: None,
            response_send_timeout: crate::client::DEFAULT_SEND_TIMEOUT,
            acknowledgement_mode: InformAcknowledgementMode::Automatic,
            max_pending_informs: 256,
            pending_inform_timeout: Duration::from_secs(30),
        }
    }

    /// Add a UDP endpoint or TCP acceptor. Explicit sources replace the default UDP bind.
    pub fn listener(mut self, source: crate::ListenerSource) -> Self {
        self.listeners.push(source);
        self
    }
    /// Prepare an outbound or supplied connected TCP session with this notification role.
    pub fn session(mut self, source: crate::TcpTransportBuilder) -> Self {
        self.listeners.push(crate::ListenerSource::Session(source));
        self
    }
    /// Limit simultaneous TCP sessions across all sources (default 128).
    pub fn max_connections(mut self, limit: usize) -> Self {
        self.network_explicit = true;
        self.max_connections = limit;
        self
    }
    /// Set the shared budget for buffered TCP input and queued writes (default 64 MiB).
    /// The largest configured TCP send capacity is reserved for output, and the
    /// remainder must accommodate the largest configured TCP inbound partition.
    /// UDP processing and response candidates use independent dispatch budgets.
    /// Decoded events are governed by [`Self::queue_capacity`].
    pub fn max_tcp_buffered_bytes(mut self, limit: usize) -> Self {
        self.network_explicit = true;
        self.tcp_buffered_bytes = limit;
        self
    }
    /// Limit intentional inbound-only TCP admission pauses (default 5 seconds).
    pub fn overload_timeout(mut self, timeout: Duration) -> Self {
        self.network_explicit = true;
        self.overload_timeout = timeout;
        self
    }

    /// Enable locally initiated exchanges on every configured endpoint/session. UDP responses
    /// have an independent bounded dispatch allowance from notification delivery.
    #[must_use]
    pub fn client_exchanges(mut self, enabled: bool) -> Self {
        self.client_exchanges = enabled;
        self
    }

    /// Set the UDP bind address.
    ///
    /// Default is `0.0.0.0:162` (UDP, standard SNMP trap port).
    #[must_use]
    pub fn bind(mut self, addr: impl Into<String>) -> Self {
        self.bind_addr = addr.into();
        self.bind_explicit = true;
        self
    }

    /// Supply an owned bound, unconnected socket, retaining its options and runtime registration.
    /// An explicit bind address conflicts with this source.
    pub fn from_socket(mut self, socket: UdpSocket) -> Self {
        self.socket = Some(socket);
        self
    }

    /// Bound queued and admitted notifications. Default: 256 events. A full UDP
    /// queue drops deliverable notifications before ordinary Inform acknowledgement.
    pub fn queue_capacity(mut self, capacity: usize) -> Self {
        self.queue_capacity = capacity;
        self
    }

    /// Bound concurrent protocol/response work. Default: 64 tasks. UDP overload
    /// drops without blocking the reader; TCP follows its configured-role admission policy.
    pub fn max_processing(mut self, limit: usize) -> Self {
        self.max_processing = limit;
        self
    }

    /// Set validation for the standard SNMPv2c/v3 notification varbind prefix.
    ///
    /// The default [`NotificationVarbindValidation::Tolerant`] mode accepts
    /// arbitrary names when the first two values are `TimeTicks` then
    /// `ObjectIdentifier`. [`NotificationVarbindValidation::Strict`] also
    /// requires the exact `sysUpTime.0` then `snmpTrapOID.0` names and order.
    /// In either mode, a failed notification is not returned from
    /// [`NotificationReceiver::recv`], and a failed Inform is not acknowledged.
    ///
    /// This setting does not apply to SNMPv1 traps and does not change
    /// authentication, SNMPv3 engine correlation, or outbound validation.
    #[must_use]
    pub fn varbind_validation(mut self, policy: NotificationVarbindValidation) -> Self {
        self.varbind_validation = policy;
        self
    }

    /// Set the local upper bound for managed Inform responses and V3 Reports.
    ///
    /// The default is the maximum UDP payload. Values below the SNMPv3
    /// advertisement minimum are permitted as response/drop policy and are not
    /// copied into outgoing V3 `msgMaxSize`, which remains this receiver's local
    /// receive capacity. If the ordinary Inform response and its `tooBig`
    /// alternate both exceed the effective limit, the receiver discards the
    /// Inform and increments [`NotificationReceiver::snmp_silent_drops`].
    #[must_use]
    pub fn max_message_size(mut self, size: usize) -> Self {
        self.max_message_size = size;
        self
    }

    /// Set the deadline for each Inform acknowledgement or SNMPv3 Report send.
    ///
    /// The default is five seconds. Expiry completes the admitted Inform with
    /// a failed acknowledgement outcome while other processing can continue.
    #[must_use]
    pub fn response_send_timeout(mut self, timeout: Duration) -> Self {
        self.response_send_timeout = timeout;
        self
    }

    /// Set bounded notification-decoding compatibility.
    ///
    /// The same snapshot applies to community notifications and every staged
    /// V3 decode. The default is [`crate::DecodeConfig::DEFAULT`].
    #[must_use]
    pub fn decode_config(mut self, config: crate::DecodeConfig) -> Self {
        self.decode_config = config;
        self
    }

    /// Set a receiver admission policy. It runs after protocol processing and
    /// notification-prefix validation, before Inform sizing and delivery.
    ///
    /// A receiver with USM users requires this method,
    /// [`try_admission_policy`](Self::try_admission_policy), or
    /// [`admit_all_notifications`](Self::admit_all_notifications). Rejection or
    /// panic discards the notification without an Inform Response.
    #[must_use]
    pub fn admission_policy(
        self,
        policy: impl Fn(&NotificationAdmissionInfo<'_>) -> NotificationAdmissionDecision
        + Send
        + Sync
        + 'static,
    ) -> Self {
        self.try_admission_policy(InfallibleAdmissionPolicy(policy))
    }

    /// Set a fallible receiver admission policy.
    ///
    /// Evaluation occurs at the same point as
    /// [`admission_policy`](Self::admission_policy). An error is traced and
    /// rejects the notification without an Inform Response.
    #[must_use]
    pub fn try_admission_policy(mut self, policy: impl NotificationAdmissionPolicy) -> Self {
        self.admission_policy = Some(Arc::new(policy));
        self
    }

    /// Explicitly admit every successfully processed notification.
    ///
    /// For v3 this includes lower security levels supported by a configured
    /// inbound user, including `noAuthNoPriv`. At that level the username,
    /// context, and notification content are unverified and spoofable. Prefer
    /// [`admission_policy`](Self::admission_policy) with a minimum
    /// [`SecurityLevel::AuthNoPriv`] when authenticated input is required.
    #[must_use]
    pub fn admit_all_notifications(self) -> Self {
        self.try_admission_policy(AdmitAllNotifications)
    }

    /// Add a USM user for V3 processing.
    ///
    /// Adding any user requires a persisted [`AuthoritativeEngine`] and an
    /// explicit [`admission_policy`](Self::admission_policy),
    /// [`try_admission_policy`](Self::try_admission_policy), or
    /// [`admit_all_notifications`](Self::admit_all_notifications) before
    /// [`prepare`](Self::prepare), because this receiver is authoritative for V3
    /// Inform exchanges.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use async_snmp::notification::{NotificationAdmissionDecision, NotificationReceiver};
    /// use async_snmp::{AuthProtocol, AuthoritativeEngine, PrivProtocol, SecurityLevel};
    /// use std::convert::Infallible;
    ///
    /// # async fn example() -> Result<(), Box<async_snmp::Error>> {
    /// # // Replace this no-op with durable storage in an application.
    /// let engine = AuthoritativeEngine::install(b"receiver-engine".to_vec(), |_| {
    ///     Ok::<(), Infallible>(())
    /// })?;
    /// let mut receiver = NotificationReceiver::builder()
    ///     .bind("0.0.0.0:162")
    ///     .authoritative_engine(engine)
    ///     .usm_user("trapuser", |u| {
    ///         u.auth_priv(
    ///             AuthProtocol::Sha1,
    ///             b"authpassword",
    ///             PrivProtocol::Aes128,
    ///             b"privpassword",
    ///         )
    ///     }).unwrap()
    ///     .admission_policy(|notification| {
    ///         if notification.security_level >= Some(SecurityLevel::AuthNoPriv) {
    ///             NotificationAdmissionDecision::Admit
    ///         } else {
    ///             NotificationAdmissionDecision::Reject
    ///         }
    ///     })
    ///     .spawn()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn usm_user<F>(
        mut self,
        username: impl Into<Bytes>,
        configure: F,
    ) -> crate::CryptoResult<Self>
    where
        F: FnOnce(UsmUser) -> crate::CryptoResult<UsmUser>,
    {
        let username_bytes: Bytes = username.into();
        let config = configure(UsmUser::new(username_bytes.clone()))?;
        self.usm_users.insert(username_bytes, config);
        Ok(self)
    }

    /// Restrict accepted v1/v2c notifications to the given community string.
    ///
    /// Community filtering is opt-in. With no community configured the
    /// receiver accepts v1/v2c notifications under any community and surfaces
    /// the unverified community on the returned [`Notification`] for
    /// caller-side policy. Community strings are cleartext and do not provide
    /// message integrity. An allowlist confirms only that the received value
    /// matched one of the configured entries.
    /// Once one or more communities are configured, a v1/v2c notification
    /// whose community matches none of them is dropped and never returned
    /// from [`NotificationReceiver::recv`]; a dropped inform is not
    /// acknowledged. Comparison is constant-time. This does not affect v3,
    /// which is gated by USM.
    ///
    /// Call multiple times to accept several communities.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use async_snmp::notification::NotificationReceiver;
    ///
    /// # async fn example() -> Result<(), Box<async_snmp::Error>> {
    /// let mut receiver = NotificationReceiver::builder()
    ///     .bind("0.0.0.0:162")
    ///     .community(b"public")
    ///     .spawn()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn community(mut self, community: impl Into<Community>) -> Self {
        self.communities.push(community.into());
        self
    }

    /// Restrict accepted v1/v2c notifications to any of the given communities.
    ///
    /// Convenience for calling [`Self::community`] once per entry. See that
    /// method for the filtering semantics.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use async_snmp::notification::NotificationReceiver;
    ///
    /// # async fn example() -> Result<(), Box<async_snmp::Error>> {
    /// let mut receiver = NotificationReceiver::builder()
    ///     .bind("0.0.0.0:162")
    ///     .communities(["public", "monitor"])
    ///     .spawn()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn communities<I, C>(mut self, communities: I) -> Self
    where
        I: IntoIterator<Item = C>,
        C: Into<Community>,
    {
        for c in communities {
            self.communities.push(c.into());
        }
        self
    }

    /// Set the persisted local authoritative engine state for `SNMPv3`.
    ///
    /// A receiver with USM users can be authoritative for Informs and requires
    /// this value. Construct it with [`AuthoritativeEngine::install`] on first
    /// installation or [`AuthoritativeEngine::restart`] on later starts. The
    /// retained callback persists runtime rollover increments before use.
    #[must_use]
    pub fn authoritative_engine(mut self, engine: AuthoritativeEngine) -> Self {
        self.authoritative_engine = Some(engine);
        self
    }

    /// Select shared inbound USM credentials and remote timeliness state.
    /// Conflicts with separately configured `usm_user` entries. An explicit
    /// context requires persisted local engine state and an admission policy
    /// even when initially empty, including across later user replacement.
    #[must_use]
    pub fn security_context(mut self, context: crate::UsmSecurityContext) -> Self {
        self.security_context = Some(context);
        self
    }

    /// Share local engine identity, clock, counters and privacy-sender state.
    /// Conflicts with `authoritative_engine` or `des_salt_state` configuration.
    /// Credentials, remote timeliness and admission remain receiver-specific.
    #[must_use]
    pub fn local_engine(mut self, engine: crate::LocalEngine) -> Self {
        self.local_engine = Some(engine);
        self
    }

    /// Set durable local generating-engine state for DES/3DES Inform responses.
    #[must_use]
    pub fn des_salt_state(mut self, state: DesSaltState) -> Self {
        self.des_salt_state = Some(state);
        self
    }

    #[cfg(test)]
    pub(crate) fn engine_id(mut self, engine_id: impl Into<Vec<u8>>) -> Self {
        let boots = self
            .authoritative_engine
            .as_ref()
            .map_or(1, AuthoritativeEngine::engine_boots);
        self.authoritative_engine = Some(AuthoritativeEngine::for_test(engine_id.into(), boots));
        self
    }

    #[cfg(all(test, any(feature = "crypto-rustcrypto", feature = "crypto-fips")))]
    pub(crate) fn engine_boots(mut self, boots: u32) -> Self {
        let engine_id = self
            .authoritative_engine
            .as_ref()
            .map(|engine| engine.engine_id().to_vec())
            .unwrap_or_else(|| {
                crate::v3::generate_engine_id()
                    .expect("test engine ID generation")
                    .to_vec()
            });
        self.authoritative_engine = Some(AuthoritativeEngine::for_test(engine_id, boots));
        self
    }

    /// Prepare the notification receiver and its unstarted runner.
    ///
    /// Returns a configuration error when USM credentials are invalid, USM
    /// users do not have an explicit admission policy, or a USM user is
    /// configured without a persisted [`AuthoritativeEngine`]. Returns
    /// [`Error::RandomSource`] when a generated engine ID or required privacy
    /// salt cannot be initialized.
    pub async fn prepare(self) -> Result<PreparedNotificationReceiver> {
        self.prepare_with_engine_id_generator(crate::v3::generate_engine_id)
            .await
    }

    async fn prepare_with_engine_id_generator(
        mut self,
        generate_engine_id: impl FnOnce() -> Result<Bytes>,
    ) -> Result<PreparedNotificationReceiver> {
        self.validate_acknowledgement()?;
        if self.security_context.is_some() && !self.usm_users.is_empty() {
            return Err(Error::Config(
                "security_context conflicts with usm_user configuration".into(),
            )
            .boxed());
        }
        let security_context_required =
            self.security_context.is_some() || !self.usm_users.is_empty();
        if self.queue_capacity == 0
            || self.queue_capacity > tokio::sync::Semaphore::MAX_PERMITS
            || self.max_processing == 0
            || self.max_processing > tokio::sync::Semaphore::MAX_PERMITS
        {
            return Err(Error::Config(
                "notification queue and processing limits must be nonzero and representable".into(),
            )
            .boxed());
        }
        if self.socket.is_some() && self.bind_explicit {
            return Err(Error::Config(
                "supplied notification socket conflicts with bind address".into(),
            )
            .boxed());
        }
        if security_context_required && self.admission_policy.is_none() {
            return Err(Error::Config(
                "a notification receiver with USM users requires an admission policy".into(),
            )
            .boxed());
        }

        if self.max_message_size > crate::message_size::MESSAGE_SIZE_MAXIMUM {
            return Err(
                Error::Config("max_message_size exceeds the SNMP size range".into()).boxed(),
            );
        }
        crate::transport::checked_deadline(
            self.response_send_timeout,
            "notification response send timeout",
        )?;

        if let Some(engine) = &self.local_engine {
            if self.authoritative_engine.is_some() || self.des_salt_state.is_some() {
                return Err(Error::Config(
                    "local_engine conflicts with authoritative_engine or des_salt_state".into(),
                )
                .boxed());
            }
            self.authoritative_engine = engine.authoritative_engine().cloned();
            self.des_salt_state = engine.des_salt_state();
        }

        let context_users = self
            .security_context
            .as_ref()
            .map(crate::UsmSecurityContext::snapshot);
        let uses_des = self
            .usm_users
            .values()
            .chain(context_users.iter().flat_map(|users| users.values()))
            .any(|security| {
                security
                    .priv_protocol()
                    .is_some_and(PrivProtocol::is_des_family)
            });
        let uses_aes = self
            .usm_users
            .values()
            .chain(context_users.iter().flat_map(|users| users.values()))
            .any(|security| {
                security
                    .priv_protocol()
                    .is_some_and(|protocol| !protocol.is_des_family())
            });
        if uses_des
            && self.des_salt_state.is_none()
            && self.acknowledgement_mode == InformAcknowledgementMode::Automatic
        {
            return Err(Error::Config(
                "durable DES sender state is required for DES/3DES notification receiving".into(),
            )
            .boxed());
        }
        if uses_des
            && let (Some(engine), Some(state)) = (&self.authoritative_engine, &self.des_salt_state)
            && engine.engine_boots() != state.engine_boots()
        {
            return Err(Error::Config(
                "DES sender boots must match the receiver authoritative engine boots".into(),
            )
            .boxed());
        }
        let requires_authoritative_engine = security_context_required;
        let validated_usm = validate_authoritative_usm(
            std::mem::take(&mut self.usm_users),
            self.authoritative_engine.take(),
            requires_authoritative_engine,
            "invalid USM user configuration",
            "authoritative engine state is required for SNMPv3 notification receiving",
        )?;

        if !self.listeners.is_empty() && (self.bind_explicit || self.socket.is_some()) {
            return Err(Error::Config(
                "explicit listeners conflict with notification bind/socket configuration".into(),
            )
            .boxed());
        }
        if self.listeners.len() > 32
            || self
                .listeners
                .iter()
                .filter(|source| matches!(source, crate::ListenerSource::Session(_)))
                .count()
                > self.max_connections
            || self.max_connections == 0
            || self.max_connections > tokio::sync::Semaphore::MAX_PERMITS
            || self.tcp_buffered_bytes == 0
            || self.tcp_buffered_bytes > u32::MAX as usize
            || self.tcp_buffered_bytes > tokio::sync::Semaphore::MAX_PERMITS
            || self.overload_timeout.is_zero()
        {
            return Err(Error::Config("invalid notification network limits".into()).boxed());
        }
        crate::transport::checked_deadline(self.overload_timeout, "notification overload timeout")?;
        let (sender, _) = mpsc::channel(self.max_processing);
        let ingress = crate::transport::ingress::ApplicationIngress {
            #[cfg(test)]
            admission_hook: None,
            sender,
            disabled: tokio_util::sync::CancellationToken::new(),
            capacity: Arc::new(tokio::sync::Semaphore::new(self.max_processing)),
            budget: Arc::new(crate::transport::framing::BufferBudget::new(
                self.tcp_buffered_bytes,
            )),
            overload_timeout: self.overload_timeout,
            drops: Arc::new(AtomicU64::new(0)),
            session: None,
        };
        let sources = if self.listeners.is_empty() {
            vec![match self.socket.take() {
                Some(socket) => crate::ListenerSource::udp_socket(socket),
                None => crate::ListenerSource::udp(&self.bind_addr),
            }]
        } else {
            std::mem::take(&mut self.listeners)
        };
        let mut listeners = Vec::new();
        for source in sources {
            listeners.push(source.prepare(ingress.clone()).await?);
        }
        let network = Arc::new(crate::transport::network::NetworkState::new(
            &listeners,
            self.max_connections,
        )?);

        let PreparedAuthoritativeUsm {
            users: usm_users,
            authoritative_engine,
            engine_id,
            engine_boots,
        } = validated_usm.prepare(generate_engine_id)?;
        let security_context = self
            .security_context
            .take()
            .unwrap_or_else(|| crate::UsmSecurityContext::from_prepared(usm_users));
        let local_engine = match self.local_engine.take() {
            Some(engine) => {
                if uses_aes {
                    engine.ensure_salt_counter(SaltCounter::new)?;
                }
                engine
            }
            None => crate::LocalEngine::from_prepared(
                authoritative_engine,
                engine_id,
                engine_boots,
                uses_aes.then(SaltCounter::new).transpose()?.map(Arc::new),
                self.des_salt_state.take(),
            ),
        };
        let capacity_registration =
            crate::transport::listener::PreparedListener::register_receive_capacities(
                &mut listeners,
                &local_engine,
            );
        let enabled = self.client_exchanges;
        let engine = PreparedNotificationRole {
            local_engine,
            security_context,
            requires_policy: security_context_required,
            capacity_registration,
        };
        let (receiver, processor, cleanup) = self.prepare_role(engine, network.clone())?;
        let roles = Arc::new(crate::transport::dispatch::DispatchRoles::new(
            None,
            Some(processor.clone()),
            processor.inner.security_context.clone(),
            enabled,
            processor.processing_limit(),
        ));
        for listener in &mut listeners {
            listener.configure_dispatch(roles.clone());
        }
        let runner = NotificationRunner::from_network(network, listeners, processor, cleanup);
        Ok(PreparedNotificationReceiver { receiver, runner })
    }
    fn prepare_role(
        self,
        engine: PreparedNotificationRole,
        network: Arc<crate::transport::network::NetworkState>,
    ) -> Result<(NotificationReceiver, NotificationRole, RunnerCleanup)> {
        self.validate_acknowledgement()?;
        if self.queue_capacity == 0
            || self.queue_capacity > tokio::sync::Semaphore::MAX_PERMITS
            || self.max_processing == 0
            || self.max_processing > tokio::sync::Semaphore::MAX_PERMITS
        {
            return Err(Error::Config(
                "notification queue and processing limits must be nonzero and representable".into(),
            )
            .boxed());
        }
        if self.max_message_size > crate::message_size::MESSAGE_SIZE_MAXIMUM {
            return Err(
                Error::Config("max_message_size exceeds the SNMP size range".into()).boxed(),
            );
        }
        crate::transport::checked_deadline(
            self.response_send_timeout,
            "notification response send timeout",
        )?;
        if engine.requires_policy && self.admission_policy.is_none() {
            return Err(Error::Config(
                "shared USM notification role requires an explicit admission policy".into(),
            )
            .boxed());
        }
        let (sender, events) = mpsc::channel(self.queue_capacity);
        let delivery = Arc::new(Delivery::new(sender));
        let pending = pending::PendingRegistry::new(self.max_pending_informs);
        let inner = Arc::new(ReceiverInner {
            protocol: NotificationProcessor::configured(
                engine.local_engine,
                engine.security_context,
                self.communities,
                self.varbind_validation,
                self.max_message_size,
                self.decode_config,
                self.admission_policy,
            ),
            #[cfg(test)]
            udp_responder: network.udp.first().map(crate::UdpEndpoint::test_responder),
            #[cfg(test)]
            endpoint_id: network.bound[0].endpoint_id,
            delivery: delivery.clone(),
            pending: pending.clone(),
            acknowledgement_mode: self.acknowledgement_mode,
            pending_inform_timeout: self.pending_inform_timeout,
            max_processing: self.max_processing,
            active: std::sync::atomic::AtomicUsize::new(0),
            idle: tokio::sync::Notify::new(),
            response_send_timeout: self.response_send_timeout,
            #[cfg(test)]
            response_send_gate: Mutex::new(None),
            #[cfg(test)]
            response_sends_started: AtomicU32::new(0),
            #[cfg(test)]
            response_send_errors: Mutex::new(std::collections::VecDeque::new()),
            #[cfg(test)]
            response_construction_errors: Mutex::new(std::collections::VecDeque::new()),
            #[cfg(test)]
            receive_errors: Arc::new(Mutex::new(std::collections::VecDeque::new())),
            #[cfg(test)]
            receive_error_ready: Arc::new(tokio::sync::Notify::new()),
        });
        let state = Arc::new(lifecycle::ServiceState::new());
        let lease = Arc::new(NotificationLease::new(state.shutdown.clone()));
        let receiver = NotificationReceiver {
            network,
            inner: inner.clone(),
            events,
            state: state.clone(),
            lease,
        };
        Ok((
            receiver,
            NotificationRole { inner },
            RunnerCleanup {
                delivery,
                state,
                pending,
                capacity_registration: engine.capacity_registration,
            },
        ))
    }

    #[cfg(feature = "agent")]
    pub(crate) fn validate_attached(&self, has_users: bool) -> Result<()> {
        self.validate_acknowledgement()?;
        if self.socket.is_some()
            || self.network_explicit
            || !self.listeners.is_empty()
            || self.bind_explicit
            || self.local_engine.is_some()
            || self.authoritative_engine.is_some()
            || self.security_context.is_some()
            || !self.usm_users.is_empty()
            || self.des_salt_state.is_some()
            || self.client_exchanges
        {
            return Err(Error::Config("attached notifications inherit the agent endpoint, client capability and prepared USM engine; independent socket, engine, users or client capability conflict".into()).boxed());
        }
        if self.queue_capacity == 0
            || self.queue_capacity > tokio::sync::Semaphore::MAX_PERMITS
            || self.max_processing == 0
            || self.max_processing > tokio::sync::Semaphore::MAX_PERMITS
        {
            return Err(Error::Config(
                "notification queue and processing limits must be nonzero and representable".into(),
            )
            .boxed());
        }

        if self.max_message_size > crate::message_size::MESSAGE_SIZE_MAXIMUM {
            return Err(
                Error::Config("max_message_size exceeds the SNMP size range".into()).boxed(),
            );
        }
        crate::transport::checked_deadline(
            self.response_send_timeout,
            "notification response send timeout",
        )?;
        if has_users && self.admission_policy.is_none() {
            return Err(Error::Config(
                "shared USM notification role requires an explicit admission policy".into(),
            )
            .boxed());
        }
        Ok(())
    }

    #[cfg(feature = "agent")]
    pub(crate) fn prepare_attached(
        self,
        agent: &crate::agent::AgentProcessor,
        network: &Arc<crate::transport::network::NetworkState>,
    ) -> Result<(NotificationReceiver, NotificationRole, RunnerCleanup)> {
        self.validate_attached(agent.inner.security_context_required)?;
        let engine = PreparedNotificationRole {
            local_engine: agent.inner.state.local_engine.clone(),
            security_context: agent.inner.security_context.clone(),
            requires_policy: agent.inner.security_context_required,
            capacity_registration: None,
        };
        self.prepare_role(engine, network.clone())
    }

    /// Prepare and spawn the same runner on the current runtime.
    pub async fn spawn(self) -> Result<RunningNotificationReceiver> {
        Ok(self.prepare().await?.spawn())
    }

    /// Prepare the receiver where this future is polled, then spawn its runner
    /// on `runtime`.
    ///
    /// Preparation registers new sockets with the polling Tokio runtime's I/O
    /// driver. A configured TCP connect timeout also uses timers on that
    /// runtime. Supplied, registered I/O keeps its original registration.
    /// Keep the I/O runtimes alive and driven while their sockets are in use.
    /// The runner uses timers on `runtime` and registers accepted TCP streams
    /// there.
    pub async fn spawn_on(
        self,
        runtime: &tokio::runtime::Handle,
    ) -> Result<RunningNotificationReceiver> {
        Ok(self.prepare().await?.spawn_on(runtime))
    }
}

impl Default for NotificationReceiverBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Received SNMP notification.
///
/// An SNMP notification received from the network.
///
/// - SNMPv1 Trap (different PDU structure)
/// - SNMPv2c/v3 Trap (standard PDU with sysUpTime.0 and snmpTrapOID.0)
/// - `InformRequest` (confirmed notification; managed automatic mode attempts
///   its response before delivery, manual mode returns a pending capability)
///
/// V1/v2c community and content are cleartext and have no cryptographic
/// integrity; without a configured community allowlist they are unverified.
/// V3 username, context, and declared envelope content are authenticated only
/// at `AuthNoPriv` or `AuthPriv`; all are spoofable at `NoAuthNoPriv`.
#[derive(Debug, Clone)]
pub enum Notification {
    /// `SNMPv1` Trap with unique PDU structure.
    TrapV1 {
        /// Cleartext community string; unverified without a configured allowlist.
        community: Community,
        /// The trap PDU
        trap: TrapV1Pdu,
        /// Accepted BER/value deviations from the received message.
        decode_anomalies: Vec<crate::DecodeAnomaly>,
    },

    /// `SNMPv2c` Trap (unconfirmed notification).
    TrapV2c {
        /// Cleartext community string; unverified without a configured allowlist.
        community: Community,
        /// sysUpTime.0 value (hundredths of seconds since agent init)
        uptime: u32,
        /// snmpTrapOID.0 value (trap type identifier)
        trap_oid: Oid,
        /// Additional variable bindings
        varbinds: Vec<VarBind>,
        /// Original request ID (for logging/correlation)
        request_id: i32,
        /// Accepted BER/value deviations from the received message.
        decode_anomalies: Vec<crate::DecodeAnomaly>,
    },

    /// `SNMPv3` Trap (unconfirmed notification).
    TrapV3 {
        /// Username from USM; authenticated only at `AuthNoPriv`/`AuthPriv`.
        username: Bytes,
        /// Context engine ID; authenticated only at `AuthNoPriv`/`AuthPriv`.
        context_engine_id: Bytes,
        /// Context name; authenticated only at `AuthNoPriv`/`AuthPriv`.
        context_name: Bytes,
        /// Security level the message was received at. At `NoAuthNoPriv`, the
        /// username, context, and notification content are unverified and
        /// spoofable. Callers requiring authentication must check this.
        security_level: SecurityLevel,
        /// sysUpTime.0 value
        uptime: u32,
        /// snmpTrapOID.0 value
        trap_oid: Oid,
        /// Additional variable bindings
        varbinds: Vec<VarBind>,
        /// Original request ID
        request_id: i32,
        /// Accepted BER/value deviations from the received message.
        decode_anomalies: Vec<crate::DecodeAnomaly>,
    },

    /// `InformRequest` (confirmed notification) - v2c.
    ///
    /// When returned by [`NotificationReceiver`], the Inform has passed admission
    /// and response sizing. Automatic mode attempts its response before delivery;
    /// application-controlled mode delivers a pending acknowledgement.
    InformV2c {
        /// Cleartext community string; unverified without a configured allowlist.
        community: Community,
        /// sysUpTime.0 value
        uptime: u32,
        /// snmpTrapOID.0 value
        trap_oid: Oid,
        /// Additional variable bindings
        varbinds: Vec<VarBind>,
        /// Request ID (used in response)
        request_id: i32,
        /// Accepted BER/value deviations from the received message.
        decode_anomalies: Vec<crate::DecodeAnomaly>,
    },

    /// `InformRequest` (confirmed notification) - v3.
    ///
    /// When returned by [`NotificationReceiver`], the Inform has passed admission
    /// and response sizing. Automatic mode attempts its response before delivery;
    /// application-controlled mode delivers a pending acknowledgement.
    InformV3 {
        /// Username from USM; authenticated only at `AuthNoPriv`/`AuthPriv`.
        username: Bytes,
        /// Context engine ID; authenticated only at `AuthNoPriv`/`AuthPriv`.
        context_engine_id: Bytes,
        /// Context name; authenticated only at `AuthNoPriv`/`AuthPriv`.
        context_name: Bytes,
        /// Security level the message was received at. At `NoAuthNoPriv`, the
        /// username, context, and notification content are unverified and
        /// spoofable. Callers requiring authentication must check this.
        security_level: SecurityLevel,
        /// sysUpTime.0 value
        uptime: u32,
        /// snmpTrapOID.0 value
        trap_oid: Oid,
        /// Additional variable bindings
        varbinds: Vec<VarBind>,
        /// Request ID
        request_id: i32,
        /// Accepted BER/value deviations from the received message.
        decode_anomalies: Vec<crate::DecodeAnomaly>,
    },
}

impl Notification {
    /// Accepted BER/value deviations from the received message, in decode order.
    ///
    /// Community and V3 `NoAuthNoPriv` anomalies are unauthenticated. For
    /// authenticated V3 messages, anomalies within the declared envelope are
    /// authenticated, but a top-level [`crate::DecodeAnomaly::TrailingBytes`]
    /// describes bytes outside that envelope and remains unauthenticated.
    #[must_use]
    pub fn decode_anomalies(&self) -> &[crate::DecodeAnomaly] {
        match self {
            Self::TrapV1 {
                decode_anomalies, ..
            }
            | Self::TrapV2c {
                decode_anomalies, ..
            }
            | Self::TrapV3 {
                decode_anomalies, ..
            }
            | Self::InformV2c {
                decode_anomalies, ..
            }
            | Self::InformV3 {
                decode_anomalies, ..
            } => decode_anomalies,
        }
    }

    /// Returns the trap or notification OID.
    ///
    /// For `TrapV1`, this is derived from enterprise + generic/specific trap.
    /// For v2c/v3, this is the snmpTrapOID.0 value.
    pub fn trap_oid(&self) -> Result<Oid> {
        match self {
            Notification::TrapV1 { trap, .. } => trap.v2_trap_oid(),
            Notification::TrapV2c { trap_oid, .. }
            | Notification::TrapV3 { trap_oid, .. }
            | Notification::InformV2c { trap_oid, .. }
            | Notification::InformV3 { trap_oid, .. } => Ok(trap_oid.clone()),
        }
    }

    /// Returns the uptime value (`sysUpTime.0` or `time_stamp` for SNMPv1).
    pub fn uptime(&self) -> u32 {
        match self {
            Notification::TrapV1 { trap, .. } => trap.time_stamp,
            Notification::TrapV2c { uptime, .. }
            | Notification::TrapV3 { uptime, .. }
            | Notification::InformV2c { uptime, .. }
            | Notification::InformV3 { uptime, .. } => *uptime,
        }
    }

    /// Returns the variable bindings.
    pub fn varbinds(&self) -> &[VarBind] {
        match self {
            Notification::TrapV1 { trap, .. } => &trap.varbinds,
            Notification::TrapV2c { varbinds, .. }
            | Notification::TrapV3 { varbinds, .. }
            | Notification::InformV2c { varbinds, .. }
            | Notification::InformV3 { varbinds, .. } => varbinds,
        }
    }

    /// Returns the security level at which the notification was received.
    ///
    /// Returns `None` for v1/v2c notifications (community-based, no USM
    /// security level); their community and content are cleartext and not
    /// cryptographically authenticated. For v3 notifications,
    /// `NoAuthNoPriv` means the username, context, and content are unverified
    /// and spoofable. `AuthNoPriv` and `AuthPriv` authenticate those fields.
    pub fn security_level(&self) -> Option<SecurityLevel> {
        match self {
            Notification::TrapV1 { .. }
            | Notification::TrapV2c { .. }
            | Notification::InformV2c { .. } => None,
            Notification::TrapV3 { security_level, .. }
            | Notification::InformV3 { security_level, .. } => Some(*security_level),
        }
    }

    /// Check if this is a confirmed notification (`InformRequest`).
    pub fn is_confirmed(&self) -> bool {
        matches!(
            self,
            Notification::InformV2c { .. } | Notification::InformV3 { .. }
        )
    }

    /// Returns the SNMP version of this notification.
    pub fn version(&self) -> Version {
        match self {
            Notification::TrapV1 { .. } => Version::V1,
            Notification::TrapV2c { .. } | Notification::InformV2c { .. } => Version::V2c,
            Notification::TrapV3 { .. } | Notification::InformV3 { .. } => Version::V3,
        }
    }
}

/// SNMP Notification Receiver.
///
/// Receives SNMP traps and informs on UDP endpoints, TCP listeners, and
/// configured TCP sessions.
///
/// For accepted `InformRequest` notifications, automatic mode finalizes and
/// attempts the ordinary Response-PDU before delivery. Application-controlled
/// mode returns a pending acknowledgement for explicit completion. In either
/// mode, the receiver discards an Inform before delivery if its ordinary
/// response exceeds the size limit. It attempts the `tooBig` alternate when it
/// fits or counts a silent drop.
///
/// # SNMPv3 authentication
///
/// To receive authenticated V3 notifications, use the builder pattern to
/// configure USM credentials and persisted authoritative engine state:
///
/// ```rust,no_run
/// use async_snmp::notification::{NotificationAdmissionDecision, NotificationReceiver};
/// use async_snmp::{AuthProtocol, AuthoritativeEngine, SecurityLevel};
/// use std::convert::Infallible;
///
/// # async fn example() -> Result<(), Box<async_snmp::Error>> {
/// # // Replace this no-op with durable storage in an application.
/// let engine = AuthoritativeEngine::install(b"receiver-engine".to_vec(), |_| {
///     Ok::<(), Infallible>(())
/// })?;
/// let mut receiver = NotificationReceiver::builder()
///     .bind("0.0.0.0:162")
///     .authoritative_engine(engine)
///     .usm_user("trapuser", |u| {
///         u.auth(AuthProtocol::Sha1, b"authpassword")
///     }).unwrap()
///     .admission_policy(|notification| {
///         if notification.security_level >= Some(SecurityLevel::AuthNoPriv) {
///             NotificationAdmissionDecision::Admit
///         } else {
///             NotificationAdmissionDecision::Reject
///         }
///     })
///     .spawn()
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct NotificationReceiver {
    network: Arc<crate::transport::network::NetworkState>,
    inner: Arc<ReceiverInner>,
    events: mpsc::Receiver<ReceivedNotification>,
    state: Arc<lifecycle::ServiceState>,
    pub(crate) lease: Arc<NotificationLease>,
}

/// Application protocol state, independent of socket and public lifetime ownership.
#[derive(Clone)]
pub(crate) struct NotificationRole {
    inner: Arc<ReceiverInner>,
}

struct PreparedNotificationRole {
    local_engine: crate::LocalEngine,
    security_context: crate::UsmSecurityContext,
    requires_policy: bool,
    capacity_registration: Option<crate::ReceiveCapacityRegistration>,
}

struct ReceiverInner {
    protocol: NotificationProcessor,
    max_processing: usize,
    active: std::sync::atomic::AtomicUsize,
    idle: tokio::sync::Notify,
    #[cfg(test)]
    udp_responder: Option<Arc<UdpResponder>>,
    #[cfg(test)]
    endpoint_id: crate::EndpointId,
    delivery: Arc<Delivery>,
    pending: Arc<pending::PendingRegistry>,
    acknowledgement_mode: InformAcknowledgementMode,
    pending_inform_timeout: Duration,
    response_send_timeout: Duration,
    #[cfg(test)]
    response_send_gate: Mutex<Option<Arc<tokio::sync::Semaphore>>>,
    #[cfg(test)]
    response_sends_started: AtomicU32,
    #[cfg(test)]
    response_send_errors: Mutex<std::collections::VecDeque<std::io::Error>>,
    #[cfg(test)]
    response_construction_errors: Mutex<std::collections::VecDeque<Box<Error>>>,
    #[cfg(test)]
    receive_errors: Arc<Mutex<std::collections::VecDeque<std::io::Error>>>,
    #[cfg(test)]
    receive_error_ready: Arc<tokio::sync::Notify>,
}

impl ReceiverInner {
    #[cfg(test)]
    fn publish_authoritative_boots_time(&self, pair: (u32, u32)) -> (u32, u32) {
        self.local_engine.publish_boots_time(pair)
    }
}

impl std::ops::Deref for ReceiverInner {
    type Target = processor::ProcessorInner;
    fn deref(&self) -> &Self::Target {
        &self.protocol.inner
    }
}

use crate::v3::local::unpack_boots_time;

impl NotificationReceiver {
    /// Create a builder for configuring the notification receiver.
    ///
    /// Use this to configure varbind validation or USM credentials for V3
    /// authentication.
    #[must_use]
    pub fn builder() -> NotificationReceiverBuilder {
        NotificationReceiverBuilder::new()
    }

    /// Return the receiver's `snmpSilentDrops` value.
    ///
    /// This counter increments when the receiver discards an Inform during
    /// protocol processing because both the ordinary response and its exact
    /// empty-varbind `tooBig` alternate exceed the effective size limit.
    #[must_use]
    pub fn snmp_silent_drops(&self) -> u32 {
        self.inner.snmp_silent_drops.load(Ordering::Relaxed)
    }

    /// Bind to a local address.
    ///
    /// The standard SNMP notification port is 162. This construction path uses
    /// [`NotificationVarbindValidation::Tolerant`]; use the builder to select
    /// strict validation.
    ///
    /// A receiver constructed this way handles v1 and v2c notifications
    /// only: it has no USM user table, so every v3 notification (including
    /// noAuthNoPriv) is rejected with `usmStatsUnknownUserNames` (RFC 3414
    /// Section 3.2 Step 4). To receive v3 notifications, use
    /// [`NotificationReceiver::builder()`] and register users with
    /// `usm_user`.
    ///
    /// This path configures no community allowlist. Received v1/v2c community
    /// strings and content are therefore cleartext, unverified, and spoofable;
    /// use [`NotificationReceiverBuilder::community`] to require a configured
    /// community value.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use async_snmp::notification::NotificationReceiver;
    ///
    /// # async fn example() -> Result<(), Box<async_snmp::Error>> {
    /// // Bind to the standard trap port (requires root/admin on most systems)
    /// let mut receiver = NotificationReceiver::spawn("0.0.0.0:162").await?;
    ///
    /// // Or use an unprivileged port for testing
    /// let mut receiver = NotificationReceiver::spawn("0.0.0.0:1162").await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error when the address is invalid, the socket cannot be
    /// created, or the operating system cannot provide randomness for the
    /// receiver's engine ID.
    pub async fn spawn(addr: impl AsRef<str>) -> Result<RunningNotificationReceiver> {
        Self::builder().bind(addr.as_ref()).spawn().await
    }

    #[cfg(test)]
    async fn bind_with_engine_id_generator(
        addr: impl AsRef<str>,
        generate_engine_id: impl FnOnce() -> Result<Bytes>,
    ) -> Result<PreparedNotificationReceiver> {
        Self::builder()
            .bind(addr.as_ref())
            .prepare_with_engine_id_generator(generate_engine_id)
            .await
    }

    #[cfg(test)]
    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.network.bound[0].local_addr
    }

    /// Return the configured notification decode configuration.
    #[must_use]
    pub fn decode_config(&self) -> crate::DecodeConfig {
        self.inner.decode_config
    }

    /// Shared local engine state, independent of this receiver's endpoints.
    pub fn local_engine(&self) -> crate::LocalEngine {
        self.inner.local_engine.clone()
    }

    /// Returns the local engine ID.
    ///
    /// With an [`AuthoritativeEngine`] this is the stable persisted V3
    /// identity. A receiver without USM users instead has a generated
    /// process-local ID.
    #[must_use]
    pub fn engine_id(&self) -> &[u8] {
        &self.inner.engine_id
    }

    /// Returns the most recently sampled local engine boots value.
    ///
    /// Any role sharing the local engine can sample its authoritative clock.
    /// Rollover increments are stored through the retained persistence callback
    /// before publication. This getter does not sample the clock or run the
    /// persistence callback; it reads the latest shared snapshot.
    #[must_use]
    pub fn engine_boots(&self) -> u32 {
        unpack_boots_time(self.inner.authoritative_snapshot.load(Ordering::Relaxed)).0
    }

    /// Returns the usmStatsUnknownEngineIDs counter value.
    #[must_use]
    pub fn usm_unknown_engine_ids(&self) -> u32 {
        self.inner
            .usm_stats
            .unknown_engine_ids
            .load(Ordering::Relaxed)
    }

    /// Returns the usmStatsUnknownUserNames counter value.
    #[must_use]
    pub fn usm_unknown_usernames(&self) -> u32 {
        self.inner
            .usm_stats
            .unknown_usernames
            .load(Ordering::Relaxed)
    }

    /// Returns the usmStatsWrongDigests counter value.
    #[must_use]
    pub fn usm_wrong_digests(&self) -> u32 {
        self.inner.usm_stats.wrong_digests.load(Ordering::Relaxed)
    }

    /// Returns the usmStatsNotInTimeWindows counter value.
    #[must_use]
    pub fn usm_not_in_time_windows(&self) -> u32 {
        self.inner
            .usm_stats
            .not_in_time_windows
            .load(Ordering::Relaxed)
    }

    /// Returns the usmStatsUnsupportedSecLevels counter value.
    #[must_use]
    pub fn usm_unsupported_sec_levels(&self) -> u32 {
        self.inner
            .usm_stats
            .unsupported_sec_levels
            .load(Ordering::Relaxed)
    }

    /// Returns the usmStatsDecryptionErrors counter value.
    #[must_use]
    pub fn usm_decryption_errors(&self) -> u32 {
        self.inner
            .usm_stats
            .decryption_errors
            .load(Ordering::Relaxed)
    }
}

impl NotificationRole {
    #[cfg(test)]
    fn test_message(
        &self,
        data: Bytes,
        source: SocketAddr,
        destination: Option<crate::udp_responder::DestinationMetadata>,
    ) -> crate::transport::ReceivedMessage {
        let received = ReceivedDatagram {
            len: data.len(),
            source,
            destination,
        };
        let responder = self.inner.udp_responder.clone().expect("UDP test fixture");
        let info = crate::ReceivedMessageInfo::udp(
            self.inner.endpoint_id,
            responder.test_socket(|socket| socket.local_addr().unwrap()),
            source,
            destination.map(|destination| destination.ip),
            tokio::time::Instant::now(),
            data.len(),
        );
        crate::transport::ReceivedMessage::udp(
            data,
            info,
            responder,
            received,
            crate::transport::ProcessingLimits::UDP,
        )
    }

    async fn send_response(
        &self,
        data: bytes::Bytes,
        route: &crate::transport::ReplyRoute,
    ) -> Result<()> {
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.response_send_timeout)
            .expect("response send timeout validated by builder");
        self.send_response_before(data, route, deadline).await
    }

    async fn send_response_before(
        &self,
        data: bytes::Bytes,
        route: &crate::transport::ReplyRoute,
        deadline: tokio::time::Instant,
    ) -> Result<()> {
        let started = tokio::time::Instant::now();
        if started >= deadline {
            return Err(route.timeout_error(started));
        }
        #[cfg(test)]
        let response_send_gate = self.inner.response_send_gate.lock().unwrap().clone();
        tokio::select! {
            biased;
            () = tokio::time::sleep_until(deadline) => Err(route.timeout_error(started)),
            result = async {
                #[cfg(test)]
                self.inner.response_sends_started.fetch_add(1, Ordering::Relaxed);
                #[cfg(test)]
                if let Some(source) = self.inner.response_send_errors.lock().unwrap().pop_front() {
                    return Err(Error::Network { target: route.peer_addr(), source }.boxed());
                }
                #[cfg(test)]
                if let Some(gate) = &response_send_gate {
                    gate.acquire().await.expect("test send gate remains open").forget();
                }
                route.send_before(data, deadline).await
            } => result,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use super::*;

    #[tokio::test]
    async fn invalid_response_send_timeout_precedes_bind() {
        let error = NotificationReceiver::builder()
            .bind("not a socket address")
            .response_send_timeout(Duration::MAX)
            .spawn()
            .await
            .err()
            .expect("invalid timeout must fail");
        assert!(matches!(
            *error,
            Error::Config(ref message) if message.contains("notification response send timeout")
        ));
    }

    #[tokio::test]
    async fn decoding_policy_defaults_strict_preset_and_targeted_override() {
        let default = NotificationReceiver::spawn("127.0.0.1:0").await.unwrap();
        assert_eq!(default.decode_config(), crate::DecodeConfig::DEFAULT);

        let mut targeted = crate::DecodeConfig::STRICT;
        targeted.empty_counter64_as_zero = true;
        let configured = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .decode_config(targeted)
            .spawn()
            .await
            .unwrap();
        assert_eq!(configured.decode_config(), targeted);
    }
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    use crate::Value;
    use crate::message::SecurityLevel;
    use crate::oid;
    use crate::pdu::GenericTrap;
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    use crate::pdu::Pdu;
    use crate::util::{EmptyCommunityPolicy, community_matches};
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    use crate::v3::AuthProtocol;

    #[test]
    fn test_notification_trap_v1() {
        let trap = TrapV1Pdu::new(
            oid!(1, 3, 6, 1, 4, 1, 9999),
            [192, 168, 1, 1],
            GenericTrap::LinkDown,
            0,
            12345,
            vec![],
        );

        let notification = Notification::TrapV1 {
            community: Community::from(Bytes::from_static(b"public")),
            trap,
            decode_anomalies: Vec::new(),
        };

        assert!(!notification.is_confirmed());
        assert_eq!(notification.version(), Version::V1);
        assert_eq!(notification.uptime(), 12345);
        assert_eq!(notification.trap_oid().unwrap(), oids::link_down());
    }

    #[test]
    fn test_notification_trap_v2c() {
        let notification = Notification::TrapV2c {
            community: Community::from(Bytes::from_static(b"public")),
            uptime: 54321,
            trap_oid: oids::link_up(),
            varbinds: vec![],
            request_id: 1,
            decode_anomalies: Vec::new(),
        };

        assert!(!notification.is_confirmed());
        assert_eq!(notification.version(), Version::V2c);
        assert_eq!(notification.uptime(), 54321);
        assert_eq!(notification.trap_oid().unwrap(), oids::link_up());
    }

    #[test]
    fn test_notification_inform() {
        let notification = Notification::InformV2c {
            community: Community::from(Bytes::from_static(b"public")),
            uptime: 11111,
            trap_oid: oids::cold_start(),
            varbinds: vec![],
            request_id: 42,
            decode_anomalies: Vec::new(),
        };

        assert!(notification.is_confirmed());
        assert_eq!(notification.version(), Version::V2c);
    }

    #[test]
    fn test_notification_receiver_builder_default() {
        let builder = NotificationReceiverBuilder::new();
        assert_eq!(builder.bind_addr, "0.0.0.0:162");
        assert!(builder.usm_users.is_empty());
        assert_eq!(
            builder.varbind_validation,
            NotificationVarbindValidation::Tolerant
        );
        assert_eq!(
            NotificationVarbindValidation::default(),
            NotificationVarbindValidation::Tolerant
        );
    }

    #[test]
    fn test_notification_receiver_builder_varbind_validation() {
        let builder = NotificationReceiverBuilder::new()
            .varbind_validation(NotificationVarbindValidation::Strict);
        assert_eq!(
            builder.varbind_validation,
            NotificationVarbindValidation::Strict
        );
    }

    #[test]
    fn admission_policy_ignored_argument_is_inferred() {
        let _builder = NotificationReceiverBuilder::new()
            .admission_policy(|_| NotificationAdmissionDecision::Admit);
    }

    #[tokio::test]
    async fn convenience_bind_matches_default_builder_configuration() {
        let built = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .spawn()
            .await
            .unwrap();
        let bound = NotificationReceiver::spawn("127.0.0.1:0").await.unwrap();

        for receiver in [&bound, &built] {
            assert!(receiver.inner.authoritative_engine.is_none());
            assert!(receiver.inner.security_context.snapshot().is_empty());
            assert!(receiver.inner.communities.is_empty());
            assert_eq!(
                receiver.inner.varbind_validation,
                NotificationVarbindValidation::Tolerant
            );
            crate::v3::validate_engine_id(receiver.engine_id()).unwrap();
            assert!(receiver.inner.local_engine.salt_counter().is_none());
            assert_eq!(receiver.inner.engine_boots_base, 1);
            assert!(
                receiver
                    .inner
                    .security_context
                    .remote_engines()
                    .lock()
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(
                receiver.inner.max_message_size,
                crate::UDP_RECEIVE_LIMITS.advertised().as_usize()
            );
            assert_eq!(receiver.inner.decode_config, crate::DecodeConfig::default());
            assert_eq!(receiver.snmp_silent_drops(), 0);
            assert!(receiver.inner.admission_policy.is_none());
            assert_eq!(
                receiver
                    .inner
                    .udp_responder
                    .as_ref()
                    .unwrap()
                    .test_socket(|socket| socket.local_addr().unwrap()),
                receiver.local_addr()
            );
        }

        assert_ne!(bound.engine_id(), built.engine_id());

        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        for receiver in [&bound, &built] {
            let notification = receiver
                .handle_v2c(build_v2c_trap(b"not-preconfigured"), source)
                .await
                .unwrap();
            assert!(matches!(
                notification,
                Some(ReceivedNotification {
                    notification: Notification::TrapV2c { .. },
                    ..
                })
            ));
        }
    }

    fn unavailable_engine_id() -> Result<Bytes> {
        Err(Box::new(Error::RandomSource {
            source: getrandom::Error::UNEXPECTED,
        }))
    }

    #[tokio::test]
    async fn bind_errors_precede_engine_id_entropy_for_both_paths() {
        let bound_error = NotificationReceiver::bind_with_engine_id_generator(
            "not a socket address",
            unavailable_engine_id,
        )
        .await
        .err()
        .expect("invalid convenience bind must fail");
        let built_error = NotificationReceiver::builder()
            .bind("not a socket address")
            .prepare_with_engine_id_generator(unavailable_engine_id)
            .await
            .err()
            .expect("invalid builder bind must fail");
        assert_eq!(bound_error.to_string(), built_error.to_string());
        assert!(matches!(
            *bound_error,
            Error::Config(ref message)
                if message.as_ref() == "invalid bind address: not a socket address"
        ));

        let occupied = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let occupied_addr = occupied.local_addr().unwrap();
        let bound_error = NotificationReceiver::bind_with_engine_id_generator(
            occupied_addr.to_string(),
            unavailable_engine_id,
        )
        .await
        .err()
        .expect("occupied convenience bind must fail");
        let built_error = NotificationReceiver::builder()
            .bind(occupied_addr.to_string())
            .prepare_with_engine_id_generator(unavailable_engine_id)
            .await
            .err()
            .expect("occupied builder bind must fail");
        for error in [bound_error, built_error] {
            assert!(matches!(
                *error,
                Error::Network { target, ref source }
                    if target == occupied_addr
                        && source.kind() == std::io::ErrorKind::AddrInUse
            ));
        }
    }

    #[tokio::test]
    async fn engine_id_entropy_failure_releases_socket_for_both_paths() {
        let reservation = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = reservation.local_addr().unwrap();
        drop(reservation);

        let built_error = NotificationReceiver::builder()
            .bind(addr.to_string())
            .prepare_with_engine_id_generator(unavailable_engine_id)
            .await
            .err()
            .expect("builder entropy failure must fail");
        assert_eq!(built_error.kind(), crate::ErrorKind::RandomSource);
        let rebound = UdpSocket::bind(addr).await.unwrap();
        drop(rebound);

        let bound_error = NotificationReceiver::bind_with_engine_id_generator(
            addr.to_string(),
            unavailable_engine_id,
        )
        .await
        .err()
        .expect("convenience entropy failure must fail");
        assert_eq!(bound_error.kind(), crate::ErrorKind::RandomSource);
        let _rebound = UdpSocket::bind(addr).await.unwrap();
    }

    #[tokio::test]
    async fn configured_engine_id_avoids_engine_id_entropy() {
        let configured_engine_id = b"receiver-engine";
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .engine_id(configured_engine_id.to_vec())
            .prepare_with_engine_id_generator(|| panic!("engine ID generator must not be called"))
            .await
            .unwrap();

        assert_eq!(receiver.receiver.engine_id(), configured_engine_id);
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[test]
    fn test_notification_receiver_builder_with_user() {
        let builder = NotificationReceiverBuilder::new()
            .bind("0.0.0.0:1162")
            .usm_user("trapuser", |u| u.auth(AuthProtocol::Sha1, b"authpass"))
            .unwrap();

        assert_eq!(builder.bind_addr, "0.0.0.0:1162");
        assert_eq!(builder.usm_users.len(), 1);

        let user = builder
            .usm_users
            .get(&Bytes::from_static(b"trapuser"))
            .unwrap();
        assert_eq!(user.maximum_security_level(), SecurityLevel::AuthNoPriv);
    }

    #[tokio::test]
    async fn test_v3_receiver_requires_authoritative_engine_before_bind() {
        let result = NotificationReceiver::builder()
            .bind("not a socket address")
            .usm_user("user", Ok)
            .unwrap()
            .admit_all_notifications()
            .spawn()
            .await;

        let err = result.err().expect("expected build to fail");
        assert!(matches!(
            *err,
            Error::Config(ref message)
                if message.contains("authoritative engine state is required")
        ));
    }

    #[tokio::test]
    async fn v3_receiver_requires_explicit_admission_policy_before_bind() {
        let result = NotificationReceiver::builder()
            .bind("not a socket address")
            .usm_user("user", Ok)
            .unwrap()
            .spawn()
            .await;
        let error = result.err().expect("missing receiver policy must fail");
        assert!(matches!(
            *error,
            Error::Config(ref message) if message.contains("requires an admission policy")
        ));
    }

    #[tokio::test]
    async fn test_invalid_usm_user_is_rejected_before_bind() {
        let result = NotificationReceiver::builder()
            .bind("not a socket address")
            .usm_user("", Ok)
            .unwrap()
            .admit_all_notifications()
            .spawn()
            .await;

        let err = result.err().expect("expected build to fail");
        assert!(matches!(
            *err,
            Error::Config(ref message) if message.contains("USM username")
        ));
    }

    #[tokio::test]
    async fn test_receiver_authoritative_engine_persistence_failure_precedes_bind() {
        let engine = AuthoritativeEngine::with_rollover_persistence_failure_for_test(
            b"test-receiver-engine".to_vec(),
        );
        let result = NotificationReceiver::builder()
            .bind("not a socket address")
            .authoritative_engine(engine)
            .spawn()
            .await;

        let err = result.err().expect("expected build to fail");
        assert_eq!(err.kind(), crate::ErrorKind::AuthoritativeEnginePersistence);
        let persistence = err
            .authoritative_engine_persistence()
            .expect("receiver must preserve the persistence failure");
        assert_eq!(
            persistence.operation(),
            crate::AuthoritativeEnginePersistenceOperation::EngineTimeRollover
        );
        assert_eq!(persistence.previous_engine_boots(), Some(1));
        assert_eq!(persistence.attempted_engine_boots(), 2);
        assert_eq!(
            persistence
                .downcast_source_ref::<std::io::Error>()
                .expect("concrete callback error")
                .kind(),
            std::io::ErrorKind::Other
        );
        assert!(err.to_string().contains("storage unavailable"));
    }

    #[tokio::test]
    async fn receiver_engine_boots_is_pure_and_v3_processing_reports_rollover_failure() {
        let calls = Arc::new(AtomicUsize::new(0));
        let callback_calls = Arc::clone(&calls);
        let engine = AuthoritativeEngine::install(b"test-receiver-engine".to_vec(), move |_| {
            if callback_calls.fetch_add(1, Ordering::Relaxed) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::other("rollover persistence unavailable"))
            }
        })
        .unwrap();
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .authoritative_engine(engine)
            .spawn()
            .await
            .unwrap();
        receiver
            .inner
            .authoritative_engine
            .as_ref()
            .unwrap()
            .set_elapsed_for_test(u64::from(crate::v3::MAX_ENGINE_TIME) + 1);

        assert_eq!(receiver.engine_boots(), 1);
        assert_eq!(calls.load(Ordering::Relaxed), 1);

        let error = receiver
            .handle_v3(
                build_v3_discovery_request(1, true),
                "127.0.0.1:1162".parse().unwrap(),
            )
            .await
            .unwrap_err();
        assert_eq!(
            error.kind(),
            crate::ErrorKind::AuthoritativeEnginePersistence
        );
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        assert_eq!(receiver.engine_boots(), 1);
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[tokio::test]
    async fn runner_reports_pre_acceptance_persistence_degradation() {
        let engine_id = Bytes::from_static(b"local-persist-engine");
        let calls = Arc::new(AtomicUsize::new(0));
        let callback_calls = Arc::clone(&calls);
        let engine = AuthoritativeEngine::install(engine_id.clone(), move |_| {
            if callback_calls.fetch_add(1, Ordering::Relaxed) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::other("persistence unavailable"))
            }
        })
        .unwrap();
        let mut receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .authoritative_engine(engine.clone())
            .usm_user("informuser", |user| {
                user.auth(AuthProtocol::Sha1, b"authpass12345678")
            })
            .unwrap()
            .admit_all_notifications()
            .spawn()
            .await
            .unwrap();
        engine.set_elapsed_for_test(u64::from(crate::v3::MAX_ENGINE_TIME) + 1);
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender
            .send_to(
                &build_authed_v3_inform(
                    &engine_id,
                    1,
                    0,
                    b"informuser",
                    b"authpass12345678",
                    AuthProtocol::Sha1,
                ),
                receiver.local_addr(),
            )
            .await
            .unwrap();

        let mut health = receiver.control().subscribe_health();
        tokio::time::timeout(Duration::from_secs(1), async {
            while *health.borrow_and_update() == NotificationHealth::Healthy {
                health.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        assert!(matches!(
            receiver.control().health(),
            NotificationHealth::AuthoritativePersistenceDegraded { .. }
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(20), receiver.recv())
                .await
                .is_err()
        );
        assert_eq!(receiver.control().status(), NotificationStatus::Running);
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[tokio::test]
    async fn completion_persistence_failure_does_not_block_remote_trap() {
        let engine_id = Bytes::from_static(b"local-persist-engine-2");
        let calls = Arc::new(AtomicUsize::new(0));
        let callback_calls = Arc::clone(&calls);
        let engine = AuthoritativeEngine::install(engine_id.clone(), move |_| {
            if callback_calls.fetch_add(1, Ordering::Relaxed) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::other("persistence unavailable"))
            }
        })
        .unwrap();
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .authoritative_engine(engine.clone())
            .usm_user("informuser", Ok)
            .unwrap()
            .usm_user("trapuser", |user| {
                user.auth(AuthProtocol::Sha1, b"authpass12345678")
            })
            .unwrap()
            .admit_all_notifications()
            .acknowledgement_mode(InformAcknowledgementMode::ApplicationControlled)
            .spawn()
            .await
            .unwrap();

        let inform = receiver
            .handle_v3(
                build_noauth_v3_inform(&engine_id, b"informuser"),
                "127.0.0.1:9999".parse().unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        let NotificationAcknowledgement::Pending(pending) = inform.inform_ack else {
            panic!("expected a pending acknowledgement");
        };
        engine.set_elapsed_for_test(u64::from(crate::v3::MAX_ENGINE_TIME) + 1);
        assert!(matches!(
            pending.acknowledge().await,
            InformAckOutcome::Failed(error)
                if error.kind() == crate::ErrorKind::AuthoritativeEnginePersistence
        ));
        let calls_after_failure = calls.load(Ordering::Relaxed);

        let trap = receiver
            .handle_v3(
                build_authed_v3_trap(b"remote-sender-engine", 7, 123_456),
                "127.0.0.1:9999".parse().unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(trap.notification, Notification::TrapV3 { .. }));
        assert!(matches!(
            trap.inform_ack,
            NotificationAcknowledgement::NotRequired
        ));
        assert_eq!(
            calls.load(Ordering::Relaxed),
            calls_after_failure,
            "remote-authoritative trap must not sample local persistence"
        );
    }

    #[tokio::test]
    async fn receiver_snapshot_rejects_delayed_pre_rollover_clone_sample() {
        let stored = Arc::new(Mutex::new(Vec::new()));
        let stored_for_callback = Arc::clone(&stored);
        let engine = AuthoritativeEngine::install(b"test-receiver-engine".to_vec(), move |state| {
            stored_for_callback
                .lock()
                .unwrap()
                .push(state.engine_boots());
            Ok::<(), std::convert::Infallible>(())
        })
        .unwrap();
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .authoritative_engine(engine)
            .spawn()
            .await
            .unwrap();
        let cycle = u64::from(crate::v3::MAX_ENGINE_TIME) + 1;
        let stale_sampled = Arc::new(std::sync::Barrier::new(2));
        let rollover_published = Arc::new(std::sync::Barrier::new(2));

        let stale_inner = Arc::clone(&receiver.inner);
        let stale_engine = stale_inner.authoritative_engine.as_ref().unwrap().clone();
        let stale_sampled_thread = Arc::clone(&stale_sampled);
        let rollover_published_thread = Arc::clone(&rollover_published);
        let stale = std::thread::spawn(move || {
            let pair = stale_engine
                .current_boots_time_at_for_test(cycle - 1)
                .unwrap();
            assert_eq!(pair, (1, crate::v3::MAX_ENGINE_TIME));
            stale_sampled_thread.wait();
            rollover_published_thread.wait();
            stale_inner.publish_authoritative_boots_time(pair)
        });

        stale_sampled.wait();
        let current = receiver
            .inner
            .authoritative_engine
            .as_ref()
            .unwrap()
            .current_boots_time_at_for_test(cycle)
            .unwrap();
        assert_eq!(current, (2, 0));
        assert_eq!(
            receiver.inner.publish_authoritative_boots_time(current),
            (2, 0)
        );
        rollover_published.wait();

        assert_eq!(stale.join().unwrap(), (2, 0));
        assert_eq!(receiver.engine_boots(), 2);
        assert_eq!(
            unpack_boots_time(
                receiver
                    .inner
                    .authoritative_snapshot
                    .load(Ordering::Relaxed)
            ),
            (2, 0)
        );
        assert_eq!(stored.lock().unwrap().as_slice(), &[1, 2]);
    }

    #[test]
    fn test_notification_v3_inform() {
        let notification = Notification::InformV3 {
            username: Bytes::from_static(b"testuser"),
            context_engine_id: Bytes::from_static(b"engine123"),
            context_name: Bytes::new(),
            security_level: SecurityLevel::AuthNoPriv,
            uptime: 99999,
            trap_oid: oids::warm_start(),
            varbinds: vec![],
            request_id: 100,
            decode_anomalies: Vec::new(),
        };

        assert!(notification.is_confirmed());
        assert_eq!(notification.version(), Version::V3);
        assert_eq!(notification.uptime(), 99999);
        assert_eq!(notification.trap_oid().unwrap(), oids::warm_start());
    }

    #[test]
    fn test_notification_security_level_accessor() {
        let trap_v3 = Notification::TrapV3 {
            username: Bytes::from_static(b"testuser"),
            context_engine_id: Bytes::from_static(b"engine123"),
            context_name: Bytes::new(),
            security_level: SecurityLevel::AuthPriv,
            uptime: 1,
            trap_oid: oids::cold_start(),
            varbinds: vec![],
            request_id: 1,
            decode_anomalies: Vec::new(),
        };
        assert_eq!(trap_v3.security_level(), Some(SecurityLevel::AuthPriv));

        let inform_v3 = Notification::InformV3 {
            username: Bytes::from_static(b"testuser"),
            context_engine_id: Bytes::from_static(b"engine123"),
            context_name: Bytes::new(),
            security_level: SecurityLevel::NoAuthNoPriv,
            uptime: 1,
            trap_oid: oids::cold_start(),
            varbinds: vec![],
            request_id: 1,
            decode_anomalies: Vec::new(),
        };
        assert_eq!(
            inform_v3.security_level(),
            Some(SecurityLevel::NoAuthNoPriv)
        );

        let trap_v2c = Notification::TrapV2c {
            community: Community::from(Bytes::from_static(b"public")),
            uptime: 1,
            trap_oid: oids::cold_start(),
            varbinds: vec![],
            request_id: 1,
            decode_anomalies: Vec::new(),
        };
        assert_eq!(trap_v2c.security_level(), None);
    }

    #[test]
    fn test_notification_trap_v1_enterprise_specific_oid() {
        let trap = TrapV1Pdu::new(
            oid!(1, 3, 6, 1, 4, 1, 9999, 1, 2),
            [192, 168, 1, 1],
            GenericTrap::EnterpriseSpecific,
            42,
            12345,
            vec![],
        );

        let notification = Notification::TrapV1 {
            community: Community::from(Bytes::from_static(b"public")),
            trap,
            decode_anomalies: Vec::new(),
        };

        assert_eq!(
            notification.trap_oid().unwrap(),
            oid!(1, 3, 6, 1, 4, 1, 9999, 1, 2, 0, 42)
        );
    }

    #[test]
    fn test_compute_engine_boots_time_basic() {
        let (boots, time) = crate::v3::compute_engine_boots_time(1, 1000);
        assert_eq!(boots, 1);
        assert_eq!(time, 1000);
    }

    #[test]
    fn test_compute_engine_boots_time_zero_elapsed() {
        let (boots, time) = crate::v3::compute_engine_boots_time(1, 0);
        assert_eq!(boots, 1);
        assert_eq!(time, 0);
    }

    #[test]
    fn test_builder_authoritative_engine_default() {
        let builder = NotificationReceiverBuilder::new();
        assert!(builder.authoritative_engine.is_none());
    }

    #[test]
    fn test_builder_authoritative_engine_custom() {
        let engine = AuthoritativeEngine::for_test(b"test-engine".to_vec(), 5);
        let builder = NotificationReceiverBuilder::new().authoritative_engine(engine);
        assert_eq!(builder.authoritative_engine.unwrap().engine_boots(), 5);
    }

    /// Build a V3 notification message of the given PDU type with the given
    /// `engine_boots` and `engine_time` in the USM parameters. With
    /// `auth: Some((password, protocol))` the message is AuthNoPriv with a
    /// valid HMAC; with `None` it is noAuthNoPriv.
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    fn build_v3_notification(
        pdu_type: crate::pdu::PduType,
        engine_id: &[u8],
        engine_boots: u32,
        engine_time: u32,
        username: &[u8],
        auth: Option<(&[u8], AuthProtocol)>,
    ) -> Bytes {
        build_v3_notification_with_max(
            pdu_type,
            engine_id,
            engine_boots,
            engine_time,
            username,
            auth,
            65507,
        )
    }

    /// As [`build_v3_notification`], but with an explicit advertised
    /// `msg_max_size` in the message header.
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    fn build_v3_notification_with_max(
        pdu_type: crate::pdu::PduType,
        engine_id: &[u8],
        engine_boots: u32,
        engine_time: u32,
        username: &[u8],
        auth: Option<(&[u8], AuthProtocol)>,
        msg_max_size: i32,
    ) -> Bytes {
        use crate::message::{MsgFlags, MsgGlobalData, ScopedPdu, V3Message};
        use crate::pdu::Pdu;
        use crate::v3::auth::authenticate_message;
        use crate::v3::{LocalizedKey, UsmSecurityParams};
        use crate::value::Value;

        let auth_key = auth.map(|(password, protocol)| {
            LocalizedKey::from_password(protocol, password, engine_id).unwrap()
        });

        // Build a notification PDU with sysUpTime.0 and snmpTrapOID.0
        let pdu = Pdu::standard(
            crate::pdu::StandardPduType::try_from(pdu_type).unwrap(),
            1,
            0,
            0,
            vec![
                VarBind::new(oids::sys_uptime(), Value::TimeTicks(1000)),
                VarBind::new(
                    oids::snmp_trap_oid(),
                    Value::ObjectIdentifier(oids::cold_start()),
                ),
            ],
        );

        let level = if auth_key.is_some() {
            SecurityLevel::AuthNoPriv
        } else {
            SecurityLevel::NoAuthNoPriv
        };
        // Informs are Confirmed Class and are sent with the reportableFlag
        // set; traps are Unconfirmed Class and are not (RFC 3412 Section 6.4).
        let reportable = pdu_type == crate::pdu::PduType::InformRequest;
        let global = MsgGlobalData::new(
            1,
            crate::MessageSize::from_i32(msg_max_size).unwrap(),
            MsgFlags::new(level, reportable),
        )
        .unwrap();

        let mut usm_params = UsmSecurityParams::new(
            Bytes::copy_from_slice(engine_id),
            engine_boots,
            engine_time,
            Bytes::copy_from_slice(username),
        )
        .unwrap();
        if let Some(key) = &auth_key {
            usm_params = usm_params.with_auth_placeholder(key.mac_len()).unwrap();
        }

        let scoped = ScopedPdu::new(Bytes::copy_from_slice(engine_id), Bytes::new(), pdu);
        let msg = V3Message::new(global, usm_params.encode().unwrap(), scoped).unwrap();
        let mut msg_bytes = msg.encode().unwrap().to_vec();

        // Compute and insert HMAC
        if let Some(key) = &auth_key {
            let (auth_offset, auth_len) =
                UsmSecurityParams::find_auth_params_offset(&msg_bytes).unwrap();
            authenticate_message(key, &mut msg_bytes, auth_offset, auth_len).unwrap();
        }

        Bytes::from(msg_bytes)
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    fn inform_security(level: SecurityLevel, username: &[u8]) -> crate::v3::UsmConfig {
        use crate::v3::PrivProtocol;

        let username = Bytes::copy_from_slice(username);
        match level {
            SecurityLevel::NoAuthNoPriv => crate::v3::UsmConfig::new(username),
            SecurityLevel::AuthNoPriv => crate::v3::UsmConfig::new(username)
                .auth(AuthProtocol::Sha256, b"inform-auth-password")
                .unwrap(),
            SecurityLevel::AuthPriv => crate::v3::UsmConfig::new(username)
                .auth_priv(
                    AuthProtocol::Sha256,
                    b"inform-auth-password",
                    PrivProtocol::Aes128,
                    b"inform-priv-password",
                )
                .unwrap(),
        }
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    fn inform_user(level: SecurityLevel, username: &[u8]) -> crate::v3::UsmUser {
        use crate::v3::PrivProtocol;

        let username = Bytes::copy_from_slice(username);
        match level {
            SecurityLevel::NoAuthNoPriv => crate::v3::UsmUser::new(username),
            SecurityLevel::AuthNoPriv => crate::v3::UsmUser::new(username)
                .auth(AuthProtocol::Sha256, b"inform-auth-password")
                .unwrap(),
            SecurityLevel::AuthPriv => crate::v3::UsmUser::new(username)
                .auth_priv(
                    AuthProtocol::Sha256,
                    b"inform-auth-password",
                    PrivProtocol::Aes128,
                    b"inform-priv-password",
                )
                .unwrap(),
        }
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    fn build_v3_inform_at_level(
        engine_id: &[u8],
        username: &[u8],
        level: SecurityLevel,
        msg_max_size: crate::MessageSize,
    ) -> (Bytes, Pdu, crate::v3::DerivedKeys) {
        let pdu = Pdu::standard(
            crate::pdu::StandardPduType::InformRequest,
            1,
            0,
            0,
            vec![
                VarBind::new(oids::sys_uptime(), Value::TimeTicks(1000)),
                VarBind::new(
                    oids::snmp_trap_oid(),
                    Value::ObjectIdentifier(oids::cold_start()),
                ),
            ],
        );
        let config = inform_security(level, username);
        let keys = config.derive_keys(engine_id).unwrap();
        let encoded = crate::v3::encode::encode_v3_message(
            &pdu,
            1,
            engine_id,
            1,
            0,
            &config,
            Some(&keys),
            Some(&crate::v3::SaltCounter::new().unwrap()),
            None,
            None,
            true,
            msg_max_size,
        )
        .unwrap();
        (Bytes::from(encoded), pdu, keys)
    }

    /// Build an authenticated V3 `InformRequest` message with the given
    /// `engine_boots` and `engine_time` in the USM parameters.
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    pub(super) fn build_authed_v3_inform(
        engine_id: &[u8],
        engine_boots: u32,
        engine_time: u32,
        username: &[u8],
        auth_password: &[u8],
        auth_protocol: AuthProtocol,
    ) -> Bytes {
        build_v3_notification(
            crate::pdu::PduType::InformRequest,
            engine_id,
            engine_boots,
            engine_time,
            username,
            Some((auth_password, auth_protocol)),
        )
    }

    /// Build an authenticated V3 `SNMPv2-Trap` message with the given
    /// `engine_boots` and `engine_time` in the USM parameters.
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    pub(super) fn build_authed_v3_trap(
        engine_id: &[u8],
        engine_boots: u32,
        engine_time: u32,
    ) -> Bytes {
        build_v3_notification(
            crate::pdu::PduType::TrapV2,
            engine_id,
            engine_boots,
            engine_time,
            b"trapuser",
            Some((b"authpass12345678", AuthProtocol::Sha1)),
        )
    }

    /// Build an unauthenticated (noAuthNoPriv) V3 `SNMPv2-Trap` message.
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    fn build_noauth_v3_trap(engine_id: &[u8], username: &[u8]) -> Bytes {
        build_v3_notification(crate::pdu::PduType::TrapV2, engine_id, 0, 0, username, None)
    }

    /// Build a receiver with its own engine ID and a `trapuser` configured,
    /// for tests exercising traps sent under a remote sender's engine ID.
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    async fn remote_trap_receiver() -> RunningNotificationReceiver {
        NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .engine_id(b"my-receiver-engine".to_vec())
            .engine_boots(1)
            .usm_user("trapuser", |u| {
                u.auth(AuthProtocol::Sha1, b"authpass12345678")
            })
            .unwrap()
            .admit_all_notifications()
            .spawn()
            .await
            .unwrap()
    }

    /// For traps the SENDER is the authoritative engine (RFC 3414 Section
    /// 1.5.1): a real remote agent sends under its own engine ID with its
    /// own boots/time. The receiver must accept it without being configured
    /// with the sender's engine ID or clock, and the delivered notification
    /// reports the security level it was received at (RFC 3411 Section
    /// 3.4.3: securityLevel accompanies every message up to the
    /// application).
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[tokio::test]
    async fn test_v3_trap_from_remote_sender_engine_accepted() {
        let receiver = remote_trap_receiver().await;
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        // Sender's own engine ID, arbitrary boots and time
        let msg = build_authed_v3_trap(b"remote-sender-engine", 7, 123_456);

        let result = receiver.handle_v3(msg, source).await.unwrap();
        match result {
            Some(ReceivedNotification {
                notification:
                    Notification::TrapV3 {
                        username,
                        security_level,
                        ..
                    },
                ..
            }) => {
                assert_eq!(username.as_ref(), b"trapuser");
                assert_eq!(security_level, SecurityLevel::AuthNoPriv);
            }
            other => panic!("expected TrapV3, got {other:?}"),
        }
    }

    /// A noAuthNoPriv V3 trap from a configured user is delivered (no
    /// per-user minimum is enforced here) but must be distinguishable from
    /// an authenticated one via its security level.
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[tokio::test]
    async fn test_v3_noauth_trap_carries_security_level() {
        let receiver = remote_trap_receiver().await;
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let msg = build_noauth_v3_trap(b"remote-sender-engine", b"trapuser");
        match receiver.handle_v3(msg, source).await.unwrap() {
            Some(ReceivedNotification {
                notification:
                    Notification::TrapV3 {
                        security_level,
                        username,
                        ..
                    },
                ..
            }) => {
                assert_eq!(security_level, SecurityLevel::NoAuthNoPriv);
                assert_eq!(username.as_ref(), b"trapuser");
            }
            other => panic!("expected TrapV3, got {other:?}"),
        }
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[tokio::test]
    async fn receiver_policy_drops_lower_level_trap() {
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .engine_id(b"my-receiver-engine".to_vec())
            .engine_boots(1)
            .usm_user("trapuser", |user| {
                user.auth(AuthProtocol::Sha1, b"authpass12345678")
            })
            .unwrap()
            .admission_policy(|notification: &NotificationAdmissionInfo<'_>| {
                if notification.username == Some(b"trapuser")
                    && notification.security_level >= Some(SecurityLevel::AuthNoPriv)
                {
                    NotificationAdmissionDecision::Admit
                } else {
                    NotificationAdmissionDecision::Reject
                }
            })
            .spawn()
            .await
            .unwrap();
        let message = build_noauth_v3_trap(b"remote-sender-engine", b"trapuser");
        let result = receiver
            .handle_v3(message, "127.0.0.1:9999".parse().unwrap())
            .await
            .unwrap();
        assert!(result.is_none());
        assert_eq!(receiver.usm_unsupported_sec_levels(), 0);
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[tokio::test]
    async fn admission_policy_rejects_lower_security_v3_inform_before_sizing() {
        let engine_id = b"my-receiver-engine".to_vec();
        let message = build_noauth_v3_inform(&engine_id, b"informuser");
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for limit in [message.len(), message.len() - 1, 1] {
            let calls = Arc::new(AtomicU32::new(0));
            let calls_for_policy = Arc::clone(&calls);
            let receiver = NotificationReceiver::builder()
                .bind("127.0.0.1:0")
                .engine_id(engine_id.clone())
                .engine_boots(1)
                .usm_user("informuser", |user| {
                    user.auth(AuthProtocol::Sha1, b"authpass12345678")
                })
                .unwrap()
                .admission_policy(move |notification: &NotificationAdmissionInfo<'_>| {
                    assert_eq!(
                        notification.security_level,
                        Some(SecurityLevel::NoAuthNoPriv)
                    );
                    calls_for_policy.fetch_add(1, Ordering::Relaxed);
                    if notification.security_level >= Some(SecurityLevel::AuthNoPriv) {
                        NotificationAdmissionDecision::Admit
                    } else {
                        NotificationAdmissionDecision::Reject
                    }
                })
                .max_message_size(limit)
                .spawn()
                .await
                .unwrap();
            assert!(
                receiver
                    .handle_v3(message.clone(), client.local_addr().unwrap())
                    .await
                    .unwrap()
                    .is_none()
            );
            assert_eq!(calls.load(Ordering::Relaxed), 1);
            assert_eq!(receiver.snmp_silent_drops(), 0);
            assert_eq!(receiver.usm_unsupported_sec_levels(), 0);
            let mut reply = [0];
            assert!(
                tokio::time::timeout(Duration::from_millis(50), client.recv_from(&mut reply))
                    .await
                    .is_err(),
                "denied v3 Inform produced a reply at limit {limit}"
            );
        }
    }

    /// RFC 3414 Section 3.2 Step 4 is unconditional: the user must exist in
    /// the local configuration regardless of security level, so a
    /// noAuthNoPriv message from an unknown user is dropped and counted,
    /// not delivered.
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[tokio::test]
    async fn test_v3_noauth_trap_unknown_user_rejected_and_counted() {
        let receiver = remote_trap_receiver().await;
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let msg = build_noauth_v3_trap(b"remote-sender-engine", b"nosuchuser");
        let result = receiver.handle_v3(msg, source).await.unwrap();
        assert!(result.is_none(), "unknown user must not be delivered");
        assert_eq!(receiver.usm_unknown_usernames(), 1);
    }

    /// Each remote engine gets independent timeliness state: traps from
    /// multiple senders with unrelated boots/time are all accepted.
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[tokio::test]
    async fn test_v3_traps_from_multiple_remote_engines_accepted() {
        let receiver = remote_trap_receiver().await;
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let msg_a = build_authed_v3_trap(b"sender-engine-a", 7, 123_456);
        let msg_b = build_authed_v3_trap(b"sender-engine-b", 2, 42);

        assert!(
            receiver.handle_v3(msg_a, source).await.unwrap().is_some(),
            "trap from first remote engine should be accepted"
        );
        assert!(
            receiver.handle_v3(msg_b, source).await.unwrap().is_some(),
            "trap from second remote engine should be accepted"
        );
    }

    /// The remote-engine table is bounded: once `MAX_REMOTE_ENGINES` entries
    /// exist, an authenticated trap under a new engine ID evicts an old entry
    /// rather than growing the map, so a credential holder cannot exhaust
    /// memory by fabricating engine IDs.
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[tokio::test]
    async fn test_v3_remote_engines_table_bounded() {
        let receiver = remote_trap_receiver().await;
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        // Pre-fill the table to capacity with cheap dummy entries.
        {
            let mut engines = receiver
                .inner
                .security_context
                .remote_engines()
                .lock()
                .unwrap();
            for i in 0..MAX_REMOTE_ENGINES {
                let id = Bytes::from(format!("dummy-engine-{i}"));
                let state = crate::v3::EngineState::new(id.clone(), 1, 1);
                let updated_at = state
                    .last_authenticated_update_at()
                    .expect("dummy state has authenticated time");
                engines.insert(id, state, updated_at);
            }
            assert_eq!(engines.len(), MAX_REMOTE_ENGINES);
        }

        // An authenticated trap under a not-yet-seen engine ID is accepted.
        let msg = build_authed_v3_trap(b"fresh-remote-engine", 7, 123_456);
        assert!(receiver.handle_v3(msg, source).await.unwrap().is_some());

        // The table stayed at capacity (an old entry was evicted) and the new
        // engine is now tracked.
        let engines = receiver
            .inner
            .security_context
            .remote_engines()
            .lock()
            .unwrap();
        assert_eq!(engines.len(), MAX_REMOTE_ENGINES);
        assert!(engines.contains_key(&Bytes::from_static(b"fresh-remote-engine")));
        assert!(!engines.contains_key(&Bytes::from_static(b"dummy-engine-0")));
    }

    /// A replayed (stale) trap from a known remote engine is rejected:
    /// its engine time is more than 150 seconds behind the local notion
    /// established by an earlier authentic message (RFC 3414 Section 3.2
    /// Step 7b).
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[tokio::test]
    async fn test_v3_trap_remote_engine_stale_time_rejected() {
        let receiver = remote_trap_receiver().await;
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let fresh = build_authed_v3_trap(b"remote-sender-engine", 7, 10_000);
        assert!(receiver.handle_v3(fresh, source).await.unwrap().is_some());

        // Same boots, time far behind the notion just established
        let stale = build_authed_v3_trap(b"remote-sender-engine", 7, 5_000);
        assert!(
            receiver.handle_v3(stale, source).await.is_err(),
            "stale engine time should be rejected as outside the time window"
        );
    }

    /// A trap claiming an older boot cycle than previously seen is rejected.
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[tokio::test]
    async fn test_v3_trap_remote_engine_old_boots_rejected() {
        let receiver = remote_trap_receiver().await;
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let fresh = build_authed_v3_trap(b"remote-sender-engine", 7, 10_000);
        assert!(receiver.handle_v3(fresh, source).await.unwrap().is_some());

        let old_boots = build_authed_v3_trap(b"remote-sender-engine", 6, 99_999);
        assert!(
            receiver.handle_v3(old_boots, source).await.is_err(),
            "older boot cycle should be rejected"
        );
    }

    /// A sender reboot (higher boots, low time) is tolerated and updates
    /// the local notion; the previous boot cycle is then rejected.
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[tokio::test]
    async fn test_v3_trap_remote_engine_reboot_accepted() {
        let receiver = remote_trap_receiver().await;
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let before = build_authed_v3_trap(b"remote-sender-engine", 7, 10_000);
        assert!(receiver.handle_v3(before, source).await.unwrap().is_some());

        let after_reboot = build_authed_v3_trap(b"remote-sender-engine", 8, 5);
        assert!(
            receiver
                .handle_v3(after_reboot, source)
                .await
                .unwrap()
                .is_some(),
            "trap after sender reboot should be accepted"
        );

        let from_old_cycle = build_authed_v3_trap(b"remote-sender-engine", 7, 20_000);
        assert!(
            receiver.handle_v3(from_old_cycle, source).await.is_err(),
            "trap from superseded boot cycle should be rejected"
        );
    }

    /// A trap with a bad HMAC from an unknown remote engine must not seed
    /// timeliness state or be accepted.
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[tokio::test]
    async fn test_v3_trap_remote_engine_bad_auth_rejected() {
        let receiver = remote_trap_receiver().await;
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let msg = build_v3_notification(
            crate::pdu::PduType::TrapV2,
            b"remote-sender-engine",
            7,
            123_456,
            b"trapuser",
            Some((b"wrong-password-1234", AuthProtocol::Sha1)),
        );
        assert!(
            receiver.handle_v3(msg, source).await.is_err(),
            "trap with wrong auth key should be rejected"
        );

        // A correctly authenticated trap still works afterwards
        let good = build_authed_v3_trap(b"remote-sender-engine", 7, 123_456);
        assert!(receiver.handle_v3(good, source).await.unwrap().is_some());
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[tokio::test]
    async fn test_v3_inform_outside_time_window_rejected() {
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .engine_id(b"test-engine".to_vec())
            .engine_boots(1)
            .usm_user("informuser", |u| {
                u.auth(AuthProtocol::Sha1, b"authpass12345678")
            })
            .unwrap()
            .admit_all_notifications()
            .spawn()
            .await
            .unwrap();

        let engine_id = b"test-engine";
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        // Engine time far in the future (5000 seconds, well beyond 150-second window)
        let msg = build_authed_v3_inform(
            engine_id,
            1,    // correct boots
            5000, // way outside time window (receiver started ~0 seconds ago)
            b"informuser",
            b"authpass12345678",
            AuthProtocol::Sha1,
        );

        let result = receiver.handle_v3(msg, source).await;
        assert!(
            result.is_err(),
            "message with engine_time=5000 should be rejected (outside 150s window)"
        );
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[tokio::test]
    async fn test_v3_inform_wrong_boots_rejected() {
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .engine_id(b"test-engine".to_vec())
            .engine_boots(1)
            .usm_user("informuser", |u| {
                u.auth(AuthProtocol::Sha1, b"authpass12345678")
            })
            .unwrap()
            .admit_all_notifications()
            .spawn()
            .await
            .unwrap();

        let engine_id = b"test-engine";
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        // Wrong engine boots (receiver has boots=1)
        let msg = build_authed_v3_inform(
            engine_id,
            2, // wrong boots
            0, // time is fine
            b"informuser",
            b"authpass12345678",
            AuthProtocol::Sha1,
        );

        let result = receiver.handle_v3(msg, source).await;
        assert!(
            result.is_err(),
            "message with wrong engine_boots should be rejected"
        );
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[tokio::test]
    async fn test_v3_inform_within_time_window_accepted() {
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .engine_id(b"test-engine".to_vec())
            .engine_boots(1)
            .usm_user("informuser", |u| {
                u.auth(AuthProtocol::Sha1, b"authpass12345678")
            })
            .unwrap()
            .admit_all_notifications()
            .spawn()
            .await
            .unwrap();

        let engine_id = b"test-engine";
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        // Engine time within the window (receiver started ~0 seconds ago, engine_time=0 is fine)
        let msg = build_authed_v3_inform(
            engine_id,
            1, // correct boots
            0, // within window
            b"informuser",
            b"authpass12345678",
            AuthProtocol::Sha1,
        );

        let result = receiver.handle_v3(msg, source).await;
        // Should succeed (or at least not fail due to time window).
        // The Inform response send will fail since source is fake, but
        // the time window check itself should pass. The error if any
        // should be a network error from trying to send the response,
        // not an Auth error.
        match result {
            Ok(Some(_)) => {} // unexpected but ok (socket might succeed on loopback)
            Err(e) => {
                let err_str = format!("{e}");
                assert!(
                    !err_str.contains("Auth"),
                    "should not be an auth error for valid time window, got: {err_str}"
                );
            }
            Ok(None) => panic!("should not return None for a valid InformRequest"),
        }
    }

    /// Build a V3 discovery request message (empty engine ID, noAuthNoPriv).
    fn build_v3_discovery_request(msg_id: i32, reportable: bool) -> Bytes {
        use crate::message::{MsgFlags, MsgGlobalData, ScopedPdu, V3Message};
        use crate::pdu::Pdu;
        use crate::v3::UsmSecurityParams;

        let pdu = Pdu::standard(crate::pdu::StandardPduType::GetRequest, 0, 0, 0, vec![]);

        let global = MsgGlobalData::new(
            msg_id,
            crate::MessageSize::new(65507).unwrap(),
            MsgFlags::new(SecurityLevel::NoAuthNoPriv, reportable),
        )
        .unwrap();

        let usm_params = UsmSecurityParams::discovery();

        let scoped = ScopedPdu::new(Bytes::new(), Bytes::new(), pdu);
        let msg = V3Message::new(global, usm_params.encode().unwrap(), scoped).unwrap();
        msg.encode().unwrap()
    }

    fn build_noauth_v3_inform(engine_id: &[u8], username: &[u8]) -> Bytes {
        use crate::message::{MsgFlags, MsgGlobalData, ScopedPdu, V3Message};
        use crate::pdu::{Pdu, StandardPduType};
        use crate::v3::UsmSecurityParams;
        use crate::value::Value;

        let pdu = Pdu::standard(
            StandardPduType::InformRequest,
            7,
            0,
            0,
            vec![
                VarBind::new(oids::sys_uptime(), Value::TimeTicks(1000)),
                VarBind::new(
                    oids::snmp_trap_oid(),
                    Value::ObjectIdentifier(oids::cold_start()),
                ),
            ],
        );
        let global = MsgGlobalData::new(
            7,
            crate::UDP_RECEIVE_LIMITS.advertised(),
            MsgFlags::new(SecurityLevel::NoAuthNoPriv, true),
        )
        .unwrap();
        let usm_params = UsmSecurityParams::new(
            Bytes::copy_from_slice(engine_id),
            1,
            0,
            Bytes::copy_from_slice(username),
        )
        .unwrap();
        let scoped = ScopedPdu::new(Bytes::copy_from_slice(engine_id), Bytes::new(), pdu);
        V3Message::new(global, usm_params.encode().unwrap(), scoped)
            .unwrap()
            .encode()
            .unwrap()
    }

    #[tokio::test]
    async fn test_v3_discovery_gets_response() {
        use crate::message::V3Message;
        use crate::v3::UsmSecurityParams;
        use crate::value::Value;

        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .engine_id(b"test-discovery-engine".to_vec())
            .spawn()
            .await
            .unwrap();

        // Bind a separate socket to receive the Report; handle_v3 is called
        // directly with this socket's address as source.
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();

        let discovery_msg = build_v3_discovery_request(42, true);
        let result = receiver.handle_v3(discovery_msg, client_addr).await;

        // Discovery should return Ok(None) - not a notification
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());

        // Counter should be incremented
        assert_eq!(receiver.usm_unknown_engine_ids(), 1);

        // The Report must carry usmStatsUnknownEngineIDs with the counter
        // value and the receiver's engine ID (RFC 3414 Section 4).
        let mut buf = vec![0u8; 4096];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.recv_from(&mut buf),
        )
        .await
        .expect("expected a discovery Report")
        .unwrap();

        let report = V3Message::decode(
            Bytes::copy_from_slice(&buf[..len]),
            crate::DecodeConfig::default(),
        )
        .unwrap()
        .value;
        assert_eq!(
            report.global_data.msg_flags.security_level,
            SecurityLevel::NoAuthNoPriv
        );
        let report_usm = UsmSecurityParams::decode(
            report.security_params.clone(),
            crate::DecodeConfig::default(),
        )
        .unwrap()
        .value;
        assert_eq!(report_usm.engine_id.as_ref(), b"test-discovery-engine");
        let scoped = report.scoped_pdu().expect("report should be plaintext");
        assert_eq!(scoped.pdu.pdu_type(), crate::pdu::PduType::Report);
        assert_eq!(
            scoped.pdu.varbinds[0].oid,
            crate::v3::report_oids::unknown_engine_ids()
        );
        assert_eq!(scoped.pdu.varbinds[0].value, Value::Counter32(1));
    }

    #[tokio::test]
    async fn convenience_bind_keeps_v3_failure_reports_and_generated_identity() {
        use crate::message::V3Message;
        use crate::v3::UsmSecurityParams;

        let mut receiver = NotificationReceiver::spawn("127.0.0.1:0").await.unwrap();
        let destination = receiver.local_addr();
        let engine_id = Bytes::copy_from_slice(receiver.engine_id());
        crate::v3::validate_engine_id(&engine_id).unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        client.send_to(&[0x30, 0], destination).await.unwrap();
        client
            .send_to(&build_v3_discovery_request(42, true), destination)
            .await
            .unwrap();

        let mut buf = [0_u8; 4096];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.recv_from(&mut buf),
        )
        .await
        .expect("convenience receiver did not return a discovery Report")
        .unwrap();
        let report = V3Message::decode(
            Bytes::copy_from_slice(&buf[..len]),
            crate::DecodeConfig::default(),
        )
        .unwrap()
        .value;
        let report_usm = UsmSecurityParams::decode(
            report.security_params.clone(),
            crate::DecodeConfig::default(),
        )
        .unwrap()
        .value;
        assert_eq!(report_usm.engine_id, engine_id);
        let scoped = report.scoped_pdu().expect("Report must be plaintext");
        assert_eq!(scoped.pdu.pdu_type(), crate::pdu::PduType::Report);
        assert_eq!(
            scoped.pdu.varbinds[0].oid,
            crate::v3::report_oids::unknown_engine_ids()
        );
        assert_eq!(receiver.usm_unknown_engine_ids(), 1);

        client
            .send_to(
                &build_noauth_v3_inform(&engine_id, b"unconfigured-user"),
                destination,
            )
            .await
            .unwrap();
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.recv_from(&mut buf),
        )
        .await
        .expect("convenience receiver did not return an unknown-user Report")
        .unwrap();
        let report = V3Message::decode(
            Bytes::copy_from_slice(&buf[..len]),
            crate::DecodeConfig::default(),
        )
        .unwrap()
        .value;
        assert_eq!(
            report.global_data.msg_flags.security_level,
            SecurityLevel::NoAuthNoPriv
        );
        let report_usm = UsmSecurityParams::decode(
            report.security_params.clone(),
            crate::DecodeConfig::default(),
        )
        .unwrap()
        .value;
        assert_eq!(report_usm.engine_id, engine_id);
        let scoped = report.scoped_pdu().expect("Report must be plaintext");
        assert_eq!(scoped.pdu.pdu_type(), crate::pdu::PduType::Report);
        assert_eq!(
            scoped.pdu.varbinds[0].oid,
            crate::v3::report_oids::unknown_user_names()
        );
        assert_eq!(receiver.usm_unknown_usernames(), 1);

        receiver.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_v3_discovery_non_reportable_ignored() {
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .engine_id(b"test-discovery-engine".to_vec())
            .spawn()
            .await
            .unwrap();

        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let discovery_msg = build_v3_discovery_request(42, false);

        let result = receiver.handle_v3(discovery_msg, source).await;

        // A non-reportable message with an unknown (empty) engine ID gets no
        // response, but the counter tracks the occurrence like every other
        // usmStats counter.
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
        assert_eq!(receiver.usm_unknown_engine_ids(), 1);
    }

    /// RFC 3414 Section 1.5.1: the receiver of a Confirmed-class PDU is the
    /// authoritative engine, so an Inform must be localized to this receiver's
    /// local engine ID. An Inform localized to a foreign (e.g. the sender's)
    /// authoritative engine ID is rejected rather than acknowledged under that
    /// foreign engine.
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[tokio::test]
    async fn test_v3_inform_under_remote_engine_id_rejected() {
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .engine_id(b"my-receiver-engine".to_vec())
            .engine_boots(1)
            .usm_user("informuser", |u| {
                u.auth(AuthProtocol::Sha1, b"authpass12345678")
            })
            .unwrap()
            .admit_all_notifications()
            .spawn()
            .await
            .unwrap();

        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        // Build a message with a DIFFERENT (foreign) authoritative engine ID.
        let msg = build_authed_v3_inform(
            b"remote-engine-id",
            1,
            0,
            b"informuser",
            b"authpass12345678",
            AuthProtocol::Sha1,
        );

        let result = receiver.handle_v3(msg, source).await.unwrap();
        assert!(
            result.is_none(),
            "inform under a foreign authoritative engine ID should be dropped, got {result:?}"
        );
    }

    /// An Inform localized to the receiver's own local engine ID is accepted
    /// (RFC 3414 Section 1.5.1: the receiver is the authoritative engine for a
    /// Confirmed-class PDU).
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[tokio::test]
    async fn test_v3_inform_under_local_engine_id_accepted() {
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .engine_id(b"my-receiver-engine".to_vec())
            .engine_boots(1)
            .usm_user("informuser", |u| {
                u.auth(AuthProtocol::Sha1, b"authpass12345678")
            })
            .unwrap()
            .admit_all_notifications()
            .spawn()
            .await
            .unwrap();

        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        // Localized to the receiver's own engine ID.
        let msg = build_authed_v3_inform(
            b"my-receiver-engine",
            1,
            0,
            b"informuser",
            b"authpass12345678",
            AuthProtocol::Sha1,
        );

        let result = receiver.handle_v3(msg, source).await.unwrap();
        assert!(
            matches!(
                result,
                Some(ReceivedNotification {
                    notification: Notification::InformV3 { .. },
                    ..
                })
            ),
            "inform under the local engine ID should be accepted, got {result:?}"
        );
    }

    /// RFC 3412 Section 6.3: the inform acknowledgement advertises the
    /// receiver's own receive capacity, not the sender's echoed msgMaxSize.
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[tokio::test]
    async fn test_v3_inform_ack_advertises_local_max_size() {
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .engine_id(b"my-receiver-engine".to_vec())
            .engine_boots(1)
            .usm_user("informuser", |u| {
                u.auth(AuthProtocol::Sha1, b"authpass12345678")
            })
            .unwrap()
            .admit_all_notifications()
            .spawn()
            .await
            .unwrap();

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();

        // Inform advertises a small msgMaxSize (1400); the ack must NOT echo it.
        // The Inform is localized to the receiver's own engine ID, as required
        // for a Confirmed-class PDU (RFC 3414 Section 1.5.1).
        let msg = build_v3_notification_with_max(
            crate::pdu::PduType::InformRequest,
            b"my-receiver-engine",
            1,
            0,
            b"informuser",
            Some((b"authpass12345678", AuthProtocol::Sha1)),
            1400,
        );

        let result = receiver.handle_v3(msg, client_addr).await.unwrap();
        assert!(
            matches!(
                result,
                Some(ReceivedNotification {
                    notification: Notification::InformV3 { .. },
                    ..
                })
            ),
            "inform should be accepted, got {result:?}"
        );

        let mut buf = vec![0u8; 4096];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.recv_from(&mut buf),
        )
        .await
        .expect("expected the inform acknowledgement")
        .unwrap();

        use crate::message::V3Message;
        let ack = V3Message::decode(
            Bytes::copy_from_slice(&buf[..len]),
            crate::DecodeConfig::default(),
        )
        .unwrap()
        .value;
        assert_eq!(
            ack.global_data.msg_max_size,
            crate::UDP_RECEIVE_LIMITS.advertised(),
            "ack must advertise the receiver's local receive capacity, not the sender's 1400"
        );
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[tokio::test]
    async fn receiver_inform_ack_rejects_des_state_after_authoritative_rollover() {
        let engine = AuthoritativeEngine::for_test(&b"receiver-engine"[..], 1);
        engine.set_elapsed_for_test(u64::from(crate::v3::MAX_ENGINE_TIME) + 1);
        let response_des_state =
            crate::v3::DesSaltState::install(|_| Ok::<(), std::convert::Infallible>(())).unwrap();
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .authoritative_engine(engine)
            .des_salt_state(response_des_state.clone())
            .usm_user("informuser", |user| {
                user.auth_priv(
                    AuthProtocol::Sha1,
                    b"auth-password",
                    crate::v3::PrivProtocol::Des,
                    b"priv-password",
                )
            })
            .unwrap()
            .admit_all_notifications()
            .spawn()
            .await
            .unwrap();

        let security = crate::v3::UsmConfig::new("informuser")
            .auth_priv(
                AuthProtocol::Sha1,
                b"auth-password",
                crate::v3::PrivProtocol::Des,
                b"priv-password",
            )
            .unwrap();
        let keys = security.derive_keys(receiver.engine_id()).unwrap();
        let sender_des_state = crate::v3::DesSaltState::restart(
            crate::v3::PersistedDesSaltState::new(4).unwrap(),
            |_| Ok::<(), std::convert::Infallible>(()),
        )
        .unwrap();
        let pdu = Pdu::standard(
            crate::pdu::StandardPduType::InformRequest,
            1,
            0,
            0,
            vec![
                VarBind::new(oids::sys_uptime(), Value::TimeTicks(1000)),
                VarBind::new(
                    oids::snmp_trap_oid(),
                    Value::ObjectIdentifier(oids::cold_start()),
                ),
            ],
        );
        let encoded = crate::v3::encode::encode_v3_message(
            &pdu,
            1,
            receiver.engine_id(),
            2,
            0,
            &security,
            Some(&keys),
            None,
            Some(&sender_des_state),
            Some(sender_des_state.engine_boots()),
            true,
            crate::UDP_RECEIVE_LIMITS.advertised(),
        )
        .unwrap();

        let received = receiver
            .handle_v3(Bytes::from(encoded), "127.0.0.1:9999".parse().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            received.inform_ack,
            crate::NotificationAcknowledgement::Completed(InformAckOutcome::Failed(error))
                if matches!(
                    *error,
                    Error::Privacy(crate::v3::PrivacyError::DesEngineBootsMismatch {
                        state_engine_boots: 1,
                        generating_engine_boots: 2,
                    })
                )
        ));
        assert_eq!(response_des_state.reserve().unwrap().salt(), 1);
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[tokio::test]
    async fn v3_inform_direct_fallback_and_drop_at_all_security_levels() {
        use crate::v3::UsmSecurityParams;
        use crate::v3::encode::encode_v3_response;

        let engine_id = Bytes::from_static(b"\x80\x00\x00\x00\x01informrecv");
        let username = Bytes::from_static(b"informuser");

        for level in [
            SecurityLevel::NoAuthNoPriv,
            SecurityLevel::AuthNoPriv,
            SecurityLevel::AuthPriv,
        ] {
            let (message, inform_pdu, keys) = build_v3_inform_at_level(
                &engine_id,
                &username,
                level,
                crate::UDP_RECEIVE_LIMITS.advertised(),
            );
            let encode = |pdu| {
                encode_v3_response(
                    pdu,
                    1,
                    crate::UDP_RECEIVE_LIMITS.advertised(),
                    level,
                    UsmSecurityParams::new(engine_id.clone(), 1, 0, username.clone()).unwrap(),
                    engine_id.clone(),
                    Bytes::new(),
                    Some(&keys),
                    Some(&SaltCounter::new().unwrap()),
                    None,
                    "127.0.0.1:9999".parse().unwrap(),
                )
            };
            let candidate_len = encode(inform_pdu.to_response(Version::V3).unwrap())
                .unwrap()
                .len();
            let alternate_len = encode(Pdu::response(
                inform_pdu.request_id,
                crate::ErrorStatus::TooBig.as_i32(),
                0,
                Vec::new(),
            ))
            .unwrap()
            .len();
            assert!(alternate_len < candidate_len);

            for (limit, expected_len, expected_status) in [
                (
                    candidate_len,
                    Some(candidate_len),
                    crate::ErrorStatus::NoError,
                ),
                (
                    candidate_len - 1,
                    Some(alternate_len),
                    crate::ErrorStatus::TooBig,
                ),
                (alternate_len - 1, None, crate::ErrorStatus::TooBig),
            ] {
                let config = inform_user(level, &username);
                let policy_calls = Arc::new(AtomicU32::new(0));
                let policy_calls_for_receiver = Arc::clone(&policy_calls);
                let policy_engine_id = engine_id.clone();
                let policy_username = username.clone();
                let receiver = NotificationReceiver::builder()
                    .bind("127.0.0.1:0")
                    .authoritative_engine(AuthoritativeEngine::for_test(engine_id.clone(), 1))
                    .usm_user(username.clone(), move |_| Ok(config))
                    .unwrap()
                    .admission_policy(move |notification: &NotificationAdmissionInfo<'_>| {
                        assert_eq!(notification.version, Version::V3);
                        assert!(notification.community.is_none());
                        assert_eq!(notification.username, Some(policy_username.as_ref()));
                        assert_eq!(notification.security_level, Some(level));
                        assert_eq!(notification.pdu_class, NotificationPduClass::Inform);
                        assert_eq!(
                            notification.context_engine_id,
                            Some(policy_engine_id.as_ref())
                        );
                        assert_eq!(notification.context_name, Some(b"".as_slice()));
                        assert_eq!(
                            notification.authoritative_engine_id,
                            Some(policy_engine_id.as_ref())
                        );
                        assert_eq!(notification.trap_oid().unwrap(), oids::cold_start());
                        policy_calls_for_receiver.fetch_add(1, Ordering::Relaxed);
                        NotificationAdmissionDecision::Admit
                    })
                    .max_message_size(limit)
                    .spawn()
                    .await
                    .unwrap();
                let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let received = receiver
                    .handle_v3(message.clone(), client.local_addr().unwrap())
                    .await
                    .unwrap();
                if expected_status == crate::ErrorStatus::NoError {
                    let received = received.expect("a fitting Inform is delivered");
                    assert!(matches!(
                        received.notification,
                        Notification::InformV3 { .. }
                    ));
                    assert!(matches!(
                        received.inform_ack,
                        crate::NotificationAcknowledgement::Completed(InformAckOutcome::Sent)
                    ));
                    assert_eq!(received.wire_identity.version, Version::V3);
                    assert_eq!(received.wire_identity.request_id, Some(1));
                    let v3_identity = received.wire_identity.v3.unwrap();
                    assert_eq!(v3_identity.msg_id, 1);
                    assert_eq!(v3_identity.authoritative_engine_id, engine_id);
                    assert_eq!(v3_identity.username, username);
                    assert_eq!(v3_identity.security_level, level);
                } else {
                    assert!(received.is_none());
                }
                assert_eq!(policy_calls.load(Ordering::Relaxed), 1);
                let mut buf = vec![0_u8; 4096];
                if let Some(expected_len) = expected_len {
                    let (len, _) = tokio::time::timeout(
                        std::time::Duration::from_secs(1),
                        client.recv_from(&mut buf),
                    )
                    .await
                    .expect("expected Inform response")
                    .unwrap();
                    assert_eq!(len, expected_len);
                    let ack = crate::message::V3Message::decode(
                        Bytes::copy_from_slice(&buf[..len]),
                        crate::DecodeConfig::default(),
                    )
                    .unwrap()
                    .value;
                    assert_eq!(
                        ack.global_data.msg_max_size,
                        crate::UDP_RECEIVE_LIMITS.advertised()
                    );
                    assert_eq!(ack.security_level(), level);
                    if let Some(pdu) = ack.pdu() {
                        assert_eq!(pdu.error_status_enum(), expected_status);
                    }
                    assert_eq!(receiver.snmp_silent_drops(), 0);
                } else {
                    assert_eq!(receiver.snmp_silent_drops(), 1);
                    assert!(client.try_recv_from(&mut buf).is_err());
                }
            }
        }
    }

    /// RFC 3414 Section 3.1 Steps 1(a) and 6: an Inform Response is generated
    /// under the local authoritative engine and carries its current boots/time
    /// tuple rather than echoing the accepted request's tuple.
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[tokio::test]
    async fn test_v3_inform_ack_uses_current_authoritative_time() {
        use crate::message::V3Message;
        use crate::v3::UsmSecurityParams;

        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .engine_id(b"my-receiver-engine".to_vec())
            .engine_boots(7)
            .usm_user("informuser", |u| {
                u.auth(AuthProtocol::Sha1, b"authpass12345678")
            })
            .unwrap()
            .admit_all_notifications()
            .spawn()
            .await
            .unwrap();

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();

        // This time is inside the authoritative window but deliberately ahead
        // of the receiver's current clock, making an echo observable.
        let incoming_time = 149;
        let msg = build_authed_v3_inform(
            b"my-receiver-engine",
            7,
            incoming_time,
            b"informuser",
            b"authpass12345678",
            AuthProtocol::Sha1,
        );

        let earliest = receiver.inner.local_engine.current_boots_time().unwrap();
        let result = receiver.handle_v3(msg, client_addr).await.unwrap();
        let latest = receiver.inner.local_engine.current_boots_time().unwrap();
        assert!(matches!(
            result,
            Some(ReceivedNotification {
                notification: Notification::InformV3 { .. },
                ..
            })
        ));

        let mut buf = vec![0u8; 4096];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.recv_from(&mut buf),
        )
        .await
        .expect("expected the inform acknowledgement")
        .unwrap();

        let ack = V3Message::decode(
            Bytes::copy_from_slice(&buf[..len]),
            crate::DecodeConfig::default(),
        )
        .unwrap()
        .value;
        let ack_usm =
            UsmSecurityParams::decode(ack.security_params, crate::DecodeConfig::default())
                .unwrap()
                .value;
        let ack_pair = (ack_usm.engine_boots, ack_usm.engine_time);

        assert_eq!(ack_usm.engine_id.as_ref(), receiver.engine_id());
        assert_ne!(ack_usm.engine_time, incoming_time);
        assert_eq!(ack_pair.0, 7);
        assert!(
            ack_pair.1 >= earliest.1 && ack_pair.1 <= latest.1,
            "ack pair {ack_pair:?} should come from one current elapsed-time sample between {earliest:?} and {latest:?}"
        );
    }

    #[test]
    fn test_auto_generated_engine_id_non_empty() {
        let builder = NotificationReceiverBuilder::new();
        assert!(builder.authoritative_engine.is_none());
    }

    #[tokio::test]
    async fn test_bind_generates_engine_id() {
        let first = NotificationReceiver::spawn("127.0.0.1:0").await.unwrap();
        let second = NotificationReceiver::spawn("127.0.0.1:0").await.unwrap();

        crate::v3::validate_engine_id(first.engine_id()).unwrap();
        crate::v3::validate_engine_id(second.engine_id()).unwrap();
        assert_eq!(first.engine_id().len(), 17);
        assert_ne!(first.engine_id(), second.engine_id());
    }

    #[tokio::test]
    async fn test_builder_generates_engine_id() {
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .spawn()
            .await
            .unwrap();
        assert_eq!(receiver.engine_id().len(), 17);
        crate::v3::validate_engine_id(receiver.engine_id()).unwrap();
    }

    #[tokio::test]
    async fn test_builder_custom_engine_id() {
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .engine_id(b"custom-engine".to_vec())
            .spawn()
            .await
            .unwrap();
        assert_eq!(receiver.engine_id(), b"custom-engine");
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[tokio::test]
    async fn test_usm_counter_accessors_default_zero() {
        let receiver = remote_trap_receiver().await;
        assert_eq!(receiver.usm_unknown_engine_ids(), 0);
        assert_eq!(receiver.usm_unknown_usernames(), 0);
        assert_eq!(receiver.usm_wrong_digests(), 0);
        assert_eq!(receiver.usm_not_in_time_windows(), 0);
        assert_eq!(receiver.usm_unsupported_sec_levels(), 0);
        assert_eq!(receiver.usm_decryption_errors(), 0);
    }

    /// RFC 3414 Section 3.2 Step 6: a failed HMAC increments
    /// usmStatsWrongDigests.
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[tokio::test]
    async fn test_v3_trap_wrong_digest_increments_counter() {
        let policy_calls = Arc::new(AtomicU32::new(0));
        let policy_calls_for_receiver = Arc::clone(&policy_calls);
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .engine_id(b"my-receiver-engine".to_vec())
            .engine_boots(1)
            .usm_user("trapuser", |u| {
                u.auth(AuthProtocol::Sha1, b"authpass12345678")
            })
            .unwrap()
            .admission_policy(move |_: &NotificationAdmissionInfo<'_>| {
                policy_calls_for_receiver.fetch_add(1, Ordering::Relaxed);
                NotificationAdmissionDecision::Admit
            })
            .spawn()
            .await
            .unwrap();
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let msg = build_v3_notification(
            crate::pdu::PduType::TrapV2,
            b"remote-sender-engine",
            7,
            123_456,
            b"trapuser",
            Some((b"wrong-password-1234", AuthProtocol::Sha1)),
        );
        assert!(receiver.handle_v3(msg, source).await.is_err());
        assert_eq!(receiver.usm_wrong_digests(), 1);
        assert_eq!(policy_calls.load(Ordering::Relaxed), 0);
    }

    /// RFC 3414 Section 3.2 Step 4: an authenticated message for a user not
    /// in the local configuration increments usmStatsUnknownUserNames.
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[tokio::test]
    async fn test_v3_trap_unknown_user_increments_counter() {
        let receiver = remote_trap_receiver().await;
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let msg = build_v3_notification(
            crate::pdu::PduType::TrapV2,
            b"remote-sender-engine",
            7,
            123_456,
            b"nosuchuser",
            Some((b"authpass12345678", AuthProtocol::Sha1)),
        );
        let result = receiver.handle_v3(msg, source).await.unwrap();
        assert!(result.is_none(), "unknown user must not be delivered");
        assert_eq!(receiver.usm_unknown_usernames(), 1);
        assert_eq!(receiver.usm_wrong_digests(), 0);
    }

    /// RFC 3414 Section 3.2 Step 5: an authenticated message for a user
    /// configured without an auth key increments
    /// usmStatsUnsupportedSecLevels.
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[tokio::test]
    async fn test_v3_trap_user_without_auth_key_increments_counter() {
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .engine_id(b"my-receiver-engine".to_vec())
            .usm_user("plainuser", Ok)
            .unwrap()
            .admit_all_notifications()
            .spawn()
            .await
            .unwrap();
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let msg = build_v3_notification(
            crate::pdu::PduType::TrapV2,
            b"remote-sender-engine",
            7,
            123_456,
            b"plainuser",
            Some((b"authpass12345678", AuthProtocol::Sha1)),
        );
        let result = receiver.handle_v3(msg, source).await.unwrap();
        assert!(result.is_none());
        assert_eq!(receiver.usm_unsupported_sec_levels(), 1);
        assert_eq!(receiver.usm_unknown_usernames(), 0);
    }

    /// RFC 3414 Section 3.2 Step 7a: an inform under the receiver's engine ID
    /// outside the time window increments usmStatsNotInTimeWindows.
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[tokio::test]
    async fn test_v3_inform_time_window_failure_increments_counter() {
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .engine_id(b"test-engine".to_vec())
            .engine_boots(1)
            .usm_user("informuser", |u| {
                u.auth(AuthProtocol::Sha1, b"authpass12345678")
            })
            .unwrap()
            .admit_all_notifications()
            .spawn()
            .await
            .unwrap();
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let msg = build_authed_v3_inform(
            b"test-engine",
            1,
            5000,
            b"informuser",
            b"authpass12345678",
            AuthProtocol::Sha1,
        );
        assert!(receiver.handle_v3(msg, source).await.is_err());
        assert_eq!(receiver.usm_not_in_time_windows(), 1);
    }

    /// RFC 3414 Section 3.2 Step 7b: when the sender is the authoritative
    /// engine, a timeliness failure is a bare error indication.
    /// usmStatsNotInTimeWindows and its Report belong to the authoritative
    /// case (Step 7a) only, matching net-snmp's
    /// usm_check_and_update_timeliness.
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[tokio::test]
    async fn test_v3_trap_remote_stale_not_counted() {
        let receiver = remote_trap_receiver().await;
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let fresh = build_authed_v3_trap(b"remote-sender-engine", 7, 10_000);
        assert!(receiver.handle_v3(fresh, source).await.unwrap().is_some());

        let stale = build_authed_v3_trap(b"remote-sender-engine", 7, 5_000);
        assert!(receiver.handle_v3(stale, source).await.is_err());
        assert_eq!(receiver.usm_not_in_time_windows(), 0);
    }

    /// A foreign Inform uses the receiver's authority. Its Report advertises
    /// the local engine and the remote trap clock remains usable.
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[tokio::test]
    async fn test_v3_inform_stale_engine_gets_report_without_updating_trap_clock() {
        let receiver = remote_trap_receiver().await;

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();

        let fresh = build_authed_v3_trap(b"remote-sender-engine", 7, 10_000);
        assert!(
            receiver
                .handle_v3(fresh.clone(), client_addr)
                .await
                .unwrap()
                .is_some()
        );

        let mut buf = vec![0u8; 4096];

        let stale = build_v3_notification(
            crate::pdu::PduType::InformRequest,
            b"remote-sender-engine",
            8,
            5_000,
            b"trapuser",
            Some((b"authpass12345678", AuthProtocol::Sha1)),
        );
        assert!(
            receiver
                .handle_v3(stale, client_addr)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(receiver.usm_not_in_time_windows(), 0);

        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            client.recv_from(&mut buf),
        )
        .await
        .unwrap()
        .unwrap();
        let report = crate::message::V3Message::decode(
            Bytes::copy_from_slice(&buf[..len]),
            crate::DecodeConfig::DEFAULT,
        )
        .unwrap()
        .value;
        assert_eq!(
            crate::v3::classify_report(report.pdu().unwrap()).unwrap(),
            crate::v3::ReportStatus::UnknownEngineId { counter: 1 },
        );
        assert!(
            receiver
                .handle_v3(fresh, client_addr)
                .await
                .unwrap()
                .is_some()
        );
    }

    /// Build an authPriv V3 trap for the given username, HMAC'd with the
    /// given password, with undecryptable privacy parameters (wrong salt
    /// length) and garbage ciphertext.
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    fn build_v3_trap_bad_ciphertext(
        engine_id: &[u8],
        username: &[u8],
        auth_password: &[u8],
    ) -> Bytes {
        use crate::message::{MsgFlags, MsgGlobalData, V3Message};
        use crate::v3::auth::authenticate_message;
        use crate::v3::{LocalizedKey, UsmSecurityParams};

        let auth_key =
            LocalizedKey::from_password(AuthProtocol::Sha1, auth_password, engine_id).unwrap();

        let global = MsgGlobalData::new(
            1,
            crate::MessageSize::new(65507).unwrap(),
            MsgFlags::new(SecurityLevel::AuthPriv, false),
        )
        .unwrap();
        let usm_params = UsmSecurityParams::new(
            Bytes::copy_from_slice(engine_id),
            7,
            123_456,
            Bytes::copy_from_slice(username),
        )
        .unwrap()
        .with_auth_placeholder(auth_key.mac_len())
        .unwrap()
        .with_priv_params(Bytes::from_static(b"bad"))
        .unwrap();

        let msg = V3Message::new_with_opaque_encrypted_scoped_pdu(
            global,
            usm_params.encode().unwrap(),
            Bytes::from_static(b"not-a-valid-ciphertext"),
        )
        .unwrap();
        let mut msg_bytes = msg.encode().unwrap().to_vec();
        let (auth_offset, auth_len) =
            UsmSecurityParams::find_auth_params_offset(&msg_bytes).unwrap();
        authenticate_message(&auth_key, &mut msg_bytes, auth_offset, auth_len).unwrap();
        Bytes::from(msg_bytes)
    }

    /// RFC 3414 Section 3.2 Step 8: a decryption failure increments
    /// usmStatsDecryptionErrors.
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[tokio::test]
    async fn test_v3_decryption_error_increments_counter() {
        let policy_calls = Arc::new(AtomicU32::new(0));
        let policy_calls_for_receiver = Arc::clone(&policy_calls);
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .engine_id(b"my-receiver-engine".to_vec())
            .usm_user("privuser", |u| {
                u.auth_priv(
                    AuthProtocol::Sha1,
                    b"authpass12345678",
                    crate::v3::PrivProtocol::Aes128,
                    b"privpass12345678",
                )
            })
            .unwrap()
            .admission_policy(move |_: &NotificationAdmissionInfo<'_>| {
                policy_calls_for_receiver.fetch_add(1, Ordering::Relaxed);
                NotificationAdmissionDecision::Admit
            })
            .spawn()
            .await
            .unwrap();
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let msg =
            build_v3_trap_bad_ciphertext(b"remote-sender-engine", b"privuser", b"authpass12345678");
        assert!(receiver.handle_v3(msg, source).await.is_err());
        assert_eq!(receiver.usm_decryption_errors(), 1);
        assert_eq!(policy_calls.load(Ordering::Relaxed), 0);
    }

    /// RFC 3414 Section 3.2 Step 5 precedes Step 6: an authPriv message for
    /// a user configured without privacy increments
    /// usmStatsUnsupportedSecLevels even when its HMAC is invalid, not
    /// usmStatsWrongDigests.
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[tokio::test]
    async fn test_v3_authpriv_for_auth_only_user_counts_unsupported_sec_level() {
        let receiver = remote_trap_receiver().await;
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let msg = build_v3_trap_bad_ciphertext(
            b"remote-sender-engine",
            b"trapuser",
            b"wrong-password-1234",
        );
        let result = receiver.handle_v3(msg, source).await.unwrap();
        assert!(result.is_none());
        assert_eq!(receiver.usm_unsupported_sec_levels(), 1);
        assert_eq!(receiver.usm_wrong_digests(), 0);
    }

    /// A USM-failed inform (Confirmed Class, reportableFlag set) gets a
    /// Report back (RFC 3412 Section 7.1 Step 3). The notInTimeWindows
    /// report carries the receiver's engine ID/boots/time for time
    /// resynchronization and is authenticated at authNoPriv
    /// (RFC 3414 Section 3.2 Step 7).
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[tokio::test]
    async fn test_v3_failed_inform_gets_authenticated_time_window_report() {
        use crate::message::V3Message;
        use crate::v3::auth::verify_message;
        use crate::v3::{LocalizedKey, UsmSecurityParams};

        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .engine_id(b"test-engine".to_vec())
            .engine_boots(1)
            .usm_user("informuser", |u| {
                u.auth(AuthProtocol::Sha1, b"authpass12345678")
            })
            .unwrap()
            .admit_all_notifications()
            .spawn()
            .await
            .unwrap();

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();

        let msg = build_authed_v3_inform(
            b"test-engine",
            1,
            5000, // outside the 150s window
            b"informuser",
            b"authpass12345678",
            AuthProtocol::Sha1,
        );
        assert!(receiver.handle_v3(msg, client_addr).await.is_err());

        let mut buf = vec![0u8; 4096];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.recv_from(&mut buf),
        )
        .await
        .expect("expected a Report in response to the failed inform")
        .unwrap();
        let report_bytes = Bytes::copy_from_slice(&buf[..len]);

        let report = V3Message::decode(report_bytes.clone(), crate::DecodeConfig::default())
            .unwrap()
            .value;
        assert_eq!(
            report.global_data.msg_flags.security_level,
            SecurityLevel::AuthNoPriv,
            "notInTimeWindows report must be authenticated (authNoPriv)"
        );
        assert!(!report.global_data.msg_flags.reportable);

        let report_usm = UsmSecurityParams::decode(
            report.security_params.clone(),
            crate::DecodeConfig::default(),
        )
        .unwrap()
        .value;
        assert_eq!(report_usm.engine_id.as_ref(), b"test-engine");

        // The HMAC must verify with the user's key localized to the
        // receiver's engine ID.
        let key =
            LocalizedKey::from_password(AuthProtocol::Sha1, b"authpass12345678", b"test-engine")
                .unwrap();
        let (auth_offset, auth_len) =
            UsmSecurityParams::find_auth_params_offset(&report_bytes).unwrap();
        assert!(verify_message(&key, &report_bytes, auth_offset, auth_len).unwrap());

        let scoped = report.scoped_pdu().expect("report should be plaintext");
        assert_eq!(scoped.pdu.pdu_type(), crate::pdu::PduType::Report);
        assert_eq!(
            scoped.pdu.varbinds[0].oid,
            crate::v3::report_oids::not_in_time_windows()
        );
    }

    /// RFC 3414 Section 3.2 Step 7a lists latched engine boots as a Time
    /// Window failure and mandates the report be authenticated at
    /// authNoPriv, like the other notInTimeWindows reports.
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[tokio::test]
    async fn test_v3_latched_boots_report_is_authenticated() {
        use crate::message::V3Message;
        use crate::v3::MAX_ENGINE_TIME;
        use crate::v3::auth::verify_message;
        use crate::v3::{LocalizedKey, UsmSecurityParams};

        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .engine_id(b"test-engine".to_vec())
            .engine_boots(MAX_ENGINE_TIME)
            .usm_user("informuser", |u| {
                u.auth(AuthProtocol::Sha1, b"authpass12345678")
            })
            .unwrap()
            .admit_all_notifications()
            .spawn()
            .await
            .unwrap();

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();

        let msg = build_authed_v3_inform(
            b"test-engine",
            MAX_ENGINE_TIME,
            0,
            b"informuser",
            b"authpass12345678",
            AuthProtocol::Sha1,
        );
        assert!(receiver.handle_v3(msg, client_addr).await.is_err());
        assert_eq!(receiver.usm_not_in_time_windows(), 1);

        let mut buf = vec![0u8; 4096];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.recv_from(&mut buf),
        )
        .await
        .expect("expected a Report in response to the failed inform")
        .unwrap();
        let report_bytes = Bytes::copy_from_slice(&buf[..len]);

        let report = V3Message::decode(report_bytes.clone(), crate::DecodeConfig::default())
            .unwrap()
            .value;
        assert_eq!(
            report.global_data.msg_flags.security_level,
            SecurityLevel::AuthNoPriv,
            "notInTimeWindows report must be authenticated (authNoPriv)"
        );
        let key =
            LocalizedKey::from_password(AuthProtocol::Sha1, b"authpass12345678", b"test-engine")
                .unwrap();
        let (auth_offset, auth_len) =
            UsmSecurityParams::find_auth_params_offset(&report_bytes).unwrap();
        assert!(verify_message(&key, &report_bytes, auth_offset, auth_len).unwrap());

        let scoped = report.scoped_pdu().expect("report should be plaintext");
        assert_eq!(
            scoped.pdu.varbinds[0].oid,
            crate::v3::report_oids::not_in_time_windows()
        );
    }

    /// A USM-failed inform for an unknown user gets an unauthenticated
    /// Report (no key exists to authenticate it with).
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[tokio::test]
    async fn test_v3_failed_inform_unknown_user_gets_noauth_report() {
        use crate::message::V3Message;
        use crate::v3::UsmSecurityParams;

        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .engine_id(b"test-engine".to_vec())
            .engine_boots(1)
            .usm_user("informuser", |u| {
                u.auth(AuthProtocol::Sha1, b"authpass12345678")
            })
            .unwrap()
            .admit_all_notifications()
            .spawn()
            .await
            .unwrap();

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();

        let msg = build_authed_v3_inform(
            b"test-engine",
            1,
            0,
            b"nosuchuser",
            b"authpass12345678",
            AuthProtocol::Sha1,
        );
        let result = receiver.handle_v3(msg, client_addr).await.unwrap();
        assert!(result.is_none());
        assert_eq!(receiver.usm_unknown_usernames(), 1);

        let mut buf = vec![0u8; 4096];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.recv_from(&mut buf),
        )
        .await
        .expect("expected a Report in response to the failed inform")
        .unwrap();

        let report = V3Message::decode(
            Bytes::copy_from_slice(&buf[..len]),
            crate::DecodeConfig::default(),
        )
        .unwrap()
        .value;
        assert_eq!(
            report.global_data.msg_flags.security_level,
            SecurityLevel::NoAuthNoPriv
        );
        let report_usm = UsmSecurityParams::decode(
            report.security_params.clone(),
            crate::DecodeConfig::default(),
        )
        .unwrap()
        .value;
        assert_eq!(report_usm.engine_id.as_ref(), b"test-engine");
        let scoped = report.scoped_pdu().expect("report should be plaintext");
        assert_eq!(scoped.pdu.pdu_type(), crate::pdu::PduType::Report);
        assert_eq!(
            scoped.pdu.varbinds[0].oid,
            crate::v3::report_oids::unknown_user_names()
        );
    }

    /// A USM-failed trap must NOT get a Report: traps are Unconfirmed Class
    /// and carry reportableFlag=0 (RFC 3412 Sections 6.4 and 7.1 Step 3).
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[tokio::test]
    async fn test_v3_failed_trap_gets_no_report() {
        let receiver = remote_trap_receiver().await;

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();

        let msg = build_v3_notification(
            crate::pdu::PduType::TrapV2,
            b"remote-sender-engine",
            7,
            123_456,
            b"trapuser",
            Some((b"wrong-password-1234", AuthProtocol::Sha1)),
        );
        assert!(receiver.handle_v3(msg, client_addr).await.is_err());
        assert_eq!(receiver.usm_wrong_digests(), 1);

        let mut buf = vec![0u8; 4096];
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            client.recv_from(&mut buf),
        )
        .await;
        assert!(result.is_err(), "no Report may be sent for a failed trap");
    }

    #[test]
    fn test_receiver_community_matching_preserves_allow_empty_policy() {
        // Empty allowlist accepts any community (opt-in filtering).
        assert!(community_matches(
            &[],
            b"public",
            EmptyCommunityPolicy::Allow
        ));
        assert!(community_matches(&[], b"", EmptyCommunityPolicy::Allow));

        let configured = vec![Community::from("public"), Community::from("monitor")];
        assert!(community_matches(
            &configured,
            b"public",
            EmptyCommunityPolicy::Allow
        ));
        assert!(community_matches(
            &configured,
            b"monitor",
            EmptyCommunityPolicy::Allow
        ));
        // Non-matching, prefix, and length-mismatch are all rejected.
        for community in [b"private".as_slice(), b"pub", b"publicx", b""] {
            assert!(!community_matches(
                &configured,
                community,
                EmptyCommunityPolicy::Allow
            ));
        }
    }

    pub(super) fn build_v2c_trap(community: &[u8]) -> Bytes {
        build_v2c_trap_with_request_id(community, 1)
    }

    pub(super) fn build_v2c_trap_with_request_id(community: &[u8], request_id: i32) -> Bytes {
        use crate::message::CommunityMessage;
        use crate::pdu::Pdu;
        let pdu = Pdu::trap_v2(request_id, 100, &oids::cold_start(), vec![]);
        CommunityMessage::v2c(Bytes::copy_from_slice(community), pdu)
            .unwrap()
            .encode()
            .unwrap()
    }

    pub(super) fn build_v2c_inform(community: &[u8]) -> Bytes {
        use crate::message::CommunityMessage;
        use crate::pdu::Pdu;
        let pdu = Pdu::inform_request(1, 100, &oids::cold_start(), vec![]);
        CommunityMessage::v2c(Bytes::copy_from_slice(community), pdu)
            .unwrap()
            .encode()
            .unwrap()
    }

    fn build_oversized_v2c_inform(community: &[u8]) -> Bytes {
        use crate::message::CommunityMessage;
        use crate::pdu::Pdu;
        let pdu = Pdu::inform_request(
            1,
            100,
            &oids::cold_start(),
            vec![VarBind::new(
                crate::oid!(1, 3, 6, 1, 4, 1, 99999, 1),
                crate::Value::OctetString(Bytes::from(vec![0x44; 512])),
            )],
        );
        CommunityMessage::v2c(Bytes::copy_from_slice(community), pdu)
            .unwrap()
            .encode()
            .unwrap()
    }

    fn build_v1_trap(community: &[u8]) -> Bytes {
        use crate::message::CommunityMessage;
        use crate::pdu::GenericTrap;
        let trap = TrapV1Pdu::new(
            oid!(1, 3, 6, 1, 4, 1, 9999),
            [192, 168, 1, 1],
            GenericTrap::ColdStart,
            0,
            12345,
            vec![],
        );
        CommunityMessage::v1_trap(Bytes::copy_from_slice(community), trap)
            .unwrap()
            .encode()
            .unwrap()
    }

    fn push_malformed_integer_varbind(buf: &mut crate::ber::EncodeBuf) -> crate::Result<()> {
        buf.push_sequence(|buf| {
            buf.push_bytes(&[0x02, 0x05, 1, 0, 0, 0, 9]);
            buf.push_oid(&oid!(1, 3, 6, 1, 4, 1, 9999, 1, 0))
        })
    }

    fn build_notification_with_malformed_integer(version: crate::Version) -> Bytes {
        let mut buf = crate::ber::EncodeBuf::new();
        buf.push_sequence(|buf| {
            match version {
                crate::Version::V1 => {
                    buf.push_constructed(crate::ber::tag::pdu::TRAP_V1, |buf| {
                        buf.push_sequence(push_malformed_integer_varbind)?;
                        buf.push_unsigned32(crate::ber::tag::application::TIMETICKS, 123);
                        buf.push_integer(0);
                        buf.push_integer(0);
                        buf.push_ip_address([127, 0, 0, 1]);
                        buf.push_oid(&oid!(1, 3, 6, 1, 4, 1, 9999))
                    })?;
                }
                crate::Version::V2c => {
                    buf.push_constructed(crate::ber::tag::pdu::TRAP_V2, |buf| {
                        buf.push_sequence(|buf| {
                            push_malformed_integer_varbind(buf)?;
                            crate::VarBind::new(
                                oids::snmp_trap_oid(),
                                crate::Value::ObjectIdentifier(oids::cold_start()),
                            )
                            .encode(buf)?;
                            crate::VarBind::new(oids::sys_uptime(), crate::Value::TimeTicks(123))
                                .encode(buf)
                        })?;
                        buf.push_integer(0);
                        buf.push_integer(0);
                        buf.push_integer(41);
                        Ok(())
                    })?;
                }
                crate::Version::V3 => unreachable!(),
            }
            buf.push_octet_string(b"public")?;
            buf.push_integer(version.as_i32());
            Ok(())
        })
        .unwrap();
        buf.finish()
    }

    #[tokio::test]
    async fn test_v2c_trap_matching_community_accepted() {
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .spawn()
            .await
            .unwrap();
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let result = receiver
            .handle_v2c(build_v2c_trap(b"public"), source)
            .await
            .unwrap();
        assert!(matches!(
            result,
            Some(ReceivedNotification {
                notification: Notification::TrapV2c { .. },
                ..
            })
        ));
    }

    #[tokio::test]
    async fn received_metadata_preserves_complete_datagrams_and_policy_identity() {
        let observed = Arc::new(Mutex::new(Vec::new()));
        let policy_observed = observed.clone();
        let mut receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .admission_policy(move |envelope: &NotificationAdmissionInfo<'_>| {
                policy_observed.lock().unwrap().push(envelope.receive_info);
                NotificationAdmissionDecision::Admit
            })
            .spawn()
            .await
            .unwrap();
        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut endpoint = None;
        for (message, suffix) in [
            (build_v1_trap(b"public"), 512),
            (build_v2c_trap(b"public"), 0),
            (build_v2c_inform(b"public"), 5),
        ] {
            let mut bytes = message.to_vec();
            bytes.resize(bytes.len() + suffix, 0xa5);
            let before = tokio::time::Instant::now();
            sender.send_to(&bytes, receiver.local_addr()).await.unwrap();
            let received = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
                .await
                .unwrap()
                .unwrap();
            let info = received.receive_info;
            assert_eq!(info.received_len(), bytes.len());
            assert_eq!(info.peer_addr(), sender.local_addr().unwrap());
            assert_eq!(info.local_addr(), receiver.local_addr());
            assert_eq!(info.transport(), crate::TransportKind::Udp);
            assert_eq!(info.session_id(), None);
            assert!(info.received_at() >= before);
            assert!(info.received_at() <= tokio::time::Instant::now());
            assert_eq!(observed.lock().unwrap().last(), Some(&info));
            if let Some(endpoint) = endpoint {
                assert_eq!(info.endpoint_id(), endpoint);
            }
            endpoint = Some(info.endpoint_id());
        }
    }

    #[tokio::test]
    async fn community_receiver_exposes_trailing_anomalies_in_delivered_notification() {
        let receiver = NotificationReceiver::spawn("127.0.0.1:0").await.unwrap();
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        for (version, mut encoded) in [
            (crate::Version::V1, build_v1_trap(b"public").to_vec()),
            (crate::Version::V2c, build_v2c_trap(b"public").to_vec()),
        ] {
            encoded.extend_from_slice(&[0x05, 0]);
            let notification = match version {
                crate::Version::V1 => receiver.handle_v1(Bytes::from(encoded), source).await,
                crate::Version::V2c => receiver.handle_v2c(Bytes::from(encoded), source).await,
                crate::Version::V3 => unreachable!(),
            }
            .unwrap()
            .unwrap();
            let expected = [crate::DecodeAnomaly::TrailingBytes {
                original_length: 2,
                canonical_length: 0,
            }];
            assert_eq!(notification.notification.decode_anomalies(), expected);
        }
    }

    #[tokio::test]
    async fn strict_receiver_rejects_suffixes_for_v1_and_v2c() {
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .decode_config(crate::DecodeConfig::STRICT)
            .spawn()
            .await
            .unwrap();
        let source = "127.0.0.1:9999".parse().unwrap();
        for (version, mut packet) in [
            (crate::Version::V1, build_v1_trap(b"public").to_vec()),
            (crate::Version::V2c, build_v2c_trap(b"public").to_vec()),
        ] {
            packet.extend_from_slice(&[0x05, 0]);
            let result = match version {
                crate::Version::V1 => receiver.handle_v1(Bytes::from(packet), source).await,
                crate::Version::V2c => receiver.handle_v2c(Bytes::from(packet), source).await,
                crate::Version::V3 => unreachable!(),
            };
            assert!(result.is_err(), "strict {version:?} accepted a suffix");
        }
    }

    #[tokio::test]
    async fn community_receiver_supports_strict_and_targeted_value_policy() {
        let source = "127.0.0.1:9999".parse().unwrap();
        for version in [crate::Version::V1, crate::Version::V2c] {
            let strict = NotificationReceiver::builder()
                .bind("127.0.0.1:0")
                .decode_config(crate::DecodeConfig::STRICT)
                .spawn()
                .await
                .unwrap();
            let packet = build_notification_with_malformed_integer(version);
            let result = match version {
                crate::Version::V1 => strict.handle_v1(packet, source).await,
                crate::Version::V2c => strict.handle_v2c(packet, source).await,
                crate::Version::V3 => unreachable!(),
            };
            assert!(result.is_err());

            let mut targeted = crate::DecodeConfig::STRICT;
            targeted.truncate_numeric_values = true;
            let receiver = NotificationReceiver::builder()
                .bind("127.0.0.1:0")
                .decode_config(targeted)
                .spawn()
                .await
                .unwrap();
            let packet = build_notification_with_malformed_integer(version);
            let notification = match version {
                crate::Version::V1 => receiver.handle_v1(packet, source).await,
                crate::Version::V2c => receiver.handle_v2c(packet, source).await,
                crate::Version::V3 => unreachable!(),
            }
            .unwrap()
            .unwrap();
            assert!(matches!(
                notification.notification.decode_anomalies(),
                [crate::DecodeAnomaly::SignedIntegerTruncation {
                    encoded_length: 5,
                    ..
                }]
            ));
        }
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[tokio::test]
    async fn v3_receiver_exposes_trailing_anomalies_at_all_security_levels() {
        let engine_id = Bytes::from_static(b"\x80\x00\x00\x00\x01anomalyrecv");
        let username = Bytes::from_static(b"anomalyuser");

        for level in [
            SecurityLevel::NoAuthNoPriv,
            SecurityLevel::AuthNoPriv,
            SecurityLevel::AuthPriv,
        ] {
            let (message, _, _) = build_v3_inform_at_level(
                &engine_id,
                &username,
                level,
                crate::UDP_RECEIVE_LIMITS.advertised(),
            );
            let config = inform_user(level, &username);
            let mut receiver = NotificationReceiver::builder()
                .bind("127.0.0.1:0")
                .authoritative_engine(AuthoritativeEngine::for_test(engine_id.clone(), 1))
                .usm_user(username.clone(), move |_| Ok(config))
                .unwrap()
                .admit_all_notifications()
                .spawn()
                .await
                .unwrap();
            let source_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut message = message.to_vec();
            message.extend_from_slice(&[0x05, 0]);
            let received_len = message.len();
            source_socket
                .send_to(&message, receiver.local_addr())
                .await
                .unwrap();
            let notification = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(notification.receive_info.received_len(), received_len);
            assert_eq!(
                notification.receive_info.peer_addr(),
                source_socket.local_addr().unwrap()
            );
            assert_eq!(
                notification.notification.decode_anomalies(),
                [crate::DecodeAnomaly::TrailingBytes {
                    original_length: 2,
                    canonical_length: 0,
                }]
            );
        }
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[tokio::test]
    async fn strict_v3_receiver_rejects_suffixes_at_all_security_levels() {
        let engine_id = Bytes::from_static(b"\x80\x00\x00\x00\x01strictrecv");
        let username = Bytes::from_static(b"strictuser");
        for level in [
            SecurityLevel::NoAuthNoPriv,
            SecurityLevel::AuthNoPriv,
            SecurityLevel::AuthPriv,
        ] {
            let (message, _, _) = build_v3_inform_at_level(
                &engine_id,
                &username,
                level,
                crate::UDP_RECEIVE_LIMITS.advertised(),
            );
            let config = inform_user(level, &username);
            let receiver = NotificationReceiver::builder()
                .bind("127.0.0.1:0")
                .authoritative_engine(AuthoritativeEngine::for_test(engine_id.clone(), 1))
                .usm_user(username.clone(), move |_| Ok(config))
                .unwrap()
                .admit_all_notifications()
                .decode_config(crate::DecodeConfig::STRICT)
                .spawn()
                .await
                .unwrap();
            let mut message = message.to_vec();
            message.extend_from_slice(&[0x05, 0]);
            let result = receiver
                .handle_v3(Bytes::from(message), "127.0.0.1:9999".parse().unwrap())
                .await;
            assert!(result.is_err(), "strict {level:?} accepted a suffix");
        }
    }

    #[tokio::test]
    async fn test_v2c_trap_wrong_community_dropped() {
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .spawn()
            .await
            .unwrap();
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let result = receiver
            .handle_v2c(build_v2c_trap(b"private"), source)
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_v2c_trap_no_allowlist_accepts_any_community() {
        let receiver = NotificationReceiver::spawn("127.0.0.1:0").await.unwrap();
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let result = receiver
            .handle_v2c(build_v2c_trap(b"anything"), source)
            .await
            .unwrap();
        assert!(matches!(
            result,
            Some(ReceivedNotification {
                notification: Notification::TrapV2c { .. },
                ..
            })
        ));
    }

    #[tokio::test]
    async fn test_v1_trap_wrong_community_dropped() {
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .spawn()
            .await
            .unwrap();
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        assert!(
            receiver
                .handle_v1(build_v1_trap(b"private"), source)
                .await
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            receiver
                .handle_v1(build_v1_trap(b"public"), source)
                .await
                .unwrap(),
            Some(ReceivedNotification {
                notification: Notification::TrapV1 { .. },
                ..
            })
        ));
    }

    #[tokio::test]
    async fn admission_info_normalizes_v1_identity_and_oid() {
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .admission_policy(move |notification: &NotificationAdmissionInfo<'_>| {
                assert_eq!(notification.receive_info.peer_addr(), source);
                assert_eq!(notification.version, Version::V1);
                assert_eq!(
                    notification.community.map(Community::as_bytes),
                    Some(b"public".as_slice())
                );
                assert_eq!(notification.username, None);
                assert_eq!(notification.security_level, None);
                assert_eq!(notification.pdu_class, NotificationPduClass::Trap);
                assert_eq!(notification.context_engine_id, None);
                assert_eq!(notification.context_name, None);
                assert_eq!(notification.authoritative_engine_id, None);
                assert_eq!(notification.trap_oid().unwrap(), oids::cold_start());
                NotificationAdmissionDecision::Admit
            })
            .spawn()
            .await
            .unwrap();

        assert!(matches!(
            receiver
                .handle_v1(build_v1_trap(b"public"), source)
                .await
                .unwrap(),
            Some(ReceivedNotification {
                notification: Notification::TrapV1 { .. },
                ..
            })
        ));
    }

    /// An inform rejected by the community filter is dropped before the ack is
    /// built, so no Response datagram is sent to the source.
    #[tokio::test]
    async fn test_v2c_inform_wrong_community_dropped_without_ack() {
        let policy_calls = Arc::new(AtomicU32::new(0));
        let policy_calls_for_receiver = Arc::clone(&policy_calls);
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .admission_policy(move |_: &NotificationAdmissionInfo<'_>| {
                policy_calls_for_receiver.fetch_add(1, Ordering::Relaxed);
                NotificationAdmissionDecision::Admit
            })
            .spawn()
            .await
            .unwrap();

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();

        let result = receiver
            .handle_v2c(build_v2c_inform(b"private"), client_addr)
            .await
            .unwrap();
        assert!(result.is_none());

        let mut buf = vec![0u8; 4096];
        let recv = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            client.recv_from(&mut buf),
        )
        .await;
        assert!(recv.is_err(), "a filtered inform must not be acknowledged");
        assert_eq!(policy_calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn admission_policy_rejects_v2c_inform_by_oid_before_sizing() {
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let source = client.local_addr().unwrap();
        let message = build_oversized_v2c_inform(b"public");
        for limit in [message.len(), message.len() - 1, 1] {
            let calls = Arc::new(AtomicU32::new(0));
            let calls_for_policy = Arc::clone(&calls);
            let receiver = NotificationReceiver::builder()
                .bind("127.0.0.1:0")
                .community(b"public")
                .admission_policy(move |notification: &NotificationAdmissionInfo<'_>| {
                    assert_eq!(notification.receive_info.peer_addr(), source);
                    assert_eq!(notification.version, Version::V2c);
                    assert_eq!(
                        notification.community.map(Community::as_bytes),
                        Some(b"public".as_slice())
                    );
                    assert_eq!(notification.authoritative_engine_id, None);
                    assert_eq!(notification.username, None);
                    assert_eq!(notification.security_level, None);
                    assert_eq!(notification.pdu_class, NotificationPduClass::Inform);
                    assert_eq!(notification.context_engine_id, None);
                    assert_eq!(notification.context_name, None);
                    calls_for_policy.fetch_add(1, Ordering::Relaxed);
                    if notification
                        .trap_oid()
                        .is_ok_and(|oid| oid == oids::cold_start())
                    {
                        NotificationAdmissionDecision::Reject
                    } else {
                        NotificationAdmissionDecision::Admit
                    }
                })
                .max_message_size(limit)
                .spawn()
                .await
                .unwrap();
            assert!(
                receiver
                    .handle_v2c(message.clone(), source)
                    .await
                    .unwrap()
                    .is_none()
            );
            assert_eq!(calls.load(Ordering::Relaxed), 1);
            assert_eq!(receiver.snmp_silent_drops(), 0);
            let mut reply = [0];
            assert!(
                tokio::time::timeout(Duration::from_millis(50), client.recv_from(&mut reply))
                    .await
                    .is_err(),
                "denied v2c Inform produced a reply at limit {limit}"
            );
        }
    }

    #[tokio::test]
    async fn admission_policy_error_rejects_inform_without_ack() {
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .max_message_size(1)
            .try_admission_policy(|_: &NotificationAdmissionInfo<'_>| {
                Err(NotificationAdmissionError::new(
                    "policy backend unavailable",
                ))
            })
            .spawn()
            .await
            .unwrap();
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let result = receiver
            .handle_v2c(build_v2c_inform(b"public"), client.local_addr().unwrap())
            .await
            .unwrap();
        assert!(result.is_none());
        assert_eq!(receiver.snmp_silent_drops(), 0);
        let mut buf = [0_u8; 1];
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(50),
                client.recv_from(&mut buf),
            )
            .await
            .is_err(),
            "failed policy must not acknowledge an Inform"
        );
    }

    #[tokio::test]
    async fn admission_policy_panic_rejects_inform_and_recv_continues_to_next_datagram() {
        let calls = Arc::new(AtomicU32::new(0));
        let calls_for_receiver = Arc::clone(&calls);
        let inform = build_v2c_inform(b"public");
        let mut receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .max_message_size(inform.len() - 1)
            .admission_policy(move |_: &NotificationAdmissionInfo<'_>| {
                if calls_for_receiver.fetch_add(1, Ordering::Relaxed) == 0 {
                    panic!("policy failure");
                }
                NotificationAdmissionDecision::Admit
            })
            .spawn()
            .await
            .unwrap();
        let receiver_addr = receiver.local_addr();
        let receive = tokio::spawn(async move { receiver.recv().await });
        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

        sender.send_to(&inform, receiver_addr).await.unwrap();
        let mut buf = [0_u8; 1];
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(50),
                sender.recv_from(&mut buf),
            )
            .await
            .is_err(),
            "panicking policy must not acknowledge an Inform"
        );

        sender
            .send_to(&build_v2c_trap(b"public"), receiver_addr)
            .await
            .unwrap();
        let received = tokio::time::timeout(std::time::Duration::from_secs(1), receive)
            .await
            .expect("receiver did not continue after policy panic")
            .unwrap()
            .unwrap();
        assert_eq!(
            received.receive_info.peer_addr(),
            sender.local_addr().unwrap()
        );
        assert!(matches!(
            received.notification,
            Notification::TrapV2c { .. }
        ));
        assert_eq!(calls.load(Ordering::Relaxed), 2);
    }

    /// A matching inform is still acknowledged (the filter does not suppress
    /// valid acks).
    #[tokio::test]
    async fn test_v2c_inform_matching_community_acked() {
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .spawn()
            .await
            .unwrap();

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();

        let received = receiver
            .handle_v2c(build_v2c_inform(b"public"), client_addr)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            received.notification,
            Notification::InformV2c { .. }
        ));
        assert_eq!(received.wire_identity.version, Version::V2c);
        assert_eq!(received.wire_identity.request_id, Some(1));
        assert!(received.wire_identity.v3.is_none());
        assert!(matches!(
            received.inform_ack,
            crate::NotificationAcknowledgement::Completed(InformAckOutcome::Sent)
        ));

        let mut buf = vec![0u8; 4096];
        let (len, ack_source) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.recv_from(&mut buf),
        )
        .await
        .expect("a matching inform must be acknowledged")
        .unwrap();
        assert!(len > 0);
        assert_eq!(ack_source, receiver.local_addr());
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(50),
                client.recv_from(&mut buf),
            )
            .await
            .is_err(),
            "one accepted Inform must produce exactly one acknowledgement"
        );
    }

    #[tokio::test]
    async fn each_accepted_inform_datagram_is_returned_exactly_once() {
        let mut receiver = NotificationReceiver::spawn("127.0.0.1:0").await.unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let message = build_v2c_inform(b"public");

        sender
            .send_to(&message, receiver.local_addr())
            .await
            .unwrap();
        let first = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
            .await
            .expect("accepted Inform was not returned")
            .unwrap();
        assert_eq!(first.receive_info.peer_addr(), sender.local_addr().unwrap());
        assert_eq!(first.wire_identity.request_id, Some(1));
        assert!(matches!(
            first.inform_ack,
            crate::NotificationAcknowledgement::Completed(InformAckOutcome::Sent)
        ));

        assert!(
            tokio::time::timeout(Duration::from_millis(25), receiver.recv())
                .await
                .is_err(),
            "one accepted datagram was returned more than once"
        );

        // An identical retry is a second accepted datagram and therefore a
        // second application event; wire identity is not semantic deduplication.
        sender
            .send_to(&message, receiver.local_addr())
            .await
            .unwrap();
        let retry = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
            .await
            .expect("accepted Inform retry was not returned")
            .unwrap();
        assert_eq!(retry.wire_identity, first.wire_identity);
        assert!(matches!(
            retry.inform_ack,
            crate::NotificationAcknowledgement::Completed(InformAckOutcome::Sent)
        ));
    }

    #[tokio::test]
    async fn zero_response_timeout_emits_no_inform_acknowledgement() {
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .response_send_timeout(Duration::ZERO)
            .spawn()
            .await
            .unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let received = receiver
            .handle_v2c(build_v2c_inform(b"public"), sender.local_addr().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            received.inform_ack,
            crate::NotificationAcknowledgement::Completed(InformAckOutcome::Failed(error))
                if error.kind() == crate::ErrorKind::Timeout
        ));
        let mut buf = [0u8; 16];
        assert!(
            tokio::time::timeout(Duration::from_millis(25), sender.recv_from(&mut buf))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn accepted_v2c_inform_reports_construction_and_non_timeout_send_failures() {
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let receiver = NotificationReceiver::spawn("127.0.0.1:0").await.unwrap();
        receiver
            .inner
            .response_construction_errors
            .lock()
            .unwrap()
            .push_back(Error::InvalidMessage("injected construction failure".into()).boxed());
        let received = receiver
            .handle_v2c(build_v2c_inform(b"public"), source)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            received.inform_ack,
            crate::NotificationAcknowledgement::Completed(InformAckOutcome::Failed(error))
                if error.kind() == crate::ErrorKind::InvalidMessage
        ));

        receiver
            .inner
            .response_send_errors
            .lock()
            .unwrap()
            .push_back(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
        let received = receiver
            .handle_v2c(build_v2c_inform(b"public"), source)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            received.inform_ack,
            crate::NotificationAcknowledgement::Completed(InformAckOutcome::Failed(error))
                if matches!(&*error, Error::Network { source, .. }
                    if source.kind() == std::io::ErrorKind::BrokenPipe)
        ));
    }

    #[tokio::test]
    async fn accepted_v3_inform_reports_construction_send_and_timeout_failures() {
        let engine_id = Bytes::from_static(b"local-inform-engine");
        for failure in ["construction", "send", "timeout"] {
            let receiver = NotificationReceiver::builder()
                .bind("127.0.0.1:0")
                .authoritative_engine(AuthoritativeEngine::for_test(engine_id.clone(), 1))
                .usm_user("informuser", Ok)
                .unwrap()
                .admit_all_notifications()
                .response_send_timeout(if failure == "timeout" {
                    Duration::ZERO
                } else {
                    Duration::from_secs(1)
                })
                .spawn()
                .await
                .unwrap();
            if failure == "construction" {
                receiver
                    .inner
                    .response_construction_errors
                    .lock()
                    .unwrap()
                    .push_back(
                        Error::InvalidMessage("injected construction failure".into()).boxed(),
                    );
            } else if failure == "send" {
                receiver
                    .inner
                    .response_send_errors
                    .lock()
                    .unwrap()
                    .push_back(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
            }
            let received = receiver
                .handle_v3(
                    build_noauth_v3_inform(&engine_id, b"informuser"),
                    "127.0.0.1:9999".parse().unwrap(),
                )
                .await
                .unwrap()
                .unwrap();
            match (failure, received.inform_ack) {
                (
                    "construction",
                    crate::NotificationAcknowledgement::Completed(InformAckOutcome::Failed(error)),
                ) => {
                    assert_eq!(error.kind(), crate::ErrorKind::InvalidMessage);
                }
                (
                    "send",
                    crate::NotificationAcknowledgement::Completed(InformAckOutcome::Failed(error)),
                ) => assert!(matches!(
                    &*error,
                    Error::Network { source, .. }
                        if source.kind() == std::io::ErrorKind::BrokenPipe
                )),
                (
                    "timeout",
                    crate::NotificationAcknowledgement::Completed(InformAckOutcome::Failed(error)),
                ) => assert_eq!(error.kind(), crate::ErrorKind::Timeout),
                other => panic!("unexpected acknowledgement result: {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn v2c_inform_preflight_sizes_original_error_index() {
        use crate::ber::{EncodeBuf, tag};
        use crate::message::CommunityMessage;
        use crate::pdu::Pdu;

        let request_id = 43;
        let request = Pdu::inform_request(request_id, 100, &oids::cold_start(), vec![]);
        let ordinary = CommunityMessage::v2c("public", request.to_response(Version::V2c).unwrap())
            .unwrap()
            .encode()
            .unwrap();

        // RFC 3416 §4.2.7 sizes the original error-index before normalizing it
        // to zero. Encode the received fields directly because the outbound
        // Inform encoder requires zero error fields.
        let mut buf = EncodeBuf::new();
        buf.push_sequence(|buf| {
            buf.push_constructed(tag::pdu::INFORM_REQUEST, |buf| {
                crate::varbind::encode_varbind_list(buf, request.varbinds())?;
                buf.push_integer(128);
                buf.push_integer(0);
                buf.push_integer(request_id);
                Ok(())
            })?;
            buf.push_octet_string(b"public")?;
            buf.push_integer(Version::V2c.as_i32());
            Ok(())
        })
        .unwrap();
        let incoming = buf.finish();
        assert_eq!(incoming.len(), ordinary.len() + 1);

        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .max_message_size(ordinary.len())
            .spawn()
            .await
            .unwrap();
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let delivered = receiver
            .handle_v2c(incoming, client.local_addr().unwrap())
            .await
            .unwrap();
        assert!(delivered.is_none());

        let mut buf = [0; 128];
        let (len, _) = tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let response = CommunityMessage::decode(
            Bytes::copy_from_slice(&buf[..len]),
            crate::DecodeConfig::DEFAULT,
        )
        .unwrap()
        .value;
        let pdu = response.pdu().standard().unwrap();
        assert_eq!(pdu.pdu_type(), crate::PduType::Response);
        assert_eq!(pdu.request_id(), request_id);
        assert_eq!(pdu.error_status(), crate::ErrorStatus::TooBig.as_i32());
        assert_eq!(pdu.error_index(), 0);
        assert!(pdu.varbinds().is_empty());
        assert_eq!(receiver.snmp_silent_drops(), 0);
    }

    #[tokio::test]
    async fn oversized_v2c_inform_uses_fitting_toobig_without_counting_drop() {
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .max_message_size(80)
            .spawn()
            .await
            .unwrap();
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let received = receiver
            .handle_v2c(
                build_oversized_v2c_inform(b"public"),
                client.local_addr().unwrap(),
            )
            .await
            .unwrap();
        assert!(received.is_none());

        let mut buf = vec![0; 1024];
        let (len, _) = client.recv_from(&mut buf).await.unwrap();
        let response = crate::message::CommunityMessage::decode(
            Bytes::copy_from_slice(&buf[..len]),
            crate::DecodeConfig::default(),
        )
        .unwrap()
        .value;
        let pdu = response.pdu().standard().unwrap();
        assert_eq!(pdu.error_status(), crate::ErrorStatus::TooBig.as_i32());
        assert!(pdu.varbinds.is_empty());
        assert_eq!(receiver.snmp_silent_drops(), 0);
    }

    #[tokio::test]
    async fn inform_counts_only_when_toobig_alternate_cannot_fit() {
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .max_message_size(1)
            .spawn()
            .await
            .unwrap();
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let received = receiver
            .handle_v2c(
                build_oversized_v2c_inform(b"public"),
                client.local_addr().unwrap(),
            )
            .await
            .unwrap();
        assert!(received.is_none());
        assert_eq!(receiver.snmp_silent_drops(), 1);

        let mut buf = [0; 64];
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), client.recv(&mut buf))
                .await
                .is_err()
        );

        receiver
            .handle_v2c(build_v2c_trap(b"public"), client.local_addr().unwrap())
            .await
            .unwrap();
        assert_eq!(receiver.snmp_silent_drops(), 1);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn wildcard_ipv4_inform_reply_uses_received_destination_as_source() {
        let mut receiver = NotificationReceiver::spawn("0.0.0.0:0").await.unwrap();
        let destination = SocketAddr::from(([127, 0, 0, 2], receiver.local_addr().port()));
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let receive_task = tokio::spawn(async move { receiver.recv().await });
        client
            .send_to(&build_v2c_inform(b"public"), destination)
            .await
            .unwrap();

        let mut response = [0_u8; 1024];
        let (_, source) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.recv_from(&mut response),
        )
        .await
        .expect("wildcard receiver did not acknowledge Inform")
        .unwrap();
        assert_eq!(source.ip(), destination.ip());

        let received = receive_task.await.unwrap().unwrap();
        assert_eq!(
            received
                .receive_info
                .datagram_destination()
                .map(|ip| ip.to_canonical()),
            Some(destination.ip().to_canonical())
        );
        assert!(received.receive_info.local_addr().ip().is_unspecified());
        assert!(matches!(
            received.notification,
            Notification::InformV2c { .. }
        ));
        let client_addr = client.local_addr().unwrap();
        assert_eq!(received.receive_info.peer_addr().port(), client_addr.port());
        assert_eq!(
            received.receive_info.peer_addr().ip().to_canonical(),
            client_addr.ip().to_canonical()
        );
    }

    #[cfg(not(target_os = "macos"))]
    #[tokio::test]
    async fn receive_buffer_reuses_capacity_at_udp_boundaries() {
        let mut receiver = NotificationReceiver::spawn("127.0.0.1:0").await.unwrap();
        let destination = receiver.local_addr();
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let mut maximum_datagram = build_v2c_trap_with_request_id(b"public", 70).to_vec();
        let message_len = maximum_datagram.len();
        maximum_datagram.resize(crate::MAX_UDP_PAYLOAD, 0xa5);
        assert_eq!(
            client
                .send_to(&maximum_datagram, destination)
                .await
                .unwrap(),
            crate::MAX_UDP_PAYLOAD
        );

        let received = tokio::time::timeout(std::time::Duration::from_secs(2), receiver.recv())
            .await
            .expect("maximum UDP notification stalled")
            .unwrap();
        assert_eq!(received.receive_info.received_len(), crate::MAX_UDP_PAYLOAD);
        let Notification::TrapV2c {
            request_id,
            decode_anomalies,
            ..
        } = received.notification
        else {
            panic!("expected v2c trap")
        };
        assert_eq!(request_id, 70);
        assert_eq!(
            decode_anomalies,
            vec![crate::DecodeAnomaly::TrailingBytes {
                original_length: crate::MAX_UDP_PAYLOAD - message_len,
                canonical_length: 0,
            }],
            "the maximum legal IPv4 UDP payload must not be truncated"
        );

        client
            .send_to(&build_v2c_trap_with_request_id(b"public", 71), destination)
            .await
            .unwrap();
        let received = receiver.recv().await.unwrap();
        assert!(matches!(
            received.notification,
            Notification::TrapV2c { request_id: 71, .. }
        ));
    }

    #[cfg(not(target_os = "macos"))]
    #[tokio::test]
    async fn receive_buffer_accepts_maximum_native_ipv6_udp_payload() {
        const IPV6_MAX_UDP_PAYLOAD: usize = 65_527;

        let mut receiver = NotificationReceiver::spawn("[::1]:0").await.unwrap();
        let destination = receiver.local_addr();
        let client = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();

        let mut maximum_datagram = build_v2c_trap_with_request_id(b"public", 72).to_vec();
        let message_len = maximum_datagram.len();
        maximum_datagram.resize(IPV6_MAX_UDP_PAYLOAD, 0xa5);
        assert_eq!(
            client
                .send_to(&maximum_datagram, destination)
                .await
                .unwrap(),
            IPV6_MAX_UDP_PAYLOAD
        );

        let received = tokio::time::timeout(std::time::Duration::from_secs(2), receiver.recv())
            .await
            .expect("maximum native IPv6 UDP notification stalled")
            .unwrap();
        let Notification::TrapV2c {
            request_id,
            decode_anomalies,
            ..
        } = received.notification
        else {
            panic!("expected v2c trap")
        };
        assert_eq!(request_id, 72);
        assert_eq!(
            decode_anomalies,
            vec![crate::DecodeAnomaly::TrailingBytes {
                original_length: IPV6_MAX_UDP_PAYLOAD - message_len,
                canonical_length: 0,
            }],
            "the maximum legal native IPv6 UDP payload must not be truncated"
        );
    }

    #[tokio::test]
    async fn receive_buffer_survives_skipped_datagrams_policy_errors_and_panics() {
        let mut receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .try_admission_policy(
                |notification: &NotificationAdmissionInfo<'_>| match notification
                    .community
                    .map(Community::as_bytes)
                {
                    Some(b"reject") => Ok(NotificationAdmissionDecision::Reject),
                    Some(b"error") => Err(NotificationAdmissionError::new("injected policy error")),
                    Some(b"panic") => panic!("injected policy panic"),
                    _ => Ok(NotificationAdmissionDecision::Admit),
                },
            )
            .spawn()
            .await
            .unwrap();
        let destination = receiver.local_addr();
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

        for datagram in [
            Bytes::from_static(&[0x30, 0x01, 0xff]),
            build_v2c_trap_with_request_id(b"reject", 1),
            build_v2c_trap_with_request_id(b"error", 2),
            build_v2c_trap_with_request_id(b"panic", 3),
            build_v2c_trap_with_request_id(b"public", 4),
        ] {
            client.send_to(&datagram, destination).await.unwrap();
        }

        let received = tokio::time::timeout(std::time::Duration::from_secs(1), receiver.recv())
            .await
            .expect("receiver did not advance past skipped datagrams")
            .unwrap();
        assert!(matches!(
            received.notification,
            Notification::TrapV2c { request_id: 4, .. }
        ));
    }

    /// A dual-stack IPv6 wildcard socket receives this IPv4 datagram through
    /// an IPv4-mapped address. The two loopback aliases make source selection
    /// deterministic without requiring host network configuration.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn wildcard_ipv6_dual_stack_inform_reply_preserves_mapped_destination() {
        let mut receiver = NotificationReceiver::spawn("[::]:0").await.unwrap();
        let destination = SocketAddr::from(([127, 0, 0, 2], receiver.local_addr().port()));
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let receive_task = tokio::spawn(async move { receiver.recv().await });
        client
            .send_to(&build_v2c_inform(b"public"), destination)
            .await
            .unwrap();

        let mut response = [0_u8; 1024];
        let (_, source) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.recv_from(&mut response),
        )
        .await
        .expect("dual-stack wildcard receiver did not acknowledge Inform")
        .unwrap();
        assert_eq!(source.ip(), destination.ip());

        let received = receive_task.await.unwrap().unwrap();
        assert_eq!(
            received
                .receive_info
                .datagram_destination()
                .map(|ip| ip.to_canonical()),
            Some(destination.ip().to_canonical())
        );
        assert!(received.receive_info.local_addr().ip().is_unspecified());
        assert!(matches!(
            received.notification,
            Notification::InformV2c { .. }
        ));
        let client_addr = client.local_addr().unwrap();
        assert_eq!(received.receive_info.peer_addr().port(), client_addr.port());
        assert_eq!(
            received.receive_info.peer_addr().ip().to_canonical(),
            client_addr.ip().to_canonical()
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn wildcard_ipv6_report_uses_received_destination_as_source() {
        let mut receiver = NotificationReceiver::builder()
            .bind("[::]:0")
            .engine_id(b"test-report-source".to_vec())
            .spawn()
            .await
            .unwrap();
        let destination = SocketAddr::new(
            std::net::Ipv6Addr::LOCALHOST.into(),
            receiver.local_addr().port(),
        );
        let client = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();

        let receive_task = tokio::spawn(async move { receiver.recv().await });
        client
            .send_to(&build_v3_discovery_request(42, true), destination)
            .await
            .unwrap();

        let mut report = [0_u8; 1024];
        let (_, source) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.recv_from(&mut report),
        )
        .await
        .expect("wildcard receiver did not return discovery Report")
        .unwrap();
        assert_eq!(source.ip(), destination.ip());

        receive_task.abort();
        let _ = receive_task.await;
    }

    #[cfg(all(
        target_os = "linux",
        any(feature = "crypto-rustcrypto", feature = "crypto-fips")
    ))]
    #[tokio::test]
    async fn wildcard_ipv4_v3_inform_reply_uses_received_destination_as_source() {
        let mut receiver = NotificationReceiver::builder()
            .bind("0.0.0.0:0")
            .engine_id(b"wildcard-inform-engine".to_vec())
            .engine_boots(1)
            .usm_user("informuser", |user| {
                user.auth(AuthProtocol::Sha1, b"authpass12345678")
            })
            .unwrap()
            .admit_all_notifications()
            .spawn()
            .await
            .unwrap();
        let destination = SocketAddr::from(([127, 0, 0, 2], receiver.local_addr().port()));
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let message = build_authed_v3_inform(
            b"wildcard-inform-engine",
            1,
            0,
            b"informuser",
            b"authpass12345678",
            AuthProtocol::Sha1,
        );

        let receive_task = tokio::spawn(async move { receiver.recv().await });
        client.send_to(&message, destination).await.unwrap();

        let mut response = [0_u8; 1024];
        let (_, source) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.recv_from(&mut response),
        )
        .await
        .expect("wildcard receiver did not acknowledge v3 Inform")
        .unwrap();
        assert_eq!(source.ip(), destination.ip());

        let received = receive_task.await.unwrap().unwrap();
        assert_eq!(
            received
                .receive_info
                .datagram_destination()
                .map(|ip| ip.to_canonical()),
            Some(destination.ip().to_canonical())
        );
        assert!(received.receive_info.local_addr().ip().is_unspecified());
        assert!(matches!(
            received.notification,
            Notification::InformV3 { .. }
        ));
    }
}
