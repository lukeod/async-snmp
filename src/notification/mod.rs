//! SNMP notification receiver (RFC 3413).
//!
//! [`NotificationReceiver`] receives:
//! - `TrapV1` (SNMP v1 format, different PDU structure)
//! - `TrapV2`/`SNMPv2-Trap` (SNMP v2c/v3 format)
//! - `InformRequest` (confirmed notification, requires response)
//!
//! # SNMPv1 and SNMPv2c
//!
//! Receive v1/v2c notifications. A receiver constructed with `bind` has no
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
//!     let receiver = NotificationReceiver::bind("0.0.0.0:1162").await?;
//!
//!     loop {
//!         match receiver.recv().await {
//!             Ok((notification, source)) => {
//!                 println!("Received notification from {}: {:?}", source, notification);
//!             }
//!             Err(e) => {
//!                 eprintln!("Error receiving notification: {}", e);
//!             }
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
//! acceptance policy before building. Only `authNoPriv` and `authPriv`
//! authenticate the USM username, scoped context, and notification content;
//! every such field in a `noAuthNoPriv` message is an unverified, spoofable
//! claim.
//!
//! ```rust,no_run
//! use async_snmp::notification::{NotificationAcceptance, NotificationReceiver};
//! use async_snmp::{AuthProtocol, AuthoritativeEngine, PrivProtocol, SecurityLevel};
//! use std::convert::Infallible;
//!
//! # async fn example() -> Result<(), Box<async_snmp::Error>> {
//! # // Replace this no-op with durable storage in an application.
//! let engine = AuthoritativeEngine::install(b"receiver-engine".to_vec(), |_| {
//!     Ok::<(), Infallible>(())
//! })?;
//! let receiver = NotificationReceiver::builder()
//!     .bind("0.0.0.0:1162")
//!     .authoritative_engine(engine)
//!     .usm_user("informuser", |u| {
//!         u.auth_priv(
//!             AuthProtocol::Sha1,
//!             b"authpass123",
//!             PrivProtocol::Aes128,
//!             b"privpass123",
//!         )
//!     })
//!     .acceptance_policy(|notification| {
//!         if notification.security_level >= Some(SecurityLevel::AuthNoPriv) {
//!             NotificationAcceptance::Accept
//!         } else {
//!             NotificationAcceptance::Reject
//!         }
//!     })
//!     .build()
//!     .await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Mixed versions on one port
//!
//! A single receiver on one UDP port handles v1, v2c, and v3 concurrently;
//! each datagram is dispatched by its version field. Community filtering
//! (v1/v2c) and USM users (v3) are independent and can be configured
//! together — configuring one does not disable the other:
//!
//! ```rust,no_run
//! use async_snmp::notification::{NotificationAcceptance, NotificationReceiver};
//! use async_snmp::{AuthProtocol, AuthoritativeEngine, PrivProtocol, SecurityLevel};
//! use std::convert::Infallible;
//!
//! # async fn example() -> Result<(), Box<async_snmp::Error>> {
//! # // Replace this no-op with durable storage in an application.
//! let engine = AuthoritativeEngine::install(b"receiver-engine".to_vec(), |_| {
//!     Ok::<(), Infallible>(())
//! })?;
//! let receiver = NotificationReceiver::builder()
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
//!     .acceptance_policy(|notification| match notification.security_level {
//!         None => NotificationAcceptance::Accept, // community allowlist matched
//!         Some(level) if level >= SecurityLevel::AuthNoPriv => {
//!             NotificationAcceptance::Accept
//!         }
//!         Some(_) => NotificationAcceptance::Reject,
//!     })
//!     .build()
//!     .await?;
//! # Ok(())
//! # }
//! ```
//!
//! The two mechanisms confer very different assurance. V1/v2c community and
//! content are cleartext; without an allowlist they are unverified, while a
//! match checks only the cleartext community value. V3 username, context, and
//! content are authenticated at `authNoPriv` or `authPriv`, but remain
//! spoofable at `noAuthNoPriv`. Each [`Notification`] carries the community or
//! username and [`security_level`](Notification::security_level), so branch on
//! those fields when applying per-version policy.
//!
//! # SNMPv3 authoritative roles
//!
//! The sender of an unconfirmed V3 trap is authoritative. The receiver applies
//! per-sender engine processing and reports the received security level to the
//! application; authentication of identity and content occurs only at
//! `authNoPriv` or `authPriv`. For a V3 Inform, this receiver is authoritative:
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
//! # Application acceptance and Inform acknowledgement
//!
//! [`NotificationReceiverBuilder::acceptance_policy`] receives one borrowed
//! [`NotificationEnvelope`] after the transport, community or USM identity,
//! scoped context, notification class, prefix, uptime, trap OID, varbinds, and
//! decode anomalies are known, though their authentication assurance still
//! depends on the version, allowlist, and security level described above.
//! Returning [`NotificationAcceptance::Reject`]
//! drops the notification and withholds an Inform response. Policy errors and
//! panics have the same behavior. After acceptance, an Inform response is
//! finalized and, when encodable within the effective response limit, sent
//! before [`NotificationReceiver::recv`] delivers the notification. If both
//! the ordinary response and its `tooBig` alternate exceed that limit, no
//! response is sent, [`NotificationReceiver::snmp_silent_drops`] increments,
//! and the accepted notification is still delivered. The response attempt
//! therefore does not guarantee that the originator received an
//! acknowledgement.
//!
//! [`NotificationReceiverBuilder::accept_all_notifications`] is the explicit
//! auto-accept convenience for receivers with USM users. It also accepts
//! spoofable `noAuthNoPriv` messages, so use a policy that requires at least
//! [`SecurityLevel::AuthNoPriv`] when authenticated identity and content are
//! required.

mod handlers;
mod varbind;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::Community;
use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::Mutex as AsyncMutex;
use tracing::instrument;

use crate::error::{Error, Result};
use crate::message::SecurityLevel;
use crate::oid::Oid;
use crate::pdu::TrapV1Pdu;
use crate::udp_responder::UdpResponder;
use crate::util::{PreparedAuthoritativeUsm, bind_udp_socket, validate_authoritative_usm};
use crate::v3::process::UsmStats;
use crate::v3::{AuthoritativeEngine, EngineState, SaltCounter};
use crate::varbind::VarBind;
use crate::version::Version;

use crate::v3::UsmUser;
pub use varbind::{NotificationVarbindValidation, validate_notification_varbinds};

/// Maximum number of distinct remote authoritative engines whose timeliness
/// state is retained for trap senders. A peer holding one USM credential can
/// authenticate under arbitrarily many fabricated engine IDs (keys are
/// localized per engine ID), so the table is bounded and the
/// least-recently-updated engine is evicted when full.
const MAX_REMOTE_ENGINES: usize = 8192;

/// Notification PDU class presented to an acceptance policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NotificationPduClass {
    /// An unconfirmed v1 or v2-style trap.
    Trap,
    /// A confirmed Inform request.
    Inform,
}

/// Decision returned by a [`NotificationAcceptancePolicy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NotificationAcceptance {
    /// Deliver the notification and attempt a response when it is an Inform.
    ///
    /// The response is attempted before delivery, but response-size
    /// finalization can increment `snmpSilentDrops` and deliver the accepted
    /// notification without sending a response.
    Accept,
    /// Drop the notification without acknowledging it.
    Reject,
}

/// Application-policy failure while evaluating a notification.
///
/// Policy failures reject the notification and are emitted through tracing;
/// they are not returned from [`NotificationReceiver::recv`] because that
/// method continues waiting for the next acceptable datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationAcceptanceError {
    message: Box<str>,
}

impl NotificationAcceptanceError {
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

impl std::fmt::Display for NotificationAcceptanceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for NotificationAcceptanceError {}

/// Result returned by a fallible [`NotificationAcceptancePolicy`].
pub type NotificationAcceptanceResult =
    std::result::Result<NotificationAcceptance, NotificationAcceptanceError>;

/// A borrowed, normalized view of one fully processed notification.
///
/// Protocol decoding, configured community filtering, applicable USM
/// authentication/decryption, and standard notification-prefix validation
/// finish before this envelope is created. Its fields have the assurance
/// indicated by [`security_level`](Self::security_level): v1/v2c community and
/// content are cleartext and, without an allowlist, unverified; v3 username,
/// context, and content are authenticated only at
/// [`SecurityLevel::AuthNoPriv`] or [`SecurityLevel::AuthPriv`] and are
/// spoofable at [`SecurityLevel::NoAuthNoPriv`]. The policy decision is made
/// before any Inform response attempt or delivery.
#[derive(Debug, Clone, Copy)]
pub struct NotificationEnvelope<'a> {
    /// Datagram source address; SNMP does not cryptographically authenticate it.
    pub source: SocketAddr,
    /// Protocol version.
    pub version: Version,
    /// Community for v1/v2c, or `None` for v3.
    ///
    /// The value is cleartext. Without a configured community allowlist it is
    /// an unverified claim; an allowlist checks equality but provides no
    /// message integrity.
    pub community: Option<&'a Community>,
    /// USM username for v3, or `None` for v1/v2c.
    ///
    /// Authenticated only when `security_level` is `AuthNoPriv` or `AuthPriv`;
    /// spoofable when it is `NoAuthNoPriv`.
    pub username: Option<&'a [u8]>,
    /// Actual v3 wire security level, or `None` for v1/v2c.
    pub security_level: Option<SecurityLevel>,
    /// Trap or Inform classification.
    pub pdu_class: NotificationPduClass,
    /// Scoped-PDU context engine ID for v3, or `None` for v1/v2c.
    ///
    /// Authenticated only at `AuthNoPriv` or `AuthPriv`; spoofable at
    /// `NoAuthNoPriv`.
    pub context_engine_id: Option<&'a [u8]>,
    /// Scoped-PDU context name for v3, or `None` for v1/v2c.
    ///
    /// Authenticated only at `AuthNoPriv` or `AuthPriv`; spoofable at
    /// `NoAuthNoPriv`.
    pub context_name: Option<&'a [u8]>,
    /// sysUpTime.0, or the v1 trap timestamp, in hundredths of a second.
    ///
    /// This content is authenticated only for v3 `AuthNoPriv`/`AuthPriv`.
    pub uptime: u32,
    /// Notification-specific variable bindings, excluding the standard v2/v3
    /// uptime and trap-OID prefix.
    ///
    /// This content is authenticated only for v3 `AuthNoPriv`/`AuthPriv`.
    pub varbinds: &'a [VarBind],
    /// Request ID for v2c/v3 notifications, or `None` for v1 traps.
    pub request_id: Option<i32>,
    /// Accepted BER/value deviations from the received message, in decode order.
    pub decode_anomalies: &'a [crate::DecodeAnomaly],
    notification: &'a Notification,
}

impl<'a> NotificationEnvelope<'a> {
    fn new(source: SocketAddr, notification: &'a Notification) -> Self {
        match notification {
            Notification::TrapV1 {
                community,
                trap,
                decode_anomalies,
            } => Self {
                source,
                version: Version::V1,
                community: Some(community),
                username: None,
                security_level: None,
                pdu_class: NotificationPduClass::Trap,
                context_engine_id: None,
                context_name: None,
                uptime: trap.time_stamp,
                varbinds: &trap.varbinds,
                request_id: None,
                decode_anomalies,
                notification,
            },
            Notification::TrapV2c {
                community,
                uptime,
                varbinds,
                request_id,
                decode_anomalies,
                ..
            }
            | Notification::InformV2c {
                community,
                uptime,
                varbinds,
                request_id,
                decode_anomalies,
                ..
            } => Self {
                source,
                version: Version::V2c,
                community: Some(community),
                username: None,
                security_level: None,
                pdu_class: if notification.is_confirmed() {
                    NotificationPduClass::Inform
                } else {
                    NotificationPduClass::Trap
                },
                context_engine_id: None,
                context_name: None,
                uptime: *uptime,
                varbinds,
                request_id: Some(*request_id),
                decode_anomalies,
                notification,
            },
            Notification::TrapV3 {
                username,
                context_engine_id,
                context_name,
                security_level,
                uptime,
                varbinds,
                request_id,
                decode_anomalies,
                ..
            }
            | Notification::InformV3 {
                username,
                context_engine_id,
                context_name,
                security_level,
                uptime,
                varbinds,
                request_id,
                decode_anomalies,
                ..
            } => Self {
                source,
                version: Version::V3,
                community: None,
                username: Some(username),
                security_level: Some(*security_level),
                pdu_class: if notification.is_confirmed() {
                    NotificationPduClass::Inform
                } else {
                    NotificationPduClass::Trap
                },
                context_engine_id: Some(context_engine_id),
                context_name: Some(context_name),
                uptime: *uptime,
                varbinds,
                request_id: Some(*request_id),
                decode_anomalies,
                notification,
            },
        }
    }

    /// Return the normalized notification OID.
    ///
    /// V1 trap OIDs are derived from the generic/specific trap fields and can
    /// fail when a decoded enterprise-specific trap cannot form a valid OID.
    /// Like the rest of the notification content, this value is authenticated
    /// only for v3 `AuthNoPriv`/`AuthPriv` messages.
    pub fn trap_oid(&self) -> Result<Oid> {
        self.notification.trap_oid()
    }

    /// Return the complete version-specific notification.
    ///
    /// Consult [`Self::security_level`] before treating v3 identity, context,
    /// or content as authenticated. V1/v2c values have no cryptographic
    /// integrity.
    #[must_use]
    pub fn notification(&self) -> &'a Notification {
        self.notification
    }
}

/// Synchronous application policy evaluated before notification delivery and
/// any Inform response attempt.
///
/// The blanket implementation accepts fallible closures with the same
/// signature. A policy error or panic is contained by the receiver and treated as
/// [`NotificationAcceptance::Reject`]. Keeping this decision synchronous means
/// it has no independent timeout or cancellation lifecycle; applications that
/// need external state should expose a bounded in-memory snapshot to the
/// policy.
pub trait NotificationAcceptancePolicy: Send + Sync + 'static {
    /// Decide whether a fully processed notification should be accepted.
    fn evaluate(&self, notification: &NotificationEnvelope<'_>) -> NotificationAcceptanceResult;
}

impl<F> NotificationAcceptancePolicy for F
where
    F: Fn(&NotificationEnvelope<'_>) -> NotificationAcceptanceResult + Send + Sync + 'static,
{
    fn evaluate(&self, notification: &NotificationEnvelope<'_>) -> NotificationAcceptanceResult {
        self(notification)
    }
}

struct AcceptAllNotifications;

impl NotificationAcceptancePolicy for AcceptAllNotifications {
    fn evaluate(&self, _notification: &NotificationEnvelope<'_>) -> NotificationAcceptanceResult {
        Ok(NotificationAcceptance::Accept)
    }
}

struct InfallibleAcceptancePolicy<F>(F);

impl<F> NotificationAcceptancePolicy for InfallibleAcceptancePolicy<F>
where
    F: Fn(&NotificationEnvelope<'_>) -> NotificationAcceptance + Send + Sync + 'static,
{
    fn evaluate(&self, notification: &NotificationEnvelope<'_>) -> NotificationAcceptanceResult {
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
/// acceptance policy. See the
/// [module docs](crate::notification#mixed-versions-on-one-port).
pub struct NotificationReceiverBuilder {
    bind_addr: String,
    usm_users: HashMap<Bytes, UsmUser>,
    communities: Vec<Community>,
    authoritative_engine: Option<AuthoritativeEngine>,
    varbind_validation: NotificationVarbindValidation,
    max_message_size: usize,
    decode_policy: crate::message::DecodePolicy,
    compatibility_policy: crate::CompatibilityPolicy,
    acceptance_policy: Option<Arc<dyn NotificationAcceptancePolicy>>,
}

impl NotificationReceiverBuilder {
    /// Create a new builder with default settings.
    ///
    /// Defaults:
    /// - Bind address: `0.0.0.0:162` (UDP, standard SNMP trap port)
    /// - No USM users (v3 notifications rejected until users are added)
    /// - No authoritative engine (required when adding a USM user)
    /// - Tolerant notification varbind validation
    /// - No explicit acceptance policy (required when adding a USM user)
    #[must_use]
    pub fn new() -> Self {
        Self {
            bind_addr: "0.0.0.0:162".to_string(),
            usm_users: HashMap::new(),
            communities: Vec::new(),
            authoritative_engine: None,
            varbind_validation: NotificationVarbindValidation::Tolerant,
            max_message_size: crate::UDP_RECEIVE_LIMITS.advertised().as_usize(),
            decode_policy: crate::message::DecodePolicy::Compatible,
            compatibility_policy: crate::CompatibilityPolicy::default(),
            acceptance_policy: None,
        }
    }

    /// Set the UDP bind address.
    ///
    /// Default is `0.0.0.0:162` (UDP, standard SNMP trap port).
    #[must_use]
    pub fn bind(mut self, addr: impl Into<String>) -> Self {
        self.bind_addr = addr.into();
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

    /// Set the local upper bound for automatic Inform responses and V3 Reports.
    ///
    /// The default is the maximum UDP payload. Values below the SNMPv3
    /// advertisement minimum are permitted as response/drop policy and are not
    /// copied into outgoing V3 `msgMaxSize`, which remains this receiver's local
    /// receive capacity. If neither an accepted Inform's ordinary response nor
    /// its `tooBig` alternate fits the effective limit, the receiver increments
    /// [`NotificationReceiver::snmp_silent_drops`], sends no response, and
    /// still delivers the notification.
    #[must_use]
    pub fn max_message_size(mut self, size: usize) -> Self {
        self.max_message_size = size;
        self
    }

    /// Set top-level notification-envelope handling (default: compatible).
    ///
    /// Compatible mode accepts a bounded suffix after one declared SNMP
    /// message and exposes a trailing-byte anomaly. Strict mode rejects it.
    #[must_use]
    pub fn decode_policy(mut self, policy: crate::message::DecodePolicy) -> Self {
        self.decode_policy = policy;
        self
    }

    /// Set BER/value interoperability handling (default: compatible).
    ///
    /// The policy applies to v1/v2c notifications and every staged v3 decode,
    /// including security parameters and plaintext or decrypted scoped PDUs.
    #[must_use]
    pub fn compatibility_policy(mut self, policy: crate::CompatibilityPolicy) -> Self {
        self.compatibility_policy = policy;
        self
    }

    /// Require canonical top-level envelopes and canonical BER/value input.
    #[must_use]
    pub fn strict_decoding(mut self) -> Self {
        self.decode_policy = crate::message::DecodePolicy::Strict;
        self.compatibility_policy = crate::CompatibilityPolicy::STRICT;
        self
    }

    /// Set the application policy evaluated after protocol processing and
    /// notification-prefix validation, but before delivery or any Inform
    /// response attempt.
    ///
    /// A receiver with USM users must select this method,
    /// [`try_acceptance_policy`](Self::try_acceptance_policy), or
    /// [`accept_all_notifications`](Self::accept_all_notifications). Returning
    /// [`NotificationAcceptance::Reject`] silently drops a trap and leaves an
    /// Inform unacknowledged. Policy panics are contained and have the same
    /// rejection behavior. Acceptance causes an Inform response attempt before
    /// delivery; response-size finalization may instead count a silent drop and
    /// deliver the accepted notification without sending a response.
    #[must_use]
    pub fn acceptance_policy(
        mut self,
        policy: impl Fn(&NotificationEnvelope<'_>) -> NotificationAcceptance + Send + Sync + 'static,
    ) -> Self {
        self.acceptance_policy = Some(Arc::new(InfallibleAcceptancePolicy(policy)));
        self
    }

    /// Set a fallible application acceptance policy.
    ///
    /// Evaluation occurs at the same point as
    /// [`acceptance_policy`](Self::acceptance_policy). An error is traced and
    /// rejects the notification without acknowledging an Inform. The policy is
    /// evaluated before response finalization, so it cannot observe whether an
    /// accepted Inform's response fits the effective response limit.
    #[must_use]
    pub fn try_acceptance_policy(mut self, policy: impl NotificationAcceptancePolicy) -> Self {
        self.acceptance_policy = Some(Arc::new(policy));
        self
    }

    /// Explicitly accept every successfully processed notification.
    ///
    /// For v3 this includes lower security levels supported by a configured
    /// inbound user, including `noAuthNoPriv`. At that level the username,
    /// context, and notification content are unverified and spoofable. Prefer
    /// [`acceptance_policy`](Self::acceptance_policy) with a minimum
    /// [`SecurityLevel::AuthNoPriv`] when authenticated input is required.
    #[must_use]
    pub fn accept_all_notifications(mut self) -> Self {
        self.acceptance_policy = Some(Arc::new(AcceptAllNotifications));
        self
    }

    /// Add a USM user for V3 processing.
    ///
    /// Adding any user requires a persisted [`AuthoritativeEngine`] and an
    /// explicit [`acceptance_policy`](Self::acceptance_policy),
    /// [`try_acceptance_policy`](Self::try_acceptance_policy), or
    /// [`accept_all_notifications`](Self::accept_all_notifications) before
    /// [`build`](Self::build), because this receiver is authoritative for V3
    /// Inform exchanges.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use async_snmp::notification::{NotificationAcceptance, NotificationReceiver};
    /// use async_snmp::{AuthProtocol, AuthoritativeEngine, PrivProtocol, SecurityLevel};
    /// use std::convert::Infallible;
    ///
    /// # async fn example() -> Result<(), Box<async_snmp::Error>> {
    /// # // Replace this no-op with durable storage in an application.
    /// let engine = AuthoritativeEngine::install(b"receiver-engine".to_vec(), |_| {
    ///     Ok::<(), Infallible>(())
    /// })?;
    /// let receiver = NotificationReceiver::builder()
    ///     .bind("0.0.0.0:162")
    ///     .authoritative_engine(engine)
    ///     .usm_user("trapuser", |u| {
    ///         u.auth_priv(
    ///             AuthProtocol::Sha1,
    ///             b"authpassword",
    ///             PrivProtocol::Aes128,
    ///             b"privpassword",
    ///         )
    ///     })
    ///     .acceptance_policy(|notification| {
    ///         if notification.security_level >= Some(SecurityLevel::AuthNoPriv) {
    ///             NotificationAcceptance::Accept
    ///         } else {
    ///             NotificationAcceptance::Reject
    ///         }
    ///     })
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn usm_user<F>(mut self, username: impl Into<Bytes>, configure: F) -> Self
    where
        F: FnOnce(UsmUser) -> UsmUser,
    {
        let username_bytes: Bytes = username.into();
        let config = configure(UsmUser::new(username_bytes.clone()));
        self.usm_users.insert(username_bytes, config);
        self
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
    /// let receiver = NotificationReceiver::builder()
    ///     .bind("0.0.0.0:162")
    ///     .community(b"public")
    ///     .build()
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
    /// let receiver = NotificationReceiver::builder()
    ///     .bind("0.0.0.0:162")
    ///     .communities(["public", "monitor"])
    ///     .build()
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

    /// Build the notification receiver.
    ///
    /// Returns a configuration error when USM credentials are invalid, USM
    /// users do not have an explicit acceptance policy, or a USM user is
    /// configured without a persisted [`AuthoritativeEngine`]. Returns
    /// [`Error::RandomSource`] when a generated engine ID or required privacy
    /// salt cannot be initialized.
    pub async fn build(self) -> Result<NotificationReceiver> {
        self.build_with_engine_id_generator(crate::v3::generate_engine_id)
            .await
    }

    async fn build_with_engine_id_generator(
        self,
        generate_engine_id: impl FnOnce() -> Result<Bytes>,
    ) -> Result<NotificationReceiver> {
        if !self.usm_users.is_empty() && self.acceptance_policy.is_none() {
            return Err(Error::Config(
                "a notification receiver with USM users requires an acceptance policy".into(),
            )
            .boxed());
        }
        if self.max_message_size > crate::UDP_RECEIVE_LIMITS.advertised().as_usize() {
            return Err(Error::Config(
                format!(
                    "max_message_size must not exceed UDP capacity {}",
                    crate::UDP_RECEIVE_LIMITS.advertised()
                )
                .into(),
            )
            .boxed());
        }

        let requires_privacy = self
            .usm_users
            .values()
            .any(|security| security.maximum_security_level().requires_priv());
        let requires_authoritative_engine = !self.usm_users.is_empty();
        let validated_usm = validate_authoritative_usm(
            self.usm_users,
            self.authoritative_engine,
            requires_authoritative_engine,
            "invalid USM user configuration",
            "authoritative engine state is required for SNMPv3 notification receiving",
        )?;

        let bind_addr: SocketAddr = self.bind_addr.parse().map_err(|_| {
            Error::Config(format!("invalid bind address: {}", self.bind_addr).into())
        })?;

        let socket = bind_udp_socket(bind_addr, None, None, false)
            .await
            .map_err(|e| Error::Network {
                target: bind_addr,
                source: e,
            })?;

        let local_addr = socket.local_addr().map_err(|e| Error::Network {
            target: bind_addr,
            source: e,
        })?;

        let PreparedAuthoritativeUsm {
            users: usm_users,
            authoritative_engine,
            engine_id,
            engine_boots,
        } = validated_usm.prepare(generate_engine_id)?;
        let salt_counter = requires_privacy.then(SaltCounter::new).transpose()?;
        let udp_responder = UdpResponder::new(&socket);

        Ok(NotificationReceiver {
            inner: Arc::new(ReceiverInner {
                authoritative_engine,
                socket,
                udp_responder,
                local_addr,
                usm_users,
                communities: self.communities,
                varbind_validation: self.varbind_validation,
                engine_id,
                salt_counter,
                authoritative_snapshot: AtomicU64::new(pack_boots_time((engine_boots, 0))),
                engine_boots_base: engine_boots,
                engine_start: Instant::now(),
                usm_stats: UsmStats::default(),
                remote_engines: Mutex::new(HashMap::new()),
                max_message_size: self.max_message_size,
                decode_policy: self.decode_policy,
                compatibility_policy: self.compatibility_policy,
                snmp_silent_drops: AtomicU32::new(0),
                acceptance_policy: self.acceptance_policy,
                recv_gate: AsyncMutex::new(vec![0; crate::UDP_RECEIVE_BUFFER_SIZE]),
            }),
        })
    }
}

impl Default for NotificationReceiverBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Received SNMP notification.
///
/// This enum represents all types of SNMP notifications that can be received:
/// - `SNMPv1` Trap (different PDU structure)
/// - SNMPv2c/v3 Trap (standard PDU with sysUpTime.0 and snmpTrapOID.0)
/// - `InformRequest` (confirmed notification, with a response attempted after
///   application acceptance and before delivery)
///
/// V1/v2c community and content are cleartext and have no cryptographic
/// integrity; without a configured community allowlist they are unverified.
/// V3 username, context, and content are authenticated only at `AuthNoPriv` or
/// `AuthPriv`; all are spoofable at `NoAuthNoPriv`.
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
    /// When returned by [`NotificationReceiver`], application acceptance
    /// occurred first and the receiver attempted the response before delivery.
    /// Response-size finalization may instead have counted an
    /// `snmpSilentDrops` size drop and delivered the value without sending one.
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
    /// When returned by [`NotificationReceiver`], application acceptance
    /// occurred first and the receiver attempted the response before delivery.
    /// Response-size finalization may instead have counted an
    /// `snmpSilentDrops` size drop and delivered the value without sending one.
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

    /// Get the trap/notification OID.
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

    /// Get the uptime value (sysUpTime.0 or `time_stamp` for v1).
    pub fn uptime(&self) -> u32 {
        match self {
            Notification::TrapV1 { trap, .. } => trap.time_stamp,
            Notification::TrapV2c { uptime, .. }
            | Notification::TrapV3 { uptime, .. }
            | Notification::InformV2c { uptime, .. }
            | Notification::InformV3 { uptime, .. } => *uptime,
        }
    }

    /// Get the variable bindings.
    pub fn varbinds(&self) -> &[VarBind] {
        match self {
            Notification::TrapV1 { trap, .. } => &trap.varbinds,
            Notification::TrapV2c { varbinds, .. }
            | Notification::TrapV3 { varbinds, .. }
            | Notification::InformV2c { varbinds, .. }
            | Notification::InformV3 { varbinds, .. } => varbinds,
        }
    }

    /// Get the security level the notification was received at.
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

    /// Get the SNMP version of this notification.
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
/// Listens for incoming SNMP notifications (traps and informs) on a UDP socket.
/// For accepted `InformRequest` notifications, finalizes and attempts a
/// Response-PDU before delivery. If the response and its `tooBig` alternate
/// exceed the effective response limit, it sends neither, increments
/// [`Self::snmp_silent_drops`], and still delivers the notification.
///
/// # V3 Authentication
///
/// To receive authenticated V3 notifications, use the builder pattern to
/// configure USM credentials and persisted authoritative engine state:
///
/// ```rust,no_run
/// use async_snmp::notification::{NotificationAcceptance, NotificationReceiver};
/// use async_snmp::{AuthProtocol, AuthoritativeEngine, SecurityLevel};
/// use std::convert::Infallible;
///
/// # async fn example() -> Result<(), Box<async_snmp::Error>> {
/// # // Replace this no-op with durable storage in an application.
/// let engine = AuthoritativeEngine::install(b"receiver-engine".to_vec(), |_| {
///     Ok::<(), Infallible>(())
/// })?;
/// let receiver = NotificationReceiver::builder()
///     .bind("0.0.0.0:162")
///     .authoritative_engine(engine)
///     .usm_user("trapuser", |u| {
///         u.auth(AuthProtocol::Sha1, b"authpassword")
///     })
///     .acceptance_policy(|notification| {
///         if notification.security_level >= Some(SecurityLevel::AuthNoPriv) {
///             NotificationAcceptance::Accept
///         } else {
///             NotificationAcceptance::Reject
///         }
///     })
///     .build()
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct NotificationReceiver {
    inner: Arc<ReceiverInner>,
}

struct ReceiverInner {
    authoritative_engine: Option<AuthoritativeEngine>,
    socket: UdpSocket,
    udp_responder: UdpResponder,
    local_addr: SocketAddr,
    /// Configured USM users for V3 authentication
    usm_users: HashMap<Bytes, UsmUser>,
    /// Accepted v1/v2c community strings. Empty means accept any community
    /// (community filtering is opt-in); otherwise a v1/v2c notification whose
    /// community matches none of these is dropped.
    communities: Vec<Community>,
    /// Validation policy for SNMPv2c/v3 standard notification varbind prefixes.
    varbind_validation: NotificationVarbindValidation,
    /// Engine ID for V3 discovery responses
    engine_id: Bytes,
    /// Salt counter for privacy operations
    salt_counter: Option<SaltCounter>,
    /// Most recently sampled authoritative boots/time tuple.
    authoritative_snapshot: AtomicU64,
    /// Initial engine boots value at startup, used to compute overflow-adjusted boots.
    engine_boots_base: u32,
    /// Time when the receiver was started, used to compute engine time.
    engine_start: Instant,
    /// RFC 3414 usmStats counters
    usm_stats: UsmStats,
    /// Timeliness state for remote authoritative engines (trap senders),
    /// keyed by engine ID (RFC 3414 Section 2.3). Seeded from the first
    /// authenticated message from each engine, so only holders of configured
    /// credentials can add entries. Bounded to `MAX_REMOTE_ENGINES` with
    /// least-recently-updated eviction so a credential holder cannot grow it
    /// without limit by fabricating engine IDs.
    remote_engines: Mutex<HashMap<Bytes, EngineState>>,
    /// Local outbound response policy limit.
    max_message_size: usize,
    decode_policy: crate::message::DecodePolicy,
    compatibility_policy: crate::CompatibilityPolicy,
    /// Confirmed notifications dropped because even the alternate Response did not fit.
    snmp_silent_drops: AtomicU32,
    acceptance_policy: Option<Arc<dyn NotificationAcceptancePolicy>>,
    /// Fairly serializes cloned `recv` calls and retains their shared UDP buffer.
    recv_gate: AsyncMutex<Vec<u8>>,
}

impl ReceiverInner {
    fn accepts(&self, source: SocketAddr, notification: &Notification) -> bool {
        let Some(policy) = &self.acceptance_policy else {
            return true;
        };
        let envelope = NotificationEnvelope::new(source, notification);
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| policy.evaluate(&envelope)))
        {
            Ok(Ok(NotificationAcceptance::Accept)) => true,
            Ok(Ok(NotificationAcceptance::Reject)) => false,
            Ok(Err(error)) => {
                tracing::error!(target: "async_snmp::notification", { snmp.source = %source, error = %error }, "notification acceptance policy failed; rejected notification");
                false
            }
            Err(_) => {
                tracing::error!(target: "async_snmp::notification", { snmp.source = %source }, "notification acceptance policy panicked; rejected notification");
                false
            }
        }
    }

    /// Return one coherent authoritative boots/time pair for the current instant.
    fn authoritative_boots_time(&self) -> Result<(u32, u32)> {
        let pair = match &self.authoritative_engine {
            Some(engine) => engine.current_boots_time(),
            None => {
                let total_secs = self.engine_start.elapsed().as_secs();
                Ok(crate::v3::compute_engine_boots_time(
                    self.engine_boots_base,
                    total_secs,
                ))
            }
        }?;
        Ok(self.publish_authoritative_boots_time(pair))
    }

    fn publish_authoritative_boots_time(&self, pair: (u32, u32)) -> (u32, u32) {
        let packed = pack_boots_time(pair);
        let previous = self
            .authoritative_snapshot
            .fetch_max(packed, Ordering::Relaxed);
        unpack_boots_time(previous.max(packed))
    }
}

const fn pack_boots_time((boots, time): (u32, u32)) -> u64 {
    (boots as u64) << 32 | time as u64
}

const fn unpack_boots_time(packed: u64) -> (u32, u32) {
    ((packed >> 32) as u32, packed as u32)
}

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
    /// This counter changes only when a confirmed Inform response is oversized
    /// and its exact empty-varbind `tooBig` alternate also exceeds the effective
    /// local/originator limit. The accepted Inform is still delivered in this
    /// case even though no response is sent. Authentication, engine-boots, and
    /// unrelated receive failures do not affect it.
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
    /// let receiver = NotificationReceiver::bind("0.0.0.0:162").await?;
    ///
    /// // Or use an unprivileged port for testing
    /// let receiver = NotificationReceiver::bind("0.0.0.0:1162").await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error when the address is invalid, the socket cannot be
    /// created, or the operating system cannot provide randomness for the
    /// receiver's engine ID.
    pub async fn bind(addr: impl AsRef<str>) -> Result<Self> {
        Self::builder().bind(addr.as_ref()).build().await
    }

    #[cfg(test)]
    async fn bind_with_engine_id_generator(
        addr: impl AsRef<str>,
        generate_engine_id: impl FnOnce() -> Result<Bytes>,
    ) -> Result<Self> {
        Self::builder()
            .bind(addr.as_ref())
            .build_with_engine_id_generator(generate_engine_id)
            .await
    }

    /// Get the local address this receiver is bound to.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr
    }

    /// Return the configured top-level notification-envelope policy.
    #[must_use]
    pub fn decode_policy(&self) -> crate::message::DecodePolicy {
        self.inner.decode_policy
    }

    /// Return the configured BER/value compatibility policy.
    #[must_use]
    pub fn compatibility_policy(&self) -> crate::CompatibilityPolicy {
        self.inner.compatibility_policy
    }

    /// Get the local engine ID.
    ///
    /// With an [`AuthoritativeEngine`] this is the stable persisted V3
    /// identity. A receiver without USM users instead has a generated
    /// process-local ID.
    #[must_use]
    pub fn engine_id(&self) -> &[u8] {
        &self.inner.engine_id
    }

    /// Get the most recently sampled local engine boots value.
    ///
    /// V3 processing samples the authoritative clock. Any rollover increment
    /// has already been stored through the retained persistence callback before
    /// this snapshot is published. This getter does not sample the clock or run
    /// the persistence callback, so it can remain unchanged while the receiver
    /// is idle.
    #[must_use]
    pub fn engine_boots(&self) -> u32 {
        unpack_boots_time(self.inner.authoritative_snapshot.load(Ordering::Relaxed)).0
    }

    /// Get the usmStatsUnknownEngineIDs counter value.
    #[must_use]
    pub fn usm_unknown_engine_ids(&self) -> u32 {
        self.inner
            .usm_stats
            .unknown_engine_ids
            .load(Ordering::Relaxed)
    }

    /// Get the usmStatsUnknownUserNames counter value.
    #[must_use]
    pub fn usm_unknown_usernames(&self) -> u32 {
        self.inner
            .usm_stats
            .unknown_usernames
            .load(Ordering::Relaxed)
    }

    /// Get the usmStatsWrongDigests counter value.
    #[must_use]
    pub fn usm_wrong_digests(&self) -> u32 {
        self.inner.usm_stats.wrong_digests.load(Ordering::Relaxed)
    }

    /// Get the usmStatsNotInTimeWindows counter value.
    #[must_use]
    pub fn usm_not_in_time_windows(&self) -> u32 {
        self.inner
            .usm_stats
            .not_in_time_windows
            .load(Ordering::Relaxed)
    }

    /// Get the usmStatsUnsupportedSecLevels counter value.
    #[must_use]
    pub fn usm_unsupported_sec_levels(&self) -> u32 {
        self.inner
            .usm_stats
            .unsupported_sec_levels
            .load(Ordering::Relaxed)
    }

    /// Get the usmStatsDecryptionErrors counter value.
    #[must_use]
    pub fn usm_decryption_errors(&self) -> u32 {
        self.inner
            .usm_stats
            .decryption_errors
            .load(Ordering::Relaxed)
    }

    /// Receive a notification.
    ///
    /// This method blocks until a notification passes protocol processing,
    /// prefix validation, and the application acceptance policy. Policy
    /// rejection, error, or panic drops the notification and withholds an
    /// Inform response while this method continues waiting.
    ///
    /// For an accepted `InformRequest`, the receiver finalizes and attempts a
    /// Response-PDU before returning. A successful send completes before
    /// delivery. If the response and exact `tooBig` alternate both exceed the
    /// effective response limit, however, no response is sent,
    /// [`Self::snmp_silent_drops`] increments, and this method still returns
    /// the accepted notification. Return therefore does not prove that the
    /// originator received an acknowledgement.
    ///
    /// V1/v2c community and content are cleartext and unverified unless a
    /// community allowlist was configured. Even an allowlist match provides no
    /// cryptographic integrity. V3 username, context, and content are
    /// authenticated only at [`SecurityLevel::AuthNoPriv`] or
    /// [`SecurityLevel::AuthPriv`] and remain spoofable at
    /// [`SecurityLevel::NoAuthNoPriv`].
    ///
    /// Clones share the socket and one fixed receive buffer; cloning does not
    /// allocate another UDP-sized buffer. Concurrent calls are queued in FIFO
    /// order. The active call retains its queue position while it skips
    /// malformed, rejected, or non-notification datagrams. Cancelling a queued
    /// or active call releases its position and leaves the shared buffer ready
    /// for the next waiter.
    ///
    /// Returns the notification and the source address.
    #[instrument(skip(self), err, fields(snmp.local_addr = %self.local_addr()))]
    pub async fn recv(&self) -> Result<(Notification, SocketAddr)> {
        // Tokio's mutex queues callers in FIFO order. Keeping the guard while
        // malformed/non-notification datagrams are skipped prevents a later
        // cloned receiver from overtaking the earlier call.
        let mut buf = self.inner.recv_gate.lock().await;

        loop {
            let received = self
                .inner
                .udp_responder
                .recv(&self.inner.socket, buf.as_mut_slice())
                .await
                .map_err(|source| Error::Network {
                    target: self.inner.local_addr,
                    source,
                })?;
            let source = received.source;
            if received.len > crate::UDP_RECEIVE_LIMITS.advertised().as_usize() {
                tracing::debug!(target: "async_snmp::notification", { snmp.source = %source, received_size = received.len, advertised_size = crate::UDP_RECEIVE_LIMITS.advertised().as_usize() }, "accepted bounded UDP datagram above advertised capacity");
            }
            let data = Bytes::copy_from_slice(&buf[..received.len]);

            match self
                .parse_and_respond(data, source, received.destination)
                .await
            {
                Ok(Some(notification)) => return Ok((notification, source)),
                Ok(None) => {} // Not a notification PDU, ignore
                Err(e) => {
                    // Log parsing error but continue receiving
                    tracing::warn!(target: "async_snmp::notification", { snmp.source = %source, error = %e }, "failed to parse notification");
                }
            }
        }
    }

    /// Parse received data and send response if needed.
    ///
    /// Returns `None` if the message is not a notification PDU.
    async fn parse_and_respond(
        &self,
        data: Bytes,
        source: SocketAddr,
        response_source: Option<crate::udp_responder::DestinationMetadata>,
    ) -> Result<Option<Notification>> {
        match crate::message::peek_version(data.clone(), source)? {
            Version::V1 => self.handle_v1(data, source).await,
            Version::V2c => self.handle_v2c_at(data, source, response_source).await,
            Version::V3 => self.handle_v3_at(data, source, response_source).await,
        }
    }

    async fn send_response(
        &self,
        data: &[u8],
        destination: SocketAddr,
        source: Option<crate::udp_responder::DestinationMetadata>,
    ) -> std::io::Result<()> {
        self.inner
            .udp_responder
            .send_to(&self.inner.socket, data, destination, source)
            .await
    }
}

impl Clone for NotificationReceiver {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use super::*;

    #[tokio::test]
    async fn decoding_policy_defaults_strict_preset_and_targeted_override() {
        let default = NotificationReceiver::bind("127.0.0.1:0").await.unwrap();
        assert_eq!(
            default.decode_policy(),
            crate::message::DecodePolicy::Compatible
        );
        assert_eq!(
            default.compatibility_policy(),
            crate::CompatibilityPolicy::DEFAULT
        );

        let mut targeted = crate::CompatibilityPolicy::STRICT;
        targeted.empty_counter64_as_zero = true;
        let configured = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .strict_decoding()
            .compatibility_policy(targeted)
            .build()
            .await
            .unwrap();
        assert_eq!(
            configured.decode_policy(),
            crate::message::DecodePolicy::Strict
        );
        assert_eq!(configured.compatibility_policy(), targeted);
    }
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    use crate::Value;
    use crate::message::SecurityLevel;
    use crate::oid;
    use crate::pdu::GenericTrap;
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    use crate::pdu::Pdu;
    use crate::util::{EmptyCommunityPolicy, community_matches};
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
    fn acceptance_policy_ignored_argument_is_inferred() {
        let _builder = NotificationReceiverBuilder::new()
            .acceptance_policy(|_| NotificationAcceptance::Accept);
    }

    #[tokio::test]
    async fn convenience_bind_matches_default_builder_configuration() {
        let built = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .build()
            .await
            .unwrap();
        let bound = NotificationReceiver::bind("127.0.0.1:0").await.unwrap();

        for receiver in [&bound, &built] {
            assert!(receiver.inner.authoritative_engine.is_none());
            assert!(receiver.inner.usm_users.is_empty());
            assert!(receiver.inner.communities.is_empty());
            assert_eq!(
                receiver.inner.varbind_validation,
                NotificationVarbindValidation::Tolerant
            );
            crate::v3::validate_engine_id(receiver.engine_id()).unwrap();
            assert!(receiver.inner.salt_counter.is_none());
            assert_eq!(receiver.inner.engine_boots_base, 1);
            assert!(receiver.inner.remote_engines.lock().unwrap().is_empty());
            assert_eq!(
                receiver.inner.max_message_size,
                crate::UDP_RECEIVE_LIMITS.advertised().as_usize()
            );
            assert_eq!(
                receiver.inner.decode_policy,
                crate::message::DecodePolicy::Compatible
            );
            assert_eq!(
                receiver.inner.compatibility_policy,
                crate::CompatibilityPolicy::default()
            );
            assert_eq!(receiver.snmp_silent_drops(), 0);
            assert!(receiver.inner.acceptance_policy.is_none());
            assert_eq!(
                receiver.inner.socket.local_addr().unwrap(),
                receiver.local_addr()
            );

            let receive_buffer = receiver.inner.recv_gate.lock().await;
            assert_eq!(receive_buffer.len(), crate::UDP_RECEIVE_BUFFER_SIZE);
            assert!(receive_buffer.capacity() >= crate::UDP_RECEIVE_BUFFER_SIZE);
        }

        assert_ne!(bound.engine_id(), built.engine_id());

        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        for receiver in [&bound, &built] {
            let notification = receiver
                .handle_v2c(build_v2c_trap(b"not-preconfigured"), source)
                .await
                .unwrap();
            assert!(matches!(notification, Some(Notification::TrapV2c { .. })));
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
            .build_with_engine_id_generator(unavailable_engine_id)
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
            .build_with_engine_id_generator(unavailable_engine_id)
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
            .build_with_engine_id_generator(unavailable_engine_id)
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
            .build_with_engine_id_generator(|| panic!("engine ID generator must not be called"))
            .await
            .unwrap();

        assert_eq!(receiver.engine_id(), configured_engine_id);
    }

    #[test]
    fn test_notification_receiver_builder_with_user() {
        let builder = NotificationReceiverBuilder::new()
            .bind("0.0.0.0:1162")
            .usm_user("trapuser", |u| u.auth(AuthProtocol::Sha1, b"authpass"));

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
            .usm_user("user", |user| user)
            .accept_all_notifications()
            .build()
            .await;

        let err = result.err().expect("expected build to fail");
        assert!(matches!(
            *err,
            Error::Config(ref message)
                if message.contains("authoritative engine state is required")
        ));
    }

    #[tokio::test]
    async fn v3_receiver_requires_explicit_acceptance_policy_before_bind() {
        let result = NotificationReceiver::builder()
            .bind("not a socket address")
            .usm_user("user", |user| user)
            .build()
            .await;
        let error = result.err().expect("missing receiver policy must fail");
        assert!(matches!(
            *error,
            Error::Config(ref message) if message.contains("requires an acceptance policy")
        ));
    }

    #[tokio::test]
    async fn test_invalid_usm_user_is_rejected_before_bind() {
        let result = NotificationReceiver::builder()
            .bind("not a socket address")
            .usm_user("", |user| user)
            .accept_all_notifications()
            .build()
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
            .build()
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
        let mut receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .authoritative_engine(engine)
            .build()
            .await
            .unwrap();
        Arc::get_mut(&mut receiver.inner)
            .unwrap()
            .authoritative_engine
            .as_mut()
            .unwrap()
            .set_elapsed_for_test(u64::from(crate::v3::MAX_ENGINE_TIME) + 1);

        assert_eq!(receiver.engine_boots(), 1);
        assert_eq!(calls.load(Ordering::Relaxed), 1);

        let error = receiver
            .handle_v3(Bytes::new(), "127.0.0.1:1162".parse().unwrap())
            .await
            .unwrap_err();
        assert_eq!(
            error.kind(),
            crate::ErrorKind::AuthoritativeEnginePersistence
        );
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        assert_eq!(receiver.engine_boots(), 1);
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
            .build()
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
                .auth(AuthProtocol::Sha256, b"inform-auth-password"),
            SecurityLevel::AuthPriv => crate::v3::UsmConfig::new(username).auth_priv(
                AuthProtocol::Sha256,
                b"inform-auth-password",
                PrivProtocol::Aes128,
                b"inform-priv-password",
            ),
        }
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    fn inform_user(level: SecurityLevel, username: &[u8]) -> crate::v3::UsmUser {
        use crate::v3::PrivProtocol;

        let username = Bytes::copy_from_slice(username);
        match level {
            SecurityLevel::NoAuthNoPriv => crate::v3::UsmUser::new(username),
            SecurityLevel::AuthNoPriv => crate::v3::UsmUser::new(username)
                .auth(AuthProtocol::Sha256, b"inform-auth-password"),
            SecurityLevel::AuthPriv => crate::v3::UsmUser::new(username).auth_priv(
                AuthProtocol::Sha256,
                b"inform-auth-password",
                PrivProtocol::Aes128,
                b"inform-priv-password",
            ),
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
            true,
            msg_max_size,
        )
        .unwrap();
        (Bytes::from(encoded), pdu, keys)
    }

    /// Build an authenticated V3 `InformRequest` message with the given
    /// `engine_boots` and `engine_time` in the USM parameters.
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    fn build_authed_v3_inform(
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
    fn build_authed_v3_trap(engine_id: &[u8], engine_boots: u32, engine_time: u32) -> Bytes {
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
    async fn remote_trap_receiver() -> NotificationReceiver {
        NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .engine_id(b"my-receiver-engine".to_vec())
            .engine_boots(1)
            .usm_user("trapuser", |u| {
                u.auth(AuthProtocol::Sha1, b"authpass12345678")
            })
            .accept_all_notifications()
            .build()
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
            Some(Notification::TrapV3 {
                username,
                security_level,
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
            Some(Notification::TrapV3 {
                security_level,
                username,
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
            .acceptance_policy(|notification: &NotificationEnvelope<'_>| {
                if notification.username == Some(b"trapuser")
                    && notification.security_level >= Some(SecurityLevel::AuthNoPriv)
                {
                    NotificationAcceptance::Accept
                } else {
                    NotificationAcceptance::Reject
                }
            })
            .build()
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
    async fn receiver_policy_drops_lower_level_inform_without_acknowledgement() {
        let engine_id = b"my-receiver-engine".to_vec();
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .engine_id(engine_id.clone())
            .engine_boots(1)
            .usm_user("informuser", |user| {
                user.auth(AuthProtocol::Sha1, b"authpass12345678")
            })
            .acceptance_policy(|notification: &NotificationEnvelope<'_>| {
                if notification.pdu_class == NotificationPduClass::Inform
                    && notification.security_level >= Some(SecurityLevel::AuthNoPriv)
                {
                    NotificationAcceptance::Accept
                } else {
                    NotificationAcceptance::Reject
                }
            })
            .build()
            .await
            .unwrap();
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let message = build_v3_notification(
            crate::PduType::InformRequest,
            &engine_id,
            0,
            0,
            b"informuser",
            None,
        );
        let result = receiver
            .handle_v3(message, client.local_addr().unwrap())
            .await
            .unwrap();
        assert!(result.is_none());
        let mut response = [0_u8; 1];
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(50),
                client.recv_from(&mut response),
            )
            .await
            .is_err(),
            "denied Inform must not be acknowledged"
        );
        assert_eq!(receiver.usm_unsupported_sec_levels(), 0);
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
            let mut engines = receiver.inner.remote_engines.lock().unwrap();
            for i in 0..MAX_REMOTE_ENGINES {
                let id = Bytes::from(format!("dummy-engine-{i}"));
                engines.insert(id.clone(), EngineState::new(id, 1, 1));
            }
            assert_eq!(engines.len(), MAX_REMOTE_ENGINES);
        }

        // An authenticated trap under a not-yet-seen engine ID is accepted.
        let msg = build_authed_v3_trap(b"fresh-remote-engine", 7, 123_456);
        assert!(receiver.handle_v3(msg, source).await.unwrap().is_some());

        // The table stayed at capacity (an old entry was evicted) and the new
        // engine is now tracked.
        let engines = receiver.inner.remote_engines.lock().unwrap();
        assert_eq!(engines.len(), MAX_REMOTE_ENGINES);
        assert!(engines.contains_key(&Bytes::from_static(b"fresh-remote-engine")));
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
            .accept_all_notifications()
            .build()
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
            .accept_all_notifications()
            .build()
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
            .accept_all_notifications()
            .build()
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
            .build()
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

        let report = V3Message::decode(Bytes::copy_from_slice(&buf[..len])).unwrap();
        assert_eq!(
            report.global_data.msg_flags.security_level,
            SecurityLevel::NoAuthNoPriv
        );
        let report_usm = UsmSecurityParams::decode(report.security_params.clone()).unwrap();
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

        let receiver = NotificationReceiver::bind("127.0.0.1:0").await.unwrap();
        let destination = receiver.local_addr();
        let engine_id = Bytes::copy_from_slice(receiver.engine_id());
        crate::v3::validate_engine_id(&engine_id).unwrap();

        let receive_receiver = receiver.clone();
        let receive_task = tokio::spawn(async move { receive_receiver.recv().await });
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
        let report = V3Message::decode(Bytes::copy_from_slice(&buf[..len])).unwrap();
        let report_usm = UsmSecurityParams::decode(report.security_params.clone()).unwrap();
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
        let report = V3Message::decode(Bytes::copy_from_slice(&buf[..len])).unwrap();
        assert_eq!(
            report.global_data.msg_flags.security_level,
            SecurityLevel::NoAuthNoPriv
        );
        let report_usm = UsmSecurityParams::decode(report.security_params.clone()).unwrap();
        assert_eq!(report_usm.engine_id, engine_id);
        let scoped = report.scoped_pdu().expect("Report must be plaintext");
        assert_eq!(scoped.pdu.pdu_type(), crate::pdu::PduType::Report);
        assert_eq!(
            scoped.pdu.varbinds[0].oid,
            crate::v3::report_oids::unknown_user_names()
        );
        assert_eq!(receiver.usm_unknown_usernames(), 1);

        receive_task.abort();
        let _ = receive_task.await;
    }

    #[tokio::test]
    async fn test_v3_discovery_non_reportable_ignored() {
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .engine_id(b"test-discovery-engine".to_vec())
            .build()
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
            .accept_all_notifications()
            .build()
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
            .accept_all_notifications()
            .build()
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
            matches!(result, Some(Notification::InformV3 { .. })),
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
            .accept_all_notifications()
            .build()
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
            matches!(result, Some(Notification::InformV3 { .. })),
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
        let ack = V3Message::decode(Bytes::copy_from_slice(&buf[..len])).unwrap();
        assert_eq!(
            ack.global_data.msg_max_size,
            crate::UDP_RECEIVE_LIMITS.advertised(),
            "ack must advertise the receiver's local receive capacity, not the sender's 1400"
        );
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
                    "127.0.0.1:9999".parse().unwrap(),
                )
            };
            let candidate_len = encode(inform_pdu.to_response(Version::V2c).unwrap())
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

            let config = inform_user(level, &username);
            let policy_calls = Arc::new(AtomicU32::new(0));
            let policy_calls_for_receiver = Arc::clone(&policy_calls);
            let policy_engine_id = engine_id.clone();
            let policy_username = username.clone();
            let receiver = NotificationReceiver::builder()
                .bind("127.0.0.1:0")
                .authoritative_engine(AuthoritativeEngine::for_test(engine_id.clone(), 1))
                .usm_user(username.clone(), move |_| config)
                .acceptance_policy(move |notification: &NotificationEnvelope<'_>| {
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
                    assert_eq!(notification.uptime, 1000);
                    assert_eq!(notification.trap_oid().unwrap(), oids::cold_start());
                    assert!(notification.varbinds.is_empty());
                    assert_eq!(notification.request_id, Some(1));
                    assert!(notification.decode_anomalies.is_empty());
                    assert!(matches!(
                        notification.notification(),
                        Notification::InformV3 { .. }
                    ));
                    policy_calls_for_receiver.fetch_add(1, Ordering::Relaxed);
                    NotificationAcceptance::Accept
                })
                .max_message_size(candidate_len - 1)
                .build()
                .await
                .unwrap();
            let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let client_addr = client.local_addr().unwrap();
            let notification = receiver
                .handle_v3(message.clone(), client_addr)
                .await
                .unwrap();
            assert!(matches!(notification, Some(Notification::InformV3 { .. })));
            let mut buf = vec![0_u8; 4096];
            let (len, _) = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                client.recv_from(&mut buf),
            )
            .await
            .expect("tooBig acknowledgement should be sent")
            .unwrap();
            assert_eq!(len, alternate_len);
            let ack =
                crate::message::V3Message::decode(Bytes::copy_from_slice(&buf[..len])).unwrap();
            assert_eq!(
                ack.global_data.msg_max_size,
                crate::UDP_RECEIVE_LIMITS.advertised()
            );
            assert_eq!(receiver.snmp_silent_drops(), 0);
            assert_eq!(policy_calls.load(Ordering::Relaxed), 1);

            let config = inform_user(level, &username);
            let receiver = NotificationReceiver::builder()
                .bind("127.0.0.1:0")
                .authoritative_engine(AuthoritativeEngine::for_test(engine_id.clone(), 1))
                .usm_user(username.clone(), move |_| config)
                .accept_all_notifications()
                .max_message_size(1)
                .build()
                .await
                .unwrap();
            let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let client_addr = client.local_addr().unwrap();
            let notification = receiver
                .handle_v3(message.clone(), client_addr)
                .await
                .unwrap();
            assert!(matches!(notification, Some(Notification::InformV3 { .. })));
            assert_eq!(receiver.snmp_silent_drops(), 1);
            let mut buf = [0_u8; 1];
            assert!(
                tokio::time::timeout(
                    std::time::Duration::from_millis(50),
                    client.recv_from(&mut buf),
                )
                .await
                .is_err(),
                "final-drop path must not send an acknowledgement"
            );
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
            .accept_all_notifications()
            .build()
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

        let earliest = receiver.inner.authoritative_boots_time().unwrap();
        let result = receiver.handle_v3(msg, client_addr).await.unwrap();
        let latest = receiver.inner.authoritative_boots_time().unwrap();
        assert!(matches!(result, Some(Notification::InformV3 { .. })));

        let mut buf = vec![0u8; 4096];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.recv_from(&mut buf),
        )
        .await
        .expect("expected the inform acknowledgement")
        .unwrap();

        let ack = V3Message::decode(Bytes::copy_from_slice(&buf[..len])).unwrap();
        let ack_usm = UsmSecurityParams::decode(ack.security_params).unwrap();
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
        let first = NotificationReceiver::bind("127.0.0.1:0").await.unwrap();
        let second = NotificationReceiver::bind("127.0.0.1:0").await.unwrap();

        crate::v3::validate_engine_id(first.engine_id()).unwrap();
        crate::v3::validate_engine_id(second.engine_id()).unwrap();
        assert_eq!(first.engine_id().len(), 17);
        assert_ne!(first.engine_id(), second.engine_id());
    }

    #[tokio::test]
    async fn test_builder_generates_engine_id() {
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .build()
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
            .build()
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
            .acceptance_policy(move |_: &NotificationEnvelope<'_>| {
                policy_calls_for_receiver.fetch_add(1, Ordering::Relaxed);
                NotificationAcceptance::Accept
            })
            .build()
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
            .usm_user("plainuser", |u| u)
            .accept_all_notifications()
            .build()
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
            .accept_all_notifications()
            .build()
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

    /// A stale inform under a remote sender's engine ID (Step 7b) gets no
    /// notInTimeWindows Report even though its reportableFlag is set: the
    /// receiver is not authoritative for that engine's clock. Timeliness
    /// (Step 7b) is evaluated in the shared USM core before the Inform is
    /// rejected as foreign-engine (RFC 3414 Section 1.5.1), so a stale
    /// remote-engine inform still fails at Step 7b rather than being
    /// acknowledged.
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[tokio::test]
    async fn test_v3_inform_remote_stale_gets_no_report() {
        let receiver = remote_trap_receiver().await;

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();

        // Seed the remote engine's timeliness state with a fresh trap under the
        // same engine ID (the per-engine state is keyed by engine ID and shared
        // with informs).
        let fresh = build_authed_v3_trap(b"remote-sender-engine", 7, 10_000);
        assert!(
            receiver
                .handle_v3(fresh, client_addr)
                .await
                .unwrap()
                .is_some()
        );

        let mut buf = vec![0u8; 4096];

        let stale = build_v3_notification(
            crate::pdu::PduType::InformRequest,
            b"remote-sender-engine",
            7,
            5_000,
            b"trapuser",
            Some((b"authpass12345678", AuthProtocol::Sha1)),
        );
        assert!(receiver.handle_v3(stale, client_addr).await.is_err());
        assert_eq!(receiver.usm_not_in_time_windows(), 0);

        let result = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            client.recv_from(&mut buf),
        )
        .await;
        assert!(
            result.is_err(),
            "no Report may be sent for a Step 7b timeliness failure"
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
            .acceptance_policy(move |_: &NotificationEnvelope<'_>| {
                policy_calls_for_receiver.fetch_add(1, Ordering::Relaxed);
                NotificationAcceptance::Accept
            })
            .build()
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
            .accept_all_notifications()
            .build()
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

        let report = V3Message::decode(report_bytes.clone()).unwrap();
        assert_eq!(
            report.global_data.msg_flags.security_level,
            SecurityLevel::AuthNoPriv,
            "notInTimeWindows report must be authenticated (authNoPriv)"
        );
        assert!(!report.global_data.msg_flags.reportable);

        let report_usm = UsmSecurityParams::decode(report.security_params.clone()).unwrap();
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
            .accept_all_notifications()
            .build()
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

        let report = V3Message::decode(report_bytes.clone()).unwrap();
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
            .accept_all_notifications()
            .build()
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

        let report = V3Message::decode(Bytes::copy_from_slice(&buf[..len])).unwrap();
        assert_eq!(
            report.global_data.msg_flags.security_level,
            SecurityLevel::NoAuthNoPriv
        );
        let report_usm = UsmSecurityParams::decode(report.security_params.clone()).unwrap();
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

    fn build_v2c_trap(community: &[u8]) -> Bytes {
        build_v2c_trap_with_request_id(community, 1)
    }

    fn build_v2c_trap_with_request_id(community: &[u8], request_id: i32) -> Bytes {
        use crate::message::CommunityMessage;
        use crate::pdu::Pdu;
        let pdu = Pdu::trap_v2(request_id, 100, &oids::cold_start(), vec![]);
        CommunityMessage::v2c(Bytes::copy_from_slice(community), pdu)
            .unwrap()
            .encode()
            .unwrap()
    }

    async fn receive_buffer_identity(receiver: &NotificationReceiver) -> (usize, usize, usize) {
        let buffer = receiver.inner.recv_gate.lock().await;
        (buffer.as_ptr() as usize, buffer.len(), buffer.capacity())
    }

    fn build_v2c_inform(community: &[u8]) -> Bytes {
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
        buf.try_push_sequence(|buf| {
            buf.push_bytes(&[0x02, 0x05, 1, 0, 0, 0, 9]);
            buf.push_oid(&oid!(1, 3, 6, 1, 4, 1, 9999, 1, 0))
        })
    }

    fn build_notification_with_malformed_integer(version: crate::Version) -> Bytes {
        let mut buf = crate::ber::EncodeBuf::new();
        buf.try_push_sequence(|buf| {
            match version {
                crate::Version::V1 => {
                    buf.try_push_constructed(crate::ber::tag::pdu::TRAP_V1, |buf| {
                        buf.try_push_sequence(push_malformed_integer_varbind)?;
                        buf.push_unsigned32(crate::ber::tag::application::TIMETICKS, 123);
                        buf.push_integer(0);
                        buf.push_integer(0);
                        buf.push_ip_address([127, 0, 0, 1]);
                        buf.push_oid(&oid!(1, 3, 6, 1, 4, 1, 9999))
                    })?;
                }
                crate::Version::V2c => {
                    buf.try_push_constructed(crate::ber::tag::pdu::TRAP_V2, |buf| {
                        buf.try_push_sequence(|buf| {
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
            buf.push_octet_string(b"public");
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
            .build()
            .await
            .unwrap();
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let result = receiver
            .handle_v2c(build_v2c_trap(b"public"), source)
            .await
            .unwrap();
        assert!(matches!(result, Some(Notification::TrapV2c { .. })));
    }

    #[tokio::test]
    async fn community_receiver_exposes_trailing_anomalies_in_notification_and_metadata() {
        let observed = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let policy_observed = std::sync::Arc::clone(&observed);
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .acceptance_policy(move |notification: &NotificationEnvelope<'_>| {
                *policy_observed.lock().unwrap() = notification.decode_anomalies.to_vec();
                NotificationAcceptance::Accept
            })
            .build()
            .await
            .unwrap();
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
            assert_eq!(notification.decode_anomalies(), expected);
            assert_eq!(observed.lock().unwrap().as_slice(), expected);
        }
    }

    #[tokio::test]
    async fn strict_receiver_rejects_suffixes_for_v1_and_v2c() {
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .strict_decoding()
            .build()
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
                .compatibility_policy(crate::CompatibilityPolicy::STRICT)
                .build()
                .await
                .unwrap();
            let packet = build_notification_with_malformed_integer(version);
            let result = match version {
                crate::Version::V1 => strict.handle_v1(packet, source).await,
                crate::Version::V2c => strict.handle_v2c(packet, source).await,
                crate::Version::V3 => unreachable!(),
            };
            assert!(result.is_err());

            let mut targeted = crate::CompatibilityPolicy::STRICT;
            targeted.truncate_numeric_values = true;
            let receiver = NotificationReceiver::builder()
                .bind("127.0.0.1:0")
                .compatibility_policy(targeted)
                .build()
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
                notification.decode_anomalies(),
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
            let receiver = NotificationReceiver::builder()
                .bind("127.0.0.1:0")
                .authoritative_engine(AuthoritativeEngine::for_test(engine_id.clone(), 1))
                .usm_user(username.clone(), move |_| config)
                .accept_all_notifications()
                .build()
                .await
                .unwrap();
            let source_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut message = message.to_vec();
            message.extend_from_slice(&[0x05, 0]);
            let notification = receiver
                .handle_v3(Bytes::from(message), source_socket.local_addr().unwrap())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                notification.decode_anomalies(),
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
                .usm_user(username.clone(), move |_| config)
                .accept_all_notifications()
                .strict_decoding()
                .build()
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
            .build()
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
        let receiver = NotificationReceiver::bind("127.0.0.1:0").await.unwrap();
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let result = receiver
            .handle_v2c(build_v2c_trap(b"anything"), source)
            .await
            .unwrap();
        assert!(matches!(result, Some(Notification::TrapV2c { .. })));
    }

    #[tokio::test]
    async fn test_v1_trap_wrong_community_dropped() {
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .build()
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
            Some(Notification::TrapV1 { .. })
        ));
    }

    #[tokio::test]
    async fn acceptance_envelope_normalizes_v1_transport_security_and_content() {
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .acceptance_policy(move |notification: &NotificationEnvelope<'_>| {
                assert_eq!(notification.source, source);
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
                assert_eq!(notification.uptime, 12_345);
                assert_eq!(notification.trap_oid().unwrap(), oids::cold_start());
                assert!(notification.varbinds.is_empty());
                assert_eq!(notification.request_id, None);
                assert!(notification.decode_anomalies.is_empty());
                assert!(matches!(
                    notification.notification(),
                    Notification::TrapV1 { .. }
                ));
                NotificationAcceptance::Accept
            })
            .build()
            .await
            .unwrap();

        assert!(matches!(
            receiver
                .handle_v1(build_v1_trap(b"public"), source)
                .await
                .unwrap(),
            Some(Notification::TrapV1 { .. })
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
            .acceptance_policy(move |_: &NotificationEnvelope<'_>| {
                policy_calls_for_receiver.fetch_add(1, Ordering::Relaxed);
                NotificationAcceptance::Accept
            })
            .build()
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
    async fn acceptance_policy_can_reject_v2c_inform_by_arbitrary_content_without_ack() {
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let source = client.local_addr().unwrap();
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .acceptance_policy(move |notification: &NotificationEnvelope<'_>| {
                let inspected = notification.source == source
                    && notification.version == Version::V2c
                    && notification.community.map(Community::as_bytes)
                        == Some(b"public".as_slice())
                    && notification.username.is_none()
                    && notification.security_level.is_none()
                    && notification.pdu_class == NotificationPduClass::Inform
                    && notification.context_engine_id.is_none()
                    && notification.context_name.is_none()
                    && notification.uptime == 100
                    && notification
                        .trap_oid()
                        .is_ok_and(|oid| oid == oids::cold_start())
                    && notification.request_id == Some(1)
                    && notification.varbinds.len() == 1
                    && notification.varbinds[0].oid == oid!(1, 3, 6, 1, 4, 1, 99999, 1)
                    && notification.decode_anomalies.is_empty();
                if inspected {
                    NotificationAcceptance::Reject
                } else {
                    NotificationAcceptance::Accept
                }
            })
            .build()
            .await
            .unwrap();

        let result = receiver
            .handle_v2c(build_oversized_v2c_inform(b"public"), source)
            .await
            .unwrap();
        assert!(result.is_none());
        let mut buf = [0_u8; 1];
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(50),
                client.recv_from(&mut buf),
            )
            .await
            .is_err(),
            "content-rejected Inform must not be acknowledged"
        );
    }

    #[tokio::test]
    async fn acceptance_policy_error_rejects_inform_without_ack() {
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .try_acceptance_policy(|_: &NotificationEnvelope<'_>| {
                Err(NotificationAcceptanceError::new(
                    "policy backend unavailable",
                ))
            })
            .build()
            .await
            .unwrap();
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let result = receiver
            .handle_v2c(build_v2c_inform(b"public"), client.local_addr().unwrap())
            .await
            .unwrap();
        assert!(result.is_none());
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
    async fn acceptance_policy_panic_rejects_inform_and_recv_continues_to_next_datagram() {
        let calls = Arc::new(AtomicU32::new(0));
        let calls_for_receiver = Arc::clone(&calls);
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .acceptance_policy(move |_: &NotificationEnvelope<'_>| {
                if calls_for_receiver.fetch_add(1, Ordering::Relaxed) == 0 {
                    panic!("policy failure");
                }
                NotificationAcceptance::Accept
            })
            .build()
            .await
            .unwrap();
        let receiver_addr = receiver.local_addr();
        let receive = tokio::spawn(async move { receiver.recv().await });
        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

        sender
            .send_to(&build_v2c_inform(b"public"), receiver_addr)
            .await
            .unwrap();
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
        let (notification, source) =
            tokio::time::timeout(std::time::Duration::from_secs(1), receive)
                .await
                .expect("receiver did not continue after policy panic")
                .unwrap()
                .unwrap();
        assert_eq!(source, sender.local_addr().unwrap());
        assert!(matches!(notification, Notification::TrapV2c { .. }));
        assert_eq!(calls.load(Ordering::Relaxed), 2);
    }

    /// A matching inform is still acknowledged (the filter does not suppress
    /// valid acks).
    #[tokio::test]
    async fn test_v2c_inform_matching_community_acked() {
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .build()
            .await
            .unwrap();

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();

        let result = receiver
            .handle_v2c(build_v2c_inform(b"public"), client_addr)
            .await
            .unwrap();
        assert!(matches!(result, Some(Notification::InformV2c { .. })));

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
    async fn oversized_v2c_inform_uses_fitting_toobig_without_counting_drop() {
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .max_message_size(80)
            .build()
            .await
            .unwrap();
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let notification = receiver
            .handle_v2c(
                build_oversized_v2c_inform(b"public"),
                client.local_addr().unwrap(),
            )
            .await
            .unwrap();
        assert!(matches!(notification, Some(Notification::InformV2c { .. })));

        let mut buf = vec![0; 1024];
        let (len, _) = client.recv_from(&mut buf).await.unwrap();
        let response =
            crate::message::CommunityMessage::decode(Bytes::copy_from_slice(&buf[..len])).unwrap();
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
            .build()
            .await
            .unwrap();
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

        receiver
            .handle_v2c(
                build_oversized_v2c_inform(b"public"),
                client.local_addr().unwrap(),
            )
            .await
            .unwrap();
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
        let receiver = NotificationReceiver::bind("0.0.0.0:0").await.unwrap();
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

        let (notification, peer) = receive_task.await.unwrap().unwrap();
        assert!(matches!(notification, Notification::InformV2c { .. }));
        let client_addr = client.local_addr().unwrap();
        assert_eq!(peer.port(), client_addr.port());
        assert_eq!(peer.ip().to_canonical(), client_addr.ip().to_canonical());
    }

    #[tokio::test]
    async fn receive_buffer_reuses_capacity_at_udp_boundaries() {
        let receiver = NotificationReceiver::bind("127.0.0.1:0").await.unwrap();
        let destination = receiver.local_addr();
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let initial = receive_buffer_identity(&receiver).await;
        assert_eq!(initial.1, crate::UDP_RECEIVE_BUFFER_SIZE);
        assert!(initial.2 >= crate::UDP_RECEIVE_BUFFER_SIZE);

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

        let (notification, _) =
            tokio::time::timeout(std::time::Duration::from_secs(2), receiver.recv())
                .await
                .expect("maximum UDP notification stalled")
                .unwrap();
        let Notification::TrapV2c {
            request_id,
            decode_anomalies,
            ..
        } = notification
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
        assert_eq!(receive_buffer_identity(&receiver).await, initial);

        client
            .send_to(&build_v2c_trap_with_request_id(b"public", 71), destination)
            .await
            .unwrap();
        let (notification, _) = receiver.recv().await.unwrap();
        assert!(matches!(
            notification,
            Notification::TrapV2c { request_id: 71, .. }
        ));
        assert_eq!(receive_buffer_identity(&receiver).await, initial);
    }

    #[tokio::test]
    async fn receive_buffer_accepts_maximum_native_ipv6_udp_payload() {
        const IPV6_MAX_UDP_PAYLOAD: usize = 65_527;

        let receiver = NotificationReceiver::bind("[::1]:0").await.unwrap();
        let destination = receiver.local_addr();
        let client = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
        let initial = receive_buffer_identity(&receiver).await;
        assert_eq!(initial.1, crate::UDP_RECEIVE_BUFFER_SIZE);
        assert!(initial.2 >= crate::UDP_RECEIVE_BUFFER_SIZE);

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

        let (notification, _) =
            tokio::time::timeout(std::time::Duration::from_secs(2), receiver.recv())
                .await
                .expect("maximum native IPv6 UDP notification stalled")
                .unwrap();
        let Notification::TrapV2c {
            request_id,
            decode_anomalies,
            ..
        } = notification
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
        assert_eq!(receive_buffer_identity(&receiver).await, initial);
    }

    #[tokio::test]
    async fn receive_buffer_survives_skipped_datagrams_policy_errors_and_panics() {
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .try_acceptance_policy(|notification: &NotificationEnvelope<'_>| {
                match notification.request_id {
                    Some(1) => Ok(NotificationAcceptance::Reject),
                    Some(2) => Err(NotificationAcceptanceError::new("injected policy error")),
                    Some(3) => panic!("injected policy panic"),
                    _ => Ok(NotificationAcceptance::Accept),
                }
            })
            .build()
            .await
            .unwrap();
        let destination = receiver.local_addr();
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let initial = receive_buffer_identity(&receiver).await;

        for datagram in [
            Bytes::from_static(&[0x30, 0x01, 0xff]),
            build_v2c_trap_with_request_id(b"public", 1),
            build_v2c_trap_with_request_id(b"public", 2),
            build_v2c_trap_with_request_id(b"public", 3),
            build_v2c_trap_with_request_id(b"public", 4),
        ] {
            client.send_to(&datagram, destination).await.unwrap();
        }

        let (notification, _) =
            tokio::time::timeout(std::time::Duration::from_secs(1), receiver.recv())
                .await
                .expect("receiver did not advance past skipped datagrams")
                .unwrap();
        assert!(matches!(
            notification,
            Notification::TrapV2c { request_id: 4, .. }
        ));
        assert_eq!(receive_buffer_identity(&receiver).await, initial);
    }

    #[tokio::test]
    async fn cancelled_cloned_recv_returns_shared_buffer_to_next_waiter() {
        use std::task::Poll;

        let receiver = NotificationReceiver::bind("127.0.0.1:0").await.unwrap();
        let cloned = receiver.clone();
        assert!(Arc::ptr_eq(&receiver.inner, &cloned.inner));
        let initial = receive_buffer_identity(&receiver).await;

        let mut cancelled = Box::pin(cloned.recv());
        assert!(matches!(futures::poll!(&mut cancelled), Poll::Pending));
        drop(cancelled);
        assert_eq!(receive_buffer_identity(&receiver).await, initial);

        let gate = receiver.inner.recv_gate.lock().await;
        let queued_clone = receiver.clone();
        let mut queued = Box::pin(queued_clone.recv());
        assert!(matches!(futures::poll!(&mut queued), Poll::Pending));
        drop(queued);
        drop(gate);
        assert_eq!(receive_buffer_identity(&receiver).await, initial);

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .send_to(&build_v2c_trap(b"public"), receiver.local_addr())
            .await
            .unwrap();
        let (notification, _) = receiver.recv().await.unwrap();
        assert!(matches!(notification, Notification::TrapV2c { .. }));
        assert_eq!(receive_buffer_identity(&receiver).await, initial);
    }

    #[tokio::test]
    async fn concurrent_cloned_recv_waiters_preserve_fifo_without_stalling() {
        use std::task::Poll;

        let receiver = NotificationReceiver::bind("127.0.0.1:0").await.unwrap();
        let destination = receiver.local_addr();
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let initial = receive_buffer_identity(&receiver).await;

        // Hold the gate while each future is polled once. This deterministically
        // establishes the FIFO waiter order before the datagram burst arrives.
        let gate = receiver.inner.recv_gate.lock().await;
        let first_receiver = receiver.clone();
        let second_receiver = receiver.clone();
        let third_receiver = receiver.clone();
        let mut first = Box::pin(first_receiver.recv());
        let mut second = Box::pin(second_receiver.recv());
        let mut third = Box::pin(third_receiver.recv());
        assert!(matches!(futures::poll!(&mut first), Poll::Pending));
        assert!(matches!(futures::poll!(&mut second), Poll::Pending));
        assert!(matches!(futures::poll!(&mut third), Poll::Pending));

        for request_id in [11, 12, 13] {
            client
                .send_to(
                    &build_v2c_trap_with_request_id(b"public", request_id),
                    destination,
                )
                .await
                .unwrap();
        }
        drop(gate);

        let results = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            futures::join!(first, second, third)
        })
        .await
        .expect("concurrent recv waiters stalled");
        let request_ids = [results.0, results.1, results.2].map(|result| match result.unwrap().0 {
            Notification::TrapV2c { request_id, .. } => request_id,
            other => panic!("unexpected notification: {other:?}"),
        });
        assert_eq!(request_ids, [11, 12, 13]);
        assert_eq!(receive_buffer_identity(&receiver).await, initial);
    }

    /// A dual-stack IPv6 wildcard socket receives this IPv4 datagram through
    /// an IPv4-mapped address. The two loopback aliases make source selection
    /// deterministic without requiring host network configuration.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn wildcard_ipv6_dual_stack_inform_reply_preserves_mapped_destination() {
        let receiver = NotificationReceiver::bind("[::]:0").await.unwrap();
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

        let (notification, peer) = receive_task.await.unwrap().unwrap();
        assert!(matches!(notification, Notification::InformV2c { .. }));
        let client_addr = client.local_addr().unwrap();
        assert_eq!(peer.port(), client_addr.port());
        assert_eq!(peer.ip().to_canonical(), client_addr.ip().to_canonical());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn wildcard_ipv6_report_uses_received_destination_as_source() {
        let receiver = NotificationReceiver::builder()
            .bind("[::]:0")
            .engine_id(b"test-report-source".to_vec())
            .build()
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
        let receiver = NotificationReceiver::builder()
            .bind("0.0.0.0:0")
            .engine_id(b"wildcard-inform-engine".to_vec())
            .engine_boots(1)
            .usm_user("informuser", |user| {
                user.auth(AuthProtocol::Sha1, b"authpass12345678")
            })
            .accept_all_notifications()
            .build()
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

        let (notification, _) = receive_task.await.unwrap().unwrap();
        assert!(matches!(notification, Notification::InformV3 { .. }));
    }
}
