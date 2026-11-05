//! Socketless `SNMPv3` notification processing.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use bytes::Bytes;

use crate::error::{Error, Result};
use crate::message::{MsgGlobalData, RawV3Message, ScopedPdu, SecurityLevel};
use crate::message_size::MessageSize;
use crate::pdu::{Pdu, PduType};
use crate::response_finalizer::FinalizedResponse;
use crate::v3::process::{
    RemoteEngineTable, UsmCounters, V3Inbound, V3InboundMessage, V3LocalContext, V3Role,
    process_v3_inbound,
};
use crate::v3::{
    AuthoritativeEngine, CryptoResult, DerivedKeys, DesSaltState, SaltCounter, UsmFailure,
    UsmSecurityParams, UsmStats, UsmUser,
};

use super::handlers::{V3InformResponder, finalize_v3_inform_response, v3_notification};
use super::{
    MAX_REMOTE_ENGINES, Notification, NotificationVarbindValidation, NotificationWireIdentity,
    V3NotificationWireIdentity,
};

/// Local authoritative engine state shared by [`NotificationProcessor`]s.
///
/// Clones share the [`AuthoritativeEngine`], the usmStats counters,
/// `snmpSilentDrops`, and the AES privacy salt counter. Processors built from
/// one engine therefore report one set of RFC 3414 statistics while each
/// keeps its own users and remote-engine timeliness state.
#[derive(Clone)]
pub struct NotificationEngine {
    inner: Arc<EngineInner>,
}

struct EngineInner {
    authoritative_engine: AuthoritativeEngine,
    engine_id: Bytes,
    usm_stats: UsmCounters,
    snmp_silent_drops: AtomicU32,
    salt_counter: SaltCounter,
}

impl std::fmt::Debug for NotificationEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotificationEngine")
            .field("engine_id", &self.inner.engine_id)
            .field("usm_stats", &self.usm_stats())
            .field("snmp_silent_drops", &self.snmp_silent_drops())
            .finish_non_exhaustive()
    }
}

impl NotificationEngine {
    /// Create shared notification state for a persisted authoritative engine.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RandomSource`] if the AES privacy salt counter cannot
    /// be initialized.
    pub fn new(engine: AuthoritativeEngine) -> Result<Self> {
        Ok(Self {
            inner: Arc::new(EngineInner {
                engine_id: Bytes::copy_from_slice(engine.engine_id()),
                authoritative_engine: engine,
                usm_stats: UsmCounters::default(),
                snmp_silent_drops: AtomicU32::new(0),
                salt_counter: SaltCounter::new()?,
            }),
        })
    }

    /// The local authoritative engine ID.
    #[must_use]
    pub fn engine_id(&self) -> &[u8] {
        &self.inner.engine_id
    }

    /// The persisted authoritative engine state.
    #[must_use]
    pub fn authoritative_engine(&self) -> &AuthoritativeEngine {
        &self.inner.authoritative_engine
    }

    /// Return the current usmStats counter values.
    #[must_use]
    pub fn usm_stats(&self) -> UsmStats {
        self.inner.usm_stats.snapshot()
    }

    /// Return the `snmpSilentDrops` value.
    ///
    /// This counter changes only when an Inform response and its exact
    /// empty-varbind `tooBig` alternate both exceed the effective limit.
    #[must_use]
    pub fn snmp_silent_drops(&self) -> u32 {
        self.inner.snmp_silent_drops.load(Ordering::Relaxed)
    }

    fn boots_time(&self) -> Result<(u32, u32)> {
        self.inner.authoritative_engine.current_boots_time()
    }
}

/// Builder for [`NotificationProcessor`].
///
/// Created with [`NotificationProcessor::builder`].
pub struct NotificationProcessorBuilder {
    engine: NotificationEngine,
    usm_users: HashMap<Bytes, UsmUser>,
    des_salt_state: Option<DesSaltState>,
    max_remote_engines: usize,
    max_message_size: usize,
    decode_config: crate::DecodeConfig,
}

impl NotificationProcessorBuilder {
    fn new(engine: NotificationEngine) -> Self {
        Self {
            engine,
            usm_users: HashMap::new(),
            des_salt_state: None,
            max_remote_engines: MAX_REMOTE_ENGINES,
            max_message_size: crate::UDP_RECEIVE_LIMITS.advertised().as_usize(),
            decode_config: crate::DecodeConfig::default(),
        }
    }

    /// Add a USM user for V3 processing.
    ///
    /// This has the same shape as [`NotificationReceiverBuilder::usm_user`](super::NotificationReceiverBuilder::usm_user).
    pub fn usm_user<F>(mut self, username: impl Into<Bytes>, configure: F) -> CryptoResult<Self>
    where
        F: FnOnce(UsmUser) -> CryptoResult<UsmUser>,
    {
        let username_bytes: Bytes = username.into();
        let config = configure(UsmUser::new(username_bytes.clone()))?;
        self.usm_users.insert(username_bytes, config);
        Ok(self)
    }

    /// Set durable local generating-engine state for DES/3DES Inform responses.
    ///
    /// Without this state, a DES/3DES Inform is still processed, but
    /// [`NotificationProcessor::encode_inform_response`] fails.
    #[must_use]
    pub fn des_salt_state(mut self, state: DesSaltState) -> Self {
        self.des_salt_state = Some(state);
        self
    }

    /// Set the number of remote authoritative engines whose timeliness state
    /// is retained for trap senders.
    ///
    /// The default is 8192. When full, the least-recently-updated engine is
    /// evicted.
    #[must_use]
    pub fn max_remote_engines(mut self, max: usize) -> Self {
        self.max_remote_engines = max;
        self
    }

    /// Set the local upper bound for Inform responses and V3 Reports.
    ///
    /// This has the same meaning as
    /// [`NotificationReceiverBuilder::max_message_size`](super::NotificationReceiverBuilder::max_message_size).
    #[must_use]
    pub fn max_message_size(mut self, size: usize) -> Self {
        self.max_message_size = size;
        self
    }

    /// Set bounded notification-decoding compatibility.
    ///
    /// The default is [`crate::DecodeConfig::DEFAULT`].
    #[must_use]
    pub fn decode_config(mut self, config: crate::DecodeConfig) -> Self {
        self.decode_config = config;
        self
    }

    /// Build the notification processor.
    ///
    /// Returns a configuration error when USM credentials are invalid,
    /// `max_remote_engines` is zero, `max_message_size` exceeds the UDP
    /// capacity, or the DES sender boots do not match the authoritative
    /// engine boots.
    pub fn build(self) -> Result<NotificationProcessor> {
        if self.max_remote_engines == 0 {
            return Err(Error::Config("max_remote_engines must be non-zero".into()).boxed());
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
        if let Some(state) = &self.des_salt_state {
            check_des_salt_state(&self.engine, state)?;
        }
        let usm_users = prepare_users(self.usm_users.into_values()).map_err(|error| {
            Error::Config(format!("invalid USM user configuration: {error}").into()).boxed()
        })?;

        Ok(NotificationProcessor {
            engine: self.engine,
            usm_users: RwLock::new(Arc::new(usm_users)),
            des_salt_state: Mutex::new(self.des_salt_state),
            remote_engines: Mutex::new(RemoteEngineTable::new(self.max_remote_engines)),
            max_message_size: self.max_message_size,
            decode_config: self.decode_config,
        })
    }
}

fn prepare_users(
    users: impl IntoIterator<Item = UsmUser>,
) -> CryptoResult<HashMap<Bytes, UsmUser>> {
    let users: BTreeMap<Bytes, UsmUser> = users
        .into_iter()
        .map(|user| (user.username().clone(), user))
        .collect();
    users
        .into_iter()
        .map(|(username, mut user)| {
            user.validate_and_precompute()?;
            Ok((username, user))
        })
        .collect()
}

fn check_des_salt_state(engine: &NotificationEngine, state: &DesSaltState) -> Result<()> {
    if engine.authoritative_engine().engine_boots() != state.engine_boots() {
        return Err(Error::Config(
            "DES sender boots must match the authoritative engine boots".into(),
        )
        .boxed());
    }
    Ok(())
}

/// Socketless `SNMPv3` notification processor.
///
/// The processor runs the same RFC 3414 USM processing as
/// [`NotificationReceiver`](super::NotificationReceiver) for one datagram at a
/// time, but leaves the socket to the caller: it returns Reports to send
/// instead of sending them, and encodes an Inform response only when the
/// caller decides to acknowledge. It handles `SNMPv3` only.
///
/// Each processor owns its USM users and remote-engine timeliness state, and
/// shares its local authoritative engine, counters, and AES salt counter
/// through a [`NotificationEngine`].
///
/// # Example
///
/// ```rust,no_run
/// use async_snmp::notification::{
///     NotificationEngine, NotificationProcessor, NotificationVarbindValidation, V3Processed,
/// };
/// use async_snmp::{AuthProtocol, AuthoritativeEngine, InformResponse, SecurityLevel};
/// use std::convert::Infallible;
/// use tokio::net::UdpSocket;
///
/// # async fn example() -> Result<(), Box<async_snmp::Error>> {
/// # // Replace this no-op with durable storage in an application.
/// let engine = AuthoritativeEngine::install(b"receiver-engine".to_vec(), |_| {
///     Ok::<(), Infallible>(())
/// })?;
/// let processor = NotificationProcessor::builder(NotificationEngine::new(engine)?)
///     .usm_user("informuser", |u| u.auth(AuthProtocol::Sha256, b"authpass123"))
///     .unwrap()
///     .build()?;
///
/// let socket = UdpSocket::bind("0.0.0.0:1162").await.unwrap();
/// let mut buf = vec![0; async_snmp::UDP_RECEIVE_BUFFER_SIZE];
/// loop {
///     let (len, source) = socket.recv_from(&mut buf).await.unwrap();
///     let datagram = bytes::Bytes::copy_from_slice(&buf[..len]);
///     match processor.process(datagram, source) {
///         Ok(V3Processed::Authenticated(message)) => {
///             if message.security_level() < SecurityLevel::AuthNoPriv {
///                 continue;
///             }
///             let Ok(Some(notification)) =
///                 message.to_notification(NotificationVarbindValidation::Tolerant)
///             else {
///                 continue;
///             };
///             println!("{notification:?}");
///             if let Some(ack) = message.inform_ack() {
///                 match processor.encode_inform_response(&ack)? {
///                     InformResponse::Response(bytes) | InformResponse::TooBig(bytes) => {
///                         socket.send_to(&bytes, source).await.unwrap();
///                     }
///                     _ => {}
///                 }
///             }
///         }
///         Ok(V3Processed::UsmFailed { report: Some(report), .. }) => {
///             socket.send_to(&report, source).await.unwrap();
///         }
///         Ok(_) => {}
///         Err(error) => eprintln!("dropped datagram from {source}: {error}"),
///     }
/// }
/// # }
/// ```
pub struct NotificationProcessor {
    engine: NotificationEngine,
    usm_users: RwLock<Arc<HashMap<Bytes, UsmUser>>>,
    des_salt_state: Mutex<Option<DesSaltState>>,
    /// Timeliness state for remote authoritative engines (trap senders),
    /// bounded with least-recently-updated eviction like the receiver's.
    remote_engines: Mutex<RemoteEngineTable>,
    max_message_size: usize,
    decode_config: crate::DecodeConfig,
}

impl std::fmt::Debug for NotificationProcessor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotificationProcessor")
            .field("engine", &self.engine)
            .field("max_message_size", &self.max_message_size)
            .finish_non_exhaustive()
    }
}

impl NotificationProcessor {
    /// Create a builder for a processor sharing `engine`.
    #[must_use]
    pub fn builder(engine: NotificationEngine) -> NotificationProcessorBuilder {
        NotificationProcessorBuilder::new(engine)
    }

    /// The shared local engine state.
    #[must_use]
    pub fn engine(&self) -> &NotificationEngine {
        &self.engine
    }

    /// Replace the configured USM users.
    ///
    /// Users are validated and precomputed before the table is replaced; on
    /// error the previous users remain. Remote-engine timeliness state is
    /// kept. A datagram already being processed completes with the users it
    /// started with.
    pub fn set_usm_users(&self, users: impl IntoIterator<Item = UsmUser>) -> CryptoResult<()> {
        let users = prepare_users(users)?;
        *self
            .usm_users
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Arc::new(users);
        Ok(())
    }

    /// Replace the durable DES/3DES sender state used for Inform responses.
    ///
    /// Returns a configuration error, leaving the previous state, when the
    /// state's boots do not match the authoritative engine boots.
    pub fn set_des_salt_state(&self, state: Option<DesSaltState>) -> Result<()> {
        if let Some(state) = &state {
            check_des_salt_state(&self.engine, state)?;
        }
        *self
            .des_salt_state
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = state;
        Ok(())
    }

    /// Run USM processing (RFC 3414 Section 3.2) over one `SNMPv3` datagram.
    ///
    /// Messages under the local engine ID use its authoritative time window;
    /// messages under a remote authoritative engine ID use per-engine
    /// timeliness state seeded from the first authenticated message. A USM
    /// failure is counted and may carry a Report for the caller to send to
    /// `source`.
    ///
    /// Any authenticated PDU type is returned; use
    /// [`V3InboundNotification::to_notification`] to select notifications.
    /// Returns an error for a datagram that cannot be decoded.
    pub fn process(&self, datagram: Bytes, source: SocketAddr) -> Result<V3Processed> {
        let users = Arc::clone(
            &self
                .usm_users
                .read()
                .unwrap_or_else(PoisonError::into_inner),
        );
        let sample_authoritative_time = || self.engine.boots_time();
        let ctx = self.local_context(&users, &sample_authoritative_time, source);
        let role = V3Role::Receiver {
            remote_engines: &self.remote_engines,
        };

        Ok(match process_v3_inbound(datagram, &ctx, &role)? {
            V3Inbound::Message(message) => V3Processed::Authenticated(Box::new(
                V3InboundNotification::new(*message, &self.engine.inner.engine_id, source),
            )),
            V3Inbound::Failed { failure, report } => V3Processed::UsmFailed { failure, report },
            V3Inbound::RemoteNotInTimeWindow => V3Processed::RemoteNotInTimeWindow,
        })
    }

    /// Answer an `SNMPv3` datagram as the authoritative engine with no users.
    ///
    /// Use this for a datagram that no processor claims. An empty
    /// (discovery), invalid, or foreign authoritative engine ID increments
    /// usmStatsUnknownEngineIDs and returns the Report when the message is
    /// reportable. A message under the local engine ID returns `None` and is
    /// not counted.
    pub fn report_unknown_engine(
        &self,
        datagram: Bytes,
        source: SocketAddr,
    ) -> Result<Option<Bytes>> {
        let message = RawV3Message::decode_bounded_with_target(
            datagram.clone(),
            crate::UDP_RECEIVE_LIMITS.accepted(),
            source,
            self.decode_config,
        )?
        .value;
        let usm_params = UsmSecurityParams::decode_with_context(
            message.security_params.clone(),
            message.security_params_offset,
            source,
            self.decode_config,
        )?
        .value;
        if usm_params.engine_id == self.engine.inner.engine_id {
            return Ok(None);
        }

        let users = HashMap::new();
        let sample_authoritative_time = || self.engine.boots_time();
        let ctx = self.local_context(&users, &sample_authoritative_time, source);
        match process_v3_inbound(datagram, &ctx, &V3Role::Authoritative)? {
            V3Inbound::Failed { report, .. } => Ok(report),
            V3Inbound::Message(_) | V3Inbound::RemoteNotInTimeWindow => {
                unreachable!("an authoritative engine without users accepts no foreign engine ID")
            }
        }
    }

    /// Encode the Response for an accepted Inform (RFC 3416 Section 4.2.7).
    ///
    /// The Response carries the authoritative boots/time sampled now, not when
    /// the Inform was processed. If it exceeds the smaller of the local and
    /// originator limits, the empty-varbind `tooBig` alternate is returned
    /// instead. If that also exceeds the limit, `snmpSilentDrops` is
    /// incremented and [`InformResponse::Suppressed`] is returned.
    ///
    /// Returns a configuration error when `ack` was localized to another
    /// engine ID, or when a DES/3DES response has no matching DES sender
    /// state. Persistence and crypto failures are also returned.
    pub fn encode_inform_response(&self, ack: &InformAck) -> Result<InformResponse> {
        if ack.engine_id != self.engine.inner.engine_id {
            return Err(Error::Config(
                "Inform acknowledgement belongs to another authoritative engine".into(),
            )
            .boxed());
        }
        let des_salt_state = self
            .des_salt_state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let sample_authoritative_time = || self.engine.boots_time();
        let responder = V3InformResponder {
            engine_id: &self.engine.inner.engine_id,
            authoritative_time: &sample_authoritative_time,
            max_message_size: self.max_message_size,
            salt_counter: Some(&self.engine.inner.salt_counter),
            des_salt_state: des_salt_state.as_ref(),
            snmp_silent_drops: &self.engine.inner.snmp_silent_drops,
            target: ack.source,
        };
        Ok(match finalize_v3_inform_response(ack, &responder)? {
            FinalizedResponse::Candidate(bytes) => InformResponse::Response(bytes),
            FinalizedResponse::Alternate(bytes) => InformResponse::TooBig(bytes),
            FinalizedResponse::Dropped => InformResponse::Suppressed,
        })
    }

    fn local_context<'a>(
        &'a self,
        usm_users: &'a HashMap<Bytes, UsmUser>,
        authoritative_time: &'a (dyn Fn() -> Result<(u32, u32)> + Send + Sync),
        source: SocketAddr,
    ) -> V3LocalContext<'a> {
        V3LocalContext {
            engine_id: &self.engine.inner.engine_id,
            engine_boots: self.engine.authoritative_engine().engine_boots(),
            engine_time: 0,
            authoritative_time: Some(authoritative_time),
            local_receive_capacity: crate::UDP_RECEIVE_LIMITS.advertised(),
            accepted_receive_size: crate::UDP_RECEIVE_LIMITS.accepted(),
            decode_config: self.decode_config,
            outbound_limit: self.max_message_size,
            usm_users,
            stats: &self.engine.inner.usm_stats,
            mpd: None,
            source,
        }
    }
}

/// Outcome of [`NotificationProcessor::process`].
#[derive(Debug)]
#[non_exhaustive]
pub enum V3Processed {
    /// Every USM check passed and the scoped PDU was decoded (and decrypted).
    Authenticated(Box<V3InboundNotification>),
    /// A USM step failed and its usmStats counter was incremented.
    ///
    /// `report` is the Report to send to the datagram's source, present only
    /// when the message was reportable and the Report fits the effective
    /// limit.
    UsmFailed {
        /// The failed USM step.
        failure: UsmFailure,
        /// The encoded Report, if one may be sent.
        report: Option<Bytes>,
    },
    /// An authenticated message from a remote authoritative engine was
    /// outside its time window (RFC 3414 Section 3.2 Step 7b).
    ///
    /// No counter is incremented and no Report is sent.
    RemoteNotInTimeWindow,
}

/// One authenticated `SNMPv3` message from [`NotificationProcessor::process`].
///
/// The username, context, and PDU are authenticated only at
/// [`SecurityLevel::AuthNoPriv`] or [`SecurityLevel::AuthPriv`].
pub struct V3InboundNotification {
    global_data: MsgGlobalData,
    usm_params: UsmSecurityParams,
    scoped_pdu: ScopedPdu,
    security_level: SecurityLevel,
    derived_keys: Arc<DerivedKeys>,
    decode_anomalies: Vec<crate::DecodeAnomaly>,
    is_local_engine: bool,
    source: SocketAddr,
}

impl std::fmt::Debug for V3InboundNotification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("V3InboundNotification")
            .field("msg_id", &self.global_data.msg_id)
            .field("authoritative_engine_id", &self.usm_params.engine_id)
            .field("username", &self.usm_params.username)
            .field("security_level", &self.security_level)
            .field("scoped_pdu", &self.scoped_pdu)
            .field("decode_anomalies", &self.decode_anomalies)
            .finish_non_exhaustive()
    }
}

impl V3InboundNotification {
    pub(super) fn new(
        message: V3InboundMessage,
        local_engine_id: &Bytes,
        source: SocketAddr,
    ) -> Self {
        Self {
            is_local_engine: message.usm_params.engine_id == *local_engine_id,
            global_data: message.global_data,
            usm_params: message.usm_params,
            scoped_pdu: message.scoped_pdu,
            security_level: message.security_level,
            derived_keys: Arc::new(message.derived_keys),
            decode_anomalies: message.decode_anomalies,
            source,
        }
    }

    /// Authoritative engine ID carried in the USM security parameters.
    #[must_use]
    pub fn authoritative_engine_id(&self) -> &Bytes {
        &self.usm_params.engine_id
    }

    /// Whether the message is localized to the local authoritative engine.
    #[must_use]
    pub fn is_local_engine(&self) -> bool {
        self.is_local_engine
    }

    /// USM username carried on the wire.
    #[must_use]
    pub fn username(&self) -> &Bytes {
        &self.usm_params.username
    }

    /// Actual security level carried on the wire.
    #[must_use]
    pub fn security_level(&self) -> SecurityLevel {
        self.security_level
    }

    /// V3 message ID from msgGlobalData.
    #[must_use]
    pub fn msg_id(&self) -> i32 {
        self.global_data.msg_id
    }

    /// The originator's advertised maximum message size.
    #[must_use]
    pub fn msg_max_size(&self) -> MessageSize {
        self.global_data.msg_max_size
    }

    /// The decoded (and decrypted) scoped PDU.
    #[must_use]
    pub fn scoped_pdu(&self) -> &ScopedPdu {
        &self.scoped_pdu
    }

    /// Accepted BER/value deviations from the received message, in decode order.
    #[must_use]
    pub fn decode_anomalies(&self) -> &[crate::DecodeAnomaly] {
        &self.decode_anomalies
    }

    /// Version, request ID, and V3 message/security identity from the wire.
    #[must_use]
    pub fn wire_identity(&self) -> NotificationWireIdentity {
        NotificationWireIdentity {
            version: crate::Version::V3,
            request_id: Some(self.scoped_pdu.pdu.request_id),
            v3: Some(V3NotificationWireIdentity {
                msg_id: self.global_data.msg_id,
                authoritative_engine_id: self.usm_params.engine_id.clone(),
                username: self.usm_params.username.clone(),
                security_level: self.security_level,
            }),
        }
    }

    /// Convert a V3 trap or Inform into a [`Notification`].
    ///
    /// Returns `None` for other PDU types and for an Inform localized to a
    /// foreign engine ID, because the receiver of an Inform is authoritative.
    /// Returns an error when the notification varbind prefix fails
    /// `validation`.
    pub fn to_notification(
        &self,
        validation: NotificationVarbindValidation,
    ) -> Result<Option<Notification>> {
        if self.scoped_pdu.pdu.pdu_type() == PduType::InformRequest && !self.is_local_engine {
            return Ok(None);
        }
        v3_notification(
            &self.usm_params.username,
            &self.scoped_pdu,
            self.security_level,
            &self.decode_anomalies,
            validation,
        )
    }

    /// Return the state needed to acknowledge this Inform later.
    ///
    /// Returns `None` unless the PDU is an `InformRequest` localized to the
    /// local engine ID.
    #[must_use]
    pub fn inform_ack(&self) -> Option<InformAck> {
        (self.scoped_pdu.pdu.pdu_type() == PduType::InformRequest && self.is_local_engine).then(
            || InformAck {
                request: self.scoped_pdu.pdu.clone(),
                msg_id: self.global_data.msg_id,
                msg_max_size: self.global_data.msg_max_size,
                security_level: self.security_level,
                engine_id: self.usm_params.engine_id.clone(),
                username: self.usm_params.username.clone(),
                context_engine_id: self.scoped_pdu.context_engine_id.clone(),
                context_name: self.scoped_pdu.context_name.clone(),
                derived_keys: Arc::clone(&self.derived_keys),
                source: self.source,
            },
        )
    }
}

/// Owned state for acknowledging one accepted V3 Inform.
///
/// Pass it to [`NotificationProcessor::encode_inform_response`] once the
/// application has decided to acknowledge. It retains the user's localized
/// keys, which its `Debug` output omits.
pub struct InformAck {
    pub(super) request: Pdu,
    pub(super) msg_id: i32,
    pub(super) msg_max_size: MessageSize,
    pub(super) security_level: SecurityLevel,
    pub(super) engine_id: Bytes,
    pub(super) username: Bytes,
    pub(super) context_engine_id: Bytes,
    pub(super) context_name: Bytes,
    pub(super) derived_keys: Arc<DerivedKeys>,
    pub(super) source: SocketAddr,
}

impl std::fmt::Debug for InformAck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InformAck")
            .field("request_id", &self.request.request_id)
            .field("msg_id", &self.msg_id)
            .field("security_level", &self.security_level)
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

impl InformAck {
    /// The Inform request ID.
    #[must_use]
    pub fn request_id(&self) -> i32 {
        self.request.request_id
    }

    /// The security level of the Inform and its Response.
    #[must_use]
    pub fn security_level(&self) -> SecurityLevel {
        self.security_level
    }
}

/// Encoded Response from [`NotificationProcessor::encode_inform_response`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InformResponse {
    /// The Response echoing the Inform's variable bindings.
    Response(Bytes),
    /// The empty-varbind `tooBig` alternate, sent because the Response
    /// exceeded the effective limit.
    TooBig(Bytes),
    /// Neither fit; `snmpSilentDrops` was incremented and nothing is sent.
    Suppressed,
}

#[cfg(test)]
mod tests {
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    use super::super::tests::{
        build_authed_v3_inform, build_authed_v3_trap, build_v3_inform_at_level, inform_user,
    };
    use super::super::tests::{build_noauth_v3_inform, build_v3_discovery_request};
    use super::*;
    use crate::message::V3Message;
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    use crate::v3::AuthProtocol;
    use crate::v3::{ReportStatus, classify_report};

    const ENGINE_ID: &[u8] = b"my-receiver-engine";

    fn source() -> SocketAddr {
        "127.0.0.1:9999".parse().unwrap()
    }

    fn engine(engine_id: &[u8], boots: u32) -> NotificationEngine {
        let engine = AuthoritativeEngine::for_test(Bytes::copy_from_slice(engine_id), boots);
        engine.set_elapsed_for_test(0);
        NotificationEngine::new(engine).unwrap()
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    fn processor_builder(engine: &NotificationEngine) -> NotificationProcessorBuilder {
        NotificationProcessor::builder(engine.clone())
            .usm_user("trapuser", |u| {
                u.auth(AuthProtocol::Sha1, b"authpass12345678")
            })
            .unwrap()
            .usm_user("informuser", |u| {
                u.auth(AuthProtocol::Sha1, b"authpass12345678")
            })
            .unwrap()
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    fn processor(engine: &NotificationEngine) -> NotificationProcessor {
        processor_builder(engine).build().unwrap()
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    fn local_inform(engine_boots: u32, engine_time: u32) -> Bytes {
        build_authed_v3_inform(
            ENGINE_ID,
            engine_boots,
            engine_time,
            b"informuser",
            b"authpass12345678",
            AuthProtocol::Sha1,
        )
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    fn authenticated(outcome: Result<V3Processed>) -> Box<V3InboundNotification> {
        match outcome.unwrap() {
            V3Processed::Authenticated(message) => message,
            other => panic!("expected an authenticated message, got {other:?}"),
        }
    }

    fn decode_pdu(message: &Bytes) -> (UsmSecurityParams, V3Message) {
        let message = V3Message::decode(message.clone(), crate::DecodeConfig::default())
            .unwrap()
            .value;
        let usm = UsmSecurityParams::decode(
            message.security_params().clone(),
            crate::DecodeConfig::default(),
        )
        .unwrap()
        .value;
        (usm, message)
    }

    fn report_status(report: &Bytes) -> ReportStatus {
        let (_, message) = decode_pdu(report);
        classify_report(message.pdu().expect("Report is plaintext")).unwrap()
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[test]
    fn remote_trap_is_accepted() {
        let processor = processor(&engine(ENGINE_ID, 1));

        let message = authenticated(processor.process(
            build_authed_v3_trap(b"remote-sender-engine", 7, 123_456),
            source(),
        ));

        assert!(!message.is_local_engine());
        assert_eq!(
            message.authoritative_engine_id().as_ref(),
            b"remote-sender-engine"
        );
        assert_eq!(message.username().as_ref(), b"trapuser");
        assert_eq!(message.security_level(), SecurityLevel::AuthNoPriv);
        assert!(message.inform_ack().is_none());
        assert!(matches!(
            message.to_notification(NotificationVarbindValidation::Strict),
            Ok(Some(Notification::TrapV3 { .. }))
        ));
        let wire_identity = message.wire_identity().v3.unwrap();
        assert_eq!(wire_identity.msg_id, message.msg_id());
        assert_eq!(
            wire_identity.authoritative_engine_id.as_ref(),
            b"remote-sender-engine"
        );
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[test]
    fn stale_remote_trap_is_not_in_time_window() {
        let processor = processor(&engine(ENGINE_ID, 1));

        authenticated(processor.process(
            build_authed_v3_trap(b"remote-sender-engine", 7, 10_000),
            source(),
        ));
        let stale = processor
            .process(
                build_authed_v3_trap(b"remote-sender-engine", 7, 5_000),
                source(),
            )
            .unwrap();

        assert!(matches!(stale, V3Processed::RemoteNotInTimeWindow));
        assert_eq!(processor.engine().usm_stats().not_in_time_windows, 0);
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[test]
    fn max_remote_engines_evicts_least_recently_updated_engine() {
        let engine = engine(ENGINE_ID, 1);
        assert!(
            processor_builder(&engine)
                .max_remote_engines(0)
                .build()
                .is_err()
        );
        let processor = processor_builder(&engine)
            .max_remote_engines(1)
            .build()
            .unwrap();

        authenticated(processor.process(
            build_authed_v3_trap(b"remote-engine-a", 7, 10_000),
            source(),
        ));
        authenticated(processor.process(
            build_authed_v3_trap(b"remote-engine-b", 7, 10_000),
            source(),
        ));
        {
            let engines = processor.remote_engines.lock().unwrap();
            assert_eq!(engines.len(), 1);
            assert!(engines.contains_key(&Bytes::from_static(b"remote-engine-b")));
        }

        // Engine A's state was evicted, so a time it would have rejected
        // seeds a new entry.
        authenticated(
            processor.process(build_authed_v3_trap(b"remote-engine-a", 7, 5_000), source()),
        );
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[test]
    fn local_inform_returns_ack() {
        let processor = processor(&engine(ENGINE_ID, 1));

        let message = authenticated(processor.process(local_inform(1, 0), source()));

        assert!(message.is_local_engine());
        assert!(matches!(
            message.to_notification(NotificationVarbindValidation::Strict),
            Ok(Some(Notification::InformV3 { .. }))
        ));
        let ack = message.inform_ack().expect("local Inform has an ack");
        assert_eq!(ack.request_id(), 1);
        assert_eq!(ack.security_level(), SecurityLevel::AuthNoPriv);
        assert!(!format!("{ack:?}").contains("key"));

        let foreign = authenticated(processor.process(
            build_authed_v3_inform(
                b"remote-sender-engine",
                7,
                10_000,
                b"informuser",
                b"authpass12345678",
                AuthProtocol::Sha1,
            ),
            source(),
        ));
        assert!(foreign.inform_ack().is_none());
        assert!(
            foreign
                .to_notification(NotificationVarbindValidation::Strict)
                .unwrap()
                .is_none()
        );
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[test]
    fn out_of_window_inform_gets_authenticated_report() {
        let processor = processor(&engine(ENGINE_ID, 1));

        let V3Processed::UsmFailed {
            failure: UsmFailure::NotInTimeWindows,
            report: Some(report),
        } = processor.process(local_inform(1, 5_000), source()).unwrap()
        else {
            panic!("expected a notInTimeWindows Report");
        };

        let (usm, message) = decode_pdu(&report);
        assert_eq!(message.security_level(), SecurityLevel::AuthNoPriv);
        assert_eq!(usm.engine_id.as_ref(), ENGINE_ID);
        assert_eq!(
            report_status(&report),
            ReportStatus::NotInTimeWindow { counter: 1 }
        );
        assert_eq!(processor.engine().usm_stats().not_in_time_windows, 1);
    }

    #[test]
    fn discovery_reports_only_when_reportable() {
        let processor = NotificationProcessor::builder(engine(ENGINE_ID, 1))
            .build()
            .unwrap();

        let V3Processed::UsmFailed {
            failure: UsmFailure::UnknownEngineIds,
            report: Some(report),
        } = processor
            .process(build_v3_discovery_request(42, true), source())
            .unwrap()
        else {
            panic!("expected a discovery Report");
        };
        let (usm, message) = decode_pdu(&report);
        assert_eq!(usm.engine_id.as_ref(), ENGINE_ID);
        assert_eq!(message.msg_id(), 42);
        assert_eq!(
            report_status(&report),
            ReportStatus::UnknownEngineId { counter: 1 }
        );

        assert!(matches!(
            processor
                .process(build_v3_discovery_request(43, false), source())
                .unwrap(),
            V3Processed::UsmFailed {
                failure: UsmFailure::UnknownEngineIds,
                report: None,
            }
        ));
        assert_eq!(processor.engine().usm_stats().unknown_engine_ids, 2);
    }

    #[test]
    fn report_unknown_engine_answers_empty_and_foreign_engine_ids() {
        let processor = NotificationProcessor::builder(engine(ENGINE_ID, 1))
            .build()
            .unwrap();

        let report = processor
            .report_unknown_engine(build_v3_discovery_request(42, true), source())
            .unwrap()
            .expect("discovery is reportable");
        assert_eq!(
            report_status(&report),
            ReportStatus::UnknownEngineId { counter: 1 }
        );

        let report = processor
            .report_unknown_engine(
                build_noauth_v3_inform(b"foreign-engine-id", b"informuser"),
                source(),
            )
            .unwrap()
            .expect("an Inform is reportable");
        let (usm, _) = decode_pdu(&report);
        assert_eq!(usm.engine_id.as_ref(), ENGINE_ID);
        assert_eq!(
            report_status(&report),
            ReportStatus::UnknownEngineId { counter: 2 }
        );

        assert!(
            processor
                .report_unknown_engine(build_noauth_v3_inform(ENGINE_ID, b"informuser"), source())
                .unwrap()
                .is_none()
        );
        let stats = processor.engine().usm_stats();
        assert_eq!(stats.unknown_engine_ids, 2);
        assert_eq!(stats.unknown_usernames, 0);
    }

    #[test]
    fn processors_on_one_engine_share_counters() {
        let engine = engine(ENGINE_ID, 1);
        let first = NotificationProcessor::builder(engine.clone())
            .build()
            .unwrap();
        let second = NotificationProcessor::builder(engine.clone())
            .build()
            .unwrap();

        first
            .process(build_v3_discovery_request(1, true), source())
            .unwrap();
        second
            .process(build_noauth_v3_inform(ENGINE_ID, b"unknown"), source())
            .unwrap();

        let stats = engine.usm_stats();
        assert_eq!(stats.unknown_engine_ids, 1);
        assert_eq!(stats.unknown_usernames, 1);
        assert_eq!(first.engine().usm_stats(), stats);
        assert_eq!(second.engine().usm_stats(), stats);
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[test]
    fn set_usm_users_keeps_remote_engine_state() {
        let processor = processor(&engine(ENGINE_ID, 1));
        authenticated(processor.process(
            build_authed_v3_trap(b"remote-sender-engine", 7, 10_000),
            source(),
        ));

        assert!(
            processor
                .set_usm_users([UsmUser::new(Bytes::new())])
                .is_err()
        );
        authenticated(processor.process(
            build_authed_v3_trap(b"remote-sender-engine", 7, 10_000),
            source(),
        ));

        processor
            .set_usm_users([UsmUser::new("trapuser")
                .auth(AuthProtocol::Sha1, b"authpass12345678")
                .unwrap()])
            .unwrap();
        assert!(matches!(
            processor
                .process(
                    build_authed_v3_trap(b"remote-sender-engine", 7, 5_000),
                    source()
                )
                .unwrap(),
            V3Processed::RemoteNotInTimeWindow
        ));
        assert!(matches!(
            processor.process(local_inform(1, 0), source()).unwrap(),
            V3Processed::UsmFailed {
                failure: UsmFailure::UnknownUserNames,
                ..
            }
        ));
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[test]
    fn deferred_inform_response_uses_current_boots_and_time() {
        let engine = engine(ENGINE_ID, 7);
        engine.authoritative_engine().set_elapsed_for_test(10);
        let processor = processor(&engine);
        let ack = authenticated(processor.process(local_inform(7, 10), source()))
            .inform_ack()
            .unwrap();

        engine.authoritative_engine().set_elapsed_for_test(100);
        let InformResponse::Response(response) = processor.encode_inform_response(&ack).unwrap()
        else {
            panic!("expected a Response");
        };

        let (usm, message) = decode_pdu(&response);
        assert_eq!(usm.engine_id.as_ref(), ENGINE_ID);
        assert_eq!((usm.engine_boots, usm.engine_time), (7, 100));
        assert_eq!(usm.username.as_ref(), b"informuser");
        assert_eq!(message.msg_id(), 1);
        assert_eq!(
            message.global_data().msg_max_size(),
            crate::UDP_RECEIVE_LIMITS.advertised()
        );
        let pdu = message.pdu().unwrap();
        assert_eq!(pdu.pdu_type(), PduType::Response);
        assert_eq!(pdu.request_id, ack.request_id());

        let other = processor_builder(&self::engine(b"other-receiver-engine", 7))
            .build()
            .unwrap();
        assert!(other.encode_inform_response(&ack).is_err());
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[test]
    fn oversized_inform_response_falls_back_to_too_big_then_suppressed() {
        let engine = engine(ENGINE_ID, 1);
        let ack = authenticated(processor(&engine).process(local_inform(1, 0), source()))
            .inform_ack()
            .unwrap();
        let InformResponse::Response(response) =
            processor(&engine).encode_inform_response(&ack).unwrap()
        else {
            panic!("expected a Response");
        };

        let processor = processor_builder(&engine)
            .max_message_size(response.len() - 1)
            .build()
            .unwrap();
        let InformResponse::TooBig(alternate) = processor.encode_inform_response(&ack).unwrap()
        else {
            panic!("expected the tooBig alternate");
        };
        assert!(alternate.len() < response.len());
        let (_, message) = decode_pdu(&alternate);
        let pdu = message.pdu().unwrap();
        assert_eq!(pdu.error_status(), crate::ErrorStatus::TooBig.as_i32());
        assert!(pdu.varbinds.is_empty());
        assert_eq!(engine.snmp_silent_drops(), 0);

        let processor = processor_builder(&engine)
            .max_message_size(1)
            .build()
            .unwrap();
        assert_eq!(
            processor.encode_inform_response(&ack).unwrap(),
            InformResponse::Suppressed
        );
        assert_eq!(engine.snmp_silent_drops(), 1);
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn des_inform_without_sender_state_fails_only_at_encode() {
        use crate::v3::{PersistedDesSaltState, PrivProtocol, UsmConfig};

        let engine = engine(ENGINE_ID, 1);
        let processor = NotificationProcessor::builder(engine)
            .usm_user("desuser", |user| {
                user.auth_priv(
                    AuthProtocol::Sha1,
                    b"auth-password",
                    PrivProtocol::Des,
                    b"priv-password",
                )
            })
            .unwrap()
            .build()
            .unwrap();

        let security = UsmConfig::new("desuser")
            .auth_priv(
                AuthProtocol::Sha1,
                b"auth-password",
                PrivProtocol::Des,
                b"priv-password",
            )
            .unwrap();
        let keys = security.derive_keys(ENGINE_ID).unwrap();
        let sender_des_state =
            DesSaltState::install(|_| Ok::<(), std::convert::Infallible>(())).unwrap();
        let pdu = Pdu::standard(
            crate::pdu::StandardPduType::InformRequest,
            1,
            0,
            0,
            vec![
                crate::VarBind::new(
                    super::super::oids::sys_uptime(),
                    crate::Value::TimeTicks(1000),
                ),
                crate::VarBind::new(
                    super::super::oids::snmp_trap_oid(),
                    crate::Value::ObjectIdentifier(super::super::oids::cold_start()),
                ),
            ],
        );
        let encoded = crate::v3::encode::encode_v3_message(
            &pdu,
            1,
            ENGINE_ID,
            1,
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

        let message = authenticated(processor.process(Bytes::from(encoded), source()));
        assert_eq!(message.security_level(), SecurityLevel::AuthPriv);
        let ack = message.inform_ack().unwrap();
        let error = processor.encode_inform_response(&ack).unwrap_err();
        assert!(matches!(*error, Error::Config(_)), "{error:?}");

        let mismatched = DesSaltState::restart(PersistedDesSaltState::new(4).unwrap(), |_| {
            Ok::<(), std::convert::Infallible>(())
        })
        .unwrap();
        assert!(processor.set_des_salt_state(Some(mismatched)).is_err());
        processor
            .set_des_salt_state(Some(
                DesSaltState::install(|_| Ok::<(), std::convert::Infallible>(())).unwrap(),
            ))
            .unwrap();
        assert!(matches!(
            processor.encode_inform_response(&ack).unwrap(),
            InformResponse::Response(_)
        ));
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[test]
    fn aes_auth_priv_inform_round_trip() {
        let processor = NotificationProcessor::builder(engine(ENGINE_ID, 1))
            .usm_user("informuser", |_| {
                Ok(inform_user(SecurityLevel::AuthPriv, b"informuser"))
            })
            .unwrap()
            .build()
            .unwrap();
        let (inform, request, _) = build_v3_inform_at_level(
            ENGINE_ID,
            b"informuser",
            SecurityLevel::AuthPriv,
            crate::UDP_RECEIVE_LIMITS.advertised(),
        );

        let message = authenticated(processor.process(inform, source()));
        assert_eq!(message.security_level(), SecurityLevel::AuthPriv);
        assert!(matches!(
            message.to_notification(NotificationVarbindValidation::Strict),
            Ok(Some(Notification::InformV3 { uptime: 1000, .. }))
        ));
        let InformResponse::Response(response) = processor
            .encode_inform_response(&message.inform_ack().unwrap())
            .unwrap()
        else {
            panic!("expected a Response");
        };

        // The Response is localized to this engine, so the processor can
        // authenticate and decrypt it again.
        let response = authenticated(processor.process(response, source()));
        assert_eq!(response.security_level(), SecurityLevel::AuthPriv);
        let pdu = &response.scoped_pdu().pdu;
        assert_eq!(pdu.pdu_type(), PduType::Response);
        assert_eq!(pdu.request_id, request.request_id);
        assert_eq!(pdu.varbinds, request.varbinds);
    }

    #[test]
    fn processor_is_send_sync_and_ack_is_owned() {
        fn assert_send_sync<T: Send + Sync + 'static>() {}
        assert_send_sync::<NotificationProcessor>();
        assert_send_sync::<NotificationEngine>();
        assert_send_sync::<InformAck>();
    }
}
