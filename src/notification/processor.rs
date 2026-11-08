//! Complete-message notification processing without socket or task ownership.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use bytes::Bytes;

use super::varbind::extract_notification_varbinds;
use super::{
    Community, Notification, NotificationAcceptance, NotificationAcceptancePolicy,
    NotificationEnvelope, NotificationVarbindValidation, NotificationWireIdentity,
    V3NotificationWireIdentity,
};
use crate::message::{CommunityMessage, CommunityPdu};
use crate::pdu::{Pdu, PduType};
use crate::response_finalizer::{FinalizedResponse, finalize_response};
use crate::v3::process::{
    MpdCounters, UsmFailure, V3Inbound, V3InboundMessage, V3LocalContext, V3Role,
    process_prepared_v3_inbound,
};
use crate::{
    Error, LocalEngine, ProcessingInput, ProcessingLimits, Result, UsmSecurityContext, Version,
};

/// Configuration for a socketless [`NotificationProcessor`].
///
/// Building creates no sockets or background tasks. An explicitly configured
/// USM context, including an empty one, requires a persisted local engine and
/// an explicit acceptance policy before users can be installed at runtime.
pub struct NotificationProcessorBuilder {
    local_engine: Option<LocalEngine>,
    security_context: Option<UsmSecurityContext>,
    communities: Vec<Community>,
    varbind_validation: NotificationVarbindValidation,
    max_message_size: usize,
    decode_config: crate::DecodeConfig,
    acceptance_policy: Option<Arc<dyn NotificationAcceptancePolicy>>,
}

impl Default for NotificationProcessorBuilder {
    fn default() -> Self {
        Self {
            local_engine: None,
            security_context: None,
            communities: Vec::new(),
            varbind_validation: NotificationVarbindValidation::Tolerant,
            max_message_size: crate::MESSAGE_SIZE_MAXIMUM,
            decode_config: crate::DecodeConfig::DEFAULT,
            acceptance_policy: None,
        }
    }
}

impl NotificationProcessorBuilder {
    /// Use local identity, authoritative time, counters and sender state shared
    /// with other notification processors, clients or command responders.
    pub fn local_engine(mut self, engine: LocalEngine) -> Self {
        self.local_engine = Some(engine);
        self
    }

    /// Select credentials and remote-engine timeliness for this processor.
    /// Selection occurs before processing; security failure never tries another context.
    pub fn security_context(mut self, context: UsmSecurityContext) -> Self {
        self.security_context = Some(context);
        self
    }

    /// Accept this cleartext community for v1/v2c notifications. With no entries,
    /// any community is accepted; a matching community is not authentication.
    pub fn community(mut self, community: impl Into<Community>) -> Self {
        self.communities.push(community.into());
        self
    }

    /// Select notification-prefix validation (default: tolerant).
    pub fn varbind_validation(mut self, validation: NotificationVarbindValidation) -> Self {
        self.varbind_validation = validation;
        self
    }

    /// Bound encoded Responses and Reports independently of input limits.
    /// The default applies only the supplied endpoint and peer limits.
    pub fn max_message_size(mut self, size: usize) -> Self {
        self.max_message_size = size;
        self
    }

    /// Select bounded message-decoding compatibility.
    pub fn decode_config(mut self, config: crate::DecodeConfig) -> Self {
        self.decode_config = config;
        self
    }

    /// Apply a synchronous policy before accepting a notification. An error or
    /// panic rejects it without producing an Inform response capability.
    pub fn try_acceptance_policy(mut self, policy: impl NotificationAcceptancePolicy) -> Self {
        self.acceptance_policy = Some(Arc::new(policy));
        self
    }

    /// Apply an infallible synchronous acceptance policy.
    pub fn acceptance_policy(
        self,
        policy: impl Fn(&NotificationEnvelope<'_>) -> NotificationAcceptance + Send + Sync + 'static,
    ) -> Self {
        self.try_acceptance_policy(super::InfallibleAcceptancePolicy(policy))
    }

    /// Explicitly accept all notifications, including unauthenticated messages.
    pub fn accept_all_notifications(self) -> Self {
        self.try_acceptance_policy(super::AcceptAllNotifications)
    }

    /// Validate configuration and prepare protocol state without I/O or tasks.
    /// Community-only processors can omit local state; an ephemeral identity is
    /// generated for protocol Reports. Durable DES state is needed at response
    /// encoding, not merely to accept or authenticate a DES notification.
    pub fn build(self) -> Result<NotificationProcessor> {
        if self.max_message_size > crate::MESSAGE_SIZE_MAXIMUM {
            return Err(
                Error::Config("max_message_size exceeds the SNMP size range".into()).boxed(),
            );
        }
        if self.security_context.is_some() {
            if self.acceptance_policy.is_none() {
                return Err(Error::Config(
                    "a USM notification processor requires an acceptance policy".into(),
                )
                .boxed());
            }
            if self
                .local_engine
                .as_ref()
                .and_then(LocalEngine::authoritative_engine)
                .is_none()
            {
                return Err(Error::Config(
                    "persisted local engine state is required for SNMPv3 notification processing"
                        .into(),
                )
                .boxed());
            }
        }
        let local_engine = match self.local_engine {
            Some(engine) => engine,
            None => {
                LocalEngine::from_prepared(None, crate::v3::generate_engine_id()?, 1, None, None)
            }
        };
        Ok(NotificationProcessor::configured(
            local_engine,
            self.security_context.unwrap_or_default(),
            self.communities,
            self.varbind_validation,
            self.max_message_size,
            self.decode_config,
            self.acceptance_policy,
        ))
    }
}

/// Socketless SNMPv1/v2c/v3 notification processing.
///
/// Supply complete datagrams or framed stream messages with [`ProcessingInput`].
/// This processor owns protocol configuration, not a socket, runner or delivery
/// queue. A successful Inform carries an owned response capability: encode it
/// only after application acceptance/persistence, then send the bytes through
/// the caller-owned transport. Dropping the capability does not acknowledge.
/// Managed [`super::NotificationReceiver`] services use the same machinery.
#[derive(Clone)]
pub struct NotificationProcessor {
    pub(super) inner: Arc<ProcessorInner>,
}

pub(super) struct ProcessorInner {
    pub(super) local_engine: LocalEngine,
    pub(super) security_context: UsmSecurityContext,
    pub(super) communities: Vec<Community>,
    pub(super) varbind_validation: NotificationVarbindValidation,
    pub(super) max_message_size: usize,
    pub(super) decode_config: crate::DecodeConfig,
    pub(super) acceptance_policy: Option<Arc<dyn NotificationAcceptancePolicy>>,
}

impl std::ops::Deref for ProcessorInner {
    type Target = crate::v3::local::LocalEngineInner;
    fn deref(&self) -> &Self::Target {
        &self.local_engine.inner
    }
}

impl std::fmt::Debug for NotificationProcessor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotificationProcessor")
            .field("local_engine", &self.inner.local_engine)
            .field("security_context", &self.inner.security_context)
            .finish_non_exhaustive()
    }
}

/// Protocol outcome for one complete input. Security failures retain any Report
/// bytes alongside their indication; callers decide whether to send them.
#[derive(Debug)]
#[non_exhaustive]
pub enum NotificationProcessResult {
    /// Notification passed security, prefix validation and acceptance policy.
    Accepted(Box<ProcessedNotification>),
    /// Not a notification, or filtered/rejected by application policy.
    Rejected,
    /// Failed USM processing; the corresponding local counter was incremented.
    UsmFailed {
        /// Specific failed USM step.
        failure: UsmFailure,
        /// Report permitted by the message flags and effective size limit.
        report: Option<Bytes>,
    },
    /// Remote-authoritative timeliness failure; no counter or Report is emitted.
    RemoteNotInTimeWindow,
}

/// One accepted notification and its original complete-message metadata.
#[derive(Debug)]
pub struct ProcessedNotification {
    /// Accepted notification content. Authentication depends on version/level.
    pub notification: Notification,
    /// Original metadata, without an authenticated transport identity claim.
    pub receive_info: crate::ReceivedMessageInfo,
    /// Original version and wire transaction/security identity.
    pub wire_identity: NotificationWireIdentity,
    /// Present for an Inform; absent for a trap. No response has been encoded.
    pub inform_response: Option<InformResponse>,
}

/// An owned, validated Inform response capability.
///
/// Its request, selected credential keys, local engine and transport limits are
/// private and cannot be forged or retargeted. Credential replacement affects
/// later inputs; this capability retains the keys that validated its request.
/// Encoding samples current authoritative time and current DES sender state.
/// Completion consumes the capability. Dropping it sends/encodes nothing;
/// retransmissions can produce independent capabilities and are not deduplicated.
#[must_use = "encode after application acceptance, or drop without acknowledging"]
pub struct InformResponse {
    engine: LocalEngine,
    limits: ProcessingLimits,
    max_message_size: usize,
    info: crate::ReceivedMessageInfo,
    request: InformRequest,
}

enum InformRequest {
    Community { community: Community, pdu: Pdu },
    V3(Box<V3InboundMessage>),
}

impl std::fmt::Debug for InformResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InformResponse")
            .field("receive_info", &self.info)
            .finish_non_exhaustive()
    }
}

/// Exact Inform response encoding result. Encoded bytes have not been sent.
pub enum EncodedInformResponse {
    /// The ordinary Response fit.
    Response(Bytes),
    /// The exact empty-varbind `tooBig` alternate fit.
    TooBig(Bytes),
    /// Neither encoding fit; the engine's silent-drop counter was incremented.
    Suppressed,
}

impl std::fmt::Debug for EncodedInformResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Response(bytes) => f.debug_tuple("Response").field(&bytes.len()).finish(),
            Self::TooBig(bytes) => f.debug_tuple("TooBig").field(&bytes.len()).finish(),
            Self::Suppressed => f.write_str("Suppressed"),
        }
    }
}

impl InformResponse {
    /// Encode now, using captured request keys and current local engine state.
    /// No socket, timer or runtime is required. DES absence/rollover, persistence
    /// failure and encoding failures are returned without sending anything.
    pub fn encode(self) -> Result<EncodedInformResponse> {
        let local_limit = self.max_message_size.min(self.limits.send());
        let finalized = match self.request {
            InformRequest::Community { community, pdu } => finalize_response(
                Version::V2c,
                &pdu,
                pdu.to_response(Version::V2c)?,
                local_limit,
                None,
                &self.engine.inner.snmp_silent_drops,
                |response| CommunityMessage::v2c(community.clone(), response)?.encode(),
            )?,
            InformRequest::V3(inbound) => {
                let (boots, time) = self.engine.current_boots_time()?;
                if inbound.security_level.requires_auth() && boots == crate::v3::MAX_ENGINE_TIME {
                    return Err(Error::Auth {
                        target: self.info.peer_addr(),
                    }
                    .boxed());
                }
                if inbound.security_level.requires_priv()
                    && inbound
                        .derived_keys
                        .priv_key
                        .as_ref()
                        .is_some_and(|key| !key.protocol().is_des_family())
                {
                    self.engine
                        .ensure_salt_counter(crate::v3::SaltCounter::new)?;
                }
                let usm = crate::v3::UsmSecurityParams::new(
                    self.engine.inner.engine_id.clone(),
                    boots,
                    time,
                    inbound.usm_params.username.clone(),
                )?;
                let salts = self.engine.salt_counter();
                let des = self.engine.des_salt_state();
                let pdu = &inbound.scoped_pdu.pdu;
                finalize_response(
                    Version::V3,
                    pdu,
                    pdu.to_response(Version::V3)?,
                    local_limit,
                    Some(inbound.global_data.msg_max_size.as_usize()),
                    &self.engine.inner.snmp_silent_drops,
                    |response| {
                        crate::v3::encode::encode_v3_response(
                            response,
                            inbound.global_data.msg_id,
                            self.limits.receive().advertised(),
                            inbound.security_level,
                            usm.clone(),
                            inbound.scoped_pdu.context_engine_id.clone(),
                            inbound.scoped_pdu.context_name.clone(),
                            Some(&inbound.derived_keys),
                            salts.as_deref(),
                            des.as_ref(),
                            self.info.peer_addr(),
                        )
                    },
                )?
            }
        };
        Ok(match finalized {
            FinalizedResponse::Candidate(bytes) => EncodedInformResponse::Response(bytes),
            FinalizedResponse::Alternate(bytes) => EncodedInformResponse::TooBig(bytes),
            FinalizedResponse::Dropped => EncodedInformResponse::Suppressed,
        })
    }
}

impl NotificationProcessor {
    /// Configure processing independently of network preparation or execution.
    pub fn builder() -> NotificationProcessorBuilder {
        NotificationProcessorBuilder::default()
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn configured(
        local_engine: LocalEngine,
        security_context: UsmSecurityContext,
        communities: Vec<Community>,
        varbind_validation: NotificationVarbindValidation,
        max_message_size: usize,
        decode_config: crate::DecodeConfig,
        acceptance_policy: Option<Arc<dyn NotificationAcceptancePolicy>>,
    ) -> Self {
        Self {
            inner: Arc::new(ProcessorInner {
                local_engine,
                security_context,
                communities,
                varbind_validation,
                max_message_size,
                decode_config,
                acceptance_policy,
            }),
        }
    }

    /// Shared local authoritative state and protocol counters.
    pub fn local_engine(&self) -> LocalEngine {
        self.inner.local_engine.clone()
    }

    /// Process one complete message without encoding an Inform response or
    /// performing transport I/O. Reports are protocol results and may already
    /// be encoded independently of application persistence/acknowledgement.
    pub fn process(&self, input: ProcessingInput) -> Result<NotificationProcessResult> {
        self.process_admitted(input, &mut || true)
    }

    pub(super) fn process_admitted(
        &self,
        input: ProcessingInput,
        reserve: &mut impl FnMut() -> bool,
    ) -> Result<NotificationProcessResult> {
        let result = self.process_inner(input, reserve);
        self.observe_error(&result);
        result
    }

    fn observe_error<T>(&self, result: &Result<T>) {
        if matches!(result, Err(error) if matches!(&**error,
            Error::Decode(error) if !matches!(error.kind, crate::DecodeErrorKind::UnknownVersion(_)
                | crate::DecodeErrorKind::InvalidMsgFlags | crate::DecodeErrorKind::UnknownSecurityModel(_))))
        {
            self.inner
                .snmp_in_asn_parse_errs
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    fn accepted(
        &self,
        notification: Notification,
        info: crate::ReceivedMessageInfo,
        identity: NotificationWireIdentity,
        response: Option<InformResponse>,
        reserve: &mut impl FnMut() -> bool,
    ) -> NotificationProcessResult {
        if !reserve() {
            return NotificationProcessResult::Rejected;
        }
        if let Some(policy) = &self.inner.acceptance_policy {
            let envelope = NotificationEnvelope::new(info, &notification);
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                policy.evaluate(&envelope)
            })) {
                Ok(Ok(NotificationAcceptance::Accept)) => {}
                Ok(Ok(NotificationAcceptance::Reject)) => {
                    return NotificationProcessResult::Rejected;
                }
                Ok(Err(error)) => {
                    tracing::error!(target: "async_snmp::notification", source = %info.peer_addr(), %error, "notification acceptance policy failed; rejected notification");
                    return NotificationProcessResult::Rejected;
                }
                Err(_) => {
                    tracing::error!(target: "async_snmp::notification", source = %info.peer_addr(), "notification acceptance policy panicked; rejected notification");
                    return NotificationProcessResult::Rejected;
                }
            }
        }
        NotificationProcessResult::Accepted(Box::new(ProcessedNotification {
            notification,
            receive_info: info,
            wire_identity: identity,
            inform_response: response,
        }))
    }

    fn process_inner(
        &self,
        input: ProcessingInput,
        reserve: &mut impl FnMut() -> bool,
    ) -> Result<NotificationProcessResult> {
        let version =
            crate::message::peek_version(input.bytes().clone(), input.info().peer_addr())?;
        if version == Version::V3 {
            let info = input.info();
            let limits = input.limits();
            return match self
                .v3_inbound(input, false)?
                .expect("receiver processes every input")
            {
                V3Inbound::Failed { failure, report } => {
                    Ok(NotificationProcessResult::UsmFailed { failure, report })
                }
                V3Inbound::RemoteNotInTimeWindow => {
                    Ok(NotificationProcessResult::RemoteNotInTimeWindow)
                }
                V3Inbound::Message(inbound) => {
                    let scoped = &inbound.scoped_pdu;
                    let pdu = &scoped.pdu;
                    if !matches!(pdu.pdu_type(), PduType::TrapV2 | PduType::InformRequest)
                        || (pdu.pdu_type() == PduType::InformRequest
                            && inbound.usm_params.engine_id != self.inner.engine_id)
                    {
                        return Ok(NotificationProcessResult::Rejected);
                    }
                    let (uptime, trap_oid, varbinds) =
                        extract_notification_varbinds(pdu, self.inner.varbind_validation)?;
                    let identity = NotificationWireIdentity {
                        version,
                        request_id: Some(pdu.request_id),
                        v3: Some(V3NotificationWireIdentity {
                            msg_id: inbound.global_data.msg_id,
                            authoritative_engine_id: inbound.usm_params.engine_id.clone(),
                            username: inbound.usm_params.username.clone(),
                            security_level: inbound.security_level,
                        }),
                    };
                    let inform = pdu.pdu_type() == PduType::InformRequest;
                    let notification = if inform {
                        Notification::InformV3 {
                            username: inbound.usm_params.username.clone(),
                            context_engine_id: scoped.context_engine_id.clone(),
                            context_name: scoped.context_name.clone(),
                            security_level: inbound.security_level,
                            uptime,
                            trap_oid,
                            varbinds,
                            request_id: pdu.request_id,
                            decode_anomalies: inbound.decode_anomalies.clone(),
                        }
                    } else {
                        Notification::TrapV3 {
                            username: inbound.usm_params.username.clone(),
                            context_engine_id: scoped.context_engine_id.clone(),
                            context_name: scoped.context_name.clone(),
                            security_level: inbound.security_level,
                            uptime,
                            trap_oid,
                            varbinds,
                            request_id: pdu.request_id,
                            decode_anomalies: inbound.decode_anomalies.clone(),
                        }
                    };
                    let response =
                        inform.then(|| self.response(info, limits, InformRequest::V3(inbound)));
                    Ok(self.accepted(notification, info, identity, response, reserve))
                }
            };
        }
        let info = input.info();
        let limits = input.limits();
        let decoded = CommunityMessage::decode_with_target(
            input.into_parts().0.into_parts().0,
            Some(info.peer_addr()),
            self.inner.decode_config,
        )?;
        let anomalies = decoded.anomalies;
        let (version, community, pdu) = decoded.value.into_parts();
        if !crate::util::community_matches(
            &self.inner.communities,
            community.as_bytes(),
            crate::util::EmptyCommunityPolicy::Allow,
        ) {
            return Ok(NotificationProcessResult::Rejected);
        }
        match pdu {
            CommunityPdu::TrapV1(trap) => Ok(self.accepted(
                Notification::TrapV1 {
                    community,
                    trap,
                    decode_anomalies: anomalies,
                },
                info,
                NotificationWireIdentity {
                    version: Version::V1,
                    request_id: None,
                    v3: None,
                },
                None,
                reserve,
            )),
            CommunityPdu::Standard(pdu) if version == Version::V2c => {
                if !matches!(pdu.pdu_type(), PduType::TrapV2 | PduType::InformRequest) {
                    return Ok(NotificationProcessResult::Rejected);
                }
                let (uptime, trap_oid, varbinds) =
                    extract_notification_varbinds(&pdu, self.inner.varbind_validation)?;
                let request_id = pdu.request_id;
                let inform = pdu.pdu_type() == PduType::InformRequest;
                let notification = if inform {
                    Notification::InformV2c {
                        community: community.clone(),
                        uptime,
                        trap_oid,
                        varbinds,
                        request_id,
                        decode_anomalies: anomalies,
                    }
                } else {
                    Notification::TrapV2c {
                        community: community.clone(),
                        uptime,
                        trap_oid,
                        varbinds,
                        request_id,
                        decode_anomalies: anomalies,
                    }
                };
                let response = inform.then(|| {
                    self.response(info, limits, InformRequest::Community { community, pdu })
                });
                Ok(self.accepted(
                    notification,
                    info,
                    NotificationWireIdentity {
                        version: Version::V2c,
                        request_id: Some(request_id),
                        v3: None,
                    },
                    response,
                    reserve,
                ))
            }
            _ => Ok(NotificationProcessResult::Rejected),
        }
    }

    fn response(
        &self,
        info: crate::ReceivedMessageInfo,
        limits: ProcessingLimits,
        request: InformRequest,
    ) -> InformResponse {
        InformResponse {
            engine: self.inner.local_engine.clone(),
            info,
            limits,
            max_message_size: self.inner.max_message_size,
            request,
        }
    }

    /// Report an unclaimed v3 datagram/frame as this local authoritative engine.
    /// Empty, invalid or foreign engine IDs use common authoritative processing.
    /// A message naming this local engine returns `None` without user lookup,
    /// application acceptance, timeliness updates or unknown-user accounting.
    pub fn report_unknown_engine(&self, input: ProcessingInput) -> Result<Option<Bytes>> {
        let result = self.v3_inbound(input, true).map(|inbound| match inbound {
            Some(V3Inbound::Failed { report, .. }) => report,
            _ => None,
        });
        self.observe_error(&result);
        result
    }

    fn v3_inbound(&self, input: ProcessingInput, unclaimed: bool) -> Result<Option<V3Inbound>> {
        let (packet, limits) = input.into_parts();
        let (data, info, prepared) = packet.into_prepared();
        let users = self
            .inner
            .security_context
            .users_for_input(&data, prepared.as_deref())?;
        let (boots, time) = crate::v3::local::unpack_boots_time(
            self.inner.authoritative_snapshot.load(Ordering::Relaxed),
        );
        let clock = || self.inner.local_engine.current_boots_time();
        let context = V3LocalContext {
            engine_id: &self.inner.engine_id,
            engine_boots: boots,
            engine_time: time,
            authoritative_time: Some(&clock),
            local_receive_capacity: limits.receive().advertised(),
            accepted_receive_size: limits.receive().accepted(),
            decode_config: self.inner.decode_config,
            outbound_limit: self.inner.max_message_size.min(limits.send()),
            usm_users: users,
            stats: &self.inner.usm_stats,
            mpd: Some(MpdCounters {
                invalid_msgs: &self.inner.snmp_invalid_msgs,
                unknown_security_models: &self.inner.snmp_unknown_security_models,
            }),
            source: info.peer_addr(),
        };
        let role = if unclaimed {
            V3Role::Authoritative
        } else {
            V3Role::Receiver {
                remote_engines: self.inner.security_context.remote_engines(),
            }
        };
        let prepared = if unclaimed {
            let peeked = (|| {
                let mut prepared = prepared.unwrap_or_else(|| {
                    Box::new(crate::v3::prepared::PreparedV3::selected(
                        data.clone(),
                        self.inner.decode_config,
                        context.usm_users.clone(),
                    ))
                });
                let raw = prepared.decode_raw(
                    data.clone(),
                    limits.receive().accepted(),
                    info.peer_addr(),
                    self.inner.decode_config,
                )?;
                let usm =
                    prepared.decode_usm(&raw.value, info.peer_addr(), self.inner.decode_config)?;
                if usm.value.engine_id == self.inner.engine_id {
                    return Ok(None);
                }
                let mut selected = crate::v3::prepared::PreparedV3::selected(
                    data.clone(),
                    self.inner.decode_config,
                    context.usm_users.clone(),
                );
                selected.raw = Some(raw);
                selected.usm = Some(usm);
                Ok::<_, Box<Error>>(Some(Box::new(selected)))
            })();
            match peeked {
                Ok(Some(prepared)) => Some(prepared),
                Ok(None) => return Ok(None),
                // Let the common core account for invalid flags/security models
                // and return its ordinary decode indication exactly once.
                Err(_) => {
                    return process_prepared_v3_inbound(data, &context, &role, None).map(Some);
                }
            }
        } else {
            prepared
        };
        process_prepared_v3_inbound(data, &context, &role, prepared).map(Some)
    }
}
