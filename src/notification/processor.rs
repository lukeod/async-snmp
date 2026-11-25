//! Complete-message notification processing without socket or task ownership.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use bytes::Bytes;

use super::varbind::extract_notification_varbinds;
use super::{
    Community, Notification, NotificationAdmissionDecision, NotificationAdmissionInfo,
    NotificationAdmissionPolicy, NotificationPduClass, NotificationVarbindValidation,
    NotificationWireIdentity, V3NotificationWireIdentity,
};
use crate::message::{CommunityMessage, CommunityPdu};
use crate::pdu::{Pdu, PduType, ResponsePdu};
use crate::response_finalizer::effective_limit;
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
/// an explicit admission policy before users can be installed at runtime.
pub struct NotificationProcessorBuilder {
    local_engine: Option<LocalEngine>,
    security_context: Option<UsmSecurityContext>,
    communities: Vec<Community>,
    varbind_validation: NotificationVarbindValidation,
    max_message_size: usize,
    decode_config: crate::DecodeConfig,
    admission_policy: Option<Arc<dyn NotificationAdmissionPolicy>>,
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
            admission_policy: None,
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

    /// Apply a fallible admission policy before Inform sizing and delivery.
    /// An error or panic discards the notification without an Inform Response.
    pub fn try_admission_policy(mut self, policy: impl NotificationAdmissionPolicy) -> Self {
        self.admission_policy = Some(Arc::new(policy));
        self
    }

    /// Apply an infallible synchronous admission policy.
    pub fn admission_policy(
        self,
        policy: impl Fn(&NotificationAdmissionInfo<'_>) -> NotificationAdmissionDecision
        + Send
        + Sync
        + 'static,
    ) -> Self {
        self.try_admission_policy(super::InfallibleAdmissionPolicy(policy))
    }

    /// Explicitly admit all validated notifications, including unauthenticated messages.
    pub fn admit_all_notifications(self) -> Self {
        self.try_admission_policy(super::AdmitAllNotifications)
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
            if self.admission_policy.is_none() {
                return Err(Error::Config(
                    "a USM notification processor requires an admission policy".into(),
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
            self.admission_policy,
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
    pub(super) admission_policy: Option<Arc<dyn NotificationAdmissionPolicy>>,
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
    /// Notification passed security, prefix validation and admission policy.
    Accepted(Box<ProcessedNotification>),
    /// An admitted Inform exceeded the effective response-size limit.
    /// Processing ends before delivery.
    InformTooBig {
        /// Encoded empty-varbind `tooBig` reply to send, or `None` for a
        /// counted silent drop.
        response: Option<Bytes>,
    },
    /// The input was filtered by notification processing or the admission policy.
    Rejected,
    /// Failed USM processing; the corresponding local counter was incremented.
    UsmFailed {
        /// Specific failed USM step.
        failure: UsmFailure,
        /// Encoded Report when the PDU type and effective size limit permit one.
        /// If the type is unknown, the reportable flag determines
        /// eligibility. Send the Report on the incoming route.
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

enum InformResponseSize {
    Fits,
    Oversized(Option<Bytes>),
}

impl std::fmt::Debug for InformResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InformResponse")
            .field("receive_info", &self.info)
            .finish_non_exhaustive()
    }
}

/// Result of encoding the response to an accepted Inform.
#[non_exhaustive]
pub enum EncodedInformResponse {
    /// The ordinary response fit.
    Response(Bytes),
    /// The ordinary response grew beyond the limit after admission and the
    /// empty-varbind `tooBig` alternate fit.
    TooBig(Bytes),
    /// Both responses exceeded the limit and the silent drop was counted.
    Suppressed,
}

impl EncodedInformResponse {
    /// Take the encoded reply, if one fit.
    pub fn into_bytes(self) -> Option<Bytes> {
        match self {
            Self::Response(bytes) | Self::TooBig(bytes) => Some(bytes),
            Self::Suppressed => None,
        }
    }
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
    fn limit(&self) -> usize {
        let peer_limit = match &self.request {
            InformRequest::Community { .. } => None,
            InformRequest::V3(inbound) => Some(inbound.global_data.msg_max_size.as_usize()),
        };
        effective_limit(self.max_message_size.min(self.limits.send()), peer_limit)
    }

    /// Encode the reply using captured request keys and current local engine
    /// state. This requires no socket, timer or runtime.
    /// If updated SNMPv3 boots or time push the ordinary response over the
    /// limit after admission, try the empty-varbind `tooBig` alternate.
    pub fn encode(self) -> Result<EncodedInformResponse> {
        match &self.request {
            InformRequest::Community { community, pdu } => self
                .encode_community(community, pdu.to_response(Version::V2c)?)
                .map(EncodedInformResponse::Response),
            InformRequest::V3(inbound) => {
                let usm = self.response_usm(inbound)?;
                let ordinary = inbound.scoped_pdu.pdu.to_response(Version::V3)?;
                match self.check_response_size(
                    Version::V3,
                    &ordinary,
                    |pdu| self.v3_response_size(inbound, pdu, &usm),
                    |pdu| self.encode_v3(inbound, pdu, usm.clone()),
                )? {
                    InformResponseSize::Fits => self
                        .encode_v3(inbound, ordinary, usm)
                        .map(EncodedInformResponse::Response),
                    InformResponseSize::Oversized(Some(bytes)) => {
                        Ok(EncodedInformResponse::TooBig(bytes))
                    }
                    InformResponseSize::Oversized(None) => Ok(EncodedInformResponse::Suppressed),
                }
            }
        }
    }

    fn preflight(&self) -> Result<InformResponseSize> {
        // RFC 3416 §4.2.7 sizes a Response with the Inform's original fields.
        // The ordinary acknowledgement uses zero status and index on the wire.
        match &self.request {
            InformRequest::Community { community, pdu } => self.check_response_size(
                Version::V2c,
                pdu,
                |pdu| {
                    use crate::ber::{integer_content_len, tlv_encoded_len};
                    Ok(tlv_encoded_len(
                        tlv_encoded_len(integer_content_len(Version::V2c.as_i32()))
                            + tlv_encoded_len(community.as_bytes().len())
                            + pdu.standard_encoded_size(),
                    ))
                },
                |pdu| self.encode_community(community, pdu),
            ),
            InformRequest::V3(inbound) => {
                let usm = self.response_usm(inbound)?;
                self.check_response_size(
                    Version::V3,
                    &inbound.scoped_pdu.pdu,
                    |pdu| self.v3_response_size(inbound, pdu, &usm),
                    |pdu| self.encode_v3(inbound, pdu, usm.clone()),
                )
            }
        }
    }

    fn check_response_size(
        &self,
        version: Version,
        candidate: &Pdu,
        encoded_size: impl Fn(&Pdu) -> Result<usize>,
        encode: impl FnOnce(Pdu) -> Result<Bytes>,
    ) -> Result<InformResponseSize> {
        let limit = self.limit();
        if encoded_size(candidate)? <= limit {
            return Ok(InformResponseSize::Fits);
        }
        let alternate =
            ResponsePdu::too_big(version, candidate.request_id(), Vec::new())?.into_raw();
        if encoded_size(&alternate)? <= limit {
            return Ok(InformResponseSize::Oversized(Some(encode(alternate)?)));
        }
        self.engine
            .inner
            .snmp_silent_drops
            .fetch_add(1, Ordering::Relaxed);
        Ok(InformResponseSize::Oversized(None))
    }

    fn encode_community(&self, community: &Community, pdu: Pdu) -> Result<Bytes> {
        let bytes = CommunityMessage::v2c(community.clone(), pdu)?.encode()?;
        crate::message_size::enforce_outbound_size(bytes.len(), self.limit())?;
        Ok(bytes)
    }

    fn response_usm(&self, inbound: &V3InboundMessage) -> Result<crate::v3::UsmSecurityParams> {
        let (boots, time) = self.engine.current_boots_time()?;
        if inbound.security_level.requires_auth() && boots == crate::v3::MAX_ENGINE_TIME {
            return Err(Error::Auth {
                target: self.info.peer_addr(),
            }
            .boxed());
        }
        crate::v3::UsmSecurityParams::new(
            self.engine.inner.engine_id.clone(),
            boots,
            time,
            inbound.usm_params.username.clone(),
        )
    }

    fn v3_response_size(
        &self,
        inbound: &V3InboundMessage,
        pdu: &Pdu,
        usm: &crate::v3::UsmSecurityParams,
    ) -> Result<usize> {
        crate::v3::encode::v3_response_encoded_size(
            pdu.standard_encoded_size(),
            &inbound.global_data,
            self.limits.receive().advertised(),
            usm,
            &inbound.scoped_pdu,
            &inbound.derived_keys,
            self.info.peer_addr(),
        )
    }

    fn encode_v3(
        &self,
        inbound: &V3InboundMessage,
        pdu: Pdu,
        usm: crate::v3::UsmSecurityParams,
    ) -> Result<Bytes> {
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
        let bytes = crate::v3::encode::encode_v3_response(
            pdu,
            inbound.global_data.msg_id,
            self.limits.receive().advertised(),
            inbound.security_level,
            usm,
            inbound.scoped_pdu.context_engine_id.clone(),
            inbound.scoped_pdu.context_name.clone(),
            Some(&inbound.derived_keys),
            self.engine.salt_counter().as_deref(),
            self.engine.des_salt_state().as_ref(),
            self.info.peer_addr(),
        )?;
        crate::message_size::enforce_outbound_size(bytes.len(), self.limit())?;
        Ok(bytes)
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
        admission_policy: Option<Arc<dyn NotificationAdmissionPolicy>>,
    ) -> Self {
        Self {
            inner: Arc::new(ProcessorInner {
                local_engine,
                security_context,
                communities,
                varbind_validation,
                max_message_size,
                decode_config,
                admission_policy,
            }),
        }
    }

    /// Shared local authoritative state and protocol counters.
    pub fn local_engine(&self) -> LocalEngine {
        self.inner.local_engine.clone()
    }

    /// Process one complete message after selecting this logical listener.
    ///
    /// This also handles SNMPv3 engine discovery and stale Inform engine IDs.
    /// Send Reports and `tooBig` replies from the result on the incoming route.
    /// An accepted Inform carries an [`InformResponse`] for deferred encoding.
    pub fn process(&self, input: ProcessingInput) -> Result<NotificationProcessResult> {
        let result = self.process_inner(input);
        self.inner.local_engine.count_asn_parse_error(&result);
        result
    }

    fn admit_notification(
        &self,
        notification: Notification,
        info: crate::ReceivedMessageInfo,
        identity: NotificationWireIdentity,
        response: Option<InformResponse>,
    ) -> Result<NotificationProcessResult> {
        if let Some(policy) = &self.inner.admission_policy {
            let pdu_class = if response.is_some() {
                NotificationPduClass::Inform
            } else {
                NotificationPduClass::Trap
            };
            let admission =
                NotificationAdmissionInfo::new(info, &notification, &identity, pdu_class);
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                policy.evaluate(&admission)
            })) {
                Ok(Ok(NotificationAdmissionDecision::Admit)) => {}
                Ok(Ok(NotificationAdmissionDecision::Reject)) => {
                    return Ok(NotificationProcessResult::Rejected);
                }
                Ok(Err(error)) => {
                    tracing::error!(target: "async_snmp::notification", source = %info.peer_addr(), %error, "notification admission policy failed; rejected notification");
                    return Ok(NotificationProcessResult::Rejected);
                }
                Err(_) => {
                    tracing::error!(target: "async_snmp::notification", source = %info.peer_addr(), "notification admission policy panicked; rejected notification");
                    return Ok(NotificationProcessResult::Rejected);
                }
            }
        }
        if let Some(inform) = &response
            && let InformResponseSize::Oversized(response) = inform.preflight()?
        {
            return Ok(NotificationProcessResult::InformTooBig { response });
        }
        Ok(NotificationProcessResult::Accepted(Box::new(
            ProcessedNotification {
                notification,
                receive_info: info,
                wire_identity: identity,
                inform_response: response,
            },
        )))
    }

    fn process_inner(&self, input: ProcessingInput) -> Result<NotificationProcessResult> {
        let version =
            crate::message::peek_version(input.bytes().clone(), input.info().peer_addr())?;
        if version == Version::V3 {
            let info = input.info();
            let limits = input.limits();
            return match self.v3_inbound(input)? {
                V3Inbound::Failed { failure, report } => {
                    Ok(NotificationProcessResult::UsmFailed { failure, report })
                }
                V3Inbound::RemoteNotInTimeWindow => {
                    Ok(NotificationProcessResult::RemoteNotInTimeWindow)
                }
                V3Inbound::Ignored => Ok(NotificationProcessResult::Rejected),
                V3Inbound::Message(inbound) => {
                    let scoped = &inbound.scoped_pdu;
                    let pdu = &scoped.pdu;
                    if !matches!(pdu.pdu_type(), PduType::TrapV2 | PduType::InformRequest)
                        || (pdu.pdu_type() == PduType::InformRequest
                            && inbound.usm_params.engine_id.as_ref()
                                != self.inner.local_engine.engine_id())
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
                    self.admit_notification(notification, info, identity, response)
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
            CommunityPdu::TrapV1(trap) => self.admit_notification(
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
            ),
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
                self.admit_notification(
                    notification,
                    info,
                    NotificationWireIdentity {
                        version: Version::V2c,
                        request_id: Some(request_id),
                        v3: None,
                    },
                    response,
                )
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

    fn v3_inbound(&self, input: ProcessingInput) -> Result<V3Inbound> {
        let (packet, limits) = input.into_parts();
        let (data, info, prepared) = packet.into_prepared();
        let users = self
            .inner
            .security_context
            .users_for_input(&data, prepared.as_deref())?;
        let engine = &self.inner.local_engine;
        let state = &engine.inner;
        let (boots, time) = crate::v3::local::unpack_boots_time(
            state.authoritative_snapshot.load(Ordering::Relaxed),
        );
        let clock = || engine.current_boots_time();
        let context = V3LocalContext {
            engine_id: &state.engine_id,
            engine_boots: boots,
            engine_time: time,
            authoritative_time: Some(&clock),
            local_receive_capacity: limits.receive().advertised(),
            accepted_receive_size: limits.receive().accepted(),
            decode_config: self.inner.decode_config,
            outbound_limit: self.inner.max_message_size.min(limits.send()),
            usm_users: Some(users),
            stats: &state.usm_stats,
            mpd: Some(MpdCounters {
                invalid_msgs: &state.snmp_invalid_msgs,
                unknown_security_models: &state.snmp_unknown_security_models,
            }),
            source: info.peer_addr(),
        };
        let role = V3Role::Receiver {
            remote_engines: self.inner.security_context.remote_engines(),
        };
        process_prepared_v3_inbound(data, &context, &role, prepared)
    }
}
