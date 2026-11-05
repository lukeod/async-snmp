//! Protocol version-specific notification handlers.
//!
//! This module contains the internal handlers for processing `SNMPv1`, v2c, and v3
//! notification messages.

use std::net::SocketAddr;
use std::sync::atomic::AtomicU32;

use bytes::Bytes;

use crate::udp_responder::DestinationMetadata;

use crate::error::{Error, Result};
use crate::message::{CommunityMessage, ScopedPdu, SecurityLevel};
use crate::pdu::{Pdu, PduType};
use crate::response_finalizer::FinalizedResponse;
use crate::v3::encode::encode_v3_response;
use crate::v3::process::{UsmFailure, V3Inbound, V3LocalContext, V3Role, process_v3_inbound};
use crate::v3::{DesSaltState, SaltCounter, UsmSecurityParams};

use super::processor::{InformAck, V3InboundNotification};
use super::varbind::extract_notification_varbinds;
use super::{
    InformAckOutcome, Notification, NotificationPduClass, NotificationVarbindValidation,
    NotificationWireIdentity, ReceivedNotification,
};

impl super::NotificationReceiver {
    /// Handle `SNMPv1` message.
    pub(super) async fn handle_v1(
        &self,
        data: Bytes,
        source: SocketAddr,
    ) -> Result<Option<ReceivedNotification>> {
        let decoded =
            CommunityMessage::decode_with_target(data, Some(source), self.inner.decode_config)?;
        let decode_anomalies = decoded.anomalies;
        let msg = decoded.value;

        if !crate::util::community_matches(
            &self.inner.communities,
            msg.community().as_bytes(),
            crate::util::EmptyCommunityPolicy::Allow,
        ) {
            tracing::debug!(target: "async_snmp::notification", { snmp.source = %source }, "dropped v1 notification with unaccepted community");
            return Ok(None);
        }

        let (_, community, pdu) = msg.into_parts();
        match pdu {
            crate::message::CommunityPdu::TrapV1(trap) => {
                let notification = Notification::TrapV1 {
                    community,
                    trap,
                    decode_anomalies,
                };
                if !self.inner.accepts(source, &notification) {
                    tracing::debug!(target: "async_snmp::notification", { snmp.source = %source }, "notification acceptance policy dropped v1 trap");
                    return Ok(None);
                }
                Ok(Some(ReceivedNotification::trap(
                    notification,
                    source,
                    NotificationWireIdentity {
                        version: crate::Version::V1,
                        request_id: None,
                        v3: None,
                    },
                )))
            }
            crate::message::CommunityPdu::Standard(_) => Ok(None),
        }
    }

    /// Handle `SNMPv2c` message.
    #[cfg(test)]
    pub(super) async fn handle_v2c(
        &self,
        data: Bytes,
        source: SocketAddr,
    ) -> Result<Option<ReceivedNotification>> {
        self.handle_v2c_at(data, source, None).await
    }

    pub(super) async fn handle_v2c_at(
        &self,
        data: Bytes,
        source: SocketAddr,
        response_source: Option<DestinationMetadata>,
    ) -> Result<Option<ReceivedNotification>> {
        let decoded =
            CommunityMessage::decode_with_target(data, Some(source), self.inner.decode_config)?;
        let decode_anomalies = decoded.anomalies;
        let msg = decoded.value;

        if !crate::util::community_matches(
            &self.inner.communities,
            msg.community().as_bytes(),
            crate::util::EmptyCommunityPolicy::Allow,
        ) {
            tracing::debug!(target: "async_snmp::notification", { snmp.source = %source }, "dropped v2c notification with unaccepted community");
            return Ok(None);
        }

        // V2c messages carry standard PDUs; TrapV1 is only valid in V1 messages.
        let Some(pdu) = msg.pdu().standard() else {
            return Ok(None);
        };

        match pdu.pdu_type() {
            PduType::TrapV2 => {
                let (uptime, trap_oid, varbinds) =
                    extract_notification_varbinds(pdu, self.inner.varbind_validation)?;
                let notification = Notification::TrapV2c {
                    community: msg.community().clone(),
                    uptime,
                    trap_oid,
                    varbinds,
                    request_id: pdu.request_id,
                    decode_anomalies,
                };
                if !self.inner.accepts(source, &notification) {
                    tracing::debug!(target: "async_snmp::notification", { snmp.source = %source }, "notification acceptance policy dropped v2c trap");
                    return Ok(None);
                }
                Ok(Some(ReceivedNotification::trap(
                    notification,
                    source,
                    NotificationWireIdentity {
                        version: crate::Version::V2c,
                        request_id: Some(pdu.request_id),
                        v3: None,
                    },
                )))
            }
            PduType::InformRequest => {
                let (uptime, trap_oid, varbinds) =
                    extract_notification_varbinds(pdu, self.inner.varbind_validation)?;
                let request_id = pdu.request_id;
                let notification = Notification::InformV2c {
                    community: msg.community().clone(),
                    uptime,
                    trap_oid,
                    varbinds,
                    request_id,
                    decode_anomalies,
                };
                if !self.inner.accepts(source, &notification) {
                    tracing::debug!(target: "async_snmp::notification", { snmp.source = %source }, "notification acceptance policy dropped v2c Inform");
                    return Ok(None);
                }

                #[cfg(test)]
                let injected_error = self
                    .inner
                    .response_construction_errors
                    .lock()
                    .unwrap()
                    .pop_front();
                #[cfg(not(test))]
                let injected_error: Option<Box<Error>> = None;
                let finalized = if let Some(error) = injected_error {
                    Err(error)
                } else {
                    pdu.to_response(crate::Version::V2c).and_then(|response| {
                        crate::response_finalizer::finalize_response(
                            crate::Version::V2c,
                            pdu,
                            response,
                            self.inner.max_message_size,
                            None,
                            &self.inner.snmp_silent_drops,
                            |response| {
                                CommunityMessage::v2c(msg.community().clone(), response)?.encode()
                            },
                        )
                    })
                };
                let outcome = match finalized {
                    Ok(crate::response_finalizer::FinalizedResponse::Dropped) => {
                        tracing::debug!(target: "async_snmp::notification", { snmp.source = %source, snmp.request_id = request_id }, "Inform response and tooBig alternate exceed max message size");
                        InformAckOutcome::SuppressedBySize
                    }
                    Ok(finalized) => {
                        let response_bytes = finalized
                            .into_bytes()
                            .expect("non-dropped response contains bytes");
                        match self
                            .send_response(&response_bytes, source, response_source)
                            .await
                        {
                            Ok(()) => {
                                tracing::debug!(target: "async_snmp::notification", { snmp.source = %source, snmp.request_id = request_id }, "sent Inform response");
                                InformAckOutcome::Sent
                            }
                            Err(error) => InformAckOutcome::Failed(
                                Error::Network {
                                    target: source,
                                    source: error,
                                }
                                .boxed(),
                            ),
                        }
                    }
                    Err(error) => InformAckOutcome::Failed(error),
                };

                Ok(Some(ReceivedNotification::inform(
                    notification,
                    source,
                    NotificationWireIdentity {
                        version: crate::Version::V2c,
                        request_id: Some(request_id),
                        v3: None,
                    },
                    outcome,
                )))
            }
            _ => Ok(None), // Not a notification PDU
        }
    }

    /// Handle `SNMPv3` message.
    ///
    /// USM processing (RFC 3414 Section 3.2) runs in the shared
    /// [`process_v3_inbound`] core in the receiver role: informs under this
    /// receiver's engine ID use the authoritative time window (Step 7a),
    /// traps under a remote authoritative engine ID use per-engine
    /// timeliness state (Step 7b).
    #[cfg(test)]
    pub(super) async fn handle_v3(
        &self,
        data: Bytes,
        source: SocketAddr,
    ) -> Result<Option<ReceivedNotification>> {
        self.handle_v3_at(data, source, None).await
    }

    pub(super) async fn handle_v3_at(
        &self,
        data: Bytes,
        source: SocketAddr,
        response_source: Option<DestinationMetadata>,
    ) -> Result<Option<ReceivedNotification>> {
        let (our_boots, our_time) = super::unpack_boots_time(
            self.inner
                .authoritative_snapshot
                .load(std::sync::atomic::Ordering::Relaxed),
        );
        let sample_authoritative_time = || self.inner.authoritative_boots_time();
        let usm_ctx = V3LocalContext {
            engine_id: &self.inner.engine_id,
            engine_boots: our_boots,
            engine_time: our_time,
            authoritative_time: Some(&sample_authoritative_time),
            local_receive_capacity: crate::UDP_RECEIVE_LIMITS.advertised(),
            accepted_receive_size: crate::UDP_RECEIVE_LIMITS.accepted(),
            decode_config: self.inner.decode_config,
            outbound_limit: self.inner.max_message_size,
            usm_users: &self.inner.usm_users,
            stats: &self.inner.usm_stats,
            mpd: None,
            source,
        };
        let role = V3Role::Receiver {
            remote_engines: &self.inner.remote_engines,
        };

        let inbound = match process_v3_inbound(data, &usm_ctx, &role)? {
            V3Inbound::Failed { failure, report } => {
                // The shared core logs USM failures at debug; re-surface them
                // at warn in the receiver role so a misconfigured trap sender
                // is diagnosable at the default log level.
                tracing::warn!(target: "async_snmp::notification", { snmp.source = %source, snmp.failure = ?failure }, "USM processing failed for inbound message");
                if let Some(report) = report {
                    if let Err(e) = self.send_response(&report, source, response_source).await {
                        tracing::debug!(target: "async_snmp::notification", { snmp.source = %source, error = %e }, "failed to send USM report");
                    } else {
                        tracing::debug!(target: "async_snmp::notification", { snmp.source = %source }, "sent USM report");
                    }
                }
                // Authentication-class failures are error indications to the
                // caller; the rest are quietly dropped after the report.
                return match failure {
                    UsmFailure::WrongDigests
                    | UsmFailure::NotInTimeWindows
                    | UsmFailure::DecryptionErrors => Err(Error::Auth { target: source }.boxed()),
                    UsmFailure::UnknownEngineIds
                    | UsmFailure::UnknownUserNames
                    | UsmFailure::UnsupportedSecLevels => Ok(None),
                };
            }
            V3Inbound::RemoteNotInTimeWindow => {
                return Err(Error::Auth { target: source }.boxed());
            }
            V3Inbound::Message(inbound) => inbound,
        };
        let inbound = V3InboundNotification::new(*inbound, &self.inner.engine_id, source);
        let security_level = inbound.security_level();
        let pdu_class = match inbound.scoped_pdu().pdu.pdu_type() {
            PduType::TrapV2 => NotificationPduClass::Trap,
            PduType::InformRequest => {
                // The receiver of a Confirmed-class PDU is authoritative.
                if !inbound.is_local_engine() {
                    tracing::warn!(target: "async_snmp::notification", { snmp.source = %source }, "dropped v3 Inform localized to a foreign authoritative engine ID");
                    return Ok(None);
                }
                NotificationPduClass::Inform
            }
            _ => return Ok(None),
        };
        let Some(notification) = inbound.to_notification(self.inner.varbind_validation)? else {
            return Ok(None);
        };
        if !self.inner.accepts(source, &notification) {
            tracing::debug!(target: "async_snmp::notification", { snmp.source = %source, snmp.security_level = ?security_level, pdu_class = ?pdu_class }, "notification acceptance policy dropped v3 notification");
            return Ok(None);
        }
        let wire_identity = inbound.wire_identity();
        let Some(ack) = inbound.inform_ack() else {
            return Ok(Some(ReceivedNotification::trap(
                notification,
                source,
                wire_identity,
            )));
        };
        let request_id = ack.request_id();

        #[cfg(test)]
        let injected_error = self
            .inner
            .response_construction_errors
            .lock()
            .unwrap()
            .pop_front();
        #[cfg(not(test))]
        let injected_error: Option<Box<Error>> = None;
        let finalized = if let Some(error) = injected_error {
            Err(error)
        } else {
            let sample_authoritative_time = || self.inner.authoritative_boots_time();
            finalize_v3_inform_response(
                &ack,
                &V3InformResponder {
                    engine_id: &self.inner.engine_id,
                    authoritative_time: &sample_authoritative_time,
                    max_message_size: self.inner.max_message_size,
                    salt_counter: self.inner.salt_counter.as_ref(),
                    des_salt_state: self.inner.des_salt_state.as_ref(),
                    snmp_silent_drops: &self.inner.snmp_silent_drops,
                    target: self.inner.local_addr,
                },
            )
        };
        let outcome = match finalized {
            Ok(FinalizedResponse::Dropped) => {
                tracing::debug!(target: "async_snmp::notification", { snmp.source = %source, snmp.request_id = request_id, snmp.security_level = ?security_level }, "V3 Inform response and tooBig alternate exceed max message size");
                InformAckOutcome::SuppressedBySize
            }
            Ok(finalized) => {
                let response_bytes = finalized
                    .into_bytes()
                    .expect("non-dropped response contains bytes");
                match self
                    .send_response(&response_bytes, source, response_source)
                    .await
                {
                    Ok(()) => {
                        tracing::debug!(target: "async_snmp::notification", { snmp.source = %source, snmp.request_id = request_id, snmp.security_level = ?security_level }, "sent V3 Inform response");
                        InformAckOutcome::Sent
                    }
                    Err(error) => InformAckOutcome::Failed(
                        Error::Network {
                            target: source,
                            source: error,
                        }
                        .boxed(),
                    ),
                }
            }
            Err(error) => InformAckOutcome::Failed(error),
        };

        Ok(Some(ReceivedNotification::inform(
            notification,
            source,
            wire_identity,
            outcome,
        )))
    }
}

/// Convert an authenticated V3 trap or Inform into a [`Notification`].
///
/// Returns `None` for any other PDU type.
pub(super) fn v3_notification(
    username: &Bytes,
    scoped_pdu: &ScopedPdu,
    security_level: SecurityLevel,
    decode_anomalies: &[crate::DecodeAnomaly],
    validation: NotificationVarbindValidation,
) -> Result<Option<Notification>> {
    let pdu = &scoped_pdu.pdu;
    let notification = match pdu.pdu_type() {
        PduType::TrapV2 => {
            let (uptime, trap_oid, varbinds) = extract_notification_varbinds(pdu, validation)?;
            Notification::TrapV3 {
                username: username.clone(),
                context_engine_id: scoped_pdu.context_engine_id.clone(),
                context_name: scoped_pdu.context_name.clone(),
                security_level,
                uptime,
                trap_oid,
                varbinds,
                request_id: pdu.request_id,
                decode_anomalies: decode_anomalies.to_vec(),
            }
        }
        PduType::InformRequest => {
            let (uptime, trap_oid, varbinds) = extract_notification_varbinds(pdu, validation)?;
            Notification::InformV3 {
                username: username.clone(),
                context_engine_id: scoped_pdu.context_engine_id.clone(),
                context_name: scoped_pdu.context_name.clone(),
                security_level,
                uptime,
                trap_oid,
                varbinds,
                request_id: pdu.request_id,
                decode_anomalies: decode_anomalies.to_vec(),
            }
        }
        _ => return Ok(None),
    };
    Ok(Some(notification))
}

/// Local authoritative state for encoding a V3 Inform response.
pub(super) struct V3InformResponder<'a> {
    pub(super) engine_id: &'a Bytes,
    pub(super) authoritative_time: &'a dyn Fn() -> Result<(u32, u32)>,
    pub(super) max_message_size: usize,
    pub(super) salt_counter: Option<&'a SaltCounter>,
    pub(super) des_salt_state: Option<&'a DesSaltState>,
    pub(super) snmp_silent_drops: &'a AtomicU32,
    pub(super) target: SocketAddr,
}

/// Encode the Response to an accepted V3 Inform, falling back to the `tooBig`
/// alternate when it exceeds the local or originator limit.
pub(super) fn finalize_v3_inform_response(
    ack: &InformAck,
    responder: &V3InformResponder<'_>,
) -> Result<FinalizedResponse> {
    let response = ack.request.to_response(crate::Version::V3)?;
    crate::response_finalizer::finalize_response(
        crate::Version::V3,
        &ack.request,
        response,
        responder.max_message_size,
        Some(ack.msg_max_size.as_usize()),
        responder.snmp_silent_drops,
        |response_pdu| build_v3_response(ack, responder, response_pdu),
    )
}

/// Build a V3 response message with appropriate security.
///
/// The response uses the current authoritative engine tuple and echoes only
/// the requester's username from the incoming USM parameters.
fn build_v3_response(
    ack: &InformAck,
    responder: &V3InformResponder<'_>,
    response_pdu: Pdu,
) -> Result<Bytes> {
    // Derive both fields from one elapsed-time sample immediately before
    // encoding so the response is current and cannot straddle a rollover.
    let (engine_boots, engine_time) = (responder.authoritative_time)()?;
    let response_usm = UsmSecurityParams::new(
        responder.engine_id.clone(),
        engine_boots,
        engine_time,
        ack.username.clone(),
    )?;

    encode_v3_response(
        response_pdu,
        ack.msg_id,
        // RFC 3412 Section 6.3: msgMaxSize advertises this receiver's own
        // receive capacity, not the sender's echoed value. The receiver has no
        // configurable limit, so advertise the default UDP receive capacity.
        crate::UDP_RECEIVE_LIMITS.advertised(),
        ack.security_level,
        response_usm,
        ack.context_engine_id.clone(),
        ack.context_name.clone(),
        Some(&ack.derived_keys),
        responder.salt_counter,
        responder.des_salt_state,
        responder.target,
    )
}
