//! Protocol version-specific notification handlers.
//!
//! This module contains the internal handlers for processing `SNMPv1`, v2c, and v3
//! notification messages.

use std::net::SocketAddr;

use bytes::Bytes;

use crate::udp_responder::DestinationMetadata;

use crate::error::{Error, Result};
use crate::message::{CommunityMessage, MsgGlobalData};
use crate::pdu::{Pdu, PduType};
use crate::v3::UsmSecurityParams;
use crate::v3::encode::encode_v3_response;
use crate::v3::process::{UsmFailure, V3Inbound, V3LocalContext, V3Role, process_v3_inbound};

use super::varbind::extract_notification_varbinds;
use super::{
    InformAckOutcome, Notification, NotificationPduClass, NotificationWireIdentity,
    ReceivedNotification, ReceiverInner, V3NotificationWireIdentity,
};
use crate::v3::DerivedKeys;

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
        let global_data = &inbound.global_data;
        let usm_params = &inbound.usm_params;
        let scoped_pdu = &inbound.scoped_pdu;
        let security_level = inbound.security_level;
        let decode_anomalies = inbound.decode_anomalies.clone();
        let username = usm_params.username.clone();
        let wire_identity = NotificationWireIdentity {
            version: crate::Version::V3,
            request_id: Some(inbound.scoped_pdu.pdu.request_id),
            v3: Some(V3NotificationWireIdentity {
                msg_id: global_data.msg_id,
                authoritative_engine_id: usm_params.engine_id.clone(),
                username: username.clone(),
                security_level,
            }),
        };

        let context_engine_id = scoped_pdu.context_engine_id.clone();
        let context_name = scoped_pdu.context_name.clone();
        let pdu = &scoped_pdu.pdu;

        let pdu_class = match pdu.pdu_type() {
            PduType::TrapV2 => NotificationPduClass::Trap,
            PduType::InformRequest => {
                // The receiver of a Confirmed-class PDU is authoritative.
                if usm_params.engine_id.as_ref() != self.inner.engine_id.as_ref() {
                    tracing::warn!(target: "async_snmp::notification", { snmp.source = %source }, "dropped v3 Inform localized to a foreign authoritative engine ID");
                    return Ok(None);
                }
                NotificationPduClass::Inform
            }
            _ => return Ok(None),
        };
        match pdu.pdu_type() {
            PduType::TrapV2 => {
                let (uptime, trap_oid, varbinds) =
                    extract_notification_varbinds(pdu, self.inner.varbind_validation)?;
                let notification = Notification::TrapV3 {
                    username,
                    context_engine_id,
                    context_name,
                    security_level,
                    uptime,
                    trap_oid,
                    varbinds,
                    request_id: pdu.request_id,
                    decode_anomalies,
                };
                if !self.inner.accepts(source, &notification) {
                    tracing::debug!(target: "async_snmp::notification", { snmp.source = %source, snmp.security_level = ?security_level, pdu_class = ?pdu_class }, "notification acceptance policy dropped v3 notification");
                    return Ok(None);
                }
                Ok(Some(ReceivedNotification::trap(
                    notification,
                    source,
                    wire_identity,
                )))
            }
            PduType::InformRequest => {
                let (uptime, trap_oid, varbinds) =
                    extract_notification_varbinds(pdu, self.inner.varbind_validation)?;
                let request_id = pdu.request_id;
                let notification = Notification::InformV3 {
                    username,
                    context_engine_id: context_engine_id.clone(),
                    context_name: context_name.clone(),
                    security_level,
                    uptime,
                    trap_oid,
                    varbinds,
                    request_id,
                    decode_anomalies,
                };
                if !self.inner.accepts(source, &notification) {
                    tracing::debug!(target: "async_snmp::notification", { snmp.source = %source, snmp.security_level = ?security_level, pdu_class = ?pdu_class }, "notification acceptance policy dropped v3 notification");
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
                    pdu.to_response(crate::Version::V3).and_then(|response| {
                        crate::response_finalizer::finalize_response(
                            crate::Version::V3,
                            pdu,
                            response,
                            self.inner.max_message_size,
                            Some(global_data.msg_max_size.as_usize()),
                            &self.inner.snmp_silent_drops,
                            |response_pdu| {
                                build_v3_response(
                                    &self.inner,
                                    global_data,
                                    usm_params,
                                    response_pdu,
                                    context_engine_id.clone(),
                                    context_name.clone(),
                                    Some(&inbound.derived_keys),
                                )
                            },
                        )
                    })
                };
                let outcome = match finalized {
                    Ok(crate::response_finalizer::FinalizedResponse::Dropped) => {
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
            _ => Ok(None),
        }
    }
}

/// Build a V3 response message with appropriate security.
///
/// The response uses the receiver's current authoritative engine tuple and
/// echoes only the requester's username from the incoming USM parameters.
fn build_v3_response(
    inner: &ReceiverInner,
    incoming: &MsgGlobalData,
    incoming_usm: &UsmSecurityParams,
    response_pdu: Pdu,
    context_engine_id: Bytes,
    context_name: Bytes,
    derived_keys: Option<&DerivedKeys>,
) -> Result<Bytes> {
    // Derive both fields from one elapsed-time sample immediately before
    // encoding so the response is current and cannot straddle a rollover.
    let (engine_boots, engine_time) = inner.authoritative_boots_time()?;
    let response_usm = UsmSecurityParams::new(
        inner.engine_id.clone(),
        engine_boots,
        engine_time,
        incoming_usm.username.clone(),
    )?;

    encode_v3_response(
        response_pdu,
        incoming.msg_id,
        // RFC 3412 Section 6.3: msgMaxSize advertises this receiver's own
        // receive capacity, not the sender's echoed value. The receiver has no
        // configurable limit, so advertise the default UDP receive capacity.
        crate::UDP_RECEIVE_LIMITS.advertised(),
        incoming.msg_flags.security_level,
        response_usm,
        context_engine_id,
        context_name,
        derived_keys,
        inner.salt_counter.as_ref(),
        inner.des_salt_state.as_ref(),
        inner.local_addr,
    )
}
