//! Protocol version-specific notification handlers.
//!
//! This module contains the internal handlers for processing `SNMPv1`, v2c, and v3
//! notification messages.

use std::net::SocketAddr;

use bytes::Bytes;

use crate::error::{Error, Result};
use crate::message::{CommunityMessage, MsgGlobalData};
use crate::pdu::{Pdu, PduType};
use crate::v3::UsmSecurityParams;
use crate::v3::encode::encode_v3_response;
use crate::v3::process::{UsmFailure, V3Inbound, V3LocalContext, V3Role, process_v3_inbound};

use super::varbind::extract_notification_varbinds;
use super::{Notification, ReceiverInner};
use crate::v3::DerivedKeys;

impl super::NotificationReceiver {
    /// Handle `SNMPv1` message.
    pub(super) async fn handle_v1(
        &self,
        data: Bytes,
        source: SocketAddr,
    ) -> Result<Option<Notification>> {
        let msg = CommunityMessage::decode_with_target(data, source)?;

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
                Ok(Some(Notification::TrapV1 { community, trap }))
            }
            crate::message::CommunityPdu::Standard(_) => Ok(None),
        }
    }

    /// Handle `SNMPv2c` message.
    pub(super) async fn handle_v2c(
        &self,
        data: Bytes,
        source: SocketAddr,
    ) -> Result<Option<Notification>> {
        let msg = CommunityMessage::decode_with_target(data, source)?;

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
                Ok(Some(Notification::TrapV2c {
                    community: msg.community().clone(),
                    uptime,
                    trap_oid,
                    varbinds,
                    request_id: pdu.request_id,
                }))
            }
            PduType::InformRequest => {
                let (uptime, trap_oid, varbinds) =
                    extract_notification_varbinds(pdu, self.inner.varbind_validation)?;
                let request_id = pdu.request_id;

                let finalized = crate::response_finalizer::finalize_response(
                    crate::Version::V2c,
                    pdu,
                    pdu.to_response(),
                    self.inner.max_message_size,
                    None,
                    &self.inner.snmp_silent_drops,
                    |response| CommunityMessage::v2c(msg.community().clone(), response)?.encode(),
                )?;

                if let Some(response_bytes) = finalized.into_bytes() {
                    self.inner
                        .socket
                        .send_to(&response_bytes, source)
                        .await
                        .map_err(|e| Error::Network {
                            target: source,
                            source: e,
                        })?;
                    tracing::debug!(target: "async_snmp::notification", { snmp.source = %source, snmp.request_id = request_id }, "sent Inform response");
                } else {
                    tracing::debug!(target: "async_snmp::notification", { snmp.source = %source, snmp.request_id = request_id }, "Inform response and tooBig alternate exceed max message size");
                }

                Ok(Some(Notification::InformV2c {
                    community: msg.community().clone(),
                    uptime,
                    trap_oid,
                    varbinds,
                    request_id,
                }))
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
    pub(super) async fn handle_v3(
        &self,
        data: Bytes,
        source: SocketAddr,
    ) -> Result<Option<Notification>> {
        let (our_boots, our_time) = self.inner.authoritative_boots_time()?;
        let usm_ctx = V3LocalContext {
            engine_id: &self.inner.engine_id,
            engine_boots: our_boots,
            engine_time: our_time,
            local_receive_capacity: crate::UDP_RECEIVE_LIMITS.advertised(),
            accepted_receive_size: crate::UDP_RECEIVE_LIMITS.accepted(),
            outbound_limit: self.inner.max_message_size,
            usm_users: &self.inner.usm_users,
            stats: &self.inner.usm_stats,
            mpd: None,
            source,
        };
        let role = V3Role::Receiver {
            remote_engines: &self.inner.remote_engines,
            max_remote_engines: super::MAX_REMOTE_ENGINES,
        };

        let inbound = match process_v3_inbound(data, &usm_ctx, &role)? {
            V3Inbound::Failed { failure, report } => {
                // The shared core logs USM failures at debug; re-surface them
                // at warn in the receiver role so a misconfigured trap sender
                // is diagnosable at the default log level.
                tracing::warn!(target: "async_snmp::notification", { snmp.source = %source, snmp.failure = ?failure }, "USM processing failed for inbound message");
                if let Some(report) = report {
                    if let Err(e) = self.inner.socket.send_to(&report, source).await {
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
        let username = usm_params.username.clone();

        let context_engine_id = scoped_pdu.context_engine_id.clone();
        let context_name = scoped_pdu.context_name.clone();
        let pdu = &scoped_pdu.pdu;

        match pdu.pdu_type() {
            PduType::TrapV2 => {
                let (uptime, trap_oid, varbinds) =
                    extract_notification_varbinds(pdu, self.inner.varbind_validation)?;
                Ok(Some(Notification::TrapV3 {
                    username,
                    context_engine_id,
                    context_name,
                    security_level,
                    uptime,
                    trap_oid,
                    varbinds,
                    request_id: pdu.request_id,
                }))
            }
            PduType::InformRequest => {
                // RFC 3414 Section 1.5.1: the receiver of a Confirmed-class PDU
                // is the authoritative engine, so an Inform must be localized to
                // this receiver's local engine ID. Reject an Inform whose
                // authoritative engine ID is a foreign (e.g. the sender's)
                // engine: accepting one would acknowledge under, and sign the
                // ack with keys localized to, an engine other than this
                // receiver. Unconfirmed-class traps (handled above) remain under
                // the remote authoritative engine ID and are unaffected.
                if usm_params.engine_id.as_ref() != self.inner.engine_id.as_ref() {
                    tracing::warn!(target: "async_snmp::notification", { snmp.source = %source }, "dropped v3 Inform localized to a foreign authoritative engine ID");
                    return Ok(None);
                }

                let (uptime, trap_oid, varbinds) =
                    extract_notification_varbinds(pdu, self.inner.varbind_validation)?;
                let request_id = pdu.request_id;

                let finalized = crate::response_finalizer::finalize_response(
                    crate::Version::V3,
                    pdu,
                    pdu.to_response(),
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
                )?;

                if let Some(response_bytes) = finalized.into_bytes() {
                    self.inner
                        .socket
                        .send_to(&response_bytes, source)
                        .await
                        .map_err(|e| Error::Network {
                            target: source,
                            source: e,
                        })?;
                    tracing::debug!(target: "async_snmp::notification", { snmp.source = %source, snmp.request_id = request_id, snmp.security_level = ?security_level }, "sent V3 Inform response");
                } else {
                    tracing::debug!(target: "async_snmp::notification", { snmp.source = %source, snmp.request_id = request_id, snmp.security_level = ?security_level }, "V3 Inform response and tooBig alternate exceed max message size");
                }

                Ok(Some(Notification::InformV3 {
                    username,
                    context_engine_id,
                    context_name,
                    security_level,
                    uptime,
                    trap_oid,
                    varbinds,
                    request_id,
                }))
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
        &inner.salt_counter,
        inner.local_addr,
    )
}
