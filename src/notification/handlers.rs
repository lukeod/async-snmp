//! Protocol version-specific notification handlers.
//!
//! This module contains the internal handlers for processing `SNMPv1`, v2c, and v3
//! notification messages.

use std::net::SocketAddr;

use bytes::Bytes;

use crate::ber::{Decoder, tag};
use crate::error::internal::DecodeErrorKind;
use crate::error::{Error, Result};
use crate::message::{CommunityMessage, V3Message};
use crate::pdu::{Pdu, PduType, TrapV1Pdu};
use crate::v3::UsmSecurityParams;
use crate::v3::compute_engine_boots_time;
use crate::v3::encode::encode_v3_response;
use crate::v3::process::{UsmFailure, V3Inbound, V3LocalContext, V3Role, process_v3_inbound};

use super::types::DerivedKeys;
use super::varbind::extract_notification_varbinds;
use super::{Notification, ReceiverInner};

impl super::NotificationReceiver {
    /// Handle `SNMPv1` message.
    pub(super) async fn handle_v1(
        &self,
        data: Bytes,
        source: SocketAddr,
    ) -> Result<Option<Notification>> {
        // For v1, we need to check if it's a Trap PDU (has different structure)
        let mut decoder = Decoder::with_target(data, source);
        let mut seq = decoder.read_sequence()?;

        let _version = seq.read_integer()?;
        let community = seq.read_octet_string()?;

        if !super::community_allowed(&self.inner.communities, &community) {
            tracing::debug!(target: "async_snmp::notification", { snmp.source = %source }, "dropped v1 notification with unaccepted community");
            return Ok(None);
        }

        // Peek at PDU tag
        let pdu_tag = seq.peek_tag().ok_or_else(|| {
            tracing::debug!(target: "async_snmp::notification", { source = %source, kind = %DecodeErrorKind::TruncatedData }, "truncated notification data");
            Error::MalformedResponse { target: source }.boxed()
        })?;

        if pdu_tag == tag::pdu::TRAP_V1 {
            let trap = TrapV1Pdu::decode(&mut seq)?;
            Ok(Some(Notification::TrapV1 { community, trap }))
        } else {
            // Not a trap, ignore (could be a v1 request which we don't handle)
            Ok(None)
        }
    }

    /// Handle `SNMPv2c` message.
    pub(super) async fn handle_v2c(
        &self,
        data: Bytes,
        source: SocketAddr,
    ) -> Result<Option<Notification>> {
        let msg = CommunityMessage::decode(data)?;

        if !super::community_allowed(&self.inner.communities, &msg.community) {
            tracing::debug!(target: "async_snmp::notification", { snmp.source = %source }, "dropped v2c notification with unaccepted community");
            return Ok(None);
        }

        // V2c messages carry standard PDUs; TrapV1 is only valid in V1 messages.
        let Some(pdu) = msg.pdu.standard() else {
            return Ok(None);
        };

        match pdu.pdu_type {
            PduType::TrapV2 => {
                let (uptime, trap_oid, varbinds) = extract_notification_varbinds(pdu)?;
                Ok(Some(Notification::TrapV2c {
                    community: msg.community,
                    uptime,
                    trap_oid,
                    varbinds,
                    request_id: pdu.request_id,
                }))
            }
            PduType::InformRequest => {
                let (uptime, trap_oid, varbinds) = extract_notification_varbinds(pdu)?;
                let request_id = pdu.request_id;

                // Send response
                let response = pdu.to_response();
                let response_msg = CommunityMessage::v2c(msg.community.clone(), response);
                let response_bytes = response_msg.encode();

                self.inner
                    .socket
                    .send_to(&response_bytes, source)
                    .await
                    .map_err(|e| Error::Network {
                        target: source,
                        source: e,
                    })?;

                tracing::debug!(target: "async_snmp::notification", { snmp.source = %source, snmp.request_id = request_id }, "sent Inform response");

                Ok(Some(Notification::InformV2c {
                    community: msg.community,
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
        let total_secs = self.inner.engine_start.elapsed().as_secs();
        let (our_boots, our_time) =
            compute_engine_boots_time(self.inner.engine_boots_base, total_secs);
        let usm_ctx = V3LocalContext {
            engine_id: &self.inner.engine_id,
            engine_boots: our_boots,
            engine_time: our_time,
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
        let msg = &inbound.msg;
        let usm_params = &inbound.usm_params;
        let scoped_pdu = &inbound.scoped_pdu;
        let security_level = inbound.security_level;
        let username = usm_params.username.clone();

        let context_engine_id = scoped_pdu.context_engine_id.clone();
        let context_name = scoped_pdu.context_name.clone();
        let pdu = &scoped_pdu.pdu;

        match pdu.pdu_type {
            PduType::TrapV2 => {
                let (uptime, trap_oid, varbinds) = extract_notification_varbinds(pdu)?;
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
                let (uptime, trap_oid, varbinds) = extract_notification_varbinds(pdu)?;
                let request_id = pdu.request_id;

                // Build and send response with appropriate security level
                let response_pdu = pdu.to_response();

                let response_bytes = build_v3_response(
                    &self.inner,
                    msg,
                    usm_params,
                    response_pdu,
                    context_engine_id.clone(),
                    context_name.clone(),
                    Some(&inbound.derived_keys),
                )?;

                self.inner
                    .socket
                    .send_to(&response_bytes, source)
                    .await
                    .map_err(|e| Error::Network {
                        target: source,
                        source: e,
                    })?;

                tracing::debug!(target: "async_snmp::notification", { snmp.source = %source, snmp.request_id = request_id, snmp.security_level = ?security_level }, "sent V3 Inform response");

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
/// The response echoes the incoming message's engine ID/boots/time (rather
/// than the receiver's own): informs are addressed to this receiver's engine
/// ID, and echoing also interoperates with senders that used their own.
fn build_v3_response(
    inner: &ReceiverInner,
    incoming_msg: &V3Message,
    incoming_usm: &UsmSecurityParams,
    response_pdu: Pdu,
    context_engine_id: Bytes,
    context_name: Bytes,
    derived_keys: Option<&DerivedKeys>,
) -> Result<Bytes> {
    let response_usm = UsmSecurityParams::new(
        incoming_usm.engine_id.clone(),
        incoming_usm.engine_boots,
        incoming_usm.engine_time,
        incoming_usm.username.clone(),
    );

    encode_v3_response(
        response_pdu,
        incoming_msg.global_data.msg_id,
        // RFC 3412 Section 6.3: msgMaxSize advertises this receiver's own
        // receive capacity, not the sender's echoed value. The receiver has no
        // configurable limit, so advertise the default UDP receive capacity.
        crate::v3::DEFAULT_MSG_MAX_SIZE as i32,
        incoming_msg.global_data.msg_flags.security_level,
        response_usm,
        context_engine_id,
        context_name,
        derived_keys,
        &inner.salt_counter,
        inner.local_addr,
    )
}
