//! Protocol version-specific notification handlers.
//!
//! This module contains the internal handlers for processing `SNMPv1`, v2c, and v3
//! notification messages.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;

use bytes::Bytes;

use crate::ber::{Decoder, tag};
use crate::error::internal::{AuthErrorKind, CryptoErrorKind, DecodeErrorKind, EncodeErrorKind};
use crate::error::{Error, Result};
use crate::message::{
    CommunityMessage, MsgFlags, MsgGlobalData, ScopedPdu, SecurityLevel, V3Message, V3MessageData,
};
use crate::oid::Oid;
use crate::pdu::{Pdu, PduType, TrapV1Pdu};
use crate::v3::auth::{authenticate_message, verify_message};
use crate::v3::{EngineState, LocalizedKey, MAX_ENGINE_TIME, TIME_WINDOW, UsmSecurityParams};
use crate::value::Value;
use crate::varbind::VarBind;

use super::types::DerivedKeys;
use super::varbind::extract_notification_varbinds;
use super::{Notification, ReceiverInner};
use crate::v3::compute_engine_boots_time;

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
    pub(super) async fn handle_v3(
        &self,
        data: Bytes,
        source: SocketAddr,
    ) -> Result<Option<Notification>> {
        let msg = V3Message::decode(data.clone())?;
        let security_level = msg.global_data.msg_flags.security_level;

        // Decode USM security parameters
        let usm_params = UsmSecurityParams::decode(msg.security_params.clone())?;

        // Check for discovery request (empty engine ID)
        if usm_params.engine_id.is_empty() {
            return self.handle_v3_discovery(&msg, &usm_params, source).await;
        }

        let username = usm_params.username.clone();
        let engine_id = usm_params.engine_id.clone();

        // RFC 3414 Section 3.2 Step 4: the user must exist in the local
        // configuration regardless of security level.
        let Some(user_config) = self.inner.usm_users.get(&username) else {
            tracing::warn!(target: "async_snmp::notification", { snmp.source = %source, snmp.username = %String::from_utf8_lossy(&username) }, "V3 message for unknown user");
            let count = self
                .inner
                .usm_unknown_usernames
                .fetch_add(1, Ordering::Relaxed)
                + 1;
            self.send_usm_report(
                &msg,
                &usm_params,
                crate::v3::report_oids::unknown_user_names(),
                count,
                None,
                source,
            )
            .await;
            return Ok(None);
        };
        let derived_keys = user_config
            .derive_keys(&engine_id)
            .map_err(|e| Error::Config(e.to_string().into()).boxed())?;

        // RFC 3414 Section 3.2 Step 5: the user must support the requested
        // security level, checked before authentication (Step 6). The
        // missing-auth-key half of Step 5 is handled by the match below,
        // which also dispatches before any digest is verified.
        if security_level == SecurityLevel::AuthPriv && derived_keys.priv_key.is_none() {
            tracing::warn!(target: "async_snmp::notification", { snmp.source = %source, snmp.username = %String::from_utf8_lossy(&username) }, "received encrypted V3 message but no privacy key configured for user");
            let count = self
                .inner
                .usm_unsupported_sec_levels
                .fetch_add(1, Ordering::Relaxed)
                + 1;
            self.send_usm_report(
                &msg,
                &usm_params,
                crate::v3::report_oids::unsupported_sec_levels(),
                count,
                None,
                source,
            )
            .await;
            return Ok(None);
        }

        // Verify authentication if required
        if security_level == SecurityLevel::AuthNoPriv || security_level == SecurityLevel::AuthPriv
        {
            match derived_keys.auth_key.as_ref() {
                Some(auth_key) => {
                    let (auth_offset, auth_len) = UsmSecurityParams::find_auth_params_offset(&data)
                        .ok_or_else(|| {
                            tracing::debug!(target: "async_snmp::notification", { source = %source, kind = %AuthErrorKind::AuthParamsNotFound }, "could not find auth params in notification");
                            Error::Auth { target: source }.boxed()
                        })?;

                    if !verify_message(auth_key, &data, auth_offset, auth_len)
                        .map_err(|_| Error::Auth { target: source }.boxed())?
                    {
                        tracing::warn!(target: "async_snmp::notification", { snmp.source = %source, snmp.username = %String::from_utf8_lossy(&username) }, "V3 authentication failed");
                        let count =
                            self.inner.usm_wrong_digests.fetch_add(1, Ordering::Relaxed) + 1;
                        self.send_usm_report(
                            &msg,
                            &usm_params,
                            crate::v3::report_oids::wrong_digests(),
                            count,
                            None,
                            source,
                        )
                        .await;
                        return Err(Error::Auth { target: source }.boxed());
                    }
                    tracing::trace!(target: "async_snmp::notification", { snmp.source = %source }, "V3 authentication verified");

                    // Verify time window (RFC 3414 Section 3.2 Step 7)
                    if engine_id == self.inner.engine_id {
                        // We are the authoritative engine for this message
                        // (informs sent under our engine ID): Step 7a,
                        // checked against our own boots/time.
                        let total_secs = self.inner.engine_start.elapsed().as_secs();
                        let (our_boots, our_time) =
                            compute_engine_boots_time(self.inner.engine_boots_base, total_secs);

                        // When boots is latched at MAX_ENGINE_TIME, reject all authenticated messages.
                        // The report is unauthenticated: a latched engine must not
                        // authenticate further messages (RFC 3414 Section 2.3).
                        if our_boots == MAX_ENGINE_TIME {
                            tracing::warn!(target: "async_snmp::notification", { snmp.source = %source }, "engine boots at maximum, rejecting authenticated notification");
                            let count = self.bump_not_in_time_windows();
                            self.send_usm_report(
                                &msg,
                                &usm_params,
                                crate::v3::report_oids::not_in_time_windows(),
                                count,
                                None,
                                source,
                            )
                            .await;
                            return Err(Error::Auth { target: source }.boxed());
                        }

                        if usm_params.engine_boots != our_boots {
                            tracing::warn!(target: "async_snmp::notification", { snmp.source = %source, snmp.msg_boots = usm_params.engine_boots, snmp.our_boots = our_boots }, "V3 notification engine boots mismatch");
                            let count = self.bump_not_in_time_windows();
                            self.send_usm_report(
                                &msg,
                                &usm_params,
                                crate::v3::report_oids::not_in_time_windows(),
                                count,
                                Some(auth_key),
                                source,
                            )
                            .await;
                            return Err(Error::Auth { target: source }.boxed());
                        }

                        let time_diff =
                            (i64::from(usm_params.engine_time) - i64::from(our_time)).abs();
                        if time_diff > i64::from(TIME_WINDOW) {
                            tracing::warn!(target: "async_snmp::notification", { snmp.source = %source, snmp.msg_time = usm_params.engine_time, snmp.our_time = our_time }, "V3 notification outside time window");
                            let count = self.bump_not_in_time_windows();
                            self.send_usm_report(
                                &msg,
                                &usm_params,
                                crate::v3::report_oids::not_in_time_windows(),
                                count,
                                Some(auth_key),
                                source,
                            )
                            .await;
                            return Err(Error::Auth { target: source }.boxed());
                        }
                    } else {
                        // The sender is the authoritative engine (traps sent
                        // under the sender's engine ID): Step 7b, checked
                        // against per-engine state seeded from the first
                        // authenticated message.
                        //
                        // Copy the engine ID out of the received datagram so a
                        // stored entry does not pin the whole packet buffer.
                        let engine_key = Bytes::copy_from_slice(&engine_id);
                        // Scoped so the lock is released before any await.
                        let timely = {
                            let mut engines = self
                                .inner
                                .remote_engines
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            // Bound the table: a peer holding one credential can
                            // authenticate under arbitrarily many fabricated engine
                            // IDs, so evict the least-recently-updated engine when
                            // full before seeding a new one.
                            if !engines.contains_key(&engine_key)
                                && engines.len() >= super::MAX_REMOTE_ENGINES
                                && let Some(oldest) = engines
                                    .iter()
                                    .min_by_key(|(_, s)| s.synced_at)
                                    .map(|(k, _)| k.clone())
                            {
                                engines.remove(&oldest);
                            }
                            let state = engines.entry(engine_key).or_insert_with_key(|k| {
                                EngineState::new(
                                    k.clone(),
                                    usm_params.engine_boots,
                                    usm_params.engine_time,
                                )
                            });
                            let timely = state.check_and_update_timeliness(
                                usm_params.engine_boots,
                                usm_params.engine_time,
                            );
                            if !timely {
                                tracing::warn!(target: "async_snmp::notification", { snmp.source = %source, snmp.msg_boots = usm_params.engine_boots, snmp.msg_time = usm_params.engine_time, snmp.our_boots = state.engine_boots, snmp.our_time = state.estimated_time() }, "V3 notification outside time window");
                            }
                            timely
                        };
                        if !timely {
                            // RFC 3414 Section 3.2 Step 7b: for a remote
                            // authoritative engine this is a bare error
                            // indication. usmStatsNotInTimeWindows and the
                            // notInTimeWindows Report apply only to the
                            // authoritative case (Step 7a); net-snmp counts
                            // the local-reference branch only.
                            return Err(Error::Auth { target: source }.boxed());
                        }
                    }
                }
                None => {
                    // RFC 3414 Section 3.2 Step 5: the user exists but cannot
                    // meet the requested security level.
                    tracing::warn!(target: "async_snmp::notification", { snmp.source = %source, snmp.username = %String::from_utf8_lossy(&username) }, "received authenticated V3 message but user has no auth key");
                    let count = self
                        .inner
                        .usm_unsupported_sec_levels
                        .fetch_add(1, Ordering::Relaxed)
                        + 1;
                    self.send_usm_report(
                        &msg,
                        &usm_params,
                        crate::v3::report_oids::unsupported_sec_levels(),
                        count,
                        None,
                        source,
                    )
                    .await;
                    return Ok(None);
                }
            }
        }

        // Decrypt if needed
        let scoped_pdu = if security_level == SecurityLevel::AuthPriv {
            // Presence checked at Step 5 above.
            let priv_key = derived_keys
                .priv_key
                .as_ref()
                .expect("authPriv without a privacy key is rejected at Step 5");
            let encrypted_data = match &msg.data {
                V3MessageData::Encrypted(data) => data,
                V3MessageData::Plaintext(_) => {
                    tracing::debug!(target: "async_snmp::notification", { source = %source, kind = %DecodeErrorKind::UnexpectedEncryption }, "expected encrypted scoped PDU in notification");
                    return Err(Error::MalformedResponse { target: source }.boxed());
                }
            };

            let decrypted = priv_key.decrypt(
                encrypted_data,
                usm_params.engine_boots,
                usm_params.engine_time,
                &usm_params.priv_params,
            );
            let decrypted = match decrypted {
                Ok(data) => data,
                Err(e) => {
                    tracing::debug!(target: "async_snmp::notification", { source = %source, error = %e }, "decryption failed");
                    let count = self
                        .inner
                        .usm_decryption_errors
                        .fetch_add(1, Ordering::Relaxed)
                        + 1;
                    self.send_usm_report(
                        &msg,
                        &usm_params,
                        crate::v3::report_oids::decryption_errors(),
                        count,
                        None,
                        source,
                    )
                    .await;
                    return Err(Error::Auth { target: source }.boxed());
                }
            };

            let mut decoder = Decoder::with_target(decrypted, source);
            ScopedPdu::decode(&mut decoder)?
        } else if let Some(sp) = msg.scoped_pdu() {
            sp.clone()
        } else {
            tracing::warn!(target: "async_snmp::notification", { snmp.source = %source }, "unexpected encrypted V3 message");
            return Ok(None);
        };

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
                    &msg,
                    &usm_params,
                    response_pdu,
                    context_engine_id.clone(),
                    context_name.clone(),
                    Some(&derived_keys),
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

    /// Handle `SNMPv3` engine discovery request.
    ///
    /// Per RFC 3414 Section 4, responds with a Report PDU containing
    /// usmStatsUnknownEngineIDs and the receiver's engine ID in USM params.
    async fn handle_v3_discovery(
        &self,
        msg: &V3Message,
        usm_params: &UsmSecurityParams,
        source: SocketAddr,
    ) -> Result<Option<Notification>> {
        // Only respond if reportable flag is set
        if !msg.global_data.msg_flags.reportable {
            return Ok(None);
        }

        let total_secs = self.inner.engine_start.elapsed().as_secs();
        let (boots, time) = compute_engine_boots_time(self.inner.engine_boots_base, total_secs);
        let count = self
            .inner
            .usm_unknown_engine_ids
            .fetch_add(1, Ordering::Relaxed)
            + 1;

        let report_pdu = Pdu {
            pdu_type: PduType::Report,
            request_id: msg.global_data.msg_id,
            error_status: 0,
            error_index: 0,
            varbinds: vec![VarBind::new(
                crate::v3::report_oids::unknown_engine_ids(),
                Value::Counter32(count),
            )],
        };

        let response_global = MsgGlobalData::new(
            msg.global_data.msg_id,
            msg.global_data.msg_max_size,
            MsgFlags::new(SecurityLevel::NoAuthNoPriv, false),
        );
        let response_usm = UsmSecurityParams::new(
            self.inner.engine_id.clone(),
            boots,
            time,
            usm_params.username.clone(),
        );
        let response_scoped =
            ScopedPdu::new(self.inner.engine_id.clone(), Bytes::new(), report_pdu);
        let response_msg = V3Message::new(response_global, response_usm.encode(), response_scoped);

        self.inner
            .socket
            .send_to(&response_msg.encode(), source)
            .await
            .map_err(|e| Error::Network {
                target: source,
                source: e,
            })?;

        tracing::debug!(target: "async_snmp::notification", { snmp.source = %source }, "sent discovery response");
        Ok(None)
    }

    fn bump_not_in_time_windows(&self) -> u32 {
        self.inner
            .usm_not_in_time_windows
            .fetch_add(1, Ordering::Relaxed)
            + 1
    }

    /// Send a Report PDU for a USM processing failure, best-effort.
    ///
    /// Per RFC 3412 Section 7.1 Step 3 a Report may only be sent when the PDU
    /// is Confirmed Class or, when the PDU class cannot be determined (the
    /// case here: the message failed USM processing), when the reportableFlag
    /// is set. Informs are sent with the flag set and traps without, so this
    /// answers USM-failed informs while staying silent for traps.
    ///
    /// With `auth_key` (localized to the receiver's engine ID) the report is
    /// sent authenticated at authNoPriv, as RFC 3414 Section 3.2 Step 7
    /// requires for notInTimeWindows reports so the sender can trust the
    /// boots/time for resynchronization. Otherwise it is sent noAuthNoPriv.
    ///
    /// Send failures are logged and swallowed: the caller is already on a
    /// failure path and the report is advisory.
    async fn send_usm_report(
        &self,
        msg: &V3Message,
        usm_params: &UsmSecurityParams,
        report_oid: Oid,
        count: u32,
        auth_key: Option<&LocalizedKey>,
        source: SocketAddr,
    ) {
        if !msg.global_data.msg_flags.reportable {
            return;
        }

        let total_secs = self.inner.engine_start.elapsed().as_secs();
        let (boots, time) = compute_engine_boots_time(self.inner.engine_boots_base, total_secs);

        let report_pdu = Pdu {
            pdu_type: PduType::Report,
            request_id: msg.global_data.msg_id,
            error_status: 0,
            error_index: 0,
            varbinds: vec![VarBind::new(report_oid, Value::Counter32(count))],
        };

        let security_level = if auth_key.is_some() {
            SecurityLevel::AuthNoPriv
        } else {
            SecurityLevel::NoAuthNoPriv
        };
        let response_global = MsgGlobalData::new(
            msg.global_data.msg_id,
            msg.global_data.msg_max_size,
            MsgFlags::new(security_level, false),
        );
        let mut response_usm = UsmSecurityParams::new(
            self.inner.engine_id.clone(),
            boots,
            time,
            usm_params.username.clone(),
        );
        if let Some(key) = auth_key {
            response_usm = response_usm.with_auth_placeholder(key.mac_len());
        }
        let response_scoped =
            ScopedPdu::new(self.inner.engine_id.clone(), Bytes::new(), report_pdu);
        let response_msg = V3Message::new(response_global, response_usm.encode(), response_scoped);
        let mut response_bytes = response_msg.encode().to_vec();

        if let Some(key) = auth_key {
            let Some((auth_offset, auth_len)) =
                UsmSecurityParams::find_auth_params_offset(&response_bytes)
            else {
                tracing::debug!(target: "async_snmp::notification", { kind = %EncodeErrorKind::MissingAuthParams }, "could not find auth params in USM report");
                return;
            };
            if let Err(e) = authenticate_message(key, &mut response_bytes, auth_offset, auth_len) {
                tracing::debug!(target: "async_snmp::notification", { error = %e }, "failed to authenticate USM report");
                return;
            }
        }

        if let Err(e) = self.inner.socket.send_to(&response_bytes, source).await {
            tracing::debug!(target: "async_snmp::notification", { snmp.source = %source, error = %e }, "failed to send USM report");
        } else {
            tracing::debug!(target: "async_snmp::notification", { snmp.source = %source }, "sent USM report");
        }
    }
}

/// Build a V3 response message with appropriate security.
fn build_v3_response(
    inner: &ReceiverInner,
    incoming_msg: &V3Message,
    incoming_usm: &UsmSecurityParams,
    response_pdu: Pdu,
    context_engine_id: Bytes,
    context_name: Bytes,
    derived_keys: Option<&DerivedKeys>,
) -> Result<Bytes> {
    let security_level = incoming_msg.global_data.msg_flags.security_level;

    // Build response with same security level but reportable=false
    let response_global = MsgGlobalData::new(
        incoming_msg.global_data.msg_id,
        incoming_msg.global_data.msg_max_size,
        MsgFlags::new(security_level, false),
    );

    let response_scoped = ScopedPdu::new(context_engine_id, context_name, response_pdu);

    match security_level {
        SecurityLevel::NoAuthNoPriv => {
            // Simple case: no authentication or encryption
            let response_usm = UsmSecurityParams::new(
                incoming_usm.engine_id.clone(),
                incoming_usm.engine_boots,
                incoming_usm.engine_time,
                incoming_usm.username.clone(),
            );
            let response_msg =
                V3Message::new(response_global, response_usm.encode(), response_scoped);
            Ok(response_msg.encode())
        }
        SecurityLevel::AuthNoPriv => {
            // Authentication only
            let local_addr = inner.local_addr;
            let keys = derived_keys.ok_or_else(|| {
                tracing::debug!(target: "async_snmp::notification", { kind = %AuthErrorKind::NoCredentials }, "no credentials for notification response");
                Error::Auth { target: local_addr }.boxed()
            })?;
            let auth_key = keys.auth_key.as_ref().ok_or_else(|| {
                tracing::debug!(target: "async_snmp::notification", { kind = %AuthErrorKind::NoAuthKey }, "no auth key for notification response");
                Error::Auth { target: local_addr }.boxed()
            })?;

            let mac_len = auth_key.mac_len();
            let response_usm = UsmSecurityParams::new(
                incoming_usm.engine_id.clone(),
                incoming_usm.engine_boots,
                incoming_usm.engine_time,
                incoming_usm.username.clone(),
            )
            .with_auth_placeholder(mac_len);

            let response_msg =
                V3Message::new(response_global, response_usm.encode(), response_scoped);

            let mut response_bytes = response_msg.encode().to_vec();

            // Find and fill in the authentication parameters
            let (auth_offset, auth_len) =
                UsmSecurityParams::find_auth_params_offset(&response_bytes).ok_or_else(|| {
                    tracing::debug!(target: "async_snmp::notification", { kind = %EncodeErrorKind::MissingAuthParams }, "could not find auth params in notification response");
                    Error::MalformedResponse { target: local_addr }.boxed()
                })?;

            authenticate_message(auth_key, &mut response_bytes, auth_offset, auth_len)
                .map_err(|e| Error::Config(e.to_string().into()).boxed())?;

            Ok(Bytes::from(response_bytes))
        }
        SecurityLevel::AuthPriv => {
            // Authentication and encryption
            let local_addr = inner.local_addr;
            let keys = derived_keys.ok_or_else(|| {
                tracing::debug!(target: "async_snmp::notification", { kind = %AuthErrorKind::NoCredentials }, "no credentials for notification response");
                Error::Auth { target: local_addr }.boxed()
            })?;
            let auth_key = keys.auth_key.as_ref().ok_or_else(|| {
                tracing::debug!(target: "async_snmp::notification", { kind = %AuthErrorKind::NoAuthKey }, "no auth key for notification response");
                Error::Auth { target: local_addr }.boxed()
            })?;
            let priv_key = keys.priv_key.as_ref().ok_or_else(|| {
                tracing::debug!(target: "async_snmp::notification", { kind = %CryptoErrorKind::NoPrivKey }, "no privacy key for notification response");
                Error::Auth { target: local_addr }.boxed()
            })?;

            // Encrypt the scoped PDU
            let scoped_pdu_bytes = response_scoped.encode_to_bytes();
            let (encrypted, priv_params) = priv_key
                .encrypt(
                    &scoped_pdu_bytes,
                    incoming_usm.engine_boots,
                    incoming_usm.engine_time,
                    Some(&inner.salt_counter),
                )
                .map_err(|e| {
                    tracing::debug!(target: "async_snmp::notification", { error = %e }, "encryption failed for notification response");
                    Error::Auth { target: local_addr }.boxed()
                })?;

            let mac_len = auth_key.mac_len();
            let response_usm = UsmSecurityParams::new(
                incoming_usm.engine_id.clone(),
                incoming_usm.engine_boots,
                incoming_usm.engine_time,
                incoming_usm.username.clone(),
            )
            .with_auth_placeholder(mac_len)
            .with_priv_params(priv_params);

            let response_msg =
                V3Message::new_encrypted(response_global, response_usm.encode(), encrypted);

            let mut response_bytes = response_msg.encode().to_vec();

            // Find and fill in the authentication parameters
            let (auth_offset, auth_len) =
                UsmSecurityParams::find_auth_params_offset(&response_bytes).ok_or_else(|| {
                    tracing::debug!(target: "async_snmp::notification", { kind = %EncodeErrorKind::MissingAuthParams }, "could not find auth params in notification response");
                    Error::MalformedResponse { target: local_addr }.boxed()
                })?;

            authenticate_message(auth_key, &mut response_bytes, auth_offset, auth_len)
                .map_err(|e| Error::Config(e.to_string().into()).boxed())?;

            Ok(Bytes::from(response_bytes))
        }
    }
}
