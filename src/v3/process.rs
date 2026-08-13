//! Shared inbound `SNMPv3` message processing.
//!
//! Implements the RFC 3412 Section 7.2 dispatch checks and the RFC 3414
//! Section 3.2 USM step sequence once, for every receiving role. The agent
//! (authoritative engine) and the notification receiver (non-authoritative
//! for traps, authoritative for informs) both collapse onto
//! [`process_v3_inbound`]; role-legitimate differences are carried by
//! [`V3Role`].

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

use bytes::Bytes;

use super::{DerivedKeys, UsmUser};
use crate::error::{Error, Result};
use crate::message::{
    MsgGlobalData, RawMsgData, RawV3Message, ScopedPdu, SecurityLevel, combine_staged_v3_anomalies,
    decode_scoped_pdu_with_policies,
};
use crate::message_size::MessageSize;
use crate::oid::Oid;
use crate::v3::auth::verify_message;
use crate::v3::encode::encode_v3_report;
use crate::v3::{
    EngineState, LocalizedKey, UsmSecurityParams, in_authoritative_time_window, report_oids,
    validate_engine_id,
};

/// RFC 3414 usmStats counters, shared by every receiving role.
#[derive(Debug, Default)]
pub(crate) struct UsmStats {
    /// usmStatsUnknownEngineIDs (1.3.6.1.6.3.15.1.1.4)
    pub(crate) unknown_engine_ids: AtomicU32,
    /// usmStatsUnknownUserNames (1.3.6.1.6.3.15.1.1.3)
    pub(crate) unknown_usernames: AtomicU32,
    /// usmStatsWrongDigests (1.3.6.1.6.3.15.1.1.5)
    pub(crate) wrong_digests: AtomicU32,
    /// usmStatsNotInTimeWindows (1.3.6.1.6.3.15.1.1.2)
    pub(crate) not_in_time_windows: AtomicU32,
    /// usmStatsUnsupportedSecLevels (1.3.6.1.6.3.15.1.1.1)
    pub(crate) unsupported_sec_levels: AtomicU32,
    /// usmStatsDecryptionErrors (1.3.6.1.6.3.15.1.1.6)
    pub(crate) decryption_errors: AtomicU32,
}

impl UsmStats {
    fn counter(&self, failure: UsmFailure) -> &AtomicU32 {
        match failure {
            UsmFailure::UnknownEngineIds => &self.unknown_engine_ids,
            UsmFailure::UnknownUserNames => &self.unknown_usernames,
            UsmFailure::WrongDigests => &self.wrong_digests,
            UsmFailure::NotInTimeWindows => &self.not_in_time_windows,
            UsmFailure::UnsupportedSecLevels => &self.unsupported_sec_levels,
            UsmFailure::DecryptionErrors => &self.decryption_errors,
        }
    }

    /// Increment the counter for `failure` and return the new value.
    fn count(&self, failure: UsmFailure) -> u32 {
        self.counter(failure)
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1)
    }
}

/// A USM processing failure, binding the usmStats counter to the report OID
/// sent for it (RFC 3414 Section 3.2) so the pair cannot be mismatched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UsmFailure {
    UnknownEngineIds,
    UnknownUserNames,
    WrongDigests,
    NotInTimeWindows,
    UnsupportedSecLevels,
    DecryptionErrors,
}

impl UsmFailure {
    fn report_oid(self) -> Oid {
        match self {
            Self::UnknownEngineIds => report_oids::unknown_engine_ids(),
            Self::UnknownUserNames => report_oids::unknown_user_names(),
            Self::WrongDigests => report_oids::wrong_digests(),
            Self::NotInTimeWindows => report_oids::not_in_time_windows(),
            Self::UnsupportedSecLevels => report_oids::unsupported_sec_levels(),
            Self::DecryptionErrors => report_oids::decryption_errors(),
        }
    }
}

/// RFC 3412 MPD statistics counters. Only the agent exposes the MPD MIB;
/// the notification receiver passes `None`.
pub(crate) struct MpdCounters<'a> {
    /// snmpInvalidMsgs (1.3.6.1.6.3.11.2.1.2)
    pub(crate) invalid_msgs: &'a AtomicU32,
    /// snmpUnknownSecurityModels (1.3.6.1.6.3.11.2.1.1)
    pub(crate) unknown_security_models: &'a AtomicU32,
}

/// Receiving role for [`process_v3_inbound`], carrying the differences the
/// RFC assigns to each engine role.
pub(crate) enum V3Role<'a> {
    /// Authoritative engine (agent): only messages under its own engine ID
    /// are accepted (RFC 3414 Section 3.2 Step 3), timeliness is Step 7a
    /// against its own boots/time.
    #[cfg(any(feature = "agent", test))]
    Authoritative,
    /// Non-authoritative receiver (notification receiver): messages under
    /// its own engine ID (informs) use Step 7a; messages under a remote
    /// authoritative engine ID (traps) use Step 7b against per-engine state
    /// seeded from the first authenticated message.
    Receiver {
        remote_engines: &'a Mutex<HashMap<Bytes, EngineState>>,
        max_remote_engines: usize,
    },
}

impl V3Role<'_> {
    #[cfg(any(feature = "agent", test))]
    fn is_authoritative(&self) -> bool {
        matches!(self, Self::Authoritative)
    }

    #[cfg(not(any(feature = "agent", test)))]
    fn is_authoritative(&self) -> bool {
        false
    }

    fn receiver_config(&self) -> (&Mutex<HashMap<Bytes, EngineState>>, usize) {
        #[cfg(any(feature = "agent", test))]
        match self {
            Self::Authoritative => unreachable!("authoritative role rejected a foreign engine ID"),
            Self::Receiver {
                remote_engines,
                max_remote_engines,
            } => (remote_engines, *max_remote_engines),
        }

        #[cfg(not(any(feature = "agent", test)))]
        {
            let Self::Receiver {
                remote_engines,
                max_remote_engines,
            } = self;
            (remote_engines, *max_remote_engines)
        }
    }
}

/// Local engine identity, user table, and counters for USM processing.
pub(crate) struct V3LocalContext<'a> {
    pub(crate) engine_id: &'a Bytes,
    pub(crate) engine_boots: u32,
    pub(crate) engine_time: u32,
    /// Wire-valid `msgMaxSize` advertising this receiver's local capacity.
    pub(crate) local_receive_capacity: MessageSize,
    /// Hard total-message bound for inbound decoding.
    pub(crate) accepted_receive_size: usize,
    /// Top-level message envelope consumption policy.
    pub(crate) decode_policy: crate::message::DecodePolicy,
    /// BER/value malformed-input compatibility policy.
    pub(crate) compatibility_policy: crate::CompatibilityPolicy,
    /// Local policy bound for outbound responses and Reports.
    pub(crate) outbound_limit: usize,
    pub(crate) usm_users: &'a HashMap<Bytes, UsmUser>,
    pub(crate) stats: &'a UsmStats,
    pub(crate) mpd: Option<MpdCounters<'a>>,
    pub(crate) source: SocketAddr,
}

/// A fully USM-processed inbound message.
pub(crate) struct V3InboundMessage {
    pub(crate) global_data: MsgGlobalData,
    pub(crate) usm_params: UsmSecurityParams,
    pub(crate) scoped_pdu: ScopedPdu,
    pub(crate) security_level: SecurityLevel,
    pub(crate) derived_keys: DerivedKeys,
    pub(crate) decode_anomalies: Vec<crate::DecodeAnomaly>,
}

/// Outcome of inbound USM processing.
pub(crate) enum V3Inbound {
    /// All security checks passed; the scoped PDU is decoded (and decrypted).
    Message(Box<V3InboundMessage>),
    /// A USM step failed: the usmStats counter has been incremented and a
    /// Report is encoded when RFC 3412 Section 7.1 Step 3 permits one.
    Failed {
        failure: UsmFailure,
        report: Option<Bytes>,
    },
    /// RFC 3414 Section 3.2 Step 7b failure for a remote authoritative
    /// engine: a bare error indication. usmStatsNotInTimeWindows and the
    /// notInTimeWindows Report apply only to the authoritative case (7a).
    RemoteNotInTimeWindow,
}

/// Run the RFC 3414 Section 3.2 step sequence over an inbound V3 message.
///
/// Steps run in fixed order: decode, engine-ID handling (Step 3, including
/// discovery), user lookup (Step 4), security-level support (Step 5),
/// authentication (Step 6), timeliness (Step 7a/7b per role, with 7a also
/// covering the RFC 3414 Section 2.3 latched-boots state), decryption, and
/// scoped-PDU decode.
pub(crate) fn process_v3_inbound(
    data: Bytes,
    ctx: &V3LocalContext<'_>,
    role: &V3Role<'_>,
) -> Result<V3Inbound> {
    let source = ctx.source;

    let decoded = match RawV3Message::decode_bounded_with_target_and_compatibility(
        data.clone(),
        ctx.accepted_receive_size,
        source,
        ctx.decode_policy,
        ctx.compatibility_policy,
    ) {
        Ok(outcome) => outcome,
        Err(e) => {
            // RFC 3412 Section 7.2.4/7.2.7: invalid msgFlags and unknown
            // security models are counted before the message is discarded.
            if let Some(mpd) = &ctx.mpd {
                match crate::message::classify_mpd_failure(data) {
                    Some(crate::message::MpdFailure::InvalidMsgFlags) => {
                        mpd.invalid_msgs.fetch_add(1, Ordering::Relaxed);
                    }
                    Some(crate::message::MpdFailure::UnknownSecurityModel) => {
                        mpd.unknown_security_models.fetch_add(1, Ordering::Relaxed);
                    }
                    None => {}
                }
            }
            return Err(e);
        }
    };
    let trailing_bytes = decoded
        .anomalies
        .iter()
        .find_map(|anomaly| match anomaly {
            crate::DecodeAnomaly::TrailingBytes {
                original_length, ..
            } => Some(*original_length),
            _ => None,
        })
        .unwrap_or(0);
    let authenticated_data = data.slice(..data.len() - trailing_bytes);
    let mut decode_anomalies = decoded.anomalies;
    let msg = decoded.value;
    let security_level = msg.global_data.msg_flags.security_level;
    let usm_params = UsmSecurityParams::decode_with_context_and_compatibility(
        msg.security_params.clone(),
        msg.security_params_offset,
        source,
        ctx.compatibility_policy,
    )?;

    // Encodes the Report for `failure` (counting it first), unauthenticated
    // unless `auth_key` is given (notInTimeWindows, RFC 3414 3.2 Step 7a).
    let fail = |failure: UsmFailure, auth_key: Option<&LocalizedKey>| -> Result<V3Inbound> {
        let count = ctx.stats.count(failure);
        // RFC 3412 Section 7.1 Step 3: a Report may only be sent when the
        // PDU is Confirmed Class or, when the PDU class cannot be determined
        // (the case here: the message failed USM processing), when the
        // reportableFlag is set.
        let report = if msg.global_data.msg_flags.reportable {
            let encoded = encode_v3_report(
                msg.global_data.msg_id,
                ctx.local_receive_capacity,
                UsmSecurityParams::new(
                    ctx.engine_id.clone(),
                    ctx.engine_boots,
                    ctx.engine_time,
                    usm_params.username.clone(),
                )?,
                failure.report_oid(),
                count,
                auth_key,
                source,
            )?;
            crate::response_finalizer::finalize_report(
                encoded,
                ctx.outbound_limit,
                Some(msg.global_data.msg_max_size.as_usize()),
            )
        } else {
            None
        };
        Ok(V3Inbound::Failed { failure, report })
    };

    // RFC 3414 Section 3.2 Step 3: engine-ID handling. An empty engine ID is
    // a discovery request (RFC 3414 Section 4); both cases answer with
    // usmStatsUnknownEngineIDs. Do not validate authentication/privacy field
    // relationships here: Steps 3 and 4 take precedence over those semantics.
    if usm_params.engine_id.is_empty() {
        return fail(UsmFailure::UnknownEngineIds, None);
    }
    if validate_engine_id(&usm_params.engine_id).is_err() {
        tracing::debug!(target: "async_snmp::v3", { snmp.source = %source, length = usm_params.engine_id.len() }, "invalid engine ID");
        return fail(UsmFailure::UnknownEngineIds, None);
    }
    let engine_is_local = usm_params.engine_id == *ctx.engine_id;
    if role.is_authoritative() && !engine_is_local {
        tracing::debug!(target: "async_snmp::v3", { snmp.source = %source }, "engine ID mismatch");
        return fail(UsmFailure::UnknownEngineIds, None);
    }

    // RFC 3414 Section 3.2 Step 4: the user must exist in the local user
    // database regardless of security level.
    let Some(user_config) = ctx.usm_users.get(&usm_params.username) else {
        tracing::debug!(target: "async_snmp::v3", { snmp.source = %source, snmp.username = ?usm_params.username }, "unknown user");
        return fail(UsmFailure::UnknownUserNames, None);
    };
    // Keys are localized to the message's (authoritative) engine ID: the
    // local engine ID for the authoritative role and informs, the sender's
    // for traps from a remote authoritative engine.
    let derived_keys = user_config
        .derive_keys(&usm_params.engine_id)
        .map_err(|e| Error::Config(e.to_string().into()).boxed())?;

    // RFC 3414 Section 3.2 Step 5: the user must support the requested
    // security level, checked before authentication (Step 6) and
    // timeliness (Step 7).
    if security_level.requires_auth() {
        let supported = derived_keys.auth_key.is_some()
            && (security_level != SecurityLevel::AuthPriv || derived_keys.priv_key.is_some());
        if !supported {
            tracing::debug!(target: "async_snmp::v3", { snmp.source = %source, snmp.username = ?usm_params.username }, "user does not support requested security level");
            return fail(UsmFailure::UnsupportedSecLevels, None);
        }
    }

    if security_level.requires_auth() {
        // RFC 3414 Section 3.2 Step 6: verify authentication. The auth key
        // is guaranteed present by the Step 5 check above.
        let auth_key = derived_keys
            .auth_key
            .as_ref()
            .expect("authenticated message without an auth key is rejected at Step 5");
        let Some((auth_offset, auth_len)) = UsmSecurityParams::find_auth_params_offset(&data)
        else {
            // The USM sequence was structurally decoded above, so this is
            // defensive. At Step 6 an unusable authentication field is
            // authentication failure, not an uncounted local decode error.
            tracing::debug!(target: "async_snmp::v3", { source = %source }, "could not locate authentication parameters");
            return fail(UsmFailure::WrongDigests, None);
        };
        if !verify_message(auth_key, &authenticated_data, auth_offset, auth_len)
            .map_err(|_| Error::Auth { target: source }.boxed())?
        {
            tracing::debug!(target: "async_snmp::v3", { snmp.source = %source }, "authentication failed");
            return fail(UsmFailure::WrongDigests, None);
        }

        // RFC 3414 Section 3.2 Step 7: timeliness.
        if engine_is_local {
            // Step 7a: this engine is authoritative for the message; local
            // boots must not be latched at maximum (RFC 3414 Section 2.3),
            // boots must match, and time must be within 150 seconds.
            if !in_authoritative_time_window(
                ctx.engine_boots,
                ctx.engine_time,
                usm_params.engine_boots,
                usm_params.engine_time,
            ) {
                tracing::debug!(target: "async_snmp::v3", { snmp.source = %source, snmp.msg_boots = usm_params.engine_boots, snmp.msg_time = usm_params.engine_time, snmp.our_boots = ctx.engine_boots, snmp.our_time = ctx.engine_time }, "message outside time window");
                // RFC 3414 Section 3.2 Step 7a: the report must be
                // authenticated at authNoPriv so the sender can authenticate
                // the tuple and apply normal Step 7(b) timeliness processing.
                return fail(UsmFailure::NotInTimeWindows, Some(auth_key));
            }
        } else {
            let (remote_engines, max_remote_engines) = role.receiver_config();
            // Step 7b: the sender is the authoritative engine (traps sent
            // under the sender's engine ID), checked against per-engine
            // state seeded from the first authenticated message.
            //
            // Copy the engine ID out of the received datagram so a stored
            // entry does not pin the whole packet buffer.
            let engine_key = Bytes::copy_from_slice(&usm_params.engine_id);
            let timely = {
                let mut engines = remote_engines
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                // Bound the table: a peer holding one credential can
                // authenticate under arbitrarily many fabricated engine
                // IDs, so evict the least-recently-updated engine when
                // full before seeding a new one.
                if !engines.contains_key(&engine_key)
                    && engines.len() >= max_remote_engines
                    && let Some(oldest) = engines
                        .iter()
                        .min_by_key(|(_, state)| state.last_authenticated_update_at())
                        .map(|(k, _)| k.clone())
                {
                    engines.remove(&oldest);
                }
                let state = engines.entry(engine_key).or_insert_with_key(|k| {
                    EngineState::new(k.clone(), usm_params.engine_boots, usm_params.engine_time)
                });
                let timely = state
                    .check_and_update_timeliness(usm_params.engine_boots, usm_params.engine_time);
                if !timely {
                    let (our_boots, our_time) = state.estimated_boots_time();
                    tracing::warn!(target: "async_snmp::v3", { snmp.source = %source, snmp.msg_boots = usm_params.engine_boots, snmp.msg_time = usm_params.engine_time, snmp.our_boots = our_boots, snmp.our_time = our_time }, "message outside time window");
                }
                timely
            };
            if !timely {
                return Ok(V3Inbound::RemoteNotInTimeWindow);
            }
        }
    }

    // RFC 3414 does not assign a failure counter to extra auth/priv fields at
    // a lower requested security level. Receive permissively after all
    // applicable ordered steps have passed: the fields are bounded by the
    // enclosing message limit, ignored, and made observable through tracing.
    let ignored_auth_params = !security_level.requires_auth() && !usm_params.auth_params.is_empty();
    let ignored_priv_params = !security_level.requires_priv() && !usm_params.priv_params.is_empty();
    if ignored_auth_params || ignored_priv_params {
        tracing::debug!(
            target: "async_snmp::v3",
            {
                snmp.source = %source,
                security_level = ?security_level,
                ignored_auth_params,
                auth_params_length = usm_params.auth_params.len(),
                ignored_priv_params,
                priv_params_length = usm_params.priv_params.len(),
            },
            "ignoring USM fields above requested security level"
        );
    }

    // Parse (and for authPriv decrypt) the scoped PDU only after every
    // security check has passed. The msgData form is tied to the received
    // privacy flag by RawV3Message::decode, so the match is total.
    let scoped_outcome = match &msg.msg_data {
        RawMsgData::Encrypted(encrypted_data) => {
            let priv_key = derived_keys
                .priv_key
                .as_ref()
                .expect("authPriv without a privacy key is rejected at Step 5");
            let decrypted = match priv_key.decrypt(
                encrypted_data,
                usm_params.engine_boots,
                usm_params.engine_time,
                &usm_params.priv_params,
            ) {
                Ok(data) => data,
                Err(e) => {
                    tracing::debug!(target: "async_snmp::v3", { source = %source, error = %e }, "decryption failed");
                    return fail(UsmFailure::DecryptionErrors, None);
                }
            };

            decode_scoped_pdu_with_policies(
                decrypted,
                0,
                source,
                Some(priv_key.protocol()),
                ctx.compatibility_policy,
            )?
        }
        RawMsgData::Plaintext { data, offset } => decode_scoped_pdu_with_policies(
            data.clone(),
            *offset,
            source,
            None,
            ctx.compatibility_policy,
        )?,
    };
    decode_anomalies = combine_staged_v3_anomalies(decode_anomalies, scoped_outcome.anomalies);
    let scoped_pdu = scoped_outcome.value;

    Ok(V3Inbound::Message(Box::new(V3InboundMessage {
        global_data: msg.global_data,
        usm_params,
        scoped_pdu,
        security_level,
        derived_keys,
        decode_anomalies,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usm_report_counter_wraps_at_counter32_rollover() {
        let stats = UsmStats::default();
        stats
            .unknown_engine_ids
            .store(u32::MAX - 1, Ordering::Relaxed);

        assert_eq!(stats.count(UsmFailure::UnknownEngineIds), u32::MAX);
        assert_eq!(stats.count(UsmFailure::UnknownEngineIds), 0);
        assert_eq!(stats.unknown_engine_ids.load(Ordering::Relaxed), 0);
    }
    use crate::message::{MsgFlags, MsgGlobalData, V3Message};
    use crate::pdu::{Pdu, PduType};

    fn local_engine_id() -> Bytes {
        Bytes::from_static(b"\x80\x00\x00\x00\x01local")
    }

    fn test_ctx<'a>(
        engine_id: &'a Bytes,
        usm_users: &'a HashMap<Bytes, UsmUser>,
        stats: &'a UsmStats,
        mpd: Option<MpdCounters<'a>>,
    ) -> V3LocalContext<'a> {
        V3LocalContext {
            engine_id,
            engine_boots: 7,
            engine_time: 1000,
            local_receive_capacity: MessageSize::new(8192).unwrap(),
            accepted_receive_size: crate::UDP_RECEIVE_LIMITS.accepted(),
            decode_policy: crate::message::DecodePolicy::Compatible,
            compatibility_policy: crate::CompatibilityPolicy::default(),
            outbound_limit: 8192,
            usm_users,
            stats,
            mpd,
            source: "127.0.0.1:9999".parse().unwrap(),
        }
    }

    /// Build a plaintext noAuthNoPriv V3 message carrying a GetRequest.
    fn build_msg(engine_id: &[u8], username: &[u8], reportable: bool) -> Bytes {
        let global = MsgGlobalData::new(
            1,
            crate::MessageSize::new(65507).unwrap(),
            MsgFlags::new(SecurityLevel::NoAuthNoPriv, reportable),
        )
        .unwrap();
        let usm = if engine_id.is_empty() {
            UsmSecurityParams::discovery()
        } else {
            UsmSecurityParams::new(
                Bytes::copy_from_slice(engine_id),
                7,
                1000,
                Bytes::copy_from_slice(username),
            )
            .unwrap()
        };
        let scoped = ScopedPdu::new(
            Bytes::copy_from_slice(engine_id),
            Bytes::new(),
            Pdu::get_request(42, &[]),
        );
        V3Message::new(global, usm.encode().unwrap(), scoped)
            .unwrap()
            .encode()
            .unwrap()
    }

    /// Build a structurally valid message without applying outbound USM field
    /// relationship validation. This models contradictory peer input for the
    /// RFC 3414 Section 3.2 precedence tests.
    fn build_raw_usm_msg(
        engine_id: &[u8],
        username: &[u8],
        level: SecurityLevel,
        reportable: bool,
        auth_params: &[u8],
        priv_params: &[u8],
    ) -> Bytes {
        let global = MsgGlobalData::new(
            1,
            crate::MessageSize::new(65507).unwrap(),
            MsgFlags::new(level, reportable),
        )
        .unwrap();
        let mut usm = crate::ber::EncodeBuf::new();
        usm.push_sequence(|buf| {
            buf.push_octet_string(priv_params);
            buf.push_octet_string(auth_params);
            buf.push_octet_string(username);
            buf.push_integer(1000);
            buf.push_integer(7);
            buf.push_octet_string(engine_id);
        });

        let mut message = crate::ber::EncodeBuf::new();
        message.push_sequence(|buf| {
            if level.requires_priv() {
                buf.push_octet_string(b"ciphertext");
            } else {
                let scoped = ScopedPdu::new(
                    Bytes::copy_from_slice(engine_id),
                    Bytes::new(),
                    Pdu::get_request(42, &[]),
                )
                .encode_to_bytes()
                .unwrap();
                buf.push_bytes(&scoped);
            }
            buf.push_octet_string(&usm.finish());
            global.encode(buf).unwrap();
            buf.push_integer(3);
        });
        message.finish()
    }

    fn assert_report(
        outcome: V3Inbound,
        expected_failure: UsmFailure,
        expected_oid: Oid,
        expected_count: u32,
    ) {
        let V3Inbound::Failed { failure, report } = outcome else {
            panic!("expected USM failure");
        };
        assert_eq!(failure, expected_failure);
        let report = V3Message::decode(report.expect("reportable failure gets a Report")).unwrap();
        let pdu = report.pdu().expect("failure Report is plaintext");
        assert_eq!(pdu.pdu_type(), PduType::Report);
        assert_eq!(pdu.varbinds.len(), 1);
        assert_eq!(pdu.varbinds[0].oid, expected_oid);
        assert_eq!(
            pdu.varbinds[0].value,
            crate::Value::Counter32(expected_count)
        );
    }

    /// Patch the first occurrence of `pattern` in `data` at `offset` within
    /// the pattern to `value`.
    fn patch(data: &Bytes, pattern: &[u8], offset: usize, value: u8) -> Bytes {
        let mut bytes = data.to_vec();
        let pos = bytes
            .windows(pattern.len())
            .position(|w| w == pattern)
            .expect("pattern not found");
        bytes[pos + offset] = value;
        Bytes::from(bytes)
    }

    /// RFC 3412 Section 7.2.7: msgFlags with priv-without-auth (0x02) is
    /// counted as snmpInvalidMsgs before the message is discarded.
    #[test]
    fn test_invalid_msg_flags_counts_snmp_invalid_msgs() {
        let engine_id = local_engine_id();
        let users = HashMap::new();
        let stats = UsmStats::default();
        let invalid_msgs = AtomicU32::new(0);
        let unknown_models = AtomicU32::new(0);
        let ctx = test_ctx(
            &engine_id,
            &users,
            &stats,
            Some(MpdCounters {
                invalid_msgs: &invalid_msgs,
                unknown_security_models: &unknown_models,
            }),
        );

        // noAuthNoPriv reportable=true encodes msgFlags 0x04; patch to 0x02.
        let data = build_msg(&engine_id, b"user", true);
        let data = patch(&data, &[0x04, 0x01, 0x04], 2, 0x02);

        let result = process_v3_inbound(data, &ctx, &V3Role::Authoritative);
        assert!(result.is_err(), "invalid msgFlags must be discarded");
        assert_eq!(invalid_msgs.load(Ordering::Relaxed), 1);
        assert_eq!(unknown_models.load(Ordering::Relaxed), 0);
    }

    /// RFC 3412 Section 7.2.4: an unrecognized msgSecurityModel is counted
    /// as snmpUnknownSecurityModels before the message is discarded.
    #[test]
    fn test_unknown_security_model_counts_snmp_unknown_security_models() {
        let engine_id = local_engine_id();
        let users = HashMap::new();
        let stats = UsmStats::default();
        let invalid_msgs = AtomicU32::new(0);
        let unknown_models = AtomicU32::new(0);
        let ctx = test_ctx(
            &engine_id,
            &users,
            &stats,
            Some(MpdCounters {
                invalid_msgs: &invalid_msgs,
                unknown_security_models: &unknown_models,
            }),
        );

        // msgSecurityModel INTEGER 3 follows the msgFlags octet string;
        // patch the model to 99.
        let data = build_msg(&engine_id, b"user", true);
        let data = patch(&data, &[0x04, 0x01, 0x04, 0x02, 0x01, 0x03], 5, 99);

        let result = process_v3_inbound(data, &ctx, &V3Role::Authoritative);
        assert!(result.is_err(), "unknown security model must be discarded");
        assert_eq!(unknown_models.load(Ordering::Relaxed), 1);
        assert_eq!(invalid_msgs.load(Ordering::Relaxed), 0);
    }

    /// RFC 3414 Section 4: an empty engine ID is a discovery request and is
    /// answered with a usmStatsUnknownEngineIDs Report carrying the local
    /// engine ID.
    #[test]
    fn test_discovery_produces_unknown_engine_ids_report() {
        let engine_id = local_engine_id();
        let users = HashMap::new();
        let stats = UsmStats::default();
        let ctx = test_ctx(&engine_id, &users, &stats, None);

        let data = V3Message::discovery_request(5, crate::UDP_RECEIVE_LIMITS.advertised())
            .unwrap()
            .encode()
            .unwrap();
        let request = V3Message::decode(data.clone()).unwrap();
        assert_ne!(
            request.global_data.msg_max_size, ctx.local_receive_capacity,
            "test requires distinct requester and local capacities"
        );
        let outcome = process_v3_inbound(data, &ctx, &V3Role::Authoritative).unwrap();

        let V3Inbound::Failed { failure, report } = outcome else {
            panic!("discovery must fail USM processing");
        };
        assert_eq!(failure, UsmFailure::UnknownEngineIds);
        assert_eq!(stats.unknown_engine_ids.load(Ordering::Relaxed), 1);

        let report = V3Message::decode(report.expect("reportable message gets a report")).unwrap();
        assert_eq!(report.global_data.msg_id, 5);
        assert_eq!(
            report.global_data.msg_max_size, 8192,
            "Report must advertise the local receive capacity, not the requester's value"
        );
        let report_usm = UsmSecurityParams::decode(report.security_params.clone()).unwrap();
        assert_eq!(report_usm.engine_id, engine_id);
        assert_eq!(report_usm.engine_boots, 7);
        let pdu = report.pdu().unwrap();
        assert_eq!(pdu.pdu_type(), PduType::Report);
        assert_eq!(pdu.varbinds[0].oid, report_oids::unknown_engine_ids());
    }

    /// RFC 3414 Section 3.2 Step 3 precedes field semantics: even an empty
    /// engine ID carrying auth/priv material at noAuthNoPriv is counted and
    /// reported as unknownEngineID.
    #[test]
    fn empty_engine_id_precedes_contradictory_usm_fields() {
        let engine_id = local_engine_id();
        let users = HashMap::new();
        let stats = UsmStats::default();
        let ctx = test_ctx(&engine_id, &users, &stats, None);
        let data = build_raw_usm_msg(
            b"",
            b"unexpected",
            SecurityLevel::NoAuthNoPriv,
            true,
            b"unexpected-auth",
            b"unexpected-priv",
        );

        let outcome = process_v3_inbound(data, &ctx, &V3Role::Authoritative).unwrap();
        assert_report(
            outcome,
            UsmFailure::UnknownEngineIds,
            report_oids::unknown_engine_ids(),
            1,
        );
        assert_eq!(stats.unknown_engine_ids.load(Ordering::Relaxed), 1);
        assert_eq!(stats.unknown_usernames.load(Ordering::Relaxed), 0);
        assert_eq!(stats.wrong_digests.load(Ordering::Relaxed), 0);
        assert_eq!(stats.decryption_errors.load(Ordering::Relaxed), 0);
    }

    /// The authoritative engine's Step 3 foreign-ID failure likewise wins
    /// over missing fields required by authPriv.
    #[test]
    fn foreign_engine_id_precedes_missing_auth_priv_fields() {
        let engine_id = local_engine_id();
        let users = HashMap::new();
        let stats = UsmStats::default();
        let ctx = test_ctx(&engine_id, &users, &stats, None);
        let data = build_raw_usm_msg(
            b"\x80\x00\x00\x00\x01remote",
            b"nobody",
            SecurityLevel::AuthPriv,
            true,
            b"",
            b"",
        );

        let outcome = process_v3_inbound(data, &ctx, &V3Role::Authoritative).unwrap();
        assert_report(
            outcome,
            UsmFailure::UnknownEngineIds,
            report_oids::unknown_engine_ids(),
            1,
        );
        assert_eq!(stats.unknown_engine_ids.load(Ordering::Relaxed), 1);
        assert_eq!(stats.unknown_usernames.load(Ordering::Relaxed), 0);
        assert_eq!(stats.unsupported_sec_levels.load(Ordering::Relaxed), 0);
        assert_eq!(stats.wrong_digests.load(Ordering::Relaxed), 0);
        assert_eq!(stats.decryption_errors.load(Ordering::Relaxed), 0);
    }

    /// A notification receiver accepts a foreign authoritative engine ID, so
    /// Step 4 unknown-user processing precedes contradictory required fields.
    #[test]
    fn receiver_unknown_user_precedes_missing_auth_priv_fields() {
        let engine_id = local_engine_id();
        let users = HashMap::new();
        let stats = UsmStats::default();
        let ctx = test_ctx(&engine_id, &users, &stats, None);
        let data = build_raw_usm_msg(
            b"\x80\x00\x00\x00\x01remote",
            b"nobody",
            SecurityLevel::AuthPriv,
            true,
            b"",
            b"",
        );
        let remote_engines = Mutex::new(HashMap::new());
        let role = V3Role::Receiver {
            remote_engines: &remote_engines,
            max_remote_engines: 16,
        };

        let outcome = process_v3_inbound(data, &ctx, &role).unwrap();
        assert_report(
            outcome,
            UsmFailure::UnknownUserNames,
            report_oids::unknown_user_names(),
            1,
        );
        assert!(remote_engines.lock().unwrap().is_empty());
        assert_eq!(stats.unknown_engine_ids.load(Ordering::Relaxed), 0);
        assert_eq!(stats.unknown_usernames.load(Ordering::Relaxed), 1);
        assert_eq!(stats.unsupported_sec_levels.load(Ordering::Relaxed), 0);
        assert_eq!(stats.wrong_digests.load(Ordering::Relaxed), 0);
        assert_eq!(stats.decryption_errors.load(Ordering::Relaxed), 0);
    }

    /// RFC 3414 Step 4 wins once the engine ID is local, irrespective of
    /// contradictory security fields.
    #[test]
    fn local_engine_unknown_user_precedes_missing_auth_priv_fields() {
        let engine_id = local_engine_id();
        let users = HashMap::new();
        let stats = UsmStats::default();
        let ctx = test_ctx(&engine_id, &users, &stats, None);
        let data = build_raw_usm_msg(
            &engine_id,
            b"nobody",
            SecurityLevel::AuthPriv,
            true,
            b"",
            b"",
        );

        let outcome = process_v3_inbound(data, &ctx, &V3Role::Authoritative).unwrap();
        assert_report(
            outcome,
            UsmFailure::UnknownUserNames,
            report_oids::unknown_user_names(),
            1,
        );
        assert_eq!(stats.unknown_engine_ids.load(Ordering::Relaxed), 0);
        assert_eq!(stats.unknown_usernames.load(Ordering::Relaxed), 1);
        assert_eq!(stats.unsupported_sec_levels.load(Ordering::Relaxed), 0);
        assert_eq!(stats.wrong_digests.load(Ordering::Relaxed), 0);
        assert_eq!(stats.decryption_errors.load(Ordering::Relaxed), 0);
    }

    /// RFC 3414 Step 5 precedes authentication/privacy field processing.
    #[test]
    fn local_engine_unsupported_level_precedes_missing_auth_priv_fields() {
        let engine_id = local_engine_id();
        let mut users = HashMap::new();
        users.insert(Bytes::from_static(b"user"), UsmUser::new("user"));
        let stats = UsmStats::default();
        let ctx = test_ctx(&engine_id, &users, &stats, None);
        let data = build_raw_usm_msg(&engine_id, b"user", SecurityLevel::AuthPriv, true, b"", b"");

        let outcome = process_v3_inbound(data, &ctx, &V3Role::Authoritative).unwrap();
        assert_report(
            outcome,
            UsmFailure::UnsupportedSecLevels,
            report_oids::unsupported_sec_levels(),
            1,
        );
        assert_eq!(stats.unsupported_sec_levels.load(Ordering::Relaxed), 1);
        assert_eq!(stats.wrong_digests.load(Ordering::Relaxed), 0);
        assert_eq!(stats.decryption_errors.load(Ordering::Relaxed), 0);
    }

    /// At RFC 3414 Step 6, missing authentication material is a wrong digest;
    /// an extra privacy field cannot turn it into an earlier generic error.
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[test]
    fn local_engine_missing_auth_with_extra_priv_counts_wrong_digest() {
        use crate::v3::AuthProtocol;

        let engine_id = local_engine_id();
        let mut users = HashMap::new();
        users.insert(
            Bytes::from_static(b"user"),
            UsmUser::new("user").auth(AuthProtocol::Sha256, b"auth-password"),
        );
        let stats = UsmStats::default();
        let ctx = test_ctx(&engine_id, &users, &stats, None);
        let data = build_raw_usm_msg(
            &engine_id,
            b"user",
            SecurityLevel::AuthNoPriv,
            true,
            b"",
            b"unexpected-priv",
        );

        let outcome = process_v3_inbound(data, &ctx, &V3Role::Authoritative).unwrap();
        assert_report(
            outcome,
            UsmFailure::WrongDigests,
            report_oids::wrong_digests(),
            1,
        );
        assert_eq!(stats.wrong_digests.load(Ordering::Relaxed), 1);
        assert_eq!(stats.decryption_errors.load(Ordering::Relaxed), 0);
    }

    /// An extra bounded privacy field does not invalidate an authNoPriv message
    /// once the required authentication and timeliness checks succeed.
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[test]
    fn authenticated_no_priv_message_permits_extra_privacy_field() {
        use crate::v3::AuthProtocol;

        let engine_id = local_engine_id();
        let user = UsmUser::new("user").auth(AuthProtocol::Sha256, b"auth-password");
        let keys = user.derive_keys(&engine_id).unwrap();
        let auth_key = keys.auth_key.as_ref().unwrap();
        let mut users = HashMap::new();
        users.insert(Bytes::from_static(b"user"), user);
        let stats = UsmStats::default();
        let ctx = test_ctx(&engine_id, &users, &stats, None);
        let mut data = build_raw_usm_msg(
            &engine_id,
            b"user",
            SecurityLevel::AuthNoPriv,
            true,
            &vec![0; auth_key.mac_len()],
            b"ignored-privacy",
        )
        .to_vec();
        let (auth_offset, auth_len) = UsmSecurityParams::find_auth_params_offset(&data).unwrap();
        crate::v3::auth::authenticate_message(auth_key, &mut data, auth_offset, auth_len).unwrap();

        let outcome = process_v3_inbound(data.into(), &ctx, &V3Role::Authoritative).unwrap();
        let V3Inbound::Message(message) = outcome else {
            panic!("valid authNoPriv message with an extra privacy field must be accepted");
        };
        assert_eq!(message.security_level, SecurityLevel::AuthNoPriv);
        assert_eq!(
            message.usm_params.priv_params,
            b"ignored-privacy".as_slice()
        );
        assert_eq!(stats.wrong_digests.load(Ordering::Relaxed), 0);
        assert_eq!(stats.not_in_time_windows.load(Ordering::Relaxed), 0);
        assert_eq!(stats.decryption_errors.load(Ordering::Relaxed), 0);
    }

    /// Once authentication and timeliness pass, malformed required privacy
    /// material is RFC 3414 Step 8 decryptionError.
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[test]
    fn local_engine_malformed_privacy_material_counts_decryption_error() {
        use crate::v3::{AuthProtocol, PrivProtocol};

        let engine_id = local_engine_id();
        let user = UsmUser::new("user").auth_priv(
            AuthProtocol::Sha256,
            b"auth-password",
            PrivProtocol::Aes128,
            b"priv-password",
        );
        let keys = user.derive_keys(&engine_id).unwrap();
        let auth_key = keys.auth_key.as_ref().unwrap();
        let mut users = HashMap::new();
        users.insert(Bytes::from_static(b"user"), user);
        let stats = UsmStats::default();
        let ctx = test_ctx(&engine_id, &users, &stats, None);
        let mut data = build_raw_usm_msg(
            &engine_id,
            b"user",
            SecurityLevel::AuthPriv,
            true,
            &vec![0; auth_key.mac_len()],
            b"bad",
        )
        .to_vec();
        let (auth_offset, auth_len) = UsmSecurityParams::find_auth_params_offset(&data).unwrap();
        crate::v3::auth::authenticate_message(auth_key, &mut data, auth_offset, auth_len).unwrap();

        let outcome = process_v3_inbound(data.into(), &ctx, &V3Role::Authoritative).unwrap();
        assert_report(
            outcome,
            UsmFailure::DecryptionErrors,
            report_oids::decryption_errors(),
            1,
        );
        assert_eq!(stats.wrong_digests.load(Ordering::Relaxed), 0);
        assert_eq!(stats.not_in_time_windows.load(Ordering::Relaxed), 0);
        assert_eq!(stats.decryption_errors.load(Ordering::Relaxed), 1);
    }

    /// Once valid authPriv input reaches scoped-PDU parsing, any structural
    /// failure is measured in decrypted plaintext rather than packet bytes.
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[test]
    fn inbound_decrypted_scoped_pdu_error_uses_plaintext_origin() {
        use crate::error::DecodeErrorOrigin;
        use crate::v3::{AuthProtocol, PrivProtocol, SaltCounter, UsmConfig};

        let engine_id = local_engine_id();
        let user = UsmUser::new("user").auth_priv(
            AuthProtocol::Sha256,
            b"auth-password",
            PrivProtocol::Aes128,
            b"priv-password",
        );
        let security = UsmConfig::new("user").auth_priv(
            AuthProtocol::Sha256,
            b"auth-password",
            PrivProtocol::Aes128,
            b"priv-password",
        );
        let keys = security.derive_keys(&engine_id).unwrap();
        let auth_key = keys.auth_key.as_ref().unwrap();
        let mut users = HashMap::new();
        users.insert(Bytes::from_static(b"user"), user);
        let stats = UsmStats::default();
        let ctx = test_ctx(&engine_id, &users, &stats, None);
        let mut data = crate::v3::encode::encode_v3_message(
            &Pdu::get_request(42, &[]),
            1,
            &engine_id,
            7,
            1000,
            &security,
            Some(&keys),
            Some(&SaltCounter::from_value(1)),
            true,
            crate::UDP_RECEIVE_LIMITS.advertised(),
        )
        .unwrap();
        let raw = RawV3Message::decode(Bytes::copy_from_slice(&data)).unwrap();
        let RawMsgData::Encrypted(ciphertext) = raw.msg_data else {
            panic!("authPriv encoder must produce ciphertext");
        };
        let ciphertext_offset = data
            .windows(ciphertext.len())
            .position(|window| window == ciphertext.as_ref())
            .unwrap();
        data[ciphertext_offset..ciphertext_offset + ciphertext.len()].fill(0);
        let (auth_offset, auth_len) = UsmSecurityParams::find_auth_params_offset(&data).unwrap();
        data[auth_offset..auth_offset + auth_len].fill(0);
        crate::v3::auth::authenticate_message(auth_key, &mut data, auth_offset, auth_len).unwrap();

        let error = match process_v3_inbound(data.into(), &ctx, &V3Role::Authoritative) {
            Err(error) => error,
            Ok(_) => panic!("malformed decrypted scoped PDU must fail"),
        };
        assert!(matches!(&*error, Error::Decode(error)
            if error.origin == DecodeErrorOrigin::DecryptedScopedPdu
                && error.peer == Some(ctx.source)));
    }

    /// Lower-level extra fields have no RFC 3414 failure counter. Once the
    /// ordered engine and user checks pass, bounded extra fields are ignored.
    #[test]
    fn local_no_auth_message_permits_bounded_extra_security_fields() {
        let engine_id = local_engine_id();
        let mut users = HashMap::new();
        users.insert(Bytes::from_static(b"user"), UsmUser::new("user"));
        let stats = UsmStats::default();
        let ctx = test_ctx(&engine_id, &users, &stats, None);
        let data = build_raw_usm_msg(
            &engine_id,
            b"user",
            SecurityLevel::NoAuthNoPriv,
            true,
            b"ignored-auth",
            b"ignored-priv",
        );

        let outcome = process_v3_inbound(data, &ctx, &V3Role::Authoritative).unwrap();
        assert!(matches!(outcome, V3Inbound::Message(_)));
        assert_eq!(stats.unknown_engine_ids.load(Ordering::Relaxed), 0);
        assert_eq!(stats.unknown_usernames.load(Ordering::Relaxed), 0);
        assert_eq!(stats.unsupported_sec_levels.load(Ordering::Relaxed), 0);
        assert_eq!(stats.wrong_digests.load(Ordering::Relaxed), 0);
        assert_eq!(stats.decryption_errors.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn report_exact_limit_minus_one_limit_and_plus_one() {
        let engine_id = local_engine_id();
        let users = HashMap::new();

        let stats = UsmStats::default();
        let ctx = test_ctx(&engine_id, &users, &stats, None);
        let outcome =
            process_v3_inbound(build_msg(b"", b"", true), &ctx, &V3Role::Authoritative).unwrap();
        let V3Inbound::Failed {
            report: Some(report),
            ..
        } = outcome
        else {
            panic!("discovery must produce a Report with the unrestricted limit");
        };
        let exact = report.len();

        for (limit, report_fits) in [(exact - 1, false), (exact, true), (exact + 1, true)] {
            let stats = UsmStats::default();
            let mut ctx = test_ctx(&engine_id, &users, &stats, None);
            ctx.outbound_limit = limit;
            let outcome =
                process_v3_inbound(build_msg(b"", b"", true), &ctx, &V3Role::Authoritative)
                    .unwrap();
            let V3Inbound::Failed { failure, report } = outcome else {
                panic!("discovery must fail USM processing");
            };
            assert_eq!(failure, UsmFailure::UnknownEngineIds);
            assert_eq!(
                report.is_some(),
                report_fits,
                "limit {limit}, exact {exact}"
            );
            assert_eq!(stats.unknown_engine_ids.load(Ordering::Relaxed), 1);
        }
    }

    /// RFC 3412 Section 7.1 Step 3: with reportable=false the counter is
    /// still incremented but no Report is generated.
    #[test]
    fn test_unreportable_failure_counts_without_report() {
        let engine_id = local_engine_id();
        let users = HashMap::new();
        let stats = UsmStats::default();
        let ctx = test_ctx(&engine_id, &users, &stats, None);

        let data = build_msg(&engine_id, b"nobody", false);
        let outcome = process_v3_inbound(data, &ctx, &V3Role::Authoritative).unwrap();

        let V3Inbound::Failed { failure, report } = outcome else {
            panic!("unknown user must fail USM processing");
        };
        assert_eq!(failure, UsmFailure::UnknownUserNames);
        assert!(
            report.is_none(),
            "reportable=false must suppress the report"
        );
        assert_eq!(stats.unknown_usernames.load(Ordering::Relaxed), 1);
    }

    /// RFC 3414 Section 3.2 Step 6 precedes scoped-PDU parsing: a message
    /// whose digest fails must be answered with usmStatsWrongDigests even
    /// when its plaintext scoped PDU is malformed garbage. Parsing the
    /// plaintext before authentication would turn this into a bare decode
    /// error and skip the counter and Report.
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[test]
    fn test_wrong_digest_reported_before_plaintext_pdu_parse() {
        use crate::ber::EncodeBuf;
        use crate::v3::AuthProtocol;

        let engine_id = local_engine_id();
        let mut users = HashMap::new();
        users.insert(
            Bytes::from_static(b"user"),
            UsmUser::new("user").auth(AuthProtocol::Sha1, "authpass12345678"),
        );
        let stats = UsmStats::default();
        let ctx = test_ctx(&engine_id, &users, &stats, None);

        let usm = UsmSecurityParams::new(engine_id.clone(), 7, 1000, Bytes::from_static(b"user"))
            .unwrap()
            .with_auth_params(vec![0xAA; 12])
            .unwrap(); // not a valid HMAC
        let mut buf = EncodeBuf::new();
        buf.push_sequence(|buf| {
            // msgData: SEQUENCE TLV wrapping garbage, not a parsable ScopedPDU
            buf.push_sequence(|buf| {
                buf.push_bytes(&[0xDE, 0xAD, 0xBE, 0xEF]);
            });
            buf.push_octet_string(&usm.encode().unwrap());
            crate::message::MsgGlobalData::new(
                1,
                crate::MessageSize::new(65507).unwrap(),
                MsgFlags::new(SecurityLevel::AuthNoPriv, true),
            )
            .unwrap()
            .encode(buf)
            .unwrap();
            buf.push_integer(3);
        });
        let data = buf.finish();

        let outcome = process_v3_inbound(data, &ctx, &V3Role::Authoritative).unwrap();
        let V3Inbound::Failed { failure, report } = outcome else {
            panic!("failed authentication must be a USM failure, not a decode error");
        };
        assert_eq!(failure, UsmFailure::WrongDigests);
        assert!(report.is_some(), "reportable message gets a report");
        assert_eq!(stats.wrong_digests.load(Ordering::Relaxed), 1);
    }

    fn build_raw_msg_with_engine_id(engine_id: &[u8]) -> Bytes {
        let global = MsgGlobalData::new(
            1,
            crate::MessageSize::new(65507).unwrap(),
            MsgFlags::new(SecurityLevel::NoAuthNoPriv, true),
        )
        .unwrap();
        let scoped = ScopedPdu::new(
            Bytes::copy_from_slice(engine_id),
            Bytes::new(),
            Pdu::get_request(42, &[]),
        )
        .encode_to_bytes()
        .unwrap();
        let mut usm = crate::ber::EncodeBuf::new();
        usm.push_sequence(|buf| {
            buf.push_octet_string(&[]);
            buf.push_octet_string(&[]);
            buf.push_octet_string(b"user");
            buf.push_integer(0);
            buf.push_integer(0);
            buf.push_octet_string(engine_id);
        });
        let mut message = crate::ber::EncodeBuf::new();
        message.push_sequence(|buf| {
            buf.push_bytes(&scoped);
            buf.push_octet_string(&usm.finish());
            global.encode(buf).unwrap();
            buf.push_integer(3);
        });
        message.finish()
    }

    #[test]
    fn invalid_engine_ids_are_rejected_before_role_lookup_or_state() {
        let engine_id = local_engine_id();
        let users = HashMap::new();
        let stats = UsmStats::default();
        let ctx = test_ctx(&engine_id, &users, &stats, None);
        let remote_engines = Mutex::new(HashMap::new());
        let receiver = V3Role::Receiver {
            remote_engines: &remote_engines,
            max_remote_engines: 16,
        };

        for invalid in [
            b"abcd".as_slice(),
            [0_u8; 8].as_slice(),
            [0xff_u8; 8].as_slice(),
            [1_u8; 33].as_slice(),
        ] {
            for role in [&V3Role::Authoritative, &receiver] {
                let outcome =
                    process_v3_inbound(build_raw_msg_with_engine_id(invalid), &ctx, role).unwrap();
                let V3Inbound::Failed { failure, .. } = outcome else {
                    panic!("invalid engine ID must fail before role processing");
                };
                assert_eq!(failure, UsmFailure::UnknownEngineIds);
            }
        }
        assert!(remote_engines.lock().unwrap().is_empty());
        assert_eq!(stats.unknown_usernames.load(Ordering::Relaxed), 0);
        assert_eq!(stats.unknown_engine_ids.load(Ordering::Relaxed), 8);
    }

    /// RFC 3414 Section 3.2 Step 3: the authoritative role rejects messages
    /// under a foreign engine ID; the receiver role defers them to Step 7b
    /// (and accepts unauthenticated ones).
    #[test]
    fn test_foreign_engine_id_role_split() {
        let engine_id = local_engine_id();
        let mut users = HashMap::new();
        users.insert(Bytes::from_static(b"user"), UsmUser::new("user"));
        let stats = UsmStats::default();
        let ctx = test_ctx(&engine_id, &users, &stats, None);

        let data = build_msg(b"\x80\x00\x00\x00\x01remote", b"user", true);

        let outcome = process_v3_inbound(data.clone(), &ctx, &V3Role::Authoritative).unwrap();
        let V3Inbound::Failed { failure, .. } = outcome else {
            panic!("authoritative role must reject a foreign engine ID");
        };
        assert_eq!(failure, UsmFailure::UnknownEngineIds);

        let remote_engines = Mutex::new(HashMap::new());
        let role = V3Role::Receiver {
            remote_engines: &remote_engines,
            max_remote_engines: 16,
        };
        let outcome = process_v3_inbound(data, &ctx, &role).unwrap();
        assert!(
            matches!(outcome, V3Inbound::Message(_)),
            "receiver role must accept a noAuthNoPriv message under a remote engine ID"
        );
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[test]
    fn keyed_inbound_users_accept_supported_lower_security_levels() {
        use crate::v3::{AuthProtocol, PrivProtocol, UsmConfig};

        let engine_id = local_engine_id();
        for user in [
            UsmUser::new("user").auth(AuthProtocol::Sha256, b"auth-password"),
            UsmUser::new("user").auth_priv(
                AuthProtocol::Sha256,
                b"auth-password",
                PrivProtocol::Aes128,
                b"priv-password",
            ),
        ] {
            let mut users = HashMap::new();
            users.insert(Bytes::from_static(b"user"), user);
            let stats = UsmStats::default();
            let ctx = test_ctx(&engine_id, &users, &stats, None);
            let outcome = process_v3_inbound(
                build_msg(&engine_id, b"user", true),
                &ctx,
                &V3Role::Authoritative,
            )
            .unwrap();
            let V3Inbound::Message(message) = outcome else {
                panic!("supported lower security level must be accepted");
            };
            assert_eq!(message.security_level, SecurityLevel::NoAuthNoPriv);
            assert_eq!(stats.unsupported_sec_levels.load(Ordering::Relaxed), 0);
        }

        let inbound_user = UsmUser::new("user").auth_priv(
            AuthProtocol::Sha256,
            b"auth-password",
            PrivProtocol::Aes128,
            b"priv-password",
        );
        let mut users = HashMap::new();
        users.insert(Bytes::from_static(b"user"), inbound_user);
        let outbound = UsmConfig::new("user").auth(AuthProtocol::Sha256, b"auth-password");
        let keys = outbound.derive_keys(&engine_id).unwrap();
        let data = crate::v3::encode::encode_v3_message(
            &Pdu::get_request(42, &[]),
            1,
            &engine_id,
            7,
            1000,
            &outbound,
            Some(&keys),
            None,
            true,
            crate::UDP_RECEIVE_LIMITS.advertised(),
        )
        .unwrap();
        let stats = UsmStats::default();
        let ctx = test_ctx(&engine_id, &users, &stats, None);
        let outcome = process_v3_inbound(data.into(), &ctx, &V3Role::Authoritative).unwrap();
        let V3Inbound::Message(message) = outcome else {
            panic!("authPriv-capable user must accept authNoPriv");
        };
        assert_eq!(message.security_level, SecurityLevel::AuthNoPriv);
        assert_eq!(stats.unsupported_sec_levels.load(Ordering::Relaxed), 0);
    }
}
