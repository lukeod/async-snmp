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

use crate::ber::Decoder;
use crate::error::internal::DecodeErrorKind;
use crate::error::{Error, Result};
use crate::message::{ScopedPdu, SecurityLevel, V3Message, V3MessageData};
use crate::notification::{DerivedKeys, UsmConfig};
use crate::oid::Oid;
use crate::v3::auth::verify_message;
use crate::v3::encode::encode_v3_report;
use crate::v3::{
    EngineState, LocalizedKey, UsmSecurityParams, in_authoritative_time_window, report_oids,
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
        self.counter(failure).fetch_add(1, Ordering::Relaxed) + 1
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

/// Local engine identity, user table, and counters for USM processing.
pub(crate) struct V3LocalContext<'a> {
    pub(crate) engine_id: &'a Bytes,
    pub(crate) engine_boots: u32,
    pub(crate) engine_time: u32,
    pub(crate) usm_users: &'a HashMap<Bytes, UsmConfig>,
    pub(crate) stats: &'a UsmStats,
    pub(crate) mpd: Option<MpdCounters<'a>>,
    pub(crate) source: SocketAddr,
}

/// A fully USM-processed inbound message.
pub(crate) struct V3InboundMessage {
    pub(crate) msg: V3Message,
    pub(crate) usm_params: UsmSecurityParams,
    pub(crate) scoped_pdu: ScopedPdu,
    pub(crate) security_level: SecurityLevel,
    pub(crate) derived_keys: Option<DerivedKeys>,
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

    let msg = match V3Message::decode(data.clone()) {
        Ok(msg) => msg,
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
    let security_level = msg.global_data.msg_flags.security_level;
    let usm_params = UsmSecurityParams::decode(msg.security_params.clone())?;

    // Encodes the Report for `failure` (counting it first), unauthenticated
    // unless `auth_key` is given (notInTimeWindows, RFC 3414 3.2 Step 7a).
    let fail = |failure: UsmFailure, auth_key: Option<&LocalizedKey>| -> Result<V3Inbound> {
        let count = ctx.stats.count(failure);
        // RFC 3412 Section 7.1 Step 3: a Report may only be sent when the
        // PDU is Confirmed Class or, when the PDU class cannot be determined
        // (the case here: the message failed USM processing), when the
        // reportableFlag is set.
        let report = if msg.global_data.msg_flags.reportable {
            Some(encode_v3_report(
                msg.global_data.msg_id,
                msg.global_data.msg_max_size,
                UsmSecurityParams::new(
                    ctx.engine_id.clone(),
                    ctx.engine_boots,
                    ctx.engine_time,
                    usm_params.username.clone(),
                ),
                failure.report_oid(),
                count,
                auth_key,
                source,
            )?)
        } else {
            None
        };
        Ok(V3Inbound::Failed { failure, report })
    };

    // RFC 3414 Section 3.2 Step 3: engine-ID handling. An empty engine ID is
    // a discovery request (RFC 3414 Section 4); both cases answer with
    // usmStatsUnknownEngineIDs.
    if usm_params.engine_id.is_empty() {
        return fail(UsmFailure::UnknownEngineIds, None);
    }
    let engine_is_local = usm_params.engine_id == *ctx.engine_id;
    if matches!(role, V3Role::Authoritative) && !engine_is_local {
        tracing::debug!(target: "async_snmp::v3", { snmp.source = %source }, "engine ID mismatch");
        return fail(UsmFailure::UnknownEngineIds, None);
    }

    // RFC 3414 Section 3.2 Step 4: the user must exist in the local user
    // database regardless of security level.
    let Some(user_config) = ctx.usm_users.get(&usm_params.username) else {
        tracing::debug!(target: "async_snmp::v3", { snmp.source = %source, snmp.username = %String::from_utf8_lossy(&usm_params.username) }, "unknown user");
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
            tracing::debug!(target: "async_snmp::v3", { snmp.source = %source, snmp.username = %String::from_utf8_lossy(&usm_params.username) }, "user does not support requested security level");
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
        let (auth_offset, auth_len) =
            UsmSecurityParams::find_auth_params_offset(&data).ok_or_else(|| {
                tracing::debug!(target: "async_snmp::v3", { source = %source }, "could not find auth params in message");
                Error::Auth { target: source }.boxed()
            })?;
        if !verify_message(auth_key, &data, auth_offset, auth_len)
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
                // authenticated at authNoPriv so the sender can trust the
                // boots/time for resynchronization.
                return fail(UsmFailure::NotInTimeWindows, Some(auth_key));
            }
        } else if let V3Role::Receiver {
            remote_engines,
            max_remote_engines,
        } = role
        {
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
                    && engines.len() >= *max_remote_engines
                    && let Some(oldest) = engines
                        .iter()
                        .min_by_key(|(_, s)| s.synced_at)
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
                    tracing::warn!(target: "async_snmp::v3", { snmp.source = %source, snmp.msg_boots = usm_params.engine_boots, snmp.msg_time = usm_params.engine_time, snmp.our_boots = state.engine_boots, snmp.our_time = state.estimated_time() }, "message outside time window");
                }
                timely
            };
            if !timely {
                return Ok(V3Inbound::RemoteNotInTimeWindow);
            }
        }
    }

    // Decrypt if needed. Key presence was checked at Step 5.
    let scoped_pdu = if security_level == SecurityLevel::AuthPriv {
        let priv_key = derived_keys
            .priv_key
            .as_ref()
            .expect("authPriv without a privacy key is rejected at Step 5");
        let encrypted_data = match &msg.data {
            V3MessageData::Encrypted(data) => data,
            V3MessageData::Plaintext(_) => {
                tracing::debug!(target: "async_snmp::v3", { source = %source, kind = %DecodeErrorKind::ExpectedEncryption }, "expected encrypted scoped PDU");
                return Err(Error::MalformedResponse { target: source }.boxed());
            }
        };

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

        let mut decoder = Decoder::with_target(decrypted, source);
        ScopedPdu::decode(&mut decoder)?
    } else if let Some(sp) = msg.scoped_pdu() {
        sp.clone()
    } else {
        tracing::debug!(target: "async_snmp::v3", { source = %source, kind = %DecodeErrorKind::UnexpectedEncryption }, "unexpected encrypted scoped PDU");
        return Err(Error::MalformedResponse { target: source }.boxed());
    };

    Ok(V3Inbound::Message(Box::new(V3InboundMessage {
        msg,
        usm_params,
        scoped_pdu,
        security_level,
        derived_keys: Some(derived_keys),
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{MsgFlags, MsgGlobalData, V3Message};
    use crate::pdu::{Pdu, PduType};

    fn local_engine_id() -> Bytes {
        Bytes::from_static(b"\x80\x00\x00\x00\x01local")
    }

    fn test_ctx<'a>(
        engine_id: &'a Bytes,
        usm_users: &'a HashMap<Bytes, UsmConfig>,
        stats: &'a UsmStats,
        mpd: Option<MpdCounters<'a>>,
    ) -> V3LocalContext<'a> {
        V3LocalContext {
            engine_id,
            engine_boots: 7,
            engine_time: 1000,
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
            65507,
            MsgFlags::new(SecurityLevel::NoAuthNoPriv, reportable),
        );
        let usm = UsmSecurityParams::new(
            Bytes::copy_from_slice(engine_id),
            7,
            1000,
            Bytes::copy_from_slice(username),
        );
        let scoped = ScopedPdu::new(
            Bytes::copy_from_slice(engine_id),
            Bytes::new(),
            Pdu::get_request(42, &[]),
        );
        V3Message::new(global, usm.encode(), scoped).encode()
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

        let data = V3Message::discovery_request(5).encode();
        let outcome = process_v3_inbound(data, &ctx, &V3Role::Authoritative).unwrap();

        let V3Inbound::Failed { failure, report } = outcome else {
            panic!("discovery must fail USM processing");
        };
        assert_eq!(failure, UsmFailure::UnknownEngineIds);
        assert_eq!(stats.unknown_engine_ids.load(Ordering::Relaxed), 1);

        let report = V3Message::decode(report.expect("reportable message gets a report")).unwrap();
        assert_eq!(report.global_data.msg_id, 5);
        let report_usm = UsmSecurityParams::decode(report.security_params.clone()).unwrap();
        assert_eq!(report_usm.engine_id, engine_id);
        assert_eq!(report_usm.engine_boots, 7);
        let pdu = report.pdu().unwrap();
        assert_eq!(pdu.pdu_type, PduType::Report);
        assert_eq!(pdu.varbinds[0].oid, report_oids::unknown_engine_ids());
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
        assert!(report.is_none(), "reportable=false must suppress the report");
        assert_eq!(stats.unknown_usernames.load(Ordering::Relaxed), 1);
    }

    /// RFC 3414 Section 3.2 Step 3: the authoritative role rejects messages
    /// under a foreign engine ID; the receiver role defers them to Step 7b
    /// (and accepts unauthenticated ones).
    #[test]
    fn test_foreign_engine_id_role_split() {
        let engine_id = local_engine_id();
        let mut users = HashMap::new();
        users.insert(Bytes::from_static(b"user"), UsmConfig::new("user"));
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
}
