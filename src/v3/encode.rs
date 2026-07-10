//! V3 message encoding.
//!
//! Standalone V3 message building used by both the client and agent.
//! Takes explicit parameters rather than reading from a specific owner's state.

use std::net::SocketAddr;

use bytes::Bytes;

use crate::error::internal::{AuthErrorKind, CryptoErrorKind, EncodeErrorKind};
use crate::error::{Error, Result};
use crate::message::{MsgFlags, MsgGlobalData, ScopedPdu, SecurityLevel, V3Message, V3MessageData};
use crate::notification::{DerivedKeys, UsmConfig};
use crate::oid::Oid;
use crate::pdu::{Pdu, PduType};
use crate::v3::auth::authenticate_message;
use crate::v3::{LocalizedKey, SaltCounter, UsmSecurityParams};
use crate::value::Value;
use crate::varbind::VarBind;

/// Build and encode a V3 message with authentication and/or encryption.
///
/// This is the shared encoding path used by both `Client` (for requests and
/// traps) and `Agent` (for trap sink sending). All inputs are explicit so
/// callers can supply engine state, keys, and salt counters from whatever
/// context they own.
///
/// # Parameters
///
/// - `pdu` - The PDU to encode
/// - `msg_id` - Message ID (separate from `pdu.request_id` per RFC 3412 Section 6.2)
/// - `engine_id` - Authoritative engine ID (sender's for traps, receiver's for requests)
/// - `engine_boots` - Current engine boots value
/// - `engine_time` - Current engine time value
/// - `security` - USM security configuration (username, context, security level)
/// - `derived_keys` - Keys derived against `engine_id`
/// - `salt_counter` - Salt counter for encryption IV generation
/// - `reportable` - Whether the receiver should send Report PDUs on error
/// - `msg_max_size` - Maximum message size to advertise
#[allow(clippy::too_many_arguments)]
pub fn encode_v3_message(
    pdu: &Pdu,
    msg_id: i32,
    engine_id: &[u8],
    engine_boots: u32,
    engine_time: u32,
    security: &UsmConfig,
    derived_keys: Option<&DerivedKeys>,
    salt_counter: &SaltCounter,
    reportable: bool,
    msg_max_size: u32,
) -> Result<Vec<u8>> {
    let security_level = security.security_level();

    // Build scoped PDU
    let scoped_pdu = ScopedPdu::new(
        Bytes::copy_from_slice(engine_id),
        security.context_name.clone(),
        pdu.clone(),
    );

    // Handle encryption if needed
    let (msg_data, priv_params) = if security_level.requires_priv() {
        let priv_key = derived_keys
            .and_then(|d| d.priv_key.as_ref())
            .ok_or_else(|| Error::Config("privacy key not available".into()).boxed())?;

        let scoped_pdu_bytes = scoped_pdu.encode_to_bytes();
        let (ciphertext, salt) = priv_key
            .encrypt(
                &scoped_pdu_bytes,
                engine_boots,
                engine_time,
                Some(salt_counter),
            )
            .map_err(|e| Error::Config(e.to_string().into()).boxed())?;

        (V3MessageData::Encrypted(ciphertext), salt)
    } else {
        (V3MessageData::Plaintext(scoped_pdu), Bytes::new())
    };

    // Resolve auth key if authentication is required.
    let auth_key = if security_level.requires_auth() {
        Some(
            derived_keys
                .and_then(|d| d.auth_key.as_ref())
                .ok_or_else(|| Error::Config("auth key not available".into()).boxed())?,
        )
    } else {
        None
    };

    // Build USM security parameters
    let mut usm_params = UsmSecurityParams::new(
        Bytes::copy_from_slice(engine_id),
        engine_boots,
        engine_time,
        security.username.clone(),
    );

    if let Some(key) = &auth_key {
        usm_params = usm_params.with_auth_placeholder(key.mac_len());
    }

    if security_level.requires_priv() {
        usm_params = usm_params.with_priv_params(priv_params);
    }

    let usm_encoded = usm_params.encode();

    // Build global data
    let msg_flags = MsgFlags::new(security_level, reportable);
    let global_data = MsgGlobalData::new(msg_id, msg_max_size as i32, msg_flags);

    // Build complete message
    let msg = match msg_data {
        V3MessageData::Plaintext(scoped_pdu) => {
            V3Message::new(global_data, usm_encoded, scoped_pdu)
        }
        V3MessageData::Encrypted(ciphertext) => {
            V3Message::new_encrypted(global_data, usm_encoded, ciphertext)
        }
    };

    let mut encoded = msg.encode().to_vec();

    // Apply authentication if needed
    if let Some(key) = &auth_key {
        if let Some((offset, len)) = UsmSecurityParams::find_auth_params_offset(&encoded) {
            authenticate_message(key, &mut encoded, offset, len)
                .map_err(|e| Error::Config(e.to_string().into()).boxed())?;
        } else {
            return Err(Error::Config("could not find auth params position".into()).boxed());
        }
    }

    Ok(encoded)
}

/// Fill in the HMAC of an encoded V3 message built with an auth placeholder.
///
/// `target` is only used as the error's target address.
pub(crate) fn sign_v3_message(
    auth_key: &LocalizedKey,
    message: &mut [u8],
    target: SocketAddr,
) -> Result<()> {
    let (auth_offset, auth_len) =
        UsmSecurityParams::find_auth_params_offset(message).ok_or_else(|| {
            tracing::debug!(target: "async_snmp::v3", { kind = %EncodeErrorKind::MissingAuthParams }, "could not find auth params in outgoing V3 message");
            Error::MalformedResponse { target }.boxed()
        })?;
    authenticate_message(auth_key, message, auth_offset, auth_len).map_err(|e| {
        tracing::debug!(target: "async_snmp::v3", { error = %e }, "failed to authenticate outgoing V3 message");
        Error::Config(e.to_string().into()).boxed()
    })
}

/// Build and encode a V3 Report message (RFC 3412 Section 7.1 Step 3).
///
/// Shared by the agent and the notification receiver. `usm` carries the
/// responder's engine ID/boots/time and echoes the requester's username;
/// `msg_id` and `msg_max_size` echo the incoming message header. With
/// `auth_key` the report is sent authenticated at authNoPriv, as RFC 3414
/// Section 3.2 Step 7a requires for notInTimeWindows reports so the sender
/// can trust the boots/time for resynchronization. Otherwise noAuthNoPriv.
///
/// The reportableFlag check (whether a report may be sent at all) is the
/// caller's responsibility.
pub(crate) fn encode_v3_report(
    msg_id: i32,
    msg_max_size: i32,
    usm: UsmSecurityParams,
    report_oid: Oid,
    counter_value: u32,
    auth_key: Option<&LocalizedKey>,
    target: SocketAddr,
) -> Result<Bytes> {
    // RFC 3412 Section 7.1 Step 3c4: request-id is the value extracted from the
    // original request PDU, or 0 when it cannot be extracted. Every USM-failure
    // path reaches here before the scopedPDU is decoded, so it cannot be
    // extracted. (msgID, which correlates the Report, is carried separately in
    // the header.)
    let report_pdu = Pdu {
        pdu_type: PduType::Report,
        request_id: 0,
        error_status: 0,
        error_index: 0,
        varbinds: vec![VarBind::new(report_oid, Value::Counter32(counter_value))],
    };

    let security_level = if auth_key.is_some() {
        SecurityLevel::AuthNoPriv
    } else {
        SecurityLevel::NoAuthNoPriv
    };
    let global = MsgGlobalData::new(msg_id, msg_max_size, MsgFlags::new(security_level, false));

    let scoped = ScopedPdu::new(usm.engine_id.clone(), Bytes::new(), report_pdu);

    let usm = match auth_key {
        Some(key) => usm.with_auth_placeholder(key.mac_len()),
        None => usm,
    };
    let msg = V3Message::new(global, usm.encode(), scoped);

    match auth_key {
        Some(key) => {
            let mut bytes = msg.encode().to_vec();
            sign_v3_message(key, &mut bytes, target)?;
            Ok(Bytes::from(bytes))
        }
        None => Ok(msg.encode()),
    }
}

/// Build and encode a V3 Response message at the incoming security level.
///
/// Shared by the agent and the notification receiver (Inform acks). `usm`
/// carries the authoritative engine ID/boots/time the response will claim
/// and echoes the requester's username; `msg_id`, `msg_max_size`, and
/// `security_level` echo the incoming message header. Encryption (authPriv)
/// uses the boots/time already present in `usm`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn encode_v3_response(
    response_pdu: Pdu,
    msg_id: i32,
    msg_max_size: i32,
    security_level: SecurityLevel,
    usm: UsmSecurityParams,
    context_engine_id: Bytes,
    context_name: Bytes,
    derived_keys: Option<&DerivedKeys>,
    salt_counter: &SaltCounter,
    target: SocketAddr,
) -> Result<Bytes> {
    // Same security level as the request, but reportable=false
    let global = MsgGlobalData::new(msg_id, msg_max_size, MsgFlags::new(security_level, false));
    let scoped = ScopedPdu::new(context_engine_id, context_name, response_pdu);

    match security_level {
        SecurityLevel::NoAuthNoPriv => Ok(V3Message::new(global, usm.encode(), scoped).encode()),
        SecurityLevel::AuthNoPriv => {
            let (_, auth_key) = require_auth_key(derived_keys, target)?;
            let usm = usm.with_auth_placeholder(auth_key.mac_len());
            let mut bytes = V3Message::new(global, usm.encode(), scoped)
                .encode()
                .to_vec();
            sign_v3_message(auth_key, &mut bytes, target)?;
            Ok(Bytes::from(bytes))
        }
        SecurityLevel::AuthPriv => {
            let (keys, auth_key) = require_auth_key(derived_keys, target)?;
            let priv_key = keys.priv_key.as_ref().ok_or_else(|| {
                tracing::debug!(target: "async_snmp::v3", { kind = %CryptoErrorKind::NoPrivKey }, "no privacy key for response");
                Error::Auth { target }.boxed()
            })?;

            let scoped_pdu_bytes = scoped.encode_to_bytes();
            let (encrypted, priv_params) = priv_key
                .encrypt(
                    &scoped_pdu_bytes,
                    usm.engine_boots,
                    usm.engine_time,
                    Some(salt_counter),
                )
                .map_err(|e| {
                    tracing::debug!(target: "async_snmp::v3", { error = %e }, "encryption failed for response");
                    Error::Auth { target }.boxed()
                })?;

            let usm = usm
                .with_auth_placeholder(auth_key.mac_len())
                .with_priv_params(priv_params);
            let mut bytes = V3Message::new_encrypted(global, usm.encode(), encrypted)
                .encode()
                .to_vec();
            sign_v3_message(auth_key, &mut bytes, target)?;
            Ok(Bytes::from(bytes))
        }
    }
}

/// Validate `derived_keys` and return them along with the auth key.
fn require_auth_key(
    derived_keys: Option<&DerivedKeys>,
    target: SocketAddr,
) -> Result<(&DerivedKeys, &LocalizedKey)> {
    let keys = derived_keys.ok_or_else(|| {
        tracing::debug!(target: "async_snmp::v3", { kind = %AuthErrorKind::NoCredentials }, "no credentials for response");
        Error::Auth { target }.boxed()
    })?;
    let auth_key = keys.auth_key.as_ref().ok_or_else(|| {
        tracing::debug!(target: "async_snmp::v3", { kind = %AuthErrorKind::NoAuthKey }, "no auth key for response");
        Error::Auth { target }.boxed()
    })?;
    Ok((keys, auth_key))
}
