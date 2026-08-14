//! V3 message encoding.
//!
//! Standalone V3 message building used by both the client and agent.
//! Takes explicit parameters rather than reading from a specific owner's state.

use std::net::SocketAddr;

use bytes::Bytes;

use super::{DerivedKeys, UsmConfig};
use crate::error::internal::{AuthErrorKind, CryptoErrorKind, EncodeErrorKind};
use crate::error::{Error, Result};
use crate::message::{MsgFlags, MsgGlobalData, ScopedPdu, SecurityLevel, V3Message, V3MessageData};
use crate::message_size::MessageSize;
use crate::oid::Oid;
use crate::pdu::{Pdu, ResponsePdu};
use crate::v3::auth::authenticate_message;
use crate::v3::{
    DesSaltState, LocalizedKey, PrivProtocol, PrivacyEncryptContext, SaltCounter, UsmSecurityParams,
};
use crate::value::Value;
use crate::varbind::VarBind;

/// Build and encode a V3 message with authentication and/or encryption.
///
/// This is the shared encoding path used by both `Client` (for requests and
/// traps) and `Agent` (for trap sink sending). All inputs are explicit so
/// callers can supply engine state, keys, and sender state from whatever
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
/// - `salt_counter` - AES-only salt counter; required for AES `authPriv`
/// - `des_salt_state` - Durable DES/3DES sender state; required for DES-family
///   `authPriv`
/// - `des_generating_engine_boots` - Current local generating-engine boots for
///   DES/3DES. This is intentionally separate from the authoritative
///   `engine_boots` used by USM and AES.
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
    salt_counter: Option<&SaltCounter>,
    des_salt_state: Option<&DesSaltState>,
    des_generating_engine_boots: Option<u32>,
    reportable: bool,
    msg_max_size: MessageSize,
) -> Result<Vec<u8>> {
    let security_level = security.security_level();

    let privacy_context = if security_level.requires_priv() {
        let priv_key = derived_keys
            .and_then(|d| d.priv_key.as_ref())
            .ok_or_else(|| Error::Config("privacy key not available".into()).boxed())?;
        Some(match priv_key.protocol() {
            PrivProtocol::Des | PrivProtocol::Des3 => {
                let state = des_salt_state.ok_or_else(|| {
                    Error::Config(
                        "durable DES sender state is required for DES/3DES privacy".into(),
                    )
                    .boxed()
                })?;
                let generating_engine_boots = des_generating_engine_boots.ok_or_else(|| {
                    Error::Config(
                        "local generating-engine boots are required for DES/3DES privacy".into(),
                    )
                    .boxed()
                })?;
                state
                    .validate_generating_engine_boots(generating_engine_boots)
                    .map_err(|error| Error::Privacy(error).boxed())?;
                PrivacyEncryptContext::Des(
                    state
                        .reserve()
                        .map_err(|error| Error::Privacy(error).boxed())?,
                )
            }
            _ => PrivacyEncryptContext::Aes {
                engine_boots,
                engine_time,
                salt_counter: salt_counter.ok_or_else(|| {
                    Error::Config("AES privacy salt counter not initialized".into()).boxed()
                })?,
            },
        })
    } else {
        None
    };

    // Build scoped PDU after DES allocation so any later failure burns it.
    let scoped_pdu = ScopedPdu::new(
        Bytes::copy_from_slice(engine_id),
        security.configured_context_name().clone(),
        pdu.clone(),
    );

    // Handle encryption if needed
    let (msg_data, priv_params) = if security_level.requires_priv() {
        let priv_key = derived_keys
            .and_then(|d| d.priv_key.as_ref())
            .ok_or_else(|| Error::Config("privacy key not available".into()).boxed())?;
        let scoped_pdu_bytes = scoped_pdu.encode_to_bytes()?;
        let (ciphertext, salt) = priv_key
            .encrypt_with_context(
                &scoped_pdu_bytes,
                privacy_context.expect("privacy context prepared for authPriv"),
            )
            .map_err(|error| Error::Privacy(error).boxed())?;

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
        security.username().clone(),
    )?;

    if let Some(key) = &auth_key {
        usm_params = usm_params.with_auth_placeholder(key.mac_len())?;
    }

    if security_level.requires_priv() {
        usm_params = usm_params.with_priv_params(priv_params)?;
    }

    let usm_encoded = usm_params.encode()?;

    // Build global data
    let msg_flags = MsgFlags::new(security_level, reportable);
    let global_data = MsgGlobalData::new(msg_id, msg_max_size, msg_flags)?;

    // Build complete message
    let msg = match msg_data {
        V3MessageData::Plaintext(scoped_pdu) => {
            V3Message::new(global_data, usm_encoded, scoped_pdu)?
        }
        V3MessageData::Encrypted(ciphertext) => {
            V3Message::new_with_opaque_encrypted_scoped_pdu(global_data, usm_encoded, ciphertext)?
        }
    };

    let mut encoded = msg.encode()?.to_vec();

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
            Error::InvalidMessage(
                format!("could not locate authentication parameters for {target}").into(),
            )
            .boxed()
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
/// `msg_id` correlates the incoming message, while `local_receive_capacity`
/// advertises the Report sender's own receive capability. With `auth_key` the
/// report is sent authenticated at authNoPriv, as RFC 3414 Section 3.2 Step 7a
/// requires for notInTimeWindows reports so the sender can authenticate the
/// tuple and apply normal Step 7(b) timeliness processing. Otherwise it is
/// noAuthNoPriv.
///
/// The reportableFlag check (whether a report may be sent at all) is the
/// caller's responsibility.
pub(crate) fn encode_v3_report(
    msg_id: i32,
    local_receive_capacity: MessageSize,
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
    let report_pdu = ResponsePdu::report(
        0,
        vec![VarBind::new(report_oid, Value::Counter32(counter_value))],
    )?
    .into_raw();

    let security_level = if auth_key.is_some() {
        SecurityLevel::AuthNoPriv
    } else {
        SecurityLevel::NoAuthNoPriv
    };
    let global = MsgGlobalData::new(
        msg_id,
        local_receive_capacity,
        MsgFlags::new(security_level, false),
    )?;

    let scoped = ScopedPdu::new(usm.engine_id.clone(), Bytes::new(), report_pdu);

    let usm = match auth_key {
        Some(key) => usm.with_auth_placeholder(key.mac_len())?,
        None => usm,
    };
    let msg = V3Message::new(global, usm.encode()?, scoped)?;

    match auth_key {
        Some(key) => {
            let mut bytes = msg.encode()?.to_vec();
            sign_v3_message(key, &mut bytes, target)?;
            Ok(Bytes::from(bytes))
        }
        None => msg.encode(),
    }
}

/// Build and encode a V3 Response message at the incoming security level.
///
/// Shared by the agent and the notification receiver (Inform acks). `usm`
/// carries the authoritative engine ID/boots/time the response will claim
/// and echoes the requester's username. `msg_id` and `security_level` correspond
/// to the incoming message, while `msg_max_size` advertises the responder's local
/// receive capacity (it is not the requester's value). Encryption (authPriv) uses
/// the boots/time already present in `usm`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn encode_v3_response(
    response_pdu: Pdu,
    msg_id: i32,
    msg_max_size: MessageSize,
    security_level: SecurityLevel,
    usm: UsmSecurityParams,
    context_engine_id: Bytes,
    context_name: Bytes,
    derived_keys: Option<&DerivedKeys>,
    salt_counter: Option<&SaltCounter>,
    des_salt_state: Option<&DesSaltState>,
    target: SocketAddr,
) -> Result<Bytes> {
    response_pdu.validate_outbound(crate::Version::V3, crate::pdu::PduDirection::Response)?;

    // Same security level as the request, but reportable=false
    let global = MsgGlobalData::new(msg_id, msg_max_size, MsgFlags::new(security_level, false))?;
    let scoped = ScopedPdu::new(context_engine_id, context_name, response_pdu);

    match security_level {
        SecurityLevel::NoAuthNoPriv => V3Message::new(global, usm.encode()?, scoped)?.encode(),
        SecurityLevel::AuthNoPriv => {
            let (_, auth_key) = require_auth_key(derived_keys, target)?;
            let usm = usm.with_auth_placeholder(auth_key.mac_len())?;
            let mut bytes = V3Message::new(global, usm.encode()?, scoped)?
                .encode()?
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
            let privacy_context = match priv_key.protocol() {
                PrivProtocol::Des | PrivProtocol::Des3 => {
                    let state = des_salt_state.ok_or_else(|| {
                        Error::Config(
                            "durable DES sender state is required for DES/3DES privacy".into(),
                        )
                        .boxed()
                    })?;
                    state
                        .validate_generating_engine_boots(usm.engine_boots)
                        .map_err(|error| Error::Privacy(error).boxed())?;
                    PrivacyEncryptContext::Des(
                        state
                            .reserve()
                            .map_err(|error| Error::Privacy(error).boxed())?,
                    )
                }
                _ => PrivacyEncryptContext::Aes {
                    engine_boots: usm.engine_boots,
                    engine_time: usm.engine_time,
                    salt_counter: salt_counter.ok_or_else(|| {
                        Error::Config("AES privacy salt counter not initialized".into()).boxed()
                    })?,
                },
            };

            // DES reservation deliberately precedes fallible scoped-PDU encoding.
            let scoped_pdu_bytes = scoped.encode_to_bytes()?;
            let (encrypted, priv_params) = priv_key
                .encrypt_with_context(&scoped_pdu_bytes, privacy_context)
                .map_err(|e| {
                    tracing::debug!(target: "async_snmp::v3", { error = %e }, "encryption failed for response");
                    Error::Privacy(e).boxed()
                })?;

            let usm = usm
                .with_auth_placeholder(auth_key.mac_len())?
                .with_priv_params(priv_params)?;
            let mut bytes =
                V3Message::new_with_opaque_encrypted_scoped_pdu(global, usm.encode()?, encrypted)?
                    .encode()?
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oid;
    use crate::varbind::VarBind;

    fn message_size() -> MessageSize {
        MessageSize::new(65_507).unwrap()
    }

    #[test]
    fn shared_v3_request_encoder_rejects_malformed_pdu_without_mutation() {
        let pdu = Pdu {
            request_id: 7,
            body: crate::pdu::PduBody::GetBulk {
                non_repeaters: crate::pdu::MAX_GET_BULK_VALUE + 1,
                max_repetitions: 0,
            },
            varbinds: vec![VarBind::null(oid!(1, 3, 6, 1))],
        };
        let original = pdu.clone();
        let security = UsmConfig::new("user");
        let salt = SaltCounter::from_value(1);

        let result = encode_v3_message(
            &pdu,
            11,
            b"engine-id",
            1,
            1,
            &security,
            None,
            Some(&salt),
            None,
            None,
            true,
            message_size(),
        );

        assert!(result.is_err());
        assert_eq!(pdu, original);
    }

    #[test]
    fn shared_v3_notification_encoder_rejects_exception_values() {
        let pdu = Pdu::standard(
            crate::pdu::StandardPduType::TrapV2,
            7,
            0,
            0,
            vec![VarBind::new(oid!(1, 3, 6, 1), Value::EndOfMibView)],
        );
        let security = UsmConfig::new("user");
        let salt = SaltCounter::from_value(1);

        let result = encode_v3_message(
            &pdu,
            11,
            b"engine-id",
            1,
            1,
            &security,
            None,
            Some(&salt),
            None,
            None,
            false,
            message_size(),
        );

        assert!(result.is_err());
    }

    #[test]
    fn shared_agent_response_encoder_rejects_invalid_response_fields() {
        let pdu = Pdu::response(7, 0, 1, vec![VarBind::null(oid!(1, 3, 6, 1))]);
        let usm = UsmSecurityParams::new(
            Bytes::from_static(b"engine-id"),
            1,
            1,
            Bytes::from_static(b"user"),
        )
        .unwrap();
        let salt = SaltCounter::from_value(1);

        let result = encode_v3_response(
            pdu,
            11,
            message_size(),
            SecurityLevel::NoAuthNoPriv,
            usm,
            Bytes::from_static(b"engine-id"),
            Bytes::new(),
            None,
            Some(&salt),
            None,
            "127.0.0.1:161".parse().unwrap(),
        );

        assert!(result.is_err());
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn polling_des_uses_local_sender_boots_not_remote_authoritative_boots() {
        let pdu = Pdu::get_request(7, &[oid!(1, 3, 6, 1)]);
        let mut security = UsmConfig::new("user")
            .auth_priv(
                crate::v3::AuthProtocol::Sha1,
                b"auth-password",
                PrivProtocol::Des,
                b"priv-password",
            )
            .unwrap();
        security.validate_and_precompute().unwrap();
        let keys = security.derive_keys(b"remote-engine-id").unwrap();
        let state = DesSaltState::install(|_| Ok::<(), std::convert::Infallible>(())).unwrap();

        let encoded = encode_v3_message(
            &pdu,
            11,
            b"remote-engine-id",
            77,
            123,
            &security,
            Some(&keys),
            None,
            Some(&state),
            Some(state.engine_boots()),
            true,
            message_size(),
        )
        .unwrap();
        let message =
            crate::message::V3Message::decode(Bytes::from(encoded), crate::DecodeConfig::default())
                .unwrap()
                .value;
        let usm = UsmSecurityParams::decode(
            message.security_params().clone(),
            crate::DecodeConfig::default(),
        )
        .unwrap()
        .value;

        assert_eq!(usm.engine_boots, 77);
        assert_eq!(&usm.priv_params()[..4], &state.engine_boots().to_be_bytes());
        assert_ne!(&usm.priv_params()[..4], &77_u32.to_be_bytes());
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn authoritative_des_message_rejects_stale_sender_epoch_before_reservation() {
        let pdu = Pdu::get_request(7, &[oid!(1, 3, 6, 1)]);
        let mut security = UsmConfig::new("user")
            .auth_priv(
                crate::v3::AuthProtocol::Sha1,
                b"auth-password",
                PrivProtocol::Des,
                b"priv-password",
            )
            .unwrap();
        security.validate_and_precompute().unwrap();
        let keys = security.derive_keys(b"local-engine-id").unwrap();
        let state = DesSaltState::install(|_| Ok::<(), std::convert::Infallible>(())).unwrap();

        let error = encode_v3_message(
            &pdu,
            11,
            b"local-engine-id",
            2,
            0,
            &security,
            Some(&keys),
            None,
            Some(&state),
            Some(2),
            false,
            message_size(),
        )
        .unwrap_err();

        assert!(matches!(
            *error,
            Error::Privacy(crate::v3::PrivacyError::DesEngineBootsMismatch {
                state_engine_boots: 1,
                generating_engine_boots: 2,
            })
        ));
        assert_eq!(state.reserve().unwrap().salt(), 1);
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn authoritative_des_response_rejects_stale_sender_epoch_before_reservation() {
        let response = Pdu::response(7, 0, 0, vec![VarBind::null(oid!(1, 3, 6, 1))]);
        let security = UsmConfig::new("user")
            .auth_priv(
                crate::v3::AuthProtocol::Sha1,
                b"auth-password",
                PrivProtocol::Des,
                b"priv-password",
            )
            .unwrap();
        let keys = security.derive_keys(b"local-engine-id").unwrap();
        let state = DesSaltState::install(|_| Ok::<(), std::convert::Infallible>(())).unwrap();
        let usm = UsmSecurityParams::new(
            Bytes::from_static(b"local-engine-id"),
            2,
            0,
            Bytes::from_static(b"user"),
        )
        .unwrap();

        let error = encode_v3_response(
            response,
            11,
            message_size(),
            SecurityLevel::AuthPriv,
            usm,
            Bytes::from_static(b"local-engine-id"),
            Bytes::new(),
            Some(&keys),
            None,
            Some(&state),
            "127.0.0.1:161".parse().unwrap(),
        )
        .unwrap_err();

        assert!(matches!(
            *error,
            Error::Privacy(crate::v3::PrivacyError::DesEngineBootsMismatch {
                state_engine_boots: 1,
                generating_engine_boots: 2,
            })
        ));
        assert_eq!(state.reserve().unwrap().salt(), 1);
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn des_reservation_is_burned_before_later_encoding_failure() {
        let pdu = Pdu {
            request_id: 7,
            body: crate::pdu::PduBody::GetBulk {
                non_repeaters: crate::pdu::MAX_GET_BULK_VALUE + 1,
                max_repetitions: 0,
            },
            varbinds: vec![VarBind::null(oid!(1, 3, 6, 1))],
        };
        let mut security = UsmConfig::new("user")
            .auth_priv(
                crate::v3::AuthProtocol::Sha1,
                b"auth-password",
                PrivProtocol::Des,
                b"priv-password",
            )
            .unwrap();
        security.validate_and_precompute().unwrap();
        let keys = security.derive_keys(b"engine-id").unwrap();
        let state = DesSaltState::install(|_| Ok::<(), std::convert::Infallible>(())).unwrap();

        let result = encode_v3_message(
            &pdu,
            11,
            b"engine-id",
            77,
            123,
            &security,
            Some(&keys),
            None,
            Some(&state),
            Some(state.engine_boots()),
            true,
            message_size(),
        );

        assert!(result.is_err());
        assert_eq!(state.reserve().unwrap().salt(), 2);
    }
}
