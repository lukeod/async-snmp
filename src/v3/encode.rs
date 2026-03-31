//! V3 message encoding.
//!
//! Standalone V3 message building used by both the client and agent.
//! Takes explicit parameters rather than reading from a specific owner's state.

use bytes::Bytes;

use crate::error::{Error, Result};
use crate::message::{MsgFlags, MsgGlobalData, ScopedPdu, V3Message, V3MessageData};
use crate::notification::{DerivedKeys, UsmConfig};
use crate::pdu::Pdu;
use crate::v3::SaltCounter;
use crate::v3::UsmSecurityParams;
use crate::v3::auth::authenticate_message;

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
/// - `msg_id` - Message ID (separate from pdu.request_id per RFC 3412 Section 6.2)
/// - `engine_id` - Authoritative engine ID (sender's for traps, receiver's for requests)
/// - `engine_boots` - Current engine boots value
/// - `engine_time` - Current engine time value
/// - `security` - USM security configuration (username, context, security level)
/// - `derived_keys` - Keys derived against `engine_id`
/// - `salt_counter` - Salt counter for encryption IV generation
/// - `reportable` - Whether the receiver should send Report PDUs on error
/// - `msg_max_size` - Maximum message size to advertise
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
