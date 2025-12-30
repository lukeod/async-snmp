//! Protocol version-specific notification handlers.
//!
//! This module contains the internal handlers for processing SNMPv1, v2c, and v3
//! notification messages.

use std::net::SocketAddr;

use bytes::Bytes;

use crate::ber::{Decoder, tag};
use crate::error::{
    AuthErrorKind, CryptoErrorKind, DecodeErrorKind, EncodeErrorKind, Error, Result,
};
use crate::message::{
    CommunityMessage, MsgFlags, MsgGlobalData, ScopedPdu, SecurityLevel, V3Message, V3MessageData,
};
use crate::pdu::{Pdu, PduType, TrapV1Pdu};
use crate::v3::UsmSecurityParams;
use crate::v3::auth::{authenticate_message, verify_message};

use super::types::DerivedKeys;
use super::varbind::extract_notification_varbinds;
use super::{Notification, ReceiverInner};

impl super::NotificationReceiver {
    /// Handle SNMPv1 message.
    pub(super) async fn handle_v1(
        &self,
        data: Bytes,
        _source: SocketAddr,
    ) -> Result<Option<Notification>> {
        // For v1, we need to check if it's a Trap PDU (has different structure)
        let mut decoder = Decoder::new(data);
        let mut seq = decoder.read_sequence()?;

        let _version = seq.read_integer()?;
        let community = seq.read_octet_string()?;

        // Peek at PDU tag
        let pdu_tag = seq
            .peek_tag()
            .ok_or_else(|| Error::decode(seq.offset(), DecodeErrorKind::TruncatedData))?;

        if pdu_tag == tag::pdu::TRAP_V1 {
            let trap = TrapV1Pdu::decode(&mut seq)?;
            Ok(Some(Notification::TrapV1 { community, trap }))
        } else {
            // Not a trap, ignore (could be a v1 request which we don't handle)
            Ok(None)
        }
    }

    /// Handle SNMPv2c message.
    pub(super) async fn handle_v2c(
        &self,
        data: Bytes,
        source: SocketAddr,
    ) -> Result<Option<Notification>> {
        let msg = CommunityMessage::decode(data)?;

        match msg.pdu.pdu_type {
            PduType::TrapV2 => {
                let (uptime, trap_oid, varbinds) = extract_notification_varbinds(&msg.pdu)?;
                Ok(Some(Notification::TrapV2c {
                    community: msg.community,
                    uptime,
                    trap_oid,
                    varbinds,
                    request_id: msg.pdu.request_id,
                }))
            }
            PduType::InformRequest => {
                let (uptime, trap_oid, varbinds) = extract_notification_varbinds(&msg.pdu)?;

                // Send response
                let response = msg.pdu.to_response();
                let response_msg = CommunityMessage::v2c(msg.community.clone(), response);
                let response_bytes = response_msg.encode();

                self.inner
                    .socket
                    .send_to(&response_bytes, source)
                    .await
                    .map_err(|e| Error::Io {
                        target: Some(source),
                        source: e,
                    })?;

                tracing::debug!(
                    snmp.source = %source,
                    snmp.request_id = msg.pdu.request_id,
                    "sent Inform response"
                );

                Ok(Some(Notification::InformV2c {
                    community: msg.community,
                    uptime,
                    trap_oid,
                    varbinds,
                    request_id: msg.pdu.request_id,
                }))
            }
            _ => Ok(None), // Not a notification PDU
        }
    }

    /// Handle SNMPv3 message.
    pub(super) async fn handle_v3(
        &self,
        data: Bytes,
        source: SocketAddr,
    ) -> Result<Option<Notification>> {
        let msg = V3Message::decode(data.clone())?;
        let security_level = msg.global_data.msg_flags.security_level;

        // Decode USM security parameters
        let usm_params = UsmSecurityParams::decode(msg.security_params.clone())?;
        let username = usm_params.username.clone();
        let engine_id = usm_params.engine_id.clone();

        // Look up user credentials if we have them configured
        let user_config = self.inner.usm_users.get(&username);
        let derived_keys = user_config.map(|u| u.derive_keys(&engine_id));

        // Verify authentication if required
        if security_level == SecurityLevel::AuthNoPriv || security_level == SecurityLevel::AuthPriv
        {
            match &derived_keys {
                Some(keys) if keys.auth_key.is_some() => {
                    let auth_key = keys.auth_key.as_ref().unwrap();
                    let (auth_offset, auth_len) = UsmSecurityParams::find_auth_params_offset(&data)
                        .ok_or_else(|| Error::auth(None, AuthErrorKind::AuthParamsNotFound))?;

                    if !verify_message(auth_key, &data, auth_offset, auth_len) {
                        tracing::warn!(
                            snmp.source = %source,
                            snmp.username = %String::from_utf8_lossy(&username),
                            "V3 authentication failed"
                        );
                        return Err(Error::auth(None, AuthErrorKind::HmacMismatch));
                    }
                    tracing::trace!(snmp.source = %source, "V3 authentication verified");
                }
                _ => {
                    tracing::warn!(
                        snmp.source = %source,
                        snmp.username = %String::from_utf8_lossy(&username),
                        "received authenticated V3 message but no credentials configured for user"
                    );
                    return Ok(None);
                }
            }
        }

        // Decrypt if needed
        let scoped_pdu = if security_level == SecurityLevel::AuthPriv {
            match &derived_keys {
                Some(keys) if keys.priv_key.is_some() => {
                    let priv_key = keys.priv_key.as_ref().unwrap();
                    let encrypted_data = match &msg.data {
                        V3MessageData::Encrypted(data) => data,
                        V3MessageData::Plaintext(_) => {
                            return Err(Error::decode(0, DecodeErrorKind::UnexpectedEncryption));
                        }
                    };

                    let decrypted = priv_key.decrypt(
                        encrypted_data,
                        usm_params.engine_boots,
                        usm_params.engine_time,
                        &usm_params.priv_params,
                    )?;

                    let mut decoder = Decoder::new(decrypted);
                    ScopedPdu::decode(&mut decoder)?
                }
                _ => {
                    tracing::warn!(
                        snmp.source = %source,
                        snmp.username = %String::from_utf8_lossy(&username),
                        "received encrypted V3 message but no privacy key configured for user"
                    );
                    return Ok(None);
                }
            }
        } else {
            match msg.scoped_pdu() {
                Some(sp) => sp.clone(),
                None => {
                    tracing::warn!(snmp.source = %source, "unexpected encrypted V3 message");
                    return Ok(None);
                }
            }
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
                    derived_keys.as_ref(),
                )?;

                self.inner
                    .socket
                    .send_to(&response_bytes, source)
                    .await
                    .map_err(|e| Error::Io {
                        target: Some(source),
                        source: e,
                    })?;

                tracing::debug!(
                    snmp.source = %source,
                    snmp.request_id = request_id,
                    snmp.security_level = ?security_level,
                    "sent V3 Inform response"
                );

                Ok(Some(Notification::InformV3 {
                    username,
                    context_engine_id,
                    context_name,
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
            let keys =
                derived_keys.ok_or_else(|| Error::auth(None, AuthErrorKind::NoCredentials))?;
            let auth_key = keys
                .auth_key
                .as_ref()
                .ok_or_else(|| Error::auth(None, AuthErrorKind::NoAuthKey))?;

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
                UsmSecurityParams::find_auth_params_offset(&response_bytes)
                    .ok_or_else(|| Error::encode(EncodeErrorKind::MissingAuthParams))?;

            authenticate_message(auth_key, &mut response_bytes, auth_offset, auth_len);

            Ok(Bytes::from(response_bytes))
        }
        SecurityLevel::AuthPriv => {
            // Authentication and encryption
            let keys =
                derived_keys.ok_or_else(|| Error::auth(None, AuthErrorKind::NoCredentials))?;
            let auth_key = keys
                .auth_key
                .as_ref()
                .ok_or_else(|| Error::auth(None, AuthErrorKind::NoAuthKey))?;
            let priv_key = keys
                .priv_key
                .as_ref()
                .ok_or_else(|| Error::encrypt(None, CryptoErrorKind::NoPrivKey))?;

            // Encrypt the scoped PDU
            let scoped_pdu_bytes = response_scoped.encode_to_bytes();
            let mut priv_key_clone = priv_key.clone();
            let (encrypted, priv_params) = priv_key_clone.encrypt(
                &scoped_pdu_bytes,
                incoming_usm.engine_boots,
                incoming_usm.engine_time,
                Some(&inner.salt_counter),
            )?;

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
                UsmSecurityParams::find_auth_params_offset(&response_bytes)
                    .ok_or_else(|| Error::encode(EncodeErrorKind::MissingAuthParams))?;

            authenticate_message(auth_key, &mut response_bytes, auth_offset, auth_len);

            Ok(Bytes::from(response_bytes))
        }
    }
}
