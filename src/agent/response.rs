//! V3 response building for the SNMP agent.

use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;

use crate::error::{AuthErrorKind, CryptoErrorKind, EncodeErrorKind, Error, Result};
use crate::message::{MsgFlags, MsgGlobalData, ScopedPdu, SecurityLevel, V3Message};
use crate::notification::DerivedKeys;
use crate::oid::Oid;
use crate::pdu::{Pdu, PduType};
use crate::v3::UsmSecurityParams;
use crate::v3::auth::authenticate_message;
use crate::value::Value;
use crate::varbind::VarBind;

use super::Agent;

impl Agent {
    /// Send a V3 Report PDU.
    ///
    /// Per RFC 3412 Section 7.1 Step 3, Report PDUs may only be sent if:
    /// - The PDU is from the Confirmed Class, OR
    /// - The reportableFlag is set AND the PDU class cannot be determined
    ///
    /// When this function is called, we haven't successfully decoded the PDU
    /// (due to auth/decryption errors), so we must check reportableFlag.
    pub(super) fn send_v3_report(
        &self,
        incoming: &V3Message,
        incoming_usm: &UsmSecurityParams,
        report_oid: Oid,
        _source: SocketAddr,
    ) -> Result<Option<Bytes>> {
        // Check reportableFlag before sending Report (RFC 3412 Section 7.1 Step 3)
        if !incoming.global_data.msg_flags.reportable {
            tracing::debug!("message has reportable=false, not sending report");
            return Ok(None);
        }

        let engine_boots = self.inner.engine_boots.load(Ordering::Relaxed);
        let engine_time = self.inner.engine_time.load(Ordering::Relaxed);

        let report_pdu = Pdu {
            pdu_type: PduType::Report,
            request_id: incoming.global_data.msg_id,
            error_status: 0,
            error_index: 0,
            varbinds: vec![VarBind::new(report_oid, Value::Counter32(0))],
        };

        let response_global = MsgGlobalData::new(
            incoming.global_data.msg_id,
            incoming.global_data.msg_max_size,
            MsgFlags::new(SecurityLevel::NoAuthNoPriv, false),
        );

        let response_usm = UsmSecurityParams::new(
            Bytes::copy_from_slice(&self.inner.engine_id),
            engine_boots,
            engine_time,
            incoming_usm.username.clone(),
        );

        let response_scoped = ScopedPdu::new(
            Bytes::copy_from_slice(&self.inner.engine_id),
            Bytes::new(),
            report_pdu,
        );

        let response_msg = V3Message::new(response_global, response_usm.encode(), response_scoped);

        Ok(Some(response_msg.encode()))
    }

    /// Build a V3 response message with appropriate security.
    pub(super) fn build_v3_response(
        &self,
        incoming: &V3Message,
        incoming_usm: &UsmSecurityParams,
        response_pdu: Pdu,
        context_engine_id: Bytes,
        context_name: Bytes,
        derived_keys: Option<&DerivedKeys>,
    ) -> Result<Option<Bytes>> {
        let security_level = incoming.global_data.msg_flags.security_level;
        let engine_boots = self.inner.engine_boots.load(Ordering::Relaxed);
        let engine_time = self.inner.engine_time.load(Ordering::Relaxed);

        let response_global = MsgGlobalData::new(
            incoming.global_data.msg_id,
            incoming.global_data.msg_max_size,
            MsgFlags::new(security_level, false),
        );

        let response_scoped = ScopedPdu::new(context_engine_id, context_name, response_pdu);

        match security_level {
            SecurityLevel::NoAuthNoPriv => {
                let response_usm = UsmSecurityParams::new(
                    Bytes::copy_from_slice(&self.inner.engine_id),
                    engine_boots,
                    engine_time,
                    incoming_usm.username.clone(),
                );
                let response_msg =
                    V3Message::new(response_global, response_usm.encode(), response_scoped);
                Ok(Some(response_msg.encode()))
            }
            SecurityLevel::AuthNoPriv => {
                let keys =
                    derived_keys.ok_or_else(|| Error::auth(None, AuthErrorKind::NoCredentials))?;
                let auth_key = keys
                    .auth_key
                    .as_ref()
                    .ok_or_else(|| Error::auth(None, AuthErrorKind::NoAuthKey))?;

                let mac_len = auth_key.mac_len();
                let response_usm = UsmSecurityParams::new(
                    Bytes::copy_from_slice(&self.inner.engine_id),
                    engine_boots,
                    engine_time,
                    incoming_usm.username.clone(),
                )
                .with_auth_placeholder(mac_len);

                let response_msg =
                    V3Message::new(response_global, response_usm.encode(), response_scoped);

                let mut response_bytes = response_msg.encode().to_vec();

                let (auth_offset, auth_len) =
                    UsmSecurityParams::find_auth_params_offset(&response_bytes)
                        .ok_or_else(|| Error::encode(EncodeErrorKind::MissingAuthParams))?;

                authenticate_message(auth_key, &mut response_bytes, auth_offset, auth_len);

                Ok(Some(Bytes::from(response_bytes)))
            }
            SecurityLevel::AuthPriv => {
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
                    engine_boots,
                    engine_time,
                    Some(&self.inner.salt_counter),
                )?;

                let mac_len = auth_key.mac_len();
                let response_usm = UsmSecurityParams::new(
                    Bytes::copy_from_slice(&self.inner.engine_id),
                    engine_boots,
                    engine_time,
                    incoming_usm.username.clone(),
                )
                .with_auth_placeholder(mac_len)
                .with_priv_params(priv_params);

                let response_msg =
                    V3Message::new_encrypted(response_global, response_usm.encode(), encrypted);

                let mut response_bytes = response_msg.encode().to_vec();

                let (auth_offset, auth_len) =
                    UsmSecurityParams::find_auth_params_offset(&response_bytes)
                        .ok_or_else(|| Error::encode(EncodeErrorKind::MissingAuthParams))?;

                authenticate_message(auth_key, &mut response_bytes, auth_offset, auth_len);

                Ok(Some(Bytes::from(response_bytes)))
            }
        }
    }
}
