//! Request handling for different SNMP versions.

use bytes::Bytes;
use std::net::SocketAddr;

use crate::ber::Decoder;
use crate::error::{CryptoErrorKind, DecodeErrorKind, Error, Result};
use crate::handler::{RequestContext, SecurityModel};
use crate::message::{
    CommunityMessage, MsgFlags, MsgGlobalData, ScopedPdu, SecurityLevel, V3Message, V3MessageData,
};
use crate::pdu::{Pdu, PduType};
use crate::v3::UsmSecurityParams;
use crate::v3::auth::verify_message;
use crate::value::Value;
use crate::varbind::VarBind;
use crate::version::Version;

use std::sync::atomic::Ordering;

use super::Agent;

impl Agent {
    /// Handle SNMPv1 request.
    pub(super) async fn handle_v1(&self, data: Bytes, source: SocketAddr) -> Result<Option<Bytes>> {
        let msg = CommunityMessage::decode(data)?;

        // Validate community
        if !self.validate_community(&msg.community) {
            tracing::debug!(snmp.source = %source, "invalid community string");
            return Ok(None);
        }

        // Skip non-request PDUs
        if !is_request_pdu(msg.pdu.pdu_type) {
            return Ok(None);
        }

        // Build request context
        let mut ctx = RequestContext {
            source,
            version: Version::V1,
            security_model: SecurityModel::V1,
            security_name: msg.community.clone(),
            security_level: SecurityLevel::NoAuthNoPriv,
            context_name: Bytes::new(),
            request_id: msg.pdu.request_id,
            pdu_type: msg.pdu.pdu_type,
            group_name: None,
            read_view: None,
            write_view: None,
        };

        // VACM resolution (if enabled)
        if let Some(ref vacm) = self.inner.vacm
            && let Some(group) = vacm.get_group(SecurityModel::V1, &ctx.security_name)
        {
            ctx.group_name = Some(group.clone());
            if let Some(access) = vacm.get_access(
                group,
                &ctx.context_name,
                ctx.security_model,
                ctx.security_level,
            ) {
                ctx.read_view = Some(access.read_view.clone());
                ctx.write_view = Some(access.write_view.clone());
            }
        }

        let response_pdu = self.dispatch_request(&ctx, &msg.pdu).await?;
        let response_msg = CommunityMessage::v1(msg.community, response_pdu);

        Ok(Some(response_msg.encode()))
    }

    /// Handle SNMPv2c request.
    pub(super) async fn handle_v2c(
        &self,
        data: Bytes,
        source: SocketAddr,
    ) -> Result<Option<Bytes>> {
        let msg = CommunityMessage::decode(data)?;

        // Validate community
        if !self.validate_community(&msg.community) {
            tracing::debug!(snmp.source = %source, "invalid community string");
            return Ok(None);
        }

        // Skip non-request PDUs
        if !is_request_pdu(msg.pdu.pdu_type) {
            return Ok(None);
        }

        // Build request context
        let mut ctx = RequestContext {
            source,
            version: Version::V2c,
            security_model: SecurityModel::V2c,
            security_name: msg.community.clone(),
            security_level: SecurityLevel::NoAuthNoPriv,
            context_name: Bytes::new(),
            request_id: msg.pdu.request_id,
            pdu_type: msg.pdu.pdu_type,
            group_name: None,
            read_view: None,
            write_view: None,
        };

        // VACM resolution (if enabled)
        if let Some(ref vacm) = self.inner.vacm
            && let Some(group) = vacm.get_group(SecurityModel::V2c, &ctx.security_name)
        {
            ctx.group_name = Some(group.clone());
            if let Some(access) = vacm.get_access(
                group,
                &ctx.context_name,
                ctx.security_model,
                ctx.security_level,
            ) {
                ctx.read_view = Some(access.read_view.clone());
                ctx.write_view = Some(access.write_view.clone());
            }
        }

        let response_pdu = self.dispatch_request(&ctx, &msg.pdu).await?;
        let response_msg = CommunityMessage::v2c(msg.community, response_pdu);

        Ok(Some(response_msg.encode()))
    }

    /// Handle SNMPv3 request.
    pub(super) async fn handle_v3(&self, data: Bytes, source: SocketAddr) -> Result<Option<Bytes>> {
        let msg = match V3Message::decode(data.clone()) {
            Ok(msg) => msg,
            Err(Error::Decode { kind, .. }) => {
                // Increment statistics counters for specific decode errors
                match kind {
                    DecodeErrorKind::InvalidMsgFlags => {
                        self.inner.snmp_invalid_msgs.fetch_add(1, Ordering::Relaxed);
                        tracing::debug!(snmp.source = %source, "invalid msgFlags (priv without auth)");
                    }
                    DecodeErrorKind::UnknownSecurityModel(model) => {
                        self.inner
                            .snmp_unknown_security_models
                            .fetch_add(1, Ordering::Relaxed);
                        tracing::debug!(snmp.source = %source, snmp.security_model = model, "unknown security model");
                    }
                    _ => {}
                }
                return Err(Error::Decode { offset: 0, kind });
            }
            Err(e) => return Err(e),
        };
        let security_level = msg.global_data.msg_flags.security_level;

        // Decode USM parameters
        let usm_params = UsmSecurityParams::decode(msg.security_params.clone())?;
        let username = usm_params.username.clone();

        // Check if this is a discovery request (empty engine ID)
        if usm_params.engine_id.is_empty() {
            return self.handle_v3_discovery(&msg, source);
        }

        // Verify engine ID matches ours
        if usm_params.engine_id.as_ref() != self.inner.engine_id.as_slice() {
            tracing::debug!(snmp.source = %source, "engine ID mismatch");
            return self.send_v3_report(
                &msg,
                &usm_params,
                crate::oid!(1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0), // usmStatsUnknownEngineIDs
                source,
            );
        }

        // Look up user credentials
        let user_config = self.inner.usm_users.get(&username);
        let derived_keys = user_config.map(|u| u.derive_keys(&self.inner.engine_id));

        // Verify authentication if required
        if security_level == SecurityLevel::AuthNoPriv || security_level == SecurityLevel::AuthPriv
        {
            match &derived_keys {
                Some(keys) if keys.auth_key.is_some() => {
                    let auth_key = keys.auth_key.as_ref().unwrap();
                    let (auth_offset, auth_len) = UsmSecurityParams::find_auth_params_offset(&data)
                        .ok_or_else(|| {
                            Error::auth(None, crate::error::AuthErrorKind::AuthParamsNotFound)
                        })?;

                    if !verify_message(auth_key, &data, auth_offset, auth_len) {
                        tracing::debug!(snmp.source = %source, "authentication failed");
                        return self.send_v3_report(
                            &msg,
                            &usm_params,
                            crate::oid!(1, 3, 6, 1, 6, 3, 15, 1, 1, 5, 0), // usmStatsWrongDigests
                            source,
                        );
                    }

                    // Verify time window (150 seconds)
                    let our_time = self.inner.engine_time.load(Ordering::Relaxed);
                    let time_diff = (usm_params.engine_time as i64 - our_time as i64).abs();
                    if time_diff > 150 {
                        tracing::debug!(snmp.source = %source, "message outside time window");
                        return self.send_v3_report(
                            &msg,
                            &usm_params,
                            crate::oid!(1, 3, 6, 1, 6, 3, 15, 1, 1, 2, 0), // usmStatsNotInTimeWindows
                            source,
                        );
                    }
                }
                _ => {
                    tracing::debug!(
                        snmp.source = %source,
                        snmp.username = %String::from_utf8_lossy(&username),
                        "unknown user or no credentials"
                    );
                    return self.send_v3_report(
                        &msg,
                        &usm_params,
                        crate::oid!(1, 3, 6, 1, 6, 3, 15, 1, 1, 3, 0), // usmStatsUnknownUserNames
                        source,
                    );
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
                            return Err(Error::decode(0, DecodeErrorKind::ExpectedEncryption));
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
                    return Err(Error::decrypt(None, CryptoErrorKind::NoPrivKey));
                }
            }
        } else {
            match msg.scoped_pdu() {
                Some(sp) => sp.clone(),
                None => {
                    return Err(Error::decode(0, DecodeErrorKind::UnexpectedEncryption));
                }
            }
        };

        let pdu = &scoped_pdu.pdu;

        // Skip non-request PDUs
        if !is_request_pdu(pdu.pdu_type) {
            return Ok(None);
        }

        // Build request context
        let mut ctx = RequestContext {
            source,
            version: Version::V3,
            security_model: SecurityModel::Usm,
            security_name: username.clone(),
            security_level,
            context_name: scoped_pdu.context_name.clone(),
            request_id: pdu.request_id,
            pdu_type: pdu.pdu_type,
            group_name: None,
            read_view: None,
            write_view: None,
        };

        // VACM resolution (if enabled)
        if let Some(ref vacm) = self.inner.vacm
            && let Some(group) = vacm.get_group(SecurityModel::Usm, &ctx.security_name)
        {
            ctx.group_name = Some(group.clone());
            if let Some(access) = vacm.get_access(
                group,
                &ctx.context_name,
                ctx.security_model,
                ctx.security_level,
            ) {
                ctx.read_view = Some(access.read_view.clone());
                ctx.write_view = Some(access.write_view.clone());
            }
        }

        let response_pdu = self.dispatch_request(&ctx, pdu).await?;

        // Build response
        self.build_v3_response(
            &msg,
            &usm_params,
            response_pdu,
            scoped_pdu.context_engine_id.clone(),
            scoped_pdu.context_name.clone(),
            derived_keys.as_ref(),
        )
    }

    /// Handle SNMPv3 discovery request.
    ///
    /// Per RFC 3412 Section 7.1 Step 3, Report PDUs may only be sent if:
    /// - The PDU is from the Confirmed Class, OR
    /// - The reportableFlag is set AND the PDU class cannot be determined
    ///
    /// For discovery requests, the PDU content cannot be determined (empty engine ID),
    /// so we check the reportableFlag.
    pub(super) fn handle_v3_discovery(
        &self,
        incoming: &V3Message,
        _source: SocketAddr,
    ) -> Result<Option<Bytes>> {
        // Check reportableFlag before sending Report (RFC 3412 Section 7.1 Step 3)
        if !incoming.global_data.msg_flags.reportable {
            tracing::debug!("discovery request has reportable=false, not sending report");
            return Ok(None);
        }

        let engine_boots = self.inner.engine_boots.load(Ordering::Relaxed);
        let engine_time = self.inner.engine_time.load(Ordering::Relaxed);

        // Build Report PDU with usmStatsUnknownEngineIDs
        let report_pdu = Pdu {
            pdu_type: PduType::Report,
            request_id: incoming.global_data.msg_id,
            error_status: 0,
            error_index: 0,
            varbinds: vec![VarBind::new(
                crate::oid!(1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0), // usmStatsUnknownEngineIDs
                Value::Counter32(0),
            )],
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
            Bytes::new(),
        );

        let response_scoped = ScopedPdu::new(
            Bytes::copy_from_slice(&self.inner.engine_id),
            Bytes::new(),
            report_pdu,
        );

        let response_msg = V3Message::new(response_global, response_usm.encode(), response_scoped);

        Ok(Some(response_msg.encode()))
    }
}

/// Check if a PDU type is a request that should be handled.
///
/// InformRequest is a confirmed-class PDU (RFC 3416) that requires a Response.
/// While Informs are typically handled by notification receivers, agents should
/// also respond to them per RFC 3413 Section 4.
pub(super) fn is_request_pdu(pdu_type: PduType) -> bool {
    matches!(
        pdu_type,
        PduType::GetRequest
            | PduType::GetNextRequest
            | PduType::GetBulkRequest
            | PduType::SetRequest
            | PduType::InformRequest
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_request_pdu() {
        assert!(is_request_pdu(PduType::GetRequest));
        assert!(is_request_pdu(PduType::GetNextRequest));
        assert!(is_request_pdu(PduType::GetBulkRequest));
        assert!(is_request_pdu(PduType::SetRequest));
        assert!(is_request_pdu(PduType::InformRequest));
        assert!(!is_request_pdu(PduType::Response));
        assert!(!is_request_pdu(PduType::TrapV2));
    }
}
