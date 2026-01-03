//! Varbind extraction and validation for SNMP notifications.
//!
//! Per RFC 3416, notification PDUs have a specific varbind structure:
//! - First varbind: sysUpTime.0 (1.3.6.1.2.1.1.3.0) with TimeTicks value
//! - Second varbind: snmpTrapOID.0 (1.3.6.1.6.3.1.1.4.1.0) with OID value
//! - Remaining varbinds: notification-specific data

use crate::error::internal::DecodeErrorKind;
use crate::error::{Error, Result, UNKNOWN_TARGET};
use crate::oid::Oid;
use crate::pdu::Pdu;
use crate::value::Value;
use crate::varbind::VarBind;

use super::oids;

/// Extract uptime, trap OID, and additional varbinds from a notification PDU.
///
/// Per RFC 3416, the first two varbinds are always:
/// 1. sysUpTime.0 (1.3.6.1.2.1.1.3.0) - TimeTicks
/// 2. snmpTrapOID.0 (1.3.6.1.6.3.1.1.4.1.0) - OID of the trap
pub(crate) fn extract_notification_varbinds(pdu: &Pdu) -> Result<(u32, Oid, Vec<VarBind>)> {
    extract_notification_varbinds_impl(pdu, false)
}

/// Extract uptime, trap OID, and additional varbinds with optional strict OID validation.
///
/// When `strict` is true, validates that the first two varbinds have the correct OIDs:
/// - First varbind OID must be sysUpTime.0 (1.3.6.1.2.1.1.3.0)
/// - Second varbind OID must be snmpTrapOID.0 (1.3.6.1.6.3.1.1.4.1.0)
///
/// When `strict` is false (default), only validates the value types.
fn extract_notification_varbinds_impl(pdu: &Pdu, strict: bool) -> Result<(u32, Oid, Vec<VarBind>)> {
    let target = UNKNOWN_TARGET;

    if pdu.varbinds.len() < 2 {
        tracing::debug!(
            target: "async_snmp::notification",
            kind = %DecodeErrorKind::MissingPdu,
            "notification has fewer than 2 varbinds"
        );
        return Err(Error::MalformedResponse { target }.boxed());
    }

    // First varbind: sysUpTime.0
    if strict && pdu.varbinds[0].oid != oids::sys_uptime() {
        tracing::warn!(
            expected = %oids::sys_uptime(),
            actual = %pdu.varbinds[0].oid,
            "strict mode: first varbind OID is not sysUpTime.0"
        );
        tracing::debug!(
            target: "async_snmp::notification",
            kind = %DecodeErrorKind::InvalidOid,
            "invalid first varbind OID"
        );
        return Err(Error::MalformedResponse { target }.boxed());
    }
    let uptime = match &pdu.varbinds[0].value {
        Value::TimeTicks(t) => *t,
        _other => {
            tracing::debug!(
                target: "async_snmp::notification",
                kind = %DecodeErrorKind::MissingPdu,
                "first varbind is not TimeTicks"
            );
            return Err(Error::MalformedResponse { target }.boxed());
        }
    };

    // Second varbind: snmpTrapOID.0
    if strict && pdu.varbinds[1].oid != oids::snmp_trap_oid() {
        tracing::warn!(
            expected = %oids::snmp_trap_oid(),
            actual = %pdu.varbinds[1].oid,
            "strict mode: second varbind OID is not snmpTrapOID.0"
        );
        tracing::debug!(
            target: "async_snmp::notification",
            kind = %DecodeErrorKind::InvalidOid,
            "invalid second varbind OID"
        );
        return Err(Error::MalformedResponse { target }.boxed());
    }
    let trap_oid = match &pdu.varbinds[1].value {
        Value::ObjectIdentifier(oid) => oid.clone(),
        _other => {
            tracing::debug!(
                target: "async_snmp::notification",
                kind = %DecodeErrorKind::MissingPdu,
                "second varbind is not OID"
            );
            return Err(Error::MalformedResponse { target }.boxed());
        }
    };

    // Remaining varbinds
    let varbinds = pdu.varbinds[2..].to_vec();

    Ok((uptime, trap_oid, varbinds))
}

/// Validate notification varbinds strictly per RFC 3416.
///
/// Returns `true` if the first two varbinds have the correct OIDs:
/// - First: sysUpTime.0 (1.3.6.1.2.1.1.3.0) with TimeTicks value
/// - Second: snmpTrapOID.0 (1.3.6.1.6.3.1.1.4.1.0) with OID value
///
/// This is useful for validating incoming notifications before processing.
pub fn validate_notification_varbinds(pdu: &Pdu) -> bool {
    if pdu.varbinds.len() < 2 {
        return false;
    }

    // Check first varbind is sysUpTime.0 with TimeTicks
    if pdu.varbinds[0].oid != oids::sys_uptime() {
        return false;
    }
    if !matches!(pdu.varbinds[0].value, Value::TimeTicks(_)) {
        return false;
    }

    // Check second varbind is snmpTrapOID.0 with OID
    if pdu.varbinds[1].oid != oids::snmp_trap_oid() {
        return false;
    }
    if !matches!(pdu.varbinds[1].value, Value::ObjectIdentifier(_)) {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oid;
    use crate::pdu::PduType;

    #[test]
    fn test_extract_notification_varbinds() {
        let pdu = Pdu {
            pdu_type: PduType::TrapV2,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbinds: vec![
                VarBind::new(oids::sys_uptime(), Value::TimeTicks(12345)),
                VarBind::new(
                    oids::snmp_trap_oid(),
                    Value::ObjectIdentifier(oids::link_down()),
                ),
                VarBind::new(oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 1), Value::Integer(1)),
            ],
        };

        let (uptime, trap_oid, varbinds) = extract_notification_varbinds(&pdu).unwrap();
        assert_eq!(uptime, 12345);
        assert_eq!(trap_oid, oids::link_down());
        assert_eq!(varbinds.len(), 1);
    }

    #[test]
    fn test_extract_notification_varbinds_too_few() {
        let pdu = Pdu {
            pdu_type: PduType::TrapV2,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbinds: vec![VarBind::new(oids::sys_uptime(), Value::TimeTicks(12345))],
        };

        let result = extract_notification_varbinds(&pdu);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_notification_varbinds_valid() {
        let pdu = Pdu {
            pdu_type: PduType::TrapV2,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbinds: vec![
                VarBind::new(oids::sys_uptime(), Value::TimeTicks(12345)),
                VarBind::new(
                    oids::snmp_trap_oid(),
                    Value::ObjectIdentifier(oids::link_down()),
                ),
            ],
        };

        assert!(validate_notification_varbinds(&pdu));
    }

    #[test]
    fn test_validate_notification_varbinds_wrong_first_oid() {
        let pdu = Pdu {
            pdu_type: PduType::TrapV2,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbinds: vec![
                // Wrong OID for first varbind
                VarBind::new(oid!(1, 2, 3, 4), Value::TimeTicks(12345)),
                VarBind::new(
                    oids::snmp_trap_oid(),
                    Value::ObjectIdentifier(oids::link_down()),
                ),
            ],
        };

        assert!(!validate_notification_varbinds(&pdu));
    }

    #[test]
    fn test_validate_notification_varbinds_wrong_second_oid() {
        let pdu = Pdu {
            pdu_type: PduType::TrapV2,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbinds: vec![
                VarBind::new(oids::sys_uptime(), Value::TimeTicks(12345)),
                // Wrong OID for second varbind
                VarBind::new(oid!(1, 2, 3, 4), Value::ObjectIdentifier(oids::link_down())),
            ],
        };

        assert!(!validate_notification_varbinds(&pdu));
    }

    #[test]
    fn test_validate_notification_varbinds_wrong_first_type() {
        let pdu = Pdu {
            pdu_type: PduType::TrapV2,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbinds: vec![
                // Wrong value type for first varbind (should be TimeTicks)
                VarBind::new(oids::sys_uptime(), Value::Integer(12345)),
                VarBind::new(
                    oids::snmp_trap_oid(),
                    Value::ObjectIdentifier(oids::link_down()),
                ),
            ],
        };

        assert!(!validate_notification_varbinds(&pdu));
    }

    #[test]
    fn test_validate_notification_varbinds_wrong_second_type() {
        let pdu = Pdu {
            pdu_type: PduType::TrapV2,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbinds: vec![
                VarBind::new(oids::sys_uptime(), Value::TimeTicks(12345)),
                // Wrong value type for second varbind (should be OID)
                VarBind::new(oids::snmp_trap_oid(), Value::Integer(1)),
            ],
        };

        assert!(!validate_notification_varbinds(&pdu));
    }

    #[test]
    fn test_validate_notification_varbinds_too_few() {
        let pdu = Pdu {
            pdu_type: PduType::TrapV2,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbinds: vec![
                VarBind::new(oids::sys_uptime(), Value::TimeTicks(12345)),
                // Missing second varbind
            ],
        };

        assert!(!validate_notification_varbinds(&pdu));
    }
}
