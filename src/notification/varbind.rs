//! Varbind extraction and validation for SNMP notifications.
//!
//! Per RFC 3416, notification PDUs have a specific varbind structure:
//! - First varbind: sysUpTime.0 (1.3.6.1.2.1.1.3.0) with `TimeTicks` value
//! - Second varbind: snmpTrapOID.0 (1.3.6.1.6.3.1.1.4.1.0) with OID value
//! - Remaining varbinds: notification-specific data

use crate::error::internal::DecodeErrorKind;
use crate::error::{Error, Result, UNKNOWN_TARGET};
use crate::oid::Oid;
use crate::pdu::Pdu;
use crate::value::Value;
use crate::varbind::VarBind;

use super::oids;

/// Validation applied to the standard varbind prefix of received notifications.
///
/// This policy affects only SNMPv2c and SNMPv3 TrapV2 and Inform PDUs. Both
/// modes require at least two varbinds whose values are `TimeTicks` followed by
/// `ObjectIdentifier`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum NotificationVarbindValidation {
    /// Accept any names for the two mandatory values.
    ///
    /// This accommodates devices that send usable notification values under
    /// non-standard OID names.
    #[default]
    Tolerant,
    /// Require the names and order specified by RFC 3416.
    ///
    /// The first name must be `sysUpTime.0` and the second must be
    /// `snmpTrapOID.0`.
    Strict,
}

/// Extract uptime, trap OID, and additional varbinds from a notification PDU.
pub(crate) fn extract_notification_varbinds(
    pdu: &Pdu,
    policy: NotificationVarbindValidation,
) -> Result<(u32, Oid, Vec<VarBind>)> {
    let (uptime, trap_oid) = notification_prefix(pdu, policy)?;
    Ok((uptime, trap_oid, pdu.varbinds[2..].to_vec()))
}

fn notification_prefix(pdu: &Pdu, policy: NotificationVarbindValidation) -> Result<(u32, Oid)> {
    let target = UNKNOWN_TARGET;

    if pdu.varbinds.len() < 2 {
        tracing::debug!(target: "async_snmp::notification", { kind = %DecodeErrorKind::MissingPdu }, "notification has fewer than 2 varbinds");
        return Err(Error::MalformedResponse { target }.boxed());
    }

    if policy == NotificationVarbindValidation::Strict && pdu.varbinds[0].oid != oids::sys_uptime()
    {
        tracing::warn!(target: "async_snmp::notification", { expected = %oids::sys_uptime(), actual = %pdu.varbinds[0].oid }, "strict mode: first varbind OID is not sysUpTime.0");
        tracing::debug!(target: "async_snmp::notification", { kind = %DecodeErrorKind::InvalidOid }, "invalid first varbind OID");
        return Err(Error::MalformedResponse { target }.boxed());
    }
    let uptime = match &pdu.varbinds[0].value {
        Value::TimeTicks(ticks) => *ticks,
        _ => {
            tracing::debug!(target: "async_snmp::notification", { kind = %DecodeErrorKind::MissingPdu }, "first varbind is not TimeTicks");
            return Err(Error::MalformedResponse { target }.boxed());
        }
    };

    if policy == NotificationVarbindValidation::Strict
        && pdu.varbinds[1].oid != oids::snmp_trap_oid()
    {
        tracing::warn!(target: "async_snmp::notification", { expected = %oids::snmp_trap_oid(), actual = %pdu.varbinds[1].oid }, "strict mode: second varbind OID is not snmpTrapOID.0");
        tracing::debug!(target: "async_snmp::notification", { kind = %DecodeErrorKind::InvalidOid }, "invalid second varbind OID");
        return Err(Error::MalformedResponse { target }.boxed());
    }
    let trap_oid = match &pdu.varbinds[1].value {
        Value::ObjectIdentifier(oid) => oid.clone(),
        _ => {
            tracing::debug!(target: "async_snmp::notification", { kind = %DecodeErrorKind::MissingPdu }, "second varbind is not OID");
            return Err(Error::MalformedResponse { target }.boxed());
        }
    };

    Ok((uptime, trap_oid))
}

/// Validate notification varbinds strictly per RFC 3416.
///
/// Returns `true` if the first two varbinds have the correct OIDs:
/// - First: sysUpTime.0 (1.3.6.1.2.1.1.3.0) with `TimeTicks` value
/// - Second: snmpTrapOID.0 (1.3.6.1.6.3.1.1.4.1.0) with OID value
///
/// This is useful for validating incoming notifications before processing.
#[must_use]
pub fn validate_notification_varbinds(pdu: &Pdu) -> bool {
    notification_prefix(pdu, NotificationVarbindValidation::Strict).is_ok()
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

        let (uptime, trap_oid, varbinds) =
            extract_notification_varbinds(&pdu, NotificationVarbindValidation::Tolerant).unwrap();
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

        for policy in [
            NotificationVarbindValidation::Tolerant,
            NotificationVarbindValidation::Strict,
        ] {
            assert!(extract_notification_varbinds(&pdu, policy).is_err());
        }
    }

    #[test]
    fn tolerant_accepts_nonstandard_prefix_names_but_strict_rejects_them() {
        let pdu = Pdu {
            pdu_type: PduType::TrapV2,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbinds: vec![
                VarBind::new(oid!(1, 2, 3, 4), Value::TimeTicks(12345)),
                VarBind::new(oid!(1, 2, 3, 5), Value::ObjectIdentifier(oids::link_down())),
            ],
        };

        let result =
            extract_notification_varbinds(&pdu, NotificationVarbindValidation::Tolerant).unwrap();
        assert_eq!(result.0, 12345);
        assert_eq!(result.1, oids::link_down());
        assert!(
            extract_notification_varbinds(&pdu, NotificationVarbindValidation::Strict).is_err()
        );
        assert!(!validate_notification_varbinds(&pdu));
    }

    #[test]
    fn strict_rejects_each_incorrect_prefix_name() {
        for varbinds in [
            vec![
                VarBind::new(oid!(1, 2, 3, 4), Value::TimeTicks(12345)),
                VarBind::new(
                    oids::snmp_trap_oid(),
                    Value::ObjectIdentifier(oids::link_down()),
                ),
            ],
            vec![
                VarBind::new(oids::sys_uptime(), Value::TimeTicks(12345)),
                VarBind::new(oid!(1, 2, 3, 4), Value::ObjectIdentifier(oids::link_down())),
            ],
        ] {
            let pdu = Pdu {
                pdu_type: PduType::TrapV2,
                request_id: 1,
                error_status: 0,
                error_index: 0,
                varbinds,
            };
            assert!(
                extract_notification_varbinds(&pdu, NotificationVarbindValidation::Strict).is_err()
            );
        }
    }

    #[test]
    fn both_policies_reject_each_incorrect_prefix_value_type() {
        for varbinds in [
            vec![
                VarBind::new(oids::sys_uptime(), Value::Integer(12345)),
                VarBind::new(
                    oids::snmp_trap_oid(),
                    Value::ObjectIdentifier(oids::link_down()),
                ),
            ],
            vec![
                VarBind::new(oids::sys_uptime(), Value::TimeTicks(12345)),
                VarBind::new(oids::snmp_trap_oid(), Value::Integer(1)),
            ],
        ] {
            let pdu = Pdu {
                pdu_type: PduType::TrapV2,
                request_id: 1,
                error_status: 0,
                error_index: 0,
                varbinds,
            };
            for policy in [
                NotificationVarbindValidation::Tolerant,
                NotificationVarbindValidation::Strict,
            ] {
                assert!(extract_notification_varbinds(&pdu, policy).is_err());
            }
        }
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
