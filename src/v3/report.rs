//! Typed classification of SNMPv3 Report PDUs.

use crate::pdu::{Pdu, PduType};
use crate::{Oid, Value};

use super::report_oids;

/// Status carried by a structurally valid SNMPv3 Report PDU.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReportStatus {
    /// The requested security level is unsupported for the selected user.
    UnsupportedSecurityLevel { counter: u32 },
    /// The authenticated message was outside the authoritative engine's time window.
    NotInTimeWindow { counter: u32 },
    /// The requested USM security name is unknown.
    UnknownUserName { counter: u32 },
    /// The authoritative engine ID is unknown.
    UnknownEngineId { counter: u32 },
    /// Authentication verification failed.
    WrongDigest { counter: u32 },
    /// Scoped-PDU decryption failed.
    DecryptionError { counter: u32 },
    /// A non-USM or otherwise unrecognized Report status.
    Other { oid: Oid, value: Value },
}

impl std::fmt::Display for ReportStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedSecurityLevel { counter } => {
                write!(f, "unsupported security level (counter {counter})")
            }
            Self::NotInTimeWindow { counter } => {
                write!(f, "message outside time window (counter {counter})")
            }
            Self::UnknownUserName { counter } => {
                write!(f, "unknown user name (counter {counter})")
            }
            Self::UnknownEngineId { counter } => {
                write!(f, "unknown engine ID (counter {counter})")
            }
            Self::WrongDigest { counter } => write!(f, "wrong digest (counter {counter})"),
            Self::DecryptionError { counter } => {
                write!(f, "decryption error (counter {counter})")
            }
            Self::Other { oid, .. } => write!(f, "unrecognized Report status {oid}"),
        }
    }
}

/// Error returned when a PDU does not have the exact shape required for a Report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("malformed SNMPv3 Report PDU")]
pub struct MalformedReport;

/// Classify an SNMPv3 Report PDU after security processing and message correlation.
///
/// A valid Report has zero error status/index and exactly one varbind. Standard
/// USM report objects must carry a `Counter32`; unknown report objects preserve
/// their value in [`ReportStatus::Other`].
pub fn classify_report(pdu: &Pdu) -> Result<ReportStatus, MalformedReport> {
    if pdu.pdu_type() != PduType::Report || pdu.error_status() != 0 || pdu.error_index() != 0 {
        return Err(MalformedReport);
    }

    let [varbind] = pdu.varbinds.as_slice() else {
        return Err(MalformedReport);
    };

    let standard_status = if varbind.oid == report_oids::unsupported_sec_levels() {
        Some(ReportStatus::UnsupportedSecurityLevel {
            counter: counter32(&varbind.value)?,
        })
    } else if varbind.oid == report_oids::not_in_time_windows() {
        Some(ReportStatus::NotInTimeWindow {
            counter: counter32(&varbind.value)?,
        })
    } else if varbind.oid == report_oids::unknown_user_names() {
        Some(ReportStatus::UnknownUserName {
            counter: counter32(&varbind.value)?,
        })
    } else if varbind.oid == report_oids::unknown_engine_ids() {
        Some(ReportStatus::UnknownEngineId {
            counter: counter32(&varbind.value)?,
        })
    } else if varbind.oid == report_oids::wrong_digests() {
        Some(ReportStatus::WrongDigest {
            counter: counter32(&varbind.value)?,
        })
    } else if varbind.oid == report_oids::decryption_errors() {
        Some(ReportStatus::DecryptionError {
            counter: counter32(&varbind.value)?,
        })
    } else {
        None
    };

    Ok(standard_status.unwrap_or_else(|| ReportStatus::Other {
        oid: varbind.oid.clone(),
        value: varbind.value.clone(),
    }))
}

fn counter32(value: &Value) -> Result<u32, MalformedReport> {
    match value {
        Value::Counter32(counter) => Ok(*counter),
        _ => Err(MalformedReport),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{VarBind, oid};

    fn report(oid: Oid, value: Value) -> Pdu {
        Pdu::standard(
            crate::pdu::StandardPduType::Report,
            1,
            0,
            0,
            vec![VarBind::new(oid, value)],
        )
    }

    #[test]
    fn classifies_every_standard_usm_status() {
        let cases = [
            (
                report_oids::unsupported_sec_levels(),
                ReportStatus::UnsupportedSecurityLevel { counter: 7 },
            ),
            (
                report_oids::not_in_time_windows(),
                ReportStatus::NotInTimeWindow { counter: 7 },
            ),
            (
                report_oids::unknown_user_names(),
                ReportStatus::UnknownUserName { counter: 7 },
            ),
            (
                report_oids::unknown_engine_ids(),
                ReportStatus::UnknownEngineId { counter: 7 },
            ),
            (
                report_oids::wrong_digests(),
                ReportStatus::WrongDigest { counter: 7 },
            ),
            (
                report_oids::decryption_errors(),
                ReportStatus::DecryptionError { counter: 7 },
            ),
        ];

        for (oid, expected) in cases {
            assert_eq!(
                classify_report(&report(oid, Value::Counter32(7))),
                Ok(expected)
            );
        }
    }

    #[test]
    fn preserves_unknown_report_status() {
        let oid = oid!(1, 3, 6, 1, 6, 3, 12, 1, 5, 0);
        assert_eq!(
            classify_report(&report(oid.clone(), Value::Integer(9))),
            Ok(ReportStatus::Other {
                oid,
                value: Value::Integer(9),
            })
        );
    }

    #[test]
    fn rejects_malformed_report_shapes() {
        let valid = report(report_oids::not_in_time_windows(), Value::Counter32(1));

        let mut non_report = valid.clone();
        assert!(non_report.set_standard_pdu_type(crate::pdu::StandardPduType::Response));
        assert_eq!(classify_report(&non_report), Err(MalformedReport));

        let mut status = valid.clone();
        assert!(status.set_error_status(1));
        assert_eq!(classify_report(&status), Err(MalformedReport));

        let mut index = valid.clone();
        assert!(index.set_error_index(1));
        assert_eq!(classify_report(&index), Err(MalformedReport));

        let mut empty = valid.clone();
        empty.varbinds.clear();
        assert_eq!(classify_report(&empty), Err(MalformedReport));

        let mut multiple = valid.clone();
        multiple.varbinds.push(VarBind::new(
            report_oids::wrong_digests(),
            Value::Counter32(2),
        ));
        assert_eq!(classify_report(&multiple), Err(MalformedReport));

        let wrong_type = report(report_oids::not_in_time_windows(), Value::Integer(1));
        assert_eq!(classify_report(&wrong_type), Err(MalformedReport));
    }
}
