//! Exact outbound response-size finalization shared by responders.

use std::sync::atomic::{AtomicU32, Ordering};

use bytes::Bytes;

use crate::Version;
use crate::error::Result;
use crate::pdu::{Pdu, ResponsePdu};

/// The result of exact response finalization.
#[derive(Debug)]
pub(crate) enum FinalizedResponse {
    /// The requested candidate fit the effective limit.
    Candidate(Bytes),
    /// The candidate did not fit, but the protocol's `tooBig` alternate did.
    Alternate(Bytes),
    /// Neither the candidate nor its alternate fit.
    Dropped,
}

impl FinalizedResponse {
    pub(crate) fn into_bytes(self) -> Option<Bytes> {
        match self {
            Self::Candidate(bytes) | Self::Alternate(bytes) => Some(bytes),
            Self::Dropped => None,
        }
    }

    #[cfg(all(test, feature = "agent"))]
    pub(crate) fn is_none(&self) -> bool {
        matches!(self, Self::Dropped)
    }

    #[cfg(all(test, feature = "agent"))]
    pub(crate) fn is_some(&self) -> bool {
        !self.is_none()
    }

    #[cfg(all(test, feature = "agent"))]
    pub(crate) fn expect(self, message: &str) -> Bytes {
        self.into_bytes().expect(message)
    }
}

/// Return the smaller local/originator response limit.
pub(crate) fn effective_limit(local_limit: usize, originator_limit: Option<usize>) -> usize {
    originator_limit.map_or(local_limit, |limit| local_limit.min(limit))
}

/// Encode a response candidate exactly and apply the version-specific `tooBig`
/// fallback when it exceeds the effective response limit.
///
/// `snmpSilentDrops` is incremented only when the confirmed request's alternate
/// also fails the exact encoded-size check.
pub(crate) fn finalize_response(
    version: Version,
    request: &Pdu,
    candidate: Pdu,
    local_limit: usize,
    originator_limit: Option<usize>,
    silent_drops: &AtomicU32,
    mut encode: impl FnMut(Pdu) -> Result<Bytes>,
) -> Result<FinalizedResponse> {
    let limit = effective_limit(local_limit, originator_limit);
    let candidate = encode(candidate)?;
    if candidate.len() <= limit {
        return Ok(FinalizedResponse::Candidate(candidate));
    }

    let varbinds = if version == Version::V1 {
        request.varbinds.clone()
    } else {
        Vec::new()
    };
    let alternate = ResponsePdu::too_big(version, request.request_id(), varbinds)?.into_raw();
    let alternate = encode(alternate)?;
    if alternate.len() <= limit {
        Ok(FinalizedResponse::Alternate(alternate))
    } else {
        silent_drops.fetch_add(1, Ordering::Relaxed);
        Ok(FinalizedResponse::Dropped)
    }
}

/// Apply the exact local/originator limit to a Report whose PDU class could not
/// be recovered during security processing. Such a Report has no confirmed
/// request from which to construct an alternate Response and never affects
/// `snmpSilentDrops`.
pub(crate) fn finalize_report(
    report: Bytes,
    local_limit: usize,
    originator_limit: Option<usize>,
) -> Option<Bytes> {
    (report.len() <= effective_limit(local_limit, originator_limit)).then_some(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oid;
    use crate::{ErrorStatus, Value, VarBind};

    fn request() -> Pdu {
        Pdu::standard(
            crate::pdu::StandardPduType::GetRequest,
            7,
            0,
            0,
            vec![VarBind::new(
                oid!(1, 3, 6, 1),
                Value::OctetString(Bytes::from_static(b"request-value")),
            )],
        )
    }

    fn encode_structured_response(version: Version, pdu: Pdu) -> Result<Bytes> {
        match version {
            Version::V1 | Version::V2c => {
                let version = match version {
                    Version::V1 => crate::CommunityVersion::V1,
                    Version::V2c => crate::CommunityVersion::V2c,
                    Version::V3 => unreachable!("V3 handled separately"),
                };
                crate::message::CommunityMessage::new(version, "public", pdu)?.encode()
            }
            Version::V3 => {
                crate::message::ScopedPdu::new(Bytes::from_static(b"engine"), Bytes::new(), pdu)
                    .encode_to_bytes()
            }
        }
    }

    #[test]
    fn exact_candidate_boundaries_and_local_originator_minimum() {
        let request = request();
        for (local, originator, expected) in [
            (99, Some(100), FinalizedResponseKind::Alternate),
            (100, Some(101), FinalizedResponseKind::Candidate),
            (101, Some(100), FinalizedResponseKind::Candidate),
        ] {
            let counter = AtomicU32::new(0);
            let result = finalize_response(
                Version::V2c,
                &request,
                Pdu::response(7, 0, 0, vec![]),
                local,
                originator,
                &counter,
                |pdu| {
                    let len = if pdu.error_status() == ErrorStatus::TooBig.as_i32() {
                        40
                    } else {
                        100
                    };
                    Ok(Bytes::from(vec![0; len]))
                },
            )
            .unwrap();
            assert_eq!(FinalizedResponseKind::from(&result), expected);
            assert_eq!(counter.load(Ordering::Relaxed), 0);
        }
    }

    #[test]
    fn counter_changes_only_when_alternate_cannot_fit() {
        let request = request();
        let counter = AtomicU32::new(0);
        let result = finalize_response(
            Version::V2c,
            &request,
            Pdu::response(7, 0, 0, request.varbinds.clone()),
            39,
            None,
            &counter,
            |pdu| {
                let len = if pdu.error_status() == ErrorStatus::TooBig.as_i32() {
                    40
                } else {
                    100
                };
                Ok(Bytes::from(vec![0; len]))
            },
        )
        .unwrap();
        assert!(matches!(result, FinalizedResponse::Dropped));
        assert_eq!(counter.load(Ordering::Relaxed), 1);

        assert!(finalize_report(Bytes::from(vec![0; 100]), 99, None).is_none());
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn v1_alternate_keeps_identical_varbinds() {
        let request = request();
        let counter = AtomicU32::new(0);
        let result = finalize_response(
            Version::V1,
            &request,
            Pdu::response(7, 0, 0, vec![]),
            50,
            None,
            &counter,
            |pdu| {
                if pdu.error_status() == ErrorStatus::TooBig.as_i32() {
                    assert_eq!(pdu.varbinds, request.varbinds);
                    Ok(Bytes::from(vec![0; 50]))
                } else {
                    Ok(Bytes::from(vec![0; 51]))
                }
            },
        )
        .unwrap();
        assert!(matches!(result, FinalizedResponse::Alternate(_)));
    }

    #[test]
    fn generated_alternates_pass_version_specific_structured_validation() {
        for version in [Version::V1, Version::V2c, Version::V3] {
            let request = request();
            let candidate = Pdu::response(
                request.request_id,
                0,
                0,
                vec![VarBind::new(
                    oid!(1, 3, 6, 1, 4, 1),
                    Value::OctetString(Bytes::from(vec![0x55; 300])),
                )],
            );
            let candidate_size = encode_structured_response(version, candidate.clone())
                .unwrap()
                .len();
            let counter = AtomicU32::new(0);
            let mut saw_alternate = false;
            let result = finalize_response(
                version,
                &request,
                candidate,
                candidate_size - 1,
                None,
                &counter,
                |pdu| {
                    if pdu.error_status() == ErrorStatus::TooBig.as_i32() {
                        saw_alternate = true;
                        assert_eq!(pdu.error_index(), 0);
                        if version == Version::V1 {
                            assert_eq!(pdu.varbinds, request.varbinds);
                        } else {
                            assert!(pdu.varbinds.is_empty());
                        }
                    }
                    encode_structured_response(version, pdu)
                },
            )
            .unwrap();

            assert!(saw_alternate, "{version:?}");
            assert!(matches!(result, FinalizedResponse::Alternate(_)));
            assert_eq!(counter.load(Ordering::Relaxed), 0);
        }
    }

    #[test]
    fn community_exact_limit_minus_one_limit_and_plus_one() {
        let community = Bytes::from(vec![b'c'; 220]);
        for version in [Version::V1, Version::V2c] {
            let request = request();
            let candidate = Pdu::response(
                request.request_id,
                0,
                0,
                vec![VarBind::new(
                    oid!(1, 3, 6, 1, 4, 1),
                    Value::OctetString(Bytes::from(vec![0x55; 300])),
                )],
            );
            let encode = |pdu| {
                let version = match version {
                    Version::V1 => crate::CommunityVersion::V1,
                    Version::V2c => crate::CommunityVersion::V2c,
                    Version::V3 => unreachable!("V3 handled separately"),
                };
                crate::message::CommunityMessage::new(version, community.clone(), pdu)?.encode()
            };
            let exact = encode(candidate.clone()).unwrap().len();

            for (limit, candidate_fits) in [(exact - 1, false), (exact, true), (exact + 1, true)] {
                let counter = AtomicU32::new(0);
                let result = finalize_response(
                    version,
                    &request,
                    candidate.clone(),
                    limit,
                    None,
                    &counter,
                    encode,
                )
                .unwrap();
                if candidate_fits {
                    assert!(matches!(result, FinalizedResponse::Candidate(_)));
                } else {
                    assert!(matches!(result, FinalizedResponse::Alternate(_)));
                }
            }
        }
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[test]
    fn v3_all_security_levels_use_exact_boundaries_with_long_envelope_fields() {
        use crate::message::SecurityLevel;
        use crate::v3::encode::encode_v3_response;
        use crate::v3::{AuthProtocol, PrivProtocol, SaltCounter, UsmConfig, UsmSecurityParams};

        let engine_id = Bytes::from(vec![0x81; 32]);
        let username = Bytes::from(vec![b'u'; 32]);
        let context_name = Bytes::from(vec![b'x'; 240]);
        let request = request();
        let candidate = Pdu::response(
            request.request_id,
            0,
            0,
            vec![VarBind::new(
                oid!(1, 3, 6, 1, 4, 1),
                Value::OctetString(Bytes::from(vec![0x77; 300])),
            )],
        );

        for level in [
            SecurityLevel::NoAuthNoPriv,
            SecurityLevel::AuthNoPriv,
            SecurityLevel::AuthPriv,
        ] {
            let config = match level {
                SecurityLevel::NoAuthNoPriv => UsmConfig::new(username.clone()),
                SecurityLevel::AuthNoPriv => UsmConfig::new(username.clone())
                    .auth(AuthProtocol::Sha256, b"long-auth-password")
                    .unwrap(),
                SecurityLevel::AuthPriv => UsmConfig::new(username.clone())
                    .auth_priv(
                        AuthProtocol::Sha256,
                        b"long-auth-password",
                        PrivProtocol::Aes128,
                        b"long-privacy-password",
                    )
                    .unwrap(),
            };
            let keys = config.derive_keys(&engine_id).unwrap();
            let salt = SaltCounter::new().unwrap();
            let encode = |pdu| {
                encode_v3_response(
                    pdu,
                    17,
                    crate::UDP_RECEIVE_LIMITS.advertised(),
                    level,
                    UsmSecurityParams::new(engine_id.clone(), 7, 11, username.clone()).unwrap(),
                    engine_id.clone(),
                    context_name.clone(),
                    Some(&keys),
                    Some(&salt),
                    None,
                    "127.0.0.1:161".parse().unwrap(),
                )
            };
            let exact = encode(candidate.clone()).unwrap().len();
            for (local_limit, originator_limit, candidate_fits) in [
                (exact - 1, exact + 10, false),
                (exact, exact + 10, true),
                (exact + 1, exact + 10, true),
                // Exercise the actual V3 envelope with the originator as the
                // smaller effective limit at its exact boundaries.
                (exact + 10, exact - 1, false),
                (exact + 10, exact, true),
                (exact + 10, exact + 1, true),
            ] {
                let counter = AtomicU32::new(0);
                let result = finalize_response(
                    Version::V3,
                    &request,
                    candidate.clone(),
                    local_limit,
                    Some(originator_limit),
                    &counter,
                    encode,
                )
                .unwrap();
                if candidate_fits {
                    assert!(matches!(result, FinalizedResponse::Candidate(_)));
                } else {
                    assert!(matches!(result, FinalizedResponse::Alternate(_)));
                }
                assert_eq!(counter.load(Ordering::Relaxed), 0);
            }
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    enum FinalizedResponseKind {
        Candidate,
        Alternate,
        Dropped,
    }

    impl From<&FinalizedResponse> for FinalizedResponseKind {
        fn from(value: &FinalizedResponse) -> Self {
            match value {
                FinalizedResponse::Candidate(_) => Self::Candidate,
                FinalizedResponse::Alternate(_) => Self::Alternate,
                FinalizedResponse::Dropped => Self::Dropped,
            }
        }
    }
}
