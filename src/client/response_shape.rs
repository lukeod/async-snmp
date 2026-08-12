//! Fixed-cardinality response-shape validation.

use crate::{Oid, Value, VarBind};
use std::ops::Range;

/// Receive-side handling for malformed fixed-cardinality responses.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum ResponseShapePolicy {
    /// Preserve all decoded bindings and describe any shape anomalies.
    #[default]
    Compatible,
    /// Reject a response containing any shape anomaly.
    Strict,
}

/// The request operation associated with a fixed-cardinality response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FixedCardinalityOperation {
    Get,
    GetNext,
    Set,
}

/// Metadata retained from decoding one or more network responses.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResponseMetadata {
    /// Accepted BER/value deviations in response and decode order.
    pub decode_anomalies: Vec<crate::DecodeAnomaly>,
}

impl ResponseMetadata {
    pub(crate) fn append(&mut self, mut other: Self) {
        self.decode_anomalies.append(&mut other.decode_anomalies);
    }

    pub(crate) fn from_decode_anomalies(decode_anomalies: Vec<crate::DecodeAnomaly>) -> Self {
        Self { decode_anomalies }
    }
}

/// A GETBULK response and its wire-decode metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BulkResponse {
    /// Every decoded binding in received order.
    pub varbinds: Vec<VarBind>,
    /// Wire-decode metadata.
    pub metadata: ResponseMetadata,
}

/// A decoded fixed-cardinality response and its shape diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedCardinalityResponse {
    pub operation: FixedCardinalityOperation,
    /// Every decoded response binding, in received order.
    pub varbinds: Vec<VarBind>,
    /// Shape anomalies. Empty means the response exactly satisfied the request shape.
    pub anomalies: Vec<ResponseShapeAnomaly>,
    /// Accepted BER/value deviations from the wire response, in decode order.
    pub metadata: ResponseMetadata,
}

impl FixedCardinalityResponse {
    pub(crate) fn empty(operation: FixedCardinalityOperation) -> Self {
        Self {
            operation,
            varbinds: Vec::new(),
            anomalies: Vec::new(),
            metadata: ResponseMetadata::default(),
        }
    }

    /// Returns the sole response binding when the response has exactly one
    /// binding and no shape anomalies.
    ///
    /// Compatible response-shape handling can preserve empty, excess, renamed,
    /// or otherwise anomalous responses. Callers that require a valid singleton
    /// can use this method without discarding those diagnostics.
    #[must_use]
    pub fn single(&self) -> Option<&VarBind> {
        if self.anomalies.is_empty() {
            let [varbind] = self.varbinds.as_slice() else {
                return None;
            };
            Some(varbind)
        } else {
            None
        }
    }

    /// Consumes this response and returns its sole binding when it has exactly
    /// one binding and no shape anomalies.
    ///
    /// On failure, the original response is returned so that every received
    /// binding and shape diagnostic remains available to the caller.
    pub fn into_single(mut self) -> Result<VarBind, Self> {
        if self.anomalies.is_empty() && self.varbinds.len() == 1 {
            Ok(self.varbinds.remove(0))
        } else {
            Err(self)
        }
    }
}

/// A bounded, structured diagnostic for a fixed-cardinality response.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResponseShapeAnomaly {
    /// A response batch contained fewer bindings than requested.
    Truncated {
        request_range: Range<usize>,
        response_range: Range<usize>,
        expected: usize,
        actual: usize,
    },
    /// A response batch contained more bindings than requested.
    Excess {
        request_range: Range<usize>,
        response_range: Range<usize>,
        expected: usize,
        actual: usize,
    },
    /// An exact-count response is a uniquely provable non-identity permutation.
    Reordered {
        request_range: Range<usize>,
        response_range: Range<usize>,
    },
    /// An exact-count GET or SET response changed a positional OID.
    OidMismatch {
        request_index: usize,
        response_index: usize,
        expected: Oid,
        actual: Oid,
    },
    /// An ordinary GETNEXT result did not advance lexicographically.
    GetNextNotSuccessor {
        request_index: usize,
        response_index: usize,
        cursor: Oid,
        actual: Oid,
    },
    /// EndOfMibView was returned under a name other than the request cursor.
    GetNextEndOfMibNameMismatch {
        request_index: usize,
        response_index: usize,
        cursor: Oid,
        actual: Oid,
    },
    /// GETNEXT returned a non-EndOfMibView exception.
    GetNextUnexpectedException {
        request_index: usize,
        response_index: usize,
        value: Value,
    },
    /// An exact-count, positionally named SET echo changed a value.
    SetValueMismatch {
        request_index: usize,
        response_index: usize,
        expected: Value,
        actual: Value,
    },
}

pub(crate) enum RequestShape<'a> {
    Get(&'a [Oid]),
    GetNext(&'a [Oid]),
    Set(&'a [(Oid, Value)]),
}

impl RequestShape<'_> {
    fn operation(&self) -> FixedCardinalityOperation {
        match self {
            Self::Get(_) => FixedCardinalityOperation::Get,
            Self::GetNext(_) => FixedCardinalityOperation::GetNext,
            Self::Set(_) => FixedCardinalityOperation::Set,
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::Get(oids) | Self::GetNext(oids) => oids.len(),
            Self::Set(varbinds) => varbinds.len(),
        }
    }

    fn oid(&self, index: usize) -> &Oid {
        match self {
            Self::Get(oids) | Self::GetNext(oids) => &oids[index],
            Self::Set(varbinds) => &varbinds[index].0,
        }
    }
}

/// Classify one successful response batch. Count mismatches deliberately skip
/// semantic checks because positional correspondence is then ambiguous.
pub(crate) fn classify(
    request: RequestShape<'_>,
    varbinds: Vec<VarBind>,
    request_offset: usize,
    response_offset: usize,
) -> FixedCardinalityResponse {
    let operation = request.operation();
    let expected = request.len();
    let actual = varbinds.len();
    let request_range = request_offset..request_offset + expected;
    let response_range = response_offset..response_offset + actual;
    let mut anomalies = Vec::new();

    if actual != expected {
        anomalies.push(if actual < expected {
            ResponseShapeAnomaly::Truncated {
                request_range,
                response_range,
                expected,
                actual,
            }
        } else {
            ResponseShapeAnomaly::Excess {
                request_range,
                response_range,
                expected,
                actual,
            }
        });
        return FixedCardinalityResponse {
            operation,
            varbinds,
            anomalies,
            metadata: ResponseMetadata::default(),
        };
    }

    match &request {
        RequestShape::Get(_) | RequestShape::Set(_) => {
            if unique_non_identity_permutation(&request, &varbinds) {
                anomalies.push(ResponseShapeAnomaly::Reordered {
                    request_range,
                    response_range,
                });
            } else {
                for (index, vb) in varbinds.iter().enumerate() {
                    let expected_oid = request.oid(index);
                    if vb.oid != *expected_oid {
                        anomalies.push(ResponseShapeAnomaly::OidMismatch {
                            request_index: request_offset + index,
                            response_index: response_offset + index,
                            expected: expected_oid.clone(),
                            actual: vb.oid.clone(),
                        });
                    } else if let RequestShape::Set(values) = &request
                        && vb.value != values[index].1
                    {
                        anomalies.push(ResponseShapeAnomaly::SetValueMismatch {
                            request_index: request_offset + index,
                            response_index: response_offset + index,
                            expected: values[index].1.clone(),
                            actual: vb.value.clone(),
                        });
                    }
                }
            }
        }
        RequestShape::GetNext(cursors) => {
            for (index, (cursor, vb)) in cursors.iter().zip(&varbinds).enumerate() {
                let request_index = request_offset + index;
                let response_index = response_offset + index;
                match vb.value {
                    Value::EndOfMibView if vb.oid != *cursor => {
                        anomalies.push(ResponseShapeAnomaly::GetNextEndOfMibNameMismatch {
                            request_index,
                            response_index,
                            cursor: cursor.clone(),
                            actual: vb.oid.clone(),
                        });
                    }
                    Value::EndOfMibView => {}
                    Value::NoSuchObject | Value::NoSuchInstance => {
                        anomalies.push(ResponseShapeAnomaly::GetNextUnexpectedException {
                            request_index,
                            response_index,
                            value: vb.value.clone(),
                        });
                    }
                    _ if vb.oid <= *cursor => {
                        anomalies.push(ResponseShapeAnomaly::GetNextNotSuccessor {
                            request_index,
                            response_index,
                            cursor: cursor.clone(),
                            actual: vb.oid.clone(),
                        });
                    }
                    _ => {}
                }
            }
        }
    }

    FixedCardinalityResponse {
        operation,
        varbinds,
        anomalies,
        metadata: ResponseMetadata::default(),
    }
}

fn unique_non_identity_permutation(request: &RequestShape<'_>, varbinds: &[VarBind]) -> bool {
    if (0..request.len()).any(|i| (i + 1..request.len()).any(|j| request.oid(i) == request.oid(j)))
        || (0..varbinds.len())
            .any(|i| (i + 1..varbinds.len()).any(|j| varbinds[i].oid == varbinds[j].oid))
    {
        return false;
    }

    let Some(permutation) = varbinds
        .iter()
        .map(|vb| (0..request.len()).find(|&index| request.oid(index) == &vb.oid))
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };
    permutation
        .iter()
        .enumerate()
        .any(|(index, &mapped)| index != mapped)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oid(last: u32) -> Oid {
        Oid::from_slice(&[1, 3, 6, 1, last])
    }

    fn fixed_response(
        varbinds: Vec<VarBind>,
        anomalies: Vec<ResponseShapeAnomaly>,
    ) -> FixedCardinalityResponse {
        FixedCardinalityResponse {
            operation: FixedCardinalityOperation::Get,
            varbinds,
            anomalies,
            metadata: ResponseMetadata::default(),
        }
    }

    #[test]
    fn singleton_extractors_return_clean_single_binding() {
        let varbind = VarBind::new(oid(1), Value::Integer(42));
        let response = fixed_response(vec![varbind.clone()], Vec::new());

        assert_eq!(response.single(), Some(&varbind));
        assert_eq!(response.into_single(), Ok(varbind));
    }

    #[test]
    fn singleton_extractors_reject_other_cardinalities_and_preserve_response() {
        let responses = [
            fixed_response(Vec::new(), Vec::new()),
            fixed_response(
                vec![
                    VarBind::new(oid(1), Value::Integer(1)),
                    VarBind::new(oid(2), Value::Integer(2)),
                ],
                Vec::new(),
            ),
        ];

        for response in responses {
            assert_eq!(response.single(), None);
            assert_eq!(response.clone().into_single(), Err(response));
        }
    }

    #[test]
    fn singleton_extractors_reject_every_anomaly_and_preserve_response() {
        let anomalies = [
            ResponseShapeAnomaly::Truncated {
                request_range: 0..2,
                response_range: 0..1,
                expected: 2,
                actual: 1,
            },
            ResponseShapeAnomaly::Excess {
                request_range: 0..0,
                response_range: 0..1,
                expected: 0,
                actual: 1,
            },
            ResponseShapeAnomaly::Reordered {
                request_range: 0..1,
                response_range: 0..1,
            },
            ResponseShapeAnomaly::OidMismatch {
                request_index: 0,
                response_index: 0,
                expected: oid(1),
                actual: oid(2),
            },
            ResponseShapeAnomaly::GetNextNotSuccessor {
                request_index: 0,
                response_index: 0,
                cursor: oid(2),
                actual: oid(1),
            },
            ResponseShapeAnomaly::GetNextEndOfMibNameMismatch {
                request_index: 0,
                response_index: 0,
                cursor: oid(1),
                actual: oid(2),
            },
            ResponseShapeAnomaly::GetNextUnexpectedException {
                request_index: 0,
                response_index: 0,
                value: Value::NoSuchInstance,
            },
            ResponseShapeAnomaly::SetValueMismatch {
                request_index: 0,
                response_index: 0,
                expected: Value::Integer(1),
                actual: Value::Integer(2),
            },
        ];

        for anomaly in anomalies {
            let response = fixed_response(
                vec![VarBind::new(oid(1), Value::Integer(42))],
                vec![anomaly],
            );
            assert_eq!(response.single(), None);
            assert_eq!(response.clone().into_single(), Err(response));
        }
    }

    #[test]
    fn count_mismatch_does_not_infer_positional_semantics() {
        let response = classify(
            RequestShape::Get(&[oid(1), oid(2)]),
            vec![VarBind::null(oid(9))],
            4,
            7,
        );
        assert_eq!(response.varbinds, vec![VarBind::null(oid(9))]);
        assert!(matches!(
            response.anomalies.as_slice(),
            [ResponseShapeAnomaly::Truncated {
                request_range,
                response_range,
                expected: 2,
                actual: 1,
            }] if request_range == &(4..6) && response_range == &(7..8)
        ));
    }

    #[test]
    fn unique_reorder_is_distinguished_from_ambiguous_duplicates() {
        let reordered = classify(
            RequestShape::Get(&[oid(1), oid(2)]),
            vec![VarBind::null(oid(2)), VarBind::null(oid(1))],
            0,
            0,
        );
        assert!(matches!(
            reordered.anomalies[0],
            ResponseShapeAnomaly::Reordered { .. }
        ));

        let ambiguous = classify(
            RequestShape::Get(&[oid(1), oid(1)]),
            vec![VarBind::null(oid(1)), VarBind::null(oid(2))],
            0,
            0,
        );
        assert!(matches!(
            ambiguous.anomalies[0],
            ResponseShapeAnomaly::OidMismatch { .. }
        ));
    }

    #[test]
    fn getnext_exception_and_successor_rules_are_checked() {
        let cursors = [oid(1), oid(2), oid(3), oid(4)];
        let response = classify(
            RequestShape::GetNext(&cursors),
            vec![
                VarBind::new(oid(1), Value::Null),
                VarBind::new(oid(9), Value::EndOfMibView),
                VarBind::new(oid(3), Value::NoSuchInstance),
                VarBind::new(oid(5), Value::Integer(1)),
            ],
            0,
            0,
        );
        assert_eq!(response.anomalies.len(), 3);
        assert!(matches!(
            response.anomalies[0],
            ResponseShapeAnomaly::GetNextNotSuccessor { .. }
        ));
        assert!(matches!(
            response.anomalies[1],
            ResponseShapeAnomaly::GetNextEndOfMibNameMismatch { .. }
        ));
        assert!(matches!(
            response.anomalies[2],
            ResponseShapeAnomaly::GetNextUnexpectedException { .. }
        ));
    }

    #[test]
    fn set_changed_value_is_reported() {
        let requested = [(oid(1), Value::Integer(1))];
        let response = classify(
            RequestShape::Set(&requested),
            vec![VarBind::new(oid(1), Value::Integer(2))],
            0,
            0,
        );
        assert!(matches!(
            response.anomalies[0],
            ResponseShapeAnomaly::SetValueMismatch { .. }
        ));

        let requested = [(oid(1), Value::Integer(1)), (oid(2), Value::Integer(2))];
        let reordered = classify(
            RequestShape::Set(&requested),
            vec![
                VarBind::new(oid(2), Value::Integer(9)),
                VarBind::new(oid(1), Value::Integer(1)),
            ],
            0,
            0,
        );
        // Reordering is observable, but the classifier does not infer a
        // request-to-response mapping for value comparison.
        assert!(matches!(
            reordered.anomalies.as_slice(),
            [ResponseShapeAnomaly::Reordered { .. }]
        ));
    }
}
