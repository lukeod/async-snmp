//! Variable binding (VarBind) type.
//!
//! A VarBind pairs an OID with a value.

use crate::ber::{Decoder, EncodeBuf};
use crate::error::Result;
use crate::oid::Oid;
use crate::value::Value;

/// Variable binding - an OID-value pair.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VarBind {
    /// The object identifier.
    pub oid: Oid,
    /// The value.
    pub value: Value,
}

impl VarBind {
    /// Create a new VarBind.
    pub fn new(oid: Oid, value: Value) -> Self {
        Self { oid, value }
    }

    /// Create a VarBind with a NULL value (for GET requests).
    pub fn null(oid: Oid) -> Self {
        Self {
            oid,
            value: Value::Null,
        }
    }

    /// Encode to BER.
    pub fn encode(&self, buf: &mut EncodeBuf) {
        buf.push_sequence(|buf| {
            self.value.encode(buf);
            buf.push_oid(&self.oid);
        });
    }

    /// Returns the exact encoded size of this VarBind in bytes.
    ///
    /// Computes the size arithmetically without allocating.
    /// Useful for response size estimation in GETBULK processing.
    pub fn encoded_size(&self) -> usize {
        use crate::ber::length_encoded_len;

        // VarBind is SEQUENCE { oid, value }
        let oid_len = self.oid.ber_encoded_len();
        let value_len = self.value.ber_encoded_len();
        let content_len = oid_len + value_len;

        // SEQUENCE tag (1) + length encoding + content
        1 + length_encoded_len(content_len) + content_len
    }

    /// Decode from BER.
    pub fn decode(decoder: &mut Decoder) -> Result<Self> {
        let mut seq = decoder.read_sequence()?;
        let oid = seq.read_oid()?;
        let value = Value::decode(&mut seq)?;
        Ok(VarBind { oid, value })
    }
}

impl std::fmt::Display for VarBind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} = {}", self.oid, self.value)
    }
}

/// Encodes a list of VarBinds to BER format.
///
/// Writes the VarBinds as a SEQUENCE of SEQUENCE elements, where each inner
/// SEQUENCE contains an OID and its associated value.
pub fn encode_varbind_list(buf: &mut EncodeBuf, varbinds: &[VarBind]) {
    buf.push_sequence(|buf| {
        // Encode in reverse order since we're using reverse buffer
        for vb in varbinds.iter().rev() {
            vb.encode(buf);
        }
    });
}

/// Decodes a BER-encoded VarBind list into a vector of VarBinds.
///
/// Expects a SEQUENCE containing zero or more VarBind SEQUENCE elements.
pub fn decode_varbind_list(decoder: &mut Decoder) -> Result<Vec<VarBind>> {
    let mut seq = decoder.read_sequence()?;

    // Estimate capacity: typical VarBind is 20-50 bytes, use 16 as conservative divisor
    // to minimize reallocations while not over-allocating
    let estimated_capacity = (seq.remaining() / 16).max(1);
    let mut varbinds = Vec::with_capacity(estimated_capacity);

    while !seq.is_empty() {
        varbinds.push(VarBind::decode(&mut seq)?);
    }

    Ok(varbinds)
}

/// Encodes OIDs with NULL values for GET requests.
///
/// Creates a VarBind list where each OID is paired with a NULL value,
/// as required by SNMP GET, GETNEXT, and GETBULK request PDUs.
pub fn encode_null_varbinds(buf: &mut EncodeBuf, oids: &[Oid]) {
    buf.push_sequence(|buf| {
        for oid in oids.iter().rev() {
            buf.push_sequence(|buf| {
                buf.push_null();
                buf.push_oid(oid);
            });
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oid;
    use bytes::Bytes;

    #[test]
    fn test_varbind_roundtrip() {
        let vb = VarBind::new(oid!(1, 3, 6, 1), Value::Integer(42));

        let mut buf = EncodeBuf::new();
        vb.encode(&mut buf);
        let bytes = buf.finish();

        let mut decoder = Decoder::new(bytes);
        let decoded = VarBind::decode(&mut decoder).unwrap();

        assert_eq!(vb, decoded);
    }

    #[test]
    fn test_varbind_list_roundtrip() {
        let varbinds = vec![
            VarBind::new(oid!(1, 3, 6, 1), Value::Integer(1)),
            VarBind::new(oid!(1, 3, 6, 2), Value::Integer(2)),
        ];

        let mut buf = EncodeBuf::new();
        encode_varbind_list(&mut buf, &varbinds);
        let bytes = buf.finish();

        let mut decoder = Decoder::new(bytes);
        let decoded = decode_varbind_list(&mut decoder).unwrap();

        assert_eq!(varbinds, decoded);
    }

    // ========================================================================
    // Exception Value VarBind Tests
    // ========================================================================

    #[test]
    fn test_varbind_no_such_object() {
        let vb = VarBind::new(oid!(1, 3, 6, 1, 2, 1, 1, 1, 0), Value::NoSuchObject);

        let mut buf = EncodeBuf::new();
        vb.encode(&mut buf);
        let bytes = buf.finish();

        let mut decoder = Decoder::new(bytes);
        let decoded = VarBind::decode(&mut decoder).unwrap();

        assert_eq!(vb, decoded);
        assert!(decoded.value.is_exception());
    }

    #[test]
    fn test_varbind_no_such_instance() {
        let vb = VarBind::new(oid!(1, 3, 6, 1, 2, 1, 1, 1, 0), Value::NoSuchInstance);

        let mut buf = EncodeBuf::new();
        vb.encode(&mut buf);
        let bytes = buf.finish();

        let mut decoder = Decoder::new(bytes);
        let decoded = VarBind::decode(&mut decoder).unwrap();

        assert_eq!(vb, decoded);
        assert!(decoded.value.is_exception());
    }

    #[test]
    fn test_varbind_end_of_mib_view() {
        let vb = VarBind::new(oid!(1, 3, 6, 1, 2, 1, 1, 1, 0), Value::EndOfMibView);

        let mut buf = EncodeBuf::new();
        vb.encode(&mut buf);
        let bytes = buf.finish();

        let mut decoder = Decoder::new(bytes);
        let decoded = VarBind::decode(&mut decoder).unwrap();

        assert_eq!(vb, decoded);
        assert!(decoded.value.is_exception());
    }

    // ========================================================================
    // VarBind List Edge Cases
    // ========================================================================

    #[test]
    fn test_varbind_list_empty() {
        let varbinds: Vec<VarBind> = vec![];

        let mut buf = EncodeBuf::new();
        encode_varbind_list(&mut buf, &varbinds);
        let bytes = buf.finish();

        let mut decoder = Decoder::new(bytes);
        let decoded = decode_varbind_list(&mut decoder).unwrap();

        assert!(decoded.is_empty());
    }

    #[test]
    fn test_varbind_list_single() {
        let varbinds = vec![VarBind::new(oid!(1, 3, 6, 1), Value::Integer(42))];

        let mut buf = EncodeBuf::new();
        encode_varbind_list(&mut buf, &varbinds);
        let bytes = buf.finish();

        let mut decoder = Decoder::new(bytes);
        let decoded = decode_varbind_list(&mut decoder).unwrap();

        assert_eq!(varbinds, decoded);
    }

    #[test]
    fn test_varbind_list_with_exceptions() {
        let varbinds = vec![
            VarBind::new(
                oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
                Value::OctetString(Bytes::from_static(b"Linux router")),
            ),
            VarBind::new(oid!(1, 3, 6, 1, 2, 1, 1, 99, 0), Value::NoSuchObject),
            VarBind::new(oid!(1, 3, 6, 1, 2, 1, 1, 3, 0), Value::TimeTicks(123456)),
            VarBind::new(oid!(1, 3, 6, 1, 2, 1, 1, 100, 0), Value::NoSuchInstance),
        ];

        let mut buf = EncodeBuf::new();
        encode_varbind_list(&mut buf, &varbinds);
        let bytes = buf.finish();

        let mut decoder = Decoder::new(bytes);
        let decoded = decode_varbind_list(&mut decoder).unwrap();

        assert_eq!(varbinds, decoded);
        assert!(!decoded[0].value.is_exception());
        assert!(decoded[1].value.is_exception());
        assert!(!decoded[2].value.is_exception());
        assert!(decoded[3].value.is_exception());
    }

    #[test]
    fn test_varbind_list_all_exceptions() {
        let varbinds = vec![
            VarBind::new(oid!(1, 3, 6, 1, 2, 1, 1, 1, 0), Value::NoSuchObject),
            VarBind::new(oid!(1, 3, 6, 1, 2, 1, 1, 2, 0), Value::NoSuchInstance),
            VarBind::new(oid!(1, 3, 6, 1, 2, 1, 1, 3, 0), Value::EndOfMibView),
        ];

        let mut buf = EncodeBuf::new();
        encode_varbind_list(&mut buf, &varbinds);
        let bytes = buf.finish();

        let mut decoder = Decoder::new(bytes);
        let decoded = decode_varbind_list(&mut decoder).unwrap();

        assert_eq!(varbinds, decoded);
        assert!(decoded.iter().all(|vb| vb.value.is_exception()));
    }

    #[test]
    fn test_varbind_list_mixed_value_types() {
        let varbinds = vec![
            VarBind::new(
                oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
                Value::OctetString(Bytes::from_static(b"test")),
            ),
            VarBind::new(oid!(1, 3, 6, 1, 2, 1, 1, 2, 0), Value::Integer(42)),
            VarBind::new(oid!(1, 3, 6, 1, 2, 1, 1, 3, 0), Value::Counter32(1000)),
            VarBind::new(oid!(1, 3, 6, 1, 2, 1, 1, 4, 0), Value::Gauge32(500)),
            VarBind::new(oid!(1, 3, 6, 1, 2, 1, 1, 5, 0), Value::TimeTicks(99999)),
            VarBind::new(
                oid!(1, 3, 6, 1, 2, 1, 1, 6, 0),
                Value::IpAddress([192, 168, 1, 1]),
            ),
            VarBind::new(oid!(1, 3, 6, 1, 2, 1, 1, 7, 0), Value::Counter64(u64::MAX)),
            VarBind::new(
                oid!(1, 3, 6, 1, 2, 1, 1, 8, 0),
                Value::ObjectIdentifier(oid!(1, 3, 6, 1, 4)),
            ),
            VarBind::new(oid!(1, 3, 6, 1, 2, 1, 1, 9, 0), Value::Null),
        ];

        let mut buf = EncodeBuf::new();
        encode_varbind_list(&mut buf, &varbinds);
        let bytes = buf.finish();

        let mut decoder = Decoder::new(bytes);
        let decoded = decode_varbind_list(&mut decoder).unwrap();

        assert_eq!(varbinds, decoded);
    }

    #[test]
    fn test_null_varbinds_encoding() {
        let oids = vec![
            oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
            oid!(1, 3, 6, 1, 2, 1, 1, 3, 0),
            oid!(1, 3, 6, 1, 2, 1, 1, 5, 0),
        ];

        let mut buf = EncodeBuf::new();
        encode_null_varbinds(&mut buf, &oids);
        let bytes = buf.finish();

        let mut decoder = Decoder::new(bytes);
        let decoded = decode_varbind_list(&mut decoder).unwrap();

        assert_eq!(decoded.len(), 3);
        for (i, vb) in decoded.iter().enumerate() {
            assert_eq!(vb.oid, oids[i]);
            assert_eq!(vb.value, Value::Null);
        }
    }

    #[test]
    fn test_null_varbinds_empty() {
        let oids: Vec<Oid> = vec![];

        let mut buf = EncodeBuf::new();
        encode_null_varbinds(&mut buf, &oids);
        let bytes = buf.finish();

        let mut decoder = Decoder::new(bytes);
        let decoded = decode_varbind_list(&mut decoder).unwrap();

        assert!(decoded.is_empty());
    }

    // ========================================================================
    // VarBind Display Tests
    // ========================================================================

    #[test]
    fn test_varbind_display() {
        let vb = VarBind::new(oid!(1, 3, 6, 1, 2, 1, 1, 1, 0), Value::Integer(42));
        let display = format!("{}", vb);
        assert!(display.contains("1.3.6.1.2.1.1.1.0"));
        assert!(display.contains("42"));
    }

    #[test]
    fn test_varbind_display_exception() {
        let vb = VarBind::new(oid!(1, 3, 6, 1), Value::NoSuchObject);
        let display = format!("{}", vb);
        assert!(display.contains("noSuchObject"));
    }

    // ========================================================================
    // VarBind::null() Constructor Test
    // ========================================================================

    #[test]
    fn test_varbind_null_constructor() {
        let vb = VarBind::null(oid!(1, 3, 6, 1, 2, 1, 1, 1, 0));
        assert_eq!(vb.oid, oid!(1, 3, 6, 1, 2, 1, 1, 1, 0));
        assert_eq!(vb.value, Value::Null);
    }

    // ========================================================================
    // VarBind::encoded_size() Tests
    // ========================================================================

    /// Helper to verify encoded_size() matches actual encoding length
    fn verify_encoded_size(vb: &VarBind) {
        let mut buf = EncodeBuf::new();
        vb.encode(&mut buf);
        let actual = buf.len();
        let computed = vb.encoded_size();
        assert_eq!(
            computed, actual,
            "encoded_size mismatch for {:?}: computed={}, actual={}",
            vb, computed, actual
        );
    }

    #[test]
    fn test_encoded_size_null() {
        verify_encoded_size(&VarBind::null(oid!(1, 3, 6, 1)));
        verify_encoded_size(&VarBind::null(oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)));
    }

    #[test]
    fn test_encoded_size_integer() {
        verify_encoded_size(&VarBind::new(oid!(1, 3, 6, 1), Value::Integer(0)));
        verify_encoded_size(&VarBind::new(oid!(1, 3, 6, 1), Value::Integer(127)));
        verify_encoded_size(&VarBind::new(oid!(1, 3, 6, 1), Value::Integer(128)));
        verify_encoded_size(&VarBind::new(oid!(1, 3, 6, 1), Value::Integer(-1)));
        verify_encoded_size(&VarBind::new(oid!(1, 3, 6, 1), Value::Integer(i32::MAX)));
        verify_encoded_size(&VarBind::new(oid!(1, 3, 6, 1), Value::Integer(i32::MIN)));
    }

    #[test]
    fn test_encoded_size_octet_string() {
        verify_encoded_size(&VarBind::new(
            oid!(1, 3, 6, 1),
            Value::OctetString(Bytes::new()),
        ));
        verify_encoded_size(&VarBind::new(
            oid!(1, 3, 6, 1),
            Value::OctetString(Bytes::from_static(b"hello world")),
        ));
        // Large string
        verify_encoded_size(&VarBind::new(
            oid!(1, 3, 6, 1),
            Value::OctetString(Bytes::from(vec![0u8; 200])),
        ));
    }

    #[test]
    fn test_encoded_size_counters() {
        verify_encoded_size(&VarBind::new(oid!(1, 3, 6, 1), Value::Counter32(0)));
        verify_encoded_size(&VarBind::new(oid!(1, 3, 6, 1), Value::Counter32(u32::MAX)));
        verify_encoded_size(&VarBind::new(oid!(1, 3, 6, 1), Value::Gauge32(12345)));
        verify_encoded_size(&VarBind::new(oid!(1, 3, 6, 1), Value::TimeTicks(99999)));
        verify_encoded_size(&VarBind::new(oid!(1, 3, 6, 1), Value::Counter64(0)));
        verify_encoded_size(&VarBind::new(oid!(1, 3, 6, 1), Value::Counter64(u64::MAX)));
    }

    #[test]
    fn test_encoded_size_oid_value() {
        verify_encoded_size(&VarBind::new(
            oid!(1, 3, 6, 1, 2, 1, 1, 2, 0),
            Value::ObjectIdentifier(oid!(1, 3, 6, 1, 4, 1, 9999)),
        ));
    }

    #[test]
    fn test_encoded_size_exceptions() {
        verify_encoded_size(&VarBind::new(oid!(1, 3, 6, 1), Value::NoSuchObject));
        verify_encoded_size(&VarBind::new(oid!(1, 3, 6, 1), Value::NoSuchInstance));
        verify_encoded_size(&VarBind::new(oid!(1, 3, 6, 1), Value::EndOfMibView));
    }

    #[test]
    fn test_encoded_size_ip_address() {
        verify_encoded_size(&VarBind::new(
            oid!(1, 3, 6, 1),
            Value::IpAddress([192, 168, 1, 1]),
        ));
    }

    mod proptests {
        use super::*;
        use crate::oid::Oid;
        use proptest::prelude::*;

        fn arb_oid() -> impl Strategy<Value = Oid> {
            // Generate valid OIDs: first arc 0-2, second arc 0-39 (for arc1 < 2) or 0-999
            (0u32..3, 0u32..40, prop::collection::vec(0u32..10000, 0..8)).prop_map(
                |(arc1, arc2, rest)| {
                    let mut arcs = vec![arc1, arc2];
                    arcs.extend(rest);
                    Oid::from_slice(&arcs)
                },
            )
        }

        fn arb_value() -> impl Strategy<Value = Value> {
            prop_oneof![
                any::<i32>().prop_map(Value::Integer),
                prop::collection::vec(any::<u8>(), 0..256)
                    .prop_map(|v| Value::OctetString(Bytes::from(v))),
                Just(Value::Null),
                arb_oid().prop_map(Value::ObjectIdentifier),
                any::<[u8; 4]>().prop_map(Value::IpAddress),
                any::<u32>().prop_map(Value::Counter32),
                any::<u32>().prop_map(Value::Gauge32),
                any::<u32>().prop_map(Value::TimeTicks),
                any::<u64>().prop_map(Value::Counter64),
                Just(Value::NoSuchObject),
                Just(Value::NoSuchInstance),
                Just(Value::EndOfMibView),
            ]
        }

        proptest! {
            #[test]
            fn encoded_size_matches_encoding(
                oid in arb_oid(),
                value in arb_value()
            ) {
                let vb = VarBind::new(oid, value);
                let mut buf = EncodeBuf::new();
                vb.encode(&mut buf);
                prop_assert_eq!(
                    vb.encoded_size(),
                    buf.len(),
                    "encoded_size mismatch: computed={}, actual={}",
                    vb.encoded_size(),
                    buf.len()
                );
            }
        }
    }
}
