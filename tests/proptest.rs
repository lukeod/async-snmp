//! Property-based tests for BER codec round-trips.
//!
//! Uses proptest to verify that encode(decode(x)) == x for all types.

use async_snmp::ber::{Decoder, EncodeBuf};
use async_snmp::oid::Oid;
use async_snmp::pdu::{GetBulkPdu, Pdu, PduType, TrapV1Pdu};
use async_snmp::value::Value;
use async_snmp::varbind::VarBind;
use bytes::Bytes;
use proptest::prelude::*;

// =============================================================================
// Arbitrary Implementations
// =============================================================================

/// Strategy for generating valid OIDs that can round-trip through BER.
///
/// OID constraints per X.690 Section 8.19:
/// - arc1 must be 0, 1, or 2
/// - arc2 must be <= 39 when arc1 is 0 or 1
/// - arc2 can be any value when arc1 is 2 (but limited to avoid overflow)
/// - BER encoding combines first two arcs as (arc1 * 40) + arc2, so single-arc
///   OIDs cannot round-trip (they become 2-arc OIDs on decode)
/// - Empty OIDs and OIDs with >= 2 arcs round-trip correctly
fn arb_oid() -> impl Strategy<Value = Oid> {
    prop_oneof![
        // Empty OID
        Just(Oid::empty()),
        // OIDs with 2+ arcs (these round-trip correctly)
        (0u32..=2, prop::collection::vec(any::<u32>(), 1..=19)).prop_filter_map(
            "valid OID",
            |(arc1, remaining_arcs)| {
                let arc2 = if arc1 < 2 {
                    // arc2 must be <= 39 when arc1 < 2
                    remaining_arcs[0] % 40
                } else {
                    // arc1 == 2: arc2 can be large, but must not overflow
                    // (arc1 * 40) + arc2 must fit in u32: arc2 <= u32::MAX - 80
                    remaining_arcs[0] % (u32::MAX - 80)
                };

                let mut arcs = vec![arc1, arc2];
                arcs.extend_from_slice(&remaining_arcs[1..]);

                let oid = Oid::from_slice(&arcs);
                if oid.validate().is_ok() {
                    Some(oid)
                } else {
                    None
                }
            }
        ),
    ]
}

/// Strategy for generating arbitrary byte data (for OctetString, Opaque).
fn arb_bytes() -> impl Strategy<Value = Bytes> {
    prop::collection::vec(any::<u8>(), 0..=256).prop_map(Bytes::from)
}

/// Strategy for generating valid Value variants.
fn arb_value() -> impl Strategy<Value = Value> {
    prop_oneof![
        // Integer: full i32 range
        any::<i32>().prop_map(Value::Integer),
        // OctetString: arbitrary bytes
        arb_bytes().prop_map(Value::OctetString),
        // Null
        Just(Value::Null),
        // ObjectIdentifier: valid OID
        arb_oid().prop_map(Value::ObjectIdentifier),
        // IpAddress: 4 bytes
        any::<[u8; 4]>().prop_map(Value::IpAddress),
        // Counter32: full u32 range
        any::<u32>().prop_map(Value::Counter32),
        // Gauge32: full u32 range
        any::<u32>().prop_map(Value::Gauge32),
        // TimeTicks: full u32 range
        any::<u32>().prop_map(Value::TimeTicks),
        // Opaque: arbitrary bytes
        arb_bytes().prop_map(Value::Opaque),
        // Counter64: full u64 range
        any::<u64>().prop_map(Value::Counter64),
        // Exception values
        Just(Value::NoSuchObject),
        Just(Value::NoSuchInstance),
        Just(Value::EndOfMibView),
    ]
}

/// Strategy for generating VarBinds.
fn arb_varbind() -> impl Strategy<Value = VarBind> {
    (arb_oid(), arb_value()).prop_map(|(oid, value)| VarBind::new(oid, value))
}

/// Strategy for generating a vector of VarBinds.
fn arb_varbinds() -> impl Strategy<Value = Vec<VarBind>> {
    prop::collection::vec(arb_varbind(), 0..=10)
}

/// Strategy for generating PDU types (excluding TrapV1 which has different structure).
fn arb_pdu_type() -> impl Strategy<Value = PduType> {
    prop_oneof![
        Just(PduType::GetRequest),
        Just(PduType::GetNextRequest),
        Just(PduType::Response),
        Just(PduType::SetRequest),
        Just(PduType::GetBulkRequest),
        Just(PduType::InformRequest),
        Just(PduType::TrapV2),
        Just(PduType::Report),
    ]
}

/// Strategy for generating generic PDUs.
fn arb_pdu() -> impl Strategy<Value = Pdu> {
    (
        arb_pdu_type(),
        any::<i32>(),
        any::<i32>(),
        any::<i32>(),
        arb_varbinds(),
    )
        .prop_map(
            |(pdu_type, request_id, error_status, error_index, varbinds)| Pdu {
                pdu_type,
                request_id,
                error_status,
                error_index,
                varbinds,
            },
        )
}

/// Strategy for generating GETBULK PDUs.
fn arb_getbulk_pdu() -> impl Strategy<Value = GetBulkPdu> {
    (any::<i32>(), 0i32..=100, 0i32..=1000, arb_varbinds()).prop_map(
        |(request_id, non_repeaters, max_repetitions, varbinds)| GetBulkPdu {
            request_id,
            non_repeaters,
            max_repetitions,
            varbinds,
        },
    )
}

/// Strategy for generating TrapV1 PDUs.
fn arb_trap_v1_pdu() -> impl Strategy<Value = TrapV1Pdu> {
    (
        arb_oid(),
        any::<[u8; 4]>(),
        0i32..=6,
        any::<i32>(),
        any::<u32>(),
        arb_varbinds(),
    )
        .prop_map(
            |(enterprise, agent_addr, generic_trap, specific_trap, time_stamp, varbinds)| {
                TrapV1Pdu {
                    enterprise,
                    agent_addr,
                    generic_trap,
                    specific_trap,
                    time_stamp,
                    varbinds,
                }
            },
        )
}

// =============================================================================
// Round-trip Property Tests
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    // -------------------------------------------------------------------------
    // OID round-trip tests
    // -------------------------------------------------------------------------

    #[test]
    fn oid_ber_roundtrip(oid in arb_oid()) {
        let encoded = oid.to_ber();
        let decoded = Oid::from_ber(&encoded).expect("decode should succeed");
        prop_assert_eq!(oid, decoded, "OID round-trip failed");
    }

    #[test]
    fn oid_display_parse_roundtrip(oid in arb_oid()) {
        // Only test non-empty OIDs since parse("") returns empty
        if !oid.is_empty() {
            let display = oid.to_string();
            let parsed = Oid::parse(&display).expect("parse should succeed");
            prop_assert_eq!(oid, parsed, "OID display/parse round-trip failed");
        }
    }

    // -------------------------------------------------------------------------
    // Value round-trip tests
    // -------------------------------------------------------------------------

    #[test]
    fn value_ber_roundtrip(value in arb_value()) {
        let mut buf = EncodeBuf::new();
        value.encode(&mut buf);
        let bytes = buf.finish();

        let mut decoder = Decoder::new(bytes);
        let decoded = Value::decode(&mut decoder).expect("decode should succeed");

        prop_assert_eq!(value, decoded, "Value round-trip failed");
    }

    // -------------------------------------------------------------------------
    // VarBind round-trip tests
    // -------------------------------------------------------------------------

    #[test]
    fn varbind_ber_roundtrip(varbind in arb_varbind()) {
        let mut buf = EncodeBuf::new();
        varbind.encode(&mut buf);
        let bytes = buf.finish();

        let mut decoder = Decoder::new(bytes);
        let decoded = VarBind::decode(&mut decoder).expect("decode should succeed");

        prop_assert_eq!(varbind, decoded, "VarBind round-trip failed");
    }

    // -------------------------------------------------------------------------
    // PDU round-trip tests
    // -------------------------------------------------------------------------

    #[test]
    fn pdu_ber_roundtrip(pdu in arb_pdu()) {
        let mut buf = EncodeBuf::new();
        pdu.encode(&mut buf);
        let bytes = buf.finish();

        let mut decoder = Decoder::new(bytes);
        let decoded = Pdu::decode(&mut decoder).expect("decode should succeed");

        prop_assert_eq!(pdu.pdu_type, decoded.pdu_type);
        prop_assert_eq!(pdu.request_id, decoded.request_id);
        prop_assert_eq!(pdu.error_status, decoded.error_status);
        prop_assert_eq!(pdu.error_index, decoded.error_index);
        prop_assert_eq!(pdu.varbinds, decoded.varbinds);
    }

    #[test]
    fn getbulk_pdu_ber_roundtrip(pdu in arb_getbulk_pdu()) {
        let mut buf = EncodeBuf::new();
        pdu.encode(&mut buf);
        let bytes = buf.finish();

        let mut decoder = Decoder::new(bytes);
        let decoded = GetBulkPdu::decode(&mut decoder).expect("decode should succeed");

        prop_assert_eq!(pdu.request_id, decoded.request_id);
        prop_assert_eq!(pdu.non_repeaters, decoded.non_repeaters);
        prop_assert_eq!(pdu.max_repetitions, decoded.max_repetitions);
        prop_assert_eq!(pdu.varbinds, decoded.varbinds);
    }

    #[test]
    fn trap_v1_pdu_ber_roundtrip(pdu in arb_trap_v1_pdu()) {
        let mut buf = EncodeBuf::new();
        pdu.encode(&mut buf);
        let bytes = buf.finish();

        let mut decoder = Decoder::new(bytes);
        let decoded = TrapV1Pdu::decode(&mut decoder).expect("decode should succeed");

        prop_assert_eq!(pdu.enterprise, decoded.enterprise);
        prop_assert_eq!(pdu.agent_addr, decoded.agent_addr);
        prop_assert_eq!(pdu.generic_trap, decoded.generic_trap);
        prop_assert_eq!(pdu.specific_trap, decoded.specific_trap);
        prop_assert_eq!(pdu.time_stamp, decoded.time_stamp);
        prop_assert_eq!(pdu.varbinds, decoded.varbinds);
    }

    // -------------------------------------------------------------------------
    // BER primitive round-trip tests
    // -------------------------------------------------------------------------

    #[test]
    fn integer_ber_roundtrip(value: i32) {
        let mut buf = EncodeBuf::new();
        buf.push_integer(value);
        let bytes = buf.finish();

        let mut decoder = Decoder::new(bytes);
        let decoded = decoder.read_integer().expect("decode should succeed");

        prop_assert_eq!(value, decoded);
    }

    #[test]
    fn unsigned32_ber_roundtrip(value: u32) {
        use async_snmp::ber::tag;

        let mut buf = EncodeBuf::new();
        buf.push_unsigned32(tag::application::COUNTER32, value);
        let bytes = buf.finish();

        let mut decoder = Decoder::new(bytes);
        let decoded = decoder.read_unsigned32(tag::application::COUNTER32).expect("decode should succeed");

        prop_assert_eq!(value, decoded);
    }

    #[test]
    fn counter64_ber_roundtrip(value: u64) {
        use async_snmp::ber::tag;

        let mut buf = EncodeBuf::new();
        buf.push_integer64(value);
        let bytes = buf.finish();

        let mut decoder = Decoder::new(bytes);
        let decoded = decoder.read_integer64(tag::application::COUNTER64).expect("decode should succeed");

        prop_assert_eq!(value, decoded);
    }

    #[test]
    fn octet_string_ber_roundtrip(data in prop::collection::vec(any::<u8>(), 0..=1024)) {
        let mut buf = EncodeBuf::new();
        buf.push_octet_string(&data);
        let bytes = buf.finish();

        let mut decoder = Decoder::new(bytes);
        let decoded = decoder.read_octet_string().expect("decode should succeed");

        prop_assert_eq!(&data[..], &decoded[..]);
    }

    #[test]
    fn ip_address_ber_roundtrip(addr: [u8; 4]) {
        let mut buf = EncodeBuf::new();
        buf.push_ip_address(addr);
        let bytes = buf.finish();

        let mut decoder = Decoder::new(bytes);
        let decoded = decoder.read_ip_address().expect("decode should succeed");

        prop_assert_eq!(addr, decoded);
    }
}

// =============================================================================
// Edge Case Tests (deterministic, not property-based)
// =============================================================================

#[test]
fn oid_empty_roundtrip() {
    let oid = Oid::empty();
    let encoded = oid.to_ber();
    assert!(encoded.is_empty());
    let decoded = Oid::from_ber(&encoded).unwrap();
    assert_eq!(oid, decoded);
}

#[test]
fn oid_single_arc_encoding_behavior() {
    // Single-arc OIDs encode as arc1 * 40, which decodes to [arc1, 0].
    // This is correct per X.690 Section 8.19 - BER always combines the first
    // two arcs, so single-arc OIDs cannot be represented distinctly.
    for arc1 in 0..=2 {
        let oid = Oid::from_slice(&[arc1]);
        let encoded = oid.to_ber();
        let decoded = Oid::from_ber(&encoded).unwrap();
        // Decoded OID should be [arc1, 0] since BER can't represent single arcs
        let expected = Oid::from_slice(&[arc1, 0]);
        assert_eq!(
            decoded, expected,
            "single arc {} should decode to [{}, 0]",
            arc1, arc1
        );
    }
}

#[test]
fn oid_two_arc_roundtrip() {
    // Two-arc OIDs round-trip correctly
    for arc1 in 0..=2 {
        for arc2 in [0, 1, 10, 39] {
            if arc1 < 2 && arc2 >= 40 {
                continue; // Invalid per X.690
            }
            let oid = Oid::from_slice(&[arc1, arc2]);
            let encoded = oid.to_ber();
            let decoded = Oid::from_ber(&encoded).unwrap();
            assert_eq!(oid, decoded, "arc1={}, arc2={} failed", arc1, arc2);
        }
    }
}

#[test]
fn oid_max_arc2_values() {
    // Test arc2 boundary values
    // arc1=0, arc2=39 (max valid)
    let oid = Oid::from_slice(&[0, 39]);
    assert!(oid.validate().is_ok());
    let encoded = oid.to_ber();
    let decoded = Oid::from_ber(&encoded).unwrap();
    assert_eq!(oid, decoded);

    // arc1=1, arc2=39 (max valid)
    let oid = Oid::from_slice(&[1, 39]);
    assert!(oid.validate().is_ok());
    let encoded = oid.to_ber();
    let decoded = Oid::from_ber(&encoded).unwrap();
    assert_eq!(oid, decoded);

    // arc1=2, arc2=large value (but not so large it overflows arc1*40 + arc2)
    // Maximum safe arc2 when arc1=2: u32::MAX - 80
    let oid = Oid::from_slice(&[2, u32::MAX - 80]);
    assert!(oid.validate().is_ok());
    let encoded = oid.to_ber();
    let decoded = Oid::from_ber(&encoded).unwrap();
    assert_eq!(oid, decoded);
}

#[test]
fn integer_boundary_values() {
    for value in [0i32, 1, -1, 127, 128, -128, -129, i32::MIN, i32::MAX] {
        let mut buf = EncodeBuf::new();
        buf.push_integer(value);
        let bytes = buf.finish();

        let mut decoder = Decoder::new(bytes);
        let decoded = decoder.read_integer().unwrap();
        assert_eq!(value, decoded, "integer {} failed", value);
    }
}

#[test]
fn unsigned32_boundary_values() {
    use async_snmp::ber::tag;

    for value in [0u32, 1, 127, 128, 255, 256, u32::MAX] {
        let mut buf = EncodeBuf::new();
        buf.push_unsigned32(tag::application::GAUGE32, value);
        let bytes = buf.finish();

        let mut decoder = Decoder::new(bytes);
        let decoded = decoder.read_unsigned32(tag::application::GAUGE32).unwrap();
        assert_eq!(value, decoded, "unsigned32 {} failed", value);
    }
}

#[test]
fn counter64_boundary_values() {
    use async_snmp::ber::tag;

    for value in [0u64, 1, 127, 128, 255, 256, u32::MAX as u64, u64::MAX] {
        let mut buf = EncodeBuf::new();
        buf.push_integer64(value);
        let bytes = buf.finish();

        let mut decoder = Decoder::new(bytes);
        let decoded = decoder.read_integer64(tag::application::COUNTER64).unwrap();
        assert_eq!(value, decoded, "counter64 {} failed", value);
    }
}

#[test]
fn value_all_variants_roundtrip() {
    let values = vec![
        Value::Integer(0),
        Value::Integer(i32::MIN),
        Value::Integer(i32::MAX),
        Value::OctetString(Bytes::from_static(b"")),
        Value::OctetString(Bytes::from_static(b"hello world")),
        Value::Null,
        Value::ObjectIdentifier(Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 1, 0])),
        Value::IpAddress([0, 0, 0, 0]),
        Value::IpAddress([255, 255, 255, 255]),
        Value::Counter32(0),
        Value::Counter32(u32::MAX),
        Value::Gauge32(0),
        Value::Gauge32(u32::MAX),
        Value::TimeTicks(0),
        Value::TimeTicks(u32::MAX),
        Value::Opaque(Bytes::from_static(b"\x00\x01\x02")),
        Value::Counter64(0),
        Value::Counter64(u64::MAX),
        Value::NoSuchObject,
        Value::NoSuchInstance,
        Value::EndOfMibView,
    ];

    for value in values {
        let mut buf = EncodeBuf::new();
        value.encode(&mut buf);
        let bytes = buf.finish();

        let mut decoder = Decoder::new(bytes);
        let decoded = Value::decode(&mut decoder).unwrap();
        assert_eq!(value, decoded, "value {:?} failed", value);
    }
}

// =============================================================================
// BER Decoder Malformed Input Tests
// =============================================================================

/// Tests for truncated data - decoder should return TruncatedData error
mod truncated_data {
    use super::*;

    #[test]
    fn empty_input() {
        let mut decoder = Decoder::new(Bytes::new());
        let result = decoder.read_tag();
        assert!(result.is_err());
    }

    #[test]
    fn truncated_after_tag() {
        // Tag present, but no length byte
        let mut decoder = Decoder::new(Bytes::from_static(&[0x02])); // INTEGER tag
        let result = decoder.read_integer();
        assert!(result.is_err());
    }

    #[test]
    fn truncated_in_length_long_form() {
        // Tag + long form length indicator, but missing length bytes
        // 0x82 means 2 bytes follow for length, but none provided
        let mut decoder = Decoder::new(Bytes::from_static(&[0x02, 0x82]));
        let result = decoder.read_integer();
        assert!(result.is_err());
    }

    #[test]
    fn truncated_in_length_long_form_partial() {
        // Tag + long form length, but only 1 of 2 length bytes
        let mut decoder = Decoder::new(Bytes::from_static(&[0x02, 0x82, 0x01]));
        let result = decoder.read_integer();
        assert!(result.is_err());
    }

    #[test]
    fn truncated_in_content() {
        // Tag + length=5, but only 3 content bytes
        let mut decoder = Decoder::new(Bytes::from_static(&[0x04, 0x05, 0x41, 0x42, 0x43]));
        let result = decoder.read_octet_string();
        assert!(result.is_err());
    }

    #[test]
    fn truncated_sequence() {
        // SEQUENCE tag + length=10, but only 5 bytes
        let mut decoder = Decoder::new(Bytes::from_static(&[0x30, 0x0A, 0x02, 0x01, 0x01]));
        let result = decoder.read_sequence();
        assert!(result.is_err());
    }

    #[test]
    fn truncated_oid() {
        // OID tag + length=5, but only 2 content bytes
        let mut decoder = Decoder::new(Bytes::from_static(&[0x06, 0x05, 0x2B, 0x06]));
        let result = decoder.read_oid();
        assert!(result.is_err());
    }

    #[test]
    fn truncated_ip_address() {
        // IP address tag + length=4, but only 2 bytes
        let mut decoder = Decoder::new(Bytes::from_static(&[0x40, 0x04, 0xC0, 0xA8]));
        let result = decoder.read_ip_address();
        assert!(result.is_err());
    }
}

/// Tests for invalid/unexpected tags
mod invalid_tags {
    use super::*;

    #[test]
    fn expect_integer_get_string() {
        // Expecting INTEGER (0x02) but got OCTET STRING (0x04)
        let mut decoder = Decoder::new(Bytes::from_static(&[0x04, 0x03, 0x41, 0x42, 0x43]));
        let result = decoder.read_integer();
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("expected tag 0x02"), "error: {}", err_msg);
    }

    #[test]
    fn expect_null_get_integer() {
        let mut decoder = Decoder::new(Bytes::from_static(&[0x02, 0x01, 0x42]));
        let result = decoder.read_null();
        assert!(result.is_err());
    }

    #[test]
    fn expect_sequence_get_integer() {
        let mut decoder = Decoder::new(Bytes::from_static(&[0x02, 0x01, 0x42]));
        let result = decoder.read_sequence();
        assert!(result.is_err());
    }

    #[test]
    fn expect_oid_get_string() {
        let mut decoder = Decoder::new(Bytes::from_static(&[0x04, 0x03, 0x41, 0x42, 0x43]));
        let result = decoder.read_oid();
        assert!(result.is_err());
    }
}

/// Tests for corrupted/invalid length values
mod invalid_lengths {
    use super::*;

    #[test]
    fn indefinite_length_rejected() {
        // Indefinite length (0x80) is not supported
        let mut decoder = Decoder::new(Bytes::from_static(&[0x02, 0x80]));
        let result = decoder.read_integer();
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("indefinite"), "error: {}", err_msg);
    }

    #[test]
    fn length_exceeds_data() {
        // Length says 100 bytes, but only 3 available
        let mut decoder = Decoder::new(Bytes::from_static(&[0x04, 0x64, 0x41, 0x42, 0x43]));
        let result = decoder.read_octet_string();
        assert!(result.is_err());
    }

    #[test]
    fn length_too_many_octets() {
        // Length with 5 octets (0x85) - exceeds our 4-byte limit
        let mut decoder = Decoder::new(Bytes::from_static(&[
            0x02, 0x85, 0x01, 0x02, 0x03, 0x04, 0x05, 0x42,
        ]));
        let result = decoder.read_integer();
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("too long"), "error: {}", err_msg);
    }

    #[test]
    fn zero_length_integer() {
        // INTEGER with length 0 is invalid
        let mut decoder = Decoder::new(Bytes::from_static(&[0x02, 0x00]));
        let result = decoder.read_integer();
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("zero-length"), "error: {}", err_msg);
    }

    #[test]
    fn null_with_nonzero_length() {
        // NULL must have length 0
        let mut decoder = Decoder::new(Bytes::from_static(&[0x05, 0x01, 0x00]));
        let result = decoder.read_null();
        assert!(result.is_err());
    }

    #[test]
    fn ip_address_wrong_length() {
        // IP address must be exactly 4 bytes
        let mut decoder = Decoder::new(Bytes::from_static(&[0x40, 0x03, 0xC0, 0xA8, 0x01]));
        let result = decoder.read_ip_address();
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("4 bytes"), "error: {}", err_msg);
    }

    #[test]
    fn integer64_too_long() {
        use async_snmp::ber::tag;
        // Counter64 with more than 9 bytes
        let mut decoder = Decoder::new(Bytes::from_static(&[
            0x46, 0x0A, // tag=Counter64, len=10
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        ]));
        let result = decoder.read_integer64(tag::application::COUNTER64);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("too long"), "error: {}", err_msg);
    }
}

/// Tests for TLV overflow (TLV extends past end of container)
mod tlv_overflow {
    use super::*;

    #[test]
    fn skip_tlv_overflow() {
        // Tag + length claims more bytes than available
        let mut decoder = Decoder::new(Bytes::from_static(&[0x02, 0x10, 0x42])); // claims 16, has 1
        let result = decoder.skip_tlv();
        assert!(result.is_err());
    }
}

// =============================================================================
// Non-Minimal BER Encoding Tests
// =============================================================================

/// Tests that decoder accepts non-minimal encodings (matches net-snmp behavior)
mod permissive_parsing {
    use super::*;

    #[test]
    fn non_minimal_integer_extra_leading_zero() {
        // Value 127 encoded with extra leading zero: 02 02 00 7F
        // Should decode to 127 (permissive)
        let mut decoder = Decoder::new(Bytes::from_static(&[0x02, 0x02, 0x00, 0x7F]));
        let result = decoder.read_integer().unwrap();
        assert_eq!(result, 127);
    }

    #[test]
    fn non_minimal_integer_extra_leading_ff() {
        // Value -1 encoded with extra leading FF: 02 02 FF FF
        // Should decode to -1 (permissive)
        let mut decoder = Decoder::new(Bytes::from_static(&[0x02, 0x02, 0xFF, 0xFF]));
        let result = decoder.read_integer().unwrap();
        assert_eq!(result, -1);
    }

    #[test]
    fn non_minimal_integer_many_leading_zeros() {
        // Value 1 encoded with many leading zeros: 02 04 00 00 00 01
        let mut decoder = Decoder::new(Bytes::from_static(&[0x02, 0x04, 0x00, 0x00, 0x00, 0x01]));
        let result = decoder.read_integer().unwrap();
        assert_eq!(result, 1);
    }

    #[test]
    fn non_minimal_unsigned32_extra_leading_zero() {
        use async_snmp::ber::tag;
        // Value 255 with extra leading zero: 41 02 00 FF
        let mut decoder = Decoder::new(Bytes::from_static(&[0x41, 0x02, 0x00, 0xFF]));
        let result = decoder
            .read_unsigned32(tag::application::COUNTER32)
            .unwrap();
        assert_eq!(result, 255);
    }

    #[test]
    fn non_minimal_length_encoding() {
        // Length 5 encoded with long form (81 05 instead of just 05)
        // OCTET STRING with non-minimal length
        let mut decoder = Decoder::new(Bytes::from_static(&[
            0x04, 0x81, 0x05, 0x48, 0x65, 0x6C, 0x6C, 0x6F,
        ]));
        let result = decoder.read_octet_string().unwrap();
        assert_eq!(&result[..], b"Hello");
    }

    #[test]
    fn non_minimal_length_two_byte_for_small() {
        // Length 3 encoded with 2-byte long form (82 00 03)
        let mut decoder = Decoder::new(Bytes::from_static(&[
            0x04, 0x82, 0x00, 0x03, 0x41, 0x42, 0x43,
        ]));
        let result = decoder.read_octet_string().unwrap();
        assert_eq!(&result[..], b"ABC");
    }
}

// =============================================================================
// Integer Overflow/Truncation Tests
// =============================================================================

mod integer_overflow {
    use super::*;

    #[test]
    fn integer_5_bytes_truncates() {
        // Integer encoded with 5 bytes - should truncate to 4 bytes with warning
        // 02 05 01 02 03 04 05 (value would be ~4.3 billion if full)
        let mut decoder = Decoder::new(Bytes::from_static(&[
            0x02, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
        ]));
        // Should succeed (permissive truncation per net-snmp behavior)
        let result = decoder.read_integer();
        assert!(result.is_ok(), "should truncate, not fail");
    }

    #[test]
    fn unsigned32_boundary_max() {
        use async_snmp::ber::tag;
        // u32::MAX = 4294967295 = 0xFFFFFFFF
        // Encoded as 5 bytes (leading zero for unsigned): 41 05 00 FF FF FF FF
        let mut decoder = Decoder::new(Bytes::from_static(&[
            0x41, 0x05, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
        ]));
        let result = decoder
            .read_unsigned32(tag::application::COUNTER32)
            .unwrap();
        assert_eq!(result, u32::MAX);
    }

    #[test]
    fn counter64_boundary_max() {
        use async_snmp::ber::tag;
        // u64::MAX = 0xFFFFFFFFFFFFFFFF
        // Encoded as 9 bytes (leading zero): 46 09 00 FF FF FF FF FF FF FF FF
        let mut decoder = Decoder::new(Bytes::from_static(&[
            0x46, 0x09, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ]));
        let result = decoder.read_integer64(tag::application::COUNTER64).unwrap();
        assert_eq!(result, u64::MAX);
    }

    #[test]
    fn integer_min_value() {
        // i32::MIN = -2147483648 = 0x80000000
        // Encoded as: 02 04 80 00 00 00
        let mut decoder = Decoder::new(Bytes::from_static(&[0x02, 0x04, 0x80, 0x00, 0x00, 0x00]));
        let result = decoder.read_integer().unwrap();
        assert_eq!(result, i32::MIN);
    }

    #[test]
    fn integer_max_value() {
        // i32::MAX = 2147483647 = 0x7FFFFFFF
        // Encoded as: 02 04 7F FF FF FF
        let mut decoder = Decoder::new(Bytes::from_static(&[0x02, 0x04, 0x7F, 0xFF, 0xFF, 0xFF]));
        let result = decoder.read_integer().unwrap();
        assert_eq!(result, i32::MAX);
    }
}

// =============================================================================
// V3 msgFlags Validation Tests (Invalid msgFlags rejection)
// =============================================================================

mod v3_msg_flags {
    use async_snmp::message::{MsgFlags, SecurityLevel};

    #[test]
    fn invalid_priv_without_auth_rejected() {
        // msgFlags 0x02 = priv=1, auth=0 - this is INVALID per RFC 3412
        let result = MsgFlags::from_byte(0x02);
        assert!(result.is_err(), "priv without auth should be rejected");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("invalid") || err_msg.contains("msgFlags"),
            "error: {}",
            err_msg
        );
    }

    #[test]
    fn invalid_priv_without_auth_with_reportable() {
        // msgFlags 0x06 = priv=1, auth=0, reportable=1 - still invalid
        let result = MsgFlags::from_byte(0x06);
        assert!(result.is_err());
    }

    #[test]
    fn valid_no_auth_no_priv() {
        let result = MsgFlags::from_byte(0x00).unwrap();
        assert_eq!(result.security_level, SecurityLevel::NoAuthNoPriv);
        assert!(!result.reportable);
    }

    #[test]
    fn valid_auth_no_priv() {
        let result = MsgFlags::from_byte(0x01).unwrap();
        assert_eq!(result.security_level, SecurityLevel::AuthNoPriv);
    }

    #[test]
    fn valid_auth_priv() {
        let result = MsgFlags::from_byte(0x03).unwrap();
        assert_eq!(result.security_level, SecurityLevel::AuthPriv);
    }

    #[test]
    fn valid_with_reportable_flag() {
        let result = MsgFlags::from_byte(0x07).unwrap(); // auth=1, priv=1, reportable=1
        assert_eq!(result.security_level, SecurityLevel::AuthPriv);
        assert!(result.reportable);
    }

    #[test]
    fn reserved_bits_ignored() {
        // RFC 3412: reserved bits (3-7) SHOULD be ignored when receiving
        // 0x38 = reserved bits set, no auth/priv
        let result = MsgFlags::from_byte(0x38);
        // Should succeed - reserved bits are ignored
        assert!(result.is_ok(), "reserved bits should be ignored");
        let flags = result.unwrap();
        assert_eq!(flags.security_level, SecurityLevel::NoAuthNoPriv);
    }
}

// =============================================================================
// Request ID Mismatch Tests
// =============================================================================

mod request_id_mismatch {
    use super::*;
    use async_snmp::pdu::{Pdu, PduType};

    fn make_response(request_id: i32, varbinds: Vec<VarBind>) -> Pdu {
        Pdu {
            pdu_type: PduType::Response,
            request_id,
            error_status: 0,
            error_index: 0,
            varbinds,
        }
    }

    #[test]
    fn pdu_request_id_decode() {
        // Create a Response PDU with request_id=12345
        let pdu = make_response(
            12345,
            vec![VarBind::new(
                Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 1, 0]),
                Value::OctetString(Bytes::from_static(b"test")),
            )],
        );

        let mut buf = EncodeBuf::new();
        pdu.encode(&mut buf);
        let encoded = buf.finish();

        let mut decoder = Decoder::new(encoded);
        let decoded = Pdu::decode(&mut decoder).unwrap();

        assert_eq!(decoded.request_id, 12345);
    }

    #[test]
    fn pdu_request_id_negative() {
        // Request IDs can be negative (i32)
        let pdu = make_response(-999, vec![]);

        let mut buf = EncodeBuf::new();
        pdu.encode(&mut buf);
        let encoded = buf.finish();

        let mut decoder = Decoder::new(encoded);
        let decoded = Pdu::decode(&mut decoder).unwrap();

        assert_eq!(decoded.request_id, -999);
    }

    #[test]
    fn pdu_request_id_boundary_values() {
        for request_id in [0i32, 1, -1, i32::MIN, i32::MAX] {
            let pdu = make_response(request_id, vec![]);

            let mut buf = EncodeBuf::new();
            pdu.encode(&mut buf);
            let encoded = buf.finish();

            let mut decoder = Decoder::new(encoded);
            let decoded = Pdu::decode(&mut decoder).unwrap();

            assert_eq!(
                decoded.request_id, request_id,
                "request_id {} failed",
                request_id
            );
        }
    }
}

// =============================================================================
// OID Malformed Input Tests
// =============================================================================

mod oid_malformed {
    use super::*;

    #[test]
    fn oid_empty_is_valid() {
        // Empty OID (length 0) is valid
        let result = Oid::from_ber(&[]);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn oid_truncated_subidentifier() {
        // Subidentifier with continuation bit set but no following byte
        // 0x81 means continuation (high bit set), but nothing follows
        let result = Oid::from_ber(&[0x2B, 0x81]); // 1.3 then incomplete subid
        assert!(result.is_err());
    }

    #[test]
    fn oid_very_long_subidentifier() {
        // Very long subidentifier (many continuation bytes)
        // This tests that we don't overflow during decoding
        // 0xFF 0xFF 0xFF 0xFF 0x7F would be a huge number but valid format
        let bytes = [0x2B, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F];
        let result = Oid::from_ber(&bytes);
        // May succeed or fail depending on overflow handling, but should not panic
        let _ = result;
    }
}

// =============================================================================
// Value::Unknown Forward Compatibility Test
// =============================================================================

#[test]
fn unknown_value_tag_preserved() {
    // Unknown tag 0x99 with some data - should be preserved as Value::Unknown
    let mut decoder = Decoder::new(Bytes::from_static(&[0x99, 0x03, 0x01, 0x02, 0x03]));
    let result = Value::decode(&mut decoder).unwrap();

    match result {
        Value::Unknown { tag, data } => {
            assert_eq!(tag, 0x99);
            assert_eq!(&data[..], &[0x01, 0x02, 0x03]);
        }
        _ => panic!("expected Value::Unknown, got {:?}", result),
    }
}
