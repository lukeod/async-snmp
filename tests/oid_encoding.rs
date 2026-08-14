use async_snmp::ber::{Decoder, EncodeBuf};
use async_snmp::message::{
    CommunityMessage, MsgFlags, MsgGlobalData, ScopedPdu, SecurityLevel, V3Message,
};
use async_snmp::v3::UsmSecurityParams;
use async_snmp::{
    DecodeConfig, Error, GenericTrap, NotificationPdu, Oid, Pdu, PduBody, PduType, RequestPdu,
    StandardPduType, TrapV1Pdu, Value, VarBind, Version,
};
use bytes::Bytes;

fn invalid_oids() -> Vec<Oid> {
    vec![
        Oid::empty(),
        Oid::from_slice(&[1]),
        Oid::new(std::iter::repeat_n(1, async_snmp::oid::MAX_OID_LEN + 1)),
        Oid::from_slice(&[3, 0]),
        Oid::from_slice(&[0, 40]),
        Oid::from_slice(&[1, 40]),
    ]
}

fn assert_invalid<T>(result: async_snmp::Result<T>) {
    match result {
        Err(error) => assert!(
            matches!(&*error, Error::InvalidOid(_)),
            "expected InvalidOid, got {error:?}"
        ),
        Ok(_) => panic!("invalid OID was encoded"),
    }
}

fn assert_invalid_message<T>(result: async_snmp::Result<T>) {
    match result {
        Err(error) => assert!(matches!(&*error, Error::InvalidMessage(_))),
        Ok(_) => panic!("invalid message envelope was accepted"),
    }
}

fn pdu_with(pdu_type: PduType, varbind: VarBind) -> Pdu {
    if pdu_type == PduType::GetBulkRequest {
        Pdu::from_raw_parts(
            7,
            PduBody::GetBulk {
                non_repeaters: 0,
                max_repetitions: 10,
            },
            vec![varbind],
        )
    } else {
        Pdu::from_raw_parts(
            7,
            PduBody::Standard {
                pdu_type: StandardPduType::try_from(pdu_type).unwrap(),
                error_status: 0,
                error_index: 0,
            },
            vec![varbind],
        )
    }
}

#[test]
fn invalid_oid_matrix_is_rejected_across_structured_encoders() {
    let valid_name = Oid::from_slice(&[1, 3, 6, 1]);

    for oid in invalid_oids() {
        assert_invalid(oid.to_ber());

        let mut buf = EncodeBuf::new();
        assert_invalid(buf.push_oid(&oid));
        assert!(buf.is_empty());

        let mut buf = EncodeBuf::new();
        assert_invalid(Value::ObjectIdentifier(oid.clone()).encode(&mut buf));
        assert!(buf.is_empty());

        let invalid_name = VarBind::null(oid.clone());
        let invalid_value = VarBind::new(valid_name.clone(), Value::ObjectIdentifier(oid.clone()));
        for varbind in [invalid_name.clone(), invalid_value] {
            let mut buf = EncodeBuf::new();
            assert_invalid(varbind.encode(&mut buf));
            assert!(buf.is_empty());
        }

        for pdu_type in [
            PduType::GetRequest,
            PduType::GetNextRequest,
            PduType::SetRequest,
            PduType::GetBulkRequest,
            PduType::InformRequest,
            PduType::TrapV2,
            PduType::Report,
            PduType::Response,
        ] {
            let pdu = pdu_with(pdu_type, invalid_name.clone());
            if pdu_type == PduType::Report {
                // Report is not a valid v2c PDU, so envelope validation
                // intentionally takes precedence over the nested invalid OID.
                assert_invalid_message(CommunityMessage::v2c("public", pdu.clone()));
            } else {
                assert_invalid(CommunityMessage::v2c("public", pdu.clone()));
            }

            let scoped = ScopedPdu::new(Bytes::new(), Bytes::new(), pdu);
            let global = MsgGlobalData::new(
                11,
                async_snmp::MessageSize::new(65_507).unwrap(),
                MsgFlags::new(SecurityLevel::NoAuthNoPriv, false),
            )
            .unwrap();
            let security_params = UsmSecurityParams::discovery().encode().unwrap();
            assert_invalid(V3Message::new(global, security_params, scoped));
        }

        let trap = TrapV1Pdu::from_raw_parts(
            oid.clone(),
            [127, 0, 0, 1],
            GenericTrap::EnterpriseSpecific,
            1,
            10,
            vec![],
        );
        assert_invalid(CommunityMessage::v1_trap("public", trap));

        assert_invalid(NotificationPdu::trap_v2(Version::V2c, 7, 10, &oid, vec![]));
        assert_invalid(NotificationPdu::inform(Version::V2c, 7, 10, &oid, vec![]));
    }
}

#[test]
fn valid_oid_boundaries_preserve_identity() {
    let mut at_limit = vec![1, 3];
    at_limit.resize(async_snmp::oid::MAX_OID_LEN, u32::MAX);
    let oids = [
        Oid::from_slice(&[0, 0]),
        Oid::from_slice(&[1, 39]),
        Oid::from_slice(&[2, u32::MAX - 80]),
        Oid::from_slice(&[2, u32::MAX - 79]),
        Oid::from_slice(&[2, u32::MAX]),
        Oid::new(at_limit),
    ];

    for oid in oids {
        let content = oid.to_ber().unwrap();
        assert_eq!(Oid::from_ber(&content).unwrap(), oid);

        let pdu = RequestPdu::get(Version::V2c, 7, std::slice::from_ref(&oid)).unwrap();
        let bytes = CommunityMessage::v2c("public", pdu)
            .unwrap()
            .encode()
            .unwrap();
        let decoded = CommunityMessage::decode(bytes, DecodeConfig::default())
            .unwrap()
            .value;
        assert_eq!(decoded.into_pdu().unwrap().varbinds()[0].oid, oid);
    }
}

#[test]
fn root_two_u32_arc_boundaries_have_exact_ber_encodings() {
    let cases: &[(u32, &[u8])] = &[
        (u32::MAX - 80, &[0x8f, 0xff, 0xff, 0xff, 0x7f]),
        (u32::MAX - 79, &[0x90, 0x80, 0x80, 0x80, 0x00]),
        (u32::MAX, &[0x90, 0x80, 0x80, 0x80, 0x4f]),
    ];

    for &(arc2, expected) in cases {
        let oid = Oid::from_slice(&[2, arc2]);
        assert_eq!(oid.to_ber().unwrap(), expected);
        assert_eq!(oid.to_ber_checked().unwrap(), expected);
        assert_eq!(Oid::from_ber(expected).unwrap(), oid);

        let pdu = RequestPdu::get(Version::V2c, 7, std::slice::from_ref(&oid)).unwrap();
        let encoded = CommunityMessage::v2c("public", pdu)
            .unwrap()
            .encode()
            .unwrap();
        let expected_tlv = [&[0x06, expected.len() as u8][..], expected].concat();
        assert!(
            encoded
                .windows(expected_tlv.len())
                .any(|window| window == expected_tlv),
            "structured message omitted exact BER for {oid}"
        );
        let decoded = CommunityMessage::decode(encoded, DecodeConfig::default())
            .unwrap()
            .value;
        assert_eq!(decoded.into_pdu().unwrap().varbinds()[0].oid, oid);
    }
}

#[test]
fn combined_first_subidentifier_overflow_is_rejected_without_wrapping() {
    // u32::MAX + 81, one above the largest combined value (80 + u32::MAX).
    let above_limit = [0x90, 0x80, 0x80, 0x80, 0x50];
    assert!(Oid::from_ber(&above_limit).is_err());

    // Receive-side compatibility permits a non-minimal leading zero group, but
    // it must not let the same overflow value wrap into the accepted range.
    let non_minimal_above_limit = [0x80, 0x90, 0x80, 0x80, 0x80, 0x50];
    assert!(Oid::from_ber(&non_minimal_above_limit).is_err());

    // A value far beyond u64 also fails during accumulation rather than wrapping.
    assert!(Oid::from_ber(&[0xff; 11]).is_err());
}

#[test]
fn empty_ber_oid_remains_receive_compatible() {
    assert_eq!(Oid::from_ber(&[]).unwrap(), Oid::empty());

    let encoded_varbind = Bytes::from_static(&[0x30, 0x04, 0x06, 0x00, 0x82, 0x00]);
    let mut compatible = Decoder::new(encoded_varbind.clone());
    assert_eq!(VarBind::decode(&mut compatible).unwrap().oid, Oid::empty());

    let mut config = DecodeConfig::DEFAULT;
    config.empty_object_identifier = false;
    let mut strict = Decoder::new(encoded_varbind).with_decode_config(config);
    assert!(VarBind::decode(&mut strict).is_err());
}
