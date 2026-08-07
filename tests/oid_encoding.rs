use async_snmp::ber::EncodeBuf;
use async_snmp::message::{
    CommunityMessage, MsgFlags, MsgGlobalData, ScopedPdu, SecurityLevel, V3Message,
};
use async_snmp::pdu::GetBulkPdu;
use async_snmp::{Error, GenericTrap, Oid, Pdu, PduType, TrapV1Pdu, Value, VarBind};
use bytes::Bytes;

fn invalid_oids() -> Vec<Oid> {
    vec![
        Oid::empty(),
        Oid::from_slice(&[1]),
        Oid::new(std::iter::repeat_n(1, async_snmp::oid::MAX_OID_LEN + 1)),
        Oid::from_slice(&[3, 0]),
        Oid::from_slice(&[0, 40]),
        Oid::from_slice(&[1, 40]),
        Oid::from_slice(&[2, u32::MAX]),
    ]
}

fn assert_invalid<T>(result: async_snmp::Result<T>) {
    match result {
        Err(error) => assert!(matches!(&*error, Error::InvalidOid(_))),
        Ok(_) => panic!("invalid OID was encoded"),
    }
}

fn pdu_with(pdu_type: PduType, varbind: VarBind) -> Pdu {
    Pdu {
        pdu_type,
        request_id: 7,
        error_status: 0,
        error_index: 0,
        varbinds: vec![varbind],
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
            let mut buf = EncodeBuf::new();
            assert_invalid(pdu.encode(&mut buf));
            assert!(buf.is_empty());

            assert_invalid(CommunityMessage::v2c("public", pdu.clone()).encode());

            let scoped = ScopedPdu::new(Bytes::new(), Bytes::new(), pdu);
            let global = MsgGlobalData::new(
                11,
                65_507,
                MsgFlags::new(SecurityLevel::NoAuthNoPriv, false),
            );
            assert_invalid(V3Message::new(global, Bytes::new(), scoped).encode());
        }

        let bulk = GetBulkPdu::new(7, 0, 10, std::slice::from_ref(&oid));
        assert_invalid(CommunityMessage::encode_bulk(
            async_snmp::Version::V2c,
            "public",
            &bulk,
        ));

        let trap = TrapV1Pdu::new(
            oid.clone(),
            [127, 0, 0, 1],
            GenericTrap::EnterpriseSpecific,
            1,
            10,
            vec![],
        );
        assert_invalid(CommunityMessage::v1_trap("public", trap).encode());

        let trap_v2 = Pdu::trap_v2(7, 10, &oid, vec![]);
        assert_invalid(CommunityMessage::v2c("public", trap_v2).encode());
        let inform = Pdu::inform_request(7, 10, &oid, vec![]);
        assert_invalid(CommunityMessage::v2c("public", inform).encode());
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
        Oid::new(at_limit),
    ];

    for oid in oids {
        let content = oid.to_ber().unwrap();
        assert_eq!(Oid::from_ber(&content).unwrap(), oid);

        let pdu = Pdu::get_request(7, std::slice::from_ref(&oid));
        let bytes = CommunityMessage::v2c("public", pdu).encode().unwrap();
        let decoded = CommunityMessage::decode(bytes).unwrap();
        assert_eq!(decoded.into_pdu().unwrap().varbinds[0].oid, oid);
    }
}

#[test]
fn empty_ber_oid_remains_receive_compatible() {
    assert_eq!(Oid::from_ber(&[]).unwrap(), Oid::empty());
}
