use std::time::Duration;

use async_snmp::transport::TcpOptions;
use async_snmp::{
    Auth, Client, ClientConfig, CommunityVersion, CompatibilityPolicy, ConstructionStage,
    DEFAULT_CONSTRUCTION_TIMEOUT, DEFAULT_REQUEST_TIMEOUT, DEFAULT_SEND_TIMEOUT, Error, ErrorKind,
    ErrorStatus, Oid, Pdu, RequestRegistration, Target, UdpControl, UdpHandle, UdpStats,
    UdpTransport, Value, ValueKind, VarBind, Version, WalkAbortReason,
};
#[cfg(feature = "agent")]
use async_snmp::{
    GetNextResult, GetResult, NotificationSendStream, NotificationSinkId, NotificationSinkSummary,
    oid,
};
use bytes::Bytes;

#[test]
fn extensible_configs_support_default_plus_field_mutation() {
    let mut client = ClientConfig::default();
    client.auth = Auth::v1("private");
    client.request_timeout = Duration::from_secs(2);
    client.send_timeout = Duration::from_secs(3);
    assert_eq!(client.request_timeout, Duration::from_secs(2));
    assert_eq!(client.send_timeout, Duration::from_secs(3));

    let mut compatibility = CompatibilityPolicy::STRICT;
    compatibility.clamp_bounded_strings = true;
    assert!(compatibility.clamp_bounded_strings);

    let mut tcp = TcpOptions::default();
    tcp.max_message_size = 4096;
    assert_eq!(tcp.max_message_size, 4096);
}

#[test]
fn timeout_apis_are_separate_and_public() {
    let _builder = Client::builder("example.invalid", Auth::v2c("public"))
        .request_timeout(Duration::from_secs(2))
        .send_timeout(Duration::from_secs(3))
        .construction_timeout(Duration::from_secs(3));
    let _tcp_builder = async_snmp::TcpTransport::builder().connect_timeout(Duration::from_secs(4));
    #[cfg(feature = "agent")]
    let _agent_builder = async_snmp::Agent::builder().trap_send_timeout(Duration::from_secs(4));

    assert_eq!(DEFAULT_REQUEST_TIMEOUT, Duration::from_secs(5));
    assert_eq!(DEFAULT_SEND_TIMEOUT, Duration::from_secs(5));
    assert_eq!(ClientConfig::default().send_timeout, DEFAULT_SEND_TIMEOUT);
    assert_eq!(DEFAULT_CONSTRUCTION_TIMEOUT, Duration::from_secs(5));

    let error = Error::ConstructionTimeout {
        target: Target::from("unresolved.example"),
        stage: ConstructionStage::Resolve,
        elapsed: Duration::from_secs(5),
    };
    assert!(error.to_string().contains("unresolved.example"));
}

#[test]
fn bounded_walk_abort_reason_is_public_and_structured() {
    let reason = WalkAbortReason::ResultLimitExceeded { limit: 12 };
    assert_eq!(reason.to_string(), "result limit of 12 exceeded");

    let error = Error::WalkAborted {
        target: "127.0.0.1:161".parse().unwrap(),
        reason,
    };
    assert!(matches!(
        error,
        Error::WalkAborted {
            reason: WalkAbortReason::ResultLimitExceeded { limit: 12 },
            ..
        }
    ));
}

#[test]
fn stable_value_and_error_kinds_are_public() {
    assert_eq!(Value::Integer(1).kind(), ValueKind::Integer);
    assert_eq!(ValueKind::Integer.as_str(), "integer");
    assert_eq!(Error::Config("bad input".into()).kind(), ErrorKind::Config);
    assert_eq!(ErrorKind::Config.as_str(), "configuration");

    // The kind remains nameable when the feature-gated parent error does not.
    let agent_kind = ErrorKind::AgentAlreadyRunning;
    assert_eq!(agent_kind.to_string(), "agent_already_running");
}

#[test]
fn request_registration_exposes_read_only_normalized_metadata() {
    let registration = RequestRegistration::community(
        42,
        Duration::from_secs(3),
        CommunityVersion::V2c,
        Bytes::from_static(b"public"),
        async_snmp::CommunityResponsePolicy::Exact,
    )
    .with_aliases([40, 41, 42, 40]);

    assert_eq!(registration.request_id(), 42);
    assert_eq!(registration.timeout(), Duration::from_secs(3));
    assert_eq!(registration.aliases(), &[40, 41]);
}

#[tokio::test]
async fn udp_handle_construction_is_publicly_fallible() {
    let transport = UdpTransport::bind("127.0.0.1:0").await.unwrap();
    let handle: async_snmp::Result<UdpHandle> = transport.handle("127.0.0.1:161".parse().unwrap());
    let handle = handle.unwrap();
    let control: UdpControl = transport.control();
    let _: UdpStats = handle.stats();
    let _: UdpStats = control.stats();
}

#[test]
fn intentional_compatibility_surface_remains_available() {
    let oid = Oid::from_slice(&[2, u32::MAX]);
    assert_eq!(oid.to_ber_checked().unwrap(), oid.to_ber().unwrap());

    let result: async_snmp::Result<()> = Ok(());
    let _: std::result::Result<(), Box<async_snmp::Error>> = result;
}

#[test]
fn public_structured_envelopes_enforce_version_specific_too_big_shape() {
    use async_snmp::ber::{EncodeBuf, tag};
    use async_snmp::message::{
        CommunityMessage, MsgFlags, MsgGlobalData, ScopedPdu, SecurityLevel, V3Message,
    };
    use async_snmp::v3::UsmSecurityParams;

    fn assert_invalid_message<T: std::fmt::Debug>(result: async_snmp::Result<T>) {
        let error = result.unwrap_err();
        assert!(matches!(error.as_ref(), Error::InvalidMessage(_)));
        assert_eq!(error.kind(), ErrorKind::InvalidMessage);
    }

    fn push_noncanonical_too_big(buf: &mut EncodeBuf, varbind: &VarBind) {
        buf.try_push_constructed(tag::pdu::RESPONSE, |buf| {
            buf.try_push_sequence(|buf| varbind.encode(buf))?;
            buf.push_integer(0);
            buf.push_integer(ErrorStatus::TooBig.as_i32());
            buf.push_integer(7);
            Ok(())
        })
        .unwrap();
    }

    fn raw_v2c_message(varbind: &VarBind) -> Bytes {
        let mut buf = EncodeBuf::new();
        buf.try_push_sequence(|buf| {
            push_noncanonical_too_big(buf, varbind);
            buf.try_push_octet_string(b"public")?;
            buf.push_integer(Version::V2c.as_i32());
            Ok(())
        })
        .unwrap();
        buf.finish()
    }

    fn raw_v3_message(global: &MsgGlobalData, security_params: &[u8], varbind: &VarBind) -> Bytes {
        let mut buf = EncodeBuf::new();
        buf.try_push_sequence(|buf| {
            buf.try_push_sequence(|buf| {
                push_noncanonical_too_big(buf, varbind);
                buf.try_push_octet_string(b"")?;
                buf.try_push_octet_string(b"engine")?;
                Ok(())
            })?;
            buf.try_push_octet_string(security_params)?;
            global.encode(buf)?;
            buf.push_integer(Version::V3.as_i32());
            Ok(())
        })
        .unwrap();
        buf.finish()
    }

    let varbinds = vec![VarBind::null(Oid::from_slice(&[1, 3, 6, 1]))];
    let too_big = Pdu::response(7, ErrorStatus::TooBig.as_i32(), 0, varbinds.clone());

    let mut pdu_buf = EncodeBuf::new();
    pdu_buf.push_byte(0x5a);
    assert_invalid_message(too_big.encode(&mut pdu_buf));
    assert_eq!(pdu_buf.finish().as_ref(), &[0x5a]);

    CommunityMessage::v1("public", too_big.clone())
        .unwrap()
        .encode()
        .unwrap();
    assert_invalid_message(CommunityMessage::v2c("public", too_big.clone()));
    let decoded_v2c = CommunityMessage::decode(raw_v2c_message(&varbinds[0])).unwrap();
    assert_invalid_message(decoded_v2c.encode());

    let scoped = ScopedPdu::new(Bytes::from_static(b"engine"), Bytes::new(), too_big);
    let mut scoped_buf = EncodeBuf::new();
    scoped_buf.push_byte(0x5a);
    assert_invalid_message(scoped.encode(&mut scoped_buf));
    assert_eq!(scoped_buf.finish().as_ref(), &[0x5a]);
    assert_invalid_message(scoped.encode_to_bytes());

    let global = MsgGlobalData::new(
        1,
        async_snmp::MessageSize::new(65_507).unwrap(),
        MsgFlags::new(SecurityLevel::NoAuthNoPriv, false),
    )
    .unwrap();
    let security_params = UsmSecurityParams::new(b"engine".as_slice(), 0, 0, Bytes::new())
        .unwrap()
        .encode()
        .unwrap();
    assert_invalid_message(V3Message::new(
        global.clone(),
        security_params.clone(),
        scoped,
    ));
    let decoded_v3 =
        V3Message::decode(raw_v3_message(&global, &security_params, &varbinds[0])).unwrap();
    assert_invalid_message(decoded_v3.encode());

    for version in [Version::V2c, Version::V3] {
        let empty = Pdu::response(7, ErrorStatus::TooBig.as_i32(), 0, vec![]);
        match version {
            Version::V2c => {
                CommunityMessage::v2c("public", empty)
                    .unwrap()
                    .encode()
                    .unwrap();
            }
            Version::V3 => {
                ScopedPdu::with_empty_context(empty)
                    .encode_to_bytes()
                    .unwrap();
            }
            _ => unreachable!(),
        }
    }
}

#[cfg(feature = "agent")]
#[test]
fn unambiguous_handler_conversions_remain_available() {
    let get: GetResult = Value::Integer(7).into();
    assert_eq!(get, GetResult::Value(Value::Integer(7)));

    let varbind = VarBind::new(oid!(1, 3, 6, 1), Value::Null);
    let get_next: GetNextResult = varbind.clone().into();
    assert_eq!(get_next, GetNextResult::Value(varbind));
}

#[cfg(feature = "agent")]
#[test]
fn security_model_canonical_paths_remain_available() {
    let from_handler = async_snmp::handler::SecurityModel::Usm;
    let from_root = async_snmp::SecurityModel::Usm;
    assert_eq!(from_handler, from_root);
}

#[cfg(feature = "agent")]
#[test]
fn notification_sink_identity_types_are_public() {
    let id = NotificationSinkId::from("primary");
    assert_eq!(id.as_str(), "primary");
    let _: Option<NotificationSinkSummary> = None;
    let _: Option<NotificationSendStream<'static>> = None;
}
