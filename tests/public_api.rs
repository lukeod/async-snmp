use std::collections::BTreeSet;
use std::error::Error as _;
use std::fmt::{Display, Formatter};
use std::net::SocketAddr;
use std::time::Duration;

use async_snmp::message::Message;
use async_snmp::transport::TcpOptions;
#[cfg(feature = "agent")]
use async_snmp::{
    Agent, AgentBuilder, BoxFuture, GetNextResult, GetResult, NotificationSendStream,
    NotificationSinkId, NotificationSinkIdError, NotificationSinkSummary, PreparedSet,
    RequestContext, SetCommitError, SetCommitResult, SetTestError, SetTestResult, SetUndoError,
    SetUndoResult, oid,
};
use async_snmp::{
    Auth, AuthoritativeEngine, AuthoritativeEnginePersistenceError,
    AuthoritativeEnginePersistenceOperation, Client, ClientConfig, CommunityVersion,
    ConstructionStage, DEFAULT_CONSTRUCTION_TIMEOUT, DEFAULT_REQUEST_TIMEOUT, DEFAULT_SEND_TIMEOUT,
    DecodeConfig, DecodeError, DecodeErrorKind, DecodeErrorOrigin, Error, ErrorIndex, ErrorKind,
    ErrorStatus, GetBulkPdu, Oid, Pdu, PduBody, RequestPdu, RequestRegistration, ResponsePdu,
    StandardPduType, Target, UdpControl, UdpHandle, UdpStats, UdpTransport, Value, ValueKind,
    VarBind, Version, WalkAbortReason,
};
use bytes::Bytes;

#[test]
fn notification_acceptance_policy_surface_is_public() {
    use async_snmp::{
        NotificationAcceptance, NotificationAcceptanceError, NotificationAcceptancePolicy,
        NotificationAcceptanceResult, NotificationEnvelope, NotificationReceiver,
    };

    fn accepts_public_policy(_policy: impl NotificationAcceptancePolicy) {}

    accepts_public_policy(
        |notification: &NotificationEnvelope<'_>| -> NotificationAcceptanceResult {
            if notification
                .security_level
                .is_some_and(|level| level.requires_auth())
            {
                Ok(NotificationAcceptance::Accept)
            } else {
                Err(NotificationAcceptanceError::new(
                    "authenticated notification required",
                ))
            }
        },
    );

    let _infallible = NotificationReceiver::builder()
        .acceptance_policy(|_: &NotificationEnvelope<'_>| NotificationAcceptance::Reject);
    let _fallible = NotificationReceiver::builder().try_acceptance_policy(
        |_: &NotificationEnvelope<'_>| -> NotificationAcceptanceResult {
            Ok(NotificationAcceptance::Reject)
        },
    );
}

#[test]
fn engine_cache_public_seeding_encodes_and_validates_trust() {
    use async_snmp::v3::MAX_ENGINE_TIME;
    use async_snmp::{DiscoveredEngine, EngineCache, MessageSize};

    let target: SocketAddr = "192.0.2.1:161".parse().unwrap();
    let capacity = MessageSize::new(1400).unwrap();
    let discovered = || DiscoveredEngine::new(Bytes::from_static(b"remote-engine"), capacity);
    let cache = EngineCache::new();
    assert_eq!(cache.recovery_count(), 0);

    cache
        .insert_discovered(target, discovered().unwrap())
        .unwrap();
    let state = cache.get(&target).unwrap();
    assert_eq!(state.engine_id(), b"remote-engine".as_slice());
    assert_eq!(state.msg_max_size(), capacity);
    assert!(state.authenticated_time().is_none());

    cache
        .seed_authenticated(target, discovered().unwrap(), 0, 10)
        .unwrap();
    assert_eq!(
        cache
            .get(&target)
            .unwrap()
            .authenticated_time()
            .unwrap()
            .boots(),
        0
    );
    assert!(
        cache
            .seed_authenticated(target, discovered().unwrap(), 1, MAX_ENGINE_TIME + 1)
            .is_err()
    );
    assert_eq!(
        cache
            .get(&target)
            .unwrap()
            .authenticated_time()
            .unwrap()
            .latest_received_time(),
        10
    );

    cache
        .seed_authenticated(target, discovered().unwrap(), 7, 500)
        .unwrap();
    let state = cache.get(&target).unwrap();
    let authenticated = state.authenticated_time().unwrap();
    assert_eq!(authenticated.boots(), 7);
    assert_eq!(authenticated.latest_received_time(), 500);
}

#[test]
fn extensible_configs_support_default_plus_field_mutation() {
    let mut client = ClientConfig::default();
    client.auth = Auth::v1("private");
    client.request_timeout = Duration::from_secs(2);
    client.send_timeout = Duration::from_secs(3);
    assert_eq!(client.request_timeout, Duration::from_secs(2));
    assert_eq!(client.send_timeout, Duration::from_secs(3));

    let mut config = DecodeConfig::STRICT;
    config.clamp_bounded_strings = true;
    assert!(config.clamp_bounded_strings);

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
    assert_eq!(
        AuthoritativeEnginePersistenceOperation::EngineTimeRollover.to_string(),
        "engine-time rollover"
    );
    assert_eq!(
        ErrorKind::AuthoritativeEnginePersistence.as_str(),
        "authoritative_engine_persistence"
    );

    // The kind remains nameable when the feature-gated parent error does not.
    let agent_kind = ErrorKind::AgentAlreadyRunning;
    assert_eq!(agent_kind.to_string(), "agent_already_running");
}

#[test]
fn authoritative_persistence_error_surface_preserves_callback_type() {
    #[derive(Debug, PartialEq, Eq)]
    struct PublicPersistenceSentinel;

    impl Display for PublicPersistenceSentinel {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.write_str("public persistence sentinel")
        }
    }

    impl std::error::Error for PublicPersistenceSentinel {}

    fn accepts_public_type(_error: &AuthoritativeEnginePersistenceError) {}

    let error = AuthoritativeEngine::install(b"public-api-engine".to_vec(), |_| {
        Err(PublicPersistenceSentinel)
    })
    .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::AuthoritativeEnginePersistence);

    let persistence = error
        .authoritative_engine_persistence()
        .expect("typed persistence error");
    accepts_public_type(persistence);
    assert_eq!(
        persistence.operation(),
        AuthoritativeEnginePersistenceOperation::Install
    );
    assert_eq!(persistence.previous_engine_boots(), None);
    assert_eq!(persistence.attempted_engine_boots(), 1);
    assert_eq!(
        persistence.downcast_source_ref::<PublicPersistenceSentinel>(),
        Some(&PublicPersistenceSentinel)
    );
    assert!(
        persistence
            .persistence_source()
            .is::<PublicPersistenceSentinel>()
    );
}

#[test]
fn authoritative_persistence_accepts_boxed_dynamic_errors() {
    #[derive(Debug, PartialEq, Eq)]
    struct BoxedPersistenceSentinel;

    impl Display for BoxedPersistenceSentinel {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.write_str("boxed persistence sentinel")
        }
    }

    impl std::error::Error for BoxedPersistenceSentinel {}

    let error = AuthoritativeEngine::install(b"boxed-error-engine".to_vec(), |_| {
        let error: Box<dyn std::error::Error + Send + Sync + 'static> =
            Box::new(BoxedPersistenceSentinel);
        Err(error)
    })
    .unwrap_err();
    let persistence = error
        .authoritative_engine_persistence()
        .expect("typed persistence error");

    assert_eq!(
        persistence.downcast_source_ref::<BoxedPersistenceSentinel>(),
        Some(&BoxedPersistenceSentinel)
    );
}

#[test]
fn authoritative_persistence_retains_nested_source_chain() {
    #[derive(Debug, PartialEq, Eq)]
    struct NestedPersistenceCause;

    impl Display for NestedPersistenceCause {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.write_str("nested persistence cause")
        }
    }

    impl std::error::Error for NestedPersistenceCause {}

    #[derive(Debug)]
    struct PublicPersistenceContext {
        source: NestedPersistenceCause,
    }

    impl Display for PublicPersistenceContext {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            write!(f, "public persistence context: {}", self.source)
        }
    }

    impl std::error::Error for PublicPersistenceContext {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.source)
        }
    }

    struct IntoOnlyPersistenceError(PublicPersistenceContext);

    impl From<IntoOnlyPersistenceError> for Box<dyn std::error::Error + Send + Sync + 'static> {
        fn from(error: IntoOnlyPersistenceError) -> Self {
            Box::new(error.0)
        }
    }

    let error = AuthoritativeEngine::install(b"nested-error-engine".to_vec(), |_| {
        Err(IntoOnlyPersistenceError(PublicPersistenceContext {
            source: NestedPersistenceCause,
        }))
    })
    .unwrap_err();
    let persistence = error
        .authoritative_engine_persistence()
        .expect("typed persistence error");

    assert!(
        persistence
            .downcast_source_ref::<PublicPersistenceContext>()
            .is_some()
    );
    assert!(
        persistence
            .source()
            .and_then(std::error::Error::source)
            .is_some_and(|source| source.is::<NestedPersistenceCause>())
    );
    assert!(error.to_string().contains("nested persistence cause"));
}

#[cfg(feature = "agent")]
#[test]
fn prepared_set_lifecycle_types_are_public() {
    struct PublicPreparedSet;

    impl PreparedSet for PublicPreparedSet {
        fn commit<'a>(
            &'a mut self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
            _value: &'a Value,
        ) -> BoxFuture<'a, SetCommitResult> {
            Box::pin(async { Ok(()) })
        }

        fn undo<'a>(
            &'a mut self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
            _value: &'a Value,
        ) -> BoxFuture<'a, SetUndoResult> {
            Box::pin(async { Ok(()) })
        }
    }

    let prepared: SetTestResult = Ok(Box::new(PublicPreparedSet));
    assert!(prepared.is_ok());

    fn expected_test_status(failure: SetTestError) -> async_snmp::ErrorStatus {
        match failure {
            SetTestError::GeneralFailure => async_snmp::ErrorStatus::GenErr,
            SetTestError::NoAccess => async_snmp::ErrorStatus::NoAccess,
            SetTestError::NotWritable => async_snmp::ErrorStatus::NotWritable,
            SetTestError::WrongType => async_snmp::ErrorStatus::WrongType,
            SetTestError::WrongLength => async_snmp::ErrorStatus::WrongLength,
            SetTestError::WrongEncoding => async_snmp::ErrorStatus::WrongEncoding,
            SetTestError::WrongValue => async_snmp::ErrorStatus::WrongValue,
            SetTestError::NoCreation => async_snmp::ErrorStatus::NoCreation,
            SetTestError::InconsistentValue => async_snmp::ErrorStatus::InconsistentValue,
            SetTestError::ResourceUnavailable => async_snmp::ErrorStatus::ResourceUnavailable,
            SetTestError::InconsistentName => async_snmp::ErrorStatus::InconsistentName,
        }
    }

    for failure in [
        SetTestError::GeneralFailure,
        SetTestError::NoAccess,
        SetTestError::NotWritable,
        SetTestError::WrongType,
        SetTestError::WrongLength,
        SetTestError::WrongEncoding,
        SetTestError::WrongValue,
        SetTestError::NoCreation,
        SetTestError::InconsistentValue,
        SetTestError::ResourceUnavailable,
        SetTestError::InconsistentName,
    ] {
        assert_eq!(failure.to_error_status(), expected_test_status(failure));
    }
    assert_eq!(
        SetCommitError::Failed.to_error_status(),
        async_snmp::ErrorStatus::CommitFailed
    );
    assert_eq!(
        SetUndoError::Failed.to_error_status(),
        async_snmp::ErrorStatus::UndoFailed
    );
}

#[test]
fn decode_errors_are_public_structured_and_peer_free_for_standalone_input() {
    let error =
        Message::decode(Bytes::from_static(&[0x31, 0x00]), DecodeConfig::default()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Decode);
    assert!(matches!(
        error.as_ref(),
        Error::Decode(DecodeError {
            origin: DecodeErrorOrigin::Packet,
            offset: 0,
            kind: DecodeErrorKind::UnexpectedTag {
                expected: 0x30,
                actual: 0x31,
            },
            peer: None,
        })
    ));
    assert!(std::error::Error::source(error.as_ref()).is_some());
    assert!(error.to_string().contains("packet offset 0"));
    assert!(!error.to_string().contains("0.0.0.0:0"));
}

#[test]
fn request_registration_exposes_read_only_normalized_metadata() {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let registration = RequestRegistration::community(
        42,
        deadline,
        CommunityVersion::V2c,
        Bytes::from_static(b"public"),
        async_snmp::CommunityResponsePolicy::Exact,
    )
    .with_aliases([40, 41, 42, 40])
    .unwrap();

    assert_eq!(registration.request_id(), 42);
    assert_eq!(registration.deadline(), deadline);
    assert_eq!(registration.aliases(), &BTreeSet::from([40, 41]));
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

#[cfg(feature = "agent")]
#[test]
fn agent_clock_surface_is_coherent_and_fallible() {
    let _: fn(&Agent) -> async_snmp::Result<(u32, u32)> = Agent::engine_boots_time;
}

#[test]
fn retrieval_requests_reencode_ignored_non_null_values_for_each_version() {
    use async_snmp::ber::EncodeBuf;
    use async_snmp::message::{
        CommunityMessage, MsgFlags, MsgGlobalData, ScopedPdu, SecurityLevel, V3Message,
    };
    use async_snmp::v3::UsmSecurityParams;

    let name = Oid::from_slice(&[1, 3, 6, 1]);
    let binding = || VarBind::new(name.clone(), Value::Integer(37));

    for version in [Version::V1, Version::V2c, Version::V3] {
        for kind in [StandardPduType::GetRequest, StandardPduType::GetNextRequest] {
            let raw = Pdu::from_raw_parts(
                7,
                PduBody::Standard {
                    pdu_type: kind,
                    error_status: 0,
                    error_index: 0,
                },
                vec![binding()],
            );
            let request = RequestPdu::try_from_raw(version, raw).unwrap();

            match version {
                Version::V1 | Version::V2c => {
                    let encoded = CommunityMessage::new(version, "public", request)
                        .unwrap()
                        .encode()
                        .unwrap();
                    let decoded =
                        CommunityMessage::decode(encoded.clone(), DecodeConfig::default())
                            .unwrap()
                            .value;
                    assert_eq!(decoded.encode().unwrap(), encoded);
                }
                Version::V3 => {
                    let global = MsgGlobalData::new(
                        9,
                        async_snmp::MessageSize::new(65_507).unwrap(),
                        MsgFlags::new(SecurityLevel::NoAuthNoPriv, false),
                    )
                    .unwrap();
                    let security = UsmSecurityParams::new(b"engine".as_slice(), 0, 0, Bytes::new())
                        .unwrap()
                        .encode()
                        .unwrap();
                    let encoded =
                        V3Message::new(global, security, ScopedPdu::with_empty_context(request))
                            .unwrap()
                            .encode()
                            .unwrap();
                    let decoded = V3Message::decode(encoded.clone(), DecodeConfig::default())
                        .unwrap()
                        .value;
                    assert_eq!(decoded.encode().unwrap(), encoded);
                }
                _ => unreachable!("test enumerates all supported versions"),
            }
        }
    }

    for version in [Version::V2c, Version::V3] {
        let bulk = GetBulkPdu::new(version, 7, 0, 10, vec![binding()]).unwrap();
        let mut encoded = EncodeBuf::new();
        bulk.encode(&mut encoded).unwrap();
        let bytes = encoded.finish();
        let mut decoder = async_snmp::ber::Decoder::new(bytes.clone());
        let raw = Pdu::decode(&mut decoder).unwrap();
        let mut reencoded = EncodeBuf::new();
        GetBulkPdu::try_from_raw(version, raw)
            .unwrap()
            .encode(&mut reencoded)
            .unwrap();
        assert_eq!(reencoded.finish(), bytes);
    }
}

#[test]
fn error_index_public_integer32_boundaries_do_not_require_varbind_allocation() {
    assert_eq!(
        ErrorIndex::new(i32::MAX as u32, usize::MAX).unwrap().get(),
        i32::MAX as u32
    );
    assert!(ErrorIndex::new(i32::MAX as u32 + 1, usize::MAX).is_err());
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
        buf.push_constructed(tag::pdu::RESPONSE, |buf| {
            buf.push_sequence(|buf| varbind.encode(buf))?;
            buf.push_integer(0);
            buf.push_integer(ErrorStatus::TooBig.as_i32());
            buf.push_integer(7);
            Ok(())
        })
        .unwrap();
    }

    fn raw_v2c_message(varbind: &VarBind) -> Bytes {
        let mut buf = EncodeBuf::new();
        buf.push_sequence(|buf| {
            push_noncanonical_too_big(buf, varbind);
            buf.push_octet_string(b"public")?;
            buf.push_integer(Version::V2c.as_i32());
            Ok(())
        })
        .unwrap();
        buf.finish()
    }

    fn raw_v3_message(global: &MsgGlobalData, security_params: &[u8], varbind: &VarBind) -> Bytes {
        let mut buf = EncodeBuf::new();
        buf.push_sequence(|buf| {
            buf.push_sequence(|buf| {
                push_noncanonical_too_big(buf, varbind);
                buf.push_octet_string(b"")?;
                buf.push_octet_string(b"engine")?;
                Ok(())
            })?;
            buf.push_octet_string(security_params)?;
            global.encode(buf)?;
            buf.push_integer(Version::V3.as_i32());
            Ok(())
        })
        .unwrap();
        buf.finish()
    }

    let varbinds = vec![VarBind::null(Oid::from_slice(&[1, 3, 6, 1]))];
    let too_big = Pdu::from_raw_parts(
        7,
        PduBody::Standard {
            pdu_type: StandardPduType::Response,
            error_status: ErrorStatus::TooBig.as_i32(),
            error_index: 0,
        },
        varbinds.clone(),
    );

    CommunityMessage::v1(
        "public",
        ResponsePdu::too_big(Version::V1, 7, varbinds.clone()).unwrap(),
    )
    .unwrap()
    .encode()
    .unwrap();
    assert_invalid_message(CommunityMessage::v2c("public", too_big.clone()));
    let decoded_v2c =
        CommunityMessage::decode(raw_v2c_message(&varbinds[0]), DecodeConfig::default())
            .unwrap()
            .value;
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
    let decoded_v3 = V3Message::decode(
        raw_v3_message(&global, &security_params, &varbinds[0]),
        DecodeConfig::default(),
    )
    .unwrap()
    .value;
    assert_invalid_message(decoded_v3.encode());

    for version in [Version::V2c, Version::V3] {
        let empty = ResponsePdu::too_big(version, 7, vec![]).unwrap();
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
fn vacm_duplicate_and_replacement_apis_are_public() {
    use async_snmp::agent::vacm::AccessEntryBuilder;
    use async_snmp::{SecurityLevel, SecurityModel, VacmBuilder, VacmConfig};

    let direct_first =
        AccessEntryBuilder::new("group", SecurityModel::Usm, SecurityLevel::AuthNoPriv)
            .read_view("first")
            .build();
    let direct_replacement =
        AccessEntryBuilder::new("group", SecurityModel::Usm, SecurityLevel::AuthNoPriv)
            .read_view("replacement")
            .build();
    let mut direct = VacmConfig::new();
    direct.add_access(direct_first).unwrap();
    assert!(direct.replace_access(direct_replacement).is_some());

    let duplicate: async_snmp::DuplicateVacmAccessEntry = VacmBuilder::new()
        .access(
            "group",
            SecurityModel::Usm,
            SecurityLevel::AuthNoPriv,
            |entry| entry.read_view("first"),
        )
        .access(
            "group",
            SecurityModel::Usm,
            SecurityLevel::AuthNoPriv,
            |entry| entry.read_view("duplicate"),
        )
        .build()
        .unwrap_err();
    let _: &async_snmp::VacmAccessIndex = duplicate.index();

    VacmBuilder::new()
        .access(
            "group",
            SecurityModel::Usm,
            SecurityLevel::AuthNoPriv,
            |entry| entry.read_view("first"),
        )
        .replace_access(
            "group",
            SecurityModel::Usm,
            SecurityLevel::AuthNoPriv,
            |entry| entry.read_view("replacement"),
        )
        .build()
        .unwrap();
}

#[cfg(feature = "agent")]
#[test]
fn notification_sink_identity_types_are_public() {
    use std::collections::{BTreeMap, HashMap};

    let one = NotificationSinkId::new("p").unwrap();
    let thirty_two = NotificationSinkId::try_from([b'x'; 32]).unwrap();
    let non_utf8 = NotificationSinkId::try_from(&b"edge\xff"[..]).unwrap();

    assert_eq!(one.as_bytes(), b"p");
    assert_eq!(thirty_two.as_bytes(), &[b'x'; 32]);
    assert_eq!(non_utf8.as_bytes(), b"edge\xff");
    assert_eq!(non_utf8.to_string(), "edge\\xff");
    assert_eq!(
        format!("{non_utf8:?}"),
        "NotificationSinkId(b\"edge\\xff\")"
    );

    let empty: NotificationSinkIdError = NotificationSinkId::new([]).unwrap_err();
    assert_eq!(empty.length(), 0);
    assert_eq!(
        empty.to_string(),
        "notification sink ID length 0 is outside 1..=32 octets"
    );
    let too_long = NotificationSinkId::try_from(vec![b'x'; 33]).unwrap_err();
    assert_eq!(too_long.length(), 33);
    let multibyte = NotificationSinkId::new("é".repeat(17)).unwrap_err();
    assert_eq!(multibyte.length(), 34);

    let from_str = NotificationSinkId::try_from(String::from("primary")).unwrap();
    let from_bytes = NotificationSinkId::try_from(Vec::from(&b"primary"[..])).unwrap();
    assert_eq!(from_str, from_bytes);

    let mut hash = HashMap::new();
    hash.insert(from_str.clone(), "hash");
    assert_eq!(hash.get(&from_bytes), Some(&"hash"));
    let ordered = BTreeMap::from([(non_utf8.clone(), 2), (one.clone(), 1)]);
    assert_eq!(ordered.keys().next(), Some(&non_utf8));

    let builder: AgentBuilder =
        Agent::builder().trap_sink(from_str, "127.0.0.1:162", async_snmp::Auth::v2c("public"));
    drop(builder);
    let _: Option<NotificationSinkSummary> = None;
    let _: Option<NotificationSendStream<'static>> = None;
}
