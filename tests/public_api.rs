use std::time::Duration;

use async_snmp::transport::TcpOptions;
use async_snmp::{
    Auth, Client, ClientConfig, CommunityVersion, CompatibilityPolicy, ConstructionStage,
    DEFAULT_CONSTRUCTION_TIMEOUT, DEFAULT_REQUEST_TIMEOUT, Error, ErrorKind, Oid,
    RequestRegistration, Target, UdpControl, UdpHandle, UdpStats, UdpTransport, Value, ValueKind,
    WalkAbortReason,
};
#[cfg(feature = "agent")]
use async_snmp::{GetNextResult, GetResult, VarBind, oid};
use bytes::Bytes;

#[test]
fn extensible_configs_support_default_plus_field_mutation() {
    let mut client = ClientConfig::default();
    client.auth = Auth::v1("private");
    client.request_timeout = Duration::from_secs(2);
    assert_eq!(client.request_timeout, Duration::from_secs(2));

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
        .construction_timeout(Duration::from_secs(3));
    let _tcp_builder = async_snmp::TcpTransport::builder().connect_timeout(Duration::from_secs(4));

    assert_eq!(DEFAULT_REQUEST_TIMEOUT, Duration::from_secs(5));
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
