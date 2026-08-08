use std::time::Duration;

use async_snmp::transport::TcpOptions;
use async_snmp::{
    Auth, ClientConfig, CommunityVersion, CompatibilityPolicy, Oid, RequestRegistration,
};
#[cfg(feature = "agent")]
use async_snmp::{GetNextResult, GetResult, Value, VarBind, oid};
use bytes::Bytes;

#[test]
fn extensible_configs_support_default_plus_field_mutation() {
    let mut client = ClientConfig::default();
    client.auth = Auth::v1("private");
    client.timeout = Duration::from_secs(2);
    assert_eq!(client.timeout, Duration::from_secs(2));

    let mut compatibility = CompatibilityPolicy::STRICT;
    compatibility.clamp_bounded_strings = true;
    assert!(compatibility.clamp_bounded_strings);

    let mut tcp = TcpOptions::default();
    tcp.max_message_size = 4096;
    assert_eq!(tcp.max_message_size, 4096);
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
