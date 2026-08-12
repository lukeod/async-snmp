use std::fmt::Debug;
use std::time::Duration;

use async_snmp::message::{CommunityMessage, DecodePolicy, Message};
use async_snmp::{
    Auth, ClientBuilder, Community, CommunityResponsePolicy, CommunityVersion, GenericTrap,
    Notification, Pdu, RequestRegistration, TrapV1Pdu, oid,
};
use bytes::Bytes;

const SENTINEL: &str = "community-redaction-sentinel-4d91";

fn assert_redacted(value: &impl Debug) {
    for rendered in [format!("{value:?}"), format!("{value:#?}")] {
        assert!(
            rendered.contains("REDACTED"),
            "missing redaction marker: {rendered}"
        );
        assert!(!rendered.contains(SENTINEL), "community leaked: {rendered}");
    }
}

fn request_pdu(request_id: i32) -> Pdu {
    Pdu::get_request(request_id, &[oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)])
}

#[test]
fn community_raw_access_is_explicit_and_handles_arbitrary_octets() {
    for bytes in [b"".as_slice(), b"\x00\xffcommunity\x80".as_slice()] {
        let community = Community::from(bytes);
        assert_eq!(community.as_bytes(), bytes);
        assert_redacted(&community);
        assert_eq!(community.into_bytes(), Bytes::copy_from_slice(bytes));
    }
}

#[test]
fn auth_message_decode_outcome_and_builder_debug_are_transitively_redacted() {
    let community = Community::from(SENTINEL);
    let auth = Auth::v2c(community.clone());
    assert_redacted(&auth);
    assert!(format!("{auth:?}").contains("V2c"));

    let community_message = CommunityMessage::v2c(community.clone(), request_pdu(412)).unwrap();
    assert_redacted(&community_message);
    let message_debug = format!("{community_message:?}");
    assert!(message_debug.contains("V2c"));
    assert!(message_debug.contains("412"));

    let message = Message::from(community_message.clone());
    assert_redacted(&message);

    let outcome = CommunityMessage::decode_with_policy(
        community_message.encode().unwrap(),
        DecodePolicy::Compatible,
    )
    .unwrap();
    assert_redacted(&outcome);
    assert!(format!("{outcome:?}").contains("412"));

    let builder =
        ClientBuilder::new(("192.0.2.44", 1161), auth).request_timeout(Duration::from_secs(17));
    assert_redacted(&builder);
    let builder_debug = format!("{builder:?}");
    assert!(builder_debug.contains("192.0.2.44"));
    assert!(builder_debug.contains("17s"));
}

#[test]
fn community_notification_debug_is_redacted_for_every_variant() {
    let community = Community::from(SENTINEL);
    let trap_oid = oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 3);
    let notifications = [
        Notification::TrapV1 {
            community: community.clone(),
            trap: TrapV1Pdu::new(
                oid!(1, 3, 6, 1, 4, 1, 4242),
                [192, 0, 2, 9],
                GenericTrap::LinkDown,
                7,
                1234,
                vec![],
            ),
            decode_anomalies: Vec::new(),
        },
        Notification::TrapV2c {
            community: community.clone(),
            uptime: 1234,
            trap_oid: trap_oid.clone(),
            varbinds: vec![],
            request_id: 413,
            decode_anomalies: Vec::new(),
        },
        Notification::InformV2c {
            community,
            uptime: 1234,
            trap_oid: trap_oid.clone(),
            varbinds: vec![],
            request_id: 414,
            decode_anomalies: Vec::new(),
        },
    ];

    for notification in notifications {
        assert_redacted(&notification);
        let rendered = format!("{notification:?}");
        match notification {
            Notification::TrapV1 { .. } => {
                assert!(rendered.contains("LinkDown"));
                assert!(rendered.contains("1.3.6.1.4.1.4242"));
            }
            Notification::TrapV2c { .. } => {
                assert!(rendered.contains("413"));
                assert!(rendered.contains("1.3.6.1.6.3.1.1.5.3"));
            }
            Notification::InformV2c { .. } => {
                assert!(rendered.contains("414"));
                assert!(rendered.contains("1.3.6.1.6.3.1.1.5.3"));
            }
            Notification::TrapV3 { .. } | Notification::InformV3 { .. } => unreachable!(),
        }
        assert_eq!(notification.trap_oid().unwrap(), trap_oid);
    }
}

#[test]
fn request_registration_debug_redacts_identity_but_keeps_correlation_details() {
    let registration = RequestRegistration::community(
        415,
        Duration::from_secs(19),
        CommunityVersion::V2c,
        Community::from(SENTINEL),
        CommunityResponsePolicy::Exact,
    );

    assert_redacted(&registration);
    let rendered = format!("{registration:?}");
    assert!(rendered.contains("415"));
    assert!(rendered.contains("19s"));
    assert!(rendered.contains("V2c"));
    assert_eq!(registration.request_id(), 415);
    assert_eq!(registration.timeout(), Duration::from_secs(19));
}

#[cfg(feature = "agent")]
#[test]
fn request_context_redacts_communities_and_keeps_usm_usernames() {
    use async_snmp::{RequestContext, SecurityModel, SecurityName, Version};

    let mut context = RequestContext::test_context();
    context.source = "192.0.2.55:6161".parse().unwrap();
    context.request_id = 416;
    context.security_name = SecurityName::Community(Community::from(SENTINEL));
    assert_redacted(&context);
    let community_debug = format!("{context:?}");
    assert!(community_debug.contains("192.0.2.55:6161"));
    assert!(community_debug.contains("416"));
    assert!(community_debug.contains("V2c"));

    context.version = Version::V3;
    context.security_model = SecurityModel::Usm;
    context.security_name = SecurityName::Usm(Bytes::from_static(b"visible-usm-user"));
    let usm_debug = format!("{context:#?}");
    assert!(usm_debug.contains("visible-usm-user"));
    assert!(usm_debug.contains("192.0.2.55:6161"));
}

#[cfg(feature = "agent")]
#[test]
fn vacm_debug_redacts_all_security_name_selectors() {
    use async_snmp::{SecurityModel, VacmConfig, VacmSecurityModel};

    let mut vacm = VacmConfig::new();
    vacm.add_group(SENTINEL, SecurityModel::V2c, "readers");
    vacm.add_group(
        "any-selector-security-name",
        VacmSecurityModel::Any,
        "fallback",
    );
    vacm.add_group("usm-security-name", SecurityModel::Usm, "admins");

    assert_redacted(&vacm);
    let rendered = format!("{vacm:#?}");
    assert!(!rendered.contains("any-selector-security-name"));
    assert!(!rendered.contains("usm-security-name"));
    assert!(rendered.contains("Any"));
    assert!(rendered.contains("V2c"));
    assert!(rendered.contains("readers"));
}
