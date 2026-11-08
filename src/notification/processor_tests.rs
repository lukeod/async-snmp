use super::*;
use crate::message::{CommunityMessage, MsgFlags, MsgGlobalData, ScopedPdu, V3Message};
use crate::v3::UsmSecurityParams;
use crate::{
    LocalEngine, NotificationPdu, ProcessingInput, ProcessingLimits, ReceivedMessageInfo,
    ReceivedPacket, oid,
};
#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
use crate::{UsmSecurityContext, UsmUserEntry};
#[cfg(feature = "crypto-rustcrypto")]
use std::convert::Infallible;

fn engine() -> LocalEngine {
    LocalEngine::new(AuthoritativeEngine::for_test(
        b"socketless-core-tests".as_slice(),
        1,
    ))
    .unwrap()
}

fn input(bytes: Bytes, limits: ProcessingLimits) -> ProcessingInput {
    let info = ReceivedMessageInfo::udp(
        crate::EndpointId::new(),
        "127.0.0.1:162".parse().unwrap(),
        "127.0.0.1:40000".parse().unwrap(),
        None,
        tokio::time::Instant::now(),
        bytes.len(),
    );
    ProcessingInput::new(ReceivedPacket::new(bytes, info), limits).unwrap()
}

fn pdu(version: Version) -> crate::Pdu {
    NotificationPdu::inform(version, 42, 0, &oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1), vec![])
        .unwrap()
        .into_raw()
}

fn response(result: NotificationProcessResult) -> InformResponse {
    let NotificationProcessResult::Accepted(event) = result else {
        panic!("expected accepted Inform")
    };
    event.inform_response.unwrap()
}

fn wire_no_auth(id: &[u8], user: &str) -> Bytes {
    let usm = UsmSecurityParams::new(
        Bytes::copy_from_slice(id),
        1,
        0,
        Bytes::copy_from_slice(user.as_bytes()),
    )
    .unwrap();
    V3Message::new(
        MsgGlobalData::new(
            71,
            crate::MessageSize::new(8192).unwrap(),
            MsgFlags::new(SecurityLevel::NoAuthNoPriv, true),
        )
        .unwrap(),
        usm.encode().unwrap(),
        ScopedPdu::new(Bytes::copy_from_slice(id), Bytes::new(), pdu(Version::V3)),
    )
    .unwrap()
    .encode()
    .unwrap()
}

#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
fn signed_input(
    local: &LocalEngine,
    security: &crate::UsmConfig,
    des: Option<&DesSaltState>,
) -> ProcessingInput {
    let (boots, time) = local.current_boots_time().unwrap();
    let keys = security.derive_keys(local.engine_id()).unwrap();
    let encoded = crate::v3::encode::encode_v3_message(
        &pdu(Version::V3),
        77,
        local.engine_id(),
        boots,
        time,
        security,
        Some(&keys),
        Some(&SaltCounter::new().unwrap()),
        des,
        des.map(DesSaltState::engine_boots),
        true,
        crate::MessageSize::new(8192).unwrap(),
    )
    .unwrap();
    input(Bytes::from(encoded), ProcessingLimits::UDP)
}

#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
#[test]
fn deferred_response_uses_current_clock_and_retains_selected_credentials() {
    let local = engine();
    let user = UsmUser::new("user")
        .auth(crate::AuthProtocol::Sha256, b"old-password")
        .unwrap();
    let context = UsmSecurityContext::new([UsmUserEntry::new(user)]).unwrap();
    let processor = NotificationProcessor::builder()
        .local_engine(local.clone())
        .security_context(context.clone())
        .accept_all_notifications()
        .build()
        .unwrap();
    let security = crate::UsmConfig::new("user")
        .auth(crate::AuthProtocol::Sha256, b"old-password")
        .unwrap();
    let received = signed_input(&local, &security, None);
    let original = received.bytes().clone();
    let pending = response(processor.process(received).unwrap());
    context
        .replace_users([UsmUserEntry::new(
            UsmUser::new("user")
                .auth(crate::AuthProtocol::Sha256, b"new-password")
                .unwrap(),
        )])
        .unwrap();
    local
        .authoritative_engine()
        .unwrap()
        .set_elapsed_for_test(125);
    let EncodedInformResponse::Response(encoded) = pending.encode().unwrap() else {
        panic!("expected response")
    };
    let decoded = V3Message::decode(encoded.clone(), crate::DecodeConfig::DEFAULT)
        .unwrap()
        .value;
    let usm = UsmSecurityParams::decode(
        decoded.security_params().clone(),
        crate::DecodeConfig::DEFAULT,
    )
    .unwrap()
    .value;
    assert_eq!(usm.engine_boots(), 1);
    assert!(usm.engine_time() >= 125);
    assert_eq!(
        decoded.global_data().msg_max_size().as_usize(),
        crate::MAX_UDP_PAYLOAD
    );
    let old = security.derive_keys(local.engine_id()).unwrap();
    let new = crate::UsmConfig::new("user")
        .auth(crate::AuthProtocol::Sha256, b"new-password")
        .unwrap()
        .derive_keys(local.engine_id())
        .unwrap();
    let (offset, length) = UsmSecurityParams::find_auth_params_offset(&encoded).unwrap();
    assert!(
        crate::v3::auth::verify_message(old.auth_key.as_ref().unwrap(), &encoded, offset, length)
            .unwrap()
    );
    assert!(
        !crate::v3::auth::verify_message(new.auth_key.as_ref().unwrap(), &encoded, offset, length)
            .unwrap()
    );
    let result = processor
        .process(input(original, ProcessingLimits::UDP))
        .unwrap();
    assert!(matches!(
        result,
        NotificationProcessResult::UsmFailed {
            failure: crate::UsmFailure::WrongDigests,
            report: Some(_)
        }
    ));
    assert_eq!(local.usm_stats().wrong_digests, 1);
}

#[cfg(feature = "crypto-rustcrypto")]
#[test]
fn deferred_des_response_observes_missing_removed_and_replaced_sender_state() {
    let local = engine();
    let state = DesSaltState::install(|_| Ok::<_, Infallible>(())).unwrap();
    let context = UsmSecurityContext::new([UsmUserEntry::new(
        UsmUser::new("user")
            .auth_priv(
                crate::AuthProtocol::Sha1,
                b"authentication",
                PrivProtocol::Des,
                b"privacy-password",
            )
            .unwrap(),
    )])
    .unwrap();
    let security = crate::UsmConfig::new("user")
        .auth_priv(
            crate::AuthProtocol::Sha1,
            b"authentication",
            PrivProtocol::Des,
            b"privacy-password",
        )
        .unwrap();
    let processor = NotificationProcessor::builder()
        .local_engine(local.clone())
        .security_context(context)
        .accept_all_notifications()
        .build()
        .unwrap();
    let accept = || {
        response(
            processor
                .process(signed_input(&local, &security, Some(&state)))
                .unwrap(),
        )
    };
    let missing = accept();
    assert!(matches!(*missing.encode().unwrap_err(), Error::Config(_)));
    local.set_des_salt_state(Some(state.clone())).unwrap();
    let removed = accept();
    local.set_des_salt_state(None).unwrap();
    assert!(matches!(*removed.encode().unwrap_err(), Error::Config(_)));
    local.set_des_salt_state(Some(state.clone())).unwrap();
    let stale = accept();
    let replace = accept();
    local
        .authoritative_engine()
        .unwrap()
        .set_elapsed_for_test(u64::from(crate::v3::MAX_ENGINE_TIME) + 1);
    assert!(matches!(
        *stale.encode().unwrap_err(),
        Error::Privacy(crate::v3::PrivacyError::DesEngineBootsMismatch {
            state_engine_boots: 1,
            generating_engine_boots: 2
        })
    ));
    let renewed =
        DesSaltState::restart(state.persisted_state(), |_| Ok::<_, Infallible>(())).unwrap();
    local.set_des_salt_state(Some(renewed)).unwrap();
    let EncodedInformResponse::Response(encoded) = replace.encode().unwrap() else {
        panic!("expected replacement state response")
    };
    let decoded = V3Message::decode(encoded, crate::DecodeConfig::DEFAULT)
        .unwrap()
        .value;
    let usm = UsmSecurityParams::decode(
        decoded.security_params().clone(),
        crate::DecodeConfig::DEFAULT,
    )
    .unwrap()
    .value;
    assert_eq!(usm.engine_boots(), 2);
    assert_eq!(&usm.priv_params()[..4], &2u32.to_be_bytes());
}

#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
#[test]
fn lower_security_notification_does_not_initialize_unused_aes_state() {
    let authoritative = AuthoritativeEngine::for_test(b"unused-notification-aes".as_slice(), 1);
    let local = LocalEngine::from_prepared(
        Some(authoritative),
        Bytes::from_static(b"unused-notification-aes"),
        1,
        None,
        None,
    );
    let context = UsmSecurityContext::new([UsmUserEntry::new(
        UsmUser::new("user")
            .auth_priv(
                crate::AuthProtocol::Sha256,
                b"authentication",
                PrivProtocol::Aes128,
                b"privacy-password",
            )
            .unwrap(),
    )])
    .unwrap();
    let processor = NotificationProcessor::builder()
        .local_engine(local.clone())
        .security_context(context)
        .accept_all_notifications()
        .build()
        .unwrap();
    let pending = response(
        processor
            .process(input(
                wire_no_auth(local.engine_id(), "user"),
                ProcessingLimits::UDP,
            ))
            .unwrap(),
    );
    assert!(matches!(
        pending.encode().unwrap(),
        EncodedInformResponse::Response(_)
    ));
    assert!(local.salt_counter().is_none());
}

#[test]
fn dropping_deferred_inform_does_not_encode_or_increment_silent_drops() {
    let local = engine();
    let processor = NotificationProcessor::builder()
        .local_engine(local.clone())
        .build()
        .unwrap();
    let wire = CommunityMessage::v2c("public", pdu(Version::V2c))
        .unwrap()
        .encode()
        .unwrap();
    let limits = ProcessingLimits::new(crate::UDP_RECEIVE_LIMITS, 1).unwrap();
    let pending = response(processor.process(input(wire.clone(), limits)).unwrap());
    assert_eq!(local.inner.snmp_silent_drops.load(Ordering::Relaxed), 0);
    drop(pending);
    assert_eq!(local.inner.snmp_silent_drops.load(Ordering::Relaxed), 0);
    assert!(matches!(
        response(processor.process(input(wire, limits)).unwrap())
            .encode()
            .unwrap(),
        EncodedInformResponse::Suppressed
    ));
    assert_eq!(local.inner.snmp_silent_drops.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn managed_and_custom_processing_count_decode_errors_once() {
    let local = engine();
    let processor = NotificationProcessor::builder()
        .local_engine(local.clone())
        .build()
        .unwrap();
    let prepared = NotificationReceiver::builder()
        .bind("127.0.0.1:0")
        .local_engine(local.clone())
        .prepare()
        .await
        .unwrap();
    let (receiver, runner) = prepared.into_parts();
    let bad = Bytes::from_static(&[0x30, 0x03, 0x02]);
    assert!(
        processor
            .process(input(bad.clone(), ProcessingLimits::UDP))
            .is_err()
    );
    assert_eq!(
        local.inner.snmp_in_asn_parse_errs.load(Ordering::Relaxed),
        1
    );
    assert!(
        receiver
            .handle_v3(bad, "127.0.0.1:40000".parse().unwrap())
            .await
            .is_err()
    );
    assert_eq!(
        local.inner.snmp_in_asn_parse_errs.load(Ordering::Relaxed),
        2
    );
    drop(receiver);
    drop(runner);
}

#[test]
fn unclaimed_and_receiver_invalid_flags_have_common_mpd_accounting() {
    let local = engine();
    let processor = NotificationProcessor::builder()
        .local_engine(local.clone())
        .build()
        .unwrap();
    let mut wire = wire_no_auth(b"foreign-engine", "unknown").to_vec();
    let flags = wire
        .windows(3)
        .position(|window| window == [0x04, 0x01, 0x04])
        .unwrap()
        + 2;
    wire[flags] = 0x02;
    let wire = Bytes::from(wire);
    assert!(
        processor
            .process(input(wire.clone(), ProcessingLimits::UDP))
            .is_err()
    );
    assert_eq!(local.inner.snmp_invalid_msgs.load(Ordering::Relaxed), 1);
    assert!(
        processor
            .report_unknown_engine(input(wire, ProcessingLimits::UDP))
            .is_err()
    );
    assert_eq!(local.inner.snmp_invalid_msgs.load(Ordering::Relaxed), 2);
    assert_eq!(
        local.inner.snmp_in_asn_parse_errs.load(Ordering::Relaxed),
        0
    );
    assert_eq!(local.usm_stats(), crate::UsmStatsSnapshot::default());
}
