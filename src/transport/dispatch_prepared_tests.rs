use super::*;
use crate::message::SecurityLevel;
use crate::v3::prepared::test_counts::{Counts, measure};
use crate::v3::process::{
    UsmFailure, UsmStats, V3Inbound, V3LocalContext, V3Role, process_prepared_v3_inbound,
};

fn security(password: &[u8]) -> crate::UsmConfig {
    crate::UsmConfig::new("prepared-user")
        .auth_priv(
            crate::AuthProtocol::Sha256,
            password,
            crate::PrivProtocol::Aes128,
            b"prepared-privacy",
        )
        .unwrap()
}
fn user(password: &[u8]) -> UsmUser {
    let mut user = UsmUser::new("prepared-user")
        .auth_priv(
            crate::AuthProtocol::Sha256,
            password,
            crate::PrivProtocol::Aes128,
            b"prepared-privacy",
        )
        .unwrap();
    user.validate_and_precompute().unwrap();
    user
}
async fn message() -> ReceivedMessage {
    let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let source = "127.0.0.1:9999".parse().unwrap();
    let config = security(b"prepared-authentication");
    let keys = config.derive_keys(b"prepared-engine").unwrap();
    let wire: Bytes = crate::v3::encode::encode_v3_message(
        &crate::Pdu::get_request(42, &[]),
        9,
        b"prepared-engine",
        7,
        1000,
        &config,
        Some(&keys),
        Some(&crate::v3::SaltCounter::new().unwrap()),
        None,
        None,
        true,
        crate::MessageSize::new(8192).unwrap(),
    )
    .unwrap()
    .into();
    let responder = Arc::new(crate::udp_responder::UdpResponder::new(&socket));
    let info = crate::ReceivedMessageInfo::udp(
        crate::EndpointId::new(),
        socket.local_addr().unwrap(),
        source,
        None,
        tokio::time::Instant::now(),
        wire.len(),
    );
    ReceivedMessage::udp(
        wire,
        info,
        socket,
        responder,
        crate::udp_responder::ReceivedDatagram {
            len: info.received_len(),
            source,
            destination: None,
        },
        super::super::EndpointLimits::UDP,
    )
}
fn context<'a>(
    engine: &'a Bytes,
    users: &'a HashMap<Bytes, UsmUser>,
    stats: &'a UsmStats,
    config: crate::DecodeConfig,
) -> V3LocalContext<'a> {
    V3LocalContext {
        engine_id: engine,
        engine_boots: 7,
        engine_time: 1000,
        authoritative_time: None,
        local_receive_capacity: crate::MessageSize::new(8192).unwrap(),
        accepted_receive_size: crate::UDP_RECEIVE_LIMITS.accepted(),
        decode_config: config,
        outbound_limit: 8192,
        usm_users: users,
        stats,
        mpd: None,
        source: "127.0.0.1:9999".parse().unwrap(),
    }
}
#[tokio::test]
async fn prepared_application_reuses_crypto_with_policy_and_budget_fallbacks() {
    let users = HashMap::from([(
        Bytes::from_static(b"prepared-user"),
        user(b"prepared-authentication"),
    )]);
    let roles = DispatchRoles::new(None, None, users.clone(), false, 1);
    let engine = Bytes::from_static(b"prepared-engine");
    for (config, retain_plaintext) in [
        (crate::DecodeConfig::DEFAULT, true),
        (crate::DecodeConfig::STRICT, true),
        (crate::DecodeConfig::DEFAULT, false),
    ] {
        let mut message = message().await;
        let capacity = message.bytes.len() * if retain_plaintext { 3 } else { 1 };
        let budget = Arc::new(Semaphore::new(capacity));
        let mut buffers: super::super::framing::BufferPermits = budget
            .clone()
            .try_acquire_many_owned(message.bytes.len() as u32)
            .unwrap()
            .into();
        let stats = UsmStats::default();
        let ctx = context(&engine, &users, &stats, config);
        let (result, counts) = measure(|| {
            let envelope = CorrelationEnvelope::parse(&message.bytes);
            assert_eq!(
                roles
                    .classify(&mut message, None, envelope, &mut false, &mut buffers)
                    .unwrap(),
                Some(PduType::GetRequest)
            );
            assert_eq!(
                message.prepared.as_ref().unwrap().plaintext_len() > 0,
                retain_plaintext
            );
            process_prepared_v3_inbound(
                message.bytes,
                &ctx,
                &V3Role::Authoritative,
                message.prepared,
            )
        });
        let V3Inbound::Message(inbound) = result.unwrap() else {
            panic!("expected accepted request")
        };
        assert_eq!(inbound.security_level, SecurityLevel::AuthPriv);
        assert_eq!(inbound.scoped_pdu.pdu.request_id(), 42);
        assert_eq!(
            counts,
            Counts {
                raw: if config == crate::DecodeConfig::STRICT {
                    2
                } else {
                    1
                },
                usm: if config == crate::DecodeConfig::STRICT {
                    2
                } else {
                    1
                },
                auth: 1,
                decrypt: if retain_plaintext { 1 } else { 2 }
            }
        );
        drop(buffers);
        assert_eq!(budget.available_permits(), capacity);
    }
}
#[tokio::test]
async fn udp_command_admission_accounts_for_optional_plaintext() {
    let users = HashMap::from([(
        Bytes::from_static(b"prepared-user"),
        user(b"prepared-authentication"),
    )]);
    let roles = DispatchRoles::new(None, None, users.clone(), false, 1);
    for retain_plaintext in [false, true] {
        let mut message = message().await;
        let mut classifier: super::super::framing::BufferPermits = Arc::new(Semaphore::new(8192))
            .try_acquire_many_owned(message.bytes.len() as u32)
            .unwrap()
            .into();
        let envelope = CorrelationEnvelope::parse(&message.bytes);
        roles
            .classify(&mut message, None, envelope, &mut false, &mut classifier)
            .unwrap();
        assert!(message.prepared.as_ref().unwrap().plaintext_len() > 0);
        let capacity = message.bytes.len() * if retain_plaintext { 3 } else { 1 };
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        let ingress = ApplicationIngress {
            admission_hook: None,
            sender,
            disabled: tokio_util::sync::CancellationToken::new(),
            capacity: Arc::new(Semaphore::new(1)),
            budget: Arc::new(super::super::framing::BufferBudget::new(capacity)),
            overload_timeout: std::time::Duration::from_secs(1),
            drops: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            session: None,
        };
        ingress.deliver_udp(message);
        drop(classifier);
        let work = receiver
            .try_recv()
            .expect("cache retention must not prevent original-size admission");
        assert_eq!(
            work.message.prepared.as_ref().unwrap().plaintext_len() > 0,
            retain_plaintext
        );
        assert_eq!(
            work._buffers.as_ref().unwrap()._local.num_permits(),
            work.message.buffered_len()
        );
        drop(work);
        assert_eq!(ingress.budget.inbound.available_permits(), capacity);
    }
}

#[tokio::test]
async fn prepared_evidence_does_not_cross_credentials_or_replaced_input() {
    let users = HashMap::from([(
        Bytes::from_static(b"prepared-user"),
        user(b"prepared-authentication"),
    )]);
    let wrong_users = HashMap::from([(
        Bytes::from_static(b"prepared-user"),
        user(b"different-authentication"),
    )]);
    let roles = DispatchRoles::new(None, None, users.clone(), false, 1);
    let engine = Bytes::from_static(b"prepared-engine");
    for replace_input in [false, true] {
        let mut message = message().await;
        let mut buffers: super::super::framing::BufferPermits = Arc::new(Semaphore::new(8192))
            .try_acquire_many_owned(message.bytes.len() as u32)
            .unwrap()
            .into();
        let stats = UsmStats::default();
        let ctx = context(
            &engine,
            if replace_input { &users } else { &wrong_users },
            &stats,
            crate::DecodeConfig::DEFAULT,
        );
        let (result, counts) = measure(|| {
            let envelope = CorrelationEnvelope::parse(&message.bytes);
            roles
                .classify(&mut message, None, envelope, &mut false, &mut buffers)
                .unwrap();
            if replace_input {
                let mut bytes = message.bytes.to_vec();
                *bytes.last_mut().unwrap() ^= 1;
                message.bytes = bytes.into();
            }
            process_prepared_v3_inbound(
                message.bytes,
                &ctx,
                &V3Role::Authoritative,
                message.prepared,
            )
        });
        assert!(matches!(
            result.unwrap(),
            V3Inbound::Failed {
                failure: UsmFailure::WrongDigests,
                ..
            }
        ));
        assert_eq!(counts.auth, 2);
        assert_eq!(counts.decrypt, 1);
        assert_eq!(
            stats
                .wrong_digests
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }
}
#[tokio::test]
async fn strict_application_rejects_cached_compatible_suffix_before_security_publication() {
    let users = HashMap::from([(
        Bytes::from_static(b"prepared-user"),
        user(b"prepared-authentication"),
    )]);
    let roles = DispatchRoles::new(None, None, users.clone(), false, 1);
    let mut message = message().await;
    let mut bytes = message.bytes.to_vec();
    bytes.extend_from_slice(b"suffix");
    message.bytes = bytes.into();
    let mut buffers: super::super::framing::BufferPermits = Arc::new(Semaphore::new(8192))
        .try_acquire_many_owned(message.bytes.len() as u32)
        .unwrap()
        .into();
    let engine = Bytes::from_static(b"prepared-engine");
    let stats = UsmStats::default();
    let ctx = context(&engine, &users, &stats, crate::DecodeConfig::STRICT);
    let (result, counts) = measure(|| {
        let envelope = CorrelationEnvelope::parse(&message.bytes);
        roles
            .classify(&mut message, None, envelope, &mut false, &mut buffers)
            .unwrap();
        process_prepared_v3_inbound(
            message.bytes,
            &ctx,
            &V3Role::Authoritative,
            message.prepared,
        )
    });
    assert!(matches!(*result.err().unwrap(), Error::Decode(_)));
    assert_eq!(
        counts,
        Counts {
            raw: 2,
            usm: 1,
            auth: 1,
            decrypt: 1
        }
    );
    assert_eq!(
        stats
            .wrong_digests
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
}
