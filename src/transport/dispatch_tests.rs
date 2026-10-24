//! Real-socket composition checks. Each endpoint has one owned reader.
use super::*;
use crate::message::CommunityMessage;
use crate::{Agent, Auth, Client, ClientBuilder, NotificationReceiver, Retry, Value, oid};
use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::net::UdpSocket;

fn engine(id: &'static [u8]) -> crate::AuthoritativeEngine {
    crate::AuthoritativeEngine::install(id.to_vec(), |_| Ok::<_, Infallible>(())).unwrap()
}
fn agent(id: &'static [u8]) -> crate::agent::AgentBuilder {
    Agent::builder()
        .bind("127.0.0.1:0")
        .community(b"public")
        .allow_all_access()
        .authoritative_engine(engine(id))
        .client_exchanges(true)
        .notifications(NotificationReceiver::builder().accept_all_notifications())
}
fn endpoint(agent: &Agent) -> UdpEndpoint {
    agent
        .udp_endpoint(agent.bound_addresses()[0].endpoint_id)
        .unwrap()
}
fn client(endpoint: &UdpEndpoint, target: std::net::SocketAddr, auth: Auth) -> Client<UdpHandle> {
    ClientBuilder::new(auth)
        .retry(Retry::none())
        .request_timeout(Duration::from_secs(2))
        .build_with_transport(endpoint.handle(target).unwrap())
        .unwrap()
}
fn get_oid() -> crate::Oid {
    oid!(1, 3, 6, 1, 6, 3, 10, 2, 1, 1, 0)
}
fn community(pdu: crate::Pdu) -> bytes::Bytes {
    CommunityMessage::v2c("public", pdu)
        .unwrap()
        .encode()
        .unwrap()
}
async fn receive(socket: &UdpSocket) -> (bytes::Bytes, std::net::SocketAddr) {
    let mut buffer = [0; 65535];
    let (n, source) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    (bytes::Bytes::copy_from_slice(&buffer[..n]), source)
}
fn registration(id: i32) -> RequestRegistration {
    RequestRegistration::community(
        id,
        tokio::time::Instant::now() + Duration::from_secs(2),
        crate::CommunityVersion::V2c,
        "public",
        CommunityResponsePolicy::Exact,
    )
}

#[tokio::test]
async fn command_only_community_dispatch_keeps_admission_and_unmatched_responses() {
    use super::dispatch::DispatchRoles;
    use super::framing::BufferBudget;
    use super::ingress::ApplicationIngress;
    use std::collections::HashMap;
    use tokio::sync::{Semaphore, mpsc};
    use tokio::task::JoinSet;
    use tokio_util::sync::CancellationToken;

    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (observer, mut events) = TransportObserver::channel(16).unwrap();
    let observation = super::observation::Observation(Some(observer));
    let responder =
        Arc::new(crate::udp_responder::UdpResponder::new(&socket).with_observation(observation));
    let endpoint = EndpointId::new();
    for version in [crate::CommunityVersion::V1, crate::CommunityVersion::V2c] {
        let (sender, mut receiver) = mpsc::channel(1);
        let disabled = CancellationToken::new();
        let drops = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let ingress = ApplicationIngress {
            admission_hook: None,
            sender,
            disabled: disabled.clone(),
            capacity: Arc::new(Semaphore::new(1)),
            budget: Arc::new(BufferBudget::new(1024)),
            overload_timeout: Duration::from_secs(1),
            drops: drops.clone(),
            session: None,
        };
        let roles = Arc::new(DispatchRoles::new(
            Some(ingress),
            None,
            HashMap::new(),
            false,
            1,
        ));
        let core = Arc::new(super::udp_core::UdpCore::new());
        let mut tasks = JoinSet::new();
        let message = |pdu| {
            let bytes = match version {
                crate::CommunityVersion::V1 => CommunityMessage::v1("public", pdu),
                crate::CommunityVersion::V2c => CommunityMessage::v2c("public", pdu),
            }
            .unwrap()
            .encode()
            .unwrap();
            let received = crate::udp_responder::ReceivedDatagram {
                len: bytes.len(),
                source: peer.local_addr().unwrap(),
                destination: None,
            };
            let info = ReceivedMessageInfo::udp(
                endpoint,
                socket.local_addr().unwrap(),
                received.source,
                None,
                tokio::time::Instant::now(),
                bytes.len(),
            );
            ReceivedMessage::udp(
                bytes,
                info,
                socket.clone(),
                responder.clone(),
                received,
                EndpointLimits::UDP,
            )
        };

        let first = message(crate::Pdu::get_request(1, &[get_oid()]));
        let info = first.info;
        roles.dispatch(first, core.clone(), &mut tasks);
        let work = receiver.try_recv().unwrap();
        assert_eq!(work.message.info, info);
        assert!(
            tasks.is_empty(),
            "command admission must not wait on a classifier task"
        );
        roles.dispatch(
            message(crate::Pdu::get_request(2, &[get_oid()])),
            core.clone(),
            &mut tasks,
        );
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        roles.dispatch(
            message(crate::Pdu::response(3, 0, 0, vec![])),
            core.clone(),
            &mut tasks,
        );
        assert!(receiver.try_recv().is_err());
        disabled.cancel();
        drop(work);
        roles.dispatch(
            message(crate::Pdu::get_request(4, &[get_oid()])),
            core,
            &mut tasks,
        );
        assert!(receiver.try_recv().is_err());
        assert!(tasks.is_empty());
        for disposition in [
            MessageDisposition::ApplicationQueued,
            MessageDisposition::Overloaded,
            MessageDisposition::Unmatched,
            MessageDisposition::Disabled,
        ] {
            assert!(
                matches!(events.try_recv().unwrap(), ObservationEvent::Disposition { disposition: actual, .. } if actual == disposition)
            );
        }
    }
}

#[tokio::test]
async fn bidirectional_commands_and_notifications_share_source_ports() {
    let mut a = agent(b"shared-endpoint-a").spawn().await.unwrap();
    let mut b = agent(b"shared-endpoint-b").spawn().await.unwrap();
    let mut notifications_a = a.take_notifications().unwrap();
    let mut notifications_b = b.take_notifications().unwrap();
    assert!(a.take_notifications().is_none());
    assert_eq!(notifications_a.engine_id(), a.engine_id());
    let ea = endpoint(&a);
    let eb = endpoint(&b);
    for auth in [Auth::v1("public"), Auth::v2c("public")] {
        let ab = client(&ea, eb.local_addr(), auth.clone());
        let ba = client(&eb, ea.local_addr(), auth);
        let oid = get_oid();
        let (left, right) = tokio::join!(ab.get(&oid), ba.get(&oid));
        assert_eq!(
            left.unwrap().varbinds[0].value,
            Value::OctetString(b.engine_id().to_vec().into())
        );
        assert_eq!(
            right.unwrap().varbinds[0].value,
            Value::OctetString(a.engine_id().to_vec().into())
        );
        ab.send_trap(&crate::notification::oids::cold_start(), 1, vec![])
            .await
            .unwrap();
        assert_eq!(
            notifications_b
                .recv()
                .await
                .unwrap()
                .receive_info
                .peer_addr(),
            ea.local_addr()
        );
    }
    let ab = client(&ea, eb.local_addr(), Auth::v2c("public"));
    let ba = client(&eb, ea.local_addr(), Auth::v2c("public"));
    let trap = crate::notification::oids::cold_start();
    let oid = get_oid();
    let (inform, command) = tokio::join!(ab.send_inform(&trap, 1, vec![]), ba.get(&oid));
    inform.unwrap();
    command.unwrap();
    assert_eq!(
        notifications_b
            .recv()
            .await
            .unwrap()
            .receive_info
            .peer_addr(),
        ea.local_addr()
    );
    ba.send_inform(&trap, 2, vec![]).await.unwrap();
    assert_eq!(
        notifications_a
            .recv()
            .await
            .unwrap()
            .receive_info
            .peer_addr(),
        eb.local_addr()
    );
    a.shutdown().await.unwrap();
    b.shutdown().await.unwrap();
}

#[tokio::test]
async fn colliding_community_ids_deliver_each_role_for_same_and_distinct_peers() {
    let mut service = agent(b"collision-endpoint").spawn().await.unwrap();
    let mut notifications = service.take_notifications().unwrap();
    let endpoint = endpoint(&service);
    for same_peer in [true, false] {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let other = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let handle = endpoint
            .handle(peer.local_addr().unwrap())
            .unwrap()
            .strict_source(true);
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let request = tokio::spawn(async move {
            handle
                .request_with(
                    &community(crate::Pdu::get_request(41, &[get_oid()])),
                    registration(41),
                    move |packet| {
                        let (bytes, _) = packet.into_parts();
                        count.fetch_add(1, Ordering::Relaxed);
                        let decoded =
                            CommunityMessage::decode(bytes, crate::DecodeConfig::DEFAULT)?
                                .value
                                .into_pdu()
                                .unwrap();
                        assert_eq!(decoded.pdu_type(), crate::PduType::Response);
                        Ok(Candidate::Accept(decoded))
                    },
                )
                .await
        });
        let (_, source) = receive(&peer).await;
        assert_eq!(source, endpoint.local_addr());
        let sender = if same_peer { &peer } else { &other };
        sender
            .send_to(
                &community(crate::Pdu::get_request(41, &[get_oid()])),
                source,
            )
            .await
            .unwrap();
        receive(sender).await;
        sender
            .send_to(
                &community(crate::Pdu::inform_request(
                    41,
                    1,
                    &crate::notification::oids::cold_start(),
                    vec![],
                )),
                source,
            )
            .await
            .unwrap();
        receive(sender).await;
        assert_eq!(
            notifications.recv().await.unwrap().wire_identity.request_id,
            Some(41)
        );
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        peer.send_to(&community(crate::Pdu::response(41, 0, 0, vec![])), source)
            .await
            .unwrap();
        request.await.unwrap().unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }
    service.shutdown().await.unwrap();
}

#[tokio::test]
async fn role_closure_and_root_abort_propagate_to_their_own_scope() {
    let mut service = agent(b"closing-shared-endpoint").spawn().await.unwrap();
    let mut notifications = service.take_notifications().unwrap();
    let endpoint = endpoint(&service);
    let remote = agent(b"closing-remote-endpoint").spawn().await.unwrap();
    let outgoing = client(
        &endpoint,
        remote.bound_addresses()[0].local_addr,
        Auth::v2c("public"),
    );
    let incoming = Client::builder(endpoint.local_addr().to_string(), Auth::v2c("public"))
        .connect()
        .await
        .unwrap();
    notifications.control().shutdown().await;
    assert!(notifications.recv().await.is_none());
    incoming.get(&get_oid()).await.unwrap();
    outgoing.get(&get_oid()).await.unwrap();
    service.close_commands();
    outgoing.get(&get_oid()).await.unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let handle = endpoint.handle(peer.local_addr().unwrap()).unwrap();
    let pending = tokio::spawn(async move {
        handle
            .request_with(
                &community(crate::Pdu::get_request(4, &[get_oid()])),
                registration(4),
                |_| Ok(Candidate::Accept(())),
            )
            .await
    });
    receive(&peer).await;
    service.task().abort();
    assert!(matches!(
        *pending.await.unwrap().unwrap_err(),
        crate::Error::Closed { .. }
    ));
    assert!(service.join().await.is_err());
    assert!(endpoint.control().is_shutdown());
    remote.shutdown().await.unwrap();
}

#[tokio::test]
async fn peer_and_endpoint_control_retain_service_after_root_handle_drop() {
    for retain_control in [false, true] {
        let (agent, runner) = agent(b"retained-shared-endpoint")
            .prepare()
            .await
            .unwrap()
            .into_parts();
        let endpoint = endpoint(&agent);
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let handle = endpoint.handle(peer.local_addr().unwrap()).unwrap();
        let control = endpoint.control();
        let task = tokio::spawn(runner.run());
        drop(agent);
        drop(endpoint);
        if retain_control {
            drop(handle);
            assert!(!control.is_shutdown());
            drop(control);
        } else {
            drop(control);
            handle
                .send(&community(crate::Pdu::get_request(3, &[get_oid()])))
                .await
                .unwrap();
            receive(&peer).await;
            drop(handle);
        }
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn client_decode_policy_is_independent_of_strict_command_policy() {
    let mut service = agent(b"asymmetric-decode")
        .decode_config(crate::DecodeConfig::STRICT)
        .spawn()
        .await
        .unwrap();
    let _notifications = service.take_notifications();
    let endpoint = endpoint(&service);
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client = client(&endpoint, peer.local_addr().unwrap(), Auth::v2c("public"));
    let pending = tokio::spawn(async move { client.get(&get_oid()).await });
    let (request, source) = receive(&peer).await;
    let pdu = CommunityMessage::decode(request, crate::DecodeConfig::DEFAULT)
        .unwrap()
        .value
        .into_pdu()
        .unwrap();
    let mut bytes = community(crate::Pdu::response(
        pdu.request_id(),
        0,
        0,
        pdu.varbinds().to_vec(),
    ))
    .to_vec();
    bytes.extend_from_slice(b"suffix");
    peer.send_to(&bytes, source).await.unwrap();
    pending.await.unwrap().unwrap();
    service.shutdown().await.unwrap();
}

#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
fn secured_agent(id: &'static [u8]) -> crate::agent::AgentBuilder {
    agent(id)
        .usm_user("noauth", Ok)
        .unwrap()
        .usm_user("auth", |u| {
            u.auth(crate::AuthProtocol::Sha256, b"shared-auth-password")
        })
        .unwrap()
        .usm_user("priv", |u| {
            u.auth_priv(
                crate::AuthProtocol::Sha256,
                b"shared-auth-password",
                crate::PrivProtocol::Aes128,
                b"shared-priv-password",
            )
        })
        .unwrap()
}
#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
fn security(name: &str) -> crate::UsmConfig {
    let config = crate::UsmConfig::new(name.to_owned());
    match name {
        "noauth" => config,
        "auth" => config
            .auth(crate::AuthProtocol::Sha256, b"shared-auth-password")
            .unwrap(),
        _ => config
            .auth_priv(
                crate::AuthProtocol::Sha256,
                b"shared-auth-password",
                crate::PrivProtocol::Aes128,
                b"shared-priv-password",
            )
            .unwrap(),
    }
}
#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
fn secured(pdu: crate::Pdu, id: i32, engine: &[u8], config: &crate::UsmConfig) -> bytes::Bytes {
    let keys = config.derive_keys(engine).unwrap();
    let reportable = matches!(
        pdu.pdu_type(),
        crate::PduType::GetRequest | crate::PduType::InformRequest
    );
    crate::v3::encode::encode_v3_message(
        &pdu,
        id,
        engine,
        1,
        0,
        config,
        Some(&keys),
        Some(&crate::v3::SaltCounter::new().unwrap()),
        None,
        None,
        reportable,
        crate::MessageSize::from_i32(65507).unwrap(),
    )
    .unwrap()
    .into()
}

#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
#[tokio::test]
async fn shared_v3_discovery_get_and_inform_at_every_security_level() {
    let mut a = secured_agent(b"secured-endpoint-a").spawn().await.unwrap();
    let mut b = secured_agent(b"secured-endpoint-b").spawn().await.unwrap();
    let mut na = a.take_notifications().unwrap();
    let mut nb = b.take_notifications().unwrap();
    for name in ["noauth", "auth", "priv"] {
        let ab = client(
            &endpoint(&a),
            b.bound_addresses()[0].local_addr,
            security(name).into(),
        );
        let ba = client(
            &endpoint(&b),
            a.bound_addresses()[0].local_addr,
            security(name).into(),
        );
        let oid = get_oid();
        let trap = crate::notification::oids::cold_start();
        let (get, inform) = tokio::join!(ab.get(&oid), ba.send_inform(&trap, 1, vec![]));
        assert_eq!(
            get.unwrap().varbinds[0].value,
            Value::OctetString(b.engine_id().to_vec().into())
        );
        inform.unwrap();
        assert_eq!(
            na.recv().await.unwrap().receive_info.peer_addr(),
            b.bound_addresses()[0].local_addr
        );
        ab.send_inform(&trap, 1, vec![]).await.unwrap();
        assert_eq!(
            nb.recv().await.unwrap().receive_info.peer_addr(),
            a.bound_addresses()[0].local_addr
        );
    }
    a.shutdown().await.unwrap();
    b.shutdown().await.unwrap();
}

#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
#[tokio::test]
async fn encrypted_collisions_select_commands_informs_and_remote_traps_without_consuming_exchange()
{
    let mut service = secured_agent(b"collision-local-engine")
        .spawn()
        .await
        .unwrap();
    let mut notifications = service.take_notifications().unwrap();
    let endpoint = endpoint(&service);
    for same_peer in [true, false] {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let other = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let handle = endpoint
            .handle(peer.local_addr().unwrap())
            .unwrap()
            .strict_source(true);
        let config = security("priv");
        let registration =
            RequestRegistration::v3(77, tokio::time::Instant::now() + Duration::from_secs(2))
                .with_classification_usm(
                    config.clone(),
                    Some(bytes::Bytes::from_static(b"remote-response-engine")),
                );
        let bytes = secured(
            crate::Pdu::get_request(77, &[get_oid()]),
            77,
            b"remote-response-engine",
            &config,
        );
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let request = tokio::spawn(async move {
            handle
                .request_with(&bytes, registration, move |packet| {
                    let (_, _) = packet.into_parts();
                    count.fetch_add(1, Ordering::Relaxed);
                    Ok(Candidate::Accept(()))
                })
                .await
        });
        let (_, source) = receive(&peer).await;
        let sender = if same_peer { &peer } else { &other };
        sender
            .send_to(
                &secured(
                    crate::Pdu::get_request(77, &[get_oid()]),
                    77,
                    service.engine_id(),
                    &config,
                ),
                source,
            )
            .await
            .unwrap();
        receive(sender).await;
        sender
            .send_to(
                &secured(
                    crate::Pdu::inform_request(
                        77,
                        1,
                        &crate::notification::oids::cold_start(),
                        vec![],
                    ),
                    77,
                    service.engine_id(),
                    &config,
                ),
                source,
            )
            .await
            .unwrap();
        receive(sender).await;
        assert_eq!(
            notifications.recv().await.unwrap().wire_identity.request_id,
            Some(77)
        );
        sender
            .send_to(
                &secured(
                    crate::Pdu::trap_v2(77, 1, &crate::notification::oids::cold_start(), vec![]),
                    77,
                    b"remote-response-engine",
                    &config,
                ),
                source,
            )
            .await
            .unwrap();
        assert_eq!(
            notifications.recv().await.unwrap().wire_identity.request_id,
            Some(77)
        );
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        peer.send_to(
            &secured(
                crate::Pdu::response(77, 0, 0, vec![]),
                77,
                b"remote-response-engine",
                &config,
            ),
            source,
        )
        .await
        .unwrap();
        request.await.unwrap().unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }
    service.shutdown().await.unwrap();
}

#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
#[tokio::test]
async fn failed_client_security_never_reenters_application_or_publishes_reports() {
    let mut service = secured_agent(b"failure-local-engine")
        .spawn()
        .await
        .unwrap();
    let notifications = service.take_notifications().unwrap();
    let endpoint = endpoint(&service);
    for username in ["priv", "client-only"] {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let handle = endpoint.handle(peer.local_addr().unwrap()).unwrap();
        let config = security(username);
        let registration =
            RequestRegistration::v3(78, tokio::time::Instant::now() + Duration::from_secs(2))
                .with_classification_usm(
                    config.clone(),
                    Some(bytes::Bytes::from_static(b"failure-remote-engine")),
                );
        let data = secured(
            crate::Pdu::get_request(78, &[get_oid()]),
            78,
            b"failure-remote-engine",
            &config,
        );
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let pending = tokio::spawn(async move {
            handle
                .request_with(&data, registration, move |packet| {
                    let (_, _) = packet.into_parts();
                    if count.fetch_add(1, Ordering::Relaxed) == 0 {
                        Ok(Candidate::Reject)
                    } else {
                        Ok(Candidate::Accept(()))
                    }
                })
                .await
        });
        let (_, source) = receive(&peer).await;
        let response = secured(
            crate::Pdu::response(78, 0, 0, vec![]),
            78,
            b"failure-remote-engine",
            &config,
        );
        let mut corrupted = response.to_vec();
        *corrupted.last_mut().unwrap() ^= 1;
        peer.send_to(&corrupted, source).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while calls.load(Ordering::Relaxed) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(notifications.usm_unknown_engine_ids(), 0);
        assert_eq!(notifications.usm_unknown_usernames(), 0);
        assert_eq!(notifications.usm_wrong_digests(), 0);
        assert!(
            tokio::time::timeout(Duration::from_millis(30), peer.recv(&mut [0; 2048]))
                .await
                .is_err()
        );
        peer.send_to(&response, source).await.unwrap();
        pending.await.unwrap().unwrap();
    }
    service.shutdown().await.unwrap();
}

#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
#[tokio::test]
async fn ambiguous_usm_credentials_are_rejected_before_outbound_send() {
    let mut service = secured_agent(b"ambiguous-credentials")
        .spawn()
        .await
        .unwrap();
    let _notifications = service.take_notifications();
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let bad = crate::UsmConfig::new("priv")
        .auth_priv(
            crate::AuthProtocol::Sha256,
            b"different-auth-password",
            crate::PrivProtocol::Aes128,
            b"shared-priv-password",
        )
        .unwrap();
    let client = client(&endpoint(&service), peer.local_addr().unwrap(), bad.into());
    assert!(matches!(
        *client.get(&get_oid()).await.unwrap_err(),
        crate::Error::Config(_)
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(30), peer.recv(&mut [0; 2048]))
            .await
            .is_err()
    );
    service.shutdown().await.unwrap();
}

#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
#[tokio::test]
async fn closing_commands_keeps_fresh_inform_discovery_and_notification_security() {
    let mut service = secured_agent(b"closed-commands-informs")
        .spawn()
        .await
        .unwrap();
    let mut notifications = service.take_notifications().unwrap();
    service.close_commands();
    let client = Client::builder(
        service.bound_addresses()[0].local_addr.to_string(),
        security("priv"),
    )
    .retry(Retry::none())
    .request_timeout(Duration::from_secs(2))
    .connect()
    .await
    .unwrap();
    client
        .send_inform(&crate::notification::oids::cold_start(), 1, vec![])
        .await
        .unwrap();
    assert!(notifications.recv().await.unwrap().inform_ack.is_some());
    service.shutdown().await.unwrap();
}

#[tokio::test]
async fn command_only_proxy_uses_listener_endpoint_for_upstream_request() {
    use crate::handler::{
        BoxFuture, GetNextResult, GetResult, HandlerResult, MibHandler, RequestContext,
    };
    struct Proxy(std::sync::OnceLock<Client<UdpHandle>>);
    impl MibHandler for Proxy {
        fn get<'a>(
            &'a self,
            _: &'a RequestContext,
            _: &'a crate::Oid,
        ) -> BoxFuture<'a, HandlerResult<GetResult>> {
            Box::pin(async move {
                let result = self.0.get().unwrap().get(&get_oid()).await.unwrap();
                Ok(GetResult::Value(result.varbinds[0].value.clone()))
            })
        }
        fn get_next<'a>(
            &'a self,
            _: &'a RequestContext,
            _: &'a crate::Oid,
        ) -> BoxFuture<'a, HandlerResult<GetNextResult>> {
            Box::pin(async { Ok(GetNextResult::EndOfMibView) })
        }
    }
    let upstream = Agent::builder()
        .bind("127.0.0.1:0")
        .community(b"public")
        .allow_all_access()
        .spawn()
        .await
        .unwrap();
    let proxy = Arc::new(Proxy(std::sync::OnceLock::new()));
    let prepared = Agent::builder()
        .bind("127.0.0.1:0")
        .community(b"public")
        .allow_all_access()
        .client_exchanges(true)
        .handler(oid!(1, 3, 6, 1, 4, 1, 99999), proxy.clone())
        .prepare()
        .await
        .unwrap();
    let (agent, runner) = prepared.into_parts();
    let upstream_client = client(
        &endpoint(&agent),
        upstream.bound_addresses()[0].local_addr,
        Auth::v2c("public"),
    );
    assert!(proxy.0.set(upstream_client).is_ok());
    let task = tokio::spawn(runner.run());
    let downstream = Client::builder(
        agent.bound_addresses()[0].local_addr.to_string(),
        Auth::v2c("public"),
    )
    .connect()
    .await
    .unwrap();
    let result = downstream
        .get(&oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0))
        .await
        .unwrap();
    assert_eq!(
        result.varbinds[0].value,
        Value::OctetString(upstream.engine_id().to_vec().into())
    );
    agent.control().shutdown().await;
    task.await.unwrap().unwrap();
    upstream.shutdown().await.unwrap();
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
async fn shared_wildcard_commands_and_inform_acks_preserve_received_destination() {
    let mut service = agent(b"shared-wildcard")
        .bind("0.0.0.0:0")
        .spawn()
        .await
        .unwrap();
    let mut notifications = service.take_notifications().unwrap();
    let address = std::net::SocketAddr::from((
        [127, 0, 0, 2],
        service.bound_addresses()[0].local_addr.port(),
    ));
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for pdu in [
        crate::Pdu::get_request(9, &[get_oid()]),
        crate::Pdu::inform_request(10, 1, &crate::notification::oids::cold_start(), vec![]),
    ] {
        peer.send_to(&community(pdu), address).await.unwrap();
        let (_, source) = receive(&peer).await;
        assert_eq!(source, address);
    }
    assert_eq!(
        notifications
            .recv()
            .await
            .unwrap()
            .receive_info
            .datagram_destination(),
        Some(address.ip())
    );
    service.shutdown().await.unwrap();
}

#[tokio::test]
async fn one_peers_parked_candidates_leave_response_bytes_for_other_peers() {
    let mut service = agent(b"peer-response-fairness").spawn().await.unwrap();
    let _notifications = service.take_notifications();
    let endpoint = endpoint(&service);
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let handle = endpoint.handle(peer.local_addr().unwrap()).unwrap();
    let request = community(crate::Pdu::get_request(1, &[get_oid()]));
    let mut pending = Vec::new();
    for id in 1..=80 {
        let mut exchange = Box::pin(
            handle.request_with(&request, registration(id), |_| Ok(Candidate::Accept(()))),
        );
        tokio::select! {
            result = &mut exchange => panic!("request completed before peer received it: {result:?}"),
            _ = receive(&peer) => {}
        }
        pending.push(exchange); // Deliberately leave response validation unpolled.
    }
    for id in 1..=80 {
        let response = community(crate::Pdu::response(
            id,
            0,
            0,
            vec![crate::VarBind::new(
                get_oid(),
                Value::OctetString(vec![42; 60_000].into()),
            )],
        ));
        peer.send_to(&response, endpoint.local_addr())
            .await
            .unwrap();
        tokio::task::yield_now().await;
    }
    tokio::time::timeout(Duration::from_secs(1), async {
        while service.control().overload_drops() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(endpoint.stats().correlated_datagrams <= 17);
    let other = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let handle = endpoint.handle(other.local_addr().unwrap()).unwrap();
    let progress = tokio::spawn(async move {
        handle
            .request_with(
                &community(crate::Pdu::get_request(90, &[get_oid()])),
                registration(90),
                |_| Ok(Candidate::Accept(())),
            )
            .await
    });
    receive(&other).await;
    other
        .send_to(
            &community(crate::Pdu::response(90, 0, 0, vec![])),
            endpoint.local_addr(),
        )
        .await
        .unwrap();
    progress.await.unwrap().unwrap();
    drop(pending);
    service.shutdown().await.unwrap();
}

#[tokio::test]
async fn standalone_collector_polls_with_full_queue_and_after_consumer_drop() {
    let (mut collector, runner) = NotificationReceiver::builder()
        .bind("127.0.0.1:0")
        .client_exchanges(true)
        .queue_capacity(1)
        .prepare()
        .await
        .unwrap()
        .into_parts();
    let endpoint = collector
        .udp_endpoint(collector.bound_addresses()[0].endpoint_id)
        .unwrap();
    let task = tokio::spawn(runner.run());
    let remote = agent(b"collector-polled-device").spawn().await.unwrap();
    let originator = client(
        &self::endpoint(&remote),
        collector.local_addr(),
        Auth::v2c("public"),
    );
    originator
        .send_inform(&crate::notification::oids::cold_start(), 1, vec![])
        .await
        .unwrap();
    let poller = client(
        &endpoint,
        remote.bound_addresses()[0].local_addr,
        Auth::v2c("public"),
    );
    poller.get(&get_oid()).await.unwrap();
    collector.close();
    assert_eq!(
        collector.recv().await.unwrap().receive_info.peer_addr(),
        remote.bound_addresses()[0].local_addr
    );
    assert!(collector.recv().await.is_none());
    drop(collector);
    poller.get(&get_oid()).await.unwrap();
    drop(poller);
    drop(endpoint);
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    remote.shutdown().await.unwrap();
}

#[tokio::test]
async fn root_abort_ends_attached_consumer_and_pending_exchange() {
    let mut service = agent(b"attached-root-abort").spawn().await.unwrap();
    let mut notifications = service.take_notifications().unwrap();
    let endpoint = endpoint(&service);
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let handle = endpoint.handle(peer.local_addr().unwrap()).unwrap();
    let pending = tokio::spawn(async move {
        handle
            .request_with(
                &community(crate::Pdu::get_request(1, &[get_oid()])),
                registration(1),
                |_| Ok(Candidate::Accept(())),
            )
            .await
    });
    receive(&peer).await;
    service.task().abort();
    assert!(matches!(
        *pending.await.unwrap().unwrap_err(),
        crate::Error::Closed { .. }
    ));
    assert!(
        tokio::time::timeout(Duration::from_secs(1), notifications.recv())
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        notifications.control().status(),
        crate::notification::NotificationStatus::Interrupted
    );
    assert!(endpoint.control().is_shutdown());
    assert!(service.join().await.is_err());
}

#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
#[tokio::test]
async fn failed_remote_trap_keeps_remote_authority_security_processing() {
    let mut service = secured_agent(b"remote-trap-failure").spawn().await.unwrap();
    let notifications = service.take_notifications().unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut trap = secured(
        crate::Pdu::trap_v2(1, 1, &crate::notification::oids::cold_start(), vec![]),
        1,
        b"remote-trap-engine",
        &security("priv"),
    )
    .to_vec();
    *trap.last_mut().unwrap() ^= 1;
    peer.send_to(&trap, service.bound_addresses()[0].local_addr)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while notifications.usm_wrong_digests() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(notifications.usm_wrong_digests(), 1);
    assert_eq!(notifications.usm_unknown_engine_ids(), 0);
    assert!(
        tokio::time::timeout(Duration::from_millis(30), peer.recv(&mut [0; 2048]))
            .await
            .is_err()
    );
    service.shutdown().await.unwrap();
}

#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
#[tokio::test]
async fn combined_application_failures_publish_shared_counters_once() {
    let mut service = secured_agent(b"shared-message-counters")
        .spawn()
        .await
        .unwrap();
    let _notifications = service.take_notifications();
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let valid = secured(
        crate::Pdu::get_request(1, &[get_oid()]),
        1,
        service.engine_id(),
        &security("noauth"),
    );
    let header = valid
        .windows(6)
        .position(|bytes| bytes == [4, 1, 4, 2, 1, 3])
        .unwrap();
    let mut invalid_flags = valid.to_vec();
    invalid_flags[header + 2] = 2;
    let mut unknown_model = valid.to_vec();
    unknown_model[header + 5] = 4;
    for bytes in [
        &invalid_flags[..],
        &unknown_model[..],
        &[0x30, 0x03, 0x02][..],
    ] {
        peer.send_to(bytes, service.bound_addresses()[0].local_addr)
            .await
            .unwrap();
    }
    tokio::time::timeout(Duration::from_secs(1), async {
        while service.snmp_invalid_msgs() == 0
            || service.snmp_unknown_security_models() == 0
            || service.snmp_in_asn_parse_errs() == 0
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(service.snmp_invalid_msgs(), 1);
    assert_eq!(service.snmp_unknown_security_models(), 1);
    assert_eq!(service.snmp_in_asn_parse_errs(), 1);
    service.shutdown().await.unwrap();
}

#[tokio::test]
async fn attached_notification_silent_drop_is_visible_on_shared_engine() {
    let mut service = agent(b"shared-silent-drop")
        .notifications(NotificationReceiver::builder().max_message_size(1))
        .spawn()
        .await
        .unwrap();
    let mut notifications = service.take_notifications().unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    peer.send_to(
        &community(crate::Pdu::inform_request(
            1,
            1,
            &crate::notification::oids::cold_start(),
            vec![],
        )),
        service.bound_addresses()[0].local_addr,
    )
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(1), notifications.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(service.snmp_silent_drops(), 1);
    assert_eq!(notifications.snmp_silent_drops(), 1);
    service.shutdown().await.unwrap();
}
