#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
use std::convert::Infallible;
use std::time::Duration;

#[cfg(feature = "agent")]
use async_snmp::Auth;
use async_snmp::message::CommunityMessage;
#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
use async_snmp::{AuthoritativeEngine, RequestTransport, TransportKind};
#[cfg(any(
    feature = "agent",
    feature = "crypto-rustcrypto",
    feature = "crypto-fips"
))]
use async_snmp::{Client, Retry};
use async_snmp::{
    ErrorKind, InformAckOutcome, InformAcknowledgementMode, ListenerSource, MessageDisposition,
    NotificationAcknowledgement, NotificationPdu, NotificationReceiver, ObservationEvent,
    PendingInformAck, TcpListenerSource, TransportObserver, Value, VarBind, Version, oid,
};
use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

#[path = "common/wildcard_udp.rs"]
mod wildcard_udp;
use wildcard_udp::wildcard_udp_destination;

const WAIT: Duration = Duration::from_secs(3);

fn manual() -> async_snmp::NotificationReceiverBuilder {
    NotificationReceiver::builder()
        .acknowledgement_mode(InformAcknowledgementMode::ApplicationControlled)
        .max_pending_informs(1)
        .pending_inform_timeout(WAIT)
}
fn wire(id: i32) -> Bytes {
    wire_with_varbinds(id, vec![])
}

fn wire_with_varbinds(id: i32, varbinds: Vec<VarBind>) -> Bytes {
    CommunityMessage::v2c(
        "public",
        NotificationPdu::inform(
            Version::V2c,
            id,
            0,
            &oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1),
            varbinds,
        )
        .unwrap()
        .into_raw(),
    )
    .unwrap()
    .encode()
    .unwrap()
}
fn oversized_wire(id: i32) -> Bytes {
    wire_with_varbinds(
        id,
        vec![VarBind::new(
            oid!(1, 3, 6, 1, 4, 1, 9, 1),
            Value::OctetString(Bytes::from_static(&[0; 128])),
        )],
    )
}
fn pending(event: async_snmp::ReceivedNotification) -> PendingInformAck {
    let NotificationAcknowledgement::Pending(pending) = event.inform_ack else {
        panic!("expected a manual capability")
    };
    pending
}
async fn event(
    receiver: &mut async_snmp::RunningNotificationReceiver,
) -> async_snmp::ReceivedNotification {
    tokio::time::timeout(WAIT, receiver.recv())
        .await
        .unwrap()
        .unwrap()
}
async fn udp_reply(socket: &UdpSocket) -> (Bytes, std::net::SocketAddr) {
    let mut bytes = vec![0; 65535];
    let (len, source) = tokio::time::timeout(WAIT, socket.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    (Bytes::copy_from_slice(&bytes[..len]), source)
}
async fn tcp_reply(stream: &mut TcpStream) -> CommunityMessage {
    tokio::time::timeout(WAIT, async {
        let mut bytes = Vec::new();
        loop {
            assert!(stream.read_buf(&mut bytes).await.unwrap() > 0);
            if let Ok(message) = CommunityMessage::decode(
                Bytes::copy_from_slice(&bytes),
                async_snmp::DecodeConfig::DEFAULT,
            ) {
                break message.value;
            }
        }
    })
    .await
    .unwrap()
}
async fn assert_tcp_too_big(peer: &mut TcpStream, request_id: i32) {
    let reply = tcp_reply(peer).await;
    let pdu = reply.pdu().standard().unwrap();
    assert_eq!(pdu.request_id(), request_id);
    assert_eq!(pdu.error_status_enum(), async_snmp::ErrorStatus::TooBig);
    assert_eq!(pdu.error_index(), 0);
    assert!(pdu.varbinds().is_empty());
}

#[tokio::test]
async fn udp_manual_ack_preserves_wildcard_destination_and_close_keeps_admitted_token() {
    let mut receiver = manual().bind("0.0.0.0:0").spawn().await.unwrap();
    let destination = wildcard_udp_destination(receiver.bound_addresses()[0].local_addr.port());
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    peer.send_to(&wire(17), destination).await.unwrap();
    let notification = event(&mut receiver).await;
    assert_eq!(
        notification.receive_info.datagram_destination(),
        Some(destination.ip())
    );
    let ack = pending(notification);
    assert!(
        tokio::time::timeout(Duration::from_millis(30), peer.recv(&mut [0; 2048]))
            .await
            .is_err()
    );
    receiver.close();
    assert!(matches!(ack.acknowledge().await, InformAckOutcome::Sent));
    let (bytes, source) = udp_reply(&peer).await;
    assert_eq!(source, destination);
    let response = CommunityMessage::decode(bytes, async_snmp::DecodeConfig::DEFAULT)
        .unwrap()
        .value;
    assert_eq!(response.pdu().standard().unwrap().request_id(), 17);
    receiver.shutdown().await.unwrap();
}

#[tokio::test]
async fn receiver_udp_endpoint_shutdown_preserves_tcp_informs() {
    let mut receiver = manual()
        .listener(ListenerSource::udp("127.0.0.1:0"))
        .listener(ListenerSource::tcp("127.0.0.1:0"))
        .spawn()
        .await
        .unwrap();
    let udp = receiver
        .udp_endpoint(receiver.bound_addresses()[0].endpoint_id)
        .unwrap()
        .control();
    let mut peer = TcpStream::connect(receiver.bound_addresses()[1].local_addr)
        .await
        .unwrap();
    peer.write_all(&wire(1)).await.unwrap();
    let first = pending(event(&mut receiver).await);

    udp.shutdown().await;
    assert_eq!(udp.status(), async_snmp::UdpStatus::Stopped);
    assert!(matches!(first.acknowledge().await, InformAckOutcome::Sent));
    let reply = tcp_reply(&mut peer).await;
    assert_eq!(reply.pdu().standard().unwrap().request_id(), 1);

    peer.write_all(&wire(2)).await.unwrap();
    let second = pending(event(&mut receiver).await);
    assert!(matches!(second.acknowledge().await, InformAckOutcome::Sent));
    let reply = tcp_reply(&mut peer).await;
    assert_eq!(reply.pdu().standard().unwrap().request_id(), 2);
    assert_eq!(
        receiver.control().status(),
        async_snmp::NotificationStatus::Running
    );
    receiver.shutdown().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn closing_the_only_udp_endpoint_leaves_receiver_under_service_control() {
    let mut receiver = NotificationReceiver::spawn("127.0.0.1:0").await.unwrap();
    let udp = receiver
        .udp_endpoint(receiver.bound_addresses()[0].endpoint_id)
        .unwrap()
        .control();
    udp.shutdown().await;
    assert!(
        tokio::time::timeout(WAIT, receiver.control().wait_closed())
            .await
            .is_err()
    );
    receiver.shutdown().await.unwrap();
}

#[tokio::test]
async fn tcp_pending_saturation_preserves_session_and_drop_releases_outstanding_slot() {
    let mut receiver = manual()
        .listener(ListenerSource::tcp("127.0.0.1:0"))
        .spawn()
        .await
        .unwrap();
    let mut peer = TcpStream::connect(receiver.bound_addresses()[0].local_addr)
        .await
        .unwrap();
    peer.write_all(&wire(1)).await.unwrap();
    let first = pending(event(&mut receiver).await);
    peer.write_all(&wire(2)).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(50), receiver.recv())
            .await
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(30), peer.read(&mut [0; 2048]))
            .await
            .is_err()
    );
    assert_eq!(receiver.control().overload_drops(), 1);
    drop(first);
    peer.write_all(&wire(3)).await.unwrap();
    let third = pending(event(&mut receiver).await);
    assert!(matches!(third.acknowledge().await, InformAckOutcome::Sent));
    assert_eq!(
        tcp_reply(&mut peer)
            .await
            .pdu()
            .standard()
            .unwrap()
            .request_id(),
        3
    );
    peer.write_all(&wire(4)).await.unwrap();
    pending(event(&mut receiver).await).reject();
    assert!(
        tokio::time::timeout(Duration::from_millis(30), peer.read(&mut [0; 2048]))
            .await
            .is_err()
    );
    receiver.shutdown().await.unwrap();
}

#[tokio::test]
async fn oversized_tcp_inform_gets_toobig_while_the_event_queue_is_full() {
    let trap = CommunityMessage::v2c(
        "public",
        NotificationPdu::trap_v2(
            Version::V2c,
            1,
            0,
            &oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1),
            vec![],
        )
        .unwrap()
        .into_raw(),
    )
    .unwrap()
    .encode()
    .unwrap();
    let oversized = oversized_wire(2);
    for client_exchanges in [false, true] {
        for mode in [
            InformAcknowledgementMode::Automatic,
            InformAcknowledgementMode::ApplicationControlled,
        ] {
            let (observer, mut observations) = TransportObserver::channel(8).unwrap();
            let mut receiver = NotificationReceiver::builder()
                .listener(ListenerSource::Tcp(
                    TcpListenerSource::bind("127.0.0.1:0").observer(observer),
                ))
                .client_exchanges(client_exchanges)
                .acknowledgement_mode(mode)
                .queue_capacity(1)
                .max_message_size(wire(1).len())
                .spawn()
                .await
                .unwrap();
            let mut peer = TcpStream::connect(receiver.bound_addresses()[0].local_addr)
                .await
                .unwrap();
            peer.write_all(&trap).await.unwrap();
            tokio::time::timeout(WAIT, async {
                while !matches!(
                    observations.recv().await.unwrap(),
                    ObservationEvent::Disposition {
                        disposition: MessageDisposition::NotificationDelivered,
                        ..
                    }
                ) {}
            })
            .await
            .unwrap();

            peer.write_all(&oversized).await.unwrap();
            assert_tcp_too_big(&mut peer, 2).await;
            assert_eq!(receiver.control().overload_drops(), 0);
            assert_eq!(event(&mut receiver).await.wire_identity.request_id, Some(1));
            receiver.shutdown().await.unwrap();
            assert!(receiver.recv().await.is_none());
        }
    }
}

#[tokio::test]
async fn oversized_tcp_inform_gets_toobig_while_the_only_manual_slot_is_occupied() {
    let ordinary = wire(1);
    let oversized = oversized_wire(2);
    let mut receiver = manual()
        .listener(ListenerSource::tcp("127.0.0.1:0"))
        .queue_capacity(1)
        .max_message_size(ordinary.len())
        .spawn()
        .await
        .unwrap();
    let mut peer = TcpStream::connect(receiver.bound_addresses()[0].local_addr)
        .await
        .unwrap();
    peer.write_all(&ordinary).await.unwrap();
    let first = pending(event(&mut receiver).await);

    peer.write_all(&oversized).await.unwrap();
    assert_tcp_too_big(&mut peer, 2).await;
    assert_eq!(receiver.control().overload_drops(), 0);

    assert!(matches!(first.acknowledge().await, InformAckOutcome::Sent));
    let reply = tcp_reply(&mut peer).await;
    assert_eq!(reply.pdu().standard().unwrap().request_id(), 1);
    peer.write_all(&wire(3)).await.unwrap();
    let next = event(&mut receiver).await;
    assert_eq!(next.wire_identity.request_id, Some(3));
    pending(next).reject();
    receiver.shutdown().await.unwrap();
}

#[tokio::test]
async fn closing_original_tcp_session_never_retargets_pending_ack_to_a_replacement() {
    let mut receiver = manual()
        .listener(ListenerSource::tcp("127.0.0.1:0"))
        .spawn()
        .await
        .unwrap();
    let target = receiver.bound_addresses()[0].local_addr;
    let mut old = TcpStream::connect(target).await.unwrap();
    old.write_all(&wire(1)).await.unwrap();
    let old_event = event(&mut receiver).await;
    let old_session = old_event.receive_info.session_id();
    let old_ack = pending(old_event);
    drop(old);
    tokio::time::timeout(WAIT, async {
        while receiver
            .tcp_sessions()
            .iter()
            .any(|session| Some(session.session_id()) == old_session)
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let mut replacement = TcpStream::connect(target).await.unwrap();
    replacement.write_all(&wire(2)).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(50), receiver.recv())
            .await
            .is_err()
    );
    // The outstanding first Inform still holds capacity until its completion.
    assert!(matches!(
        old_ack.acknowledge().await,
        InformAckOutcome::Failed(error) if error.kind() == ErrorKind::Closed
    ));
    replacement.write_all(&wire(3)).await.unwrap();
    let new_event = event(&mut receiver).await;
    assert_ne!(new_event.receive_info.session_id(), old_session);
    let new_ack = pending(new_event);
    assert!(
        tokio::time::timeout(Duration::from_millis(30), replacement.read(&mut [0; 2048]))
            .await
            .is_err()
    );
    assert!(matches!(
        new_ack.acknowledge().await,
        InformAckOutcome::Sent
    ));
    assert_eq!(
        tcp_reply(&mut replacement)
            .await
            .pdu()
            .standard()
            .unwrap()
            .request_id(),
        3
    );
    receiver.shutdown().await.unwrap();
}

#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
async fn client_inform<T: RequestTransport + 'static>(
    client: Client<T>,
    receiver: &mut async_snmp::RunningNotificationReceiver,
    kind: TransportKind,
    context: &async_snmp::UsmSecurityContext,
) {
    let mut send = tokio::spawn(async move {
        client
            .send_inform(&oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1), 0, vec![])
            .await
    });
    let notification = event(receiver).await;
    assert_eq!(notification.receive_info.transport(), kind);
    let ack = pending(notification);
    assert!(
        tokio::time::timeout(Duration::from_millis(30), &mut send)
            .await
            .is_err()
    );
    context
        .replace_users([async_snmp::UsmUserEntry::new(async_snmp::UsmUser::new(
            "replacement",
        ))])
        .unwrap();
    assert!(matches!(ack.acknowledge().await, InformAckOutcome::Sent));
    send.await.unwrap().unwrap();
}

#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
#[tokio::test]
async fn v3_udp_tcp_manual_ack_retains_captured_credentials_at_every_security_level() {
    for tcp in [false, true] {
        for level in [
            async_snmp::SecurityLevel::NoAuthNoPriv,
            async_snmp::SecurityLevel::AuthNoPriv,
            async_snmp::SecurityLevel::AuthPriv,
        ] {
            let context = async_snmp::UsmSecurityContext::new([async_snmp::UsmUserEntry::new(
                async_snmp::UsmUser::new("user")
                    .auth_priv(
                        async_snmp::AuthProtocol::Sha256,
                        b"authentication-password",
                        async_snmp::PrivProtocol::Aes128,
                        b"privacy-password",
                    )
                    .unwrap(),
            )])
            .unwrap();
            let engine = AuthoritativeEngine::install(b"manual-security-engine".as_slice(), |_| {
                Ok::<_, Infallible>(())
            })
            .unwrap();
            let builder = manual()
                .authoritative_engine(engine)
                .security_context(context.clone())
                .admit_all_notifications();
            let builder = if tcp {
                builder.listener(ListenerSource::tcp("127.0.0.1:0"))
            } else {
                builder.bind("127.0.0.1:0")
            };
            let mut receiver = builder.spawn().await.unwrap();
            let config = async_snmp::UsmConfig::new("user");
            let config = match level {
                async_snmp::SecurityLevel::NoAuthNoPriv => config,
                async_snmp::SecurityLevel::AuthNoPriv => config
                    .auth(async_snmp::AuthProtocol::Sha256, b"authentication-password")
                    .unwrap(),
                async_snmp::SecurityLevel::AuthPriv => config
                    .auth_priv(
                        async_snmp::AuthProtocol::Sha256,
                        b"authentication-password",
                        async_snmp::PrivProtocol::Aes128,
                        b"privacy-password",
                    )
                    .unwrap(),
            };
            let client =
                Client::builder(receiver.bound_addresses()[0].local_addr.to_string(), config)
                    .request_timeout(WAIT)
                    .retry(Retry::none());
            if tcp {
                client_inform(
                    client.connect_tcp().await.unwrap(),
                    &mut receiver,
                    TransportKind::Tcp,
                    &context,
                )
                .await;
            } else {
                client_inform(
                    client.connect().await.unwrap(),
                    &mut receiver,
                    TransportKind::Udp,
                    &context,
                )
                .await;
            }
            receiver.shutdown().await.unwrap();
        }
    }
}

#[cfg(feature = "agent")]
#[tokio::test]
async fn attached_manual_role_shutdown_invalidates_tokens_without_stopping_commands_or_clients() {
    let mut service = async_snmp::Agent::builder()
        .bind("127.0.0.1:0")
        .community("public")
        .allow_all_access()
        .client_exchanges(true)
        .notifications(manual().community("public"))
        .spawn()
        .await
        .unwrap();
    let mut notifications = service.take_notifications().unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    peer.send_to(&wire(1), service.bound_addresses()[0].local_addr)
        .await
        .unwrap();
    let ack = pending(
        tokio::time::timeout(WAIT, notifications.recv())
            .await
            .unwrap()
            .unwrap(),
    );
    let control = notifications.control();
    control.request_shutdown();
    assert!(
        tokio::time::timeout(WAIT, notifications.recv())
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(control.status(), async_snmp::NotificationStatus::Stopped);
    tokio::time::timeout(WAIT, control.wait_closed())
        .await
        .unwrap();
    assert!(matches!(
        ack.acknowledge().await,
        InformAckOutcome::Failed(_)
    ));
    let query = Client::builder(
        service.bound_addresses()[0].local_addr.to_string(),
        Auth::v2c("public"),
    )
    .request_timeout(WAIT)
    .retry(Retry::none())
    .connect()
    .await
    .unwrap();
    query
        .get(&oid!(1, 3, 6, 1, 6, 3, 10, 2, 1, 1, 0))
        .await
        .unwrap();
    let device = async_snmp::Agent::builder()
        .bind("127.0.0.1:0")
        .community("public")
        .allow_all_access()
        .spawn()
        .await
        .unwrap();
    let endpoint = service
        .udp_endpoint(service.bound_addresses()[0].endpoint_id)
        .unwrap();
    let poller = async_snmp::ClientBuilder::new(Auth::v2c("public"))
        .request_timeout(WAIT)
        .retry(Retry::none())
        .build_with_transport(
            endpoint
                .handle(device.bound_addresses()[0].local_addr)
                .unwrap(),
        )
        .unwrap();
    poller
        .get(&oid!(1, 3, 6, 1, 6, 3, 10, 2, 1, 1, 0))
        .await
        .unwrap();
    device.shutdown().await.unwrap();
    service.shutdown().await.unwrap();
}

#[tokio::test]
async fn manual_configuration_is_validated_before_binding() {
    for builder in [
        manual().max_pending_informs(0),
        manual().pending_inform_timeout(Duration::ZERO),
        manual().pending_inform_timeout(Duration::MAX),
    ] {
        assert!(matches!(
            *builder.bind("invalid").prepare().await.err().unwrap(),
            async_snmp::Error::Config(_)
        ));
    }
}

#[cfg(feature = "crypto-rustcrypto")]
#[tokio::test]
async fn manual_des_receives_before_sender_state_is_installed_and_encodes_on_completion() {
    let engine = AuthoritativeEngine::install(b"manual-des-receiver".as_slice(), |_| {
        Ok::<_, Infallible>(())
    })
    .unwrap();
    let mut receiver = manual()
        .bind("127.0.0.1:0")
        .authoritative_engine(engine)
        .usm_user("user", |user| {
            user.auth_priv(
                async_snmp::AuthProtocol::Sha256,
                b"authentication-password",
                async_snmp::PrivProtocol::Des,
                b"privacy-password",
            )
        })
        .unwrap()
        .admit_all_notifications()
        .spawn()
        .await
        .unwrap();
    let sender = async_snmp::LocalEngine::new(
        AuthoritativeEngine::install(b"manual-des-sender".as_slice(), |_| Ok::<_, Infallible>(()))
            .unwrap(),
    )
    .unwrap();
    sender
        .set_des_salt_state(Some(
            async_snmp::DesSaltState::install(|_| Ok::<_, Infallible>(())).unwrap(),
        ))
        .unwrap();
    let config = async_snmp::UsmConfig::new("user")
        .auth_priv(
            async_snmp::AuthProtocol::Sha256,
            b"authentication-password",
            async_snmp::PrivProtocol::Des,
            b"privacy-password",
        )
        .unwrap();
    let client = Client::builder(receiver.bound_addresses()[0].local_addr.to_string(), config)
        .local_engine(sender)
        .retry(Retry::none())
        .request_timeout(WAIT)
        .connect()
        .await
        .unwrap();
    let mut send = tokio::spawn(async move {
        client
            .send_inform(&oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1), 0, vec![])
            .await
    });
    let token = pending(event(&mut receiver).await);
    assert!(
        tokio::time::timeout(Duration::from_millis(30), &mut send)
            .await
            .is_err()
    );
    receiver
        .local_engine()
        .set_des_salt_state(Some(
            async_snmp::DesSaltState::install(|_| Ok::<_, Infallible>(())).unwrap(),
        ))
        .unwrap();
    assert!(matches!(token.acknowledge().await, InformAckOutcome::Sent));
    send.await.unwrap().unwrap();
    receiver.shutdown().await.unwrap();
}
