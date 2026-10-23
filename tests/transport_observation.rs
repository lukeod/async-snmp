//! Observation counts physical I/O independently of application provenance.
#![cfg(feature = "agent")]

use async_snmp::{
    Agent, Auth, AuthoritativeEngine, Client, ClientBuilder, ListenerSource, MessageDisposition,
    NotificationReceiver, NotificationSinkId, NotificationTarget, ObservationEvent, Retry,
    TcpListenerSource, TcpTransport, TransportObserver, UdpEndpoint, oid,
};
use std::{convert::Infallible, time::Duration};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, UdpSocket};
const WAIT: Duration = Duration::from_secs(3);
fn query() -> async_snmp::Oid {
    oid!(1, 3, 6, 1, 6, 3, 10, 2, 1, 1, 0)
}
fn cold() -> async_snmp::Oid {
    oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1)
}

#[tokio::test]
async fn full_or_dropped_observer_does_not_backpressure_shared_udp() {
    assert!(TransportObserver::channel(0).is_err());
    assert!(TransportObserver::channel(65_537).is_err());
    let (observer, mut events) = TransportObserver::channel(1).unwrap();
    let agent = Agent::builder()
        .community("public")
        .allow_all_access()
        .listener(ListenerSource::Udp(
            UdpEndpoint::builder()
                .bind("127.0.0.1:0")
                .observer(observer.clone()),
        ))
        .spawn()
        .await
        .unwrap();
    let client = Client::builder(agent.bound_addresses()[0].local_addr, Auth::v2c("public"))
        .retry(Retry::none())
        .request_timeout(WAIT)
        .connect()
        .await
        .unwrap();
    for _ in 0..4 {
        client.get(&query()).await.unwrap();
    }
    let stats = observer.stats();
    assert_eq!(stats.received_messages, 4);
    assert_eq!(stats.sent_messages, 4);
    assert_eq!(stats.socket_read_bytes, stats.received_message_bytes);
    assert_eq!(stats.socket_written_bytes, stats.sent_message_bytes);
    assert!(stats.dropped_events > 0);
    assert!(matches!(
        events.try_recv().unwrap(),
        ObservationEvent::Received(_)
    ));
    assert!(events.try_recv().is_err());
    drop(events);
    client.get(&query()).await.unwrap();
    assert_eq!(observer.stats().sent_messages, 5);
    assert!(observer.stats().dropped_events > stats.dropped_events);
    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn shared_udp_observes_commands_sink_sends_and_inform_acknowledgements_once() {
    let (observer, mut events) = TransportObserver::channel(64).unwrap();
    let mut remote = NotificationReceiver::spawn("127.0.0.1:0").await.unwrap();
    let mut agent = Agent::builder()
        .community("public")
        .allow_all_access()
        .listener(ListenerSource::Udp(
            UdpEndpoint::builder()
                .bind("0.0.0.0:0")
                .max_message_size(4096)
                .observer(observer.clone()),
        ))
        .notifications(NotificationReceiver::builder())
        .notification_sink(
            NotificationSinkId::new("remote").unwrap(),
            NotificationTarget::shared_udp(0, remote.bound_addresses()[0].local_addr.to_string()),
            Auth::v2c("public"),
        )
        .inform_retry(Retry::none())
        .inform_timeout(WAIT)
        .spawn()
        .await
        .unwrap();
    let bound = agent.bound_addresses()[0];
    let mut notifications = agent.take_notifications().unwrap();
    let address = format!("127.0.0.2:{}", bound.local_addr.port());
    let client = Client::builder(address, Auth::v2c("public"))
        .retry(Retry::none())
        .request_timeout(WAIT)
        .connect()
        .await
        .unwrap();
    let q = query();
    let trap = cold();
    let (get, incoming, inform, sent) = tokio::join!(
        client.get(&q),
        client.send_inform(&trap, 1, vec![]),
        agent.send_inform(&trap, 2, vec![]),
        agent.send_trap(&trap, 3, vec![])
    );
    get.unwrap();
    incoming.unwrap();
    assert!(inform.all_succeeded());
    assert!(sent.all_succeeded());
    let notification = tokio::time::timeout(WAIT, notifications.recv())
        .await
        .unwrap()
        .unwrap();
    for _ in 0..2 {
        tokio::time::timeout(WAIT, remote.recv())
            .await
            .unwrap()
            .unwrap();
    }
    let stats = observer.stats();
    assert_eq!((stats.received_messages, stats.sent_messages), (3, 4));
    assert_eq!(stats.socket_read_bytes, stats.received_message_bytes);
    assert_eq!(stats.socket_written_bytes, stats.sent_message_bytes);
    let mut received = Vec::new();
    let mut sent = Vec::new();
    let mut delivered = 0;
    while let Ok(event) = events.try_recv() {
        match event {
            ObservationEvent::Received(info) => {
                assert_eq!(info.endpoint_id(), bound.endpoint_id);
                received.push(info);
            }
            ObservationEvent::Sent(info) => {
                assert_eq!(info.endpoint_id, bound.endpoint_id);
                sent.push(info);
            }
            ObservationEvent::Disposition {
                info,
                disposition: MessageDisposition::NotificationDelivered,
            } => {
                assert_eq!(info, notification.receive_info);
                delivered += 1;
            }
            _ => {}
        }
    }
    assert_eq!(received.len(), 3);
    assert_eq!(sent.len(), 4);
    assert_eq!(delivered, 1);
    assert_eq!(
        received
            .iter()
            .filter(|&&info| info == notification.receive_info)
            .count(),
        1
    );
    assert!(
        received
            .iter()
            .any(|info| info.datagram_destination() == Some("127.0.0.2".parse().unwrap()))
    );
    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn accepted_and_outbound_tcp_sessions_keep_distinct_observation_identity() {
    let (observer, mut events) = TransportObserver::channel(32).unwrap();
    let agent = Agent::builder()
        .community("public")
        .allow_all_access()
        .listener(ListenerSource::Tcp(
            TcpListenerSource::bind("127.0.0.1:0").observer(observer.clone()),
        ))
        .spawn()
        .await
        .unwrap();
    let bound = agent.bound_addresses()[0];
    let running = TcpTransport::builder()
        .target(bound.local_addr)
        .observer(observer.clone())
        .spawn()
        .await
        .unwrap();
    let client = ClientBuilder::new(Auth::v2c("public"))
        .retry(Retry::none())
        .request_timeout(WAIT)
        .build_with_transport(running.transport())
        .unwrap();
    let response = client.get(&query()).await.unwrap();
    let stats = observer.stats();
    assert_eq!((stats.received_messages, stats.sent_messages), (2, 2));
    assert_eq!(stats.socket_read_bytes, stats.received_message_bytes);
    assert_eq!(stats.socket_written_bytes, stats.sent_message_bytes);
    let mut inputs = Vec::new();
    while let Ok(event) = events.try_recv() {
        if let ObservationEvent::Received(info) = event {
            inputs.push(info);
        }
    }
    assert_eq!(inputs.len(), 2);
    assert_eq!(
        inputs
            .iter()
            .filter(|&&info| info == response.metadata.received_messages[0].info)
            .count(),
        1
    );
    assert!(
        inputs
            .iter()
            .any(|info| info.endpoint_id() == bound.endpoint_id)
    );
    assert_ne!(inputs[0].session_id(), inputs[1].session_id());
    running.shutdown().await.unwrap();
    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn incomplete_and_oversized_tcp_input_counts_only_successful_socket_reads() {
    for bytes in [vec![0x30, 3, 1], vec![0x30, 0x82, 2, 0]] {
        let (observer, mut events) = TransportObserver::channel(8).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (prepared, accepted) = tokio::join!(
            TcpTransport::builder()
                .target(listener.local_addr().unwrap())
                .max_message_size(484)
                .observer(observer.clone())
                .prepare(),
            listener.accept()
        );
        let running = prepared.unwrap().spawn();
        let mut peer = accepted.unwrap().0;
        peer.write_all(&bytes).await.unwrap();
        peer.shutdown().await.unwrap();
        tokio::time::timeout(WAIT, running.control().wait_closed())
            .await
            .unwrap();
        assert!(running.join().await.is_err());
        assert_eq!(observer.stats().socket_read_bytes, bytes.len() as u64);
        assert_eq!(observer.stats().received_messages, 0);
        assert!(events.try_recv().is_err());
        drop(observer);
        assert!(
            tokio::time::timeout(WAIT, events.recv())
                .await
                .unwrap()
                .is_none()
        );
    }
}

#[tokio::test]
async fn shared_discovery_provenance_does_not_duplicate_physical_receipts() {
    let (observer, mut events) = TransportObserver::channel(32).unwrap();
    let engine =
        AuthoritativeEngine::install(b"observed-engine".to_vec(), |_| Ok::<_, Infallible>(()))
            .unwrap();
    let agent = Agent::builder()
        .bind("127.0.0.1:0")
        .authoritative_engine(engine)
        .allow_all_access()
        .usm_user("user", Ok)
        .unwrap()
        .spawn()
        .await
        .unwrap();
    let endpoint = UdpEndpoint::builder()
        .bind("127.0.0.1:0")
        .observer(observer.clone())
        .spawn()
        .await
        .unwrap();
    let client = Client::builder(agent.bound_addresses()[0].local_addr, Auth::usm("user"))
        .retry(Retry::none())
        .request_timeout(WAIT)
        .build_with(&endpoint)
        .await
        .unwrap();
    let q = query();
    let (first, second) = tokio::join!(client.get(&q), client.get(&q));
    let first = first.unwrap();
    let second = second.unwrap();
    let a = &first.metadata.received_messages;
    let b = &second.metadata.received_messages;
    assert_eq!((a.len(), b.len()), (2, 2));
    assert_eq!(a[0].info.reception_id(), b[0].info.reception_id());
    assert_eq!(observer.stats().received_messages, 3);
    let mut receptions = Vec::new();
    while let Ok(event) = events.try_recv() {
        if let ObservationEvent::Received(info) = event {
            receptions.push(info.reception_id());
        }
    }
    assert_eq!(
        receptions
            .iter()
            .filter(|&&id| id == a[0].info.reception_id())
            .count(),
        1
    );
    endpoint.shutdown().await.unwrap();
    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn rejected_and_disabled_notification_inputs_remain_observable() {
    let (observer, mut events) = TransportObserver::channel(32).unwrap();
    let mut receiver = NotificationReceiver::builder()
        .listener(ListenerSource::Udp(
            UdpEndpoint::builder()
                .bind("127.0.0.1:0")
                .observer(observer.clone()),
        ))
        .acceptance_policy(|_| async_snmp::NotificationAcceptance::Reject)
        .spawn()
        .await
        .unwrap();
    let address = receiver.bound_addresses()[0].local_addr;
    let client = Client::builder(address, Auth::v2c("public"))
        .connect()
        .await
        .unwrap();
    client.send_trap(&cold(), 1, vec![]).await.unwrap();
    let mut rejected = None;
    while rejected.is_none() {
        if let ObservationEvent::Disposition {
            info,
            disposition: MessageDisposition::Rejected,
        } = tokio::time::timeout(WAIT, events.recv())
            .await
            .unwrap()
            .unwrap()
        {
            rejected = Some(info);
        }
    }
    receiver.close();
    client.send_trap(&cold(), 2, vec![]).await.unwrap();
    let mut disabled = None;
    while disabled.is_none() {
        if let ObservationEvent::Disposition {
            info,
            disposition: MessageDisposition::Disabled,
        } = tokio::time::timeout(WAIT, events.recv())
            .await
            .unwrap()
            .unwrap()
        {
            disabled = Some(info);
        }
    }
    assert_ne!(
        rejected.unwrap().reception_id(),
        disabled.unwrap().reception_id()
    );
    assert_eq!(observer.stats().received_messages, 2);
    assert_eq!(observer.stats().sent_messages, 0);
    receiver.shutdown().await.unwrap();
}

#[tokio::test]
async fn malformed_udp_input_is_counted_before_correlation() {
    let (observer, mut events) = TransportObserver::channel(8).unwrap();
    let endpoint = UdpEndpoint::builder()
        .bind("127.0.0.1:0")
        .observer(observer.clone())
        .spawn()
        .await
        .unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket
        .send_to(b"malformed", endpoint.local_addr())
        .await
        .unwrap();
    let ObservationEvent::Received(info) = tokio::time::timeout(WAIT, events.recv())
        .await
        .unwrap()
        .unwrap()
    else {
        panic!("receipt first")
    };
    assert_eq!(info.received_len(), 9);
    assert!(
        matches!(tokio::time::timeout(WAIT, events.recv()).await.unwrap().unwrap(), ObservationEvent::Disposition { info: same, disposition: MessageDisposition::Malformed } if same == info)
    );
    assert_eq!(observer.stats().socket_read_bytes, 9);
    assert_eq!(observer.stats().received_message_bytes, 9);
    endpoint.shutdown().await.unwrap();
}

#[tokio::test]
async fn delivery_overload_is_a_disposition_without_extra_message_accounting() {
    let (observer, mut events) = TransportObserver::channel(32).unwrap();
    let mut receiver = NotificationReceiver::builder()
        .queue_capacity(1)
        .listener(ListenerSource::Udp(
            UdpEndpoint::builder()
                .bind("127.0.0.1:0")
                .observer(observer.clone()),
        ))
        .spawn()
        .await
        .unwrap();
    let client = Client::builder(
        receiver.bound_addresses()[0].local_addr,
        Auth::v2c("public"),
    )
    .connect()
    .await
    .unwrap();
    client.send_trap(&cold(), 1, vec![]).await.unwrap();
    loop {
        if matches!(
            tokio::time::timeout(WAIT, events.recv())
                .await
                .unwrap()
                .unwrap(),
            ObservationEvent::Disposition {
                disposition: MessageDisposition::NotificationDelivered,
                ..
            }
        ) {
            break;
        }
    }
    client.send_trap(&cold(), 2, vec![]).await.unwrap();
    let overloaded = loop {
        if let ObservationEvent::Disposition {
            info,
            disposition: MessageDisposition::Overloaded,
        } = tokio::time::timeout(WAIT, events.recv())
            .await
            .unwrap()
            .unwrap()
        {
            break info;
        }
    };
    assert_eq!(observer.stats().received_messages, 2);
    assert_eq!(
        observer.stats().socket_read_bytes,
        observer.stats().received_message_bytes
    );
    assert_eq!(observer.stats().sent_messages, 0);
    let delivered = receiver.recv().await.unwrap();
    assert_ne!(
        delivered.receive_info.reception_id(),
        overloaded.reception_id()
    );
    receiver.shutdown().await.unwrap();
}
