use super::tests::{build_v2c_inform, build_v2c_trap, build_v2c_trap_with_request_id};
use super::*;
use crate::{MessageDisposition, ObservationEvent, ObservationReceiver, TransportObserver};
use std::sync::atomic::AtomicUsize;

static_assertions::assert_not_impl_any!(NotificationReceiver: Clone);
static_assertions::assert_not_impl_any!(RunningNotificationReceiver: std::ops::DerefMut);
static_assertions::assert_impl_all!(NotificationReceiver: Send);
static_assertions::assert_impl_all!(NotificationRunner: Send);

async fn await_ack(socket: &UdpSocket) {
    let mut bytes = [0; 2048];
    tokio::time::timeout(Duration::from_secs(1), socket.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
}
async fn no_ack(socket: &UdpSocket) {
    let mut bytes = [0; 2048];
    assert!(
        tokio::time::timeout(Duration::from_millis(30), socket.recv_from(&mut bytes))
            .await
            .is_err()
    );
}
async fn processing_started(receiver: &NotificationReceiver) {
    tokio::time::timeout(Duration::from_secs(1), async {
        while receiver
            .inner
            .response_sends_started
            .load(Ordering::Relaxed)
            == 0
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[cfg(feature = "agent")]
#[tokio::test]
async fn attached_shutdown_drains_automatic_ack_and_preserves_terminal_status() {
    use std::sync::atomic::AtomicBool;

    let fail_accept = Arc::new(AtomicBool::new(false));
    let failure = fail_accept.clone();
    let tcp = crate::TcpListenerSource::bind("127.0.0.1:0").test_accept_hook(move || {
        if failure.load(Ordering::Acquire) {
            return Err(std::io::ErrorKind::InvalidInput.into());
        }
        Ok(())
    });
    let mut agent = crate::Agent::builder()
        .listener(crate::ListenerSource::udp("127.0.0.1:0"))
        .listener(crate::ListenerSource::Tcp(tcp))
        .notifications(NotificationReceiver::builder())
        .spawn()
        .await
        .unwrap();
    let mut receiver = agent.take_notifications().unwrap();
    let control = receiver.control();
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    *receiver.inner.response_send_gate.lock().unwrap() = Some(gate.clone());
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sender
        .send_to(&build_v2c_inform(b"public"), receiver.local_addr())
        .await
        .unwrap();
    processing_started(&receiver).await;

    control.request_shutdown();
    assert_eq!(control.status(), NotificationStatus::Running);
    gate.add_permits(1);
    await_ack(&sender).await;
    let event = receiver.recv().await.unwrap();
    assert!(matches!(
        event.inform_ack,
        NotificationAcknowledgement::Completed(InformAckOutcome::Sent)
    ));
    let wait = Duration::from_secs(1);
    assert!(
        tokio::time::timeout(wait, receiver.recv())
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(control.status(), NotificationStatus::Stopped);

    fail_accept.store(true, Ordering::Release);
    let _ = tokio::net::TcpStream::connect(agent.bound_addresses()[1].local_addr).await;
    let error = tokio::time::timeout(wait, agent.join())
        .await
        .unwrap()
        .unwrap_err();
    assert!(matches!(*error, Error::Listener { .. }));
    assert_eq!(control.status(), NotificationStatus::Stopped);
}

#[cfg(feature = "agent")]
#[tokio::test]
async fn attached_shutdown_before_start_completes_when_runner_is_driven_or_dropped() {
    for drive in [true, false] {
        let (agent, runner, receiver) = crate::Agent::builder()
            .bind("127.0.0.1:0")
            .notifications(NotificationReceiver::builder())
            .prepare()
            .await
            .unwrap()
            .into_parts();
        let mut receiver = receiver.unwrap();
        let control = receiver.control();
        control.request_shutdown();
        assert_eq!(control.status(), NotificationStatus::Prepared);

        let wait = Duration::from_secs(1);
        if drive {
            let task = tokio::spawn(runner.run());
            assert!(
                tokio::time::timeout(wait, receiver.recv())
                    .await
                    .unwrap()
                    .is_none()
            );
            assert_eq!(control.status(), NotificationStatus::Stopped);
            assert_eq!(agent.control().status(), crate::AgentStatus::Running);
            agent.control().request_shutdown();
            task.await.unwrap().unwrap();
        } else {
            drop(runner);
            assert!(receiver.recv().await.is_none());
            assert_eq!(control.status(), NotificationStatus::Interrupted);
        }
        tokio::time::timeout(wait, control.wait_closed())
            .await
            .unwrap();
    }
}

async fn next_disposition(events: &mut ObservationReceiver) -> MessageDisposition {
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if let ObservationEvent::Disposition { disposition, .. } = events.recv().await.unwrap()
            {
                return disposition;
            }
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn unpolled_consumer_acknowledges_and_full_queue_blocks_the_next_ack() {
    let accepted = Arc::new(AtomicUsize::new(0));
    let calls = accepted.clone();
    let mut receiver = NotificationReceiver::builder()
        .bind("127.0.0.1:0")
        .queue_capacity(1)
        .admission_policy(move |_| {
            calls.fetch_add(1, Ordering::Relaxed);
            NotificationAdmissionDecision::Admit
        })
        .spawn()
        .await
        .unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sender
        .send_to(&build_v2c_inform(b"public"), receiver.local_addr())
        .await
        .unwrap();
    await_ack(&sender).await;
    assert_eq!(accepted.load(Ordering::Relaxed), 1);
    sender
        .send_to(&build_v2c_inform(b"public"), receiver.local_addr())
        .await
        .unwrap();
    no_ack(&sender).await;
    assert_eq!(accepted.load(Ordering::Relaxed), 2);
    assert_eq!(receiver.control().overload_drops(), 1);
    let event = receiver.recv().await.unwrap();
    assert!(matches!(
        event.inform_ack,
        crate::NotificationAcknowledgement::Completed(InformAckOutcome::Sent)
    ));
    receiver.close();
    assert!(receiver.recv().await.is_none());
    receiver.shutdown().await.unwrap();
}

#[tokio::test]
async fn close_preserves_admitted_permit_through_acknowledgement_and_publication() {
    let mut receiver = NotificationReceiver::spawn("127.0.0.1:0").await.unwrap();
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    *receiver.inner.response_send_gate.lock().unwrap() = Some(gate.clone());
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sender
        .send_to(&build_v2c_inform(b"public"), receiver.local_addr())
        .await
        .unwrap();
    processing_started(&receiver).await;
    receiver.close();
    gate.add_permits(1);
    await_ack(&sender).await;
    assert!(matches!(
        receiver.recv().await.unwrap().inform_ack,
        crate::NotificationAcknowledgement::Completed(InformAckOutcome::Sent)
    ));
    assert!(receiver.recv().await.is_none());
    sender
        .send_to(&build_v2c_inform(b"public"), receiver.local_addr())
        .await
        .unwrap();
    no_ack(&sender).await;
    assert_eq!(receiver.control().overload_drops(), 0);
    assert_eq!(receiver.control().status(), NotificationStatus::Running);
    receiver.shutdown().await.unwrap();
}

#[tokio::test]
async fn cancellation_of_recv_leaves_admission_and_event_available() {
    let mut receiver = NotificationReceiver::spawn("127.0.0.1:0").await.unwrap();
    let mut pending = Box::pin(receiver.recv());
    assert!(matches!(
        futures::poll!(&mut pending),
        std::task::Poll::Pending
    ));
    drop(pending);
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sender
        .send_to(
            &build_v2c_trap_with_request_id(b"public", 9),
            receiver.local_addr(),
        )
        .await
        .unwrap();
    let event = receiver.recv().await.unwrap();
    assert_eq!(event.wire_identity.request_id, Some(9));
}

#[tokio::test]
async fn consumer_drop_disables_acceptance_without_stopping_retained_control() {
    let (receiver, runner) = NotificationReceiver::builder()
        .bind("127.0.0.1:0")
        .prepare()
        .await
        .unwrap()
        .into_parts();
    let address = receiver.local_addr();
    let control = receiver.control();
    let task = tokio::spawn(runner.run());
    drop(receiver);
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sender
        .send_to(&build_v2c_inform(b"public"), address)
        .await
        .unwrap();
    no_ack(&sender).await;
    assert_eq!(control.status(), NotificationStatus::Running);
    assert!(!control.is_shutdown());
    assert_eq!(control.overload_drops(), 0);
    control.shutdown().await;
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn graceful_shutdown_drains_admitted_ack_without_waiting_for_consumption() {
    let (mut receiver, runner) = NotificationReceiver::builder()
        .bind("127.0.0.1:0")
        .response_send_timeout(Duration::from_millis(40))
        .prepare()
        .await
        .unwrap()
        .into_parts();
    *receiver.inner.response_send_gate.lock().unwrap() =
        Some(Arc::new(tokio::sync::Semaphore::new(0)));
    let task = tokio::spawn(runner.run());
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sender
        .send_to(&build_v2c_inform(b"public"), receiver.local_addr())
        .await
        .unwrap();
    processing_started(&receiver).await;
    receiver.control().request_shutdown();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(matches!(
        receiver.recv().await.unwrap().inform_ack,
        crate::NotificationAcknowledgement::Completed(InformAckOutcome::Failed(_))
    ));
    assert!(receiver.recv().await.is_none());
}

#[tokio::test]
async fn running_shutdown_releases_udp_port_with_queued_inform() {
    let mut receiver = NotificationReceiver::spawn("127.0.0.1:0").await.unwrap();
    let local_addr = receiver.local_addr();
    let endpoint = receiver
        .udp_endpoint(receiver.bound_addresses()[0].endpoint_id)
        .unwrap();
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    *receiver.inner.response_send_gate.lock().unwrap() = Some(gate.clone());
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sender
        .send_to(&build_v2c_inform(b"public"), local_addr)
        .await
        .unwrap();
    processing_started(&receiver).await;

    receiver.control().request_shutdown();
    gate.add_permits(1);
    tokio::time::timeout(Duration::from_secs(1), receiver.shutdown())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(endpoint.control().status(), crate::UdpStatus::Stopped);
    endpoint.control().join().await.unwrap();
    let _rebound = UdpSocket::bind(local_addr).await.unwrap();
    await_ack(&sender).await;
    assert_eq!(receiver.local_addr(), local_addr);
    assert!(matches!(
        receiver.recv().await.unwrap().inform_ack,
        crate::NotificationAcknowledgement::Completed(InformAckOutcome::Sent)
    ));
    assert!(receiver.recv().await.is_none());
}

#[tokio::test]
async fn protocol_work_limit_drops_without_blocking_reader() {
    let mut receiver = NotificationReceiver::builder()
        .bind("127.0.0.1:0")
        .max_processing(1)
        .queue_capacity(2)
        .spawn()
        .await
        .unwrap();
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    *receiver.inner.response_send_gate.lock().unwrap() = Some(gate.clone());
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sender
        .send_to(&build_v2c_inform(b"public"), receiver.local_addr())
        .await
        .unwrap();
    processing_started(&receiver).await;
    sender
        .send_to(&build_v2c_trap(b"public"), receiver.local_addr())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while receiver.control().overload_drops() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    gate.add_permits(1);
    await_ack(&sender).await;
    assert!(matches!(
        receiver.recv().await.unwrap().inform_ack,
        crate::NotificationAcknowledgement::Completed(_)
    ));
    receiver.close();
    assert!(receiver.recv().await.is_none());
}

#[cfg(feature = "agent")]
#[tokio::test]
async fn shared_udp_overload_uses_active_role_attribution() {
    let (observer, mut events) = TransportObserver::channel(16).unwrap();
    let mut agent = crate::Agent::builder()
        .listener(crate::ListenerSource::Udp(
            crate::UdpEndpoint::builder()
                .bind("127.0.0.1:0")
                .observer(observer),
        ))
        .notifications(
            NotificationReceiver::builder()
                .max_processing(1)
                .response_send_timeout(Duration::from_secs(5)),
        )
        .spawn()
        .await
        .unwrap();
    let mut receiver = agent.take_notifications().unwrap();
    let agent_control = agent.control();
    let notification_control = receiver.control();
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    *receiver.inner.response_send_gate.lock().unwrap() = Some(gate.clone());
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = receiver.local_addr();
    sender
        .send_to(&build_v2c_inform(b"public"), target)
        .await
        .unwrap();
    processing_started(&receiver).await;

    let trap = build_v2c_trap(b"public");
    sender.send_to(&trap, target).await.unwrap();
    assert_eq!(
        next_disposition(&mut events).await,
        MessageDisposition::Overloaded
    );
    assert_eq!(agent_control.overload_drops(), 1);
    assert_eq!(notification_control.overload_drops(), 0);

    agent_control.close_commands();
    sender.send_to(&trap, target).await.unwrap();
    assert_eq!(
        next_disposition(&mut events).await,
        MessageDisposition::Overloaded
    );
    assert_eq!(agent_control.overload_drops(), 1);
    assert_eq!(notification_control.overload_drops(), 1);

    gate.add_permits(1);
    await_ack(&sender).await;
    assert_eq!(
        next_disposition(&mut events).await,
        MessageDisposition::NotificationDelivered
    );
    receiver.close();
    sender.send_to(&trap, target).await.unwrap();
    assert_eq!(
        next_disposition(&mut events).await,
        MessageDisposition::Disabled
    );
    assert_eq!(agent_control.overload_drops(), 1);
    assert_eq!(notification_control.overload_drops(), 1);
    agent.shutdown().await.unwrap();
}

#[tokio::test]
async fn tcp_notification_admission_overload_is_counted_once() {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;

    for client_exchanges in [false, true] {
        let (observer, mut events) = TransportObserver::channel(16).unwrap();
        let mut receiver = NotificationReceiver::builder()
            .listener(crate::ListenerSource::Tcp(
                crate::TcpListenerSource::bind("127.0.0.1:0").observer(observer),
            ))
            .queue_capacity(1)
            .client_exchanges(client_exchanges)
            .overload_timeout(Duration::from_millis(20))
            .spawn()
            .await
            .unwrap();
        let mut peer = TcpStream::connect(receiver.bound_addresses()[0].local_addr)
            .await
            .unwrap();
        let trap = build_v2c_trap(b"public");
        peer.write_all(&trap).await.unwrap();
        assert_eq!(
            next_disposition(&mut events).await,
            MessageDisposition::NotificationDelivered
        );
        let session = receiver.tcp_sessions()[0].control();

        peer.write_all(&trap).await.unwrap();
        assert_eq!(
            next_disposition(&mut events).await,
            MessageDisposition::Overloaded
        );
        assert_eq!(receiver.control().overload_drops(), 1);
        let error = tokio::time::timeout(Duration::from_secs(1), session.join())
            .await
            .unwrap()
            .unwrap_err();
        let reason = if client_exchanges {
            "TCP notification delivery overload"
        } else {
            "admission overload deadline"
        };
        assert!(error.to_string().contains(reason), "{error}");
        assert!(receiver.recv().await.is_some());
        receiver.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn slow_ack_does_not_hold_up_other_notifications() {
    let mut receiver = NotificationReceiver::builder()
        .bind("127.0.0.1:0")
        .spawn()
        .await
        .unwrap();
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    *receiver.inner.response_send_gate.lock().unwrap() = Some(gate.clone());
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sender
        .send_to(&build_v2c_inform(b"public"), receiver.local_addr())
        .await
        .unwrap();
    processing_started(&receiver).await;
    sender
        .send_to(&build_v2c_trap(b"public"), receiver.local_addr())
        .await
        .unwrap();
    assert!(matches!(
        receiver.recv().await.unwrap().notification,
        Notification::TrapV2c { .. }
    ));
    gate.add_permits(1);
    assert!(matches!(
        receiver.recv().await.unwrap().inform_ack,
        crate::NotificationAcknowledgement::Completed(InformAckOutcome::Sent)
    ));
}

#[tokio::test]
async fn unpolled_drop_and_task_abort_close_event_stream() {
    for future in [false, true] {
        let (mut receiver, runner) = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .prepare()
            .await
            .unwrap()
            .into_parts();
        if future {
            drop(runner.run());
        } else {
            drop(runner);
        }
        receiver.control().wait_closed().await;
        assert_eq!(receiver.control().status(), NotificationStatus::Interrupted);
        assert!(receiver.recv().await.is_none());
    }
    let mut receiver = NotificationReceiver::spawn("127.0.0.1:0").await.unwrap();
    receiver.task().unwrap().abort();
    receiver.control().wait_closed().await;
    assert_eq!(receiver.control().status(), NotificationStatus::Interrupted);
    assert!(receiver.recv().await.is_none());
    assert!(receiver.join().await.is_err());
    assert_eq!(receiver.control().status(), NotificationStatus::Interrupted);
    assert!(receiver.task().is_none());
}

#[tokio::test]
async fn shutdown_before_start_needs_runner_drop_and_final_handle_drop_cancels_driver() {
    let (mut receiver, runner) = NotificationReceiver::builder()
        .bind("127.0.0.1:0")
        .prepare()
        .await
        .unwrap()
        .into_parts();
    receiver.control().request_shutdown();
    assert!(
        tokio::time::timeout(Duration::from_millis(10), receiver.control().wait_closed())
            .await
            .is_err()
    );
    drop(runner);
    assert!(receiver.recv().await.is_none());
    let (receiver, runner) = NotificationReceiver::builder()
        .bind("127.0.0.1:0")
        .prepare()
        .await
        .unwrap()
        .into_parts();
    let task = tokio::spawn(runner.run());
    drop(receiver);
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn transient_receive_recovers_and_fatal_receive_closes_after_queued_events() {
    let mut receiver = NotificationReceiver::spawn("127.0.0.1:0").await.unwrap();
    receiver.inner.receive_errors.lock().unwrap().extend([
        std::io::ErrorKind::InvalidData.into(),
        std::io::ErrorKind::ConnectionRefused.into(),
    ]);
    receiver.inner.receive_error_ready.notify_one();
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sender
        .send_to(&build_v2c_inform(b"public"), receiver.local_addr())
        .await
        .unwrap();
    await_ack(&sender).await;
    receiver
        .inner
        .receive_errors
        .lock()
        .unwrap()
        .push_back(std::io::ErrorKind::InvalidInput.into());
    receiver.inner.receive_error_ready.notify_one();
    assert!(receiver.join().await.is_err());
    assert!(matches!(
        receiver.control().status(),
        NotificationStatus::Failed(_)
    ));
    assert!(matches!(
        receiver.recv().await.unwrap().inform_ack,
        crate::NotificationAcknowledgement::Completed(InformAckOutcome::Sent)
    ));
    assert!(receiver.recv().await.is_none());
}

#[tokio::test]
async fn supplied_socket_preserves_options_and_rejects_conflicts_and_unbound_sockets() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.set_ttl(29).unwrap();
    let local = socket.local_addr().unwrap();
    let (receiver, runner) = NotificationReceiver::builder()
        .from_socket(socket)
        .prepare()
        .await
        .unwrap()
        .into_parts();
    assert_eq!(receiver.local_addr(), local);
    assert_eq!(
        receiver
            .inner
            .udp_responder
            .as_ref()
            .unwrap()
            .test_socket(|socket| socket.ttl().unwrap()),
        29
    );
    drop(runner);
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    assert!(
        NotificationReceiver::builder()
            .from_socket(socket)
            .bind("127.0.0.1:0")
            .prepare()
            .await
            .is_err()
    );
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect("127.0.0.1:161").await.unwrap();
    assert!(
        NotificationReceiver::builder()
            .from_socket(socket)
            .prepare()
            .await
            .is_err()
    );
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None).unwrap();
    socket.set_nonblocking(true).unwrap();
    let socket = UdpSocket::from_std(socket.into()).unwrap();
    assert!(
        NotificationReceiver::builder()
            .from_socket(socket)
            .prepare()
            .await
            .is_err()
    );
    for builder in [
        NotificationReceiver::builder().queue_capacity(0),
        NotificationReceiver::builder().max_processing(0),
    ] {
        assert!(builder.prepare().await.is_err());
    }
}

#[test]
fn supplied_socket_prepares_outside_runtime_then_runs_on_second_runtime() {
    let original = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let socket = original.block_on(UdpSocket::bind("127.0.0.1:0")).unwrap();
    let prepared = futures::executor::block_on(
        NotificationReceiver::builder()
            .from_socket(socket)
            .prepare(),
    )
    .unwrap();
    let execution = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut receiver = prepared.spawn_on(execution.handle());
    assert!(receiver.task().is_some());
    execution.block_on(async {
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender
            .send_to(&build_v2c_inform(b"public"), receiver.local_addr())
            .await
            .unwrap();
        await_ack(&sender).await;
        receiver.shutdown().await.unwrap();
        assert!(receiver.task().is_none());
        assert!(receiver.recv().await.is_some());
        assert!(receiver.recv().await.is_none());
    });
}

#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
#[tokio::test]
async fn persistence_degradation_withholds_local_acceptance_and_recovers_without_blocking_other_traffic()
 {
    use super::tests::{build_authed_v3_inform, build_authed_v3_trap};
    use crate::v3::LocalEngineHealth;
    use std::sync::atomic::AtomicBool;
    let unavailable = Arc::new(AtomicBool::new(false));
    let failed = unavailable.clone();
    let engine_id = Bytes::from_static(b"notification-health-engine");
    let engine = AuthoritativeEngine::install(engine_id.clone(), move |_| {
        if failed.load(Ordering::Relaxed) {
            Err(std::io::Error::other("unavailable"))
        } else {
            Ok(())
        }
    })
    .unwrap();
    let mut receiver = NotificationReceiver::builder()
        .bind("127.0.0.1:0")
        .authoritative_engine(engine.clone())
        .usm_user("informuser", |user| {
            user.auth(crate::AuthProtocol::Sha1, b"authpass12345678")
        })
        .unwrap()
        .usm_user("trapuser", |user| {
            user.auth(crate::AuthProtocol::Sha1, b"authpass12345678")
        })
        .unwrap()
        .admit_all_notifications()
        .spawn()
        .await
        .unwrap();
    unavailable.store(true, Ordering::Relaxed);
    engine.set_elapsed_for_test(u64::from(crate::v3::MAX_ENGINE_TIME) + 1);
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let control = receiver.control();
    let mut health = control.subscribe_health();
    sender
        .send_to(
            &build_authed_v3_inform(
                &engine_id,
                2,
                0,
                b"informuser",
                b"authpass12345678",
                crate::AuthProtocol::Sha1,
            ),
            receiver.local_addr(),
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), health.changed())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        control.health(),
        LocalEngineHealth::AuthoritativePersistenceDegraded {
            consecutive_failures: 1,
            ..
        }
    ));
    no_ack(&sender).await;
    sender
        .send_to(&build_v2c_trap(b"public"), receiver.local_addr())
        .await
        .unwrap();
    assert!(matches!(
        receiver.recv().await.unwrap().notification,
        Notification::TrapV2c { .. }
    ));
    sender
        .send_to(
            &build_authed_v3_trap(b"remote-health-engine", 1, 0),
            receiver.local_addr(),
        )
        .await
        .unwrap();
    assert!(matches!(
        receiver.recv().await.unwrap().notification,
        Notification::TrapV3 { .. }
    ));
    assert!(matches!(
        control.health(),
        LocalEngineHealth::AuthoritativePersistenceDegraded { .. }
    ));
    unavailable.store(false, Ordering::Relaxed);
    sender
        .send_to(
            &build_authed_v3_inform(
                &engine_id,
                2,
                0,
                b"informuser",
                b"authpass12345678",
                crate::AuthProtocol::Sha1,
            ),
            receiver.local_addr(),
        )
        .await
        .unwrap();
    await_ack(&sender).await;
    assert!(matches!(
        receiver.recv().await.unwrap().inform_ack,
        crate::NotificationAcknowledgement::Completed(InformAckOutcome::Sent)
    ));
    assert_eq!(control.health(), LocalEngineHealth::Healthy);
}

#[tokio::test]
async fn colliding_informs_blocked_in_ack_leave_response_allowance_available() {
    use crate::transport::{
        Candidate, CommunityResponsePolicy, RequestRegistration, RequestTransport,
    };
    let mut receiver = NotificationReceiver::builder()
        .bind("127.0.0.1:0")
        .max_tcp_buffered_bytes(1)
        .client_exchanges(true)
        .queue_capacity(64)
        .max_processing(64)
        .response_send_timeout(Duration::from_secs(10))
        .spawn()
        .await
        .unwrap();
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    *receiver.inner.response_send_gate.lock().unwrap() = Some(gate.clone());
    let endpoint = receiver
        .udp_endpoint(receiver.bound_addresses()[0].endpoint_id)
        .unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let handle = endpoint.handle(peer.local_addr().unwrap()).unwrap();
    let pending = tokio::spawn(async move {
        let request =
            crate::message::CommunityMessage::v2c("public", crate::Pdu::get_request(1, &[]))
                .unwrap()
                .encode()
                .unwrap();
        handle
            .request_with(
                request.clone(),
                RequestRegistration::community(
                    1,
                    tokio::time::Instant::now() + Duration::from_secs(5),
                    crate::CommunityVersion::V2c,
                    "public",
                    CommunityResponsePolicy::Exact,
                ),
                |packet| {
                    let (data, _) = packet.into_parts();
                    assert_eq!(
                        crate::message::CommunityMessage::decode(
                            data,
                            crate::DecodeConfig::DEFAULT
                        )?
                        .value
                        .pdu()
                        .pdu_type(),
                        crate::PduType::Response
                    );
                    Ok(Candidate::Accept(()))
                },
            )
            .await
    });
    await_ack(&peer).await; // Outgoing request establishes the pending ID.
    for _ in 0..64 {
        peer.send_to(&build_v2c_inform(b"public"), receiver.local_addr())
            .await
            .unwrap();
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        while receiver
            .inner
            .response_sends_started
            .load(Ordering::Relaxed)
            < 64
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let response =
        crate::message::CommunityMessage::v2c("public", crate::Pdu::response(1, 0, 0, vec![]))
            .unwrap()
            .encode()
            .unwrap();
    peer.send_to(&response, receiver.local_addr())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), pending)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        receiver
            .inner
            .response_sends_started
            .load(Ordering::Relaxed),
        64
    );
    gate.add_permits(64);
    receiver.shutdown().await.unwrap();
    for _ in 0..64 {
        assert!(receiver.recv().await.is_some());
    }
    assert!(receiver.recv().await.is_none());
}

#[tokio::test]
async fn tcp_shutdown_drains_reserved_acknowledgement_and_abort_terminates_route() {
    use crate::{Auth, Client, ListenerSource, Retry};
    for abort in [false, true] {
        let (mut receiver, runner) = NotificationReceiver::builder()
            .listener(ListenerSource::tcp("127.0.0.1:0"))
            .queue_capacity(1)
            .prepare()
            .await
            .unwrap()
            .into_parts();
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        *receiver.inner.response_send_gate.lock().unwrap() = Some(gate.clone());
        let driver = tokio::spawn(runner.run());
        let client = Client::builder(
            receiver.bound_addresses()[0].local_addr.to_string(),
            Auth::v2c("public"),
        )
        .retry(Retry::none())
        .request_timeout(Duration::from_secs(1))
        .connect_tcp()
        .await
        .unwrap();
        let inform =
            tokio::spawn(async move { client.send_inform(&oids::cold_start(), 1, vec![]).await });
        processing_started(&receiver).await;
        let engine = receiver.local_engine();
        let capacity = engine.receive_capacity().unwrap();
        if abort {
            driver.abort();
            assert!(driver.await.is_err());
            assert_eq!(engine.receive_capacity(), None);
            gate.add_permits(1);
            assert!(inform.await.unwrap().is_err());
            assert!(receiver.recv().await.is_none());
            assert_eq!(receiver.control().status(), NotificationStatus::Interrupted);
        } else {
            let session = receiver.tcp_sessions()[0].control();
            receiver.control().request_shutdown();
            receiver.close();
            tokio::task::yield_now().await;
            assert!(!driver.is_finished());
            assert_eq!(engine.receive_capacity(), Some(capacity));
            gate.add_permits(1);
            inform.await.unwrap().unwrap();
            driver.await.unwrap().unwrap();
            assert_eq!(session.status(), crate::TcpStatus::Stopped);
            session.join().await.unwrap();
            assert_eq!(engine.receive_capacity(), None);
            assert!(matches!(
                receiver.recv().await.unwrap().inform_ack,
                crate::NotificationAcknowledgement::Completed(InformAckOutcome::Sent)
            ));
            assert!(receiver.recv().await.is_none());
            assert_eq!(receiver.control().status(), NotificationStatus::Stopped);
        }
    }
}
