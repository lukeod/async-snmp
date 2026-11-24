//! Bounded, service-owned Inform response completion.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};

use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, oneshot};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use super::{InformAckOutcome, InformResponse, NotificationRole};
use crate::Error;

/// When managed receivers acknowledge accepted Informs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum InformAcknowledgementMode {
    /// Attempt the response before delivery into the accepted-event queue.
    #[default]
    Automatic,
    /// Deliver a pending capability for completion after application processing.
    ApplicationControlled,
}

/// A notification's complete managed acknowledgement state.
#[derive(Debug)]
pub enum NotificationAcknowledgement {
    /// Traps do not require a response.
    NotRequired,
    /// An automatic attempt or manual-admission installation failure completed.
    Completed(InformAckOutcome),
    /// An Inform carries a completion capability; it may expire or be invalidated
    /// before the application acts. Completion reports that failure explicitly.
    Pending(PendingInformAck),
}

/// An owned capability to acknowledge one accepted Inform on its original route.
///
/// The service owns the request, keys and outstanding-work permit; this token
/// retains only an identifier. Expiry/shutdown releases pending payloads even
/// when an application keeps a token or an unpolled completion future forever.
/// Drop or [`Self::reject`] sends nothing. Retransmissions are independent events.
#[must_use = "acknowledge after application processing, or reject/drop without sending"]
pub struct PendingInformAck {
    registry: Weak<PendingRegistry>,
    key: Key,
    source: SocketAddr,
    submitted: bool,
}

impl std::fmt::Debug for PendingInformAck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingInformAck")
            .field("deadline", &self.key.0)
            .finish_non_exhaustive()
    }
}

impl PendingInformAck {
    /// Absolute deadline measured from acceptance, including completion/send.
    pub fn deadline(&self) -> Instant {
        self.key.0
    }

    /// Reject this Inform without acknowledging it and release retained work.
    pub fn reject(self) {
        drop(self);
    }

    /// Submit one bounded response attempt and await its local outcome.
    ///
    /// On first poll the attempt is committed to the supervised service worker.
    /// Dropping this wait future after submission does not cancel that attempt;
    /// the worker finishes under its absolute deadline or service shutdown.
    /// Stream writes retain their existing finish-frame-or-close semantics.
    /// Encoding uses the original validated credentials and current engine time.
    pub async fn acknowledge(mut self) -> InformAckOutcome {
        let submitted = match self.registry.upgrade() {
            Some(registry) => registry.request(self.key),
            None => Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "notification service closed",
            )),
        };
        self.submitted = true;
        match submitted {
            Ok(result) => result.await.unwrap_or_else(|_| {
                failed(
                    self.source,
                    std::io::ErrorKind::NotConnected,
                    "notification completion stopped",
                )
            }),
            Err(error) => InformAckOutcome::Failed(
                Error::Network {
                    target: self.source,
                    source: error,
                }
                .boxed(),
            ),
        }
    }
}

impl Drop for PendingInformAck {
    fn drop(&mut self) {
        if !self.submitted
            && let Some(registry) = self.registry.upgrade()
        {
            registry.remove(self.key);
        }
    }
}

type Key = (Instant, u64);

struct Payload {
    response: InformResponse,
    route: crate::transport::ReplyRoute,
    source: SocketAddr,
    _permit: OwnedSemaphorePermit,
}

enum Entry {
    Waiting {
        payload: Box<Payload>,
        requested: Option<oneshot::Sender<InformAckOutcome>>,
    },
    Running(CancellationToken),
}

struct State {
    closed: bool,
    next_id: u64,
    entries: BTreeMap<Key, Entry>,
}

pub(super) struct PendingRegistry {
    pub(super) slots: Arc<Semaphore>,
    state: Mutex<State>,
    changed: Notify,
    active: AtomicUsize,
    idle: Notify,
}

impl PendingRegistry {
    pub(super) fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            slots: Arc::new(Semaphore::new(limit)),
            state: Mutex::new(State {
                closed: false,
                next_id: 0,
                entries: BTreeMap::new(),
            }),
            changed: Notify::new(),
            active: AtomicUsize::new(0),
            idle: Notify::new(),
        })
    }

    pub(super) fn install(
        self: &Arc<Self>,
        response: InformResponse,
        route: crate::transport::ReplyRoute,
        source: SocketAddr,
        permit: OwnedSemaphorePermit,
        deadline: Instant,
    ) -> std::result::Result<PendingInformAck, InformAckOutcome> {
        let mut state = self.state.lock().unwrap();
        if state.closed {
            return Err(failed(
                source,
                std::io::ErrorKind::NotConnected,
                "notification role closed",
            ));
        }
        state.next_id = state
            .next_id
            .checked_add(1)
            .expect("pending Inform identity exhausted");
        let key = (deadline, state.next_id);
        state.entries.insert(
            key,
            Entry::Waiting {
                payload: Box::new(Payload {
                    response,
                    route,
                    source,
                    _permit: permit,
                }),
                requested: None,
            },
        );
        drop(state);
        self.changed.notify_one();
        Ok(PendingInformAck {
            registry: Arc::downgrade(self),
            key,
            source,
            submitted: false,
        })
    }

    fn request(&self, key: Key) -> std::io::Result<oneshot::Receiver<InformAckOutcome>> {
        let mut state = self.state.lock().unwrap();
        if state.closed {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "notification role closed",
            ));
        }
        if Instant::now() >= key.0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "pending Inform expired",
            ));
        }
        let Some(Entry::Waiting { requested, .. }) = state.entries.get_mut(&key) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "pending Inform no longer available",
            ));
        };
        let (sender, receiver) = oneshot::channel();
        *requested = Some(sender);
        drop(state);
        self.changed.notify_one();
        Ok(receiver)
    }

    fn remove(&self, key: Key) {
        let removed = self.state.lock().unwrap().entries.remove(&key);
        if let Some(Entry::Running(cancel)) = &removed {
            cancel.cancel();
        }
        drop(removed);
        self.changed.notify_one();
    }

    fn expire(&self) {
        let now = Instant::now();
        let expired = {
            let mut state = self.state.lock().unwrap();
            let keys: Vec<_> = state
                .entries
                .range(..=(now, u64::MAX))
                .map(|(key, _)| *key)
                .collect();
            keys.into_iter()
                .filter_map(|key| state.entries.remove(&key))
                .collect::<Vec<_>>()
        };
        for entry in expired {
            stop(
                entry,
                std::io::ErrorKind::TimedOut,
                "pending Inform expired",
            );
        }
    }

    pub(super) fn shutdown(&self) {
        let entries = {
            let mut state = self.state.lock().unwrap();
            state.closed = true;
            std::mem::take(&mut state.entries)
        };
        self.slots.close();
        for (_, entry) in entries {
            stop(
                entry,
                std::io::ErrorKind::NotConnected,
                "notification role closed",
            );
        }
        self.changed.notify_one();
    }

    pub(super) async fn drain(&self) {
        loop {
            let notified = self.idle.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.active.load(Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }

    fn requested(self: &Arc<Self>, root_shutdown: &CancellationToken) -> Vec<Work> {
        let mut state = self.state.lock().unwrap();
        let mut work = Vec::new();
        for (key, entry) in &mut state.entries {
            if !matches!(
                entry,
                Entry::Waiting {
                    requested: Some(_),
                    ..
                }
            ) {
                continue;
            }
            let cancel = root_shutdown.child_token();
            let Entry::Waiting {
                payload,
                requested: Some(result),
            } = std::mem::replace(entry, Entry::Running(cancel.clone()))
            else {
                unreachable!()
            };
            self.active.fetch_add(1, Ordering::AcqRel);
            work.push(Work {
                payload,
                result,
                cancel,
                guard: WorkGuard {
                    registry: self.clone(),
                    key: *key,
                },
            });
        }
        work
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.state
            .lock()
            .unwrap()
            .entries
            .keys()
            .next()
            .map(|key| key.0)
    }
}

fn stop(entry: Entry, kind: std::io::ErrorKind, message: &'static str) {
    match entry {
        Entry::Waiting { payload, requested } => {
            if let Some(result) = requested {
                let _ = result.send(failed(payload.source, kind, message));
            }
        }
        Entry::Running(cancel) => cancel.cancel(),
    }
}

struct Work {
    payload: Box<Payload>,
    result: oneshot::Sender<InformAckOutcome>,
    cancel: CancellationToken,
    guard: WorkGuard,
}

struct WorkGuard {
    registry: Arc<PendingRegistry>,
    key: Key,
}
impl Drop for WorkGuard {
    fn drop(&mut self) {
        self.registry.remove(self.key);
        self.registry.active.fetch_sub(1, Ordering::AcqRel);
        self.registry.idle.notify_waiters();
    }
}

struct WorkerCleanup(Arc<PendingRegistry>);
impl Drop for WorkerCleanup {
    fn drop(&mut self) {
        self.0.shutdown();
    }
}

pub(super) fn failed(
    source: SocketAddr,
    kind: std::io::ErrorKind,
    message: &'static str,
) -> InformAckOutcome {
    InformAckOutcome::Failed(
        Error::Network {
            target: source,
            source: std::io::Error::new(kind, message),
        }
        .boxed(),
    )
}

impl NotificationRole {
    /// One supervised expiry/completion worker. Attached roles park after role
    /// shutdown so their completion cannot terminate the agent network runner.
    pub(crate) async fn run_pending(self, root_shutdown: CancellationToken) -> crate::Result<()> {
        let registry = self.inner.pending.clone();
        let _cleanup = WorkerCleanup(registry.clone());
        let mut work = tokio::task::JoinSet::new();
        loop {
            if root_shutdown.is_cancelled() {
                break;
            }
            // Reap completed children even under continuous admission/expiry
            // notifications, keeping supervisor bookkeeping bounded too.
            while let Some(joined) = work.try_join_next() {
                if let Err(error) = joined {
                    tracing::debug!(%error, "Inform completion task stopped");
                }
            }
            registry.expire();
            for item in registry.requested(&root_shutdown) {
                let role = self.clone();
                work.spawn(async move {
                    let Work { payload, result, cancel, guard } = item;
                    let deadline = Instant::now().checked_add(role.inner.response_send_timeout).unwrap_or(guard.key.0).min(guard.key.0);
                    let Payload { response, route, source, _permit } = *payload;
                    let outcome = tokio::select! {
                        biased;
                        () = cancel.cancelled() => if Instant::now() >= deadline {
                            failed(source, std::io::ErrorKind::TimedOut, "pending Inform expired")
                        } else { failed(source, std::io::ErrorKind::NotConnected, "notification completion cancelled") },
                        () = tokio::time::sleep_until(deadline) => failed(source, std::io::ErrorKind::TimedOut, "pending Inform expired"),
                        outcome = role.complete_response(response, route, source, Some(deadline), Some(cancel.clone())) => outcome,
                    };
                    let _ = result.send(outcome);
                    drop(_permit);
                    drop(guard);
                });
            }
            let deadline = registry.next_deadline();
            tokio::select! {
                biased;
                () = root_shutdown.cancelled() => break,
                () = registry.changed.notified() => {},
                () = async { match deadline { Some(deadline) => tokio::time::sleep_until(deadline).await, None => std::future::pending().await } } => {},
                joined = work.join_next(), if !work.is_empty() => {
                    if let Some(Err(error)) = joined { tracing::debug!(%error, "Inform completion task stopped"); }
                }
            }
        }
        registry.shutdown();
        work.abort_all();
        while work.join_next().await.is_some() {}
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::CommunityMessage;
    use crate::notification::{NotificationReceiver, NotificationReceiverBuilder};
    use crate::{NotificationPdu, Value, VarBind, Version, oid};
    use bytes::Bytes;
    use std::sync::atomic::AtomicBool;
    use std::time::Duration;

    struct TrackedInput {
        wire: Vec<u8>,
        dropped: Arc<AtomicBool>,
    }
    impl AsRef<[u8]> for TrackedInput {
        fn as_ref(&self) -> &[u8] {
            &self.wire
        }
    }
    impl Drop for TrackedInput {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::Release);
        }
    }

    fn inform(dropped: Arc<AtomicBool>) -> Bytes {
        let pdu = NotificationPdu::inform(
            Version::V2c,
            17,
            0,
            &crate::notification::oids::cold_start(),
            vec![VarBind::new(
                oid!(1, 3, 6, 1, 4, 1, 99, 0),
                Value::OctetString(Bytes::from(vec![42; 8192])),
            )],
        )
        .unwrap()
        .into_raw();
        let wire = CommunityMessage::v2c("public", pdu)
            .unwrap()
            .encode()
            .unwrap()
            .to_vec();
        Bytes::from_owner(TrackedInput { wire, dropped })
    }

    fn manual() -> NotificationReceiverBuilder {
        NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .acknowledgement_mode(InformAcknowledgementMode::ApplicationControlled)
            .max_pending_informs(1)
            .pending_inform_timeout(Duration::from_secs(1))
    }

    async fn admitted(
        receiver: &NotificationReceiver,
        source: SocketAddr,
        dropped: Arc<AtomicBool>,
    ) -> PendingInformAck {
        let event = receiver
            .processor()
            .handle_v2c(inform(dropped), source)
            .await
            .unwrap()
            .unwrap();
        let NotificationAcknowledgement::Pending(pending) = event.inform_ack else {
            panic!("manual Inform must be pending")
        };
        pending
    }

    async fn started(role: &NotificationRole) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while role.inner.response_sends_started.load(Ordering::Acquire) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn expiry_releases_actual_request_storage_and_permit_with_token_or_unpolled_future_held()
    {
        for hold_future in [false, true] {
            let (receiver, _runner) = manual().prepare().await.unwrap().into_parts();
            let role = receiver.processor();
            let root = CancellationToken::new();
            let worker = tokio::spawn(role.clone().run_pending(root.clone()));
            let dropped = Arc::new(AtomicBool::new(false));
            let pending = admitted(
                &receiver,
                "127.0.0.1:9999".parse().unwrap(),
                dropped.clone(),
            )
            .await;
            let deadline = pending.deadline();
            assert!(!dropped.load(Ordering::Acquire));
            assert_eq!(role.inner.pending.slots.available_permits(), 0);
            if hold_future {
                let future = pending.acknowledge();
                tokio::time::advance(deadline - Instant::now()).await;
                tokio::task::yield_now().await;
                assert!(
                    dropped.load(Ordering::Acquire),
                    "unpolled future retained request bytes"
                );
                assert_eq!(role.inner.pending.slots.available_permits(), 1);
                assert!(matches!(future.await, InformAckOutcome::Failed(_)));
            } else {
                tokio::time::advance(deadline - Instant::now()).await;
                tokio::task::yield_now().await;
                assert!(
                    dropped.load(Ordering::Acquire),
                    "held token retained request bytes"
                );
                assert_eq!(role.inner.pending.slots.available_permits(), 1);
                assert!(matches!(
                    pending.acknowledge().await,
                    InformAckOutcome::Failed(_)
                ));
            }
            root.cancel();
            worker.await.unwrap().unwrap();
        }
    }

    #[tokio::test]
    async fn dropping_unpolled_runner_synchronously_releases_pending_request_storage() {
        let (receiver, runner) = manual().prepare().await.unwrap().into_parts();
        let dropped = Arc::new(AtomicBool::new(false));
        let pending = admitted(
            &receiver,
            "127.0.0.1:9999".parse().unwrap(),
            dropped.clone(),
        )
        .await;
        assert!(!dropped.load(Ordering::Acquire));
        drop(runner);
        assert!(dropped.load(Ordering::Acquire));
        assert_eq!(receiver.inner.pending.slots.available_permits(), 1);
        assert!(matches!(
            pending.acknowledge().await,
            InformAckOutcome::Failed(_)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn submitted_completion_expires_even_when_its_wait_future_is_never_polled_again() {
        let (receiver, _runner) = manual().prepare().await.unwrap().into_parts();
        let role = receiver.processor();
        *role.inner.response_send_gate.lock().unwrap() = Some(Arc::new(Semaphore::new(0)));
        let root = CancellationToken::new();
        let worker = tokio::spawn(role.clone().run_pending(root.clone()));
        let pending = admitted(
            &receiver,
            "127.0.0.1:9999".parse().unwrap(),
            Arc::new(AtomicBool::new(false)),
        )
        .await;
        let deadline = pending.deadline();
        let mut future = Box::pin(pending.acknowledge());
        assert!(futures::poll!(&mut future).is_pending());
        started(&role).await;
        assert_eq!(role.inner.pending.slots.available_permits(), 0);
        assert_eq!(role.inner.pending.active.load(Ordering::Acquire), 1);
        tokio::time::advance(deadline - Instant::now()).await;
        role.inner.pending.drain().await;
        assert_eq!(role.inner.pending.slots.available_permits(), 1);
        assert!(matches!(future.await, InformAckOutcome::Failed(_)));
        root.cancel();
        worker.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn dropping_completion_waiter_does_not_abandon_supervised_send() {
        let (receiver, _runner) = manual()
            .pending_inform_timeout(Duration::from_secs(3))
            .prepare()
            .await
            .unwrap()
            .into_parts();
        let role = receiver.processor();
        let gate = Arc::new(Semaphore::new(0));
        *role.inner.response_send_gate.lock().unwrap() = Some(gate.clone());
        let root = CancellationToken::new();
        let worker = tokio::spawn(role.clone().run_pending(root.clone()));
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let pending = admitted(
            &receiver,
            peer.local_addr().unwrap(),
            Arc::new(AtomicBool::new(false)),
        )
        .await;
        let mut future = Box::pin(pending.acknowledge());
        assert!(futures::poll!(&mut future).is_pending());
        started(&role).await;
        drop(future);
        assert_eq!(role.inner.pending.slots.available_permits(), 0);
        gate.add_permits(1);
        tokio::time::timeout(Duration::from_secs(2), peer.recv(&mut [0; 20000]))
            .await
            .unwrap()
            .unwrap();
        role.inner.pending.drain().await;
        assert_eq!(role.inner.pending.slots.available_permits(), 1);
        root.cancel();
        worker.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn already_cancelled_root_does_not_start_submitted_completion() {
        let (receiver, _runner) = manual().prepare().await.unwrap().into_parts();
        let role = receiver.processor();
        let pending = admitted(
            &receiver,
            "127.0.0.1:9999".parse().unwrap(),
            Arc::new(AtomicBool::new(false)),
        )
        .await;
        let mut future = Box::pin(pending.acknowledge());
        assert!(futures::poll!(&mut future).is_pending());
        let root = CancellationToken::new();
        root.cancel();
        role.clone().run_pending(root).await.unwrap();
        assert_eq!(role.inner.response_sends_started.load(Ordering::Acquire), 0);
        assert_eq!(role.inner.pending.slots.available_permits(), 1);
        assert!(matches!(future.await, InformAckOutcome::Failed(_)));
    }

    #[tokio::test]
    async fn shutdown_racing_with_pending_reservation_is_disabled_without_overload() {
        let (receiver, _runner) = manual().prepare().await.unwrap().into_parts();
        let role = receiver.processor();
        let data = inform(Arc::new(AtomicBool::new(false)));
        let message = role.test_message(data, "127.0.0.1:9999".parse().unwrap(), None);
        let mut work = role.prepare(message).unwrap();
        assert!(work.admission.reserve(&role.inner.delivery));
        role.inner.pending.shutdown();
        assert_eq!(
            work.run().await,
            super::super::lifecycle::NotificationDisposition::Disabled
        );
        assert_eq!(receiver.control().overload_drops(), 0);
    }

    #[tokio::test]
    async fn control_shutdown_drains_started_completion_without_polling_its_waiter() {
        let (receiver, runner) = manual().prepare().await.unwrap().into_parts();
        let role = receiver.processor();
        *role.inner.response_send_gate.lock().unwrap() = Some(Arc::new(Semaphore::new(0)));
        let task = tokio::spawn(runner.run());
        let pending = admitted(
            &receiver,
            "127.0.0.1:9999".parse().unwrap(),
            Arc::new(AtomicBool::new(false)),
        )
        .await;
        let mut future = Box::pin(pending.acknowledge());
        assert!(futures::poll!(&mut future).is_pending());
        started(&role).await;
        tokio::time::timeout(Duration::from_secs(1), receiver.control().shutdown())
            .await
            .unwrap();
        task.await.unwrap().unwrap();
        assert_eq!(role.inner.pending.active.load(Ordering::Acquire), 0);
        assert_eq!(role.inner.pending.slots.available_permits(), 1);
        assert!(matches!(future.await, InformAckOutcome::Failed(_)));
    }

    #[tokio::test]
    async fn aborting_running_service_releases_payload_while_token_is_held() {
        let (receiver, runner) = manual().prepare().await.unwrap().into_parts();
        let dropped = Arc::new(AtomicBool::new(false));
        let token = admitted(
            &receiver,
            "127.0.0.1:9999".parse().unwrap(),
            dropped.clone(),
        )
        .await;
        let task = tokio::spawn(runner.run());
        tokio::task::yield_now().await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(dropped.load(Ordering::Acquire));
        assert_eq!(receiver.inner.pending.slots.available_permits(), 1);
        assert!(matches!(
            token.acknowledge().await,
            InformAckOutcome::Failed(_)
        ));
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[tokio::test]
    async fn managed_v3_completion_sends_too_big_when_engine_time_grows() {
        let engine = crate::AuthoritativeEngine::for_test(b"manual-clock-engine".as_slice(), 1);
        engine.set_elapsed_for_test(127);
        let security = crate::UsmConfig::new("user")
            .auth(crate::AuthProtocol::Sha256, b"authentication-password")
            .unwrap();
        let keys = security.derive_keys(engine.engine_id()).unwrap();
        let pdu = NotificationPdu::inform(
            Version::V3,
            17,
            0,
            &crate::notification::oids::cold_start(),
            vec![],
        )
        .unwrap()
        .into_raw();
        let wire = crate::v3::encode::encode_v3_message(
            &pdu,
            17,
            engine.engine_id(),
            1,
            127,
            &security,
            Some(&keys),
            None,
            None,
            None,
            true,
            crate::UDP_RECEIVE_LIMITS.advertised(),
        )
        .unwrap();
        // At time 127 the ordinary response differs in the PDU tag, flags and
        // digest, all of which retain their encoded widths.
        let limit = wire.len();
        let mut receiver = manual()
            .pending_inform_timeout(Duration::from_secs(3))
            .authoritative_engine(engine.clone())
            .usm_user("user", |user| {
                user.auth(crate::AuthProtocol::Sha256, b"authentication-password")
            })
            .unwrap()
            .admit_all_notifications()
            .max_message_size(limit)
            .spawn()
            .await
            .unwrap();
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        peer.send_to(&wire, receiver.bound_addresses()[0].local_addr)
            .await
            .unwrap();
        let event = tokio::time::timeout(Duration::from_secs(2), receiver.recv())
            .await
            .unwrap()
            .unwrap();
        let NotificationAcknowledgement::Pending(token) = event.inform_ack else {
            panic!("expected manual response")
        };
        engine.set_elapsed_for_test(128);
        assert!(matches!(
            token.acknowledge().await,
            InformAckOutcome::SentTooBig
        ));
        let mut wire = vec![0; 8192];
        let len = tokio::time::timeout(Duration::from_secs(2), peer.recv(&mut wire))
            .await
            .unwrap()
            .unwrap();
        assert!(len <= limit);
        let response = crate::message::V3Message::decode(
            Bytes::copy_from_slice(&wire[..len]),
            crate::DecodeConfig::DEFAULT,
        )
        .unwrap()
        .value;
        let reply = &response.scoped_pdu().unwrap().pdu;
        assert_eq!(reply.request_id(), 17);
        assert_eq!(reply.error_status_enum(), crate::ErrorStatus::TooBig);
        assert_eq!(reply.error_index(), 0);
        assert!(reply.varbinds().is_empty());
        let usm = crate::v3::UsmSecurityParams::decode(
            response.security_params,
            crate::DecodeConfig::DEFAULT,
        )
        .unwrap()
        .value;
        assert_eq!(usm.engine_time, 128);
        receiver.shutdown().await.unwrap();
    }
}
