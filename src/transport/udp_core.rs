//! Core infrastructure for UDP response correlation.
//!
//! Provides a sharded pending request map with per-request wakeup.

use bytes::Bytes;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Notify;

use super::{Candidate, RequestRegistration, ResponseIdentity, checked_deadline};
use crate::error::{Error, Result};

const SHARDS: usize = 64;
const MAX_PARKED_CANDIDATES: usize = 16;

/// Sharded pending request tracking with per-request wakeup.
///
/// Uses 64 shards to reduce lock contention under high load.
/// Each pending request has its own [`Notify`], so delivering a
/// response wakes only the task waiting for that specific request.
pub struct UdpCore {
    shards: Box<[Shard; SHARDS]>,
    stats: CoreStats,
    /// Set when the owning transport shuts down; waiters fail immediately.
    closed: AtomicBool,
}

/// Counters for transport health monitoring.
struct CoreStats {
    /// Datagrams successfully correlated and queued for a pending request.
    correlated_datagrams: AtomicU64,
    /// Requests that timed out without receiving a response.
    expired_registrations: AtomicU64,
    /// Datagrams discarded because they were late, duplicate, unregistered,
    /// over queue capacity, or rejected by source/community correlation.
    discarded_datagrams: AtomicU64,
    /// Datagrams from which no request ID could be extracted.
    malformed_datagrams: AtomicU64,
}

/// UDP endpoint statistics.
///
/// These cumulative counters are shared by every transport, handle, client,
/// and control capability using the same UDP endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct UdpStats {
    /// Datagrams successfully correlated and queued for a pending request.
    pub correlated_datagrams: u64,
    /// Requests that timed out without receiving a response.
    pub expired_registrations: u64,
    /// Datagrams discarded because they were late, duplicate, unregistered,
    /// over queue capacity, or rejected by source/community correlation.
    pub discarded_datagrams: u64,
    /// Datagrams from which no request ID could be extracted.
    pub malformed_datagrams: u64,
}

struct Shard {
    pending: Mutex<HashMap<i32, PendingEntry>>,
}

struct RegistrationOwner {
    /// Timing remains available after periodic cleanup removes map entries.
    registered_at: Instant,
    deadline: Instant,
    retries: u32,
    expired: AtomicBool,
    notify: Arc<Notify>,
}

impl RegistrationOwner {
    fn note_expired(&self, stats: &CoreStats) {
        if !self.expired.swap(true, Ordering::AcqRel) {
            stats.expired_registrations.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn elapsed(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.registered_at)
    }
}

struct ResponseSlot {
    responses: VecDeque<(Bytes, SocketAddr)>,
    owner: Arc<RegistrationOwner>,
    /// Configured target, used by conditional community rewrite policy.
    target_source: SocketAddr,
    /// When true, only responses from exactly the target are delivered.
    strict_source: bool,
    registration: RequestRegistration,
}

enum PendingEntry {
    Slot(ResponseSlot),
    /// Retransmission window alias: datagrams keyed by a prior attempt's
    /// msgID are delivered to the current attempt's slot.
    Alias {
        primary: i32,
        owner: Arc<RegistrationOwner>,
    },
}

impl PendingEntry {
    fn owner(&self) -> &Arc<RegistrationOwner> {
        match self {
            Self::Slot(slot) => &slot.owner,
            Self::Alias { owner, .. } => owner,
        }
    }
}

/// Owns one UDP correlation registration and removes only its entries on drop.
pub(crate) struct UdpRegistration {
    core: Arc<UdpCore>,
    primary: i32,
    aliases: Vec<i32>,
    owner: Arc<RegistrationOwner>,
}

impl UdpRegistration {
    pub(crate) fn request_id(&self) -> i32 {
        self.primary
    }
}

impl Drop for UdpRegistration {
    fn drop(&mut self) {
        self.core.remove_owned(self.primary, &self.owner);
        for alias in &self.aliases {
            self.core.remove_owned(*alias, &self.owner);
        }
    }
}

impl UdpCore {
    /// Create a new `UdpCore` with empty shards.
    pub fn new() -> Self {
        let shards: Vec<Shard> = (0..SHARDS)
            .map(|_| Shard {
                pending: Mutex::new(HashMap::new()),
            })
            .collect();

        Self {
            shards: shards
                .try_into()
                .unwrap_or_else(|_| unreachable!("Vec has exactly SHARDS elements")),
            stats: CoreStats {
                correlated_datagrams: AtomicU64::new(0),
                expired_registrations: AtomicU64::new(0),
                discarded_datagrams: AtomicU64::new(0),
                malformed_datagrams: AtomicU64::new(0),
            },
            closed: AtomicBool::new(false),
        }
    }

    /// Mark the core closed and wake all pending waiters.
    ///
    /// Called when the transport's recv loop exits. Waiters observe the
    /// closed flag and fail immediately instead of at their deadlines;
    /// any already-delivered response is still returned.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
        for shard in self.shards.iter() {
            let notifies: Vec<_> = shard
                .pending
                .lock()
                .unwrap()
                .values()
                .filter_map(|entry| match entry {
                    PendingEntry::Slot(slot) => Some(slot.owner.notify.clone()),
                    PendingEntry::Alias { .. } => None,
                })
                .collect();
            for notify in notifies {
                notify.notify_one();
            }
        }
    }

    /// Get the shard for a given request ID.
    fn shard_index(request_id: i32) -> usize {
        request_id as usize % SHARDS
    }

    fn shard(&self, request_id: i32) -> &Shard {
        &self.shards[Self::shard_index(request_id)]
    }

    /// Atomically reserve a primary request ID and all of its unique aliases.
    pub fn register(
        self: &Arc<Self>,
        registration: RequestRegistration,
        target_source: SocketAddr,
        strict_source: bool,
    ) -> Result<UdpRegistration> {
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::Closed {
                target: target_source,
            }
            .boxed());
        }

        let primary = registration.request_id();
        let now = Instant::now();
        let deadline = checked_deadline(registration.timeout(), "UDP timeout")?;
        let aliases = registration.aliases().to_vec();

        let mut ids = Vec::with_capacity(1 + aliases.len());
        ids.push(primary);
        for alias in &aliases {
            if *alias != primary && !ids.contains(alias) {
                ids.push(*alias);
            }
        }

        // Hold every involved shard in ascending order so no observer can see
        // a partially installed alias set.
        let mut shard_indices: Vec<_> = ids.iter().map(|id| Self::shard_index(*id)).collect();
        shard_indices.sort_unstable();
        shard_indices.dedup();
        let mut guards: Vec<_> = shard_indices
            .iter()
            .map(|index| (*index, self.shards[*index].pending.lock().unwrap()))
            .collect();

        // Synchronize with `close()`: once it has marked the core closed, no
        // registration may be installed, even if this call began just before
        // cancellation and was waiting for a shard lock.
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::Closed {
                target: target_source,
            }
            .boxed());
        }

        let mut expired_owners = Vec::new();
        let mut collision = None;
        for id in &ids {
            let shard_index = Self::shard_index(*id);
            let guard_index = guards
                .binary_search_by_key(&shard_index, |(index, _)| *index)
                .unwrap();
            let pending = &mut guards[guard_index].1;
            if let Some(entry) = pending.get(id) {
                if entry.owner().deadline <= now {
                    let owner = entry.owner().clone();
                    pending.remove(id);
                    expired_owners.push(owner);
                } else {
                    collision = Some(*id);
                    break;
                }
            }
        }

        if let Some(request_id) = collision {
            drop(guards);
            for owner in expired_owners {
                owner.note_expired(&self.stats);
                owner.notify.notify_one();
            }
            return Err(Error::RequestIdInUse { request_id }.boxed());
        }

        let owner = Arc::new(RegistrationOwner {
            registered_at: now,
            deadline,
            retries: 0,
            expired: AtomicBool::new(false),
            notify: Arc::new(Notify::new()),
        });
        let slot = ResponseSlot {
            responses: VecDeque::new(),
            owner: owner.clone(),
            target_source,
            strict_source,
            registration,
        };

        let primary_shard = Self::shard_index(primary);
        let primary_guard = guards
            .binary_search_by_key(&primary_shard, |(index, _)| *index)
            .unwrap();
        guards[primary_guard]
            .1
            .insert(primary, PendingEntry::Slot(slot));
        for alias in &aliases {
            let shard_index = Self::shard_index(*alias);
            let guard_index = guards
                .binary_search_by_key(&shard_index, |(index, _)| *index)
                .unwrap();
            guards[guard_index].1.insert(
                *alias,
                PendingEntry::Alias {
                    primary,
                    owner: owner.clone(),
                },
            );
        }
        drop(guards);

        for expired_owner in expired_owners {
            expired_owner.note_expired(&self.stats);
            expired_owner.notify.notify_one();
        }

        Ok(UdpRegistration {
            core: self.clone(),
            primary,
            aliases,
            owner,
        })
    }

    /// Deliver a response to its waiting request.
    ///
    /// Returns `true` if the slot existed and the response was stored,
    /// `false` if there was no matching pending request.
    pub fn deliver(&self, request_id: i32, data: Bytes, source: SocketAddr) -> bool {
        let (target_id, owner) = {
            let pending = self.shard(request_id).pending.lock().unwrap();
            match pending.get(&request_id) {
                Some(PendingEntry::Slot(slot)) => (request_id, Some(slot.owner.clone())),
                Some(PendingEntry::Alias { primary, owner, .. }) => (*primary, Some(owner.clone())),
                None => (request_id, None),
            }
        };
        self.deliver_to(target_id, owner.as_ref(), request_id, data, source)
    }

    fn deliver_to(
        &self,
        target_id: i32,
        expected_owner: Option<&Arc<RegistrationOwner>>,
        request_id: i32,
        data: Bytes,
        source: SocketAddr,
    ) -> bool {
        let shard = self.shard(target_id);
        let mut pending = shard.pending.lock().unwrap();

        if let Some(PendingEntry::Slot(slot)) = pending.get_mut(&target_id)
            && expected_owner.is_none_or(|owner| Arc::ptr_eq(owner, &slot.owner))
        {
            if slot.owner.deadline <= Instant::now() {
                let owner = slot.owner.clone();
                drop(pending);
                owner.note_expired(&self.stats);
                owner.notify.notify_one();
                self.stats
                    .discarded_datagrams
                    .fetch_add(1, Ordering::Relaxed);
                return false;
            }

            let source_is_target = slot.target_source == source;
            if slot.strict_source && !source_is_target {
                // Leave the slot and original deadline intact.
                drop(pending);
                self.stats
                    .discarded_datagrams
                    .fetch_add(1, Ordering::Relaxed);
                tracing::debug!(target: "async_snmp::transport::udp", { request_id, %source }, "response rejected by strict source correlation");
                return false;
            }
            match slot
                .registration
                .evaluate_response_identity(&data, source_is_target)
            {
                ResponseIdentity::Reject => {
                    drop(pending);
                    self.stats
                        .discarded_datagrams
                        .fetch_add(1, Ordering::Relaxed);
                    tracing::debug!(target: "async_snmp::transport::udp", { request_id, %source }, "response rejected by community correlation");
                    return false;
                }
                ResponseIdentity::AcceptedCommunityMismatch => {
                    tracing::warn!(target: "async_snmp::transport::udp", { request_id, %source }, "accepted rewritten response community");
                }
                ResponseIdentity::Match => {}
            }
            if slot
                .responses
                .iter()
                .any(|(parked, parked_source)| *parked_source == source && *parked == data)
                || slot.responses.len() >= MAX_PARKED_CANDIDATES
            {
                // Ignore exact duplicates and bound per-exchange memory if
                // candidates arrive faster than
                // the waiting task can validate them.
                drop(pending);
                self.stats
                    .discarded_datagrams
                    .fetch_add(1, Ordering::Relaxed);
                return false;
            }
            slot.responses.push_back((data, source));
            let notify = slot.owner.notify.clone();
            drop(pending);
            notify.notify_one();
            self.stats
                .correlated_datagrams
                .fetch_add(1, Ordering::Relaxed);
            return true;
        }
        self.stats
            .discarded_datagrams
            .fetch_add(1, Ordering::Relaxed);
        false
    }

    /// Record a datagram from which no request ID could be extracted.
    pub(crate) fn note_malformed(&self) {
        self.stats
            .malformed_datagrams
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Wait until a response candidate is accepted for the given request.
    pub async fn wait_for_response_with<T, F>(
        &self,
        registration: &UdpRegistration,
        target: SocketAddr,
        mut validate: F,
    ) -> Result<T>
    where
        F: FnMut(Bytes, SocketAddr) -> Result<Candidate<T>>,
    {
        let request_id = registration.primary;
        let shard = self.shard(request_id);

        loop {
            // Enforce the absolute deadline before offering even an already
            // parked candidate to the validator. In particular, a zero timeout
            // is an immediate timeout rather than a race with response delivery.
            let now = Instant::now();
            if now >= registration.owner.deadline {
                registration.owner.note_expired(&self.stats);
                let elapsed = registration.owner.elapsed(now);
                tracing::debug!(target: "async_snmp::transport::udp", { request_id, %target, ?elapsed }, "transport timeout");
                return Err(Error::Timeout {
                    target,
                    elapsed,
                    retries: registration.owner.retries,
                }
                .boxed());
            }

            // Take a parked candidate without removing the registration. This
            // allows validation to reject it while preserving the owner and
            // original deadline.
            let response = {
                let mut pending = shard.pending.lock().unwrap();
                if let Some(PendingEntry::Slot(slot)) = pending.get_mut(&request_id)
                    && Arc::ptr_eq(&slot.owner, &registration.owner)
                {
                    slot.responses.pop_front()
                } else if self.closed.load(Ordering::Acquire) {
                    tracing::debug!(target: "async_snmp::transport::udp", { request_id, %target }, "transport shut down (slot missing)");
                    return Err(Error::Closed { target }.boxed());
                } else {
                    let now = Instant::now();
                    registration.owner.note_expired(&self.stats);
                    let elapsed = registration.owner.elapsed(now);
                    tracing::debug!(target: "async_snmp::transport::udp", { request_id, %target, ?elapsed }, "transport timeout (slot missing)");
                    return Err(Error::Timeout {
                        target,
                        elapsed,
                        retries: registration.owner.retries,
                    }
                    .boxed());
                }
            };

            if let Some((data, source)) = response {
                match validate(data, source)? {
                    Candidate::Accept(value) => {
                        self.remove_owned(request_id, &registration.owner);
                        return Ok(value);
                    }
                    Candidate::Reject => {
                        tracing::debug!(target: "async_snmp::transport::udp", { request_id, %source }, "response rejected by client validation");
                        continue;
                    }
                }
            }

            // Checked after the response lookup so a response delivered
            // before shutdown is still offered to the validator.
            if self.closed.load(Ordering::Acquire) {
                tracing::debug!(target: "async_snmp::transport::udp", { request_id, %target }, "transport shut down");
                return Err(Error::Closed { target }.boxed());
            }

            tokio::select! {
                () = registration.owner.notify.notified() => {}
                () = tokio::time::sleep_until(tokio::time::Instant::from_std(registration.owner.deadline)) => {}
            }
        }
    }

    #[cfg(test)]
    async fn wait_for_response(
        &self,
        registration: &UdpRegistration,
        target: SocketAddr,
    ) -> Result<(Bytes, SocketAddr)> {
        self.wait_for_response_with(registration, target, |data, source| {
            Ok(Candidate::Accept((data, source)))
        })
        .await
    }

    /// Snapshot current stats.
    pub fn stats(&self) -> UdpStats {
        UdpStats {
            correlated_datagrams: self.stats.correlated_datagrams.load(Ordering::Relaxed),
            expired_registrations: self.stats.expired_registrations.load(Ordering::Relaxed),
            discarded_datagrams: self.stats.discarded_datagrams.load(Ordering::Relaxed),
            malformed_datagrams: self.stats.malformed_datagrams.load(Ordering::Relaxed),
        }
    }

    fn remove_owned(&self, request_id: i32, owner: &Arc<RegistrationOwner>) {
        let mut pending = self.shard(request_id).pending.lock().unwrap();
        let matches = match pending.get(&request_id) {
            Some(PendingEntry::Slot(slot)) => Arc::ptr_eq(&slot.owner, owner),
            Some(PendingEntry::Alias {
                owner: alias_owner, ..
            }) => Arc::ptr_eq(alias_owner, owner),
            None => false,
        };
        if matches {
            pending.remove(&request_id);
        }
    }

    #[cfg(test)]
    pub(crate) fn pending_counts(&self) -> (usize, usize) {
        self.shards.iter().fold((0, 0), |(slots, aliases), shard| {
            shard.pending.lock().unwrap().values().fold(
                (slots, aliases),
                |(slots, aliases), entry| match entry {
                    PendingEntry::Slot(_) => (slots + 1, aliases),
                    PendingEntry::Alias { .. } => (slots, aliases + 1),
                },
            )
        })
    }

    /// Remove all expired request slots.
    ///
    /// Should be called periodically to clean up slots that timed out
    /// but were never waited on.
    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        let mut expired_owners = Vec::new();
        for shard in self.shards.iter() {
            let mut pending = shard.pending.lock().unwrap();
            pending.retain(|_, entry| {
                let keep = entry.owner().deadline > now;
                if !keep {
                    expired_owners.push(entry.owner().clone());
                }
                keep
            });
        }
        for owner in expired_owners {
            owner.note_expired(&self.stats);
            owner.notify.notify_one();
        }
    }
}

impl Default for UdpCore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::super::CommunityResponsePolicy;
    use super::*;

    fn test_addr() -> SocketAddr {
        "127.0.0.1:161".parse().unwrap()
    }

    fn register_v3(
        core: &Arc<UdpCore>,
        request_id: i32,
        timeout: Duration,
        strict: bool,
    ) -> UdpRegistration {
        core.register(
            RequestRegistration::test_unchecked(request_id, timeout),
            test_addr(),
            strict,
        )
        .unwrap()
    }

    #[test]
    fn closed_core_rejects_registration_without_pending_state() {
        let core = Arc::new(UdpCore::new());
        core.close();

        let result = core.register(
            RequestRegistration::test_unchecked(42, Duration::from_secs(30)),
            test_addr(),
            false,
        );
        let Err(error) = result else {
            panic!("closed core accepted a registration");
        };

        assert!(matches!(*error, Error::Closed { .. }));
        assert_eq!(core.pending_counts(), (0, 0));
    }

    fn community_packet(request_id: i32, community: &'static [u8]) -> Bytes {
        use crate::message::CommunityMessage;
        use crate::pdu::Pdu;

        CommunityMessage::v2c(
            Bytes::from_static(community),
            Pdu::response(request_id, 0, 0, Vec::new()),
        )
        .unwrap()
        .encode()
        .unwrap()
    }

    #[tokio::test]
    async fn timeout_reports_elapsed_from_registration() {
        let core = Arc::new(UdpCore::new());
        let timeout = Duration::from_millis(50);
        let registration = register_v3(&core, 1, timeout, false);

        let err = core
            .wait_for_response(&registration, test_addr())
            .await
            .unwrap_err();
        match *err {
            Error::Timeout {
                elapsed, retries, ..
            } => {
                assert!(elapsed >= timeout);
                assert!(elapsed < Duration::from_secs(1));
                assert_eq!(retries, 0);
            }
            other => panic!("expected Timeout, got {other:?}"),
        }
        drop(registration);
        assert_eq!(core.pending_counts(), (0, 0));
    }

    #[tokio::test]
    async fn distinct_candidates_are_queued_until_validation() {
        let core = Arc::new(UdpCore::new());
        let addr = test_addr();
        let registration = register_v3(&core, 7, Duration::from_secs(30), false);
        let first = Bytes::from_static(b"first");

        assert!(core.deliver(7, first.clone(), addr));
        assert!(core.deliver(7, Bytes::from_static(b"second"), addr));
        assert_eq!(core.stats().correlated_datagrams, 2);
        assert_eq!(core.stats().discarded_datagrams, 0);
        let (data, _) = core.wait_for_response(&registration, addr).await.unwrap();
        assert_eq!(data, first);
    }

    #[tokio::test]
    async fn validator_rejection_keeps_registration_for_queued_candidate() {
        let core = Arc::new(UdpCore::new());
        let addr = test_addr();
        let registration = register_v3(&core, 8, Duration::from_secs(30), false);
        assert!(core.deliver(8, Bytes::from_static(b"reject"), addr));
        assert!(core.deliver(8, Bytes::from_static(b"accept"), addr));

        let accepted = core
            .wait_for_response_with(&registration, addr, |data, _| {
                if data.as_ref() == b"accept" {
                    Ok(Candidate::Accept(data))
                } else {
                    Ok(Candidate::Reject)
                }
            })
            .await
            .unwrap();
        assert_eq!(accepted.as_ref(), b"accept");
        assert_eq!(core.pending_counts(), (0, 0));
    }

    #[tokio::test]
    async fn alias_routes_delivery_to_owned_primary() {
        let core = Arc::new(UdpCore::new());
        let target = test_addr();
        let registration = core
            .register(
                RequestRegistration::test_unchecked(2, Duration::from_secs(5)).with_aliases([1]),
                target,
                false,
            )
            .unwrap();
        assert_eq!(core.pending_counts(), (1, 1));
        assert!(core.deliver(1, Bytes::from_static(b"late"), target));
        let (data, source) = core.wait_for_response(&registration, target).await.unwrap();
        assert_eq!(data.as_ref(), b"late");
        assert_eq!(source, target);
        drop(registration);
        assert_eq!(core.pending_counts(), (0, 0));
    }

    #[test]
    fn guard_drop_removes_primary_and_all_aliases() {
        let core = Arc::new(UdpCore::new());
        let registration = core
            .register(
                RequestRegistration::v3(30, Duration::from_secs(300)).with_aliases([10, 20, 25]),
                test_addr(),
                false,
            )
            .unwrap();
        assert_eq!(core.pending_counts(), (1, 3));
        drop(registration);
        assert_eq!(core.pending_counts(), (0, 0));
    }

    #[tokio::test]
    async fn collisions_do_not_modify_the_first_owner() {
        let core = Arc::new(UdpCore::new());
        let target = test_addr();
        let first = core
            .register(
                RequestRegistration::test_unchecked(20, Duration::from_secs(30))
                    .with_aliases([10, 11]),
                target,
                false,
            )
            .unwrap();

        for registration in [
            RequestRegistration::v3(20, Duration::from_secs(30)),
            RequestRegistration::v3(10, Duration::from_secs(30)),
            RequestRegistration::v3(30, Duration::from_secs(30)).with_aliases([11]),
        ] {
            let error = core
                .register(registration, target, false)
                .err()
                .expect("live primary or alias collision must fail");
            assert!(matches!(*error, Error::RequestIdInUse { .. }));
            assert_eq!(core.pending_counts(), (1, 2));
        }

        assert!(core.deliver(10, Bytes::from_static(b"first"), target));
        let (data, _) = core.wait_for_response(&first, target).await.unwrap();
        assert_eq!(data.as_ref(), b"first");
    }

    #[test]
    fn concurrent_collisions_allow_exactly_one_owner() {
        let target = test_addr();
        for (left, right) in [
            (
                RequestRegistration::v3(100, Duration::from_secs(30)),
                RequestRegistration::v3(100, Duration::from_secs(30)),
            ),
            (
                RequestRegistration::v3(100, Duration::from_secs(30)).with_aliases([90]),
                RequestRegistration::v3(90, Duration::from_secs(30)),
            ),
            (
                RequestRegistration::v3(100, Duration::from_secs(30)).with_aliases([90]),
                RequestRegistration::v3(200, Duration::from_secs(30)).with_aliases([90]),
            ),
        ] {
            let core = Arc::new(UdpCore::new());
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let spawn = |registration| {
                let core = core.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    core.register(registration, target, false)
                })
            };
            let left_task = spawn(left);
            let right_task = spawn(right);
            let left = left_task.join().unwrap();
            let right = right_task.join().unwrap();
            assert_ne!(left.is_ok(), right.is_ok());
            let error = left.err().or_else(|| right.err()).unwrap();
            assert!(matches!(*error, Error::RequestIdInUse { .. }));
        }
    }

    #[test]
    fn duplicate_aliases_are_reserved_once() {
        let core = Arc::new(UdpCore::new());
        let registration = core
            .register(
                RequestRegistration::v3(30, Duration::from_secs(30))
                    .with_aliases([10, 10, 30, 11, 10, 11]),
                test_addr(),
                false,
            )
            .unwrap();
        assert_eq!(registration.aliases, vec![10, 11]);
        assert_eq!(core.pending_counts(), (1, 2));
    }

    #[tokio::test]
    async fn cleanup_preserves_timeout_metadata_and_counts_once() {
        let core = Arc::new(UdpCore::new());
        let registration = register_v3(&core, 40, Duration::ZERO, false);
        std::thread::sleep(Duration::from_millis(2));

        core.cleanup_expired();
        core.cleanup_expired();
        let error = core
            .wait_for_response(&registration, test_addr())
            .await
            .unwrap_err();
        match *error {
            Error::Timeout {
                elapsed, retries, ..
            } => {
                assert!(elapsed >= Duration::from_millis(1));
                assert_eq!(retries, 0);
            }
            other => panic!("expected Timeout, got {other:?}"),
        }
        assert_eq!(core.stats().expired_registrations, 1);
    }

    #[test]
    fn unrepresentable_deadline_creates_no_pending_state() {
        let core = Arc::new(UdpCore::new());
        let error = core
            .register(
                RequestRegistration::v3(50, Duration::MAX).with_aliases([49]),
                test_addr(),
                false,
            )
            .err()
            .expect("unrepresentable deadline must fail");
        assert!(matches!(*error, Error::Config(_)));
        assert_eq!(core.pending_counts(), (0, 0));
    }

    #[tokio::test]
    async fn zero_deadline_does_not_accept_a_parked_candidate() {
        let core = Arc::new(UdpCore::new());
        let target = test_addr();
        let registration = register_v3(&core, 51, Duration::ZERO, false);

        assert!(!core.deliver(51, Bytes::from_static(b"candidate"), target));
        let error = core
            .wait_for_response(&registration, target)
            .await
            .unwrap_err();
        assert!(matches!(*error, Error::Timeout { .. }));
        let stats = core.stats();
        assert_eq!(stats.correlated_datagrams, 0);
        assert_eq!(stats.expired_registrations, 1);
        assert_eq!(stats.discarded_datagrams, 1);

        core.cleanup_expired();
        assert_eq!(core.stats().expired_registrations, 1);
    }

    #[tokio::test]
    async fn parked_candidate_is_not_validated_after_deadline() {
        let core = Arc::new(UdpCore::new());
        let target = test_addr();
        let registration = register_v3(&core, 52, Duration::from_millis(5), false);
        assert!(core.deliver(52, Bytes::from_static(b"candidate"), target));
        tokio::time::sleep(Duration::from_millis(10)).await;

        let mut validations = 0;
        let error = core
            .wait_for_response_with(&registration, target, |data, source| {
                validations += 1;
                Ok(Candidate::Accept((data, source)))
            })
            .await
            .unwrap_err();
        assert!(matches!(*error, Error::Timeout { .. }));
        assert_eq!(validations, 0);
        assert_eq!(core.stats().expired_registrations, 1);
    }

    #[test]
    fn expired_alias_cleanup_does_not_remove_live_primary() {
        let core = Arc::new(UdpCore::new());
        let target = test_addr();
        let registration = core
            .register(
                RequestRegistration::v3(2, Duration::ZERO).with_aliases([1]),
                target,
                false,
            )
            .unwrap();
        core.cleanup_expired();
        assert_eq!(core.pending_counts(), (0, 0));
        assert_eq!(core.stats().expired_registrations, 1);
        drop(registration);
    }

    #[tokio::test]
    async fn community_rejection_is_non_consuming_and_preserves_deadline() {
        let core = Arc::new(UdpCore::new());
        let target = test_addr();
        let other = "127.0.0.2:161".parse().unwrap();
        let request_id = 500;
        let registration = core
            .register(
                RequestRegistration::community(
                    request_id,
                    Duration::from_secs(5),
                    crate::CommunityVersion::V2c,
                    Bytes::from_static(b"public"),
                    CommunityResponsePolicy::Exact,
                ),
                target,
                false,
            )
            .unwrap();
        let (notify, original_deadline) = {
            let pending = core.shard(request_id).pending.lock().unwrap();
            let PendingEntry::Slot(slot) = pending.get(&request_id).unwrap() else {
                panic!("expected pending slot");
            };
            (slot.owner.notify.clone(), slot.owner.deadline)
        };

        assert!(!core.deliver(request_id, community_packet(request_id, b"wrong"), other,));
        assert!(
            tokio::time::timeout(Duration::from_millis(10), notify.notified())
                .await
                .is_err()
        );
        {
            let pending = core.shard(request_id).pending.lock().unwrap();
            let PendingEntry::Slot(slot) = pending.get(&request_id).unwrap() else {
                panic!("expected retained pending slot");
            };
            assert_eq!(slot.owner.deadline, original_deadline);
            assert!(slot.responses.is_empty());
        }

        assert!(core.deliver(request_id, community_packet(request_id, b"public"), target,));
        let (accepted, _) = core.wait_for_response(&registration, target).await.unwrap();
        assert_eq!(
            super::super::extract_community_identity(&accepted)
                .unwrap()
                .1,
            b"public"
        );
    }

    #[tokio::test]
    async fn strict_suffix_rejection_preserves_registration_and_deadline() {
        let core = Arc::new(UdpCore::new());
        let target = test_addr();
        let request_id = 501;
        let prior_request_id = 500;
        let registration = core
            .register(
                RequestRegistration::community(
                    request_id,
                    Duration::from_secs(5),
                    crate::CommunityVersion::V2c,
                    Bytes::from_static(b"public"),
                    CommunityResponsePolicy::Exact,
                )
                .with_decode_policy(crate::message::DecodePolicy::Strict)
                .with_aliases([prior_request_id]),
                target,
                false,
            )
            .unwrap();
        let original_deadline = registration.owner.deadline;
        let clean = community_packet(request_id, b"public");
        let mut suffixed = community_packet(prior_request_id, b"public").to_vec();
        suffixed.extend_from_slice(b"suffix");

        assert!(!core.deliver(prior_request_id, Bytes::from(suffixed), target));
        {
            let pending = core.shard(request_id).pending.lock().unwrap();
            let PendingEntry::Slot(slot) = pending.get(&request_id).unwrap() else {
                panic!("expected retained pending slot");
            };
            assert!(Arc::ptr_eq(&slot.owner, &registration.owner));
            assert_eq!(slot.owner.deadline, original_deadline);
            assert!(slot.responses.is_empty());
        }
        {
            let pending = core.shard(prior_request_id).pending.lock().unwrap();
            let PendingEntry::Alias { primary, owner } = pending.get(&prior_request_id).unwrap()
            else {
                panic!("expected retained retry alias");
            };
            assert_eq!(*primary, request_id);
            assert!(Arc::ptr_eq(owner, &registration.owner));
            assert_eq!(owner.deadline, original_deadline);
        }
        assert_eq!(core.pending_counts(), (1, 1));
        assert_eq!(core.stats().discarded_datagrams, 1);
        assert_eq!(core.stats().expired_registrations, 0);

        assert!(core.deliver(request_id, clean.clone(), target));
        let (accepted, source) = core.wait_for_response(&registration, target).await.unwrap();
        assert_eq!(accepted, clean);
        assert_eq!(source, target);
        assert_eq!(core.pending_counts(), (0, 1));
        assert_eq!(core.stats().correlated_datagrams, 1);
        assert_eq!(core.stats().expired_registrations, 0);
        drop(registration);
        assert_eq!(core.pending_counts(), (0, 0));
    }

    #[test]
    fn strict_source_rejection_keeps_owned_slot() {
        let core = Arc::new(UdpCore::new());
        let target = test_addr();
        let other = "127.0.0.2:161".parse().unwrap();
        let _registration = register_v3(&core, 2, Duration::from_secs(5), true);
        assert!(!core.deliver(2, Bytes::from_static(b"spoof"), other));
        assert!(core.deliver(2, Bytes::from_static(b"real"), target));
    }
}
