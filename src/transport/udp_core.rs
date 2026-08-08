//! Core infrastructure for UDP response correlation.
//!
//! Provides a sharded pending request map with per-request wakeup.

use bytes::Bytes;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Notify;

use super::{CorrelationResult, RequestRegistration, ResponseCorrelation};
use crate::error::{Error, Result};

const SHARDS: usize = 64;

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
    /// Responses successfully matched to a pending request.
    delivered: AtomicU64,
    /// Requests that timed out without receiving a response.
    expired: AtomicU64,
    /// Responses with no matching pending request (late, duplicate, or
    /// never registered).
    unmatched: AtomicU64,
    /// Datagrams from which no request ID could be extracted.
    malformed: AtomicU64,
}

/// Transport-level statistics.
///
/// Returned by [`UdpTransport::stats()`](super::UdpTransport::stats).
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct TransportStats {
    /// Responses successfully matched to a pending request.
    pub delivered: u64,
    /// Requests that timed out without receiving a response.
    pub expired: u64,
    /// Responses with no matching pending request (late, duplicate, or
    /// never registered).
    pub unmatched: u64,
    /// Datagrams from which no request ID could be extracted.
    pub malformed: u64,
}

struct Shard {
    pending: Mutex<HashMap<i32, PendingEntry>>,
}

struct RegistrationIdentity;

struct ResponseSlot {
    response: Option<(Bytes, SocketAddr)>,
    owner: Arc<RegistrationIdentity>,
    /// When the request was registered; used to report the real elapsed time
    /// on timeout instead of deriving it from the deadline.
    registered_at: Instant,
    deadline: Instant,
    notify: Arc<Notify>,
    /// Configured target, used by conditional community rewrite policy.
    target_source: SocketAddr,
    /// When true, only responses from exactly the target are delivered.
    strict_source: bool,
    correlation: ResponseCorrelation,
}

enum PendingEntry {
    Slot(ResponseSlot),
    /// Retransmission window alias: datagrams keyed by a prior attempt's
    /// msgID are delivered to the current attempt's slot.
    Alias {
        primary: i32,
        deadline: Instant,
        owner: Arc<RegistrationIdentity>,
    },
}

/// Owns one UDP correlation registration and removes only its entries on drop.
pub(crate) struct UdpRegistration {
    core: Arc<UdpCore>,
    primary: i32,
    aliases: Vec<i32>,
    owner: Arc<RegistrationIdentity>,
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
                delivered: AtomicU64::new(0),
                expired: AtomicU64::new(0),
                unmatched: AtomicU64::new(0),
                malformed: AtomicU64::new(0),
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
                    PendingEntry::Slot(slot) => Some(slot.notify.clone()),
                    PendingEntry::Alias { .. } => None,
                })
                .collect();
            for notify in notifies {
                notify.notify_one();
            }
        }
    }

    /// Get the shard for a given request ID.
    fn shard(&self, request_id: i32) -> &Shard {
        &self.shards[request_id as usize % SHARDS]
    }

    /// Register a pending request and return its cancellation cleanup owner.
    pub fn register(
        self: &Arc<Self>,
        registration: RequestRegistration,
        target_source: SocketAddr,
        strict_source: bool,
    ) -> UdpRegistration {
        let primary = registration.request_id;
        let timeout = registration.timeout;
        let aliases = registration.aliases().to_vec();
        let owner = Arc::new(RegistrationIdentity);
        let now = Instant::now();
        let slot = ResponseSlot {
            response: None,
            owner: owner.clone(),
            registered_at: now,
            deadline: now + timeout,
            notify: Arc::new(Notify::new()),
            target_source,
            strict_source,
            correlation: registration.correlation,
        };
        self.shard(primary)
            .pending
            .lock()
            .unwrap()
            .insert(primary, PendingEntry::Slot(slot));

        for alias in &aliases {
            let carried = {
                let mut pending = self.shard(*alias).pending.lock().unwrap();
                let carried = match pending.remove(alias) {
                    Some(PendingEntry::Slot(slot)) => slot.response,
                    _ => None,
                };
                pending.insert(
                    *alias,
                    PendingEntry::Alias {
                        primary,
                        deadline: now + timeout,
                        owner: owner.clone(),
                    },
                );
                carried
            };
            if let Some((data, source)) = carried {
                self.deliver_owned(primary, &owner, data, source);
            }
        }

        UdpRegistration {
            core: self.clone(),
            primary,
            aliases,
            owner,
        }
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

    fn deliver_owned(
        &self,
        request_id: i32,
        owner: &Arc<RegistrationIdentity>,
        data: Bytes,
        source: SocketAddr,
    ) -> bool {
        self.deliver_to(request_id, Some(owner), request_id, data, source)
    }

    fn deliver_to(
        &self,
        target_id: i32,
        expected_owner: Option<&Arc<RegistrationIdentity>>,
        request_id: i32,
        data: Bytes,
        source: SocketAddr,
    ) -> bool {
        let shard = self.shard(target_id);
        let mut pending = shard.pending.lock().unwrap();

        if let Some(PendingEntry::Slot(slot)) = pending.get_mut(&target_id)
            && expected_owner.is_none_or(|owner| Arc::ptr_eq(owner, &slot.owner))
        {
            let source_is_target = slot.target_source == source;
            if slot.strict_source && !source_is_target {
                // Leave the slot and original deadline intact.
                drop(pending);
                self.stats.unmatched.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(target: "async_snmp::transport::udp", { request_id, %source }, "response rejected by strict source correlation");
                return false;
            }
            match slot.correlation.evaluate(&data, source_is_target) {
                CorrelationResult::Reject => {
                    drop(pending);
                    self.stats.unmatched.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!(target: "async_snmp::transport::udp", { request_id, %source }, "response rejected by community correlation");
                    return false;
                }
                CorrelationResult::AcceptedCommunityMismatch => {
                    tracing::warn!(target: "async_snmp::transport::udp", { request_id, %source }, "accepted rewritten response community");
                }
                CorrelationResult::Match => {}
            }
            if slot.response.is_some() {
                // A response is already waiting to be consumed for this
                // request-id. Ignore the duplicate datagram rather than
                // overwriting the pending response and double-counting.
                drop(pending);
                self.stats.unmatched.fetch_add(1, Ordering::Relaxed);
                return false;
            }
            slot.response = Some((data, source));
            let notify = slot.notify.clone();
            drop(pending);
            notify.notify_one();
            self.stats.delivered.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        self.stats.unmatched.fetch_add(1, Ordering::Relaxed);
        false
    }

    /// Record a datagram from which no request ID could be extracted.
    pub(crate) fn note_malformed(&self) {
        self.stats.malformed.fetch_add(1, Ordering::Relaxed);
    }

    /// Wait for a response to arrive for the given request.
    ///
    /// Returns the response data and source address, or an error on timeout
    /// or if the slot was already cancelled/expired.
    pub async fn wait_for_response(
        &self,
        registration: &UdpRegistration,
        target: SocketAddr,
    ) -> Result<(Bytes, SocketAddr)> {
        let request_id = registration.primary;
        let shard = self.shard(request_id);

        loop {
            // Single lock: check for response, or grab notify + deadline for waiting.
            let (notify, deadline, registered_at) = {
                let mut pending = shard.pending.lock().unwrap();
                if let Some(PendingEntry::Slot(slot)) = pending.get_mut(&request_id)
                    && Arc::ptr_eq(&slot.owner, &registration.owner)
                {
                    if let Some(response) = slot.response.take() {
                        pending.remove(&request_id);
                        return Ok(response);
                    }
                    (slot.notify.clone(), slot.deadline, slot.registered_at)
                } else if self.closed.load(Ordering::Acquire) {
                    tracing::debug!(target: "async_snmp::transport::udp", { request_id, %target }, "transport shut down (slot missing)");
                    return Err(Error::Closed { target }.boxed());
                } else {
                    tracing::debug!(target: "async_snmp::transport::udp", { request_id, %target, elapsed = ?Duration::ZERO }, "transport timeout (slot missing)");
                    return Err(Error::Timeout {
                        target,
                        elapsed: Duration::ZERO,
                        retries: 0,
                    }
                    .boxed());
                }
            };

            // Checked after the response lookup so a response delivered
            // before shutdown is still returned.
            if self.closed.load(Ordering::Acquire) {
                tracing::debug!(target: "async_snmp::transport::udp", { request_id, %target }, "transport shut down");
                return Err(Error::Closed { target }.boxed());
            }

            let now = Instant::now();
            if now >= deadline {
                self.stats.expired.fetch_add(1, Ordering::Relaxed);
                let elapsed = now.saturating_duration_since(registered_at);
                tracing::debug!(target: "async_snmp::transport::udp", { request_id, %target, ?elapsed }, "transport timeout");
                return Err(Error::Timeout {
                    target,
                    elapsed,
                    retries: 0,
                }
                .boxed());
            }

            tokio::select! {
                () = notify.notified() => {
                    // Response delivered, loop back to retrieve it
                }
                () = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {
                    // Timeout reached, loop will detect and return error
                }
            }
        }
    }

    /// Snapshot current stats.
    pub fn stats(&self) -> TransportStats {
        TransportStats {
            delivered: self.stats.delivered.load(Ordering::Relaxed),
            expired: self.stats.expired.load(Ordering::Relaxed),
            unmatched: self.stats.unmatched.load(Ordering::Relaxed),
            malformed: self.stats.malformed.load(Ordering::Relaxed),
        }
    }

    fn remove_owned(&self, request_id: i32, owner: &Arc<RegistrationIdentity>) {
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
        let mut removed = 0u64;
        for shard in self.shards.iter() {
            let mut pending = shard.pending.lock().unwrap();
            pending.retain(|_, entry| match entry {
                PendingEntry::Slot(slot) => {
                    let keep = slot.deadline > now;
                    if !keep {
                        removed += 1;
                    }
                    keep
                }
                PendingEntry::Alias { deadline, .. } => *deadline > now,
            });
        }
        if removed > 0 {
            self.stats.expired.fetch_add(removed, Ordering::Relaxed);
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
            RequestRegistration::v3(request_id, timeout),
            test_addr(),
            strict,
        )
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
    async fn duplicate_delivery_is_ignored() {
        let core = Arc::new(UdpCore::new());
        let addr = test_addr();
        let registration = register_v3(&core, 7, Duration::from_secs(30), false);
        let first = Bytes::from_static(b"first");

        assert!(core.deliver(7, first.clone(), addr));
        assert!(!core.deliver(7, Bytes::from_static(b"second"), addr));
        assert_eq!(core.stats().delivered, 1);
        assert_eq!(core.stats().unmatched, 1);
        let (data, _) = core.wait_for_response(&registration, addr).await.unwrap();
        assert_eq!(data, first);
    }

    #[tokio::test]
    async fn alias_routes_delivery_to_owned_primary() {
        let core = Arc::new(UdpCore::new());
        let target = test_addr();
        let registration = core.register(
            RequestRegistration::v3(2, Duration::from_secs(5)).with_aliases([1]),
            target,
            false,
        );
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
        let registration = core.register(
            RequestRegistration::v3(30, Duration::from_secs(300)).with_aliases([10, 20, 25]),
            test_addr(),
            false,
        );
        assert_eq!(core.pending_counts(), (1, 3));
        drop(registration);
        assert_eq!(core.pending_counts(), (0, 0));
    }

    #[tokio::test]
    async fn stale_guard_and_alias_cannot_affect_replacement() {
        let core = Arc::new(UdpCore::new());
        let target = test_addr();
        let stale = core.register(
            RequestRegistration::v3(2, Duration::from_secs(30)).with_aliases([1]),
            target,
            false,
        );
        let replacement = register_v3(&core, 2, Duration::from_secs(30), false);

        assert!(!core.deliver(1, Bytes::from_static(b"stale"), target));
        drop(stale);
        assert_eq!(core.pending_counts(), (1, 0));
        assert!(core.deliver(2, Bytes::from_static(b"current"), target));
        let (data, _) = core.wait_for_response(&replacement, target).await.unwrap();
        assert_eq!(data.as_ref(), b"current");
    }

    #[test]
    fn expired_alias_cleanup_does_not_remove_live_primary() {
        let core = Arc::new(UdpCore::new());
        let target = test_addr();
        let registration = core.register(
            RequestRegistration::v3(2, Duration::ZERO).with_aliases([1]),
            target,
            false,
        );
        core.cleanup_expired();
        assert_eq!(core.pending_counts(), (0, 0));
        assert_eq!(core.stats().expired, 1);
        drop(registration);
    }

    #[tokio::test]
    async fn community_rejection_is_non_consuming_and_preserves_deadline() {
        let core = Arc::new(UdpCore::new());
        let target = test_addr();
        let other = "127.0.0.2:161".parse().unwrap();
        let request_id = 500;
        let registration = core.register(
            RequestRegistration::community(
                request_id,
                Duration::from_secs(5),
                crate::Version::V2c,
                Bytes::from_static(b"public"),
                CommunityResponsePolicy::Exact,
            ),
            target,
            false,
        );
        let (notify, original_deadline) = {
            let pending = core.shard(request_id).pending.lock().unwrap();
            let PendingEntry::Slot(slot) = pending.get(&request_id).unwrap() else {
                panic!("expected pending slot");
            };
            (slot.notify.clone(), slot.deadline)
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
            assert_eq!(slot.deadline, original_deadline);
            assert!(slot.response.is_none());
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
