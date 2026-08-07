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

struct ResponseSlot {
    response: Option<(Bytes, SocketAddr)>,
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
    },
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

    /// Register a pending request with its target and correlation metadata.
    pub fn register(
        &self,
        registration: RequestRegistration,
        target_source: SocketAddr,
        strict_source: bool,
    ) {
        let shard = self.shard(registration.request_id);
        let now = Instant::now();
        let slot = ResponseSlot {
            response: None,
            registered_at: now,
            deadline: now + registration.timeout,
            notify: Arc::new(Notify::new()),
            target_source,
            strict_source,
            correlation: registration.correlation,
        };
        shard
            .pending
            .lock()
            .unwrap()
            .insert(registration.request_id, PendingEntry::Slot(slot));
    }

    /// Route future deliveries for `alias_id` to the slot registered under
    /// `primary_id`. Replaces any existing entry for `alias_id`; a response
    /// already parked there is forwarded to the primary slot. Aliases are one
    /// hop: the caller re-points every prior ID at the newest primary, so an
    /// alias always names a slot, never another alias.
    ///
    /// Aliases are never explicitly unregistered. This is safe only because
    /// every operation exit path removes its primary slot (consume,
    /// timeout-unregister, send-failure-unregister, close), so a lingering
    /// alias always ends up naming a dead slot and is reclaimed by
    /// `cleanup_expired` once its own deadline passes. If a primary slot
    /// could ever outlive its operation, aliases would need explicit cleanup
    /// too.
    pub fn register_alias(&self, alias_id: i32, primary_id: i32, timeout: Duration) {
        if alias_id == primary_id {
            return;
        }
        let carried = {
            let mut pending = self.shard(alias_id).pending.lock().unwrap();
            let carried = match pending.remove(&alias_id) {
                Some(PendingEntry::Slot(slot)) => slot.response,
                _ => None,
            };
            pending.insert(
                alias_id,
                PendingEntry::Alias {
                    primary: primary_id,
                    deadline: Instant::now() + timeout,
                },
            );
            carried
        };
        if let Some((data, source)) = carried {
            self.deliver(primary_id, data, source);
        }
    }

    /// Deliver a response to its waiting request.
    ///
    /// Returns `true` if the slot existed and the response was stored,
    /// `false` if there was no matching pending request.
    pub fn deliver(&self, request_id: i32, data: Bytes, source: SocketAddr) -> bool {
        let target_id = {
            let pending = self.shard(request_id).pending.lock().unwrap();
            match pending.get(&request_id) {
                Some(PendingEntry::Alias { primary, .. }) => *primary,
                _ => request_id,
            }
        };

        let shard = self.shard(target_id);
        let mut pending = shard.pending.lock().unwrap();

        if let Some(PendingEntry::Slot(slot)) = pending.get_mut(&target_id) {
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
        request_id: i32,
        target: SocketAddr,
    ) -> Result<(Bytes, SocketAddr)> {
        let shard = self.shard(request_id);

        loop {
            // Single lock: check for response, or grab notify + deadline for waiting.
            let (notify, deadline, registered_at) = {
                let mut pending = shard.pending.lock().unwrap();
                if let Some(PendingEntry::Slot(slot)) = pending.get_mut(&request_id) {
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
                self.unregister(request_id);
                tracing::debug!(target: "async_snmp::transport::udp", { request_id, %target }, "transport shut down");
                return Err(Error::Closed { target }.boxed());
            }

            let now = Instant::now();
            if now >= deadline {
                self.unregister(request_id);
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

    /// Remove a pending request slot.
    ///
    /// Called for cancellation or cleanup.
    pub fn unregister(&self, request_id: i32) {
        let shard = self.shard(request_id);
        shard.pending.lock().unwrap().remove(&request_id);
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
    use super::*;

    fn test_addr() -> SocketAddr {
        "127.0.0.1:161".parse().unwrap()
    }

    fn register_v3(core: &UdpCore, request_id: i32, timeout: Duration, strict: bool) {
        core.register(
            RequestRegistration::v3(request_id, timeout),
            test_addr(),
            strict,
        );
    }

    // A timed-out wait reports elapsed based on the registration time, not a
    // hardcoded 1s offset from the deadline, and does not panic when the
    // deadline is close to the Instant epoch (short timeout).
    #[tokio::test]
    async fn timeout_reports_elapsed_from_registration() {
        let core = UdpCore::new();
        let addr = test_addr();
        let timeout = Duration::from_millis(50);
        register_v3(&core, 1, timeout, false);

        let err = core.wait_for_response(1, addr).await.unwrap_err();
        match *err {
            Error::Timeout {
                elapsed, retries, ..
            } => {
                // Elapsed reflects the configured timeout, not deadline - 1s.
                assert!(
                    elapsed >= timeout,
                    "elapsed {elapsed:?} should be at least the timeout {timeout:?}"
                );
                assert!(
                    elapsed < Duration::from_secs(1),
                    "elapsed {elapsed:?} should not be derived from a 1s offset"
                );
                assert_eq!(retries, 0);
            }
            other => panic!("expected Timeout, got {other:?}"),
        }
    }

    // A duplicate datagram for a request-id whose response has not yet been
    // consumed is ignored: it neither overwrites the pending response nor
    // increments the delivered counter a second time.
    #[tokio::test]
    async fn duplicate_delivery_is_ignored() {
        let core = UdpCore::new();
        let addr = test_addr();
        register_v3(&core, 7, Duration::from_secs(30), false);

        let first = Bytes::from_static(b"first");
        let dup = Bytes::from_static(b"second");

        assert!(core.deliver(7, first.clone(), addr));
        // Second datagram for the same request-id, response still unconsumed.
        assert!(!core.deliver(7, dup, addr));

        let stats = core.stats();
        assert_eq!(stats.delivered, 1, "duplicate must not be counted");
        assert_eq!(stats.unmatched, 1, "duplicate counts as unmatched");

        let (data, _) = core.wait_for_response(7, addr).await.unwrap();
        assert_eq!(data, first, "original response must not be overwritten");
    }

    #[tokio::test]
    async fn alias_routes_delivery_to_primary_slot() {
        let core = UdpCore::new();
        let target: SocketAddr = "127.0.0.1:161".parse().unwrap();
        register_v3(&core, 2, Duration::from_secs(5), false);
        core.register_alias(1, 2, Duration::from_secs(5));
        assert!(core.deliver(1, Bytes::from_static(b"late"), target));
        let (data, source) = core.wait_for_response(2, target).await.unwrap();
        assert_eq!(data.as_ref(), b"late");
        assert_eq!(source, target);
    }

    #[tokio::test]
    async fn alias_replacement_repoints_to_newest_primary() {
        let core = UdpCore::new();
        let target: SocketAddr = "127.0.0.1:161".parse().unwrap();
        register_v3(&core, 3, Duration::from_secs(5), false);
        core.register_alias(1, 2, Duration::from_secs(5));
        core.register_alias(1, 3, Duration::from_secs(5));
        core.register_alias(2, 3, Duration::from_secs(5));
        assert!(core.deliver(1, Bytes::from_static(b"a1"), target));
        let (data, _) = core.wait_for_response(3, target).await.unwrap();
        assert_eq!(data.as_ref(), b"a1");
    }

    #[test]
    fn alias_to_missing_primary_counts_unmatched() {
        let core = UdpCore::new();
        let target: SocketAddr = "127.0.0.1:161".parse().unwrap();
        core.register_alias(1, 99, Duration::from_secs(5));
        assert!(!core.deliver(1, Bytes::from_static(b"x"), target));
        assert_eq!(core.stats().unmatched, 1);
    }

    #[test]
    fn expired_alias_is_cleaned_up() {
        let core = UdpCore::new();
        let target: SocketAddr = "127.0.0.1:161".parse().unwrap();
        register_v3(&core, 2, Duration::from_secs(5), false);
        core.register_alias(1, 2, Duration::ZERO);
        core.cleanup_expired();
        // The expired alias is gone, but the still-live primary slot is not
        // touched, and removing an alias must not count toward the
        // requests-timed-out stat.
        assert!(!core.deliver(1, Bytes::from_static(b"x"), target));
        assert!(core.deliver(2, Bytes::from_static(b"x"), target));
        assert_eq!(core.stats().expired, 0);
    }

    #[tokio::test]
    async fn alias_registration_forwards_parked_response_to_primary() {
        let core = UdpCore::new();
        let target: SocketAddr = "127.0.0.1:161".parse().unwrap();
        register_v3(&core, 2, Duration::from_secs(5), false);
        assert!(core.deliver(2, Bytes::from_static(b"parked"), target));
        register_v3(&core, 3, Duration::from_secs(5), false);
        core.register_alias(2, 3, Duration::from_secs(5));
        let (data, _) = core.wait_for_response(3, target).await.unwrap();
        assert_eq!(data.as_ref(), b"parked");
    }

    // Same-shard variant of `alias_routes_delivery_to_primary_slot`: alias 2
    // and primary 66 land in the same shard (SHARDS=64), pinning the
    // release-then-reacquire of a single shard mutex inside `deliver`.
    #[tokio::test]
    async fn alias_routes_delivery_to_primary_slot_same_shard() {
        let core = UdpCore::new();
        let target: SocketAddr = "127.0.0.1:161".parse().unwrap();
        register_v3(&core, 66, Duration::from_secs(5), false);
        core.register_alias(2, 66, Duration::from_secs(5));
        assert!(core.deliver(2, Bytes::from_static(b"late"), target));
        let (data, source) = core.wait_for_response(66, target).await.unwrap();
        assert_eq!(data.as_ref(), b"late");
        assert_eq!(source, target);
    }

    fn community_packet(request_id: i32, community: &'static [u8]) -> Bytes {
        use crate::message::CommunityMessage;
        use crate::pdu::{Pdu, PduType};

        CommunityMessage::v2c(
            Bytes::from_static(community),
            Pdu {
                pdu_type: PduType::Response,
                request_id,
                error_status: 0,
                error_index: 0,
                varbinds: Vec::new(),
            },
        )
        .encode()
    }

    #[tokio::test]
    async fn community_policy_source_matrix_and_non_consuming_rejection() {
        use super::super::CommunityResponsePolicy;

        let target = test_addr();
        let other: SocketAddr = "127.0.0.2:161".parse().unwrap();
        let policies = [
            CommunityResponsePolicy::Exact,
            CommunityResponsePolicy::AllowMismatchFromTarget,
            CommunityResponsePolicy::AllowMismatchFromAnySource,
        ];
        let mut request_id = 100;

        for strict in [false, true] {
            for policy in policies {
                for source_is_target in [false, true] {
                    for community_matches in [false, true] {
                        request_id += 1;
                        let core = UdpCore::new();
                        core.register(
                            RequestRegistration::community(
                                request_id,
                                Duration::from_secs(5),
                                crate::Version::V2c,
                                Bytes::from_static(b"public"),
                                policy,
                            ),
                            target,
                            strict,
                        );
                        let source = if source_is_target { target } else { other };
                        let packet = community_packet(
                            request_id,
                            if community_matches {
                                b"public"
                            } else {
                                b"rewritten"
                            },
                        );
                        let expected = (!strict || source_is_target)
                            && (community_matches
                                || policy == CommunityResponsePolicy::AllowMismatchFromAnySource
                                || (policy == CommunityResponsePolicy::AllowMismatchFromTarget
                                    && source_is_target));
                        assert_eq!(
                            core.deliver(request_id, packet, source),
                            expected,
                            "strict={strict} policy={policy:?} source_is_target={source_is_target} community_matches={community_matches}"
                        );
                        assert_eq!(core.stats().delivered, u64::from(expected));
                        assert_eq!(core.stats().unmatched, u64::from(!expected));
                    }
                }
            }
        }

        let core = UdpCore::new();
        let request_id = 500;
        core.register(
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
                .is_err(),
            "rejection must not wake the waiter"
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
        let (accepted, _) = core.wait_for_response(request_id, target).await.unwrap();
        assert_eq!(
            super::super::extract_community_identity(&accepted)
                .unwrap()
                .1,
            b"public"
        );
    }

    #[test]
    fn alias_respects_primary_expected_source() {
        let core = UdpCore::new();
        let target: SocketAddr = "127.0.0.1:161".parse().unwrap();
        let other: SocketAddr = "127.0.0.2:161".parse().unwrap();
        register_v3(&core, 2, Duration::from_secs(5), true);
        core.register_alias(1, 2, Duration::from_secs(5));
        assert!(!core.deliver(1, Bytes::from_static(b"spoof"), other));
        assert!(core.deliver(1, Bytes::from_static(b"real"), target));
    }
}
