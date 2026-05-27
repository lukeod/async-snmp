//! Engine discovery and time synchronization (RFC 3414 Section 4).
//!
//! `SNMPv3` requires knowing the authoritative engine's ID, boots counter,
//! and time value before authenticated messages can be sent. This module
//! provides:
//!
//! - `EngineCache`: Thread-safe cache of discovered engine state
//! - `EngineState`: Per-engine state (ID, boots, time)
//! - Discovery response parsing
//!
//! # Discovery Flow
//!
//! 1. Client sends discovery request (noAuthNoPriv, empty engine ID)
//! 2. Agent responds with Report PDU containing usmStatsUnknownEngineIDs
//! 3. Response's USM params contain the engine ID, boots, and time
//! 4. Client caches these values for subsequent authenticated requests
//!
//! # Time Synchronization
//!
//! Per RFC 3414 Section 2.3, a non-authoritative engine (client) maintains:
//! - `snmpEngineBoots`: Boot counter from authoritative engine
//! - `snmpEngineTime`: Time value from authoritative engine
//! - `latestReceivedEngineTime`: Highest time received (anti-replay)
//!
//! The time window is 150 seconds. Messages outside this window are rejected.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::error::{Error, Result};
use crate::v3::UsmSecurityParams;

/// Time window in seconds (RFC 3414 Section 2.2.3).
pub const TIME_WINDOW: u32 = 150;

/// Maximum valid snmpEngineTime value (RFC 3414 Section 2.2.1).
///
/// Per RFC 3414, snmpEngineTime is a 31-bit value (0..2,147,483,647).
/// When the value reaches this maximum, the authoritative engine should
/// reset it to zero and increment snmpEngineBoots.
pub const MAX_ENGINE_TIME: u32 = 2_147_483_647;

/// Default msgMaxSize for UDP transport (65535 - 20 IPv4 - 8 UDP = 65507).
pub const DEFAULT_MSG_MAX_SIZE: u32 = 65507;

/// Compute engine boots and time from a base boots value and total elapsed
/// seconds since engine start.
///
/// Per RFC 3414 Section 2.3, each time the elapsed seconds reaches
/// `MAX_ENGINE_TIME` (2^31-1), boots increments by one and time wraps to zero.
/// The boots value is capped at `MAX_ENGINE_TIME` (the "latched" state per
/// RFC 3414 Section 2.2.3).
#[must_use]
pub fn compute_engine_boots_time(boots_base: u32, total_elapsed_secs: u64) -> (u32, u32) {
    let max = u64::from(MAX_ENGINE_TIME);
    let additional_boots = total_elapsed_secs / max;
    let current_time = (total_elapsed_secs % max) as u32;
    let boots = (u64::from(boots_base) + additional_boots).min(max) as u32;
    (boots, current_time)
}

/// USM statistics OIDs used in Report PDUs.
pub mod report_oids {
    use crate::Oid;
    use crate::oid;

    /// 1.3.6.1.6.3.15.1.1.1.0 - usmStatsUnsupportedSecLevels
    #[must_use]
    pub fn unsupported_sec_levels() -> Oid {
        oid!(1, 3, 6, 1, 6, 3, 15, 1, 1, 1, 0)
    }

    /// 1.3.6.1.6.3.15.1.1.2.0 - usmStatsNotInTimeWindows
    #[must_use]
    pub fn not_in_time_windows() -> Oid {
        oid!(1, 3, 6, 1, 6, 3, 15, 1, 1, 2, 0)
    }

    /// 1.3.6.1.6.3.15.1.1.3.0 - usmStatsUnknownUserNames
    #[must_use]
    pub fn unknown_user_names() -> Oid {
        oid!(1, 3, 6, 1, 6, 3, 15, 1, 1, 3, 0)
    }

    /// 1.3.6.1.6.3.15.1.1.4.0 - usmStatsUnknownEngineIDs
    #[must_use]
    pub fn unknown_engine_ids() -> Oid {
        oid!(1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0)
    }

    /// 1.3.6.1.6.3.15.1.1.5.0 - usmStatsWrongDigests
    #[must_use]
    pub fn wrong_digests() -> Oid {
        oid!(1, 3, 6, 1, 6, 3, 15, 1, 1, 5, 0)
    }

    /// 1.3.6.1.6.3.15.1.1.6.0 - usmStatsDecryptionErrors
    #[must_use]
    pub fn decryption_errors() -> Oid {
        oid!(1, 3, 6, 1, 6, 3, 15, 1, 1, 6, 0)
    }
}

/// Discovered engine state.
#[derive(Debug, Clone)]
pub struct EngineState {
    /// Authoritative engine ID
    pub engine_id: Bytes,
    /// Engine boot count
    pub engine_boots: u32,
    /// Engine time at last sync
    pub engine_time: u32,
    /// Local time when `engine_time` was received
    pub synced_at: Instant,
    /// Latest received engine time (for anti-replay, RFC 3414 Section 2.3)
    pub latest_received_engine_time: u32,
    /// Maximum message size the remote engine can accept (from msgMaxSize header).
    pub msg_max_size: u32,
}

impl EngineState {
    /// Create new engine state from discovery response.
    pub fn new(engine_id: Bytes, engine_boots: u32, engine_time: u32) -> Self {
        Self {
            engine_id,
            engine_boots,
            engine_time,
            synced_at: Instant::now(),
            latest_received_engine_time: engine_time,
            msg_max_size: DEFAULT_MSG_MAX_SIZE,
        }
    }

    /// Create with explicit msgMaxSize from agent's header.
    pub fn with_msg_max_size(
        engine_id: Bytes,
        engine_boots: u32,
        engine_time: u32,
        msg_max_size: u32,
    ) -> Self {
        Self {
            engine_id,
            engine_boots,
            engine_time,
            synced_at: Instant::now(),
            latest_received_engine_time: engine_time,
            msg_max_size,
        }
    }

    /// Create with msgMaxSize capped to session maximum.
    ///
    /// Non-compliant agents may advertise msgMaxSize values larger than they
    /// can handle. This caps the value to a known safe session limit.
    pub fn with_msg_max_size_capped(
        engine_id: Bytes,
        engine_boots: u32,
        engine_time: u32,
        reported_msg_max_size: u32,
        session_max: u32,
    ) -> Self {
        let msg_max_size = if reported_msg_max_size > session_max {
            tracing::debug!(target: "async_snmp::v3", { reported = reported_msg_max_size, session_max = session_max }, "capping msgMaxSize to session limit");
            session_max
        } else {
            reported_msg_max_size
        };

        Self {
            engine_id,
            engine_boots,
            engine_time,
            synced_at: Instant::now(),
            latest_received_engine_time: engine_time,
            msg_max_size,
        }
    }

    /// Get the estimated current engine time.
    ///
    /// This adds elapsed local time to the synced engine time.
    /// Per RFC 3414 Section 2.2.1, the result is capped at `MAX_ENGINE_TIME`
    /// (2^31-1).
    ///
    /// Note: the client does not locally increment `engine_boots` when the
    /// estimated time reaches `MAX_ENGINE_TIME`. The authoritative engine
    /// (agent) is responsible for the boots increment; the client will
    /// learn the new boots value from the agent's next response or from
    /// a notInTimeWindow Report. Until that happens, the capped time is
    /// the best estimate the client can produce.
    pub fn estimated_time(&self) -> u32 {
        let elapsed = self.synced_at.elapsed().as_secs() as u32;
        self.engine_time
            .saturating_add(elapsed)
            .min(MAX_ENGINE_TIME)
    }

    /// Update time from a response.
    ///
    /// Per RFC 3414 Section 3.2 Step 7b, only update if:
    /// - Response boots > local boots, OR
    /// - Response boots == local boots AND response time > `latest_received_engine_time`
    pub fn update_time(&mut self, response_boots: u32, response_time: u32) -> bool {
        if response_boots > self.engine_boots {
            // New boot cycle
            self.engine_boots = response_boots;
            self.engine_time = response_time;
            self.synced_at = Instant::now();
            self.latest_received_engine_time = response_time;
            true
        } else if response_boots == self.engine_boots
            && response_time > self.latest_received_engine_time
        {
            // Same boot cycle, newer time
            self.engine_time = response_time;
            self.synced_at = Instant::now();
            self.latest_received_engine_time = response_time;
            true
        } else {
            false
        }
    }

    /// Check if a message time is within the time window.
    ///
    /// Per RFC 3414 Section 2.2.3, a message is outside the window if:
    /// - Local boots is 2,147,483,647 (latched), OR
    /// - Message boots differs from local boots, OR
    /// - |`message_time` - `local_time`| > 150 seconds
    pub fn is_in_time_window(&self, msg_boots: u32, msg_time: u32) -> bool {
        // Check for latched boots (max value)
        if self.engine_boots == 2_147_483_647 {
            return false;
        }

        // Boots must match
        if msg_boots != self.engine_boots {
            return false;
        }

        // Time must be within window
        let local_time = self.estimated_time();
        let diff = msg_time.abs_diff(local_time);

        diff <= TIME_WINDOW
    }
}

/// Default TTL for engine cache entries (5 minutes).
///
/// Entries not refreshed by a successful authenticated exchange within
/// this duration are considered stale. This handles device replacement
/// (new engine ID at the same IP) without requiring unauthenticated
/// re-discovery on Report PDUs.
const DEFAULT_ENGINE_CACHE_TTL: Duration = Duration::from_secs(300);

/// Thread-safe cache of discovered `SNMPv3` engine state.
///
/// Before sending authenticated `SNMPv3` messages, a client must discover
/// the target engine's ID, boot counter, and time (RFC 3414 Section 4).
/// This cache stores those results so that subsequent requests, or other
/// clients sharing the same cache via [`Arc`](std::sync::Arc), skip the discovery round trip.
///
/// # Entry lifetime
///
/// Each entry tracks a `synced_at` timestamp that is reset on every
/// successful time update ([`update_time`](Self::update_time)). Entries
/// whose `synced_at` exceeds the configured TTL (default 5 minutes) are
/// treated as expired: [`get`](Self::get) returns `None` and the stale
/// entry is removed, causing the next request to re-run discovery.
///
/// This TTL-based expiry handles **device replacement** (a new device with
/// a different engine ID appearing at the same IP address). Without it,
/// the client would hold a stale engine ID indefinitely and every request
/// would fail with `usmStatsUnknownEngineIDs`. Automatic re-discovery on
/// that Report PDU was considered but rejected because Report PDUs are
/// unauthenticated, making it possible for a spoofed report to force
/// re-discovery toward a rogue engine. The TTL approach avoids this: only
/// entries that have not been refreshed by a successful authenticated
/// exchange are expired.
///
/// Actively polled targets refresh their entry on every response, so the
/// TTL has no effect during normal operation.
///
/// # Capacity
///
/// The cache is unbounded by default. Each entry is roughly 100-150 bytes,
/// so even 100k targets uses only ~10-15 MB. For deployments that scan
/// very large address ranges, [`with_max_capacity`](Self::with_max_capacity)
/// sets a hard limit with oldest-entry eviction.
///
/// # Example
///
/// ```ignore
/// use std::sync::Arc;
///
/// let cache = Arc::new(EngineCache::new());
///
/// let client1 = Client::builder("192.168.1.1:161")
///     .username("admin")
///     .auth(AuthProtocol::Sha1, "authpass")
///     .engine_cache(cache.clone())
///     .connect()
///     .await?;
///
/// let client2 = Client::builder("192.168.1.2:161")
///     .username("admin")
///     .auth(AuthProtocol::Sha1, "authpass")
///     .engine_cache(cache.clone())
///     .connect()
///     .await?;
/// ```
#[derive(Debug)]
pub struct EngineCache {
    engines: RwLock<HashMap<SocketAddr, EngineState>>,
    max_capacity: Option<usize>,
    ttl: Duration,
}

impl Default for EngineCache {
    fn default() -> Self {
        Self::new()
    }
}

impl EngineCache {
    /// Create a new empty engine cache with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            engines: RwLock::new(HashMap::new()),
            max_capacity: None,
            ttl: DEFAULT_ENGINE_CACHE_TTL,
        }
    }

    /// Set a maximum capacity. When full, the oldest entry is evicted on insert.
    #[must_use]
    pub fn with_max_capacity(mut self, max_capacity: usize) -> Self {
        self.max_capacity = Some(max_capacity.max(1));
        self
    }

    /// Set the TTL for cache entries. Entries not refreshed within this
    /// duration are removed on lookup, triggering re-discovery.
    #[must_use]
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Get cached engine state for a target.
    ///
    /// Returns `None` if the entry does not exist or has expired.
    /// Expired entries are removed from the cache.
    pub fn get(&self, target: &SocketAddr) -> Option<EngineState> {
        // Fast path: read lock, check existence and TTL.
        {
            let engines = self.engines.read().ok()?;
            match engines.get(target) {
                None => return None,
                Some(state) if state.synced_at.elapsed() <= self.ttl => {
                    return Some(state.clone());
                }
                Some(_) => {} // expired, fall through to evict
            }
        }
        // Slow path: write lock to remove the stale entry.
        if let Ok(mut engines) = self.engines.write()
            && let Some(state) = engines.get(target)
            && state.synced_at.elapsed() > self.ttl
        {
            engines.remove(target);
        }
        None
    }

    /// Store engine state for a target.
    ///
    /// If a max capacity is set and the cache is full, the entry with
    /// the oldest `synced_at` time is evicted.
    pub fn insert(&self, target: SocketAddr, state: EngineState) {
        if let Ok(mut engines) = self.engines.write() {
            if let Some(cap) = self.max_capacity
                && !engines.contains_key(&target)
                && engines.len() >= cap
                && let Some(oldest) = engines
                    .iter()
                    .min_by_key(|(_, s)| s.synced_at)
                    .map(|(k, _)| *k)
            {
                engines.remove(&oldest);
            }
            engines.insert(target, state);
        }
    }

    /// Update time for an existing entry.
    ///
    /// Returns true if the entry was updated, false if not found or not updated.
    pub fn update_time(
        &self,
        target: &SocketAddr,
        response_boots: u32,
        response_time: u32,
    ) -> bool {
        if let Ok(mut engines) = self.engines.write()
            && let Some(state) = engines.get_mut(target)
        {
            return state.update_time(response_boots, response_time);
        }
        false
    }

    /// Remove cached state for a target.
    pub fn remove(&self, target: &SocketAddr) -> Option<EngineState> {
        self.engines.write().ok()?.remove(target)
    }

    /// Clear all cached state.
    pub fn clear(&self) {
        if let Ok(mut engines) = self.engines.write() {
            engines.clear();
        }
    }

    /// Get the number of cached engines (including expired entries).
    pub fn len(&self) -> usize {
        self.engines.read().map_or(0, |e| e.len())
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Extract engine state from a discovery response's USM security parameters.
///
/// The discovery response (Report PDU) contains the authoritative engine's
/// ID, boots, and time in the USM security parameters field.
pub fn parse_discovery_response(security_params: &Bytes) -> Result<EngineState> {
    parse_discovery_response_with_limits(
        security_params,
        DEFAULT_MSG_MAX_SIZE,
        DEFAULT_MSG_MAX_SIZE,
    )
}

/// Extract engine state with explicit msgMaxSize and session limit.
///
/// The `reported_msg_max_size` comes from the V3 message header (`MsgGlobalData`).
/// The `session_max` is our transport's maximum message size.
/// Values are capped to prevent issues with non-compliant agents.
pub fn parse_discovery_response_with_limits(
    security_params: &Bytes,
    reported_msg_max_size: u32,
    session_max: u32,
) -> Result<EngineState> {
    let usm = UsmSecurityParams::decode(security_params.clone())?;

    if usm.engine_id.is_empty() {
        tracing::debug!(target: "async_snmp::engine", "discovery response contained empty engine ID");
        return Err(Error::MalformedResponse {
            target: SocketAddr::from(([0, 0, 0, 0], 0)),
        }
        .boxed());
    }

    Ok(EngineState::with_msg_max_size_capped(
        usm.engine_id,
        usm.engine_boots,
        usm.engine_time,
        reported_msg_max_size,
        session_max,
    ))
}

/// Returns true if `pdu` is a Report PDU containing a varbind with the given OID.
fn pdu_has_report_oid(pdu: &crate::pdu::Pdu, expected_oid: &crate::Oid) -> bool {
    use crate::pdu::PduType;
    pdu.pdu_type == PduType::Report && pdu.varbinds.iter().any(|vb| &vb.oid == expected_oid)
}

/// Check if a Report PDU indicates "unknown engine ID" (discovery response).
///
/// Returns true if the PDU contains usmStatsUnknownEngineIDs varbind.
#[must_use]
pub fn is_unknown_engine_id_report(pdu: &crate::pdu::Pdu) -> bool {
    pdu_has_report_oid(pdu, &report_oids::unknown_engine_ids())
}

/// Check if a Report PDU indicates "not in time window".
///
/// Returns true if the PDU contains usmStatsNotInTimeWindows varbind.
#[must_use]
pub fn is_not_in_time_window_report(pdu: &crate::pdu::Pdu) -> bool {
    pdu_has_report_oid(pdu, &report_oids::not_in_time_windows())
}

/// Check if a Report PDU indicates "wrong digest" (authentication failure).
///
/// Returns true if the PDU contains usmStatsWrongDigests varbind.
#[must_use]
pub fn is_wrong_digest_report(pdu: &crate::pdu::Pdu) -> bool {
    pdu_has_report_oid(pdu, &report_oids::wrong_digests())
}

/// Check if a Report PDU indicates "unsupported security level".
///
/// Returns true if the PDU contains usmStatsUnsupportedSecLevels varbind.
#[must_use]
pub fn is_unsupported_sec_level_report(pdu: &crate::pdu::Pdu) -> bool {
    pdu_has_report_oid(pdu, &report_oids::unsupported_sec_levels())
}

/// Check if a Report PDU indicates "unknown user name".
///
/// Returns true if the PDU contains usmStatsUnknownUserNames varbind.
#[must_use]
pub fn is_unknown_user_name_report(pdu: &crate::pdu::Pdu) -> bool {
    pdu_has_report_oid(pdu, &report_oids::unknown_user_names())
}

/// Check if a Report PDU indicates "decryption error".
///
/// Returns true if the PDU contains usmStatsDecryptionErrors varbind.
#[must_use]
pub fn is_decryption_error_report(pdu: &crate::pdu::Pdu) -> bool {
    pdu_has_report_oid(pdu, &report_oids::decryption_errors())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_state_estimated_time() {
        let state = EngineState::new(Bytes::from_static(b"engine"), 1, 1000);

        // Estimated time should be at least engine_time
        let estimated = state.estimated_time();
        assert!(estimated >= 1000);
    }

    #[test]
    fn test_engine_state_update_time() {
        let mut state = EngineState::new(Bytes::from_static(b"engine"), 1, 1000);

        // Same boots, newer time -> should update
        assert!(state.update_time(1, 1100));
        assert_eq!(state.latest_received_engine_time, 1100);

        // Same boots, older time -> should NOT update
        assert!(!state.update_time(1, 1050));
        assert_eq!(state.latest_received_engine_time, 1100);

        // New boot cycle -> should update
        assert!(state.update_time(2, 500));
        assert_eq!(state.engine_boots, 2);
        assert_eq!(state.latest_received_engine_time, 500);
    }

    /// Test anti-replay protection via latestReceivedEngineTime (RFC 3414 Section 3.2 Step 7b).
    ///
    /// The anti-replay mechanism rejects messages with engine time values that are
    /// not newer than the latest received time. This prevents replay attacks where
    /// an attacker captures and re-sends old authenticated messages.
    #[test]
    fn test_anti_replay_rejects_old_time() {
        let mut state = EngineState::new(Bytes::from_static(b"engine"), 1, 1000);
        state.latest_received_engine_time = 1500; // Simulate having received up to time 1500

        // Attempt to replay a message from time 1400 (before latest)
        // update_time returns false, indicating the update was rejected
        assert!(
            !state.update_time(1, 1400),
            "Should reject replay: time 1400 < latest 1500"
        );
        assert_eq!(
            state.latest_received_engine_time, 1500,
            "Latest should not change"
        );

        // Even time 1500 (equal) should be rejected - must be strictly greater
        assert!(
            !state.update_time(1, 1500),
            "Should reject replay: time 1500 == latest 1500"
        );
        assert_eq!(state.latest_received_engine_time, 1500);

        // Time 1501 (newer) should be accepted
        assert!(
            state.update_time(1, 1501),
            "Should accept: time 1501 > latest 1500"
        );
        assert_eq!(state.latest_received_engine_time, 1501);
    }

    /// Test anti-replay across boot cycles.
    ///
    /// A new boot cycle (higher boots value) always resets the `latest_received_engine_time`
    /// since the agent has rebooted and time values are relative to the boot.
    #[test]
    fn test_anti_replay_new_boot_cycle_resets() {
        let mut state = EngineState::new(Bytes::from_static(b"engine"), 1, 1000);
        state.latest_received_engine_time = 5000; // High value from long uptime

        // New boot cycle with lower time value - should accept
        // because the engine rebooted (boots increased)
        assert!(
            state.update_time(2, 100),
            "New boot cycle should accept even with lower time"
        );
        assert_eq!(state.engine_boots, 2);
        assert_eq!(state.engine_time, 100);
        assert_eq!(
            state.latest_received_engine_time, 100,
            "Latest should reset to new time"
        );

        // Now subsequent updates in the new boot cycle follow normal rules
        assert!(
            !state.update_time(2, 50),
            "Should reject older time in same boot cycle"
        );
        assert!(state.update_time(2, 150), "Should accept newer time");
        assert_eq!(state.latest_received_engine_time, 150);
    }

    /// Test anti-replay rejects old boot cycles.
    ///
    /// An attacker cannot replay messages from a previous boot cycle.
    #[test]
    fn test_anti_replay_rejects_old_boot_cycle() {
        let mut state = EngineState::new(Bytes::from_static(b"engine"), 5, 1000);
        state.latest_received_engine_time = 1000;

        // Attempt to use old boot cycle (boots=4) - should reject
        assert!(
            !state.update_time(4, 9999),
            "Should reject old boot cycle even with high time"
        );
        assert_eq!(state.engine_boots, 5, "Boots should not change");
        assert_eq!(
            state.latest_received_engine_time, 1000,
            "Latest should not change"
        );

        // Attempt boots=0 - should reject
        assert!(!state.update_time(0, 9999), "Should reject boots=0 replay");
    }

    /// Test anti-replay with exact boundary values.
    #[test]
    fn test_anti_replay_boundary_values() {
        let mut state = EngineState::new(Bytes::from_static(b"engine"), 1, 0);

        // Start with time=0
        assert_eq!(state.latest_received_engine_time, 0);

        // Time=1 should be accepted (> 0)
        assert!(state.update_time(1, 1));
        assert_eq!(state.latest_received_engine_time, 1);

        // Time=0 should be rejected (< 1)
        assert!(!state.update_time(1, 0));

        // Large time value should work
        assert!(state.update_time(1, u32::MAX - 1));
        assert_eq!(state.latest_received_engine_time, u32::MAX - 1);

        // u32::MAX should still work
        assert!(state.update_time(1, u32::MAX));
        assert_eq!(state.latest_received_engine_time, u32::MAX);

        // Nothing can be newer than u32::MAX in the same boot cycle
        assert!(!state.update_time(1, u32::MAX));
    }

    #[test]
    fn test_engine_state_time_window() {
        let state = EngineState::new(Bytes::from_static(b"engine"), 1, 1000);

        // Same boots, within window
        assert!(state.is_in_time_window(1, 1000));
        assert!(state.is_in_time_window(1, 1100)); // +100s
        assert!(state.is_in_time_window(1, 900)); // -100s

        // Different boots -> out of window
        assert!(!state.is_in_time_window(2, 1000));
        assert!(!state.is_in_time_window(0, 1000));

        // Way outside time window
        assert!(!state.is_in_time_window(1, 2000)); // +1000s > 150s
    }

    /// Test the exact 150-second time window boundary per RFC 3414 Section 2.2.3.
    ///
    /// The time window is exactly 150 seconds. Messages with time difference
    /// of exactly 150 seconds should be accepted, but 151 seconds should fail.
    #[test]
    fn test_time_window_150s_exact_boundary() {
        // Use high engine_time to avoid underflow complications
        let state = EngineState::new(Bytes::from_static(b"engine"), 1, 10000);

        // At exactly +150 seconds from engine_time (10000 + 150 = 10150)
        // The is_in_time_window compares against estimated_time(), which adds
        // elapsed time. For a fresh EngineState, elapsed should be ~0.
        // So msg_time of 10150 should be within window (diff = 150 <= TIME_WINDOW)
        assert!(
            state.is_in_time_window(1, 10150),
            "Message at exactly +150s boundary should be in window"
        );

        // At exactly +151 seconds (diff = 151 > TIME_WINDOW = 150)
        assert!(
            !state.is_in_time_window(1, 10151),
            "Message at +151s should be outside window"
        );

        // At exactly -150 seconds (10000 - 150 = 9850)
        assert!(
            state.is_in_time_window(1, 9850),
            "Message at exactly -150s boundary should be in window"
        );

        // At exactly -151 seconds (10000 - 151 = 9849)
        assert!(
            !state.is_in_time_window(1, 9849),
            "Message at -151s should be outside window"
        );
    }

    /// Test time window with maximum engine boots value (2_147_483_647).
    ///
    /// Per RFC 3414 Section 2.2.3, when snmpEngineBoots is 2_147_483_647 (latched),
    /// all messages should be rejected as outside the time window.
    #[test]
    fn test_time_window_boots_latched() {
        // Maximum boots value indicates the engine has been rebooted too many times
        // and should reject all authenticated messages
        let state = EngineState::new(Bytes::from_static(b"engine"), 2_147_483_647, 1000);

        // Even with matching boots and same time, should fail when latched
        assert!(
            !state.is_in_time_window(2_147_483_647, 1000),
            "Latched boots should reject all messages"
        );

        // Any other time should also fail
        assert!(!state.is_in_time_window(2_147_483_647, 1100));
        assert!(!state.is_in_time_window(2_147_483_647, 900));
    }

    /// Test time window edge cases with boot counter differences.
    ///
    /// Boot counter must match exactly; any difference means out of window.
    #[test]
    fn test_time_window_boots_mismatch() {
        let state = EngineState::new(Bytes::from_static(b"engine"), 100, 1000);

        // Boots too high
        assert!(!state.is_in_time_window(101, 1000));
        assert!(!state.is_in_time_window(200, 1000));

        // Boots too low (replay from previous boot cycle)
        assert!(!state.is_in_time_window(99, 1000));
        assert!(!state.is_in_time_window(0, 1000));
    }

    #[test]
    fn test_engine_cache_basic_operations() {
        let cache = EngineCache::new();
        let addr: SocketAddr = "192.168.1.1:161".parse().unwrap();

        // Initially empty
        assert!(cache.is_empty());
        assert!(cache.get(&addr).is_none());

        // Insert
        let state = EngineState::new(Bytes::from_static(b"engine1"), 1, 1000);
        cache.insert(addr, state);

        assert_eq!(cache.len(), 1);
        assert!(!cache.is_empty());

        // Get
        let retrieved = cache.get(&addr).unwrap();
        assert_eq!(retrieved.engine_id.as_ref(), b"engine1");
        assert_eq!(retrieved.engine_boots, 1);

        // Update time
        assert!(cache.update_time(&addr, 1, 1100));

        // Remove
        let removed = cache.remove(&addr).unwrap();
        assert_eq!(removed.latest_received_engine_time, 1100);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_engine_cache_ttl_expiry() {
        let cache = EngineCache::new().with_ttl(Duration::from_millis(50));
        let addr: SocketAddr = "192.168.1.1:161".parse().unwrap();

        let state = EngineState::new(Bytes::from_static(b"engine1"), 1, 1000);
        cache.insert(addr, state);
        assert!(cache.get(&addr).is_some());

        // Wait well past TTL to avoid flakiness on slow CI
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            cache.get(&addr).is_none(),
            "expired entry should return None"
        );
        assert!(cache.is_empty(), "expired entry should be removed");
    }

    #[test]
    fn test_engine_cache_ttl_refresh_on_time_update() {
        let cache = EngineCache::new().with_ttl(Duration::from_millis(500));
        let addr: SocketAddr = "192.168.1.1:161".parse().unwrap();

        let state = EngineState::new(Bytes::from_static(b"engine1"), 1, 1000);
        cache.insert(addr, state);

        // Wait partway, then refresh via update_time
        std::thread::sleep(Duration::from_millis(300));
        assert!(cache.update_time(&addr, 1, 1050));

        // Wait again - would have expired without the refresh
        std::thread::sleep(Duration::from_millis(300));
        assert!(
            cache.get(&addr).is_some(),
            "refreshed entry should still be alive"
        );
    }

    #[test]
    fn test_engine_cache_max_capacity_eviction() {
        let cache = EngineCache::new().with_max_capacity(2);
        let addr1: SocketAddr = "192.168.1.1:161".parse().unwrap();
        let addr2: SocketAddr = "192.168.1.2:161".parse().unwrap();
        let addr3: SocketAddr = "192.168.1.3:161".parse().unwrap();

        cache.insert(addr1, EngineState::new(Bytes::from_static(b"e1"), 1, 100));
        std::thread::sleep(Duration::from_millis(10));
        cache.insert(addr2, EngineState::new(Bytes::from_static(b"e2"), 1, 200));
        std::thread::sleep(Duration::from_millis(10));

        assert_eq!(cache.len(), 2);

        // Third insert should evict addr1 (oldest synced_at)
        cache.insert(addr3, EngineState::new(Bytes::from_static(b"e3"), 1, 300));
        assert_eq!(cache.len(), 2);
        assert!(
            cache.get(&addr1).is_none(),
            "oldest entry should be evicted"
        );
        assert!(cache.get(&addr2).is_some());
        assert!(cache.get(&addr3).is_some());
    }

    #[test]
    fn test_parse_discovery_response() {
        let usm = UsmSecurityParams::new(b"test-engine-id".as_slice(), 42, 12345, b"".as_slice());
        let encoded = usm.encode();

        let state = parse_discovery_response(&encoded).unwrap();
        assert_eq!(state.engine_id.as_ref(), b"test-engine-id");
        assert_eq!(state.engine_boots, 42);
        assert_eq!(state.engine_time, 12345);
    }

    #[test]
    fn test_parse_discovery_response_empty_engine_id() {
        let usm = UsmSecurityParams::empty();
        let encoded = usm.encode();

        let result = parse_discovery_response(&encoded);
        assert!(matches!(
            *result.unwrap_err(),
            Error::MalformedResponse { .. }
        ));
    }

    #[test]
    fn test_is_unknown_engine_id_report() {
        use crate::Value;
        use crate::VarBind;
        use crate::pdu::{Pdu, PduType};

        // Report with usmStatsUnknownEngineIDs
        let mut pdu = Pdu {
            pdu_type: PduType::Report,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbinds: vec![VarBind {
                oid: report_oids::unknown_engine_ids(),
                value: Value::Counter32(1),
            }],
        };

        assert!(is_unknown_engine_id_report(&pdu));

        // Different report type
        pdu.varbinds[0].oid = report_oids::not_in_time_windows();
        assert!(!is_unknown_engine_id_report(&pdu));

        // Not a Report PDU
        pdu.pdu_type = PduType::Response;
        assert!(!is_unknown_engine_id_report(&pdu));
    }

    // ========================================================================
    // Engine Boots Overflow Tests (RFC 3414 Section 2.2.3)
    // ========================================================================

    /// Test that `update_time` accepts transition to maximum boots value.
    ///
    /// When the engine reboots and boots reaches 2_147_483_647 (`i32::MAX`),
    /// the update should be accepted since it's a valid new boot cycle.
    #[test]
    fn test_engine_boots_transition_to_max() {
        let mut state = EngineState::new(Bytes::from_static(b"engine"), 2_147_483_646, 1000);

        // Boot cycle to max value should be accepted
        assert!(
            state.update_time(2_147_483_647, 100),
            "Transition to boots=2_147_483_647 should be accepted"
        );
        assert_eq!(state.engine_boots, 2_147_483_647);
        assert_eq!(state.engine_time, 100);
    }

    /// Test `update_time` behavior when boots is latched.
    ///
    /// The `update_time` function still tracks received times for anti-replay
    /// purposes. The security rejection happens in `is_in_time_window()`.
    /// However, when boots=2_147_483_647, there's no valid "higher" boots value,
    /// so boot cycle transitions are impossible.
    #[test]
    fn test_engine_boots_latched_update_behavior() {
        let mut state = EngineState::new(Bytes::from_static(b"engine"), 2_147_483_647, 1000);

        // Time tracking still works for same boots
        assert!(
            state.update_time(2_147_483_647, 2000),
            "Time tracking updates should still work"
        );
        assert_eq!(state.latest_received_engine_time, 2000);

        // Old time rejected per normal anti-replay
        assert!(!state.update_time(2_147_483_647, 1500));
        assert_eq!(state.latest_received_engine_time, 2000);

        // The key security check is in is_in_time_window
        assert!(
            !state.is_in_time_window(2_147_483_647, 2000),
            "Latched state should still reject all messages"
        );
    }

    /// Test that time window rejects all messages when boots is latched.
    ///
    /// This is the key security property: once an engine's boots counter
    /// reaches its maximum value, all authenticated messages should be
    /// rejected to prevent replay attacks.
    #[test]
    fn test_engine_boots_latched_time_window_always_fails() {
        let state = EngineState::new(Bytes::from_static(b"engine"), 2_147_483_647, 1000);

        // All time values should fail when latched
        assert!(!state.is_in_time_window(2_147_483_647, 0));
        assert!(!state.is_in_time_window(2_147_483_647, 1000));
        assert!(!state.is_in_time_window(2_147_483_647, 1001));
        assert!(!state.is_in_time_window(2_147_483_647, u32::MAX));

        // Even previous boots values should fail
        assert!(!state.is_in_time_window(2_147_483_646, 1000));
        assert!(!state.is_in_time_window(0, 1000));
    }

    /// Test creating `EngineState` directly with latched boots value.
    ///
    /// An agent that has been running for a very long time might already
    /// be in the latched state when we first discover it.
    #[test]
    fn test_engine_state_created_latched() {
        let state = EngineState::new(Bytes::from_static(b"engine"), 2_147_483_647, 5000);

        assert_eq!(state.engine_boots, 2_147_483_647);
        assert_eq!(state.engine_time, 5000);
        assert_eq!(state.latest_received_engine_time, 5000);

        // Should immediately be in latched state
        assert!(
            !state.is_in_time_window(2_147_483_647, 5000),
            "Newly created latched engine should reject all messages"
        );
    }

    /// Test that boots values near the maximum work correctly.
    ///
    /// Verify normal operation just before reaching the latch point.
    #[test]
    fn test_engine_boots_near_max_operates_normally() {
        let mut state = EngineState::new(Bytes::from_static(b"engine"), 2_147_483_645, 1000);

        // Normal time window checks should work
        assert!(state.is_in_time_window(2_147_483_645, 1000));
        assert!(state.is_in_time_window(2_147_483_645, 1100));
        assert!(!state.is_in_time_window(2_147_483_645, 1200)); // Outside 150s window

        // Should accept boot to 2_147_483_646
        assert!(state.update_time(2_147_483_646, 500));
        assert_eq!(state.engine_boots, 2_147_483_646);
        assert!(state.is_in_time_window(2_147_483_646, 500));

        // Should accept boot to 2_147_483_647 (becomes latched)
        assert!(state.update_time(2_147_483_647, 100));
        assert_eq!(state.engine_boots, 2_147_483_647);

        // Now latched - all messages rejected
        assert!(!state.is_in_time_window(2_147_483_647, 100));
    }

    /// Test that `update_time` correctly handles the comparison when
    /// current boots is high but not yet latched.
    #[test]
    fn test_engine_boots_high_value_update_logic() {
        let mut state = EngineState::new(Bytes::from_static(b"engine"), 2_147_483_640, 1000);

        // Old boot cycles should be rejected
        assert!(!state.update_time(2147483639, 9999));
        assert!(!state.update_time(0, 9999));

        // Same boot, older time should be rejected
        assert!(!state.update_time(2_147_483_640, 500));

        // Same boot, newer time should be accepted
        assert!(state.update_time(2_147_483_640, 1500));
        assert_eq!(state.latest_received_engine_time, 1500);

        // New boot should be accepted
        assert!(state.update_time(2_147_483_641, 100));
        assert_eq!(state.engine_boots, 2_147_483_641);
    }

    /// Test `EngineCache` behavior with latched engines.
    ///
    /// Even when latched, time tracking updates are accepted (for anti-replay).
    /// The security rejection is enforced by `is_in_time_window()`, not `update_time()`.
    #[test]
    fn test_engine_cache_latched_engine() {
        let cache = EngineCache::new();
        let addr: SocketAddr = "192.168.1.1:161".parse().unwrap();

        // Insert latched engine
        cache.insert(
            addr,
            EngineState::new(Bytes::from_static(b"latched"), 2_147_483_647, 1000),
        );

        // Time tracking still works
        assert!(
            cache.update_time(&addr, 2_147_483_647, 2000),
            "Time tracking should update even for latched engine"
        );

        // Verify state was updated
        let state = cache.get(&addr).unwrap();
        assert_eq!(state.latest_received_engine_time, 2000);

        // But the key security property: is_in_time_window rejects
        assert!(
            !state.is_in_time_window(2_147_483_647, 2000),
            "Latched engine should reject all time window checks"
        );
    }

    // ========================================================================
    // msgMaxSize Capping Tests
    // ========================================================================
    //
    // Per net-snmp behavior, agent-reported msgMaxSize values should be capped
    // to the session's maximum to prevent buffer issues with non-compliant agents.

    /// Test that `EngineState` stores the agent's advertised msgMaxSize.
    ///
    /// The `msg_max_size` field tracks the maximum message size the remote engine
    /// can accept, as reported in `SNMPv3` message headers.
    #[test]
    fn test_engine_state_stores_msg_max_size() {
        let state = EngineState::with_msg_max_size(Bytes::from_static(b"engine"), 1, 1000, 65507);
        assert_eq!(state.msg_max_size, 65507);
    }

    /// Test that the default constructor uses the maximum UDP message size.
    ///
    /// When msgMaxSize is not provided (e.g., during basic discovery),
    /// default to the maximum safe UDP datagram size (65507 bytes).
    #[test]
    fn test_engine_state_default_msg_max_size() {
        let state = EngineState::new(Bytes::from_static(b"engine"), 1, 1000);
        assert_eq!(
            state.msg_max_size, DEFAULT_MSG_MAX_SIZE,
            "Default msg_max_size should be the maximum UDP datagram size"
        );
    }

    /// Test that msgMaxSize is capped to session maximum.
    ///
    /// Non-compliant agents may advertise msgMaxSize values larger than they
    /// (or we) can actually handle. Values exceeding the session maximum are
    /// silently capped to prevent buffer issues.
    #[test]
    fn test_engine_state_msg_max_size_capped_to_session_max() {
        // Agent advertises 2GB, but we cap to 65507 (our session max)
        let state = EngineState::with_msg_max_size_capped(
            Bytes::from_static(b"engine"),
            1,
            1000,
            2_000_000_000, // Agent claims 2GB
            65507,         // Our session maximum
        );
        assert_eq!(
            state.msg_max_size, 65507,
            "msg_max_size should be capped to session maximum"
        );
    }

    /// Test that msgMaxSize within session maximum is not modified.
    ///
    /// When the agent advertises a reasonable value below our maximum,
    /// it should be stored as-is without capping.
    #[test]
    fn test_engine_state_msg_max_size_within_limit_not_capped() {
        let state = EngineState::with_msg_max_size_capped(
            Bytes::from_static(b"engine"),
            1,
            1000,
            1472,  // Agent claims 1472 (Ethernet MTU - headers)
            65507, // Our session maximum
        );
        assert_eq!(
            state.msg_max_size, 1472,
            "msg_max_size within limit should not be capped"
        );
    }

    /// Test msgMaxSize capping at exact boundary.
    ///
    /// When agent's msgMaxSize exactly equals session maximum, no capping occurs.
    #[test]
    fn test_engine_state_msg_max_size_at_exact_boundary() {
        let state = EngineState::with_msg_max_size_capped(
            Bytes::from_static(b"engine"),
            1,
            1000,
            65507, // Exactly at session max
            65507, // Our session maximum
        );
        assert_eq!(state.msg_max_size, 65507);
    }

    /// Test msgMaxSize capping with TCP transport maximum.
    ///
    /// TCP transports may have higher limits. Verify capping works with
    /// the larger TCP message size limit.
    #[test]
    fn test_engine_state_msg_max_size_tcp_limit() {
        const TCP_MAX: u32 = 0x7FFF_FFFF; // net-snmp TCP maximum

        // Agent claims i32::MAX, we have same limit
        let state = EngineState::with_msg_max_size_capped(
            Bytes::from_static(b"engine"),
            1,
            1000,
            TCP_MAX,
            TCP_MAX,
        );
        assert_eq!(state.msg_max_size, TCP_MAX);

        // Agent claims more than i32::MAX (wrapped negative), cap to limit
        let state = EngineState::with_msg_max_size_capped(
            Bytes::from_static(b"engine"),
            1,
            1000,
            u32::MAX, // Larger than any valid msgMaxSize
            TCP_MAX,
        );
        assert_eq!(
            state.msg_max_size, TCP_MAX,
            "Values exceeding session max should be capped"
        );
    }

    /// Test that `EngineState::new` uses the default `msg_max_size` constant.
    #[test]
    fn test_engine_state_new_uses_default_constant() {
        let state = EngineState::new(Bytes::from_static(b"engine"), 1, 1000);

        // DEFAULT_MSG_MAX_SIZE is the maximum UDP payload (65507)
        assert_eq!(state.msg_max_size, DEFAULT_MSG_MAX_SIZE);
    }

    // ========================================================================
    // Engine Time Overflow Tests (RFC 3414 Section 2.2.1)
    // ========================================================================
    //
    // Per RFC 3414, snmpEngineTime is a 31-bit value (0..2_147_483_647).
    // When the time value would exceed this, it must not go beyond MAX_ENGINE_TIME.

    /// Test that `estimated_time` caps at `MAX_ENGINE_TIME` (2^31-1).
    ///
    /// Per RFC 3414 Section 2.2.1, snmpEngineTime is 31-bit (0..2_147_483_647).
    /// If time would exceed this value, it should cap at `MAX_ENGINE_TIME` rather
    /// than continuing to `u32::MAX`.
    #[test]
    fn test_estimated_time_caps_at_max_engine_time() {
        // Create state with engine_time near the maximum
        let state = EngineState::new(Bytes::from_static(b"engine"), 1, MAX_ENGINE_TIME - 10);

        // Even though we're adding elapsed time, result should never exceed MAX_ENGINE_TIME
        let estimated = state.estimated_time();
        assert!(
            estimated <= MAX_ENGINE_TIME,
            "estimated_time() should never exceed MAX_ENGINE_TIME ({MAX_ENGINE_TIME}), got {estimated}"
        );
    }

    /// Test that `estimated_time` at `MAX_ENGINE_TIME` stays at `MAX_ENGINE_TIME`.
    ///
    /// When `engine_time` is already at the maximum, adding more elapsed time
    /// should not increase it further.
    #[test]
    fn test_estimated_time_at_max_stays_at_max() {
        let state = EngineState::new(Bytes::from_static(b"engine"), 1, MAX_ENGINE_TIME);

        // Should stay at MAX_ENGINE_TIME
        let estimated = state.estimated_time();
        assert_eq!(
            estimated, MAX_ENGINE_TIME,
            "estimated_time() at max should stay at MAX_ENGINE_TIME"
        );
    }

    /// Test that `engine_time` values beyond `MAX_ENGINE_TIME` are invalid.
    ///
    /// This verifies the constant value is correct per RFC 3414.
    #[test]
    fn test_max_engine_time_constant() {
        // RFC 3414 specifies 31-bit (0..2_147_483_647), which is i32::MAX
        assert_eq!(MAX_ENGINE_TIME, 2_147_483_647);
        assert_eq!(MAX_ENGINE_TIME, i32::MAX as u32);
    }

    /// Test that normal time estimation works below `MAX_ENGINE_TIME`.
    ///
    /// For typical time values well below the maximum, estimation should
    /// work normally without artificial capping.
    #[test]
    fn test_estimated_time_normal_operation() {
        let state = EngineState::new(Bytes::from_static(b"engine"), 1, 1000);

        // For a fresh state, elapsed should be ~0, so estimated should be ~engine_time
        let estimated = state.estimated_time();
        assert!(
            estimated >= 1000,
            "estimated_time() should be at least engine_time"
        );
        // Should not hit the cap
        assert!(
            estimated < MAX_ENGINE_TIME,
            "Normal time values should not hit MAX_ENGINE_TIME cap"
        );
    }
}
