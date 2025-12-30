//! Engine discovery and time synchronization (RFC 3414 Section 4).
//!
//! SNMPv3 requires knowing the authoritative engine's ID, boots counter,
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
use std::time::Instant;

use bytes::Bytes;

use crate::error::{Error, Result};
use crate::v3::UsmSecurityParams;

/// Time window in seconds (RFC 3414 Section 2.2.3).
pub const TIME_WINDOW: u32 = 150;

/// USM statistics OIDs used in Report PDUs.
pub mod report_oids {
    use crate::Oid;
    use crate::oid;

    /// 1.3.6.1.6.3.15.1.1.1.0 - usmStatsUnsupportedSecLevels
    pub fn unsupported_sec_levels() -> Oid {
        oid!(1, 3, 6, 1, 6, 3, 15, 1, 1, 1, 0)
    }

    /// 1.3.6.1.6.3.15.1.1.2.0 - usmStatsNotInTimeWindows
    pub fn not_in_time_windows() -> Oid {
        oid!(1, 3, 6, 1, 6, 3, 15, 1, 1, 2, 0)
    }

    /// 1.3.6.1.6.3.15.1.1.3.0 - usmStatsUnknownUserNames
    pub fn unknown_user_names() -> Oid {
        oid!(1, 3, 6, 1, 6, 3, 15, 1, 1, 3, 0)
    }

    /// 1.3.6.1.6.3.15.1.1.4.0 - usmStatsUnknownEngineIDs
    pub fn unknown_engine_ids() -> Oid {
        oid!(1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0)
    }

    /// 1.3.6.1.6.3.15.1.1.5.0 - usmStatsWrongDigests
    pub fn wrong_digests() -> Oid {
        oid!(1, 3, 6, 1, 6, 3, 15, 1, 1, 5, 0)
    }

    /// 1.3.6.1.6.3.15.1.1.6.0 - usmStatsDecryptionErrors
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
    /// Local time when engine_time was received
    pub synced_at: Instant,
    /// Latest received engine time (for anti-replay, RFC 3414 Section 2.3)
    pub latest_received_engine_time: u32,
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
        }
    }

    /// Get the estimated current engine time.
    ///
    /// This adds elapsed local time to the synced engine time.
    pub fn estimated_time(&self) -> u32 {
        let elapsed = self.synced_at.elapsed().as_secs() as u32;
        self.engine_time.saturating_add(elapsed)
    }

    /// Update time from a response.
    ///
    /// Per RFC 3414 Section 3.2 Step 7b, only update if:
    /// - Response boots > local boots, OR
    /// - Response boots == local boots AND response time > latest_received_engine_time
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
    /// - Local boots is 2147483647 (latched), OR
    /// - Message boots differs from local boots, OR
    /// - |message_time - local_time| > 150 seconds
    pub fn is_in_time_window(&self, msg_boots: u32, msg_time: u32) -> bool {
        // Check for latched boots (max value)
        if self.engine_boots == 2147483647 {
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

/// Thread-safe cache of discovered engine state.
///
/// Use this to share engine discovery results across multiple clients
/// targeting different engines.
///
/// # Example
///
/// ```ignore
/// let cache = EngineCache::new();
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
#[derive(Debug, Default)]
pub struct EngineCache {
    engines: RwLock<HashMap<SocketAddr, EngineState>>,
}

impl EngineCache {
    /// Create a new empty engine cache.
    pub fn new() -> Self {
        Self {
            engines: RwLock::new(HashMap::new()),
        }
    }

    /// Get cached engine state for a target.
    pub fn get(&self, target: &SocketAddr) -> Option<EngineState> {
        self.engines.read().ok()?.get(target).cloned()
    }

    /// Store engine state for a target.
    pub fn insert(&self, target: SocketAddr, state: EngineState) {
        if let Ok(mut engines) = self.engines.write() {
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

    /// Get the number of cached engines.
    pub fn len(&self) -> usize {
        self.engines.read().map(|e| e.len()).unwrap_or(0)
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Clone for EngineCache {
    fn clone(&self) -> Self {
        // Clone creates a new cache with the same contents
        let engines = self.engines.read().map(|e| e.clone()).unwrap_or_default();
        Self {
            engines: RwLock::new(engines),
        }
    }
}

/// Extract engine state from a discovery response's USM security parameters.
///
/// The discovery response (Report PDU) contains the authoritative engine's
/// ID, boots, and time in the USM security parameters field.
pub fn parse_discovery_response(security_params: &Bytes) -> Result<EngineState> {
    let usm = UsmSecurityParams::decode(security_params.clone())?;

    if usm.engine_id.is_empty() {
        return Err(Error::UnknownEngineId { target: None });
    }

    Ok(EngineState::new(
        usm.engine_id,
        usm.engine_boots,
        usm.engine_time,
    ))
}

/// Check if a Report PDU indicates "unknown engine ID" (discovery response).
///
/// Returns true if the PDU contains usmStatsUnknownEngineIDs varbind.
pub fn is_unknown_engine_id_report(pdu: &crate::pdu::Pdu) -> bool {
    use crate::pdu::PduType;

    if pdu.pdu_type != PduType::Report {
        return false;
    }

    let unknown_engine_ids_oid = report_oids::unknown_engine_ids();
    pdu.varbinds
        .iter()
        .any(|vb| vb.oid == unknown_engine_ids_oid)
}

/// Check if a Report PDU indicates "not in time window".
///
/// Returns true if the PDU contains usmStatsNotInTimeWindows varbind.
pub fn is_not_in_time_window_report(pdu: &crate::pdu::Pdu) -> bool {
    use crate::pdu::PduType;

    if pdu.pdu_type != PduType::Report {
        return false;
    }

    let not_in_time_windows_oid = report_oids::not_in_time_windows();
    pdu.varbinds
        .iter()
        .any(|vb| vb.oid == not_in_time_windows_oid)
}

/// Check if a Report PDU indicates "wrong digest" (authentication failure).
///
/// Returns true if the PDU contains usmStatsWrongDigests varbind.
pub fn is_wrong_digest_report(pdu: &crate::pdu::Pdu) -> bool {
    use crate::pdu::PduType;

    if pdu.pdu_type != PduType::Report {
        return false;
    }

    let wrong_digests_oid = report_oids::wrong_digests();
    pdu.varbinds.iter().any(|vb| vb.oid == wrong_digests_oid)
}

/// Check if a Report PDU indicates "unsupported security level".
///
/// Returns true if the PDU contains usmStatsUnsupportedSecLevels varbind.
pub fn is_unsupported_sec_level_report(pdu: &crate::pdu::Pdu) -> bool {
    use crate::pdu::PduType;

    if pdu.pdu_type != PduType::Report {
        return false;
    }

    let oid = report_oids::unsupported_sec_levels();
    pdu.varbinds.iter().any(|vb| vb.oid == oid)
}

/// Check if a Report PDU indicates "unknown user name".
///
/// Returns true if the PDU contains usmStatsUnknownUserNames varbind.
pub fn is_unknown_user_name_report(pdu: &crate::pdu::Pdu) -> bool {
    use crate::pdu::PduType;

    if pdu.pdu_type != PduType::Report {
        return false;
    }

    let oid = report_oids::unknown_user_names();
    pdu.varbinds.iter().any(|vb| vb.oid == oid)
}

/// Check if a Report PDU indicates "decryption error".
///
/// Returns true if the PDU contains usmStatsDecryptionErrors varbind.
pub fn is_decryption_error_report(pdu: &crate::pdu::Pdu) -> bool {
    use crate::pdu::PduType;

    if pdu.pdu_type != PduType::Report {
        return false;
    }

    let oid = report_oids::decryption_errors();
    pdu.varbinds.iter().any(|vb| vb.oid == oid)
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
    /// A new boot cycle (higher boots value) always resets the latest_received_engine_time
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

    /// Test time window with maximum engine boots value (2147483647).
    ///
    /// Per RFC 3414 Section 2.2.3, when snmpEngineBoots is 2147483647 (latched),
    /// all messages should be rejected as outside the time window.
    #[test]
    fn test_time_window_boots_latched() {
        // Maximum boots value indicates the engine has been rebooted too many times
        // and should reject all authenticated messages
        let state = EngineState::new(Bytes::from_static(b"engine"), 2147483647, 1000);

        // Even with matching boots and same time, should fail when latched
        assert!(
            !state.is_in_time_window(2147483647, 1000),
            "Latched boots should reject all messages"
        );

        // Any other time should also fail
        assert!(!state.is_in_time_window(2147483647, 1100));
        assert!(!state.is_in_time_window(2147483647, 900));
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
    fn test_engine_cache_clone() {
        let cache1 = EngineCache::new();
        let addr: SocketAddr = "192.168.1.1:161".parse().unwrap();

        cache1.insert(
            addr,
            EngineState::new(Bytes::from_static(b"engine1"), 1, 1000),
        );

        // Clone should have same content
        let cache2 = cache1.clone();
        assert_eq!(cache2.len(), 1);
        assert!(cache2.get(&addr).is_some());

        // But modifications are independent
        cache2.clear();
        assert_eq!(cache1.len(), 1);
        assert_eq!(cache2.len(), 0);
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
        assert!(matches!(result, Err(Error::UnknownEngineId { .. })));
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

    /// Test that update_time accepts transition to maximum boots value.
    ///
    /// When the engine reboots and boots reaches 2147483647 (i32::MAX),
    /// the update should be accepted since it's a valid new boot cycle.
    #[test]
    fn test_engine_boots_transition_to_max() {
        let mut state = EngineState::new(Bytes::from_static(b"engine"), 2147483646, 1000);

        // Boot cycle to max value should be accepted
        assert!(
            state.update_time(2147483647, 100),
            "Transition to boots=2147483647 should be accepted"
        );
        assert_eq!(state.engine_boots, 2147483647);
        assert_eq!(state.engine_time, 100);
    }

    /// Test update_time behavior when boots is latched.
    ///
    /// The update_time function still tracks received times for anti-replay
    /// purposes. The security rejection happens in is_in_time_window().
    /// However, when boots=2147483647, there's no valid "higher" boots value,
    /// so boot cycle transitions are impossible.
    #[test]
    fn test_engine_boots_latched_update_behavior() {
        let mut state = EngineState::new(Bytes::from_static(b"engine"), 2147483647, 1000);

        // Time tracking still works for same boots
        assert!(
            state.update_time(2147483647, 2000),
            "Time tracking updates should still work"
        );
        assert_eq!(state.latest_received_engine_time, 2000);

        // Old time rejected per normal anti-replay
        assert!(!state.update_time(2147483647, 1500));
        assert_eq!(state.latest_received_engine_time, 2000);

        // The key security check is in is_in_time_window
        assert!(
            !state.is_in_time_window(2147483647, 2000),
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
        let state = EngineState::new(Bytes::from_static(b"engine"), 2147483647, 1000);

        // All time values should fail when latched
        assert!(!state.is_in_time_window(2147483647, 0));
        assert!(!state.is_in_time_window(2147483647, 1000));
        assert!(!state.is_in_time_window(2147483647, 1001));
        assert!(!state.is_in_time_window(2147483647, u32::MAX));

        // Even previous boots values should fail
        assert!(!state.is_in_time_window(2147483646, 1000));
        assert!(!state.is_in_time_window(0, 1000));
    }

    /// Test creating EngineState directly with latched boots value.
    ///
    /// An agent that has been running for a very long time might already
    /// be in the latched state when we first discover it.
    #[test]
    fn test_engine_state_created_latched() {
        let state = EngineState::new(Bytes::from_static(b"engine"), 2147483647, 5000);

        assert_eq!(state.engine_boots, 2147483647);
        assert_eq!(state.engine_time, 5000);
        assert_eq!(state.latest_received_engine_time, 5000);

        // Should immediately be in latched state
        assert!(
            !state.is_in_time_window(2147483647, 5000),
            "Newly created latched engine should reject all messages"
        );
    }

    /// Test that boots values near the maximum work correctly.
    ///
    /// Verify normal operation just before reaching the latch point.
    #[test]
    fn test_engine_boots_near_max_operates_normally() {
        let mut state = EngineState::new(Bytes::from_static(b"engine"), 2147483645, 1000);

        // Normal time window checks should work
        assert!(state.is_in_time_window(2147483645, 1000));
        assert!(state.is_in_time_window(2147483645, 1100));
        assert!(!state.is_in_time_window(2147483645, 1200)); // Outside 150s window

        // Should accept boot to 2147483646
        assert!(state.update_time(2147483646, 500));
        assert_eq!(state.engine_boots, 2147483646);
        assert!(state.is_in_time_window(2147483646, 500));

        // Should accept boot to 2147483647 (becomes latched)
        assert!(state.update_time(2147483647, 100));
        assert_eq!(state.engine_boots, 2147483647);

        // Now latched - all messages rejected
        assert!(!state.is_in_time_window(2147483647, 100));
    }

    /// Test that update_time correctly handles the comparison when
    /// current boots is high but not yet latched.
    #[test]
    fn test_engine_boots_high_value_update_logic() {
        let mut state = EngineState::new(Bytes::from_static(b"engine"), 2147483640, 1000);

        // Old boot cycles should be rejected
        assert!(!state.update_time(2147483639, 9999));
        assert!(!state.update_time(0, 9999));

        // Same boot, older time should be rejected
        assert!(!state.update_time(2147483640, 500));

        // Same boot, newer time should be accepted
        assert!(state.update_time(2147483640, 1500));
        assert_eq!(state.latest_received_engine_time, 1500);

        // New boot should be accepted
        assert!(state.update_time(2147483641, 100));
        assert_eq!(state.engine_boots, 2147483641);
    }

    /// Test EngineCache behavior with latched engines.
    ///
    /// Even when latched, time tracking updates are accepted (for anti-replay).
    /// The security rejection is enforced by is_in_time_window(), not update_time().
    #[test]
    fn test_engine_cache_latched_engine() {
        let cache = EngineCache::new();
        let addr: SocketAddr = "192.168.1.1:161".parse().unwrap();

        // Insert latched engine
        cache.insert(
            addr,
            EngineState::new(Bytes::from_static(b"latched"), 2147483647, 1000),
        );

        // Time tracking still works
        assert!(
            cache.update_time(&addr, 2147483647, 2000),
            "Time tracking should update even for latched engine"
        );

        // Verify state was updated
        let state = cache.get(&addr).unwrap();
        assert_eq!(state.latest_received_engine_time, 2000);

        // But the key security property: is_in_time_window rejects
        assert!(
            !state.is_in_time_window(2147483647, 2000),
            "Latched engine should reject all time window checks"
        );
    }
}
