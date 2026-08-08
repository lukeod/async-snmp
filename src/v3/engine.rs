//! Engine discovery and time synchronization (RFC 3414 Section 4).
//!
//! `SNMPv3` discovers an authoritative engine's identity before authenticated
//! traffic, then establishes boots/time only from an HMAC-verified message.
//! This module keeps those trust domains separate and provides:
//!
//! - `EngineCache`: Thread-safe target identities and per-engine trusted time
//! - `EngineState`: Discovered identity with optional trusted time
//! - Discovery response parsing
//!
//! # Discovery Flow
//!
//! 1. Client sends discovery request (noAuthNoPriv, empty engine ID)
//! 2. Agent responds with Report PDU containing usmStatsUnknownEngineIDs
//! 3. The client adopts only the response's engine ID and message-size limit
//! 4. Its first authenticated request uses boots/time zero
//! 5. An HMAC-verified response or Report establishes trusted boots/time
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
use crate::message_size::{MessageSize, UDP_RECEIVE_LIMITS};
use crate::v3::UsmSecurityParams;

/// Time window in seconds (RFC 3414 Section 2.2.3).
pub const TIME_WINDOW: u32 = 150;

/// Maximum valid snmpEngineTime value (RFC 3414 Section 2.2.1).
///
/// Per RFC 3414, snmpEngineTime is a 31-bit value (0..2,147,483,647).
/// When the value reaches this maximum, the authoritative engine should
/// reset it to zero and increment snmpEngineBoots.
pub const MAX_ENGINE_TIME: u32 = 2_147_483_647;

/// Compute engine boots and time from a base boots value and total elapsed
/// seconds since engine start.
///
/// Per RFC 3414 Section 2.3, engine time spans the complete 31-bit range
/// `0..=MAX_ENGINE_TIME`. On the following second, boots increments and time
/// wraps to zero. The boots value is capped at `MAX_ENGINE_TIME` (the
/// "latched" state per RFC 3414 Section 2.2.3).
#[must_use]
pub fn compute_engine_boots_time(boots_base: u32, total_elapsed_secs: u64) -> (u32, u32) {
    let cycle = u64::from(MAX_ENGINE_TIME) + 1;
    let additional_boots = total_elapsed_secs / cycle;
    let current_time = (total_elapsed_secs % cycle) as u32;
    let boots = (u64::from(boots_base) + additional_boots).min(u64::from(MAX_ENGINE_TIME)) as u32;
    (boots, current_time)
}

/// Minimum valid SnmpEngineID length in octets (RFC 3411 Section 5).
pub const MIN_ENGINE_ID_LEN: usize = 5;

/// Maximum valid SnmpEngineID length in octets (RFC 3411 Section 5).
pub const MAX_ENGINE_ID_LEN: usize = 32;

/// Private Enterprise Number used in generated engine IDs.
///
/// 32473 is the IANA example PEN reserved for documentation and testing
/// (RFC 5612), used here as a stand-in since the crate has no registered
/// enterprise number of its own.
const GENERATED_ENGINE_ID_PEN: u32 = 32473;

/// Format octet value 5: "administratively assigned octets" (RFC 3411
/// Section 5), a variable-length opaque local identifier.
const ENGINE_ID_FORMAT_OCTETS: u8 = 5;

/// Number of random octets appended to a generated engine ID.
const GENERATED_ENGINE_ID_RANDOM_LEN: usize = 12;

/// Generate a locally-unique authoritative SnmpEngineID (RFC 3411 Section 5).
///
/// Layout: a 4-octet enterprise number with the high bit set, followed by a
/// format octet of 5 ("administratively assigned octets"), followed by 12
/// random octets from the OS CSPRNG. The total length is 17 octets, within
/// the RFC 3411 5..32 range. The random suffix ensures two instances started
/// in the same second (or on the same host) do not collide, which would
/// otherwise yield identical localized keys under shared credentials.
#[must_use]
pub fn generate_engine_id() -> Bytes {
    let mut id = Vec::with_capacity(5 + GENERATED_ENGINE_ID_RANDOM_LEN);
    // High bit of the first octet signals the RFC 3411 variable-length format.
    let enterprise = 0x8000_0000_u32 | GENERATED_ENGINE_ID_PEN;
    id.extend_from_slice(&enterprise.to_be_bytes());
    id.push(ENGINE_ID_FORMAT_OCTETS);
    let mut random = [0_u8; GENERATED_ENGINE_ID_RANDOM_LEN];
    getrandom::fill(&mut random).expect("getrandom failed");
    id.extend_from_slice(&random);
    Bytes::from(id)
}

/// Validate a user-configured SnmpEngineID (RFC 3411 Section 5).
///
/// Rejects IDs whose length is outside the 5..32 octet range, IDs that are
/// all zero, and IDs that are all 0xff. All three are invalid or reserved
/// per RFC 3411 and would break USM key localization or engine discovery.
pub fn validate_engine_id(engine_id: &[u8]) -> Result<()> {
    let len = engine_id.len();
    if !(MIN_ENGINE_ID_LEN..=MAX_ENGINE_ID_LEN).contains(&len) {
        return Err(Error::Config(
            format!(
                "engine ID length {len} out of range (must be {MIN_ENGINE_ID_LEN}..={MAX_ENGINE_ID_LEN} octets)"
            )
            .into(),
        )
        .boxed());
    }
    if engine_id.iter().all(|&b| b == 0x00) {
        return Err(Error::Config("engine ID must not be all zero".into()).boxed());
    }
    if engine_id.iter().all(|&b| b == 0xff) {
        return Err(Error::Config("engine ID must not be all 0xff".into()).boxed());
    }
    Ok(())
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

/// HMAC-established notion of an authoritative engine's boots/time tuple.
///
/// Discovery never constructs this value. It is created and advanced only by
/// RFC 3414 Section 3.2 Step 7(b) after a message's HMAC has been verified.
#[derive(Debug, Clone)]
pub struct TrustedEngineTime {
    boots: u32,
    received_time_base: u32,
    received_at: Instant,
    latest_received_time: u32,
}

impl TrustedEngineTime {
    fn new_at(boots: u32, time: u32, now: Instant) -> Self {
        Self {
            boots,
            received_time_base: time,
            received_at: now,
            latest_received_time: time,
        }
    }

    /// The boots value at the last trusted high-water update.
    #[must_use]
    pub fn boots(&self) -> u32 {
        self.boots
    }

    /// The engine time at the last trusted high-water update.
    #[must_use]
    pub fn received_time_base(&self) -> u32 {
        self.received_time_base
    }

    /// The greatest authenticated engine time received for the current boots.
    #[must_use]
    pub fn latest_received_time(&self) -> u32 {
        self.latest_received_time
    }

    fn estimated_at(&self, now: Instant) -> (u32, u32) {
        if self.boots == MAX_ENGINE_TIME {
            return (
                MAX_ENGINE_TIME,
                self.received_time_base.min(MAX_ENGINE_TIME),
            );
        }

        let elapsed = now
            .checked_duration_since(self.received_at)
            .unwrap_or_default()
            .as_secs();
        let total_time = u64::from(self.received_time_base).saturating_add(elapsed);
        let cycle = u64::from(MAX_ENGINE_TIME) + 1;
        let additional_boots = total_time / cycle;
        let engine_time = (total_time % cycle) as u32;
        let engine_boots =
            (u64::from(self.boots) + additional_boots).min(u64::from(MAX_ENGINE_TIME)) as u32;
        (engine_boots, engine_time)
    }

    fn roll_forward_at(&mut self, now: Instant) {
        let (estimated_boots, estimated_time) = self.estimated_at(now);
        if estimated_boots > self.boots {
            self.boots = estimated_boots;
            self.received_time_base = estimated_time;
            self.received_at = now;
            self.latest_received_time = estimated_time;
        }
    }

    fn update_at(&mut self, response_boots: u32, response_time: u32, now: Instant) -> bool {
        self.roll_forward_at(now);
        if response_boots > self.boots
            || (response_boots == self.boots && response_time > self.latest_received_time)
        {
            self.boots = response_boots;
            self.received_time_base = response_time;
            self.received_at = now;
            self.latest_received_time = response_time;
            true
        } else {
            false
        }
    }
}

/// Identity discovered for a remote authoritative engine, with optional
/// HMAC-established trusted time.
#[derive(Debug, Clone)]
pub struct EngineState {
    /// Authoritative engine ID.
    pub(crate) engine_id: Bytes,
    /// Maximum message size the remote engine can accept.
    pub msg_max_size: MessageSize,
    trusted_time: Option<TrustedEngineTime>,
}

impl EngineState {
    /// Create engine state whose boots/time are already authenticated.
    pub fn new(engine_id: Bytes, engine_boots: u32, engine_time: u32) -> Self {
        Self::with_msg_max_size(
            engine_id,
            engine_boots,
            engine_time,
            UDP_RECEIVE_LIMITS.advertised(),
        )
    }

    /// Create an identity learned through unauthenticated discovery.
    #[must_use]
    pub fn discovered(engine_id: Bytes, msg_max_size: MessageSize) -> Self {
        Self {
            engine_id,
            msg_max_size,
            trusted_time: None,
        }
    }

    /// Create authenticated state with explicit msgMaxSize.
    pub fn with_msg_max_size(
        engine_id: Bytes,
        engine_boots: u32,
        engine_time: u32,
        msg_max_size: MessageSize,
    ) -> Self {
        Self {
            engine_id,
            msg_max_size,
            trusted_time: Some(TrustedEngineTime::new_at(
                engine_boots,
                engine_time,
                Instant::now(),
            )),
        }
    }

    /// Create authenticated state with msgMaxSize capped to a session limit.
    pub fn with_msg_max_size_capped(
        engine_id: Bytes,
        engine_boots: u32,
        engine_time: u32,
        reported_msg_max_size: MessageSize,
        session_max: MessageSize,
    ) -> Self {
        Self::with_msg_max_size(
            engine_id,
            engine_boots,
            engine_time,
            cap_msg_max_size(reported_msg_max_size, session_max),
        )
    }

    /// Return the authoritative engine ID.
    #[must_use]
    pub fn engine_id(&self) -> &Bytes {
        &self.engine_id
    }

    /// Return the HMAC-established trusted time, if synchronization occurred.
    #[must_use]
    pub fn trusted_time(&self) -> Option<&TrustedEngineTime> {
        self.trusted_time.as_ref()
    }

    /// Return the progressing trusted boots/time pair, or `(0, 0)` before the
    /// first authenticated message establishes a notion.
    #[must_use]
    pub fn estimated_boots_time(&self) -> (u32, u32) {
        self.estimated_boots_time_at(Instant::now())
    }

    pub(crate) fn estimated_boots_time_at(&self, now: Instant) -> (u32, u32) {
        self.trusted_time
            .as_ref()
            .map_or((0, 0), |time| time.estimated_at(now))
    }

    pub(crate) fn last_trusted_update_at(&self) -> Option<Instant> {
        self.trusted_time.as_ref().map(|time| time.received_at)
    }

    /// Retained convenience accessor for the estimated time component.
    #[must_use]
    pub fn estimated_time(&self) -> u32 {
        self.estimated_boots_time().1
    }

    /// Apply a forward-only authenticated high-water update.
    ///
    /// The caller must have verified the message HMAC and engine identity.
    pub fn update_time(&mut self, response_boots: u32, response_time: u32) -> bool {
        self.update_time_at(response_boots, response_time, Instant::now())
    }

    fn update_time_at(&mut self, response_boots: u32, response_time: u32, now: Instant) -> bool {
        match self.trusted_time.as_mut() {
            Some(time) => time.update_at(response_boots, response_time, now),
            None => {
                self.trusted_time = Some(TrustedEngineTime::new_at(
                    response_boots,
                    response_time,
                    now,
                ));
                true
            }
        }
    }

    /// Merge only a newer trusted notion from another clone of this identity.
    pub(crate) fn merge_from(&mut self, other: &Self) -> bool {
        if self.engine_id != other.engine_id {
            return false;
        }
        self.msg_max_size = self.msg_max_size.min(other.msg_max_size);
        let Some(other_time) = &other.trusted_time else {
            return false;
        };
        match self.trusted_time.as_mut() {
            Some(time) => time.update_at(
                other_time.boots,
                other_time.latest_received_time,
                other_time.received_at,
            ),
            None => {
                self.trusted_time = Some(other_time.clone());
                true
            }
        }
    }

    /// Apply RFC 3414 Step 7(b) and evaluate the asymmetric time window.
    /// The caller must first verify the message HMAC and engine identity.
    pub fn check_and_update_timeliness(&mut self, msg_boots: u32, msg_time: u32) -> bool {
        self.check_and_update_timeliness_at(msg_boots, msg_time, Instant::now())
    }

    fn check_and_update_timeliness_at(
        &mut self,
        msg_boots: u32,
        msg_time: u32,
        now: Instant,
    ) -> bool {
        self.update_time_at(msg_boots, msg_time, now);
        let (local_boots, local_time) = self.estimated_boots_time_at(now);
        local_boots != MAX_ENGINE_TIME
            && msg_boots >= local_boots
            && (msg_boots != local_boots || msg_time >= local_time.saturating_sub(TIME_WINDOW))
    }

    /// Check the authoritative-role symmetric window against trusted time.
    #[must_use]
    pub fn is_in_time_window(&self, msg_boots: u32, msg_time: u32) -> bool {
        let (local_boots, local_time) = self.estimated_boots_time();
        in_authoritative_time_window(local_boots, local_time, msg_boots, msg_time)
    }
}

fn cap_msg_max_size(reported: MessageSize, session_max: MessageSize) -> MessageSize {
    if reported > session_max {
        tracing::debug!(target: "async_snmp::v3", { reported = reported.as_usize(), session_max = session_max.as_usize() }, "capping msgMaxSize to session limit");
        session_max
    } else {
        reported
    }
}

/// Time window check when the local engine's boots/time are the reference
/// (RFC 3414 Section 2.2.3, applied by Section 3.2 Step 7a in the
/// authoritative role).
///
/// The message is in the window only if local boots is not latched at
/// [`MAX_ENGINE_TIME`], the message boots equals local boots, and the message
/// time is within [`TIME_WINDOW`] seconds of local time (symmetric).
///
/// For messages from a remote authoritative engine (Step 7b), use
/// [`EngineState::check_and_update_timeliness`] instead: that check is
/// asymmetric and self-updating.
pub fn in_authoritative_time_window(
    local_boots: u32,
    local_time: u32,
    msg_boots: u32,
    msg_time: u32,
) -> bool {
    local_boots != MAX_ENGINE_TIME
        && msg_boots == local_boots
        && msg_time.abs_diff(local_time) <= TIME_WINDOW
}

/// Default TTL for engine cache entries (5 minutes).
///
/// Entries not refreshed by a successful authenticated exchange within
/// this duration are considered stale for future cache lookups. This avoids
/// handing an old target mapping to newly constructed clients indefinitely;
/// an existing client retains its established identity until
/// [`Client::rediscover_engine`](crate::Client::rediscover_engine) is called.
const DEFAULT_ENGINE_CACHE_TTL: Duration = Duration::from_secs(300);

#[derive(Debug)]
struct CachedTarget {
    engine_id: Bytes,
    msg_max_size: MessageSize,
    refreshed_at: Instant,
}

#[derive(Debug, Default)]
struct EngineCacheInner {
    targets: HashMap<SocketAddr, CachedTarget>,
    trusted_times: HashMap<Bytes, TrustedEngineTime>,
}

/// Thread-safe cache of discovered `SNMPv3` engine state.
///
/// Target addresses map to discovered identities and remote message-size
/// limits. Trusted time is keyed separately by authoritative engine ID, so
/// clients reaching the same engine through multiple targets converge on one
/// high-water value. Whole-state inserts merge monotonically and cannot replace
/// a newer trusted tuple with a stale clone.
///
/// # Entry lifetime
///
/// Each target identity has a refresh timestamp. Every accepted HMAC-verified
/// message refreshes it, including an older in-window message that does not
/// advance trusted time. Entries older than the configured TTL
/// (default 5 minutes) are removed by [`get`](Self::get).
///
/// Expiry prevents a shared entry from being handed indefinitely to newly
/// constructed clients after a target is replaced. It does not silently clear
/// an existing client's established identity; call
/// [`Client::rediscover_engine`](crate::Client::rediscover_engine) to replace it
/// intentionally.
///
/// Actively polled authenticated targets refresh their entry on every accepted
/// HMAC-verified response or Report, so the TTL has no effect during normal
/// authenticated operation.
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
/// ```rust,no_run
/// use async_snmp::{Auth, AuthProtocol, Client, EngineCache};
/// use std::sync::Arc;
///
/// # async fn example() -> async_snmp::Result<()> {
/// let cache = Arc::new(EngineCache::new());
///
/// let client1 = Client::builder("192.168.1.1:161",
///     Auth::usm("admin").auth(AuthProtocol::Sha1, "authpass"))
///     .engine_cache(cache.clone())
///     .connect()
///     .await?;
///
/// let client2 = Client::builder("192.168.1.2:161",
///     Auth::usm("admin").auth(AuthProtocol::Sha1, "authpass"))
///     .engine_cache(cache.clone())
///     .connect()
///     .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct EngineCache {
    inner: RwLock<EngineCacheInner>,
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
            inner: RwLock::new(EngineCacheInner::default()),
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
        self.get_at(target, Instant::now())
    }

    fn get_at(&self, target: &SocketAddr, now: Instant) -> Option<EngineState> {
        let mut inner = self.inner.write().ok()?;
        let cached = inner.targets.get(target)?;
        if now
            .checked_duration_since(cached.refreshed_at)
            .unwrap_or_default()
            > self.ttl
        {
            let engine_id = cached.engine_id.clone();
            inner.targets.remove(target);
            remove_orphaned_time(&mut inner, &engine_id);
            return None;
        }
        compose_cached_state(&inner, target)
    }

    /// Store engine state for a target.
    ///
    /// If a max capacity is set and the cache is full, the least recently
    /// refreshed target identity is evicted.
    pub fn insert(&self, target: SocketAddr, state: EngineState) {
        self.insert_at(target, state, Instant::now());
    }

    fn insert_at(&self, target: SocketAddr, state: EngineState, now: Instant) {
        let _ = self.store_at(target, state, now, false);
    }

    /// Replace one target identity after an explicit, validated rediscovery.
    ///
    /// Unlike ordinary inserts, this deliberately overrides an active
    /// conflicting mapping. Holding the cache write lock makes the replacement
    /// win over stale clients that reinsert the old identity while discovery is
    /// in flight; subsequent ordinary inserts cannot replace the new mapping.
    /// The returned state includes trusted time already shared under the new
    /// authoritative engine ID.
    pub(crate) fn replace_target(
        &self,
        target: SocketAddr,
        state: EngineState,
    ) -> Result<EngineState> {
        self.store_at(target, state, Instant::now(), true)
            .ok_or_else(|| Error::Config("engine cache lock poisoned".into()).boxed())
    }

    fn store_at(
        &self,
        target: SocketAddr,
        state: EngineState,
        now: Instant,
        replace_identity: bool,
    ) -> Option<EngineState> {
        let mut inner = self.inner.write().ok()?;

        if !replace_identity
            && let Some(existing) = inner.targets.get(&target)
            && existing.engine_id != state.engine_id
            && now
                .checked_duration_since(existing.refreshed_at)
                .unwrap_or_default()
                <= self.ttl
        {
            return compose_cached_state(&inner, &target);
        }

        if let Some(cap) = self.max_capacity
            && !inner.targets.contains_key(&target)
            && inner.targets.len() >= cap
            && let Some((oldest_target, oldest_engine)) = inner
                .targets
                .iter()
                .min_by_key(|(_, cached)| cached.refreshed_at)
                .map(|(target, cached)| (*target, cached.engine_id.clone()))
        {
            inner.targets.remove(&oldest_target);
            remove_orphaned_time(&mut inner, &oldest_engine);
        }

        let replaced_engine = inner
            .targets
            .get(&target)
            .filter(|cached| cached.engine_id != state.engine_id)
            .map(|cached| cached.engine_id.clone());
        if let Some(trusted) = &state.trusted_time {
            merge_trusted_time(&mut inner.trusted_times, &state.engine_id, trusted);
        }
        inner.targets.insert(
            target,
            CachedTarget {
                engine_id: state.engine_id,
                msg_max_size: state.msg_max_size,
                refreshed_at: now,
            },
        );
        if let Some(replaced_engine) = replaced_engine {
            remove_orphaned_time(&mut inner, &replaced_engine);
        }
        compose_cached_state(&inner, &target)
    }

    /// Update time for an existing entry after authenticating a message.
    ///
    /// The caller must have verified the message HMAC and engine identity.
    /// Returns true if the entry was updated, false if not found or not updated.
    pub fn update_time(
        &self,
        target: &SocketAddr,
        response_boots: u32,
        response_time: u32,
    ) -> bool {
        self.update_time_at(target, response_boots, response_time, Instant::now())
    }

    fn update_time_at(
        &self,
        target: &SocketAddr,
        response_boots: u32,
        response_time: u32,
        now: Instant,
    ) -> bool {
        let Ok(mut inner) = self.inner.write() else {
            return false;
        };
        let Some(engine_id) = inner
            .targets
            .get(target)
            .map(|cached| cached.engine_id.clone())
        else {
            return false;
        };
        let changed = match inner.trusted_times.get_mut(&engine_id) {
            Some(time) => time.update_at(response_boots, response_time, now),
            None => {
                inner.trusted_times.insert(
                    engine_id,
                    TrustedEngineTime::new_at(response_boots, response_time, now),
                );
                true
            }
        };
        if let Some(cached) = inner.targets.get_mut(target) {
            cached.refreshed_at = now;
        }
        changed
    }

    /// Atomically apply authenticated timeliness processing to shared state.
    ///
    /// The live client's trusted notion is merged before evaluating the
    /// message, so a rebuilt cache cannot weaken that client's time window.
    /// Timely authenticated messages refresh the target TTL, including older
    /// in-window messages that do not advance the high-water mark. Rejected
    /// messages still apply required forward-only high-water processing but do
    /// not refresh the target mapping.
    pub(crate) fn check_and_update_timeliness(
        &self,
        target: &SocketAddr,
        local_state: &EngineState,
        engine_id: &[u8],
        msg_boots: u32,
        msg_time: u32,
    ) -> Option<(bool, EngineState)> {
        self.check_and_update_timeliness_at(
            target,
            local_state,
            engine_id,
            msg_boots,
            msg_time,
            Instant::now(),
        )
    }

    /// Evaluate authenticated timeliness against a coherent live/cache
    /// snapshot without publishing the message tuple or refreshing cache TTL.
    ///
    /// Used while a response to a packet-local compatibility correction is
    /// still provisional. The returned state may be merged only after full
    /// response correlation succeeds.
    pub(crate) fn timeliness_candidate(
        &self,
        target: &SocketAddr,
        local_state: &EngineState,
        engine_id: &[u8],
        msg_boots: u32,
        msg_time: u32,
    ) -> Option<(bool, EngineState)> {
        let inner = self.inner.read().ok()?;
        let cached_engine_id = &inner.targets.get(target)?.engine_id;
        if cached_engine_id.as_ref() != engine_id || local_state.engine_id.as_ref() != engine_id {
            return None;
        }
        let mut candidate = local_state.clone();
        candidate.merge_from(&compose_cached_state(&inner, target)?);
        let timely = candidate.check_and_update_timeliness(msg_boots, msg_time);
        Some((timely, candidate))
    }

    fn check_and_update_timeliness_at(
        &self,
        target: &SocketAddr,
        local_state: &EngineState,
        engine_id: &[u8],
        msg_boots: u32,
        msg_time: u32,
        now: Instant,
    ) -> Option<(bool, EngineState)> {
        let mut inner = self.inner.write().ok()?;
        let cached_engine_id = inner.targets.get(target)?.engine_id.clone();
        if cached_engine_id.as_ref() != engine_id || local_state.engine_id.as_ref() != engine_id {
            return None;
        }
        if let Some(local_time) = &local_state.trusted_time {
            merge_trusted_time(&mut inner.trusted_times, &cached_engine_id, local_time);
        }
        let time = inner
            .trusted_times
            .entry(cached_engine_id.clone())
            .or_insert_with(|| TrustedEngineTime::new_at(msg_boots, msg_time, now));
        time.update_at(msg_boots, msg_time, now);
        let (local_boots, local_time) = time.estimated_at(now);
        let timely = local_boots != MAX_ENGINE_TIME
            && msg_boots >= local_boots
            && (msg_boots != local_boots || msg_time >= local_time.saturating_sub(TIME_WINDOW));
        if timely {
            inner.targets.get_mut(target)?.refreshed_at = now;
        }
        let state = compose_cached_state(&inner, target)?;
        Some((timely, state))
    }

    /// Remove cached identity for a target. Shared trusted time remains while
    /// another target still maps to the same authoritative engine.
    pub fn remove(&self, target: &SocketAddr) -> Option<EngineState> {
        let mut inner = self.inner.write().ok()?;
        let state = compose_cached_state(&inner, target)?;
        let cached = inner.targets.remove(target)?;
        remove_orphaned_time(&mut inner, &cached.engine_id);
        Some(state)
    }

    /// Clear all cached identities and trusted time.
    pub fn clear(&self) {
        if let Ok(mut inner) = self.inner.write() {
            inner.targets.clear();
            inner.trusted_times.clear();
        }
    }

    /// Get the number of cached target identities (including expired entries).
    pub fn len(&self) -> usize {
        self.inner.read().map_or(0, |inner| inner.targets.len())
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn compose_cached_state(inner: &EngineCacheInner, target: &SocketAddr) -> Option<EngineState> {
    let cached = inner.targets.get(target)?;
    Some(EngineState {
        engine_id: cached.engine_id.clone(),
        msg_max_size: cached.msg_max_size,
        trusted_time: inner.trusted_times.get(&cached.engine_id).cloned(),
    })
}

fn merge_trusted_time(
    trusted_times: &mut HashMap<Bytes, TrustedEngineTime>,
    engine_id: &Bytes,
    incoming: &TrustedEngineTime,
) {
    match trusted_times.get_mut(engine_id) {
        Some(current) => {
            current.update_at(
                incoming.boots,
                incoming.latest_received_time,
                incoming.received_at,
            );
        }
        None => {
            trusted_times.insert(engine_id.clone(), incoming.clone());
        }
    }
}

fn remove_orphaned_time(inner: &mut EngineCacheInner, engine_id: &Bytes) {
    if !inner
        .targets
        .values()
        .any(|cached| cached.engine_id == engine_id)
    {
        inner.trusted_times.remove(engine_id);
    }
}

/// Extract engine identity from a discovery response's USM security parameters.
///
/// The discovery response carries boots/time too, but this parser deliberately
/// discards them because the discovery message is unauthenticated.
pub fn parse_discovery_response(security_params: &Bytes) -> Result<EngineState> {
    parse_discovery_response_with_limits(
        security_params,
        UDP_RECEIVE_LIMITS.advertised(),
        UDP_RECEIVE_LIMITS.advertised(),
    )
}

/// Extract engine identity with explicit msgMaxSize and session limit.
///
/// The `reported_msg_max_size` comes from the V3 message header (`MsgGlobalData`).
/// The `session_max` is our transport's maximum message size.
/// Values are capped to prevent issues with non-compliant agents.
pub fn parse_discovery_response_with_limits(
    security_params: &Bytes,
    reported_msg_max_size: MessageSize,
    session_max: MessageSize,
) -> Result<EngineState> {
    let usm = UsmSecurityParams::decode(security_params.clone())?;

    // RFC 3411 Section 5: a valid SnmpEngineID is 5..=32 octets and is neither
    // all-zero nor all-0xff. Reject discovery responses carrying an engine ID
    // outside those bounds (including the empty ID) rather than caching it and
    // deriving unusable localized keys from it.
    if validate_engine_id(&usm.engine_id).is_err() {
        tracing::debug!(target: "async_snmp::engine", { length = usm.engine_id.len() }, "discovery response contained invalid engine ID");
        return Err(Error::MalformedResponse {
            target: SocketAddr::from(([0, 0, 0, 0], 0)),
        }
        .boxed());
    }

    Ok(EngineState::discovered(
        usm.engine_id,
        cap_msg_max_size(reported_msg_max_size, session_max),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_engine_id_is_valid_and_well_formed() {
        let id = generate_engine_id();

        // Valid length within RFC 3411 5..32 range.
        assert!((MIN_ENGINE_ID_LEN..=MAX_ENGINE_ID_LEN).contains(&id.len()));
        validate_engine_id(&id).expect("generated engine ID must validate");

        // High bit of the first octet set -> variable-length format.
        assert_eq!(id[0] & 0x80, 0x80);
        // Enterprise number matches the generator's PEN.
        let enterprise = u32::from_be_bytes([id[0], id[1], id[2], id[3]]);
        assert_eq!(enterprise, 0x8000_0000 | GENERATED_ENGINE_ID_PEN);
        // Format octet is "administratively assigned octets".
        assert_eq!(id[4], ENGINE_ID_FORMAT_OCTETS);
        // Random suffix present.
        assert_eq!(id.len(), 5 + GENERATED_ENGINE_ID_RANDOM_LEN);
    }

    #[test]
    fn test_generate_engine_id_distinct_across_generations() {
        let a = generate_engine_id();
        let b = generate_engine_id();
        assert_ne!(a, b, "two generated engine IDs must not collide");
    }

    #[test]
    fn test_validate_engine_id_rejects_invalid() {
        // Too short.
        assert!(validate_engine_id(&[0x80, 0x00, 0x00, 0x01]).is_err());
        // Too long.
        assert!(validate_engine_id(&[0x11; MAX_ENGINE_ID_LEN + 1]).is_err());
        // All zero.
        assert!(validate_engine_id(&[0x00; 8]).is_err());
        // All 0xff.
        assert!(validate_engine_id(&[0xff; 8]).is_err());
    }

    #[test]
    fn test_validate_engine_id_accepts_valid() {
        // Minimum length. The RFC 3411 format layouts are a recommended
        // generation algorithm, not additional syntax constraints.
        validate_engine_id(&[0x80, 0x00, 0x00, 0x00, 0x01]).unwrap();
        // Maximum length, including an enterprise-defined legacy value.
        validate_engine_id(&[0x22; MAX_ENGINE_ID_LEN]).unwrap();
        // Typical configured text value.
        validate_engine_id(b"my-engine").unwrap();
    }

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
        assert_eq!(state.trusted_time().unwrap().latest_received_time(), 1100);

        // Same boots, older time -> should NOT update
        assert!(!state.update_time(1, 1050));
        assert_eq!(state.trusted_time().unwrap().latest_received_time(), 1100);

        // New boot cycle -> should update
        assert!(state.update_time(2, 500));
        assert_eq!(state.trusted_time().unwrap().boots(), 2);
        assert_eq!(state.trusted_time().unwrap().latest_received_time(), 500);
    }

    /// Test anti-replay protection via latestReceivedEngineTime (RFC 3414 Section 3.2 Step 7b).
    ///
    /// The anti-replay mechanism rejects messages with engine time values that are
    /// not newer than the latest received time. This prevents replay attacks where
    /// an attacker captures and re-sends old authenticated messages.
    #[test]
    fn test_anti_replay_rejects_old_time() {
        let mut state = EngineState::new(Bytes::from_static(b"engine"), 1, 1000);
        assert!(state.update_time(1, 1500));

        // Attempt to replay a message from time 1400 (before latest)
        // update_time returns false, indicating the update was rejected
        assert!(
            !state.update_time(1, 1400),
            "Should reject replay: time 1400 < latest 1500"
        );
        assert_eq!(
            state.trusted_time().unwrap().latest_received_time(),
            1500,
            "Latest should not change"
        );

        // Even time 1500 (equal) should be rejected - must be strictly greater
        assert!(
            !state.update_time(1, 1500),
            "Should reject replay: time 1500 == latest 1500"
        );
        assert_eq!(state.trusted_time().unwrap().latest_received_time(), 1500);

        // Time 1501 (newer) should be accepted
        assert!(
            state.update_time(1, 1501),
            "Should accept: time 1501 > latest 1500"
        );
        assert_eq!(state.trusted_time().unwrap().latest_received_time(), 1501);
    }

    /// Test anti-replay across boot cycles.
    ///
    /// A new boot cycle (higher boots value) always resets the `latest_received_engine_time`
    /// since the agent has rebooted and time values are relative to the boot.
    #[test]
    fn test_anti_replay_new_boot_cycle_resets() {
        let mut state = EngineState::new(Bytes::from_static(b"engine"), 1, 1000);
        assert!(state.update_time(1, 5000));

        // New boot cycle with lower time value - should accept
        // because the engine rebooted (boots increased)
        assert!(
            state.update_time(2, 100),
            "New boot cycle should accept even with lower time"
        );
        assert_eq!(state.trusted_time().unwrap().boots(), 2);
        assert_eq!(state.trusted_time().unwrap().received_time_base(), 100);
        assert_eq!(
            state.trusted_time().unwrap().latest_received_time(),
            100,
            "Latest should reset to new time"
        );

        // Now subsequent updates in the new boot cycle follow normal rules
        assert!(
            !state.update_time(2, 50),
            "Should reject older time in same boot cycle"
        );
        assert!(state.update_time(2, 150), "Should accept newer time");
        assert_eq!(state.trusted_time().unwrap().latest_received_time(), 150);
    }

    /// Test anti-replay rejects old boot cycles.
    ///
    /// An attacker cannot replay messages from a previous boot cycle.
    #[test]
    fn test_anti_replay_rejects_old_boot_cycle() {
        let mut state = EngineState::new(Bytes::from_static(b"engine"), 5, 1000);

        // Attempt to use old boot cycle (boots=4) - should reject
        assert!(
            !state.update_time(4, 9999),
            "Should reject old boot cycle even with high time"
        );
        assert_eq!(
            state.trusted_time().unwrap().boots(),
            5,
            "Boots should not change"
        );
        assert_eq!(
            state.trusted_time().unwrap().latest_received_time(),
            1000,
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
        assert_eq!(state.trusted_time().unwrap().latest_received_time(), 0);

        // Time=1 should be accepted (> 0)
        assert!(state.update_time(1, 1));
        assert_eq!(state.trusted_time().unwrap().latest_received_time(), 1);

        // Time=0 should be rejected (< 1)
        assert!(!state.update_time(1, 0));

        // The largest pre-rollover time can be accepted.
        assert!(state.update_time(1, MAX_ENGINE_TIME - 1));
        assert_eq!(
            state.trusted_time().unwrap().latest_received_time(),
            MAX_ENGINE_TIME - 1
        );

        // The maximum is the final representable high-water value in this boot.
        assert!(state.update_time(1, MAX_ENGINE_TIME));
        assert_eq!(state.estimated_boots_time(), (1, MAX_ENGINE_TIME));
        assert!(!state.update_time(1, MAX_ENGINE_TIME));
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

    /// Non-authoritative timeliness (RFC 3414 Section 3.2 Step 7b): a message
    /// with time within the window is accepted without updating the LCD.
    #[test]
    fn test_check_and_update_timeliness_within_window_accepted() {
        let mut state = EngineState::new(Bytes::from_static(b"engine"), 3, 1000);

        // Older time but within 150s of our notion: accepted, latest unchanged
        assert!(state.check_and_update_timeliness(3, 900));
        assert_eq!(state.trusted_time().unwrap().latest_received_time(), 1000);

        // Exactly at the boundary (1000 - 150 = 850): accepted
        assert!(state.check_and_update_timeliness(3, 850));
    }

    #[test]
    fn test_check_and_update_timeliness_controllable_boundary_without_rollback() {
        let now = Instant::now();
        let mut at_boundary = EngineState::new(Bytes::from_static(b"engine"), 3, 1000);
        at_boundary.trusted_time.as_mut().unwrap().received_at = now;
        assert!(at_boundary.check_and_update_timeliness_at(3, 950, now + Duration::from_secs(100)));
        assert_eq!(
            at_boundary.trusted_time().unwrap().latest_received_time(),
            1000,
            "an older in-window message must not lower the high-water mark"
        );

        let mut outside = EngineState::new(Bytes::from_static(b"engine"), 3, 1000);
        outside.trusted_time.as_mut().unwrap().received_at = now;
        assert!(!outside.check_and_update_timeliness_at(3, 949, now + Duration::from_secs(100)));
        assert_eq!(outside.trusted_time().unwrap().latest_received_time(), 1000);
    }

    #[test]
    fn test_check_and_update_timeliness_newer_time_updates_lcd() {
        let mut state = EngineState::new(Bytes::from_static(b"engine"), 3, 1000);

        assert!(state.check_and_update_timeliness(3, 1200));
        assert_eq!(state.trusted_time().unwrap().latest_received_time(), 1200);
        assert_eq!(state.trusted_time().unwrap().received_time_base(), 1200);
    }

    #[test]
    fn test_check_and_update_timeliness_stale_time_rejected() {
        let mut state = EngineState::new(Bytes::from_static(b"engine"), 3, 1000);

        // 500 < 1000 - 150: replayed/stale message
        assert!(!state.check_and_update_timeliness(3, 500));
        // Just past the boundary
        assert!(!state.check_and_update_timeliness(3, 849));
    }

    #[test]
    fn test_check_and_update_timeliness_old_boots_rejected() {
        let mut state = EngineState::new(Bytes::from_static(b"engine"), 3, 1000);

        assert!(!state.check_and_update_timeliness(2, 5000));
        assert_eq!(
            state.trusted_time().unwrap().boots(),
            3,
            "old boot cycle must not update LCD"
        );
    }

    #[test]
    fn test_check_and_update_timeliness_reboot_accepted() {
        let mut state = EngineState::new(Bytes::from_static(b"engine"), 3, 1000);

        // Sender rebooted: higher boots with low time is accepted and updates LCD
        assert!(state.check_and_update_timeliness(4, 10));
        assert_eq!(state.trusted_time().unwrap().boots(), 4);
        assert_eq!(state.trusted_time().unwrap().latest_received_time(), 10);

        // Messages from the previous boot cycle are now rejected
        assert!(!state.check_and_update_timeliness(3, 99999));
    }

    #[test]
    fn test_check_and_update_timeliness_latched_boots_rejected() {
        let mut state = EngineState::new(Bytes::from_static(b"engine"), MAX_ENGINE_TIME, 1000);

        assert!(!state.check_and_update_timeliness(MAX_ENGINE_TIME, 1000));
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
        assert_eq!(retrieved.trusted_time().unwrap().boots(), 1);

        // Update time
        assert!(cache.update_time(&addr, 1, 1100));

        // Remove
        let removed = cache.remove(&addr).unwrap();
        assert_eq!(removed.trusted_time().unwrap().latest_received_time(), 1100);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_engine_cache_explicit_replacement_latches_new_identity() {
        let cache = EngineCache::new();
        let addr: SocketAddr = "192.168.1.1:161".parse().unwrap();
        let shared_addr: SocketAddr = "192.168.1.2:161".parse().unwrap();
        let old = EngineState::discovered(
            Bytes::from_static(b"old-engine"),
            crate::MessageSize::new(1400).unwrap(),
        );
        let new = EngineState::discovered(
            Bytes::from_static(b"new-engine"),
            crate::MessageSize::new(1500).unwrap(),
        );
        let shared = EngineState::new(Bytes::from_static(b"new-engine"), 7, 500);

        cache.insert(addr, old.clone());
        cache.insert(shared_addr, shared);
        let replaced = cache.replace_target(addr, new).unwrap();
        cache.insert(addr, old);

        assert_eq!(replaced.engine_id().as_ref(), b"new-engine");
        let trusted = replaced.trusted_time().unwrap();
        assert_eq!((trusted.boots(), trusted.latest_received_time()), (7, 500));

        let cached = cache.get(&addr).unwrap();
        assert_eq!(cached.engine_id().as_ref(), b"new-engine");
        assert_eq!(cached.msg_max_size, 1500);
    }

    #[test]
    fn test_engine_cache_shares_trusted_time_by_engine_id() {
        let cache = EngineCache::new();
        let addr1: SocketAddr = "192.168.1.1:161".parse().unwrap();
        let addr2: SocketAddr = "192.168.1.2:161".parse().unwrap();
        let engine_id = Bytes::from_static(b"shared-engine");

        cache.insert(
            addr1,
            EngineState::discovered(engine_id.clone(), crate::MessageSize::new(1400).unwrap()),
        );
        cache.insert(
            addr2,
            EngineState::discovered(engine_id, crate::MessageSize::new(1500).unwrap()),
        );
        assert!(cache.update_time(&addr1, 4, 500));

        let state2 = cache.get(&addr2).unwrap();
        let trusted = state2.trusted_time().unwrap();
        assert_eq!((trusted.boots(), trusted.latest_received_time()), (4, 500));
        assert_eq!(state2.msg_max_size, 1500);
    }

    #[test]
    fn test_engine_cache_stale_clone_cannot_overwrite_newer_time() {
        let cache = EngineCache::new();
        let addr: SocketAddr = "192.168.1.1:161".parse().unwrap();
        let engine_id = Bytes::from_static(b"engine1");

        cache.insert(addr, EngineState::new(engine_id.clone(), 7, 500));
        cache.insert(addr, EngineState::new(engine_id.clone(), 6, 9000));
        cache.insert(
            addr,
            EngineState::discovered(engine_id, crate::MessageSize::new(1400).unwrap()),
        );

        let state = cache.get(&addr).unwrap();
        let trusted = state.trusted_time().unwrap();
        assert_eq!((trusted.boots(), trusted.latest_received_time()), (7, 500));
    }

    #[test]
    fn test_engine_cache_concurrent_updates_converge_monotonically() {
        use std::sync::Arc;

        let cache = Arc::new(EngineCache::new());
        let addr: SocketAddr = "192.168.1.1:161".parse().unwrap();
        cache.insert(
            addr,
            EngineState::discovered(
                Bytes::from_static(b"engine1"),
                crate::MessageSize::new(1400).unwrap(),
            ),
        );

        let older = Arc::clone(&cache);
        let newer = Arc::clone(&cache);
        let older_task = std::thread::spawn(move || {
            for _ in 0..100 {
                older.update_time(&addr, 4, 9000);
            }
        });
        let newer_task = std::thread::spawn(move || {
            for _ in 0..100 {
                newer.update_time(&addr, 5, 10);
            }
        });
        older_task.join().unwrap();
        newer_task.join().unwrap();

        let state = cache.get(&addr).unwrap();
        let trusted = state.trusted_time().unwrap();
        assert_eq!((trusted.boots(), trusted.latest_received_time()), (5, 10));
    }

    #[test]
    fn test_engine_cache_ttl_expiry() {
        let cache = EngineCache::new().with_ttl(Duration::from_secs(5));
        let addr: SocketAddr = "192.168.1.1:161".parse().unwrap();
        let now = Instant::now();

        let state = EngineState::new(Bytes::from_static(b"engine1"), 1, 1000);
        cache.insert_at(addr, state, now);
        assert!(cache.get_at(&addr, now + Duration::from_secs(5)).is_some());
        assert!(
            cache.get_at(&addr, now + Duration::from_secs(6)).is_none(),
            "expired entry should return None"
        );
        assert!(cache.is_empty(), "expired entry should be removed");
    }

    #[test]
    fn test_engine_cache_ttl_refresh_on_every_accepted_authenticated_message() {
        let cache = EngineCache::new().with_ttl(Duration::from_secs(5));
        let addr: SocketAddr = "192.168.1.1:161".parse().unwrap();
        let now = Instant::now();
        let engine_id = Bytes::from_static(b"engine1");
        let local_state = EngineState::new(engine_id.clone(), 1, 1000);

        cache.insert_at(addr, local_state.clone(), now);
        let (timely, _) = cache
            .check_and_update_timeliness_at(
                &addr,
                &local_state,
                &engine_id,
                1,
                900,
                now + Duration::from_secs(4),
            )
            .unwrap();
        assert!(timely, "older in-window input remains acceptable");
        assert!(
            cache.get_at(&addr, now + Duration::from_secs(8)).is_some(),
            "accepted authenticated input must refresh TTL without advancing high-water"
        );
    }

    #[test]
    fn test_engine_cache_live_state_prevents_rebuilt_cache_from_accepting_old_boots() {
        let cache = EngineCache::new();
        let addr: SocketAddr = "192.168.1.1:161".parse().unwrap();
        let now = Instant::now();
        let engine_id = Bytes::from_static(b"engine1");
        let mut local_state = EngineState::new(engine_id.clone(), 5, 1000);
        local_state.trusted_time.as_mut().unwrap().received_at = now;

        cache.insert_at(
            addr,
            EngineState::discovered(engine_id.clone(), crate::MessageSize::new(1400).unwrap()),
            now,
        );
        let (timely, canonical) = cache
            .check_and_update_timeliness_at(
                &addr,
                &local_state,
                &engine_id,
                4,
                5000,
                now + Duration::from_secs(1),
            )
            .unwrap();

        assert!(!timely, "rebuilt cache must not weaken live client state");
        let trusted = canonical.trusted_time().unwrap();
        assert_eq!((trusted.boots(), trusted.latest_received_time()), (5, 1000));
    }

    #[test]
    fn test_engine_cache_rejected_message_does_not_refresh_existing_entry() {
        let cache = EngineCache::new().with_ttl(Duration::from_secs(5));
        let addr: SocketAddr = "192.168.1.1:161".parse().unwrap();
        let now = Instant::now();
        let engine_id = Bytes::from_static(b"engine1");
        let mut local_state = EngineState::new(engine_id.clone(), 5, 1000);
        local_state.trusted_time.as_mut().unwrap().received_at = now;

        cache.insert_at(addr, local_state.clone(), now);
        let (timely, _) = cache
            .check_and_update_timeliness_at(
                &addr,
                &local_state,
                &engine_id,
                4,
                5000,
                now + Duration::from_secs(4),
            )
            .unwrap();
        assert!(!timely);
        assert!(cache.get_at(&addr, now + Duration::from_secs(6)).is_none());
    }

    #[test]
    fn test_engine_cache_rejected_message_does_not_resurrect_expired_entry() {
        let cache = EngineCache::new().with_ttl(Duration::from_secs(5));
        let addr: SocketAddr = "192.168.1.1:161".parse().unwrap();
        let now = Instant::now();
        let engine_id = Bytes::from_static(b"engine1");
        let mut local_state = EngineState::new(engine_id.clone(), 5, 1000);
        local_state.trusted_time.as_mut().unwrap().received_at = now;

        cache.insert_at(addr, local_state.clone(), now);
        let (timely, _) = cache
            .check_and_update_timeliness_at(
                &addr,
                &local_state,
                &engine_id,
                4,
                5000,
                now + Duration::from_secs(6),
            )
            .unwrap();
        assert!(!timely);
        assert!(cache.get_at(&addr, now + Duration::from_secs(6)).is_none());
        assert!(cache.is_empty());
    }

    #[test]
    fn test_engine_cache_max_capacity_eviction() {
        let cache = EngineCache::new().with_max_capacity(2);
        let addr1: SocketAddr = "192.168.1.1:161".parse().unwrap();
        let addr2: SocketAddr = "192.168.1.2:161".parse().unwrap();
        let addr3: SocketAddr = "192.168.1.3:161".parse().unwrap();

        let now = Instant::now();
        cache.insert_at(
            addr1,
            EngineState::new(Bytes::from_static(b"e1"), 1, 100),
            now,
        );
        cache.insert_at(
            addr2,
            EngineState::new(Bytes::from_static(b"e2"), 1, 200),
            now + Duration::from_secs(1),
        );

        assert_eq!(cache.len(), 2);

        // Third insert should evict the least recently refreshed target.
        cache.insert_at(
            addr3,
            EngineState::new(Bytes::from_static(b"e3"), 1, 300),
            now + Duration::from_secs(2),
        );
        assert_eq!(cache.len(), 2);
        assert!(
            cache.get(&addr1).is_none(),
            "oldest entry should be evicted"
        );
        assert!(cache.get(&addr2).is_some());
        assert!(cache.get(&addr3).is_some());
    }

    fn raw_usm_with_engine_id(engine_id: &[u8]) -> Bytes {
        let mut buf = crate::ber::EncodeBuf::new();
        buf.push_sequence(|buf| {
            buf.push_octet_string(&[]);
            buf.push_octet_string(&[]);
            buf.push_octet_string(&[]);
            buf.push_integer(1);
            buf.push_integer(1);
            buf.push_octet_string(engine_id);
        });
        buf.finish()
    }

    #[test]
    fn test_parse_discovery_response() {
        let usm = UsmSecurityParams::new(b"test-engine-id".as_slice(), 42, 12345, b"".as_slice())
            .unwrap();
        let encoded = usm.encode().unwrap();

        let state = parse_discovery_response(&encoded).unwrap();
        assert_eq!(state.engine_id.as_ref(), b"test-engine-id");
        assert!(state.trusted_time().is_none());
        assert_eq!(state.estimated_boots_time(), (0, 0));
    }

    #[test]
    fn test_parse_discovery_response_empty_engine_id() {
        let usm = UsmSecurityParams::discovery();
        let encoded = usm.encode().unwrap();

        let result = parse_discovery_response(&encoded);
        assert!(matches!(
            *result.unwrap_err(),
            Error::MalformedResponse { .. }
        ));
    }

    #[test]
    fn test_parse_discovery_response_rejects_invalid_engine_id() {
        for engine_id in [
            b"abcd".as_slice(),
            [0_u8; 8].as_slice(),
            [0xff_u8; 8].as_slice(),
            [1_u8; 33].as_slice(),
        ] {
            assert!(matches!(
                *parse_discovery_response(&raw_usm_with_engine_id(engine_id)).unwrap_err(),
                Error::MalformedResponse { .. }
            ));
        }
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
        assert_eq!(state.trusted_time().unwrap().boots(), 2_147_483_647);
        assert_eq!(state.trusted_time().unwrap().received_time_base(), 100);
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
        assert_eq!(state.trusted_time().unwrap().latest_received_time(), 2000);

        // Old time rejected per normal anti-replay
        assert!(!state.update_time(2_147_483_647, 1500));
        assert_eq!(state.trusted_time().unwrap().latest_received_time(), 2000);

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

        assert_eq!(state.trusted_time().unwrap().boots(), 2_147_483_647);
        assert_eq!(state.trusted_time().unwrap().received_time_base(), 5000);
        assert_eq!(state.trusted_time().unwrap().latest_received_time(), 5000);

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
        assert_eq!(state.trusted_time().unwrap().boots(), 2_147_483_646);
        assert!(state.is_in_time_window(2_147_483_646, 500));

        // Should accept boot to 2_147_483_647 (becomes latched)
        assert!(state.update_time(2_147_483_647, 100));
        assert_eq!(state.trusted_time().unwrap().boots(), 2_147_483_647);

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
        assert_eq!(state.trusted_time().unwrap().latest_received_time(), 1500);

        // New boot should be accepted
        assert!(state.update_time(2_147_483_641, 100));
        assert_eq!(state.trusted_time().unwrap().boots(), 2_147_483_641);
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
        assert_eq!(state.trusted_time().unwrap().latest_received_time(), 2000);

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
        let state = EngineState::with_msg_max_size(
            Bytes::from_static(b"engine"),
            1,
            1000,
            crate::MessageSize::new(65507).unwrap(),
        );
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
            state.msg_max_size,
            UDP_RECEIVE_LIMITS.advertised(),
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
            MessageSize::new(2_000_000_000).unwrap(), // Agent claims 2GB
            UDP_RECEIVE_LIMITS.advertised(),          // Our session maximum
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
            MessageSize::new(1472).unwrap(), // Agent claims 1472 (Ethernet MTU - headers)
            UDP_RECEIVE_LIMITS.advertised(), // Our session maximum
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
            UDP_RECEIVE_LIMITS.advertised(), // Exactly at session max
            UDP_RECEIVE_LIMITS.advertised(), // Our session maximum
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
            MessageSize::try_from(TCP_MAX).unwrap(),
            MessageSize::try_from(TCP_MAX).unwrap(),
        );
        assert_eq!(state.msg_max_size, TCP_MAX);

        // Values above i32::MAX cannot enter EngineState; wire decoding and
        // transport configuration reject them before session capping.
        assert!(MessageSize::try_from(u32::MAX).is_err());
    }

    /// Test that `EngineState::new` uses the default `msg_max_size` constant.
    #[test]
    fn test_engine_state_new_uses_default_constant() {
        let state = EngineState::new(Bytes::from_static(b"engine"), 1, 1000);

        // UDP_RECEIVE_LIMITS.advertised() is the maximum UDP payload (65507)
        assert_eq!(state.msg_max_size, UDP_RECEIVE_LIMITS.advertised());
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

    /// The maximum time value is representable; rollover occurs one second later.
    #[test]
    fn test_estimated_pair_rolls_after_max_engine_time() {
        let now = Instant::now();
        let mut state = EngineState::new(Bytes::from_static(b"engine"), 1, 0);
        state.trusted_time.as_mut().unwrap().received_at = now;

        assert_eq!(
            state.estimated_boots_time_at(now + Duration::from_secs(u64::from(MAX_ENGINE_TIME))),
            (1, MAX_ENGINE_TIME)
        );
        assert_eq!(
            state
                .estimated_boots_time_at(now + Duration::from_secs(u64::from(MAX_ENGINE_TIME) + 1)),
            (2, 0)
        );
    }

    #[test]
    fn test_max_engine_time_tuple_remains_timely() {
        let now = Instant::now();
        let mut state = EngineState::new(Bytes::from_static(b"engine"), 1, MAX_ENGINE_TIME);
        state.trusted_time.as_mut().unwrap().received_at = now;

        assert!(state.check_and_update_timeliness_at(1, MAX_ENGINE_TIME, now));
        assert_eq!(state.estimated_boots_time_at(now), (1, MAX_ENGINE_TIME));
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
