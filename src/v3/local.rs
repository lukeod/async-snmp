//! Shared local SNMP engine identity, counters and privacy-sender state.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Instant;

use bytes::Bytes;

use super::process::{
    MpdCounters, UsmStats, V3Inbound, V3LocalContext, V3Role, process_prepared_v3_inbound,
};
use super::{AuthoritativeEngine, DesSaltState, SaltCounter, compute_engine_boots_time};
use crate::{DecodeConfig, Error, MessageSize, ProcessingInput, Result};

/// Current persistence health of a local authoritative SNMP engine.
///
/// All roles sharing a [`LocalEngine`] observe the same bounded, coalesced
/// state. A later successful clock acquisition restores `Healthy`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum LocalEngineHealth {
    /// No unresolved authoritative persistence failure.
    Healthy,
    /// Traffic requiring unavailable local authoritative state is withheld.
    AuthoritativePersistenceDegraded {
        /// Failed acquisitions during the current outage.
        consecutive_failures: u64,
        /// Durable transition whose publication failed.
        operation: super::AuthoritativeEnginePersistenceOperation,
        /// Last durable boots value.
        previous_engine_boots: Option<u32>,
        /// Boots value passed to the persistence callback.
        attempted_engine_boots: u32,
    },
}

/// Local SNMP engine state shared independently of sockets and applications.
///
/// Clones share identity, authoritative clock, engine counters, persistence
/// health and privacy-sender state. Credentials, remote-engine timeliness,
/// access control and delivery policy belong to the selected application or
/// security context. Construct one handle and pass clones to managed builders
/// with `local_engine` when those services represent one SNMP engine.
///
/// ```rust
/// use async_snmp::{AuthoritativeEngine, LocalEngine, NotificationReceiver};
/// use std::convert::Infallible;
/// # fn example() -> async_snmp::Result<()> {
/// let authoritative = AuthoritativeEngine::install(b"shared-engine".as_slice(), |_| {
///     Ok::<_, Infallible>(())
/// })?;
/// let engine = LocalEngine::new(authoritative)?;
/// let first = NotificationReceiver::builder().local_engine(engine.clone());
/// let second = NotificationReceiver::builder().local_engine(engine);
/// # let _ = (first, second);
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct LocalEngine {
    pub(crate) inner: Arc<LocalEngineInner>,
}

pub(crate) struct LocalEngineInner {
    pub(crate) authoritative_engine: Option<AuthoritativeEngine>,
    pub(crate) engine_id: Bytes,
    pub(crate) engine_start: Instant,
    pub(crate) engine_boots_base: u32,
    pub(crate) authoritative_snapshot: AtomicU64,
    #[cfg(test)]
    pub(crate) authoritative_elapsed_override: AtomicU64,
    pub(crate) usm_stats: Arc<UsmStats>,
    pub(crate) snmp_in_asn_parse_errs: Arc<AtomicU32>,
    pub(crate) snmp_invalid_msgs: Arc<AtomicU32>,
    pub(crate) snmp_unknown_security_models: Arc<AtomicU32>,
    pub(crate) snmp_silent_drops: Arc<AtomicU32>,
    #[cfg(feature = "agent")]
    pub(crate) snmp_unknown_contexts: AtomicU32,
    pub(crate) health: tokio::sync::watch::Sender<LocalEngineHealth>,
    salt_counter: OnceLock<Arc<SaltCounter>>,
    des_salt_state: RwLock<LocalDesState>,
    capacities: Mutex<BTreeMap<u64, RegisteredCapacity>>,
    next_capacity: AtomicU64,
}

struct RegisteredCapacity {
    advertised: MessageSize,
    #[cfg(feature = "agent")]
    endpoint: bool,
}

// Retain the allocator after removal so an independent same-epoch state cannot
// reset salts. Authoritative boots are monotonic, so one latest epoch suffices.
struct LocalDesState {
    current: Option<DesSaltState>,
    latest: Option<DesSaltState>,
}

impl std::fmt::Debug for LocalEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalEngine")
            .field("engine_id", &self.engine_id())
            .field("health", &self.health())
            .field("receive_capacity", &self.receive_capacity())
            .finish_non_exhaustive()
    }
}

impl LocalEngine {
    /// Prepare shared state around an already installed or restarted engine.
    ///
    /// This does not restart the authoritative engine. Sampling its current
    /// clock may persist a runtime rollover. AES salt initialization can return
    /// [`Error::RandomSource`]. No sockets or background tasks are created.
    pub fn new(engine: AuthoritativeEngine) -> Result<Self> {
        let boots = engine.current_boots_time()?.0;
        let id = Bytes::copy_from_slice(engine.engine_id());
        Ok(Self::from_prepared(
            Some(engine),
            id,
            boots,
            Some(Arc::new(SaltCounter::new()?)),
            None,
        ))
    }

    pub(crate) fn from_prepared(
        authoritative_engine: Option<AuthoritativeEngine>,
        engine_id: Bytes,
        engine_boots: u32,
        salt_counter: Option<Arc<SaltCounter>>,
        des_salt_state: Option<DesSaltState>,
    ) -> Self {
        let salt = OnceLock::new();
        if let Some(counter) = salt_counter {
            let _ = salt.set(counter);
        }
        Self {
            inner: Arc::new(LocalEngineInner {
                authoritative_engine,
                engine_id,
                engine_start: Instant::now(),
                engine_boots_base: engine_boots,
                authoritative_snapshot: AtomicU64::new(pack_boots_time((engine_boots, 0))),
                #[cfg(test)]
                authoritative_elapsed_override: AtomicU64::new(u64::MAX),
                usm_stats: Arc::new(UsmStats::default()),
                snmp_in_asn_parse_errs: Arc::new(AtomicU32::new(0)),
                snmp_invalid_msgs: Arc::new(AtomicU32::new(0)),
                snmp_unknown_security_models: Arc::new(AtomicU32::new(0)),
                snmp_silent_drops: Arc::new(AtomicU32::new(0)),
                #[cfg(feature = "agent")]
                snmp_unknown_contexts: AtomicU32::new(0),
                health: tokio::sync::watch::channel(LocalEngineHealth::Healthy).0,
                salt_counter: salt,
                des_salt_state: RwLock::new(LocalDesState {
                    current: des_salt_state.clone(),
                    latest: des_salt_state,
                }),
                capacities: Mutex::new(BTreeMap::new()),
                next_capacity: AtomicU64::new(1),
            }),
        }
    }

    /// The stable local engine identity.
    pub fn engine_id(&self) -> &[u8] {
        &self.inner.engine_id
    }

    /// Answer SNMPv3 discovery for a packet with no selected application.
    ///
    /// Choose this engine as the authoritative identity the endpoint advertises.
    /// Empty, invalid, and foreign IDs record an unknown-engine failure and use
    /// the common Report rules and the receive and send limits on `input`. A
    /// packet naming this engine returns `None`. Send any resulting Report on
    /// the original UDP route or exact TCP session. A selected notification
    /// listener handles discovery through [`crate::NotificationProcessor::process`].
    pub fn report_unknown_engine(
        &self,
        input: ProcessingInput,
        decode_config: DecodeConfig,
    ) -> Result<Option<Bytes>> {
        let (packet, limits) = input.into_parts();
        let (data, info, prepared) = packet.into_prepared();
        let clock = || self.current_boots_time();
        let context = V3LocalContext {
            engine_id: &self.inner.engine_id,
            engine_boots: 0,
            engine_time: 0,
            authoritative_time: Some(&clock),
            local_receive_capacity: limits.receive().advertised(),
            accepted_receive_size: limits.receive().accepted(),
            decode_config,
            outbound_limit: limits.send(),
            usm_users: None,
            stats: &self.inner.usm_stats,
            mpd: Some(MpdCounters {
                invalid_msgs: &self.inner.snmp_invalid_msgs,
                unknown_security_models: &self.inner.snmp_unknown_security_models,
            }),
            source: info.peer_addr(),
        };
        let result = process_prepared_v3_inbound(data, &context, &V3Role::Unclaimed, prepared).map(
            |inbound| match inbound {
                V3Inbound::Failed { report, .. } => report,
                _ => None,
            },
        );
        self.count_asn_parse_error(&result);
        result
    }

    pub(crate) fn count_asn_parse_error<T>(&self, result: &Result<T>) {
        use crate::DecodeErrorKind;

        if matches!(result, Err(error) if matches!(&**error,
            Error::Decode(error) if !matches!(error.kind, DecodeErrorKind::UnknownVersion(_)
                | DecodeErrorKind::InvalidMsgFlags | DecodeErrorKind::UnknownSecurityModel(_))))
        {
            self.inner
                .snmp_in_asn_parse_errs
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// The persisted authoritative state, absent only for internally generated
    /// community-only engines.
    pub fn authoritative_engine(&self) -> Option<&AuthoritativeEngine> {
        self.inner.authoritative_engine.as_ref()
    }

    /// Acquire one current coherent boots/time pair and publish engine health.
    /// A persistence failure returns an error without publishing an undurable pair.
    pub fn current_boots_time(&self) -> Result<(u32, u32)> {
        #[cfg(test)]
        let result = match self
            .inner
            .authoritative_elapsed_override
            .load(Ordering::Relaxed)
        {
            u64::MAX => self.sample_boots_time(),
            elapsed => Ok(compute_engine_boots_time(
                self.inner.engine_boots_base,
                elapsed,
            )),
        };
        #[cfg(not(test))]
        let result = self.sample_boots_time();
        match result {
            Ok(pair) => {
                self.inner.health.send_if_modified(|health| {
                    if *health == LocalEngineHealth::Healthy {
                        false
                    } else {
                        *health = LocalEngineHealth::Healthy;
                        true
                    }
                });
                Ok(self.publish_boots_time(pair))
            }
            Err(error) => {
                if let Some(persistence) = error.authoritative_engine_persistence() {
                    self.inner.health.send_modify(|health| {
                        let consecutive_failures = match *health {
                            LocalEngineHealth::Healthy => 1,
                            LocalEngineHealth::AuthoritativePersistenceDegraded {
                                consecutive_failures,
                                ..
                            } => consecutive_failures.saturating_add(1),
                        };
                        *health = LocalEngineHealth::AuthoritativePersistenceDegraded {
                            consecutive_failures,
                            operation: persistence.operation(),
                            previous_engine_boots: persistence.previous_engine_boots(),
                            attempted_engine_boots: persistence.attempted_engine_boots(),
                        };
                    });
                }
                Err(error)
            }
        }
    }

    fn sample_boots_time(&self) -> Result<(u32, u32)> {
        self.inner.authoritative_engine.as_ref().map_or_else(
            || {
                Ok(compute_engine_boots_time(
                    self.inner.engine_boots_base,
                    self.inner.engine_start.elapsed().as_secs(),
                ))
            },
            AuthoritativeEngine::current_boots_time,
        )
    }

    pub(crate) fn publish_boots_time(&self, pair: (u32, u32)) -> (u32, u32) {
        let packed = pack_boots_time(pair);
        unpack_boots_time(
            self.inner
                .authoritative_snapshot
                .fetch_max(packed, Ordering::Relaxed)
                .max(packed),
        )
    }

    /// Current shared authoritative persistence health.
    pub fn health(&self) -> LocalEngineHealth {
        *self.inner.health.borrow()
    }

    /// Sample the shared local USM statistics without exposing mutable counters.
    pub fn usm_stats(&self) -> super::UsmStatsSnapshot {
        self.inner.usm_stats.snapshot()
    }

    /// Observe the latest shared persistence health without unbounded events.
    pub fn subscribe_health(&self) -> tokio::sync::watch::Receiver<LocalEngineHealth> {
        self.inner.health.subscribe()
    }

    /// Replace or remove the shared durable DES/3DES generating state.
    ///
    /// The new state's boots must match the current authoritative boots.
    /// Validation failures leave the previous state in place. Responses already
    /// encoding retain their snapshot; response encoding also validates boots.
    /// Within a boots epoch, only clones of the previously installed allocator
    /// are accepted, including after removal. A distinct allocator requires a
    /// matching later authoritative boots epoch. This method does not install
    /// or restart the supplied durable state.
    pub fn set_des_salt_state(&self, state: Option<DesSaltState>) -> Result<()> {
        if let Some(state) = &state
            && self.current_boots_time()?.0 != state.engine_boots()
        {
            return Err(Error::Config(
                "DES sender boots must match the local authoritative engine boots".into(),
            )
            .boxed());
        }
        let mut shared = self.inner.des_salt_state.write().unwrap();
        if let Some(state) = &state {
            if let Some(previous) = &shared.latest
                && (previous.engine_boots() > state.engine_boots()
                    || (previous.engine_boots() == state.engine_boots()
                        && !previous.same_allocator(state)))
            {
                return Err(Error::Config(
                    "DES sender state must retain its allocator within a boots epoch".into(),
                )
                .boxed());
            }
            shared.latest = Some(state.clone());
        }
        shared.current = state;
        Ok(())
    }

    /// Snapshot the shared durable DES/3DES generating state.
    pub fn des_salt_state(&self) -> Option<DesSaltState> {
        self.inner.des_salt_state.read().unwrap().current.clone()
    }

    pub(crate) fn salt_counter(&self) -> Option<Arc<SaltCounter>> {
        self.inner.salt_counter.get().cloned()
    }

    pub(crate) fn ensure_salt_counter(
        &self,
        create: impl FnOnce() -> Result<SaltCounter>,
    ) -> Result<()> {
        if self.inner.salt_counter.get().is_none() {
            let _ = self.inner.salt_counter.set(Arc::new(create()?));
        }
        Ok(())
    }

    /// Minimum advertised receive capacity of declared endpoints and retained
    /// processing inputs. UDP endpoints and configured TCP sessions unregister
    /// when they close. TCP listener registrations remain through service drain.
    /// Client registrations remain until their last clone is dropped.
    /// Caller-owned command processing retains admitted input capacity through
    /// cleanup. Returns `None` while no registrations remain. Per-message v3
    /// advertisement uses the receiving endpoint's own capacity.
    pub fn receive_capacity(&self) -> Option<MessageSize> {
        self.inner
            .capacities
            .lock()
            .unwrap()
            .values()
            .map(|entry| entry.advertised)
            .min()
    }

    #[cfg(feature = "agent")]
    pub(crate) fn declared_receive_capacity(&self) -> Option<MessageSize> {
        self.inner
            .capacities
            .lock()
            .unwrap()
            .values()
            .filter(|entry| entry.endpoint)
            .map(|entry| entry.advertised)
            .min()
    }

    /// Register a caller-owned endpoint's advertised receive capacity.
    ///
    /// Retain the returned registration while that endpoint serves this engine.
    /// Register every endpoint; the engine MIB reports their minimum. Dropping
    /// the registration removes that capacity. This creates no I/O or tasks.
    pub fn register_receive_capacity(&self, capacity: MessageSize) -> ReceiveCapacityRegistration {
        let id = self.inner.next_capacity.fetch_add(1, Ordering::Relaxed);
        self.inner.capacities.lock().unwrap().insert(
            id,
            RegisteredCapacity {
                advertised: capacity,
                #[cfg(feature = "agent")]
                endpoint: true,
            },
        );
        ReceiveCapacityRegistration {
            engine: self.clone(),
            id,
        }
    }

    #[cfg(feature = "agent")]
    pub(crate) fn register_processing_capacity(
        &self,
        capacity: MessageSize,
    ) -> Result<ReceiveCapacityRegistration> {
        let mut registered = self.inner.capacities.lock().unwrap();
        if registered
            .values()
            .filter(|entry| entry.endpoint)
            .map(|entry| entry.advertised)
            .min()
            .is_none_or(|minimum| minimum > capacity)
        {
            return Err(Error::Config(
                "register the caller-owned endpoint receive capacity before command processing"
                    .into(),
            )
            .boxed());
        }
        let id = self.inner.next_capacity.fetch_add(1, Ordering::Relaxed);
        registered.insert(
            id,
            RegisteredCapacity {
                advertised: capacity,
                endpoint: false,
            },
        );
        Ok(ReceiveCapacityRegistration {
            engine: self.clone(),
            id,
        })
    }
}

/// Lifetime registration of one endpoint's advertised receive capacity.
/// Dropping it removes that endpoint from the local engine minimum.
#[must_use = "retain the registration while the caller-owned endpoint serves this engine"]
pub struct ReceiveCapacityRegistration {
    engine: LocalEngine,
    id: u64,
}

impl Drop for ReceiveCapacityRegistration {
    fn drop(&mut self) {
        self.engine
            .inner
            .capacities
            .lock()
            .unwrap()
            .remove(&self.id);
    }
}

pub(crate) const fn pack_boots_time((boots, time): (u32, u32)) -> u64 {
    (boots as u64) << 32 | time as u64
}

pub(crate) const fn unpack_boots_time(packed: u64) -> (u32, u32) {
    ((packed >> 32) as u32, packed as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;
    use std::sync::atomic::AtomicBool;

    #[test]
    fn clones_share_salts_counters_clock_and_capacity_registrations() {
        let engine = LocalEngine::new(AuthoritativeEngine::for_test(
            b"shared-local-engine".as_slice(),
            3,
        ))
        .unwrap();
        let other = engine.clone();
        assert!(Arc::ptr_eq(
            &engine.salt_counter().unwrap(),
            &other.salt_counter().unwrap()
        ));
        engine
            .inner
            .usm_stats
            .unknown_usernames
            .fetch_add(1, Ordering::Relaxed);
        assert_eq!(
            other
                .inner
                .usm_stats
                .unknown_usernames
                .load(Ordering::Relaxed),
            1
        );
        let first = engine.register_receive_capacity(MessageSize::new(8192).unwrap());
        let second = other.register_receive_capacity(MessageSize::new(32768).unwrap());
        assert_eq!(other.receive_capacity().unwrap().as_usize(), 8192);
        drop(first);
        assert_eq!(engine.receive_capacity().unwrap().as_usize(), 32768);
        drop(second);
        assert_eq!(other.receive_capacity(), None);
        engine
            .inner
            .authoritative_elapsed_override
            .store(100, Ordering::Relaxed);
        assert_eq!(other.current_boots_time().unwrap(), (3, 100));
    }

    #[test]
    fn shared_health_records_persistence_failure_and_recovery() {
        let unavailable = Arc::new(AtomicBool::new(false));
        let fail = unavailable.clone();
        let authoritative =
            AuthoritativeEngine::install(b"health-local-engine".as_slice(), move |_| {
                if fail.load(Ordering::Relaxed) {
                    Err(std::io::Error::other("storage unavailable"))
                } else {
                    Ok(())
                }
            })
            .unwrap();
        let engine = LocalEngine::new(authoritative.clone()).unwrap();
        let other = engine.clone();
        unavailable.store(true, Ordering::Relaxed);
        authoritative.set_elapsed_for_test(u64::from(super::super::MAX_ENGINE_TIME) + 1);
        assert!(engine.current_boots_time().is_err());
        assert!(matches!(
            other.health(),
            LocalEngineHealth::AuthoritativePersistenceDegraded {
                consecutive_failures: 1,
                ..
            }
        ));
        assert!(other.current_boots_time().is_err());
        assert!(matches!(
            engine.health(),
            LocalEngineHealth::AuthoritativePersistenceDegraded {
                consecutive_failures: 2,
                ..
            }
        ));
        assert_eq!(authoritative.engine_boots(), 1);
        unavailable.store(false, Ordering::Relaxed);
        let pair = other.current_boots_time().unwrap();
        assert_eq!(pair.0, 2);
        assert_eq!(engine.health(), LocalEngineHealth::Healthy);
        assert_eq!(
            unpack_boots_time(engine.inner.authoritative_snapshot.load(Ordering::Relaxed)),
            pair
        );
    }

    #[test]
    fn des_replacement_is_shared_and_rejects_an_incompatible_boots_epoch() {
        let engine = LocalEngine::new(AuthoritativeEngine::for_test(
            b"des-local-engine".as_slice(),
            1,
        ))
        .unwrap();
        let other = engine.clone();
        let state = DesSaltState::install(|_| Ok::<_, Infallible>(())).unwrap();
        engine.set_des_salt_state(Some(state.clone())).unwrap();
        let first = other.des_salt_state().unwrap().reserve().unwrap();
        let second = state.reserve().unwrap();
        assert_eq!(second.salt(), first.salt() + 1);
        let wrong =
            DesSaltState::restart(state.persisted_state(), |_| Ok::<_, Infallible>(())).unwrap();
        assert!(other.set_des_salt_state(Some(wrong)).is_err());
        assert_eq!(engine.des_salt_state().unwrap().engine_boots(), 1);
        engine.set_des_salt_state(None).unwrap();
        assert!(other.des_salt_state().is_none());
    }

    #[test]
    fn des_same_epoch_replacement_cannot_reset_salts_after_removal() {
        let authoritative = AuthoritativeEngine::for_test(b"des-epoch-engine".as_slice(), 1);
        let engine = LocalEngine::new(authoritative.clone()).unwrap();
        let first = DesSaltState::install(|_| Ok::<_, Infallible>(())).unwrap();
        let independent = DesSaltState::install(|_| Ok::<_, Infallible>(())).unwrap();
        engine.set_des_salt_state(Some(first.clone())).unwrap();
        let reserved = engine.des_salt_state().unwrap().reserve().unwrap();
        assert!(
            engine
                .set_des_salt_state(Some(independent.clone()))
                .is_err()
        );
        engine.set_des_salt_state(Some(first.clone())).unwrap();
        assert_eq!(
            engine.des_salt_state().unwrap().reserve().unwrap().salt(),
            reserved.salt() + 1
        );
        engine.set_des_salt_state(None).unwrap();
        assert!(engine.set_des_salt_state(Some(independent)).is_err());
        assert!(engine.des_salt_state().is_none());
        engine.set_des_salt_state(Some(first.clone())).unwrap();
        assert_eq!(
            engine.des_salt_state().unwrap().reserve().unwrap().salt(),
            reserved.salt() + 2
        );
        let restarted =
            DesSaltState::restart(first.persisted_state(), |_| Ok::<_, Infallible>(())).unwrap();
        authoritative.set_elapsed_for_test(u64::from(super::super::MAX_ENGINE_TIME) + 1);
        assert_eq!(engine.current_boots_time().unwrap().0, 2);
        engine.set_des_salt_state(Some(restarted)).unwrap();
        assert_eq!(
            engine
                .des_salt_state()
                .unwrap()
                .reserve()
                .unwrap()
                .engine_boots(),
            2
        );
        assert!(engine.set_des_salt_state(Some(first)).is_err());
    }
}
