//! Persistent startup state for local authoritative SNMP engines.

use std::fmt::{Debug, Formatter};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Instant;

use bytes::Bytes;

use crate::error::{Error, Result};
use crate::v3::{MAX_ENGINE_TIME, compute_engine_boots_time, validate_engine_id};

type PersistenceSource = Box<dyn std::error::Error + Send + Sync + 'static>;
type PersistCallback = Box<
    dyn FnMut(&PersistedAuthoritativeEngine) -> std::result::Result<(), PersistenceSource>
        + Send
        + 'static,
>;

/// The authoritative-engine transition whose durable write failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AuthoritativeEnginePersistenceOperation {
    /// Persisting a newly installed engine at boots value 1.
    Install,
    /// Persisting the increment performed when loaded state is restarted.
    Restart,
    /// Persisting an increment after engine time wrapped while running.
    EngineTimeRollover,
}

impl std::fmt::Display for AuthoritativeEnginePersistenceOperation {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Install => "install",
            Self::Restart => "restart",
            Self::EngineTimeRollover => "engine-time rollover",
        })
    }
}

/// Failure returned by an authoritative-engine persistence callback.
///
/// The callback diagnostic is retained, displayed, and exposed as a standard
/// error source. The wrapper itself records only the transition and boots
/// values: it does not retain or display the engine ID or persisted state.
/// Applications must avoid including sensitive persistence data in callback
/// errors.
#[derive(Debug)]
pub struct AuthoritativeEnginePersistenceError {
    operation: AuthoritativeEnginePersistenceOperation,
    previous_engine_boots: Option<u32>,
    attempted_engine_boots: u32,
    source: PersistenceSource,
}

impl AuthoritativeEnginePersistenceError {
    fn new(
        operation: AuthoritativeEnginePersistenceOperation,
        previous_engine_boots: Option<u32>,
        attempted_engine_boots: u32,
        source: PersistenceSource,
    ) -> Self {
        Self {
            operation,
            previous_engine_boots,
            attempted_engine_boots,
            source,
        }
    }

    /// The transition whose durable write failed.
    #[must_use]
    pub fn operation(&self) -> AuthoritativeEnginePersistenceOperation {
        self.operation
    }

    /// The last durable boots value before the attempted transition.
    ///
    /// A new installation has no previous boots value.
    #[must_use]
    pub fn previous_engine_boots(&self) -> Option<u32> {
        self.previous_engine_boots
    }

    /// The boots value passed to the persistence callback.
    #[must_use]
    pub fn attempted_engine_boots(&self) -> u32 {
        self.attempted_engine_boots
    }

    /// The concrete error returned by the persistence callback.
    #[must_use]
    pub fn persistence_source(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
        self.source.as_ref()
    }

    /// Downcast the persistence callback error to a concrete type.
    #[must_use]
    pub fn downcast_source_ref<E: std::error::Error + 'static>(&self) -> Option<&E> {
        self.source.downcast_ref()
    }
}

impl std::fmt::Display for AuthoritativeEnginePersistenceError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.previous_engine_boots {
            Some(previous) => write!(
                f,
                "authoritative engine persistence failed during {} (boots {previous} -> {}): {}",
                self.operation, self.attempted_engine_boots, self.source
            ),
            None => write!(
                f,
                "authoritative engine persistence failed during {} (boots {}): {}",
                self.operation, self.attempted_engine_boots, self.source
            ),
        }
    }
}

impl std::error::Error for AuthoritativeEnginePersistenceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

/// The engine identity and boots counter stored in non-volatile storage.
///
/// Construct this from the values loaded at startup, then pass it to
/// [`AuthoritativeEngine::restart`]. It is deliberately not accepted directly
/// by authoritative protocol roles: the restart transition must increment and
/// persist `snmpEngineBoots` first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedAuthoritativeEngine {
    engine_id: Bytes,
    engine_boots: u32,
}

impl PersistedAuthoritativeEngine {
    /// Validate state loaded from non-volatile storage.
    pub fn new(engine_id: impl Into<Bytes>, engine_boots: u32) -> Result<Self> {
        let engine_id = engine_id.into();
        validate_engine_id(&engine_id)?;
        validate_engine_boots(engine_boots)?;
        Ok(Self {
            engine_id,
            engine_boots,
        })
    }

    /// The stable local authoritative engine ID.
    #[must_use]
    pub fn engine_id(&self) -> &[u8] {
        &self.engine_id
    }

    /// The boots value represented by this stored record.
    #[must_use]
    pub fn engine_boots(&self) -> u32 {
        self.engine_boots
    }
}

/// Startup state for a local authoritative SNMP engine.
///
/// This value can only be created through [`install`](Self::install) or
/// [`restart`](Self::restart). Both constructors invoke and retain the supplied
/// persistence callback. A protocol role cannot receive an unpersisted startup
/// or engine-time rollover value through the public API. Clones share one
/// authoritative clock and persistence state.
///
/// This state is required for an Agent with USM users or V3 trap sinks, a
/// notification receiver with USM users, and a client originating V3 traps.
/// Polling clients and V3 Inform originators do not need local authoritative
/// state because the remote responder is authoritative for those exchanges.
#[derive(Clone)]
pub struct AuthoritativeEngine {
    inner: Arc<AuthoritativeEngineInner>,
}

struct AuthoritativeEngineInner {
    engine_id: Bytes,
    startup_boots: u32,
    clock: AuthoritativeClock,
    engine_start: Instant,
    #[cfg(test)]
    elapsed_override: Option<u64>,
    persist: Mutex<PersistCallback>,
}

struct AuthoritativeClock {
    state: Mutex<AuthoritativeClockState>,
    rollover_finished: Condvar,
    #[cfg(test)]
    rollover_waiters: std::sync::atomic::AtomicUsize,
}

struct AuthoritativeClockState {
    published: (u32, u32),
    rollover_owner: Option<std::thread::ThreadId>,
}

impl Debug for AuthoritativeEngine {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthoritativeEngine")
            .field("engine_id", &self.inner.engine_id)
            .field("startup_boots", &self.inner.startup_boots)
            .field("persisted_boots", &self.engine_boots())
            .finish_non_exhaustive()
    }
}

impl AuthoritativeEngine {
    /// Install a new authoritative engine and persist boots value 1 before use.
    ///
    /// `engine_id` must be retained with the boots counter and reused for every
    /// subsequent call to [`restart`](Self::restart). Generate the ID once with
    /// [`crate::v3::generate_engine_id`] when the application has no
    /// administratively assigned value. The callback is retained and invoked
    /// again if engine time wraps while the process remains running. Callback
    /// errors must convert into a boxed standard error that is `Send + Sync`;
    /// their concrete type remains available through
    /// [`AuthoritativeEnginePersistenceError::downcast_source_ref`]. Runtime
    /// callbacks do not hold the authoritative clock-state lock. Clock calls
    /// that require the in-flight rollover wait and retry, so a callback must
    /// not wait for another thread to advance the same engine. Direct callback
    /// inspection of the engine sees the last published durable tuple.
    pub fn install<E, F>(engine_id: impl Into<Bytes>, persist: F) -> Result<Self>
    where
        E: Into<PersistenceSource>,
        F: FnMut(&PersistedAuthoritativeEngine) -> std::result::Result<(), E> + Send + 'static,
    {
        let persisted = PersistedAuthoritativeEngine::new(engine_id, 1)?;
        Self::start(
            persisted,
            AuthoritativeEnginePersistenceOperation::Install,
            None,
            persist,
        )
    }

    /// Restart an authoritative engine, incrementing and persisting boots
    /// before use.
    ///
    /// At the RFC 3414 maximum, boots remains latched at `2147483647`.
    /// Authenticated inbound messages are then rejected by USM timeliness
    /// processing until the engine is reconfigured with a new engine ID. The
    /// persistence callback has the same error requirements and source
    /// preservation behavior as [`install`](Self::install).
    pub fn restart<E, F>(previous: PersistedAuthoritativeEngine, persist: F) -> Result<Self>
    where
        E: Into<PersistenceSource>,
        F: FnMut(&PersistedAuthoritativeEngine) -> std::result::Result<(), E> + Send + 'static,
    {
        let previous_engine_boots = previous.engine_boots;
        let persisted = PersistedAuthoritativeEngine {
            engine_id: previous.engine_id,
            engine_boots: previous.engine_boots.saturating_add(1).min(MAX_ENGINE_TIME),
        };
        Self::start(
            persisted,
            AuthoritativeEnginePersistenceOperation::Restart,
            Some(previous_engine_boots),
            persist,
        )
    }

    fn start<E, F>(
        persisted: PersistedAuthoritativeEngine,
        operation: AuthoritativeEnginePersistenceOperation,
        previous_engine_boots: Option<u32>,
        mut persist: F,
    ) -> Result<Self>
    where
        E: Into<PersistenceSource>,
        F: FnMut(&PersistedAuthoritativeEngine) -> std::result::Result<(), E> + Send + 'static,
    {
        let mut persist =
            move |state: &PersistedAuthoritativeEngine| persist(state).map_err(Into::into);
        persist_state(&persisted, operation, previous_engine_boots, &mut persist)?;
        let engine_boots = persisted.engine_boots;
        Ok(Self {
            inner: Arc::new(AuthoritativeEngineInner {
                engine_id: persisted.engine_id,
                startup_boots: engine_boots,
                clock: AuthoritativeClock {
                    state: Mutex::new(AuthoritativeClockState {
                        published: (engine_boots, 0),
                        rollover_owner: None,
                    }),
                    rollover_finished: Condvar::new(),
                    #[cfg(test)]
                    rollover_waiters: std::sync::atomic::AtomicUsize::new(0),
                },
                engine_start: Instant::now(),
                #[cfg(test)]
                elapsed_override: None,
                persist: Mutex::new(Box::new(persist)),
            }),
        })
    }

    /// The stable local authoritative engine ID.
    #[must_use]
    pub fn engine_id(&self) -> &[u8] {
        &self.inner.engine_id
    }

    /// The latest successfully persisted boots value.
    #[must_use]
    pub fn engine_boots(&self) -> u32 {
        self.inner
            .clock
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .published
            .0
    }

    /// Return the latest record successfully written by the persistence callback.
    #[must_use]
    pub fn persisted_state(&self) -> PersistedAuthoritativeEngine {
        PersistedAuthoritativeEngine {
            engine_id: self.inner.engine_id.clone(),
            engine_boots: self.engine_boots(),
        }
    }

    /// Return the current authoritative boots/time pair.
    ///
    /// If engine time has wrapped, the incremented boots value is persisted
    /// before it is returned for protocol use. All clones share this clock and
    /// persistence state. Calls racing with a rollover wait for its callback
    /// and retry against the resulting published tuple.
    pub(crate) fn current_boots_time(&self) -> Result<(u32, u32)> {
        #[cfg(not(test))]
        let elapsed = self.inner.engine_start.elapsed().as_secs();
        #[cfg(test)]
        let elapsed = self
            .inner
            .elapsed_override
            .unwrap_or_else(|| self.inner.engine_start.elapsed().as_secs());
        self.current_boots_time_at(elapsed)
    }

    fn current_boots_time_at(&self, elapsed: u64) -> Result<(u32, u32)> {
        let sampled = compute_engine_boots_time(self.inner.startup_boots, elapsed);
        let owner = std::thread::current().id();

        loop {
            let mut clock = self
                .inner
                .clock
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);

            if let Some(rollover_owner) = clock.rollover_owner {
                // A persistence callback can safely inspect its engine. It sees
                // the last durable tuple rather than waiting for itself.
                if rollover_owner == owner {
                    return Ok(clock.published);
                }
                #[cfg(test)]
                self.inner
                    .clock
                    .rollover_waiters
                    .fetch_add(1, std::sync::atomic::Ordering::Release);
                clock = self
                    .inner
                    .clock
                    .rollover_finished
                    .wait(clock)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                #[cfg(test)]
                self.inner
                    .clock
                    .rollover_waiters
                    .fetch_sub(1, std::sync::atomic::Ordering::Release);
                drop(clock);
                continue;
            }

            if sampled <= clock.published {
                return Ok(clock.published);
            }
            if sampled.0 == clock.published.0 {
                clock.published = sampled;
                return Ok(sampled);
            }

            let previous_boots = clock.published.0;
            clock.rollover_owner = Some(owner);
            drop(clock);

            let mut transition = RolloverTransition::new(&self.inner.clock, owner);
            let state = PersistedAuthoritativeEngine {
                engine_id: self.inner.engine_id.clone(),
                engine_boots: sampled.0,
            };
            let result = self
                .inner
                .persist
                .lock()
                .map_err(|_| {
                    Error::Config("authoritative engine persistence lock poisoned".into()).boxed()
                })
                .and_then(|mut persist| {
                    persist_state(
                        &state,
                        AuthoritativeEnginePersistenceOperation::EngineTimeRollover,
                        Some(previous_boots),
                        &mut *persist,
                    )
                });

            match result {
                Ok(()) => return Ok(transition.publish(sampled)),
                Err(error) => return Err(error),
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(engine_id: impl Into<Bytes>, engine_boots: u32) -> Self {
        let persisted = PersistedAuthoritativeEngine::new(engine_id, engine_boots).unwrap();
        Self::start(
            persisted,
            AuthoritativeEnginePersistenceOperation::Install,
            None,
            |_| Ok::<(), std::convert::Infallible>(()),
        )
        .unwrap()
    }

    #[cfg(test)]
    pub(crate) fn with_rollover_persistence_failure_for_test(engine_id: impl Into<Bytes>) -> Self {
        let mut first_persist = true;
        let mut engine = Self::install(engine_id, move |_| {
            if std::mem::replace(&mut first_persist, false) {
                Ok(())
            } else {
                Err(std::io::Error::other("storage unavailable"))
            }
        })
        .unwrap();
        Arc::get_mut(&mut engine.inner).unwrap().elapsed_override =
            Some(u64::from(MAX_ENGINE_TIME) + 1);
        engine
    }

    #[cfg(test)]
    pub(crate) fn set_elapsed_for_test(&mut self, elapsed: u64) {
        Arc::get_mut(&mut self.inner).unwrap().elapsed_override = Some(elapsed);
    }

    #[cfg(test)]
    pub(crate) fn current_boots_time_at_for_test(&self, elapsed: u64) -> Result<(u32, u32)> {
        self.current_boots_time_at(elapsed)
    }
}

struct RolloverTransition<'a> {
    clock: &'a AuthoritativeClock,
    owner: std::thread::ThreadId,
    active: bool,
}

impl<'a> RolloverTransition<'a> {
    fn new(clock: &'a AuthoritativeClock, owner: std::thread::ThreadId) -> Self {
        Self {
            clock,
            owner,
            active: true,
        }
    }

    fn publish(&mut self, pair: (u32, u32)) -> (u32, u32) {
        let mut state = self
            .clock
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        debug_assert_eq!(state.rollover_owner, Some(self.owner));
        state.published = state.published.max(pair);
        let published = state.published;
        state.rollover_owner = None;
        self.active = false;
        drop(state);
        self.clock.rollover_finished.notify_all();
        published
    }
}

impl Drop for RolloverTransition<'_> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut state = self
            .clock
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.rollover_owner == Some(self.owner) {
            state.rollover_owner = None;
        }
        drop(state);
        self.clock.rollover_finished.notify_all();
    }
}

fn validate_engine_boots(engine_boots: u32) -> Result<()> {
    if !(1..=MAX_ENGINE_TIME).contains(&engine_boots) {
        return Err(Error::Config(
            format!("engine boots {engine_boots} out of range (must be 1..={MAX_ENGINE_TIME})")
                .into(),
        )
        .boxed());
    }
    Ok(())
}

fn persist_state(
    state: &PersistedAuthoritativeEngine,
    operation: AuthoritativeEnginePersistenceOperation,
    previous_engine_boots: Option<u32>,
    persist: &mut dyn FnMut(
        &PersistedAuthoritativeEngine,
    ) -> std::result::Result<(), PersistenceSource>,
) -> Result<()> {
    persist(state).map_err(|source| {
        Error::AuthoritativeEnginePersistence(AuthoritativeEnginePersistenceError::new(
            operation,
            previous_engine_boots,
            state.engine_boots,
            source,
        ))
        .boxed()
    })
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::error::Error as _;
    use std::fmt::{Display, Formatter};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier, Mutex, mpsc};
    use std::time::Duration;

    use super::*;

    const ENGINE_ID: &[u8] = b"local-engine";

    #[derive(Debug, PartialEq, Eq)]
    struct PersistenceSentinel(&'static str);

    impl Display for PersistenceSentinel {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.0)
        }
    }

    impl std::error::Error for PersistenceSentinel {}

    fn assert_persistence_error(
        error: &Error,
        operation: AuthoritativeEnginePersistenceOperation,
        previous_engine_boots: Option<u32>,
        attempted_engine_boots: u32,
        marker: &'static str,
    ) {
        assert_eq!(
            error.kind(),
            crate::ErrorKind::AuthoritativeEnginePersistence
        );
        let persistence = error
            .authoritative_engine_persistence()
            .expect("dedicated persistence error");
        assert_eq!(persistence.operation(), operation);
        assert_eq!(persistence.previous_engine_boots(), previous_engine_boots);
        assert_eq!(persistence.attempted_engine_boots(), attempted_engine_boots);
        assert_eq!(
            persistence.downcast_source_ref::<PersistenceSentinel>(),
            Some(&PersistenceSentinel(marker))
        );

        let mut source = error.source();
        while let Some(current) = source {
            if current.downcast_ref::<PersistenceSentinel>().is_some() {
                return;
            }
            source = current.source();
        }
        panic!("persistence sentinel missing from standard error source chain");
    }

    #[test]
    fn install_persists_before_returning() {
        let stored = Arc::new(Mutex::new(None));
        let stored_for_callback = Arc::clone(&stored);
        let engine = AuthoritativeEngine::install(ENGINE_ID, move |state| {
            *stored_for_callback.lock().unwrap() = Some(state.clone());
            Ok::<(), Infallible>(())
        })
        .unwrap();

        assert_eq!(engine.engine_id(), ENGINE_ID);
        assert_eq!(engine.engine_boots(), 1);
        assert_eq!(
            stored.lock().unwrap().as_ref(),
            Some(&engine.persisted_state())
        );
    }

    #[test]
    fn restart_increments_and_persists_before_returning() {
        let previous = PersistedAuthoritativeEngine::new(ENGINE_ID, 41).unwrap();
        let stored = Arc::new(Mutex::new(None));
        let stored_for_callback = Arc::clone(&stored);
        let engine = AuthoritativeEngine::restart(previous, move |state| {
            *stored_for_callback.lock().unwrap() = Some(state.clone());
            Ok::<(), Infallible>(())
        })
        .unwrap();

        assert_eq!(engine.engine_boots(), 42);
        assert_eq!(
            stored.lock().unwrap().as_ref(),
            Some(&engine.persisted_state())
        );
    }

    #[test]
    fn restart_latches_maximum_boots() {
        let previous = PersistedAuthoritativeEngine::new(ENGINE_ID, MAX_ENGINE_TIME).unwrap();
        let engine = AuthoritativeEngine::restart(previous, |_| Ok::<(), Infallible>(())).unwrap();
        assert_eq!(engine.engine_boots(), MAX_ENGINE_TIME);
    }

    #[test]
    fn maximum_boots_latches_maximum_time_without_another_persistence() {
        let previous = PersistedAuthoritativeEngine::new(ENGINE_ID, MAX_ENGINE_TIME).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_callback = Arc::clone(&calls);
        let engine = AuthoritativeEngine::restart(previous, move |_| {
            calls_for_callback.fetch_add(1, Ordering::Relaxed);
            Ok::<(), Infallible>(())
        })
        .unwrap();
        let cycle = u64::from(MAX_ENGINE_TIME) + 1;

        assert_eq!(
            engine.current_boots_time_at(cycle - 1).unwrap(),
            (MAX_ENGINE_TIME, MAX_ENGINE_TIME)
        );
        assert_eq!(
            engine.current_boots_time_at(cycle).unwrap(),
            (MAX_ENGINE_TIME, MAX_ENGINE_TIME)
        );
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn install_persistence_failure_preserves_source_and_transition() {
        let error = AuthoritativeEngine::install(ENGINE_ID, |_| {
            Err(PersistenceSentinel("install unavailable"))
        })
        .unwrap_err();

        assert_persistence_error(
            &error,
            AuthoritativeEnginePersistenceOperation::Install,
            None,
            1,
            "install unavailable",
        );
        assert!(error.to_string().contains("install"));
        assert!(!error.to_string().contains("local-engine"));
    }

    #[test]
    fn restart_persistence_failure_preserves_source_and_boots_transition() {
        let previous = PersistedAuthoritativeEngine::new(ENGINE_ID, 41).unwrap();
        let error = AuthoritativeEngine::restart(previous, |_| {
            Err(PersistenceSentinel("restart unavailable"))
        })
        .unwrap_err();

        assert_persistence_error(
            &error,
            AuthoritativeEnginePersistenceOperation::Restart,
            Some(41),
            42,
            "restart unavailable",
        );
        assert!(error.to_string().contains("boots 41 -> 42"));
        assert!(!error.to_string().contains("local-engine"));
    }

    #[test]
    fn clones_share_clock_and_persist_rollover_before_use() {
        let stored = Arc::new(Mutex::new(Vec::new()));
        let stored_for_callback = Arc::clone(&stored);
        let engine = AuthoritativeEngine::install(ENGINE_ID, move |state| {
            stored_for_callback.lock().unwrap().push(state.clone());
            Ok::<(), Infallible>(())
        })
        .unwrap();
        let clone = engine.clone();
        let cycle = u64::from(MAX_ENGINE_TIME) + 1;

        assert_eq!(engine.current_boots_time_at(123).unwrap(), (1, 123));
        assert_eq!(clone.current_boots_time_at(cycle + 7).unwrap(), (2, 7));
        assert_eq!(engine.engine_boots(), 2);
        assert_eq!(engine.persisted_state().engine_boots(), 2);
        assert_eq!(stored.lock().unwrap().as_slice().len(), 2);
        assert_eq!(stored.lock().unwrap()[1].engine_boots(), 2);
    }

    #[test]
    fn out_of_order_clone_rollover_returns_published_high_water_mark() {
        let stored = Arc::new(Mutex::new(Vec::new()));
        let stored_for_callback = Arc::clone(&stored);
        let callback_calls = Arc::new(AtomicUsize::new(0));
        let calls_for_callback = Arc::clone(&callback_calls);
        let callback_entered = Arc::new(Barrier::new(2));
        let entered_for_callback = Arc::clone(&callback_entered);
        let (release_tx, release_rx) = mpsc::channel();
        let engine = AuthoritativeEngine::install(ENGINE_ID, move |state| {
            stored_for_callback.lock().unwrap().push(state.clone());
            if calls_for_callback.fetch_add(1, Ordering::Relaxed) == 1 {
                entered_for_callback.wait();
                release_rx.recv().unwrap();
            }
            Ok::<(), Infallible>(())
        })
        .unwrap();
        let cycle = u64::from(MAX_ENGINE_TIME) + 1;

        let newer_engine = engine.clone();
        let newer =
            std::thread::spawn(move || newer_engine.current_boots_time_at(2 * cycle).unwrap());
        callback_entered.wait();
        assert_eq!(engine.engine_boots(), 1);

        let older_engine = engine.clone();
        let older =
            std::thread::spawn(move || older_engine.current_boots_time_at(cycle + 17).unwrap());
        let wait_deadline = std::time::Instant::now() + Duration::from_secs(5);
        while engine.inner.clock.rollover_waiters.load(Ordering::Acquire) == 0 {
            assert!(
                std::time::Instant::now() < wait_deadline,
                "older clone did not wait for the in-flight rollover"
            );
            std::thread::yield_now();
        }
        release_tx.send(()).unwrap();

        assert_eq!(newer.join().unwrap(), (3, 0));
        assert_eq!(older.join().unwrap(), (3, 0));
        assert_eq!(engine.current_boots_time_at(cycle + 99).unwrap(), (3, 0));
        assert_eq!(callback_calls.load(Ordering::Relaxed), 2);
        let stored = stored.lock().unwrap();
        assert_eq!(stored.len(), 2);
        assert_eq!(stored[0].engine_boots(), 1);
        assert_eq!(stored[1].engine_boots(), 3);
    }

    #[test]
    fn persistence_callback_can_inspect_clock_without_deadlock() {
        let callback_engine = Arc::new(Mutex::new(None::<AuthoritativeEngine>));
        let engine_for_callback = Arc::clone(&callback_engine);
        let observed = Arc::new(Mutex::new(None));
        let observed_for_callback = Arc::clone(&observed);
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_callback = Arc::clone(&calls);
        let engine = AuthoritativeEngine::install(ENGINE_ID, move |_| {
            if calls_for_callback.fetch_add(1, Ordering::Relaxed) != 0 {
                let engine = engine_for_callback.lock().unwrap().clone().unwrap();
                *observed_for_callback.lock().unwrap() =
                    Some((engine.engine_boots(), engine.current_boots_time().unwrap()));
            }
            Ok::<(), Infallible>(())
        })
        .unwrap();
        *callback_engine.lock().unwrap() = Some(engine.clone());

        let cycle = u64::from(MAX_ENGINE_TIME) + 1;
        assert_eq!(engine.current_boots_time_at(cycle).unwrap(), (2, 0));
        assert_eq!(*observed.lock().unwrap(), Some((1, (1, 0))));
        assert_eq!(engine.engine_boots(), 2);
    }

    #[test]
    fn concurrent_clone_sampling_keeps_one_monotonic_persistence_sequence() {
        const THREADS: usize = 12;
        const SAMPLES: usize = 128;

        let stored = Arc::new(Mutex::new(Vec::new()));
        let stored_for_callback = Arc::clone(&stored);
        let engine = AuthoritativeEngine::install(ENGINE_ID, move |state| {
            stored_for_callback
                .lock()
                .unwrap()
                .push(state.engine_boots());
            Ok::<(), Infallible>(())
        })
        .unwrap();
        let start = Arc::new(Barrier::new(THREADS));
        let cycle = u64::from(MAX_ENGINE_TIME) + 1;

        let threads: Vec<_> = (0..THREADS)
            .map(|thread_index| {
                let engine = engine.clone();
                let start = Arc::clone(&start);
                std::thread::spawn(move || {
                    start.wait();
                    let mut previous = (1, 0);
                    for sample_index in 0..SAMPLES {
                        let cycle_index = (sample_index * 17 + thread_index * 11) % 32;
                        let time = (sample_index * 97 + thread_index * 53) as u64 % cycle;
                        let pair = engine
                            .current_boots_time_at(cycle_index as u64 * cycle + time)
                            .unwrap();
                        assert!(pair >= previous);
                        previous = pair;
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }

        let final_pair = engine
            .current_boots_time_at(31 * cycle + (cycle - 1))
            .unwrap();
        assert_eq!(final_pair, (32, MAX_ENGINE_TIME));
        let stored = stored.lock().unwrap();
        assert_eq!(stored.first(), Some(&1));
        assert_eq!(stored.last(), Some(&32));
        assert!(stored.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn rollover_persistence_failure_keeps_previous_boots() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_callback = Arc::clone(&calls);
        let engine = AuthoritativeEngine::install(ENGINE_ID, move |_| {
            if calls_for_callback.fetch_add(1, Ordering::Relaxed) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::other("storage unavailable"))
            }
        })
        .unwrap();
        let cycle = u64::from(MAX_ENGINE_TIME) + 1;

        let error = engine.current_boots_time_at(cycle).unwrap_err();
        assert!(error.to_string().contains("storage unavailable"));
        assert_eq!(engine.engine_boots(), 1);
        assert_eq!(engine.persisted_state().engine_boots(), 1);
    }

    #[test]
    fn rollover_persistence_failure_preserves_source_and_runtime_transition() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_callback = Arc::clone(&calls);
        let engine = AuthoritativeEngine::install(ENGINE_ID, move |_| {
            if calls_for_callback.fetch_add(1, Ordering::Relaxed) == 0 {
                Ok(())
            } else {
                Err(PersistenceSentinel("rollover unavailable"))
            }
        })
        .unwrap();
        let cycle = u64::from(MAX_ENGINE_TIME) + 1;

        let error = engine.current_boots_time_at(cycle).unwrap_err();
        assert_persistence_error(
            &error,
            AuthoritativeEnginePersistenceOperation::EngineTimeRollover,
            Some(1),
            2,
            "rollover unavailable",
        );
        assert_eq!(engine.engine_boots(), 1);
        assert!(!error.to_string().contains("local-engine"));
    }

    #[test]
    fn persisted_state_rejects_invalid_boots() {
        assert!(PersistedAuthoritativeEngine::new(ENGINE_ID, 0).is_err());
        assert!(PersistedAuthoritativeEngine::new(ENGINE_ID, MAX_ENGINE_TIME + 1).is_err());
    }
}
