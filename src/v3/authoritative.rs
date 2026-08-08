//! Persistent startup state for local authoritative SNMP engines.

use std::fmt::{Debug, Display, Formatter};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use bytes::Bytes;

use crate::error::{Error, Result};
use crate::v3::{MAX_ENGINE_TIME, compute_engine_boots_time, validate_engine_id};

type PersistCallback = Box<dyn FnMut(&PersistedAuthoritativeEngine) -> Result<()> + Send + 'static>;

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
    persisted_boots: AtomicU32,
    engine_start: Instant,
    #[cfg(test)]
    elapsed_override: Option<u64>,
    persist: Mutex<PersistCallback>,
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
    /// again if engine time wraps while the process remains running.
    pub fn install<E, F>(engine_id: impl Into<Bytes>, persist: F) -> Result<Self>
    where
        E: Display,
        F: FnMut(&PersistedAuthoritativeEngine) -> std::result::Result<(), E> + Send + 'static,
    {
        let persisted = PersistedAuthoritativeEngine::new(engine_id, 1)?;
        Self::start(persisted, persist)
    }

    /// Restart an authoritative engine, incrementing and persisting boots
    /// before use.
    ///
    /// At the RFC 3414 maximum, boots remains latched at `2147483647`.
    /// Authenticated inbound messages are then rejected by USM timeliness
    /// processing until the engine is reconfigured with a new engine ID.
    pub fn restart<E, F>(previous: PersistedAuthoritativeEngine, persist: F) -> Result<Self>
    where
        E: Display,
        F: FnMut(&PersistedAuthoritativeEngine) -> std::result::Result<(), E> + Send + 'static,
    {
        let persisted = PersistedAuthoritativeEngine {
            engine_id: previous.engine_id,
            engine_boots: previous.engine_boots.saturating_add(1).min(MAX_ENGINE_TIME),
        };
        Self::start(persisted, persist)
    }

    fn start<E, F>(persisted: PersistedAuthoritativeEngine, mut persist: F) -> Result<Self>
    where
        E: Display,
        F: FnMut(&PersistedAuthoritativeEngine) -> std::result::Result<(), E> + Send + 'static,
    {
        persist_state(&persisted, &mut persist)?;
        let engine_boots = persisted.engine_boots;
        Ok(Self {
            inner: Arc::new(AuthoritativeEngineInner {
                engine_id: persisted.engine_id,
                startup_boots: engine_boots,
                persisted_boots: AtomicU32::new(engine_boots),
                engine_start: Instant::now(),
                #[cfg(test)]
                elapsed_override: None,
                persist: Mutex::new(Box::new(move |state| persist_state(state, &mut persist))),
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
        self.inner.persisted_boots.load(Ordering::Acquire)
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
    /// persistence state.
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
        let (boots, time) = compute_engine_boots_time(self.inner.startup_boots, elapsed);
        if boots <= self.engine_boots() {
            return Ok((boots, time));
        }

        let mut persist = self.inner.persist.lock().map_err(|_| {
            Error::Config("authoritative engine persistence lock poisoned".into()).boxed()
        })?;
        if boots > self.engine_boots() {
            let state = PersistedAuthoritativeEngine {
                engine_id: self.inner.engine_id.clone(),
                engine_boots: boots,
            };
            persist(&state)?;
            self.inner.persisted_boots.store(boots, Ordering::Release);
        }
        Ok((boots, time))
    }

    #[cfg(test)]
    pub(crate) fn for_test(engine_id: impl Into<Bytes>, engine_boots: u32) -> Self {
        let persisted = PersistedAuthoritativeEngine::new(engine_id, engine_boots).unwrap();
        Self::start(persisted, |_| Ok::<(), std::convert::Infallible>(())).unwrap()
    }

    #[cfg(test)]
    pub(crate) fn with_rollover_persistence_failure_for_test(engine_id: impl Into<Bytes>) -> Self {
        let mut first_persist = true;
        let mut engine = Self::install(engine_id, move |_| {
            if std::mem::replace(&mut first_persist, false) {
                Ok(())
            } else {
                Err("storage unavailable")
            }
        })
        .unwrap();
        Arc::get_mut(&mut engine.inner).unwrap().elapsed_override =
            Some(u64::from(MAX_ENGINE_TIME) + 1);
        engine
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

fn persist_state<E, F>(state: &PersistedAuthoritativeEngine, persist: &mut F) -> Result<()>
where
    E: Display,
    F: FnMut(&PersistedAuthoritativeEngine) -> std::result::Result<(), E>,
{
    persist(state).map_err(|error| {
        Error::Config(format!("could not persist authoritative engine state: {error}").into())
            .boxed()
    })
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use super::*;

    const ENGINE_ID: &[u8] = b"local-engine";

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
    fn persistence_failure_prevents_startup_value() {
        let error =
            AuthoritativeEngine::install(ENGINE_ID, |_| Err("storage unavailable")).unwrap_err();
        assert!(error.to_string().contains("storage unavailable"));
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
    fn rollover_persistence_failure_keeps_previous_boots() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_callback = Arc::clone(&calls);
        let engine = AuthoritativeEngine::install(ENGINE_ID, move |_| {
            if calls_for_callback.fetch_add(1, Ordering::Relaxed) == 0 {
                Ok(())
            } else {
                Err("storage unavailable")
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
    fn persisted_state_rejects_invalid_boots() {
        assert!(PersistedAuthoritativeEngine::new(ENGINE_ID, 0).is_err());
        assert!(PersistedAuthoritativeEngine::new(ENGINE_ID, MAX_ENGINE_TIME + 1).is_err());
    }
}
