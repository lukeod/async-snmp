//! Persistent startup state for local authoritative SNMP engines.

use std::fmt::Display;

use bytes::Bytes;

use crate::error::{Error, Result};
use crate::v3::{MAX_ENGINE_TIME, validate_engine_id};

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
/// [`restart`](Self::restart). Both constructors invoke the supplied
/// persistence callback before returning, so a protocol role cannot receive
/// an unpersisted startup value through the public API.
#[derive(Debug, Clone)]
pub struct AuthoritativeEngine {
    persisted: PersistedAuthoritativeEngine,
}

impl AuthoritativeEngine {
    /// Install a new authoritative engine and persist boots value 1 before use.
    ///
    /// `engine_id` must be retained with the boots counter and reused for every
    /// subsequent call to [`restart`](Self::restart). Generate the ID once with
    /// [`crate::v3::generate_engine_id`] when the application has no
    /// administratively assigned value.
    pub fn install<E, F>(engine_id: impl Into<Bytes>, persist: F) -> Result<Self>
    where
        E: Display,
        F: FnOnce(&PersistedAuthoritativeEngine) -> std::result::Result<(), E>,
    {
        let persisted = PersistedAuthoritativeEngine::new(engine_id, 1)?;
        persist_state(&persisted, persist)?;
        Ok(Self { persisted })
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
        F: FnOnce(&PersistedAuthoritativeEngine) -> std::result::Result<(), E>,
    {
        let persisted = PersistedAuthoritativeEngine {
            engine_id: previous.engine_id,
            engine_boots: previous.engine_boots.saturating_add(1).min(MAX_ENGINE_TIME),
        };
        persist_state(&persisted, persist)?;
        Ok(Self { persisted })
    }

    /// The stable local authoritative engine ID.
    #[must_use]
    pub fn engine_id(&self) -> &[u8] {
        self.persisted.engine_id()
    }

    /// The current, already-persisted startup boots value.
    #[must_use]
    pub fn engine_boots(&self) -> u32 {
        self.persisted.engine_boots()
    }

    /// Return the record that was persisted before this value was created.
    #[must_use]
    pub fn persisted_state(&self) -> &PersistedAuthoritativeEngine {
        &self.persisted
    }

    #[cfg(test)]
    pub(crate) fn for_test(engine_id: impl Into<Bytes>, engine_boots: u32) -> Self {
        Self {
            persisted: PersistedAuthoritativeEngine::new(engine_id, engine_boots).unwrap(),
        }
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

fn persist_state<E, F>(state: &PersistedAuthoritativeEngine, persist: F) -> Result<()>
where
    E: Display,
    F: FnOnce(&PersistedAuthoritativeEngine) -> std::result::Result<(), E>,
{
    persist(state).map_err(|error| {
        Error::Config(format!("could not persist authoritative engine state: {error}").into())
            .boxed()
    })
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::sync::Mutex;

    use super::*;

    const ENGINE_ID: &[u8] = b"local-engine";

    #[test]
    fn install_persists_before_returning() {
        let stored = Mutex::new(None);
        let engine = AuthoritativeEngine::install(ENGINE_ID, |state| {
            *stored.lock().unwrap() = Some(state.clone());
            Ok::<(), Infallible>(())
        })
        .unwrap();

        assert_eq!(engine.engine_id(), ENGINE_ID);
        assert_eq!(engine.engine_boots(), 1);
        assert_eq!(
            stored.lock().unwrap().as_ref(),
            Some(engine.persisted_state())
        );
    }

    #[test]
    fn restart_increments_and_persists_before_returning() {
        let previous = PersistedAuthoritativeEngine::new(ENGINE_ID, 41).unwrap();
        let stored = Mutex::new(None);
        let engine = AuthoritativeEngine::restart(previous, |state| {
            *stored.lock().unwrap() = Some(state.clone());
            Ok::<(), Infallible>(())
        })
        .unwrap();

        assert_eq!(engine.engine_boots(), 42);
        assert_eq!(
            stored.lock().unwrap().as_ref(),
            Some(engine.persisted_state())
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
    fn persisted_state_rejects_invalid_boots() {
        assert!(PersistedAuthoritativeEngine::new(ENGINE_ID, 0).is_err());
        assert!(PersistedAuthoritativeEngine::new(ENGINE_ID, MAX_ENGINE_TIME + 1).is_err());
    }
}
