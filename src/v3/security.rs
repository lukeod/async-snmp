//! Selectable inbound USM credentials and remote-engine timeliness.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, RwLock};

use bytes::Bytes;

use super::process::RemoteEngineTable;
use super::{UsmUser, validate_engine_id};
use crate::{Error, Result};

pub(crate) const DEFAULT_REMOTE_ENGINE_LIMIT: usize = 8192;

/// A USM user bound to one authoritative engine, or used as an explicit default.
#[derive(Clone, Debug)]
pub struct UsmUserEntry {
    engine_id: Option<Bytes>,
    user: UsmUser,
}

impl UsmUserEntry {
    /// Use these credentials when no exact engine-ID/username entry exists.
    pub fn new(user: UsmUser) -> Self {
        Self {
            engine_id: None,
            user,
        }
    }

    /// Bind these credentials to one authoritative engine ID.
    /// Exact bindings take precedence over defaults, including when their
    /// authentication or requested security-level checks fail.
    pub fn for_engine(engine_id: impl Into<Bytes>, user: UsmUser) -> Result<Self> {
        let engine_id = engine_id.into();
        validate_engine_id(&engine_id)
            .map_err(|error| Error::Config(error.to_string().into()).boxed())?;
        Ok(Self {
            engine_id: Some(engine_id),
            user,
        })
    }

    /// Authoritative engine binding; `None` means an explicit default.
    pub fn engine_id(&self) -> Option<&[u8]> {
        self.engine_id.as_deref()
    }

    /// The configured USM username.
    pub fn username(&self) -> &[u8] {
        self.user.username()
    }
}

/// A selectable USM security context independent of local engine and transport.
///
/// Clones share credentials and a bounded remote-authoritative timeliness
/// table. Local identity, authoritative clock, privacy-sender state and counters
/// belong to [`super::LocalEngine`]. Separate contexts isolate credentials and
/// remote timeliness even when local engine state or sockets are shared.
///
/// One immutable credential snapshot is selected for each input. Replacement
/// affects later selections; in-flight processing and its response retain the
/// selected credentials. Remote timeliness survives credential replacement.
/// Exact engine-ID/username bindings precede defaults, with no retry against a
/// default after an exact entry fails security checks.
///
/// Managed builders require persisted local engine state and applicable
/// application authorization/acceptance policy even for an initially empty
/// explicit context. User replacement cannot supply those prerequisites.
///
/// ```rust
/// use async_snmp::{UsmSecurityContext, UsmUser, UsmUserEntry};
/// # fn example() -> async_snmp::Result<()> {
/// let context = UsmSecurityContext::new([
///     UsmUserEntry::new(UsmUser::new("user")),
///     UsmUserEntry::for_engine("remote-engine", UsmUser::new("user"))?,
/// ])?;
/// context.replace_users([UsmUserEntry::new(UsmUser::new("replacement"))])?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct UsmSecurityContext {
    inner: Arc<SecurityContextInner>,
}

struct SecurityContextInner {
    identity: Arc<()>,
    users: RwLock<Arc<UsmUsers>>,
    remote_engines: Mutex<RemoteEngineTable>,
}

/// One immutable table, including its originating security-context identity.
pub(crate) struct UsmUsers {
    identity: Arc<()>,
    defaults: HashMap<Bytes, UsmUser>,
    exact: HashMap<Bytes, HashMap<Bytes, UsmUser>>,
}

impl std::fmt::Debug for UsmSecurityContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let users = self.snapshot();
        f.debug_struct("UsmSecurityContext")
            .field(
                "users",
                &(users.defaults.len() + users.exact.values().map(HashMap::len).sum::<usize>()),
            )
            .finish_non_exhaustive()
    }
}

impl Default for UsmSecurityContext {
    fn default() -> Self {
        Self::from_prepared(HashMap::new())
    }
}

impl UsmSecurityContext {
    /// Validate and precompute credentials, retaining up to 8192 remote engines.
    /// Duplicate exact bindings or duplicate defaults are configuration errors.
    pub fn new(users: impl IntoIterator<Item = UsmUserEntry>) -> Result<Self> {
        Self::with_remote_engine_limit(users, DEFAULT_REMOTE_ENGINE_LIMIT)
    }

    /// Configure a nonzero bound for remote-authoritative timeliness records.
    /// When full, the least-recently-updated remote engine is evicted.
    pub fn with_remote_engine_limit(
        users: impl IntoIterator<Item = UsmUserEntry>,
        limit: usize,
    ) -> Result<Self> {
        if limit == 0 {
            return Err(Error::Config("remote engine limit must be nonzero".into()).boxed());
        }
        let identity = Arc::new(());
        let users = Arc::new(UsmUsers::validate(users, identity.clone())?);
        Ok(Self {
            inner: Arc::new(SecurityContextInner {
                identity,
                users: RwLock::new(users),
                remote_engines: Mutex::new(RemoteEngineTable::new(limit)),
            }),
        })
    }

    /// Atomically replace the credential table after validation/precomputation.
    /// Errors leave the previous snapshot intact. Existing inputs retain their
    /// snapshot and remote-engine timeliness records are preserved.
    ///
    /// On a shared endpoint, replacement can introduce an application/client
    /// credential conflict after a client exchange registered. Such inputs are
    /// rejected without trying the old exchange credentials when they are
    /// Responses/Reports or cannot be classified. Valid application PDUs retain
    /// their application ownership even when transaction IDs collide. The
    /// pending exchange may time out. Registration-time conflict checks are
    /// not a lifetime guarantee.
    pub fn replace_users(&self, users: impl IntoIterator<Item = UsmUserEntry>) -> Result<()> {
        let users = Arc::new(UsmUsers::validate(users, self.inner.identity.clone())?);
        *self.inner.users.write().unwrap() = users;
        Ok(())
    }

    pub(crate) fn from_prepared(users: HashMap<Bytes, UsmUser>) -> Self {
        let identity = Arc::new(());
        let users = Arc::new(UsmUsers {
            identity: identity.clone(),
            defaults: users,
            exact: HashMap::new(),
        });
        Self {
            inner: Arc::new(SecurityContextInner {
                identity,
                users: RwLock::new(users),
                remote_engines: Mutex::new(RemoteEngineTable::new(DEFAULT_REMOTE_ENGINE_LIMIT)),
            }),
        }
    }

    pub(crate) fn snapshot(&self) -> Arc<UsmUsers> {
        self.inner.users.read().unwrap().clone()
    }

    pub(crate) fn users_for_input(
        &self,
        bytes: &Bytes,
        prepared: Option<&super::prepared::PreparedV3>,
    ) -> Result<Arc<UsmUsers>> {
        if let Some(selected) = prepared
            .filter(|p| p.matches(bytes))
            .and_then(|p| p.selected_users.as_ref())
        {
            if !Arc::ptr_eq(&selected.identity, &self.inner.identity) {
                return Err(
                    Error::Config("input belongs to another USM security context".into()).boxed(),
                );
            }
            return Ok(selected.clone());
        }
        Ok(self.snapshot())
    }

    pub(crate) fn remote_engines(&self) -> &Mutex<RemoteEngineTable> {
        &self.inner.remote_engines
    }
}

impl UsmUsers {
    fn validate(users: impl IntoIterator<Item = UsmUserEntry>, identity: Arc<()>) -> Result<Self> {
        // Deterministic validation and duplicate detection before publication.
        let mut ordered = BTreeMap::new();
        for entry in users {
            let key = (entry.engine_id, entry.user.username().clone());
            if ordered.insert(key, entry.user).is_some() {
                return Err(Error::Config("duplicate USM engine/user binding".into()).boxed());
            }
        }
        let mut table = Self {
            identity,
            defaults: HashMap::new(),
            exact: HashMap::new(),
        };
        for ((engine, name), mut user) in ordered {
            user.validate_and_precompute().map_err(|error| {
                Error::Config(format!("invalid USM user configuration: {error}").into()).boxed()
            })?;
            match engine {
                Some(engine) => {
                    table.exact.entry(engine).or_default().insert(name, user);
                }
                None => {
                    table.defaults.insert(name, user);
                }
            }
        }
        Ok(table)
    }

    pub(crate) fn lookup(&self, engine: &[u8], username: &[u8]) -> Option<&UsmUser> {
        self.exact
            .get(engine)
            .and_then(|users| users.get(username))
            .or_else(|| self.defaults.get(username))
    }

    pub(crate) fn values(&self) -> impl Iterator<Item = &UsmUser> {
        self.defaults
            .values()
            .chain(self.exact.values().flat_map(HashMap::values))
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.defaults.is_empty() && self.exact.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_engine_bindings_precede_defaults_without_merging_contexts() {
        let default = UsmUser::new("same");
        let exact = UsmUser::new("same");
        let context = UsmSecurityContext::new([
            UsmUserEntry::new(default.clone()),
            UsmUserEntry::for_engine("engine-one", exact.clone()).unwrap(),
        ])
        .unwrap();
        let users = context.snapshot();
        assert!(Arc::ptr_eq(
            &users
                .lookup(b"engine-one", b"same")
                .unwrap()
                .credential_identity(),
            &exact.credential_identity()
        ));
        assert!(Arc::ptr_eq(
            &users
                .lookup(b"engine-two", b"same")
                .unwrap()
                .credential_identity(),
            &default.credential_identity()
        ));
        let isolated = UsmSecurityContext::new([UsmUserEntry::new(UsmUser::new("other"))]).unwrap();
        assert!(isolated.snapshot().lookup(b"engine-one", b"same").is_none());
        assert!(UsmUserEntry::for_engine("bad", UsmUser::new("same")).is_err());
    }

    #[test]
    fn replacement_validates_before_publication_and_preserves_inflight_snapshot() {
        let context = UsmSecurityContext::new([UsmUserEntry::new(UsmUser::new("old"))]).unwrap();
        let old = context.snapshot();
        assert!(
            context
                .replace_users([UsmUserEntry::new(UsmUser::new(""))])
                .is_err()
        );
        assert!(Arc::ptr_eq(&old, &context.snapshot()));
        assert!(
            context
                .replace_users([
                    UsmUserEntry::new(UsmUser::new("duplicate")),
                    UsmUserEntry::new(UsmUser::new("duplicate")),
                ])
                .is_err()
        );
        assert!(Arc::ptr_eq(&old, &context.snapshot()));
        context
            .replace_users([UsmUserEntry::new(UsmUser::new("new"))])
            .unwrap();
        assert!(old.lookup(b"engine-one", b"old").is_some());
        assert!(context.snapshot().lookup(b"engine-one", b"old").is_none());
        assert!(context.snapshot().lookup(b"engine-one", b"new").is_some());
        assert!(UsmSecurityContext::with_remote_engine_limit([], 0).is_err());
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    fn user(password: &[u8]) -> UsmUser {
        UsmUser::new("shared-user")
            .auth(crate::AuthProtocol::Sha256, password)
            .unwrap()
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    fn wire(engine: &[u8], time: u32) -> Bytes {
        let config = super::super::UsmConfig::new("shared-user")
            .auth(crate::AuthProtocol::Sha256, b"authentication-password")
            .unwrap();
        let keys = config.derive_keys(engine).unwrap();
        crate::v3::encode::encode_v3_message(
            &crate::pdu::NotificationPdu::trap_v2(
                crate::Version::V3,
                11,
                0,
                &crate::notification::oids::snmp_trap_oid(),
                vec![],
            )
            .unwrap()
            .into_raw(),
            11,
            engine,
            7,
            time,
            &config,
            Some(&keys),
            None,
            None,
            None,
            false,
            crate::MessageSize::new(8192).unwrap(),
        )
        .unwrap()
        .into()
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    fn process(
        context: &UsmSecurityContext,
        engine: &crate::LocalEngine,
        data: Bytes,
    ) -> super::super::process::V3Inbound {
        use super::super::process::{V3LocalContext, V3Role, process_prepared_v3_inbound};
        let ctx = V3LocalContext {
            engine_id: &engine.inner.engine_id,
            engine_boots: 1,
            engine_time: 0,
            authoritative_time: None,
            local_receive_capacity: crate::MessageSize::new(8192).unwrap(),
            accepted_receive_size: 8192,
            decode_config: crate::DecodeConfig::DEFAULT,
            outbound_limit: 8192,
            usm_users: context.snapshot(),
            stats: &engine.inner.usm_stats,
            mpd: None,
            source: "127.0.0.1:9999".parse().unwrap(),
        };
        process_prepared_v3_inbound(
            data,
            &ctx,
            &V3Role::Receiver {
                remote_engines: context.remote_engines(),
            },
            None,
        )
        .unwrap()
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[test]
    fn authentication_failure_for_exact_entry_does_not_try_valid_default() {
        use super::super::process::{UsmFailure, V3Inbound};
        let context = UsmSecurityContext::new([
            UsmUserEntry::new(user(b"authentication-password")),
            UsmUserEntry::for_engine("remote-one", user(b"different-password")).unwrap(),
        ])
        .unwrap();
        let engine = crate::LocalEngine::new(super::super::AuthoritativeEngine::for_test(
            b"local-engine".as_slice(),
            1,
        ))
        .unwrap();
        assert!(matches!(
            process(&context, &engine, wire(b"remote-one", 1000)),
            V3Inbound::Failed {
                failure: UsmFailure::WrongDigests,
                ..
            }
        ));
        assert!(matches!(
            process(&context, &engine, wire(b"remote-two", 1000)),
            V3Inbound::Message(_)
        ));
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[test]
    fn remote_timeliness_survives_user_replacement_and_is_isolated_per_context() {
        use super::super::process::V3Inbound;
        let context =
            UsmSecurityContext::new([UsmUserEntry::new(user(b"authentication-password"))]).unwrap();
        let independent =
            UsmSecurityContext::new([UsmUserEntry::new(user(b"authentication-password"))]).unwrap();
        let engine = crate::LocalEngine::new(super::super::AuthoritativeEngine::for_test(
            b"local-engine".as_slice(),
            1,
        ))
        .unwrap();
        assert!(matches!(
            process(&context, &engine, wire(b"remote-one", 1000)),
            V3Inbound::Message(_)
        ));
        context
            .replace_users([UsmUserEntry::new(user(b"authentication-password"))])
            .unwrap();
        assert!(matches!(
            process(&context, &engine, wire(b"remote-one", 800)),
            V3Inbound::RemoteNotInTimeWindow
        ));
        assert!(matches!(
            process(&independent, &engine, wire(b"remote-one", 800)),
            V3Inbound::Message(_)
        ));
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[test]
    fn configured_remote_engine_bound_eviction_is_shared_by_context_clones() {
        use super::super::process::V3Inbound;
        let context = UsmSecurityContext::with_remote_engine_limit(
            [UsmUserEntry::new(user(b"authentication-password"))],
            1,
        )
        .unwrap();
        let clone = context.clone();
        let engine = crate::LocalEngine::new(super::super::AuthoritativeEngine::for_test(
            b"local-engine".as_slice(),
            1,
        ))
        .unwrap();
        assert!(matches!(
            process(&context, &engine, wire(b"remote-one", 1000)),
            V3Inbound::Message(_)
        ));
        assert!(matches!(
            process(&clone, &engine, wire(b"remote-two", 1000)),
            V3Inbound::Message(_)
        ));
        let remotes = context.remote_engines().lock().unwrap();
        assert_eq!(remotes.len(), 1);
        assert!(remotes.contains_key(&Bytes::from_static(b"remote-two")));
        assert!(!remotes.contains_key(&Bytes::from_static(b"remote-one")));
    }
}
