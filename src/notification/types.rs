//! USM configuration types for `SNMPv3` authentication.
//!
//! These types store authentication and privacy settings for `SNMPv3` operations,
//! used by both the client and notification receiver.

use bytes::Bytes;

use crate::message::SecurityLevel;
use crate::v3::{AuthProtocol, LocalizedKey, PrivKey, PrivProtocol};

/// USM user credentials for `SNMPv3` authentication.
///
/// Stores the credentials needed for authenticated and/or encrypted communication.
/// Keys are derived when the engine ID is discovered.
///
/// # Master Key Caching
///
/// When polling many engines with shared credentials, use
/// [`MasterKeys`](crate::MasterKeys) to cache the expensive password-to-key
/// derivation. When `master_keys` is set, passwords are ignored and keys are
/// derived from the cached master keys.
#[derive(Clone)]
pub struct UsmConfig {
    /// Username for USM authentication
    pub username: Bytes,
    /// Authentication protocol and password
    pub auth: Option<(AuthProtocol, Vec<u8>)>,
    /// Privacy protocol and password
    pub privacy: Option<(PrivProtocol, Vec<u8>)>,
    /// `SNMPv3` context name for VACM context selection.
    pub context_name: Bytes,
    /// Pre-computed master keys for efficient key derivation
    pub master_keys: Option<crate::v3::MasterKeys>,
}

impl UsmConfig {
    /// Create a new USM config with just a username (noAuthNoPriv).
    pub fn new(username: impl Into<Bytes>) -> Self {
        Self {
            username: username.into(),
            auth: None,
            privacy: None,
            context_name: Bytes::new(),
            master_keys: None,
        }
    }

    /// Add authentication (authNoPriv or authPriv).
    #[must_use]
    pub fn auth(mut self, protocol: AuthProtocol, password: impl AsRef<[u8]>) -> Self {
        self.auth = Some((protocol, password.as_ref().to_vec()));
        self
    }

    /// Add privacy/encryption (authPriv).
    #[must_use]
    pub fn privacy(mut self, protocol: PrivProtocol, password: impl AsRef<[u8]>) -> Self {
        self.privacy = Some((protocol, password.as_ref().to_vec()));
        self
    }

    /// Set the `SNMPv3` context name for scoped PDUs.
    #[must_use]
    pub fn context_name(mut self, context_name: impl Into<Bytes>) -> Self {
        self.context_name = context_name.into();
        self
    }

    /// Use pre-computed master keys for efficient key derivation.
    ///
    /// When set, passwords are ignored and keys are derived from the cached
    /// master keys. This avoids the expensive ~850us password expansion for
    /// each engine.
    #[must_use]
    pub fn with_master_keys(mut self, master_keys: crate::v3::MasterKeys) -> Self {
        self.master_keys = Some(master_keys);
        self
    }

    /// Get the security level based on configured auth/privacy.
    pub fn security_level(&self) -> SecurityLevel {
        // Check master_keys first, then fall back to auth/privacy
        if let Some(ref master_keys) = self.master_keys {
            if master_keys.priv_protocol().is_some() {
                return SecurityLevel::AuthPriv;
            }
            return SecurityLevel::AuthNoPriv;
        }

        match (&self.auth, &self.privacy) {
            (None, _) => SecurityLevel::NoAuthNoPriv,
            (Some(_), None) => SecurityLevel::AuthNoPriv,
            (Some(_), Some(_)) => SecurityLevel::AuthPriv,
        }
    }

    /// Validate the credential configuration.
    ///
    /// Rejects privacy without authentication: RFC 3411 requires
    /// authentication whenever privacy is selected. Mirrors the client
    /// builder validation so that agent and notification-receiver USM users
    /// cannot be silently downgraded to noAuthNoPriv with the privacy key
    /// dropped.
    pub(crate) fn validate(&self) -> crate::error::Result<()> {
        if self.privacy.is_some() && self.auth.is_none() {
            return Err(
                crate::error::Error::Config("privacy requires authentication".into()).boxed(),
            );
        }
        Ok(())
    }

    /// Precompute and cache master keys from any configured passwords.
    ///
    /// The password-to-master expansion (RFC 3414 Section 2.6, a 1 MiB buffer
    /// hash) is the expensive part of key derivation. Performing it once at
    /// configuration time — rather than on every inbound packet in
    /// [`derive_keys`](Self::derive_keys) — removes an unauthenticated CPU
    /// amplification vector: without it, an attacker can force a fresh
    /// password expansion per spoofed message (a Report/discovery for a known
    /// username triggers derivation before authentication is verified).
    ///
    /// After this call the localized-key path localizes from the cached master
    /// keys (~1us) instead of re-expanding the password. Localized results are
    /// identical to the password path (the master key is the same value the
    /// password would have produced). If `master_keys` is already set, or no
    /// authentication is configured, this is a no-op. Best-effort: if the
    /// crypto backend rejects a password (e.g. too short), the config is left
    /// unchanged so the original password path (and its error) is preserved.
    pub(crate) fn precompute_master_keys(&mut self) {
        if self.master_keys.is_some() {
            return;
        }
        let Some((auth_protocol, auth_password)) = self.auth.as_ref() else {
            return;
        };
        let master_keys = match crate::v3::MasterKeys::new(*auth_protocol, auth_password) {
            Ok(mk) => mk,
            Err(_) => return,
        };
        let master_keys = match &self.privacy {
            Some((priv_protocol, priv_password)) => {
                // Same password reuses the auth master; a different password
                // needs its own expansion. Both yield identical localized
                // privacy keys.
                if priv_password == auth_password {
                    master_keys.with_privacy_same_password(*priv_protocol)
                } else {
                    match master_keys.with_privacy(*priv_protocol, priv_password) {
                        Ok(mk) => mk,
                        Err(_) => return,
                    }
                }
            }
            None => master_keys,
        };
        self.master_keys = Some(master_keys);
    }

    /// Derive localized keys for a specific engine ID.
    ///
    /// If master keys are configured, uses the cached master keys for efficient
    /// localization (~1us). Otherwise, performs full password-to-key derivation
    /// (~850us for SHA-256).
    pub fn derive_keys(&self, engine_id: &[u8]) -> crate::v3::CryptoResult<DerivedKeys> {
        // Use master keys if available (efficient path)
        if let Some(ref master_keys) = self.master_keys {
            tracing::trace!(target: "async_snmp::client", { engine_id_len = engine_id.len(), auth_protocol = ?master_keys.auth_protocol(), priv_protocol = ?master_keys.priv_protocol() }, "localizing from cached master keys");
            let (auth_key, priv_key) = master_keys.localize(engine_id)?;
            tracing::trace!(target: "async_snmp::client", "key localization complete");
            return Ok(DerivedKeys {
                auth_key: Some(auth_key),
                priv_key,
            });
        }

        // Fall back to password-based derivation
        tracing::trace!(target: "async_snmp::client", { engine_id_len = engine_id.len(), has_auth = self.auth.is_some(), has_priv = self.privacy.is_some() }, "deriving localized keys from passwords");

        let auth_key = self.auth.as_ref().map(|(protocol, password)| {
            tracing::trace!(target: "async_snmp::client", { auth_protocol = ?protocol }, "deriving auth key");
            LocalizedKey::from_password(*protocol, password, engine_id)
        }).transpose()?;

        let priv_key = match (&self.auth, &self.privacy) {
            (Some((auth_protocol, _)), Some((priv_protocol, priv_password))) => {
                tracing::trace!(target: "async_snmp::client", { priv_protocol = ?priv_protocol }, "deriving privacy key");
                Some(PrivKey::from_password(
                    *auth_protocol,
                    *priv_protocol,
                    priv_password,
                    engine_id,
                )?)
            }
            _ => None,
        };

        tracing::trace!(target: "async_snmp::client", "key derivation complete");
        Ok(DerivedKeys { auth_key, priv_key })
    }
}

impl std::fmt::Debug for UsmConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UsmConfig")
            .field("username", &String::from_utf8_lossy(&self.username))
            .field("auth", &self.auth.as_ref().map(|(p, _)| p))
            .field("privacy", &self.privacy.as_ref().map(|(p, _)| p))
            .field("context_name", &String::from_utf8_lossy(&self.context_name))
            .field(
                "master_keys",
                &self.master_keys.as_ref().map(|mk| {
                    format!(
                        "MasterKeys({:?}, {:?})",
                        mk.auth_protocol(),
                        mk.priv_protocol()
                    )
                }),
            )
            .finish()
    }
}

/// Derived keys for a specific engine ID.
///
/// Used internally for V3 authentication in both client and notification receiver.
#[derive(Debug)]
pub struct DerivedKeys {
    /// Localized authentication key
    pub auth_key: Option<LocalizedKey>,
    /// Privacy key
    pub priv_key: Option<PrivKey>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_usm_user_config_no_auth() {
        let config = UsmConfig::new(Bytes::from_static(b"testuser"));
        assert_eq!(config.security_level(), SecurityLevel::NoAuthNoPriv);
        assert!(config.auth.is_none());
        assert!(config.privacy.is_none());
    }

    #[test]
    fn test_usm_user_config_auth_only() {
        let config = UsmConfig::new(Bytes::from_static(b"testuser"))
            .auth(AuthProtocol::Sha1, b"password123");
        assert_eq!(config.security_level(), SecurityLevel::AuthNoPriv);
        assert!(config.auth.is_some());
        assert!(config.privacy.is_none());
        assert!(config.context_name.is_empty());
    }

    #[test]
    fn test_usm_user_config_auth_priv() {
        let config = UsmConfig::new(Bytes::from_static(b"testuser"))
            .auth(AuthProtocol::Sha256, b"authpass")
            .privacy(PrivProtocol::Aes128, b"privpass");
        assert_eq!(config.security_level(), SecurityLevel::AuthPriv);
        assert!(config.auth.is_some());
        assert!(config.privacy.is_some());
    }

    #[test]
    fn test_usm_user_config_context_name() {
        let config = UsmConfig::new(Bytes::from_static(b"testuser")).context_name("ctx");
        assert_eq!(config.context_name.as_ref(), b"ctx");
    }

    #[test]
    fn test_usm_user_config_derive_keys() {
        let config = UsmConfig::new(Bytes::from_static(b"testuser"))
            .auth(AuthProtocol::Sha1, b"password123");

        let engine_id = b"test-engine-id";
        let keys = config.derive_keys(engine_id).unwrap();

        assert!(keys.auth_key.is_some());
        assert!(keys.priv_key.is_none());
    }

    #[test]
    fn test_usm_user_config_derive_keys_with_privacy() {
        let config = UsmConfig::new(Bytes::from_static(b"testuser"))
            .auth(AuthProtocol::Sha256, b"authpass")
            .privacy(PrivProtocol::Aes128, b"privpass");

        let engine_id = b"test-engine-id";
        let keys = config.derive_keys(engine_id).unwrap();

        assert!(keys.auth_key.is_some());
        assert!(keys.priv_key.is_some());
    }

    /// Precomputing master keys populates the cache, so subsequent
    /// `derive_keys` calls take the master-key localization path instead of
    /// re-running the 1 MiB password expansion (the CPU-amplification vector).
    #[test]
    fn test_precompute_master_keys_populates_cache() {
        let mut config = UsmConfig::new(Bytes::from_static(b"testuser"))
            .auth(AuthProtocol::Sha256, b"authpass")
            .privacy(PrivProtocol::Aes128, b"privpass");
        assert!(config.master_keys.is_none());

        config.precompute_master_keys();
        assert!(
            config.master_keys.is_some(),
            "precompute must cache master keys so per-packet derivation avoids password expansion"
        );

        // Idempotent: a second call is a no-op and keeps the cache.
        config.precompute_master_keys();
        assert!(config.master_keys.is_some());
    }

    /// The cached (master-key) path and the uncached (password) path must
    /// derive identical localized keys, for both auth-only and authPriv.
    #[test]
    fn test_precompute_master_keys_preserves_derivation() {
        let engine_id = b"\x80\x00\x00\x00\x01test-engine";

        // authNoPriv
        let uncached =
            UsmConfig::new(Bytes::from_static(b"u")).auth(AuthProtocol::Sha256, b"authpass");
        let mut cached = uncached.clone();
        cached.precompute_master_keys();
        let a = uncached.derive_keys(engine_id).unwrap();
        let b = cached.derive_keys(engine_id).unwrap();
        assert_eq!(
            a.auth_key.as_ref().map(AsRef::as_ref),
            b.auth_key.as_ref().map(AsRef::as_ref),
            "auth key must match between password and master-key paths"
        );

        // authPriv, distinct auth/priv passwords
        let uncached = UsmConfig::new(Bytes::from_static(b"u"))
            .auth(AuthProtocol::Sha1, b"authpassword")
            .privacy(PrivProtocol::Aes128, b"privpassword");
        let mut cached = uncached.clone();
        cached.precompute_master_keys();
        let a = uncached.derive_keys(engine_id).unwrap();
        let b = cached.derive_keys(engine_id).unwrap();
        assert_eq!(
            a.auth_key.as_ref().map(AsRef::as_ref),
            b.auth_key.as_ref().map(AsRef::as_ref),
        );
        assert!(a.priv_key.is_some() && b.priv_key.is_some());

        // authPriv, same auth/priv password (with_privacy_same_password path)
        let uncached = UsmConfig::new(Bytes::from_static(b"u"))
            .auth(AuthProtocol::Sha1, b"sharedpassword")
            .privacy(PrivProtocol::Aes128, b"sharedpassword");
        let mut cached = uncached.clone();
        cached.precompute_master_keys();
        let a = uncached.derive_keys(engine_id).unwrap();
        let b = cached.derive_keys(engine_id).unwrap();
        assert_eq!(
            a.auth_key.as_ref().map(AsRef::as_ref),
            b.auth_key.as_ref().map(AsRef::as_ref),
        );
    }

    /// A password too short for the crypto backend leaves the config on the
    /// original password path (no silent success, error preserved for later).
    #[test]
    fn test_precompute_master_keys_short_password_is_noop() {
        let mut config =
            UsmConfig::new(Bytes::from_static(b"u")).auth(AuthProtocol::Sha256, b"short");
        config.precompute_master_keys();
        assert!(
            config.master_keys.is_none(),
            "a rejected password must not populate the cache"
        );
    }
}
