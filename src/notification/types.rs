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
}
