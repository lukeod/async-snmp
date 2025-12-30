//! USM user configuration types for notification receiver.
//!
//! These types store authentication and privacy settings for SNMPv3 notification handling.

use bytes::Bytes;

use crate::message::SecurityLevel;
use crate::v3::{AuthProtocol, LocalizedKey, PrivKey, PrivProtocol};

/// USM user credentials for V3 notification handling.
///
/// Stores the authentication and privacy settings for a single USM user.
#[derive(Clone)]
pub struct UsmUserConfig {
    /// Username
    pub username: Bytes,
    /// Authentication protocol and password
    pub auth: Option<(AuthProtocol, Vec<u8>)>,
    /// Privacy protocol and password
    pub privacy: Option<(PrivProtocol, Vec<u8>)>,
}

impl UsmUserConfig {
    /// Create a new USM user config with no authentication (noAuthNoPriv).
    pub fn new(username: impl Into<Bytes>) -> Self {
        Self {
            username: username.into(),
            auth: None,
            privacy: None,
        }
    }

    /// Add authentication (authNoPriv or authPriv).
    pub fn auth(mut self, protocol: AuthProtocol, password: &[u8]) -> Self {
        self.auth = Some((protocol, password.to_vec()));
        self
    }

    /// Add privacy/encryption (authPriv).
    pub fn privacy(mut self, protocol: PrivProtocol, password: &[u8]) -> Self {
        self.privacy = Some((protocol, password.to_vec()));
        self
    }

    /// Get the security level based on configured auth/privacy.
    pub fn security_level(&self) -> SecurityLevel {
        match (&self.auth, &self.privacy) {
            (None, _) => SecurityLevel::NoAuthNoPriv,
            (Some(_), None) => SecurityLevel::AuthNoPriv,
            (Some(_), Some(_)) => SecurityLevel::AuthPriv,
        }
    }

    /// Derive keys localized to a specific engine ID.
    pub fn derive_keys(&self, engine_id: &[u8]) -> DerivedKeys {
        let auth_key = self.auth.as_ref().map(|(protocol, password)| {
            LocalizedKey::from_password(*protocol, password, engine_id)
        });

        let priv_key = match (&self.auth, &self.privacy) {
            (Some((auth_protocol, _)), Some((priv_protocol, priv_password))) => Some(
                PrivKey::from_password(*auth_protocol, *priv_protocol, priv_password, engine_id),
            ),
            _ => None,
        };

        DerivedKeys { auth_key, priv_key }
    }
}

impl std::fmt::Debug for UsmUserConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UsmUserConfig")
            .field("username", &String::from_utf8_lossy(&self.username))
            .field("auth", &self.auth.as_ref().map(|(p, _)| p))
            .field("privacy", &self.privacy.as_ref().map(|(p, _)| p))
            .finish()
    }
}

/// Derived keys for a specific engine ID.
///
/// Used internally by notification receiver and agent for V3 authentication.
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
        let config = UsmUserConfig::new(Bytes::from_static(b"testuser"));
        assert_eq!(config.security_level(), SecurityLevel::NoAuthNoPriv);
        assert!(config.auth.is_none());
        assert!(config.privacy.is_none());
    }

    #[test]
    fn test_usm_user_config_auth_only() {
        let config = UsmUserConfig::new(Bytes::from_static(b"testuser"))
            .auth(AuthProtocol::Sha1, b"password123");
        assert_eq!(config.security_level(), SecurityLevel::AuthNoPriv);
        assert!(config.auth.is_some());
        assert!(config.privacy.is_none());
    }

    #[test]
    fn test_usm_user_config_auth_priv() {
        let config = UsmUserConfig::new(Bytes::from_static(b"testuser"))
            .auth(AuthProtocol::Sha256, b"authpass")
            .privacy(PrivProtocol::Aes128, b"privpass");
        assert_eq!(config.security_level(), SecurityLevel::AuthPriv);
        assert!(config.auth.is_some());
        assert!(config.privacy.is_some());
    }

    #[test]
    fn test_usm_user_config_derive_keys() {
        let config = UsmUserConfig::new(Bytes::from_static(b"testuser"))
            .auth(AuthProtocol::Sha1, b"password123");

        let engine_id = b"test-engine-id";
        let keys = config.derive_keys(engine_id);

        assert!(keys.auth_key.is_some());
        assert!(keys.priv_key.is_none());
    }

    #[test]
    fn test_usm_user_config_derive_keys_with_privacy() {
        let config = UsmUserConfig::new(Bytes::from_static(b"testuser"))
            .auth(AuthProtocol::Sha256, b"authpass")
            .privacy(PrivProtocol::Aes128, b"privpass");

        let engine_id = b"test-engine-id";
        let keys = config.derive_keys(engine_id);

        assert!(keys.auth_key.is_some());
        assert!(keys.priv_key.is_some());
    }
}
