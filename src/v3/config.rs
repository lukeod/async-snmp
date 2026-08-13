//! USM configuration types for `SNMPv3` authentication.
//!
//! [`UsmConfig`] selects the exact credentials and context used for outbound
//! messages. [`UsmUser`] describes the mechanisms an inbound user supports.

use bytes::Bytes;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::message::SecurityLevel;
use crate::v3::{
    AuthProtocol, CryptoBackend, CryptoError, CryptoResult, LocalizedKey, PrivKey, PrivProtocol,
};

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct Password(Vec<u8>);

impl AsRef<[u8]> for Password {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone)]
enum UsmCredentials {
    NoAuthNoPriv,
    Passwords {
        auth: (AuthProtocol, Password),
        privacy: Option<(PrivProtocol, Password)>,
    },
    MasterKeys(crate::v3::MasterKeys),
}

/// USM user credentials for `SNMPv3` authentication.
///
/// A configuration represents exactly one valid USM security state:
/// noAuthNoPriv, password-backed authNoPriv/authPriv, or master-key-backed
/// authNoPriv/authPriv. Privacy-only and incomplete protocol/password states
/// cannot be constructed.
///
/// # Password storage
///
/// Password-backed configurations zeroize the specifically owned password
/// buffers when those buffers are dropped. This guarantee does not extend to
/// caller-provided inputs, live clones, allocator or cryptographic-provider
/// internals, encoded message buffers, or kernel copies.
#[derive(Clone)]
pub struct UsmConfig {
    username: Bytes,
    credentials: UsmCredentials,
    context_name: Bytes,
    crypto_backend: CryptoBackend,
}

/// USM user accepted by an inbound `SNMPv3` application.
///
/// Authentication and privacy protocols are capabilities, not a minimum
/// accepted security level. A user with authentication and privacy keys also
/// supports `authNoPriv` and `noAuthNoPriv`; the Agent or notification receiver
/// applies its own authorization or acceptance policy to the packet's actual
/// security level.
///
/// Unlike [`UsmConfig`], this type has no scoped-PDU context because inbound
/// contexts come from the received message.
#[derive(Clone)]
pub struct UsmUser {
    config: UsmConfig,
}

impl UsmUser {
    /// Create an inbound user supporting `noAuthNoPriv` only.
    pub fn new(username: impl Into<Bytes>) -> Self {
        Self {
            config: UsmConfig::new(username),
        }
    }

    /// Add password-backed authentication capability.
    #[must_use]
    pub fn auth(mut self, protocol: AuthProtocol, password: impl AsRef<[u8]>) -> Self {
        self.config = self.config.auth(protocol, password);
        self
    }

    /// Add password-backed authentication and privacy capability.
    #[must_use]
    pub fn auth_priv(
        mut self,
        auth_protocol: AuthProtocol,
        auth_password: impl AsRef<[u8]>,
        priv_protocol: PrivProtocol,
        priv_password: impl AsRef<[u8]>,
    ) -> Self {
        self.config =
            self.config
                .auth_priv(auth_protocol, auth_password, priv_protocol, priv_password);
        self
    }

    /// Select the cryptographic backend for this inbound user.
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[must_use]
    pub fn with_crypto_backend(mut self, backend: CryptoBackend) -> Self {
        self.config = self.config.with_crypto_backend(backend);
        self
    }

    /// Return the selected cryptographic backend.
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[must_use]
    pub fn crypto_backend(&self) -> CryptoBackend {
        self.config.crypto_backend()
    }

    /// Use pre-computed master keys for this inbound user.
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[must_use]
    pub fn with_master_keys(mut self, master_keys: crate::v3::MasterKeys) -> Self {
        self.config = self.config.with_master_keys(master_keys);
        self
    }

    /// Return the configured username.
    #[must_use]
    pub fn username(&self) -> &Bytes {
        self.config.username()
    }

    /// Return the configured authentication protocol, if any.
    #[must_use]
    pub fn auth_protocol(&self) -> Option<AuthProtocol> {
        self.config.auth_protocol()
    }

    /// Return the configured privacy protocol, if any.
    #[must_use]
    pub fn priv_protocol(&self) -> Option<PrivProtocol> {
        self.config.priv_protocol()
    }

    /// Return the strongest security level supported by this user.
    ///
    /// This is a capability, not a minimum accepted level.
    #[must_use]
    pub fn maximum_security_level(&self) -> SecurityLevel {
        self.config.security_level()
    }

    pub(crate) fn validate_and_precompute(&mut self) -> CryptoResult<()> {
        self.config.validate_and_precompute()
    }

    pub(crate) fn derive_keys(&self, engine_id: &[u8]) -> CryptoResult<DerivedKeys> {
        self.config.derive_keys_inner(engine_id)
    }
}

impl std::fmt::Debug for UsmUser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UsmUser")
            .field("username", self.username())
            .field("auth_protocol", &self.auth_protocol())
            .field("priv_protocol", &self.priv_protocol())
            .field("maximum_security_level", &self.maximum_security_level())
            .field("crypto_backend", &self.config.crypto_backend)
            .finish()
    }
}

impl UsmConfig {
    /// Create a noAuthNoPriv USM config with the given username.
    pub fn new(username: impl Into<Bytes>) -> Self {
        Self {
            username: username.into(),
            credentials: UsmCredentials::NoAuthNoPriv,
            context_name: Bytes::new(),
            crypto_backend: CryptoBackend::default(),
        }
    }

    /// Configure password-backed authentication (authNoPriv).
    ///
    /// Backend availability is checked when the containing configuration is
    /// validated.
    #[must_use]
    pub fn auth(mut self, protocol: AuthProtocol, password: impl AsRef<[u8]>) -> Self {
        self.credentials = UsmCredentials::Passwords {
            auth: (protocol, Password(password.as_ref().to_vec())),
            privacy: None,
        };
        self
    }

    /// Configure password-backed authentication and privacy (authPriv).
    ///
    /// Backend availability is checked when the containing configuration is
    /// validated.
    #[must_use]
    pub fn auth_priv(
        mut self,
        auth_protocol: AuthProtocol,
        auth_password: impl AsRef<[u8]>,
        priv_protocol: PrivProtocol,
        priv_password: impl AsRef<[u8]>,
    ) -> Self {
        self.credentials = UsmCredentials::Passwords {
            auth: (auth_protocol, Password(auth_password.as_ref().to_vec())),
            privacy: Some((priv_protocol, Password(priv_password.as_ref().to_vec()))),
        };
        self
    }

    /// Select the cryptographic backend for this USM configuration.
    ///
    /// When both backend features are enabled the default remains RustCrypto;
    /// select `AwsLcFips` explicitly for FIPS operations.
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[must_use]
    pub fn with_crypto_backend(mut self, backend: CryptoBackend) -> Self {
        self.crypto_backend = backend;
        if let UsmCredentials::MasterKeys(master_keys) = &mut self.credentials {
            master_keys.set_crypto_backend(backend);
        }
        self
    }

    /// Return the selected cryptographic backend.
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[must_use]
    pub fn crypto_backend(&self) -> CryptoBackend {
        self.crypto_backend
    }

    /// Set the `SNMPv3` context name for scoped PDUs.
    #[must_use]
    pub fn context_name(mut self, context_name: impl Into<Bytes>) -> Self {
        self.context_name = context_name.into();
        self
    }

    /// Use pre-computed master keys.
    ///
    /// # Reusing master keys
    ///
    /// When polling many engines with shared credentials, use
    /// [`MasterKeys`](crate::MasterKeys) to avoid repeating password-to-key
    /// derivation. Calling this method replaces any password-backed credentials
    /// with the supplied master keys. Credential configurators use
    /// last-call-wins semantics.
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[must_use]
    pub fn with_master_keys(mut self, mut master_keys: crate::v3::MasterKeys) -> Self {
        master_keys.set_crypto_backend(self.crypto_backend);
        self.credentials = UsmCredentials::MasterKeys(master_keys);
        self
    }

    /// Return the configured USM username.
    #[must_use]
    pub fn username(&self) -> &Bytes {
        &self.username
    }

    /// Return the configured scoped-PDU context name.
    #[must_use]
    pub fn configured_context_name(&self) -> &Bytes {
        &self.context_name
    }

    /// Return the configured authentication protocol, if any.
    #[must_use]
    pub fn auth_protocol(&self) -> Option<AuthProtocol> {
        match &self.credentials {
            UsmCredentials::NoAuthNoPriv => None,
            UsmCredentials::Passwords { auth, .. } => Some(auth.0),
            UsmCredentials::MasterKeys(master_keys) => Some(master_keys.auth_protocol()),
        }
    }

    /// Return the configured privacy protocol, if any.
    #[must_use]
    pub fn priv_protocol(&self) -> Option<PrivProtocol> {
        match &self.credentials {
            UsmCredentials::NoAuthNoPriv | UsmCredentials::Passwords { privacy: None, .. } => None,
            UsmCredentials::Passwords {
                privacy: Some((protocol, _)),
                ..
            } => Some(*protocol),
            UsmCredentials::MasterKeys(master_keys) => master_keys.priv_protocol(),
        }
    }

    /// Get the configured security level.
    #[must_use]
    pub fn security_level(&self) -> SecurityLevel {
        match &self.credentials {
            UsmCredentials::NoAuthNoPriv => SecurityLevel::NoAuthNoPriv,
            UsmCredentials::Passwords { privacy: None, .. } => SecurityLevel::AuthNoPriv,
            UsmCredentials::Passwords {
                privacy: Some(_), ..
            } => SecurityLevel::AuthPriv,
            UsmCredentials::MasterKeys(master_keys) if master_keys.priv_protocol().is_some() => {
                SecurityLevel::AuthPriv
            }
            UsmCredentials::MasterKeys(_) => SecurityLevel::AuthNoPriv,
        }
    }

    /// Validate credentials and precompute password-backed master keys.
    ///
    /// Validation uses raw octet lengths and the selected cryptographic backend.
    /// Password-backed credentials are replaced only after all requested key
    /// derivations succeed, so an error never leaves partially updated state.
    pub(crate) fn validate_and_precompute(&mut self) -> CryptoResult<()> {
        if !(1..=32).contains(&self.username.len()) {
            return Err(CryptoError::InvalidUsmUsernameLength {
                length: self.username.len(),
            });
        }

        match &self.credentials {
            UsmCredentials::NoAuthNoPriv => Ok(()),
            UsmCredentials::MasterKeys(master_keys) => {
                self.crypto_backend
                    .validate_auth_protocol(master_keys.auth_protocol())?;
                if let Some(protocol) = master_keys.priv_protocol() {
                    self.crypto_backend.validate_priv_protocol(protocol)?;
                }
                Ok(())
            }
            UsmCredentials::Passwords { auth, privacy } => {
                let (auth_protocol, auth_password) = auth;
                if auth_password.as_ref().len() < crate::v3::auth::MIN_PASSWORD_LENGTH {
                    return Err(CryptoError::PasswordTooShort);
                }
                if privacy.as_ref().is_some_and(|(_, password)| {
                    password.as_ref().len() < crate::v3::auth::MIN_PASSWORD_LENGTH
                }) {
                    return Err(CryptoError::PasswordTooShort);
                }

                self.crypto_backend.validate_auth_protocol(*auth_protocol)?;
                if let Some((protocol, _)) = privacy {
                    self.crypto_backend.validate_priv_protocol(*protocol)?;
                }

                let master_keys = crate::v3::MasterKeys::new_with_backend(
                    *auth_protocol,
                    auth_password.as_ref(),
                    self.crypto_backend,
                )?;
                let master_keys = match privacy {
                    Some((priv_protocol, priv_password)) => {
                        master_keys.with_privacy(*priv_protocol, priv_password.as_ref())?
                    }
                    None => master_keys,
                };
                self.credentials = UsmCredentials::MasterKeys(master_keys);
                Ok(())
            }
        }
    }

    /// Derive localized keys for a specific engine ID.
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    pub fn derive_keys(&self, engine_id: &[u8]) -> crate::v3::CryptoResult<DerivedKeys> {
        self.derive_keys_inner(engine_id)
    }

    #[cfg(not(any(feature = "crypto-rustcrypto", feature = "crypto-fips")))]
    pub(crate) fn derive_keys(&self, engine_id: &[u8]) -> crate::v3::CryptoResult<DerivedKeys> {
        self.derive_keys_inner(engine_id)
    }

    fn derive_keys_inner(&self, engine_id: &[u8]) -> crate::v3::CryptoResult<DerivedKeys> {
        match &self.credentials {
            UsmCredentials::NoAuthNoPriv => Ok(DerivedKeys {
                auth_key: None,
                priv_key: None,
            }),
            UsmCredentials::MasterKeys(master_keys) => {
                tracing::trace!(target: "async_snmp::client", { engine_id_len = engine_id.len(), auth_protocol = ?master_keys.auth_protocol(), priv_protocol = ?master_keys.priv_protocol() }, "localizing from cached master keys");
                let (auth_key, priv_key) = master_keys.localize(engine_id)?;
                Ok(DerivedKeys {
                    auth_key: Some(auth_key),
                    priv_key,
                })
            }
            UsmCredentials::Passwords { auth, privacy } => {
                let (auth_protocol, auth_password) = auth;
                tracing::trace!(target: "async_snmp::client", { engine_id_len = engine_id.len(), auth_protocol = ?auth_protocol }, "deriving localized keys from passwords");
                let auth_key = LocalizedKey::from_password_with_backend(
                    *auth_protocol,
                    auth_password.as_ref(),
                    engine_id,
                    self.crypto_backend,
                )?;
                let priv_key = privacy
                    .as_ref()
                    .map(|(priv_protocol, priv_password)| {
                        PrivKey::from_password_with_backend(
                            *auth_protocol,
                            *priv_protocol,
                            priv_password.as_ref(),
                            engine_id,
                            self.crypto_backend,
                        )
                    })
                    .transpose()?;
                Ok(DerivedKeys {
                    auth_key: Some(auth_key),
                    priv_key,
                })
            }
        }
    }
}

impl std::fmt::Debug for UsmConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (auth, auth_password, privacy, priv_password, master_keys) = match &self.credentials {
            UsmCredentials::NoAuthNoPriv => (None, None, None, None, None),
            UsmCredentials::Passwords { auth, privacy } => (
                Some(auth.0),
                Some("[REDACTED]"),
                privacy.as_ref().map(|value| value.0),
                privacy.as_ref().map(|_| "[REDACTED]"),
                None,
            ),
            UsmCredentials::MasterKeys(master_keys) => (
                Some(master_keys.auth_protocol()),
                None,
                master_keys.priv_protocol(),
                None,
                Some("[REDACTED]"),
            ),
        };
        f.debug_struct("UsmConfig")
            .field("username", &self.username)
            .field("auth_protocol", &auth)
            .field("auth_password", &auth_password)
            .field("priv_protocol", &privacy)
            .field("priv_password", &priv_password)
            .field("context_name", &self.context_name)
            .field("crypto_backend", &self.crypto_backend)
            .field("master_keys", &master_keys)
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
    use static_assertions::assert_not_impl_any;

    assert_not_impl_any!(Password: PartialEq, Eq, PartialOrd, Ord, std::hash::Hash);
    assert_not_impl_any!(UsmCredentials: PartialEq, Eq, PartialOrd, Ord, std::hash::Hash);

    #[test]
    fn test_usm_user_config_no_auth() {
        let config = UsmConfig::new(Bytes::from_static(b"testuser"));
        assert_eq!(config.security_level(), SecurityLevel::NoAuthNoPriv);
        assert_eq!(config.auth_protocol(), None);
        assert_eq!(config.priv_protocol(), None);
    }

    #[test]
    fn test_usm_user_config_auth_only() {
        let config = UsmConfig::new(Bytes::from_static(b"testuser"))
            .auth(AuthProtocol::Sha1, b"password123");
        assert_eq!(config.security_level(), SecurityLevel::AuthNoPriv);
        assert_eq!(config.auth_protocol(), Some(AuthProtocol::Sha1));
        assert_eq!(config.priv_protocol(), None);
        assert!(config.configured_context_name().is_empty());
    }

    #[test]
    fn test_usm_user_config_auth_priv() {
        let config = UsmConfig::new(Bytes::from_static(b"testuser")).auth_priv(
            AuthProtocol::Sha256,
            b"authpass",
            PrivProtocol::Aes128,
            b"privpass",
        );
        assert_eq!(config.security_level(), SecurityLevel::AuthPriv);
        assert_eq!(config.auth_protocol(), Some(AuthProtocol::Sha256));
        assert_eq!(config.priv_protocol(), Some(PrivProtocol::Aes128));
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[test]
    fn test_usm_user_config_master_key_levels() {
        let auth = crate::v3::MasterKeys::new(AuthProtocol::Sha256, b"authpass").unwrap();
        let auth_config = UsmConfig::new("user").with_master_keys(auth);
        assert_eq!(auth_config.security_level(), SecurityLevel::AuthNoPriv);
        assert_eq!(auth_config.auth_protocol(), Some(AuthProtocol::Sha256));
        assert_eq!(auth_config.priv_protocol(), None);

        let auth_priv = crate::v3::MasterKeys::new(AuthProtocol::Sha256, b"authpass")
            .unwrap()
            .with_privacy(PrivProtocol::Aes128, b"privpass")
            .unwrap();
        let auth_priv_config = UsmConfig::new("user").with_master_keys(auth_priv);
        assert_eq!(auth_priv_config.security_level(), SecurityLevel::AuthPriv);
        assert_eq!(auth_priv_config.auth_protocol(), Some(AuthProtocol::Sha256));
        assert_eq!(auth_priv_config.priv_protocol(), Some(PrivProtocol::Aes128));
        let keys = auth_priv_config.derive_keys(b"test-engine-id").unwrap();
        assert!(keys.auth_key.is_some());
        assert!(keys.priv_key.is_some());
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[test]
    fn test_password_configurators_replace_master_keys() {
        let master_keys = crate::v3::MasterKeys::new(AuthProtocol::Sha256, b"masterauthpass")
            .unwrap()
            .with_privacy(PrivProtocol::Aes128, b"masterprivpass")
            .unwrap();
        let auth_config = UsmConfig::new("user")
            .with_master_keys(master_keys.clone())
            .auth(AuthProtocol::Sha1, b"passwordauth");

        assert_eq!(auth_config.security_level(), SecurityLevel::AuthNoPriv);
        assert_eq!(auth_config.auth_protocol(), Some(AuthProtocol::Sha1));
        assert_eq!(auth_config.priv_protocol(), None);

        let auth_priv_config = UsmConfig::new("user")
            .with_master_keys(master_keys)
            .auth_priv(
                AuthProtocol::Sha512,
                b"otherauthpass",
                PrivProtocol::Aes256,
                b"otherprivpass",
            );

        assert_eq!(auth_priv_config.security_level(), SecurityLevel::AuthPriv);
        assert_eq!(auth_priv_config.auth_protocol(), Some(AuthProtocol::Sha512));
        assert_eq!(auth_priv_config.priv_protocol(), Some(PrivProtocol::Aes256));
        assert!(
            auth_priv_config
                .derive_keys(b"test-engine-id")
                .unwrap()
                .priv_key
                .is_some()
        );
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[test]
    fn test_master_key_debug_redacts_key_material() {
        let master_keys = crate::v3::MasterKeys::new(AuthProtocol::Sha256, b"masterauthpass")
            .unwrap()
            .with_privacy(PrivProtocol::Aes128, b"masterprivpass")
            .unwrap();
        let rendered = format!("{:?}", UsmConfig::new("user").with_master_keys(master_keys));

        assert!(rendered.contains("[REDACTED]"), "{rendered}");
        assert!(rendered.contains("auth_password: None"), "{rendered}");
        assert!(rendered.contains("priv_password: None"), "{rendered}");
        assert!(rendered.contains("master_keys: Some"), "{rendered}");
        assert!(!rendered.contains("masterauthpass"), "{rendered}");
        assert!(!rendered.contains("masterprivpass"), "{rendered}");
    }

    #[test]
    fn test_usm_user_config_context_name() {
        let config = UsmConfig::new(Bytes::from_static(b"testuser")).context_name("ctx");
        assert_eq!(config.configured_context_name().as_ref(), b"ctx");
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[test]
    fn test_usm_user_config_derive_keys() {
        let config = UsmConfig::new(Bytes::from_static(b"testuser"))
            .auth(AuthProtocol::Sha1, b"password123");

        let engine_id = b"test-engine-id";
        let keys = config.derive_keys(engine_id).unwrap();

        assert!(keys.auth_key.is_some());
        assert!(keys.priv_key.is_none());
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[test]
    fn test_usm_user_config_derive_keys_with_privacy() {
        let config = UsmConfig::new(Bytes::from_static(b"testuser")).auth_priv(
            AuthProtocol::Sha256,
            b"authpass",
            PrivProtocol::Aes128,
            b"privpass",
        );

        let engine_id = b"test-engine-id";
        let keys = config.derive_keys(engine_id).unwrap();

        assert!(keys.auth_key.is_some());
        assert!(keys.priv_key.is_some());
    }

    /// Precomputing master keys populates the cache, so subsequent
    /// `derive_keys` calls take the master-key localization path instead of
    /// re-running the 1 MiB password expansion (the CPU-amplification vector).
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[test]
    fn test_precompute_master_keys_replaces_passwords() {
        let mut config = UsmConfig::new(Bytes::from_static(b"testuser")).auth_priv(
            AuthProtocol::Sha256,
            b"authpass",
            PrivProtocol::Aes128,
            b"privpass",
        );

        config.validate_and_precompute().unwrap();
        assert!(matches!(config.credentials, UsmCredentials::MasterKeys(_)));

        // Idempotent: a second call is a no-op and keeps the cache.
        config.validate_and_precompute().unwrap();
        assert!(matches!(config.credentials, UsmCredentials::MasterKeys(_)));
    }

    /// The cached (master-key) path and the uncached (password) path must
    /// derive identical localized keys, for both auth-only and authPriv.
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[test]
    fn test_precompute_master_keys_preserves_derivation() {
        let engine_id = b"\x80\x00\x00\x00\x01test-engine";

        // authNoPriv
        let uncached =
            UsmConfig::new(Bytes::from_static(b"u")).auth(AuthProtocol::Sha256, b"authpass");
        let mut cached = uncached.clone();
        cached.validate_and_precompute().unwrap();
        let a = uncached.derive_keys(engine_id).unwrap();
        let b = cached.derive_keys(engine_id).unwrap();
        assert_eq!(
            a.auth_key.as_ref().map(AsRef::as_ref),
            b.auth_key.as_ref().map(AsRef::as_ref),
            "auth key must match between password and master-key paths"
        );

        // authPriv, distinct auth/priv passwords
        let uncached = UsmConfig::new(Bytes::from_static(b"u")).auth_priv(
            AuthProtocol::Sha1,
            b"authpassword",
            PrivProtocol::Aes128,
            b"privpassword",
        );
        let mut cached = uncached.clone();
        cached.validate_and_precompute().unwrap();
        let a = uncached.derive_keys(engine_id).unwrap();
        let b = cached.derive_keys(engine_id).unwrap();
        assert_eq!(
            a.auth_key.as_ref().map(AsRef::as_ref),
            b.auth_key.as_ref().map(AsRef::as_ref),
        );
        let a_priv = a.priv_key.as_ref().expect("password path privacy key");
        let b_priv = b.priv_key.as_ref().expect("master-key path privacy key");
        assert_eq!(a_priv.protocol(), b_priv.protocol());
        assert_eq!(a_priv.encryption_key(), b_priv.encryption_key());

        // authPriv, same auth/priv password through the general derivation path
        let uncached = UsmConfig::new(Bytes::from_static(b"u")).auth_priv(
            AuthProtocol::Sha1,
            b"sharedpassword",
            PrivProtocol::Aes128,
            b"sharedpassword",
        );
        let mut cached = uncached.clone();
        cached.validate_and_precompute().unwrap();
        let a = uncached.derive_keys(engine_id).unwrap();
        let b = cached.derive_keys(engine_id).unwrap();
        assert_eq!(
            a.auth_key.as_ref().map(AsRef::as_ref),
            b.auth_key.as_ref().map(AsRef::as_ref),
        );
        let a_priv = a.priv_key.as_ref().expect("password path privacy key");
        let b_priv = b.priv_key.as_ref().expect("master-key path privacy key");
        assert_eq!(a_priv.protocol(), b_priv.protocol());
        assert_eq!(a_priv.encryption_key(), b_priv.encryption_key());
    }

    #[test]
    fn validate_username_octet_boundaries() {
        for username in [vec![0xff], vec![b'u'; 32]] {
            let mut config = UsmConfig::new(Bytes::from(username));
            assert!(config.validate_and_precompute().is_ok());
        }

        for username in [Vec::new(), vec![b'u'; 33]] {
            let expected = username.len();
            let mut config = UsmConfig::new(Bytes::from(username));
            assert_eq!(
                config.validate_and_precompute(),
                Err(CryptoError::InvalidUsmUsernameLength { length: expected })
            );
        }
    }

    #[test]
    fn validate_rejects_each_short_password_atomically() {
        let mut short_auth = UsmConfig::new("user").auth(AuthProtocol::Sha256, b"1234567");
        assert_eq!(
            short_auth.validate_and_precompute(),
            Err(CryptoError::PasswordTooShort)
        );
        assert!(matches!(
            short_auth.credentials,
            UsmCredentials::Passwords { .. }
        ));

        let mut short_priv = UsmConfig::new("user").auth_priv(
            AuthProtocol::Sha256,
            b"12345678",
            PrivProtocol::Aes128,
            b"1234567",
        );
        assert_eq!(
            short_priv.validate_and_precompute(),
            Err(CryptoError::PasswordTooShort)
        );
        assert!(matches!(
            short_priv.credentials,
            UsmCredentials::Passwords { .. }
        ));
    }

    #[cfg(not(any(feature = "crypto-rustcrypto", feature = "crypto-fips")))]
    #[test]
    fn password_credentials_are_rejected_without_crypto_backend() {
        let mut config = UsmConfig::new("user").auth(AuthProtocol::Sha256, b"authpassword");
        assert_eq!(
            config.validate_and_precompute(),
            Err(CryptoError::UnsupportedAlgorithm(
                "no crypto backend is enabled"
            ))
        );
        assert!(matches!(
            config.credentials,
            UsmCredentials::Passwords { .. }
        ));
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[test]
    fn validate_accepts_eight_octet_passwords() {
        let mut config = UsmConfig::new("user").auth_priv(
            AuthProtocol::Sha256,
            b"12345678",
            PrivProtocol::Aes128,
            b"abcdefgh",
        );
        config.validate_and_precompute().unwrap();
        assert!(matches!(config.credentials, UsmCredentials::MasterKeys(_)));
    }

    #[cfg(feature = "crypto-fips")]
    #[test]
    fn selected_fips_backend_rejects_unsupported_password_protocols() {
        let mut auth = UsmConfig::new("user")
            .auth(AuthProtocol::Md5, b"password")
            .with_crypto_backend(CryptoBackend::AwsLcFips);
        assert_eq!(
            auth.validate_and_precompute(),
            Err(CryptoError::UnsupportedAlgorithm("MD5"))
        );
        assert!(matches!(auth.credentials, UsmCredentials::Passwords { .. }));

        let mut privacy = UsmConfig::new("user")
            .auth_priv(
                AuthProtocol::Sha256,
                b"password",
                PrivProtocol::Des,
                b"password",
            )
            .with_crypto_backend(CryptoBackend::AwsLcFips);
        assert_eq!(
            privacy.validate_and_precompute(),
            Err(CryptoError::UnsupportedAlgorithm("DES"))
        );
        assert!(matches!(
            privacy.credentials,
            UsmCredentials::Passwords { .. }
        ));
    }

    #[cfg(feature = "crypto-fips")]
    #[test]
    fn selected_fips_backend_rejects_unsupported_master_key_privacy() {
        let master_keys = crate::v3::MasterKeys::new_with_backend(
            AuthProtocol::Sha256,
            b"password",
            CryptoBackend::AwsLcFips,
        )
        .unwrap()
        .with_privacy_same_password(PrivProtocol::Des);
        let mut config = UsmConfig::new("user")
            .with_crypto_backend(CryptoBackend::AwsLcFips)
            .with_master_keys(master_keys);

        assert_eq!(
            config.validate_and_precompute(),
            Err(CryptoError::UnsupportedAlgorithm("DES"))
        );
    }

    #[cfg(all(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[test]
    fn selected_fips_backend_rejects_unsupported_master_key_auth() {
        let master_keys = crate::v3::MasterKeys::new_with_backend(
            AuthProtocol::Md5,
            b"password",
            CryptoBackend::RustCrypto,
        )
        .unwrap();
        let mut config = UsmConfig::new("user")
            .with_master_keys(master_keys)
            .with_crypto_backend(CryptoBackend::AwsLcFips);

        assert_eq!(
            config.validate_and_precompute(),
            Err(CryptoError::UnsupportedAlgorithm("MD5"))
        );
    }
}
