//! Authentication configuration types for the SNMP client.
//!
//! This module provides the [`Auth`] enum for specifying authentication
//! configuration, supporting SNMPv1/v2c community strings and SNMPv3 USM.
//!
//! # Master Key Caching
//!
//! When polling many engines with shared credentials, use
//! [`MasterKeys`] to cache the expensive password-to-key
//! derivation:
//!
//! ```rust
//! use async_snmp::{Auth, AuthProtocol, PrivProtocol, MasterKeys};
//!
//! // Derive master keys once (expensive: ~850μs for SHA-256)
//! let master_keys = MasterKeys::new(AuthProtocol::Sha256, b"authpassword")
//!     .with_privacy(PrivProtocol::Aes128, b"privpassword");
//!
//! // Use with USM builder - localization is cheap (~1μs per engine)
//! let auth: Auth = Auth::usm("admin")
//!     .with_master_keys(master_keys)
//!     .into();
//! ```

use crate::v3::{AuthProtocol, MasterKeys, PrivProtocol};

/// SNMP version for community-based authentication.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CommunityVersion {
    /// SNMPv1
    V1,
    /// SNMPv2c
    #[default]
    V2c,
}

/// Authentication configuration for SNMP clients.
#[derive(Debug, Clone)]
pub enum Auth {
    /// Community string authentication (SNMPv1 or v2c).
    Community {
        /// SNMP version (V1 or V2c)
        version: CommunityVersion,
        /// Community string
        community: String,
    },
    /// User-based Security Model (SNMPv3).
    Usm(UsmAuth),
}

impl Default for Auth {
    /// Returns `Auth::v2c("public")`.
    fn default() -> Self {
        Auth::v2c("public")
    }
}

impl Auth {
    /// SNMPv1 community authentication.
    ///
    /// Creates authentication configuration for SNMPv1, which only supports
    /// community string authentication without encryption.
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_snmp::Auth;
    ///
    /// // Create SNMPv1 authentication with "private" community
    /// let auth = Auth::v1("private");
    /// ```
    pub fn v1(community: impl Into<String>) -> Self {
        Auth::Community {
            version: CommunityVersion::V1,
            community: community.into(),
        }
    }

    /// SNMPv2c community authentication.
    ///
    /// Creates authentication configuration for SNMPv2c, which supports
    /// community string authentication without encryption but adds GETBULK
    /// and improved error handling over SNMPv1.
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_snmp::Auth;
    ///
    /// // Create SNMPv2c authentication with "public" community
    /// let auth = Auth::v2c("public");
    ///
    /// // Auth::default() is equivalent to Auth::v2c("public")
    /// let auth = Auth::default();
    /// ```
    pub fn v2c(community: impl Into<String>) -> Self {
        Auth::Community {
            version: CommunityVersion::V2c,
            community: community.into(),
        }
    }

    /// Start building SNMPv3 USM authentication.
    ///
    /// Returns a builder that allows configuring authentication and privacy
    /// protocols. SNMPv3 supports three security levels:
    /// - noAuthNoPriv: username only (no security)
    /// - authNoPriv: username with authentication (integrity)
    /// - authPriv: username with authentication and encryption (confidentiality)
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_snmp::{Auth, AuthProtocol, PrivProtocol};
    ///
    /// // noAuthNoPriv: username only
    /// let auth: Auth = Auth::usm("readonly").into();
    ///
    /// // authNoPriv: with authentication
    /// let auth: Auth = Auth::usm("admin")
    ///     .auth(AuthProtocol::Sha256, "authpassword")
    ///     .into();
    ///
    /// // authPriv: with authentication and encryption
    /// let auth: Auth = Auth::usm("admin")
    ///     .auth(AuthProtocol::Sha256, "authpassword")
    ///     .privacy(PrivProtocol::Aes128, "privpassword")
    ///     .into();
    /// ```
    pub fn usm(username: impl Into<String>) -> UsmBuilder {
        UsmBuilder::new(username)
    }
}

/// SNMPv3 USM authentication parameters.
#[derive(Debug, Clone)]
pub struct UsmAuth {
    /// SNMPv3 username
    pub username: String,
    /// Authentication protocol (None for noAuthNoPriv)
    pub auth_protocol: Option<AuthProtocol>,
    /// Authentication password
    pub auth_password: Option<String>,
    /// Privacy protocol (None for noPriv)
    pub priv_protocol: Option<PrivProtocol>,
    /// Privacy password
    pub priv_password: Option<String>,
    /// SNMPv3 context name for VACM context selection.
    /// Most deployments use empty string (default).
    pub context_name: Option<String>,
    /// Pre-computed master keys for caching.
    /// When set, passwords are ignored and keys are derived from master keys.
    pub master_keys: Option<MasterKeys>,
}

/// Builder for SNMPv3 USM authentication.
pub struct UsmBuilder {
    username: String,
    auth: Option<(AuthProtocol, String)>,
    privacy: Option<(PrivProtocol, String)>,
    context_name: Option<String>,
    master_keys: Option<MasterKeys>,
}

impl UsmBuilder {
    /// Create a new USM builder with the given username.
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_snmp::Auth;
    ///
    /// let builder = Auth::usm("admin");
    /// ```
    pub fn new(username: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            auth: None,
            privacy: None,
            context_name: None,
            master_keys: None,
        }
    }

    /// Add authentication (authNoPriv or authPriv).
    ///
    /// This method performs the full key derivation (~850us for SHA-256) when
    /// the client connects. When polling many engines with shared credentials,
    /// consider using [`with_master_keys`](Self::with_master_keys) instead.
    ///
    /// # Supported Protocols
    ///
    /// - `AuthProtocol::Md5` - HMAC-MD5-96 (legacy)
    /// - `AuthProtocol::Sha1` - HMAC-SHA-96 (legacy)
    /// - `AuthProtocol::Sha224` - HMAC-SHA-224
    /// - `AuthProtocol::Sha256` - HMAC-SHA-256
    /// - `AuthProtocol::Sha384` - HMAC-SHA-384
    /// - `AuthProtocol::Sha512` - HMAC-SHA-512
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_snmp::{Auth, AuthProtocol};
    ///
    /// let auth: Auth = Auth::usm("admin")
    ///     .auth(AuthProtocol::Sha256, "mypassword")
    ///     .into();
    /// ```
    pub fn auth(mut self, protocol: AuthProtocol, password: impl Into<String>) -> Self {
        self.auth = Some((protocol, password.into()));
        self
    }

    /// Add privacy/encryption (authPriv).
    ///
    /// Privacy requires authentication; this is validated at connection time.
    ///
    /// # Supported Protocols
    ///
    /// - `PrivProtocol::Des` - DES-CBC (legacy, insecure)
    /// - `PrivProtocol::Aes128` - AES-128-CFB
    /// - `PrivProtocol::Aes192` - AES-192-CFB
    /// - `PrivProtocol::Aes256` - AES-256-CFB
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_snmp::{Auth, AuthProtocol, PrivProtocol};
    ///
    /// let auth: Auth = Auth::usm("admin")
    ///     .auth(AuthProtocol::Sha256, "authpassword")
    ///     .privacy(PrivProtocol::Aes128, "privpassword")
    ///     .into();
    /// ```
    pub fn privacy(mut self, protocol: PrivProtocol, password: impl Into<String>) -> Self {
        self.privacy = Some((protocol, password.into()));
        self
    }

    /// Use pre-computed master keys for authentication and privacy.
    ///
    /// This is the efficient path when polling many engines with shared
    /// credentials. The expensive password-to-key derivation
    /// (~850μs) is done once when creating the [`MasterKeys`], and only the
    /// cheap localization (~1μs) is performed per engine.
    ///
    /// When master keys are set, the [`auth`](Self::auth) and
    /// [`privacy`](Self::privacy) methods are ignored.
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_snmp::{Auth, AuthProtocol, PrivProtocol, MasterKeys};
    ///
    /// // Derive master keys once
    /// let master_keys = MasterKeys::new(AuthProtocol::Sha256, b"authpassword")
    ///     .with_privacy(PrivProtocol::Aes128, b"privpassword");
    ///
    /// // Use with multiple clients
    /// let auth: Auth = Auth::usm("admin")
    ///     .with_master_keys(master_keys)
    ///     .into();
    /// ```
    pub fn with_master_keys(mut self, master_keys: MasterKeys) -> Self {
        self.master_keys = Some(master_keys);
        self
    }

    /// Set the SNMPv3 context name for VACM context selection.
    ///
    /// The context name allows selecting different MIB views on the same agent.
    /// Most deployments use empty string (default).
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_snmp::{Auth, AuthProtocol};
    ///
    /// let auth: Auth = Auth::usm("admin")
    ///     .auth(AuthProtocol::Sha256, "password")
    ///     .context_name("vlan100")
    ///     .into();
    /// ```
    pub fn context_name(mut self, name: impl Into<String>) -> Self {
        self.context_name = Some(name.into());
        self
    }
}

impl From<UsmBuilder> for Auth {
    fn from(b: UsmBuilder) -> Auth {
        Auth::Usm(UsmAuth {
            username: b.username,
            auth_protocol: b
                .master_keys
                .as_ref()
                .map(|m| m.auth_protocol())
                .or(b.auth.as_ref().map(|(p, _)| *p)),
            auth_password: b.auth.map(|(_, pw)| pw),
            priv_protocol: b
                .master_keys
                .as_ref()
                .and_then(|m| m.priv_protocol())
                .or(b.privacy.as_ref().map(|(p, _)| *p)),
            priv_password: b.privacy.map(|(_, pw)| pw),
            context_name: b.context_name,
            master_keys: b.master_keys,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_auth() {
        let auth = Auth::default();
        match auth {
            Auth::Community { version, community } => {
                assert_eq!(version, CommunityVersion::V2c);
                assert_eq!(community, "public");
            }
            _ => panic!("expected Community variant"),
        }
    }

    #[test]
    fn test_v1_auth() {
        let auth = Auth::v1("private");
        match auth {
            Auth::Community { version, community } => {
                assert_eq!(version, CommunityVersion::V1);
                assert_eq!(community, "private");
            }
            _ => panic!("expected Community variant"),
        }
    }

    #[test]
    fn test_v2c_auth() {
        let auth = Auth::v2c("secret");
        match auth {
            Auth::Community { version, community } => {
                assert_eq!(version, CommunityVersion::V2c);
                assert_eq!(community, "secret");
            }
            _ => panic!("expected Community variant"),
        }
    }

    #[test]
    fn test_community_version_default() {
        let version = CommunityVersion::default();
        assert_eq!(version, CommunityVersion::V2c);
    }

    #[test]
    fn test_usm_no_auth_no_priv() {
        let auth: Auth = Auth::usm("readonly").into();
        match auth {
            Auth::Usm(usm) => {
                assert_eq!(usm.username, "readonly");
                assert!(usm.auth_protocol.is_none());
                assert!(usm.auth_password.is_none());
                assert!(usm.priv_protocol.is_none());
                assert!(usm.priv_password.is_none());
                assert!(usm.context_name.is_none());
            }
            _ => panic!("expected Usm variant"),
        }
    }

    #[test]
    fn test_usm_auth_no_priv() {
        let auth: Auth = Auth::usm("admin")
            .auth(AuthProtocol::Sha256, "authpass123")
            .into();
        match auth {
            Auth::Usm(usm) => {
                assert_eq!(usm.username, "admin");
                assert_eq!(usm.auth_protocol, Some(AuthProtocol::Sha256));
                assert_eq!(usm.auth_password, Some("authpass123".to_string()));
                assert!(usm.priv_protocol.is_none());
                assert!(usm.priv_password.is_none());
            }
            _ => panic!("expected Usm variant"),
        }
    }

    #[test]
    fn test_usm_auth_priv() {
        let auth: Auth = Auth::usm("admin")
            .auth(AuthProtocol::Sha256, "authpass")
            .privacy(PrivProtocol::Aes128, "privpass")
            .into();
        match auth {
            Auth::Usm(usm) => {
                assert_eq!(usm.username, "admin");
                assert_eq!(usm.auth_protocol, Some(AuthProtocol::Sha256));
                assert_eq!(usm.auth_password, Some("authpass".to_string()));
                assert_eq!(usm.priv_protocol, Some(PrivProtocol::Aes128));
                assert_eq!(usm.priv_password, Some("privpass".to_string()));
            }
            _ => panic!("expected Usm variant"),
        }
    }

    #[test]
    fn test_usm_with_context_name() {
        let auth: Auth = Auth::usm("admin")
            .auth(AuthProtocol::Sha256, "authpass")
            .context_name("vlan100")
            .into();
        match auth {
            Auth::Usm(usm) => {
                assert_eq!(usm.username, "admin");
                assert_eq!(usm.context_name, Some("vlan100".to_string()));
            }
            _ => panic!("expected Usm variant"),
        }
    }

    #[test]
    fn test_usm_builder_chaining() {
        // Verify all methods can be chained
        let auth: Auth = Auth::usm("user")
            .auth(AuthProtocol::Sha512, "auth")
            .privacy(PrivProtocol::Aes256, "priv")
            .context_name("ctx")
            .into();

        match auth {
            Auth::Usm(usm) => {
                assert_eq!(usm.username, "user");
                assert_eq!(usm.auth_protocol, Some(AuthProtocol::Sha512));
                assert_eq!(usm.auth_password, Some("auth".to_string()));
                assert_eq!(usm.priv_protocol, Some(PrivProtocol::Aes256));
                assert_eq!(usm.priv_password, Some("priv".to_string()));
                assert_eq!(usm.context_name, Some("ctx".to_string()));
            }
            _ => panic!("expected Usm variant"),
        }
    }
}
