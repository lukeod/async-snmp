//! Authentication configuration types for the SNMP client.
//!
//! This module provides the [`Auth`] enum for specifying authentication
//! configuration, supporting SNMPv1/v2c community strings and SNMPv3 USM.
//!
//! # Master Key Caching
//!
//! For high-throughput polling of many engines with shared credentials, use
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum CommunityVersion {
    /// SNMPv1
    V1,
    /// SNMPv2c
    #[default]
    V2c,
}

/// Authentication configuration for SNMP clients.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(untagged))]
pub enum Auth {
    /// Community string authentication (SNMPv1 or v2c).
    Community {
        /// SNMP version (V1 or V2c)
        #[cfg_attr(feature = "serde", serde(default))]
        version: CommunityVersion,
        /// Community string
        community: String,
    },
    /// User-based Security Model (SNMPv3).
    Usm(UsmAuth),
}

impl Default for Auth {
    fn default() -> Self {
        Auth::v2c("public")
    }
}

impl Auth {
    /// SNMPv1 community authentication.
    pub fn v1(community: impl Into<String>) -> Self {
        Auth::Community {
            version: CommunityVersion::V1,
            community: community.into(),
        }
    }

    /// SNMPv2c community authentication.
    pub fn v2c(community: impl Into<String>) -> Self {
        Auth::Community {
            version: CommunityVersion::V2c,
            community: community.into(),
        }
    }

    /// Start building SNMPv3 USM authentication.
    pub fn usm(username: impl Into<String>) -> UsmBuilder {
        UsmBuilder::new(username)
    }
}

/// SNMPv3 USM authentication parameters.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UsmAuth {
    /// SNMPv3 username
    pub username: String,
    /// Authentication protocol (None for noAuthNoPriv)
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub auth_protocol: Option<AuthProtocol>,
    /// Authentication password
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub auth_password: Option<String>,
    /// Privacy protocol (None for noPriv)
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub priv_protocol: Option<PrivProtocol>,
    /// Privacy password
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub priv_password: Option<String>,
    /// SNMPv3 context name for VACM context selection.
    /// Most deployments use empty string (default).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub context_name: Option<String>,
    /// Pre-computed master keys for caching.
    /// When set, passwords are ignored and keys are derived from master keys.
    #[cfg_attr(feature = "serde", serde(skip))]
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
    /// This method performs the full key derivation (~850μs for SHA-256) when
    /// the client connects. For high-throughput polling of many engines,
    /// consider using [`with_master_keys`](Self::with_master_keys) instead.
    pub fn auth(mut self, protocol: AuthProtocol, password: impl Into<String>) -> Self {
        self.auth = Some((protocol, password.into()));
        self
    }

    /// Add privacy/encryption (authPriv).
    ///
    /// Requires auth; validated at connection time.
    pub fn privacy(mut self, protocol: PrivProtocol, password: impl Into<String>) -> Self {
        self.privacy = Some((protocol, password.into()));
        self
    }

    /// Use pre-computed master keys for authentication and privacy.
    ///
    /// This is the efficient path for high-throughput polling of many engines
    /// with shared credentials. The expensive password-to-key derivation
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
    /// Most deployments use empty string (default).
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

#[cfg(all(test, feature = "serde"))]
mod serde_tests {
    use super::*;

    #[test]
    fn test_community_v2c_roundtrip() {
        let auth = Auth::v2c("public");
        let json = serde_json::to_string(&auth).unwrap();
        let back: Auth = serde_json::from_str(&json).unwrap();

        match back {
            Auth::Community { version, community } => {
                assert_eq!(version, CommunityVersion::V2c);
                assert_eq!(community, "public");
            }
            _ => panic!("expected Community variant"),
        }
    }

    #[test]
    fn test_community_v1_roundtrip() {
        let auth = Auth::v1("private");
        let json = serde_json::to_string(&auth).unwrap();
        let back: Auth = serde_json::from_str(&json).unwrap();

        match back {
            Auth::Community { version, community } => {
                assert_eq!(version, CommunityVersion::V1);
                assert_eq!(community, "private");
            }
            _ => panic!("expected Community variant"),
        }
    }

    #[test]
    fn test_usm_no_auth_roundtrip() {
        let auth: Auth = Auth::usm("readonly").into();
        let json = serde_json::to_string(&auth).unwrap();
        let back: Auth = serde_json::from_str(&json).unwrap();

        match back {
            Auth::Usm(usm) => {
                assert_eq!(usm.username, "readonly");
                assert!(usm.auth_protocol.is_none());
                assert!(usm.auth_password.is_none());
                assert!(usm.priv_protocol.is_none());
                assert!(usm.priv_password.is_none());
            }
            _ => panic!("expected Usm variant"),
        }
    }

    #[test]
    fn test_usm_auth_priv_roundtrip() {
        let auth: Auth = Auth::usm("admin")
            .auth(AuthProtocol::Sha256, "authpass")
            .privacy(PrivProtocol::Aes128, "privpass")
            .context_name("vlan100")
            .into();

        let json = serde_json::to_string(&auth).unwrap();
        let back: Auth = serde_json::from_str(&json).unwrap();

        match back {
            Auth::Usm(usm) => {
                assert_eq!(usm.username, "admin");
                assert_eq!(usm.auth_protocol, Some(AuthProtocol::Sha256));
                assert_eq!(usm.auth_password, Some("authpass".to_string()));
                assert_eq!(usm.priv_protocol, Some(PrivProtocol::Aes128));
                assert_eq!(usm.priv_password, Some("privpass".to_string()));
                assert_eq!(usm.context_name, Some("vlan100".to_string()));
            }
            _ => panic!("expected Usm variant"),
        }
    }

    #[test]
    fn test_community_deserialize_without_version() {
        // When deserializing, version should default to V2c if not present
        let json = r#"{"community":"public"}"#;
        let auth: Auth = serde_json::from_str(json).unwrap();

        match auth {
            Auth::Community { version, community } => {
                assert_eq!(version, CommunityVersion::V2c);
                assert_eq!(community, "public");
            }
            _ => panic!("expected Community variant"),
        }
    }

    #[test]
    fn test_usm_optional_fields_not_serialized_when_none() {
        let auth: Auth = Auth::usm("readonly").into();
        let json = serde_json::to_string(&auth).unwrap();

        // Should only contain username, no None fields
        assert!(json.contains("username"));
        assert!(!json.contains("auth_protocol"));
        assert!(!json.contains("auth_password"));
        assert!(!json.contains("priv_protocol"));
        assert!(!json.contains("priv_password"));
        assert!(!json.contains("context_name"));
    }

    #[test]
    fn test_walk_mode_roundtrip() {
        use crate::client::walk::WalkMode;

        let modes = [WalkMode::Auto, WalkMode::GetNext, WalkMode::GetBulk];

        for mode in modes {
            let json = serde_json::to_string(&mode).unwrap();
            let back: WalkMode = serde_json::from_str(&json).unwrap();
            assert_eq!(back, mode);
        }
    }

    #[test]
    fn test_oid_ordering_roundtrip() {
        use crate::client::walk::OidOrdering;

        let orderings = [OidOrdering::Strict, OidOrdering::AllowNonIncreasing];

        for ordering in orderings {
            let json = serde_json::to_string(&ordering).unwrap();
            let back: OidOrdering = serde_json::from_str(&json).unwrap();
            assert_eq!(back, ordering);
        }
    }

    #[test]
    fn test_auth_protocol_roundtrip() {
        let protocols = [
            AuthProtocol::Md5,
            AuthProtocol::Sha1,
            AuthProtocol::Sha224,
            AuthProtocol::Sha256,
            AuthProtocol::Sha384,
            AuthProtocol::Sha512,
        ];

        for proto in protocols {
            let json = serde_json::to_string(&proto).unwrap();
            let back: AuthProtocol = serde_json::from_str(&json).unwrap();
            assert_eq!(back, proto);
        }
    }

    #[test]
    fn test_priv_protocol_roundtrip() {
        let protocols = [
            PrivProtocol::Des,
            PrivProtocol::Aes128,
            PrivProtocol::Aes192,
            PrivProtocol::Aes256,
        ];

        for proto in protocols {
            let json = serde_json::to_string(&proto).unwrap();
            let back: PrivProtocol = serde_json::from_str(&json).unwrap();
            assert_eq!(back, proto);
        }
    }
}
