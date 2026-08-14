//! Authentication configuration types for the SNMP client.
//!
//! This module provides the [`Auth`] enum for specifying authentication
//! configuration, supporting SNMPv1/v2c community identifiers and `SNMPv3` USM.
//!
//! # Reusing master keys
//!
//! When polling many engines with shared credentials, use
//! [`MasterKeys`] to avoid repeating password-to-key derivation:
//!
//! ```rust
//! # #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
//! # {
//! use async_snmp::{Auth, AuthProtocol, PrivProtocol, MasterKeys, UsmConfig};
//!
//! // Derive the master keys once for these credentials.
//! let master_keys = MasterKeys::new(AuthProtocol::Sha256, b"authpassword").unwrap()
//!     .with_privacy(PrivProtocol::Aes128, b"privpassword").unwrap();
//!
//! // Each client localizes the keys for its authoritative engine.
//! let auth = Auth::from(UsmConfig::new("admin")
//!     .with_master_keys(master_keys).unwrap());
//! # }
//! ```

use crate::Community;
use crate::v3::UsmConfig;
pub use crate::version::CommunityVersion;
use crate::version::Version;

/// Authentication configuration for SNMP clients.
///
/// The [`Debug`] implementation redacts community identifiers so that credentials
/// are not leaked through logs or diagnostics.
#[derive(Clone)]
pub enum Auth {
    /// Community authentication (`SNMPv1` or v2c).
    Community {
        /// SNMP version (V1 or V2c)
        version: CommunityVersion,
        /// Community identifier bytes.
        community: Community,
    },
    /// User-based Security Model (`SNMPv3`).
    Usm(UsmConfig),
}

impl Default for Auth {
    /// Returns `Auth::v2c("public")`.
    fn default() -> Self {
        Auth::v2c("public")
    }
}

impl Auth {
    /// `SNMPv1` community authentication.
    ///
    /// Creates authentication configuration for `SNMPv1`, which only supports
    /// community authentication without encryption. Community identifiers are
    /// protocol octets and do not need to be valid UTF-8.
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_snmp::Auth;
    /// use bytes::Bytes;
    ///
    /// // String literals and owned strings can be passed directly.
    /// let auth = Auth::v1("private");
    ///
    /// // Copy a short-lived borrowed string into owned community bytes.
    /// let community = String::from("private");
    /// let auth = Auth::v1(Bytes::copy_from_slice(community.as_bytes()));
    /// ```
    pub fn v1(community: impl Into<Community>) -> Self {
        Auth::Community {
            version: CommunityVersion::V1,
            community: community.into(),
        }
    }

    /// `SNMPv2c` community authentication.
    ///
    /// Creates authentication configuration for `SNMPv2c`, which supports
    /// community authentication without encryption but adds GETBULK and
    /// improved error handling over `SNMPv1`. Community identifiers are
    /// protocol octets and do not need to be valid UTF-8.
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_snmp::Auth;
    /// use bytes::Bytes;
    ///
    /// // String literals and owned strings can be passed directly.
    /// let auth = Auth::v2c("public");
    ///
    /// // Copy a short-lived borrowed string into owned community bytes.
    /// let community = String::from("public");
    /// let auth = Auth::v2c(Bytes::copy_from_slice(community.as_bytes()));
    ///
    /// // Auth::default() is equivalent to Auth::v2c("public")
    /// let auth = Auth::default();
    /// ```
    pub fn v2c(community: impl Into<Community>) -> Self {
        Auth::Community {
            version: CommunityVersion::V2c,
            community: community.into(),
        }
    }

    /// Create an `SNMPv3` username-only (`noAuthNoPriv`) configuration.
    ///
    /// Usernames are protocol octets and do not need to be valid UTF-8. This
    /// constructor returns [`Auth`] directly, like [`Self::v1`] and
    /// [`Self::v2c`]. Construct a [`UsmConfig`] for authentication, privacy,
    /// context names, precomputed keys, or an explicit cryptographic backend.
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_snmp::Auth;
    /// use bytes::Bytes;
    ///
    /// // noAuthNoPriv: username only
    /// let auth = Auth::usm("readonly");
    ///
    /// // Arbitrary octets are preserved.
    /// let auth = Auth::usm(Bytes::from_static(b"operator\xff"));
    /// ```
    pub fn usm(username: impl AsRef<[u8]>) -> Self {
        Self::Usm(UsmConfig::new(bytes::Bytes::copy_from_slice(
            username.as_ref(),
        )))
    }

    /// Return the SNMP version selected by this authentication configuration.
    #[must_use]
    pub fn version(&self) -> Version {
        match self {
            Auth::Community {
                version: CommunityVersion::V1,
                ..
            } => Version::V1,
            Auth::Community {
                version: CommunityVersion::V2c,
                ..
            } => Version::V2c,
            Auth::Usm(_) => Version::V3,
        }
    }

    pub(crate) fn community(&self) -> Option<&Community> {
        match self {
            Auth::Community { community, .. } => Some(community),
            Auth::Usm(_) => None,
        }
    }

    pub(crate) fn community_version(&self) -> Option<CommunityVersion> {
        match self {
            Auth::Community { version, .. } => Some(*version),
            Auth::Usm(_) => None,
        }
    }

    pub(crate) fn usm_config(&self) -> Option<&UsmConfig> {
        match self {
            Auth::Usm(config) => Some(config),
            Auth::Community { .. } => None,
        }
    }
}

impl From<UsmConfig> for Auth {
    fn from(config: UsmConfig) -> Self {
        Self::Usm(config)
    }
}

/// Placeholder printed in place of a redacted secret value.
const REDACTED: &str = "[REDACTED]";

impl std::fmt::Debug for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Auth::Community { version, .. } => f
                .debug_struct("Auth::Community")
                .field("version", version)
                .field("community", &REDACTED)
                .finish(),
            Auth::Usm(usm) => f.debug_tuple("Auth::Usm").field(usm).finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::SecurityLevel;
    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    use crate::v3::{AuthProtocol, PrivProtocol};
    use bytes::Bytes;

    #[test]
    fn test_default_auth() {
        let auth = Auth::default();
        match auth {
            Auth::Community { version, community } => {
                assert_eq!(version, CommunityVersion::V2c);
                assert!(community.matches(b"public"));
            }
            Auth::Usm(_) => panic!("expected Community variant"),
        }
    }

    #[test]
    fn test_v1_auth() {
        let auth = Auth::v1("private");
        match auth {
            Auth::Community { version, community } => {
                assert_eq!(version, CommunityVersion::V1);
                assert!(community.matches(b"private"));
            }
            Auth::Usm(_) => panic!("expected Community variant"),
        }
    }

    #[test]
    fn test_v2c_auth() {
        let auth = Auth::v2c("secret");
        match auth {
            Auth::Community { version, community } => {
                assert_eq!(version, CommunityVersion::V2c);
                assert!(community.matches(b"secret"));
            }
            Auth::Usm(_) => panic!("expected Community variant"),
        }
    }

    #[test]
    fn test_non_utf8_community_auth() {
        let community = Bytes::from_static(b"public\xff");

        for (auth, expected_version) in [
            (Auth::v1(community.clone()), CommunityVersion::V1),
            (Auth::v2c(community.clone()), CommunityVersion::V2c),
        ] {
            match auth {
                Auth::Community {
                    version,
                    community: actual,
                } => {
                    assert_eq!(version, expected_version);
                    assert!(actual.matches(&community));
                }
                Auth::Usm(_) => panic!("expected Community variant"),
            }
        }
    }

    #[test]
    fn test_community_version_default() {
        let version = CommunityVersion::default();
        assert_eq!(version, CommunityVersion::V2c);
    }

    #[test]
    fn test_usm_no_auth_no_priv() {
        let auth = Auth::usm("readonly");
        match auth {
            Auth::Usm(usm) => {
                assert_eq!(usm.username().as_ref(), b"readonly");
                assert_eq!(usm.security_level(), SecurityLevel::NoAuthNoPriv);
                assert!(usm.configured_context_name().is_empty());
            }
            Auth::Community { .. } => panic!("expected Usm variant"),
        }
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[test]
    fn test_usm_auth_no_priv() {
        let auth = Auth::from(
            UsmConfig::new("admin")
                .auth(AuthProtocol::Sha256, "authpass123")
                .unwrap(),
        );
        match auth {
            Auth::Usm(usm) => {
                assert_eq!(usm.username().as_ref(), b"admin");
                assert_eq!(usm.security_level(), SecurityLevel::AuthNoPriv);
            }
            Auth::Community { .. } => panic!("expected Usm variant"),
        }
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[test]
    fn test_usm_auth_priv() {
        let auth = Auth::from(
            UsmConfig::new("admin")
                .auth_priv(
                    AuthProtocol::Sha256,
                    "authpass",
                    PrivProtocol::Aes128,
                    "privpass",
                )
                .unwrap(),
        );
        match auth {
            Auth::Usm(usm) => {
                assert_eq!(usm.username().as_ref(), b"admin");
                assert_eq!(usm.security_level(), SecurityLevel::AuthPriv);
            }
            Auth::Community { .. } => panic!("expected Usm variant"),
        }
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[test]
    fn test_usm_with_context_name() {
        let auth = Auth::from(
            UsmConfig::new("admin")
                .auth(AuthProtocol::Sha256, "authpass")
                .unwrap()
                .context_name("vlan100"),
        );
        match auth {
            Auth::Usm(usm) => {
                assert_eq!(usm.username().as_ref(), b"admin");
                assert_eq!(usm.configured_context_name().as_ref(), b"vlan100");
            }
            Auth::Community { .. } => panic!("expected Usm variant"),
        }
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[test]
    fn test_usm_config_chaining() {
        // Verify all methods can be chained
        let auth = Auth::from(
            UsmConfig::new("user")
                .auth_priv(
                    AuthProtocol::Sha512,
                    "authpass",
                    PrivProtocol::Aes256Blumenthal,
                    "privpass",
                )
                .unwrap()
                .context_name("ctx"),
        );

        match auth {
            Auth::Usm(usm) => {
                assert_eq!(usm.username().as_ref(), b"user");
                assert_eq!(usm.security_level(), SecurityLevel::AuthPriv);
                assert_eq!(usm.configured_context_name().as_ref(), b"ctx");
            }
            Auth::Community { .. } => panic!("expected Usm variant"),
        }
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[test]
    fn test_debug_redacts_secrets() {
        // Community string must not appear in Debug output.
        let community = Auth::v2c("supersecretcommunity");
        let rendered = format!("{community:?}");
        assert!(!rendered.contains("supersecretcommunity"), "{rendered}");
        assert!(rendered.contains("[REDACTED]"), "{rendered}");

        // USM auth/priv passwords must not appear in Debug output.
        let auth = Auth::from(
            UsmConfig::new("admin")
                .auth_priv(
                    AuthProtocol::Sha256,
                    "authpassword123",
                    PrivProtocol::Aes128,
                    "privpassword456",
                )
                .unwrap()
                .context_name("vlan100"),
        );
        let config_rendered = format!("{auth:?}");
        assert!(
            !config_rendered.contains("authpassword123"),
            "{config_rendered}"
        );
        assert!(
            !config_rendered.contains("privpassword456"),
            "{config_rendered}"
        );
        // Non-secret fields remain visible.
        assert!(config_rendered.contains("admin"), "{config_rendered}");
        assert!(config_rendered.contains("vlan100"), "{config_rendered}");

        let usm_rendered = format!("{auth:?}");
        assert!(!usm_rendered.contains("authpassword123"), "{usm_rendered}");
        assert!(!usm_rendered.contains("privpassword456"), "{usm_rendered}");
        assert!(usm_rendered.contains("[REDACTED]"), "{usm_rendered}");
        assert!(usm_rendered.contains("admin"), "{usm_rendered}");
    }

    #[test]
    fn test_usm_constructor_consistency_and_octets() {
        let username = Bytes::from_static(b"operator\xff");
        let constructors: [Auth; 3] = [
            Auth::v1(username.clone()),
            Auth::v2c(username.clone()),
            Auth::usm(username.clone()),
        ];

        assert_eq!(constructors[0].version(), Version::V1);
        assert_eq!(constructors[1].version(), Version::V2c);
        assert_eq!(constructors[2].version(), Version::V3);
        let Auth::Usm(config) = &constructors[2] else {
            panic!("expected Usm variant");
        };
        assert_eq!(config.username(), &username);
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[test]
    fn test_usm_config_preserves_non_utf8_octets_at_each_security_level() {
        let username = Bytes::from_static(b"user\x00\xff");
        let configurations = [
            Auth::usm(username.clone()),
            Auth::from(
                UsmConfig::new(username.clone())
                    .auth(AuthProtocol::Sha256, "authpass")
                    .unwrap(),
            ),
            Auth::from(
                UsmConfig::new(username.clone())
                    .auth_priv(
                        AuthProtocol::Sha256,
                        "authpass",
                        PrivProtocol::Aes128,
                        "privpass",
                    )
                    .unwrap(),
            ),
        ];

        for (auth, level) in configurations.iter().zip([
            SecurityLevel::NoAuthNoPriv,
            SecurityLevel::AuthNoPriv,
            SecurityLevel::AuthPriv,
        ]) {
            let Auth::Usm(config) = auth else {
                panic!("expected Usm variant");
            };
            assert_eq!(config.username(), &username);
            assert_eq!(config.security_level(), level);
        }
    }

    #[test]
    fn test_usm_auth_api_validates_username_octet_boundaries() {
        for username in [vec![0xff], vec![b'u'; 32]] {
            let Auth::Usm(mut config) = Auth::usm(username) else {
                panic!("expected Usm variant");
            };
            assert!(config.validate_and_precompute().is_ok());
        }

        for username in [Vec::new(), vec![b'u'; 33]] {
            let length = username.len();
            let Auth::Usm(mut config) = Auth::usm(username) else {
                panic!("expected Usm variant");
            };
            assert_eq!(
                config.validate_and_precompute(),
                Err(crate::v3::CryptoError::InvalidUsmUsernameLength { length })
            );
        }
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[test]
    fn test_usm_config_debug_is_byte_exact_and_redacted() {
        let config = UsmConfig::new(Bytes::from_static(b"user\xff"))
            .auth(AuthProtocol::Sha256, "authpassword")
            .unwrap();
        let rendered = format!("{config:?}");

        assert!(rendered.contains(r"user\xff"), "{rendered}");
        assert!(!rendered.contains('\u{fffd}'), "{rendered}");
        assert!(!rendered.contains("authpassword"), "{rendered}");
        assert!(rendered.contains("[REDACTED]"), "{rendered}");
    }
}
