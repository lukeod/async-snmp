//! Authentication configuration types for the SNMP client.
//!
//! This module provides the [`Auth`] enum for specifying authentication
//! configuration, supporting SNMPv1/v2c community strings and `SNMPv3` USM.
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
//! let master_keys = MasterKeys::new(AuthProtocol::Sha256, b"authpassword").unwrap()
//!     .with_privacy(PrivProtocol::Aes128, b"privpassword").unwrap();
//!
//! // Use with the shared USM config - localization is cheap (~1μs per engine)
//! let auth: Auth = Auth::usm("admin")
//!     .with_master_keys(master_keys)
//!     .into();
//! ```

use crate::v3::UsmConfig;

/// SNMP version for community-based authentication.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CommunityVersion {
    /// `SNMPv1`
    V1,
    /// `SNMPv2c`
    #[default]
    V2c,
}

/// Authentication configuration for SNMP clients.
///
/// The [`Debug`] implementation redacts community strings so that credentials
/// are not leaked through logs or diagnostics.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Auth {
    /// Community string authentication (`SNMPv1` or v2c).
    Community {
        /// SNMP version (V1 or V2c)
        version: CommunityVersion,
        /// Community string
        community: String,
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

    /// `SNMPv2c` community authentication.
    ///
    /// Creates authentication configuration for `SNMPv2c`, which supports
    /// community string authentication without encryption but adds GETBULK
    /// and improved error handling over `SNMPv1`.
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

    /// Create an `SNMPv3` USM configuration.
    ///
    /// Returns the shared [`UsmConfig`] used by clients, agents, notification
    /// receivers, and trap sinks. `SNMPv3` supports three security levels:
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
    ///     .auth_priv(
    ///         AuthProtocol::Sha256,
    ///         "authpassword",
    ///         PrivProtocol::Aes128,
    ///         "privpassword",
    ///     )
    ///     .into();
    /// ```
    pub fn usm(username: impl Into<String>) -> UsmConfig {
        UsmConfig::new(bytes::Bytes::from(username.into()))
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
    use crate::v3::{AuthProtocol, PrivProtocol};

    #[test]
    fn test_default_auth() {
        let auth = Auth::default();
        match auth {
            Auth::Community { version, community } => {
                assert_eq!(version, CommunityVersion::V2c);
                assert_eq!(community, "public");
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
                assert_eq!(community, "private");
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
                assert_eq!(community, "secret");
            }
            Auth::Usm(_) => panic!("expected Community variant"),
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
                assert_eq!(usm.username().as_ref(), b"readonly");
                assert_eq!(usm.security_level(), SecurityLevel::NoAuthNoPriv);
                assert!(usm.configured_context_name().is_empty());
            }
            Auth::Community { .. } => panic!("expected Usm variant"),
        }
    }

    #[test]
    fn test_usm_auth_no_priv() {
        let auth: Auth = Auth::usm("admin")
            .auth(AuthProtocol::Sha256, "authpass123")
            .into();
        match auth {
            Auth::Usm(usm) => {
                assert_eq!(usm.username().as_ref(), b"admin");
                assert_eq!(usm.security_level(), SecurityLevel::AuthNoPriv);
            }
            Auth::Community { .. } => panic!("expected Usm variant"),
        }
    }

    #[test]
    fn test_usm_auth_priv() {
        let auth: Auth = Auth::usm("admin")
            .auth_priv(
                AuthProtocol::Sha256,
                "authpass",
                PrivProtocol::Aes128,
                "privpass",
            )
            .into();
        match auth {
            Auth::Usm(usm) => {
                assert_eq!(usm.username().as_ref(), b"admin");
                assert_eq!(usm.security_level(), SecurityLevel::AuthPriv);
            }
            Auth::Community { .. } => panic!("expected Usm variant"),
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
                assert_eq!(usm.username().as_ref(), b"admin");
                assert_eq!(usm.configured_context_name().as_ref(), b"vlan100");
            }
            Auth::Community { .. } => panic!("expected Usm variant"),
        }
    }

    #[test]
    fn test_usm_builder_chaining() {
        // Verify all methods can be chained
        let auth: Auth = Auth::usm("user")
            .auth_priv(AuthProtocol::Sha512, "auth", PrivProtocol::Aes256, "priv")
            .context_name("ctx")
            .into();

        match auth {
            Auth::Usm(usm) => {
                assert_eq!(usm.username().as_ref(), b"user");
                assert_eq!(usm.security_level(), SecurityLevel::AuthPriv);
                assert_eq!(usm.configured_context_name().as_ref(), b"ctx");
            }
            Auth::Community { .. } => panic!("expected Usm variant"),
        }
    }

    #[test]
    fn test_debug_redacts_secrets() {
        // Community string must not appear in Debug output.
        let community = Auth::v2c("supersecretcommunity");
        let rendered = format!("{community:?}");
        assert!(!rendered.contains("supersecretcommunity"), "{rendered}");
        assert!(rendered.contains("[REDACTED]"), "{rendered}");

        // USM auth/priv passwords must not appear in Debug output.
        let config = Auth::usm("admin")
            .auth_priv(
                AuthProtocol::Sha256,
                "authpassword123",
                PrivProtocol::Aes128,
                "privpassword456",
            )
            .context_name("vlan100");
        let config_rendered = format!("{config:?}");
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

        let usm: Auth = config.into();
        let usm_rendered = format!("{usm:?}");
        assert!(!usm_rendered.contains("authpassword123"), "{usm_rendered}");
        assert!(!usm_rendered.contains("privpassword456"), "{usm_rendered}");
        assert!(usm_rendered.contains("[REDACTED]"), "{usm_rendered}");
        assert!(usm_rendered.contains("admin"), "{usm_rendered}");
    }
}
