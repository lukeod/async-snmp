//! SNMPv3 security module.
//!
//! This module implements the User-based Security Model (USM) as defined
//! in RFC 3414 and RFC 7860, including:
//!
//! - USM security parameters encoding/decoding
//! - Key localization (password-to-key derivation)
//! - Authentication (HMAC-MD5-96, HMAC-SHA-96, HMAC-SHA-224/256/384/512)
//! - Privacy (DES-CBC, AES-128/192/256-CFB)
//! - Engine discovery and time synchronization

pub mod auth;
mod engine;
mod privacy;
mod usm;

pub use auth::{LocalizedKey, MasterKey, MasterKeys};
pub use engine::{
    DEFAULT_MSG_MAX_SIZE, EngineCache, EngineState, MAX_ENGINE_TIME, TIME_WINDOW,
    parse_discovery_response, parse_discovery_response_with_limits,
};
pub use engine::{
    is_decryption_error_report, is_not_in_time_window_report, is_unknown_engine_id_report,
    is_unknown_user_name_report, is_unsupported_sec_level_report, is_wrong_digest_report,
};
pub use privacy::{PrivKey, PrivacyError, PrivacyResult, SaltCounter};
pub use usm::UsmSecurityParams;

/// Key extension strategy for privacy key derivation.
///
/// This is an internal type used to select the appropriate key extension
/// algorithm when deriving privacy keys. The correct algorithm is auto-detected
/// based on the auth/priv protocol combination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum KeyExtension {
    /// No key extension. Use standard RFC 3414 key derivation.
    #[default]
    None,
    /// Blumenthal key extension (draft-blumenthal-aes-usm-04) for AES-192/256.
    Blumenthal,
    /// Reeder key extension (draft-reeder-snmpv3-usm-3desede-00) for 3DES.
    Reeder,
}

/// Error returned when parsing a protocol name fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseProtocolError {
    input: String,
    kind: ProtocolKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProtocolKind {
    Auth,
    Priv,
}

impl std::fmt::Display for ParseProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            ProtocolKind::Auth => write!(
                f,
                "unknown authentication protocol '{}'; expected one of: MD5, SHA, SHA-224, SHA-256, SHA-384, SHA-512",
                self.input
            ),
            ProtocolKind::Priv => write!(
                f,
                "unknown privacy protocol '{}'; expected one of: DES, AES, AES-128, AES-192, AES-256",
                self.input
            ),
        }
    }
}

impl std::error::Error for ParseProtocolError {}

/// Authentication protocol identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AuthProtocol {
    /// HMAC-MD5-96 (RFC 3414)
    Md5,
    /// HMAC-SHA-96 (RFC 3414)
    Sha1,
    /// HMAC-SHA-224 (RFC 7860)
    Sha224,
    /// HMAC-SHA-256 (RFC 7860)
    Sha256,
    /// HMAC-SHA-384 (RFC 7860)
    Sha384,
    /// HMAC-SHA-512 (RFC 7860)
    Sha512,
}

impl std::fmt::Display for AuthProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Md5 => write!(f, "MD5"),
            Self::Sha1 => write!(f, "SHA"),
            Self::Sha224 => write!(f, "SHA-224"),
            Self::Sha256 => write!(f, "SHA-256"),
            Self::Sha384 => write!(f, "SHA-384"),
            Self::Sha512 => write!(f, "SHA-512"),
        }
    }
}

impl std::str::FromStr for AuthProtocol {
    type Err = ParseProtocolError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_uppercase().as_str() {
            "MD5" => Ok(Self::Md5),
            "SHA" | "SHA1" | "SHA-1" => Ok(Self::Sha1),
            "SHA224" | "SHA-224" => Ok(Self::Sha224),
            "SHA256" | "SHA-256" => Ok(Self::Sha256),
            "SHA384" | "SHA-384" => Ok(Self::Sha384),
            "SHA512" | "SHA-512" => Ok(Self::Sha512),
            _ => Err(ParseProtocolError {
                input: s.to_string(),
                kind: ProtocolKind::Auth,
            }),
        }
    }
}

impl AuthProtocol {
    /// Get the digest output length in bytes.
    ///
    /// This is also the key length produced by the key localization algorithm,
    /// which is used for privacy key derivation.
    pub fn digest_len(self) -> usize {
        match self {
            Self::Md5 => 16,
            Self::Sha1 => 20,
            Self::Sha224 => 28,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// Get the truncated MAC length for authentication parameters.
    pub fn mac_len(self) -> usize {
        match self {
            Self::Md5 | Self::Sha1 => 12, // HMAC-96
            Self::Sha224 => 16,           // RFC 7860
            Self::Sha256 => 24,           // RFC 7860
            Self::Sha384 => 32,           // RFC 7860
            Self::Sha512 => 48,           // RFC 7860
        }
    }
}

/// Privacy protocol identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PrivProtocol {
    /// DES-CBC (RFC 3414).
    ///
    /// Insecure: 56-bit keys are brute-forceable. Also slower than AES, which
    /// benefits from hardware acceleration.
    Des,
    /// 3DES-EDE in "Outside" CBC mode (draft-reeder-snmpv3-usm-3desede-00).
    ///
    /// Uses three 56-bit keys for 168-bit effective security (112-bit against
    /// meet-in-the-middle). Slower than AES and lacks hardware acceleration.
    Des3,
    /// AES-128-CFB (RFC 3826)
    Aes128,
    /// AES-192-CFB (RFC 3826)
    Aes192,
    /// AES-256-CFB (RFC 3826)
    Aes256,
}

impl std::fmt::Display for PrivProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Des => write!(f, "DES"),
            Self::Des3 => write!(f, "3DES"),
            Self::Aes128 => write!(f, "AES"),
            Self::Aes192 => write!(f, "AES-192"),
            Self::Aes256 => write!(f, "AES-256"),
        }
    }
}

impl std::str::FromStr for PrivProtocol {
    type Err = ParseProtocolError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_uppercase().as_str() {
            "DES" => Ok(Self::Des),
            "3DES" | "3DES-EDE" | "DES3" | "TDES" => Ok(Self::Des3),
            "AES" | "AES128" | "AES-128" => Ok(Self::Aes128),
            "AES192" | "AES-192" => Ok(Self::Aes192),
            "AES256" | "AES-256" => Ok(Self::Aes256),
            _ => Err(ParseProtocolError {
                input: s.to_string(),
                kind: ProtocolKind::Priv,
            }),
        }
    }
}

impl PrivProtocol {
    /// Get the key length in bytes.
    pub fn key_len(self) -> usize {
        match self {
            Self::Des => 16,  // 8 key + 8 pre-IV
            Self::Des3 => 32, // 24 key + 8 pre-IV
            Self::Aes128 => 16,
            Self::Aes192 => 24,
            Self::Aes256 => 32,
        }
    }

    /// Get the IV/salt length in bytes.
    pub fn salt_len(self) -> usize {
        8 // All protocols use 8-byte salt
    }

    /// Returns the key extension algorithm to use for this privacy protocol
    /// given the authentication protocol.
    ///
    /// Key extension is needed when the auth protocol's digest is shorter than
    /// the privacy protocol's key requirement. The algorithm is determined by
    /// the privacy protocol:
    /// - AES-192/256: Blumenthal (draft-blumenthal-aes-usm-04)
    /// - 3DES: Reeder (draft-reeder-snmpv3-usm-3desede-00)
    pub(crate) fn key_extension_for(self, auth_protocol: AuthProtocol) -> KeyExtension {
        let auth_len = auth_protocol.digest_len();
        let priv_len = self.key_len();

        if auth_len >= priv_len {
            return KeyExtension::None;
        }

        match self {
            Self::Des3 => KeyExtension::Reeder,
            Self::Aes192 | Self::Aes256 => KeyExtension::Blumenthal,
            Self::Des | Self::Aes128 => KeyExtension::None, // Never need extension
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_protocol_display() {
        assert_eq!(format!("{}", AuthProtocol::Md5), "MD5");
        assert_eq!(format!("{}", AuthProtocol::Sha1), "SHA");
        assert_eq!(format!("{}", AuthProtocol::Sha224), "SHA-224");
        assert_eq!(format!("{}", AuthProtocol::Sha256), "SHA-256");
        assert_eq!(format!("{}", AuthProtocol::Sha384), "SHA-384");
        assert_eq!(format!("{}", AuthProtocol::Sha512), "SHA-512");
    }

    #[test]
    fn test_auth_protocol_from_str() {
        assert_eq!("MD5".parse::<AuthProtocol>().unwrap(), AuthProtocol::Md5);
        assert_eq!("md5".parse::<AuthProtocol>().unwrap(), AuthProtocol::Md5);
        assert_eq!("SHA".parse::<AuthProtocol>().unwrap(), AuthProtocol::Sha1);
        assert_eq!("sha1".parse::<AuthProtocol>().unwrap(), AuthProtocol::Sha1);
        assert_eq!("SHA-1".parse::<AuthProtocol>().unwrap(), AuthProtocol::Sha1);
        assert_eq!(
            "sha-224".parse::<AuthProtocol>().unwrap(),
            AuthProtocol::Sha224
        );
        assert_eq!(
            "SHA256".parse::<AuthProtocol>().unwrap(),
            AuthProtocol::Sha256
        );
        assert_eq!(
            "SHA-256".parse::<AuthProtocol>().unwrap(),
            AuthProtocol::Sha256
        );
        assert_eq!(
            "sha384".parse::<AuthProtocol>().unwrap(),
            AuthProtocol::Sha384
        );
        assert_eq!(
            "SHA-512".parse::<AuthProtocol>().unwrap(),
            AuthProtocol::Sha512
        );

        assert!("invalid".parse::<AuthProtocol>().is_err());
    }

    #[test]
    fn test_priv_protocol_display() {
        assert_eq!(format!("{}", PrivProtocol::Des), "DES");
        assert_eq!(format!("{}", PrivProtocol::Des3), "3DES");
        assert_eq!(format!("{}", PrivProtocol::Aes128), "AES");
        assert_eq!(format!("{}", PrivProtocol::Aes192), "AES-192");
        assert_eq!(format!("{}", PrivProtocol::Aes256), "AES-256");
    }

    #[test]
    fn test_priv_protocol_from_str() {
        assert_eq!("DES".parse::<PrivProtocol>().unwrap(), PrivProtocol::Des);
        assert_eq!("des".parse::<PrivProtocol>().unwrap(), PrivProtocol::Des);
        assert_eq!("3DES".parse::<PrivProtocol>().unwrap(), PrivProtocol::Des3);
        assert_eq!("3des".parse::<PrivProtocol>().unwrap(), PrivProtocol::Des3);
        assert_eq!(
            "3DES-EDE".parse::<PrivProtocol>().unwrap(),
            PrivProtocol::Des3
        );
        assert_eq!("DES3".parse::<PrivProtocol>().unwrap(), PrivProtocol::Des3);
        assert_eq!("TDES".parse::<PrivProtocol>().unwrap(), PrivProtocol::Des3);
        assert_eq!("AES".parse::<PrivProtocol>().unwrap(), PrivProtocol::Aes128);
        assert_eq!("aes".parse::<PrivProtocol>().unwrap(), PrivProtocol::Aes128);
        assert_eq!(
            "AES128".parse::<PrivProtocol>().unwrap(),
            PrivProtocol::Aes128
        );
        assert_eq!(
            "AES-128".parse::<PrivProtocol>().unwrap(),
            PrivProtocol::Aes128
        );
        assert_eq!(
            "aes192".parse::<PrivProtocol>().unwrap(),
            PrivProtocol::Aes192
        );
        assert_eq!(
            "AES-192".parse::<PrivProtocol>().unwrap(),
            PrivProtocol::Aes192
        );
        assert_eq!(
            "aes256".parse::<PrivProtocol>().unwrap(),
            PrivProtocol::Aes256
        );
        assert_eq!(
            "AES-256".parse::<PrivProtocol>().unwrap(),
            PrivProtocol::Aes256
        );

        assert!("invalid".parse::<PrivProtocol>().is_err());
    }

    #[test]
    fn test_parse_protocol_error_display() {
        let err = "bogus".parse::<AuthProtocol>().unwrap_err();
        assert!(err.to_string().contains("bogus"));
        assert!(err.to_string().contains("authentication protocol"));

        let err = "bogus".parse::<PrivProtocol>().unwrap_err();
        assert!(err.to_string().contains("bogus"));
        assert!(err.to_string().contains("privacy protocol"));
    }
}
