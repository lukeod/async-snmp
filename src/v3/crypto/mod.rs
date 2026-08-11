//! Cryptographic backends for `SNMPv3` security operations.
//!
//! Crypto backends are additive Cargo features. When both are compiled, each
//! USM configuration explicitly chooses the backend used for its operations.
//!
//! - `crypto-rustcrypto` (**default**) supports all authentication and privacy
//!   protocols.
//! - `crypto-fips` uses aws-lc-rs and rejects MD5, DES, and 3DES.

use super::{AuthProtocol, PrivProtocol};

/// Error type for cryptographic provider operations.
///
/// This covers failures that originate from the crypto backend itself:
/// unsupported algorithms, invalid key material, and cipher-level errors.
/// Protocol-level framing errors (e.g., wrong privParameters length) live
/// in [`PrivacyError`](super::privacy::PrivacyError).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// The crypto backend does not support the requested algorithm.
    ///
    /// For example, the FIPS provider does not support MD5 or DES.
    UnsupportedAlgorithm(&'static str),
    /// The key length is invalid for the requested operation.
    InvalidKeyLength,
    /// The cipher operation failed internally.
    CipherError,
    /// The requested HMAC truncation exceeds the full digest length.
    InvalidHmacTruncationLength {
        /// Requested output length in octets.
        requested: usize,
        /// Maximum output length for the selected authentication protocol.
        digest_length: usize,
    },
    /// The supplied password is shorter than the RFC 3414 minimum (8 octets).
    ///
    /// RFC 3414 Section 11.2 requires passwords of at least 8 octets, and
    /// net-snmp rejects shorter passwords with `USM_PASSWORDTOOSHORT`.
    PasswordTooShort,
    /// The USM username is outside the RFC 3414 range of 1 through 32 octets.
    InvalidUsmUsernameLength {
        /// Supplied username length in octets.
        length: usize,
    },
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedAlgorithm(name) => {
                write!(f, "unsupported algorithm: {name}")
            }
            Self::InvalidKeyLength => write!(f, "invalid key length"),
            Self::CipherError => write!(f, "cipher operation failed"),
            Self::InvalidHmacTruncationLength {
                requested,
                digest_length,
            } => write!(
                f,
                "invalid HMAC truncation length {requested}; maximum is {digest_length} octets"
            ),
            Self::PasswordTooShort => write!(
                f,
                "password is shorter than the RFC 3414 minimum of 8 octets"
            ),
            Self::InvalidUsmUsernameLength { length } => write!(
                f,
                "USM username must contain 1 through 32 octets (got {length})"
            ),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Result type for cryptographic provider operations.
pub type CryptoResult<T> = Result<T, CryptoError>;

#[cfg(feature = "crypto-rustcrypto")]
mod rustcrypto;
#[cfg(feature = "crypto-rustcrypto")]
pub(crate) use rustcrypto::RustCryptoProvider;

#[cfg(feature = "crypto-fips")]
mod fips;
#[cfg(feature = "crypto-fips")]
pub(crate) use fips::AwsLcFipsProvider;

/// Internal interface implemented by each compile-time cryptographic backend.
///
/// This keeps auth and privacy operations independent of backend APIs without
/// promising runtime provider injection as part of the public API.
pub(crate) trait CryptoProvider: Send + Sync + 'static {
    /// Validate that this provider supports an authentication protocol.
    fn validate_auth_protocol(&self, protocol: AuthProtocol) -> CryptoResult<()>;

    /// Validate that this provider supports a privacy protocol.
    fn validate_priv_protocol(&self, protocol: PrivProtocol) -> CryptoResult<()>;

    /// Derive a master key from a password using the RFC 3414 Section A.2.1 algorithm.
    ///
    /// Expands the password to 1MB by repetition and hashes it with the protocol's
    /// hash function. Returns the raw digest bytes.
    ///
    /// Passwords shorter than eight octets return [`CryptoError::PasswordTooShort`].
    ///
    /// Returns [`CryptoError::UnsupportedAlgorithm`] if the backend does not
    /// support the requested authentication protocol.
    fn password_to_key(&self, protocol: AuthProtocol, password: &[u8]) -> CryptoResult<Vec<u8>>;

    /// Localize a master key to a specific engine ID (RFC 3414 Section A.2.2).
    ///
    /// Computes: `H(master_key || engine_id || master_key)`
    ///
    /// Returns [`CryptoError::UnsupportedAlgorithm`] if the backend does not
    /// support the requested authentication protocol.
    fn localize_key(
        &self,
        protocol: AuthProtocol,
        master_key: &[u8],
        engine_id: &[u8],
    ) -> CryptoResult<Vec<u8>>;

    /// Compute HMAC over one or more data slices, truncated to `truncate_len` bytes.
    ///
    /// The multi-slice interface avoids allocations when computing HMACs over
    /// non-contiguous data (e.g., message verification with zeroed auth params).
    ///
    /// Returns [`CryptoError::UnsupportedAlgorithm`] if the backend does not
    /// support the requested authentication protocol, or
    /// [`CryptoError::InvalidHmacTruncationLength`] if `truncate_len` exceeds
    /// the selected protocol's full digest length. Lengths from zero through
    /// the full digest length are valid.
    fn compute_hmac(
        &self,
        protocol: AuthProtocol,
        key: &[u8],
        slices: &[&[u8]],
        truncate_len: usize,
    ) -> CryptoResult<Vec<u8>>;

    /// Encrypt data in place using the specified privacy protocol.
    ///
    /// The caller is responsible for key extraction and IV construction.
    /// For block ciphers (DES, 3DES), the implementation pads unaligned
    /// plaintext to the next block boundary per RFC 3414 §8.1.1.2,
    /// extending the Vec as needed.
    fn encrypt(
        &self,
        protocol: PrivProtocol,
        key: &[u8],
        iv: &[u8],
        data: &mut Vec<u8>,
    ) -> CryptoResult<()>;

    /// Compute a bare hash digest using the protocol's hash function.
    ///
    /// Returns [`CryptoError::UnsupportedAlgorithm`] if the backend does not
    /// support the requested authentication protocol.
    fn hash(&self, protocol: AuthProtocol, data: &[u8]) -> CryptoResult<Vec<u8>>;

    /// Decrypt data in place using the specified privacy protocol.
    ///
    /// The caller is responsible for key extraction and IV reconstruction.
    fn decrypt(
        &self,
        protocol: PrivProtocol,
        key: &[u8],
        iv: &[u8],
        data: &mut [u8],
    ) -> CryptoResult<()>;
}

/// Cryptographic backend selected for a USM configuration.
///
/// Cargo features only determine which variants are available. Enabling the
/// FIPS backend does not by itself make an operation FIPS-compliant; callers
/// must select the `AwsLcFips` variant of [`CryptoBackend`] and can inspect that
/// choice through [`UsmConfig::crypto_backend`](super::UsmConfig::crypto_backend).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum CryptoBackend {
    /// The RustCrypto implementation (the default when available).
    #[cfg(feature = "crypto-rustcrypto")]
    RustCrypto,
    /// The AWS-LC FIPS implementation.
    #[cfg(feature = "crypto-fips")]
    AwsLcFips,
    #[cfg(not(any(feature = "crypto-rustcrypto", feature = "crypto-fips")))]
    #[doc(hidden)]
    Unavailable,
}

impl Default for CryptoBackend {
    fn default() -> Self {
        #[cfg(feature = "crypto-rustcrypto")]
        return Self::RustCrypto;
        #[cfg(all(not(feature = "crypto-rustcrypto"), feature = "crypto-fips"))]
        return Self::AwsLcFips;
        #[cfg(not(any(feature = "crypto-rustcrypto", feature = "crypto-fips")))]
        return Self::Unavailable;
    }
}

impl CryptoBackend {
    #[cfg(not(any(feature = "crypto-rustcrypto", feature = "crypto-fips")))]
    fn unavailable() -> CryptoError {
        CryptoError::UnsupportedAlgorithm("no crypto backend is enabled")
    }

    pub(crate) fn validate_auth_protocol(self, _protocol: AuthProtocol) -> CryptoResult<()> {
        match self {
            #[cfg(feature = "crypto-rustcrypto")]
            Self::RustCrypto => RustCryptoProvider.validate_auth_protocol(_protocol),
            #[cfg(feature = "crypto-fips")]
            Self::AwsLcFips => AwsLcFipsProvider.validate_auth_protocol(_protocol),
            #[cfg(not(any(feature = "crypto-rustcrypto", feature = "crypto-fips")))]
            Self::Unavailable => Err(Self::unavailable()),
        }
    }

    pub(crate) fn validate_priv_protocol(self, _protocol: PrivProtocol) -> CryptoResult<()> {
        match self {
            #[cfg(feature = "crypto-rustcrypto")]
            Self::RustCrypto => RustCryptoProvider.validate_priv_protocol(_protocol),
            #[cfg(feature = "crypto-fips")]
            Self::AwsLcFips => AwsLcFipsProvider.validate_priv_protocol(_protocol),
            #[cfg(not(any(feature = "crypto-rustcrypto", feature = "crypto-fips")))]
            Self::Unavailable => Err(Self::unavailable()),
        }
    }

    pub(crate) fn password_to_key(
        self,
        _protocol: AuthProtocol,
        _password: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        match self {
            #[cfg(feature = "crypto-rustcrypto")]
            Self::RustCrypto => RustCryptoProvider.password_to_key(_protocol, _password),
            #[cfg(feature = "crypto-fips")]
            Self::AwsLcFips => AwsLcFipsProvider.password_to_key(_protocol, _password),
            #[cfg(not(any(feature = "crypto-rustcrypto", feature = "crypto-fips")))]
            Self::Unavailable => Err(Self::unavailable()),
        }
    }

    pub(crate) fn localize_key(
        self,
        _protocol: AuthProtocol,
        _master_key: &[u8],
        _engine_id: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        match self {
            #[cfg(feature = "crypto-rustcrypto")]
            Self::RustCrypto => RustCryptoProvider.localize_key(_protocol, _master_key, _engine_id),
            #[cfg(feature = "crypto-fips")]
            Self::AwsLcFips => AwsLcFipsProvider.localize_key(_protocol, _master_key, _engine_id),
            #[cfg(not(any(feature = "crypto-rustcrypto", feature = "crypto-fips")))]
            Self::Unavailable => Err(Self::unavailable()),
        }
    }

    pub(crate) fn compute_hmac(
        self,
        _protocol: AuthProtocol,
        _key: &[u8],
        _slices: &[&[u8]],
        _truncate_len: usize,
    ) -> CryptoResult<Vec<u8>> {
        match self {
            #[cfg(feature = "crypto-rustcrypto")]
            Self::RustCrypto => {
                RustCryptoProvider.compute_hmac(_protocol, _key, _slices, _truncate_len)
            }
            #[cfg(feature = "crypto-fips")]
            Self::AwsLcFips => {
                AwsLcFipsProvider.compute_hmac(_protocol, _key, _slices, _truncate_len)
            }
            #[cfg(not(any(feature = "crypto-rustcrypto", feature = "crypto-fips")))]
            Self::Unavailable => Err(Self::unavailable()),
        }
    }

    pub(crate) fn hash(self, _protocol: AuthProtocol, _data: &[u8]) -> CryptoResult<Vec<u8>> {
        match self {
            #[cfg(feature = "crypto-rustcrypto")]
            Self::RustCrypto => RustCryptoProvider.hash(_protocol, _data),
            #[cfg(feature = "crypto-fips")]
            Self::AwsLcFips => AwsLcFipsProvider.hash(_protocol, _data),
            #[cfg(not(any(feature = "crypto-rustcrypto", feature = "crypto-fips")))]
            Self::Unavailable => Err(Self::unavailable()),
        }
    }

    #[cfg_attr(
        not(any(feature = "crypto-rustcrypto", feature = "crypto-fips")),
        allow(clippy::ptr_arg)
    )]
    pub(crate) fn encrypt(
        self,
        _protocol: PrivProtocol,
        _key: &[u8],
        _iv: &[u8],
        _data: &mut Vec<u8>,
    ) -> CryptoResult<()> {
        match self {
            #[cfg(feature = "crypto-rustcrypto")]
            Self::RustCrypto => RustCryptoProvider.encrypt(_protocol, _key, _iv, _data),
            #[cfg(feature = "crypto-fips")]
            Self::AwsLcFips => AwsLcFipsProvider.encrypt(_protocol, _key, _iv, _data),
            #[cfg(not(any(feature = "crypto-rustcrypto", feature = "crypto-fips")))]
            Self::Unavailable => Err(Self::unavailable()),
        }
    }

    pub(crate) fn decrypt(
        self,
        _protocol: PrivProtocol,
        _key: &[u8],
        _iv: &[u8],
        _data: &mut [u8],
    ) -> CryptoResult<()> {
        match self {
            #[cfg(feature = "crypto-rustcrypto")]
            Self::RustCrypto => RustCryptoProvider.decrypt(_protocol, _key, _iv, _data),
            #[cfg(feature = "crypto-fips")]
            Self::AwsLcFips => AwsLcFipsProvider.decrypt(_protocol, _key, _iv, _data),
            #[cfg(not(any(feature = "crypto-rustcrypto", feature = "crypto-fips")))]
            Self::Unavailable => Err(Self::unavailable()),
        }
    }
}
