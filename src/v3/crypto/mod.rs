//! Cryptographic backends for `SNMPv3` security operations.
//!
//! The active backend is selected at compile time through mutually exclusive
//! feature flags:
//!
//! - `crypto-rustcrypto` (**default**) uses the `RustCrypto` crate ecosystem and
//!   supports all authentication and privacy protocols.
//! - `crypto-fips` uses aws-lc-rs for FIPS 140-3 compliance and rejects MD5,
//!   DES, and 3DES as non-FIPS algorithms.
//!
//! Backend dispatch is internal; applications select one backend for the whole
//! crate build rather than supplying a provider at runtime.

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
    /// The OS random source is unavailable.
    RandomSource,
    /// The supplied password is shorter than the RFC 3414 minimum (8 octets).
    ///
    /// RFC 3414 Section 11.2 requires passwords of at least 8 octets, and
    /// net-snmp rejects shorter passwords with `USM_PASSWORDTOOSHORT`.
    PasswordTooShort,
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
            Self::RandomSource => write!(f, "OS random source unavailable"),
            Self::PasswordTooShort => write!(
                f,
                "password is shorter than the RFC 3414 minimum of 8 octets"
            ),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Result type for cryptographic provider operations.
pub type CryptoResult<T> = Result<T, CryptoError>;

#[cfg(all(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
compile_error!(
    "Features \"crypto-rustcrypto\" and \"crypto-fips\" are mutually exclusive. If you used --all-features, specify features explicitly instead."
);

#[cfg(not(any(feature = "crypto-rustcrypto", feature = "crypto-fips")))]
compile_error!(
    "A crypto backend is required. Enable either \"crypto-rustcrypto\" (default) or \"crypto-fips\"."
);

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

/// Returns the active crypto provider.
///
/// The provider is selected at compile time. The default uses RustCrypto.
#[cfg(feature = "crypto-rustcrypto")]
pub(crate) fn provider() -> &'static RustCryptoProvider {
    &RustCryptoProvider
}

#[cfg(feature = "crypto-fips")]
pub(crate) fn provider() -> &'static AwsLcFipsProvider {
    &AwsLcFipsProvider
}
