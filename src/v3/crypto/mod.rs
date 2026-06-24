//! Pluggable cryptographic provider for `SNMPv3` security operations.
//!
//! This module defines the [`CryptoProvider`] trait that captures the primitive
//! cryptographic operations needed by the USM layer, and provides two built-in
//! implementations:
//!
//! - [`RustCryptoProvider`] (feature `crypto-rustcrypto`, **default**) - backed by
//!   the `RustCrypto` crate ecosystem. Supports all auth and privacy protocols.
//! - [`AwsLcFipsProvider`] (feature `crypto-fips`) - backed by aws-lc-rs for
//!   FIPS 140-3 compliance. Rejects MD5, DES, and 3DES as non-FIPS algorithms.
//!
//! The active provider is selected at compile time via mutually exclusive feature
//! flags. Only one provider can be active per build. See the crate-level
//! documentation for usage.

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
    /// The OS random source is unavailable.
    RandomSource,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedAlgorithm(name) => {
                write!(f, "unsupported algorithm: {name}")
            }
            Self::InvalidKeyLength => write!(f, "invalid key length"),
            Self::CipherError => write!(f, "cipher operation failed"),
            Self::RandomSource => write!(f, "OS random source unavailable"),
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
pub use rustcrypto::RustCryptoProvider;

#[cfg(feature = "crypto-fips")]
mod fips;
#[cfg(feature = "crypto-fips")]
pub use fips::AwsLcFipsProvider;

/// Trait defining the cryptographic primitives needed by the `SNMPv3` USM layer.
///
/// This trait captures the six core operations that vary between crypto backends:
/// hashing, password-to-key derivation, key localization, HMAC computation, and
/// symmetric encryption/decryption.
///
/// # Implementors
///
/// Methods take `&self` to allow stateful providers (HSM handles, FFI contexts).
/// The default [`RustCryptoProvider`] is a stateless unit struct.
///
/// # Thread Safety
///
/// Implementations must be `Send + Sync + 'static` to support use across
/// async tasks and threads.
///
/// # Security Requirements
///
/// Implementations must uphold the following properties for correct and secure
/// `SNMPv3` operation:
///
/// - **Constant-time HMAC comparison.** The caller (`verify_message`) performs
///   the constant-time comparison, but `compute_hmac` must not short-circuit
///   or leak timing information about intermediate state.
/// - **IV/salt uniqueness.** Encryption callers supply the IV, but if your
///   provider wraps a stateful cipher context that generates IVs internally,
///   it must guarantee uniqueness across calls (RFC 3826 Section 3.1.4.1).
/// - **Key material hygiene.** Intermediate key material (e.g., expanded
///   password hashes) should be zeroized after use. Implementations backed
///   by HSMs or FIPS modules should keep keys in hardware where possible.
/// - **Algorithm support errors.** Return [`CryptoError::UnsupportedAlgorithm`]
///   rather than panicking when asked to perform an operation the backend
///   does not support.
pub trait CryptoProvider: Send + Sync + 'static {
    /// Derive a master key from a password using the RFC 3414 Section A.2.1 algorithm.
    ///
    /// Expands the password to 1MB by repetition and hashes it with the protocol's
    /// hash function. Returns the raw digest bytes.
    ///
    /// Empty passwords should return an all-zero key of the protocol's digest length.
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
    /// support the requested authentication protocol.
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
/// The provider is selected at compile time. The default uses [`RustCryptoProvider`].
/// Alternative backends can be feature-gated here.
#[cfg(feature = "crypto-rustcrypto")]
pub(crate) fn provider() -> &'static RustCryptoProvider {
    &RustCryptoProvider
}

#[cfg(feature = "crypto-fips")]
pub(crate) fn provider() -> &'static AwsLcFipsProvider {
    &AwsLcFipsProvider
}
