//! Pluggable cryptographic provider for SNMPv3 security operations.
//!
//! This module defines the [`CryptoProvider`] trait that captures the primitive
//! cryptographic operations needed by the USM layer, and provides the default
//! [`RustCryptoProvider`] implementation backed by the RustCrypto crate ecosystem.
//!
//! The active provider is selected at compile time via feature flags. The default
//! provider uses RustCrypto crates (sha2, aes, hmac, etc.). Alternative backends
//! (e.g., aws-lc-rs for FIPS 140-3) can be added as feature-gated implementations.

use super::privacy::PrivacyResult;
use super::{AuthProtocol, PrivProtocol};

#[cfg(all(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
compile_error!("Features \"crypto-rustcrypto\" and \"crypto-fips\" are mutually exclusive. Choose one crypto backend.");

#[cfg(not(any(feature = "crypto-rustcrypto", feature = "crypto-fips")))]
compile_error!("A crypto backend is required. Enable either \"crypto-rustcrypto\" (default) or \"crypto-fips\".");

#[cfg(feature = "crypto-rustcrypto")]
mod rustcrypto;
#[cfg(feature = "crypto-rustcrypto")]
pub use rustcrypto::RustCryptoProvider;

#[cfg(feature = "crypto-fips")]
mod fips;
#[cfg(feature = "crypto-fips")]
pub use fips::AwsLcFipsProvider;

/// Trait defining the cryptographic primitives needed by the SNMPv3 USM layer.
///
/// This trait captures the five core operations that vary between crypto backends:
/// password-to-key derivation, key localization, HMAC computation, and
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
pub trait CryptoProvider: Send + Sync + 'static {
    /// Derive a master key from a password using the RFC 3414 Section A.2.1 algorithm.
    ///
    /// Expands the password to 1MB by repetition and hashes it with the protocol's
    /// hash function. Returns the raw digest bytes.
    ///
    /// Empty passwords should return an all-zero key of the protocol's digest length.
    fn password_to_key(&self, protocol: AuthProtocol, password: &[u8]) -> Vec<u8>;

    /// Localize a master key to a specific engine ID (RFC 3414 Section A.2.2).
    ///
    /// Computes: `H(master_key || engine_id || master_key)`
    fn localize_key(&self, protocol: AuthProtocol, master_key: &[u8], engine_id: &[u8]) -> Vec<u8>;

    /// Compute HMAC over one or more data slices, truncated to `truncate_len` bytes.
    ///
    /// The multi-slice interface avoids allocations when computing HMACs over
    /// non-contiguous data (e.g., message verification with zeroed auth params).
    fn compute_hmac(
        &self,
        protocol: AuthProtocol,
        key: &[u8],
        slices: &[&[u8]],
        truncate_len: usize,
    ) -> Vec<u8>;

    /// Encrypt data in place using the specified privacy protocol.
    ///
    /// The caller is responsible for key extraction, IV construction, and
    /// padding (for block ciphers). This method performs only the raw cipher
    /// operation.
    fn encrypt(
        &self,
        protocol: PrivProtocol,
        key: &[u8],
        iv: &[u8],
        data: &mut [u8],
    ) -> PrivacyResult<()>;

    /// Compute a bare hash digest using the protocol's hash function.
    fn hash(&self, protocol: AuthProtocol, data: &[u8]) -> Vec<u8>;

    /// Decrypt data in place using the specified privacy protocol.
    ///
    /// The caller is responsible for key extraction and IV reconstruction.
    /// This method performs only the raw cipher operation.
    fn decrypt(
        &self,
        protocol: PrivProtocol,
        key: &[u8],
        iv: &[u8],
        data: &mut [u8],
    ) -> PrivacyResult<()>;
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
