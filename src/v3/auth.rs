//! Authentication key derivation and HMAC operations (RFC 3414).
//!
//! This module implements:
//! - Password-to-key derivation (1MB expansion + hash)
//! - Key localization (binding key to engine ID)
//! - HMAC authentication for message integrity
//!
//! # Two-Level Key Derivation
//!
//! `SNMPv3` key derivation is a two-step process:
//!
//! 1. **Password to Master Key** (~850μs for SHA-256): Expand password to 1MB
//!    by repetition and hash it. This produces a protocol-specific master key.
//!
//! 2. **Localization** (~1μs): Bind the master key to a specific engine ID by
//!    computing `H(master_key || engine_id || master_key)`.
//!
//! When polling many engines with the same credentials, cache the [`MasterKey`]
//! and call [`MasterKey::localize`] for each engine ID. This avoids repeating
//! the expensive 1MB expansion for every engine.
//!
//! ```rust
//! use async_snmp::{AuthProtocol, MasterKey};
//!
//! // Expensive: ~850μs - do once per password
//! let master = MasterKey::from_password(AuthProtocol::Sha256, b"authpassword").unwrap();
//!
//! // Cheap: ~1μs each - do per engine
//! let key1 = master.localize(b"\x80\x00\x1f\x88\x80...").unwrap();
//! let key2 = master.localize(b"\x80\x00\x1f\x88\x81...").unwrap();
//! ```

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::AuthProtocol;
use super::crypto::{CryptoProvider, CryptoResult};

/// Minimum password length required for password-based key derivation.
///
/// RFC 3414 Section 11.2 requires passwords of at least 8 octets, and net-snmp
/// rejects shorter passwords with `USM_PASSWORDTOOSHORT`. Password-based key
/// derivation entry points reject passwords shorter than this with
/// [`CryptoError::PasswordTooShort`](super::CryptoError::PasswordTooShort).
pub const MIN_PASSWORD_LENGTH: usize = 8;

/// Master authentication key (Ku) before engine localization.
///
/// This is the intermediate result of the RFC 3414 password-to-key algorithm,
/// computed by expanding the password to 1MB and hashing it. This step is
/// computationally expensive (~850μs for SHA-256) but can be cached and reused
/// across multiple engines that share the same credentials.
///
/// # Performance
///
/// | Operation | Time |
/// |-----------|------|
/// | `MasterKey::from_password` (SHA-256) | ~850 μs |
/// | `MasterKey::localize` | ~1 μs |
///
/// For applications polling many engines with shared credentials, caching the
/// `MasterKey` provides significant performance benefits.
///
/// # Security
///
/// Key material is automatically zeroed from memory when dropped, using the
/// `zeroize` crate. This provides defense-in-depth against memory scraping.
///
/// # Example
///
/// ```rust
/// use async_snmp::{AuthProtocol, MasterKey};
///
/// // Derive master key once (expensive)
/// let master = MasterKey::from_password(AuthProtocol::Sha256, b"authpassword").unwrap();
///
/// // Localize to different engines (cheap)
/// let engine1_id = b"\x80\x00\x1f\x88\x80\xe9\xb1\x04\x61\x73\x61\x00\x00\x00";
/// let engine2_id = b"\x80\x00\x1f\x88\x80\xe9\xb1\x04\x61\x73\x61\x00\x00\x01";
///
/// let key1 = master.localize(engine1_id).unwrap();
/// let key2 = master.localize(engine2_id).unwrap();
/// ```
#[derive(Clone, Zeroize, ZeroizeOnDrop, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MasterKey {
    key: Vec<u8>,
    #[zeroize(skip)]
    protocol: AuthProtocol,
}

impl MasterKey {
    /// Derive a master key from a password.
    ///
    /// This implements RFC 3414 Section A.2.1: expand the password to 1MB by
    /// repetition, then hash the result. This is computationally expensive
    /// (~850μs for SHA-256) but only needs to be done once per password.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::UnsupportedAlgorithm`](super::CryptoError::UnsupportedAlgorithm) if the active crypto
    /// backend does not support the requested authentication protocol.
    ///
    /// # Empty and Short Passwords
    ///
    /// Passwords shorter than [`MIN_PASSWORD_LENGTH`] (8 octets) are rejected
    /// with [`CryptoError::PasswordTooShort`](super::CryptoError::PasswordTooShort),
    /// matching RFC 3414 Section 11.2 and net-snmp's `USM_PASSWORDTOOSHORT`.
    /// This does not affect pre-derived key constructors such as
    /// [`from_bytes`](Self::from_bytes), which take key material rather than a
    /// plaintext password.
    pub fn from_password(protocol: AuthProtocol, password: &[u8]) -> CryptoResult<Self> {
        if password.len() < MIN_PASSWORD_LENGTH {
            return Err(super::CryptoError::PasswordTooShort);
        }
        let key = password_to_key(protocol, password)?;
        Ok(Self { key, protocol })
    }

    /// Derive a master key from a string password.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::UnsupportedAlgorithm`](super::CryptoError::UnsupportedAlgorithm) if the active crypto
    /// backend does not support the requested authentication protocol.
    pub fn from_str_password(protocol: AuthProtocol, password: &str) -> CryptoResult<Self> {
        Self::from_password(protocol, password.as_bytes())
    }

    /// Create a master key from raw bytes.
    ///
    /// Use this if you already have a master key (e.g., from configuration).
    /// The bytes should be the raw digest output from the 1MB password expansion.
    pub fn from_bytes(protocol: AuthProtocol, key: impl Into<Vec<u8>>) -> Self {
        Self {
            key: key.into(),
            protocol,
        }
    }

    /// Localize this master key to a specific engine ID.
    ///
    /// This implements RFC 3414 Section A.2.2:
    /// `localized_key = H(master_key || engine_id || master_key)`
    ///
    /// This operation is cheap (~1μs) compared to master key derivation.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::UnsupportedAlgorithm`](super::CryptoError::UnsupportedAlgorithm) if the active crypto
    /// backend does not support the key's authentication protocol.
    pub fn localize(&self, engine_id: &[u8]) -> CryptoResult<LocalizedKey> {
        let localized = localize_key(self.protocol, &self.key, engine_id)?;
        Ok(LocalizedKey {
            key: localized,
            protocol: self.protocol,
        })
    }

    /// Get the protocol this key is for.
    #[must_use]
    pub fn protocol(&self) -> AuthProtocol {
        self.protocol
    }

    /// Get the raw key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasterKey")
            .field("protocol", &self.protocol)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl AsRef<[u8]> for MasterKey {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Localized authentication key.
///
/// A key that has been derived from a password and bound to a specific engine ID.
/// This key can be used for HMAC operations on messages to/from that engine.
///
/// # Security
///
/// Key material is automatically zeroed from memory when the key is dropped,
/// using the `zeroize` crate. This provides defense-in-depth against memory
/// scraping attacks.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct LocalizedKey {
    key: Vec<u8>,
    #[zeroize(skip)]
    protocol: AuthProtocol,
}

impl LocalizedKey {
    /// Derive a localized key from a password and engine ID.
    ///
    /// This implements the key localization algorithm from RFC 3414 Section A.2:
    /// 1. Expand password to 1MB by repetition
    /// 2. Hash the expansion to get the master key
    /// 3. Hash (`master_key` || `engine_id` || `master_key`) to get the localized key
    ///
    /// # Performance Note
    ///
    /// This method performs the full key derivation (~850μs for SHA-256). When
    /// polling many engines with shared credentials, use [`MasterKey`] to cache
    /// the intermediate result and call [`MasterKey::localize`] for each engine.
    ///
    /// # Empty and Short Passwords
    ///
    /// Passwords shorter than [`MIN_PASSWORD_LENGTH`] (8 octets) are rejected
    /// with [`CryptoError::PasswordTooShort`](super::CryptoError::PasswordTooShort),
    /// matching RFC 3414 Section 11.2 and net-snmp's `USM_PASSWORDTOOSHORT`.
    pub fn from_password(
        protocol: AuthProtocol,
        password: &[u8],
        engine_id: &[u8],
    ) -> CryptoResult<Self> {
        MasterKey::from_password(protocol, password)?.localize(engine_id)
    }

    /// Derive a localized key from a string password and engine ID.
    ///
    /// This is a convenience method that converts the string to bytes and calls
    /// [`from_password`](Self::from_password).
    pub fn from_str_password(
        protocol: AuthProtocol,
        password: &str,
        engine_id: &[u8],
    ) -> CryptoResult<Self> {
        Self::from_password(protocol, password.as_bytes(), engine_id)
    }

    /// Create a localized key from a master key and engine ID.
    ///
    /// This is the efficient path when you have a cached [`MasterKey`].
    /// Equivalent to calling [`MasterKey::localize`].
    pub fn from_master_key(master: &MasterKey, engine_id: &[u8]) -> CryptoResult<Self> {
        master.localize(engine_id)
    }

    /// Create a localized key from raw bytes.
    ///
    /// Use this if you already have a localized key (e.g., from configuration).
    pub fn from_bytes(protocol: AuthProtocol, key: impl Into<Vec<u8>>) -> Self {
        Self {
            key: key.into(),
            protocol,
        }
    }

    /// Get the protocol this key is for.
    #[must_use]
    pub fn protocol(&self) -> AuthProtocol {
        self.protocol
    }

    /// Get the raw key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }

    /// Get the MAC length for this key's protocol.
    #[must_use]
    pub fn mac_len(&self) -> usize {
        self.protocol.mac_len()
    }

    /// Compute HMAC over a message and return the truncated MAC.
    ///
    /// The returned MAC is truncated to the appropriate length for the protocol
    /// (12 bytes for MD5/SHA-1, variable for SHA-2).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::UnsupportedAlgorithm`](super::CryptoError::UnsupportedAlgorithm) if the active crypto
    /// backend does not support the key's authentication protocol.
    pub fn compute_hmac(&self, data: &[u8]) -> CryptoResult<Vec<u8>> {
        compute_hmac(self.protocol, &self.key, data)
    }

    /// Verify an HMAC.
    ///
    /// Returns `true` if the MAC matches, `false` otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::UnsupportedAlgorithm`](super::CryptoError::UnsupportedAlgorithm) if the active crypto
    /// backend does not support the key's authentication protocol.
    pub fn verify_hmac(&self, data: &[u8], expected: &[u8]) -> CryptoResult<bool> {
        let computed = self.compute_hmac(data)?;
        // Constant-time comparison
        if computed.len() != expected.len() {
            return Ok(false);
        }
        let mut result = 0u8;
        for (a, b) in computed.iter().zip(expected.iter()) {
            result |= a ^ b;
        }
        Ok(result == 0)
    }
}

impl std::fmt::Debug for LocalizedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalizedKey")
            .field("protocol", &self.protocol)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl AsRef<[u8]> for LocalizedKey {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Password to key transformation (RFC 3414 Section A.2.1).
///
/// Routes through the active [`CryptoProvider`](super::crypto::CryptoProvider).
fn password_to_key(protocol: AuthProtocol, password: &[u8]) -> CryptoResult<Vec<u8>> {
    super::crypto::provider().password_to_key(protocol, password)
}

/// Key localization (RFC 3414 Section A.2.2).
///
/// Routes through the active [`CryptoProvider`](super::crypto::CryptoProvider).
fn localize_key(
    protocol: AuthProtocol,
    master_key: &[u8],
    engine_id: &[u8],
) -> CryptoResult<Vec<u8>> {
    super::crypto::provider().localize_key(protocol, master_key, engine_id)
}

/// Compute HMAC with the appropriate algorithm.
///
/// Routes through the active [`CryptoProvider`](super::crypto::CryptoProvider).
fn compute_hmac(protocol: AuthProtocol, key: &[u8], data: &[u8]) -> CryptoResult<Vec<u8>> {
    super::crypto::provider().compute_hmac(protocol, key, &[data], protocol.mac_len())
}

/// HMAC computation over multiple data slices (avoids concatenation allocation).
///
/// Routes through the active [`CryptoProvider`](super::crypto::CryptoProvider).
fn compute_hmac_slices(
    protocol: AuthProtocol,
    key: &[u8],
    slices: &[&[u8]],
) -> CryptoResult<Vec<u8>> {
    super::crypto::provider().compute_hmac(protocol, key, slices, protocol.mac_len())
}

/// Authenticate an outgoing message by computing and inserting the HMAC.
///
/// The message must already have placeholder zeros in the auth params field.
/// This function computes the HMAC over the entire message (with zeros in place)
/// and returns the message with the actual HMAC inserted.
///
/// # Errors
///
/// Returns [`CryptoError::UnsupportedAlgorithm`](super::CryptoError::UnsupportedAlgorithm) if the active crypto
/// backend does not support the key's authentication protocol.
pub fn authenticate_message(
    key: &LocalizedKey,
    message: &mut [u8],
    auth_offset: usize,
    auth_len: usize,
) -> CryptoResult<()> {
    let end = match auth_offset.checked_add(auth_len) {
        Some(e) if e <= message.len() => e,
        _ => return Ok(()),
    };

    // Compute HMAC over the message with zeros in auth params position
    let mac = key.compute_hmac(message)?;

    // Replace zeros with actual MAC
    message[auth_offset..end].copy_from_slice(&mac);
    Ok(())
}

/// Verify the authentication of an incoming message.
///
/// Returns `true` if the MAC is valid, `false` otherwise.
///
/// # Errors
///
/// Returns [`CryptoError::UnsupportedAlgorithm`](super::CryptoError::UnsupportedAlgorithm) if the active crypto
/// backend does not support the key's authentication protocol.
pub fn verify_message(
    key: &LocalizedKey,
    message: &[u8],
    auth_offset: usize,
    auth_len: usize,
) -> CryptoResult<bool> {
    const MAX_MAC_LEN: usize = 48; // SHA-512

    // No supported protocol produces a MAC longer than MAX_MAC_LEN; a larger
    // auth_len can never verify and would overrun the zeros buffer below.
    if auth_len > MAX_MAC_LEN {
        return Ok(false);
    }
    let end = match auth_offset.checked_add(auth_len) {
        Some(e) if e <= message.len() => e,
        _ => return Ok(false),
    };

    // Extract the received MAC
    let received_mac = &message[auth_offset..end];

    // Compute HMAC over the message with zeros in the auth position,
    // feeding three slices to avoid copying the entire message.
    let computed = {
        let zeros: [u8; MAX_MAC_LEN] = [0u8; MAX_MAC_LEN];
        compute_hmac_slices(
            key.protocol,
            key.as_bytes(),
            &[&message[..auth_offset], &zeros[..auth_len], &message[end..]],
        )?
    };

    // Constant-time comparison
    if computed.len() != received_mac.len() {
        return Ok(false);
    }
    let mut result = 0u8;
    for (a, b) in computed.iter().zip(received_mac.iter()) {
        result |= a ^ b;
    }
    Ok(result == 0)
}

/// Pre-computed master keys for `SNMPv3` authentication and privacy.
///
/// This struct caches the expensive password-to-key derivation results for
/// both authentication and privacy passwords. When polling many engines with
/// shared credentials, create a `MasterKeys` once and use it with
/// [`UsmBuilder`](crate::UsmBuilder) to avoid repeating the ~850μs key derivation for each engine.
///
/// # Example
///
/// ```rust
/// use async_snmp::{AuthProtocol, PrivProtocol, MasterKeys};
///
/// // Create master keys once (expensive)
/// let master_keys = MasterKeys::new(AuthProtocol::Sha256, b"authpassword").unwrap()
///     .with_privacy(PrivProtocol::Aes128, b"privpassword").unwrap();
///
/// // Use with multiple clients - localization is cheap (~1μs per engine)
/// ```
#[derive(Clone, Zeroize, ZeroizeOnDrop, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MasterKeys {
    /// Master key for authentication (and base for privacy key derivation)
    auth_master: MasterKey,
    /// Optional separate master key for privacy password
    /// If None, the `auth_master` is used for privacy (common case: same password)
    #[zeroize(skip)]
    priv_protocol: Option<super::PrivProtocol>,
    priv_master: Option<MasterKey>,
}

impl MasterKeys {
    /// Create master keys with just authentication.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::UnsupportedAlgorithm`](super::CryptoError::UnsupportedAlgorithm) if the active crypto
    /// backend does not support the requested authentication protocol.
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_snmp::{AuthProtocol, MasterKeys};
    ///
    /// let keys = MasterKeys::new(AuthProtocol::Sha256, b"authpassword").unwrap();
    /// ```
    pub fn new(auth_protocol: AuthProtocol, auth_password: &[u8]) -> CryptoResult<Self> {
        Ok(Self {
            auth_master: MasterKey::from_password(auth_protocol, auth_password)?,
            priv_protocol: None,
            priv_master: None,
        })
    }

    /// Add privacy with the same password as authentication.
    ///
    /// This is the common case where auth and priv passwords are identical.
    /// The same master key is reused, avoiding duplicate derivation.
    #[must_use]
    pub fn with_privacy_same_password(mut self, priv_protocol: super::PrivProtocol) -> Self {
        self.priv_protocol = Some(priv_protocol);
        // priv_master stays None - we'll use auth_master for priv key derivation
        self
    }

    /// Add privacy with a different password than authentication.
    ///
    /// Use this when auth and priv passwords differ. A separate master key
    /// derivation is performed for the privacy password.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::UnsupportedAlgorithm`](super::CryptoError::UnsupportedAlgorithm) if the active crypto
    /// backend does not support the authentication protocol used for key
    /// derivation.
    pub fn with_privacy(
        mut self,
        priv_protocol: super::PrivProtocol,
        priv_password: &[u8],
    ) -> CryptoResult<Self> {
        self.priv_protocol = Some(priv_protocol);
        // Use the auth protocol for priv key derivation (per RFC 3826 Section 1.2)
        self.priv_master = Some(MasterKey::from_password(
            self.auth_master.protocol(),
            priv_password,
        )?);
        Ok(self)
    }

    /// Get the authentication master key.
    #[must_use]
    pub fn auth_master(&self) -> &MasterKey {
        &self.auth_master
    }

    /// Get the privacy master key, if configured.
    ///
    /// Returns the separate priv master key if set, otherwise returns the
    /// auth master key (for same-password case).
    #[must_use]
    pub fn priv_master(&self) -> Option<&MasterKey> {
        if self.priv_protocol.is_some() {
            Some(self.priv_master.as_ref().unwrap_or(&self.auth_master))
        } else {
            None
        }
    }

    /// Get the configured privacy protocol.
    #[must_use]
    pub fn priv_protocol(&self) -> Option<super::PrivProtocol> {
        self.priv_protocol
    }

    /// Get the authentication protocol.
    #[must_use]
    pub fn auth_protocol(&self) -> AuthProtocol {
        self.auth_master.protocol()
    }

    /// Derive localized keys for a specific engine ID.
    ///
    /// Returns (`auth_key`, `priv_key`) where `priv_key` is None if no privacy
    /// was configured.
    ///
    /// Key extension is automatically applied when needed based on the auth/priv
    /// protocol combination:
    ///
    /// - AES-192/256 with SHA-1 or MD5: Blumenthal extension (draft-blumenthal-aes-usm-04)
    /// - 3DES with SHA-1 or MD5: Reeder extension (draft-reeder-snmpv3-usm-3desede-00)
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_snmp::{AuthProtocol, MasterKeys, PrivProtocol};
    ///
    /// let keys = MasterKeys::new(AuthProtocol::Sha1, b"authpassword").unwrap()
    ///     .with_privacy_same_password(PrivProtocol::Aes256);
    ///
    /// let engine_id = [0x80, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04];
    ///
    /// // SHA-1 only produces 20 bytes, but AES-256 needs 32.
    /// // Blumenthal extension is automatically applied.
    /// let (auth, priv_key) = keys.localize(&engine_id).unwrap();
    /// ```
    pub fn localize(
        &self,
        engine_id: &[u8],
    ) -> CryptoResult<(LocalizedKey, Option<crate::v3::PrivKey>)> {
        let auth_key = self.auth_master.localize(engine_id)?;

        let priv_key = self
            .priv_protocol
            .map(|priv_protocol| {
                let master = self.priv_master.as_ref().unwrap_or(&self.auth_master);
                crate::v3::PrivKey::from_master_key(master, priv_protocol, engine_id)
            })
            .transpose()?;

        Ok((auth_key, priv_key))
    }
}

impl std::fmt::Debug for MasterKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasterKeys")
            .field("auth_protocol", &self.auth_master.protocol())
            .field("priv_protocol", &self.priv_protocol)
            .field("has_separate_priv_password", &self.priv_master.is_some())
            .finish()
    }
}

/// Extend a localized key to the required length using the Blumenthal algorithm.
///
/// This implements the key extension algorithm from draft-blumenthal-aes-usm-04
/// Section 3.1.2.1, which allows AES-192/256 to be used with authentication
/// protocols that produce shorter digests (e.g., SHA-1 with AES-256).
///
/// The algorithm iteratively appends hash digests:
/// ```text
/// Kul' = Kul || H(Kul) || H(Kul || H(Kul)) || ...
/// ```
///
/// Where `H()` is the hash function of the authentication protocol.
pub(crate) fn extend_key(
    protocol: AuthProtocol,
    key: &[u8],
    target_len: usize,
) -> CryptoResult<Vec<u8>> {
    // If we already have enough bytes, just truncate
    if key.len() >= target_len {
        return Ok(key[..target_len].to_vec());
    }

    let provider = super::crypto::provider();
    let mut result = key.to_vec();

    // Keep appending H(result) until we have enough bytes
    while result.len() < target_len {
        let hash = provider.hash(protocol, &result)?;
        result.extend_from_slice(&hash);
    }

    // Truncate to exact length
    result.truncate(target_len);
    Ok(result)
}

/// Extend a localized key using the Reeder key extension algorithm.
///
/// This implements the key extension algorithm from draft-reeder-snmpv3-usm-3desede-00
/// Section 2.1. Unlike Blumenthal, this algorithm re-runs the full password-to-key (P2K)
/// algorithm using the current localized key as the "passphrase":
///
/// ```text
/// K1 = P2K(passphrase, engine_id)   // Original localized key (input)
/// K2 = P2K(K1, engine_id)           // Run full P2K with K1 as passphrase
/// localized_key = K1 || K2
/// K3 = P2K(K2, engine_id)           // If more bytes needed
/// localized_key = K1 || K2 || K3
/// ... and so on
/// ```
///
/// # Performance Warning
///
/// This is approximately 1000x slower than [`extend_key`] (Blumenthal) because each
/// iteration requires the full 1MB password expansion.
pub(crate) fn extend_key_reeder(
    protocol: AuthProtocol,
    key: &[u8],
    engine_id: &[u8],
    target_len: usize,
) -> CryptoResult<Vec<u8>> {
    // If we already have enough bytes, just truncate
    if key.len() >= target_len {
        return Ok(key[..target_len].to_vec());
    }

    let mut result = key.to_vec();
    let mut current_kul = key.to_vec();

    // Keep extending until we have enough bytes
    while result.len() < target_len {
        // Run full password-to-key using current Kul as the "passphrase"
        // This is the expensive 1MB expansion step
        let ku = password_to_key(protocol, &current_kul)?;

        // Localize the new Ku to get Kul
        let new_kul = localize_key(protocol, &ku, engine_id)?;

        // Append as many bytes as we need (or all of them)
        let bytes_needed = target_len - result.len();
        let bytes_to_copy = bytes_needed.min(new_kul.len());
        result.extend_from_slice(&new_kul[..bytes_to_copy]);

        // The next iteration uses the new Kul as input
        current_kul = new_kul;
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::hex::{decode as decode_hex, encode as encode_hex};

    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn test_password_to_key_md5() {
        // Test vector from RFC 3414 Appendix A.3.1
        // Password: "maplesyrup"
        // Expected Ku (hex): 9faf 3283 884e 9283 4ebc 9847 d8ed d963
        let password = b"maplesyrup";
        let key = password_to_key(AuthProtocol::Md5, password).unwrap();

        assert_eq!(key.len(), 16);
        assert_eq!(encode_hex(&key), "9faf3283884e92834ebc9847d8edd963");
    }

    #[test]
    fn test_password_to_key_sha1() {
        // Test vector from RFC 3414 Appendix A.3.2
        // Password: "maplesyrup"
        // Expected Ku (hex): 9fb5 cc03 8149 7b37 9352 8939 ff78 8d5d 7914 5211
        let password = b"maplesyrup";
        let key = password_to_key(AuthProtocol::Sha1, password).unwrap();

        assert_eq!(key.len(), 20);
        assert_eq!(encode_hex(&key), "9fb5cc0381497b3793528939ff788d5d79145211");
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn test_localize_key_md5() {
        // Test vector from RFC 3414 Appendix A.3.1
        // Master key from "maplesyrup"
        // Engine ID: 00 00 00 00 00 00 00 00 00 00 00 02
        // Expected Kul (hex): 526f 5eed 9fcc e26f 8964 c293 0787 d82b
        let password = b"maplesyrup";
        let engine_id = decode_hex("000000000000000000000002").unwrap();

        let key = LocalizedKey::from_password(AuthProtocol::Md5, password, &engine_id).unwrap();

        assert_eq!(key.as_bytes().len(), 16);
        assert_eq!(
            encode_hex(key.as_bytes()),
            "526f5eed9fcce26f8964c2930787d82b"
        );
    }

    #[test]
    fn test_localize_key_sha1() {
        // Test vector from RFC 3414 Appendix A.3.2
        // Engine ID: 00 00 00 00 00 00 00 00 00 00 00 02
        // Expected Kul (hex): 6695 febc 9288 e362 8223 5fc7 151f 1284 97b3 8f3f
        let password = b"maplesyrup";
        let engine_id = decode_hex("000000000000000000000002").unwrap();

        let key = LocalizedKey::from_password(AuthProtocol::Sha1, password, &engine_id).unwrap();

        assert_eq!(key.as_bytes().len(), 20);
        assert_eq!(
            encode_hex(key.as_bytes()),
            "6695febc9288e36282235fc7151f128497b38f3f"
        );
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn test_hmac_computation() {
        let key = LocalizedKey::from_bytes(
            AuthProtocol::Md5,
            vec![
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10,
            ],
        );

        let data = b"test message";
        let mac = key.compute_hmac(data).unwrap();

        // HMAC-MD5-96: 12 bytes
        assert_eq!(mac.len(), 12);

        // Verify returns true for correct MAC
        assert!(key.verify_hmac(data, &mac).unwrap());

        // Verify returns false for wrong MAC
        let mut wrong_mac = mac.clone();
        wrong_mac[0] ^= 0xFF;
        assert!(!key.verify_hmac(data, &wrong_mac).unwrap());
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn test_verify_message_oversized_auth_len() {
        let key = LocalizedKey::from_bytes(
            AuthProtocol::Md5,
            vec![
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10,
            ],
        );

        // auth_len larger than the biggest supported MAC (48 bytes for
        // SHA-512) but still within the message bounds must be rejected,
        // not panic on the internal zeros buffer.
        let message = vec![0u8; 128];
        let result = verify_message(&key, &message, 10, 49).unwrap();
        assert!(!result);
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn test_empty_password_rejected() {
        // RFC 3414 §11.2 / net-snmp USM_PASSWORDTOOSHORT: an empty password
        // must be rejected rather than deriving an all-zero key.
        assert_eq!(
            password_to_key(AuthProtocol::Md5, b""),
            Err(super::super::CryptoError::PasswordTooShort)
        );
    }

    #[test]
    fn test_short_password_rejected() {
        // A 7-octet password is below the RFC 3414 minimum of 8 and must be
        // rejected at every plaintext-password derivation entry point.
        let engine_id = decode_hex("000000000000000000000002").unwrap();
        let short = b"1234567"; // 7 octets

        assert_eq!(
            MasterKey::from_password(AuthProtocol::Sha1, short),
            Err(super::super::CryptoError::PasswordTooShort)
        );
        assert_eq!(
            LocalizedKey::from_password(AuthProtocol::Sha1, short, &engine_id).err(),
            Some(super::super::CryptoError::PasswordTooShort)
        );
        assert_eq!(
            MasterKeys::new(AuthProtocol::Sha1, short),
            Err(super::super::CryptoError::PasswordTooShort)
        );
    }

    #[test]
    fn test_min_length_password_accepted() {
        // An exactly-8-octet password meets the minimum and must succeed.
        let engine_id = decode_hex("000000000000000000000002").unwrap();
        let ok = b"12345678"; // 8 octets

        assert!(MasterKey::from_password(AuthProtocol::Sha1, ok).is_ok());
        assert!(LocalizedKey::from_password(AuthProtocol::Sha1, ok, &engine_id).is_ok());
        assert!(MasterKeys::new(AuthProtocol::Sha1, ok).is_ok());
    }

    #[test]
    fn test_from_bytes_bypasses_length_check() {
        // Pre-derived key constructors take key material, not a plaintext
        // password, and must remain unaffected by the length check.
        let short_key = vec![0xAAu8; 4];
        let master = MasterKey::from_bytes(AuthProtocol::Sha1, short_key.clone());
        assert_eq!(master.as_bytes(), short_key.as_slice());
        let localized = LocalizedKey::from_bytes(AuthProtocol::Sha1, short_key.clone());
        assert_eq!(localized.as_bytes(), short_key.as_slice());
    }

    #[test]
    fn test_from_str_password() {
        // Verify from_str_password produces same result as from_password with bytes
        let engine_id = decode_hex("000000000000000000000002").unwrap();

        let key_from_bytes =
            LocalizedKey::from_password(AuthProtocol::Sha1, b"maplesyrup", &engine_id).unwrap();
        let key_from_str =
            LocalizedKey::from_str_password(AuthProtocol::Sha1, "maplesyrup", &engine_id).unwrap();

        assert_eq!(key_from_bytes.as_bytes(), key_from_str.as_bytes());
        assert_eq!(key_from_bytes.protocol(), key_from_str.protocol());
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn test_master_key_localize_md5() {
        // Verify MasterKey produces same result as LocalizedKey::from_password
        let password = b"maplesyrup";
        let engine_id = decode_hex("000000000000000000000002").unwrap();

        let master = MasterKey::from_password(AuthProtocol::Md5, password).unwrap();
        let localized_via_master = master.localize(&engine_id).unwrap();
        let localized_direct =
            LocalizedKey::from_password(AuthProtocol::Md5, password, &engine_id).unwrap();

        assert_eq!(localized_via_master.as_bytes(), localized_direct.as_bytes());
        assert_eq!(localized_via_master.protocol(), localized_direct.protocol());

        // Verify the master key itself matches RFC 3414 test vector
        assert_eq!(
            encode_hex(master.as_bytes()),
            "9faf3283884e92834ebc9847d8edd963"
        );
    }

    #[test]
    fn test_master_key_localize_sha1() {
        let password = b"maplesyrup";
        let engine_id = decode_hex("000000000000000000000002").unwrap();

        let master = MasterKey::from_password(AuthProtocol::Sha1, password).unwrap();
        let localized_via_master = master.localize(&engine_id).unwrap();
        let localized_direct =
            LocalizedKey::from_password(AuthProtocol::Sha1, password, &engine_id).unwrap();

        assert_eq!(localized_via_master.as_bytes(), localized_direct.as_bytes());

        // Verify the master key itself matches RFC 3414 test vector
        assert_eq!(
            encode_hex(master.as_bytes()),
            "9fb5cc0381497b3793528939ff788d5d79145211"
        );
    }

    #[test]
    fn test_master_key_reuse_for_multiple_engines() {
        // Demonstrate that a single MasterKey can localize to multiple engines
        let password = b"maplesyrup";
        let engine_id_1 = decode_hex("000000000000000000000001").unwrap();
        let engine_id_2 = decode_hex("000000000000000000000002").unwrap();

        let master = MasterKey::from_password(AuthProtocol::Sha256, password).unwrap();

        let key1 = master.localize(&engine_id_1).unwrap();
        let key2 = master.localize(&engine_id_2).unwrap();

        // Keys should be different for different engines
        assert_ne!(key1.as_bytes(), key2.as_bytes());

        // Each key should match what from_password produces
        let direct1 =
            LocalizedKey::from_password(AuthProtocol::Sha256, password, &engine_id_1).unwrap();
        let direct2 =
            LocalizedKey::from_password(AuthProtocol::Sha256, password, &engine_id_2).unwrap();

        assert_eq!(key1.as_bytes(), direct1.as_bytes());
        assert_eq!(key2.as_bytes(), direct2.as_bytes());
    }

    #[test]
    fn test_from_master_key() {
        let password = b"maplesyrup";
        let engine_id = decode_hex("000000000000000000000002").unwrap();

        let master = MasterKey::from_password(AuthProtocol::Sha256, password).unwrap();
        let key_via_localize = master.localize(&engine_id).unwrap();
        let key_via_from_master = LocalizedKey::from_master_key(&master, &engine_id).unwrap();

        assert_eq!(key_via_localize.as_bytes(), key_via_from_master.as_bytes());
    }

    #[test]
    fn test_master_keys_auth_only() {
        let engine_id = decode_hex("000000000000000000000002").unwrap();
        let master_keys = MasterKeys::new(AuthProtocol::Sha256, b"authpassword").unwrap();

        assert_eq!(master_keys.auth_protocol(), AuthProtocol::Sha256);
        assert!(master_keys.priv_protocol().is_none());
        assert!(master_keys.priv_master().is_none());

        let (auth_key, priv_key) = master_keys.localize(&engine_id).unwrap();
        assert!(priv_key.is_none());
        assert_eq!(auth_key.protocol(), AuthProtocol::Sha256);
    }

    #[test]
    fn test_master_keys_with_privacy_same_password() {
        use crate::v3::PrivProtocol;

        let engine_id = decode_hex("000000000000000000000002").unwrap();
        let master_keys = MasterKeys::new(AuthProtocol::Sha256, b"sharedpassword")
            .unwrap()
            .with_privacy_same_password(PrivProtocol::Aes128);

        assert_eq!(master_keys.auth_protocol(), AuthProtocol::Sha256);
        assert_eq!(master_keys.priv_protocol(), Some(PrivProtocol::Aes128));

        let (auth_key, priv_key) = master_keys.localize(&engine_id).unwrap();
        assert!(priv_key.is_some());
        assert_eq!(auth_key.protocol(), AuthProtocol::Sha256);
    }

    #[test]
    fn test_master_keys_with_privacy_different_password() {
        use crate::v3::PrivProtocol;

        let engine_id = decode_hex("000000000000000000000002").unwrap();
        let master_keys = MasterKeys::new(AuthProtocol::Sha256, b"authpassword")
            .unwrap()
            .with_privacy(PrivProtocol::Aes128, b"privpassword")
            .unwrap();

        let (_auth_key, priv_key) = master_keys.localize(&engine_id).unwrap();
        assert!(priv_key.is_some());

        // Verify that different passwords produce different keys
        let same_password_keys = MasterKeys::new(AuthProtocol::Sha256, b"authpassword")
            .unwrap()
            .with_privacy_same_password(PrivProtocol::Aes128);
        let (_, priv_key_same) = same_password_keys.localize(&engine_id).unwrap();

        // The priv keys should differ when using different passwords
        // (auth keys are the same since they use same auth password)
        assert_ne!(
            priv_key.as_ref().unwrap().encryption_key(),
            priv_key_same.as_ref().unwrap().encryption_key()
        );
    }

    // Known-Answer Tests (KAT) for Reeder key extension algorithm
    // Test vectors from draft-reeder-snmpv3-usm-3desede-00 Appendix B

    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn test_reeder_extend_key_md5_kat() {
        // Test vector from draft-reeder Appendix B.1
        // Password: "maplesyrup"
        // Engine ID: 00 00 00 00 00 00 00 00 00 00 00 02
        // Expected 32-byte localized key:
        //   52 6f 5e ed 9f cc e2 6f 89 64 c2 93 07 87 d8 2b   (first 16 bytes = K1)
        //   79 ef f4 4a 90 65 0e e0 a3 a4 0a bf ac 5a cc 12   (next 16 bytes = K2)
        let password = b"maplesyrup";
        let engine_id = decode_hex("000000000000000000000002").unwrap();

        // Get the standard localized key (K1)
        let k1 = LocalizedKey::from_password(AuthProtocol::Md5, password, &engine_id).unwrap();
        assert_eq!(
            encode_hex(k1.as_bytes()),
            "526f5eed9fcce26f8964c2930787d82b"
        );

        // Extend using Reeder algorithm to 32 bytes
        let extended = extend_key_reeder(AuthProtocol::Md5, k1.as_bytes(), &engine_id, 32).unwrap();
        assert_eq!(extended.len(), 32);
        assert_eq!(
            encode_hex(&extended),
            "526f5eed9fcce26f8964c2930787d82b79eff44a90650ee0a3a40abfac5acc12"
        );
    }

    #[test]
    fn test_reeder_extend_key_sha1_kat() {
        // Test vector from draft-reeder Appendix B.2
        // Password: "maplesyrup"
        // Engine ID: 00 00 00 00 00 00 00 00 00 00 00 02
        // Expected 40-byte localized key:
        //   66 95 fe bc 92 88 e3 62 82 23 5f c7 15 1f 12 84 97 b3 8f 3f  (first 20 bytes = K1)
        //   9b 8b 6d 78 93 6b a6 e7 d1 9d fd 9c d2 d5 06 55 47 74 3f b5  (next 20 bytes = K2)
        let password = b"maplesyrup";
        let engine_id = decode_hex("000000000000000000000002").unwrap();

        // Get the standard localized key (K1)
        let k1 = LocalizedKey::from_password(AuthProtocol::Sha1, password, &engine_id).unwrap();
        assert_eq!(
            encode_hex(k1.as_bytes()),
            "6695febc9288e36282235fc7151f128497b38f3f"
        );

        // Extend using Reeder algorithm to 40 bytes
        let extended =
            extend_key_reeder(AuthProtocol::Sha1, k1.as_bytes(), &engine_id, 40).unwrap();
        assert_eq!(extended.len(), 40);
        assert_eq!(
            encode_hex(&extended),
            "6695febc9288e36282235fc7151f128497b38f3f9b8b6d78936ba6e7d19dfd9cd2d5065547743fb5"
        );
    }

    #[test]
    fn test_reeder_extend_key_sha1_to_32_bytes() {
        // Extending SHA-1 key to 32 bytes (for AES-256)
        // Should be the first 32 bytes of the 40-byte result
        let password = b"maplesyrup";
        let engine_id = decode_hex("000000000000000000000002").unwrap();

        let k1 = LocalizedKey::from_password(AuthProtocol::Sha1, password, &engine_id).unwrap();
        let extended =
            extend_key_reeder(AuthProtocol::Sha1, k1.as_bytes(), &engine_id, 32).unwrap();

        assert_eq!(extended.len(), 32);
        // First 20 bytes = K1, next 12 bytes = first 12 bytes of K2
        assert_eq!(
            encode_hex(&extended),
            "6695febc9288e36282235fc7151f128497b38f3f9b8b6d78936ba6e7d19dfd9c"
        );
    }

    #[test]
    fn test_reeder_extend_key_truncation() {
        // When key is already long enough, should truncate
        let long_key = vec![0xAAu8; 64];
        let engine_id = decode_hex("000000000000000000000002").unwrap();

        let extended = extend_key_reeder(AuthProtocol::Sha256, &long_key, &engine_id, 32).unwrap();
        assert_eq!(extended.len(), 32);
        assert_eq!(extended, vec![0xAAu8; 32]);
    }

    #[test]
    fn test_reeder_vs_blumenthal_differ() {
        // Verify that Reeder and Blumenthal produce different results
        let password = b"maplesyrup";
        let engine_id = decode_hex("000000000000000000000002").unwrap();

        let k1 = LocalizedKey::from_password(AuthProtocol::Sha1, password, &engine_id).unwrap();

        let reeder = extend_key_reeder(AuthProtocol::Sha1, k1.as_bytes(), &engine_id, 32).unwrap();
        let blumenthal = extend_key(AuthProtocol::Sha1, k1.as_bytes(), 32).unwrap();

        assert_eq!(reeder.len(), 32);
        assert_eq!(blumenthal.len(), 32);

        // First 20 bytes should be identical (both start with K1)
        assert_eq!(&reeder[..20], &blumenthal[..20]);
        // Extension bytes should differ (different algorithms)
        assert_ne!(&reeder[20..], &blumenthal[20..]);
    }
}
