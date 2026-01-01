//! Authentication key derivation and HMAC operations (RFC 3414).
//!
//! This module implements:
//! - Password-to-key derivation (1MB expansion + hash)
//! - Key localization (binding key to engine ID)
//! - HMAC authentication for message integrity
//!
//! # Two-Level Key Derivation
//!
//! SNMPv3 key derivation is a two-step process:
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
//! let master = MasterKey::from_password(AuthProtocol::Sha256, b"authpassword");
//!
//! // Cheap: ~1μs each - do per engine
//! let key1 = master.localize(b"\x80\x00\x1f\x88\x80...");
//! let key2 = master.localize(b"\x80\x00\x1f\x88\x81...");
//! ```

use digest::{Digest, KeyInit, Mac, OutputSizeUser, core_api::BlockSizeUser};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::AuthProtocol;

/// Minimum password length recommended by net-snmp.
///
/// Net-snmp rejects passwords shorter than 8 characters with `USM_PASSWORDTOOSHORT`.
/// While this library accepts shorter passwords for flexibility, applications should
/// enforce this minimum for security.
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
/// let master = MasterKey::from_password(AuthProtocol::Sha256, b"authpassword");
///
/// // Localize to different engines (cheap)
/// let engine1_id = b"\x80\x00\x1f\x88\x80\xe9\xb1\x04\x61\x73\x61\x00\x00\x00";
/// let engine2_id = b"\x80\x00\x1f\x88\x80\xe9\xb1\x04\x61\x73\x61\x00\x00\x01";
///
/// let key1 = master.localize(engine1_id);
/// let key2 = master.localize(engine2_id);
/// ```
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
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
    /// # Empty and Short Passwords
    ///
    /// Empty passwords result in an all-zero key. A warning is logged when
    /// the password is shorter than [`MIN_PASSWORD_LENGTH`] (8 characters).
    pub fn from_password(protocol: AuthProtocol, password: &[u8]) -> Self {
        if password.len() < MIN_PASSWORD_LENGTH {
            tracing::warn!(
                password_len = password.len(),
                min_len = MIN_PASSWORD_LENGTH,
                "SNMPv3 password is shorter than recommended minimum; \
                 net-snmp rejects passwords shorter than 8 characters"
            );
        }
        let key = password_to_key(protocol, password);
        Self { key, protocol }
    }

    /// Derive a master key from a string password.
    pub fn from_str_password(protocol: AuthProtocol, password: &str) -> Self {
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
    pub fn localize(&self, engine_id: &[u8]) -> LocalizedKey {
        let localized = localize_key(self.protocol, &self.key, engine_id);
        LocalizedKey {
            key: localized,
            protocol: self.protocol,
        }
    }

    /// Get the protocol this key is for.
    pub fn protocol(&self) -> AuthProtocol {
        self.protocol
    }

    /// Get the raw key bytes.
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
    /// 3. Hash (master_key || engine_id || master_key) to get the localized key
    ///
    /// # Performance Note
    ///
    /// This method performs the full key derivation (~850μs for SHA-256). When
    /// polling many engines with shared credentials, use [`MasterKey`] to cache
    /// the intermediate result and call [`MasterKey::localize`] for each engine.
    ///
    /// # Empty and Short Passwords
    ///
    /// Empty passwords result in an all-zero key of the appropriate length for
    /// the authentication protocol. This differs from net-snmp, which rejects
    /// passwords shorter than 8 characters with `USM_PASSWORDTOOSHORT`.
    ///
    /// While empty/short passwords are accepted for flexibility, they provide
    /// minimal security. A warning is logged at the `WARN` level when the
    /// password is shorter than [`MIN_PASSWORD_LENGTH`] (8 characters).
    pub fn from_password(protocol: AuthProtocol, password: &[u8], engine_id: &[u8]) -> Self {
        MasterKey::from_password(protocol, password).localize(engine_id)
    }

    /// Derive a localized key from a string password and engine ID.
    ///
    /// This is a convenience method that converts the string to bytes and calls
    /// [`from_password`](Self::from_password).
    pub fn from_str_password(protocol: AuthProtocol, password: &str, engine_id: &[u8]) -> Self {
        Self::from_password(protocol, password.as_bytes(), engine_id)
    }

    /// Create a localized key from a master key and engine ID.
    ///
    /// This is the efficient path when you have a cached [`MasterKey`].
    /// Equivalent to calling [`MasterKey::localize`].
    pub fn from_master_key(master: &MasterKey, engine_id: &[u8]) -> Self {
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
    pub fn protocol(&self) -> AuthProtocol {
        self.protocol
    }

    /// Get the raw key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }

    /// Get the MAC length for this key's protocol.
    pub fn mac_len(&self) -> usize {
        self.protocol.mac_len()
    }

    /// Compute HMAC over a message and return the truncated MAC.
    ///
    /// The returned MAC is truncated to the appropriate length for the protocol
    /// (12 bytes for MD5/SHA-1, variable for SHA-2).
    pub fn compute_hmac(&self, data: &[u8]) -> Vec<u8> {
        compute_hmac(self.protocol, &self.key, data)
    }

    /// Verify an HMAC.
    ///
    /// Returns `true` if the MAC matches, `false` otherwise.
    pub fn verify_hmac(&self, data: &[u8], expected: &[u8]) -> bool {
        let computed = self.compute_hmac(data);
        // Constant-time comparison
        if computed.len() != expected.len() {
            return false;
        }
        let mut result = 0u8;
        for (a, b) in computed.iter().zip(expected.iter()) {
            result |= a ^ b;
        }
        result == 0
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

/// Password to key transformation (RFC 3414 Section A.2.1).
///
/// Creates a 1MB string by repeating the password, then hashes it.
fn password_to_key(protocol: AuthProtocol, password: &[u8]) -> Vec<u8> {
    const EXPANSION_SIZE: usize = 1_048_576; // 1MB

    match protocol {
        AuthProtocol::Md5 => password_to_key_impl::<md5::Md5>(password, EXPANSION_SIZE),
        AuthProtocol::Sha1 => password_to_key_impl::<sha1::Sha1>(password, EXPANSION_SIZE),
        AuthProtocol::Sha224 => password_to_key_impl::<sha2::Sha224>(password, EXPANSION_SIZE),
        AuthProtocol::Sha256 => password_to_key_impl::<sha2::Sha256>(password, EXPANSION_SIZE),
        AuthProtocol::Sha384 => password_to_key_impl::<sha2::Sha384>(password, EXPANSION_SIZE),
        AuthProtocol::Sha512 => password_to_key_impl::<sha2::Sha512>(password, EXPANSION_SIZE),
    }
}

fn password_to_key_impl<D>(password: &[u8], expansion_size: usize) -> Vec<u8>
where
    D: Digest + Default,
{
    if password.is_empty() {
        // Empty password results in all-zero key
        return vec![0u8; <D as OutputSizeUser>::output_size()];
    }

    let mut hasher = D::new();

    // RFC 3414 A.2.1: Form a 1MB string by repeating the password
    // and hash it in 64-byte chunks (matching net-snmp's approach)
    let mut buf = [0u8; 64];
    let password_len = password.len();
    let mut password_index = 0;
    let mut count = 0;

    while count < expansion_size {
        // Fill buffer with password bytes
        for byte in &mut buf {
            *byte = password[password_index];
            password_index = (password_index + 1) % password_len;
        }
        hasher.update(buf);
        count += 64;
    }

    hasher.finalize().to_vec()
}

/// Key localization (RFC 3414 Section A.2.2).
///
/// Binds a master key to a specific engine ID:
/// localized_key = H(master_key || engine_id || master_key)
fn localize_key(protocol: AuthProtocol, master_key: &[u8], engine_id: &[u8]) -> Vec<u8> {
    match protocol {
        AuthProtocol::Md5 => localize_key_impl::<md5::Md5>(master_key, engine_id),
        AuthProtocol::Sha1 => localize_key_impl::<sha1::Sha1>(master_key, engine_id),
        AuthProtocol::Sha224 => localize_key_impl::<sha2::Sha224>(master_key, engine_id),
        AuthProtocol::Sha256 => localize_key_impl::<sha2::Sha256>(master_key, engine_id),
        AuthProtocol::Sha384 => localize_key_impl::<sha2::Sha384>(master_key, engine_id),
        AuthProtocol::Sha512 => localize_key_impl::<sha2::Sha512>(master_key, engine_id),
    }
}

fn localize_key_impl<D>(master_key: &[u8], engine_id: &[u8]) -> Vec<u8>
where
    D: Digest + Default,
{
    let mut hasher = D::new();
    hasher.update(master_key);
    hasher.update(engine_id);
    hasher.update(master_key);
    hasher.finalize().to_vec()
}

/// Compute HMAC with the appropriate algorithm.
fn compute_hmac(protocol: AuthProtocol, key: &[u8], data: &[u8]) -> Vec<u8> {
    match protocol {
        AuthProtocol::Md5 => compute_hmac_impl::<md5::Md5>(key, data, 12),
        AuthProtocol::Sha1 => compute_hmac_impl::<sha1::Sha1>(key, data, 12),
        AuthProtocol::Sha224 => compute_hmac_impl::<sha2::Sha224>(key, data, 16),
        AuthProtocol::Sha256 => compute_hmac_impl::<sha2::Sha256>(key, data, 24),
        AuthProtocol::Sha384 => compute_hmac_impl::<sha2::Sha384>(key, data, 32),
        AuthProtocol::Sha512 => compute_hmac_impl::<sha2::Sha512>(key, data, 48),
    }
}

/// Generic HMAC computation with truncation.
fn compute_hmac_impl<D>(key: &[u8], data: &[u8], truncate_len: usize) -> Vec<u8>
where
    D: Digest + BlockSizeUser + Clone,
{
    use hmac::SimpleHmac;

    let mut mac =
        <SimpleHmac<D> as KeyInit>::new_from_slice(key).expect("HMAC can take key of any size");
    Mac::update(&mut mac, data);
    let result = mac.finalize().into_bytes();
    result[..truncate_len].to_vec()
}

/// Authenticate an outgoing message by computing and inserting the HMAC.
///
/// The message must already have placeholder zeros in the auth params field.
/// This function computes the HMAC over the entire message (with zeros in place)
/// and returns the message with the actual HMAC inserted.
pub fn authenticate_message(
    key: &LocalizedKey,
    message: &mut [u8],
    auth_offset: usize,
    auth_len: usize,
) {
    // Compute HMAC over the message with zeros in auth params position
    let mac = key.compute_hmac(message);

    // Replace zeros with actual MAC
    message[auth_offset..auth_offset + auth_len].copy_from_slice(&mac);
}

/// Verify the authentication of an incoming message.
///
/// Returns `true` if the MAC is valid, `false` otherwise.
pub fn verify_message(
    key: &LocalizedKey,
    message: &[u8],
    auth_offset: usize,
    auth_len: usize,
) -> bool {
    // Extract the received MAC
    let received_mac = &message[auth_offset..auth_offset + auth_len];

    // Create a copy with zeros in the auth position
    let mut msg_copy = message.to_vec();
    msg_copy[auth_offset..auth_offset + auth_len].fill(0);

    // Compute expected MAC
    key.verify_hmac(&msg_copy, received_mac)
}

/// Pre-computed master keys for SNMPv3 authentication and privacy.
///
/// This struct caches the expensive password-to-key derivation results for
/// both authentication and privacy passwords. When polling many engines with
/// shared credentials, create a `MasterKeys` once and use it with
/// [`V3SecurityConfig`](crate::client::V3SecurityConfig) to avoid repeating
/// the ~850μs key derivation for each engine.
///
/// # Example
///
/// ```rust
/// use async_snmp::{AuthProtocol, PrivProtocol, MasterKeys};
///
/// // Create master keys once (expensive)
/// let master_keys = MasterKeys::new(AuthProtocol::Sha256, b"authpassword")
///     .with_privacy(PrivProtocol::Aes128, b"privpassword");
///
/// // Use with multiple clients - localization is cheap (~1μs per engine)
/// ```
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKeys {
    /// Master key for authentication (and base for privacy key derivation)
    auth_master: MasterKey,
    /// Optional separate master key for privacy password
    /// If None, the auth_master is used for privacy (common case: same password)
    #[zeroize(skip)]
    priv_protocol: Option<super::PrivProtocol>,
    priv_master: Option<MasterKey>,
}

impl MasterKeys {
    /// Create master keys with just authentication.
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_snmp::{AuthProtocol, MasterKeys};
    ///
    /// let keys = MasterKeys::new(AuthProtocol::Sha256, b"authpassword");
    /// ```
    pub fn new(auth_protocol: AuthProtocol, auth_password: &[u8]) -> Self {
        Self {
            auth_master: MasterKey::from_password(auth_protocol, auth_password),
            priv_protocol: None,
            priv_master: None,
        }
    }

    /// Add privacy with the same password as authentication.
    ///
    /// This is the common case where auth and priv passwords are identical.
    /// The same master key is reused, avoiding duplicate derivation.
    pub fn with_privacy_same_password(mut self, priv_protocol: super::PrivProtocol) -> Self {
        self.priv_protocol = Some(priv_protocol);
        // priv_master stays None - we'll use auth_master for priv key derivation
        self
    }

    /// Add privacy with a different password than authentication.
    ///
    /// Use this when auth and priv passwords differ. A separate master key
    /// derivation is performed for the privacy password.
    pub fn with_privacy(
        mut self,
        priv_protocol: super::PrivProtocol,
        priv_password: &[u8],
    ) -> Self {
        self.priv_protocol = Some(priv_protocol);
        // Use the auth protocol for priv key derivation (per RFC 3826 Section 1.2)
        self.priv_master = Some(MasterKey::from_password(
            self.auth_master.protocol(),
            priv_password,
        ));
        self
    }

    /// Get the authentication master key.
    pub fn auth_master(&self) -> &MasterKey {
        &self.auth_master
    }

    /// Get the privacy master key, if configured.
    ///
    /// Returns the separate priv master key if set, otherwise returns the
    /// auth master key (for same-password case).
    pub fn priv_master(&self) -> Option<&MasterKey> {
        if self.priv_protocol.is_some() {
            Some(self.priv_master.as_ref().unwrap_or(&self.auth_master))
        } else {
            None
        }
    }

    /// Get the configured privacy protocol.
    pub fn priv_protocol(&self) -> Option<super::PrivProtocol> {
        self.priv_protocol
    }

    /// Get the authentication protocol.
    pub fn auth_protocol(&self) -> AuthProtocol {
        self.auth_master.protocol()
    }

    /// Derive localized keys for a specific engine ID.
    ///
    /// Returns (auth_key, priv_key) where priv_key is None if no privacy
    /// was configured.
    pub fn localize(&self, engine_id: &[u8]) -> (LocalizedKey, Option<crate::v3::PrivKey>) {
        let auth_key = self.auth_master.localize(engine_id);

        let priv_key = self.priv_protocol.map(|priv_protocol| {
            let master = self.priv_master.as_ref().unwrap_or(&self.auth_master);
            crate::v3::PrivKey::from_master_key(master, priv_protocol, engine_id)
        });

        (auth_key, priv_key)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::hex::{decode as decode_hex, encode as encode_hex};

    #[test]
    fn test_password_to_key_md5() {
        // Test vector from RFC 3414 Appendix A.3.1
        // Password: "maplesyrup"
        // Expected Ku (hex): 9faf 3283 884e 9283 4ebc 9847 d8ed d963
        let password = b"maplesyrup";
        let key = password_to_key(AuthProtocol::Md5, password);

        assert_eq!(key.len(), 16);
        assert_eq!(encode_hex(&key), "9faf3283884e92834ebc9847d8edd963");
    }

    #[test]
    fn test_password_to_key_sha1() {
        // Test vector from RFC 3414 Appendix A.3.2
        // Password: "maplesyrup"
        // Expected Ku (hex): 9fb5 cc03 8149 7b37 9352 8939 ff78 8d5d 7914 5211
        let password = b"maplesyrup";
        let key = password_to_key(AuthProtocol::Sha1, password);

        assert_eq!(key.len(), 20);
        assert_eq!(encode_hex(&key), "9fb5cc0381497b3793528939ff788d5d79145211");
    }

    #[test]
    fn test_localize_key_md5() {
        // Test vector from RFC 3414 Appendix A.3.1
        // Master key from "maplesyrup"
        // Engine ID: 00 00 00 00 00 00 00 00 00 00 00 02
        // Expected Kul (hex): 526f 5eed 9fcc e26f 8964 c293 0787 d82b
        let password = b"maplesyrup";
        let engine_id = decode_hex("000000000000000000000002").unwrap();

        let key = LocalizedKey::from_password(AuthProtocol::Md5, password, &engine_id);

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

        let key = LocalizedKey::from_password(AuthProtocol::Sha1, password, &engine_id);

        assert_eq!(key.as_bytes().len(), 20);
        assert_eq!(
            encode_hex(key.as_bytes()),
            "6695febc9288e36282235fc7151f128497b38f3f"
        );
    }

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
        let mac = key.compute_hmac(data);

        // HMAC-MD5-96: 12 bytes
        assert_eq!(mac.len(), 12);

        // Verify returns true for correct MAC
        assert!(key.verify_hmac(data, &mac));

        // Verify returns false for wrong MAC
        let mut wrong_mac = mac.clone();
        wrong_mac[0] ^= 0xFF;
        assert!(!key.verify_hmac(data, &wrong_mac));
    }

    #[test]
    fn test_empty_password() {
        let key = password_to_key(AuthProtocol::Md5, b"");
        assert_eq!(key.len(), 16);
        assert!(key.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_from_str_password() {
        // Verify from_str_password produces same result as from_password with bytes
        let engine_id = decode_hex("000000000000000000000002").unwrap();

        let key_from_bytes =
            LocalizedKey::from_password(AuthProtocol::Sha1, b"maplesyrup", &engine_id);
        let key_from_str =
            LocalizedKey::from_str_password(AuthProtocol::Sha1, "maplesyrup", &engine_id);

        assert_eq!(key_from_bytes.as_bytes(), key_from_str.as_bytes());
        assert_eq!(key_from_bytes.protocol(), key_from_str.protocol());
    }

    #[test]
    fn test_master_key_localize_md5() {
        // Verify MasterKey produces same result as LocalizedKey::from_password
        let password = b"maplesyrup";
        let engine_id = decode_hex("000000000000000000000002").unwrap();

        let master = MasterKey::from_password(AuthProtocol::Md5, password);
        let localized_via_master = master.localize(&engine_id);
        let localized_direct = LocalizedKey::from_password(AuthProtocol::Md5, password, &engine_id);

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

        let master = MasterKey::from_password(AuthProtocol::Sha1, password);
        let localized_via_master = master.localize(&engine_id);
        let localized_direct =
            LocalizedKey::from_password(AuthProtocol::Sha1, password, &engine_id);

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

        let master = MasterKey::from_password(AuthProtocol::Sha256, password);

        let key1 = master.localize(&engine_id_1);
        let key2 = master.localize(&engine_id_2);

        // Keys should be different for different engines
        assert_ne!(key1.as_bytes(), key2.as_bytes());

        // Each key should match what from_password produces
        let direct1 = LocalizedKey::from_password(AuthProtocol::Sha256, password, &engine_id_1);
        let direct2 = LocalizedKey::from_password(AuthProtocol::Sha256, password, &engine_id_2);

        assert_eq!(key1.as_bytes(), direct1.as_bytes());
        assert_eq!(key2.as_bytes(), direct2.as_bytes());
    }

    #[test]
    fn test_from_master_key() {
        let password = b"maplesyrup";
        let engine_id = decode_hex("000000000000000000000002").unwrap();

        let master = MasterKey::from_password(AuthProtocol::Sha256, password);
        let key_via_localize = master.localize(&engine_id);
        let key_via_from_master = LocalizedKey::from_master_key(&master, &engine_id);

        assert_eq!(key_via_localize.as_bytes(), key_via_from_master.as_bytes());
    }

    #[test]
    fn test_master_keys_auth_only() {
        let engine_id = decode_hex("000000000000000000000002").unwrap();
        let master_keys = MasterKeys::new(AuthProtocol::Sha256, b"authpassword");

        assert_eq!(master_keys.auth_protocol(), AuthProtocol::Sha256);
        assert!(master_keys.priv_protocol().is_none());
        assert!(master_keys.priv_master().is_none());

        let (auth_key, priv_key) = master_keys.localize(&engine_id);
        assert!(priv_key.is_none());
        assert_eq!(auth_key.protocol(), AuthProtocol::Sha256);
    }

    #[test]
    fn test_master_keys_with_privacy_same_password() {
        use crate::v3::PrivProtocol;

        let engine_id = decode_hex("000000000000000000000002").unwrap();
        let master_keys = MasterKeys::new(AuthProtocol::Sha256, b"sharedpassword")
            .with_privacy_same_password(PrivProtocol::Aes128);

        assert_eq!(master_keys.auth_protocol(), AuthProtocol::Sha256);
        assert_eq!(master_keys.priv_protocol(), Some(PrivProtocol::Aes128));

        let (auth_key, priv_key) = master_keys.localize(&engine_id);
        assert!(priv_key.is_some());
        assert_eq!(auth_key.protocol(), AuthProtocol::Sha256);
    }

    #[test]
    fn test_master_keys_with_privacy_different_password() {
        use crate::v3::PrivProtocol;

        let engine_id = decode_hex("000000000000000000000002").unwrap();
        let master_keys = MasterKeys::new(AuthProtocol::Sha256, b"authpassword")
            .with_privacy(PrivProtocol::Aes128, b"privpassword");

        let (_auth_key, priv_key) = master_keys.localize(&engine_id);
        assert!(priv_key.is_some());

        // Verify that different passwords produce different keys
        let same_password_keys = MasterKeys::new(AuthProtocol::Sha256, b"authpassword")
            .with_privacy_same_password(PrivProtocol::Aes128);
        let (_, priv_key_same) = same_password_keys.localize(&engine_id);

        // The priv keys should differ when using different passwords
        // (auth keys are the same since they use same auth password)
        assert_ne!(
            priv_key.as_ref().unwrap().encryption_key(),
            priv_key_same.as_ref().unwrap().encryption_key()
        );
    }
}
