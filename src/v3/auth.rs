//! Authentication key derivation and HMAC operations (RFC 3414).
//!
//! This module implements:
//! - Password-to-key derivation (1MB expansion + hash)
//! - Key localization (binding key to engine ID)
//! - HMAC authentication for message integrity

use digest::{Digest, KeyInit, Mac, OutputSizeUser};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::AuthProtocol;

/// Minimum password length recommended by net-snmp.
///
/// Net-snmp rejects passwords shorter than 8 characters with `USM_PASSWORDTOOSHORT`.
/// While this library accepts shorter passwords for flexibility, applications should
/// enforce this minimum for security.
pub const MIN_PASSWORD_LENGTH: usize = 8;

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
    /// # Empty and Short Passwords
    ///
    /// Empty passwords result in an all-zero key of the appropriate length for
    /// the authentication protocol. This differs from net-snmp, which rejects
    /// passwords shorter than 8 characters with `USM_PASSWORDTOOSHORT`.
    ///
    /// While empty/short passwords are accepted for flexibility, they provide
    /// minimal security. A warning is logged at the `WARN` level when the
    /// password is shorter than [`MIN_PASSWORD_LENGTH`] (8 characters).
    /// Consider enforcing minimum password length in your application if
    /// security is a concern.
    pub fn from_password(protocol: AuthProtocol, password: &[u8], engine_id: &[u8]) -> Self {
        if password.len() < MIN_PASSWORD_LENGTH {
            tracing::warn!(
                password_len = password.len(),
                min_len = MIN_PASSWORD_LENGTH,
                "SNMPv3 password is shorter than recommended minimum; \
                 net-snmp rejects passwords shorter than 8 characters"
            );
        }
        let master_key = password_to_key(protocol, password);
        let localized = localize_key(protocol, &master_key, engine_id);
        Self {
            key: localized,
            protocol,
        }
    }

    /// Derive a localized key from a string password and engine ID.
    ///
    /// This is a convenience method that converts the string to bytes and calls
    /// [`from_password`](Self::from_password).
    pub fn from_str_password(protocol: AuthProtocol, password: &str, engine_id: &[u8]) -> Self {
        Self::from_password(protocol, password.as_bytes(), engine_id)
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
        for i in 0..64 {
            buf[i] = password[password_index];
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
        AuthProtocol::Md5 => compute_hmac_md5(key, data, 12),
        AuthProtocol::Sha1 => compute_hmac_sha1(key, data, 12),
        AuthProtocol::Sha224 => compute_hmac_sha224(key, data, 16),
        AuthProtocol::Sha256 => compute_hmac_sha256(key, data, 24),
        AuthProtocol::Sha384 => compute_hmac_sha384(key, data, 32),
        AuthProtocol::Sha512 => compute_hmac_sha512(key, data, 48),
    }
}

/// Compute HMAC-MD5 and truncate.
fn compute_hmac_md5(key: &[u8], data: &[u8], truncate_len: usize) -> Vec<u8> {
    use hmac::Hmac;
    type HmacMd5 = Hmac<md5::Md5>;

    let mut mac = <HmacMd5 as KeyInit>::new_from_slice(key).expect("HMAC can take key of any size");
    Mac::update(&mut mac, data);
    let result = mac.finalize().into_bytes();
    result[..truncate_len].to_vec()
}

/// Compute HMAC-SHA1 and truncate.
fn compute_hmac_sha1(key: &[u8], data: &[u8], truncate_len: usize) -> Vec<u8> {
    use hmac::Hmac;
    type HmacSha1 = Hmac<sha1::Sha1>;

    let mut mac =
        <HmacSha1 as KeyInit>::new_from_slice(key).expect("HMAC can take key of any size");
    Mac::update(&mut mac, data);
    let result = mac.finalize().into_bytes();
    result[..truncate_len].to_vec()
}

/// Compute HMAC-SHA224 and truncate.
fn compute_hmac_sha224(key: &[u8], data: &[u8], truncate_len: usize) -> Vec<u8> {
    use hmac::Hmac;
    type HmacSha224 = Hmac<sha2::Sha224>;

    let mut mac =
        <HmacSha224 as KeyInit>::new_from_slice(key).expect("HMAC can take key of any size");
    Mac::update(&mut mac, data);
    let result = mac.finalize().into_bytes();
    result[..truncate_len].to_vec()
}

/// Compute HMAC-SHA256 and truncate.
fn compute_hmac_sha256(key: &[u8], data: &[u8], truncate_len: usize) -> Vec<u8> {
    use hmac::Hmac;
    type HmacSha256 = Hmac<sha2::Sha256>;

    let mut mac =
        <HmacSha256 as KeyInit>::new_from_slice(key).expect("HMAC can take key of any size");
    Mac::update(&mut mac, data);
    let result = mac.finalize().into_bytes();
    result[..truncate_len].to_vec()
}

/// Compute HMAC-SHA384 and truncate.
fn compute_hmac_sha384(key: &[u8], data: &[u8], truncate_len: usize) -> Vec<u8> {
    use hmac::Hmac;
    type HmacSha384 = Hmac<sha2::Sha384>;

    let mut mac =
        <HmacSha384 as KeyInit>::new_from_slice(key).expect("HMAC can take key of any size");
    Mac::update(&mut mac, data);
    let result = mac.finalize().into_bytes();
    result[..truncate_len].to_vec()
}

/// Compute HMAC-SHA512 and truncate.
fn compute_hmac_sha512(key: &[u8], data: &[u8], truncate_len: usize) -> Vec<u8> {
    use hmac::Hmac;
    type HmacSha512 = Hmac<sha2::Sha512>;

    let mut mac =
        <HmacSha512 as KeyInit>::new_from_slice(key).expect("HMAC can take key of any size");
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{decode_hex, encode_hex};

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
}
