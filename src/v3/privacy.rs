//! Privacy (encryption) protocols for SNMPv3 (RFC 3414, RFC 3826).
//!
//! This module implements:
//! - DES-CBC privacy (RFC 3414 Section 8)
//! - AES-128-CFB privacy (RFC 3826)
//! - AES-192-CFB privacy (RFC 3826)
//! - AES-256-CFB privacy (RFC 3826)
//!
//! # Salt/IV Construction
//!
//! ## DES-CBC
//! - Salt (privParameters): engineBoots (4 bytes) || counter (4 bytes) = 8 bytes
//! - IV: pre-IV XOR salt (pre-IV is last 8 bytes of 16-byte privKey)
//!
//! ## AES-CFB-128
//! - Salt (privParameters): 64-bit counter = 8 bytes
//! - IV: engineBoots (4 bytes) || engineTime (4 bytes) || salt (8 bytes) = 16 bytes
//!   (concatenation, NOT XOR)

use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::crypto::{CryptoError, CryptoProvider};
use super::{AuthProtocol, PrivProtocol};

/// Error type for privacy (encryption/decryption) operations.
///
/// These errors indicate cryptographic failures. Callers should convert
/// these to `Error::Auth` with appropriate target context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivacyError {
    /// Invalid privParameters length (expected 8 bytes).
    InvalidPrivParamsLength { expected: usize, actual: usize },
    /// Ciphertext length not a multiple of block size.
    InvalidCiphertextLength { length: usize, block_size: usize },
    /// Cryptographic provider error (unsupported algorithm, invalid key, cipher failure).
    Crypto(CryptoError),
}

impl From<CryptoError> for PrivacyError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}

impl std::fmt::Display for PrivacyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPrivParamsLength { expected, actual } => {
                write!(
                    f,
                    "invalid privParameters length: expected {}, got {}",
                    expected, actual
                )
            }
            Self::InvalidCiphertextLength { length, block_size } => {
                write!(
                    f,
                    "ciphertext length {} not multiple of block size {}",
                    length, block_size
                )
            }
            Self::Crypto(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for PrivacyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Crypto(e) => Some(e),
            _ => None,
        }
    }
}

/// Result type for privacy operations.
pub type PrivacyResult<T> = std::result::Result<T, PrivacyError>;

/// Generate a random non-zero u64 for salt initialization.
///
/// Uses the OS cryptographic random source via `getrandom`.
fn random_nonzero_u64() -> u64 {
    let mut buf = [0u8; 8];
    loop {
        getrandom::fill(&mut buf).expect("getrandom failed");
        let val = u64::from_ne_bytes(buf);
        if val != 0 {
            return val;
        }
        // Extremely unlikely (1 in 2^64), but loop if we got zero
    }
}

/// Privacy key for encryption/decryption operations.
///
/// Derives encryption keys from a password and engine ID using the same
/// process as authentication keys, then uses the appropriate portion
/// based on the privacy protocol.
///
/// # Security
///
/// Key material is automatically zeroed from memory when the key is dropped,
/// using the `zeroize` crate. This provides defense-in-depth against memory
/// scraping attacks.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PrivKey {
    /// The localized key bytes
    key: Vec<u8>,
    /// Privacy protocol
    #[zeroize(skip)]
    protocol: PrivProtocol,
    /// Salt counter for generating unique IVs.
    /// Uses interior mutability so encrypt() can take &self.
    #[zeroize(skip)]
    salt_counter: AtomicU64,
}

/// Thread-safe salt counter for shared use across multiple encryptions.
pub struct SaltCounter(AtomicU64);

impl SaltCounter {
    /// Create a new salt counter initialized from cryptographic randomness.
    pub fn new() -> Self {
        Self(AtomicU64::new(random_nonzero_u64()))
    }

    /// Create a salt counter initialized to a specific value.
    ///
    /// This is primarily for testing purposes.
    pub fn from_value(value: u64) -> Self {
        Self(AtomicU64::new(value))
    }

    /// Get the next salt value and increment the counter.
    ///
    /// This method never returns zero. Per net-snmp behavior, zero is skipped
    /// on wraparound to avoid potential IV reuse issues.
    ///
    /// Uses the post-increment value as the salt and a single compare_exchange
    /// to skip zero atomically, avoiding the two-fetch_add race that could
    /// cause IV reuse under concurrent access.
    pub fn next(&self) -> u64 {
        let old = self.0.fetch_add(1, Ordering::SeqCst);
        let val = old.wrapping_add(1);
        if val != 0 {
            return val;
        }
        // Counter wrapped to zero. Only one thread reaches here (only one fetch_add
        // returns u64::MAX). Atomically advance from 0 to 1, then return 1.
        let _ = self
            .0
            .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst);
        1
    }
}

impl Default for SaltCounter {
    fn default() -> Self {
        Self::new()
    }
}

impl PrivKey {
    /// Derive a privacy key from a password and engine ID.
    ///
    /// The key derivation uses the same algorithm as authentication keys
    /// (RFC 3414 A.2), but the resulting key is used differently:
    /// - DES: first 8 bytes = key, last 8 bytes = pre-IV
    /// - 3DES: first 24 bytes = key, last 8 bytes = pre-IV
    /// - AES: first 16/24/32 bytes = key (depending on AES variant)
    ///
    /// Key extension is automatically applied when needed based on the auth/priv
    /// protocol combination:
    ///
    /// - AES-192/256 with SHA-1 or MD5: Blumenthal extension (draft-blumenthal-aes-usm-04)
    /// - 3DES with SHA-1 or MD5: Reeder extension (draft-reeder-snmpv3-usm-3desede-00)
    ///
    /// # Performance Note
    ///
    /// This method performs the full key derivation (~850μs for SHA-256). When
    /// polling many engines with shared credentials, use [`MasterKey`](super::MasterKey)
    /// and call [`PrivKey::from_master_key`] for each engine.
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_snmp::{AuthProtocol, PrivProtocol, v3::PrivKey};
    ///
    /// let engine_id = [0x80, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04];
    ///
    /// // SHA-1 only produces 20 bytes, but AES-256 needs 32.
    /// // Blumenthal extension is automatically applied.
    /// let priv_key = PrivKey::from_password(
    ///     AuthProtocol::Sha1,
    ///     PrivProtocol::Aes256,
    ///     b"password",
    ///     &engine_id,
    /// ).unwrap();
    /// ```
    pub fn from_password(
        auth_protocol: AuthProtocol,
        priv_protocol: PrivProtocol,
        password: &[u8],
        engine_id: &[u8],
    ) -> super::crypto::CryptoResult<Self> {
        use super::MasterKey;

        let master = MasterKey::from_password(auth_protocol, password)?;
        Self::from_master_key(&master, priv_protocol, engine_id)
    }

    /// Derive a privacy key from a master key and engine ID.
    ///
    /// This is the efficient path when you have a cached [`MasterKey`](super::MasterKey).
    /// Key extension is automatically applied when needed based on the auth/priv
    /// protocol combination:
    ///
    /// - AES-192/256 with SHA-1 or MD5: Blumenthal extension (draft-blumenthal-aes-usm-04)
    /// - 3DES with SHA-1 or MD5: Reeder extension (draft-reeder-snmpv3-usm-3desede-00)
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_snmp::{AuthProtocol, MasterKey, PrivProtocol, v3::PrivKey};
    ///
    /// let master = MasterKey::from_password(AuthProtocol::Sha1, b"password").unwrap();
    /// let engine_id = [0x80, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04];
    ///
    /// // SHA-1 only produces 20 bytes, but AES-256 needs 32.
    /// // Blumenthal extension is automatically applied.
    /// let priv_key = PrivKey::from_master_key(&master, PrivProtocol::Aes256, &engine_id).unwrap();
    /// ```
    pub fn from_master_key(
        master: &super::MasterKey,
        priv_protocol: PrivProtocol,
        engine_id: &[u8],
    ) -> super::crypto::CryptoResult<Self> {
        use super::{
            KeyExtension,
            auth::{extend_key, extend_key_reeder},
        };

        let auth_protocol = master.protocol();
        let key_extension = priv_protocol.key_extension_for(auth_protocol);

        // Localize the master key (per RFC 3826 Section 1.2)
        let localized = master.localize(engine_id)?;
        let key_bytes = localized.as_bytes();

        let key = match key_extension {
            KeyExtension::None => key_bytes.to_vec(),
            KeyExtension::Blumenthal => {
                extend_key(auth_protocol, key_bytes, priv_protocol.key_len())?
            }
            KeyExtension::Reeder => {
                extend_key_reeder(auth_protocol, key_bytes, engine_id, priv_protocol.key_len())?
            }
        };

        Ok(Self {
            key,
            protocol: priv_protocol,
            salt_counter: Self::init_salt(),
        })
    }

    /// Create a privacy key from raw localized key bytes.
    pub fn from_bytes(protocol: PrivProtocol, key: impl Into<Vec<u8>>) -> Self {
        Self {
            key: key.into(),
            protocol,
            salt_counter: Self::init_salt(),
        }
    }

    /// Initialize salt counter from cryptographic randomness.
    ///
    /// Never returns zero to avoid IV reuse issues on wraparound.
    fn init_salt() -> AtomicU64 {
        AtomicU64::new(random_nonzero_u64())
    }

    /// Get the privacy protocol.
    pub fn protocol(&self) -> PrivProtocol {
        self.protocol
    }

    /// Get the encryption key portion.
    pub fn encryption_key(&self) -> &[u8] {
        match self.protocol {
            PrivProtocol::Des => &self.key[..8],
            PrivProtocol::Des3 => &self.key[..24],
            PrivProtocol::Aes128 => &self.key[..16],
            PrivProtocol::Aes192 => &self.key[..24],
            PrivProtocol::Aes256 => &self.key[..32],
        }
    }

    /// Encrypt data and return (ciphertext, privParameters).
    ///
    /// # Arguments
    /// * `plaintext` - The data to encrypt (typically the serialized ScopedPDU)
    /// * `engine_boots` - The authoritative engine's boot count
    /// * `engine_time` - The authoritative engine's time
    /// * `salt_counter` - Optional shared salt counter; if None, uses internal counter
    ///
    /// # Returns
    /// * `Ok((ciphertext, priv_params))` on success
    /// * `Err` on encryption failure
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        engine_boots: u32,
        engine_time: u32,
        salt_counter: Option<&SaltCounter>,
    ) -> PrivacyResult<(Bytes, Bytes)> {
        let salt = salt_counter.map(|c| c.next()).unwrap_or_else(|| {
            // Fetch the current value, then increment. Skip zero.
            let val = self.salt_counter.fetch_add(1, Ordering::Relaxed);
            if val != 0 {
                return val;
            }
            // Counter was zero (initial or wrapped). Fetch the next value.
            self.salt_counter.fetch_add(1, Ordering::Relaxed)
        });

        match self.protocol {
            PrivProtocol::Des => self.encrypt_des(plaintext, engine_boots, salt),
            PrivProtocol::Des3 => self.encrypt_des3(plaintext, engine_boots, salt),
            PrivProtocol::Aes128 => {
                self.encrypt_aes(plaintext, engine_boots, engine_time, salt, 16)
            }
            PrivProtocol::Aes192 => {
                self.encrypt_aes(plaintext, engine_boots, engine_time, salt, 24)
            }
            PrivProtocol::Aes256 => {
                self.encrypt_aes(plaintext, engine_boots, engine_time, salt, 32)
            }
        }
    }

    /// Decrypt data using the privParameters from the message.
    ///
    /// # Arguments
    /// * `ciphertext` - The encrypted data
    /// * `engine_boots` - The authoritative engine's boot count (from message)
    /// * `engine_time` - The authoritative engine's time (from message)
    /// * `priv_params` - The privParameters field from the message
    ///
    /// # Returns
    /// * `Ok(plaintext)` on success
    /// * `Err` on decryption failure
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        engine_boots: u32,
        engine_time: u32,
        priv_params: &[u8],
    ) -> PrivacyResult<Bytes> {
        if priv_params.len() != 8 {
            tracing::debug!(target: "async_snmp::crypto", { expected = 8, actual = priv_params.len() }, "invalid privParameters length");
            return Err(PrivacyError::InvalidPrivParamsLength {
                expected: 8,
                actual: priv_params.len(),
            });
        }

        match self.protocol {
            PrivProtocol::Des => self.decrypt_des(ciphertext, priv_params),
            PrivProtocol::Des3 => self.decrypt_des3(ciphertext, priv_params),
            PrivProtocol::Aes128 | PrivProtocol::Aes192 | PrivProtocol::Aes256 => {
                self.decrypt_aes(ciphertext, engine_boots, engine_time, priv_params)
            }
        }
    }

    /// DES-CBC encryption (RFC 3414 Section 8.1.1).
    fn encrypt_des(
        &self,
        plaintext: &[u8],
        engine_boots: u32,
        salt_int: u64,
    ) -> PrivacyResult<(Bytes, Bytes)> {
        // DES key is first 8 bytes
        let key = &self.key[..8];
        // Pre-IV is last 8 bytes of 16-byte privKey
        let pre_iv = &self.key[8..16];

        // Salt = engineBoots (4 bytes MSB) || counter (4 bytes MSB)
        // We use the lower 32 bits of salt_int as the counter
        let mut salt = [0u8; 8];
        salt[..4].copy_from_slice(&engine_boots.to_be_bytes());
        salt[4..].copy_from_slice(&(salt_int as u32).to_be_bytes());

        // IV = pre-IV XOR salt
        let mut iv = [0u8; 8];
        for i in 0..8 {
            iv[i] = pre_iv[i] ^ salt[i];
        }

        // Pad plaintext to multiple of 8 bytes
        let padded_len = plaintext.len().next_multiple_of(8);
        let mut buffer = vec![0u8; padded_len];
        buffer[..plaintext.len()].copy_from_slice(plaintext);

        super::crypto::provider().encrypt(PrivProtocol::Des, key, &iv, &mut buffer)?;

        Ok((Bytes::from(buffer), Bytes::copy_from_slice(&salt)))
    }

    /// DES-CBC decryption (RFC 3414 Section 8.1.1).
    fn decrypt_des(&self, ciphertext: &[u8], priv_params: &[u8]) -> PrivacyResult<Bytes> {
        if !ciphertext.len().is_multiple_of(8) {
            tracing::debug!(target: "async_snmp::crypto", { length = ciphertext.len(), block_size = 8 }, "DES decryption failed: invalid ciphertext length");
            return Err(PrivacyError::InvalidCiphertextLength {
                length: ciphertext.len(),
                block_size: 8,
            });
        }

        // DES key is first 8 bytes
        let key = &self.key[..8];
        // Pre-IV is last 8 bytes of 16-byte privKey
        let pre_iv = &self.key[8..16];

        // Salt is the privParameters
        let salt = priv_params;

        // IV = pre-IV XOR salt
        let mut iv = [0u8; 8];
        for i in 0..8 {
            iv[i] = pre_iv[i] ^ salt[i];
        }

        let mut buffer = ciphertext.to_vec();
        super::crypto::provider().decrypt(PrivProtocol::Des, key, &iv, &mut buffer)?;

        Ok(Bytes::from(buffer))
    }

    /// 3DES-EDE CBC encryption (draft-reeder-snmpv3-usm-3desede-00 Section 5.1.1.2).
    fn encrypt_des3(
        &self,
        plaintext: &[u8],
        engine_boots: u32,
        salt_int: u64,
    ) -> PrivacyResult<(Bytes, Bytes)> {
        // 3DES key is first 24 bytes (K1, K2, K3)
        let key = &self.key[..24];
        // Pre-IV is bytes 24-31 of the 32-byte privKey
        let pre_iv = &self.key[24..32];

        // Salt = engineBoots (4 bytes MSB) || counter (4 bytes MSB)
        let mut salt = [0u8; 8];
        salt[..4].copy_from_slice(&engine_boots.to_be_bytes());
        salt[4..].copy_from_slice(&(salt_int as u32).to_be_bytes());

        // IV = pre-IV XOR salt
        let mut iv = [0u8; 8];
        for i in 0..8 {
            iv[i] = pre_iv[i] ^ salt[i];
        }

        // Pad plaintext to multiple of 8 bytes
        let padded_len = plaintext.len().next_multiple_of(8);
        let mut buffer = vec![0u8; padded_len];
        buffer[..plaintext.len()].copy_from_slice(plaintext);

        super::crypto::provider().encrypt(PrivProtocol::Des3, key, &iv, &mut buffer)?;

        Ok((Bytes::from(buffer), Bytes::copy_from_slice(&salt)))
    }

    /// 3DES-EDE CBC decryption (draft-reeder-snmpv3-usm-3desede-00 Section 5.1.1.3).
    fn decrypt_des3(&self, ciphertext: &[u8], priv_params: &[u8]) -> PrivacyResult<Bytes> {
        if !ciphertext.len().is_multiple_of(8) {
            tracing::debug!(target: "async_snmp::crypto", { length = ciphertext.len(), block_size = 8 }, "3DES decryption failed: invalid ciphertext length");
            return Err(PrivacyError::InvalidCiphertextLength {
                length: ciphertext.len(),
                block_size: 8,
            });
        }

        // 3DES key is first 24 bytes (K1, K2, K3)
        let key = &self.key[..24];
        // Pre-IV is bytes 24-31 of the 32-byte privKey
        let pre_iv = &self.key[24..32];

        // Salt is the privParameters
        let salt = priv_params;

        // IV = pre-IV XOR salt
        let mut iv = [0u8; 8];
        for i in 0..8 {
            iv[i] = pre_iv[i] ^ salt[i];
        }

        let mut buffer = ciphertext.to_vec();
        super::crypto::provider().decrypt(PrivProtocol::Des3, key, &iv, &mut buffer)?;

        Ok(Bytes::from(buffer))
    }

    /// AES-CFB encryption (RFC 3826 Section 3.1).
    fn encrypt_aes(
        &self,
        plaintext: &[u8],
        engine_boots: u32,
        engine_time: u32,
        salt: u64,
        key_len: usize,
    ) -> PrivacyResult<(Bytes, Bytes)> {
        // AES key is first key_len bytes
        let key = &self.key[..key_len];

        // Salt as 8 bytes (big-endian)
        let salt_bytes = salt.to_be_bytes();

        // IV = engineBoots (4) || engineTime (4) || salt (8) = 16 bytes
        // This is CONCATENATION, not XOR (unlike DES)
        let mut iv = [0u8; 16];
        iv[..4].copy_from_slice(&engine_boots.to_be_bytes());
        iv[4..8].copy_from_slice(&engine_time.to_be_bytes());
        iv[8..].copy_from_slice(&salt_bytes);

        let mut buffer = plaintext.to_vec();
        super::crypto::provider().encrypt(self.protocol, key, &iv, &mut buffer)?;

        Ok((Bytes::from(buffer), Bytes::copy_from_slice(&salt_bytes)))
    }

    /// AES-CFB decryption (RFC 3826 Section 3.1.4).
    fn decrypt_aes(
        &self,
        ciphertext: &[u8],
        engine_boots: u32,
        engine_time: u32,
        priv_params: &[u8],
    ) -> PrivacyResult<Bytes> {
        let key_len = match self.protocol {
            PrivProtocol::Aes128 => 16,
            PrivProtocol::Aes192 => 24,
            PrivProtocol::Aes256 => 32,
            _ => unreachable!(),
        };

        // AES key is first key_len bytes
        let key = &self.key[..key_len];

        // IV = engineBoots (4) || engineTime (4) || salt (8) = 16 bytes
        let mut iv = [0u8; 16];
        iv[..4].copy_from_slice(&engine_boots.to_be_bytes());
        iv[4..8].copy_from_slice(&engine_time.to_be_bytes());
        iv[8..].copy_from_slice(priv_params);

        let mut buffer = ciphertext.to_vec();
        super::crypto::provider().decrypt(self.protocol, key, &iv, &mut buffer)?;

        Ok(Bytes::from(buffer))
    }
}

impl std::fmt::Debug for PrivKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivKey")
            .field("protocol", &self.protocol)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl Clone for PrivKey {
    fn clone(&self) -> Self {
        Self {
            key: self.key.clone(),
            protocol: self.protocol,
            // Fresh counter so the clone does not replay the same salt sequence.
            salt_counter: Self::init_salt(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::hex::decode as decode_hex;

    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn test_des_encrypt_decrypt_roundtrip() {
        // Create a 16-byte key (8 for DES, 8 for pre-IV)
        let key = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // DES key
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, // pre-IV
        ];
        let priv_key = PrivKey::from_bytes(PrivProtocol::Des, key);

        let plaintext = b"Hello, SNMPv3 World!";
        let engine_boots = 100u32;
        let engine_time = 12345u32;

        let (ciphertext, priv_params) = priv_key
            .encrypt(plaintext, engine_boots, engine_time, None)
            .expect("encryption failed");

        // Verify ciphertext is different from plaintext
        assert_ne!(ciphertext.as_ref(), plaintext);
        // Verify priv_params is 8 bytes
        assert_eq!(priv_params.len(), 8);

        // Decrypt
        let decrypted = priv_key
            .decrypt(&ciphertext, engine_boots, engine_time, &priv_params)
            .expect("decryption failed");

        // DES pads to 8-byte boundary, so decrypted may be longer
        assert!(decrypted.len() >= plaintext.len());
        assert_eq!(&decrypted[..plaintext.len()], plaintext);
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn test_des3_encrypt_decrypt_roundtrip() {
        // Create a 32-byte key (24 for 3DES, 8 for pre-IV)
        let key = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // K1
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, // K2
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, // K3
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, // pre-IV
        ];
        let priv_key = PrivKey::from_bytes(PrivProtocol::Des3, key);

        let plaintext = b"Hello, SNMPv3 World with 3DES!";
        let engine_boots = 100u32;
        let engine_time = 12345u32;

        let (ciphertext, priv_params) = priv_key
            .encrypt(plaintext, engine_boots, engine_time, None)
            .expect("encryption failed");

        // Verify ciphertext is different from plaintext
        assert_ne!(ciphertext.as_ref(), plaintext);
        // Verify priv_params is 8 bytes
        assert_eq!(priv_params.len(), 8);

        // Decrypt
        let decrypted = priv_key
            .decrypt(&ciphertext, engine_boots, engine_time, &priv_params)
            .expect("decryption failed");

        // 3DES pads to 8-byte boundary, so decrypted may be longer
        assert!(decrypted.len() >= plaintext.len());
        assert_eq!(&decrypted[..plaintext.len()], plaintext);
    }

    #[test]
    fn test_aes128_encrypt_decrypt_roundtrip() {
        // Create a 16-byte key for AES-128
        let key = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let priv_key = PrivKey::from_bytes(PrivProtocol::Aes128, key);

        let plaintext = b"Hello, SNMPv3 AES World!";
        let engine_boots = 200u32;
        let engine_time = 54321u32;

        let (ciphertext, priv_params) = priv_key
            .encrypt(plaintext, engine_boots, engine_time, None)
            .expect("encryption failed");

        // Verify ciphertext is different from plaintext
        assert_ne!(ciphertext.as_ref(), plaintext);
        // Verify priv_params is 8 bytes (salt)
        assert_eq!(priv_params.len(), 8);

        // Decrypt
        let decrypted = priv_key
            .decrypt(&ciphertext, engine_boots, engine_time, &priv_params)
            .expect("decryption failed");

        // AES-CFB doesn't require padding, so lengths should match
        assert_eq!(decrypted.len(), plaintext.len());
        assert_eq!(decrypted.as_ref(), plaintext);
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn test_des_invalid_ciphertext_length() {
        let key = vec![0u8; 16];
        let priv_key = PrivKey::from_bytes(PrivProtocol::Des, key);

        // Ciphertext not multiple of 8
        let ciphertext = [0u8; 13];
        let priv_params = [0u8; 8];

        let result = priv_key.decrypt(&ciphertext, 0, 0, &priv_params);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_priv_params_length() {
        let key = vec![0u8; 16];
        let priv_key = PrivKey::from_bytes(PrivProtocol::Aes128, key);

        // priv_params should be 8 bytes
        let ciphertext = [0u8; 16];
        let priv_params = [0u8; 4]; // Wrong length

        let result = priv_key.decrypt(&ciphertext, 0, 0, &priv_params);
        assert!(result.is_err());
    }

    #[test]
    fn test_salt_counter() {
        let counter = SaltCounter::new();
        let s1 = counter.next();
        let s2 = counter.next();
        let s3 = counter.next();

        // Each call should increment
        assert_eq!(s2, s1.wrapping_add(1));
        assert_eq!(s3, s2.wrapping_add(1));
    }

    /// Test that SaltCounter never returns zero.
    ///
    /// Per net-snmp behavior (snmpusm.c:1319-1320), zero salt values should be
    /// skipped to avoid potential IV reuse issues on wraparound.
    #[test]
    fn test_salt_counter_skips_zero() {
        // Create a counter initialized to u64::MAX - 1 so the next call wraps through MAX.
        // next() returns post-increment, so:
        //   call 1: old=MAX-1, val=MAX, returns MAX
        //   call 2: old=MAX,   val=0 (wrapped), skips 0, returns 1
        //   call 3: old=1,     val=2, returns 2
        let counter = SaltCounter::from_value(u64::MAX - 1);

        let s1 = counter.next();
        assert_eq!(s1, u64::MAX);

        // This call wraps to zero; should skip and return 1
        let s2 = counter.next();
        assert_ne!(s2, 0, "SaltCounter should never return zero");
        assert_eq!(s2, 1, "SaltCounter should skip 0 and return 1");

        // Subsequent calls should continue normally
        let s3 = counter.next();
        assert_eq!(s3, 2);
    }

    /// Test that PrivKey's internal salt counter never produces zero.
    ///
    /// When using the internal counter (not a shared SaltCounter), the salt
    /// should also skip zero on wraparound.
    #[test]
    fn test_priv_key_internal_salt_skips_zero() {
        let key = vec![0u8; 16];
        let priv_key = PrivKey::from_bytes(PrivProtocol::Aes128, key);

        // Set the internal counter to u64::MAX
        priv_key.salt_counter.store(u64::MAX, Ordering::Relaxed);

        let plaintext = b"test";

        // First encryption uses u64::MAX
        let (_, salt1) = priv_key.encrypt(plaintext, 0, 0, None).unwrap();
        assert_eq!(
            u64::from_be_bytes(salt1.as_ref().try_into().unwrap()),
            u64::MAX
        );

        // Second encryption should skip 0 and use 1
        let (_, salt2) = priv_key.encrypt(plaintext, 0, 0, None).unwrap();
        let salt2_value = u64::from_be_bytes(salt2.as_ref().try_into().unwrap());
        assert_ne!(salt2_value, 0, "Salt should never be zero");
        assert_eq!(salt2_value, 1, "Salt should skip 0 and be 1");

        // Third encryption should use 2
        let (_, salt3) = priv_key.encrypt(plaintext, 0, 0, None).unwrap();
        let salt3_value = u64::from_be_bytes(salt3.as_ref().try_into().unwrap());
        assert_eq!(salt3_value, 2);
    }

    #[test]
    fn test_multiple_encryptions_different_salt() {
        let key = vec![0u8; 16];
        let priv_key = PrivKey::from_bytes(PrivProtocol::Aes128, key);

        let plaintext = b"test data";

        let (_, salt1) = priv_key.encrypt(plaintext, 0, 0, None).unwrap();
        let (_, salt2) = priv_key.encrypt(plaintext, 0, 0, None).unwrap();

        // Salts should be different for each encryption
        assert_ne!(salt1, salt2);
    }

    #[test]
    fn test_from_password() {
        // Test that we can derive a privacy key from a password
        let password = b"maplesyrup";
        let engine_id = decode_hex("000000000000000000000002").unwrap();

        let priv_key = PrivKey::from_password(
            AuthProtocol::Sha1,
            PrivProtocol::Aes128,
            password,
            &engine_id,
        )
        .unwrap();

        // Just verify we can encrypt/decrypt with the derived key
        let plaintext = b"test message";
        let (ciphertext, priv_params) = priv_key.encrypt(plaintext, 100, 200, None).unwrap();
        let decrypted = priv_key
            .decrypt(&ciphertext, 100, 200, &priv_params)
            .unwrap();

        assert_eq!(decrypted.as_ref(), plaintext);
    }

    #[test]
    fn test_aes192_encrypt_decrypt_roundtrip() {
        // Create a 24-byte key for AES-192
        let key = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        ];
        let priv_key = PrivKey::from_bytes(PrivProtocol::Aes192, key);

        let plaintext = b"Hello, SNMPv3 AES-192 World!";
        let engine_boots = 300u32;
        let engine_time = 67890u32;

        let (ciphertext, priv_params) = priv_key
            .encrypt(plaintext, engine_boots, engine_time, None)
            .expect("AES-192 encryption failed");

        // Verify ciphertext is different from plaintext
        assert_ne!(ciphertext.as_ref(), plaintext);
        // Verify priv_params is 8 bytes (salt)
        assert_eq!(priv_params.len(), 8);

        // Decrypt
        let decrypted = priv_key
            .decrypt(&ciphertext, engine_boots, engine_time, &priv_params)
            .expect("AES-192 decryption failed");

        // AES-CFB doesn't require padding, so lengths should match
        assert_eq!(decrypted.len(), plaintext.len());
        assert_eq!(decrypted.as_ref(), plaintext);
    }

    #[test]
    fn test_aes256_encrypt_decrypt_roundtrip() {
        // Create a 32-byte key for AES-256
        let key = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let priv_key = PrivKey::from_bytes(PrivProtocol::Aes256, key);

        let plaintext = b"Hello, SNMPv3 AES-256 World!";
        let engine_boots = 400u32;
        let engine_time = 11111u32;

        let (ciphertext, priv_params) = priv_key
            .encrypt(plaintext, engine_boots, engine_time, None)
            .expect("AES-256 encryption failed");

        // Verify ciphertext is different from plaintext
        assert_ne!(ciphertext.as_ref(), plaintext);
        // Verify priv_params is 8 bytes (salt)
        assert_eq!(priv_params.len(), 8);

        // Decrypt
        let decrypted = priv_key
            .decrypt(&ciphertext, engine_boots, engine_time, &priv_params)
            .expect("AES-256 decryption failed");

        // AES-CFB doesn't require padding, so lengths should match
        assert_eq!(decrypted.len(), plaintext.len());
        assert_eq!(decrypted.as_ref(), plaintext);
    }

    #[test]
    fn test_aes192_from_password() {
        // For AES-192 (24-byte key), we need SHA-224 or higher auth protocol
        let password = b"longpassword123";
        let engine_id = decode_hex("80001f8880e9b104617361000000").unwrap();

        let priv_key = PrivKey::from_password(
            AuthProtocol::Sha256, // SHA-256 produces 32 bytes, enough for AES-192
            PrivProtocol::Aes192,
            password,
            &engine_id,
        )
        .unwrap();

        let plaintext = b"test message for AES-192";
        let (ciphertext, priv_params) = priv_key.encrypt(plaintext, 100, 200, None).unwrap();
        let decrypted = priv_key
            .decrypt(&ciphertext, 100, 200, &priv_params)
            .unwrap();

        assert_eq!(decrypted.as_ref(), plaintext);
    }

    #[test]
    fn test_aes256_from_password() {
        // For AES-256 (32-byte key), we need SHA-256 or higher auth protocol
        let password = b"anotherlongpassword456";
        let engine_id = decode_hex("80001f8880e9b104617361000000").unwrap();

        let priv_key = PrivKey::from_password(
            AuthProtocol::Sha256, // SHA-256 produces 32 bytes, exactly enough for AES-256
            PrivProtocol::Aes256,
            password,
            &engine_id,
        )
        .unwrap();

        let plaintext = b"test message for AES-256";
        let (ciphertext, priv_params) = priv_key.encrypt(plaintext, 100, 200, None).unwrap();
        let decrypted = priv_key
            .decrypt(&ciphertext, 100, 200, &priv_params)
            .unwrap();

        assert_eq!(decrypted.as_ref(), plaintext);
    }

    // ========================================================================
    // Wrong Key Decryption Tests
    //
    // These tests verify that decryption with the wrong key produces garbage,
    // not the original plaintext. Note: Stream ciphers like AES-CFB don't return
    // errors on wrong-key decryption - they produce garbage. The authentication
    // layer (HMAC) is what detects tampering/wrong keys in practice (RFC 3414).
    // ========================================================================

    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn test_des_wrong_key_produces_garbage() {
        // Correct 16-byte key
        let correct_key = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
            0x17, 0x18,
        ];
        // Wrong key (different from correct key)
        let wrong_key = vec![
            0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8, 0xE7, 0xE6, 0xE5, 0xE4, 0xE3, 0xE2,
            0xE1, 0xE0,
        ];

        let correct_priv_key = PrivKey::from_bytes(PrivProtocol::Des, correct_key);
        let wrong_priv_key = PrivKey::from_bytes(PrivProtocol::Des, wrong_key);

        let plaintext = b"Secret SNMPv3 message data!";
        let engine_boots = 100u32;
        let engine_time = 12345u32;

        // Encrypt with correct key
        let (ciphertext, priv_params) = correct_priv_key
            .encrypt(plaintext, engine_boots, engine_time, None)
            .expect("encryption failed");

        // Decrypt with wrong key - this will "succeed" but produce garbage
        let wrong_decrypted = wrong_priv_key
            .decrypt(&ciphertext, engine_boots, engine_time, &priv_params)
            .expect("decryption should succeed cryptographically");

        // Verify wrong key produces different output (not the original plaintext)
        assert_ne!(
            &wrong_decrypted[..plaintext.len()],
            plaintext,
            "wrong key should NOT produce the original plaintext"
        );

        // Verify correct key still works
        let correct_decrypted = correct_priv_key
            .decrypt(&ciphertext, engine_boots, engine_time, &priv_params)
            .expect("correct key decryption failed");
        assert_eq!(
            &correct_decrypted[..plaintext.len()],
            plaintext,
            "correct key should produce the original plaintext"
        );
    }

    #[test]
    fn test_aes128_wrong_key_produces_garbage() {
        let correct_key = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let wrong_key = vec![
            0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8, 0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2,
            0xF1, 0xF0,
        ];

        let correct_priv_key = PrivKey::from_bytes(PrivProtocol::Aes128, correct_key);
        let wrong_priv_key = PrivKey::from_bytes(PrivProtocol::Aes128, wrong_key);

        let plaintext = b"Secret AES-128 message data!";
        let engine_boots = 200u32;
        let engine_time = 54321u32;

        // Encrypt with correct key
        let (ciphertext, priv_params) = correct_priv_key
            .encrypt(plaintext, engine_boots, engine_time, None)
            .expect("encryption failed");

        // Decrypt with wrong key
        let wrong_decrypted = wrong_priv_key
            .decrypt(&ciphertext, engine_boots, engine_time, &priv_params)
            .expect("decryption should succeed cryptographically");

        // Wrong key should produce garbage (not the original plaintext)
        assert_ne!(
            wrong_decrypted.as_ref(),
            plaintext,
            "wrong key should NOT produce the original plaintext"
        );

        // Correct key should work
        let correct_decrypted = correct_priv_key
            .decrypt(&ciphertext, engine_boots, engine_time, &priv_params)
            .expect("correct key decryption failed");
        assert_eq!(correct_decrypted.as_ref(), plaintext);
    }

    #[test]
    fn test_aes192_wrong_key_produces_garbage() {
        let correct_key = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        ];
        let wrong_key = vec![
            0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8, 0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2,
            0xF1, 0xF0, 0xEF, 0xEE, 0xED, 0xEC, 0xEB, 0xEA, 0xE9, 0xE8,
        ];

        let correct_priv_key = PrivKey::from_bytes(PrivProtocol::Aes192, correct_key);
        let wrong_priv_key = PrivKey::from_bytes(PrivProtocol::Aes192, wrong_key);

        let plaintext = b"Secret AES-192 message data!";
        let engine_boots = 300u32;
        let engine_time = 67890u32;

        let (ciphertext, priv_params) = correct_priv_key
            .encrypt(plaintext, engine_boots, engine_time, None)
            .expect("encryption failed");

        let wrong_decrypted = wrong_priv_key
            .decrypt(&ciphertext, engine_boots, engine_time, &priv_params)
            .expect("decryption should succeed cryptographically");

        assert_ne!(
            wrong_decrypted.as_ref(),
            plaintext,
            "wrong key should NOT produce the original plaintext"
        );
    }

    #[test]
    fn test_aes256_wrong_key_produces_garbage() {
        let correct_key = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let wrong_key = vec![
            0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8, 0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2,
            0xF1, 0xF0, 0xEF, 0xEE, 0xED, 0xEC, 0xEB, 0xEA, 0xE9, 0xE8, 0xE7, 0xE6, 0xE5, 0xE4,
            0xE3, 0xE2, 0xE1, 0xE0,
        ];

        let correct_priv_key = PrivKey::from_bytes(PrivProtocol::Aes256, correct_key);
        let wrong_priv_key = PrivKey::from_bytes(PrivProtocol::Aes256, wrong_key);

        let plaintext = b"Secret AES-256 message data!";
        let engine_boots = 400u32;
        let engine_time = 11111u32;

        let (ciphertext, priv_params) = correct_priv_key
            .encrypt(plaintext, engine_boots, engine_time, None)
            .expect("encryption failed");

        let wrong_decrypted = wrong_priv_key
            .decrypt(&ciphertext, engine_boots, engine_time, &priv_params)
            .expect("decryption should succeed cryptographically");

        assert_ne!(
            wrong_decrypted.as_ref(),
            plaintext,
            "wrong key should NOT produce the original plaintext"
        );
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn test_des_wrong_priv_params_produces_garbage() {
        // Verify that even with the correct key, wrong priv_params (salt/IV)
        // produces garbage. This tests the IV derivation logic.
        let key = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
            0x17, 0x18,
        ];

        let priv_key = PrivKey::from_bytes(PrivProtocol::Des, key);

        let plaintext = b"DES test message";
        let engine_boots = 100u32;
        let engine_time = 12345u32;

        let (ciphertext, correct_priv_params) = priv_key
            .encrypt(plaintext, engine_boots, engine_time, None)
            .expect("encryption failed");

        // Use wrong priv_params (different salt)
        let wrong_priv_params = [0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88];

        let wrong_decrypted = priv_key
            .decrypt(&ciphertext, engine_boots, engine_time, &wrong_priv_params)
            .expect("decryption should succeed cryptographically");

        // Wrong IV should produce garbage
        assert_ne!(
            &wrong_decrypted[..plaintext.len()],
            plaintext,
            "wrong priv_params should NOT produce the original plaintext"
        );

        // Correct priv_params should work
        let correct_decrypted = priv_key
            .decrypt(&ciphertext, engine_boots, engine_time, &correct_priv_params)
            .expect("correct decryption failed");
        assert_eq!(&correct_decrypted[..plaintext.len()], plaintext);
    }

    /// Test that SaltCounter never emits duplicate salts under concurrent access.
    ///
    /// This is a regression test for the two-fetch_add race where two threads
    /// could both return 1 after a wraparound left the counter at 0.
    #[test]
    fn test_salt_counter_no_duplicates_concurrent() {
        use std::collections::HashSet;
        use std::sync::{Arc, Mutex};
        use std::thread;

        let counter = Arc::new(SaltCounter::new());
        let results = Arc::new(Mutex::new(HashSet::new()));
        let iterations = 10_000usize;
        let threads = 8usize;

        let handles: Vec<_> = (0..threads)
            .map(|_| {
                let counter = Arc::clone(&counter);
                let results = Arc::clone(&results);
                thread::spawn(move || {
                    for _ in 0..iterations {
                        let salt = counter.next();
                        assert_ne!(salt, 0, "SaltCounter must never return zero");
                        let mut set = results.lock().unwrap();
                        assert!(set.insert(salt), "SaltCounter emitted duplicate: {salt}");
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().expect("thread panicked");
        }
    }

    /// Test that a cloned PrivKey starts with an independent salt counter.
    ///
    /// This is a regression test for derive(Clone) copying the salt_counter
    /// field, which caused clones to emit identical salts for their first encryptions.
    #[test]
    fn test_priv_key_clone_independent_salts() {
        let key = vec![0u8; 16];
        let original = PrivKey::from_bytes(PrivProtocol::Aes128, key);
        let cloned = original.clone();

        let plaintext = b"test";

        // Encrypt once with each key; the priv_params (salt) must differ.
        let (_, salt_orig) = original.encrypt(plaintext, 0, 0, None).unwrap();
        let (_, salt_clone) = cloned.encrypt(plaintext, 0, 0, None).unwrap();

        assert_ne!(
            salt_orig, salt_clone,
            "cloned PrivKey must start with an independent salt counter"
        );
    }

    #[test]
    fn test_aes_wrong_engine_time_produces_garbage() {
        // For AES, the IV includes engine_boots and engine_time.
        // Wrong values should produce garbage.
        let key = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];

        let priv_key = PrivKey::from_bytes(PrivProtocol::Aes128, key);

        let plaintext = b"AES test message";
        let engine_boots = 200u32;
        let engine_time = 54321u32;

        let (ciphertext, priv_params) = priv_key
            .encrypt(plaintext, engine_boots, engine_time, None)
            .expect("encryption failed");

        // Decrypt with wrong engine_time (IV mismatch)
        let wrong_decrypted = priv_key
            .decrypt(&ciphertext, engine_boots, engine_time + 1, &priv_params)
            .expect("decryption should succeed cryptographically");

        assert_ne!(
            wrong_decrypted.as_ref(),
            plaintext,
            "wrong engine_time should NOT produce the original plaintext"
        );

        // Decrypt with wrong engine_boots (IV mismatch)
        let wrong_decrypted2 = priv_key
            .decrypt(&ciphertext, engine_boots + 1, engine_time, &priv_params)
            .expect("decryption should succeed cryptographically");

        assert_ne!(
            wrong_decrypted2.as_ref(),
            plaintext,
            "wrong engine_boots should NOT produce the original plaintext"
        );
    }
}
