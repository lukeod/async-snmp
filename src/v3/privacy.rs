//! Privacy (encryption) protocols for SNMPv3 (RFC 3414, RFC 3826).
//!
//! This module implements:
//! - DES-CBC privacy (RFC 3414 Section 8)
//! - AES-128-CFB privacy (RFC 3826)
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

use super::{AuthProtocol, PrivProtocol};
use crate::error::{CryptoErrorKind, Error, Result};

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
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PrivKey {
    /// The localized key bytes
    key: Vec<u8>,
    /// Privacy protocol
    #[zeroize(skip)]
    protocol: PrivProtocol,
    /// Salt counter for generating unique IVs
    /// For thread safety, each PrivKey instance gets its own counter
    #[zeroize(skip)]
    salt_counter: u64,
}

/// Thread-safe salt counter for shared use across multiple encryptions.
pub struct SaltCounter(AtomicU64);

impl SaltCounter {
    /// Create a new salt counter initialized to a pseudo-random value.
    pub fn new() -> Self {
        // Initialize with current time for pseudo-randomness
        let init = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        Self(AtomicU64::new(init))
    }

    /// Get the next salt value and increment the counter.
    pub fn next(&self) -> u64 {
        self.0.fetch_add(1, Ordering::SeqCst)
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
    /// - AES: first 16/24/32 bytes = key (depending on AES variant)
    ///
    /// # Auth/Priv Protocol Compatibility
    ///
    /// The authentication protocol must produce sufficient key material for
    /// the privacy protocol. If not, a warning is logged and the key will
    /// be shorter than required, leading to runtime panics during encryption.
    ///
    /// Use [`AuthProtocol::is_compatible_with`] to check compatibility:
    ///
    /// | Privacy Protocol | Required Auth Protocols |
    /// |------------------|-------------------------|
    /// | DES, AES-128     | Any (MD5+)             |
    /// | AES-192          | SHA-224+               |
    /// | AES-256          | SHA-256+               |
    pub fn from_password(
        auth_protocol: AuthProtocol,
        priv_protocol: PrivProtocol,
        password: &[u8],
        engine_id: &[u8],
    ) -> Self {
        use super::LocalizedKey;

        // Check auth/priv protocol compatibility
        if !auth_protocol.is_compatible_with(priv_protocol) {
            tracing::warn!(
                auth_protocol = ?auth_protocol,
                priv_protocol = ?priv_protocol,
                auth_key_len = auth_protocol.digest_len(),
                required_key_len = priv_protocol.key_len(),
                "authentication protocol produces insufficient key material for privacy protocol; \
                 use SHA-224+ for AES-192, SHA-256+ for AES-256"
            );
        }

        // Use auth protocol for key derivation (per RFC 3826 Section 1.2)
        let localized = LocalizedKey::from_password(auth_protocol, password, engine_id);
        let key = localized.as_bytes().to_vec();

        Self {
            key,
            protocol: priv_protocol,
            salt_counter: Self::init_salt(),
        }
    }

    /// Create a privacy key from raw localized key bytes.
    pub fn from_bytes(protocol: PrivProtocol, key: impl Into<Vec<u8>>) -> Self {
        Self {
            key: key.into(),
            protocol,
            salt_counter: Self::init_salt(),
        }
    }

    /// Initialize salt with pseudo-random value.
    fn init_salt() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }

    /// Get the privacy protocol.
    pub fn protocol(&self) -> PrivProtocol {
        self.protocol
    }

    /// Get the encryption key portion.
    pub fn encryption_key(&self) -> &[u8] {
        match self.protocol {
            PrivProtocol::Des => &self.key[..8],
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
        &mut self,
        plaintext: &[u8],
        engine_boots: u32,
        engine_time: u32,
        salt_counter: Option<&SaltCounter>,
    ) -> Result<(Bytes, Bytes)> {
        let salt = salt_counter.map(|c| c.next()).unwrap_or_else(|| {
            let s = self.salt_counter;
            self.salt_counter = self.salt_counter.wrapping_add(1);
            s
        });

        match self.protocol {
            PrivProtocol::Des => self.encrypt_des(plaintext, engine_boots, salt),
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
    ) -> Result<Bytes> {
        if priv_params.len() != 8 {
            return Err(Error::decrypt(
                None,
                CryptoErrorKind::InvalidPrivParamsLength {
                    expected: 8,
                    actual: priv_params.len(),
                },
            ));
        }

        match self.protocol {
            PrivProtocol::Des => self.decrypt_des(ciphertext, priv_params),
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
    ) -> Result<(Bytes, Bytes)> {
        use cbc::cipher::{BlockEncryptMut, KeyIvInit};
        type DesCbc = cbc::Encryptor<des::Des>;

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
        let pad_len = (8 - (plaintext.len() % 8)) % 8;
        let padded_len = plaintext.len() + if pad_len == 0 { 0 } else { pad_len };
        // DES requires at least some padding if not aligned
        let padded_len = if padded_len == plaintext.len() && !plaintext.len().is_multiple_of(8) {
            plaintext.len() + (8 - plaintext.len() % 8)
        } else {
            padded_len
        };

        let mut buffer = vec![
            0u8;
            if padded_len > plaintext.len() {
                padded_len
            } else {
                plaintext.len() + 8 - (plaintext.len() % 8)
            }
        ];
        let padded_len = buffer.len();
        buffer[..plaintext.len()].copy_from_slice(plaintext);

        // Encrypt in-place
        let cipher = DesCbc::new_from_slices(key, &iv)
            .map_err(|_| Error::encrypt(None, CryptoErrorKind::InvalidKeyLength))?;

        let ciphertext = cipher
            .encrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buffer, padded_len)
            .map_err(|_| Error::encrypt(None, CryptoErrorKind::CipherError))?;

        Ok((
            Bytes::copy_from_slice(ciphertext),
            Bytes::copy_from_slice(&salt),
        ))
    }

    /// DES-CBC decryption (RFC 3414 Section 8.1.1).
    fn decrypt_des(&self, ciphertext: &[u8], priv_params: &[u8]) -> Result<Bytes> {
        use cbc::cipher::{BlockDecryptMut, KeyIvInit};
        type DesCbc = cbc::Decryptor<des::Des>;

        if !ciphertext.len().is_multiple_of(8) {
            return Err(Error::decrypt(
                None,
                CryptoErrorKind::InvalidCiphertextLength {
                    length: ciphertext.len(),
                    block_size: 8,
                },
            ));
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

        // Decrypt
        let cipher = DesCbc::new_from_slices(key, &iv)
            .map_err(|_| Error::decrypt(None, CryptoErrorKind::InvalidKeyLength))?;

        let mut buffer = ciphertext.to_vec();
        let plaintext = cipher
            .decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buffer)
            .map_err(|_| Error::decrypt(None, CryptoErrorKind::CipherError))?;

        Ok(Bytes::copy_from_slice(plaintext))
    }

    /// AES-CFB encryption (RFC 3826 Section 3.1).
    fn encrypt_aes(
        &self,
        plaintext: &[u8],
        engine_boots: u32,
        engine_time: u32,
        salt: u64,
        key_len: usize,
    ) -> Result<(Bytes, Bytes)> {
        use aes::{Aes128, Aes192, Aes256};
        use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};

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

        match key_len {
            16 => {
                type Aes128Cfb = cfb_mode::Encryptor<Aes128>;
                let cipher = Aes128Cfb::new_from_slices(key, &iv)
                    .map_err(|_| Error::encrypt(None, CryptoErrorKind::InvalidKeyLength))?;
                cipher.encrypt(&mut buffer);
            }
            24 => {
                type Aes192Cfb = cfb_mode::Encryptor<Aes192>;
                let cipher = Aes192Cfb::new_from_slices(key, &iv)
                    .map_err(|_| Error::encrypt(None, CryptoErrorKind::InvalidKeyLength))?;
                cipher.encrypt(&mut buffer);
            }
            32 => {
                type Aes256Cfb = cfb_mode::Encryptor<Aes256>;
                let cipher = Aes256Cfb::new_from_slices(key, &iv)
                    .map_err(|_| Error::encrypt(None, CryptoErrorKind::InvalidKeyLength))?;
                cipher.encrypt(&mut buffer);
            }
            _ => {
                return Err(Error::encrypt(None, CryptoErrorKind::UnsupportedProtocol));
            }
        }

        Ok((Bytes::from(buffer), Bytes::copy_from_slice(&salt_bytes)))
    }

    /// AES-CFB decryption (RFC 3826 Section 3.1.4).
    fn decrypt_aes(
        &self,
        ciphertext: &[u8],
        engine_boots: u32,
        engine_time: u32,
        priv_params: &[u8],
    ) -> Result<Bytes> {
        use aes::{Aes128, Aes192, Aes256};
        use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};

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

        match key_len {
            16 => {
                type Aes128Cfb = cfb_mode::Decryptor<Aes128>;
                let cipher = Aes128Cfb::new_from_slices(key, &iv)
                    .map_err(|_| Error::decrypt(None, CryptoErrorKind::InvalidKeyLength))?;
                cipher.decrypt(&mut buffer);
            }
            24 => {
                type Aes192Cfb = cfb_mode::Decryptor<Aes192>;
                let cipher = Aes192Cfb::new_from_slices(key, &iv)
                    .map_err(|_| Error::decrypt(None, CryptoErrorKind::InvalidKeyLength))?;
                cipher.decrypt(&mut buffer);
            }
            32 => {
                type Aes256Cfb = cfb_mode::Decryptor<Aes256>;
                let cipher = Aes256Cfb::new_from_slices(key, &iv)
                    .map_err(|_| Error::decrypt(None, CryptoErrorKind::InvalidKeyLength))?;
                cipher.decrypt(&mut buffer);
            }
            _ => {
                return Err(Error::decrypt(None, CryptoErrorKind::UnsupportedProtocol));
            }
        }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::decode_hex;

    #[test]
    fn test_des_encrypt_decrypt_roundtrip() {
        // Create a 16-byte key (8 for DES, 8 for pre-IV)
        let key = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // DES key
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, // pre-IV
        ];
        let mut priv_key = PrivKey::from_bytes(PrivProtocol::Des, key);

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

    #[test]
    fn test_aes128_encrypt_decrypt_roundtrip() {
        // Create a 16-byte key for AES-128
        let key = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];
        let mut priv_key = PrivKey::from_bytes(PrivProtocol::Aes128, key);

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

    #[test]
    fn test_multiple_encryptions_different_salt() {
        let key = vec![0u8; 16];
        let mut priv_key = PrivKey::from_bytes(PrivProtocol::Aes128, key);

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

        let mut priv_key = PrivKey::from_password(
            AuthProtocol::Sha1,
            PrivProtocol::Aes128,
            password,
            &engine_id,
        );

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
        let mut priv_key = PrivKey::from_bytes(PrivProtocol::Aes192, key);

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
        let mut priv_key = PrivKey::from_bytes(PrivProtocol::Aes256, key);

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

        let mut priv_key = PrivKey::from_password(
            AuthProtocol::Sha256, // SHA-256 produces 32 bytes, enough for AES-192
            PrivProtocol::Aes192,
            password,
            &engine_id,
        );

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

        let mut priv_key = PrivKey::from_password(
            AuthProtocol::Sha256, // SHA-256 produces 32 bytes, exactly enough for AES-256
            PrivProtocol::Aes256,
            password,
            &engine_id,
        );

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

        let mut correct_priv_key = PrivKey::from_bytes(PrivProtocol::Des, correct_key);
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

        let mut correct_priv_key = PrivKey::from_bytes(PrivProtocol::Aes128, correct_key);
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

        let mut correct_priv_key = PrivKey::from_bytes(PrivProtocol::Aes192, correct_key);
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

        let mut correct_priv_key = PrivKey::from_bytes(PrivProtocol::Aes256, correct_key);
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

    #[test]
    fn test_des_wrong_priv_params_produces_garbage() {
        // Verify that even with the correct key, wrong priv_params (salt/IV)
        // produces garbage. This tests the IV derivation logic.
        let key = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
            0x17, 0x18,
        ];

        let mut priv_key = PrivKey::from_bytes(PrivProtocol::Des, key);

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

    #[test]
    fn test_aes_wrong_engine_time_produces_garbage() {
        // For AES, the IV includes engine_boots and engine_time.
        // Wrong values should produce garbage.
        let key = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ];

        let mut priv_key = PrivKey::from_bytes(PrivProtocol::Aes128, key);

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
