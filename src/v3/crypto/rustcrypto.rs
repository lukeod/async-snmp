use super::{CryptoError, CryptoProvider, CryptoResult};
use crate::v3::{AuthProtocol, PrivProtocol};

/// Default crypto provider backed by the `RustCrypto` crate ecosystem.
///
/// This is a stateless unit struct that dispatches to the appropriate
/// `RustCrypto` implementations based on the protocol enum values.
pub struct RustCryptoProvider;

// --- Dispatch macro for auth protocol -> concrete hash type ---

macro_rules! dispatch_auth {
    ($protocol:expr, $fn:ident, $($arg:expr),*) => {
        match $protocol {
            AuthProtocol::Md5 => $fn::<md5::Md5>($($arg),*),
            AuthProtocol::Sha1 => $fn::<sha1::Sha1>($($arg),*),
            AuthProtocol::Sha224 => $fn::<sha2::Sha224>($($arg),*),
            AuthProtocol::Sha256 => $fn::<sha2::Sha256>($($arg),*),
            AuthProtocol::Sha384 => $fn::<sha2::Sha384>($($arg),*),
            AuthProtocol::Sha512 => $fn::<sha2::Sha512>($($arg),*),
        }
    };
}

impl CryptoProvider for RustCryptoProvider {
    fn hash(&self, protocol: AuthProtocol, data: &[u8]) -> CryptoResult<Vec<u8>> {
        Ok(dispatch_auth!(protocol, hash_impl, data))
    }

    fn password_to_key(&self, protocol: AuthProtocol, password: &[u8]) -> CryptoResult<Vec<u8>> {
        const EXPANSION_SIZE: usize = 1_048_576; // 1MB
        Ok(dispatch_auth!(
            protocol,
            password_to_key_impl,
            password,
            EXPANSION_SIZE
        ))
    }

    fn localize_key(
        &self,
        protocol: AuthProtocol,
        master_key: &[u8],
        engine_id: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        Ok(dispatch_auth!(
            protocol,
            localize_key_impl,
            master_key,
            engine_id
        ))
    }

    fn compute_hmac(
        &self,
        protocol: AuthProtocol,
        key: &[u8],
        slices: &[&[u8]],
        truncate_len: usize,
    ) -> CryptoResult<Vec<u8>> {
        Ok(dispatch_auth!(
            protocol,
            compute_hmac_impl,
            key,
            slices,
            truncate_len
        ))
    }

    fn encrypt(
        &self,
        protocol: PrivProtocol,
        key: &[u8],
        iv: &[u8],
        data: &mut Vec<u8>,
    ) -> CryptoResult<()> {
        match protocol {
            PrivProtocol::Des | PrivProtocol::Des3 => {
                // RFC 3414 §8.1.1.2: pad to block boundary (PKCS7)
                let block = 8;
                let padded_len = data.len().next_multiple_of(block);
                let pad_byte = (padded_len - data.len()) as u8;
                data.resize(padded_len, pad_byte);
                match protocol {
                    PrivProtocol::Des => encrypt_des_cbc(key, iv, data),
                    _ => encrypt_des3_cbc(key, iv, data),
                }
            }
            PrivProtocol::Aes128 | PrivProtocol::Aes192 | PrivProtocol::Aes256 => {
                encrypt_aes_cfb(key, iv, data)
            }
        }
    }

    fn decrypt(
        &self,
        protocol: PrivProtocol,
        key: &[u8],
        iv: &[u8],
        data: &mut [u8],
    ) -> CryptoResult<()> {
        match protocol {
            PrivProtocol::Des => decrypt_des_cbc(key, iv, data),
            PrivProtocol::Des3 => decrypt_des3_cbc(key, iv, data),
            PrivProtocol::Aes128 | PrivProtocol::Aes192 | PrivProtocol::Aes256 => {
                decrypt_aes_cfb(key, iv, data)
            }
        }
    }
}

// --- Auth primitive implementations ---

use digest::core_api::BlockSizeUser;
use digest::{Digest, KeyInit, Mac, OutputSizeUser};

fn hash_impl<D>(data: &[u8]) -> Vec<u8>
where
    D: Digest + Default,
{
    let mut hasher = D::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

fn password_to_key_impl<D>(password: &[u8], expansion_size: usize) -> Vec<u8>
where
    D: Digest + Default,
{
    if password.is_empty() {
        return vec![0u8; <D as OutputSizeUser>::output_size()];
    }

    let mut hasher = D::new();

    let mut buf = [0u8; 64];
    let password_len = password.len();
    let mut password_index = 0;
    let mut count = 0;

    while count < expansion_size {
        for byte in &mut buf {
            *byte = password[password_index];
            password_index = (password_index + 1) % password_len;
        }
        hasher.update(buf);
        count += 64;
    }

    hasher.finalize().to_vec()
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

fn compute_hmac_impl<D>(key: &[u8], slices: &[&[u8]], truncate_len: usize) -> Vec<u8>
where
    D: Digest + BlockSizeUser + Clone,
{
    use hmac::SimpleHmac;

    let mut mac =
        <SimpleHmac<D> as KeyInit>::new_from_slice(key).expect("HMAC can take key of any size");
    for slice in slices {
        Mac::update(&mut mac, slice);
    }
    let result = mac.finalize().into_bytes();
    result[..truncate_len].to_vec()
}

// --- Privacy primitive implementations ---

fn encrypt_des_cbc(key: &[u8], iv: &[u8], data: &mut [u8]) -> CryptoResult<()> {
    use cbc::cipher::{BlockEncryptMut, KeyIvInit};
    type DesCbc = cbc::Encryptor<des::Des>;

    let cipher = DesCbc::new_from_slices(key, iv).map_err(|_| {
        tracing::debug!(target: "async_snmp::crypto", "DES encryption failed: invalid key length");
        CryptoError::InvalidKeyLength
    })?;
    let len = data.len();
    cipher
        .encrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(data, len)
        .map_err(|_| {
            tracing::debug!(target: "async_snmp::crypto", "DES encryption failed: cipher error");
            CryptoError::CipherError
        })?;
    Ok(())
}

fn decrypt_des_cbc(key: &[u8], iv: &[u8], data: &mut [u8]) -> CryptoResult<()> {
    use cbc::cipher::{BlockDecryptMut, KeyIvInit};
    type DesCbc = cbc::Decryptor<des::Des>;

    let cipher = DesCbc::new_from_slices(key, iv).map_err(|_| {
        tracing::debug!(target: "async_snmp::crypto", "DES decryption failed: invalid key length");
        CryptoError::InvalidKeyLength
    })?;
    cipher
        .decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(data)
        .map_err(|_| {
            tracing::debug!(target: "async_snmp::crypto", "DES decryption failed: cipher error");
            CryptoError::CipherError
        })?;
    Ok(())
}

fn encrypt_des3_cbc(key: &[u8], iv: &[u8], data: &mut [u8]) -> CryptoResult<()> {
    use cbc::cipher::{BlockEncryptMut, KeyIvInit};
    type Des3Cbc = cbc::Encryptor<des::TdesEde3>;

    let cipher = Des3Cbc::new_from_slices(key, iv).map_err(|_| {
        tracing::debug!(target: "async_snmp::crypto", "3DES encryption failed: invalid key length");
        CryptoError::InvalidKeyLength
    })?;
    let len = data.len();
    cipher
        .encrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(data, len)
        .map_err(|_| {
            tracing::debug!(target: "async_snmp::crypto", "3DES encryption failed: cipher error");
            CryptoError::CipherError
        })?;
    Ok(())
}

fn decrypt_des3_cbc(key: &[u8], iv: &[u8], data: &mut [u8]) -> CryptoResult<()> {
    use cbc::cipher::{BlockDecryptMut, KeyIvInit};
    type Des3Cbc = cbc::Decryptor<des::TdesEde3>;

    let cipher = Des3Cbc::new_from_slices(key, iv).map_err(|_| {
        tracing::debug!(target: "async_snmp::crypto", "3DES decryption failed: invalid key length");
        CryptoError::InvalidKeyLength
    })?;
    cipher
        .decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(data)
        .map_err(|_| {
            tracing::debug!(target: "async_snmp::crypto", "3DES decryption failed: cipher error");
            CryptoError::CipherError
        })?;
    Ok(())
}

fn encrypt_aes_cfb(key: &[u8], iv: &[u8], data: &mut [u8]) -> CryptoResult<()> {
    use aes::{Aes128, Aes192, Aes256};
    use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};

    match key.len() {
        16 => {
            type Aes128Cfb = cfb_mode::Encryptor<Aes128>;
            let cipher = Aes128Cfb::new_from_slices(key, iv).map_err(|_| {
                tracing::debug!(target: "async_snmp::crypto", "AES-128 encryption failed: invalid key length");
                CryptoError::InvalidKeyLength
            })?;
            cipher.encrypt(data);
        }
        24 => {
            type Aes192Cfb = cfb_mode::Encryptor<Aes192>;
            let cipher = Aes192Cfb::new_from_slices(key, iv).map_err(|_| {
                tracing::debug!(target: "async_snmp::crypto", "AES-192 encryption failed: invalid key length");
                CryptoError::InvalidKeyLength
            })?;
            cipher.encrypt(data);
        }
        32 => {
            type Aes256Cfb = cfb_mode::Encryptor<Aes256>;
            let cipher = Aes256Cfb::new_from_slices(key, iv).map_err(|_| {
                tracing::debug!(target: "async_snmp::crypto", "AES-256 encryption failed: invalid key length");
                CryptoError::InvalidKeyLength
            })?;
            cipher.encrypt(data);
        }
        key_len => {
            tracing::debug!(target: "async_snmp::crypto", { key_len }, "AES encryption failed: unsupported key length");
            return Err(CryptoError::InvalidKeyLength);
        }
    }
    Ok(())
}

fn decrypt_aes_cfb(key: &[u8], iv: &[u8], data: &mut [u8]) -> CryptoResult<()> {
    use aes::{Aes128, Aes192, Aes256};
    use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};

    match key.len() {
        16 => {
            type Aes128Cfb = cfb_mode::Decryptor<Aes128>;
            let cipher = Aes128Cfb::new_from_slices(key, iv).map_err(|_| {
                tracing::debug!(target: "async_snmp::crypto", "AES-128 decryption failed: invalid key length");
                CryptoError::InvalidKeyLength
            })?;
            cipher.decrypt(data);
        }
        24 => {
            type Aes192Cfb = cfb_mode::Decryptor<Aes192>;
            let cipher = Aes192Cfb::new_from_slices(key, iv).map_err(|_| {
                tracing::debug!(target: "async_snmp::crypto", "AES-192 decryption failed: invalid key length");
                CryptoError::InvalidKeyLength
            })?;
            cipher.decrypt(data);
        }
        32 => {
            type Aes256Cfb = cfb_mode::Decryptor<Aes256>;
            let cipher = Aes256Cfb::new_from_slices(key, iv).map_err(|_| {
                tracing::debug!(target: "async_snmp::crypto", "AES-256 decryption failed: invalid key length");
                CryptoError::InvalidKeyLength
            })?;
            cipher.decrypt(data);
        }
        key_len => {
            tracing::debug!(target: "async_snmp::crypto", { key_len }, "AES decryption failed: unsupported key length");
            return Err(CryptoError::InvalidKeyLength);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 3414 §8.1.1.2: "if [the length] is not [a multiple of 8], the data
    /// is padded at the end as necessary." The encrypt operation must handle
    /// unaligned plaintext by padding to the next block boundary.
    #[test]
    fn des_encrypt_pads_unaligned_plaintext() {
        let provider = RustCryptoProvider;
        let key = b"\x00\x11\x22\x33\x44\x55\x66\x77";
        let iv = [0u8; 8];
        let mut data = b"Hello".to_vec(); // 5 bytes, not a multiple of 8

        let result = provider.encrypt(PrivProtocol::Des, key, &iv, &mut data);
        assert!(
            result.is_ok(),
            "DES encrypt must pad unaligned plaintext, got: {result:?}"
        );
        assert_eq!(data.len(), 8, "output must be padded to 8-byte boundary");
    }

    /// Same as DES: 3DES-CBC must pad unaligned plaintext.
    #[test]
    fn des3_encrypt_pads_unaligned_plaintext() {
        let provider = RustCryptoProvider;
        let key = [0x01u8; 24];
        let iv = [0u8; 8];
        let mut data = b"Hello".to_vec(); // 5 bytes

        let result = provider.encrypt(PrivProtocol::Des3, &key, &iv, &mut data);
        assert!(
            result.is_ok(),
            "3DES encrypt must pad unaligned plaintext, got: {result:?}"
        );
        assert_eq!(data.len(), 8, "output must be padded to 8-byte boundary");
    }

    /// DES roundtrip: unaligned plaintext should encrypt and decrypt correctly.
    #[test]
    fn des_roundtrip_unaligned() {
        let provider = RustCryptoProvider;
        let key = b"\x00\x11\x22\x33\x44\x55\x66\x77";
        let iv = [0u8; 8];
        let plaintext = b"Hello";
        let mut data = plaintext.to_vec();

        provider
            .encrypt(PrivProtocol::Des, key, &iv, &mut data)
            .unwrap();
        assert_eq!(data.len(), 8);

        provider
            .decrypt(PrivProtocol::Des, key, &iv, &mut data)
            .unwrap();
        assert_eq!(&data[..plaintext.len()], plaintext);
    }

    /// Already-aligned DES plaintext should still work (no regression).
    #[test]
    fn des_encrypt_aligned_unchanged() {
        let provider = RustCryptoProvider;
        let key = b"\x00\x11\x22\x33\x44\x55\x66\x77";
        let iv = [0u8; 8];
        let mut data = vec![0x41u8; 8]; // already 8 bytes

        let result = provider.encrypt(PrivProtocol::Des, key, &iv, &mut data);
        assert!(result.is_ok());
        assert_eq!(data.len(), 8);
    }
}
