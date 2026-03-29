use aws_lc_rs::cipher::{
    DecryptingKey, DecryptionContext, EncryptingKey, EncryptionContext, UnboundCipherKey, AES_128,
    AES_192, AES_256,
};
use aws_lc_rs::iv::FixedLength;
use aws_lc_rs::{digest, hmac};

use super::{CryptoProvider, PrivacyResult};
use crate::v3::privacy::PrivacyError;
use crate::v3::{AuthProtocol, PrivProtocol};

/// FIPS 140-3 compliant crypto provider backed by aws-lc-rs.
///
/// This is a stateless unit struct that dispatches to aws-lc-rs for all
/// cryptographic operations. MD5 is not available in FIPS mode; calling any
/// method with AuthProtocol::Md5 will panic.
pub struct AwsLcFipsProvider;

fn digest_algorithm(protocol: AuthProtocol) -> &'static digest::Algorithm {
    match protocol {
        AuthProtocol::Md5 => panic!("MD5 is not supported in FIPS mode"),
        AuthProtocol::Sha1 => &digest::SHA1_FOR_LEGACY_USE_ONLY,
        AuthProtocol::Sha224 => &digest::SHA224,
        AuthProtocol::Sha256 => &digest::SHA256,
        AuthProtocol::Sha384 => &digest::SHA384,
        AuthProtocol::Sha512 => &digest::SHA512,
    }
}

fn hmac_algorithm(protocol: AuthProtocol) -> hmac::Algorithm {
    match protocol {
        AuthProtocol::Md5 => panic!("MD5 is not supported in FIPS mode"),
        AuthProtocol::Sha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        AuthProtocol::Sha224 => hmac::HMAC_SHA224,
        AuthProtocol::Sha256 => hmac::HMAC_SHA256,
        AuthProtocol::Sha384 => hmac::HMAC_SHA384,
        AuthProtocol::Sha512 => hmac::HMAC_SHA512,
    }
}

impl CryptoProvider for AwsLcFipsProvider {
    fn hash(&self, protocol: AuthProtocol, data: &[u8]) -> Vec<u8> {
        let alg = digest_algorithm(protocol);
        digest::digest(alg, data).as_ref().to_vec()
    }

    fn password_to_key(&self, protocol: AuthProtocol, password: &[u8]) -> Vec<u8> {
        const EXPANSION_SIZE: usize = 1_048_576; // 1MB

        if password.is_empty() {
            return vec![0u8; protocol.digest_len()];
        }

        let alg = digest_algorithm(protocol);
        let mut ctx = digest::Context::new(alg);

        let mut buf = [0u8; 64];
        let password_len = password.len();
        let mut password_index = 0;
        let mut count = 0;

        while count < EXPANSION_SIZE {
            for byte in &mut buf {
                *byte = password[password_index];
                password_index = (password_index + 1) % password_len;
            }
            ctx.update(&buf);
            count += 64;
        }

        ctx.finish().as_ref().to_vec()
    }

    fn localize_key(&self, protocol: AuthProtocol, master_key: &[u8], engine_id: &[u8]) -> Vec<u8> {
        let alg = digest_algorithm(protocol);
        let mut ctx = digest::Context::new(alg);
        ctx.update(master_key);
        ctx.update(engine_id);
        ctx.update(master_key);
        ctx.finish().as_ref().to_vec()
    }

    fn compute_hmac(
        &self,
        protocol: AuthProtocol,
        key: &[u8],
        slices: &[&[u8]],
        truncate_len: usize,
    ) -> Vec<u8> {
        let alg = hmac_algorithm(protocol);
        let hmac_key = hmac::Key::new(alg, key);
        let mut ctx = hmac::Context::with_key(&hmac_key);
        for slice in slices {
            ctx.update(slice);
        }
        let tag = ctx.sign();
        tag.as_ref()[..truncate_len].to_vec()
    }

    fn encrypt(
        &self,
        protocol: PrivProtocol,
        key: &[u8],
        iv: &[u8],
        data: &mut [u8],
    ) -> PrivacyResult<()> {
        match protocol {
            PrivProtocol::Des => {
                tracing::debug!(target: "async_snmp::crypto", "DES is not supported in FIPS mode");
                Err(PrivacyError::UnsupportedProtocol)
            }
            PrivProtocol::Des3 => {
                tracing::debug!(target: "async_snmp::crypto", "3DES is not supported in FIPS mode");
                Err(PrivacyError::UnsupportedProtocol)
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
    ) -> PrivacyResult<()> {
        match protocol {
            PrivProtocol::Des => {
                tracing::debug!(target: "async_snmp::crypto", "DES is not supported in FIPS mode");
                Err(PrivacyError::UnsupportedProtocol)
            }
            PrivProtocol::Des3 => {
                tracing::debug!(target: "async_snmp::crypto", "3DES is not supported in FIPS mode");
                Err(PrivacyError::UnsupportedProtocol)
            }
            PrivProtocol::Aes128 | PrivProtocol::Aes192 | PrivProtocol::Aes256 => {
                decrypt_aes_cfb(key, iv, data)
            }
        }
    }
}

fn aes_algorithm(key_len: usize) -> Result<&'static aws_lc_rs::cipher::Algorithm, PrivacyError> {
    match key_len {
        16 => Ok(&AES_128),
        24 => Ok(&AES_192),
        32 => Ok(&AES_256),
        _ => {
            tracing::debug!(target: "async_snmp::crypto", key_len, "AES operation failed: unsupported key length");
            Err(PrivacyError::UnsupportedProtocol)
        }
    }
}

fn encrypt_aes_cfb(key: &[u8], iv: &[u8], data: &mut [u8]) -> PrivacyResult<()> {
    let alg = aes_algorithm(key.len())?;
    let iv_array: [u8; 16] = iv.try_into().map_err(|_| {
        tracing::debug!(target: "async_snmp::crypto", iv_len = iv.len(), "AES encryption failed: invalid IV length");
        PrivacyError::InvalidKeyLength
    })?;

    let unbound_key = UnboundCipherKey::new(alg, key).map_err(|_| {
        tracing::debug!(target: "async_snmp::crypto", "AES encryption failed: invalid key length");
        PrivacyError::InvalidKeyLength
    })?;
    let encrypting_key = EncryptingKey::cfb128(unbound_key).map_err(|_| {
        tracing::debug!(target: "async_snmp::crypto", "AES encryption failed: could not create CFB128 key");
        PrivacyError::CipherError
    })?;
    let context = EncryptionContext::Iv128(FixedLength::from(iv_array));
    encrypting_key.less_safe_encrypt(data, context).map_err(|_| {
        tracing::debug!(target: "async_snmp::crypto", "AES encryption failed: cipher error");
        PrivacyError::CipherError
    })?;
    Ok(())
}

fn decrypt_aes_cfb(key: &[u8], iv: &[u8], data: &mut [u8]) -> PrivacyResult<()> {
    let alg = aes_algorithm(key.len())?;
    let iv_array: [u8; 16] = iv.try_into().map_err(|_| {
        tracing::debug!(target: "async_snmp::crypto", iv_len = iv.len(), "AES decryption failed: invalid IV length");
        PrivacyError::InvalidKeyLength
    })?;

    let unbound_key = UnboundCipherKey::new(alg, key).map_err(|_| {
        tracing::debug!(target: "async_snmp::crypto", "AES decryption failed: invalid key length");
        PrivacyError::InvalidKeyLength
    })?;
    let decrypting_key = DecryptingKey::cfb128(unbound_key).map_err(|_| {
        tracing::debug!(target: "async_snmp::crypto", "AES decryption failed: could not create CFB128 key");
        PrivacyError::CipherError
    })?;
    let context = DecryptionContext::Iv128(FixedLength::from(iv_array));
    decrypting_key.decrypt(data, context).map_err(|_| {
        tracing::debug!(target: "async_snmp::crypto", "AES decryption failed: cipher error");
        PrivacyError::CipherError
    })?;
    Ok(())
}
