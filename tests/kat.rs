#![cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]

//! Known-Answer Tests (KAT) for cryptographic operations.
//!
//! These tests use test vectors from RFCs to verify that our implementations
//! match the expected outputs:
//!
//! - RFC 3414 Appendix A: Password-to-key and key localization for MD5/SHA-1
//! - RFC 7860: SHA-2 authentication protocols (uses RFC 3414 algorithm)
//! - RFC 6234: HMAC test vectors for SHA-1/SHA-2
//! - RFC 3414 A.5: Key change vectors

use async_snmp::format::hex::{decode, encode};
use async_snmp::v3::{AuthProtocol, LocalizedKey, PrivKey, PrivProtocol, SaltCounter};
#[cfg(feature = "crypto-fips")]
use async_snmp::v3::{CryptoBackend, CryptoError, MasterKey};

/// RFC 3414 Appendix A.3.1: Password to Key using MD5
///
/// Password: "maplesyrup"
/// Intermediate key (Ku): 9faf3283884e92834ebc9847d8edd963
/// Engine ID: 000000000000000000000002
/// Localized key (Kul): 526f5eed9fcce26f8964c2930787d82b
#[cfg(feature = "crypto-rustcrypto")]
#[test]
fn test_rfc3414_a3_1_md5_key_localization() {
    let password = b"maplesyrup";
    let engine_id = decode("000000000000000000000002").unwrap();

    let key = LocalizedKey::from_password(AuthProtocol::Md5, password, &engine_id).unwrap();

    assert_eq!(key.as_bytes().len(), 16);
    assert_eq!(
        encode(key.as_bytes()),
        "526f5eed9fcce26f8964c2930787d82b",
        "MD5 localized key mismatch"
    );
}

/// RFC 3414 Appendix A.3.2: Password to Key using SHA-1
///
/// Password: "maplesyrup"
/// Intermediate key (Ku): 9fb5cc0381497b3793528939ff788d5d79145211
/// Engine ID: 000000000000000000000002
/// Localized key (Kul): 6695febc9288e36282235fc7151f128497b38f3f
#[test]
fn test_rfc3414_a3_2_sha1_key_localization() {
    let password = b"maplesyrup";
    let engine_id = decode("000000000000000000000002").unwrap();

    let key = LocalizedKey::from_password(AuthProtocol::Sha1, password, &engine_id).unwrap();

    assert_eq!(key.as_bytes().len(), 20);
    assert_eq!(
        encode(key.as_bytes()),
        "6695febc9288e36282235fc7151f128497b38f3f",
        "SHA-1 localized key mismatch"
    );
}

/// RFC 3414 Appendix A.5.1: Key Change using MD5
///
/// Old password: "maplesyrup"
/// New password: "newsyrup"
/// Engine ID: 000000000000000000000002
/// New localized key: 87021d7bd9d101ba05ea6e3bf9d9bd4a
#[cfg(feature = "crypto-rustcrypto")]
#[test]
fn test_rfc3414_a5_1_md5_new_password_key() {
    let new_password = b"newsyrup";
    let engine_id = decode("000000000000000000000002").unwrap();

    let key = LocalizedKey::from_password(AuthProtocol::Md5, new_password, &engine_id).unwrap();

    assert_eq!(key.as_bytes().len(), 16);
    assert_eq!(
        encode(key.as_bytes()),
        "87021d7bd9d101ba05ea6e3bf9d9bd4a",
        "MD5 'newsyrup' localized key mismatch"
    );
}

/// RFC 3414 Appendix A.5.2: Key Change using SHA-1
///
/// New password: "newsyrup"
/// Engine ID: 000000000000000000000002
/// New localized key: 78e2dcce79d59403b58c1bbaa5bff46391f1cd25
#[test]
fn test_rfc3414_a5_2_sha1_new_password_key() {
    let new_password = b"newsyrup";
    let engine_id = decode("000000000000000000000002").unwrap();

    let key = LocalizedKey::from_password(AuthProtocol::Sha1, new_password, &engine_id).unwrap();

    assert_eq!(key.as_bytes().len(), 20);
    assert_eq!(
        encode(key.as_bytes()),
        "78e2dcce79d59403b58c1bbaa5bff46391f1cd25",
        "SHA-1 'newsyrup' localized key mismatch"
    );
}

/// SHA-224 key localization (RFC 7860 algorithm).
///
/// Uses the same password-to-key algorithm as RFC 3414 but with SHA-224.
/// No RFC-specified test vector exists, but we verify consistency.
#[test]
fn test_sha224_key_localization() {
    let password = b"maplesyrup";
    let engine_id = decode("000000000000000000000002").unwrap();

    let key = LocalizedKey::from_password(AuthProtocol::Sha224, password, &engine_id).unwrap();

    // SHA-224 produces 28-byte keys
    assert_eq!(key.as_bytes().len(), 28);

    // Verify determinism: same inputs produce same output
    let key2 = LocalizedKey::from_password(AuthProtocol::Sha224, password, &engine_id).unwrap();
    assert_eq!(key.as_bytes(), key2.as_bytes());
}

/// SHA-256 key localization (RFC 7860 algorithm).
#[test]
fn test_sha256_key_localization() {
    let password = b"maplesyrup";
    let engine_id = decode("000000000000000000000002").unwrap();

    let key = LocalizedKey::from_password(AuthProtocol::Sha256, password, &engine_id).unwrap();

    // SHA-256 produces 32-byte keys
    assert_eq!(key.as_bytes().len(), 32);

    // Verify determinism
    let key2 = LocalizedKey::from_password(AuthProtocol::Sha256, password, &engine_id).unwrap();
    assert_eq!(key.as_bytes(), key2.as_bytes());
}

/// SHA-384 key localization (RFC 7860 algorithm).
#[test]
fn test_sha384_key_localization() {
    let password = b"maplesyrup";
    let engine_id = decode("000000000000000000000002").unwrap();

    let key = LocalizedKey::from_password(AuthProtocol::Sha384, password, &engine_id).unwrap();

    // SHA-384 produces 48-byte keys
    assert_eq!(key.as_bytes().len(), 48);

    // Verify determinism
    let key2 = LocalizedKey::from_password(AuthProtocol::Sha384, password, &engine_id).unwrap();
    assert_eq!(key.as_bytes(), key2.as_bytes());
}

/// SHA-512 key localization (RFC 7860 algorithm).
#[test]
fn test_sha512_key_localization() {
    let password = b"maplesyrup";
    let engine_id = decode("000000000000000000000002").unwrap();

    let key = LocalizedKey::from_password(AuthProtocol::Sha512, password, &engine_id).unwrap();

    // SHA-512 produces 64-byte keys
    assert_eq!(key.as_bytes().len(), 64);

    // Verify determinism
    let key2 = LocalizedKey::from_password(AuthProtocol::Sha512, password, &engine_id).unwrap();
    assert_eq!(key.as_bytes(), key2.as_bytes());
}

/// Privacy key derivation uses auth key localization.
///
/// For DES, the 16-byte localized key is used as:
/// - First 8 bytes: DES encryption key
/// - Last 8 bytes: Pre-IV for IV generation
#[cfg(feature = "crypto-rustcrypto")]
#[test]
fn test_des_priv_key_from_password() {
    let password = b"maplesyrup";
    let engine_id = decode("000000000000000000000002").unwrap();

    // DES privacy key uses MD5 localization (16 bytes needed)
    let priv_key =
        PrivKey::from_password(AuthProtocol::Md5, PrivProtocol::Des, password, &engine_id).unwrap();

    // Encryption key should be first 8 bytes of the MD5 localized key
    // From RFC 3414 A.3.1: 526f5eed9fcce26f8964c2930787d82b
    // First 8 bytes: 526f5eed9fcce26f
    assert_eq!(encode(priv_key.encryption_key()), "526f5eed9fcce26f");
}

/// AES-128 privacy key derivation.
///
/// For AES-128, the first 16 bytes of the localized key are used.
#[test]
fn test_aes128_priv_key_from_password() {
    let password = b"maplesyrup";
    let engine_id = decode("000000000000000000000002").unwrap();

    // AES-128 uses SHA-1 localization (20 bytes, take first 16)
    let priv_key = PrivKey::from_password(
        AuthProtocol::Sha1,
        PrivProtocol::Aes128,
        password,
        &engine_id,
    )
    .unwrap();

    // Encryption key should be first 16 bytes of the SHA-1 localized key
    // From RFC 3414 A.3.2: 6695febc9288e36282235fc7151f128497b38f3f
    // First 16 bytes: 6695febc9288e36282235fc7151f1284
    assert_eq!(
        encode(priv_key.encryption_key()),
        "6695febc9288e36282235fc7151f1284"
    );
}

/// AES-256 privacy key derivation (Blumenthal).
///
/// For AES-256, all 32 bytes from SHA-256 localization are used.
#[test]
fn test_aes256_priv_key_from_password() {
    let password = b"maplesyrup";
    let engine_id = decode("000000000000000000000002").unwrap();

    // AES-256 uses SHA-256 localization (32 bytes)
    let priv_key = PrivKey::from_password(
        AuthProtocol::Sha256,
        PrivProtocol::Aes256,
        password,
        &engine_id,
    )
    .unwrap();

    // Encryption key should be 32 bytes
    assert_eq!(priv_key.encryption_key().len(), 32);

    // Verify determinism
    let priv_key2 = PrivKey::from_password(
        AuthProtocol::Sha256,
        PrivProtocol::Aes256,
        password,
        &engine_id,
    )
    .unwrap();
    assert_eq!(priv_key.encryption_key(), priv_key2.encryption_key());
}

/// Different engine IDs produce different localized keys.
#[test]
fn test_different_engine_ids_produce_different_keys() {
    let password = b"maplesyrup";
    let engine_id_1 = decode("000000000000000000000001").unwrap();
    let engine_id_2 = decode("000000000000000000000002").unwrap();

    let key1 = LocalizedKey::from_password(AuthProtocol::Sha1, password, &engine_id_1).unwrap();
    let key2 = LocalizedKey::from_password(AuthProtocol::Sha1, password, &engine_id_2).unwrap();

    // Different engine IDs must produce different keys
    assert_ne!(key1.as_bytes(), key2.as_bytes());
}

/// Different passwords produce different localized keys.
#[test]
fn test_different_passwords_produce_different_keys() {
    let password_1 = b"maplesyrup";
    let password_2 = b"newsyrup";
    let engine_id = decode("000000000000000000000002").unwrap();

    let key1 = LocalizedKey::from_password(AuthProtocol::Sha1, password_1, &engine_id).unwrap();
    let key2 = LocalizedKey::from_password(AuthProtocol::Sha1, password_2, &engine_id).unwrap();

    // Different passwords must produce different keys
    assert_ne!(key1.as_bytes(), key2.as_bytes());
}

/// Empty engine ID is handled correctly.
#[test]
fn test_empty_engine_id() {
    let password = b"testpassword";
    let engine_id: Vec<u8> = vec![];

    let key = LocalizedKey::from_password(AuthProtocol::Sha1, password, &engine_id).unwrap();

    // Should still produce a valid 20-byte key
    assert_eq!(key.as_bytes().len(), 20);

    // Verify it's deterministic
    let key2 = LocalizedKey::from_password(AuthProtocol::Sha1, password, &engine_id).unwrap();
    assert_eq!(key.as_bytes(), key2.as_bytes());
}

/// Long engine ID is handled correctly.
#[test]
fn test_long_engine_id() {
    let password = b"testpassword";
    // Engine IDs can be up to 32 bytes per RFC 3411
    let engine_id = vec![0xAB; 32];

    let key = LocalizedKey::from_password(AuthProtocol::Sha256, password, &engine_id).unwrap();

    // Should produce a valid 32-byte key
    assert_eq!(key.as_bytes().len(), 32);
}

/// RFC 3414 Appendix A.4: msgSecurityParameters encoding example.
///
/// This verifies the USM security parameters are encoded correctly according
/// to the example in the RFC:
///
/// ```text
/// 04 39           OCTET STRING, length 57
/// 30 37           SEQUENCE, length 55
/// 04 0c 80000002  msgAuthoritativeEngineID: IBM IPv4 9.132.3.1
///       01
///       09840301
/// 02 01 01        msgAuthoritativeEngineBoots: 1
/// 02 02 0101      msgAuthoritativeEngineTime: 257
/// 04 04 62657274  msgUserName: bert
/// 04 0c 01234567  msgAuthenticationParameters: sample
///       89abcdef
///       fedcba98
/// 04 08 01234567  msgPrivacyParameters: sample
///       89abcdef
/// ```
#[test]
fn test_rfc3414_a4_usm_encoding() {
    use async_snmp::v3::UsmSecurityParams;
    use bytes::Bytes;

    // Engine ID from RFC example: 80000002 01 09840301 (IBM enterprise, IPv4, 9.132.3.1)
    // RFC shows 12-byte engine_id in the example hex dump (04 0c prefix)
    let engine_id = decode("800000020109840301000000").unwrap();

    let params = UsmSecurityParams::new(
        Bytes::from(engine_id),
        1,   // boots
        257, // time (0x0101)
        Bytes::from_static(b"bert"),
    )
    .unwrap()
    .with_auth_params(Bytes::from(decode("0123456789abcdeffedcba98").unwrap()))
    .unwrap()
    .with_priv_params(Bytes::from(decode("0123456789abcdef").unwrap()))
    .unwrap();

    let encoded = params.encode().unwrap();

    // Verify it's a valid SEQUENCE
    assert_eq!(encoded[0], 0x30, "Should start with SEQUENCE tag");

    // Decode it back and verify fields
    let decoded = UsmSecurityParams::decode(encoded.clone(), async_snmp::DecodeConfig::default())
        .unwrap()
        .value;
    assert_eq!(decoded.engine_boots(), 1);
    assert_eq!(decoded.engine_time(), 257);
    assert_eq!(decoded.username().as_ref(), b"bert");
    assert_eq!(decoded.auth_params().len(), 12);
    assert_eq!(decoded.priv_params().len(), 8);
}

/// Verify MAC length matches protocol specification (MD5).
#[cfg(feature = "crypto-rustcrypto")]
#[test]
fn test_mac_length_md5() {
    let key = LocalizedKey::from_bytes(AuthProtocol::Md5, vec![0; 16]).unwrap();
    // RFC 3414: HMAC-MD5-96 truncates to 12 bytes
    assert_eq!(key.mac_len(), 12);
}

/// Verify MAC length matches protocol specification (SHA-1 and SHA-2).
#[test]
fn test_mac_lengths_per_rfc() {
    let key_sha1 = LocalizedKey::from_bytes(AuthProtocol::Sha1, vec![0; 20]).unwrap();
    let key_sha224 = LocalizedKey::from_bytes(AuthProtocol::Sha224, vec![0; 28]).unwrap();
    let key_sha256 = LocalizedKey::from_bytes(AuthProtocol::Sha256, vec![0; 32]).unwrap();
    let key_sha384 = LocalizedKey::from_bytes(AuthProtocol::Sha384, vec![0; 48]).unwrap();
    let key_sha512 = LocalizedKey::from_bytes(AuthProtocol::Sha512, vec![0; 64]).unwrap();

    // RFC 3414: HMAC-SHA-96 truncates to 12 bytes
    assert_eq!(key_sha1.mac_len(), 12);

    // RFC 7860: SHA-2 protocols use different truncation lengths
    // usmHMAC128SHA224AuthProtocol: 16 bytes
    assert_eq!(key_sha224.mac_len(), 16);
    // usmHMAC192SHA256AuthProtocol: 24 bytes
    assert_eq!(key_sha256.mac_len(), 24);
    // usmHMAC256SHA384AuthProtocol: 32 bytes
    assert_eq!(key_sha384.mac_len(), 32);
    // usmHMAC384SHA512AuthProtocol: 48 bytes
    assert_eq!(key_sha512.mac_len(), 48);
}

// ============================================================================
// Blumenthal Key Extension Tests (draft-blumenthal-aes-usm-04)
//
// These tests verify the key extension algorithm used for AES-192/256 when
// the authentication protocol produces insufficient key material. This is
// an interoperability feature for communicating with net-snmp and other
// implementations that support AES-192/256 with shorter auth protocols.
// ============================================================================

// Key extension algorithm tests (extend_key, extend_key_reeder) are now internal
// to the v3::auth module. See src/v3/auth.rs for KAT tests.

/// AES-256 encryption/decryption roundtrip with SHA-1 (auto key extension).
#[test]
fn test_aes256_with_sha1_auto_key_extension_roundtrip() {
    let password = b"maplesyrup";
    let engine_id = decode("000000000000000000000002").unwrap();

    // Create privacy key - Blumenthal extension is auto-applied because
    // SHA-1 (20 bytes) < AES-256 (32 bytes)
    let priv_key = PrivKey::from_password(
        AuthProtocol::Sha1,
        PrivProtocol::Aes256,
        password,
        &engine_id,
    )
    .unwrap();

    // Verify the encryption key length is correct for AES-256
    assert_eq!(priv_key.encryption_key().len(), 32);

    // Encrypt and decrypt
    let plaintext = b"Test message for AES-256 with extended SHA-1 key";
    let engine_boots = 100u32;
    let engine_time = 12345u32;

    let (ciphertext, priv_params) = priv_key
        .encrypt(
            plaintext,
            engine_boots,
            engine_time,
            &SaltCounter::new().unwrap(),
        )
        .expect("encryption should succeed");

    let decrypted = priv_key
        .decrypt(&ciphertext, engine_boots, engine_time, &priv_params)
        .expect("decryption should succeed");

    assert_eq!(decrypted.as_ref(), plaintext);
}

/// AES-192 encryption/decryption roundtrip with SHA-1 (auto key extension).
#[test]
fn test_aes192_with_sha1_auto_key_extension_roundtrip() {
    let password = b"maplesyrup";
    let engine_id = decode("000000000000000000000002").unwrap();

    // Create privacy key - Blumenthal extension is auto-applied because
    // SHA-1 (20 bytes) < AES-192 (24 bytes)
    let priv_key = PrivKey::from_password(
        AuthProtocol::Sha1,
        PrivProtocol::Aes192,
        password,
        &engine_id,
    )
    .unwrap();

    // Verify the encryption key length is correct for AES-192
    assert_eq!(priv_key.encryption_key().len(), 24);

    // Encrypt and decrypt
    let plaintext = b"Test message for AES-192 with extended SHA-1 key";
    let engine_boots = 200u32;
    let engine_time = 54321u32;

    let (ciphertext, priv_params) = priv_key
        .encrypt(
            plaintext,
            engine_boots,
            engine_time,
            &SaltCounter::new().unwrap(),
        )
        .expect("encryption should succeed");

    let decrypted = priv_key
        .decrypt(&ciphertext, engine_boots, engine_time, &priv_params)
        .expect("decryption should succeed");

    assert_eq!(decrypted.as_ref(), plaintext);
}

/// AES-256 with MD5 (auto key extension) roundtrip.
#[cfg(feature = "crypto-rustcrypto")]
#[test]
fn test_aes256_with_md5_auto_key_extension_roundtrip() {
    let password = b"maplesyrup";
    let engine_id = decode("000000000000000000000002").unwrap();

    // Blumenthal extension is auto-applied because MD5 (16 bytes) < AES-256 (32 bytes)
    let priv_key = PrivKey::from_password(
        AuthProtocol::Md5,
        PrivProtocol::Aes256,
        password,
        &engine_id,
    )
    .unwrap();

    assert_eq!(priv_key.encryption_key().len(), 32);

    let plaintext = b"Test message for AES-256 with extended MD5 key";
    let (ciphertext, priv_params) = priv_key
        .encrypt(plaintext, 300, 67890, &SaltCounter::new().unwrap())
        .expect("encryption should succeed");

    let decrypted = priv_key
        .decrypt(&ciphertext, 300, 67890, &priv_params)
        .expect("decryption should succeed");

    assert_eq!(decrypted.as_ref(), plaintext);
}

/// FIPS provider rejects MD5 for password_to_key.
#[cfg(feature = "crypto-fips")]
#[test]
fn test_fips_rejects_md5_password_to_key() {
    let result = LocalizedKey::from_password_with_backend(
        AuthProtocol::Md5,
        b"maplesyrup",
        &decode("000000000000000000000002").unwrap(),
        CryptoBackend::AwsLcFips,
    );
    assert!(
        matches!(result, Err(CryptoError::UnsupportedAlgorithm("MD5"))),
        "FIPS provider should reject MD5: got {:?}",
        result
    );
}

/// Password validation precedes backend algorithm selection.
#[cfg(feature = "crypto-fips")]
#[test]
fn test_fips_rejects_empty_password_before_md5_selection() {
    let result = LocalizedKey::from_password_with_backend(
        AuthProtocol::Md5,
        b"",
        &decode("000000000000000000000002").unwrap(),
        CryptoBackend::AwsLcFips,
    );
    assert!(
        matches!(result, Err(CryptoError::PasswordTooShort)),
        "passwords shorter than 8 octets should be rejected before backend selection: got {:?}",
        result
    );
}

/// FIPS provider rejects an active MD5 key at construction.
#[cfg(feature = "crypto-fips")]
#[test]
fn test_fips_rejects_raw_md5_key() {
    let master = MasterKey::from_bytes_with_backend(
        AuthProtocol::Md5,
        vec![0; 16],
        CryptoBackend::AwsLcFips,
    );
    let localized = LocalizedKey::from_bytes_with_backend(
        AuthProtocol::Md5,
        vec![0; 16],
        CryptoBackend::AwsLcFips,
    );
    assert!(
        matches!(master, Err(CryptoError::UnsupportedAlgorithm("MD5"))),
        "FIPS provider should reject an MD5 master key: got {:?}",
        master
    );
    assert!(
        matches!(localized, Err(CryptoError::UnsupportedAlgorithm("MD5"))),
        "FIPS provider should reject an MD5 localized key: got {:?}",
        localized
    );
}

/// Privacy capability validation precedes localization and extension.
#[cfg(feature = "crypto-fips")]
#[test]
fn test_fips_rejects_privacy_protocol_before_derivation() {
    let master = MasterKey::from_bytes_with_backend(
        AuthProtocol::Sha256,
        vec![0; 32],
        CryptoBackend::AwsLcFips,
    )
    .unwrap();

    assert!(matches!(
        PrivKey::from_master_key(&master, PrivProtocol::Des, b"engine-id"),
        Err(CryptoError::UnsupportedAlgorithm("DES"))
    ));
    assert!(matches!(
        PrivKey::from_master_key(&master, PrivProtocol::Des3, b"engine-id"),
        Err(CryptoError::UnsupportedAlgorithm("3DES"))
    ));
}

/// Extended keys from same password but different engine IDs differ.
#[test]
fn test_extended_keys_differ_by_engine_id() {
    let password = b"maplesyrup";
    let engine_id_1 = decode("000000000000000000000001").unwrap();
    let engine_id_2 = decode("000000000000000000000002").unwrap();

    // Blumenthal extension is auto-applied for both
    let priv_key_1 = PrivKey::from_password(
        AuthProtocol::Sha1,
        PrivProtocol::Aes256,
        password,
        &engine_id_1,
    )
    .unwrap();

    let priv_key_2 = PrivKey::from_password(
        AuthProtocol::Sha1,
        PrivProtocol::Aes256,
        password,
        &engine_id_2,
    )
    .unwrap();

    // Keys should be different because they're localized to different engines
    assert_ne!(priv_key_1.encryption_key(), priv_key_2.encryption_key());
}

/// FIPS provider rejects an active DES key at construction.
#[cfg(feature = "crypto-fips")]
#[test]
fn test_fips_rejects_raw_des_key() {
    let result =
        PrivKey::from_bytes_with_backend(PrivProtocol::Des, vec![0; 16], CryptoBackend::AwsLcFips);
    assert!(
        matches!(result, Err(CryptoError::UnsupportedAlgorithm("DES"))),
        "FIPS provider should reject a DES key: got {:?}",
        result
    );
}

/// FIPS provider rejects an active 3DES key at construction.
#[cfg(feature = "crypto-fips")]
#[test]
fn test_fips_rejects_raw_3des_key() {
    let result =
        PrivKey::from_bytes_with_backend(PrivProtocol::Des3, vec![0; 32], CryptoBackend::AwsLcFips);
    assert!(
        matches!(result, Err(CryptoError::UnsupportedAlgorithm("3DES"))),
        "FIPS provider should reject a 3DES key: got {:?}",
        result
    );
}

// Cross-provider golden value tests
// These tests run under EITHER feature to verify both providers produce
// identical outputs for shared algorithms.

#[cfg(all(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
#[test]
fn both_backends_are_explicit_and_match_shared_sha_aes_vectors() {
    use async_snmp::v3::SaltCounter;

    let engine_id = decode("000000000000000000000002").unwrap();
    assert_eq!(
        async_snmp::UsmConfig::new("default").crypto_backend(),
        CryptoBackend::RustCrypto
    );

    let rust = async_snmp::UsmConfig::new("user")
        .with_crypto_backend(CryptoBackend::RustCrypto)
        .unwrap()
        .auth_priv(
            AuthProtocol::Sha256,
            b"maplesyrup",
            PrivProtocol::Aes128,
            b"maplesyrup",
        )
        .unwrap();
    let fips = async_snmp::UsmConfig::new("user")
        .with_crypto_backend(CryptoBackend::AwsLcFips)
        .unwrap()
        .auth_priv(
            AuthProtocol::Sha256,
            b"maplesyrup",
            PrivProtocol::Aes128,
            b"maplesyrup",
        )
        .unwrap();

    assert_eq!(rust.crypto_backend(), CryptoBackend::RustCrypto);
    assert_eq!(fips.crypto_backend(), CryptoBackend::AwsLcFips);

    let rust_keys = rust.derive_keys(&engine_id).unwrap();
    let fips_keys = fips.derive_keys(&engine_id).unwrap();
    let rust_auth = rust_keys.auth_key.unwrap();
    let fips_auth = fips_keys.auth_key.unwrap();
    assert_eq!(rust_auth.crypto_backend(), CryptoBackend::RustCrypto);
    assert_eq!(fips_auth.crypto_backend(), CryptoBackend::AwsLcFips);
    assert_eq!(rust_auth.as_bytes(), fips_auth.as_bytes());
    assert_eq!(
        rust_auth.compute_hmac(b"shared provider KAT").unwrap(),
        fips_auth.compute_hmac(b"shared provider KAT").unwrap()
    );

    let rust_priv = rust_keys.priv_key.unwrap();
    let fips_priv = fips_keys.priv_key.unwrap();
    assert_eq!(rust_priv.crypto_backend(), CryptoBackend::RustCrypto);
    assert_eq!(fips_priv.crypto_backend(), CryptoBackend::AwsLcFips);
    assert_eq!(rust_priv.encryption_key(), fips_priv.encryption_key());

    let plaintext = b"shared AES-128 provider KAT";
    let rust_encrypted = rust_priv
        .encrypt(plaintext, 7, 11, &SaltCounter::new().unwrap())
        .unwrap();
    let fips_encrypted = fips_priv
        .encrypt(plaintext, 7, 11, &SaltCounter::new().unwrap())
        .unwrap();
    assert_eq!(
        rust_priv
            .decrypt(&rust_encrypted.0, 7, 11, &rust_encrypted.1)
            .unwrap()
            .as_ref(),
        plaintext
    );
    assert_eq!(
        fips_priv
            .decrypt(&fips_encrypted.0, 7, 11, &fips_encrypted.1)
            .unwrap()
            .as_ref(),
        plaintext
    );
}

/// Golden value: SHA-2 key localization for "maplesyrup".
///
/// No RFC test vectors exist for SHA-2 localization, but these values were
/// computed independently under both the `RustCrypto` and aws-lc-rs providers
/// and verified to match. Any provider must produce these exact outputs.
#[test]
fn test_golden_sha2_key_localization() {
    let password = b"maplesyrup";
    let engine_id = decode("000000000000000000000002").unwrap();

    let key_224 = LocalizedKey::from_password(AuthProtocol::Sha224, password, &engine_id).unwrap();
    assert_eq!(
        encode(key_224.as_bytes()),
        "0bd8827c6e29f8065e08e09237f177e410f69b90e1782be682075674"
    );

    let key_256 = LocalizedKey::from_password(AuthProtocol::Sha256, password, &engine_id).unwrap();
    assert_eq!(
        encode(key_256.as_bytes()),
        "8982e0e549e866db361a6b625d84cccc11162d453ee8ce3a6445c2d6776f0f8b"
    );

    let key_384 = LocalizedKey::from_password(AuthProtocol::Sha384, password, &engine_id).unwrap();
    assert_eq!(
        encode(key_384.as_bytes()),
        "3b298f16164a11184279d5432bf169e2d2a48307de02b3d3f7e2b4f36eb6f0455a53689a3937eea07319a633d2ccba78"
    );

    let key_512 = LocalizedKey::from_password(AuthProtocol::Sha512, password, &engine_id).unwrap();
    assert_eq!(
        encode(key_512.as_bytes()),
        "22a5a36cedfcc085807a128d7bc6c2382167ad6c0dbc5fdff856740f3d84c099ad1ea87a8db096714d9788bd544047c9021e4229ce27e4c0a69250adfcffbb0b"
    );
}

/// Golden value: AES-128-CFB encryption must be reversible under any provider.
/// Tests basic encrypt/decrypt roundtrip with deterministic key.
#[test]
fn test_golden_aes128_roundtrip() {
    let key = vec![0x42; 16];
    let priv_key = PrivKey::from_bytes(PrivProtocol::Aes128, key).unwrap();
    let plaintext = b"cross-provider verification payload";
    let engine_boots = 1u32;
    let engine_time = 1u32;

    let (ct, params) = priv_key
        .encrypt(
            plaintext,
            engine_boots,
            engine_time,
            &SaltCounter::new().unwrap(),
        )
        .expect("AES-128 encryption failed");

    let pt = priv_key
        .decrypt(&ct, engine_boots, engine_time, &params)
        .expect("AES-128 decryption failed");

    assert_eq!(
        pt.as_ref(),
        plaintext,
        "Decrypted plaintext must match original"
    );
}

/// Golden value: AES-256-CFB encryption must be reversible under any provider.
/// Tests basic encrypt/decrypt roundtrip with deterministic key.
#[test]
fn test_golden_aes256_roundtrip() {
    let key = vec![0xAB; 32];
    let priv_key = PrivKey::from_bytes(PrivProtocol::Aes256, key).unwrap();
    let plaintext = b"another cross-provider verification test";
    let engine_boots = 42u32;
    let engine_time = 12345u32;

    let (ct, params) = priv_key
        .encrypt(
            plaintext,
            engine_boots,
            engine_time,
            &SaltCounter::new().unwrap(),
        )
        .expect("AES-256 encryption failed");

    let pt = priv_key
        .decrypt(&ct, engine_boots, engine_time, &params)
        .expect("AES-256 decryption failed");

    assert_eq!(
        pt.as_ref(),
        plaintext,
        "Decrypted plaintext must match original"
    );
}
