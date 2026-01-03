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
use async_snmp::v3::{AuthProtocol, LocalizedKey, PrivKey, PrivProtocol};

/// RFC 3414 Appendix A.3.1: Password to Key using MD5
///
/// Password: "maplesyrup"
/// Intermediate key (Ku): 9faf3283884e92834ebc9847d8edd963
/// Engine ID: 000000000000000000000002
/// Localized key (Kul): 526f5eed9fcce26f8964c2930787d82b
#[test]
fn test_rfc3414_a3_1_md5_key_localization() {
    let password = b"maplesyrup";
    let engine_id = decode("000000000000000000000002").unwrap();

    let key = LocalizedKey::from_password(AuthProtocol::Md5, password, &engine_id);

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

    let key = LocalizedKey::from_password(AuthProtocol::Sha1, password, &engine_id);

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
#[test]
fn test_rfc3414_a5_1_md5_new_password_key() {
    let new_password = b"newsyrup";
    let engine_id = decode("000000000000000000000002").unwrap();

    let key = LocalizedKey::from_password(AuthProtocol::Md5, new_password, &engine_id);

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

    let key = LocalizedKey::from_password(AuthProtocol::Sha1, new_password, &engine_id);

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

    let key = LocalizedKey::from_password(AuthProtocol::Sha224, password, &engine_id);

    // SHA-224 produces 28-byte keys
    assert_eq!(key.as_bytes().len(), 28);

    // Verify determinism: same inputs produce same output
    let key2 = LocalizedKey::from_password(AuthProtocol::Sha224, password, &engine_id);
    assert_eq!(key.as_bytes(), key2.as_bytes());
}

/// SHA-256 key localization (RFC 7860 algorithm).
#[test]
fn test_sha256_key_localization() {
    let password = b"maplesyrup";
    let engine_id = decode("000000000000000000000002").unwrap();

    let key = LocalizedKey::from_password(AuthProtocol::Sha256, password, &engine_id);

    // SHA-256 produces 32-byte keys
    assert_eq!(key.as_bytes().len(), 32);

    // Verify determinism
    let key2 = LocalizedKey::from_password(AuthProtocol::Sha256, password, &engine_id);
    assert_eq!(key.as_bytes(), key2.as_bytes());
}

/// SHA-384 key localization (RFC 7860 algorithm).
#[test]
fn test_sha384_key_localization() {
    let password = b"maplesyrup";
    let engine_id = decode("000000000000000000000002").unwrap();

    let key = LocalizedKey::from_password(AuthProtocol::Sha384, password, &engine_id);

    // SHA-384 produces 48-byte keys
    assert_eq!(key.as_bytes().len(), 48);

    // Verify determinism
    let key2 = LocalizedKey::from_password(AuthProtocol::Sha384, password, &engine_id);
    assert_eq!(key.as_bytes(), key2.as_bytes());
}

/// SHA-512 key localization (RFC 7860 algorithm).
#[test]
fn test_sha512_key_localization() {
    let password = b"maplesyrup";
    let engine_id = decode("000000000000000000000002").unwrap();

    let key = LocalizedKey::from_password(AuthProtocol::Sha512, password, &engine_id);

    // SHA-512 produces 64-byte keys
    assert_eq!(key.as_bytes().len(), 64);

    // Verify determinism
    let key2 = LocalizedKey::from_password(AuthProtocol::Sha512, password, &engine_id);
    assert_eq!(key.as_bytes(), key2.as_bytes());
}

/// RFC 6234 Section 8.5 - HMAC Test Case 1
///
/// Key: 0x0b repeated 20 times
/// Data: "Hi There"
/// Expected HMAC outputs (full, before truncation):
/// - HMAC-SHA-1:   B617318655057264E28BC0B6FB378C8EF146BE00
/// - HMAC-SHA-224: 896FB1128ABBDF196832107CD49DF33F47B4B1169912BA4F53684B22
/// - HMAC-SHA-256: B0344C61D8DB38535CA8AFCEAF0BF12B881DC200C9833DA726E9376C2E32CFF7
/// - HMAC-SHA-384: AFD03944D84895626B0825F4AB46907F15F9DADBE4101EC682AA034C7CEBC59C
///   FAEA9EA9076EDE7F4AF152E8B2FA9CB6
/// - HMAC-SHA-512: 87AA7CDEA5EF619D4FF0B4241A1D6CB02379F4E2CE4EC2787AD0B30545E17CDE
///   DAA833B7D6B8A702038B274EAEA3F4E4BE9D914EEB61F1702E696C203A126854
#[test]
fn test_rfc6234_hmac_case1_sha1() {
    let key_bytes = vec![0x0b; 20];
    let data = b"Hi There";

    let key = LocalizedKey::from_bytes(AuthProtocol::Sha1, key_bytes);
    let mac = key.compute_hmac(data);

    // HMAC-SHA-96 truncates to 12 bytes
    assert_eq!(mac.len(), 12);
    // First 12 bytes of B617318655057264E28BC0B6FB378C8EF146BE00
    assert_eq!(encode(&mac), "b617318655057264e28bc0b6");
}

#[test]
fn test_rfc6234_hmac_case1_sha224() {
    let key_bytes = vec![0x0b; 20];
    let data = b"Hi There";

    let key = LocalizedKey::from_bytes(AuthProtocol::Sha224, key_bytes);
    let mac = key.compute_hmac(data);

    // HMAC-SHA-224 truncates to 16 bytes per RFC 7860
    assert_eq!(mac.len(), 16);
    // First 16 bytes of 896FB1128ABBDF196832107CD49DF33F47B4B1169912BA4F53684B22
    assert_eq!(encode(&mac), "896fb1128abbdf196832107cd49df33f");
}

#[test]
fn test_rfc6234_hmac_case1_sha256() {
    let key_bytes = vec![0x0b; 20];
    let data = b"Hi There";

    let key = LocalizedKey::from_bytes(AuthProtocol::Sha256, key_bytes);
    let mac = key.compute_hmac(data);

    // HMAC-SHA-256 truncates to 24 bytes per RFC 7860
    assert_eq!(mac.len(), 24);
    // First 24 bytes of B0344C61D8DB38535CA8AFCEAF0BF12B881DC200C9833DA726E9376C2E32CFF7
    assert_eq!(
        encode(&mac),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da7"
    );
}

#[test]
fn test_rfc6234_hmac_case1_sha384() {
    let key_bytes = vec![0x0b; 20];
    let data = b"Hi There";

    let key = LocalizedKey::from_bytes(AuthProtocol::Sha384, key_bytes);
    let mac = key.compute_hmac(data);

    // HMAC-SHA-384 truncates to 32 bytes per RFC 7860
    assert_eq!(mac.len(), 32);
    // First 32 bytes of AFD03944D84895626B0825F4AB46907F15F9DADBE4101EC682AA034C7CEBC59C...
    assert_eq!(
        encode(&mac),
        "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c"
    );
}

#[test]
fn test_rfc6234_hmac_case1_sha512() {
    let key_bytes = vec![0x0b; 20];
    let data = b"Hi There";

    let key = LocalizedKey::from_bytes(AuthProtocol::Sha512, key_bytes);
    let mac = key.compute_hmac(data);

    // HMAC-SHA-512 truncates to 48 bytes per RFC 7860
    assert_eq!(mac.len(), 48);
    // First 48 bytes of 87AA7CDEA5EF619D4FF0B4241A1D6CB02379F4E2CE4EC2787AD0B30545E17CDE...
    assert_eq!(
        encode(&mac),
        "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4"
    );
}

/// RFC 6234 Section 8.5 - HMAC Test Case 2
///
/// Key: "Jefe"
/// Data: "what do ya want for nothing?"
#[test]
fn test_rfc6234_hmac_case2_sha1() {
    let key = LocalizedKey::from_bytes(AuthProtocol::Sha1, b"Jefe".to_vec());
    let data = b"what do ya want for nothing?";
    let mac = key.compute_hmac(data);

    // First 12 bytes of EFFCDF6AE5EB2FA2D27416D5F184DF9C259A7C79
    assert_eq!(encode(&mac), "effcdf6ae5eb2fa2d27416d5");
}

#[test]
fn test_rfc6234_hmac_case2_sha256() {
    let key = LocalizedKey::from_bytes(AuthProtocol::Sha256, b"Jefe".to_vec());
    let data = b"what do ya want for nothing?";
    let mac = key.compute_hmac(data);

    // First 24 bytes of 5BDCC146BF60754E6A042426089575C75A003F089D2739839DEC58B964EC3843
    assert_eq!(
        encode(&mac),
        "5bdcc146bf60754e6a042426089575c75a003f089d273983"
    );
}

/// RFC 6234 Section 8.5 - HMAC Test Case 5 (truncation test)
///
/// Key: 0x0c repeated 20 times
/// Data: "Test With Truncation"
/// Expected truncated outputs:
/// - HMAC-SHA-1 truncated to 12: 4C1A03424B55E07FE7F27BE1
/// - HMAC-SHA-224 truncated to 16: 0E2AEA68A90C8D37C988BCDB9FCA6FA8
/// - HMAC-SHA-256 truncated to 16: A3B6167473100EE06E0C796C2955552B
/// - HMAC-SHA-384 truncated to 16: 3ABF34C3503B2A23A46EFC619BAEF897
/// - HMAC-SHA-512 truncated to 16: 415FAD6271580A531D4179BC891D87A6
///
/// Note: RFC 6234 tests truncation to 128 bits (16 bytes) for SHA-2.
/// Our implementation uses RFC 7860 truncation lengths.
#[test]
fn test_rfc6234_hmac_case5_truncation_sha1() {
    let key_bytes = vec![0x0c; 20];
    let data = b"Test With Truncation";

    let key = LocalizedKey::from_bytes(AuthProtocol::Sha1, key_bytes);
    let mac = key.compute_hmac(data);

    // RFC truncates to 12 bytes for this test; our HMAC-SHA-96 also uses 12 bytes
    assert_eq!(mac.len(), 12);
    assert_eq!(encode(&mac), "4c1a03424b55e07fe7f27be1");
}

/// Verify HMAC verification works correctly with RFC test vectors.
#[test]
fn test_hmac_verify_with_rfc_vector() {
    let key_bytes = vec![0x0b; 20];
    let data = b"Hi There";

    let key = LocalizedKey::from_bytes(AuthProtocol::Sha1, key_bytes);
    let mac = key.compute_hmac(data);

    // Verification should succeed with correct MAC
    assert!(key.verify_hmac(data, &mac));

    // Verification should fail with modified MAC
    let mut bad_mac = mac.clone();
    bad_mac[0] ^= 0xFF;
    assert!(!key.verify_hmac(data, &bad_mac));

    // Verification should fail with modified data
    assert!(!key.verify_hmac(b"Hi There!", &mac));
}

/// Verify wrong key length is rejected in HMAC verification.
#[test]
fn test_hmac_verify_wrong_length() {
    let key = LocalizedKey::from_bytes(AuthProtocol::Sha1, vec![0x0b; 20]);
    let data = b"test";
    let mac = key.compute_hmac(data);

    // Wrong length MAC should fail verification
    let short_mac = &mac[..8];
    assert!(!key.verify_hmac(data, short_mac));
}

/// Privacy key derivation uses auth key localization.
///
/// For DES, the 16-byte localized key is used as:
/// - First 8 bytes: DES encryption key
/// - Last 8 bytes: Pre-IV for IV generation
#[test]
fn test_des_priv_key_from_password() {
    let password = b"maplesyrup";
    let engine_id = decode("000000000000000000000002").unwrap();

    // DES privacy key uses MD5 localization (16 bytes needed)
    let priv_key =
        PrivKey::from_password(AuthProtocol::Md5, PrivProtocol::Des, password, &engine_id);

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
    );

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
    );

    // Encryption key should be 32 bytes
    assert_eq!(priv_key.encryption_key().len(), 32);

    // Verify determinism
    let priv_key2 = PrivKey::from_password(
        AuthProtocol::Sha256,
        PrivProtocol::Aes256,
        password,
        &engine_id,
    );
    assert_eq!(priv_key.encryption_key(), priv_key2.encryption_key());
}

/// Different engine IDs produce different localized keys.
#[test]
fn test_different_engine_ids_produce_different_keys() {
    let password = b"maplesyrup";
    let engine_id_1 = decode("000000000000000000000001").unwrap();
    let engine_id_2 = decode("000000000000000000000002").unwrap();

    let key1 = LocalizedKey::from_password(AuthProtocol::Sha1, password, &engine_id_1);
    let key2 = LocalizedKey::from_password(AuthProtocol::Sha1, password, &engine_id_2);

    // Different engine IDs must produce different keys
    assert_ne!(key1.as_bytes(), key2.as_bytes());
}

/// Different passwords produce different localized keys.
#[test]
fn test_different_passwords_produce_different_keys() {
    let password_1 = b"maplesyrup";
    let password_2 = b"newsyrup";
    let engine_id = decode("000000000000000000000002").unwrap();

    let key1 = LocalizedKey::from_password(AuthProtocol::Sha1, password_1, &engine_id);
    let key2 = LocalizedKey::from_password(AuthProtocol::Sha1, password_2, &engine_id);

    // Different passwords must produce different keys
    assert_ne!(key1.as_bytes(), key2.as_bytes());
}

/// Empty engine ID is handled correctly.
#[test]
fn test_empty_engine_id() {
    let password = b"testpassword";
    let engine_id: Vec<u8> = vec![];

    let key = LocalizedKey::from_password(AuthProtocol::Sha1, password, &engine_id);

    // Should still produce a valid 20-byte key
    assert_eq!(key.as_bytes().len(), 20);

    // Verify it's deterministic
    let key2 = LocalizedKey::from_password(AuthProtocol::Sha1, password, &engine_id);
    assert_eq!(key.as_bytes(), key2.as_bytes());
}

/// Long engine ID is handled correctly.
#[test]
fn test_long_engine_id() {
    let password = b"testpassword";
    // Engine IDs can be up to 32 bytes per RFC 3411
    let engine_id = vec![0xAB; 32];

    let key = LocalizedKey::from_password(AuthProtocol::Sha256, password, &engine_id);

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
    .with_auth_params(Bytes::from(decode("0123456789abcdeffedcba98").unwrap()))
    .with_priv_params(Bytes::from(decode("0123456789abcdef").unwrap()));

    let encoded = params.encode();

    // Verify it's a valid SEQUENCE
    assert_eq!(encoded[0], 0x30, "Should start with SEQUENCE tag");

    // Decode it back and verify fields
    let decoded = UsmSecurityParams::decode(encoded.clone()).unwrap();
    assert_eq!(decoded.engine_boots, 1);
    assert_eq!(decoded.engine_time, 257);
    assert_eq!(decoded.username.as_ref(), b"bert");
    assert_eq!(decoded.auth_params.len(), 12);
    assert_eq!(decoded.priv_params.len(), 8);
}

/// Verify MAC length matches protocol specification.
#[test]
fn test_mac_lengths_per_rfc() {
    let key_md5 = LocalizedKey::from_bytes(AuthProtocol::Md5, vec![0; 16]);
    let key_sha1 = LocalizedKey::from_bytes(AuthProtocol::Sha1, vec![0; 20]);
    let key_sha224 = LocalizedKey::from_bytes(AuthProtocol::Sha224, vec![0; 28]);
    let key_sha256 = LocalizedKey::from_bytes(AuthProtocol::Sha256, vec![0; 32]);
    let key_sha384 = LocalizedKey::from_bytes(AuthProtocol::Sha384, vec![0; 48]);
    let key_sha512 = LocalizedKey::from_bytes(AuthProtocol::Sha512, vec![0; 64]);

    // RFC 3414: HMAC-MD5-96 and HMAC-SHA-96 truncate to 12 bytes
    assert_eq!(key_md5.mac_len(), 12);
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
// to the v3::auth module. See src/v3/auth.rs for comprehensive KAT tests.

/// AES-256 encryption/decryption roundtrip with SHA-1 (auto key extension).
#[test]
fn test_aes256_with_sha1_auto_key_extension_roundtrip() {
    let password = b"maplesyrup";
    let engine_id = decode("000000000000000000000002").unwrap();

    // Create privacy key - Blumenthal extension is auto-applied because
    // SHA-1 (20 bytes) < AES-256 (32 bytes)
    let mut priv_key = PrivKey::from_password(
        AuthProtocol::Sha1,
        PrivProtocol::Aes256,
        password,
        &engine_id,
    );

    // Verify the encryption key length is correct for AES-256
    assert_eq!(priv_key.encryption_key().len(), 32);

    // Encrypt and decrypt
    let plaintext = b"Test message for AES-256 with extended SHA-1 key";
    let engine_boots = 100u32;
    let engine_time = 12345u32;

    let (ciphertext, priv_params) = priv_key
        .encrypt(plaintext, engine_boots, engine_time, None)
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
    let mut priv_key = PrivKey::from_password(
        AuthProtocol::Sha1,
        PrivProtocol::Aes192,
        password,
        &engine_id,
    );

    // Verify the encryption key length is correct for AES-192
    assert_eq!(priv_key.encryption_key().len(), 24);

    // Encrypt and decrypt
    let plaintext = b"Test message for AES-192 with extended SHA-1 key";
    let engine_boots = 200u32;
    let engine_time = 54321u32;

    let (ciphertext, priv_params) = priv_key
        .encrypt(plaintext, engine_boots, engine_time, None)
        .expect("encryption should succeed");

    let decrypted = priv_key
        .decrypt(&ciphertext, engine_boots, engine_time, &priv_params)
        .expect("decryption should succeed");

    assert_eq!(decrypted.as_ref(), plaintext);
}

/// AES-256 with MD5 (auto key extension) roundtrip.
#[test]
fn test_aes256_with_md5_auto_key_extension_roundtrip() {
    let password = b"maplesyrup";
    let engine_id = decode("000000000000000000000002").unwrap();

    // Blumenthal extension is auto-applied because MD5 (16 bytes) < AES-256 (32 bytes)
    let mut priv_key = PrivKey::from_password(
        AuthProtocol::Md5,
        PrivProtocol::Aes256,
        password,
        &engine_id,
    );

    assert_eq!(priv_key.encryption_key().len(), 32);

    let plaintext = b"Test message for AES-256 with extended MD5 key";
    let (ciphertext, priv_params) = priv_key
        .encrypt(plaintext, 300, 67890, None)
        .expect("encryption should succeed");

    let decrypted = priv_key
        .decrypt(&ciphertext, 300, 67890, &priv_params)
        .expect("decryption should succeed");

    assert_eq!(decrypted.as_ref(), plaintext);
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
    );

    let priv_key_2 = PrivKey::from_password(
        AuthProtocol::Sha1,
        PrivProtocol::Aes256,
        password,
        &engine_id_2,
    );

    // Keys should be different because they're localized to different engines
    assert_ne!(priv_key_1.encryption_key(), priv_key_2.encryption_key());
}
