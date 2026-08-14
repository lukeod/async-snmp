//! Cargo feature contract tests.

fn manifest_feature_items(feature: &str) -> Vec<&'static str> {
    let manifest = include_str!("../Cargo.toml");
    let feature_table = manifest
        .split_once("[features]")
        .expect("manifest must contain a features table")
        .1;
    let features = feature_table
        .split_once("\n[")
        .map_or(feature_table, |(table, _)| table);
    let assignment = features
        .lines()
        .find(|line| line.trim_start().starts_with(&format!("{feature} =")))
        .unwrap_or_else(|| panic!("feature {feature:?} must be declared"));
    let (_, items) = assignment
        .split_once('=')
        .expect("feature declaration must be an assignment");

    items
        .trim()
        .strip_prefix('[')
        .and_then(|items| items.strip_suffix(']'))
        .expect("feature declaration must be a single-line array")
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(|item| {
            item.strip_prefix('"')
                .and_then(|item| item.strip_suffix('"'))
                .expect("feature names must be quoted strings")
        })
        .collect()
}

#[test]
fn manifest_defaults_are_exactly_rustcrypto() {
    assert_eq!(manifest_feature_items("default"), ["crypto-rustcrypto"]);
}

#[test]
fn no_auth_no_priv_is_independent_of_crypto_features() {
    use async_snmp::{Auth, SecurityLevel, UsmConfig, UsmUser};

    let Auth::Usm(auth) = Auth::usm("readonly") else {
        panic!("expected USM configuration");
    };
    assert_eq!(auth.security_level(), SecurityLevel::NoAuthNoPriv);
    assert_eq!(
        UsmConfig::new("readonly").security_level(),
        SecurityLevel::NoAuthNoPriv
    );
    assert_eq!(
        UsmUser::new("readonly").maximum_security_level(),
        SecurityLevel::NoAuthNoPriv
    );
}

#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
#[test]
fn supported_password_and_master_key_credentials_are_accepted_during_configuration() {
    use async_snmp::{AuthProtocol, MasterKeys, PrivProtocol, SecurityLevel, UsmConfig, UsmUser};

    let password_auth = UsmConfig::new("user")
        .auth(AuthProtocol::Sha256, b"authpassword")
        .unwrap();
    assert_eq!(password_auth.security_level(), SecurityLevel::AuthNoPriv);

    let password_priv = UsmConfig::new("user")
        .auth_priv(
            AuthProtocol::Sha256,
            b"authpassword",
            PrivProtocol::Aes128,
            b"privpassword",
        )
        .unwrap();
    assert_eq!(password_priv.security_level(), SecurityLevel::AuthPriv);

    let user = UsmUser::new("user")
        .auth(AuthProtocol::Sha256, b"authpassword")
        .unwrap();
    assert_eq!(user.maximum_security_level(), SecurityLevel::AuthNoPriv);

    let master_auth = MasterKeys::new(AuthProtocol::Sha256, b"authpassword").unwrap();
    let master_auth = UsmConfig::new("user")
        .with_master_keys(master_auth)
        .unwrap();
    assert_eq!(master_auth.security_level(), SecurityLevel::AuthNoPriv);

    let master_priv = MasterKeys::new(AuthProtocol::Sha256, b"authpassword")
        .unwrap()
        .with_privacy(PrivProtocol::Aes128, b"privpassword")
        .unwrap();
    let master_priv = UsmConfig::new("user")
        .with_master_keys(master_priv)
        .unwrap();
    assert_eq!(master_priv.security_level(), SecurityLevel::AuthPriv);

    let config = async_snmp::UsmConfig::new("user")
        .auth(AuthProtocol::Sha256, b"authpassword")
        .unwrap();
    assert_eq!(config.security_level(), SecurityLevel::AuthNoPriv);
}

#[cfg(feature = "crypto-fips")]
#[test]
fn fips_capability_errors_are_returned_by_credential_configuration() {
    use async_snmp::{
        AuthProtocol, CryptoBackend, CryptoError, MasterKeys, PrivProtocol, UsmConfig,
    };

    let fips = UsmConfig::new("user")
        .with_crypto_backend(CryptoBackend::AwsLcFips)
        .unwrap();
    assert!(matches!(
        fips.clone().auth(AuthProtocol::Md5, b"authpassword"),
        Err(CryptoError::UnsupportedAlgorithm("MD5"))
    ));
    assert!(matches!(
        fips.auth_priv(
            AuthProtocol::Sha256,
            b"authpassword",
            PrivProtocol::Des,
            b"privpassword",
        ),
        Err(CryptoError::UnsupportedAlgorithm("DES"))
    ));
    assert!(matches!(
        MasterKeys::new_with_backend(AuthProtocol::Md5, b"authpassword", CryptoBackend::AwsLcFips,),
        Err(CryptoError::UnsupportedAlgorithm("MD5"))
    ));
    assert!(matches!(
        MasterKeys::new_with_backend(
            AuthProtocol::Sha256,
            b"authpassword",
            CryptoBackend::AwsLcFips,
        )
        .unwrap()
        .with_privacy_same_password(PrivProtocol::Des),
        Err(CryptoError::UnsupportedAlgorithm("DES"))
    ));
}

#[cfg(all(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
#[test]
fn rustcrypto_has_operational_precedence_when_both_providers_compile() {
    use async_snmp::{CryptoBackend, UsmConfig};

    assert_eq!(
        CryptoBackend::default_backend(),
        Some(CryptoBackend::RustCrypto)
    );
    assert_eq!(
        UsmConfig::new("user").crypto_backend(),
        Some(CryptoBackend::RustCrypto)
    );
}
