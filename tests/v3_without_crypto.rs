#![cfg(not(any(feature = "crypto-rustcrypto", feature = "crypto-fips")))]

use async_snmp::{
    Auth, AuthProtocol, CryptoBackend, CryptoError, CryptoResult, PrivProtocol, SecurityLevel,
    UsmConfig, UsmUser,
};
use bytes::Bytes;

#[test]
fn no_crypto_usm_public_signatures_use_nameable_types() {
    let config = UsmConfig::new("readonly");
    let username: &Bytes = config.username();
    let context_name: &Bytes = config.configured_context_name();
    let auth_protocol: Option<AuthProtocol> = config.auth_protocol();
    let priv_protocol: Option<PrivProtocol> = config.priv_protocol();
    let security_level: SecurityLevel = config.security_level();
    let backend: Option<CryptoBackend> = config.crypto_backend();
    let backend_selection: CryptoResult<UsmConfig> = config
        .clone()
        .with_crypto_backend(CryptoBackend::RustCrypto);

    assert_eq!(username.as_ref(), b"readonly");
    assert!(context_name.is_empty());
    assert_eq!(auth_protocol, None);
    assert_eq!(priv_protocol, None);
    assert_eq!(security_level, SecurityLevel::NoAuthNoPriv);
    assert_eq!(backend, None);
    assert_eq!(
        backend_selection.unwrap_err(),
        CryptoError::BackendNotCompiled(CryptoBackend::RustCrypto)
    );

    let user = UsmUser::new("readonly");
    let username: &Bytes = user.username();
    let auth_protocol: Option<AuthProtocol> = user.auth_protocol();
    let priv_protocol: Option<PrivProtocol> = user.priv_protocol();
    let security_level: SecurityLevel = user.maximum_security_level();
    let backend: Option<CryptoBackend> = user.crypto_backend();

    assert_eq!(username.as_ref(), b"readonly");
    assert_eq!(auth_protocol, None);
    assert_eq!(priv_protocol, None);
    assert_eq!(security_level, SecurityLevel::NoAuthNoPriv);
    assert_eq!(backend, None);
}

#[test]
fn no_auth_usm_configuration_is_available_without_crypto() {
    let auth = Auth::usm("readonly");
    let Auth::Usm(config) = auth else {
        panic!("expected USM authentication");
    };

    assert_eq!(config.security_level(), SecurityLevel::NoAuthNoPriv);
    assert_eq!(config.username().as_ref(), b"readonly");

    let config = UsmConfig::new("readonly").context_name("tenant/blue");
    assert_eq!(config.security_level(), SecurityLevel::NoAuthNoPriv);
    assert_eq!(config.configured_context_name().as_ref(), b"tenant/blue");
}

#[test]
fn password_usm_configuration_is_rejected_without_crypto() {
    let error = UsmConfig::new("readonly")
        .auth(AuthProtocol::Sha256, "authpassword")
        .unwrap_err();

    assert_eq!(error, CryptoError::BackendUnavailable);
    assert!(matches!(
        UsmConfig::new("readonly").auth(AuthProtocol::Sha256, "authpassword"),
        Err(CryptoError::BackendUnavailable)
    ));
    assert!(matches!(
        UsmUser::new("readonly").auth(AuthProtocol::Sha256, "authpassword"),
        Err(CryptoError::BackendUnavailable)
    ));
    assert!(matches!(
        UsmConfig::new("readonly").auth_priv(
            AuthProtocol::Sha256,
            "authpassword",
            PrivProtocol::Aes128,
            "privpassword",
        ),
        Err(CryptoError::BackendUnavailable)
    ));
    assert!(matches!(
        UsmUser::new("readonly").auth_priv(
            AuthProtocol::Sha256,
            "authpassword",
            PrivProtocol::Aes128,
            "privpassword",
        ),
        Err(CryptoError::BackendUnavailable)
    ));
}

#[test]
fn backend_capability_is_absent_without_crypto() {
    assert_eq!(async_snmp::CryptoBackend::default_backend(), None);
    assert!(!async_snmp::CryptoBackend::RustCrypto.is_compiled());
    assert!(!async_snmp::CryptoBackend::AwsLcFips.is_compiled());
    assert_eq!(
        UsmConfig::new("user")
            .with_crypto_backend(async_snmp::CryptoBackend::RustCrypto)
            .unwrap_err(),
        CryptoError::BackendNotCompiled(async_snmp::CryptoBackend::RustCrypto)
    );
}

#[cfg(feature = "agent")]
#[test]
fn agent_rejects_authenticated_user_before_build() {
    let result = async_snmp::Agent::builder().usm_user("authenticated", |user| {
        user.auth(AuthProtocol::Sha256, "authpassword")
    });

    assert!(matches!(result, Err(CryptoError::BackendUnavailable)));
}

#[test]
fn notification_receiver_rejects_authenticated_user_before_build() {
    let result = async_snmp::NotificationReceiver::builder().usm_user("authenticated", |user| {
        user.auth(AuthProtocol::Sha256, "authpassword")
    });

    assert!(matches!(result, Err(CryptoError::BackendUnavailable)));
}
