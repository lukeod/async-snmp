#![cfg(not(any(feature = "crypto-rustcrypto", feature = "crypto-fips")))]

use async_snmp::{
    Auth, AuthProtocol, CryptoError, PrivProtocol, SecurityLevel, UsmConfig, UsmUser,
};

#[test]
fn no_auth_usm_configuration_is_available_without_crypto() {
    let auth = Auth::usm("readonly");
    let Auth::Usm(config) = auth else {
        panic!("expected USM authentication");
    };

    assert_eq!(config.security_level(), SecurityLevel::NoAuthNoPriv);
    assert_eq!(config.username().as_ref(), b"readonly");

    let Auth::Usm(config) = Auth::usm_builder("readonly")
        .context_name("tenant/blue")
        .build()
        .unwrap()
    else {
        panic!("expected USM authentication");
    };
    assert_eq!(config.security_level(), SecurityLevel::NoAuthNoPriv);
    assert_eq!(config.configured_context_name().as_ref(), b"tenant/blue");
}

#[test]
fn password_usm_configuration_is_rejected_without_crypto() {
    let error = Auth::usm_builder("readonly")
        .auth(AuthProtocol::Sha256, "authpassword")
        .build()
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
fn backend_selection_exposes_unavailable_state_without_crypto() {
    assert_eq!(
        async_snmp::CryptoBackend::default(),
        async_snmp::CryptoBackend::Unavailable
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
