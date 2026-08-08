#![cfg(not(any(feature = "crypto-rustcrypto", feature = "crypto-fips")))]

use async_snmp::{Auth, AuthProtocol, SecurityLevel};

#[test]
fn no_auth_usm_configuration_is_available_without_crypto() {
    let config = Auth::usm("readonly");

    assert_eq!(config.security_level(), SecurityLevel::NoAuthNoPriv);
    assert_eq!(config.username().as_ref(), b"readonly");
}

#[test]
fn password_usm_configuration_is_constructible_without_crypto() {
    let config = Auth::usm("readonly").auth(AuthProtocol::Sha256, "authpassword");

    assert_eq!(config.security_level(), SecurityLevel::AuthNoPriv);
    assert_eq!(config.auth_protocol(), Some(AuthProtocol::Sha256));
}
