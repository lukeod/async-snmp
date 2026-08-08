#![cfg(all(
    feature = "v3",
    not(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))
))]

use async_snmp::{Auth, SecurityLevel};

#[test]
fn no_auth_usm_configuration_is_available_without_crypto() {
    let config = Auth::usm("readonly");

    assert_eq!(config.security_level(), SecurityLevel::NoAuthNoPriv);
    assert_eq!(config.username().as_ref(), b"readonly");
}
