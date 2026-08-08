use async_snmp::{Auth, ClientConfig, CommunityVersion};

#[test]
fn community_client_configuration_is_available_without_crypto() {
    let config = ClientConfig {
        auth: Auth::v2c("public"),
        ..ClientConfig::default()
    };

    assert!(matches!(
        config.auth,
        Auth::Community {
            version: CommunityVersion::V2c,
            ..
        }
    ));
}
