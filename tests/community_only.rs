use async_snmp::{Auth, ClientConfig, CommunityVersion};

#[test]
fn community_client_configuration_is_available_without_crypto() {
    let mut config = ClientConfig::default();
    config.auth = Auth::v2c("public");

    assert!(matches!(
        config.auth,
        Auth::Community {
            version: CommunityVersion::V2c,
            ..
        }
    ));
}
