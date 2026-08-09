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

#[cfg(all(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
#[test]
fn rustcrypto_has_operational_precedence_when_both_providers_compile() {
    use async_snmp::{CryptoBackend, UsmConfig};

    assert_eq!(CryptoBackend::default(), CryptoBackend::RustCrypto);
    assert_eq!(
        UsmConfig::new("user").crypto_backend(),
        CryptoBackend::RustCrypto
    );
}
