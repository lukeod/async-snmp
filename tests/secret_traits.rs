//! Static trait-contract checks for secret-bearing public types.

use std::hash::Hash;

use async_snmp::{
    Auth, AuthProtocol, Community, CommunityResponsePolicy, CommunityVersion, PrivProtocol,
    RequestRegistration, SecurityLevel, UsmConfig, UsmUser,
};
use static_assertions::{assert_impl_all, assert_not_impl_any};

assert_not_impl_any!(Community: PartialEq, Eq, PartialOrd, Ord, Hash);
assert_not_impl_any!(Auth: PartialEq, Eq, PartialOrd, Ord, Hash);
assert_not_impl_any!(UsmConfig: PartialEq, Eq, PartialOrd, Ord, Hash);
assert_not_impl_any!(UsmUser: PartialEq, Eq, PartialOrd, Ord, Hash);
assert_not_impl_any!(RequestRegistration: PartialEq, Eq, PartialOrd, Ord, Hash);

#[cfg(feature = "agent")]
static_assertions::assert_not_impl_any!(async_snmp::SecurityName: PartialEq, Eq, PartialOrd, Ord, Hash);

#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
mod keys {
    use std::hash::Hash;

    use async_snmp::{CryptoBackend, MasterKey, MasterKeys};
    use static_assertions::{assert_impl_all, assert_not_impl_any};

    assert_not_impl_any!(MasterKey: PartialEq, Eq, PartialOrd, Ord, Hash);
    assert_not_impl_any!(MasterKeys: PartialEq, Eq, PartialOrd, Ord, Hash);
    assert_impl_all!(CryptoBackend: Copy, PartialEq, Eq, PartialOrd, Ord, Hash);
}

assert_impl_all!(CommunityVersion: Copy, PartialEq, Eq, PartialOrd, Ord, Hash);
assert_impl_all!(AuthProtocol: Copy, PartialEq, Eq, PartialOrd, Ord, Hash);
assert_impl_all!(PrivProtocol: Copy, PartialEq, Eq, PartialOrd, Ord, Hash);
assert_impl_all!(SecurityLevel: Copy, PartialEq, Eq, PartialOrd, Ord, Hash);
assert_impl_all!(CommunityResponsePolicy: Copy, PartialEq, Eq);

#[cfg(feature = "agent")]
static_assertions::assert_impl_all!(async_snmp::SecurityModel: Copy, PartialEq, Eq, Hash);

#[test]
fn secret_and_selector_trait_contracts_compile() {}

#[test]
fn community_public_matching_handles_protocol_octets_and_mismatches() {
    let configured = Community::from(&b"private\x00\xff"[..]);

    assert!(configured.matches(b"private\x00\xff"));
    assert!(!configured.matches(b"private\x00\xfe"));
    assert!(!configured.matches(b"private\x00"));
    assert!(!configured.matches(b"private\x00\xff\x00"));
}

#[cfg(feature = "agent")]
#[test]
fn security_name_public_matching_is_variant_aware_and_byte_exact() {
    use async_snmp::SecurityName;
    use bytes::Bytes;

    let community = SecurityName::Community(Community::from(&b"operator\x00\xff"[..]));
    let same_community = SecurityName::Community(Community::from(&b"operator\x00\xff"[..]));
    let other_community = SecurityName::Community(Community::from(&b"operator\x00\xfe"[..]));
    let short_community = SecurityName::Community(Community::from(&b"operator\x00"[..]));
    let same_bytes_usm = SecurityName::Usm(Bytes::from_static(b"operator\x00\xff"));

    assert!(community.matches(&same_community));
    assert!(!community.matches(&other_community));
    assert!(!community.matches(&short_community));
    assert!(!community.matches(&same_bytes_usm));
    assert!(!same_bytes_usm.matches(&community));

    let same_usm = SecurityName::Usm(Bytes::from_static(b"operator\x00\xff"));
    let other_usm = SecurityName::Usm(Bytes::from_static(b"operator\x00\xfe"));
    let long_usm = SecurityName::Usm(Bytes::from_static(b"operator\x00\xff\x00"));
    assert!(same_bytes_usm.matches(&same_usm));
    assert!(!same_bytes_usm.matches(&other_usm));
    assert!(!same_bytes_usm.matches(&long_usm));
}
