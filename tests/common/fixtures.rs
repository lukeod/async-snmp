//! Standard test fixtures with realistic MIB data.

use async_snmp::{Oid, Value, oid};
use std::collections::BTreeMap;

// =============================================================================
// MIB data fixtures (for TestHandler)
// =============================================================================

/// Standard system MIB entries (1.3.6.1.2.1.1).
///
/// Returns OIDs for:
/// - sysDescr.0 (1.3.6.1.2.1.1.1.0)
/// - sysObjectID.0 (1.3.6.1.2.1.1.2.0)
/// - sysUpTime.0 (1.3.6.1.2.1.1.3.0)
/// - sysContact.0 (1.3.6.1.2.1.1.4.0)
/// - sysName.0 (1.3.6.1.2.1.1.5.0)
/// - sysLocation.0 (1.3.6.1.2.1.1.6.0)
/// - sysServices.0 (1.3.6.1.2.1.1.7.0)
pub fn system_mib() -> BTreeMap<Oid, Value> {
    let mut data = BTreeMap::new();

    data.insert(
        oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
        Value::OctetString("Test SNMP Agent".into()),
    );
    data.insert(
        oid!(1, 3, 6, 1, 2, 1, 1, 2, 0),
        Value::ObjectIdentifier(oid!(1, 3, 6, 1, 4, 1, 99999)),
    );
    data.insert(oid!(1, 3, 6, 1, 2, 1, 1, 3, 0), Value::TimeTicks(123_456));
    data.insert(
        oid!(1, 3, 6, 1, 2, 1, 1, 4, 0),
        Value::OctetString("admin@test.local".into()),
    );
    data.insert(
        oid!(1, 3, 6, 1, 2, 1, 1, 5, 0),
        Value::OctetString("test-agent".into()),
    );
    data.insert(
        oid!(1, 3, 6, 1, 2, 1, 1, 6, 0),
        Value::OctetString("Test Lab".into()),
    );
    data.insert(oid!(1, 3, 6, 1, 2, 1, 1, 7, 0), Value::Integer(72));

    data
}

/// Interface table entries for testing WALK operations.
///
/// Creates `count` interface entries with ifIndex, ifDescr, ifType, etc.
pub fn interface_table(count: usize) -> BTreeMap<Oid, Value> {
    let mut data = BTreeMap::new();

    // ifNumber.0
    data.insert(
        oid!(1, 3, 6, 1, 2, 1, 2, 1, 0),
        Value::Integer(count as i32),
    );

    for i in 1..=count {
        let idx = i as u32;

        // ifIndex.{i}
        data.insert(
            oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 1, idx),
            Value::Integer(i as i32),
        );

        // ifDescr.{i}
        data.insert(
            oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 2, idx),
            Value::OctetString(format!("eth{}", i - 1).into()),
        );

        // ifType.{i} - ethernetCsmacd(6)
        data.insert(oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 3, idx), Value::Integer(6));

        // ifMtu.{i}
        data.insert(
            oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 4, idx),
            Value::Integer(1500),
        );

        // ifSpeed.{i} - 1 Gbps
        data.insert(
            oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 5, idx),
            Value::Gauge32(1_000_000_000),
        );

        // ifPhysAddress.{i}
        data.insert(
            oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 6, idx),
            Value::OctetString(vec![0x00, 0x11, 0x22, 0x33, 0x44, i as u8].into()),
        );

        // ifAdminStatus.{i} - up(1)
        data.insert(oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 7, idx), Value::Integer(1));

        // ifOperStatus.{i} - up(1)
        data.insert(oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 8, idx), Value::Integer(1));
    }

    data
}

/// Combine multiple fixture sets.
pub fn combined(fixtures: impl IntoIterator<Item = BTreeMap<Oid, Value>>) -> BTreeMap<Oid, Value> {
    let mut result = BTreeMap::new();
    for fixture in fixtures {
        result.extend(fixture);
    }
    result
}

// =============================================================================
// OID helper functions
// =============================================================================

/// sysDescr.0
pub fn sys_descr() -> Oid {
    oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)
}

/// sysObjectID.0
pub fn sys_object_id() -> Oid {
    oid!(1, 3, 6, 1, 2, 1, 1, 2, 0)
}

/// sysUpTime.0
pub fn sys_uptime() -> Oid {
    oid!(1, 3, 6, 1, 2, 1, 1, 3, 0)
}

/// sysContact.0
pub fn sys_contact() -> Oid {
    oid!(1, 3, 6, 1, 2, 1, 1, 4, 0)
}

/// sysName.0
pub fn sys_name() -> Oid {
    oid!(1, 3, 6, 1, 2, 1, 1, 5, 0)
}

/// sysLocation.0
pub fn sys_location() -> Oid {
    oid!(1, 3, 6, 1, 2, 1, 1, 6, 0)
}

/// sysServices.0
pub fn sys_services() -> Oid {
    oid!(1, 3, 6, 1, 2, 1, 1, 7, 0)
}

// =============================================================================
// Subtree roots (for walks)
// =============================================================================

/// System subtree root: 1.3.6.1.2.1.1
pub fn system_subtree() -> Oid {
    oid!(1, 3, 6, 1, 2, 1, 1)
}

/// Interfaces subtree root: 1.3.6.1.2.1.2
pub fn interfaces_subtree() -> Oid {
    oid!(1, 3, 6, 1, 2, 1, 2)
}

// =============================================================================
// Test OIDs
// =============================================================================

/// Nonexistent OID for testing NoSuchObject/NoSuchInstance
pub fn nonexistent_oid() -> Oid {
    oid!(1, 3, 6, 1, 99, 99, 99, 0)
}

// =============================================================================
// Container test credentials
// =============================================================================

/// Auth password for all V3 users
pub const AUTH_PASSWORD: &str = "authpass123";
/// Privacy password for all V3 users
pub const PRIV_PASSWORD: &str = "privpass123";

/// V2c read-only community
pub const COMMUNITY_RO: &[u8] = b"public";
/// V2c read-write community
pub const COMMUNITY_RW: &[u8] = b"private";

/// V3 usernames matching the custom container configuration
pub mod users {
    // noAuthNoPriv users
    pub const NOAUTH_USER: &str = "noauth_user";
    pub const NOAUTH_RWUSER: &str = "noauth_rwuser";

    // authNoPriv users (various auth protocols)
    pub const AUTHMD5_USER: &str = "authmd5_user";
    pub const AUTHSHA1_USER: &str = "authsha1_user";
    pub const AUTHSHA224_USER: &str = "authsha224_user";
    pub const AUTHSHA256_USER: &str = "authsha256_user";
    pub const AUTHSHA384_USER: &str = "authsha384_user";
    pub const AUTHSHA512_USER: &str = "authsha512_user";

    // authPriv users (various priv protocols, all use SHA-1 or SHA-256 auth)
    pub const PRIVDES_USER: &str = "privdes_user";
    pub const PRIVAES128_USER: &str = "privaes128_user";
    pub const PRIVAES192_USER: &str = "privaes192_user";
    pub const PRIVAES256_USER: &str = "privaes256_user";
}

// =============================================================================
// Container helpers
// =============================================================================

/// Get the snmpd image to use for container tests.
/// Default: async-snmp-test:latest (our custom container with full protocol support)
///
/// The custom container supports:
/// - V2c read (public) and write (private) communities
/// - V3 noAuthNoPriv, authNoPriv, and authPriv security levels
/// - All auth protocols: MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512
/// - All priv protocols: DES, AES-128, AES-192, AES-256
///
/// Build with: docker build -t async-snmp-test:latest tests/containers/snmpd/
pub fn snmpd_image() -> String {
    std::env::var("SNMPD_IMAGE").unwrap_or_else(|_| "async-snmp-test:latest".to_string())
}

/// Parse image into name and tag.
pub fn parse_image(image: &str) -> (&str, &str) {
    if let Some(idx) = image.rfind(':') {
        // Check it's not a port number (e.g., localhost:5000/image)
        let after_colon = &image[idx + 1..];
        if !after_colon.contains('/') {
            return (&image[..idx], after_colon);
        }
    }
    (image, "latest")
}
