//! SNMP version enumeration.

/// SNMP protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[derive(Default)]
pub enum Version {
    /// SNMPv1 (RFC 1157)
    V1,
    /// SNMPv2c (RFC 1901)
    #[default]
    V2c,
    /// SNMPv3 (RFC 3411-3418)
    V3,
}

impl Version {
    /// Get the BER-encoded version number.
    pub const fn as_i32(self) -> i32 {
        match self {
            Version::V1 => 0,
            Version::V2c => 1,
            Version::V3 => 3,
        }
    }

    /// Create from BER-encoded version number.
    pub const fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Version::V1),
            1 => Some(Version::V2c),
            3 => Some(Version::V3),
            _ => None,
        }
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Version::V1 => write!(f, "SNMPv1"),
            Version::V2c => write!(f, "SNMPv2c"),
            Version::V3 => write!(f, "SNMPv3"),
        }
    }
}
