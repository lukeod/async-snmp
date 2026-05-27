//! SNMP version enumeration.

/// SNMP protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[derive(Default)]
pub enum Version {
    /// `SNMPv1` (RFC 1157)
    V1,
    /// `SNMPv2c` (RFC 1901)
    #[default]
    V2c,
    /// `SNMPv3` (RFC 3411-3418)
    V3,
}

impl Version {
    /// Get the BER-encoded version number.
    ///
    /// # Examples
    ///
    /// ```
    /// use async_snmp::Version;
    ///
    /// assert_eq!(Version::V1.as_i32(), 0);
    /// assert_eq!(Version::V2c.as_i32(), 1);
    /// assert_eq!(Version::V3.as_i32(), 3);
    /// ```
    #[must_use] 
    pub const fn as_i32(self) -> i32 {
        match self {
            Version::V1 => 0,
            Version::V2c => 1,
            Version::V3 => 3,
        }
    }

    /// Create from BER-encoded version number.
    ///
    /// # Examples
    ///
    /// ```
    /// use async_snmp::Version;
    ///
    /// assert_eq!(Version::from_i32(0), Some(Version::V1));
    /// assert_eq!(Version::from_i32(1), Some(Version::V2c));
    /// assert_eq!(Version::from_i32(3), Some(Version::V3));
    /// assert_eq!(Version::from_i32(2), None); // Invalid version
    /// ```
    #[must_use] 
    pub const fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Version::V1),
            1 => Some(Version::V2c),
            3 => Some(Version::V3),
            _ => None,
        }
    }
}

impl TryFrom<i32> for Version {
    type Error = i32;

    fn try_from(value: i32) -> std::result::Result<Self, i32> {
        Self::from_i32(value).ok_or(value)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_try_from() {
        assert_eq!(Version::try_from(0), Ok(Version::V1));
        assert_eq!(Version::try_from(1), Ok(Version::V2c));
        assert_eq!(Version::try_from(3), Ok(Version::V3));
        assert_eq!(Version::try_from(2), Err(2));
        assert_eq!(Version::try_from(-1), Err(-1));
    }
}
