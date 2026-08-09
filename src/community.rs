//! SNMP community identifiers.

use std::fmt;

use bytes::{Bytes, BytesMut};

/// An SNMPv1 or SNMPv2c community identifier.
///
/// Library-provided structured [`Debug`] output always redacts the contained
/// bytes. The bytes remain available through [`Self::as_bytes`] and
/// [`Self::into_bytes`] for protocol and application use.
///
/// Communities use ordinary cloneable storage. They are not guaranteed to be
/// zeroized, and SNMPv1/v2c transmits them in plaintext. Debug redaction avoids
/// accidental disclosure through library diagnostics; it does not provide
/// confidentiality on the wire or protect raw buffers, packet captures,
/// application copies, or downstream formatting of explicitly accessed bytes.
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Community(Bytes);

impl Community {
    /// Construct a community from owned or copyable byte input.
    #[must_use]
    pub fn new(value: impl Into<Self>) -> Self {
        value.into()
    }

    /// Return the community bytes explicitly.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consume the community and return its byte storage.
    #[must_use]
    pub fn into_bytes(self) -> Bytes {
        self.0
    }
}

impl fmt::Debug for Community {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Community([REDACTED])")
    }
}

impl From<Bytes> for Community {
    fn from(value: Bytes) -> Self {
        Self(value)
    }
}

impl From<&Bytes> for Community {
    fn from(value: &Bytes) -> Self {
        Self(value.clone())
    }
}

impl From<&Community> for Community {
    fn from(value: &Community) -> Self {
        value.clone()
    }
}

impl From<BytesMut> for Community {
    fn from(value: BytesMut) -> Self {
        Self(value.freeze())
    }
}

impl From<Vec<u8>> for Community {
    fn from(value: Vec<u8>) -> Self {
        Self(Bytes::from(value))
    }
}

impl From<&Vec<u8>> for Community {
    fn from(value: &Vec<u8>) -> Self {
        Self(Bytes::copy_from_slice(value))
    }
}

impl From<String> for Community {
    fn from(value: String) -> Self {
        Self(Bytes::from(value))
    }
}

impl From<&String> for Community {
    fn from(value: &String) -> Self {
        Self(Bytes::copy_from_slice(value.as_bytes()))
    }
}

impl From<&str> for Community {
    fn from(value: &str) -> Self {
        Self(Bytes::copy_from_slice(value.as_bytes()))
    }
}

impl From<&[u8]> for Community {
    fn from(value: &[u8]) -> Self {
        Self(Bytes::copy_from_slice(value))
    }
}

impl<const N: usize> From<&[u8; N]> for Community {
    fn from(value: &[u8; N]) -> Self {
        Self(Bytes::copy_from_slice(value))
    }
}

impl<const N: usize> From<[u8; N]> for Community {
    fn from(value: [u8; N]) -> Self {
        Self(Bytes::copy_from_slice(&value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted_and_bytes_remain_explicitly_available() {
        let community = Community::from(Bytes::from_static(b"sentinel-community"));
        assert_eq!(community.as_bytes(), b"sentinel-community");
        assert!(!format!("{community:?}").contains("sentinel-community"));
        assert!(!format!("{community:#?}").contains("sentinel-community"));
        assert_eq!(
            community.into_bytes(),
            Bytes::from_static(b"sentinel-community")
        );
    }
}
