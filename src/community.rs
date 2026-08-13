//! SNMP community identifiers.

use std::fmt;

use bytes::{Bytes, BytesMut};
use subtle::ConstantTimeEq;

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
#[derive(Clone, Default)]
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

    /// Return whether `candidate` contains the same community octets.
    ///
    /// For equal-length inputs, comparison time does not depend on the octet
    /// values. Length is not concealed: a length mismatch may return sooner.
    /// Use this method instead of comparing [`Self::as_bytes`] when matching a
    /// received community during authentication or authorization.
    #[must_use]
    pub fn matches(&self, candidate: impl AsRef<[u8]>) -> bool {
        let candidate = candidate.as_ref();
        self.0.len() == candidate.len() && bool::from(self.0.as_ref().ct_eq(candidate))
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
        assert!(community.matches(b"sentinel-community"));
        assert!(!format!("{community:?}").contains("sentinel-community"));
        assert!(!format!("{community:#?}").contains("sentinel-community"));
        assert_eq!(
            community.into_bytes(),
            Bytes::from_static(b"sentinel-community")
        );
    }

    #[test]
    fn matches_arbitrary_octets_and_rejects_content_and_length_mismatches() {
        let community = Community::from(&b"private\x00\xff"[..]);

        assert!(community.matches(b"private\x00\xff"));
        assert!(!community.matches(b"private\x00\xfe"));
        assert!(!community.matches(b"private\x00"));
        assert!(!community.matches(b"private\x00\xff\x00"));
    }
}
