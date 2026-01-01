//! Object Identifier (OID) type.
//!
//! OIDs are stored as `SmallVec<[u32; 16]>` to avoid heap allocation for common OIDs.

use crate::error::{DecodeErrorKind, Error, OidErrorKind, Result};
use smallvec::SmallVec;
use std::fmt;

/// Maximum number of arcs (subidentifiers) allowed in an OID.
///
/// SNMP implementations commonly limit OIDs to 128 subidentifiers.
/// This provides protection against DoS attacks from maliciously long OIDs.
///
/// This limit is enforced optionally via [`Oid::validate_length()`]. The standard
/// [`Oid::from_ber()`] and [`Oid::parse()`] methods accept OIDs of any length for
/// maximum flexibility.
pub const MAX_OID_LEN: usize = 128;

/// Object Identifier.
///
/// Stored as a sequence of arc values (u32). Uses SmallVec to avoid
/// heap allocation for OIDs with 16 or fewer arcs.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Oid {
    arcs: SmallVec<[u32; 16]>,
}

impl Oid {
    /// Create an empty OID.
    pub fn empty() -> Self {
        Self {
            arcs: SmallVec::new(),
        }
    }

    /// Create an OID from arc values.
    ///
    /// Accepts any iterator of `u32` values.
    ///
    /// # Examples
    ///
    /// ```
    /// use async_snmp::oid::Oid;
    ///
    /// // From a Vec
    /// let oid = Oid::new(vec![1, 3, 6, 1, 2, 1]);
    /// assert_eq!(oid.arcs(), &[1, 3, 6, 1, 2, 1]);
    ///
    /// // From an array
    /// let oid = Oid::new([1, 3, 6, 1]);
    /// assert_eq!(oid.len(), 4);
    ///
    /// // From a range
    /// let oid = Oid::new(0..5);
    /// assert_eq!(oid.arcs(), &[0, 1, 2, 3, 4]);
    /// ```
    pub fn new(arcs: impl IntoIterator<Item = u32>) -> Self {
        Self {
            arcs: arcs.into_iter().collect(),
        }
    }

    /// Create an OID from a slice of arcs.
    ///
    /// # Examples
    ///
    /// ```
    /// use async_snmp::oid::Oid;
    ///
    /// let arcs = [1, 3, 6, 1, 2, 1, 1, 1, 0];
    /// let oid = Oid::from_slice(&arcs);
    /// assert_eq!(oid.to_string(), "1.3.6.1.2.1.1.1.0");
    ///
    /// // Empty slice creates an empty OID
    /// let empty = Oid::from_slice(&[]);
    /// assert!(empty.is_empty());
    /// ```
    pub fn from_slice(arcs: &[u32]) -> Self {
        Self {
            arcs: SmallVec::from_slice(arcs),
        }
    }

    /// Parse an OID from dotted string notation (e.g., "1.3.6.1.2.1.1.1.0").
    ///
    /// # Validation
    ///
    /// This method parses the string format but does **not** validate arc constraints
    /// per X.690 Section 8.19.4. Invalid OIDs like `"3.0"` (arc1 must be 0, 1, or 2)
    /// or `"0.40"` (arc2 must be ≤39 when arc1 < 2) will parse successfully.
    ///
    /// To validate arc constraints, call [`validate()`](Self::validate) after parsing,
    /// or use [`to_ber_checked()`](Self::to_ber_checked) which validates before encoding.
    ///
    /// # Examples
    ///
    /// ```
    /// use async_snmp::oid::Oid;
    ///
    /// // Valid OID
    /// let oid = Oid::parse("1.3.6.1.2.1.1.1.0").unwrap();
    /// assert!(oid.validate().is_ok());
    ///
    /// // Invalid arc1 parses but fails validation
    /// let invalid = Oid::parse("3.0").unwrap();
    /// assert!(invalid.validate().is_err());
    /// ```
    pub fn parse(s: &str) -> Result<Self> {
        if s.is_empty() {
            return Ok(Self::empty());
        }

        let mut arcs = SmallVec::new();

        for part in s.split('.') {
            if part.is_empty() {
                continue;
            }

            let arc: u32 = part.parse().map_err(|_| {
                Error::invalid_oid_with_input(OidErrorKind::InvalidArc, s.to_string())
            })?;

            arcs.push(arc);
        }

        Ok(Self { arcs })
    }

    /// Get the arc values.
    pub fn arcs(&self) -> &[u32] {
        &self.arcs
    }

    /// Get the number of arcs.
    pub fn len(&self) -> usize {
        self.arcs.len()
    }

    /// Check if the OID is empty.
    pub fn is_empty(&self) -> bool {
        self.arcs.is_empty()
    }

    /// Check if this OID starts with another OID.
    ///
    /// Returns `true` if `self` begins with the same arcs as `other`.
    /// An OID always starts with itself, and any OID starts with an empty OID.
    ///
    /// # Examples
    ///
    /// ```
    /// use async_snmp::oid::Oid;
    ///
    /// let sys_descr = Oid::parse("1.3.6.1.2.1.1.1.0").unwrap();
    /// let system = Oid::parse("1.3.6.1.2.1.1").unwrap();
    /// let interfaces = Oid::parse("1.3.6.1.2.1.2").unwrap();
    ///
    /// // sysDescr is under the system subtree
    /// assert!(sys_descr.starts_with(&system));
    ///
    /// // sysDescr is not under the interfaces subtree
    /// assert!(!sys_descr.starts_with(&interfaces));
    ///
    /// // Every OID starts with itself
    /// assert!(sys_descr.starts_with(&sys_descr));
    ///
    /// // Every OID starts with the empty OID
    /// assert!(sys_descr.starts_with(&Oid::empty()));
    /// ```
    pub fn starts_with(&self, other: &Oid) -> bool {
        self.arcs.len() >= other.arcs.len() && self.arcs[..other.arcs.len()] == other.arcs[..]
    }

    /// Get the parent OID (all arcs except the last).
    ///
    /// Returns `None` if the OID is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use async_snmp::oid::Oid;
    ///
    /// let sys_descr = Oid::parse("1.3.6.1.2.1.1.1.0").unwrap();
    /// let parent = sys_descr.parent().unwrap();
    /// assert_eq!(parent.to_string(), "1.3.6.1.2.1.1.1");
    ///
    /// // Can chain parent() calls
    /// let grandparent = parent.parent().unwrap();
    /// assert_eq!(grandparent.to_string(), "1.3.6.1.2.1.1");
    ///
    /// // Empty OID has no parent
    /// assert!(Oid::empty().parent().is_none());
    /// ```
    pub fn parent(&self) -> Option<Oid> {
        if self.arcs.is_empty() {
            None
        } else {
            Some(Oid {
                arcs: SmallVec::from_slice(&self.arcs[..self.arcs.len() - 1]),
            })
        }
    }

    /// Create a child OID by appending an arc.
    ///
    /// # Examples
    ///
    /// ```
    /// use async_snmp::oid::Oid;
    ///
    /// let system = Oid::parse("1.3.6.1.2.1.1").unwrap();
    ///
    /// // sysDescr is system.1
    /// let sys_descr = system.child(1);
    /// assert_eq!(sys_descr.to_string(), "1.3.6.1.2.1.1.1");
    ///
    /// // sysDescr.0 is the scalar instance
    /// let sys_descr_instance = sys_descr.child(0);
    /// assert_eq!(sys_descr_instance.to_string(), "1.3.6.1.2.1.1.1.0");
    /// ```
    pub fn child(&self, arc: u32) -> Oid {
        let mut arcs = self.arcs.clone();
        arcs.push(arc);
        Oid { arcs }
    }

    /// Validate OID arcs per X.690 Section 8.19.4.
    ///
    /// - arc1 must be 0, 1, or 2
    /// - arc2 must be <= 39 when arc1 is 0 or 1
    /// - arc2 can be any value when arc1 is 2
    ///
    /// # Examples
    ///
    /// ```
    /// use async_snmp::oid::Oid;
    ///
    /// // Standard SNMP OIDs are valid
    /// let oid = Oid::parse("1.3.6.1.2.1.1.1.0").unwrap();
    /// assert!(oid.validate().is_ok());
    ///
    /// // arc1 must be 0, 1, or 2
    /// let invalid = Oid::from_slice(&[3, 0]);
    /// assert!(invalid.validate().is_err());
    ///
    /// // arc2 must be <= 39 when arc1 is 0 or 1
    /// let invalid = Oid::from_slice(&[0, 40]);
    /// assert!(invalid.validate().is_err());
    ///
    /// // arc2 can be any value when arc1 is 2
    /// let valid = Oid::from_slice(&[2, 999]);
    /// assert!(valid.validate().is_ok());
    /// ```
    pub fn validate(&self) -> Result<()> {
        if self.arcs.is_empty() {
            return Ok(());
        }

        let arc1 = self.arcs[0];

        // arc1 must be 0, 1, or 2
        if arc1 > 2 {
            return Err(Error::invalid_oid(OidErrorKind::InvalidFirstArc(arc1)));
        }

        // arc2 must be <= 39 when arc1 < 2
        if self.arcs.len() >= 2 {
            let arc2 = self.arcs[1];
            if arc1 < 2 && arc2 >= 40 {
                return Err(Error::invalid_oid(OidErrorKind::InvalidSecondArc {
                    first: arc1,
                    second: arc2,
                }));
            }
        }

        Ok(())
    }

    /// Validate that the OID doesn't exceed the maximum arc count.
    ///
    /// SNMP implementations commonly limit OIDs to 128 subidentifiers. This check
    /// provides protection against DoS attacks from maliciously long OIDs.
    ///
    /// # Examples
    ///
    /// ```
    /// use async_snmp::oid::{Oid, MAX_OID_LEN};
    ///
    /// let oid = Oid::parse("1.3.6.1.2.1.1.1.0").unwrap();
    /// assert!(oid.validate_length().is_ok());
    ///
    /// // Create an OID with too many arcs
    /// let too_long: Vec<u32> = (0..150).collect();
    /// let long_oid = Oid::new(too_long);
    /// assert!(long_oid.validate_length().is_err());
    /// ```
    pub fn validate_length(&self) -> Result<()> {
        if self.arcs.len() > MAX_OID_LEN {
            return Err(Error::invalid_oid(OidErrorKind::TooManyArcs {
                count: self.arcs.len(),
                max: MAX_OID_LEN,
            }));
        }
        Ok(())
    }

    /// Validate both arc constraints and length.
    ///
    /// Combines [`validate()`](Self::validate) and [`validate_length()`](Self::validate_length).
    pub fn validate_all(&self) -> Result<()> {
        self.validate()?;
        self.validate_length()
    }

    /// Encode to BER format, returning bytes in a stack-allocated buffer.
    ///
    /// Uses SmallVec to avoid heap allocation for OIDs with up to ~20 arcs.
    /// This is the optimized version used internally by encoding routines.
    ///
    /// OID encoding (X.690 Section 8.19):
    /// - First two arcs encoded as (arc1 * 40) + arc2 using base-128
    /// - Remaining arcs encoded as base-128 variable length
    pub fn to_ber_smallvec(&self) -> SmallVec<[u8; 64]> {
        let mut bytes = SmallVec::new();

        if self.arcs.is_empty() {
            return bytes;
        }

        // First two arcs combined into first subidentifier
        // Uses base-128 encoding because arc2 can be > 127 when arc1=2
        if self.arcs.len() >= 2 {
            let first_subid = self.arcs[0] * 40 + self.arcs[1];
            encode_subidentifier_smallvec(&mut bytes, first_subid);
        } else if self.arcs.len() == 1 {
            let first_subid = self.arcs[0] * 40;
            encode_subidentifier_smallvec(&mut bytes, first_subid);
        }

        // Remaining arcs (only if there are more than 2)
        if self.arcs.len() > 2 {
            for &arc in &self.arcs[2..] {
                encode_subidentifier_smallvec(&mut bytes, arc);
            }
        }

        bytes
    }

    /// Encode to BER format.
    ///
    /// OID encoding (X.690 Section 8.19):
    /// - First two arcs encoded as (arc1 * 40) + arc2 using base-128
    /// - Remaining arcs encoded as base-128 variable length
    ///
    /// # Empty OID Encoding
    ///
    /// Empty OIDs are encoded as zero bytes (empty content). Note that net-snmp
    /// encodes empty OIDs as `[0x00]` (single zero byte). This difference is
    /// unlikely to matter in practice since empty OIDs are rarely used in SNMP.
    ///
    /// # Validation
    ///
    /// This method does not validate arc constraints. Use [`to_ber_checked()`](Self::to_ber_checked)
    /// for validation, or call [`validate()`](Self::validate) first.
    pub fn to_ber(&self) -> Vec<u8> {
        self.to_ber_smallvec().to_vec()
    }

    /// Encode to BER format with validation.
    ///
    /// Returns an error if the OID has invalid arcs per X.690 Section 8.19.4.
    pub fn to_ber_checked(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(self.to_ber())
    }

    /// Decode from BER format.
    pub fn from_ber(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Ok(Self::empty());
        }

        let mut arcs = SmallVec::new();

        // Decode first subidentifier (which encodes arc1*40 + arc2)
        // This may be multi-byte for large arc2 values (when arc1=2)
        let (first_subid, consumed) = decode_subidentifier(data)?;

        // Decode first two arcs from the first subidentifier
        if first_subid < 40 {
            arcs.push(0);
            arcs.push(first_subid);
        } else if first_subid < 80 {
            arcs.push(1);
            arcs.push(first_subid - 40);
        } else {
            arcs.push(2);
            arcs.push(first_subid - 80);
        }

        // Decode remaining arcs
        let mut i = consumed;
        while i < data.len() {
            let (arc, bytes_consumed) = decode_subidentifier(&data[i..])?;
            arcs.push(arc);
            i += bytes_consumed;
        }

        Ok(Self { arcs })
    }
}

/// Encode a subidentifier in base-128 variable length into a SmallVec.
#[inline]
fn encode_subidentifier_smallvec(bytes: &mut SmallVec<[u8; 64]>, value: u32) {
    if value == 0 {
        bytes.push(0);
        return;
    }

    // Count how many 7-bit groups we need
    let mut temp = value;
    let mut count = 0;
    while temp > 0 {
        count += 1;
        temp >>= 7;
    }

    // Encode from MSB to LSB
    for i in (0..count).rev() {
        let mut byte = ((value >> (i * 7)) & 0x7F) as u8;
        if i > 0 {
            byte |= 0x80; // Continuation bit
        }
        bytes.push(byte);
    }
}

/// Decode a subidentifier, returning (value, bytes_consumed).
fn decode_subidentifier(data: &[u8]) -> Result<(u32, usize)> {
    let mut value: u32 = 0;
    let mut i = 0;

    loop {
        if i >= data.len() {
            return Err(Error::decode(i, DecodeErrorKind::TruncatedData));
        }

        let byte = data[i];
        i += 1;

        // Check for overflow before shifting
        if value > (u32::MAX >> 7) {
            return Err(Error::decode(i, DecodeErrorKind::IntegerOverflow));
        }

        value = (value << 7) | ((byte & 0x7F) as u32);

        if byte & 0x80 == 0 {
            // Last byte
            break;
        }
    }

    Ok((value, i))
}

impl fmt::Debug for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Oid({})", self)
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for arc in &self.arcs {
            if !first {
                write!(f, ".")?;
            }
            write!(f, "{}", arc)?;
            first = false;
        }
        Ok(())
    }
}

impl std::str::FromStr for Oid {
    type Err = crate::error::Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

impl From<&[u32]> for Oid {
    fn from(arcs: &[u32]) -> Self {
        Self::from_slice(arcs)
    }
}

impl<const N: usize> From<[u32; N]> for Oid {
    fn from(arcs: [u32; N]) -> Self {
        Self::new(arcs)
    }
}

impl PartialOrd for Oid {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Oid {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.arcs.cmp(&other.arcs)
    }
}

/// Macro to create an OID at compile time.
///
/// This is the preferred way to create OID constants since it's concise
/// and avoids parsing overhead.
///
/// # Examples
///
/// ```
/// use async_snmp::oid;
///
/// // Create an OID for sysDescr.0
/// let sys_descr = oid!(1, 3, 6, 1, 2, 1, 1, 1, 0);
/// assert_eq!(sys_descr.to_string(), "1.3.6.1.2.1.1.1.0");
///
/// // Trailing commas are allowed
/// let sys_name = oid!(1, 3, 6, 1, 2, 1, 1, 5, 0,);
///
/// // Can use in const contexts (via from_slice)
/// let interfaces = oid!(1, 3, 6, 1, 2, 1, 2);
/// assert!(sys_descr.starts_with(&oid!(1, 3, 6, 1, 2, 1, 1)));
/// ```
#[macro_export]
macro_rules! oid {
    ($($arc:expr),* $(,)?) => {
        $crate::oid::Oid::from_slice(&[$($arc),*])
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        let oid = Oid::parse("1.3.6.1.2.1.1.1.0").unwrap();
        assert_eq!(oid.arcs(), &[1, 3, 6, 1, 2, 1, 1, 1, 0]);
    }

    #[test]
    fn test_display() {
        let oid = Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 1, 0]);
        assert_eq!(oid.to_string(), "1.3.6.1.2.1.1.1.0");
    }

    #[test]
    fn test_starts_with() {
        let oid = Oid::parse("1.3.6.1.2.1.1.1.0").unwrap();
        let prefix = Oid::parse("1.3.6.1").unwrap();
        assert!(oid.starts_with(&prefix));
        assert!(!prefix.starts_with(&oid));
    }

    #[test]
    fn test_ber_roundtrip() {
        let oid = Oid::parse("1.3.6.1.2.1.1.1.0").unwrap();
        let ber = oid.to_ber();
        let decoded = Oid::from_ber(&ber).unwrap();
        assert_eq!(oid, decoded);
    }

    #[test]
    fn test_ber_encoding() {
        // 1.3.6.1 encodes as: (1*40+3)=43, 6, 1 = [0x2B, 0x06, 0x01]
        let oid = Oid::parse("1.3.6.1").unwrap();
        assert_eq!(oid.to_ber(), vec![0x2B, 0x06, 0x01]);
    }

    #[test]
    fn test_macro() {
        let oid = oid!(1, 3, 6, 1);
        assert_eq!(oid.arcs(), &[1, 3, 6, 1]);
    }

    // AUDIT-001: Test arc validation
    // X.690 Section 8.19.4: arc1 must be 0, 1, or 2; arc2 must be <= 39 when arc1 < 2
    #[test]
    fn test_validate_arc1_must_be_0_1_or_2() {
        // arc1 = 3 is invalid
        let oid = Oid::from_slice(&[3, 0]);
        let result = oid.validate();
        assert!(result.is_err(), "arc1=3 should be invalid");
    }

    #[test]
    fn test_validate_arc2_limit_when_arc1_is_0() {
        // arc1 = 0, arc2 = 40 is invalid (max is 39)
        let oid = Oid::from_slice(&[0, 40]);
        let result = oid.validate();
        assert!(result.is_err(), "arc2=40 with arc1=0 should be invalid");

        // arc1 = 0, arc2 = 39 is valid
        let oid = Oid::from_slice(&[0, 39]);
        assert!(
            oid.validate().is_ok(),
            "arc2=39 with arc1=0 should be valid"
        );
    }

    #[test]
    fn test_validate_arc2_limit_when_arc1_is_1() {
        // arc1 = 1, arc2 = 40 is invalid
        let oid = Oid::from_slice(&[1, 40]);
        let result = oid.validate();
        assert!(result.is_err(), "arc2=40 with arc1=1 should be invalid");

        // arc1 = 1, arc2 = 39 is valid
        let oid = Oid::from_slice(&[1, 39]);
        assert!(
            oid.validate().is_ok(),
            "arc2=39 with arc1=1 should be valid"
        );
    }

    #[test]
    fn test_validate_arc2_no_limit_when_arc1_is_2() {
        // arc1 = 2, arc2 can be anything (e.g., 999)
        let oid = Oid::from_slice(&[2, 999]);
        assert!(
            oid.validate().is_ok(),
            "arc2=999 with arc1=2 should be valid"
        );
    }

    #[test]
    fn test_to_ber_validates_arcs() {
        // Invalid OID should return error from to_ber_checked
        let oid = Oid::from_slice(&[3, 0]); // arc1=3 is invalid
        let result = oid.to_ber_checked();
        assert!(
            result.is_err(),
            "to_ber_checked should fail for invalid arc1"
        );
    }

    // AUDIT-002: Test first subidentifier encoding for large arc2 values
    // X.690 Section 8.19 example: OID {2 999 3} has first subidentifier = 1079
    #[test]
    fn test_ber_encoding_large_arc2() {
        // OID 2.999.3: first subid = 2*40 + 999 = 1079 = 0x437
        // 1079 in base-128: 0x88 0x37 (continuation bit set on first byte)
        let oid = Oid::from_slice(&[2, 999, 3]);
        let ber = oid.to_ber();
        // First subidentifier 1079 = 0b10000110111 = 7 bits: 0b0110111 (0x37), 7 bits: 0b0001000 (0x08)
        // In base-128: (1079 >> 7) = 8, (1079 & 0x7F) = 55
        // So: 0x88 (8 | 0x80), 0x37 (55)
        assert_eq!(
            ber[0], 0x88,
            "first byte should be 0x88 (8 with continuation)"
        );
        assert_eq!(
            ber[1], 0x37,
            "second byte should be 0x37 (55, no continuation)"
        );
        assert_eq!(ber[2], 0x03, "third byte should be 0x03 (arc 3)");
        assert_eq!(ber.len(), 3, "OID 2.999.3 should encode to 3 bytes");
    }

    #[test]
    fn test_ber_roundtrip_large_arc2() {
        // Ensure roundtrip works for OID with large arc2
        let oid = Oid::from_slice(&[2, 999, 3]);
        let ber = oid.to_ber();
        let decoded = Oid::from_ber(&ber).unwrap();
        assert_eq!(oid, decoded, "roundtrip should preserve OID 2.999.3");
    }

    #[test]
    fn test_ber_encoding_arc2_equals_80() {
        // Edge case: arc1=2, arc2=0 gives first subid = 80, which is exactly 1 byte
        let oid = Oid::from_slice(&[2, 0]);
        let ber = oid.to_ber();
        assert_eq!(ber, vec![80], "OID 2.0 should encode to [80]");
    }

    #[test]
    fn test_ber_encoding_arc2_equals_127() {
        // arc1=2, arc2=47 gives first subid = 127, still fits in 1 byte
        let oid = Oid::from_slice(&[2, 47]);
        let ber = oid.to_ber();
        assert_eq!(ber, vec![127], "OID 2.47 should encode to [127]");
    }

    #[test]
    fn test_ber_encoding_arc2_equals_128_needs_2_bytes() {
        // arc1=2, arc2=48 gives first subid = 128, needs 2 bytes in base-128
        let oid = Oid::from_slice(&[2, 48]);
        let ber = oid.to_ber();
        // 128 = 0x80 = base-128: 0x81 0x00
        assert_eq!(
            ber,
            vec![0x81, 0x00],
            "OID 2.48 should encode to [0x81, 0x00]"
        );
    }

    #[test]
    fn test_oid_non_minimal_subidentifier() {
        // Non-minimal subidentifier encoding with leading 0x80 bytes should be accepted
        // 0x80 0x01 should decode as 1 (non-minimal: minimal would be just 0x01)
        // OID: 1.3 followed by arc 1 encoded as 0x80 0x01
        let result = Oid::from_ber(&[0x2B, 0x80, 0x01]);
        assert!(
            result.is_ok(),
            "should accept non-minimal subidentifier 0x80 0x01"
        );
        let oid = result.unwrap();
        assert_eq!(oid.arcs(), &[1, 3, 1]);

        // 0x80 0x80 0x01 should decode as 1 (two leading 0x80 bytes)
        let result = Oid::from_ber(&[0x2B, 0x80, 0x80, 0x01]);
        assert!(
            result.is_ok(),
            "should accept non-minimal subidentifier 0x80 0x80 0x01"
        );
        let oid = result.unwrap();
        assert_eq!(oid.arcs(), &[1, 3, 1]);

        // 0x80 0x00 should decode as 0 (non-minimal zero)
        let result = Oid::from_ber(&[0x2B, 0x80, 0x00]);
        assert!(
            result.is_ok(),
            "should accept non-minimal subidentifier 0x80 0x00"
        );
        let oid = result.unwrap();
        assert_eq!(oid.arcs(), &[1, 3, 0]);
    }

    // Tests for MAX_OID_LEN validation
    #[test]
    fn test_validate_length_within_limit() {
        // OID with MAX_OID_LEN arcs should be valid
        let arcs: Vec<u32> = (0..MAX_OID_LEN as u32).collect();
        let oid = Oid::new(arcs);
        assert!(
            oid.validate_length().is_ok(),
            "OID with exactly MAX_OID_LEN arcs should be valid"
        );
    }

    #[test]
    fn test_validate_length_exceeds_limit() {
        // OID with more than MAX_OID_LEN arcs should fail
        let arcs: Vec<u32> = (0..(MAX_OID_LEN + 1) as u32).collect();
        let oid = Oid::new(arcs);
        let result = oid.validate_length();
        assert!(
            result.is_err(),
            "OID exceeding MAX_OID_LEN should fail validation"
        );
    }

    #[test]
    fn test_validate_all_combines_checks() {
        // Valid OID
        let oid = Oid::from_slice(&[1, 3, 6, 1]);
        assert!(oid.validate_all().is_ok());

        // Invalid arc1 (fails validate)
        let oid = Oid::from_slice(&[3, 0]);
        assert!(oid.validate_all().is_err());

        // Too many arcs (fails validate_length)
        let arcs: Vec<u32> = (0..(MAX_OID_LEN + 1) as u32).collect();
        let oid = Oid::new(arcs);
        assert!(oid.validate_all().is_err());
    }

    #[test]
    fn test_oid_fromstr() {
        // Test basic parsing via FromStr trait
        let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
        assert_eq!(oid, oid!(1, 3, 6, 1, 2, 1, 1, 1, 0));

        // Test empty OID
        let empty: Oid = "".parse().unwrap();
        assert!(empty.is_empty());

        // Test single arc
        let single: Oid = "1".parse().unwrap();
        assert_eq!(single.arcs(), &[1]);

        // Test roundtrip Display -> FromStr
        let original = oid!(1, 3, 6, 1, 4, 1, 9, 9, 42);
        let displayed = original.to_string();
        let parsed: Oid = displayed.parse().unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_oid_fromstr_invalid() {
        // Invalid arc value
        assert!("1.3.abc.1".parse::<Oid>().is_err());

        // Negative number (parsed as invalid)
        assert!("1.3.-6.1".parse::<Oid>().is_err());
    }
}
