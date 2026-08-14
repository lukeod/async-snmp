//! Explicit controls for accepting known malformed SNMP encodings.
//!
//! These controls are carried by each decoder invocation. They do not modify
//! process-global state, and each interoperability deviation can be enabled
//! independently. Structured outbound encoders always require canonical data.

/// An SNMP exception syntax whose non-empty payload was discarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ExceptionKind {
    /// `noSuchObject`.
    NoSuchObject,
    /// `noSuchInstance`.
    NoSuchInstance,
    /// `endOfMibView`.
    EndOfMibView,
}

/// An OCTET STRING-like syntax whose declared length was clamped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BoundedStringKind {
    /// Universal OCTET STRING.
    OctetString,
    /// SNMP application Opaque.
    Opaque,
}

/// A GETBULK field normalized from a negative wire value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum GetBulkField {
    /// The non-repeaters field.
    NonRepeaters,
    /// The max-repetitions field.
    MaxRepetitions,
}

/// Observable non-canonical input accepted by compatibility decoding.
///
/// Collections preserve deterministic decode-observation order. Variants contain the original and
/// canonical lengths or values needed to describe the lossy normalization.
/// They deliberately do not contain offsets: packet-relative positions cannot
/// describe anomalies found in decrypted scoped-PDU plaintext without a second
/// coordinate system.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DecodeAnomaly {
    /// An out-of-range generic INTEGER was narrowed to `i32`.
    SignedIntegerTruncation {
        /// BER content length.
        encoded_length: usize,
        /// Complete decoded wire value.
        original: i64,
        /// Public canonical representation.
        canonical: i32,
    },
    /// An out-of-range generic Unsigned32 was narrowed to `u32`.
    Unsigned32Truncation {
        /// BER content length.
        encoded_length: usize,
        /// Complete decoded wire value.
        original: u64,
        /// Public canonical representation.
        canonical: u32,
    },
    /// A zero-length Counter64 was normalized to zero.
    EmptyCounter64 {
        /// Wire content length.
        original_length: usize,
        /// Canonical numeric value.
        canonical: u64,
    },
    /// A zero-length OBJECT IDENTIFIER was normalized to an empty OID.
    EmptyObjectIdentifier {
        /// Wire content length.
        original_length: usize,
        /// Number of arcs in the normalized OID.
        canonical_arc_count: usize,
    },
    /// An over-declared bounded string was clamped to its enclosing varbind.
    BoundedStringClamp {
        /// String syntax.
        kind: BoundedStringKind,
        /// Declared wire length.
        declared_length: usize,
        /// Retained content length.
        canonical_length: usize,
    },
    /// A negative GETBULK field was normalized to zero.
    NegativeGetBulkField {
        /// Affected field.
        field: GetBulkField,
        /// Signed wire value.
        original: i32,
        /// Canonical field value.
        canonical: u32,
    },
    /// A non-empty exception payload was discarded.
    MalformedExceptionPayload {
        /// Exception syntax.
        kind: ExceptionKind,
        /// Wire payload length.
        original_length: usize,
        /// Canonical payload length.
        canonical_length: usize,
    },
    /// Bytes after the declared top-level message were discarded.
    TrailingBytes {
        /// Packet suffix length.
        original_length: usize,
        /// Canonical suffix length.
        canonical_length: usize,
    },
}

/// Configuration for bounded, unambiguous receive compatibility.
///
/// [`Default`] preserves the established receive behavior except that
/// exception values with non-empty payloads are rejected. Every accepted
/// deviation emits a warning with a stable `anomaly` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct DecodeConfig {
    /// Accept bytes after one fully consumed top-level SNMP message TLV.
    /// Default: enabled.
    pub trailing_bytes: bool,
    /// Truncate generic INTEGER and Unsigned32 values that exceed their public
    /// 32-bit representation (net-snmp-compatible). Default: enabled.
    pub truncate_numeric_values: bool,
    /// Interpret a zero-length Counter64 as zero. Default: enabled.
    pub empty_counter64_as_zero: bool,
    /// Accept a zero-length OBJECT IDENTIFIER as [`crate::Oid::empty`].
    /// Default: enabled for receive compatibility.
    pub empty_object_identifier: bool,
    /// Clamp an over-declared OCTET STRING or Opaque length to the enclosing
    /// varbind boundary. Default: enabled.
    pub clamp_bounded_strings: bool,
    /// Normalize negative GETBULK non-repeaters/max-repetitions fields to zero
    /// while decoding. Default: enabled.
    pub normalize_negative_get_bulk_fields: bool,
    /// Accept and discard non-empty payloads on SNMP exception values.
    /// Default: disabled; canonical exception values have zero-length content.
    pub malformed_exception_payloads: bool,
}

impl DecodeConfig {
    /// Disable every receive compatibility behavior.
    pub const STRICT: Self = Self {
        trailing_bytes: false,
        truncate_numeric_values: false,
        empty_counter64_as_zero: false,
        empty_object_identifier: false,
        clamp_bounded_strings: false,
        normalize_negative_get_bulk_fields: false,
        malformed_exception_payloads: false,
    };

    /// Established compatibility defaults, with malformed exception payloads
    /// intentionally kept strict.
    pub const DEFAULT: Self = Self {
        trailing_bytes: true,
        truncate_numeric_values: true,
        empty_counter64_as_zero: true,
        empty_object_identifier: true,
        clamp_bounded_strings: true,
        normalize_negative_get_bulk_fields: true,
        malformed_exception_payloads: false,
    };
}

impl Default for DecodeConfig {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_config_defaults_are_explicit() {
        let config = DecodeConfig::default();
        assert!(config.trailing_bytes);
        assert!(config.truncate_numeric_values);
        assert!(config.empty_counter64_as_zero);
        assert!(config.empty_object_identifier);
        assert!(config.clamp_bounded_strings);
        assert!(config.normalize_negative_get_bulk_fields);
        assert!(!config.malformed_exception_payloads);
    }
}
