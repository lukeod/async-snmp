//! Explicit controls for accepting known malformed SNMP encodings.
//!
//! These controls are carried by each decoder invocation. They do not modify
//! process-global state, and each interoperability deviation can be enabled
//! independently. Structured outbound encoders always require canonical data.

/// Policy for known, unambiguous interoperability deviations.
///
/// [`Default`] preserves the established receive behavior except that
/// exception values with non-empty payloads are rejected. Every accepted
/// deviation emits a warning with a stable `anomaly` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct CompatibilityPolicy {
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

impl CompatibilityPolicy {
    /// Disable every malformed-input compatibility behavior.
    pub const STRICT: Self = Self {
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
        truncate_numeric_values: true,
        empty_counter64_as_zero: true,
        empty_object_identifier: true,
        clamp_bounded_strings: true,
        normalize_negative_get_bulk_fields: true,
        malformed_exception_payloads: false,
    };
}

impl Default for CompatibilityPolicy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compatibility_policy_defaults_are_explicit() {
        let policy = CompatibilityPolicy::default();
        assert!(policy.truncate_numeric_values);
        assert!(policy.empty_counter64_as_zero);
        assert!(policy.empty_object_identifier);
        assert!(policy.clamp_bounded_strings);
        assert!(policy.normalize_negative_get_bulk_fields);
        assert!(!policy.malformed_exception_payloads);
        assert_eq!(CompatibilityPolicy::STRICT, CompatibilityPolicy::STRICT);
    }
}
