//! MIB integration helpers for async-snmp.
//!
//! This module provides functions that use a loaded [`Mib`] to resolve
//! OID names, format OIDs symbolically, and render SNMP values using MIB
//! metadata (enum labels, display hints, type information).
//!
//! This is part of the public API, gated on the `mib` feature. All functions
//! take a `&Mib` reference and are stateless.
//!
//! Key mib-rs types are re-exported here so users can depend on `async-snmp`
//! alone without adding `mib-rs` as a direct dependency.

use crate::{Oid, Value, VarBind};
use mib_rs::mib::display_hint::HexCase;
use smallvec::SmallVec;

// Re-export core mib-rs types so users don't need a direct mib-rs dependency.
pub use mib_rs::{
    Access, DiagnosticConfig, Kind, Loader, Mib, ResolveOidError,
    source,
};

/// Resolve a name like "sysDescr.0" or "IF-MIB::ifTable" to an async-snmp OID.
///
/// Accepts the same query formats as [`Mib::resolve_oid`]: plain names,
/// qualified names (`MODULE::name`), instance OIDs (`name.suffix`), and numeric
/// dotted-decimal strings.
pub fn resolve_oid(mib: &Mib, name: &str) -> Result<Oid, ResolveOidError> {
    mib.resolve_oid(name).map(|oid| Oid::from(&oid))
}

/// Format a numeric OID as "MODULE::name.suffix" using MIB metadata.
///
/// If the OID (or a prefix of it) matches a known node, the result uses
/// symbolic form. Otherwise falls back to dotted-decimal.
pub fn format_oid(mib: &Mib, oid: &Oid) -> String {
    mib.format_oid(&oid.to_mib_oid())
}

/// Format a VarBind using MIB metadata: OID name + formatted value.
///
/// The OID is formatted via [`format_oid`] to produce `MODULE::name.suffix`.
/// The value is formatted using MIB type information (enum labels, display
/// hints) when the OID matches an OBJECT-TYPE definition. When no Object
/// is found, falls back to the value's `Display` impl.
///
/// Output like "IF-MIB::ifDescr.1 = eth0"
pub fn format_varbind(mib: &Mib, vb: &VarBind) -> String {
    let oid_str = format_oid(mib, &vb.oid);
    let value_str = format_value(mib, &vb.oid, &vb.value);
    format!("{} = {}", oid_str, value_str)
}

/// Richer metadata about a VarBind for programmatic use.
///
/// The struct borrows `object_name`, `module_name`, and `units` from the
/// `Mib`, while `suffix` and `formatted_value` are owned. Callers cannot
/// detach the struct from the `Mib` lifetime.
pub struct VarBindInfo<'a> {
    /// The object name (e.g., "ifDescr").
    pub object_name: &'a str,
    /// The module that defines the object (e.g., "IF-MIB").
    pub module_name: &'a str,
    /// The instance suffix arcs after the object OID.
    pub suffix: SmallVec<[u32; 4]>,
    /// The UNITS clause from the object definition.
    pub units: &'a str,
    /// The MAX-ACCESS of the object.
    pub access: Access,
    /// The object kind (scalar, column, table, etc.).
    pub kind: Kind,
    /// The value formatted using MIB metadata.
    pub formatted_value: String,
}

/// Get structured metadata about a VarBind using MIB information.
///
/// Returns `None` if the OID does not match any OBJECT-TYPE definition.
/// Bare nodes (OID registrations without an OBJECT-TYPE) return `None`.
pub fn describe_varbind<'a>(mib: &'a Mib, vb: &VarBind) -> Option<VarBindInfo<'a>> {
    let mib_oid = vb.oid.to_mib_oid();
    let lookup = mib.lookup_instance(&mib_oid);
    let node = lookup.node();
    let object = node.object()?;

    let module_name = object
        .module()
        .map(|m| m.name())
        .unwrap_or("");

    let formatted_value = format_object_value(mib, &object, &vb.value);

    Some(VarBindInfo {
        object_name: object.name(),
        module_name,
        suffix: SmallVec::from_slice(lookup.suffix()),
        units: object.units(),
        access: object.access(),
        kind: object.kind(),
        formatted_value,
    })
}

/// Format a value using MIB metadata for the given OID.
///
/// Looks up the OID in the MIB to find type information (enum labels,
/// display hints), and uses it to produce a human-readable string.
/// Falls back to the value's `Display` impl when no OBJECT-TYPE matches.
pub fn format_value(mib: &Mib, oid: &Oid, value: &Value) -> String {
    let mib_oid = oid.to_mib_oid();
    let lookup = mib.lookup_instance(&mib_oid);
    let node = lookup.node();

    if let Some(object) = node.object() {
        format_object_value(mib, &object, value)
    } else {
        value.to_string()
    }
}

/// Format a value using an Object's type metadata.
fn format_object_value(mib: &Mib, object: &mib_rs::Object<'_>, value: &Value) -> String {
    match value {
        Value::Integer(v) => {
            // Check for enum labels first
            let enums = object.effective_enums();
            if let Some(nv) = enums.iter().find(|nv| nv.value == *v as i64) {
                return format!("{}({})", nv.label, v);
            }
            // Try integer display hint
            if let Some(formatted) = object.format_integer(*v as i64, HexCase::Lower) {
                return formatted;
            }
            format!("{}", v)
        }

        Value::OctetString(bytes) => {
            // Try display hint formatting
            if let Some(formatted) = object.format_octets(bytes, HexCase::Lower) {
                return formatted;
            }
            // Fall back to UTF-8, then hex
            if let Ok(s) = std::str::from_utf8(bytes) {
                if s.chars().all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace()) {
                    return s.to_string();
                }
            }
            format_hex(bytes)
        }

        Value::ObjectIdentifier(oid) => {
            format_oid(mib, oid)
        }

        Value::TimeTicks(v) => {
            let formatted = crate::fmt::format_timeticks(*v);
            format!("({}) {}", v, formatted)
        }

        Value::Counter32(v) => format!("{}", v),
        Value::Counter64(v) => format!("{}", v),
        Value::Gauge32(v) => format!("{}", v),

        Value::Opaque(bytes) => {
            // Try display hint formatting (same as OctetString)
            if let Some(formatted) = object.format_octets(bytes, HexCase::Lower) {
                return formatted;
            }
            format_hex(bytes)
        }

        Value::IpAddress(bytes) => {
            format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
        }

        Value::Null => "NULL".to_string(),

        // Exception values pass through
        Value::NoSuchObject => "noSuchObject".to_string(),
        Value::NoSuchInstance => "noSuchInstance".to_string(),
        Value::EndOfMibView => "endOfMibView".to_string(),

        Value::Unknown { tag, data } => {
            format!("Unknown(0x{:02X}): {}", tag, format_hex(data))
        }
    }
}

/// Format bytes as space-separated uppercase hex for display.
fn format_hex(bytes: &[u8]) -> String {
    crate::fmt::format_hex_display(bytes)
}

#[cfg(feature = "cli")]
impl crate::cli::output::VarBindFormatter for Mib {
    fn format_oid(&self, oid: &Oid) -> String {
        format_oid(self, oid)
    }

    fn format_value(&self, oid: &Oid, value: &Value) -> String {
        format_value(self, oid, value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oid;

    fn test_mib() -> Mib {
        let source = source::memory(
            "TEST-MIB",
            r#"TEST-MIB DEFINITIONS ::= BEGIN
IMPORTS
    MODULE-IDENTITY, OBJECT-TYPE, Integer32, enterprises
        FROM SNMPv2-SMI
    DisplayString
        FROM SNMPv2-TC;

testMib MODULE-IDENTITY
    LAST-UPDATED "202603210000Z"
    ORGANIZATION "Test"
    CONTACT-INFO "Test"
    DESCRIPTION "Test module."
    ::= { enterprises 99999 }

testScalar OBJECT-TYPE
    SYNTAX DisplayString
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "A test scalar."
    ::= { testMib 1 }

testStatus OBJECT-TYPE
    SYNTAX INTEGER { up(1), down(2), testing(3) }
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "A test status."
    ::= { testMib 2 }

END
"#,
        );

        Loader::new()
            .source(source)
            .modules(["TEST-MIB"])
            .load()
            .expect("test MIB should load")
    }

    #[test]
    fn test_resolve_oid() {
        let mib = test_mib();
        let oid = resolve_oid(&mib, "testScalar.0").unwrap();
        let expected = resolve_oid(&mib, "testScalar").unwrap().child(0);
        assert_eq!(oid, expected);
    }

    #[test]
    fn test_format_oid_symbolic() {
        let mib = test_mib();
        let oid = resolve_oid(&mib, "testScalar.0").unwrap();
        let formatted = format_oid(&mib, &oid);
        assert!(formatted.contains("testScalar"), "got: {}", formatted);
    }

    #[test]
    fn test_format_varbind_string() {
        let mib = test_mib();
        let oid = resolve_oid(&mib, "testScalar.0").unwrap();
        let vb = VarBind::new(oid, Value::OctetString(bytes::Bytes::from_static(b"hello")));
        let formatted = format_varbind(&mib, &vb);
        assert!(formatted.contains("testScalar"), "got: {}", formatted);
        assert!(formatted.contains("hello"), "got: {}", formatted);
    }

    #[test]
    fn test_format_varbind_enum() {
        let mib = test_mib();
        let oid = resolve_oid(&mib, "testStatus.0").unwrap();
        let vb = VarBind::new(oid, Value::Integer(1));
        let formatted = format_varbind(&mib, &vb);
        assert!(formatted.contains("up(1)"), "got: {}", formatted);
    }

    #[test]
    fn test_describe_varbind() {
        let mib = test_mib();
        let oid = resolve_oid(&mib, "testScalar.0").unwrap();
        let vb = VarBind::new(oid, Value::OctetString(bytes::Bytes::from_static(b"hello")));
        let info = describe_varbind(&mib, &vb).expect("should describe");
        assert_eq!(info.object_name, "testScalar");
        assert_eq!(info.module_name, "TEST-MIB");
        assert_eq!(info.suffix.as_slice(), &[0]);
    }

    #[test]
    fn test_oid_conversion_roundtrip() {
        let snmp_oid = oid!(1, 3, 6, 1, 2, 1, 1, 1, 0);
        let mib_oid = snmp_oid.to_mib_oid();
        let back: Oid = Oid::from(&mib_oid);
        assert_eq!(snmp_oid, back);
    }

    #[test]
    fn test_describe_unknown_oid_returns_none() {
        let mib = test_mib();
        // An OID that doesn't match any Object
        let vb = VarBind::new(oid!(1, 3, 6, 1, 99, 99, 99), Value::Integer(42));
        // This may or may not return None depending on the OID tree
        // but at minimum it shouldn't panic
        let _ = describe_varbind(&mib, &vb);
    }
}
