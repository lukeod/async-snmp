//! Well-known OID name hints.
//!
//! This module provides a small hardcoded table of common OID names for display purposes.
//! This is NOT MIB support - just friendly names for common system OIDs.

use crate::Oid;

/// Well-known OID entries.
static WELL_KNOWN_OIDS: &[(&[u32], &str)] = &[
    // SNMPv2-MIB::system
    (&[1, 3, 6, 1, 2, 1, 1, 1, 0], "sysDescr.0"),
    (&[1, 3, 6, 1, 2, 1, 1, 2, 0], "sysObjectID.0"),
    (&[1, 3, 6, 1, 2, 1, 1, 3, 0], "sysUpTime.0"),
    (&[1, 3, 6, 1, 2, 1, 1, 4, 0], "sysContact.0"),
    (&[1, 3, 6, 1, 2, 1, 1, 5, 0], "sysName.0"),
    (&[1, 3, 6, 1, 2, 1, 1, 6, 0], "sysLocation.0"),
    (&[1, 3, 6, 1, 2, 1, 1, 7, 0], "sysServices.0"),
    // IF-MIB::interfaces
    (&[1, 3, 6, 1, 2, 1, 2, 1, 0], "ifNumber.0"),
    // Common table roots (without instance)
    (&[1, 3, 6, 1, 2, 1, 1], "system"),
    (&[1, 3, 6, 1, 2, 1, 2], "interfaces"),
    (&[1, 3, 6, 1, 2, 1, 2, 2], "ifTable"),
    (&[1, 3, 6, 1, 2, 1, 2, 2, 1], "ifEntry"),
];

/// Look up a friendly name for an OID.
///
/// Returns `None` if the OID is not in the well-known table.
pub fn lookup(oid: &Oid) -> Option<&'static str> {
    let arcs = oid.arcs();
    WELL_KNOWN_OIDS
        .iter()
        .find(|(pattern, _)| *pattern == arcs)
        .map(|(_, name)| *name)
}

/// Parse an OID from string, supporting both dotted notation and well-known names.
///
/// Accepts:
/// - Dotted notation: "1.3.6.1.2.1.1.1.0"
/// - Well-known names: "sysDescr.0", "system", "ifTable"
pub fn parse_oid(s: &str) -> Result<Oid, String> {
    // First try as dotted notation
    if s.chars()
        .next()
        .map(|c| c.is_ascii_digit())
        .unwrap_or(false)
    {
        return Oid::parse(s).map_err(|e| format!("invalid OID '{}': {}", s, e));
    }

    // Try well-known names (case-insensitive)
    let lower = s.to_ascii_lowercase();
    for (arcs, name) in WELL_KNOWN_OIDS {
        if name.to_ascii_lowercase() == lower {
            return Ok(Oid::from_slice(arcs));
        }
    }

    Err(format!(
        "unknown OID name '{}'; use dotted notation (e.g., 1.3.6.1.2.1.1.1.0)",
        s
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup_found() {
        let oid = Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 1, 0]);
        assert_eq!(lookup(&oid), Some("sysDescr.0"));
    }

    #[test]
    fn test_lookup_not_found() {
        let oid = Oid::from_slice(&[1, 3, 6, 1, 99, 99, 99]);
        assert_eq!(lookup(&oid), None);
    }

    #[test]
    fn test_parse_dotted() {
        let oid = parse_oid("1.3.6.1.2.1.1.1.0").unwrap();
        assert_eq!(oid.arcs(), &[1, 3, 6, 1, 2, 1, 1, 1, 0]);
    }

    #[test]
    fn test_parse_well_known() {
        let oid = parse_oid("sysDescr.0").unwrap();
        assert_eq!(oid.arcs(), &[1, 3, 6, 1, 2, 1, 1, 1, 0]);

        let oid = parse_oid("system").unwrap();
        assert_eq!(oid.arcs(), &[1, 3, 6, 1, 2, 1, 1]);
    }

    #[test]
    fn test_parse_case_insensitive() {
        let oid = parse_oid("SYSDESCR.0").unwrap();
        assert_eq!(oid.arcs(), &[1, 3, 6, 1, 2, 1, 1, 1, 0]);
    }

    #[test]
    fn test_parse_unknown_name() {
        assert!(parse_oid("unknownOid").is_err());
    }
}
