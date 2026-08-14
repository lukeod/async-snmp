//! Output formatting for CLI tools.
//!
//! Supports human-readable, JSON, and raw output formats.

use crate::cli::args::{OutputArgs, OutputFormat};
use crate::cli::hints;
use crate::client::Auth;
use crate::format::hex;
use crate::{Oid, Value, ValueKind, VarBind, Version};
use serde::Serialize;
use std::io::{self, Write};
use std::time::Duration;

/// Operation type for verbose output.
#[derive(Debug, Clone, Copy)]
pub enum OperationType {
    Get,
    GetNext,
    GetBulk {
        non_repeaters: u32,
        max_repetitions: u32,
    },
    Set,
    Walk,
    BulkWalk {
        max_repetitions: u32,
    },
}

impl std::fmt::Display for OperationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Get => write!(f, "GET"),
            Self::GetNext => write!(f, "GETNEXT"),
            Self::GetBulk { .. } => write!(f, "GETBULK"),
            Self::Set => write!(f, "SET"),
            Self::Walk => write!(f, "WALK (GETNEXT)"),
            Self::BulkWalk { .. } => write!(f, "WALK (GETBULK)"),
        }
    }
}

/// Security info for verbose output.
#[derive(Debug, Clone)]
pub enum SecurityInfo {
    Community,
    V3 {
        username: bytes::Bytes,
        auth_protocol: Option<String>,
        priv_protocol: Option<String>,
    },
}

/// Request metadata for verbose output.
#[derive(Debug)]
pub struct RequestInfo<'a> {
    pub target: &'a str,
    pub version: Version,
    pub security: SecurityInfo,
    pub operation: OperationType,
    pub oids: Vec<Oid>,
}

/// Write verbose request header to stderr.
pub fn write_verbose_request(info: &RequestInfo) {
    let mut stderr = std::io::stderr().lock();
    write_verbose_request_to(&mut stderr, info);
}

fn write_verbose_request_to(mut output: impl Write, info: &RequestInfo) {
    let _ = writeln!(output, "--- Request ---");
    let _ = writeln!(output, "Target:    {}", info.target);
    let _ = writeln!(output, "Version:   {:?}", info.version);

    match &info.security {
        SecurityInfo::Community => {
            let _ = writeln!(output, "Community: [REDACTED]");
        }
        SecurityInfo::V3 {
            username,
            auth_protocol,
            priv_protocol,
        } => {
            let _ = writeln!(output, "Username:  {username:?}");
            if let Some(auth) = auth_protocol {
                let _ = writeln!(output, "Auth:      {}", auth);
            }
            if let Some(priv_p) = priv_protocol {
                let _ = writeln!(output, "Privacy:   {}", priv_p);
            }
        }
    }

    let _ = writeln!(output, "Operation: {}", info.operation);

    if let OperationType::GetBulk {
        non_repeaters,
        max_repetitions,
    } = info.operation
    {
        let _ = writeln!(output, "  Non-repeaters:    {}", non_repeaters);
        let _ = writeln!(output, "  Max-repetitions:  {}", max_repetitions);
    } else if let OperationType::BulkWalk { max_repetitions } = info.operation {
        let _ = writeln!(output, "  Max-repetitions:  {}", max_repetitions);
    }

    let _ = writeln!(output, "OIDs:      {} total", info.oids.len());
    for oid in &info.oids {
        let hint = hints::lookup(oid);
        if let Some(h) = hint {
            let _ = writeln!(output, "  {} ({})", oid, h);
        } else {
            let _ = writeln!(output, "  {}", oid);
        }
    }
    let _ = writeln!(output);
}

/// Write verbose response summary to stderr.
pub fn write_verbose_response(
    varbinds: &[VarBind],
    elapsed: Duration,
    show_hints: bool,
    force_hex: bool,
) {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "--- Response ---");
    let _ = writeln!(stderr, "Results:   {} varbind(s)", varbinds.len());
    let _ = writeln!(stderr, "Time:      {:.2}ms", elapsed.as_secs_f64() * 1000.0);
    let _ = writeln!(stderr);

    for vb in varbinds {
        write_verbose_varbind(&mut stderr, vb, show_hints, force_hex);
    }

    if !varbinds.is_empty() {
        let _ = writeln!(stderr);
    }
}

/// Decoded representation of a Value, used by both verbose and normal output paths.
struct DecodedValue {
    type_name: String,
    /// Human-readable display string (used by verbose output).
    display: String,
    /// JSON-serializable representation (used by structured output).
    json_value: serde_json::Value,
    /// Formatted display string for human output (timeticks, error messages, hex display).
    formatted: Option<String>,
    /// Compact hex encoding of raw bytes (used by JSON/structured output).
    raw_hex: Option<String>,
    /// Byte length (used by verbose output for byte types).
    size: Option<usize>,
}

fn fixed_type_name(kind: ValueKind) -> &'static str {
    match kind {
        ValueKind::Integer => "INTEGER",
        ValueKind::OctetString => "STRING",
        ValueKind::Null => "NULL",
        ValueKind::ObjectIdentifier => "OID",
        ValueKind::IpAddress => "IpAddress",
        ValueKind::Counter32 => "Counter32",
        ValueKind::Gauge32 => "Gauge32",
        ValueKind::UInteger32 => "UInteger32",
        ValueKind::TimeTicks => "TimeTicks",
        ValueKind::Opaque => "Opaque",
        ValueKind::Nsap => "Nsap",
        ValueKind::Counter64 => "Counter64",
        ValueKind::NoSuchObject => "NoSuchObject",
        ValueKind::NoSuchInstance => "NoSuchInstance",
        ValueKind::EndOfMibView => "EndOfMibView",
        ValueKind::Unknown => "Unknown",
    }
}

/// Decode a Value into its display components.
fn decode_value(value: &Value, force_hex: bool) -> DecodedValue {
    match value {
        Value::Integer(v) => DecodedValue {
            type_name: fixed_type_name(value.kind()).into(),
            display: v.to_string(),
            json_value: (*v).into(),
            formatted: None,
            raw_hex: None,
            size: None,
        },

        Value::OctetString(bytes) => {
            let compact_hex = hex::encode(bytes);
            let spaced_hex = format_hex_string(bytes);
            let size = Some(bytes.len());

            if force_hex || !hex::is_printable(bytes) {
                DecodedValue {
                    type_name: "Hex-STRING".into(),
                    display: spaced_hex.clone(),
                    json_value: serde_json::Value::String(compact_hex.clone()),
                    formatted: Some(spaced_hex),
                    raw_hex: Some(compact_hex),
                    size,
                }
            } else {
                let s = String::from_utf8_lossy(bytes).to_string();
                DecodedValue {
                    type_name: "STRING".into(),
                    display: format!("\"{}\"", s),
                    json_value: serde_json::Value::String(s),
                    formatted: None,
                    raw_hex: Some(compact_hex),
                    size,
                }
            }
        }

        Value::Null => DecodedValue {
            type_name: fixed_type_name(value.kind()).into(),
            display: "(null)".into(),
            json_value: serde_json::Value::Null,
            formatted: None,
            raw_hex: None,
            size: None,
        },

        Value::ObjectIdentifier(oid) => {
            let s = format_oid(oid);
            let hint = hints::lookup(oid);
            let display = if let Some(h) = hint {
                format!("{} ({})", s, h)
            } else {
                s.clone()
            };
            DecodedValue {
                type_name: fixed_type_name(value.kind()).into(),
                display,
                json_value: serde_json::Value::String(s),
                formatted: None,
                raw_hex: None,
                size: None,
            }
        }

        Value::IpAddress(bytes) => {
            let s = format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]);
            DecodedValue {
                type_name: fixed_type_name(value.kind()).into(),
                display: s.clone(),
                json_value: serde_json::Value::String(s),
                formatted: None,
                raw_hex: None,
                size: None,
            }
        }

        Value::Counter32(v) => DecodedValue {
            type_name: fixed_type_name(value.kind()).into(),
            display: v.to_string(),
            json_value: (*v).into(),
            formatted: None,
            raw_hex: None,
            size: None,
        },

        Value::Gauge32(v) => DecodedValue {
            type_name: fixed_type_name(value.kind()).into(),
            display: v.to_string(),
            json_value: (*v).into(),
            formatted: None,
            raw_hex: None,
            size: None,
        },

        Value::UInteger32(v) => DecodedValue {
            type_name: fixed_type_name(value.kind()).into(),
            display: v.to_string(),
            json_value: (*v).into(),
            formatted: None,
            raw_hex: None,
            size: None,
        },

        Value::TimeTicks(v) => {
            let human = format_timeticks(*v);
            DecodedValue {
                type_name: fixed_type_name(value.kind()).into(),
                display: format!("({}) {}", v, human),
                json_value: (*v).into(),
                formatted: Some(format!("({}) {}", v, human)),
                raw_hex: None,
                size: None,
            }
        }

        Value::Opaque(bytes) => {
            let compact_hex = hex::encode(bytes);
            let spaced_hex = format_hex_string(bytes);
            DecodedValue {
                type_name: fixed_type_name(value.kind()).into(),
                display: spaced_hex.clone(),
                json_value: serde_json::Value::String(compact_hex.clone()),
                formatted: Some(spaced_hex),
                raw_hex: Some(compact_hex),
                size: Some(bytes.len()),
            }
        }

        // NSAP addresses are binary; always render hex (matches net-snmp).
        Value::Nsap(bytes) => {
            let compact_hex = hex::encode(bytes);
            let spaced_hex = format_hex_string(bytes);

            DecodedValue {
                type_name: fixed_type_name(value.kind()).into(),
                display: spaced_hex.clone(),
                json_value: serde_json::Value::String(compact_hex.clone()),
                formatted: Some(spaced_hex),
                raw_hex: Some(compact_hex),
                size: Some(bytes.len()),
            }
        }

        Value::Counter64(v) => DecodedValue {
            type_name: fixed_type_name(value.kind()).into(),
            display: v.to_string(),
            json_value: (*v).into(),
            formatted: None,
            raw_hex: None,
            size: None,
        },

        Value::NoSuchObject => DecodedValue {
            type_name: fixed_type_name(value.kind()).into(),
            display: "No Such Object available".into(),
            json_value: serde_json::Value::Null,
            formatted: Some("No Such Object available".into()),
            raw_hex: None,
            size: None,
        },

        Value::NoSuchInstance => DecodedValue {
            type_name: fixed_type_name(value.kind()).into(),
            display: "No Such Instance currently exists".into(),
            json_value: serde_json::Value::Null,
            formatted: Some("No Such Instance currently exists".into()),
            raw_hex: None,
            size: None,
        },

        Value::EndOfMibView => DecodedValue {
            type_name: fixed_type_name(value.kind()).into(),
            display: "No more variables left in this MIB View".into(),
            json_value: serde_json::Value::Null,
            formatted: Some("No more variables left in this MIB View".into()),
            raw_hex: None,
            size: None,
        },

        Value::Unknown { tag, data } => {
            let compact_hex = hex::encode(data);
            let spaced_hex = format_hex_string(data);
            DecodedValue {
                type_name: format!("Unknown(0x{:02X})", tag),
                display: spaced_hex.clone(),
                json_value: serde_json::Value::String(compact_hex.clone()),
                formatted: Some(spaced_hex),
                raw_hex: Some(compact_hex),
                size: Some(data.len()),
            }
        }
    }
}

/// Write detailed varbind information for verbose output.
fn write_verbose_varbind<W: Write>(w: &mut W, vb: &VarBind, show_hints: bool, force_hex: bool) {
    // OID with optional hint
    let hint = if show_hints {
        hints::lookup(&vb.oid)
    } else {
        None
    };
    if let Some(h) = hint {
        let _ = writeln!(w, "  {} ({})", format_oid(&vb.oid), h);
    } else {
        let _ = writeln!(w, "  {}", format_oid(&vb.oid));
    }

    let decoded = decode_value(&vb.value, force_hex);

    let _ = writeln!(w, "    Type:    {}", decoded.type_name);
    let _ = writeln!(w, "    Value:   {}", decoded.display);

    if let Some(ref raw) = decoded.raw_hex {
        let _ = writeln!(w, "    Raw:     {}", raw);
    }

    if let Some(s) = decoded.size {
        let _ = writeln!(w, "    Size:    {} bytes", s);
    }
}

/// Result of a GET/WALK operation, ready for output.
#[derive(Debug, Serialize)]
pub struct OperationResult {
    pub target: String,
    pub version: String,
    pub results: Vec<VarBindResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timing_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retries: Option<u32>,
}

/// A single varbind result.
#[derive(Debug, Serialize)]
pub struct VarBindResult {
    pub oid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    #[serde(rename = "type")]
    pub value_type: String,
    pub value: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formatted: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_hex: Option<String>,
}

/// Trait for formatting OIDs and values using external metadata.
///
/// Implementors provide symbolic OID formatting and type-aware value rendering.
/// Used by [`OutputContext`] to produce richer output when available.
pub trait VarBindFormatter {
    /// Format a numeric OID symbolically (e.g., "IF-MIB::ifDescr.1").
    fn format_oid(&self, oid: &Oid) -> String;
    /// Format a value using type metadata for the given OID.
    fn format_value(&self, oid: &Oid, value: &Value) -> String;
}

/// Output context for formatting.
pub struct OutputContext<'a> {
    pub format: OutputFormat,
    pub show_hints: bool,
    pub force_hex: bool,
    pub show_timing: bool,
    /// Optional formatter for symbolic OID names and type-aware values.
    pub formatter: Option<&'a dyn VarBindFormatter>,
}

impl<'a> OutputContext<'a> {
    /// Create a new output context with default settings.
    pub fn new(format: OutputFormat) -> Self {
        Self {
            format,
            show_hints: true,
            force_hex: false,
            show_timing: false,
            formatter: None,
        }
    }

    /// Create an output context from CLI output arguments.
    pub fn from_args(output: &OutputArgs) -> Self {
        Self {
            format: output.format,
            show_hints: !output.no_hints,
            force_hex: output.hex,
            show_timing: output.timing,
            formatter: None,
        }
    }

    /// Write operation results to stdout.
    pub fn write_results(
        &self,
        target: &str,
        version: Version,
        varbinds: &[VarBind],
        elapsed: Option<Duration>,
        retries: Option<u32>,
    ) -> io::Result<()> {
        let result = self.build_result(target, version, varbinds, elapsed, retries);
        let mut stdout = io::stdout().lock();

        match self.format {
            OutputFormat::Human => self.write_human(&mut stdout, &result),
            OutputFormat::Json => self.write_json(&mut stdout, &result),
            OutputFormat::Raw => self.write_raw(&mut stdout, &result),
        }
    }

    fn build_result(
        &self,
        target: &str,
        version: Version,
        varbinds: &[VarBind],
        elapsed: Option<Duration>,
        retries: Option<u32>,
    ) -> OperationResult {
        let results = varbinds.iter().map(|vb| self.format_varbind(vb)).collect();

        OperationResult {
            target: target.to_string(),
            version: format!("{:?}", version),
            results,
            timing_ms: elapsed.map(|d| d.as_secs_f64() * 1000.0),
            retries,
        }
    }

    fn format_varbind(&self, vb: &VarBind) -> VarBindResult {
        if let Some(fmt) = self.formatter {
            return self.format_varbind_with_formatter(fmt, vb);
        }

        let oid_str = format_oid(&vb.oid);
        let hint = if self.show_hints {
            hints::lookup(&vb.oid).map(String::from)
        } else {
            None
        };

        let decoded = decode_value(&vb.value, self.force_hex);

        VarBindResult {
            oid: oid_str,
            hint,
            value_type: decoded.type_name,
            value: decoded.json_value,
            formatted: decoded.formatted,
            raw_hex: decoded.raw_hex,
        }
    }

    fn format_varbind_with_formatter(
        &self,
        fmt: &dyn VarBindFormatter,
        vb: &VarBind,
    ) -> VarBindResult {
        let oid_str = fmt.format_oid(&vb.oid);
        let formatted_value = fmt.format_value(&vb.oid, &vb.value);
        let decoded = decode_value(&vb.value, self.force_hex);

        VarBindResult {
            oid: oid_str,
            hint: None, // Formatter provides the OID name directly
            value_type: decoded.type_name,
            value: decoded.json_value,
            formatted: Some(formatted_value),
            raw_hex: decoded.raw_hex,
        }
    }

    fn write_human<W: Write>(&self, w: &mut W, result: &OperationResult) -> io::Result<()> {
        for vb in &result.results {
            // OID with optional hint
            if let Some(ref hint) = vb.hint {
                write!(w, "{} ({})", vb.oid, hint)?;
            } else {
                write!(w, "{}", vb.oid)?;
            }

            // Type and value
            write!(w, " = {}: ", vb.value_type)?;

            // Value - prefer formatted for display
            if let Some(ref formatted) = vb.formatted {
                writeln!(w, "{}", formatted)?;
            } else {
                match &vb.value {
                    serde_json::Value::String(s) => writeln!(w, "\"{}\"", s)?,
                    serde_json::Value::Null => writeln!(w)?,
                    other => writeln!(w, "{}", other)?,
                }
            }
        }

        if self.show_timing
            && let Some(ms) = result.timing_ms
        {
            if let Some(retries) = result.retries {
                writeln!(w, "\nTiming: {:.1}ms ({} retries)", ms, retries)?;
            } else {
                writeln!(w, "\nTiming: {:.1}ms", ms)?;
            }
        }

        Ok(())
    }

    fn write_json<W: Write>(&self, w: &mut W, result: &OperationResult) -> io::Result<()> {
        let json = serde_json::to_string_pretty(result).map_err(io::Error::other)?;
        writeln!(w, "{}", json)
    }

    fn write_raw<W: Write>(&self, w: &mut W, result: &OperationResult) -> io::Result<()> {
        for vb in &result.results {
            let value_str = match &vb.value {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Null => String::new(),
                other => other.to_string(),
            };
            writeln!(w, "{}\t{}", vb.oid, value_str)?;
        }
        Ok(())
    }
}

/// Format an OID as dotted string.
fn format_oid(oid: &Oid) -> String {
    oid.arcs()
        .iter()
        .map(|a| a.to_string())
        .collect::<Vec<_>>()
        .join(".")
}

/// Format bytes as spaced hex for display.
fn format_hex_string(bytes: &[u8]) -> String {
    crate::format::format_hex_display(bytes)
}

/// Format TimeTicks as human-readable duration.
fn format_timeticks(centiseconds: u32) -> String {
    crate::format::format_timeticks(centiseconds)
}

/// Build display security data from a constructed authentication configuration.
pub fn build_security_info(auth: &Auth) -> SecurityInfo {
    match auth {
        Auth::Community { .. } => SecurityInfo::Community,
        Auth::Usm(config) => SecurityInfo::V3 {
            username: config.username().clone(),
            auth_protocol: config.auth_protocol().map(|protocol| protocol.to_string()),
            priv_protocol: config.priv_protocol().map(|protocol| protocol.to_string()),
        },
    }
}

/// Write an error message to stderr.
pub fn write_error(err: &crate::Error) {
    eprintln!("Error: {}", err);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_kinds_drive_fixed_cli_type_names() {
        let cases = [
            (ValueKind::Integer, "INTEGER"),
            (ValueKind::OctetString, "STRING"),
            (ValueKind::Null, "NULL"),
            (ValueKind::ObjectIdentifier, "OID"),
            (ValueKind::IpAddress, "IpAddress"),
            (ValueKind::Counter32, "Counter32"),
            (ValueKind::Gauge32, "Gauge32"),
            (ValueKind::UInteger32, "UInteger32"),
            (ValueKind::TimeTicks, "TimeTicks"),
            (ValueKind::Opaque, "Opaque"),
            (ValueKind::Nsap, "Nsap"),
            (ValueKind::Counter64, "Counter64"),
            (ValueKind::NoSuchObject, "NoSuchObject"),
            (ValueKind::NoSuchInstance, "NoSuchInstance"),
            (ValueKind::EndOfMibView, "EndOfMibView"),
            (ValueKind::Unknown, "Unknown"),
        ];

        for (kind, expected) in cases {
            assert_eq!(fixed_type_name(kind), expected);
        }
    }

    #[test]
    fn payload_specific_cli_type_names_are_preserved() {
        assert_eq!(
            decode_value(&Value::from("text"), false).type_name,
            "STRING"
        );
        assert_eq!(
            decode_value(&Value::from(&[0, 1][..]), false).type_name,
            "Hex-STRING"
        );
        assert_eq!(
            decode_value(
                &Value::Unknown {
                    tag: 0x1e,
                    data: bytes::Bytes::new(),
                },
                false,
            )
            .type_name,
            "Unknown(0x1E)"
        );
    }

    #[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
    #[test]
    fn security_info_is_derived_from_constructed_auth() {
        let community = Auth::v1("private");
        assert_eq!(community.version(), Version::V1);
        assert!(matches!(
            build_security_info(&community),
            SecurityInfo::Community
        ));

        let usm = crate::Auth::from(
            crate::UsmConfig::new("operator")
                .auth(crate::AuthProtocol::Sha256, "authpassword")
                .unwrap(),
        );
        assert_eq!(usm.version(), Version::V3);
        assert!(matches!(
            build_security_info(&usm),
            SecurityInfo::V3 {
                username,
                auth_protocol: Some(protocol),
                priv_protocol: None,
            } if username.as_ref() == b"operator" && protocol == "SHA-256"
        ));
    }

    #[test]
    fn security_info_formats_non_utf8_username_without_replacement() {
        let auth = Auth::usm(bytes::Bytes::from_static(b"operator\xff"));
        let info = RequestInfo {
            target: "127.0.0.1:161",
            version: auth.version(),
            security: build_security_info(&auth),
            operation: OperationType::Get,
            oids: vec![Oid::from_slice(&[1, 3, 6, 1])],
        };
        let mut output = Vec::new();

        write_verbose_request_to(&mut output, &info);
        let verbose = String::from_utf8(output).unwrap();
        assert!(verbose.contains(r#"Username:  b"operator\xff""#));
        assert!(!verbose.contains('\u{fffd}'));
    }

    #[test]
    fn community_is_redacted_from_verbose_and_debug_output() {
        let secret = "private-community";
        let auth = Auth::v2c(secret);
        let info = RequestInfo {
            target: "127.0.0.1:161",
            version: auth.version(),
            security: build_security_info(&auth),
            operation: OperationType::Get,
            oids: vec![Oid::from_slice(&[1, 3, 6, 1])],
        };
        let mut output = Vec::new();

        write_verbose_request_to(&mut output, &info);
        let verbose = String::from_utf8(output).unwrap();
        let debug = format!("{info:?}");

        assert!(verbose.contains("Community: [REDACTED]"));
        assert!(!verbose.contains(secret));
        assert!(!debug.contains(secret));
    }

    #[test]
    fn verbose_varbind_honors_force_hex() {
        let vb = VarBind::new(
            Oid::from_slice(&[1, 3, 6, 1]),
            Value::OctetString(bytes::Bytes::from_static(b"text")),
        );
        let mut output = Vec::new();

        write_verbose_varbind(&mut output, &vb, false, true);

        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("Type:    Hex-STRING"));
        assert!(output.contains("Value:   74 65 78 74"));
    }

    #[test]
    fn test_format_timeticks() {
        // 1 day, 10 hours, 17 minutes, 36.78 seconds = 123456.78 seconds = 12345678 centiseconds
        assert_eq!(format_timeticks(12345678), "1d 10:17:36.78");

        // Less than a day
        assert_eq!(format_timeticks(360000), "01:00:00.00");

        // Zero
        assert_eq!(format_timeticks(0), "00:00:00.00");
    }

    #[test]
    fn test_is_printable() {
        assert!(hex::is_printable(b"Hello World"));
        assert!(hex::is_printable(b"Line 1\nLine 2"));
        assert!(hex::is_printable(b""));
        assert!(!hex::is_printable(&[0x00, 0x01, 0x02]));
        assert!(!hex::is_printable(&[0x80, 0x81]));
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex::encode(&[0x00, 0x1A, 0x2B]), "001a2b");
    }

    #[test]
    fn test_format_hex_string() {
        assert_eq!(format_hex_string(&[0x00, 0x1A, 0x2B]), "00 1A 2B");
    }
}
