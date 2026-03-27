//! Output formatting for CLI tools.
//!
//! Supports human-readable, JSON, and raw output formats.

use crate::cli::args::{CommonArgs, OutputArgs, OutputFormat, V3Args};
use crate::cli::hints;
use crate::format::hex;
use crate::{Oid, Value, VarBind, Version};
use serde::Serialize;
use std::io::{self, Write};
use std::time::Duration;

/// Operation type for verbose output.
#[derive(Debug, Clone, Copy)]
pub enum OperationType {
    Get,
    GetNext,
    GetBulk {
        non_repeaters: i32,
        max_repetitions: i32,
    },
    Set,
    Walk,
    BulkWalk {
        max_repetitions: i32,
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
    Community(String),
    V3 {
        username: String,
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
    let _ = writeln!(stderr, "--- Request ---");
    let _ = writeln!(stderr, "Target:    {}", info.target);
    let _ = writeln!(stderr, "Version:   {:?}", info.version);

    match &info.security {
        SecurityInfo::Community(c) => {
            let _ = writeln!(stderr, "Community: {}", c);
        }
        SecurityInfo::V3 {
            username,
            auth_protocol,
            priv_protocol,
        } => {
            let _ = writeln!(stderr, "Username:  {}", username);
            if let Some(auth) = auth_protocol {
                let _ = writeln!(stderr, "Auth:      {}", auth);
            }
            if let Some(priv_p) = priv_protocol {
                let _ = writeln!(stderr, "Privacy:   {}", priv_p);
            }
        }
    }

    let _ = writeln!(stderr, "Operation: {}", info.operation);

    if let OperationType::GetBulk {
        non_repeaters,
        max_repetitions,
    } = info.operation
    {
        let _ = writeln!(stderr, "  Non-repeaters:    {}", non_repeaters);
        let _ = writeln!(stderr, "  Max-repetitions:  {}", max_repetitions);
    } else if let OperationType::BulkWalk { max_repetitions } = info.operation {
        let _ = writeln!(stderr, "  Max-repetitions:  {}", max_repetitions);
    }

    let _ = writeln!(stderr, "OIDs:      {} total", info.oids.len());
    for oid in &info.oids {
        let hint = hints::lookup(oid);
        if let Some(h) = hint {
            let _ = writeln!(stderr, "  {} ({})", oid, h);
        } else {
            let _ = writeln!(stderr, "  {}", oid);
        }
    }
    let _ = writeln!(stderr);
}

/// Write verbose response summary to stderr.
pub fn write_verbose_response(varbinds: &[VarBind], elapsed: Duration, show_hints: bool) {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "--- Response ---");
    let _ = writeln!(stderr, "Results:   {} varbind(s)", varbinds.len());
    let _ = writeln!(stderr, "Time:      {:.2}ms", elapsed.as_secs_f64() * 1000.0);
    let _ = writeln!(stderr);

    for vb in varbinds {
        write_verbose_varbind(&mut stderr, vb, show_hints);
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

/// Decode a Value into its display components.
fn decode_value(value: &Value, force_hex: bool) -> DecodedValue {
    match value {
        Value::Integer(v) => DecodedValue {
            type_name: "INTEGER".into(),
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
            type_name: "NULL".into(),
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
                type_name: "OID".into(),
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
                type_name: "IpAddress".into(),
                display: s.clone(),
                json_value: serde_json::Value::String(s),
                formatted: None,
                raw_hex: None,
                size: None,
            }
        }

        Value::Counter32(v) => DecodedValue {
            type_name: "Counter32".into(),
            display: v.to_string(),
            json_value: (*v).into(),
            formatted: None,
            raw_hex: None,
            size: None,
        },

        Value::Gauge32(v) => DecodedValue {
            type_name: "Gauge32".into(),
            display: v.to_string(),
            json_value: (*v).into(),
            formatted: None,
            raw_hex: None,
            size: None,
        },

        Value::TimeTicks(v) => {
            let human = format_timeticks(*v);
            DecodedValue {
                type_name: "TimeTicks".into(),
                display: format!("{} ({})", v, human),
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
                type_name: "Opaque".into(),
                display: spaced_hex.clone(),
                json_value: serde_json::Value::String(compact_hex.clone()),
                formatted: Some(spaced_hex),
                raw_hex: Some(compact_hex),
                size: Some(bytes.len()),
            }
        }

        Value::Counter64(v) => DecodedValue {
            type_name: "Counter64".into(),
            display: v.to_string(),
            json_value: (*v).into(),
            formatted: None,
            raw_hex: None,
            size: None,
        },

        Value::NoSuchObject => DecodedValue {
            type_name: "NoSuchObject".into(),
            display: "No Such Object available".into(),
            json_value: serde_json::Value::Null,
            formatted: Some("No Such Object available".into()),
            raw_hex: None,
            size: None,
        },

        Value::NoSuchInstance => DecodedValue {
            type_name: "NoSuchInstance".into(),
            display: "No Such Instance currently exists".into(),
            json_value: serde_json::Value::Null,
            formatted: Some("No Such Instance currently exists".into()),
            raw_hex: None,
            size: None,
        },

        Value::EndOfMibView => DecodedValue {
            type_name: "EndOfMibView".into(),
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
fn write_verbose_varbind<W: Write>(w: &mut W, vb: &VarBind, show_hints: bool) {
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

    let decoded = decode_value(&vb.value, false);

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

/// Build a SecurityInfo from CLI arguments.
pub fn build_security_info(v3: &V3Args, common: &CommonArgs) -> SecurityInfo {
    if v3.is_v3() {
        SecurityInfo::V3 {
            username: v3.username.clone().unwrap_or_default(),
            auth_protocol: v3.auth_protocol.map(|p| format!("{}", p)),
            priv_protocol: v3.priv_protocol.map(|p| format!("{}", p)),
        }
    } else {
        SecurityInfo::Community(common.community.clone())
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
