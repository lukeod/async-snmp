//! Output formatting for CLI tools.
//!
//! Supports human-readable, JSON, and raw output formats.

use crate::cli::args::OutputFormat;
use crate::cli::hints;
use crate::{Oid, Value, VarBind, Version};
use serde::Serialize;
use std::io::{self, Write};
use std::net::SocketAddr;
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
pub struct RequestInfo {
    pub target: SocketAddr,
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

    // Type and value details
    let (type_name, decoded, raw_hex, size) = format_verbose_value(&vb.value);

    let _ = writeln!(w, "    Type:    {}", type_name);
    let _ = writeln!(w, "    Value:   {}", decoded);

    if let Some(hex) = raw_hex {
        let _ = writeln!(w, "    Raw:     {}", hex);
    }

    if let Some(s) = size {
        let _ = writeln!(w, "    Size:    {} bytes", s);
    }
}

/// Format a value for verbose output, returning (type_name, decoded_value, raw_hex, size).
fn format_verbose_value(value: &Value) -> (String, String, Option<String>, Option<usize>) {
    match value {
        Value::Integer(v) => ("INTEGER".into(), format!("{}", v), None, None),

        Value::OctetString(bytes) => {
            let raw_hex = format_hex_string(bytes);
            let size = Some(bytes.len());

            if is_printable(bytes) {
                let decoded = String::from_utf8_lossy(bytes).to_string();
                (
                    "STRING".into(),
                    format!("\"{}\"", decoded),
                    Some(raw_hex),
                    size,
                )
            } else {
                ("Hex-STRING".into(), raw_hex.clone(), Some(raw_hex), size)
            }
        }

        Value::Null => ("NULL".into(), "(null)".into(), None, None),

        Value::ObjectIdentifier(oid) => {
            let s = format_oid(oid);
            let hint = hints::lookup(oid);
            let decoded = if let Some(h) = hint {
                format!("{} ({})", s, h)
            } else {
                s
            };
            ("OID".into(), decoded, None, None)
        }

        Value::IpAddress(bytes) => {
            let s = format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]);
            ("IpAddress".into(), s, None, None)
        }

        Value::Counter32(v) => ("Counter32".into(), format!("{}", v), None, None),

        Value::Gauge32(v) => ("Gauge32".into(), format!("{}", v), None, None),

        Value::TimeTicks(v) => {
            let formatted = format_timeticks(*v);
            (
                "TimeTicks".into(),
                format!("{} ({})", v, formatted),
                None,
                None,
            )
        }

        Value::Opaque(bytes) => {
            let raw_hex = format_hex_string(bytes);
            (
                "Opaque".into(),
                raw_hex.clone(),
                Some(raw_hex),
                Some(bytes.len()),
            )
        }

        Value::Counter64(v) => ("Counter64".into(), format!("{}", v), None, None),

        Value::NoSuchObject => (
            "NoSuchObject".into(),
            "No Such Object available".into(),
            None,
            None,
        ),

        Value::NoSuchInstance => (
            "NoSuchInstance".into(),
            "No Such Instance currently exists".into(),
            None,
            None,
        ),

        Value::EndOfMibView => (
            "EndOfMibView".into(),
            "No more variables left in this MIB View".into(),
            None,
            None,
        ),

        Value::Unknown { tag, data } => {
            let raw_hex = format_hex_string(data);
            (
                format!("Unknown(0x{:02X})", tag),
                raw_hex.clone(),
                Some(raw_hex),
                Some(data.len()),
            )
        }
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

/// Output context for formatting.
pub struct OutputContext {
    pub format: OutputFormat,
    pub show_hints: bool,
    pub force_hex: bool,
    pub show_timing: bool,
}

impl OutputContext {
    /// Create a new output context with default settings.
    pub fn new(format: OutputFormat) -> Self {
        Self {
            format,
            show_hints: true,
            force_hex: false,
            show_timing: false,
        }
    }

    /// Write operation results to stdout.
    pub fn write_results(
        &self,
        target: SocketAddr,
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
        target: SocketAddr,
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
        let oid_str = format_oid(&vb.oid);
        let hint = if self.show_hints {
            hints::lookup(&vb.oid).map(String::from)
        } else {
            None
        };

        let (value_type, value, formatted, raw_hex) = format_value(&vb.value, self.force_hex);

        VarBindResult {
            oid: oid_str,
            hint,
            value_type,
            value,
            formatted,
            raw_hex,
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

/// Format a value, returning (type_name, json_value, formatted_string, raw_hex).
fn format_value(
    value: &Value,
    force_hex: bool,
) -> (String, serde_json::Value, Option<String>, Option<String>) {
    match value {
        Value::Integer(v) => ("INTEGER".into(), (*v).into(), None, None),

        Value::OctetString(bytes) => {
            let raw_hex = Some(hex_string(bytes));

            if force_hex || !is_printable(bytes) {
                let formatted = format_hex_string(bytes);
                (
                    "Hex-STRING".into(),
                    serde_json::Value::String(raw_hex.clone().unwrap()),
                    Some(formatted),
                    raw_hex,
                )
            } else {
                let s = String::from_utf8_lossy(bytes);
                (
                    "STRING".into(),
                    serde_json::Value::String(s.to_string()),
                    None,
                    raw_hex,
                )
            }
        }

        Value::Null => ("NULL".into(), serde_json::Value::Null, None, None),

        Value::ObjectIdentifier(oid) => {
            let s = format_oid(oid);
            ("OID".into(), serde_json::Value::String(s), None, None)
        }

        Value::IpAddress(bytes) => {
            let s = format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]);
            ("IpAddress".into(), serde_json::Value::String(s), None, None)
        }

        Value::Counter32(v) => ("Counter32".into(), (*v).into(), None, None),

        Value::Gauge32(v) => ("Gauge32".into(), (*v).into(), None, None),

        Value::TimeTicks(v) => {
            let formatted = format_timeticks(*v);
            (
                "TimeTicks".into(),
                (*v).into(),
                Some(format!("({}) {}", v, formatted)),
                None,
            )
        }

        Value::Opaque(bytes) => {
            let hex = hex_string(bytes);
            (
                "Opaque".into(),
                serde_json::Value::String(hex.clone()),
                Some(format_hex_string(bytes)),
                Some(hex),
            )
        }

        Value::Counter64(v) => ("Counter64".into(), (*v).into(), None, None),

        Value::NoSuchObject => (
            "NoSuchObject".into(),
            serde_json::Value::Null,
            Some("No Such Object available".into()),
            None,
        ),

        Value::NoSuchInstance => (
            "NoSuchInstance".into(),
            serde_json::Value::Null,
            Some("No Such Instance currently exists".into()),
            None,
        ),

        Value::EndOfMibView => (
            "EndOfMibView".into(),
            serde_json::Value::Null,
            Some("No more variables left in this MIB View".into()),
            None,
        ),

        Value::Unknown { tag, data } => {
            let hex = hex_string(data);
            (
                format!("Unknown(0x{:02X})", tag),
                serde_json::Value::String(hex.clone()),
                Some(format_hex_string(data)),
                Some(hex),
            )
        }
    }
}

/// Check if bytes are printable ASCII/UTF-8.
fn is_printable(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return true;
    }

    // Try UTF-8 first
    if let Ok(s) = std::str::from_utf8(bytes) {
        // Check that all characters are printable
        s.chars()
            .all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
    } else {
        false
    }
}

/// Format bytes as hex string (lowercase, no separator).
fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Format bytes as spaced hex for display.
fn format_hex_string(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Format TimeTicks as human-readable duration.
fn format_timeticks(centiseconds: u32) -> String {
    let total_seconds = centiseconds / 100;
    let cs = centiseconds % 100;

    let days = total_seconds / 86400;
    let hours = (total_seconds % 86400) / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;

    if days > 0 {
        format!(
            "{}d {:02}:{:02}:{:02}.{:02}",
            days, hours, minutes, seconds, cs
        )
    } else {
        format!("{:02}:{:02}:{:02}.{:02}", hours, minutes, seconds, cs)
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
        assert!(is_printable(b"Hello World"));
        assert!(is_printable(b"Line 1\nLine 2"));
        assert!(is_printable(b""));
        assert!(!is_printable(&[0x00, 0x01, 0x02]));
        assert!(!is_printable(&[0x80, 0x81]));
    }

    #[test]
    fn test_hex_string() {
        assert_eq!(hex_string(&[0x00, 0x1A, 0x2B]), "001a2b");
    }

    #[test]
    fn test_format_hex_string() {
        assert_eq!(format_hex_string(&[0x00, 0x1A, 0x2B]), "00 1A 2B");
    }
}
