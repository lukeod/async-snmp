//! Command-line argument structures for async-snmp CLI tools.
//!
//! This module provides reusable clap argument structures for the `asnmp-*` CLI tools.

use clap::{Parser, ValueEnum};
use std::net::SocketAddr;
use std::time::Duration;

use crate::Version;
use crate::client::{Auth, Backoff, Retry};
use crate::v3::{AuthProtocol, PrivProtocol};

/// SNMP version for CLI argument parsing.
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum SnmpVersion {
    /// SNMPv1
    #[value(name = "1")]
    V1,
    /// SNMPv2c (default)
    #[default]
    #[value(name = "2c")]
    V2c,
    /// SNMPv3
    #[value(name = "3")]
    V3,
}

impl From<SnmpVersion> for Version {
    fn from(v: SnmpVersion) -> Self {
        match v {
            SnmpVersion::V1 => Version::V1,
            SnmpVersion::V2c => Version::V2c,
            SnmpVersion::V3 => Version::V3,
        }
    }
}

/// Output format for CLI tools.
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum OutputFormat {
    /// Human-readable output with type information.
    #[default]
    Human,
    /// JSON output for scripting.
    Json,
    /// Raw tab-separated output for scripting.
    Raw,
}

/// Backoff strategy for CLI argument parsing.
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum BackoffStrategy {
    /// No delay between retries (immediate retry on timeout).
    #[default]
    None,
    /// Fixed delay between each retry.
    Fixed,
    /// Exponential backoff: delay doubles after each attempt.
    Exponential,
}

/// Common arguments shared across all CLI tools.
#[derive(Debug, Parser)]
pub struct CommonArgs {
    /// Target host or host:port (default port 161).
    #[arg(value_name = "TARGET")]
    pub target: String,

    /// SNMP version: 1, 2c, or 3.
    #[arg(short = 'v', long = "snmp-version", default_value = "2c")]
    pub snmp_version: SnmpVersion,

    /// Community string (v1/v2c).
    #[arg(short = 'c', long = "community", default_value = "public")]
    pub community: String,

    /// Request timeout in seconds.
    #[arg(short = 't', long = "timeout", default_value = "5")]
    pub timeout: f64,

    /// Retry count.
    #[arg(short = 'r', long = "retries", default_value = "3")]
    pub retries: u32,

    /// Backoff strategy between retries: none, fixed, or exponential.
    #[arg(long = "backoff", default_value = "none")]
    pub backoff: BackoffStrategy,

    /// Backoff delay in milliseconds (initial delay for exponential, fixed delay otherwise).
    #[arg(long = "backoff-delay", default_value = "1000")]
    pub backoff_delay: u64,

    /// Maximum backoff delay in milliseconds (exponential only).
    #[arg(long = "backoff-max", default_value = "5000")]
    pub backoff_max: u64,

    /// Jitter factor for exponential backoff (0.0-1.0, e.g., 0.25 means +/-25%).
    #[arg(long = "backoff-jitter", default_value = "0.25")]
    pub backoff_jitter: f64,
}

impl CommonArgs {
    /// Parse the target into a SocketAddr, defaulting to port 161.
    pub fn target_addr(&self) -> Result<SocketAddr, String> {
        // If the target doesn't contain a port, add the default SNMP port
        let addr_str = if self.target.contains(':') {
            self.target.clone()
        } else {
            format!("{}:161", self.target)
        };

        addr_str
            .parse()
            .or_else(|_| {
                // Try to resolve as hostname
                use std::net::ToSocketAddrs;
                addr_str
                    .to_socket_addrs()
                    .map_err(|e| e.to_string())?
                    .next()
                    .ok_or_else(|| format!("could not resolve hostname: {}", self.target))
            })
            .map_err(|e| format!("invalid target '{}': {}", self.target, e))
    }

    /// Get the timeout as a Duration.
    pub fn timeout_duration(&self) -> Duration {
        Duration::from_secs_f64(self.timeout)
    }

    /// Build a Retry configuration from the CLI arguments.
    pub fn retry_config(&self) -> Retry {
        let backoff = match self.backoff {
            BackoffStrategy::None => Backoff::None,
            BackoffStrategy::Fixed => Backoff::Fixed {
                delay: Duration::from_millis(self.backoff_delay),
            },
            BackoffStrategy::Exponential => Backoff::Exponential {
                initial: Duration::from_millis(self.backoff_delay),
                max: Duration::from_millis(self.backoff_max),
                jitter: self.backoff_jitter.clamp(0.0, 1.0),
            },
        };
        Retry {
            max_attempts: self.retries,
            backoff,
        }
    }
}

/// SNMPv3 security arguments.
#[derive(Debug, Parser)]
pub struct V3Args {
    /// Security name/username (implies -v 3).
    #[arg(short = 'u', long = "username")]
    pub username: Option<String>,

    /// Security level: noAuthNoPriv, authNoPriv, or authPriv.
    #[arg(short = 'l', long = "level")]
    pub level: Option<String>,

    /// Authentication protocol: MD5, SHA, SHA-224, SHA-256, SHA-384, SHA-512.
    #[arg(short = 'a', long = "auth-protocol")]
    pub auth_protocol: Option<AuthProtocol>,

    /// Authentication passphrase.
    #[arg(short = 'A', long = "auth-password")]
    pub auth_password: Option<String>,

    /// Privacy protocol: DES, AES, AES-128, AES-192, AES-256.
    #[arg(short = 'x', long = "priv-protocol")]
    pub priv_protocol: Option<PrivProtocol>,

    /// Privacy passphrase.
    #[arg(short = 'X', long = "priv-password")]
    pub priv_password: Option<String>,
}

impl V3Args {
    /// Check if V3 mode is enabled (username provided).
    pub fn is_v3(&self) -> bool {
        self.username.is_some()
    }

    /// Build an Auth configuration from the V3 args and common args.
    ///
    /// If a username is provided, builds a USM auth configuration.
    /// Otherwise, builds a community auth based on the version and community from common args.
    pub fn auth(&self, common: &CommonArgs) -> Result<Auth, String> {
        if let Some(ref username) = self.username {
            let mut builder = Auth::usm(username);
            if let Some(proto) = self.auth_protocol {
                let pass = self
                    .auth_password
                    .as_ref()
                    .ok_or("auth password required")?;
                builder = builder.auth(proto, pass);
            }
            if let Some(proto) = self.priv_protocol {
                let pass = self
                    .priv_password
                    .as_ref()
                    .ok_or("priv password required")?;
                builder = builder.privacy(proto, pass);
            }
            Ok(builder.into())
        } else {
            let community = &common.community;
            Ok(match common.snmp_version {
                SnmpVersion::V1 => Auth::v1(community),
                _ => Auth::v2c(community),
            })
        }
    }

    /// Validate V3 arguments and return an error message if invalid.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(ref _username) = self.username {
            // If auth-protocol is specified, auth-password is required
            if self.auth_protocol.is_some() && self.auth_password.is_none() {
                return Err(
                    "authentication password (-A) required when using auth protocol".into(),
                );
            }

            // If priv-protocol is specified, priv-password is required
            if self.priv_protocol.is_some() && self.priv_password.is_none() {
                return Err("privacy password (-X) required when using priv protocol".into());
            }

            // Privacy requires authentication
            if self.priv_protocol.is_some() && self.auth_protocol.is_none() {
                return Err("authentication protocol (-a) required when using privacy".into());
            }
        }
        Ok(())
    }
}

/// Output control arguments.
#[derive(Debug, Parser)]
pub struct OutputArgs {
    /// Output format: human, json, or raw.
    #[arg(short = 'O', long = "output", default_value = "human")]
    pub format: OutputFormat,

    /// Show PDU structure and wire details.
    #[arg(long = "verbose")]
    pub verbose: bool,

    /// Always display OctetString as hex.
    #[arg(long = "hex")]
    pub hex: bool,

    /// Show request timing.
    #[arg(long = "timing")]
    pub timing: bool,

    /// Disable well-known OID name hints.
    #[arg(long = "no-hints")]
    pub no_hints: bool,

    /// Enable debug logging (async_snmp=debug).
    #[arg(short = 'd', long = "debug")]
    pub debug: bool,

    /// Enable trace logging (async_snmp=trace).
    #[arg(short = 'D', long = "trace")]
    pub trace: bool,
}

impl OutputArgs {
    /// Initialize tracing based on debug/trace flags.
    ///
    /// Note: --verbose is handled separately and shows structured request/response info.
    /// Use -d/--debug for library-level tracing.
    pub fn init_tracing(&self) {
        use tracing_subscriber::EnvFilter;

        let filter = if self.trace {
            "async_snmp=trace"
        } else if self.debug {
            "async_snmp=debug"
        } else {
            "async_snmp=warn"
        };

        let _ = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::new(filter))
            .with_writer(std::io::stderr)
            .try_init();
    }
}

/// Walk-specific arguments.
#[derive(Debug, Parser)]
pub struct WalkArgs {
    /// Use GETNEXT instead of GETBULK.
    #[arg(long = "getnext")]
    pub getnext: bool,

    /// GETBULK max-repetitions.
    #[arg(long = "max-rep", default_value = "10")]
    pub max_repetitions: u32,
}

/// Set-specific type specifier for values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ValueType {
    /// INTEGER (i32)
    #[value(name = "i")]
    Integer,
    /// Unsigned32/Gauge32 (u32)
    #[value(name = "u")]
    Unsigned,
    /// STRING (OctetString from UTF-8)
    #[value(name = "s")]
    String,
    /// Hex-STRING (OctetString from hex)
    #[value(name = "x")]
    HexString,
    /// OBJECT IDENTIFIER
    #[value(name = "o")]
    Oid,
    /// IpAddress
    #[value(name = "a")]
    IpAddress,
    /// TimeTicks
    #[value(name = "t")]
    TimeTicks,
    /// Counter32
    #[value(name = "c")]
    Counter32,
    /// Counter64
    #[value(name = "C")]
    Counter64,
}

impl std::str::FromStr for ValueType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "i" => Ok(ValueType::Integer),
            "u" => Ok(ValueType::Unsigned),
            "s" => Ok(ValueType::String),
            "x" => Ok(ValueType::HexString),
            "o" => Ok(ValueType::Oid),
            "a" => Ok(ValueType::IpAddress),
            "t" => Ok(ValueType::TimeTicks),
            "c" => Ok(ValueType::Counter32),
            "C" => Ok(ValueType::Counter64),
            _ => Err(format!("invalid type specifier: {}", s)),
        }
    }
}

impl ValueType {
    /// Parse a string value into an SNMP Value according to the type specifier.
    pub fn parse_value(&self, s: &str) -> Result<crate::Value, String> {
        use crate::{Oid, Value};

        match self {
            ValueType::Integer => {
                let v: i32 = s
                    .parse()
                    .map_err(|_| format!("invalid integer value: {}", s))?;
                Ok(Value::Integer(v))
            }
            ValueType::Unsigned => {
                let v: u32 = s
                    .parse()
                    .map_err(|_| format!("invalid unsigned value: {}", s))?;
                Ok(Value::Gauge32(v))
            }
            ValueType::String => Ok(Value::OctetString(s.as_bytes().to_vec().into())),
            ValueType::HexString => {
                let bytes = parse_hex_string(s)?;
                Ok(Value::OctetString(bytes.into()))
            }
            ValueType::Oid => {
                let oid = Oid::parse(s).map_err(|e| format!("invalid OID value: {}", e))?;
                Ok(Value::ObjectIdentifier(oid))
            }
            ValueType::IpAddress => {
                let parts: Vec<&str> = s.split('.').collect();
                if parts.len() != 4 {
                    return Err(format!("invalid IP address: {}", s));
                }
                let mut bytes = [0u8; 4];
                for (i, part) in parts.iter().enumerate() {
                    bytes[i] = part
                        .parse()
                        .map_err(|_| format!("invalid IP address octet: {}", part))?;
                }
                Ok(Value::IpAddress(bytes))
            }
            ValueType::TimeTicks => {
                let v: u32 = s
                    .parse()
                    .map_err(|_| format!("invalid timeticks value: {}", s))?;
                Ok(Value::TimeTicks(v))
            }
            ValueType::Counter32 => {
                let v: u32 = s
                    .parse()
                    .map_err(|_| format!("invalid counter32 value: {}", s))?;
                Ok(Value::Counter32(v))
            }
            ValueType::Counter64 => {
                let v: u64 = s
                    .parse()
                    .map_err(|_| format!("invalid counter64 value: {}", s))?;
                Ok(Value::Counter64(v))
            }
        }
    }
}

/// Parse a hex string (with or without spaces/separators) into bytes.
fn parse_hex_string(s: &str) -> Result<Vec<u8>, String> {
    // Remove common separators: spaces, colons, dashes
    let clean: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();

    if !clean.len().is_multiple_of(2) {
        return Err("hex string must have even number of digits".into());
    }

    clean
        .as_bytes()
        .chunks(2)
        .map(|chunk| {
            let hex = std::str::from_utf8(chunk).unwrap();
            u8::from_str_radix(hex, 16).map_err(|_| format!("invalid hex: {}", hex))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_target_addr_with_port() {
        let args = CommonArgs {
            target: "192.168.1.1:162".to_string(),
            snmp_version: SnmpVersion::V2c,
            community: "public".to_string(),
            timeout: 5.0,
            retries: 3,
            backoff: BackoffStrategy::None,
            backoff_delay: 100,
            backoff_max: 5000,
            backoff_jitter: 0.25,
        };
        let addr = args.target_addr().unwrap();
        assert_eq!(addr.port(), 162);
    }

    #[test]
    fn test_target_addr_default_port() {
        let args = CommonArgs {
            target: "192.168.1.1".to_string(),
            snmp_version: SnmpVersion::V2c,
            community: "public".to_string(),
            timeout: 5.0,
            retries: 3,
            backoff: BackoffStrategy::None,
            backoff_delay: 100,
            backoff_max: 5000,
            backoff_jitter: 0.25,
        };
        let addr = args.target_addr().unwrap();
        assert_eq!(addr.port(), 161);
    }

    #[test]
    fn test_retry_config_none() {
        let args = CommonArgs {
            target: "192.168.1.1".to_string(),
            snmp_version: SnmpVersion::V2c,
            community: "public".to_string(),
            timeout: 5.0,
            retries: 3,
            backoff: BackoffStrategy::None,
            backoff_delay: 100,
            backoff_max: 5000,
            backoff_jitter: 0.25,
        };
        let retry = args.retry_config();
        assert_eq!(retry.max_attempts, 3);
        assert!(matches!(retry.backoff, Backoff::None));
    }

    #[test]
    fn test_retry_config_fixed() {
        let args = CommonArgs {
            target: "192.168.1.1".to_string(),
            snmp_version: SnmpVersion::V2c,
            community: "public".to_string(),
            timeout: 5.0,
            retries: 5,
            backoff: BackoffStrategy::Fixed,
            backoff_delay: 200,
            backoff_max: 5000,
            backoff_jitter: 0.25,
        };
        let retry = args.retry_config();
        assert_eq!(retry.max_attempts, 5);
        assert!(matches!(
            retry.backoff,
            Backoff::Fixed { delay } if delay == Duration::from_millis(200)
        ));
    }

    #[test]
    fn test_retry_config_exponential() {
        let args = CommonArgs {
            target: "192.168.1.1".to_string(),
            snmp_version: SnmpVersion::V2c,
            community: "public".to_string(),
            timeout: 5.0,
            retries: 4,
            backoff: BackoffStrategy::Exponential,
            backoff_delay: 50,
            backoff_max: 2000,
            backoff_jitter: 0.1,
        };
        let retry = args.retry_config();
        assert_eq!(retry.max_attempts, 4);
        match retry.backoff {
            Backoff::Exponential {
                initial,
                max,
                jitter,
            } => {
                assert_eq!(initial, Duration::from_millis(50));
                assert_eq!(max, Duration::from_millis(2000));
                assert!((jitter - 0.1).abs() < f64::EPSILON);
            }
            _ => panic!("expected Exponential"),
        }
    }

    #[test]
    fn test_v3_args_validation() {
        // No username - valid (not v3)
        let args = V3Args {
            username: None,
            level: None,
            auth_protocol: None,
            auth_password: None,
            priv_protocol: None,
            priv_password: None,
        };
        assert!(args.validate().is_ok());

        // Username only - valid (noAuthNoPriv)
        let args = V3Args {
            username: Some("admin".to_string()),
            level: None,
            auth_protocol: None,
            auth_password: None,
            priv_protocol: None,
            priv_password: None,
        };
        assert!(args.validate().is_ok());

        // Auth protocol without password - invalid
        let args = V3Args {
            username: Some("admin".to_string()),
            level: None,
            auth_protocol: Some(AuthProtocol::Sha256),
            auth_password: None,
            priv_protocol: None,
            priv_password: None,
        };
        assert!(args.validate().is_err());

        // Privacy without auth - invalid
        let args = V3Args {
            username: Some("admin".to_string()),
            level: None,
            auth_protocol: None,
            auth_password: None,
            priv_protocol: Some(PrivProtocol::Aes128),
            priv_password: Some("pass".to_string()),
        };
        assert!(args.validate().is_err());

        // SHA-1 with AES-256 - valid (key extension auto-applied)
        let args = V3Args {
            username: Some("admin".to_string()),
            level: None,
            auth_protocol: Some(AuthProtocol::Sha1),
            auth_password: Some("pass".to_string()),
            priv_protocol: Some(PrivProtocol::Aes256),
            priv_password: Some("pass".to_string()),
        };
        assert!(args.validate().is_ok());
    }

    #[test]
    fn test_value_type_parse_integer() {
        use crate::Value;
        let v = ValueType::Integer.parse_value("42").unwrap();
        assert!(matches!(v, Value::Integer(42)));

        let v = ValueType::Integer.parse_value("-100").unwrap();
        assert!(matches!(v, Value::Integer(-100)));

        assert!(ValueType::Integer.parse_value("not_a_number").is_err());
    }

    #[test]
    fn test_value_type_parse_unsigned() {
        use crate::Value;
        let v = ValueType::Unsigned.parse_value("42").unwrap();
        assert!(matches!(v, Value::Gauge32(42)));

        assert!(ValueType::Unsigned.parse_value("-1").is_err());
    }

    #[test]
    fn test_value_type_parse_string() {
        use crate::Value;
        let v = ValueType::String.parse_value("hello world").unwrap();
        if let Value::OctetString(bytes) = v {
            assert_eq!(&*bytes, b"hello world");
        } else {
            panic!("expected OctetString");
        }
    }

    #[test]
    fn test_value_type_parse_hex_string() {
        use crate::Value;

        // Plain hex
        let v = ValueType::HexString.parse_value("001a2b").unwrap();
        if let Value::OctetString(bytes) = v {
            assert_eq!(&*bytes, &[0x00, 0x1a, 0x2b]);
        } else {
            panic!("expected OctetString");
        }

        // With spaces
        let v = ValueType::HexString.parse_value("00 1A 2B").unwrap();
        if let Value::OctetString(bytes) = v {
            assert_eq!(&*bytes, &[0x00, 0x1a, 0x2b]);
        } else {
            panic!("expected OctetString");
        }

        // Odd number of digits
        assert!(ValueType::HexString.parse_value("001").is_err());
    }

    #[test]
    fn test_value_type_parse_ip_address() {
        use crate::Value;
        let v = ValueType::IpAddress.parse_value("192.168.1.1").unwrap();
        assert!(matches!(v, Value::IpAddress([192, 168, 1, 1])));

        assert!(ValueType::IpAddress.parse_value("192.168.1").is_err());
        assert!(ValueType::IpAddress.parse_value("256.1.1.1").is_err());
    }

    #[test]
    fn test_value_type_parse_timeticks() {
        use crate::Value;
        let v = ValueType::TimeTicks.parse_value("12345678").unwrap();
        assert!(matches!(v, Value::TimeTicks(12345678)));
    }

    #[test]
    fn test_value_type_parse_counters() {
        use crate::Value;

        let v = ValueType::Counter32.parse_value("4294967295").unwrap();
        assert!(matches!(v, Value::Counter32(4294967295)));

        let v = ValueType::Counter64
            .parse_value("18446744073709551615")
            .unwrap();
        assert!(matches!(v, Value::Counter64(18446744073709551615)));
    }
}
