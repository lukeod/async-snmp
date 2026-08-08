//! Command-line argument structures for async-snmp CLI tools.
//!
//! This module provides reusable clap argument structures for the `asnmp-*` CLI tools.

use clap::{Parser, ValueEnum};
use std::time::Duration;

use crate::Version;
use crate::client::{Auth, Retry, RetryConfigError};
use crate::format::hex;
#[cfg(any(feature = "crypto-rustcrypto", feature = "crypto-fips"))]
use crate::v3::CryptoBackend;
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

fn timeout_from_secs(value: f64) -> Result<Duration, String> {
    Duration::try_from_secs_f64(value).map_err(|_| {
        "timeout must be a non-negative finite value representable as a duration".to_string()
    })
}

fn parse_timeout(value: &str) -> Result<f64, String> {
    let timeout = value
        .parse::<f64>()
        .map_err(|_| format!("invalid timeout value: {value}"))?;
    timeout_from_secs(timeout)?;
    Ok(timeout)
}

fn parse_jitter(value: &str) -> Result<f64, String> {
    let jitter = value
        .parse::<f64>()
        .map_err(|_| format!("invalid jitter value: {value}"))?;
    Retry::validate_jitter(jitter).map_err(|error| error.to_string())?;
    Ok(jitter)
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
    #[arg(
        short = 't',
        long = "timeout",
        default_value = "5",
        value_parser = parse_timeout
    )]
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
    #[arg(
        long = "backoff-jitter",
        default_value = "0.25",
        value_parser = parse_jitter
    )]
    pub backoff_jitter: f64,
}

impl CommonArgs {
    /// Get the timeout as a Duration.
    ///
    /// # Errors
    ///
    /// Returns an error when the timeout is negative, non-finite, or not
    /// representable as a [`Duration`].
    pub fn timeout_duration(&self) -> Result<Duration, String> {
        timeout_from_secs(self.timeout)
    }

    /// Build a Retry configuration from the CLI arguments.
    ///
    /// # Errors
    ///
    /// Returns an error when the jitter factor is not finite or outside
    /// `0.0..=1.0`.
    pub fn retry_config(&self) -> Result<Retry, RetryConfigError> {
        Retry::validate_jitter(self.backoff_jitter)?;
        match self.backoff {
            BackoffStrategy::None => Ok(Retry::fixed(self.retries, Duration::ZERO)),
            BackoffStrategy::Fixed => Ok(Retry::fixed(
                self.retries,
                Duration::from_millis(self.backoff_delay),
            )),
            BackoffStrategy::Exponential => Retry::exponential(self.retries)
                .initial_delay(Duration::from_millis(self.backoff_delay))
                .max_delay(Duration::from_millis(self.backoff_max))
                .jitter(self.backoff_jitter)
                .build(),
        }
    }
}

/// Cryptographic backend for CLI SNMPv3 credentials.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CryptoBackendArg {
    /// RustCrypto backend.
    #[value(name = "rustcrypto")]
    RustCrypto,
    /// AWS-LC FIPS backend.
    #[value(name = "fips")]
    AwsLcFips,
}

/// SNMPv3 security arguments.
#[derive(Debug, Parser)]
pub struct V3Args {
    /// Security name/username (implies -v 3).
    #[arg(short = 'u', long = "username")]
    pub username: Option<String>,

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

    /// Cryptographic backend for authentication and privacy.
    #[arg(long = "crypto-backend")]
    pub crypto_backend: Option<CryptoBackendArg>,
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
        self.validate()?;
        if let Some(ref username) = self.username {
            if self.auth_protocol.is_none() && self.auth_password.is_some() {
                return Err("authentication protocol required when using auth password".into());
            }
            if self.priv_protocol.is_none() && self.priv_password.is_some() {
                return Err("privacy protocol required when using priv password".into());
            }

            let config = match (
                self.auth_protocol,
                self.auth_password.as_deref(),
                self.priv_protocol,
                self.priv_password.as_deref(),
            ) {
                (None, _, None, _) => Auth::usm(username),
                (Some(auth_protocol), Some(auth_password), None, _) => {
                    Auth::usm(username).auth(auth_protocol, auth_password)
                }
                (
                    Some(auth_protocol),
                    Some(auth_password),
                    Some(priv_protocol),
                    Some(priv_password),
                ) => Auth::usm(username).auth_priv(
                    auth_protocol,
                    auth_password,
                    priv_protocol,
                    priv_password,
                ),
                (None, _, Some(_), _) => {
                    return Err("authentication protocol required when using privacy".into());
                }
                (Some(_), None, _, _) => return Err("auth password required".into()),
                (Some(_), Some(_), Some(_), None) => {
                    return Err("priv password required".into());
                }
            };
            let config = self.select_crypto_backend(config)?;
            Ok(config.into())
        } else {
            if matches!(common.snmp_version, SnmpVersion::V3) {
                return Err("username (-u) required when using SNMPv3 (-v 3)".into());
            }
            let community = common.community.clone();
            Ok(match common.snmp_version {
                SnmpVersion::V1 => Auth::v1(community),
                SnmpVersion::V2c => Auth::v2c(community),
                SnmpVersion::V3 => unreachable!("V3 without a username was rejected"),
            })
        }
    }

    fn select_crypto_backend(
        &self,
        config: crate::v3::UsmConfig,
    ) -> Result<crate::v3::UsmConfig, String> {
        match self.crypto_backend {
            None => Ok(config),
            Some(CryptoBackendArg::RustCrypto) => {
                #[cfg(feature = "crypto-rustcrypto")]
                {
                    Ok(config.with_crypto_backend(CryptoBackend::RustCrypto))
                }
                #[cfg(not(feature = "crypto-rustcrypto"))]
                {
                    let _ = config;
                    Err("RustCrypto backend selected but the crypto-rustcrypto feature is not enabled".into())
                }
            }
            Some(CryptoBackendArg::AwsLcFips) => {
                #[cfg(feature = "crypto-fips")]
                {
                    Ok(config.with_crypto_backend(CryptoBackend::AwsLcFips))
                }
                #[cfg(not(feature = "crypto-fips"))]
                {
                    let _ = config;
                    Err("FIPS backend selected but the crypto-fips feature is not enabled".into())
                }
            }
        }
    }

    /// Validate V3 arguments and return an error message if invalid.
    pub fn validate(&self) -> Result<(), String> {
        if self.username.is_none()
            && (self.auth_protocol.is_some()
                || self.auth_password.is_some()
                || self.priv_protocol.is_some()
                || self.priv_password.is_some()
                || self.crypto_backend.is_some())
        {
            return Err("username (-u) required when using SNMPv3 security options".into());
        }

        if let Some(ref _username) = self.username {
            if self.auth_protocol.is_none() && self.auth_password.is_some() {
                return Err(
                    "authentication protocol (-a) required when using auth password".into(),
                );
            }

            if self.priv_protocol.is_none() && self.priv_password.is_some() {
                return Err("privacy protocol (-x) required when using priv password".into());
            }

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

        if matches!(self.crypto_backend, Some(CryptoBackendArg::RustCrypto))
            && !cfg!(feature = "crypto-rustcrypto")
        {
            return Err(
                "RustCrypto backend selected but the crypto-rustcrypto feature is not enabled"
                    .into(),
            );
        }
        if matches!(self.crypto_backend, Some(CryptoBackendArg::AwsLcFips))
            && !cfg!(feature = "crypto-fips")
        {
            return Err("FIPS backend selected but the crypto-fips feature is not enabled".into());
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
    /// Return elapsed as Some if timing output is enabled, None otherwise.
    pub fn elapsed(&self, elapsed: Duration) -> Option<Duration> {
        if self.timing { Some(elapsed) } else { None }
    }

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
                let bytes = hex::decode_relaxed(s).map_err(|error| match error {
                    hex::DecodeError::OddLength => {
                        "hex string must have even number of hex digits".to_string()
                    }
                    hex::DecodeError::InvalidChar => {
                        "hex string contains invalid character".to_string()
                    }
                })?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Parser)]
    struct TestCliArgs {
        #[command(flatten)]
        common: CommonArgs,
        #[command(flatten)]
        v3: V3Args,
    }

    fn common_args() -> CommonArgs {
        CommonArgs {
            target: "192.168.1.1".to_string(),
            snmp_version: SnmpVersion::V3,
            community: "public".to_string(),
            timeout: 5.0,
            retries: 3,
            backoff: BackoffStrategy::None,
            backoff_delay: 100,
            backoff_max: 5000,
            backoff_jitter: 0.25,
        }
    }

    fn assert_value_validation_error(arguments: &[&str]) {
        let error = CommonArgs::try_parse_from(arguments).unwrap_err();
        assert_eq!(error.exit_code(), 2);
        assert_eq!(error.kind(), clap::error::ErrorKind::ValueValidation);
    }

    #[test]
    fn test_timeout_parser_rejects_invalid_values() {
        for timeout in ["-1", "NaN", "inf", "1.7976931348623157e308"] {
            assert_value_validation_error(&["test", "127.0.0.1", &format!("--timeout={timeout}")]);
        }
    }

    #[test]
    fn test_timeout_parser_accepts_representable_values() {
        for timeout in ["0", "5.25"] {
            let args =
                CommonArgs::try_parse_from(["test", "127.0.0.1", &format!("--timeout={timeout}")])
                    .unwrap();
            assert_eq!(args.timeout, timeout.parse::<f64>().unwrap());
            assert!(args.timeout_duration().is_ok());
        }
    }

    #[test]
    fn test_jitter_parser_rejects_invalid_values() {
        for jitter in ["-0.1", "1.1", "NaN", "inf", "-inf"] {
            assert_value_validation_error(&[
                "test",
                "127.0.0.1",
                &format!("--backoff-jitter={jitter}"),
            ]);
        }
    }

    #[test]
    fn test_jitter_parser_accepts_endpoints() {
        for jitter in ["0", "1"] {
            let args = CommonArgs::try_parse_from([
                "test",
                "127.0.0.1",
                &format!("--backoff-jitter={jitter}"),
            ])
            .unwrap();
            assert_eq!(args.backoff_jitter, jitter.parse::<f64>().unwrap());
            assert!(args.retry_config().is_ok());
        }
    }

    #[test]
    fn test_direct_common_args_conversion_rejects_invalid_floats() {
        let mut args = common_args();
        args.timeout = f64::NAN;
        assert!(args.timeout_duration().is_err());

        args.timeout = 5.0;
        args.backoff_jitter = f64::INFINITY;
        assert!(matches!(
            args.retry_config(),
            Err(RetryConfigError::InvalidJitter(value)) if value.is_infinite()
        ));
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
        let retry = args.retry_config().unwrap();
        assert_eq!(retry.max_attempts(), 3);
        assert_eq!(retry.compute_delay(0), Duration::ZERO);
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
        let retry = args.retry_config().unwrap();
        assert_eq!(retry.max_attempts(), 5);
        assert_eq!(retry.compute_delay(0), Duration::from_millis(200));
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
            backoff_jitter: 0.0,
        };
        let retry = args.retry_config().unwrap();
        assert_eq!(retry.max_attempts(), 4);
        assert_eq!(retry.compute_delay(0), Duration::from_millis(50));
        assert_eq!(retry.compute_delay(10), Duration::from_millis(2000));
    }

    #[test]
    fn cli_parser_constructs_community_and_noauth_v3() {
        let community =
            TestCliArgs::try_parse_from(["test", "-v", "1", "-c", "private", "127.0.0.1"]).unwrap();
        let auth = community.v3.auth(&community.common).unwrap();
        assert!(matches!(
            auth,
            Auth::Community {
                version: crate::CommunityVersion::V1,
                ref community,
            } if community.as_ref() == b"private"
        ));

        let no_auth = TestCliArgs::try_parse_from(["test", "-u", "readonly", "127.0.0.1"]).unwrap();
        let Auth::Usm(config) = no_auth.v3.auth(&no_auth.common).unwrap() else {
            panic!("expected USM config");
        };
        assert_eq!(config.security_level(), crate::SecurityLevel::NoAuthNoPriv);
        assert_eq!(config.username().as_ref(), b"readonly");
    }

    #[cfg(not(any(feature = "crypto-rustcrypto", feature = "crypto-fips")))]
    #[tokio::test]
    async fn cli_password_credentials_reach_backend_validation_without_crypto() {
        let parsed = TestCliArgs::try_parse_from([
            "test",
            "-u",
            "operator",
            "-a",
            "SHA-256",
            "-A",
            "authpassword",
            "127.0.0.1",
        ])
        .unwrap();
        let auth = parsed.v3.auth(&parsed.common).unwrap();
        let error = match crate::Client::builder("127.0.0.1", auth).connect().await {
            Ok(_) => panic!("password credentials unexpectedly passed validation"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("no crypto backend is enabled"));
    }

    #[test]
    fn cli_parser_rejects_explicit_v3_without_username() {
        let parsed = TestCliArgs::try_parse_from(["test", "-v", "3", "127.0.0.1"]).unwrap();
        assert_eq!(
            parsed.v3.auth(&parsed.common).unwrap_err(),
            "username (-u) required when using SNMPv3 (-v 3)"
        );
    }

    #[test]
    fn test_v3_args_validation() {
        // No username - valid (not v3)
        let args = V3Args {
            username: None,
            auth_protocol: None,
            auth_password: None,
            priv_protocol: None,
            priv_password: None,
            crypto_backend: None,
        };
        assert!(args.validate().is_ok());

        // Username only - valid (noAuthNoPriv)
        let args = V3Args {
            username: Some("admin".to_string()),
            auth_protocol: None,
            auth_password: None,
            priv_protocol: None,
            priv_password: None,
            crypto_backend: None,
        };
        assert!(args.validate().is_ok());

        // Auth password without protocol - invalid
        let args = V3Args {
            username: Some("admin".to_string()),
            auth_protocol: None,
            auth_password: Some("pass".to_string()),
            priv_protocol: None,
            priv_password: None,
            crypto_backend: None,
        };
        assert!(args.validate().is_err());
        assert!(args.auth(&common_args()).is_err());

        // Auth protocol without password - invalid
        let args = V3Args {
            username: Some("admin".to_string()),
            auth_protocol: Some(AuthProtocol::Sha256),
            auth_password: None,
            priv_protocol: None,
            priv_password: None,
            crypto_backend: None,
        };
        assert!(args.validate().is_err());
        assert!(args.auth(&common_args()).is_err());

        // Privacy password without protocol - invalid
        let args = V3Args {
            username: Some("admin".to_string()),
            auth_protocol: Some(AuthProtocol::Sha256),
            auth_password: Some("authpass".to_string()),
            priv_protocol: None,
            priv_password: Some("privpass".to_string()),
            crypto_backend: None,
        };
        assert!(args.validate().is_err());
        assert!(args.auth(&common_args()).is_err());

        // Privacy protocol without password - invalid
        let args = V3Args {
            username: Some("admin".to_string()),
            auth_protocol: Some(AuthProtocol::Sha256),
            auth_password: Some("authpass".to_string()),
            priv_protocol: Some(PrivProtocol::Aes128),
            priv_password: None,
            crypto_backend: None,
        };
        assert!(args.validate().is_err());
        assert!(args.auth(&common_args()).is_err());

        // Privacy without auth - invalid
        let args = V3Args {
            username: Some("admin".to_string()),
            auth_protocol: None,
            auth_password: None,
            priv_protocol: Some(PrivProtocol::Aes128),
            priv_password: Some("pass".to_string()),
            crypto_backend: None,
        };
        assert!(args.validate().is_err());
        assert!(args.auth(&common_args()).is_err());

        // SHA-1 with AES-256 - valid (key extension auto-applied)
        let args = V3Args {
            username: Some("admin".to_string()),
            auth_protocol: Some(AuthProtocol::Sha1),
            auth_password: Some("pass".to_string()),
            priv_protocol: Some(PrivProtocol::Aes256),
            priv_password: Some("pass".to_string()),
            crypto_backend: None,
        };
        assert!(args.validate().is_ok());
    }

    #[test]
    fn explicit_v3_without_username_is_rejected() {
        let args = V3Args {
            username: None,
            auth_protocol: None,
            auth_password: None,
            priv_protocol: None,
            priv_password: None,
            crypto_backend: None,
        };

        assert_eq!(
            args.auth(&common_args()).unwrap_err(),
            "username (-u) required when using SNMPv3 (-v 3)"
        );
    }

    #[test]
    fn security_options_without_username_are_rejected() {
        let args = V3Args {
            username: None,
            auth_protocol: Some(AuthProtocol::Sha256),
            auth_password: Some("authpassword".to_string()),
            priv_protocol: None,
            priv_password: None,
            crypto_backend: None,
        };

        assert_eq!(
            args.validate().unwrap_err(),
            "username (-u) required when using SNMPv3 security options"
        );
    }

    #[cfg(feature = "crypto-rustcrypto")]
    #[test]
    fn rustcrypto_backend_can_be_selected_when_available() {
        let args = V3Args {
            username: Some("user".to_string()),
            auth_protocol: Some(AuthProtocol::Sha256),
            auth_password: Some("authpassword".to_string()),
            priv_protocol: None,
            priv_password: None,
            crypto_backend: Some(CryptoBackendArg::RustCrypto),
        };
        let Auth::Usm(config) = args.auth(&common_args()).unwrap() else {
            panic!("expected USM config");
        };
        assert_eq!(config.crypto_backend(), CryptoBackend::RustCrypto);
    }

    #[cfg(feature = "crypto-fips")]
    #[test]
    fn fips_backend_can_be_selected_when_available() {
        let args = V3Args {
            username: Some("user".to_string()),
            auth_protocol: Some(AuthProtocol::Sha256),
            auth_password: Some("authpassword".to_string()),
            priv_protocol: None,
            priv_password: None,
            crypto_backend: Some(CryptoBackendArg::AwsLcFips),
        };
        let Auth::Usm(config) = args.auth(&common_args()).unwrap() else {
            panic!("expected USM config");
        };
        assert_eq!(config.crypto_backend(), CryptoBackend::AwsLcFips);
    }

    #[cfg(not(feature = "crypto-rustcrypto"))]
    #[test]
    fn unavailable_rustcrypto_backend_is_rejected() {
        let args = V3Args {
            username: Some("user".to_string()),
            auth_protocol: None,
            auth_password: None,
            priv_protocol: None,
            priv_password: None,
            crypto_backend: Some(CryptoBackendArg::RustCrypto),
        };
        assert!(args.validate().unwrap_err().contains("crypto-rustcrypto"));
    }

    #[cfg(not(feature = "crypto-fips"))]
    #[test]
    fn unavailable_fips_backend_is_rejected() {
        let args = V3Args {
            username: Some("user".to_string()),
            auth_protocol: None,
            auth_password: None,
            priv_protocol: None,
            priv_password: None,
            crypto_backend: Some(CryptoBackendArg::AwsLcFips),
        };
        assert!(args.validate().unwrap_err().contains("crypto-fips"));
    }

    #[test]
    fn test_v3_args_auth_constructs_valid_security_levels() {
        let no_auth = V3Args {
            username: Some("user".to_string()),
            auth_protocol: None,
            auth_password: None,
            priv_protocol: None,
            priv_password: None,
            crypto_backend: None,
        }
        .auth(&common_args())
        .unwrap();
        let Auth::Usm(no_auth) = no_auth else {
            panic!("expected USM config");
        };
        assert_eq!(no_auth.auth_protocol(), None);
        assert_eq!(no_auth.priv_protocol(), None);

        let auth = V3Args {
            username: Some("user".to_string()),
            auth_protocol: Some(AuthProtocol::Sha256),
            auth_password: Some("authpass".to_string()),
            priv_protocol: None,
            priv_password: None,
            crypto_backend: None,
        }
        .auth(&common_args())
        .unwrap();
        let Auth::Usm(auth) = auth else {
            panic!("expected USM config");
        };
        assert_eq!(auth.auth_protocol(), Some(AuthProtocol::Sha256));
        assert_eq!(auth.priv_protocol(), None);

        let auth_priv = V3Args {
            username: Some("user".to_string()),
            auth_protocol: Some(AuthProtocol::Sha1),
            auth_password: Some("authpass".to_string()),
            priv_protocol: Some(PrivProtocol::Aes128),
            priv_password: Some("privpass".to_string()),
            crypto_backend: None,
        }
        .auth(&common_args())
        .unwrap();
        let Auth::Usm(auth_priv) = auth_priv else {
            panic!("expected USM config");
        };
        assert_eq!(auth_priv.auth_protocol(), Some(AuthProtocol::Sha1));
        assert_eq!(auth_priv.priv_protocol(), Some(PrivProtocol::Aes128));
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

        assert_eq!(
            ValueType::HexString.parse_value("00.gg").unwrap_err(),
            "hex string contains invalid character"
        );
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
