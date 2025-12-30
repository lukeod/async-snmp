//! asnmp-set: Set SNMP OID values.
//!
//! Part of the async-snmp CLI utilities.

use async_snmp::cli::args::{CommonArgs, OutputArgs, SnmpVersion, V3Args, ValueType};
use async_snmp::cli::hints::parse_oid;
use async_snmp::cli::output::{
    OperationType, OutputContext, RequestInfo, SecurityInfo, write_error, write_verbose_request,
    write_verbose_response,
};
use async_snmp::{Client, Oid, Value, VarBind};
use clap::Parser;
use std::process::ExitCode;
use std::time::Instant;

/// Set one or more SNMP OID values.
///
/// Type specifiers:
///   i = INTEGER
///   u = Unsigned32 (Gauge32)
///   s = STRING (OctetString)
///   x = Hex-STRING (OctetString from hex)
///   o = OBJECT IDENTIFIER
///   a = IpAddress
///   t = TimeTicks
///   c = Counter32
///   C = Counter64
#[derive(Debug, Parser)]
#[command(name = "asnmp-set", version, about, verbatim_doc_comment)]
struct Args {
    #[command(flatten)]
    common: CommonArgs,

    #[command(flatten)]
    v3: V3Args,

    #[command(flatten)]
    output: OutputArgs,

    /// OID TYPE VALUE triplets (e.g., sysContact.0 s "admin@example.com").
    /// Can specify multiple triplets for atomic SET of multiple values.
    #[arg(required = true, value_name = "OID TYPE VALUE", num_args = 3..)]
    varbinds: Vec<String>,
}

/// Parsed SET varbind.
struct SetVarbind {
    oid: Oid,
    value: Value,
}

fn parse_varbinds(args: &[String]) -> Result<Vec<SetVarbind>, String> {
    if args.len() % 3 != 0 {
        return Err("arguments must be OID TYPE VALUE triplets".into());
    }

    let mut varbinds = Vec::new();

    for chunk in args.chunks(3) {
        let oid_str = &chunk[0];
        let type_str = &chunk[1];
        let value_str = &chunk[2];

        // Parse OID
        let oid = parse_oid(oid_str)?;

        // Parse type specifier
        let value_type: ValueType = type_str.parse().map_err(|_| {
            format!(
                "invalid type specifier '{}'; use i, u, s, x, o, a, t, c, or C",
                type_str
            )
        })?;

        // Parse value
        let value = value_type.parse_value(value_str)?;

        varbinds.push(SetVarbind { oid, value });
    }

    Ok(varbinds)
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();

    // Initialize tracing
    args.output.init_tracing();

    // Validate V3 arguments
    if let Err(e) = args.v3.validate() {
        eprintln!("Error: {}", e);
        return ExitCode::FAILURE;
    }

    // Parse target address
    let target = match args.common.target_addr() {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("Error: {}", e);
            return ExitCode::FAILURE;
        }
    };

    // Parse varbinds
    let varbinds = match parse_varbinds(&args.varbinds) {
        Ok(vb) => vb,
        Err(e) => {
            eprintln!("Error: {}", e);
            return ExitCode::FAILURE;
        }
    };

    // Determine version (V3 if username provided)
    let version = if args.v3.is_v3() {
        SnmpVersion::V3
    } else {
        args.common.snmp_version
    };

    // Verbose output: show request info before executing
    if args.output.verbose {
        let security = if args.v3.is_v3() {
            SecurityInfo::V3 {
                username: args.v3.username.clone().unwrap_or_default(),
                auth_protocol: args.v3.auth_protocol.map(|p| format!("{}", p)),
                priv_protocol: args.v3.priv_protocol.map(|p| format!("{}", p)),
            }
        } else {
            SecurityInfo::Community(args.common.community.clone())
        };

        let oids: Vec<_> = varbinds.iter().map(|vb| vb.oid.clone()).collect();

        let request_info = RequestInfo {
            target,
            version: version.into(),
            security,
            operation: OperationType::Set,
            oids,
        };
        write_verbose_request(&request_info);
    }

    // Build and run the SET request
    let start = Instant::now();
    let result = run_set(target, version, &args, varbinds).await;
    let elapsed = start.elapsed();

    match result {
        Ok(result_varbinds) => {
            // Verbose output: show response summary with varbind details
            if args.output.verbose {
                write_verbose_response(&result_varbinds, elapsed, !args.output.no_hints);
            }
            let output_ctx = OutputContext {
                format: args.output.format,
                show_hints: !args.output.no_hints,
                force_hex: args.output.hex,
                show_timing: args.output.timing,
            };

            let timing = if args.output.timing {
                Some(elapsed)
            } else {
                None
            };

            if let Err(e) =
                output_ctx.write_results(target, version.into(), &result_varbinds, timing, None)
            {
                eprintln!("Error writing output: {}", e);
                return ExitCode::FAILURE;
            }

            ExitCode::SUCCESS
        }
        Err(e) => {
            write_error(&e);
            ExitCode::FAILURE
        }
    }
}

async fn run_set(
    target: std::net::SocketAddr,
    version: SnmpVersion,
    args: &Args,
    varbinds: Vec<SetVarbind>,
) -> async_snmp::Result<Vec<VarBind>> {
    let timeout = args.common.timeout_duration();
    let retries = args.common.retries;

    // Convert to (Oid, Value) pairs
    let pairs: Vec<(Oid, Value)> = varbinds.into_iter().map(|vb| (vb.oid, vb.value)).collect();

    match version {
        SnmpVersion::V1 => {
            let client = Client::v1(target.to_string())
                .community(args.common.community.as_bytes())
                .timeout(timeout)
                .retries(retries)
                .connect()
                .await?;

            if pairs.len() == 1 {
                let (oid, value) = pairs.into_iter().next().unwrap();
                client.set(&oid, value).await.map(|vb| vec![vb])
            } else {
                client.set_many(&pairs).await
            }
        }
        SnmpVersion::V2c => {
            let client = Client::v2c(target.to_string())
                .community(args.common.community.as_bytes())
                .timeout(timeout)
                .retries(retries)
                .connect()
                .await?;

            if pairs.len() == 1 {
                let (oid, value) = pairs.into_iter().next().unwrap();
                client.set(&oid, value).await.map(|vb| vec![vb])
            } else {
                client.set_many(&pairs).await
            }
        }
        SnmpVersion::V3 => {
            let username = args.v3.username.clone().expect("username required for v3");

            match (&args.v3.auth_protocol, &args.v3.priv_protocol) {
                (Some(auth), Some(priv_proto)) => {
                    // authPriv
                    let auth_pass = args.v3.auth_password.clone().expect("auth password");
                    let priv_pass = args.v3.priv_password.clone().expect("priv password");

                    let client = Client::v3(target.to_string(), username)
                        .auth(*auth, auth_pass)
                        .privacy(*priv_proto, priv_pass)
                        .timeout(timeout)
                        .retries(retries)
                        .connect()
                        .await?;

                    if pairs.len() == 1 {
                        let (oid, value) = pairs.into_iter().next().unwrap();
                        client.set(&oid, value).await.map(|vb| vec![vb])
                    } else {
                        client.set_many(&pairs).await
                    }
                }
                (Some(auth), None) => {
                    // authNoPriv
                    let auth_pass = args.v3.auth_password.clone().expect("auth password");

                    let client = Client::v3(target.to_string(), username)
                        .auth(*auth, auth_pass)
                        .timeout(timeout)
                        .retries(retries)
                        .connect()
                        .await?;

                    if pairs.len() == 1 {
                        let (oid, value) = pairs.into_iter().next().unwrap();
                        client.set(&oid, value).await.map(|vb| vec![vb])
                    } else {
                        client.set_many(&pairs).await
                    }
                }
                (None, None) => {
                    // noAuthNoPriv
                    let client = Client::v3(target.to_string(), username)
                        .timeout(timeout)
                        .retries(retries)
                        .connect()
                        .await?;

                    if pairs.len() == 1 {
                        let (oid, value) = pairs.into_iter().next().unwrap();
                        client.set(&oid, value).await.map(|vb| vec![vb])
                    } else {
                        client.set_many(&pairs).await
                    }
                }
                (None, Some(_)) => {
                    unreachable!("privacy without authentication should be caught by validation");
                }
            }
        }
    }
}
