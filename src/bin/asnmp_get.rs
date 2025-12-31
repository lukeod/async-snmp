//! asnmp-get: Retrieve SNMP OID values.
//!
//! Part of the async-snmp CLI utilities.

use async_snmp::cli::args::{CommonArgs, OutputArgs, SnmpVersion, V3Args};
use async_snmp::cli::hints::parse_oid;
use async_snmp::cli::output::{
    OperationType, OutputContext, RequestInfo, SecurityInfo, write_error, write_verbose_request,
    write_verbose_response,
};
use async_snmp::{Client, Oid};
use clap::Parser;
use std::process::ExitCode;
use std::time::Instant;

/// Retrieve one or more SNMP OID values.
#[derive(Debug, Parser)]
#[command(name = "asnmp-get", version, about)]
struct Args {
    #[command(flatten)]
    common: CommonArgs,

    #[command(flatten)]
    v3: V3Args,

    #[command(flatten)]
    output: OutputArgs,

    /// OIDs to retrieve (dotted notation or well-known names).
    #[arg(required = true, value_name = "OID")]
    oids: Vec<String>,
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

    // Parse OIDs
    let oids: Vec<Oid> = match args.oids.iter().map(|s| parse_oid(s)).collect() {
        Ok(oids) => oids,
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

        let request_info = RequestInfo {
            target,
            version: version.into(),
            security,
            operation: OperationType::Get,
            oids: oids.clone(),
        };
        write_verbose_request(&request_info);
    }

    // Build and run the client
    let start = Instant::now();
    let result = run_get(target, &args, &oids).await;
    let elapsed = start.elapsed();

    match result {
        Ok(varbinds) => {
            // Verbose output: show response summary with varbind details
            if args.output.verbose {
                write_verbose_response(&varbinds, elapsed, !args.output.no_hints);
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

            if let Err(e) = output_ctx.write_results(
                target,
                version.into(),
                &varbinds,
                timing,
                None, // retries not tracked yet
            ) {
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

async fn run_get(
    target: std::net::SocketAddr,
    args: &Args,
    oids: &[Oid],
) -> async_snmp::Result<Vec<async_snmp::VarBind>> {
    let auth = args
        .v3
        .auth(&args.common)
        .map_err(|e| async_snmp::Error::Config(e.to_string()))?;

    let client = Client::builder(target.to_string(), auth)
        .timeout(args.common.timeout_duration())
        .retries(args.common.retries)
        .connect()
        .await?;

    client.get_many(oids).await
}
