//! asnmp-walk: Walk SNMP subtrees.
//!
//! Part of the async-snmp CLI utilities.

use async_snmp::cli::args::{CommonArgs, OutputArgs, SnmpVersion, V3Args, WalkArgs};
#[cfg(feature = "mib")]
use async_snmp::cli::output::VarBindFormatter;
use async_snmp::cli::output::{
    OperationType, OutputContext, RequestInfo, build_security_info, write_error,
    write_verbose_request, write_verbose_response,
};
use async_snmp::{Client, Oid, VarBind, WalkMode};
use clap::Parser;
use std::process::ExitCode;
use std::time::Instant;

/// Walk an SNMP subtree using GETNEXT or GETBULK.
#[derive(Debug, Parser)]
#[command(name = "asnmp-walk", version, about)]
struct Args {
    #[command(flatten)]
    common: CommonArgs,

    #[command(flatten)]
    v3: V3Args,

    #[command(flatten)]
    output: OutputArgs,

    #[command(flatten)]
    walk: WalkArgs,

    #[cfg(feature = "mib")]
    #[command(flatten)]
    mib: async_snmp::cli::mib_cli::MibArgs,

    /// OID subtree to walk (dotted notation or well-known name).
    #[arg(value_name = "OID")]
    oid: String,
}

#[cfg_attr(feature = "rt-multi-thread", tokio::main)]
#[cfg_attr(
    not(feature = "rt-multi-thread"),
    tokio::main(flavor = "current_thread")
)]
async fn main() -> ExitCode {
    let args = Args::parse();

    // Initialize tracing
    args.output.init_tracing();

    // Validate V3 arguments
    if let Err(e) = args.v3.validate() {
        eprintln!("Error: {}", e);
        return ExitCode::FAILURE;
    }

    let target = &args.common.target;

    // Load MIBs if requested
    #[cfg(feature = "mib")]
    let mib = match args.mib.load().await {
        Ok(mib) => mib,
        Err(e) => {
            eprintln!("Error: {}", e);
            return ExitCode::FAILURE;
        }
    };

    // Parse OID (use MIB resolution when available)
    #[cfg(feature = "mib")]
    let oid_result = async_snmp::cli::mib_cli::resolve_oid_arg(mib.as_ref(), &args.oid);
    #[cfg(not(feature = "mib"))]
    let oid_result = async_snmp::cli::hints::parse_oid(&args.oid);
    let oid = match oid_result {
        Ok(oid) => oid,
        Err(e) => {
            eprintln!("Error: {}", e);
            return ExitCode::FAILURE;
        }
    };

    // Determine version (V3 if username provided)
    let version = args.common.effective_version(&args.v3);

    // V1 doesn't support GETBULK, force GETNEXT
    let use_getnext = args.walk.getnext || matches!(version, SnmpVersion::V1);

    // Verbose output: show request info before executing
    if args.output.verbose {
        let operation = if use_getnext {
            OperationType::Walk
        } else {
            OperationType::BulkWalk {
                max_repetitions: args.walk.max_repetitions as i32,
            }
        };

        let request_info = RequestInfo {
            target: target.as_str(),
            version: version.into(),
            security: build_security_info(&args.v3, &args.common),
            operation,
            oids: vec![oid.clone()],
        };
        write_verbose_request(&request_info);
    }

    // Build and run the walk
    let start = Instant::now();
    let result = run_walk(target.as_str(), &args, oid, use_getnext).await;
    let elapsed = start.elapsed();

    match result {
        Ok(varbinds) => {
            // Verbose output: show response summary with varbind details
            if args.output.verbose {
                write_verbose_response(&varbinds, elapsed, !args.output.no_hints);
            }

            let mut output_ctx = OutputContext::from_args(&args.output);
            #[cfg(feature = "mib")]
            if let Some(m) = &mib {
                output_ctx.formatter = Some(m as &dyn VarBindFormatter);
            }

            if let Err(e) = output_ctx.write_results(
                target.as_str(),
                version.into(),
                &varbinds,
                args.output.elapsed(elapsed),
                None,
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

async fn run_walk(
    target: &str,
    args: &Args,
    oid: Oid,
    use_getnext: bool,
) -> async_snmp::Result<Vec<VarBind>> {
    let auth = args
        .v3
        .auth(&args.common)
        .map_err(|e| async_snmp::Error::Config(e.to_string().into()))?;

    // Set walk mode based on CLI flags
    let walk_mode = if use_getnext {
        WalkMode::GetNext
    } else {
        WalkMode::GetBulk
    };

    let client = Client::builder(target, auth)
        .timeout(args.common.timeout_duration())
        .retry(args.common.retry_config())
        .walk_mode(walk_mode)
        .max_repetitions(args.walk.max_repetitions)
        .connect()
        .await?;

    // Use unified walk() which respects the walk_mode setting
    client.walk(oid)?.collect().await
}
