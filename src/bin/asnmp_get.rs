//! asnmp-get: Retrieve SNMP OID values.
//!
//! Part of the async-snmp CLI utilities.

use async_snmp::cli::args::{CommonArgs, OutputArgs, V3Args};
#[cfg(feature = "mib")]
use async_snmp::cli::output::VarBindFormatter;
use async_snmp::cli::output::{
    OperationType, OutputContext, RequestInfo, build_security_info, write_error,
    write_verbose_request, write_verbose_response,
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

    #[cfg(feature = "mib")]
    #[command(flatten)]
    mib: async_snmp::cli::mib_cli::MibArgs,

    /// OIDs to retrieve (dotted notation or well-known names).
    #[arg(required = true, value_name = "OID")]
    oids: Vec<String>,
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

    // Parse OIDs (use MIB resolution when available)
    let oids: Vec<Oid> = match args
        .oids
        .iter()
        .map(|s| {
            #[cfg(feature = "mib")]
            {
                async_snmp::cli::mib_cli::resolve_oid_arg(mib.as_ref(), s)
            }
            #[cfg(not(feature = "mib"))]
            {
                async_snmp::cli::hints::parse_oid(s)
            }
        })
        .collect()
    {
        Ok(oids) => oids,
        Err(e) => {
            eprintln!("Error: {}", e);
            return ExitCode::FAILURE;
        }
    };

    // Determine version (V3 if username provided)
    let version = args.common.effective_version(&args.v3);

    // Verbose output: show request info before executing
    if args.output.verbose {
        let request_info = RequestInfo {
            target: target.as_str(),
            version: version.into(),
            security: build_security_info(&args.v3, &args.common),
            operation: OperationType::Get,
            oids: oids.clone(),
        };
        write_verbose_request(&request_info);
    }

    // Build and run the client
    let start = Instant::now();
    let result = run_get(target.as_str(), &args, &oids).await;
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
    target: &str,
    args: &Args,
    oids: &[Oid],
) -> async_snmp::Result<Vec<async_snmp::VarBind>> {
    let auth = args
        .v3
        .auth(&args.common)
        .map_err(|e| async_snmp::Error::Config(e.to_string().into()))?;

    let client = Client::builder(target, auth)
        .timeout(args.common.timeout_duration())
        .retry(args.common.retry_config())
        .connect()
        .await?;

    client.get_many(oids).await
}
