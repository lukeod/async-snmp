//! asnmp-walk: Walk SNMP subtrees.
//!
//! Part of the async-snmp CLI utilities.

use async_snmp::cli::args::{CommonArgs, OutputArgs, SnmpVersion, V3Args, WalkArgs};
use async_snmp::cli::hints::parse_oid;
use async_snmp::cli::output::{
    OperationType, OutputContext, RequestInfo, SecurityInfo, write_error, write_verbose_request,
    write_verbose_response,
};
use async_snmp::{Client, Oid, VarBind};
use clap::Parser;
use futures_core::Stream;
use std::future::poll_fn;
use std::pin::Pin;
use std::process::ExitCode;
use std::task::Context;
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

    /// OID subtree to walk (dotted notation or well-known name).
    #[arg(value_name = "OID")]
    oid: String,
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

    // Parse OID
    let oid = match parse_oid(&args.oid) {
        Ok(oid) => oid,
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

    // V1 doesn't support GETBULK, force GETNEXT
    let use_getnext = args.walk.getnext || matches!(version, SnmpVersion::V1);

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

        let operation = if use_getnext {
            OperationType::Walk
        } else {
            OperationType::BulkWalk {
                max_repetitions: args.walk.max_repetitions as i32,
            }
        };

        let request_info = RequestInfo {
            target,
            version: version.into(),
            security,
            operation,
            oids: vec![oid.clone()],
        };
        write_verbose_request(&request_info);
    }

    // Build and run the walk
    let start = Instant::now();
    let result = run_walk(target, version, &args, oid, use_getnext).await;
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

            if let Err(e) =
                output_ctx.write_results(target, version.into(), &varbinds, timing, None)
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

async fn run_walk(
    target: std::net::SocketAddr,
    version: SnmpVersion,
    args: &Args,
    oid: Oid,
    use_getnext: bool,
) -> async_snmp::Result<Vec<VarBind>> {
    let timeout = args.common.timeout_duration();
    let retries = args.common.retries;
    let max_repetitions = args.walk.max_repetitions as i32;

    match version {
        SnmpVersion::V1 => {
            let client = Client::v1(target.to_string())
                .community(args.common.community.as_bytes())
                .timeout(timeout)
                .retries(retries)
                .connect()
                .await?;

            // V1 only supports GETNEXT
            let walk = client.walk(oid);
            collect_walk(walk).await
        }
        SnmpVersion::V2c => {
            let client = Client::v2c(target.to_string())
                .community(args.common.community.as_bytes())
                .timeout(timeout)
                .retries(retries)
                .connect()
                .await?;

            if use_getnext {
                let walk = client.walk(oid);
                collect_walk(walk).await
            } else {
                let walk = client.bulk_walk(oid, max_repetitions);
                collect_walk(walk).await
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

                    if use_getnext {
                        let walk = client.walk(oid);
                        collect_walk(walk).await
                    } else {
                        let walk = client.bulk_walk(oid, max_repetitions);
                        collect_walk(walk).await
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

                    if use_getnext {
                        let walk = client.walk(oid);
                        collect_walk(walk).await
                    } else {
                        let walk = client.bulk_walk(oid, max_repetitions);
                        collect_walk(walk).await
                    }
                }
                (None, None) => {
                    // noAuthNoPriv
                    let client = Client::v3(target.to_string(), username)
                        .timeout(timeout)
                        .retries(retries)
                        .connect()
                        .await?;

                    if use_getnext {
                        let walk = client.walk(oid);
                        collect_walk(walk).await
                    } else {
                        let walk = client.bulk_walk(oid, max_repetitions);
                        collect_walk(walk).await
                    }
                }
                (None, Some(_)) => {
                    unreachable!("privacy without authentication should be caught by validation");
                }
            }
        }
    }
}

/// Collect all items from a walk stream.
async fn collect_walk<S>(walk: S) -> async_snmp::Result<Vec<VarBind>>
where
    S: Stream<Item = async_snmp::Result<VarBind>> + Unpin,
{
    let mut pinned = Box::pin(walk);
    let mut results = Vec::new();

    loop {
        let item = poll_fn(|cx: &mut Context<'_>| Pin::new(&mut pinned).poll_next(cx)).await;

        match item {
            Some(Ok(vb)) => results.push(vb),
            Some(Err(e)) => return Err(e),
            None => break,
        }
    }

    Ok(results)
}
