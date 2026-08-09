//! asnmp-set: Set SNMP OID values.
//!
//! Part of the async-snmp CLI utilities.

use async_snmp::cli::args::{CommonArgs, OutputArgs, V3Args, ValueType};
#[cfg(feature = "mib")]
use async_snmp::cli::output::VarBindFormatter;
use async_snmp::cli::output::{
    OperationType, OutputContext, RequestInfo, build_security_info, write_error,
    write_verbose_request, write_verbose_response,
};
use async_snmp::client::DEFAULT_MAX_OIDS_PER_REQUEST;
use async_snmp::{Auth, Client, Oid, Value};
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

    #[cfg(feature = "mib")]
    #[command(flatten)]
    mib: async_snmp::cli::mib_cli::MibArgs,

    /// OID TYPE VALUE triplets (e.g., sysContact.0 s "admin@example.com").
    /// Up to 10 triplets can be sent in one atomic SET request.
    #[arg(required = true, value_name = "OID TYPE VALUE", num_args = 3..)]
    varbinds: Vec<String>,
}

/// Parsed SET varbind.
#[derive(Debug)]
struct SetVarbind {
    oid: Oid,
    value: Value,
}

fn parse_varbinds(
    args: &[String],
    resolve_oid: impl Fn(&str) -> Result<Oid, String>,
) -> Result<Vec<SetVarbind>, String> {
    if !args.len().is_multiple_of(3) {
        return Err("arguments must be OID TYPE VALUE triplets".into());
    }

    let count = args.len() / 3;
    if count > DEFAULT_MAX_OIDS_PER_REQUEST {
        return Err(format!(
            "atomic SET accepts at most {DEFAULT_MAX_OIDS_PER_REQUEST} varbinds (got {count})"
        ));
    }

    let mut varbinds = Vec::new();

    for chunk in args.chunks(3) {
        let oid_str = &chunk[0];
        let type_str = &chunk[1];
        let value_str = &chunk[2];

        let oid = resolve_oid(oid_str)?;

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
    let auth = match args.v3.auth(&args.common) {
        Ok(auth) => auth,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let version = auth.version();

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

    // Parse varbinds
    let varbinds = match parse_varbinds(&args.varbinds, |s| {
        #[cfg(feature = "mib")]
        {
            async_snmp::cli::mib_cli::resolve_oid_arg(mib.as_ref(), s)
        }
        #[cfg(not(feature = "mib"))]
        {
            async_snmp::cli::hints::parse_oid(s)
        }
    }) {
        Ok(vb) => vb,
        Err(e) => {
            eprintln!("Error: {}", e);
            return ExitCode::FAILURE;
        }
    };

    // Verbose output: show request info before executing
    if args.output.verbose {
        let oids: Vec<_> = varbinds.iter().map(|vb| vb.oid.clone()).collect();

        let request_info = RequestInfo {
            target: target.as_str(),
            version,
            security: build_security_info(&auth),
            operation: OperationType::Set,
            oids,
        };
        write_verbose_request(&request_info);
    }

    // Build and run the SET request
    let start = Instant::now();
    let result = run_set(target.as_str(), &args, auth, varbinds).await;
    let elapsed = start.elapsed();

    match result {
        Ok(response) => {
            for anomaly in &response.anomalies {
                eprintln!("Response shape anomaly: {anomaly:?}");
            }
            let result_varbinds = response.varbinds;
            // Verbose output: show response summary with varbind details
            if args.output.verbose {
                write_verbose_response(
                    &result_varbinds,
                    elapsed,
                    !args.output.no_hints,
                    args.output.hex,
                );
            }

            let output_ctx = OutputContext::from_args(&args.output);
            #[cfg(feature = "mib")]
            let output_ctx = {
                let mut output_ctx = output_ctx;
                if let Some(m) = &mib {
                    output_ctx.formatter = Some(m as &dyn VarBindFormatter);
                }
                output_ctx
            };

            if let Err(e) = output_ctx.write_results(
                target.as_str(),
                version,
                &result_varbinds,
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

async fn run_set(
    target: &str,
    args: &Args,
    auth: Auth,
    varbinds: Vec<SetVarbind>,
) -> async_snmp::Result<async_snmp::FixedCardinalityResponse> {
    let timeout = args
        .common
        .timeout_duration()
        .map_err(|error| async_snmp::Error::Config(error.into()))?;
    let retry = args
        .common
        .retry_config()
        .map_err(|error| async_snmp::Error::Config(error.to_string().into()))?;

    let client = Client::builder(target, auth)
        .request_timeout(timeout)
        .retry(retry)
        .connect()
        .await?;

    // Convert to (Oid, Value) pairs
    let pairs: Vec<(Oid, Value)> = varbinds.into_iter().map(|vb| (vb.oid, vb.value)).collect();

    if pairs.len() == 1 {
        let (oid, value) = pairs.into_iter().next().unwrap();
        client.set(&oid, value).await
    } else {
        client.set_many(&pairs).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[String]) -> Result<Vec<SetVarbind>, String> {
        parse_varbinds(args, |value| {
            value.parse::<Oid>().map_err(|e| e.to_string())
        })
    }

    #[test]
    fn parse_accepts_ten_complete_atomic_triplets() {
        let mut args = Vec::new();
        for _ in 0..DEFAULT_MAX_OIDS_PER_REQUEST {
            args.extend(["1.3.6.1".to_owned(), "i".to_owned(), "1".to_owned()]);
        }

        assert_eq!(parse(&args).unwrap().len(), DEFAULT_MAX_OIDS_PER_REQUEST);
    }

    #[test]
    fn parse_rejects_more_than_atomic_request_limit() {
        let mut args = Vec::new();
        for _ in 0..=DEFAULT_MAX_OIDS_PER_REQUEST {
            args.extend(["1.3.6.1".to_owned(), "i".to_owned(), "1".to_owned()]);
        }

        let error = parse(&args).unwrap_err();
        assert!(error.contains("at most 10 varbinds"));
    }

    #[test]
    fn parse_rejects_incomplete_and_malformed_triplets() {
        let incomplete = [
            "1.3.6.1".to_owned(),
            "i".to_owned(),
            "1".to_owned(),
            "1.3.6.2".to_owned(),
        ];
        assert!(
            parse(&incomplete)
                .unwrap_err()
                .contains("OID TYPE VALUE triplets")
        );

        let malformed = ["1.3.6.1".to_owned(), "invalid".to_owned(), "1".to_owned()];
        assert!(
            parse(&malformed)
                .unwrap_err()
                .contains("invalid type specifier")
        );
    }
}
