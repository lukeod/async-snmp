//! MIB loading support for CLI tools.
//!
//! Provides CLI arguments for loading MIBs and a helper to construct a
//! [`Mib`] from those arguments. Gated on both `cli`
//! and `mib` features.

use super::hints;
use crate::mib_support::{self, DiagnosticConfig, Loader, Mib, source};
use clap::Parser;
use std::path::PathBuf;

/// MIB loading arguments for CLI tools.
#[derive(Debug, Parser)]
pub struct MibArgs {
    /// Load MIBs from these directories.
    #[arg(long = "mib-dir")]
    pub mib_dir: Vec<PathBuf>,

    /// Load specific MIB modules by name.
    #[arg(long = "load-mibs")]
    pub load_mibs: Vec<String>,

    /// Use system MIB search paths (net-snmp, libsmi).
    #[arg(long = "system-mibs")]
    pub system_mibs: bool,
}

impl MibArgs {
    /// Returns true if any MIB loading options were specified.
    pub fn is_active(&self) -> bool {
        !self.mib_dir.is_empty() || !self.load_mibs.is_empty() || self.system_mibs
    }

    /// Load MIBs based on the CLI arguments.
    ///
    /// Returns `None` if no MIB options were specified.
    /// Uses `spawn_blocking` internally because mib-rs uses rayon for
    /// parallel file loading.
    pub async fn load(&self) -> Result<Option<Mib>, String> {
        if !self.is_active() {
            return Ok(None);
        }

        let mib_dirs = self.mib_dir.clone();
        let load_mibs = self.load_mibs.clone();
        let system_mibs = self.system_mibs;

        let mib =
            tokio::task::spawn_blocking(move || load_mib_sync(&mib_dirs, &load_mibs, system_mibs))
                .await
                .map_err(|e| format!("MIB loading task failed: {}", e))??;

        Ok(Some(mib))
    }
}

/// Synchronous MIB loading (runs on a blocking thread).
fn load_mib_sync(
    mib_dirs: &[PathBuf],
    load_mibs: &[String],
    system_mibs: bool,
) -> Result<Mib, String> {
    let mut loader = Loader::new();

    // Add directory sources
    for dir in mib_dirs {
        let source = source::dir(dir)
            .map_err(|e| format!("failed to open MIB directory {:?}: {}", dir, e))?;
        loader = loader.source(source);
    }

    // Add system paths
    if system_mibs {
        loader = loader.system_paths();
    }

    // Restrict to named modules if specified
    if !load_mibs.is_empty() {
        loader = loader.modules(load_mibs.iter().map(String::as_str));
    }

    // Use quiet diagnostics for CLI
    loader = loader.diagnostic_config(DiagnosticConfig::quiet());

    loader
        .load()
        .map_err(|e| format!("MIB loading failed: {}", e))
}

/// Resolve an OID argument that may be a name (when MIBs are loaded) or
/// dotted notation.
///
/// Dotted-decimal OIDs may start with a dot. Resolve names through the loaded
/// MIB or use the static hints table when no MIB is loaded.
pub fn resolve_oid_arg(mib: Option<&Mib>, s: &str) -> Result<crate::Oid, String> {
    let Some(mib) = mib else {
        return hints::parse_oid(s);
    };
    hints::parse_numeric_oid(s).unwrap_or_else(|| {
        mib_support::resolve_oid(mib, s).map_err(|error| format!("cannot resolve '{s}': {error}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oid;

    #[test]
    fn oid_resolution_with_optional_mib() {
        let mib = Loader::new()
            .source(source::memory(
                "CLI-TEST-MIB",
                "CLI-TEST-MIB DEFINITIONS ::= BEGIN\ncliTestNode OBJECT IDENTIFIER ::= { iso 3 }\nEND",
            ))
            .modules(["CLI-TEST-MIB"])
            .load()
            .unwrap();

        for mib in [None, Some(&mib)] {
            assert_eq!(resolve_oid_arg(mib, ".1.3").unwrap(), oid!(1, 3));
            assert!(
                resolve_oid_arg(mib, ".1..3")
                    .unwrap_err()
                    .starts_with("invalid OID '.1..3': ")
            );
        }
        assert_eq!(
            resolve_oid_arg(Some(&mib), "CLI-TEST-MIB::cliTestNode").unwrap(),
            oid!(1, 3)
        );
        assert_eq!(
            resolve_oid_arg(None, "sysDescr.0").unwrap(),
            oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)
        );
    }
}
