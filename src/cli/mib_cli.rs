//! MIB loading support for CLI tools.
//!
//! Provides CLI arguments for loading MIBs and a helper to construct a
//! [`Mib`](crate::mib_support::Mib) from those arguments. Gated on both `cli`
//! and `mib` features.

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

        let mib = tokio::task::spawn_blocking(move || {
            load_mib_sync(&mib_dirs, &load_mibs, system_mibs)
        })
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

    loader.load().map_err(|e| format!("MIB loading failed: {}", e))
}

/// Resolve an OID argument that may be a name (when MIBs are loaded) or
/// dotted notation.
///
/// Arguments starting with a digit are parsed as dotted-decimal OIDs without
/// attempting MIB resolution. Named arguments are resolved through the MIB
/// if one is loaded, otherwise they fall back to the static hints table.
pub fn resolve_oid_arg(
    mib: Option<&Mib>,
    s: &str,
) -> Result<crate::Oid, String> {
    // If it starts with a digit, try dotted notation first
    if s.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        return crate::Oid::parse(s).map_err(|e| format!("invalid OID '{}': {}", s, e));
    }

    // Try MIB resolution if available
    if let Some(mib) = mib {
        return mib_support::resolve_oid(mib, s)
            .map_err(|e| format!("cannot resolve '{}': {}", s, e));
    }

    // Fall back to the static hints table
    crate::cli::hints::parse_oid(s)
}
