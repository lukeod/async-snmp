//! Append and sync a demonstration text record on a blocking worker.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;

pub async fn append(path: PathBuf, record: String) -> io::Result<()> {
    tokio::task::spawn_blocking(move || {
        let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
        writeln!(file, "{record}")?;
        file.sync_all()?;
        // Also persist a newly created log's directory entry on this filesystem.
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(std::path::Path::new("."));
        File::open(parent)?.sync_all()
    })
    .await
    .map_err(io::Error::other)?
}
