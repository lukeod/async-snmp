//! File-backed engine state for the socketless notification example.
//! The lock must be respected by every writer of this state file.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

use async_snmp::{AuthoritativeEngine, LocalEngine, PersistedAuthoritativeEngine};

pub fn load(path: &Path) -> Result<LocalEngine, Box<dyn std::error::Error>> {
    let mut lock_path = path.as_os_str().to_os_string();
    lock_path.push(".lock");
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(lock_path)?;
    fs2::FileExt::try_lock_exclusive(&lock)?;
    let previous = match std::fs::read(path) {
        Ok(bytes) if bytes.len() >= 4 => {
            let (id, boots) = bytes.split_at(bytes.len() - 4);
            Some(PersistedAuthoritativeEngine::new(
                id.to_vec(),
                u32::from_be_bytes(boots.try_into()?),
            )?)
        }
        Ok(_) => return Err(io::Error::other("invalid engine state file").into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let path = path.to_owned();
    let persist = move |state: &PersistedAuthoritativeEngine| -> io::Result<()> {
        // Retain exclusive ownership through later engine-time rollovers too.
        let _lease = &lock;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let mut replacement = tempfile::NamedTempFile::new_in(parent)?;
        replacement.write_all(state.engine_id())?;
        replacement.write_all(&state.engine_boots().to_be_bytes())?;
        replacement.as_file().sync_all()?;
        replacement.persist(&path).map_err(|error| error.error)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    };
    let authoritative = match previous {
        Some(previous) => AuthoritativeEngine::restart(previous, persist)?,
        None => AuthoritativeEngine::install(async_snmp::generate_engine_id()?, persist)?,
    };
    Ok(LocalEngine::new(authoritative)?)
}
