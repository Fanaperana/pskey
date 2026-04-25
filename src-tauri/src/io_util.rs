//! Shared filesystem & time helpers used by `vault`, `settings`, and `lockout`.
//!
//! These were duplicated in three modules; consolidating keeps the on-disk
//! atomic-write semantics consistent (write tmp, fsync, rename).

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Atomically write `bytes` to `path` via a tmp-file + rename. Optionally
/// keeps a `.bak` copy of the previous file (useful for the encrypted vault
/// where a botched write would lose every secret).
pub fn atomic_write(path: &Path, bytes: &[u8], keep_backup: bool) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    if keep_backup && path.exists() {
        let bak = path.with_extension("bak");
        // Best-effort: a missing rollback isn't fatal.
        let _ = fs::rename(path, &bak);
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Wall-clock seconds since the unix epoch. Returns 0 if the system clock is
/// before 1970 (which we treat as "no time available").
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Names of the files PSKey persists under the platform app-data directory.
pub mod files {
    use super::*;

    pub fn vault(app_data_dir: &Path) -> PathBuf {
        app_data_dir.join("vault.bin")
    }

    pub fn settings(app_data_dir: &Path) -> PathBuf {
        app_data_dir.join("settings.json")
    }

    pub fn lockout(app_data_dir: &Path) -> PathBuf {
        app_data_dir.join("lockout.json")
    }

    pub fn device_secret(app_data_dir: &Path) -> PathBuf {
        app_data_dir.join("device_secret.bin")
    }
}
