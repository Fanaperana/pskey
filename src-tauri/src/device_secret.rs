//! 32-byte device secret mixed into Argon2id alongside the vault PIN.
//!
//! With only a 4-digit PIN the keyspace is 10⁴ — trivial to brute-force
//! against an exfiltrated vault file. Mixing in a high-entropy secret that
//! lives outside the vault file means the AEAD ciphertext alone is useless:
//! an attacker who obtains `vault.bin` (the typical accidental-leak case —
//! cloud sync, manual backup, mis-shared archive) cannot mount any offline
//! attack without also stealing `device_secret.bin`.
//!
//! Storage is a separate file in the app data dir with `0600` permissions
//! on Unix. This is intentionally a different file from `vault.bin` so the
//! two are unlikely to be moved together by accident, but it is *not*
//! equivalent to an OS keychain — an attacker with full local filesystem
//! access still gets both. Hardware-backed storage (Secret Service /
//! Keychain / DPAPI) is the natural next step.

use crate::io_util;
use dryoc::rng::copy_randombytes;
use std::io;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub const SECRET_LEN: usize = 32;
pub type DeviceSecret = [u8; SECRET_LEN];

/// Read the device secret from disk, generating and persisting a fresh
/// random one on first run (or if the file is corrupt / wrong size).
pub fn load_or_create(path: &Path) -> io::Result<DeviceSecret> {
    if let Ok(bytes) = std::fs::read(path) {
        if bytes.len() == SECRET_LEN {
            let mut out = [0u8; SECRET_LEN];
            out.copy_from_slice(&bytes);
            return Ok(out);
        }
        // Wrong size — treat as missing and overwrite. We don't try to
        // recover; a bogus secret would just lock the user out of an
        // existing vault, and v01 vaults will migrate cleanly anyway.
    }
    let mut secret = [0u8; SECRET_LEN];
    copy_randombytes(&mut secret);
    io_util::atomic_write(path, &secret, false)?;
    #[cfg(unix)]
    {
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }
    Ok(secret)
}
