//! PSKey vault: Argon2id-derived key + XSalsa20-Poly1305 (libsodium `secretbox`).
//!
//! File layout (binary):
//!   [0..8]    magic "PSKEYv01" (legacy) or "PSKEYv02" (current)
//!   [8..24]   salt (16 bytes)              ─┐ header (KDF params & nonce)
//!   [24..32]  opslimit (u64 LE)             │ Tampering with any of these
//!   [32..40]  memlimit (u64 LE)             │ breaks MAC verification on
//!   [40..64]  nonce (24 bytes)             ─┘ decrypt.
//!   [64..]    ciphertext  =  secretbox(plaintext, nonce, derived_key)
//!
//! Plaintext = msgpack(VaultData).
//!
//! KDF input:
//!   v01: argon2id(pin,             salt, ops, mem)
//!   v02: argon2id(pin || device_secret, salt, ops, mem)
//!
//! `device_secret` is a 32-byte high-entropy value stored in a separate
//! file (`device_secret.bin`). Mixing it into the KDF means a stolen
//! `vault.bin` alone cannot be brute-forced — even if the PIN is only
//! 4 digits, the effective keyspace is 10⁴ × 2²⁵⁶ against an attacker who
//! lacks the secret file.
//!
//! Per-entry secrets:
//!   When an entry uses a *custom* PIN, its password is also encrypted under
//!   a key derived from that PIN — independent of the vault key. Unlocking
//!   the vault is therefore not enough to read entries with a custom PIN:
//!   decryption itself is the verification (no separate Argon2id hash to
//!   brute force in memory). Default-PIN entries are protected by the vault
//!   key alone. New per-entry secrets (`CustomSecret.version >= 1`) also
//!   mix in `device_secret`; legacy ones (`version == 0`) do not.

use crate::io_util;
use dryoc::classic::crypto_pwhash::{crypto_pwhash, PasswordHashAlgorithm};
use dryoc::classic::crypto_secretbox::{
    crypto_secretbox_easy, crypto_secretbox_open_easy, Key as SbKey, Nonce as SbNonce,
};
use dryoc::constants::{
    CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE, CRYPTO_PWHASH_MEMLIMIT_MODERATE,
    CRYPTO_PWHASH_MEMLIMIT_SENSITIVE, CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
    CRYPTO_PWHASH_OPSLIMIT_MODERATE, CRYPTO_PWHASH_OPSLIMIT_SENSITIVE, CRYPTO_PWHASH_SALTBYTES,
    CRYPTO_SECRETBOX_KEYBYTES, CRYPTO_SECRETBOX_MACBYTES, CRYPTO_SECRETBOX_NONCEBYTES,
};
use dryoc::rng::copy_randombytes;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Legacy magic (no device_secret in KDF). Read-only — vaults with this
/// magic are auto-migrated to V2 on first successful unlock.
pub const MAGIC_V1: &[u8; 8] = b"PSKEYv01";
/// Current magic. Argon2id input is `pin || device_secret`.
pub const MAGIC_V2: &[u8; 8] = b"PSKEYv02";
/// Magic used when writing fresh vaults.
pub const MAGIC: &[u8; 8] = MAGIC_V2;
pub const SALT_LEN: usize = CRYPTO_PWHASH_SALTBYTES;
pub const KEY_LEN: usize = CRYPTO_SECRETBOX_KEYBYTES;
pub const NONCE_LEN: usize = CRYPTO_SECRETBOX_NONCEBYTES;
pub const MAC_LEN: usize = CRYPTO_SECRETBOX_MACBYTES;
pub const HEADER_LEN: usize = 8 + SALT_LEN + 8 + 8 + NONCE_LEN;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultFormat {
    /// Legacy: KDF input is the PIN only.
    V1,
    /// Current: KDF input is `pin || device_secret`.
    V2,
}

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization: {0}")]
    Encode(#[from] rmp_serde::encode::Error),
    #[error("deserialization: {0}")]
    Decode(#[from] rmp_serde::decode::Error),
    #[error("kdf failure")]
    Kdf,
    #[error("decryption failed (wrong PIN or corrupted vault)")]
    Decrypt,
    #[error("encryption failed")]
    Encrypt,
    #[error("bad magic / not a PSKey vault")]
    BadMagic,
    #[error("vault file truncated")]
    Truncated,
    #[error("vault already exists")]
    AlreadyExists,
    #[error("vault does not exist")]
    NotFound,
}

pub type Result<T> = std::result::Result<T, VaultError>;

/// Legacy per-entry PIN hash (PSKey ≤ v0.1). Entries created before per-entry
/// encryption was added still carry one of these alongside a plaintext
/// `password` field; we keep the verifier so old vaults remain readable.
#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PinHash {
    pub salt: [u8; SALT_LEN],
    pub hash: [u8; 32],
    #[zeroize(skip)]
    pub opslimit: u64,
    #[zeroize(skip)]
    pub memlimit: u64,
}

/// A password protected by a per-entry PIN. The ciphertext can only be
/// decrypted with the correct PIN — no separate hash-then-compare step.
#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct CustomSecret {
    /// 0 = legacy (KDF input is PIN only). 1 = KDF input is
    /// `pin || device_secret`. New entries always write 1.
    #[serde(default)]
    #[zeroize(skip)]
    pub version: u8,
    pub salt: [u8; SALT_LEN],
    #[zeroize(skip)]
    pub opslimit: u64,
    #[zeroize(skip)]
    pub memlimit: u64,
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Entry {
    #[zeroize(skip)]
    pub id: Uuid,
    pub title: String,
    #[zeroize(skip)]
    pub has_username: bool,
    pub username: String,
    /// Plaintext password — only present for default-PIN entries (or for
    /// legacy entries that pre-date `custom_secret`).
    #[serde(default)]
    pub password: String,
    #[zeroize(skip)]
    pub use_default_pin: bool,
    /// Legacy verifier — kept readable for old vaults; never written by
    /// new code. Replaced by `custom_secret` for new entries.
    #[serde(default)]
    pub custom_pin: Option<PinHash>,
    /// Password encrypted under a key derived from the entry's PIN.
    #[serde(default)]
    pub custom_secret: Option<CustomSecret>,
    #[zeroize(skip)]
    pub created_at: u64,
    #[zeroize(skip)]
    pub updated_at: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct EntryMeta {
    pub id: Uuid,
    pub title: String,
    pub has_username: bool,
    pub use_default_pin: bool,
    pub has_custom_pin: bool,
    pub created_at: u64,
    pub updated_at: u64,
}

impl From<&Entry> for EntryMeta {
    fn from(e: &Entry) -> Self {
        Self {
            id: e.id,
            title: e.title.clone(),
            has_username: e.has_username,
            use_default_pin: e.use_default_pin,
            has_custom_pin: e.custom_secret.is_some() || e.custom_pin.is_some(),
            created_at: e.created_at,
            updated_at: e.updated_at,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct VaultData {
    #[zeroize(skip)]
    pub version: u32,
    pub entries: Vec<Entry>,
}

impl Default for VaultData {
    fn default() -> Self {
        Self {
            version: 2,
            entries: Vec::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct VaultHeader {
    pub salt: [u8; SALT_LEN],
    pub opslimit: u64,
    pub memlimit: u64,
}

/// KDF cost preset. Stored per-vault via `(opslimit, memlimit)` in the header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KdfStrength {
    Interactive,
    Moderate,
    Sensitive,
}

impl KdfStrength {
    pub fn params(self) -> (u64, u64) {
        match self {
            KdfStrength::Interactive => (
                CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE as u64,
                CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE as u64,
            ),
            KdfStrength::Moderate => (
                CRYPTO_PWHASH_OPSLIMIT_MODERATE as u64,
                CRYPTO_PWHASH_MEMLIMIT_MODERATE as u64,
            ),
            KdfStrength::Sensitive => (
                CRYPTO_PWHASH_OPSLIMIT_SENSITIVE as u64,
                CRYPTO_PWHASH_MEMLIMIT_SENSITIVE as u64,
            ),
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "interactive" => Some(KdfStrength::Interactive),
            "moderate" => Some(KdfStrength::Moderate),
            "sensitive" => Some(KdfStrength::Sensitive),
            _ => None,
        }
    }
}

impl VaultHeader {
    /// Create a fresh header with random salt at the given KDF strength.
    pub fn new_with_strength(strength: KdfStrength) -> Self {
        let mut salt = [0u8; SALT_LEN];
        copy_randombytes(&mut salt);
        let (opslimit, memlimit) = strength.params();
        Self {
            salt,
            opslimit,
            memlimit,
        }
    }
}

pub fn derive_key(
    pin: &SecretString,
    device_secret: Option<&[u8]>,
    header: &VaultHeader,
) -> Result<SbKey> {
    derive_key_raw(
        pin.expose_secret().as_bytes(),
        device_secret,
        &header.salt,
        header.opslimit,
        header.memlimit,
    )
}

fn derive_key_raw(
    pin: &[u8],
    device_secret: Option<&[u8]>,
    salt: &[u8; SALT_LEN],
    ops: u64,
    mem: u64,
) -> Result<SbKey> {
    // Combined input is the PIN bytes optionally followed by the device
    // secret. We zero the temporary buffer after the KDF call so the secret
    // isn't left dangling on the heap.
    let mut combined: Vec<u8> = Vec::with_capacity(pin.len() + 32);
    combined.extend_from_slice(pin);
    if let Some(ds) = device_secret {
        combined.extend_from_slice(ds);
    }
    let mut key: SbKey = [0u8; KEY_LEN];
    let res = crypto_pwhash(
        &mut key,
        &combined,
        salt,
        ops,
        mem as usize,
        PasswordHashAlgorithm::Argon2id13,
    );
    combined.zeroize();
    res.map_err(|_| VaultError::Kdf)?;
    Ok(key)
}

fn write_header(out: &mut Vec<u8>, header: &VaultHeader, nonce: &SbNonce) {
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&header.salt);
    out.extend_from_slice(&header.opslimit.to_le_bytes());
    out.extend_from_slice(&header.memlimit.to_le_bytes());
    out.extend_from_slice(nonce);
}

fn parse_header(bytes: &[u8]) -> Result<(VaultHeader, VaultFormat, SbNonce, &[u8])> {
    if bytes.len() < HEADER_LEN {
        return Err(VaultError::Truncated);
    }
    let format = if &bytes[0..8] == MAGIC_V2 {
        VaultFormat::V2
    } else if &bytes[0..8] == MAGIC_V1 {
        VaultFormat::V1
    } else {
        return Err(VaultError::BadMagic);
    };
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&bytes[8..8 + SALT_LEN]);
    let opslimit = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
    let memlimit = u64::from_le_bytes(bytes[32..40].try_into().unwrap());
    let mut nonce: SbNonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&bytes[40..64]);
    Ok((
        VaultHeader {
            salt,
            opslimit,
            memlimit,
        },
        format,
        nonce,
        &bytes[HEADER_LEN..],
    ))
}

pub fn encrypt_to_bytes(data: &VaultData, key: &SbKey, header: &VaultHeader) -> Result<Vec<u8>> {
    let mut plaintext = rmp_serde::to_vec_named(data)?;

    let mut nonce: SbNonce = [0u8; NONCE_LEN];
    copy_randombytes(&mut nonce);

    let mut ciphertext = vec![0u8; plaintext.len() + MAC_LEN];
    crypto_secretbox_easy(&mut ciphertext, &plaintext, &nonce, key)
        .map_err(|_| VaultError::Encrypt)?;
    plaintext.zeroize();

    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    write_header(&mut out, header, &nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn decrypt_from_bytes(
    bytes: &[u8],
    pin: &SecretString,
    device_secret: &[u8],
) -> Result<(VaultHeader, VaultFormat, SbKey, VaultData)> {
    let (header, format, nonce, ct) = parse_header(bytes)?;
    let ds_opt = match format {
        VaultFormat::V1 => None,
        VaultFormat::V2 => Some(device_secret),
    };
    let key = derive_key(pin, ds_opt, &header)?;

    if ct.len() < MAC_LEN {
        return Err(VaultError::Truncated);
    }
    let mut plaintext = vec![0u8; ct.len() - MAC_LEN];
    crypto_secretbox_open_easy(&mut plaintext, ct, &nonce, &key)
        .map_err(|_| VaultError::Decrypt)?;

    let data: VaultData = rmp_serde::from_slice(&plaintext)?;
    plaintext.zeroize();
    Ok((header, format, key, data))
}

/// Atomically write the encrypted vault to disk, keeping a one-step `.bak`
/// rollback so a crashed write can't lose every secret.
pub fn write_vault(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    io_util::atomic_write(path, bytes, true)
}

pub fn read_all(path: &Path) -> Result<Vec<u8>> {
    Ok(fs::read(path)?)
}

/// Encrypt a per-entry password under a key derived from `pin` (and the
/// device_secret) at the given KDF cost. Always writes a v1 record — the
/// device_secret is mandatory for new entries.
pub fn seal_entry_secret(
    pin: &str,
    device_secret: &[u8],
    password: &str,
    opslimit: u64,
    memlimit: u64,
) -> Result<CustomSecret> {
    let mut salt = [0u8; SALT_LEN];
    copy_randombytes(&mut salt);
    let mut key = derive_key_raw(
        pin.as_bytes(),
        Some(device_secret),
        &salt,
        opslimit,
        memlimit,
    )?;
    let mut nonce: SbNonce = [0u8; NONCE_LEN];
    copy_randombytes(&mut nonce);
    let mut ciphertext = vec![0u8; password.len() + MAC_LEN];
    crypto_secretbox_easy(&mut ciphertext, password.as_bytes(), &nonce, &key)
        .map_err(|_| VaultError::Encrypt)?;
    key.zeroize();
    Ok(CustomSecret {
        version: 1,
        salt,
        opslimit,
        memlimit,
        nonce,
        ciphertext,
    })
}

/// Decrypt a per-entry password using the supplied PIN. A wrong PIN fails
/// the secretbox MAC — there is no separate "verify" step. Legacy records
/// (`version == 0`) used the PIN alone as the KDF input.
pub fn open_entry_secret(secret: &CustomSecret, pin: &str, device_secret: &[u8]) -> Result<String> {
    let ds_opt: Option<&[u8]> = if secret.version >= 1 {
        Some(device_secret)
    } else {
        None
    };
    let mut key = derive_key_raw(
        pin.as_bytes(),
        ds_opt,
        &secret.salt,
        secret.opslimit,
        secret.memlimit,
    )?;
    if secret.ciphertext.len() < MAC_LEN {
        return Err(VaultError::Truncated);
    }
    let mut plaintext = vec![0u8; secret.ciphertext.len() - MAC_LEN];
    crypto_secretbox_open_easy(&mut plaintext, &secret.ciphertext, &secret.nonce, &key)
        .map_err(|_| VaultError::Decrypt)?;
    key.zeroize();
    let s = String::from_utf8(plaintext.clone()).map_err(|_| VaultError::Decrypt)?;
    plaintext.zeroize();
    Ok(s)
}

/// Legacy: verify a per-entry PIN against an Argon2id hash. Used only to
/// keep entries from older vaults readable.
pub fn verify_entry_pin(record: &PinHash, pin: &str) -> bool {
    let mut out = [0u8; 32];
    if crypto_pwhash(
        &mut out,
        pin.as_bytes(),
        &record.salt,
        record.opslimit,
        record.memlimit as usize,
        PasswordHashAlgorithm::Argon2id13,
    )
    .is_err()
    {
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..32 {
        diff |= out[i] ^ record.hash[i];
    }
    out.zeroize();
    diff == 0
}
