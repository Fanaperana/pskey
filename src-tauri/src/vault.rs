//! PSKey vault: Argon2id-derived key + XSalsa20-Poly1305 (libsodium `secretbox`).
//!
//! File layout (binary):
//!   [0..8]    magic "PSKEYv01"
//!   [8..24]   salt (16 bytes)              ─┐ header (KDF params & nonce)
//!   [24..32]  opslimit (u64 LE)             │ Tampering with any of these
//!   [32..40]  memlimit (u64 LE)             │ breaks MAC verification on
//!   [40..64]  nonce (24 bytes)             ─┘ decrypt.
//!   [64..]    ciphertext  =  secretbox(plaintext, nonce, derived_key)
//!
//! Plaintext = msgpack(VaultData).

use dryoc::classic::crypto_pwhash::{crypto_pwhash, PasswordHashAlgorithm};
use dryoc::classic::crypto_secretbox::{
    crypto_secretbox_easy, crypto_secretbox_open_easy, Key as SbKey, Nonce as SbNonce,
};
use dryoc::constants::{
    CRYPTO_PWHASH_MEMLIMIT_MODERATE, CRYPTO_PWHASH_OPSLIMIT_MODERATE, CRYPTO_PWHASH_SALTBYTES,
    CRYPTO_SECRETBOX_KEYBYTES, CRYPTO_SECRETBOX_MACBYTES, CRYPTO_SECRETBOX_NONCEBYTES,
};
use dryoc::rng::copy_randombytes;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const MAGIC: &[u8; 8] = b"PSKEYv01";
pub const SALT_LEN: usize = CRYPTO_PWHASH_SALTBYTES;
pub const KEY_LEN: usize = CRYPTO_SECRETBOX_KEYBYTES;
pub const NONCE_LEN: usize = CRYPTO_SECRETBOX_NONCEBYTES;
pub const MAC_LEN: usize = CRYPTO_SECRETBOX_MACBYTES;
pub const HEADER_LEN: usize = 8 + SALT_LEN + 8 + 8 + NONCE_LEN;

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

#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PinHash {
    pub salt: [u8; SALT_LEN],
    pub hash: [u8; 32],
    #[zeroize(skip)]
    pub opslimit: u64,
    #[zeroize(skip)]
    pub memlimit: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Entry {
    #[zeroize(skip)]
    pub id: Uuid,
    pub title: String,
    #[zeroize(skip)]
    pub has_username: bool,
    pub username: String,
    pub password: String,
    #[zeroize(skip)]
    pub use_default_pin: bool,
    pub custom_pin: Option<PinHash>,
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
            has_custom_pin: e.custom_pin.is_some(),
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
            version: 1,
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

impl VaultHeader {
    pub fn new_random() -> Self {
        let mut salt = [0u8; SALT_LEN];
        copy_randombytes(&mut salt);
        Self {
            salt,
            opslimit: CRYPTO_PWHASH_OPSLIMIT_MODERATE as u64,
            memlimit: CRYPTO_PWHASH_MEMLIMIT_MODERATE as u64,
        }
    }
}

pub fn derive_key(pin: &SecretString, header: &VaultHeader) -> Result<SbKey> {
    let mut key: SbKey = [0u8; KEY_LEN];
    crypto_pwhash(
        &mut key,
        pin.expose_secret().as_bytes(),
        &header.salt,
        header.opslimit,
        header.memlimit as usize,
        PasswordHashAlgorithm::Argon2id13,
    )
    .map_err(|_| VaultError::Kdf)?;
    Ok(key)
}

fn write_header(out: &mut Vec<u8>, header: &VaultHeader, nonce: &SbNonce) {
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&header.salt);
    out.extend_from_slice(&header.opslimit.to_le_bytes());
    out.extend_from_slice(&header.memlimit.to_le_bytes());
    out.extend_from_slice(nonce);
}

fn parse_header(bytes: &[u8]) -> Result<(VaultHeader, SbNonce, &[u8])> {
    if bytes.len() < HEADER_LEN {
        return Err(VaultError::Truncated);
    }
    if &bytes[0..8] != MAGIC {
        return Err(VaultError::BadMagic);
    }
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
) -> Result<(VaultHeader, SbKey, VaultData)> {
    let (header, nonce, ct) = parse_header(bytes)?;
    let key = derive_key(pin, &header)?;

    if ct.len() < MAC_LEN {
        return Err(VaultError::Truncated);
    }
    let mut plaintext = vec![0u8; ct.len() - MAC_LEN];
    crypto_secretbox_open_easy(&mut plaintext, ct, &nonce, &key)
        .map_err(|_| VaultError::Decrypt)?;

    let data: VaultData = rmp_serde::from_slice(&plaintext)?;
    plaintext.zeroize();
    Ok((header, key, data))
}

pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    if path.exists() {
        let bak = path.with_extension("bak");
        let _ = fs::rename(path, &bak);
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

pub fn read_all(path: &Path) -> Result<Vec<u8>> {
    Ok(fs::read(path)?)
}

pub fn vault_path(app_data_dir: &Path) -> PathBuf {
    app_data_dir.join("vault.bin")
}

pub fn hash_entry_pin(pin: &str) -> Result<PinHash> {
    let mut salt = [0u8; SALT_LEN];
    copy_randombytes(&mut salt);
    let opslimit = CRYPTO_PWHASH_OPSLIMIT_MODERATE as u64;
    let memlimit = CRYPTO_PWHASH_MEMLIMIT_MODERATE as u64;
    let mut hash = [0u8; 32];
    crypto_pwhash(
        &mut hash,
        pin.as_bytes(),
        &salt,
        opslimit,
        memlimit as usize,
        PasswordHashAlgorithm::Argon2id13,
    )
    .map_err(|_| VaultError::Kdf)?;
    Ok(PinHash {
        salt,
        hash,
        opslimit,
        memlimit,
    })
}

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
