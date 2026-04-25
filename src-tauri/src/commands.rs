//! Tauri state & commands — keeps secrets in Rust, exposes only metadata to JS.

use crate::device_secret::DeviceSecret;
use crate::error::{CmdResult, CommandError};
use crate::io_util::now_unix;
use crate::lockout::{self, LockoutState};
use crate::settings::{self, Settings};
use crate::vault::{
    self, decrypt_from_bytes, encrypt_to_bytes, open_entry_secret, read_all, seal_entry_secret,
    verify_entry_pin, Entry, EntryMeta, KdfStrength, VaultData, VaultFormat, VaultHeader,
};
use dryoc::classic::crypto_secretbox::Key as SbKey;
use dryoc::rng::copy_randombytes;
use parking_lot::Mutex;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Manager, State};
use tauri_plugin_clipboard_manager::ClipboardExt;
use uuid::Uuid;
use zeroize::Zeroize;

const SESSION_TTL_SECS: u64 = 30;
const CLIPBOARD_CLEAR_SECS: u64 = 15;
/// Minimum PIN length for new vaults / new entries. The 4-digit floor is
/// only safe because every Argon2id derivation also mixes in a 32-byte
/// device secret stored outside the vault file (`device_secret.bin`).
/// Without that file, brute-forcing the 10⁴ keyspace is infeasible.
pub const MIN_PIN_LEN: usize = 4;

struct Session {
    token: String,
    key: SbKey,
    header: VaultHeader,
    data: VaultData,
    expires_at: Instant,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

struct Inner {
    session: Option<Session>,
    lockout: LockoutState,
}

pub struct AppState {
    inner: Mutex<Inner>,
    vault_file: PathBuf,
    settings_file: PathBuf,
    lockout_file: PathBuf,
    /// Per-install 32-byte secret mixed into every Argon2id derivation.
    /// Lives outside the vault file (`device_secret.bin`) so vault-only
    /// theft yields no offline brute-force surface.
    device_secret: DeviceSecret,
}

impl AppState {
    pub fn new(
        vault_file: PathBuf,
        settings_file: PathBuf,
        lockout_file: PathBuf,
        device_secret: DeviceSecret,
        lockout: LockoutState,
    ) -> Self {
        Self {
            inner: Mutex::new(Inner {
                session: None,
                lockout,
            }),
            vault_file,
            settings_file,
            lockout_file,
            device_secret,
        }
    }
}

#[derive(Serialize)]
pub struct UnlockResult {
    token: String,
    expires_in_ms: u64,
    entries: Vec<EntryMeta>,
}

#[derive(Serialize)]
pub struct LockoutStatus {
    /// Seconds remaining on the active cooldown, or 0 if not locked.
    remaining_secs: u64,
    /// Number of failed attempts in the current series (since last success).
    failed_attempts: u32,
    /// Lockout level — 0 = pristine, increments after every cooldown.
    lockout_level: u32,
    /// Total attempts allowed before the next cooldown fires.
    threshold: u32,
}

#[derive(Deserialize)]
pub struct AddEntryInput {
    title: String,
    has_username: bool,
    username: String,
    password: String,
    use_default_pin: bool,
    custom_pin: Option<String>,
}

fn make_token() -> String {
    let mut buf = [0u8; 24];
    copy_randombytes(&mut buf);
    let mut s = String::with_capacity(48);
    for b in buf.iter() {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn unlock_result_from(session: &Session) -> UnlockResult {
    let remaining = session
        .expires_at
        .saturating_duration_since(Instant::now())
        .as_millis() as u64;
    UnlockResult {
        token: session.token.clone(),
        expires_in_ms: remaining,
        entries: session.data.entries.iter().map(EntryMeta::from).collect(),
    }
}

fn require_session<'a>(inner: &'a mut Inner, token: &str) -> CmdResult<&'a mut Session> {
    let s = inner.session.as_mut().ok_or(CommandError::Locked)?;
    if s.token != token {
        return Err(CommandError::InvalidToken);
    }
    if Instant::now() >= s.expires_at {
        inner.session = None;
        return Err(CommandError::SessionExpired);
    }
    // Extend on use (sliding window).
    s.expires_at = Instant::now() + Duration::from_secs(SESSION_TTL_SECS);
    Ok(inner.session.as_mut().unwrap())
}

fn persist(state: &AppState, session: &Session) -> CmdResult<()> {
    let bytes = encrypt_to_bytes(&session.data, &session.key, &session.header)?;
    vault::write_vault(&state.vault_file, &bytes)?;
    Ok(())
}

/// Reject the request if a cooldown is active.
fn check_lockout(inner: &Inner) -> CmdResult<()> {
    if inner.lockout.is_locked() {
        let secs = inner.lockout.remaining_lock_secs();
        return Err(CommandError::LockedOut {
            wait: lockout::format_wait(secs),
        });
    }
    Ok(())
}

/// Persist the lockout state to disk so it survives process restarts.
/// Errors are swallowed: a write failure shouldn't deny a legitimate user.
fn persist_lockout(state: &AppState, snap: &LockoutState) {
    let _ = lockout::save(&state.lockout_file, snap);
}

// ─── Commands ───

#[tauri::command]
pub fn vault_exists(state: State<AppState>) -> bool {
    state.vault_file.exists()
}

/// Lockout snapshot — used by the UI to render a live cooldown countdown
/// and to know when the input should be re-enabled.
#[tauri::command]
pub fn lockout_status(state: State<AppState>) -> LockoutStatus {
    let inner = state.inner.lock();
    LockoutStatus {
        remaining_secs: inner.lockout.remaining_lock_secs(),
        failed_attempts: inner.lockout.failed_attempts,
        lockout_level: inner.lockout.lockout_level,
        threshold: inner.lockout.threshold(),
    }
}

#[tauri::command]
pub async fn vault_init(pin: String, state: State<'_, AppState>) -> CmdResult<UnlockResult> {
    if state.vault_file.exists() {
        return Err(CommandError::VaultAlreadyExists);
    }
    if pin.is_empty() {
        return Err(CommandError::PinRequired);
    }
    if pin.chars().count() < MIN_PIN_LEN {
        return Err(CommandError::PinTooShort { min: MIN_PIN_LEN });
    }
    // New vaults pick up the strength configured in settings.json (default
    // INTERACTIVE). Existing vaults keep whatever's stored in their header.
    let cfg = settings::load_or_default(&state.settings_file);
    let strength = KdfStrength::parse(&cfg.kdf_strength).unwrap_or(KdfStrength::Interactive);
    let header = VaultHeader::new_with_strength(strength);
    let pin_secret = SecretString::from(pin);
    let key = vault::derive_key(&pin_secret, Some(&state.device_secret), &header)?;
    let data = VaultData::default();
    let bytes = encrypt_to_bytes(&data, &key, &header)?;
    vault::write_vault(&state.vault_file, &bytes)?;

    let session = Session {
        token: make_token(),
        key,
        header,
        data,
        expires_at: Instant::now() + Duration::from_secs(SESSION_TTL_SECS),
    };
    let result = unlock_result_from(&session);
    let mut inner = state.inner.lock();
    inner.session = Some(session);
    inner.lockout.record_success();
    let snap = inner.lockout.clone();
    drop(inner);
    persist_lockout(&state, &snap);
    Ok(result)
}

/// Shared body for both `vault_unlock` (plain PIN) and
/// `vault_unlock_challenge` (rolling-challenge PIN). Encapsulates the
/// lockout/session/persist logic so both entry points stay in lockstep.
async fn vault_unlock_inner(pin: String, state: &State<'_, AppState>) -> CmdResult<UnlockResult> {
    {
        let inner = state.inner.lock();
        check_lockout(&inner)?;
    }
    if !state.vault_file.exists() {
        return Err(CommandError::VaultMissing);
    }
    let bytes = read_all(&state.vault_file)?;
    let pin_secret = SecretString::from(pin);
    match decrypt_from_bytes(&bytes, &pin_secret, &state.device_secret) {
        Ok((header, format, key, data)) => {
            // Auto-migrate legacy v01 vaults to v02 on first successful
            // unlock: rederive the key with the device_secret mixed in and
            // rewrite the file. After this, the vault file alone is no
            // longer brute-forceable.
            let (key, header) = if format == VaultFormat::V1 {
                // SbKey is `[u8; 32]` (Copy), so the legacy-derived key
                // value goes out of scope below; libsodium clears the slot
                // on drop. We rederive a v02 key with the device_secret
                // mixed in and rewrite the file in-place.
                let _ = key;
                let new_key =
                    match vault::derive_key(&pin_secret, Some(&state.device_secret), &header) {
                        Ok(k) => k,
                        Err(_) => {
                            return Err(CommandError::Internal("v02 migration failed".into()))
                        }
                    };
                if let Ok(new_bytes) = encrypt_to_bytes(&data, &new_key, &header) {
                    let _ = vault::write_vault(&state.vault_file, &new_bytes);
                }
                (new_key, header)
            } else {
                (key, header)
            };
            let session = Session {
                token: make_token(),
                key,
                header,
                data,
                expires_at: Instant::now() + Duration::from_secs(SESSION_TTL_SECS),
            };
            let result = unlock_result_from(&session);
            let mut inner = state.inner.lock();
            inner.session = Some(session);
            inner.lockout.record_success();
            let snap = inner.lockout.clone();
            drop(inner);
            persist_lockout(state, &snap);
            Ok(result)
        }
        Err(_) => {
            let mut inner = state.inner.lock();
            let triggered = inner.lockout.record_failure();
            let snap = inner.lockout.clone();
            drop(inner);
            persist_lockout(state, &snap);
            if let Some(secs) = triggered {
                Err(CommandError::LockedOut {
                    wait: lockout::format_wait(secs),
                })
            } else {
                Err(CommandError::InvalidPin)
            }
        }
    }
}

#[tauri::command]
pub async fn vault_unlock(pin: String, state: State<'_, AppState>) -> CmdResult<UnlockResult> {
    vault_unlock_inner(pin, &state).await
}

/// Rolling-challenge unlock.
///
/// The frontend displays a per-attempt `challenge` of 4 Base36 characters
/// (`0-9A-Z`, value 0..36) and the user types a 4-character Base36
/// `response`. For each position:
///
///     response[i] = base36_char( (pin[i] + val(challenge[i])) mod 36 )
///
/// The backend recovers the PIN deterministically:
///
///     pin[i] = (val(response[i]) - val(challenge[i]) + 36) mod 36
///
/// Each recovered digit must be in 0..10 (since real PINs are decimal); a
/// response that decodes to a value ≥ 10 in any slot is rejected as
/// malformed input — *not* counted as a wrong-PIN attempt against the
/// lockout, since it can't possibly match any real PIN.
///
/// Properties:
/// - Typed characters change every attempt (challenge rotates), so a
///   keystroke-only observer learns nothing reusable.
/// - Exactly one PIN candidate per (challenge, response), so the server
///   runs only a single (expensive) Argon2id derivation per attempt.
///
/// Caveat: this only defends against keystroke-only observers. An attacker
/// who sees the screen + the keystrokes can recover the PIN trivially —
/// the real defence against an exfiltrated `vault.bin` is the device
/// secret mixed into the Argon2id input (see `vault.rs`).
#[derive(Deserialize)]
pub struct ChallengeUnlockInput {
    challenge: String,
    response: String,
}

/// Map a Base36 char (`0-9`, `A-Z`, `a-z`) to its 0..36 value.
fn base36_value(c: char) -> Option<u32> {
    c.to_digit(36)
}

fn decode_challenge_pin(challenge: &str, response: &str) -> CmdResult<String> {
    if challenge.chars().count() != response.chars().count() {
        return Err(CommandError::BadInput(
            "challenge/response length mismatch".into(),
        ));
    }
    if challenge.is_empty() {
        return Err(CommandError::PinRequired);
    }
    let mut pin = String::with_capacity(challenge.chars().count());
    for (cc, rc) in challenge.chars().zip(response.chars()) {
        let cn = base36_value(cc)
            .ok_or_else(|| CommandError::BadInput("challenge must be base36".into()))?;
        let rn = base36_value(rc)
            .ok_or_else(|| CommandError::BadInput("response must be base36".into()))?;
        // Reverse the mod-36 add. Cast through i32 to keep the subtraction
        // honest, then collapse back into 0..36.
        let pd = ((rn as i32 - cn as i32).rem_euclid(36)) as u32;
        // Real PIN digits are 0..10. Any response that decodes to ≥ 10 is
        // structurally impossible — reject as malformed instead of charging
        // a real attempt against the lockout schedule.
        if pd >= 10 {
            return Err(CommandError::InvalidPin);
        }
        pin.push(char::from_digit(pd, 10).unwrap());
    }
    Ok(pin)
}

#[tauri::command]
pub async fn vault_unlock_challenge(
    input: ChallengeUnlockInput,
    state: State<'_, AppState>,
) -> CmdResult<UnlockResult> {
    let pin = decode_challenge_pin(&input.challenge, &input.response)?;
    vault_unlock_inner(pin, &state).await
}

#[tauri::command]
pub fn vault_lock(state: State<AppState>) {
    let mut inner = state.inner.lock();
    inner.session = None;
}

/// Lock the vault from Rust (e.g. tray menu). Same effect as the command.
pub fn lock_session(state: &AppState) {
    let mut inner = state.inner.lock();
    inner.session = None;
}

#[tauri::command]
pub fn session_touch(token: String, state: State<AppState>) -> CmdResult<u64> {
    let mut inner = state.inner.lock();
    let s = require_session(&mut inner, &token)?;
    Ok(s.expires_at
        .saturating_duration_since(Instant::now())
        .as_millis() as u64)
}

#[tauri::command]
pub fn list_entries(token: String, state: State<AppState>) -> CmdResult<Vec<EntryMeta>> {
    let mut inner = state.inner.lock();
    let s = require_session(&mut inner, &token)?;
    Ok(s.data.entries.iter().map(EntryMeta::from).collect())
}

/// Authorization required for an entry's password, captured under the lock
/// so we can release the mutex before running expensive Argon2id work.
enum AuthRequest {
    None {
        password: String,
    },
    Decrypt(vault::CustomSecret),
    Legacy {
        hash: vault::PinHash,
        password: String,
    },
}

fn authorize_entry_password(entry: &Entry, pin: &Option<String>) -> CmdResult<AuthRequest> {
    if let Some(secret) = entry.custom_secret.as_ref() {
        let _ = pin.as_ref().ok_or(CommandError::PinRequired)?;
        return Ok(AuthRequest::Decrypt(secret.clone()));
    }
    if let Some(hash) = entry.custom_pin.as_ref() {
        let _ = pin.as_ref().ok_or(CommandError::PinRequired)?;
        return Ok(AuthRequest::Legacy {
            hash: hash.clone(),
            password: entry.password.clone(),
        });
    }
    Ok(AuthRequest::None {
        password: entry.password.clone(),
    })
}

async fn resolve_password(
    req: AuthRequest,
    pin: Option<String>,
    device_secret: DeviceSecret,
) -> CmdResult<String> {
    match req {
        AuthRequest::None { password } => Ok(password),
        AuthRequest::Decrypt(secret) => {
            let pin = pin.expect("pin checked");
            let res = tauri::async_runtime::spawn_blocking(move || {
                open_entry_secret(&secret, &pin, &device_secret)
            })
            .await
            .map_err(|e| CommandError::Internal(e.to_string()))?;
            res.map_err(CommandError::from)
        }
        AuthRequest::Legacy { hash, password } => {
            let pin = pin.expect("pin checked");
            let ok = tauri::async_runtime::spawn_blocking(move || verify_entry_pin(&hash, &pin))
                .await
                .map_err(|e| CommandError::Internal(e.to_string()))?;
            if ok {
                Ok(password)
            } else {
                Err(CommandError::InvalidPin)
            }
        }
    }
}

#[tauri::command]
pub async fn get_entry_secret(
    token: String,
    id: Uuid,
    pin: Option<String>,
    state: State<'_, AppState>,
) -> CmdResult<String> {
    let req = {
        let mut inner = state.inner.lock();
        let s = require_session(&mut inner, &token)?;
        let entry = s
            .data
            .entries
            .iter()
            .find(|e| e.id == id)
            .ok_or(CommandError::NotFound)?;
        authorize_entry_password(entry, &pin)?
    };
    resolve_password(req, pin, state.device_secret).await
}

#[tauri::command]
pub fn get_entry_username(token: String, id: Uuid, state: State<AppState>) -> CmdResult<String> {
    let mut inner = state.inner.lock();
    let s = require_session(&mut inner, &token)?;
    let entry = s
        .data
        .entries
        .iter()
        .find(|e| e.id == id)
        .ok_or(CommandError::NotFound)?;
    Ok(entry.username.clone())
}

#[tauri::command]
pub async fn add_entry(
    token: String,
    input: AddEntryInput,
    state: State<'_, AppState>,
) -> CmdResult<EntryMeta> {
    let title = input.title.trim().to_string();
    if title.is_empty() {
        return Err(CommandError::BadInput("title required".into()));
    }
    let (vault_ops, vault_mem) = {
        let mut inner = state.inner.lock();
        let s = require_session(&mut inner, &token)?;
        (s.header.opslimit, s.header.memlimit)
    };

    // Per-entry encryption: when the user sets a custom PIN, encrypt the
    // password under a key derived from that PIN — independent of the vault
    // key. Without the PIN, the password is unrecoverable even with full
    // access to the unlocked vault in memory.
    let mut password = input.password;
    let custom_secret = if !input.use_default_pin {
        match input.custom_pin.as_ref() {
            Some(p) if !p.is_empty() => {
                if p.chars().count() < MIN_PIN_LEN {
                    password.zeroize();
                    return Err(CommandError::PinTooShort { min: MIN_PIN_LEN });
                }
                let pin = p.clone();
                let pw = password.clone();
                let ds = state.device_secret;
                let secret = tauri::async_runtime::spawn_blocking(move || {
                    seal_entry_secret(&pin, &ds, &pw, vault_ops, vault_mem)
                })
                .await
                .map_err(|e| CommandError::Internal(e.to_string()))??;
                password.zeroize();
                password = String::new();
                Some(secret)
            }
            _ => None,
        }
    } else {
        None
    };

    let now = now_unix();
    let entry = Entry {
        id: Uuid::new_v4(),
        title,
        has_username: input.has_username,
        username: if input.has_username {
            input.username.trim().to_string()
        } else {
            String::new()
        },
        password,
        use_default_pin: input.use_default_pin,
        custom_pin: None,
        custom_secret,
        created_at: now,
        updated_at: now,
    };
    let meta = EntryMeta::from(&entry);

    let mut inner = state.inner.lock();
    let s = require_session(&mut inner, &token)?;
    s.data.entries.push(entry);
    persist(&state, s)?;
    Ok(meta)
}

#[tauri::command]
pub async fn delete_entry(
    token: String,
    id: Uuid,
    pin: Option<String>,
    state: State<'_, AppState>,
) -> CmdResult<()> {
    let req = {
        let mut inner = state.inner.lock();
        let s = require_session(&mut inner, &token)?;
        let entry = s
            .data
            .entries
            .iter()
            .find(|e| e.id == id)
            .ok_or(CommandError::NotFound)?;
        authorize_entry_password(entry, &pin)?
    };
    // Discard the plaintext — we just want the PIN gate.
    let _ = resolve_password(req, pin, state.device_secret).await?;

    let mut inner = state.inner.lock();
    let s = require_session(&mut inner, &token)?;
    let pos = s
        .data
        .entries
        .iter()
        .position(|e| e.id == id)
        .ok_or(CommandError::NotFound)?;
    s.data.entries.remove(pos);
    persist(&state, s)
}

#[tauri::command]
pub async fn copy_to_clipboard(
    app: AppHandle,
    token: String,
    id: Uuid,
    field: String, // "password" | "username"
    pin: Option<String>,
) -> CmdResult<()> {
    let state = app.state::<AppState>();
    let (req, username) = {
        let mut inner = state.inner.lock();
        let s = require_session(&mut inner, &token)?;
        let entry = s
            .data
            .entries
            .iter()
            .find(|e| e.id == id)
            .ok_or(CommandError::NotFound)?;
        match field.as_str() {
            "password" => (Some(authorize_entry_password(entry, &pin)?), None),
            "username" => (None, Some(entry.username.clone())),
            _ => return Err(CommandError::BadInput("bad field".into())),
        }
    };
    let value = if let Some(req) = req {
        resolve_password(req, pin, state.device_secret).await?
    } else {
        username.unwrap_or_default()
    };

    app.clipboard()
        .write_text(value.clone())
        .map_err(|e| CommandError::Internal(e.to_string()))?;

    // Schedule auto-clear: only clear if clipboard still contains our value.
    let app2 = app.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(CLIPBOARD_CLEAR_SECS));
        if let Ok(current) = app2.clipboard().read_text() {
            if current == value {
                let _ = app2.clipboard().write_text(String::new());
            }
        }
    });
    Ok(())
}

// ─── Settings (theme + UI scale) ───

#[tauri::command]
pub fn settings_get(state: State<AppState>) -> Settings {
    settings::load_or_default(&state.settings_file)
}

#[tauri::command]
pub fn settings_set(settings_input: Settings, state: State<AppState>) -> CmdResult<Settings> {
    let sanitized = settings_input.sanitize();
    settings::save(&state.settings_file, &sanitized)?;
    Ok(sanitized)
}

// ─── Vault rekey & strength inspection ───

#[derive(Deserialize)]
pub struct RekeyInput {
    /// Current PIN, used to decrypt the existing vault.
    current_pin: String,
    /// Optional new PIN. If `None`/empty, the current PIN is reused.
    new_pin: Option<String>,
    /// One of "interactive" | "moderate" | "sensitive".
    strength: String,
}

#[tauri::command]
pub fn vault_strength(token: String, state: State<AppState>) -> CmdResult<String> {
    let mut inner = state.inner.lock();
    let s = require_session(&mut inner, &token)?;
    let label = if (s.header.opslimit, s.header.memlimit) == KdfStrength::Interactive.params() {
        "interactive"
    } else if (s.header.opslimit, s.header.memlimit) == KdfStrength::Moderate.params() {
        "moderate"
    } else if (s.header.opslimit, s.header.memlimit) == KdfStrength::Sensitive.params() {
        "sensitive"
    } else {
        "unknown"
    };
    Ok(label.to_string())
}

#[tauri::command]
pub async fn vault_rekey(
    token: String,
    input: RekeyInput,
    state: State<'_, AppState>,
) -> CmdResult<UnlockResult> {
    let new_strength = KdfStrength::parse(&input.strength).ok_or(CommandError::UnknownStrength)?;
    let vault_path = state.vault_file.clone();
    {
        let mut inner = state.inner.lock();
        let _ = require_session(&mut inner, &token)?;
    }

    let bytes = read_all(&vault_path)?;
    let cur_secret = SecretString::from(input.current_pin);
    let (_old_header, _old_format, _old_key, mut data) =
        decrypt_from_bytes(&bytes, &cur_secret, &state.device_secret)
            .map_err(|_| CommandError::InvalidPin)?;

    let new_pin_string = match input.new_pin {
        Some(s) if !s.is_empty() => {
            if s.chars().count() < MIN_PIN_LEN {
                return Err(CommandError::PinTooShort { min: MIN_PIN_LEN });
            }
            s
        }
        _ => {
            use secrecy::ExposeSecret;
            cur_secret.expose_secret().to_string()
        }
    };
    let new_secret = SecretString::from(new_pin_string);
    let new_header = VaultHeader::new_with_strength(new_strength);
    let new_key = vault::derive_key(&new_secret, Some(&state.device_secret), &new_header)?;

    let now = now_unix();
    for e in data.entries.iter_mut() {
        e.updated_at = now;
    }

    let new_bytes = encrypt_to_bytes(&data, &new_key, &new_header)?;
    vault::write_vault(&vault_path, &new_bytes)?;

    let session = Session {
        token: make_token(),
        key: new_key,
        header: new_header,
        data,
        expires_at: Instant::now() + Duration::from_secs(SESSION_TTL_SECS),
    };
    let result = unlock_result_from(&session);
    let mut inner = state.inner.lock();
    inner.session = Some(session);
    inner.lockout.record_success();
    let snap = inner.lockout.clone();
    drop(inner);
    persist_lockout(&state, &snap);
    Ok(result)
}
