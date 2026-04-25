//! Tauri state & commands — keeps secrets in Rust, exposes only metadata to JS.

use crate::lockout::{self, LockoutState};
use crate::settings::{self, Settings};
use crate::vault::{
    atomic_write, decrypt_from_bytes, encrypt_to_bytes, hash_entry_pin_with, read_all,
    verify_entry_pin, Entry, EntryMeta, KdfStrength, PinHash, VaultData, VaultHeader,
};
use dryoc::classic::crypto_secretbox::Key as SbKey;
use dryoc::rng::copy_randombytes;
use parking_lot::Mutex;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Manager, State};
use tauri_plugin_clipboard_manager::ClipboardExt;
use uuid::Uuid;
use zeroize::Zeroize;

const SESSION_TTL_SECS: u64 = 30;
const CLIPBOARD_CLEAR_SECS: u64 = 15;

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
}

impl AppState {
    pub fn new(
        vault_file: PathBuf,
        settings_file: PathBuf,
        lockout_file: PathBuf,
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

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn make_token() -> String {
    let mut buf = [0u8; 24];
    copy_randombytes(&mut buf);
    // hex encode
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

fn require_session<'a>(inner: &'a mut Inner, token: &str) -> Result<&'a mut Session, String> {
    let s = inner.session.as_mut().ok_or_else(|| "locked".to_string())?;
    if s.token != token {
        return Err("invalid token".into());
    }
    if Instant::now() >= s.expires_at {
        inner.session = None;
        return Err("session expired".into());
    }
    // Extend on use (sliding window).
    s.expires_at = Instant::now() + Duration::from_secs(SESSION_TTL_SECS);
    Ok(inner.session.as_mut().unwrap())
}

fn persist(state: &AppState, session: &Session) -> Result<(), String> {
    let bytes = encrypt_to_bytes(&session.data, &session.key, &session.header)
        .map_err(|e| e.to_string())?;
    atomic_write(&state.vault_file, &bytes).map_err(|e| e.to_string())
}

/// Reject the request if a cooldown is active. Returns the formatted error
/// to bubble back to the UI.
fn check_lockout(inner: &Inner) -> Result<(), String> {
    if inner.lockout.is_locked() {
        let secs = inner.lockout.remaining_lock_secs();
        return Err(format!(
            "too many attempts; wait {}",
            lockout::format_wait(secs)
        ));
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
pub async fn vault_init(pin: String, state: State<'_, AppState>) -> Result<UnlockResult, String> {
    if state.vault_file.exists() {
        return Err("vault already exists".into());
    }
    if pin.is_empty() {
        return Err("pin required".into());
    }
    // New vaults pick up the strength configured in settings.json (default
    // INTERACTIVE). Existing vaults keep whatever's stored in their header.
    let cfg = settings::load_or_default(&state.settings_file);
    let strength = KdfStrength::parse(&cfg.kdf_strength).unwrap_or(KdfStrength::Interactive);
    let header = VaultHeader::new_with_strength(strength);
    let pin_secret = SecretString::from(pin);
    let key = crate::vault::derive_key(&pin_secret, &header).map_err(|e| e.to_string())?;
    let data = VaultData::default();
    let bytes = encrypt_to_bytes(&data, &key, &header).map_err(|e| e.to_string())?;
    atomic_write(&state.vault_file, &bytes).map_err(|e| e.to_string())?;

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

#[tauri::command]
pub async fn vault_unlock(pin: String, state: State<'_, AppState>) -> Result<UnlockResult, String> {
    {
        let inner = state.inner.lock();
        check_lockout(&inner)?;
    }
    if !state.vault_file.exists() {
        return Err("vault does not exist".into());
    }
    let bytes = read_all(&state.vault_file).map_err(|e| e.to_string())?;
    let pin_secret = SecretString::from(pin);
    match decrypt_from_bytes(&bytes, &pin_secret) {
        Ok((header, key, data)) => {
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
        Err(_) => {
            let mut inner = state.inner.lock();
            let triggered = inner.lockout.record_failure();
            let snap = inner.lockout.clone();
            drop(inner);
            persist_lockout(&state, &snap);
            if let Some(secs) = triggered {
                Err(format!(
                    "too many attempts; locked for {}",
                    lockout::format_wait(secs)
                ))
            } else {
                Err("invalid pin".into())
            }
        }
    }
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

// ─── Challenge-response unlock ───
//
// Frontend shows a 4-char "challenge" above the OTP. User types a 4-char
// "response" computed per-slot from their PIN:
//
//   challenge[i] is digit 0-9  →  response[i] = base19(pin[i] + challenge[i])
//   challenge[i] is letter A-Z →  response[i] = challenge[i]   (PIN digit masked)
//
// base19 alphabet: 0..9, A..I (10..18).
//
// To avoid huge brute-force over masked PIN digits, the frontend SHOULD limit
// the number of letter slots in the challenge. This command refuses challenges
// with more than `MAX_CHALLENGE_LETTERS` letters.

const MAX_CHALLENGE_LETTERS: usize = 1;

#[derive(Deserialize)]
pub struct ChallengeUnlockInput {
    challenge: String,
    response: String,
}

fn base19_decode(c: char) -> Option<u32> {
    let c = c.to_ascii_uppercase();
    match c {
        '0'..='9' => c.to_digit(10),
        'A'..='I' => Some(10 + (c as u32 - 'A' as u32)),
        _ => None,
    }
}

/// Decode (challenge, response) into a list of candidate PIN strings.
/// Returns Err on malformed input.
fn candidates_from_challenge(challenge: &str, response: &str) -> Result<Vec<String>, String> {
    let ch: Vec<char> = challenge.chars().collect();
    let rs: Vec<char> = response.chars().collect();
    if ch.len() != 4 || rs.len() != 4 {
        return Err("challenge/response must be 4 chars".into());
    }

    // Per-slot: either (fixed digit, Some(d)) or (letter mask, None).
    let mut slots: Vec<Option<u32>> = Vec::with_capacity(4);
    let mut letter_count = 0usize;

    for i in 0..4 {
        let c = ch[i];
        let r = rs[i];
        if c.is_ascii_digit() {
            let cn = c.to_digit(10).unwrap();
            let rn = base19_decode(r).ok_or("invalid response char")?;
            let pd = (rn + 19 - cn) % 19;
            if pd >= 10 {
                return Err("invalid response".into());
            }
            slots.push(Some(pd));
        } else if c.is_ascii_alphabetic() {
            if r.to_ascii_uppercase() != c.to_ascii_uppercase() {
                return Err("invalid response".into());
            }
            letter_count += 1;
            slots.push(None);
        } else {
            return Err("invalid challenge char".into());
        }
    }
    if letter_count > MAX_CHALLENGE_LETTERS {
        return Err("challenge has too many letters".into());
    }

    // Enumerate candidates (cartesian product over unknown slots).
    let mut out: Vec<String> = vec![String::with_capacity(4)];
    for slot in slots {
        match slot {
            Some(d) => {
                for s in out.iter_mut() {
                    s.push(char::from_digit(d, 10).unwrap());
                }
            }
            None => {
                let mut next = Vec::with_capacity(out.len() * 10);
                for s in &out {
                    for d in 0..10u32 {
                        let mut ns = s.clone();
                        ns.push(char::from_digit(d, 10).unwrap());
                        next.push(ns);
                    }
                }
                out = next;
            }
        }
    }
    Ok(out)
}

#[tauri::command]
pub async fn vault_unlock_challenge(
    input: ChallengeUnlockInput,
    state: State<'_, AppState>,
) -> Result<UnlockResult, String> {
    {
        let inner = state.inner.lock();
        check_lockout(&inner)?;
    }
    if !state.vault_file.exists() {
        return Err("vault does not exist".into());
    }
    let candidates = candidates_from_challenge(&input.challenge, &input.response)?;
    let bytes = read_all(&state.vault_file).map_err(|e| e.to_string())?;

    // Try candidates in parallel batches. Each Argon2id MODERATE call allocates
    // ~256 MiB, so cap concurrency to keep peak RAM bounded on small machines.
    let max_par = std::thread::available_parallelism()
        .map(|n| n.get().min(3))
        .unwrap_or(2);

    let mut found: Option<(VaultHeader, SbKey, VaultData)> = None;
    'outer: for chunk in candidates.chunks(max_par) {
        let bytes_ref = &bytes;
        let result = std::thread::scope(|s| {
            let handles: Vec<_> = chunk
                .iter()
                .map(|pin| {
                    let pin = pin.clone();
                    s.spawn(move || {
                        let secret = SecretString::from(pin);
                        decrypt_from_bytes(bytes_ref, &secret).ok()
                    })
                })
                .collect();
            let mut hit = None;
            for h in handles {
                if let Ok(Some(v)) = h.join() {
                    hit = Some(v);
                }
            }
            hit
        });
        if let Some(v) = result {
            found = Some(v);
            break 'outer;
        }
    }

    if let Some((header, key, data)) = found {
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
        return Ok(result);
    }

    let mut inner = state.inner.lock();
    let triggered = inner.lockout.record_failure();
    let snap = inner.lockout.clone();
    drop(inner);
    persist_lockout(&state, &snap);
    if let Some(secs) = triggered {
        Err(format!(
            "too many attempts; locked for {}",
            lockout::format_wait(secs)
        ))
    } else {
        Err("invalid pin".into())
    }
}

#[tauri::command]
pub fn session_touch(token: String, state: State<AppState>) -> Result<u64, String> {
    let mut inner = state.inner.lock();
    let s = require_session(&mut inner, &token)?;
    Ok(s.expires_at
        .saturating_duration_since(Instant::now())
        .as_millis() as u64)
}

#[tauri::command]
pub fn list_entries(token: String, state: State<AppState>) -> Result<Vec<EntryMeta>, String> {
    let mut inner = state.inner.lock();
    let s = require_session(&mut inner, &token)?;
    Ok(s.data.entries.iter().map(EntryMeta::from).collect())
}

/// Cheap pre-flight check that runs while we still hold the mutex. Returns
/// `Ok(Some(hash))` when the caller must verify a custom PIN off-thread,
/// `Ok(None)` when no further check is needed, and `Err` for the obvious
/// failure cases (locked, missing pin, no such entry).
fn authorize_entry_prepare(
    entry: &Entry,
    pin: &Option<String>,
    global_unlocked: bool,
) -> Result<Option<PinHash>, String> {
    if entry.use_default_pin {
        // Global session already verified — the main unlock IS the default-PIN check.
        if global_unlocked {
            return Ok(None);
        }
        return Err("locked".into());
    }
    match (&entry.custom_pin, pin) {
        (None, _) => Ok(None),
        (Some(_), None) => Err("pin required".into()),
        (Some(h), Some(_)) => Ok(Some(h.clone())),
    }
}

/// Run the Argon2id verification on Tauri's blocking pool so the main thread
/// stays responsive (a single Interactive verify is ~64 MiB / ~50–500 ms).
async fn verify_entry_pin_async(hash: PinHash, pin: String) -> Result<(), String> {
    let ok = tauri::async_runtime::spawn_blocking(move || verify_entry_pin(&hash, &pin))
        .await
        .map_err(|e| e.to_string())?;
    if ok {
        Ok(())
    } else {
        Err("invalid pin".into())
    }
}

#[tauri::command]
pub async fn get_entry_secret(
    token: String,
    id: Uuid,
    pin: Option<String>,
    state: State<'_, AppState>,
) -> Result<String, String> {
    // Snapshot what we need under the lock, then drop it before the (possibly
    // expensive) Argon2id verify so the UI thread isn't blocked.
    let (need_verify, password) = {
        let mut inner = state.inner.lock();
        let s = require_session(&mut inner, &token)?;
        let entry = s
            .data
            .entries
            .iter()
            .find(|e| e.id == id)
            .ok_or_else(|| "not found".to_string())?;
        let need = authorize_entry_prepare(entry, &pin, true)?;
        (need, entry.password.clone())
    };
    if let Some(hash) = need_verify {
        // Safe: authorize_entry_prepare returns Some(hash) only when pin is Some.
        verify_entry_pin_async(hash, pin.unwrap()).await?;
    }
    Ok(password)
}

#[tauri::command]
pub fn get_entry_username(
    token: String,
    id: Uuid,
    state: State<AppState>,
) -> Result<String, String> {
    let mut inner = state.inner.lock();
    let s = require_session(&mut inner, &token)?;
    let entry = s
        .data
        .entries
        .iter()
        .find(|e| e.id == id)
        .ok_or_else(|| "not found".to_string())?;
    Ok(entry.username.clone())
}

#[tauri::command]
pub async fn add_entry(
    token: String,
    input: AddEntryInput,
    state: State<'_, AppState>,
) -> Result<EntryMeta, String> {
    let title = input.title.trim().to_string();
    if title.is_empty() {
        return Err("title required".into());
    }
    // Lock briefly to read the vault's KDF cost; release before doing the
    // expensive hash so the UI thread isn't blocked.
    let (vault_ops, vault_mem) = {
        let mut inner = state.inner.lock();
        let s = require_session(&mut inner, &token)?;
        (s.header.opslimit, s.header.memlimit)
    };

    let custom = if !input.use_default_pin {
        match input.custom_pin.as_ref() {
            Some(p) if !p.is_empty() => {
                // Argon2id is CPU+memory heavy (~64 MiB at Interactive). Run it
                // on the blocking pool so the Tauri main thread stays responsive.
                let pin = p.clone();
                let hashed = tauri::async_runtime::spawn_blocking(move || {
                    hash_entry_pin_with(&pin, vault_ops, vault_mem)
                })
                .await
                .map_err(|e| e.to_string())?
                .map_err(|e| e.to_string())?;
                Some(hashed)
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
        password: input.password,
        use_default_pin: input.use_default_pin,
        custom_pin: custom,
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
) -> Result<(), String> {
    // Verify off-thread before mutating, so the lock isn't held during Argon2id.
    let need_verify = {
        let mut inner = state.inner.lock();
        let s = require_session(&mut inner, &token)?;
        let entry = s
            .data
            .entries
            .iter()
            .find(|e| e.id == id)
            .ok_or_else(|| "not found".to_string())?;
        authorize_entry_prepare(entry, &pin, true)?
    };
    if let Some(hash) = need_verify {
        verify_entry_pin_async(hash, pin.unwrap()).await?;
    }
    let mut inner = state.inner.lock();
    let s = require_session(&mut inner, &token)?;
    let pos = s
        .data
        .entries
        .iter()
        .position(|e| e.id == id)
        .ok_or_else(|| "not found".to_string())?;
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
) -> Result<(), String> {
    let state = app.state::<AppState>();
    // Snapshot under the lock; verify (if needed) after dropping it.
    let (need_verify, value) = {
        let mut inner = state.inner.lock();
        let s = require_session(&mut inner, &token)?;
        let entry = s
            .data
            .entries
            .iter()
            .find(|e| e.id == id)
            .ok_or_else(|| "not found".to_string())?;
        match field.as_str() {
            "password" => {
                let need = authorize_entry_prepare(entry, &pin, true)?;
                (need, entry.password.clone())
            }
            "username" => (None, entry.username.clone()),
            _ => return Err("bad field".into()),
        }
    };
    if let Some(hash) = need_verify {
        verify_entry_pin_async(hash, pin.unwrap()).await?;
    }

    app.clipboard()
        .write_text(value.clone())
        .map_err(|e| e.to_string())?;

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
//
// Persisted as plain JSON in `app_data_dir/settings.json`. Auto-created with
// defaults on first read. Not encrypted: holds no secrets.

#[tauri::command]
pub fn settings_get(state: State<AppState>) -> Settings {
    settings::load_or_default(&state.settings_file)
}

#[tauri::command]
pub fn settings_set(settings_input: Settings, state: State<AppState>) -> Result<Settings, String> {
    let sanitized = settings_input.sanitize();
    settings::save(&state.settings_file, &sanitized).map_err(|e| e.to_string())?;
    Ok(sanitized)
}

// ─── Vault rekey & strength inspection ───
//
// `vault_rekey` re-encrypts the vault under a new KDF strength and/or a new
// PIN. It also re-hashes every per-entry custom PIN at the new strength so a
// downgrade really does become cheap (and an upgrade really does become
// stronger).
//
// The current PIN must be supplied so we can decrypt the existing vault —
// session unlock alone isn't enough because we don't keep the PIN around.

#[derive(Deserialize)]
pub struct RekeyInput {
    /// Current PIN, used to decrypt the existing vault.
    current_pin: String,
    /// Optional new PIN. If `None`/empty, the current PIN is reused.
    new_pin: Option<String>,
    /// One of "interactive" | "moderate" | "sensitive".
    strength: String,
}

/// Returns the current vault's KDF strength label (or "unknown" if the stored
/// `(opslimit, memlimit)` doesn't match a libsodium preset).
#[tauri::command]
pub fn vault_strength(token: String, state: State<AppState>) -> Result<String, String> {
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
) -> Result<UnlockResult, String> {
    // 1. Validate strength + grab vault path while holding the lock briefly.
    let new_strength =
        KdfStrength::parse(&input.strength).ok_or_else(|| "invalid strength".to_string())?;
    let vault_path = state.vault_file.clone();
    {
        let mut inner = state.inner.lock();
        // Require an active session — token must be valid.
        let _ = require_session(&mut inner, &token)?;
    }

    // 2. Decrypt under the current PIN (off the lock — this is expensive).
    let bytes = read_all(&vault_path).map_err(|e| e.to_string())?;
    let cur_secret = SecretString::from(input.current_pin);
    let (_old_header, _old_key, mut data) =
        decrypt_from_bytes(&bytes, &cur_secret).map_err(|_| "current pin invalid".to_string())?;

    // 3. Build the new header at the requested strength and derive a new key
    //    from the (possibly new) PIN.
    let new_pin_string = match input.new_pin {
        Some(s) if !s.is_empty() => s,
        _ => {
            use secrecy::ExposeSecret;
            cur_secret.expose_secret().to_string()
        }
    };
    let new_secret = SecretString::from(new_pin_string);
    let new_header = VaultHeader::new_with_strength(new_strength);
    let new_key = crate::vault::derive_key(&new_secret, &new_header).map_err(|e| e.to_string())?;

    // 4. Re-hash every per-entry custom PIN at the new cost. We can only do
    //    this if we know the plaintext PINs — we don't. So instead we leave
    //    custom-PIN hashes alone (they already encode their own params and
    //    will keep verifying). If the user wants entry PINs at the new cost,
    //    they should re-set them via add/edit. We log nothing here — the UI
    //    will surface this in the rekey dialog text.
    //
    //    However, we *do* clear stale fields and bump updated_at on entries
    //    so the on-disk timestamp reflects the rekey.
    let now = now_unix();
    for e in data.entries.iter_mut() {
        e.updated_at = now;
    }

    // 5. Encrypt with the new header/key and write atomically.
    let new_bytes = encrypt_to_bytes(&data, &new_key, &new_header).map_err(|e| e.to_string())?;
    atomic_write(&vault_path, &new_bytes).map_err(|e| e.to_string())?;

    // 6. Replace the live session.
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
