//! Tauri state & commands — keeps secrets in Rust, exposes only metadata to JS.

use crate::vault::{
    atomic_write, decrypt_from_bytes, encrypt_to_bytes, hash_entry_pin, read_all,
    verify_entry_pin, Entry, EntryMeta, VaultData, VaultHeader,
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
const MAX_ATTEMPTS_BEFORE_BACKOFF: u32 = 3;

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
    failed_attempts: u32,
    locked_until: Option<Instant>,
}

pub struct AppState {
    inner: Mutex<Inner>,
    vault_file: PathBuf,
}

impl AppState {
    pub fn new(vault_file: PathBuf) -> Self {
        Self {
            inner: Mutex::new(Inner {
                session: None,
                failed_attempts: 0,
                locked_until: None,
            }),
            vault_file,
        }
    }
}

#[derive(Serialize)]
pub struct UnlockResult {
    token: String,
    expires_in_ms: u64,
    entries: Vec<EntryMeta>,
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

// ─── Commands ───

#[tauri::command]
pub fn vault_exists(state: State<AppState>) -> bool {
    state.vault_file.exists()
}

#[tauri::command]
pub fn vault_init(pin: String, state: State<AppState>) -> Result<UnlockResult, String> {
    if state.vault_file.exists() {
        return Err("vault already exists".into());
    }
    if pin.is_empty() {
        return Err("pin required".into());
    }
    let header = VaultHeader::new_random();
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
    inner.failed_attempts = 0;
    inner.locked_until = None;
    Ok(result)
}

#[tauri::command]
pub fn vault_unlock(pin: String, state: State<AppState>) -> Result<UnlockResult, String> {
    {
        let inner = state.inner.lock();
        if let Some(until) = inner.locked_until {
            if Instant::now() < until {
                let remaining = until.saturating_duration_since(Instant::now()).as_secs();
                return Err(format!("too many attempts; wait {}s", remaining.max(1)));
            }
        }
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
            inner.failed_attempts = 0;
            inner.locked_until = None;
            Ok(result)
        }
        Err(_) => {
            let mut inner = state.inner.lock();
            inner.failed_attempts = inner.failed_attempts.saturating_add(1);
            if inner.failed_attempts >= MAX_ATTEMPTS_BEFORE_BACKOFF {
                let extra = inner.failed_attempts - MAX_ATTEMPTS_BEFORE_BACKOFF;
                let backoff = Duration::from_secs(2u64.saturating_pow(extra.min(6)));
                inner.locked_until = Some(Instant::now() + backoff);
            }
            Err("invalid pin".into())
        }
    }
}

#[tauri::command]
pub fn vault_lock(state: State<AppState>) {
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
pub fn vault_unlock_challenge(
    input: ChallengeUnlockInput,
    state: State<AppState>,
) -> Result<UnlockResult, String> {
    {
        let inner = state.inner.lock();
        if let Some(until) = inner.locked_until {
            if Instant::now() < until {
                let remaining = until.saturating_duration_since(Instant::now()).as_secs();
                return Err(format!("too many attempts; wait {}s", remaining.max(1)));
            }
        }
    }
    if !state.vault_file.exists() {
        return Err("vault does not exist".into());
    }
    let candidates = candidates_from_challenge(&input.challenge, &input.response)?;
    let bytes = read_all(&state.vault_file).map_err(|e| e.to_string())?;

    for pin in candidates {
        let pin_secret = SecretString::from(pin);
        if let Ok((header, key, data)) = decrypt_from_bytes(&bytes, &pin_secret) {
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
            inner.failed_attempts = 0;
            inner.locked_until = None;
            return Ok(result);
        }
    }

    let mut inner = state.inner.lock();
    inner.failed_attempts = inner.failed_attempts.saturating_add(1);
    if inner.failed_attempts >= MAX_ATTEMPTS_BEFORE_BACKOFF {
        let extra = inner.failed_attempts - MAX_ATTEMPTS_BEFORE_BACKOFF;
        let backoff = Duration::from_secs(2u64.saturating_pow(extra.min(6)));
        inner.locked_until = Some(Instant::now() + backoff);
    }
    Err("invalid pin".into())
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

fn authorize_entry(entry: &Entry, pin: &Option<String>, global_unlocked: bool) -> Result<(), String> {
    if entry.use_default_pin {
        // Global session already verified — the main unlock IS the default-PIN check.
        if global_unlocked {
            return Ok(());
        }
        return Err("locked".into());
    }
    match (&entry.custom_pin, pin) {
        (None, _) => Ok(()),
        (Some(_), None) => Err("pin required".into()),
        (Some(h), Some(p)) => {
            if verify_entry_pin(h, p) {
                Ok(())
            } else {
                Err("invalid pin".into())
            }
        }
    }
}

#[tauri::command]
pub fn get_entry_secret(
    token: String,
    id: Uuid,
    pin: Option<String>,
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
    authorize_entry(entry, &pin, true)?;
    Ok(entry.password.clone())
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
pub fn add_entry(
    token: String,
    input: AddEntryInput,
    state: State<AppState>,
) -> Result<EntryMeta, String> {
    let title = input.title.trim().to_string();
    if title.is_empty() {
        return Err("title required".into());
    }
    let custom = if !input.use_default_pin {
        match input.custom_pin.as_ref() {
            Some(p) if !p.is_empty() => Some(hash_entry_pin(p).map_err(|e| e.to_string())?),
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
pub fn delete_entry(
    token: String,
    id: Uuid,
    pin: Option<String>,
    state: State<AppState>,
) -> Result<(), String> {
    let mut inner = state.inner.lock();
    let s = require_session(&mut inner, &token)?;
    let pos = s
        .data
        .entries
        .iter()
        .position(|e| e.id == id)
        .ok_or_else(|| "not found".to_string())?;
    authorize_entry(&s.data.entries[pos], &pin, true)?;
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
    let value = {
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
                authorize_entry(entry, &pin, true)?;
                entry.password.clone()
            }
            "username" => entry.username.clone(),
            _ => return Err("bad field".into()),
        }
    };

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
