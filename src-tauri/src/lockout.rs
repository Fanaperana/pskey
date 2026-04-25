//! Persistent lockout state — survives process restarts.
//!
//! Stored as plain JSON in `app_data_dir/lockout.json`. Holds no secrets, just
//! attempt counters and the next-allowed-unlock time (unix seconds).
//!
//! Threshold rules:
//! - Level 0 (no prior lockouts):       up to FIRST_THRESHOLD failures.
//! - Level ≥ 1 (after a lockout):       only POST_LOCKOUT_THRESHOLD failures.
//! - Successful unlock resets level to 0 and clears all counters.
//!
//! Cooldown after each lockout escalates: 1m → 3m → 5m → 10m → 15m → 30m →
//! 1h → 3h → 12h → 24h (cap).

use crate::io_util::{self, now_unix};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LockoutState {
    #[serde(default)]
    pub failed_attempts: u32,
    /// Number of lockouts triggered so far. 0 = pristine.
    #[serde(default)]
    pub lockout_level: u32,
    /// Unix epoch seconds. 0 = not currently locked.
    #[serde(default)]
    pub locked_until_unix: u64,
}

/// Cooldown durations (seconds), indexed by `lockout_level` at the time of
/// the lockout. Last entry repeats indefinitely.
const COOLDOWNS_SECS: &[u64] = &[
    60,     // 1m   (level 0 → first lockout)
    180,    // 3m
    300,    // 5m
    600,    // 10m
    900,    // 15m
    1_800,  // 30m
    3_600,  // 1h
    10_800, // 3h
    43_200, // 12h
    86_400, // 24h (cap)
];

const FIRST_THRESHOLD: u32 = 10;
const POST_LOCKOUT_THRESHOLD: u32 = 3;

impl LockoutState {
    /// How many failed attempts are allowed before the *next* lockout fires,
    /// given the current lockout level.
    pub fn threshold(&self) -> u32 {
        if self.lockout_level == 0 {
            FIRST_THRESHOLD
        } else {
            POST_LOCKOUT_THRESHOLD
        }
    }

    pub fn remaining_lock_secs(&self) -> u64 {
        self.locked_until_unix.saturating_sub(now_unix())
    }

    pub fn is_locked(&self) -> bool {
        self.remaining_lock_secs() > 0
    }

    /// Successful unlock: wipe counters and drop back to fresh threshold.
    pub fn record_success(&mut self) {
        self.failed_attempts = 0;
        self.lockout_level = 0;
        self.locked_until_unix = 0;
    }

    /// Failed unlock. Returns `Some(cooldown_secs)` if this triggered a new
    /// lockout, else `None`.
    pub fn record_failure(&mut self) -> Option<u64> {
        self.failed_attempts = self.failed_attempts.saturating_add(1);
        if self.failed_attempts >= self.threshold() {
            let idx = (self.lockout_level as usize).min(COOLDOWNS_SECS.len() - 1);
            let cooldown = COOLDOWNS_SECS[idx];
            self.locked_until_unix = now_unix().saturating_add(cooldown);
            self.lockout_level = self.lockout_level.saturating_add(1);
            self.failed_attempts = 0;
            Some(cooldown)
        } else {
            None
        }
    }
}

pub fn load(path: &Path) -> LockoutState {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => LockoutState::default(),
    }
}

pub fn save(path: &Path, s: &LockoutState) -> std::io::Result<()> {
    let bytes = serde_json::to_vec_pretty(s)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    io_util::atomic_write(path, &bytes, false)
}

/// Human-readable cooldown for error messages: "45s", "3m", "1h 30m".
pub fn format_wait(secs: u64) -> String {
    if secs >= 3600 {
        let h = secs / 3600;
        let m = (secs % 3600) / 60;
        if m == 0 {
            format!("{}h", h)
        } else {
            format!("{}h {}m", h, m)
        }
    } else if secs >= 60 {
        let m = (secs + 59) / 60;
        format!("{}m", m)
    } else {
        format!("{}s", secs.max(1))
    }
}
