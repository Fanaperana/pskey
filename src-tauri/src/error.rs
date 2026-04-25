//! Tagged error type returned to the JS bridge.
//!
//! Replaces the previous `Result<_, String>` everywhere so the frontend gets
//! a discriminable kind plus a human-readable message, and so callers can use
//! `?` instead of stringly-typed `.map_err(|e| e.to_string())` boilerplate.

use crate::vault::VaultError;
use serde::Serialize;

#[derive(Debug, thiserror::Error, Serialize)]
#[serde(tag = "kind", content = "message", rename_all = "kebab-case")]
pub enum CommandError {
    #[error("vault is locked")]
    Locked,
    #[error("session token rejected")]
    InvalidToken,
    #[error("session expired")]
    SessionExpired,
    #[error("entry not found")]
    NotFound,
    #[error("invalid PIN")]
    InvalidPin,
    #[error("PIN must be at least {min} characters")]
    PinTooShort { min: usize },
    #[error("PIN required")]
    PinRequired,
    #[error("vault already exists")]
    VaultAlreadyExists,
    #[error("vault does not exist")]
    VaultMissing,
    #[error("too many attempts; wait {wait}")]
    LockedOut { wait: String },
    #[error("invalid input: {0}")]
    BadInput(String),
    #[error("unknown KDF strength")]
    UnknownStrength,
    #[error("internal error: {0}")]
    Internal(String),
}

impl From<VaultError> for CommandError {
    fn from(e: VaultError) -> Self {
        match e {
            VaultError::Decrypt => CommandError::InvalidPin,
            VaultError::AlreadyExists => CommandError::VaultAlreadyExists,
            VaultError::NotFound => CommandError::VaultMissing,
            other => CommandError::Internal(other.to_string()),
        }
    }
}

impl From<std::io::Error> for CommandError {
    fn from(e: std::io::Error) -> Self {
        CommandError::Internal(e.to_string())
    }
}

impl From<tauri::Error> for CommandError {
    fn from(e: tauri::Error) -> Self {
        CommandError::Internal(e.to_string())
    }
}

pub type CmdResult<T> = std::result::Result<T, CommandError>;
