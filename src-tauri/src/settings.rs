//! User preferences (theme, UI scale) persisted as `settings.json` in app data dir.
//!
//! Non-secret config — plain JSON, atomically written, auto-created with defaults.

use crate::io_util;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Settings {
    #[serde(default = "default_theme")]
    pub theme: String,
    #[serde(default = "default_scale")]
    pub ui_scale: f32,
    /// KDF strength applied to *new* vaults (and to the entry-PIN hashes
    /// inside the live vault). Existing vaults keep the strength stored in
    /// their own header until rekeyed.
    #[serde(default = "default_kdf")]
    pub kdf_strength: String,
}

fn default_theme() -> String {
    "default".to_string()
}
fn default_scale() -> f32 {
    1.2
}
fn default_kdf() -> String {
    "interactive".to_string()
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            theme: default_theme(),
            ui_scale: default_scale(),
            kdf_strength: default_kdf(),
        }
    }
}

const ALLOWED_THEMES: &[&str] = &["default", "midnight", "forest", "mocha", "rose"];
const ALLOWED_SCALES: &[f32] = &[0.9, 1.0, 1.1, 1.2, 1.35, 1.5];
const ALLOWED_KDF: &[&str] = &["interactive", "moderate", "sensitive"];

impl Settings {
    /// Clamp values to known-good options so a hand-edited file can't break the UI.
    pub fn sanitize(mut self) -> Self {
        if !ALLOWED_THEMES.contains(&self.theme.as_str()) {
            self.theme = default_theme();
        }
        if !ALLOWED_SCALES
            .iter()
            .any(|s| (s - self.ui_scale).abs() < 1e-3)
        {
            self.ui_scale = default_scale();
        }
        if !ALLOWED_KDF.contains(&self.kdf_strength.as_str()) {
            self.kdf_strength = default_kdf();
        }
        self
    }
}

pub fn load_or_default(path: &Path) -> Settings {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice::<Settings>(&bytes)
            .unwrap_or_default()
            .sanitize(),
        Err(_) => {
            let s = Settings::default();
            let _ = save(path, &s);
            s
        }
    }
}

pub fn save(path: &Path, settings: &Settings) -> std::io::Result<()> {
    let bytes = serde_json::to_vec_pretty(settings)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    io_util::atomic_write(path, &bytes, false)
}
