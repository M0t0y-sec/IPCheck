//! IPCheck core.
//!
//! Layering, outermost to innermost:
//!   ui (ts)  ->  commands  ->  aggregator  ->  { probe, source }  ->  http
//!
//! The scoring engine (`score`) is pure: it takes `Signals` and returns numbers.
//! That keeps the part with actual judgement in it unit-testable without a
//! network, and makes it obvious when a change alters how a verdict is reached.

pub mod aggregator;
pub mod cache;
pub mod commands;
pub mod http;
pub mod probe;
pub mod score;
pub mod source;
pub mod tray;
pub mod types;

use std::sync::Arc;
use tokio::sync::RwLock;

/// Shared application state. `last` holds the previous snapshot so we can
/// detect the transitions the card actually needs to react to (IP change,
/// risk band change) rather than re-rendering blindly on every poll.
pub struct AppState {
    pub client: reqwest::Client,
    pub last: RwLock<Option<types::Snapshot>>,
    pub config: RwLock<Config>,
}

impl AppState {
    pub fn new() -> anyhow::Result<Arc<Self>> {
        Ok(Arc::new(Self {
            client: http::client()?,
            last: RwLock::new(None),
            config: RwLock::new(Config::default()),
        }))
    }
}

/// User-tunable settings. API keys are optional by design: every keyed source
/// has a documented degraded path when its key is absent, so the tool works
/// out of the box and gets sharper as keys are added.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    pub refresh_seconds: u64,
    pub abuseipdb_key: String,
    pub scamalytics_key: String,
    pub ipqs_key: String,
    pub enable_dnsbl: bool,
    pub enable_stun: bool,
    pub enable_sources: bool,
    /// Free-form label the user gives the current line, e.g. "US-Residential-3".
    pub label: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            refresh_seconds: 300,
            abuseipdb_key: String::new(),
            scamalytics_key: String::new(),
            ipqs_key: String::new(),
            enable_dnsbl: true,
            enable_stun: true,
            enable_sources: true,
            label: String::new(),
        }
    }
}

impl Config {
    /// Where the config lives: `%APPDATA%/<bundle-id>/config.json` on Windows.
    fn path(app: &tauri::AppHandle) -> Option<std::path::PathBuf> {
        use tauri::Manager;
        app.path().app_config_dir().ok().map(|d| d.join("config.json"))
    }

    /// Load persisted settings, falling back to defaults. A corrupt or missing
    /// file is not an error worth surfacing: defaults are always usable.
    pub fn load(app: &tauri::AppHandle) -> Self {
        Self::path(app)
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    /// Persist settings. Deliberately best-effort: failing to write a config
    /// file must not stop the app or lose the in-memory value the user just
    /// set for this session.
    pub fn save(&self, app: &tauri::AppHandle) {
        let Some(path) = Self::path(app) else {
            return;
        };
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(path, json);
        }
    }
}
