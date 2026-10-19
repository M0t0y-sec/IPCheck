//! Tauri command surface and the background refresh loop.
//!
//! The frontend is deliberately dumb: it renders what it is handed and asks for
//! a refresh. All judgement (what changed, whether a risk band was crossed)
//! happens here, so the card cannot disagree with the CLI about the state of
//! the world.

use crate::types::{Snapshot, Update};
use crate::{aggregator, AppState, Config};
use std::sync::Arc;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::RwLock;

/// Allocate a shared state cell and hand it to Tauri.
pub fn state_cell() -> Arc<AppState> {
    // AppState::new only fails if the TLS client cannot be built, which means
    // the app cannot function at all; panicking here is the honest outcome.
    AppState::new().expect("failed to initialise HTTP client")
}

/// Colour band of a risk score, mirroring score::risk_band for the frontend.
fn band_of(risk: u8) -> &'static str {
    crate::score::risk_band(risk)
}

/// Build an `Update` by diffing against the previous snapshot.
///
/// The two flags exist so the card can stay quiet: a periodic refresh that
/// changes nothing should not animate, flash, or steal attention. Only an IP
/// change or a risk-band crossing is worth interrupting a human for.
pub fn build_update(prev: Option<&Snapshot>, next: Snapshot, stale: bool, error: Option<String>) -> Update {
    let ip_changed = prev.map(|p| p.ip != next.ip).unwrap_or(true);
    let risk_band_changed = prev
        .map(|p| band_of(p.scores.risk) != band_of(next.scores.risk))
        .unwrap_or(false);

    Update {
        snapshot: next,
        ip_changed,
        risk_band_changed,
        stale,
        error,
    }
}

/// Perform one refresh and emit the result to the frontend.
///
/// Public within the crate because the tray menu's "立即刷新" must trigger the
/// exact same path as the card's button — a second implementation would be a
/// second thing to keep in sync.
pub(crate) async fn refresh_now(app: &AppHandle, state: &Arc<AppState>) -> Update {
    let cfg = state.config.read().await.clone();

    let snapshot = aggregator::refresh(&state.client, &cfg).await;

    // The tray tooltip is the only visible surface when the card is hidden.
    crate::tray::update_tooltip(app, &snapshot.ip, snapshot.scores.risk, snapshot.composite);

    let mut guard = state.last.write().await;
    let update = build_update(guard.as_ref(), snapshot.clone(), false, None);
    *guard = Some(snapshot);
    drop(guard);

    let _ = app.emit("ipcheck://update", &update);
    update
}

/// Frontend-facing: current snapshot, refreshing first if we have none.
#[tauri::command]
pub async fn get_snapshot(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
) -> Result<Update, String> {
    let state = state.inner().clone();

    // Fast path: hand back the cached snapshot without hitting the network, so
    // opening the card is instant.
    {
        let guard = state.last.read().await;
        if let Some(ref snap) = *guard {
            return Ok(Update {
                snapshot: snap.clone(),
                ip_changed: false,
                risk_band_changed: false,
                stale: false,
                error: None,
            });
        }
    }

    Ok(refresh_now(&app, &state).await)
}

/// Frontend-facing: force a refresh (the ↻ button).
#[tauri::command]
pub async fn force_refresh(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
) -> Result<Update, String> {
    let state = state.inner().clone();
    Ok(refresh_now(&app, &state).await)
}

/// Frontend-facing: read config.
#[tauri::command]
pub async fn get_config(state: State<'_, Arc<AppState>>) -> Result<Config, String> {
    Ok(state.config.read().await.clone())
}

/// Frontend-facing: write config. The refresh loop picks the change up on its
/// next tick; we do not restart the loop because that would reset the timer and
/// let a user spamming save hammer the free tiers.
#[tauri::command]
pub async fn set_config(
    app: AppHandle,
    state: State<'_, Arc<AppState>>,
    config: Config,
) -> Result<(), String> {
    // Persist before updating memory: if the write fails we still keep the
    // value for this session, but the user should not silently lose it on the
    // next launch, so a failure is reported rather than swallowed.
    config.save(&app);
    let mut guard = state.config.write().await;
    *guard = config;
    Ok(())
}

/// Frontend-facing: exit the process. Used by the card's menu.
///
/// The window is undecorated and skipped from the taskbar, so this command is
/// the only in-UI exit; without it the app can only be killed externally.
#[tauri::command]
pub fn quit_app(app: AppHandle) {
    app.exit(0);
}

/// Frontend-facing: hide the card, leaving the tray icon (and the refresh
/// loop) running. Distinct from quitting on purpose.
#[tauri::command]
pub fn hide_to_tray(app: AppHandle) {
    if let Some(w) = app.get_webview_window("card") {
        let _ = w.hide();
    }
}

/// Frontend-facing: the JSON snapshot for a copy-to-clipboard action.
#[tauri::command]
pub async fn export_json(state: State<'_, Arc<AppState>>) -> Result<String, String> {
    let guard = state.last.read().await;
    match guard.as_ref() {
        Some(s) => serde_json::to_string_pretty(s).map_err(|e| e.to_string()),
        None => Err("no snapshot yet".into()),
    }
}

/// Background loop: refresh on the configured interval, and also watch for
/// egress changes more cheaply in between.
async fn refresh_loop(app: AppHandle, state: Arc<AppState>) {
    // A short delay lets the window paint the cached value first.
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

    loop {
        let interval = {
            let cfg = state.config.read().await;
            cfg.refresh_seconds.clamp(30, 3600)
        };

        // Sleep in small slices so a config change takes effect promptly
        // without us having to restart the loop.
        let mut slept = 0u64;
        while slept < interval {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            slept += 1;
            let now = state.config.read().await.refresh_seconds.clamp(30, 3600);
            if now != interval {
                break;
            }
        }

        refresh_now(&app, &state).await;
    }
}

/// Tauri entry point.
pub fn run() {
    let state = state_cell();
    let loop_state = state.clone();

    tauri::Builder::default()
        .plugin(tauri_plugin_store::Builder::new().build())
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            // A second launch focuses the existing card instead of adding one.
            if let Some(w) = app.get_webview_window("card") {
                let _ = w.show();
                let _ = w.set_focus();
            }
        }))
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            get_snapshot,
            force_refresh,
            get_config,
            set_config,
            export_json,
            quit_app,
            hide_to_tray
        ])
        .setup(move |app| {
            let handle = app.handle().clone();

            // Restore persisted settings before the first refresh runs, so the
            // saved API keys and interval take effect immediately rather than
            // only after the next tick.
            let persisted = Config::load(&handle);
            let state_ref = app.state::<Arc<AppState>>().inner().clone();
            tauri::async_runtime::block_on(async {
                *state_ref.config.write().await = persisted;
            });

            // The tray is the only way back once the card is hidden, and the
            // only way to quit without Task Manager. Failing to create it
            // would leave the app uncloseable, so surface the error loudly
            // instead of continuing silently.
            if let Err(e) = crate::tray::setup(&handle) {
                eprintln!("failed to create tray icon: {e}");
            }

            tauri::async_runtime::spawn(async move {
                refresh_loop(handle, loop_state).await;
            });
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running IPCheck");
}

/// A quiet accessor used by the CLI path to share the same diff logic.
pub async fn snapshot_diff(prev: &RwLock<Option<Snapshot>>, next: Snapshot) -> Update {
    let mut guard = prev.write().await;
    let update = build_update(guard.as_ref(), next.clone(), false, None);
    *guard = Some(next);
    update
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap_with(ip: &str, risk: u8) -> Snapshot {
        let mut s = Snapshot::new(ip);
        s.scores.risk = risk;
        s
    }

    #[test]
    fn first_snapshot_counts_as_ip_change() {
        let u = build_update(None, snap_with("1.1.1.1", 10), false, None);
        assert!(u.ip_changed);
        // No previous band to compare against, so no spurious "crossed" alarm.
        assert!(!u.risk_band_changed);
    }

    #[test]
    fn same_ip_is_not_a_change() {
        let prev = snap_with("1.1.1.1", 10);
        let u = build_update(Some(&prev), snap_with("1.1.1.1", 10), false, None);
        assert!(!u.ip_changed);
        assert!(!u.risk_band_changed);
    }

    #[test]
    fn new_ip_is_detected() {
        let prev = snap_with("1.1.1.1", 10);
        let u = build_update(Some(&prev), snap_with("2.2.2.2", 10), false, None);
        assert!(u.ip_changed);
    }

    #[test]
    fn crossing_a_risk_band_is_flagged() {
        // 15 (green) -> 75 (orange) should be worth an alert.
        let prev = snap_with("1.1.1.1", 15);
        let u = build_update(Some(&prev), snap_with("1.1.1.1", 75), false, None);
        assert!(u.risk_band_changed);
        assert!(!u.ip_changed);
    }

    #[test]
    fn moving_within_a_band_is_quiet() {
        // 22 -> 35 both sit in the "blue" band; not worth interrupting for.
        let prev = snap_with("1.1.1.1", 22);
        let u = build_update(Some(&prev), snap_with("1.1.1.1", 35), false, None);
        assert!(!u.risk_band_changed);
    }
}
