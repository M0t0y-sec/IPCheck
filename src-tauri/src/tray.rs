//! System tray.
//!
//! The card runs with `skipTaskbar: true`, which means once it is hidden there
//! is no taskbar entry to bring it back. Before this module existed there was
//! also no way to quit at all short of Task Manager — the app could only be
//! started, never stopped. The tray is therefore not decoration: it is the
//! window's only recovery path and the app's only exit.
//!
//! The menu deliberately offers both **hide** and **quit**. Conflating them is
//! what makes tray apps feel uncloseable: hiding keeps the monitor running,
//! quitting stops it, and the user should be able to choose.

use crate::AppState;
use std::sync::Arc;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager};

const TRAY_ID: &str = "ipcheck-tray";

fn reveal(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("card") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

fn hide(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("card") {
        let _ = w.hide();
    }
}

fn toggle(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("card") {
        if w.is_visible().unwrap_or(false) {
            let _ = w.hide();
        } else {
            reveal(app);
        }
    }
}

pub fn setup(app: &AppHandle) -> tauri::Result<()> {
    let show = MenuItem::with_id(app, "show", "显示卡片", true, None::<&str>)?;
    let hide_item = MenuItem::with_id(app, "hide", "隐藏卡片", true, None::<&str>)?;
    let refresh = MenuItem::with_id(app, "refresh", "立即刷新", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "退出 IPCheck", true, None::<&str>)?;
    let sep = PredefinedMenuItem::separator(app)?;
    let menu = Menu::with_items(app, &[&show, &hide_item, &refresh, &sep, &quit])?;

    let mut builder = TrayIconBuilder::with_id(TRAY_ID)
        .tooltip("IPCheck")
        .menu(&menu)
        // Left click toggles the card; the menu is for right click. Making the
        // left click open a menu *and* the menu-only path would leave no quick
        // way to bring the card back.
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "show" => reveal(app),
            "hide" => hide(app),
            "refresh" => {
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    let state = app.state::<Arc<AppState>>().inner().clone();
                    let _ = crate::commands::refresh_now(&app, &state).await;
                });
            }
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                toggle(tray.app_handle());
            }
        });

    // The icon comes from the bundle; if it is somehow missing, still build the
    // tray so the quit path exists.
    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }

    builder.build(app)?;
    Ok(())
}

/// Put the latest verdict in the tray tooltip. When the card is hidden, the
/// tray icon is the only thing on screen, so the tooltip is the only place a
/// risk change can be noticed without reopening the card.
pub fn update_tooltip(app: &AppHandle, ip: &str, risk: u8, composite: u8) {
    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        let tip = if ip.is_empty() {
            "IPCheck · 暂无数据".to_string()
        } else {
            format!("IPCheck\n{ip}\n风险 {risk} · 综合 {composite}")
        };
        let _ = tray.set_tooltip(Some(tip));
    }
}
