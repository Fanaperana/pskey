// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/

pub mod commands;
pub mod lockout;
pub mod settings;
pub mod vault;

use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Emitter, Manager, WindowEvent,
};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                // Close button / ⌘W: hide instead of quitting. Tray "Quit" exits.
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .setup(|app| {
            let data_dir = app
                .path()
                .app_data_dir()
                .expect("failed to resolve app data dir");
            let vault_file = vault::vault_path(&data_dir);
            let settings_file = settings::settings_path(&data_dir);
            let lockout_file = lockout::lockout_path(&data_dir);
            // Ensure settings.json exists with defaults on first run.
            let _ = settings::load_or_default(&settings_file);
            // Restore any persisted lockout state — survives process restarts.
            let lockout_state = lockout::load(&lockout_file);
            app.manage(commands::AppState::new(
                vault_file,
                settings_file,
                lockout_file,
                lockout_state,
            ));

            // ── Global shortcut: ⌘⇧P (or Ctrl+Shift+P) toggles the window ──
            #[cfg(desktop)]
            {
                use tauri_plugin_global_shortcut::{
                    Code, GlobalShortcutExt, Modifiers, Shortcut, ShortcutState,
                };

                let toggle = Shortcut::new(Some(Modifiers::SUPER | Modifiers::SHIFT), Code::KeyP);

                app.handle().plugin(
                    tauri_plugin_global_shortcut::Builder::new()
                        .with_handler(move |app, shortcut, event| {
                            if event.state() != ShortcutState::Pressed {
                                return;
                            }
                            if shortcut == &toggle {
                                if let Some(w) = app.get_webview_window("main") {
                                    match w.is_visible() {
                                        Ok(true) => {
                                            let _ = w.hide();
                                        }
                                        _ => {
                                            let _ = w.show();
                                            let _ = w.set_focus();
                                        }
                                    }
                                }
                            }
                        })
                        .build(),
                )?;
                app.global_shortcut().register(toggle)?;
            }

            // ── System tray ────────────────────────────────────────────────
            let show_hide = MenuItem::with_id(app, "show_hide", "Show / Hide", true, None::<&str>)?;
            let lock = MenuItem::with_id(app, "lock", "Lock vault", true, None::<&str>)?;
            let separator = tauri::menu::PredefinedMenuItem::separator(app)?;
            let quit = MenuItem::with_id(app, "quit", "Quit PSKey", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show_hide, &lock, &separator, &quit])?;

            let tray_icon = tauri::image::Image::from_bytes(include_bytes!("../icons/tray.png"))?;

            let _tray = TrayIconBuilder::with_id("pskey-tray")
                .icon(tray_icon)
                .icon_as_template(true)
                .tooltip("PSKey")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show_hide" => {
                        if let Some(w) = app.get_webview_window("main") {
                            match w.is_visible() {
                                Ok(true) => {
                                    let _ = w.hide();
                                }
                                _ => {
                                    let _ = w.show();
                                    let _ = w.set_focus();
                                }
                            }
                        }
                    }
                    "lock" => {
                        if let Some(state) = app.try_state::<commands::AppState>() {
                            commands::lock_session(&state);
                        }
                        if let Some(w) = app.get_webview_window("main") {
                            let _ = w.emit("vault://locked", ());
                        }
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
                        let app = tray.app_handle();
                        if let Some(w) = app.get_webview_window("main") {
                            match w.is_visible() {
                                Ok(true) => {
                                    let _ = w.hide();
                                }
                                _ => {
                                    let _ = w.show();
                                    let _ = w.set_focus();
                                }
                            }
                        }
                    }
                })
                .build(app)?;

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::vault_exists,
            commands::lockout_status,
            commands::vault_init,
            commands::vault_unlock,
            commands::vault_unlock_challenge,
            commands::vault_lock,
            commands::session_touch,
            commands::list_entries,
            commands::get_entry_secret,
            commands::get_entry_username,
            commands::add_entry,
            commands::delete_entry,
            commands::copy_to_clipboard,
            commands::settings_get,
            commands::settings_set,
            commands::vault_strength,
            commands::vault_rekey,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
