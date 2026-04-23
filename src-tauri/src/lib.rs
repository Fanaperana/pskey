// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/

pub mod commands;
pub mod vault;

use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .setup(|app| {
            let data_dir = app
                .path()
                .app_data_dir()
                .expect("failed to resolve app data dir");
            let vault_file = vault::vault_path(&data_dir);
            app.manage(commands::AppState::new(vault_file));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::vault_exists,
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
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
