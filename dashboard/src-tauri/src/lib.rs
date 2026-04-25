// USB Defender — Tauri Rust backend
// Manages the Python API sidecar and exposes commands to the frontend.

use tauri::Manager;
use tauri_plugin_shell::ShellExt;
use std::sync::Mutex;

// State to track whether the backend sidecar is running
struct BackendState {
    running: Mutex<bool>,
}

/// Start the Python API sidecar process
#[tauri::command]
async fn start_backend(app: tauri::AppHandle) -> Result<String, String> {
    let shell = app.shell();

    // Spawn the sidecar — looks for "usb-defender-api" binary in the sidecar bundle
    let _output = shell
        .sidecar("usb-defender-api")
        .map_err(|e| format!("Failed to create sidecar command: {}", e))?
        .args(["--host", "127.0.0.1", "--port", "8642"])
        .spawn()
        .map_err(|e| format!("Failed to spawn sidecar: {}", e))?;

    // Update state
    let state = app.state::<BackendState>();
    *state.running.lock().unwrap() = true;

    Ok("Backend started on http://127.0.0.1:8642".to_string())
}

/// Check backend health by pinging the API
#[tauri::command]
async fn get_backend_status() -> Result<serde_json::Value, String> {
    let client = reqwest::Client::new();
    match client
        .get("http://127.0.0.1:8642/api/status")
        .timeout(std::time::Duration::from_secs(2))
        .send()
        .await
    {
        Ok(resp) => {
            if resp.status().is_success() {
                let body: serde_json::Value = resp
                    .json()
                    .await
                    .map_err(|e| format!("Failed to parse response: {}", e))?;
                Ok(body)
            } else {
                Err(format!("Backend returned status: {}", resp.status()))
            }
        }
        Err(_) => Err("Backend is not running".to_string()),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_shell::init())
        .manage(BackendState {
            running: Mutex::new(false),
        })
        .invoke_handler(tauri::generate_handler![start_backend, get_backend_status])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
