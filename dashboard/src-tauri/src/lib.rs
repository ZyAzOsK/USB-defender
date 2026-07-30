// USB Defender — Tauri Rust backend
// Manages the Python API sidecar and exposes commands to the frontend.

use std::sync::Mutex;
use tauri::{Manager, RunEvent};
use tauri_plugin_shell::process::{CommandChild, CommandEvent};
use tauri_plugin_shell::ShellExt;

const API_HOST: &str = "127.0.0.1";
const API_PORT: &str = "8642";

/// Holds the running sidecar so it can be terminated deliberately.
///
/// The shell plugin does not kill spawned children when the app exits. An
/// orphaned sidecar keeps port 8642 bound, so the next launch hits the
/// "port already in use" guard, exits, and the UI shows "Engine Offline"
/// forever until the user finds the stray process.
#[derive(Default)]
struct BackendState {
    child: Mutex<Option<CommandChild>>,
}

/// Spawn the Python API sidecar, forwarding its output to our stdout.
fn spawn_sidecar(app: &tauri::AppHandle) -> Result<CommandChild, String> {
    let (mut rx, child) = app
        .shell()
        .sidecar("usb-defender-api")
        .map_err(|e| format!("Failed to create sidecar command: {e}"))?
        .args(["--host", API_HOST, "--port", API_PORT])
        .spawn()
        .map_err(|e| format!("Failed to spawn sidecar: {e}"))?;

    // Without draining the event channel the sidecar's output is discarded,
    // which makes diagnosing a backend that failed to start impossible.
    tauri::async_runtime::spawn(async move {
        while let Some(event) = rx.recv().await {
            match event {
                CommandEvent::Stdout(line) => {
                    print!("[api] {}", String::from_utf8_lossy(&line));
                }
                CommandEvent::Stderr(line) => {
                    eprint!("[api] {}", String::from_utf8_lossy(&line));
                }
                CommandEvent::Terminated(payload) => {
                    eprintln!("[api] sidecar exited with {:?}", payload.code);
                }
                _ => {}
            }
        }
    });

    Ok(child)
}

/// Start the Python API sidecar if it is not already running.
#[tauri::command]
async fn start_backend(app: tauri::AppHandle) -> Result<String, String> {
    let state = app.state::<BackendState>();

    {
        let guard = state.child.lock().map_err(|e| e.to_string())?;
        if guard.is_some() {
            return Ok(format!("Backend already running on http://{API_HOST}:{API_PORT}"));
        }
    }

    let child = spawn_sidecar(&app)?;
    *state.child.lock().map_err(|e| e.to_string())? = Some(child);

    Ok(format!("Backend started on http://{API_HOST}:{API_PORT}"))
}

/// Terminate the sidecar.
#[tauri::command]
async fn stop_backend(app: tauri::AppHandle) -> Result<String, String> {
    let state = app.state::<BackendState>();
    let child = state.child.lock().map_err(|e| e.to_string())?.take();

    match child {
        Some(c) => {
            c.kill().map_err(|e| format!("Failed to stop sidecar: {e}"))?;
            Ok("Backend stopped".to_string())
        }
        None => Ok("Backend was not running".to_string()),
    }
}

/// Check backend health by pinging the API.
#[tauri::command]
async fn get_backend_status() -> Result<serde_json::Value, String> {
    let client = reqwest::Client::new();
    match client
        .get(format!("http://{API_HOST}:{API_PORT}/api/status"))
        .timeout(std::time::Duration::from_secs(2))
        .send()
        .await
    {
        Ok(resp) => {
            if resp.status().is_success() {
                resp.json()
                    .await
                    .map_err(|e| format!("Failed to parse response: {e}"))
            } else {
                Err(format!("Backend returned status: {}", resp.status()))
            }
        }
        Err(_) => Err("Backend is not running".to_string()),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_shell::init())
        .manage(BackendState::default())
        .setup(|app| {
            // Auto-start the Python API sidecar on app launch.
            let handle = app.handle();
            match spawn_sidecar(handle) {
                Ok(child) => {
                    println!("✅ Sidecar started on http://{API_HOST}:{API_PORT}");
                    *handle.state::<BackendState>().child.lock().unwrap() = Some(child);
                }
                Err(e) => {
                    eprintln!("❌ Failed to start sidecar: {e}");
                }
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            start_backend,
            stop_backend,
            get_backend_status
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application");

    app.run(|app_handle, event| {
        if let RunEvent::Exit = event {
            // Reap the sidecar so it cannot outlive the window and hold the port.
            if let Some(child) = app_handle
                .state::<BackendState>()
                .child
                .lock()
                .ok()
                .and_then(|mut guard| guard.take())
            {
                let _ = child.kill();
                println!("🧹 Sidecar terminated on exit");
            }
        }
    });
}
