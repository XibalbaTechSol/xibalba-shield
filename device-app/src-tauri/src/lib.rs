//! Thin native shell for the Shield device app.
//!
//! All decision logic lives in `device-core` (plain Rust, unit-tested without a GUI). This file
//! only: exposes two commands to the web UI, owns the system-tray icon, and hides the window on
//! close so the app keeps watching in the tray.
//!
//! STATUS: this crate needs the platform webview libraries (webkit2gtk on Linux) and could NOT be
//! compiled in the sandbox where it was written. `device-core` is tested; this shell is not.
//! Build and exercise it with `npm run tauri dev` on a desktop machine before relying on it.

use device_core::{overview, resume_command, Overview, Paths, ProcState};
use serde::Serialize;
use std::path::Path;
use std::process::Command;
use std::time::Duration;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, WindowEvent};

const TRAY_ID: &str = "main";
const POLL_SECONDS: u64 = 5;
const DECISION_LIMIT: usize = 50;

/// Where Shield keeps its logs. `SHIELD_DATA_DIR` overrides; otherwise `~/.xibalba-shield`,
/// the same directory the Python CLI defaults to.
fn paths() -> Result<Paths, String> {
    let override_dir = std::env::var("SHIELD_DATA_DIR").ok();
    let home = std::env::var("HOME").ok().or_else(|| std::env::var("USERPROFILE").ok());
    Paths::resolve(override_dir.as_deref(), home.as_deref())
        .ok_or_else(|| "cannot locate the Shield data directory: set SHIELD_DATA_DIR".to_string())
}

#[tauri::command]
fn device_overview() -> Result<Overview, String> {
    Ok(overview(&paths()?, Path::new("/proc"), DECISION_LIMIT))
}

#[derive(Serialize)]
struct ResumeResult {
    ok: bool,
    stdout: String,
    stderr: String,
}

/// Resume a frozen process by running the audited `shield resume` CLI. The pid and event id are
/// validated in `device-core`, and the command is spawned as an argument vector, never through a
/// shell. The app never sends signals itself.
#[tauri::command]
fn resume_process(pid: i64, event_id: Option<String>) -> Result<ResumeResult, String> {
    let p = paths()?;
    let shield_bin = std::env::var("SHIELD_BIN").unwrap_or_else(|_| "shield".to_string());
    // Optional: lets `shield resume` tell the backend, so this resume counts toward the fleet
    // false-freeze rate. Without it the resume is recorded locally only.
    let device_config = std::env::var("SHIELD_DEVICE_CONFIG").ok().filter(|c| !c.is_empty());
    let cmd = resume_command(
        &shield_bin,
        pid,
        event_id.as_deref(),
        &p.decisions,
        &p.outcomes,
        device_config.as_deref().map(Path::new),
    )?;
    let out = Command::new(&cmd.program)
        .args(&cmd.args)
        .output()
        .map_err(|e| format!("could not run `{}`: {e}. Set SHIELD_BIN to the shield executable.", cmd.program))?;
    Ok(ResumeResult {
        ok: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

fn show_main(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

/// Tooltip text from real state: only freezes the OS still shows as stopped are counted.
fn tooltip() -> String {
    match paths() {
        Ok(p) => {
            let o = overview(&p, Path::new("/proc"), 0);
            let stopped = o.frozen.iter().filter(|f| f.state == ProcState::Stopped).count();
            match stopped {
                0 => "Xibalba Shield: nothing frozen".to_string(),
                n => format!("Xibalba Shield: {n} process(es) frozen"),
            }
        }
        Err(_) => "Xibalba Shield: data directory unknown".to_string(),
    }
}

pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![device_overview, resume_process])
        .setup(|app| {
            let open = MenuItem::with_id(app, "open", "Open Shield", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&open, &quit])?;

            let mut builder = TrayIconBuilder::with_id(TRAY_ID)
                .tooltip("Xibalba Shield")
                .menu(&menu)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "open" => show_main(app),
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
                        show_main(tray.app_handle());
                    }
                });
            if let Some(icon) = app.default_window_icon() {
                builder = builder.icon(icon.clone());
            }
            builder.build(app)?;

            // Keep the tooltip honest without the window open.
            let handle = app.handle().clone();
            std::thread::spawn(move || loop {
                if let Some(tray) = handle.tray_by_id(TRAY_ID) {
                    let _ = tray.set_tooltip(Some(tooltip()));
                }
                std::thread::sleep(Duration::from_secs(POLL_SECONDS));
            });
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the window hides it; "Quit" in the tray menu is the only way to exit, so
            // the app keeps watching in the tray.
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running the Shield device app");
}
