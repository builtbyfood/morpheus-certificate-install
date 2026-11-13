//! morpheus-certificate-install 0.4.0 — Tauri app.
//!
//! Every command takes one JSON object (`args`) and returns JSON or an error string — the same
//! request/response bodies as the Python app's /api/* routes, so ui/index.html only swaps fetch()
//! for invoke() (see ui/bridge.js). Long work runs as a job emitting events on `mci` (events.rs).
//!
//!   /api/state → state            /api/connect → connect          /api/disconnect → disconnect
//!   /api/charon → charon_discover /api/preflight → preflight      /api/analyze → analyze
//!   /api/clear-files → clear_files /api/fetch-chain → fetch_chain /api/export → export_zip
//!   /api/plan → plan              /api/apply → apply              /api/verify → verify
//!   /api/runs → runs              /api/reattach → reattach        /api/stop → stop
//!   /api/backups → backups        /api/rollback → rollback        /api/morpheus → morpheus_check
//!   /api/morpheus/appliance-url → set_appliance_url
//!   /api/shell/open|input|resize → shell_open | shell_input | shell_resize
//!
//! export_zip differs: it asks for a save path with the dialog plugin and writes the zip itself
//! (webview downloads are unreliable), returning {saved: path|null, files: [...]}.
//!
//! [`configure`] builds the app for any runtime: the real one in [`run`], tauri's MockRuntime in
//! the tests (tests/commands.rs, tests/engine_e2e.rs), which drive the same commands without a window.

/// Clean up this appliance, forget it, leave no trace (0.3.17).
pub mod cleanup;
pub mod engine;
pub mod events;
mod fetch;
pub mod morpheus_api;
pub mod paths;
/// Data reads from the appliance (stdout only, via Transport::run_data).
pub mod reads;
pub mod state;
/// Public so the integration tests can drive a transport directly.
pub mod transport;
/// The "Trust this CA" default, from the actual root (0.3.17).
pub mod trust;
pub mod verify;

use serde_json::Value;
use std::sync::Arc;
use tauri::{Emitter, Manager, Runtime};

type Res = Result<Value, String>;

macro_rules! cmd {
    ($($name:ident),* $(,)?) => {
        $(
            #[tauri::command]
            async fn $name<R: Runtime>(app: tauri::AppHandle<R>, state: tauri::State<'_, Arc<state::AppState>>, args: Option<Value>) -> Res {
                engine::$name(&app, state.inner().clone(), args.unwrap_or(Value::Null)).await
            }
        )*
    };
}

cmd!(state, connect, disconnect, charon_discover, preflight, analyze, clear_files, fetch_chain, export_zip,
     plan, apply, verify, runs, reattach, stop, backups, rollback, morpheus_check, set_appliance_url,
     shell_open, shell_input, shell_resize, cleanup_list, cleanup_plan, cleanup, forget_appliance, set_leave_no_trace);

/// Where the app keeps its data, how export_zip picks a path, and whether to open the window.
pub struct Setup {
    pub paths: paths::AppPaths,
    /// `None`: the save dialog. Tests pass a function that returns a path (or None, "cancelled").
    pub pick_save: Option<state::PickSave>,
    /// The real app opens its window here (so portable mode can give it its own webview profile).
    pub open_window: bool,
}

/// The app's plugins, state, commands and (optionally) its window, for any runtime.
pub fn configure<R: Runtime>(b: tauri::Builder<R>, setup: Setup) -> tauri::Builder<R> {
    // The state is made in a plugin's setup, which runs when the app is built; the app's own
    // `.setup` runs only once the event loop starts, which the MockRuntime tests never do.
    let (paths, pick_save) = (setup.paths.clone(), setup.pick_save.clone());
    let state_plugin = tauri::plugin::Builder::<R, ()>::new("mci-state")
        .setup(move |app, _api| {
            let h = app.clone();
            let emit: state::Emit = Arc::new(move |ev: events::Event| {
                let _ = h.emit(events::CHANNEL, ev);
            });
            app.manage(Arc::new(state::AppState::new(paths.clone(), emit, pick_save.clone())));
            Ok(())
        })
        .build();
    b.plugin(tauri_plugin_dialog::init())
        .plugin(state_plugin)
        .setup(move |app| {
            if setup.open_window {
                // The window is declared in tauri.conf.json with "create": false and built here,
                // so portable mode can put the WebView2/webkit profile in ./data/webview.
                let conf = app.config().app.windows.first().cloned().ok_or("tauri.conf.json declares no window")?;
                let mut w = tauri::WebviewWindowBuilder::from_config(app, &conf)?;
                if let Some(dir) = setup.paths.webview_data_dir() {
                    w = w.data_directory(dir);
                }
                w.build()?;
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            state, connect, disconnect, charon_discover, preflight, analyze, clear_files,
            fetch_chain, export_zip, plan, apply, verify, runs, reattach, stop,
            backups, rollback, morpheus_check, set_appliance_url, shell_open, shell_input,
            shell_resize, cleanup_list, cleanup_plan, cleanup, forget_appliance, set_leave_no_trace
        ])
}

/// Test-only hooks, compiled into debug and test builds only (`debug_assertions`); a release build
/// has none (tests/click/suites/release-hooks.mjs checks the release exe). R8's click tests use them.
/// Only one exists, and nothing else may bypass a user confirmation:
/// - `MCI_TEST_SAVE_DIR=<dir>`: export_zip writes `<dir>/<name>.zip` without the save dialog.
#[cfg(debug_assertions)]
mod test_hooks {
    pub fn pick_save() -> Option<crate::state::PickSave> {
        let dir = std::env::var_os("MCI_TEST_SAVE_DIR").filter(|d| !d.is_empty())?;
        let dir = std::path::PathBuf::from(dir);
        Some(std::sync::Arc::new(move |name: String| Some(dir.join(name))))
    }
}
#[cfg(not(debug_assertions))]
mod test_hooks {
    pub fn pick_save() -> Option<crate::state::PickSave> { None }
}

pub fn run() {
    let paths = paths::AppPaths::detect().expect("data dir");
    // Portable "Leave no trace": the last session's folder couldn't be deleted at exit? Try again
    // now, before the webview starts, and tell the user either way.
    let notice = if paths.portable { cleanup::retry_at_start(&paths.data_dir) } else { None };
    if notice.is_some() { let _ = std::fs::create_dir_all(&paths.data_dir); }
    let app = configure(tauri::Builder::default(), Setup { paths, pick_save: test_hooks::pick_save(), open_window: true })
        .build(tauri::generate_context!())
        .expect("error while building morpheus-certificate-install");
    if let Some(n) = notice {
        if let Some(st) = app.try_state::<Arc<state::AppState>>() { *st.notice.blocking_lock() = Some(n); }
    }
    app.run(|h, ev| {
        if let tauri::RunEvent::Exit = ev {
            let Some(st) = h.try_state::<Arc<state::AppState>>() else { return };
            if st.paths.portable && st.leave_no_trace.load(std::sync::atomic::Ordering::SeqCst) {
                let _ = cleanup::delete_data_dir(&st.paths.data_dir);
            }
        }
    });
}
