//! morpheus-certificate-install 0.4.0 — the app on tauri's MockRuntime: the real commands, state
//! and events (`mci::configure`), invoked over IPC without a window (R7).

use mci_app::paths::AppPaths;
use mci_app::state::PickSave;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::ipc::{CallbackFn, InvokeBody};
use tauri::test::{get_ipc_response, mock_builder, mock_context, noop_assets, MockRuntime, INVOKE_KEY};
use tauri::webview::InvokeRequest;
use tauri::{Listener, WebviewWindow};

pub struct App {
    _app: tauri::App<MockRuntime>,
    w: WebviewWindow<MockRuntime>,
    /// Every event on `mci`, as the page would receive it (JSON).
    pub events: Arc<Mutex<Vec<Value>>>,
    pub data_dir: PathBuf,
}

impl App {
    /// A fresh app with its own data dir. `pick_save` stands in for the save dialog.
    pub fn new(tag: &str, pick_save: Option<PickSave>) -> App { App::new_with(tag, pick_save, false) }

    /// `portable`: as if portable.flag sat beside the exe (the data dir is still the temp one).
    pub fn new_with(tag: &str, pick_save: Option<PickSave>, portable: bool) -> App {
        let data_dir = std::env::temp_dir().join(format!("mci-r7-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&data_dir);
        std::fs::create_dir_all(&data_dir).unwrap();
        let setup = mci_app::Setup { paths: AppPaths { portable, data_dir: data_dir.clone() }, pick_save, open_window: false };
        let app = mci_app::configure(mock_builder(), setup).build(mock_context(noop_assets())).expect("build the mock app");
        let events = Arc::new(Mutex::new(Vec::new()));
        let ev = events.clone();
        app.listen_any("mci", move |e| {
            ev.lock().unwrap().push(serde_json::from_str::<Value>(e.payload()).unwrap_or_else(|_| json!({"unparsed": e.payload()})));
        });
        let w = tauri::WebviewWindowBuilder::new(&app, "main", Default::default()).build().expect("mock window");
        App { _app: app, w, events, data_dir }
    }

    /// Invoke a command the way ui/bridge.js does: `invoke(cmd, {args})`.
    pub fn call(&self, cmd: &str, args: Value) -> Result<Value, String> {
        let req = InvokeRequest {
            cmd: cmd.into(),
            callback: CallbackFn(0),
            error: CallbackFn(1),
            url: if cfg!(windows) { "http://tauri.localhost" } else { "tauri://localhost" }.parse().unwrap(),
            body: InvokeBody::Json(json!({ "args": args })),
            headers: Default::default(),
            invoke_key: INVOKE_KEY.to_string(),
        };
        match get_ipc_response(&self.w, req) {
            Ok(b) => Ok(b.deserialize::<Value>().unwrap()),
            Err(Value::String(s)) => Err(s),
            Err(v) => Err(v.to_string()),
        }
    }

    pub fn ok(&self, cmd: &str, args: Value) -> Value {
        self.call(cmd, args).unwrap_or_else(|e| panic!("{cmd}: {e}"))
    }

    pub fn mark(&self) -> usize { self.events.lock().unwrap().len() }

    pub fn events_since(&self, mark: usize) -> Vec<Value> { self.events.lock().unwrap()[mark..].to_vec() }

    /// Wait for job `name` (started after `mark`) to finish; returns its `job` event (done or error).
    pub fn wait_job(&self, name: &str, mark: usize, timeout: Duration) -> Value {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(e) = self.events_since(mark).into_iter()
                .find(|e| e["type"] == "job" && e["name"] == name && (e["status"] == "done" || e["status"] == "error")) {
                return e;
            }
            assert!(Instant::now() < deadline, "job {name} didn't finish within {timeout:?}; events: {:#?}", self.events_since(mark));
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Run a job command and wait for it; panics unless it finished "done". Returns its result.
    pub fn job(&self, cmd: &str, name: &str, args: Value, timeout: Duration) -> Value {
        let m = self.mark();
        assert_eq!(self.ok(cmd, args), json!({"ok": true}), "{cmd}");
        let e = self.wait_job(name, m, timeout);
        assert_eq!(e["status"], "done", "{name} failed: {}\n{}", e["error"], self.log_since(m));
        e["result"].clone()
    }

    /// The `log` and `remote` text since `mark`, for failure messages.
    pub fn log_since(&self, mark: usize) -> String {
        self.events_since(mark).iter().filter_map(|e| e["text"].as_str().map(String::from)).collect()
    }

    pub fn settings(&self) -> Value {
        std::fs::read_to_string(self.data_dir.join("settings.json")).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(json!({}))
    }
}

impl Drop for App {
    /// The data dir is the test's own; leave nothing in the temp directory.
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.data_dir); }
}

/// `{name, b64}` for a corpus file, as the page sends it.
pub fn corpus_file(name: &str) -> Value {
    use base64::Engine;
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures/corpus").join(name);
    json!({"name": name, "b64": base64::engine::general_purpose::STANDARD.encode(std::fs::read(&p).unwrap())})
}

/// The local `step` ids/statuses since `mark`, as "id:status".
pub fn steps(evs: &[Value]) -> Vec<String> {
    evs.iter().filter(|e| e["type"] == "step").map(|e| format!("{}:{}", e["id"].as_str().unwrap(), e["status"].as_str().unwrap())).collect()
}
