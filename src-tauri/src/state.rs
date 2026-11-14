//! morpheus-certificate-install 0.4.1 — process state (one window, one operator). Secrets live here
//! only, in memory: the transport holds SSH/sudo passwords; `morpheus_token` is the API token.

use crate::events::Event;
use crate::transport::Transport;
use mci_core::analyze::Analysis;
use mci_core::formats::InputFile;
use serde_json::Value;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{watch, Mutex};

/// Sends one event on the `mci` channel.
pub type Emit = Arc<dyn Fn(Event) + Send + Sync>;
/// export_zip's "where to save `<name>`?" — the save dialog in the app; None means cancelled.
pub type PickSave = Arc<dyn Fn(String) -> Option<PathBuf> + Send + Sync>;

pub struct AppState {
    pub paths: crate::paths::AppPaths,
    pub emit: Emit,
    pub pick_save: Option<PickSave>,
    pub transport: Mutex<Option<Arc<dyn Transport>>>,
    /// KEY=VALUE facts from preflight (lowercased keys) + morpheus_rb text + served chain summary.
    pub facts: Mutex<Option<Value>>,
    /// Every input so far (uploads replace same-named ones; fetched chain certs are added as `fetched: <cn>.crt`).
    pub files: Mutex<Vec<InputFile>>,
    pub analysis: Mutex<Option<Arc<Analysis>>>,
    /// Plan shown to the user; `apply` must echo its `stamp` back or it refuses ("Plan changed; review it again.").
    pub plan: Mutex<Option<crate::engine::Plan>>,
    /// A job (preflight, apply, verify, reattach, rollback) is running.
    pub busy: Arc<AtomicBool>,
    /// Stop following a run (the run itself continues on the appliance).
    pub stop: watch::Sender<bool>,
    pub morpheus_url: Mutex<String>,
    pub morpheus_token: Mutex<String>,
    /// The cleanup shown in the confirm dialog; `cleanup` must echo its token (0.3.17).
    pub cleanup_plan: Mutex<Option<crate::cleanup::Plan>>,
    /// Portable mode's "Leave no trace": nothing saved to settings, data folder deleted at exit.
    pub leave_no_trace: Arc<AtomicBool>,
    /// Shown once on the page (e.g. the last leave-no-trace deletion failed).
    pub notice: Mutex<Option<String>>,
}

impl AppState {
    pub fn new(paths: crate::paths::AppPaths, emit: Emit, pick_save: Option<PickSave>) -> Self {
        Self {
            paths,
            emit,
            pick_save,
            transport: Default::default(),
            facts: Default::default(),
            files: Default::default(),
            analysis: Default::default(),
            plan: Default::default(),
            busy: Default::default(),
            stop: watch::channel(false).0,
            morpheus_url: Default::default(),
            morpheus_token: Default::default(),
            cleanup_plan: Default::default(),
            leave_no_trace: Default::default(),
            notice: Default::default(),
        }
    }
    pub fn is_busy(&self) -> bool { self.busy.load(Ordering::SeqCst) }
}
