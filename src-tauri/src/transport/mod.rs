//! morpheus-certificate-install 0.4.0 — how commands reach the appliance.
//!
//! Two implementations, same surface as the Python reference's Transport:
//!   ssh.rs        — own SSH via the charon-ssh crate (host-key TOFU, sudo detection, PTY shell)
//!   charon_mcp.rs — a session already open in Charon, via its MCP HTTP server
//! All shell text comes from mci_core::appliance; transports only wrap (sudo) and deliver.

pub mod charon_mcp;
pub mod ssh;

use async_trait::async_trait;
use mci_core::appliance::SudoMode;
use serde_json::Value;
use tokio::sync::watch;

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// First connection or changed key: the UI shows the fingerprint and reconnects with `trust_fingerprint`.
    #[error("host key {}", if *.mismatch { "CHANGED" } else { "unknown" })]
    HostKey { host: String, key_type: String, fingerprint: String, mismatch: bool },
    #[error("{0}")]
    Msg(String),
}

pub type TResult<T> = Result<T, TransportError>;

/// What `Transport::run_data` returns.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DataOut {
    pub rc: i32,
    /// The data.
    pub stdout: String,
    /// For error messages only.
    pub stderr: String,
}

impl DataOut {
    /// The tail of what the command said, for an error message: stderr if there is any, else stdout.
    pub fn complaint(&self, max: usize) -> String {
        let t = if self.stderr.trim().is_empty() { self.stdout.trim() } else { self.stderr.trim() };
        let n = t.chars().count();
        t.chars().skip(n.saturating_sub(max)).collect()
    }
}

#[async_trait]
pub trait Transport: Send + Sync {
    fn kind(&self) -> &'static str;
    /// Shown in the header chip: `mcitest@appliance`, `Charon · appliance`.
    fn label(&self) -> String;
    fn login_user(&self) -> String;
    fn sudo_mode(&self) -> SudoMode;
    /// `{kind,label,user,sudo_mode,shell,...}` — same keys as the Python `info()`; the UI reads them.
    fn info(&self) -> Value;

    /// Run `cmd` (built by mci_core::appliance), optionally under sudo, with optional stdin.
    /// Returns (exit code, combined stdout+stderr). SSH password-sudo prepends the password line
    /// to stdin (see appliance::ssh_wrap — never send it without `-k`).
    async fn run(&self, cmd: &str, sudo: bool, stdin: Option<&[u8]>, timeout_s: u64) -> TResult<(i32, String)>;

    /// `run` for reads whose output is **data to parse**, not text to show (morpheus.rb, stat,
    /// served_chain, list_runs/list_backups, manifests, preflight KEY=VALUE). `stdout` is the data;
    /// stderr — sudo's first-use lecture, warnings, `cat: …: No such file` — is kept apart, for error
    /// messages only, and never parsed. Merged output (`run`) would carry it into the data.
    /// See crate::reads for the reads themselves.
    async fn run_data(&self, cmd: &str, sudo: bool, stdin: Option<&[u8]>, timeout_s: u64) -> TResult<DataOut>;

    /// Write a root-owned file atomically (appliance::put_root_from_stdin / _from_staged).
    async fn put_root(&self, path: &str, data: &[u8], mode: &str, dir_mode: &str) -> TResult<()>;

    /// Follow a runner log until its rc file appears; call `on_text` with each chunk.
    /// Returns Some(rc), or None if `stop` fired (the run continues on the appliance).
    async fn follow(&self, log: &str, rc: &str, on_text: &(dyn Fn(String) + Send + Sync), stop: watch::Receiver<bool>) -> TResult<Option<i32>>;

    /// Interactive shell (SSH only; Charon users use the Charon tab).
    async fn shell_open(&self, _cols: u16, _rows: u16, _on_data: Box<dyn Fn(Vec<u8>) + Send + Sync>, _on_close: Box<dyn Fn() + Send + Sync>) -> TResult<()> {
        Err(TransportError::Msg("The Shell tab needs the app's own SSH connection. With Charon, use the Charon tab itself.".into()))
    }
    async fn shell_input(&self, _data: &[u8]) -> TResult<()> { Err(TransportError::Msg("No shell open.".into())) }
    async fn shell_resize(&self, _cols: u16, _rows: u16) -> TResult<()> { Ok(()) }
    async fn close(&self) {}
}
