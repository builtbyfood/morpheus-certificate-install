//! morpheus-certificate-install 0.4.2 — SSH transport on the charon-ssh crate. **Round 1, R5.**
//!
//! Port of reference transport.SshTransport. Behaviour that matters:
//! * Host keys: TOFU against <data>/known_hosts (charon-ssh `HostKeys::with_paths`, never
//!   `~/.ssh/known_hosts`). Unknown → `TransportError::HostKey` with the SHA256 fingerprint; the UI
//!   confirms and reconnects with `trust_fingerprint`, which must match exactly before the key is
//!   saved. Changed key → `HostKey { mismatch: true }`, never auto-trusted (charon-ssh refuses it
//!   before any policy is asked).
//! * Auth: key file (+passphrase, `~` expanded), then the password if the key is refused; password
//!   alone; neither → agent, then ~/.ssh default keys (`Auth::Auto`, paramiko's allow_agent +
//!   look_for_keys).
//! * Sudo detection after connect: `id -u` == 0 → Root; `appliance::SUDO_PROBE` exit 0 → Nopasswd;
//!   else Password. The sudo password defaults to the login password. Password mode: stdin =
//!   password + "\n" + data, exec line from `appliance::ssh_wrap` (`sudo -k -S -p ''`), so sudo
//!   always consumes the password line. A wrong password is an error naming the Sudo password field.
//! * run: exec channel, stderr merged in arrival order, stdin then end-of-input, wait for the exit
//!   status; a timeout closes the channel (charon-ssh `exec_cancellable`) and is an error.
//! * follow: `ssh_wrap(appliance::ssh_follow(log, rc))`; `@@RC=<n>` ends it; stop closes only this
//!   channel — the runner keeps going on the appliance.
//! * Shell: PTY `xterm-256color` opened on demand on the same connection (charon-ssh `open_shell`);
//!   closing it leaves the connection up.
//!
//! **Secrets:** the SSH and sudo passwords and the key passphrase live only in this struct and in
//! the stdin bytes of a sudo command. They're never in a command line, a log line, an event or an
//! error message.

use super::{DataOut, TResult, Transport, TransportError};
use async_trait::async_trait;
use charon_ssh::{Auth, ExecOut, HostKeyPolicy, HostKeyPrompt, HostKeys, Output, Shell, SshError, SshSession};
use mci_core::appliance::{self, SudoMode};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::sync::{watch, Mutex};

/// The whole connect (TCP, banner, key exchange, auth) must finish within this. The reference
/// allowed 15 s connect + 20 s banner + 20 s auth.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(45);

pub struct SshParams {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    pub key_path: String,
    pub key_passphrase: String,
    pub sudo_password: String,
    pub trust_fingerprint: String,
    pub known_hosts: std::path::PathBuf,
}

/// Unknown host keys are accepted only when they match the fingerprint the user confirmed.
/// Every prompt is remembered so a refusal can be turned into `TransportError::HostKey`.
struct ConfirmedKeyOnly {
    trust: String,
    seen: StdMutex<Option<HostKeyPrompt>>,
}

#[async_trait]
impl HostKeyPolicy for ConfirmedKeyOnly {
    async fn approve_unknown(&self, prompt: &HostKeyPrompt) -> bool {
        if let Ok(mut s) = self.seen.lock() {
            *s = Some(prompt.clone());
        }
        !self.trust.is_empty() && self.trust == prompt.fingerprint
    }
}

fn expand_home(path: &str) -> String {
    match path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\")) {
        Some(rest) => dirs::home_dir().map(|h| h.join(rest).to_string_lossy().into_owned()).unwrap_or_else(|| path.to_string()),
        None if path == "~" => dirs::home_dir().map(|h| h.to_string_lossy().into_owned()).unwrap_or_else(|| path.to_string()),
        None => path.to_string(),
    }
}

/// The exec line and stdin for `cmd`, as the reference's `_wrap`: commands come from
/// mci_core::appliance, the wrap from `appliance::ssh_wrap`, and in password mode the sudo
/// password line goes first on stdin.
pub fn exec_line(cmd: &str, sudo: bool, mode: SudoMode, sudo_password: &str, stdin: Option<&[u8]>) -> TResult<(String, Option<Vec<u8>>)> {
    let (line, needs_password) = appliance::ssh_wrap(cmd, sudo, mode);
    if !needs_password {
        return Ok((line, stdin.map(<[u8]>::to_vec)));
    }
    if sudo_password.is_empty() {
        return Err(TransportError::Msg("sudo needs a password for this account. Enter it in the Connect step (Sudo password).".into()));
    }
    let mut data = Vec::with_capacity(sudo_password.len() + 1 + stdin.map_or(0, <[u8]>::len));
    data.extend_from_slice(sudo_password.as_bytes());
    data.push(b'\n');
    if let Some(s) = stdin {
        data.extend_from_slice(s);
    }
    Ok((line, Some(data)))
}

/// Finds `@@RC=<n>` in a follow stream that arrives in arbitrary chunks. Text before the marker is
/// passed on; the marker may be split across chunks, so the last few bytes are held back until
/// they can't be its start.
#[derive(Default)]
pub struct RcScanner {
    pending: String,
    rc: Option<i32>,
    found: bool,
}

const MARK: &str = "@@RC=";

impl RcScanner {
    /// Feed a chunk; returns the text to show now.
    pub fn push(&mut self, chunk: &str) -> String {
        if self.found {
            self.pending.push_str(chunk);
            self.parse_rc();
            return String::new();
        }
        self.pending.push_str(chunk);
        if let Some(i) = self.pending.find(MARK) {
            let before = self.pending[..i].to_string();
            self.pending = self.pending[i + MARK.len()..].to_string();
            self.found = true;
            self.parse_rc();
            return before;
        }
        // Hold back a tail that could be the start of the marker.
        let keep = (1..MARK.len()).rev().find(|&n| self.pending.ends_with(&MARK[..n])).unwrap_or(0);
        let cut = self.pending.len() - keep;
        let out = self.pending[..cut].to_string();
        self.pending.drain(..cut);
        out
    }

    fn parse_rc(&mut self) {
        let digits: String = self.pending.trim_start().chars().take_while(|c| c.is_ascii_digit() || *c == '-').collect();
        if let Ok(n) = digits.parse() {
            self.rc = Some(n);
        }
    }

    /// End of stream: whatever is still held back that isn't the marker.
    pub fn finish(&mut self) -> (String, Option<i32>) {
        let rest = if self.found { String::new() } else { std::mem::take(&mut self.pending) };
        (rest, self.rc)
    }
}

pub struct SshTransport {
    session: Arc<SshSession>,
    host: String,
    port: u16,
    user: String,
    label: String,
    fingerprint: String,
    sudo_mode: SudoMode,
    sudo_password: String,
    shell: Mutex<Option<Shell>>,
}

/// How a command started by `raw` ended.
enum Ended {
    Done(i32),
    Stopped,
}

pub async fn connect(p: SshParams) -> TResult<Box<dyn Transport>> {
    let port = if p.port == 0 { 22 } else { p.port };
    let keys = Arc::new(HostKeys::with_paths(p.known_hosts.clone(), None).with_label(mci_core::SLUG));
    let attempt = |auth: Auth| {
        let keys = keys.clone();
        let policy = Arc::new(ConfirmedKeyOnly { trust: p.trust_fingerprint.clone(), seen: StdMutex::new(None) });
        let mut params = charon_ssh::SshParams::new(p.host.clone(), p.user.clone(), auth);
        params.port = port;
        async move {
            let r = tokio::time::timeout(CONNECT_TIMEOUT, SshSession::connect_exec(keys, policy.clone(), params)).await;
            (r, policy)
        }
    };
    let key_auth = (!p.key_path.is_empty()).then(|| Auth::Key {
        key: expand_home(&p.key_path),
        passphrase: (!p.key_passphrase.is_empty()).then(|| p.key_passphrase.clone()),
    });
    let first = match (&key_auth, p.password.is_empty()) {
        (Some(k), _) => k.clone(),
        (None, false) => Auth::Password(p.password.clone()),
        (None, true) => Auth::Auto,
    };
    let (mut result, mut policy) = attempt(first).await;
    // paramiko with both a key file and a password tries the key, then the password.
    if key_auth.is_some() && !p.password.is_empty() && matches!(&result, Ok(Err(e)) if is_auth_rejected(e)) {
        (result, policy) = attempt(Auth::Password(p.password.clone())).await;
    }
    let session = match result {
        Err(_) => return Err(TransportError::Msg(format!(
            "Could not connect to {}:{port}: no answer within {} s. Check the host, the port and any firewall in between.",
            p.host, CONNECT_TIMEOUT.as_secs()))),
        Ok(Err(e)) => return Err(map_connect_error(&e, &p.host, port, &p.user, &policy)),
        Ok(Ok(s)) => s,
    };
    let fingerprint = session.server_key().map(|(_, f)| f.to_string()).unwrap_or_default();
    let mut t = SshTransport {
        session,
        host: p.host.clone(),
        port,
        user: p.user.clone(),
        label: format!("{}@{}{}", p.user, p.host, if port != 22 { format!(":{port}") } else { String::new() }),
        fingerprint,
        sudo_mode: SudoMode::Password,
        sudo_password: if p.sudo_password.is_empty() { p.password.clone() } else { p.sudo_password.clone() },
        shell: Mutex::new(None),
    };
    t.sudo_mode = t.detect_sudo().await?;
    Ok(Box::new(t))
}

fn is_auth_rejected(e: &anyhow::Error) -> bool {
    matches!(e.downcast_ref::<SshError>(), Some(SshError::AuthRejected { .. }))
}

fn map_connect_error(e: &anyhow::Error, host: &str, port: u16, user: &str, policy: &ConfirmedKeyOnly) -> TransportError {
    match e.downcast_ref::<SshError>() {
        Some(SshError::HostKeyChanged(d)) => TransportError::HostKey {
            host: host.to_string(),
            key_type: d.key_type.clone(),
            fingerprint: d.fingerprint.clone(),
            mismatch: true,
        },
        Some(SshError::HostKeyRejected) => match policy.seen.lock().ok().and_then(|s| s.clone()) {
            Some(prompt) => TransportError::HostKey { host: host.to_string(), key_type: prompt.key_type, fingerprint: prompt.fingerprint, mismatch: false },
            None => TransportError::Msg(format!("Could not connect to {host}:{port}: the host key was refused.")),
        },
        Some(SshError::AuthRejected { .. }) => TransportError::Msg(format!(
            "Authentication failed for {user}@{host}: the server didn't accept the password or key. Check them on the Connect step.")),
        _ => TransportError::Msg(format!("Could not connect to {host}:{port}: {e:#}")),
    }
}

impl SshTransport {
    async fn detect_sudo(&self) -> TResult<SudoMode> {
        let r = self.raw("id -u", None, 15).await?;
        if r.rc == 0 && r.stdout.trim() == "0" {
            return Ok(SudoMode::Root);
        }
        // -k: ignore any cached sudo timestamp, so success here really means NOPASSWD.
        let r = self.raw(appliance::SUDO_PROBE, None, 15).await?;
        Ok(if r.rc == 0 { SudoMode::Nopasswd } else { SudoMode::Password })
    }

    async fn raw(&self, line: &str, stdin: Option<&[u8]>, timeout_s: u64) -> TResult<Collected> {
        // Nothing stops a plain run; `_keep` holds the sender for the call's lifetime (a bare `_`
        // would drop it at once — 0.3.5–0.3.9 did, and every run ended as "stopped", rc -2).
        let (_keep, stop) = watch::channel(false);
        let mut c = Collected::default();
        let ended = self
            .raw_stream(line, stdin, timeout_s, &mut |s, t| {
                c.merged.push_str(t);
                match s {
                    Stream::Out => c.stdout.push_str(t),
                    Stream::Err => c.stderr.push_str(t),
                }
            }, stop)
            .await?;
        c.rc = match ended { Ended::Done(rc) => rc, Ended::Stopped => -2 };
        Ok(c)
    }

    /// `exec_line` + `raw` + the reference's wrong-sudo-password check, for `run` and `run_data`.
    async fn run_collected(&self, cmd: &str, sudo: bool, stdin: Option<&[u8]>, timeout_s: u64) -> TResult<Collected> {
        let (line, data) = exec_line(cmd, sudo, self.sudo_mode, &self.sudo_password, stdin)?;
        let c = self.raw(&line, data.as_deref(), timeout_s).await?;
        if sudo && self.sudo_mode == SudoMode::Password && c.rc != 0 && sudo_rejected(&c.merged) {
            return Err(TransportError::Msg("sudo rejected the password. Fix the Sudo password on the Connect step.".into()));
        }
        Ok(c)
    }

    /// Exec `line`, passing each piece of output to `on_text` with the stream it came from, in
    /// arrival order. `timeout_s` 0 means none. A stop or a timeout closes the channel.
    async fn raw_stream(
        &self,
        line: &str,
        stdin: Option<&[u8]>,
        timeout_s: u64,
        on_text: &mut (dyn FnMut(Stream, &str) + Send),
        stop: watch::Receiver<bool>,
    ) -> TResult<Ended> {
        if self.session.is_closed().await {
            return Err(TransportError::Msg("SSH connection is closed. Reconnect on the Connect step.".into()));
        }
        // Some(b"") rather than None keeps the end-of-input explicit whatever charon-ssh version.
        let (handle, mut rx) = self
            .session
            .exec_cancellable(line, Some(stdin.unwrap_or(b"")))
            .await
            .map_err(|e| TransportError::Msg(format!("Couldn't start a command on {}: {e:#}", self.host)))?;
        pump(&mut rx, &|| handle.close(), line, timeout_s, on_text, stop).await
    }
}

/// The loop behind `raw_stream`, apart from the SSH session so it can be unit-tested: read the
/// command's output until it ends, a timeout (`timeout_s`, 0 = none) or a stop request, calling
/// `close` on the last two. A stop *sender* that has gone away is not a stop request (the 0.3.10
/// fix: every plain run used to end as "stopped", rc -2).
async fn pump(
    rx: &mut tokio::sync::mpsc::Receiver<ExecOut>,
    close: &(dyn Fn() + Sync),
    line: &str,
    timeout_s: u64,
    on_text: &mut (dyn FnMut(Stream, &str) + Send),
    mut stop: watch::Receiver<bool>,
) -> TResult<Ended> {
    let deadline = (timeout_s > 0).then(|| tokio::time::Instant::now() + Duration::from_secs(timeout_s));
    let mut rc = -1; // paramiko's recv_exit_status() when the far end sent none
    // One decoder per stream: a character split across reads continues in its own stream.
    let (mut out8, mut err8) = (Utf8Chunks::default(), Utf8Chunks::default());
    // Already stopped before the command produced anything: honour it straight away.
    let mut stop_live = true;
    if *stop.borrow() {
        close();
        return Ok(Ended::Stopped);
    }
    loop {
        let sleep = async {
            match deadline {
                Some(d) => tokio::time::sleep_until(d).await,
                None => std::future::pending::<()>().await,
            }
        };
        tokio::select! {
            item = rx.recv() => match item {
                Some(ExecOut::Stdout(b)) => on_text(Stream::Out, &out8.push(&b)),
                Some(ExecOut::Stderr(b)) => on_text(Stream::Err, &err8.push(&b)),
                Some(ExecOut::Exit(c)) => rc = c as i32,
                Some(ExecOut::Eof) | None => break,
            },
            _ = sleep => {
                close();
                let shown: String = line.chars().take(120).collect();
                return Err(TransportError::Msg(format!("timed out after {timeout_s}s: {shown}")));
            }
            // A dropped sender means nobody can ask for a stop any more — not a stop.
            changed = stop.changed(), if stop_live => match changed {
                Err(_) => stop_live = false,
                Ok(()) if *stop.borrow() => {
                    close();
                    on_text(Stream::Out, &out8.finish());
                    on_text(Stream::Err, &err8.finish());
                    return Ok(Ended::Stopped);
                }
                Ok(()) => {}
            },
        }
    }
    on_text(Stream::Out, &out8.finish());
    on_text(Stream::Err, &err8.finish());
    Ok(Ended::Done(rc))
}

/// Which channel stream a piece of output came from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Stream {
    Out,
    Err,
}

/// A finished command: both streams merged in arrival order (for display), and each alone.
#[derive(Default, Debug)]
struct Collected {
    rc: i32,
    merged: String,
    stdout: String,
    stderr: String,
}

/// sudo's wrong-password messages (the reference's test; they arrive on stderr).
fn sudo_rejected(text: &str) -> bool {
    text.contains("incorrect password") || text.contains("Sorry, try again")
}

/// Decode UTF-8 across chunk boundaries (a multi-byte character can straddle two reads);
/// invalid bytes become U+FFFD, as Python's `decode(errors="replace")`.
#[derive(Default)]
struct Utf8Chunks {
    held: Vec<u8>,
}

impl Utf8Chunks {
    fn push(&mut self, b: &[u8]) -> String {
        self.held.extend_from_slice(b);
        let valid_up_to = match std::str::from_utf8(&self.held) {
            Ok(_) => self.held.len(),
            Err(e) if e.error_len().is_none() => e.valid_up_to(), // incomplete tail: keep it
            Err(_) => self.held.len(),
        };
        let out = String::from_utf8_lossy(&self.held[..valid_up_to]).into_owned();
        self.held.drain(..valid_up_to);
        out
    }
    fn finish(&mut self) -> String {
        let out = String::from_utf8_lossy(&self.held).into_owned();
        self.held.clear();
        out
    }
}

fn mode_name(m: SudoMode) -> &'static str {
    match m {
        SudoMode::Root => "root",
        SudoMode::Nopasswd => "nopasswd",
        SudoMode::Password => "password",
        SudoMode::Charon => "charon",
    }
}

#[async_trait]
impl Transport for SshTransport {
    fn kind(&self) -> &'static str { "ssh" }
    fn label(&self) -> String { self.label.clone() }
    fn login_user(&self) -> String { self.user.clone() }
    fn sudo_mode(&self) -> SudoMode { self.sudo_mode }
    fn info(&self) -> Value {
        json!({
            "kind": "ssh", "label": self.label, "user": self.user,
            "host": self.host, "port": self.port, "sudo_mode": mode_name(self.sudo_mode),
            "fingerprint": self.fingerprint, "shell": true,
        })
    }

    async fn run(&self, cmd: &str, sudo: bool, stdin: Option<&[u8]>, timeout_s: u64) -> TResult<(i32, String)> {
        let c = self.run_collected(cmd, sudo, stdin, timeout_s).await?;
        Ok((c.rc, c.merged))
    }

    async fn run_data(&self, cmd: &str, sudo: bool, stdin: Option<&[u8]>, timeout_s: u64) -> TResult<DataOut> {
        let c = self.run_collected(cmd, sudo, stdin, timeout_s).await?;
        Ok(DataOut { rc: c.rc, stdout: c.stdout, stderr: c.stderr })
    }

    async fn put_root(&self, path: &str, data: &[u8], mode: &str, dir_mode: &str) -> TResult<()> {
        let (rc, out) = self.run(&appliance::put_root_from_stdin(path, mode, dir_mode), true, Some(data), 120).await?;
        if rc != 0 {
            let tail: String = { let t = out.trim(); let n = t.chars().count(); t.chars().skip(n.saturating_sub(400)).collect() };
            return Err(TransportError::Msg(format!("writing {path} failed (exit {rc}): {tail}")));
        }
        Ok(())
    }

    async fn follow(&self, log: &str, rc: &str, on_text: &(dyn Fn(String) + Send + Sync), stop: watch::Receiver<bool>) -> TResult<Option<i32>> {
        let (line, _) = appliance::ssh_wrap(&appliance::ssh_follow(log, rc), false, self.sudo_mode);
        let mut scan = RcScanner::default();
        let ended = self
            .raw_stream(&line, None, 0, &mut |_, t| {
                let shown = scan.push(t);
                if !shown.is_empty() {
                    on_text(shown);
                }
            }, stop)
            .await?;
        let (rest, code) = scan.finish();
        if !rest.is_empty() {
            on_text(rest);
        }
        Ok(match ended {
            Ended::Stopped => None,
            Ended::Done(_) => code,
        })
    }

    async fn shell_open(&self, cols: u16, rows: u16, on_data: Box<dyn Fn(Vec<u8>) + Send + Sync>, on_close: Box<dyn Fn() + Send + Sync>) -> TResult<()> {
        let mut slot = self.shell.lock().await;
        if let Some(old) = slot.take() {
            old.close().await;
        }
        let (shell, mut rx) = self.session.open_shell(cols, rows).await
            .map_err(|e| TransportError::Msg(format!("Couldn't open a shell on {}: {e:#}", self.host)))?;
        *slot = Some(shell);
        tokio::spawn(async move {
            while let Some(o) = rx.recv().await {
                match o {
                    Output::Data(d) => on_data(d),
                    Output::Closed(_) => break,
                }
            }
            on_close();
        });
        Ok(())
    }

    async fn shell_input(&self, data: &[u8]) -> TResult<()> {
        match self.shell.lock().await.as_ref() {
            Some(s) => s.write(data).await.map_err(|_| TransportError::Msg("No shell open.".into())),
            None => Err(TransportError::Msg("No shell open.".into())),
        }
    }

    async fn shell_resize(&self, cols: u16, rows: u16) -> TResult<()> {
        if let Some(s) = self.shell.lock().await.as_ref() {
            let _ = s.resize(cols, rows).await;
        }
        Ok(())
    }

    async fn close(&self) {
        if let Some(s) = self.shell.lock().await.take() {
            s.close().await;
        }
        self.session.close().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn golden(k: &str) -> String {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/golden/transport-commands.json");
        let v: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
        v["commands"][k][0].as_str().unwrap().to_string()
    }

    #[test]
    fn exec_lines_match_the_reference_transport() {
        let (l, d) = exec_line(&appliance::put_root_from_stdin("/etc/morpheus/ssl/m_cust_test.key", "0600", "0700"), true, SudoMode::Nopasswd, "", Some(b"KEY")).unwrap();
        assert_eq!(l, golden("ssh_put_root"));
        assert_eq!(d.as_deref(), Some(&b"KEY"[..]));
        let (l, d) = exec_line("id -un", true, SudoMode::Password, "PW", None).unwrap();
        assert_eq!(l, golden("ssh_sudo_wrap_password"));
        assert_eq!(d.as_deref(), Some(&b"PW\n"[..]), "the password line goes first on stdin");
        let (_, d) = exec_line("cat > x", true, SudoMode::Password, "PW", Some(b"data")).unwrap();
        assert_eq!(d.as_deref(), Some(&b"PW\ndata"[..]));
        assert_eq!(exec_line("id -un", true, SudoMode::Nopasswd, "PW", None).unwrap(), (golden("ssh_sudo_wrap_nopasswd"), None));
        let (l, _) = appliance::ssh_wrap(&appliance::ssh_follow("/var/log/morpheus-certificate-install/R.log", "/var/log/morpheus-certificate-install/R.rc"), false, SudoMode::Password);
        assert_eq!(l, golden("ssh_stream_file"));
        // No password in password mode: a clear error, and nothing is run.
        let e = exec_line("id", true, SudoMode::Password, "", None).unwrap_err().to_string();
        assert!(e.contains("Sudo password"), "{e}");
        // The password is never part of the exec line.
        assert!(!exec_line("id", true, SudoMode::Password, "hunter2", None).unwrap().0.contains("hunter2"));
    }

    #[test]
    fn rc_marker_split_across_chunks() {
        for chunks in [vec!["log line\n\n@@RC=0\n"], vec!["log line\n\n@@R", "C=", "0", "\n"], vec!["log line\n\n@", "@RC=12\n"]] {
            let mut s = RcScanner::default();
            let mut shown = String::new();
            for c in &chunks { shown.push_str(&s.push(c)); }
            let (rest, rc) = s.finish();
            shown.push_str(&rest);
            assert_eq!(shown, "log line\n\n", "{chunks:?}");
            assert!(rc == Some(0) || rc == Some(12), "{chunks:?}: {rc:?}");
        }
        // No marker (stopped): everything is shown, no rc.
        let mut s = RcScanner::default();
        let a = s.push("abc @@");
        let (rest, rc) = s.finish();
        assert_eq!(format!("{a}{rest}"), "abc @@");
        assert_eq!(rc, None);
    }

    #[test]
    fn utf8_split_across_chunks() {
        let mut u = Utf8Chunks::default();
        let bytes = "→ ok".as_bytes();
        let mut s = u.push(&bytes[..1]);
        s.push_str(&u.push(&bytes[1..]));
        s.push_str(&u.finish());
        assert_eq!(s, "→ ok");
    }

    /// Feed `pump` a finished command and collect what it reports.
    async fn pumped(items: Vec<ExecOut>, stop: watch::Receiver<bool>, timeout_s: u64, keep_open: bool)
        -> (TResult<Ended>, String, usize) {
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        let _tx_alive = keep_open.then(|| tx.clone()); // keep the channel open: no Eof
        // Deliver the output a moment later, as a real command does: until then the stop branch is
        // the only one ready, which is exactly when a dropped sender used to be read as "stop".
        // (Queued up front, select! picks a ready branch at random and the old bug could hide.)
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            for i in items { let _ = tx.send(i).await; }
        });
        let closed = std::sync::atomic::AtomicUsize::new(0);
        let mut text = String::new();
        let r = pump(&mut rx, &|| { closed.fetch_add(1, std::sync::atomic::Ordering::SeqCst); },
                     "id -un", timeout_s, &mut |_, t| text.push_str(t), stop).await;
        (r, text, closed.load(std::sync::atomic::Ordering::SeqCst))
    }

    #[tokio::test]
    async fn a_run_without_a_stop_request_is_never_reported_stopped() {
        // The 0.3.10 bug: the stop sender was dropped at once, and that read as "stopped" (rc -2).
        let (_, stop) = watch::channel(false); // sender dropped right here, as the bug did
        let (r, text, closed) = pumped(vec![ExecOut::Stdout(b"root\n".to_vec()), ExecOut::Exit(0), ExecOut::Eof], stop, 30, false).await;
        assert!(matches!(r, Ok(Ended::Done(0))), "{:?}", r.as_ref().map(|e| matches!(e, Ended::Stopped)));
        assert_eq!((text.as_str(), closed), ("root\n", 0));
        // With the sender kept alive and never used: the same.
        let (_keep, stop) = watch::channel(false);
        let (r, _, _) = pumped(vec![ExecOut::Exit(3), ExecOut::Eof], stop, 30, false).await;
        assert!(matches!(r, Ok(Ended::Done(3))));
    }

    #[tokio::test]
    async fn a_real_stop_request_stops_and_closes() {
        let (tx, stop) = watch::channel(false);
        tx.send(true).unwrap();
        let (r, _, closed) = pumped(vec![], stop, 30, true).await;
        assert!(matches!(r, Ok(Ended::Stopped)));
        assert_eq!(closed, 1);
    }

    #[tokio::test]
    async fn a_timeout_closes_and_says_so() {
        let (_keep, stop) = watch::channel(false);
        let (r, _, closed) = pumped(vec![ExecOut::Stdout(b"partial".to_vec())], stop, 1, true).await;
        let e = match r { Err(e) => e.to_string(), Ok(_) => panic!("no timeout") };
        assert!(e.starts_with("timed out after 1s: id -un"), "{e}");
        assert_eq!(closed, 1);
    }

    #[test]
    fn home_expansion() {
        let h = dirs::home_dir().unwrap();
        assert_eq!(expand_home("~/.ssh/id"), h.join(".ssh/id").to_string_lossy());
        assert_eq!(expand_home("/abs/key"), "/abs/key");
    }
}
