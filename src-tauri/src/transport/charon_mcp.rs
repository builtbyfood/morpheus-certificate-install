//! morpheus-certificate-install 0.4.2 — drive an open Charon session over Charon's MCP server. **Round 1, R6.**
//!
//! Contract (builtbyfood/charon src-tauri/src/mcp): POST JSON-RPC to http://127.0.0.1:<port>/ with
//! `Authorization: Bearer <token>`; port+token from `<charon data>/mcp-endpoint.json`. Methods:
//! `initialize`, `tools/call` {name, arguments}. Tool results: {content:[{type:"text",text}], isError?};
//! text is JSON for list_sessions / run_command ({output, exit_code}) / sftp_put ({ok}).
//!
//! * Discovery dirs (first hit wins), as the reference: a user-entered dir (portable Charon's data/),
//!   CHARON_DATA, %APPDATA%\charon (Windows), ~/Library/Application Support/charon (macOS),
//!   $XDG_CONFIG_HOME|~/.config/charon.
//! * Saved hosts: `<charon data>/charon.db`, opened READ-ONLY. Only `json_extract` of the keys shown
//!   (host, port, user, jump_host, tags) is asked of SQLite, so nothing else in a node's settings —
//!   a `credential` above all — ever reaches this process. Effective settings = walk parents
//!   root→leaf, later non-null wins.
//! * run (display): `run_command` {session, command: appliance::charon_wrap(cmd, sudo), timeout_s ≤ 600};
//!   CR is stripped before the text goes anywhere. Charon's hidden capture times out at 120 s, so only
//!   short commands go through it; long work is the detached runner. "denied" in an error →
//!   "Denied in Charon's approval dialog."
//! * run_data (data): run_command's output comes from a terminal — merged streams, CRLF, escape
//!   sequences, sudo's lecture and prompt — so it isn't trusted. The command goes out framed by
//!   appliance::charon_data_read (stdout and stderr base64 between markers, stderr via a file in the
//!   0700 staging dir that is always removed, rc last) and appliance::parse_charon_data_read decodes
//!   it; anything outside the frame is ignored. (docs/PARITY.md divergence 21.)
//! * put_root: data to a local temp file (0600 on Unix), `sftp_put` to `$HOME/<CHARON_STAGE>/put-<ms>`
//!   (stage dir from appliance::charon_make_stage), appliance::put_root_from_staged under sudo, then
//!   appliance::shred of the staged copy whatever happened. The local temp file is always deleted.
//! * follow: long-poll with appliance::charon_long_poll(log, rc, offset, LONG_POLL_S) as a framed
//!   data read (0.3.16; was charon_poll every 2 s): the command waits on the appliance until the log
//!   grows, the rc file appears or LONG_POLL_S pass, then returns the new bytes. Decode the base64
//!   payload, advance the offset by the decoded length, poll again at once; stop when RC= is non-empty.
//! * sudo_mode: Nopasswd if appliance::SUDO_PROBE exits 0, else Charon (Charon answers the prompt).
//!
//! The MCP token is a secret: never logged, never in an error or event.

use super::{DataOut, TResult, Transport, TransportError};
use async_trait::async_trait;
use mci_core::appliance::{self, SudoMode};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::{watch, Mutex};

/// How long one follow poll waits on the appliance for new output: under Charon's 120 s command limit.
pub const LONG_POLL_S: u32 = 90;

// ------------------------------------------------------------------ discovery

pub struct Discovery {
    pub searched: Vec<String>,
    pub data_dir: Option<PathBuf>,
    /// (port, has_token) from mcp-endpoint.json.
    pub endpoint: Option<(u16, bool)>,
    pub sessions: Option<Vec<Value>>,
    pub sessions_error: Option<String>,
    pub hosts: Vec<Value>,
}

impl Discovery {
    /// The reference's `/api/charon` body.
    pub fn to_json(&self) -> Value {
        let mut v = json!({
            "searched": self.searched,
            "data_dir": self.data_dir.as_ref().map(|d| d.to_string_lossy().into_owned()),
            "endpoint": self.endpoint.map(|(port, has_token)| json!({"port": port, "has_token": has_token})),
            "hosts": self.hosts,
        });
        if let Some(s) = &self.sessions { v["sessions"] = json!(s); }
        if let Some(e) = &self.sessions_error { v["sessions_error"] = json!(e); }
        v
    }
}

fn expand_home(p: &str) -> PathBuf {
    match p.strip_prefix("~/").or_else(|| p.strip_prefix("~\\")) {
        Some(rest) => dirs::home_dir().map(|h| h.join(rest)).unwrap_or_else(|| PathBuf::from(p)),
        None => PathBuf::from(p),
    }
}

/// Where Charon may keep its data, in the reference's order.
pub fn data_dirs(extra_dir: &str) -> Vec<PathBuf> {
    let mut v = Vec::new();
    if !extra_dir.trim().is_empty() { v.push(expand_home(extra_dir.trim())); }
    if let Ok(d) = std::env::var("CHARON_DATA") { if !d.is_empty() { v.push(PathBuf::from(d)); } }
    if cfg!(windows) {
        if let Ok(a) = std::env::var("APPDATA") { v.push(PathBuf::from(a).join("charon")); }
    } else if cfg!(target_os = "macos") {
        if let Some(h) = dirs::home_dir() { v.push(h.join("Library/Application Support/charon")); }
    }
    let xdg = std::env::var("XDG_CONFIG_HOME").ok().filter(|s| !s.is_empty()).map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|h| h.join(".config")));
    if let Some(x) = xdg { v.push(x.join("charon")); }
    let mut seen = std::collections::HashSet::new();
    v.retain(|d| seen.insert(d.to_string_lossy().into_owned()));
    v
}

/// Find Charon's MCP endpoint, its saved SSH hosts (never credentials) and its open sessions.
pub async fn discover(extra_dir: &str) -> Discovery {
    let dirs = data_dirs(extra_dir);
    let mut d = Discovery {
        searched: dirs.iter().map(|p| p.to_string_lossy().into_owned()).collect(),
        data_dir: None, endpoint: None, sessions: None, sessions_error: None, hosts: vec![],
    };
    for dir in dirs {
        if !dir.is_dir() || !(dir.join("mcp-endpoint.json").exists() || dir.join("charon.db").exists()) { continue; }
        if let Ok((port, token)) = read_endpoint(&dir) { d.endpoint = Some((port, !token.is_empty())); }
        let db = dir.join("charon.db");
        if db.exists() { d.hosts = saved_hosts(&db).unwrap_or_default(); }
        if let Ok((port, token)) = read_endpoint(&dir) {
            match Rpc::new(port, token).and_then_init().await {
                Ok(rpc) => match rpc.tool("list_sessions", json!({}), 30).await {
                    Ok(Value::Array(s)) => d.sessions = Some(s),
                    Ok(other) => d.sessions_error = Some(format!("Charon list_sessions returned {other}")),
                    Err(e) => d.sessions_error = Some(e.to_string()),
                },
                Err(e) => d.sessions_error = Some(e.to_string()),
            }
        }
        d.data_dir = Some(dir);
        break;
    }
    d
}

fn read_endpoint(dir: &Path) -> TResult<(u16, String)> {
    let text = std::fs::read_to_string(dir.join("mcp-endpoint.json")).map_err(|e| TransportError::Msg(format!(
        "Couldn't read Charon's mcp-endpoint.json in {}: {e}. Enable the MCP server in Charon's settings.", dir.display())))?;
    let v: Value = serde_json::from_str(&text).map_err(|_| TransportError::Msg(format!(
        "Charon's mcp-endpoint.json in {} isn't valid JSON. Restart the MCP server in Charon.", dir.display())))?;
    let port = v["port"].as_u64().and_then(|p| u16::try_from(p).ok())
        .ok_or_else(|| TransportError::Msg("Charon's mcp-endpoint.json has no port. Restart the MCP server in Charon.".into()))?;
    Ok((port, v["token"].as_str().unwrap_or("").to_string()))
}

/// Saved SSH hosts from charon.db, read-only, and only the fields shown — see the module docs.
pub fn saved_hosts(db: &Path) -> Result<Vec<Value>, String> {
    use rusqlite::{types::Value as Sql, Connection, OpenFlags};
    let con = Connection::open_with_flags(db, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX)
        .map_err(|e| e.to_string())?;
    let _ = con.busy_timeout(Duration::from_secs(2));
    // Only these keys are extracted inside SQLite; nothing else of `settings` is read.
    let mut st = con.prepare(
        "SELECT id, parent_id, kind, name, \
                json_extract(settings, '$.host'), json_extract(settings, '$.port'), json_extract(settings, '$.user'), \
                json_extract(settings, '$.jump_host'), json_extract(settings, '$.tags') \
         FROM nodes").map_err(|e| e.to_string())?;
    let to_json = |v: Sql| -> Value {
        match v {
            Sql::Null => Value::Null,
            Sql::Integer(i) => json!(i),
            Sql::Real(f) => json!(f),
            Sql::Text(t) => json!(t),
            Sql::Blob(_) => Value::Null,
        }
    };
    struct Node { id: Value, parent: Value, kind: String, name: String, fields: [Value; 5] }
    let rows = st.query_map([], |r| {
        Ok(Node {
            id: to_json(r.get::<_, Sql>(0)?),
            parent: to_json(r.get::<_, Sql>(1)?),
            kind: r.get::<_, Option<String>>(2)?.unwrap_or_default(),
            name: r.get::<_, Option<String>>(3)?.unwrap_or_default(),
            fields: [to_json(r.get(4)?), to_json(r.get(5)?), to_json(r.get(6)?), to_json(r.get(7)?), to_json(r.get(8)?)],
        })
    }).map_err(|e| e.to_string())?;
    let nodes: Vec<Node> = rows.filter_map(Result::ok).collect();
    let by_id: std::collections::HashMap<String, &Node> = nodes.iter().map(|n| (n.id.to_string(), n)).collect();
    let mut out = Vec::new();
    for n in nodes.iter().filter(|n| n.kind == "ssh") {
        // chain leaf → root (cycle-safe), then apply root → leaf, later non-null wins
        let mut chain = vec![n];
        let mut cur = n.parent.clone();
        while !cur.is_null() && chain.len() < 50 {
            match by_id.get(&cur.to_string()) { Some(p) => { chain.push(p); cur = p.parent.clone(); } None => break }
        }
        let mut eff: [Value; 5] = Default::default();
        let mut path = Vec::new();
        for node in chain.iter().rev() {
            path.push(node.name.clone());
            for (i, f) in node.fields.iter().enumerate() { if !f.is_null() { eff[i] = f.clone(); } }
        }
        let [host, port, user, jump, tags] = eff;
        if host.is_null() || host.as_str() == Some("") { continue; }
        // tags are stored as a JSON array; json_extract hands it back as text
        let tags = match tags { Value::String(s) => serde_json::from_str(&s).unwrap_or(json!([])), Value::Null => json!([]), t => t };
        path.pop();
        out.push(json!({
            "id": n.id, "name": n.name, "path": path.join(" / "), "host": host,
            "port": if port.is_null() { json!(22) } else { port },
            "user": if user.is_null() { json!("") } else { user },
            "jump_host": jump, "tags": tags,
        }));
    }
    out.sort_by(|a, b| (a["path"].as_str(), a["name"].as_str()).cmp(&(b["path"].as_str(), b["name"].as_str())));
    Ok(out)
}

// ------------------------------------------------------------------ JSON-RPC

struct Rpc {
    http: reqwest::Client,
    url: String,
    token: String,
    id: AtomicU64,
}

impl Rpc {
    fn new(port: u16, token: String) -> Self {
        Rpc { http: reqwest::Client::new(), url: format!("http://127.0.0.1:{port}/"), token, id: AtomicU64::new(0) }
    }

    async fn and_then_init(self) -> TResult<Self> {
        self.call("initialize", json!({"protocolVersion": "2024-11-05", "capabilities": {},
            "clientInfo": {"name": mci_core::SLUG, "version": mci_core::VERSION}}), 30).await?;
        Ok(self)
    }

    async fn call(&self, method: &str, params: Value, timeout_s: u64) -> TResult<Value> {
        let id = self.id.fetch_add(1, Ordering::SeqCst) + 1;
        let resp = self.http.post(&self.url)
            .bearer_auth(&self.token)
            .timeout(Duration::from_secs(timeout_s))
            .json(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
            .send().await
            .map_err(|e| TransportError::Msg(format!(
                "Could not reach Charon's MCP server at {} — is it enabled? ({})", self.url, without_url(&e))))?;
        if resp.status().as_u16() == 401 {
            return Err(TransportError::Msg("Charon rejected the MCP token. Restart the MCP server in Charon and rediscover.".into()));
        }
        if !resp.status().is_success() {
            return Err(TransportError::Msg(format!("Charon MCP HTTP {}", resp.status().as_u16())));
        }
        let v: Value = resp.json().await.map_err(|e| TransportError::Msg(format!("Charon sent a reply that isn't JSON-RPC ({e}).")))?;
        if let Some(err) = v.get("error") {
            return Err(TransportError::Msg(format!("Charon: {}", err["message"].as_str().unwrap_or("error"))));
        }
        Ok(v.get("result").cloned().unwrap_or(Value::Null))
    }

    /// A tool's result: its text parsed as JSON when it is JSON, else the text.
    async fn tool(&self, name: &str, args: Value, timeout_s: u64) -> TResult<Value> {
        let res = self.call("tools/call", json!({"name": name, "arguments": args}), timeout_s).await?;
        let text: String = res["content"].as_array().map(|c| c.iter().filter_map(|x| x["text"].as_str()).collect()).unwrap_or_default();
        if res["isError"].as_bool() == Some(true) {
            if text.to_lowercase().contains("denied") {
                return Err(TransportError::Msg("Denied in Charon's approval dialog.".into()));
            }
            return Err(TransportError::Msg(format!("Charon {name}: {text}")));
        }
        Ok(serde_json::from_str(&text).unwrap_or(Value::String(text)))
    }
}

/// reqwest's error text includes the URL; ours is in the message already.
fn without_url(e: &reqwest::Error) -> String {
    let s = e.to_string();
    if e.is_timeout() { "timed out".into() } else if e.is_connect() { "connection refused".into() } else { s }
}

// ------------------------------------------------------------------ the transport

pub struct CharonTransport {
    rpc: Rpc,
    session: String,
    label: String,
    tier: String,
    login_user: String,
    sudo_mode: SudoMode,
    stage: Mutex<Option<String>>,
}

/// Connect to `session` through the Charon whose data dir is `data_dir`.
pub async fn connect(data_dir: &Path, session: &str) -> TResult<Box<dyn Transport>> {
    let (port, token) = read_endpoint(data_dir)?;
    let rpc = Rpc::new(port, token).and_then_init().await?;
    let sessions = rpc.tool("list_sessions", json!({}), 30).await?;
    let m = sessions.as_array().and_then(|a| a.iter().find(|s| s["id"].as_str() == Some(session)).cloned())
        .ok_or_else(|| TransportError::Msg("That Charon session is no longer open. Refresh the session list.".into()))?;
    if m["kind"].as_str() != Some("ssh") {
        return Err(TransportError::Msg("Pick an SSH session in Charon (this one is local/serial).".into()));
    }
    let shown = m["title"].as_str().filter(|s| !s.is_empty()).or(m["host"].as_str()).unwrap_or(session);
    let mut t = CharonTransport {
        rpc,
        session: session.to_string(),
        label: format!("Charon · {shown}"),
        tier: m["tier"].as_str().unwrap_or("").to_string(),
        login_user: String::new(),
        sudo_mode: SudoMode::Charon,
        stage: Mutex::new(None),
    };
    let who = t.run_data("id -un", false, None, 60).await?;
    if who.rc != 0 {
        return Err(TransportError::Msg(format!("Charon could not run a command in that session: {}", who.complaint(300))));
    }
    t.login_user = who.stdout.trim().to_string();
    let (rc, _) = t.run(appliance::SUDO_PROBE, false, None, 60).await?;
    t.sudo_mode = if rc == 0 { SudoMode::Nopasswd } else { SudoMode::Charon };
    Ok(Box::new(t))
}

impl CharonTransport {
    async fn run_command(&self, line: &str, timeout_s: u64) -> TResult<(i32, String)> {
        let t = timeout_s.clamp(1, 600);
        let v = self.rpc.tool("run_command", json!({"session": self.session, "command": line, "timeout_s": t}), t + 30).await?;
        let rc = v["exit_code"].as_i64().map(|c| c as i32).unwrap_or(-1);
        let out = match &v { Value::Object(_) => v["output"].as_str().unwrap_or("").to_string(), Value::String(s) => s.clone(), o => o.to_string() };
        Ok((rc, out))
    }

    /// `$HOME/<CHARON_STAGE>`, made 0700 once per connection.
    async fn stage_dir(&self) -> TResult<String> {
        let mut g = self.stage.lock().await;
        if let Some(s) = g.as_ref() { return Ok(s.clone()); }
        let (rc, out) = self.run_command(&appliance::charon_wrap(&appliance::charon_make_stage(), false), 60).await?;
        let clean = appliance::strip_terminal(&out);
        let dir = clean.lines().map(str::trim).rfind(|l| l.starts_with('/') && l.ends_with(appliance::CHARON_STAGE))
            .ok_or_else(|| TransportError::Msg(format!("Couldn't create the staging folder in the session's home (exit {rc}).")))?
            .to_string();
        *g = Some(dir.clone());
        Ok(dir)
    }

    fn nonce() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..16].to_string()
    }
}

fn mode_name(m: SudoMode) -> &'static str {
    match m { SudoMode::Root => "root", SudoMode::Nopasswd => "nopasswd", SudoMode::Password => "password", SudoMode::Charon => "charon" }
}

#[async_trait]
impl Transport for CharonTransport {
    fn kind(&self) -> &'static str { "charon" }
    fn label(&self) -> String { self.label.clone() }
    fn login_user(&self) -> String { self.login_user.clone() }
    fn sudo_mode(&self) -> SudoMode { self.sudo_mode }
    fn info(&self) -> Value {
        json!({"kind": "charon", "label": self.label, "user": self.login_user, "tier": self.tier,
               "sudo_mode": mode_name(self.sudo_mode), "shell": false, "session": self.session})
    }

    async fn run(&self, cmd: &str, sudo: bool, stdin: Option<&[u8]>, timeout_s: u64) -> TResult<(i32, String)> {
        if stdin.is_some() {
            return Err(TransportError::Msg("internal: the Charon transport passes data through files, not stdin".into()));
        }
        let (rc, out) = self.run_command(&appliance::charon_wrap(cmd, sudo && self.sudo_mode != SudoMode::Root), timeout_s).await?;
        Ok((rc, appliance::strip_cr(&out)))
    }

    async fn run_data(&self, cmd: &str, sudo: bool, stdin: Option<&[u8]>, timeout_s: u64) -> TResult<DataOut> {
        if stdin.is_some() {
            return Err(TransportError::Msg("internal: the Charon transport passes data through files, not stdin".into()));
        }
        let stage = self.stage_dir().await?;
        let nonce = Self::nonce();
        let line = appliance::charon_data_read(cmd, sudo && self.sudo_mode != SudoMode::Root, &stage, &nonce);
        let (_, out) = self.run_command(&line, timeout_s).await?;
        let d = appliance::parse_charon_data_read(&out, &nonce).map_err(TransportError::Msg)?;
        Ok(DataOut {
            rc: d.rc,
            stdout: String::from_utf8_lossy(&d.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&d.stderr).into_owned(),
        })
    }

    async fn put_root(&self, path: &str, data: &[u8], mode: &str, dir_mode: &str) -> TResult<()> {
        let stage = self.stage_dir().await?;
        let ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
        let remote = format!("{stage}/put-{ms}-{}", &Self::nonce()[..6]);
        // Local copy for sftp_put: owner-only, always deleted.
        let local = std::env::temp_dir().join(format!("mci-put-{ms}-{}", Self::nonce()));
        let write = || -> std::io::Result<()> {
            let mut o = std::fs::OpenOptions::new();
            o.write(true).create_new(true);
            #[cfg(unix)]
            { use std::os::unix::fs::OpenOptionsExt; o.mode(0o600); }
            std::io::Write::write_all(&mut o.open(&local)?, data)
        };
        let sent = match write() {
            Ok(()) => self.rpc.tool("sftp_put", json!({"session": self.session, "local": local.to_string_lossy(), "remote": remote}), 300).await.map(|_| ()),
            Err(e) => Err(TransportError::Msg(format!("Couldn't write a temporary file for {path}: {e}"))),
        };
        let _ = std::fs::remove_file(&local);
        // From here the staged copy may exist on the appliance: shred it whatever happens next.
        let installed = match sent {
            Ok(()) => match self.run(&appliance::put_root_from_staged(&remote, path, mode, dir_mode), true, None, 120).await {
                Ok((0, _)) => Ok(()),
                Ok((rc, out)) => {
                    let t = out.trim();
                    let tail: String = t.chars().skip(t.chars().count().saturating_sub(400)).collect();
                    Err(TransportError::Msg(format!("install {path} failed (exit {rc}): {tail}")))
                }
                Err(e) => Err(e),
            },
            Err(e) => Err(e),
        };
        let shredded = self.run(&appliance::shred(&remote), false, None, 60).await;
        installed?;
        shredded.map(|_| ())
    }

    async fn follow(&self, log: &str, rc: &str, on_text: &(dyn Fn(String) + Send + Sync), mut stop: watch::Receiver<bool>) -> TResult<Option<i32>> {
        let mut off: u64 = 0;
        let mut stop_live = true;
        loop {
            if *stop.borrow() { return Ok(None); }
            // A long poll (0.3.16): the command waits on the appliance for new output, the rc file,
            // or LONG_POLL_S, so at the exec-approve tier there's one approval per update, not one
            // every 2 s. A stop request abandons the poll at once (the remote wait just runs out).
            let cmd = appliance::charon_long_poll(log, rc, off, LONG_POLL_S);
            let poll = self.run_data(&cmd, false, None, u64::from(LONG_POLL_S) + 25);
            tokio::pin!(poll);
            let r = loop {
                tokio::select! {
                    r = &mut poll => break r?,
                    // A dropped sender means nobody can ask for a stop any more — not a stop.
                    changed = stop.changed(), if stop_live => match changed {
                        Err(_) => stop_live = false,
                        Ok(()) => if *stop.borrow() { return Ok(None) },
                    },
                }
            };
            let lines: Vec<&str> = r.stdout.lines().collect();
            let rcv = lines.iter().find_map(|l| l.strip_prefix("RC=")).unwrap_or("").trim().to_string();
            let payload = lines.iter().position(|l| l.starts_with("RC=")).and_then(|i| lines.get(i + 1)).map(|l| l.trim()).unwrap_or("");
            if !payload.is_empty() {
                use base64::Engine;
                if let Ok(chunk) = base64::engine::general_purpose::STANDARD.decode(payload) {
                    off += chunk.len() as u64;
                    on_text(String::from_utf8_lossy(&chunk).into_owned());
                    continue; // more may be waiting; poll again straight away
                }
            }
            if !rcv.is_empty() {
                return Ok(Some(rcv.parse().unwrap_or(-1)));
            }
            // Nothing new within LONG_POLL_S: wait again straight away.
        }
    }
}
