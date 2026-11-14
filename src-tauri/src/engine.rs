//! morpheus-certificate-install 0.4.2 — the command handlers and job orchestration (R7).
//!
//! Port of reference/python app.py (handlers) + engine.py (preflight/plan/apply/verify/rollback).
//! Request/response JSON = the Python /api/* bodies; events = events.rs.
//!
//! **Data reads go through crate::reads** (Transport::run_data, stdout only): morpheus.rb, its
//! stat mode, served_chain, list_runs, list_backups, manifests and the preflight KEY=VALUE facts.
//! `run` (merged stdout+stderr) is only for commands whose output is shown or whose exit code is
//! the answer (backup, key/cert match, launching the runner, the rollback restore).
//!
//! **Every morpheus.rb write passes the appliance_url guard** (`morpheus_rb::guard`,
//! PARITY divergence 19): plan builds the new text with `transform_checked`, apply re-reads with
//! `reads::morpheus_rb_for_edit` before writing anything and transforms with `transform_checked`, rollback checks the
//! backup's copy with `reads::backup_morpheus_rb_checked` before restoring anything.
//!
//! apply — the appliance sequence is fixtures/golden/apply-command-sequence.json (tested below
//! with a recording transport):
//!   1 backup: run(sudo) appliance::backup(BACKUP_DIR/<stamp>); put_root manifest.json 0600
//!   0 server: read morpheus.rb and run the appliance_url guard first; on refusal nothing at all is
//!     written (PARITY divergence 19; the golden's `rust_expect_override` moves this read here)
//!   2 server: put_root <crt> 0600; put_root <key> 0600; stat mode; put_root morpheus.rb (edited from
//!     the text read in 0, same mode); run(sudo) key_matches_cert → must exit 0
//!   3 trust: put_root TRUST_DIR/<alias>.pem 0644, dir 0755, root first then intermediates
//!   4 runner: put_root RUN_DIR/<id>.sh 0700; run(sudo) launch_runner; emit Run; follow
//!   5 (the apply job) on rc 0: verify and emit Verify.
//!
//! Jobs: one at a time ("Another operation is running…"); `stop` stops following, not the remote
//! run; events go on `mci`.

use crate::events::{log, step, Event, StepStatus};
use crate::state::{AppState, Emit};
use crate::transport::{Transport, TransportError};
use crate::{morpheus_api, reads, verify as tls};
use base64::Engine as _;
use mci_core::analyze::{self, Analysis};
use mci_core::appliance::{self, BACKUP_DIR, LOG_DIR, MORPHEUS_RB, RUN_DIR, SSL_DIR, TRUST_DIR};
use mci_core::formats::{InputFile, Passwords};
use mci_core::runner::{self, Mode, RunnerPlan};
use mci_core::{morpheus_rb, names};
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tauri::{AppHandle, Runtime};
use tokio::sync::watch;

type Res = Result<Value, String>;

fn te(e: TransportError) -> String { e.to_string() }

// ------------------------------------------------------------------ small helpers

/// Python truthiness of a JSON value.
fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// `b.get(k, "")` as text (numbers as their text).
fn s(b: &Value, k: &str) -> String {
    match b.get(k) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

/// `int(b.get(k) or default)`; the page sends ports as text.
fn port(b: &Value, k: &str, default: u16) -> Result<u16, String> {
    let t = s(b, k);
    let t = t.trim();
    if t.is_empty() { return Ok(default); }
    t.parse().map_err(|_| format!("{t:?} isn't a port number. Use a number from 1 to 65535."))
}

/// Local time `YYYYmmdd-HHMMSS`, the reference's stamp().
pub fn stamp() -> String {
    let t = time::OffsetDateTime::now_local().unwrap_or_else(|_| time::OffsetDateTime::now_utc());
    format!("{:04}{:02}{:02}-{:02}{:02}{:02}", t.year(), t.month() as u8, t.day(), t.hour(), t.minute(), t.second())
}

fn now_unix() -> i64 { time::OffsetDateTime::now_utc().unix_timestamp() }

fn watch_cmd(run_id: &str) -> String { format!("tail -n +1 -F {LOG_DIR}/{run_id}.log") }

/// The tier of a Charon session that isn't `trusted` (each command then needs approval in Charon).
fn approval_tier(t: &dyn Transport) -> Option<String> {
    let i = t.info();
    (i["kind"] == "charon" && i["tier"] != "trusted").then(|| i["tier"].as_str().unwrap_or("unknown").to_string())
}

/// A run started or was re-attached: the Run event, and, when Charon asks for approval for each
/// command, a notice in the Run log with the line to follow it in the Charon tab instead (0.3.16).
fn run_started(t: &dyn Transport, emit: &Emit, run_id: &str) {
    emit(Event::Run { id: run_id.into(), watch: watch_cmd(run_id) });
    if let Some(tier) = approval_tier(t) {
        emit(log(format!(
            "The Charon session is at the {tier} tier, so each update of this log needs your approval in Charon \
             (one per new output, at most one every 90 s while it's quiet). To follow it in the Charon tab instead, run there:\n  {}\n",
            watch_cmd(run_id))));
    }
}

// ------------------------------------------------------------------ settings (no secrets)

pub const SETTINGS_KEYS: [&str; 10] = ["host", "port", "user", "key_path", "fqdn", "connect_addr", "morpheus_url", "mode", "charon_dir", "tls_port"];

pub fn load_settings(st: &AppState) -> Value {
    std::fs::read_to_string(st.paths.settings()).ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({}))
}

/// Write settings.json as given (no-op under "Leave no trace").
pub fn write_settings(st: &AppState, v: &Value) -> Result<(), String> {
    if st.leave_no_trace.load(Ordering::SeqCst) { return Ok(()); }
    let _ = std::fs::create_dir_all(&st.paths.data_dir);
    std::fs::write(st.paths.settings(), serde_json::to_string_pretty(v).unwrap_or_default())
        .map_err(|e| format!("Couldn't write {}: {e}", st.paths.settings().display()))
}

/// Merge `d` into settings.json, keeping only the allowed keys (no secrets on disk: SECURITY.md).
/// Nothing is written under portable mode's "Leave no trace".
pub fn save_settings(st: &AppState, d: Value) {
    if st.leave_no_trace.load(Ordering::SeqCst) { return; }
    let mut cur = load_settings(st);
    if let (Some(c), Some(d)) = (cur.as_object_mut(), d.as_object()) {
        for (k, v) in d {
            if SETTINGS_KEYS.contains(&k.as_str()) {
                c.insert(k.clone(), v.clone());
            }
        }
    }
    let _ = std::fs::create_dir_all(&st.paths.data_dir);
    let _ = std::fs::write(st.paths.settings(), serde_json::to_string_pretty(&cur).unwrap_or_default());
}

// ------------------------------------------------------------------ jobs

/// Run `work` as the one job, emitting job running / done / error. Its error text is logged too.
fn start_job<F, Fut>(st: &Arc<AppState>, name: &'static str, work: F) -> Result<(), String>
where
    F: FnOnce(watch::Receiver<bool>) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<Value, String>> + Send + 'static,
{
    if st.busy.swap(true, Ordering::SeqCst) {
        return Err("Another operation is running. Wait for it, or stop following it first.".into());
    }
    st.stop.send_replace(false);
    let rx = st.stop.subscribe();
    let (emit, busy) = (st.emit.clone(), st.busy.clone());
    tauri::async_runtime::spawn(async move {
        emit(Event::Job { name: name.into(), status: "running".into(), result: None, error: None });
        // A panic in the job must still clear `busy` and report.
        let r = tokio::spawn(work(rx)).await.unwrap_or_else(|e| Err(format!("internal error: {e}")));
        busy.store(false, Ordering::SeqCst);
        match r {
            Ok(v) => emit(Event::Job { name: name.into(), status: "done".into(), result: Some(v), error: None }),
            Err(e) => {
                emit(log(format!("\n✖ {e}\n")));
                emit(Event::Job { name: name.into(), status: "error".into(), result: None, error: Some(e) });
            }
        }
    });
    Ok(())
}

async fn need_t(st: &AppState) -> Result<Arc<dyn Transport>, String> {
    st.transport.lock().await.clone().ok_or_else(|| "Not connected. Connect to the appliance first.".to_string())
}

// ------------------------------------------------------------------ preflight / served chain

/// What nginx serves on 127.0.0.1:443 (the reference's served_chain()).
pub async fn served_chain(t: &dyn Transport, sni: &str) -> Result<Value, String> {
    let (_, out) = reads::served_chain(t, sni).await.map_err(te)?;
    let chain = mci_core::formats::certs_from_pem_text(&out, "served");
    let Some(leaf) = chain.first() else {
        return Ok(json!({"ok": false, "error": "nothing answered TLS on 127.0.0.1:443"}));
    };
    Ok(json!({
        "ok": true,
        "leaf": analyze::summary(leaf, "served", now_unix()),
        "chain_len": chain.len(),
        "fingerprints": chain.iter().map(|c| c.fp256()).collect::<Vec<_>>(),
    }))
}

pub async fn run_preflight(t: &dyn Transport, emit: &Emit) -> Result<Value, String> {
    let mut facts = Map::new();
    facts.insert("transport".into(), t.info());
    emit(log("Checking the appliance…\n"));
    for (k, v) in reads::preflight(t).await.map_err(te)? {
        facts.insert(k, json!(v));
    }
    let rb = reads::morpheus_rb_opt(t).await.map_err(te)?;
    let rb_text = rb.clone().unwrap_or_default();
    facts.insert("morpheus_rb".into(), json!(rb_text));
    let nginx: Map<String, Value> = if rb.is_some() {
        morpheus_rb::current_nginx_ssl(&rb_text).into_iter().map(|(k, v)| (k, json!(v))).collect()
    } else {
        Map::new()
    };
    facts.insert("nginx_ssl".into(), Value::Object(nginx));
    if let Some(u) = reads::appliance_url_from_rb(&rb_text) {
        facts.insert("appliance_url_rb".into(), json!(u));
    }
    facts.insert("served".into(), served_chain(t, "").await?);
    let get = |k: &str| facts.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let mut problems = vec![];
    if get("mctl").is_empty() { problems.push("morpheus-ctl not found — is this a Morpheus appliance (Manager)?".to_string()); }
    if get("rb") != "yes" { problems.push(format!("{MORPHEUS_RB} is missing.")); }
    if get("openssl").is_empty() { problems.push("openssl is not installed on the appliance; verification steps will be skipped.".into()); }
    facts.insert("problems".into(), json!(problems));
    Ok(Value::Object(facts))
}

fn public_facts(f: &Value) -> Value {
    let mut f = f.clone();
    if let Some(o) = f.as_object_mut() { o.remove("morpheus_rb"); }
    f
}

// ------------------------------------------------------------------ plan

#[derive(Debug, Clone, Serialize)]
pub struct Plan {
    pub stamp: String,
    pub crt: String,
    pub key: String,
    pub server: bool,
    pub trust: bool,
    pub restart_ui: bool,
    pub include_root: bool,
    pub storepass: String,
    pub steps: Vec<Value>,
    pub rb_diff: String,
    pub rb_new: String,
    pub aliases: Vec<String>,
    pub systemd: bool,
}

impl Plan {
    /// The plan without `rb_new` (the reference's _public_plan).
    pub fn public(&self) -> Value {
        let mut v = serde_json::to_value(self).unwrap_or_default();
        if let Some(o) = v.as_object_mut() { o.remove("rb_new"); }
        v
    }
}

fn alias(c: &mci_core::model::Cert) -> String { names::alias_for(&c.cn, &c.fp256_hex()) }

pub fn build_plan(an: &Analysis, facts: &Value, opts: &Value) -> Result<Plan, String> {
    let base = names::safe_name(&an.fqdn);
    let crt = format!("{SSL_DIR}/{base}.crt");
    let key = format!("{SSL_DIR}/{base}.key");
    let do_server = opts.get("server").map(truthy).unwrap_or(true);
    let do_trust = opts.get("trust").map(truthy).unwrap_or(false) && !an.ca_certs().is_empty();
    let restart_ui = opts.get("restart_ui").map(truthy).unwrap_or(do_trust);
    let include_root = opts.get("include_root").map(truthy).unwrap_or(false);
    let st = stamp();
    let rb_old = facts.get("morpheus_rb").and_then(Value::as_str).unwrap_or("").to_string();
    let rb_new = if do_server { morpheus_rb::transform_checked(&rb_old, &crt, &key, &st)? } else { rb_old.clone() };
    let mut steps = vec![json!({"id": "backup", "title": "Back up /etc/morpheus/ssl and morpheus.rb", "detail": format!("{BACKUP_DIR}/{st}/ (root-only)")})];
    if do_server {
        let n = an.intermediates.len();
        steps.push(json!({"id": "files", "title": "Write certificate and key",
            "detail": format!("{crt} (server + {n} intermediate{}{}, 0600 root)\n{key} (decrypted PKCS#8, 0600 root)",
                              if n != 1 { "s" } else { "" }, if include_root && an.root.is_some() { " + root" } else { "" })}));
        steps.push(json!({"id": "rb", "title": "Point nginx at them in morpheus.rb", "detail": "nginx['ssl_certificate'] / nginx['ssl_server_key']"}));
        steps.push(json!({"id": "match", "title": "Check the key matches the certificate on the appliance", "detail": "openssl pubkey compare"}));
    }
    let cas = an.ca_certs();
    if do_trust {
        steps.push(json!({"id": "trustfiles", "title": "Copy the CA chain to trusted_certs",
            "detail": cas.iter().map(|c| format!("{TRUST_DIR}/{}.pem  ({})", alias(c), c.cn)).collect::<Vec<_>>().join("\n")}));
    }
    let mut r = vec!["morpheus-ctl reconfigure".to_string()];
    if do_trust { r.push(format!("keytool -importcert for {} CA cert(s) into the embedded Java cacerts", cas.len())); }
    if do_server { r.push("morpheus-ctl restart nginx".into()); }
    if restart_ui { r.push("morpheus-ctl restart morpheus-ui (UI unavailable while it starts, often 5–10 min)".into()); }
    steps.push(json!({"id": "runner", "title": "Run on the appliance (detached, streamed live)", "detail": r.join("\n")}));
    steps.push(json!({"id": "verify", "title": "Verify what nginx serves", "detail": "fingerprint compare on 127.0.0.1:443 + chain check from here"}));
    let storepass = opts.get("storepass").and_then(Value::as_str).filter(|s| !s.is_empty()).unwrap_or("changeit").to_string();
    Ok(Plan {
        rb_diff: if do_server { morpheus_rb::unified_diff(&rb_old, &rb_new, MORPHEUS_RB) } else { String::new() },
        aliases: if do_trust { cas.iter().map(|c| alias(c)).collect() } else { vec![] },
        systemd: facts.get("systemdrun").and_then(Value::as_str) == Some("yes"),
        stamp: st, crt, key, server: do_server, trust: do_trust, restart_ui, include_root, storepass, steps, rb_new,
    })
}

// ------------------------------------------------------------------ runner

/// Run a tool step under sudo. Success: its stdout only (sudo's lecture and other stderr noise never
/// reach the Run log). Failure: what it said, stderr first (0.3.19).
async fn check(t: &dyn Transport, cmd: &str, what: &str) -> Result<String, String> {
    let r = t.run_data(cmd, true, None, 120).await.map_err(te)?;
    if r.rc != 0 {
        return Err(format!("{what} failed (exit {}): {}", r.rc, r.complaint(800)));
    }
    Ok(r.stdout)
}

// ------------------------------------------------------------------ installed-files ledger (0.3.19)

/// The ledger's entries ({path, kind, stamp, fqdn}); empty when there's none (or it can't be read
/// as JSON — then it's replaced on the next write, and the Run log says so).
pub(crate) async fn ledger_entries(t: &dyn Transport, emit: &Emit) -> Result<Vec<Value>, String> {
    let text = reads::ledger(t).await.map_err(te)?;
    if text.trim().is_empty() { return Ok(vec![]); }
    match serde_json::from_str::<Value>(&text) {
        Ok(v) => Ok(v["files"].as_array().cloned().unwrap_or_default()),
        Err(_) => {
            emit(log(format!("! {} isn't valid JSON; starting a new ledger.\n", appliance::LEDGER)));
            Ok(vec![])
        }
    }
}

async fn ledger_write(t: &dyn Transport, files: Vec<Value>) -> Result<(), String> {
    let v = json!({"note": "Certificate and key files morpheus-certificate-install installed. Kept when backups are removed; cleanup may remove ones morpheus.rb no longer names.", "files": files});
    t.put_root(appliance::LEDGER, serde_json::to_string_pretty(&v).unwrap_or_default().as_bytes(), "0600", "0700").await.map_err(te)
}

/// Record installed files (replacing entries for the same paths).
async fn ledger_add(t: &dyn Transport, emit: &Emit, add: &[(&str, &str)], stamp: &str, fqdn: &str) -> Result<(), String> {
    let mut files = ledger_entries(t, emit).await?;
    files.retain(|e| !add.iter().any(|(p, _)| e["path"] == *p));
    for (p, kind) in add { files.push(json!({"path": p, "kind": kind, "stamp": stamp, "fqdn": fqdn})); }
    ledger_write(t, files).await
}

/// Drop removed paths from the ledger.
pub(crate) async fn ledger_drop(t: &dyn Transport, emit: &Emit, removed: &[String]) -> Result<(), String> {
    if removed.is_empty() { return Ok(()); }
    let mut files = ledger_entries(t, emit).await?;
    files.retain(|e| !removed.iter().any(|p| e["path"] == *p));
    ledger_write(t, files).await
}

/// The paths in "shredded <path>" / "removed <path>" lines.
pub fn removed_paths(out: &str) -> Vec<String> {
    out.lines().filter_map(|l| l.strip_prefix("shredded ").or_else(|| l.strip_prefix("removed "))).map(|p| p.trim().to_string()).collect()
}

/// Write the runner script and start it detached (systemd-run, or setsid).
pub async fn launch_runner(t: &dyn Transport, run_id: &str, script: &str, systemd: bool) -> Result<(), String> {
    let path = format!("{RUN_DIR}/{run_id}.sh");
    t.put_root(&path, script.as_bytes(), "0700", "0700").await.map_err(te)?;
    check(t, &appliance::launch_runner(run_id, &path, systemd), "start runner").await?;
    Ok(())
}

/// Follow a run's log, emitting Remote text and `run:<step>` Step events. None = stopped following.
pub async fn follow(t: &dyn Transport, run_id: &str, emit: &Emit, stop: watch::Receiver<bool>) -> Result<Option<i32>, String> {
    let (log_path, rc_path) = (format!("{LOG_DIR}/{run_id}.log"), format!("{LOG_DIR}/{run_id}.rc"));
    let buf = std::sync::Mutex::new(String::new());
    let emit2 = emit.clone();
    let on_text = move |txt: String| {
        emit2(Event::Remote { text: txt.clone() });
        let mut b = buf.lock().unwrap_or_else(|p| p.into_inner());
        b.push_str(&txt);
        while let Some(i) = b.find('\n') {
            let line: String = b.drain(..=i).collect();
            match runner::parse_marker(line.trim_end_matches('\n')) {
                Some(runner::Marker::Step(s)) => emit2(step(&format!("run:{s}"), StepStatus::Running)),
                Some(runner::Marker::Rc { step: s, rc }) => emit2(step(&format!("run:{s}"), if rc == 0 { StepStatus::Ok } else { StepStatus::Fail })),
                _ => {}
            }
        }
        // the reference keeps at most the last 4000 characters of an unfinished line
        let n = b.chars().count();
        if n > 4000 { *b = b.chars().skip(n - 4000).collect(); }
    };
    t.follow(&log_path, &rc_path, &on_text, stop).await.map_err(te)
}

// ------------------------------------------------------------------ apply

#[derive(Serialize)]
struct Manifest<'a> {
    stamp: &'a str,
    tool: String,
    fqdn: &'a str,
    crt: Option<&'a str>,
    key: Option<&'a str>,
    aliases: &'a [String],
    leaf_sha256: Option<String>,
    transport: Value,
}

pub async fn apply_steps(t: &dyn Transport, an: &Analysis, facts: &Value, plan: &Plan, emit: &Emit, stop: watch::Receiver<bool>) -> Result<Value, String> {
    let st = plan.stamp.as_str();
    let run_id = st;
    let bdir = format!("{BACKUP_DIR}/{st}");
    let stepx = |id: &str, status: StepStatus, text: &str| {
        emit(step(id, status));
        if !text.is_empty() { emit(log(format!("{text}\n"))); }
    };
    let stopped = || *stop.borrow();

    // 0. morpheus.rb: read it and run the appliance_url guard before anything is written —
    // backup, certificate and key included (PARITY divergence 19). The edit is made from this text.
    let new_rb = if plan.server {
        let checked = match reads::morpheus_rb_for_edit(t).await {
            Ok(cur) => morpheus_rb::transform_checked(&cur, &plan.crt, &plan.key, st).map(|new| (cur, new)),
            Err(e) => Err(te(e)),
        };
        let (cur, new) = match checked {
            Ok(x) => x,
            Err(e) => { emit(step("rb", StepStatus::Fail)); return Err(e); }
        };
        if Some(cur.as_str()) != facts.get("morpheus_rb").and_then(Value::as_str) {
            emit(log("morpheus.rb changed since the plan was made; applying the edit to the current file.\n"));
        }
        Some(new)
    } else {
        None
    };

    // 1. backup
    stepx("backup", StepStatus::Running, &format!("Backing up to {bdir}"));
    check(t, &appliance::backup(&bdir), "backup").await?;
    let manifest = Manifest {
        stamp: st,
        tool: format!("{} {}", mci_core::SLUG, mci_core::VERSION),
        fqdn: &an.fqdn,
        crt: plan.server.then_some(plan.crt.as_str()),
        key: plan.server.then_some(plan.key.as_str()),
        aliases: &plan.aliases,
        leaf_sha256: an.leaf.as_ref().map(|l| l.fp256()),
        transport: t.info().get("label").cloned().unwrap_or(Value::Null),
    };
    let m = serde_json::to_string_pretty(&manifest).map_err(|e| e.to_string())?;
    t.put_root(&format!("{bdir}/manifest.json"), m.as_bytes(), "0600", "0700").await.map_err(te)?;
    stepx("backup", StepStatus::Ok, "");
    if stopped() { return Ok(json!({"ok": false, "stopped": true})); }

    // 2. files + morpheus.rb
    if plan.server {
        stepx("files", StepStatus::Running, &format!("Writing {} and {}", plan.crt, plan.key));
        let key_pem = an.key_pem().ok_or("The analysis has no private key; load the key file in step 2 and plan again.")?;
        t.put_root(&plan.crt, an.fullchain_pem(plan.include_root).as_bytes(), "0600", "0700").await.map_err(te)?;
        t.put_root(&plan.key, key_pem.as_bytes(), "0600", "0700").await.map_err(te)?;
        stepx("files", StepStatus::Ok, "");
        stepx("rb", StepStatus::Running, &format!("Updating {MORPHEUS_RB}"));
        let new = new_rb.as_deref().unwrap_or_default();
        let mode = reads::morpheus_rb_mode(t).await;
        t.put_root(MORPHEUS_RB, new.as_bytes(), &mode, "0700").await.map_err(te)?;
        stepx("rb", StepStatus::Ok, "");
        stepx("match", StepStatus::Running, "");
        let out = match check(t, &appliance::key_matches_cert(&plan.crt, &plan.key), "key/cert match on the appliance").await {
            Ok(o) => o,
            Err(e) => { emit(step("match", StepStatus::Fail)); return Err(e); }
        };
        stepx("match", StepStatus::Ok, out.trim());
        // The ledger of installed files (0.3.19): survives backup removal; rollback and cleanup use it.
        ledger_add(t, emit, &[(&plan.crt, "crt"), (&plan.key, "key")], st, &an.fqdn).await?;
    }
    if plan.trust {
        stepx("trustfiles", StepStatus::Running, "");
        for (c, a) in an.ca_certs().iter().zip(&plan.aliases) {
            t.put_root(&format!("{TRUST_DIR}/{a}.pem"), c.pem().as_bytes(), "0644", "0755").await.map_err(te)?;
            emit(log(format!("  {TRUST_DIR}/{a}.pem  ({})\n", c.cn)));
        }
        stepx("trustfiles", StepStatus::Ok, "");
    }
    if stopped() { return Ok(json!({"ok": false, "stopped": true, "backup": bdir})); }

    // 3. runner
    stepx("runner", StepStatus::Running, "Starting the runner on the appliance. Output below is live; it keeps running if this window closes.");
    let rp = RunnerPlan { server: plan.server, trust: plan.trust, restart_ui: plan.restart_ui, storepass: plan.storepass.clone(), aliases: plan.aliases.clone() };
    let script = runner::runner_script(run_id, &t.login_user(), &rp, Mode::Apply, &[]);
    launch_runner(t, run_id, &script, plan.systemd).await?;
    run_started(t, emit, run_id);
    match follow(t, run_id, emit, stop.clone()).await? {
        None => {
            stepx("runner", StepStatus::Fail, "Stopped following. The run continues on the appliance — re-attach from Runs.");
            Ok(json!({"ok": false, "run_id": run_id, "backup": bdir, "detached": true}))
        }
        Some(rc) => {
            stepx("runner", if rc == 0 { StepStatus::Ok } else { StepStatus::Fail }, &format!("Runner finished with exit {rc}."));
            if rc != 0 { Ok(json!({"ok": false, "run_id": run_id, "backup": bdir, "rc": rc})) }
            else { Ok(json!({"ok": true, "run_id": run_id, "backup": bdir})) }
        }
    }
}

// ------------------------------------------------------------------ verify

pub async fn run_verify(t: Option<&dyn Transport>, an: Option<&Analysis>, target: &str, port: u16, connect_addr: &str, emit: &Emit) -> Result<Value, String> {
    let want = an.and_then(|a| a.leaf.as_ref()).map(|l| l.fp256());
    let mut res = json!({"remote": null, "local": null});
    if let Some(t) = t {
        let mut served = served_chain(t, target).await?;
        if served["ok"] == json!(true) {
            let m = want.as_deref().is_some_and(|w| served["fingerprints"][0] == json!(w));
            served["matches_new"] = json!(m);
            let sha: String = served["leaf"]["sha256"].as_str().unwrap_or("").chars().take(23).collect();
            emit(log(format!("Appliance (127.0.0.1:443, SNI {target}): serving \"{}\"{} {sha}…, {} cert(s) in chain — {}\n",
                served["leaf"]["cn"].as_str().unwrap_or(""),
                if served["leaf"]["self_signed"] == json!(true) { " (self-signed)" } else { "" }, served["chain_len"],
                if m { "matches the new certificate" } else { "NOT the new certificate" })));
        }
        res["remote"] = served;
    }
    let root = an.and_then(|a| a.root.as_ref()).map(|r| r.der.clone());
    let loc = tls::local_tls(target, port, connect_addr, want.as_deref(), root.as_deref()).await;
    if !loc["ok"].is_null() {
        emit(log(format!("From this machine ({}): {}\n", loc["addr"].as_str().unwrap_or(""), loc["summary"].as_str().unwrap_or(""))));
    }
    res["local"] = loc;
    Ok(res)
}

// ------------------------------------------------------------------ runs / backups / rollback

pub fn parse_runs(out: &str) -> Vec<Value> {
    let mut runs: Vec<(i64, Value)> = out.lines().filter_map(|l| {
        let p: Vec<&str> = l.split('|').collect();
        (p.len() == 3).then(|| {
            let mtime = p[1].trim().parse::<i64>().unwrap_or(0);
            (mtime, json!({"id": p[0], "mtime": mtime, "rc": if p[2].is_empty() { Value::Null } else { json!(p[2]) }}))
        })
    }).collect();
    runs.sort_by(|a, b| b.0.cmp(&a.0));
    runs.into_iter().map(|r| r.1).collect()
}

pub fn parse_backups(out: &str) -> Vec<Value> {
    let mut items: Vec<Value> = vec![];
    let (mut cur, mut buf): (Option<String>, Vec<&str>) = (None, vec![]);
    for l in out.lines().chain(std::iter::once("@@B __end__")) {
        if let Some(id) = l.strip_prefix("@@B ") {
            if let Some(c) = cur.take() {
                let text = buf.join("\n");
                let m = if text.trim().is_empty() { Map::new() } else {
                    serde_json::from_str::<Value>(&text).ok().and_then(|v| v.as_object().cloned()).unwrap_or_default()
                };
                let mut item = Map::new();
                item.insert("id".into(), json!(c));
                item.extend(m);
                items.push(Value::Object(item));
            }
            let id = id.trim().to_string();
            buf.clear();
            if id == "__end__" { break; }
            cur = Some(id);
        } else {
            buf.push(l);
        }
    }
    items.sort_by(|a, b| b["id"].as_str().cmp(&a["id"].as_str()));
    items
}

pub async fn run_rollback(t: &dyn Transport, backup_id: &str, systemd: bool, emit: &Emit, stop: watch::Receiver<bool>) -> Result<Value, String> {
    if backup_id.is_empty() || backup_id.contains('/') || backup_id.starts_with('.') {
        return Err("bad backup id".into());
    }
    let bdir = format!("{BACKUP_DIR}/{backup_id}");
    let m = reads::manifest(t, &bdir).await.map_err(te)?.unwrap_or_else(|| json!({}));
    let aliases: Vec<String> = m.get("aliases").and_then(Value::as_array).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
    emit(step("restore", StepStatus::Running));
    // Nothing is restored from a backup whose morpheus.rb isn't one (divergence 19).
    if let Err(e) = reads::backup_morpheus_rb_checked(t, &bdir, backup_id).await {
        emit(step("restore", StepStatus::Fail));
        return Err(te(e));
    }
    let pre = format!("{BACKUP_DIR}/{}-pre-rollback", stamp());
    if let Err(e) = check(t, &appliance::rollback_restore(&bdir, &pre, backup_id, &aliases), "restore").await {
        emit(step("restore", StepStatus::Fail));
        return Err(e);
    }
    emit(log(format!("Restored morpheus.rb and {SSL_DIR} from {bdir} (current state saved to {pre}).\n")));
    // What the rolled-back install wrote (its manifest) and the backup didn't have goes, keys
    // shredded, so /etc/morpheus/ssl is exactly the backup's (PARITY divergence 29, 0.3.19).
    let installed: Vec<String> = ["crt", "key"].iter().filter_map(|k| m.get(*k).and_then(Value::as_str)).map(String::from)
        .filter(|p| appliance::installed_name(p).is_ok()).collect();
    if !installed.is_empty() {
        let cmd = appliance::rollback_remove_installed(&bdir, &installed)?;
        let out = match check(t, &cmd, "removing the rolled-back install's files").await {
            Ok(o) => o,
            Err(e) => { emit(step("restore", StepStatus::Fail)); return Err(e); }
        };
        if !out.trim().is_empty() { emit(log(out.clone())); }
        ledger_drop(t, emit, &removed_paths(&out)).await?;
    }
    emit(step("restore", StepStatus::Ok));
    let run_id = format!("{}-rollback", stamp());
    let rp = RunnerPlan { server: true, trust: false, restart_ui: !aliases.is_empty(), storepass: "changeit".into(), aliases: vec![] };
    emit(step("runner", StepStatus::Running));
    launch_runner(t, &run_id, &runner::runner_script(&run_id, &t.login_user(), &rp, Mode::Rollback, &aliases), systemd).await?;
    run_started(t, emit, &run_id);
    let rc = follow(t, &run_id, emit, stop).await?;
    emit(step("runner", if rc == Some(0) { StepStatus::Ok } else { StepStatus::Fail }));
    Ok(json!({"ok": rc == Some(0), "run_id": run_id, "saved_current": pre}))
}

// ------------------------------------------------------------------ handlers

pub async fn state<R: Runtime>(_app: &AppHandle<R>, st: Arc<AppState>, _b: Value) -> Res {
    let t = st.transport.lock().await.clone();
    let facts = st.facts.lock().await.clone();
    let an = st.analysis.lock().await.clone();
    let plan = st.plan.lock().await.clone();
    Ok(json!({
        "version": mci_core::VERSION,
        "connected": t.is_some(),
        "transport": t.map(|t| t.info()),
        "facts": facts.map(|f| public_facts(&f)),
        "analysis": an.map(|a| crate::trust::analysis_json(&a)),
        "plan": plan.map(|p| p.public()),
        "busy": st.is_busy(),
        "settings": load_settings(&st),
        "morpheus_url": st.morpheus_url.lock().await.clone(),
        "has_morpheus_token": !st.morpheus_token.lock().await.is_empty(),
        "portable": st.paths.portable,
        "leave_no_trace": st.leave_no_trace.load(Ordering::SeqCst),
        "notice": st.notice.lock().await.take(),
    }))
}

pub async fn connect<R: Runtime>(_app: &AppHandle<R>, st: Arc<AppState>, b: Value) -> Res {
    if st.is_busy() {
        return Err("An operation is running; connect after it finishes.".into());
    }
    if let Some(old) = st.transport.lock().await.take() {
        old.close().await;
    }
    *st.facts.lock().await = None;
    *st.plan.lock().await = None;
    let t: Arc<dyn Transport> = if s(&b, "mode") == "charon" {
        let dir = s(&b, "charon_dir");
        let d = crate::transport::charon_mcp::discover(&dir).await;
        let (Some(data_dir), Some(_)) = (d.data_dir.clone(), d.endpoint) else {
            return Err("Charon's MCP server isn't running (no mcp-endpoint.json). In Charon: MCP panel → Start.".into());
        };
        let session = s(&b, "session");
        if session.is_empty() { return Err("Pick a Charon session first.".into()); }
        let t = crate::transport::charon_mcp::connect(&data_dir, &session).await.map_err(te)?;
        save_settings(&st, json!({"mode": "charon", "charon_dir": dir}));
        Arc::from(t)
    } else {
        let host = s(&b, "host").trim().to_string();
        let user = s(&b, "user").trim().to_string();
        if host.is_empty() || user.is_empty() { return Err("Enter the appliance's host and the user to log in as.".into()); }
        let p = port(&b, "port", 22)?;
        let params = crate::transport::ssh::SshParams {
            host: host.clone(), port: p, user: user.clone(), password: s(&b, "password"),
            key_path: s(&b, "key_path").trim().to_string(), key_passphrase: s(&b, "key_passphrase"),
            sudo_password: s(&b, "sudo_password"), trust_fingerprint: s(&b, "trust_fingerprint"),
            known_hosts: st.paths.known_hosts(),
        };
        let t = match crate::transport::ssh::connect(params).await {
            Ok(t) => t,
            Err(TransportError::HostKey { host, key_type, fingerprint, mismatch }) => {
                return Ok(json!({"ok": false, "hostkey": {"host": host, "type": key_type, "fingerprint": fingerprint, "mismatch": mismatch}}));
            }
            Err(e) => return Err(te(e)),
        };
        save_settings(&st, json!({"mode": "ssh", "host": host, "port": p, "user": user, "key_path": s(&b, "key_path").trim()}));
        Arc::from(t)
    };
    let info = t.info();
    *st.transport.lock().await = Some(t);
    (st.emit)(Event::Connected { transport: info.clone() });
    (st.emit)(log(format!("Connected: {} (sudo: {})\n", info["label"].as_str().unwrap_or(""), info["sudo_mode"].as_str().unwrap_or(""))));
    if let Some(tier) = st.transport.lock().await.as_deref().and_then(approval_tier) {
        (st.emit)(log(format!("The Charon session is at the {tier} tier: every command this app sends needs your approval in Charon.\n")));
    }
    Ok(json!({"ok": true, "transport": info}))
}

pub async fn disconnect<R: Runtime>(_app: &AppHandle<R>, st: Arc<AppState>, _b: Value) -> Res {
    if st.is_busy() { st.stop.send_replace(true); }
    if let Some(t) = st.transport.lock().await.take() { t.close().await; }
    *st.facts.lock().await = None;
    *st.plan.lock().await = None;
    (st.emit)(Event::Disconnected);
    Ok(json!({"ok": true}))
}

pub async fn charon_discover<R: Runtime>(_app: &AppHandle<R>, _st: Arc<AppState>, b: Value) -> Res {
    Ok(crate::transport::charon_mcp::discover(&s(&b, "charon_dir")).await.to_json())
}

pub async fn preflight<R: Runtime>(_app: &AppHandle<R>, st: Arc<AppState>, _b: Value) -> Res {
    let t = need_t(&st).await?;
    let st2 = st.clone();
    start_job(&st, "preflight", move |_stop| async move {
        let facts = run_preflight(&*t, &st2.emit).await?;
        (st2.emit)(Event::Facts { facts: public_facts(&facts) });
        let problems: Vec<String> = facts["problems"].as_array().map(|a| a.iter().filter_map(|p| p.as_str().map(String::from)).collect()).unwrap_or_default();
        *st2.facts.lock().await = Some(facts);
        if problems.is_empty() {
            (st2.emit)(log("Appliance looks right: morpheus-ctl, morpheus.rb and /etc/morpheus/ssl present.\n"));
        }
        for p in problems { (st2.emit)(log(format!("! {p}\n"))); }
        Ok(json!({"ok": true}))
    })?;
    Ok(json!({"ok": true}))
}

fn passwords(b: &Value) -> Passwords {
    Passwords { pfx: s(b, "pfx_password"), key: s(b, "key_password"), extra: vec![] }
}

async fn appliance_url_for(st: &AppState, b: &Value) -> String {
    let u = s(b, "appliance_url");
    if !u.is_empty() { return u; }
    st.facts.lock().await.as_ref().and_then(|f| f.get("appliance_url_rb")).and_then(Value::as_str).unwrap_or("").to_string()
}

/// The appliance's own names from preflight (`hostname -f`), for a wildcard certificate's FQDN
/// suggestion (`analyze_with_hosts`). Empty when not connected or not checked yet.
async fn appliance_hosts(st: &AppState) -> Vec<String> {
    st.facts.lock().await.as_ref().and_then(|f| f.get("host")).and_then(Value::as_str)
        .filter(|h| !h.trim().is_empty()).map(|h| vec![h.trim().to_string()]).unwrap_or_default()
}

pub async fn analyze<R: Runtime>(_app: &AppHandle<R>, st: Arc<AppState>, b: Value) -> Res {
    let mut incoming = vec![];
    for f in b.get("files").and_then(Value::as_array).cloned().unwrap_or_default() {
        let name = s(&f, "name");
        let data = base64::engine::general_purpose::STANDARD.decode(s(&f, "b64").as_bytes())
            .map_err(|_| format!("{name} didn't arrive intact (bad base64). Add it again."))?;
        incoming.push(InputFile { name, data });
    }
    let pasted = s(&b, "pasted");
    if !pasted.trim().is_empty() {
        incoming.push(InputFile { name: "pasted text".into(), data: pasted.into_bytes() });
    }
    let files = {
        let mut files = st.files.lock().await;
        if !incoming.is_empty() {
            // New uploads replace same-named ones; earlier files and fetched chain certs stay.
            files.retain(|f| !incoming.iter().any(|n| n.name == f.name));
            files.extend(incoming);
        }
        if files.is_empty() { return Err("Add certificate files or paste PEM text first.".into()); }
        files.clone()
    };
    let bundle = mci_core::formats::parse_files(&files, &passwords(&b));
    let an = analyze::analyze_with_hosts(&bundle, s(&b, "fqdn").trim(), &appliance_url_for(&st, &b).await, now_unix(), &appliance_hosts(&st).await);
    let out = crate::trust::analysis_json(&an);
    save_settings(&st, json!({"fqdn": an.fqdn}));
    *st.analysis.lock().await = Some(Arc::new(an));
    *st.plan.lock().await = None;
    Ok(out)
}

pub async fn fetch_chain<R: Runtime>(_app: &AppHandle<R>, st: Arc<AppState>, b: Value) -> Res {
    let files = st.files.lock().await.clone();
    if files.is_empty() { return Err("Load the certificate first.".into()); }
    let pw = passwords(&b);
    let (log_lines, fetched) = tokio::task::spawn_blocking(move || {
        let mut bundle = mci_core::formats::parse_files(&files, &pw);
        let before = bundle.certs.len();
        let log_lines = mci_core::aia::complete_chain(&mut bundle, &crate::fetch::fetch);
        let fetched: Vec<InputFile> = bundle.certs[before..].iter().map(|c| InputFile { name: format!("fetched: {}.crt", c.cn), data: c.pem().into_bytes() }).collect();
        (log_lines, fetched)
    }).await.map_err(|e| format!("internal error: {e}"))?;
    let files = {
        let mut f = st.files.lock().await;
        f.extend(fetched);
        f.clone()
    };
    let bundle = mci_core::formats::parse_files(&files, &passwords(&b));
    let an = analyze::analyze_with_hosts(&bundle, s(&b, "fqdn").trim(), &appliance_url_for(&st, &b).await, now_unix(), &appliance_hosts(&st).await);
    let aj = crate::trust::analysis_json(&an);
    *st.analysis.lock().await = Some(Arc::new(an));
    *st.plan.lock().await = None;
    Ok(json!({"log": log_lines, "analysis": aj}))
}

pub async fn export_zip<R: Runtime>(app: &AppHandle<R>, st: Arc<AppState>, b: Value) -> Res {
    let an = st.analysis.lock().await.clone().ok_or("Check the certificate first.")?;
    let local = time::OffsetDateTime::now_local().unwrap_or_else(|_| time::OffsetDateTime::now_utc());
    let now = format!("{:04}-{:02}-{:02} {:02}:{:02}", local.year(), local.month() as u8, local.day(), local.hour(), local.minute());
    let files = mci_core::export::build_files(&an, b.get("include_root").map(truthy).unwrap_or(false), &now)?;
    let folder = format!("{}-morpheus", names::safe_name(&an.fqdn));
    let when = (local.year() as u16, local.month() as u8, local.day(), local.hour(), local.minute(), local.second());
    let zip = mci_core::export::to_zip(&files, &folder, when)?;
    let mut list: Vec<String> = files.iter().map(|(n, _)| n.clone()).collect();
    list.sort();
    let name = format!("{folder}.zip");
    let path = match &st.pick_save {
        Some(pick) => pick(name),
        None => {
            use tauri_plugin_dialog::DialogExt;
            let d = app.dialog().file().set_file_name(&name).add_filter("Zip archive", &["zip"]);
            tokio::task::spawn_blocking(move || d.blocking_save_file()).await.map_err(|e| format!("internal error: {e}"))?
                .and_then(|p| p.into_path().ok())
        }
    };
    let Some(path) = path else { return Ok(json!({"saved": null, "files": list})) };
    std::fs::write(&path, zip).map_err(|e| format!("Couldn't write {}: {e}. Choose another folder and export again.", path.display()))?;
    Ok(json!({"saved": path.to_string_lossy(), "files": list}))
}

pub async fn clear_files<R: Runtime>(_app: &AppHandle<R>, st: Arc<AppState>, _b: Value) -> Res {
    st.files.lock().await.clear();
    *st.analysis.lock().await = None;
    *st.plan.lock().await = None;
    Ok(json!({"ok": true}))
}

pub async fn plan<R: Runtime>(_app: &AppHandle<R>, st: Arc<AppState>, b: Value) -> Res {
    let an = st.analysis.lock().await.clone().filter(|a| a.ok())
        .ok_or("Load a valid certificate first (the Certificate step shows what's wrong).")?;
    let facts = st.facts.lock().await.clone().ok_or("Run the appliance check on the Connect step first.")?;
    if !b.get("server").map(truthy).unwrap_or(true) && !b.get("trust").map(truthy).unwrap_or(false) {
        return Err("Pick at least one: install the server certificate, or trust the CA chain.".into());
    }
    let p = build_plan(&an, &facts, &b)?;
    let public = p.public();
    *st.plan.lock().await = Some(p);
    Ok(public)
}

pub async fn apply<R: Runtime>(_app: &AppHandle<R>, st: Arc<AppState>, b: Value) -> Res {
    let t = need_t(&st).await?;
    let plan = st.plan.lock().await.clone().ok_or("Review the plan first.")?;
    if s(&b, "confirm") != plan.stamp {
        return Err("Plan changed; review it again.".into());
    }
    let an = st.analysis.lock().await.clone().ok_or("Load a valid certificate first (the Certificate step shows what's wrong).")?;
    let facts = st.facts.lock().await.clone().unwrap_or_else(|| json!({}));
    let st2 = st.clone();
    start_job(&st, "apply", move |stop| async move {
        let r = apply_steps(&*t, &an, &facts, &plan, &st2.emit, stop).await;
        *st2.plan.lock().await = None;
        let mut res = r?;
        if res["ok"] == json!(true) {
            (st2.emit)(log("\nInstalled. Verifying…\n"));
            let set = load_settings(&st2);
            let p = port(&set, "tls_port", 443).unwrap_or(443);
            let v = run_verify(Some(&*t), Some(&an), &an.fqdn, p, &s(&set, "connect_addr"), &st2.emit).await?;
            res["verify"] = v.clone();
            (st2.emit)(Event::Verify { result: v });
        }
        Ok(res)
    })?;
    Ok(json!({"ok": true}))
}

pub async fn verify<R: Runtime>(_app: &AppHandle<R>, st: Arc<AppState>, b: Value) -> Res {
    let an = st.analysis.lock().await.clone();
    let mut target = s(&b, "fqdn").trim().to_string();
    if target.is_empty() { target = an.as_ref().map(|a| a.fqdn.clone()).unwrap_or_default(); }
    if target.is_empty() { return Err("Enter the FQDN to check.".into()); }
    if target.contains('*') {
        return Err(format!("{target} is a wildcard. Enter the appliance's own FQDN, the name Morpheus is reached by."));
    }
    let p = port(&b, "port", 443)?;
    let addr = s(&b, "connect_addr").trim().to_string();
    save_settings(&st, json!({"connect_addr": addr, "tls_port": p}));
    let t = st.transport.lock().await.clone();
    let st2 = st.clone();
    start_job(&st, "verify", move |_stop| async move {
        let v = run_verify(t.as_deref(), an.as_deref(), &target, p, &addr, &st2.emit).await?;
        (st2.emit)(Event::Verify { result: v.clone() });
        Ok(v)
    })?;
    Ok(json!({"ok": true}))
}

pub async fn runs<R: Runtime>(_app: &AppHandle<R>, st: Arc<AppState>, _b: Value) -> Res {
    let t = need_t(&st).await?;
    Ok(json!({"runs": parse_runs(&reads::list_runs(&*t).await.map_err(te)?)}))
}

pub async fn reattach<R: Runtime>(_app: &AppHandle<R>, st: Arc<AppState>, b: Value) -> Res {
    let t = need_t(&st).await?;
    let rid = s(&b, "id");
    if rid.is_empty() || rid.contains('/') { return Err("bad run id".into()); }
    let st2 = st.clone();
    start_job(&st, "reattach", move |stop| async move {
        run_started(&*t, &st2.emit, &rid);
        let rc = follow(&*t, &rid, &st2.emit, stop).await?;
        Ok(json!({"rc": rc}))
    })?;
    Ok(json!({"ok": true}))
}

pub async fn stop<R: Runtime>(_app: &AppHandle<R>, st: Arc<AppState>, _b: Value) -> Res {
    st.stop.send_replace(true);
    Ok(json!({"ok": true, "note": "Stopped following. Anything already running on the appliance carries on."}))
}

pub async fn backups<R: Runtime>(_app: &AppHandle<R>, st: Arc<AppState>, _b: Value) -> Res {
    let t = need_t(&st).await?;
    Ok(json!({"backups": parse_backups(&reads::list_backups(&*t).await.map_err(te)?)}))
}

pub async fn rollback<R: Runtime>(_app: &AppHandle<R>, st: Arc<AppState>, b: Value) -> Res {
    let t = need_t(&st).await?;
    let bid = s(&b, "id");
    let systemd = st.facts.lock().await.as_ref().and_then(|f| f.get("systemdrun")).and_then(Value::as_str) == Some("yes");
    let st2 = st.clone();
    start_job(&st, "rollback", move |stop| async move { run_rollback(&*t, &bid, systemd, &st2.emit, stop).await })?;
    Ok(json!({"ok": true}))
}

pub async fn morpheus_check<R: Runtime>(_app: &AppHandle<R>, st: Arc<AppState>, b: Value) -> Res {
    let url = s(&b, "url").trim().to_string();
    let token = s(&b, "token");
    if !token.is_empty() { *st.morpheus_token.lock().await = token.trim().to_string(); }
    if !url.is_empty() {
        *st.morpheus_url.lock().await = url.clone();
        save_settings(&st, json!({"morpheus_url": url}));
    }
    let (url, token) = (st.morpheus_url.lock().await.clone(), st.morpheus_token.lock().await.clone());
    if url.is_empty() || token.is_empty() { return Err("Enter the Morpheus URL and an API token.".into()); }
    let an = st.analysis.lock().await.clone();
    Ok(morpheus_api::morpheus_check(&url, &token, an.as_deref()).await)
}

pub async fn set_appliance_url<R: Runtime>(_app: &AppHandle<R>, st: Arc<AppState>, b: Value) -> Res {
    let (url, token) = (st.morpheus_url.lock().await.clone(), st.morpheus_token.lock().await.clone());
    if url.is_empty() || token.is_empty() { return Err("Check the Morpheus API first.".into()); }
    let new = s(&b, "new_url").trim().to_string();
    if !new.starts_with("https://") { return Err("The Appliance URL should start with https://".into()); }
    let an = st.analysis.lock().await.clone();
    morpheus_api::set_appliance_url(&url, &token, &new, an.as_deref()).await?;
    Ok(morpheus_api::morpheus_check(&url, &token, an.as_deref()).await)
}

pub async fn shell_open<R: Runtime>(_app: &AppHandle<R>, st: Arc<AppState>, b: Value) -> Res {
    let t = need_t(&st).await?;
    let (cols, rows) = (port(&b, "cols", 120).unwrap_or(120), port(&b, "rows", 32).unwrap_or(32));
    let (e1, e2) = (st.emit.clone(), st.emit.clone());
    t.shell_open(cols, rows,
        Box::new(move |d: Vec<u8>| e1(Event::Shell { data: base64::engine::general_purpose::STANDARD.encode(d) })),
        Box::new(move || e2(Event::ShellClosed))).await.map_err(te)?;
    Ok(json!({"ok": true}))
}

pub async fn shell_input<R: Runtime>(_app: &AppHandle<R>, st: Arc<AppState>, b: Value) -> Res {
    let t = need_t(&st).await?;
    let data = base64::engine::general_purpose::STANDARD.decode(s(&b, "b64").as_bytes()).map_err(|_| "bad shell input".to_string())?;
    t.shell_input(&data).await.map_err(te)?;
    Ok(json!({"ok": true}))
}

pub async fn shell_resize<R: Runtime>(_app: &AppHandle<R>, st: Arc<AppState>, b: Value) -> Res {
    let t = need_t(&st).await?;
    t.shell_resize(port(&b, "cols", 120).unwrap_or(120), port(&b, "rows", 32).unwrap_or(32)).await.map_err(te)?;
    Ok(json!({"ok": true}))
}

#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;

// ------------------------------------------------------------------ cleanup, forget, leave no trace (0.3.17)

/// Everything cleanup may offer: what the tool left, plus the installed files from the ledger
/// (marked in use when morpheus.rb names them).
async fn cleanup_items(t: &dyn Transport, emit: &Emit) -> Result<Vec<crate::cleanup::Entry>, String> {
    let mut items = crate::cleanup::parse_inventory(&reads::cleanup_inventory(t).await.map_err(te)?, crate::cleanup::now());
    let ledger: Vec<String> = ledger_entries(t, emit).await?.iter().filter_map(|e| e["path"].as_str().map(String::from))
        .filter(|p| appliance::installed_name(p).is_ok()).collect();
    if !ledger.is_empty() {
        let rb = reads::morpheus_rb_opt(t).await.map_err(te)?.unwrap_or_default();
        let named: Vec<String> = morpheus_rb::current_nginx_ssl(&rb).into_iter().map(|(_, v)| v).collect();
        let stat = t.run_data(&appliance::stat_installed(&ledger)?, true, None, 60).await.map_err(te)?;
        items.extend(crate::cleanup::installed_entries(&ledger, &stat.stdout, &named));
    }
    Ok(items)
}

pub async fn cleanup_list<R: Runtime>(_app: &AppHandle<R>, st: Arc<AppState>, _b: Value) -> Res {
    let t = need_t(&st).await?;
    let items = cleanup_items(&*t, &st.emit).await?;
    Ok(crate::cleanup::list_json(&items))
}

pub async fn cleanup_plan<R: Runtime>(_app: &AppHandle<R>, st: Arc<AppState>, b: Value) -> Res {
    let t = need_t(&st).await?;
    let c = crate::cleanup::Choices::from_args(&b);
    let items = cleanup_items(&*t, &st.emit).await?;
    let (remove, keep) = crate::cleanup::select(&items, c);
    if remove.is_empty() {
        return Err("Nothing to remove with those choices. Tick what should go, or there's nothing left to clean up.".into());
    }
    let plan = crate::cleanup::Plan { token: format!("cleanup-{}", stamp()), stage: remove.iter().any(|e| e.kind == "stage"), remove };
    let v = crate::cleanup::plan_json(&plan, &keep, c);
    *st.cleanup_plan.lock().await = Some(plan);
    Ok(v)
}

pub async fn cleanup<R: Runtime>(_app: &AppHandle<R>, st: Arc<AppState>, b: Value) -> Res {
    let t = need_t(&st).await?;
    let plan = st.cleanup_plan.lock().await.clone().ok_or("Review what will be removed first.")?;
    if s(&b, "confirm") != plan.token {
        return Err("The list changed; review it again.".into());
    }
    let st2 = st.clone();
    start_job(&st, "cleanup", move |_stop| async move {
        *st2.cleanup_plan.lock().await = None;
        crate::cleanup::run_cleanup(&*t, &plan, &st2.emit).await
    })?;
    Ok(json!({"ok": true}))
}

pub async fn forget_appliance<R: Runtime>(_app: &AppHandle<R>, st: Arc<AppState>, b: Value) -> Res {
    if st.is_busy() { return Err("An operation is running; forget the appliance after it finishes.".into()); }
    let set = load_settings(&st);
    let mut host = s(&b, "host").trim().to_string();
    if host.is_empty() { host = s(&set, "host").trim().to_string(); }
    if host.is_empty() { return Err("No appliance to forget: enter its host, or connect once first.".into()); }
    let p = if s(&b, "port").trim().is_empty() { port(&set, "port", 22)? } else { port(&b, "port", 22)? };
    // Connected to it over SSH: disconnect first.
    let connected = st.transport.lock().await.as_ref().map(|t| t.info()).filter(|i| i["kind"] == "ssh"
        && i["host"].as_str().is_some_and(|h| h.eq_ignore_ascii_case(&host)) && i["port"].as_u64() == Some(u64::from(p)));
    if connected.is_some() { disconnect(_app, st.clone(), json!({})).await?; }
    let r = crate::cleanup::forget(&st, &host, p)?;
    (st.emit)(log(format!("Forgot {host}:{p}: {} host key line(s) and its saved settings removed.\n", r["known_hosts_removed"])));
    Ok(r)
}

pub async fn set_leave_no_trace<R: Runtime>(_app: &AppHandle<R>, st: Arc<AppState>, b: Value) -> Res {
    if !st.paths.portable {
        return Err("Leave no trace is for the portable app on Windows and Linux (portable.flag beside the exe), whose data folder it deletes at exit. The installed app and the macOS app keep their data in your profile; use Forget this appliance to remove an appliance from it.".into());
    }
    let on = b.get("on").map(truthy).unwrap_or(false);
    st.leave_no_trace.store(on, Ordering::SeqCst);
    Ok(json!({"ok": true, "leave_no_trace": on, "data_dir": st.paths.data_dir.to_string_lossy()}))
}
