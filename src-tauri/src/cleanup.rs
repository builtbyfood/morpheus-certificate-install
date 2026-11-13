//! morpheus-certificate-install 0.4.0 — "Clean up this appliance", "Forget this appliance" and
//! portable mode's "Leave no trace".
//!
//! Cleanup works like install: `cleanup_list` shows what the tool left (runner scripts, run logs,
//! backups, the Charon staging dir; sizes and dates), `cleanup_plan` turns the user's choices into
//! the exact list of paths that will go, and `cleanup` (with the plan's token) removes exactly that
//! list as a job, with the Run log showing each path. The commands come from
//! `mci_core::appliance::cleanup_*` (golden-tested), which only ever name our own paths. Backups
//! hold previous private keys: every file in a backup is shredded before the directory goes.
//! A run that may still be going (a log with no .rc file, written in the last 15 minutes) is
//! listed but never removed.

use crate::events::{log, Event};
use crate::state::AppState;
use mci_core::appliance::{self, CleanupItem, BACKUP_DIR, LOG_DIR, RUN_DIR};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeSet;

/// Seconds a log without an .rc file counts as a run still going.
pub const RUNNING_WINDOW_S: i64 = 15 * 60;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Entry {
    /// script | log | backup | stage
    pub kind: String,
    pub path: String,
    /// The file or directory name (what the removal names); the path for the staging dir.
    pub name: String,
    pub bytes: u64,
    pub mtime: i64,
    /// Backups: how many .key files are in it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keys: Option<u32>,
    /// A run that may still be going: listed, never removed.
    pub running: bool,
    /// Installed files (ledger): morpheus.rb names it, so it's in use and never removed.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub in_use: bool,
}

/// Parse `kind|path|bytes|mtime[|keys]` lines; anything not under our dirs is dropped.
pub fn parse_inventory(text: &str, now: i64) -> Vec<Entry> {
    let mut v: Vec<Entry> = text.lines().filter_map(|l| {
        let p: Vec<&str> = l.split('|').collect();
        if p.len() < 4 { return None; }
        let (kind, path) = (p[0], p[1]);
        let name = path.rsplit('/').next().unwrap_or("").to_string();
        let ours = match kind {
            "script" => path == format!("{RUN_DIR}/{name}"),
            "log" => path == format!("{LOG_DIR}/{name}"),
            "backup" => path == format!("{BACKUP_DIR}/{name}"),
            "stage" => path.ends_with(&format!("/{}", appliance::CHARON_STAGE)),
            _ => false,
        };
        if !ours { return None; }
        Some(Entry {
            kind: kind.into(), path: path.into(), name: if kind == "stage" { path.into() } else { name },
            bytes: p[2].trim().parse().unwrap_or(0),
            mtime: p[3].trim().split('.').next().unwrap_or("0").parse().unwrap_or(0),
            keys: p.get(4).and_then(|k| k.trim().parse().ok()),
            running: false,
            in_use: false,
        })
    }).collect();
    // A run is still going when its log has no .rc and was written recently: keep its files.
    let rcs: BTreeSet<String> = v.iter().filter(|e| e.kind == "log" && e.name.ends_with(".rc")).map(|e| e.name.trim_end_matches(".rc").to_string()).collect();
    let running: BTreeSet<String> = v.iter()
        .filter(|e| e.kind == "log" && e.name.ends_with(".log") && now - e.mtime < RUNNING_WINDOW_S)
        .map(|e| e.name.trim_end_matches(".log").to_string()).filter(|id| !rcs.contains(id)).collect();
    for e in v.iter_mut() {
        let id = e.name.trim_end_matches(".log").trim_end_matches(".rc").trim_end_matches(".sh");
        if (e.kind == "log" || e.kind == "script") && running.contains(id) { e.running = true; }
    }
    v.sort_by(|a, b| (a.kind.as_str(), a.name.as_str()).cmp(&(b.kind.as_str(), b.name.as_str())));
    v
}

/// The user's choices on the page.
#[derive(Debug, Clone, Copy)]
pub struct Choices { pub runs: bool, pub stage: bool, pub old_backups: bool, pub all_backups: bool,
                     /// Certificate and key files the ledger lists that morpheus.rb no longer names (0.3.19).
                     pub unused_installed: bool }

impl Choices {
    pub fn from_args(b: &Value) -> Self {
        let f = |k: &str, d: bool| b.get(k).and_then(Value::as_bool).unwrap_or(d);
        Choices { runs: f("runs", true), stage: f("stage", true), old_backups: f("old_backups", true), all_backups: f("all_backups", false),
                  unused_installed: f("unused_installed", false) }
    }
}

/// The newest backup's id (ids are stamps, so they sort by time).
pub fn newest_backup(items: &[Entry]) -> Option<String> {
    items.iter().filter(|e| e.kind == "backup").map(|e| e.name.clone()).max()
}

/// Split the inventory into (remove, keep) for the choices.
pub fn select(items: &[Entry], c: Choices) -> (Vec<Entry>, Vec<Entry>) {
    let newest = newest_backup(items);
    items.iter().cloned().partition(|e| match e.kind.as_str() {
        "script" | "log" => c.runs && !e.running,
        "stage" => c.stage,
        "backup" => c.all_backups || (c.old_backups && Some(&e.name) != newest.as_ref()),
        "installed" => c.unused_installed && !e.in_use,
        _ => false,
    })
}

/// The root-owned items as `CleanupItem`s (the staging dir is separate: no sudo).
pub fn to_items(remove: &[Entry]) -> Vec<CleanupItem> {
    remove.iter().filter_map(|e| match e.kind.as_str() {
        "script" => Some(CleanupItem::Script(e.name.clone())),
        "log" => Some(CleanupItem::Log(e.name.clone())),
        "backup" => Some(CleanupItem::Backup(e.name.clone())),
        _ => None,
    }).collect()
}

fn totals(items: &[Entry]) -> Value {
    let mut t = serde_json::Map::new();
    for k in ["script", "log", "backup", "stage", "installed"] {
        let (n, b) = items.iter().filter(|e| e.kind == k).fold((0u64, 0u64), |(n, b), e| (n + 1, b + e.bytes));
        t.insert(k.into(), json!({"count": n, "bytes": b}));
    }
    Value::Object(t)
}

/// The plan shown in the confirm dialog; `cleanup` must echo `token`.
#[derive(Debug, Clone)]
pub struct Plan { pub token: String, pub remove: Vec<Entry>, pub stage: bool }

/// Installed files (from the ledger) as entries: `ledger_paths` that `stat_text` (`path|bytes|mtime`
/// lines) shows exist; `named` are the paths morpheus.rb names (in use).
pub fn installed_entries(ledger_paths: &[String], stat_text: &str, named: &[String]) -> Vec<Entry> {
    stat_text.lines().filter_map(|l| {
        let p: Vec<&str> = l.split('|').collect();
        if p.len() != 3 || !ledger_paths.iter().any(|x| x == p[0]) || appliance::installed_name(p[0]).is_err() { return None; }
        Some(Entry {
            kind: "installed".into(), path: p[0].into(), name: p[0].into(),
            bytes: p[1].trim().parse().unwrap_or(0), mtime: p[2].trim().parse().unwrap_or(0),
            keys: None, running: false, in_use: named.iter().any(|n| n == p[0]),
        })
    }).collect()
}

/// The installed files to remove (paths), from a plan's entries.
pub fn installed_paths(remove: &[Entry]) -> Vec<String> {
    remove.iter().filter(|e| e.kind == "installed").map(|e| e.path.clone()).collect()
}

pub fn list_json(items: &[Entry]) -> Value {
    json!({
        "items": items,
        "totals": totals(items),
        "newest_backup": newest_backup(items),
        "defaults": {"runs": true, "stage": true, "old_backups": true, "all_backups": false, "unused_installed": false},
    })
}

pub fn plan_json(p: &Plan, keep: &[Entry], c: Choices) -> Value {
    let mut v = json!({"token": p.token, "remove": p.remove, "keep": keep, "totals": totals(&p.remove)});
    if c.all_backups && p.remove.iter().any(|e| e.kind == "backup") {
        v["warning"] = json!("Every backup will be removed, so rollback becomes impossible: there will be nothing to roll back to.");
    }
    v
}

/// Run a job's removal: root items (sudo), then the staging dir; one Run log line per path.
pub async fn run_cleanup(t: &dyn crate::transport::Transport, plan: &Plan, emit: &crate::state::Emit) -> Result<Value, String> {
    let items = to_items(&plan.remove);
    let mut ok = true;
    if !items.is_empty() {
        emit(log(format!("Removing {} item(s) under {} and {}…\n", items.len(), appliance::STATE_DIR, LOG_DIR)));
        let cmd = appliance::cleanup_remove(&items)?;
        ok &= show(t, &cmd, true, 600, emit).await?;
    }
    let installed = installed_paths(&plan.remove);
    if !installed.is_empty() {
        emit(log(format!("Removing {} installed certificate/key file(s) morpheus.rb no longer names…\n", installed.len())));
        let r = t.run_data(&appliance::remove_installed(&installed)?, true, None, 300).await.map_err(|e| e.to_string())?;
        emit(Event::Remote { text: r.stdout.clone() });
        if r.rc != 0 { ok = false; emit(log(format!("! Some files couldn't be removed (exit {}): {}\n", r.rc, r.complaint(400)))); }
        crate::engine::ledger_drop(t, emit, &crate::engine::removed_paths(&r.stdout)).await?;
    }
    if plan.stage {
        emit(log("Removing the Charon staging directory…\n"));
        ok &= show(t, &appliance::cleanup_remove_stage(), false, 300, emit).await?;
    }
    let left = parse_inventory(&crate::reads::cleanup_inventory(t).await.map_err(|e| e.to_string())?, now());
    emit(log(format!("Left by this tool on the appliance now: {} item(s).\n", left.len())));
    Ok(json!({"ok": ok, "removed": plan.remove.len(), "left": left}))
}

pub fn now() -> i64 { time::OffsetDateTime::now_utc().unix_timestamp() }

/// Run a removal and show its stdout in the Run log; its stderr only when it fails (0.3.19).
async fn show(t: &dyn crate::transport::Transport, cmd: &str, sudo: bool, timeout: u64, emit: &crate::state::Emit) -> Result<bool, String> {
    let r = t.run_data(cmd, sudo, None, timeout).await.map_err(|e| e.to_string())?;
    emit(Event::Remote { text: r.stdout.clone() });
    if r.rc != 0 {
        emit(log(format!("! Some items couldn't be removed (exit {}): {}\n", r.rc, r.complaint(400))));
    }
    Ok(r.rc == 0)
}

// ------------------------------------------------------------------ forget this appliance

/// Settings that belong to one appliance (removed by "Forget this appliance"). `mode` and
/// `charon_dir` stay: they're about this computer.
pub const APPLIANCE_KEYS: [&str; 8] = ["host", "port", "user", "key_path", "fqdn", "connect_addr", "tls_port", "morpheus_url"];

/// Remove `host:port` from known_hosts and the appliance's settings. Returns what was removed.
pub fn forget(st: &AppState, host: &str, port: u16) -> Result<Value, String> {
    let keys = charon_ssh::HostKeys::with_paths(st.paths.known_hosts(), None);
    let removed = if st.paths.known_hosts().exists() {
        keys.forget(host, port).map_err(|e| format!("Couldn't update {}: {e}", st.paths.known_hosts().display()))?
    } else { 0 };
    let mut set = crate::engine::load_settings(st);
    let mut gone = vec![];
    if let Some(o) = set.as_object_mut() {
        let same = o.get("host").and_then(Value::as_str).is_some_and(|h| h.eq_ignore_ascii_case(host));
        if same {
            for k in APPLIANCE_KEYS { if o.remove(k).is_some() { gone.push(k); } }
        }
    }
    crate::engine::write_settings(st, &set)?;
    Ok(json!({"ok": true, "known_hosts_removed": removed, "settings_removed": gone}))
}

// ------------------------------------------------------------------ leave no trace (portable)

/// Written into the data folder when it couldn't be deleted at exit; read at the next start.
pub const LNT_MARKER: &str = ".leave-no-trace-incomplete";

/// Delete the portable data folder (settings, known_hosts, webview profile). Retries for a few
/// seconds (the webview's helper processes may still hold files). On failure, writes the marker
/// with what's left, so the next start can say so and try again.
pub fn delete_data_dir(dir: &std::path::Path) -> Result<(), String> {
    let mut last = String::new();
    for _ in 0..20 {
        match std::fs::remove_dir_all(dir) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => last = e.to_string(),
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    let _ = std::fs::create_dir_all(dir);
    let _ = std::fs::write(dir.join(LNT_MARKER), format!("Leave no trace: this folder couldn't be deleted at exit: {last}\n"));
    Err(last)
}

/// At start, portable: if the last session's leave-no-trace deletion failed, try again (the
/// webview isn't running yet) and return the notice to show.
pub fn retry_at_start(dir: &std::path::Path) -> Option<String> {
    if !dir.join(LNT_MARKER).exists() { return None; }
    Some(match delete_data_dir(dir) {
        Ok(()) => format!("Leave no trace: the last session's data folder ({}) couldn't be deleted when the app closed. It has been deleted now.", dir.display()),
        Err(e) => format!("Leave no trace: the last session's data folder ({}) still couldn't be deleted ({e}). Close every copy of the app and delete it by hand.", dir.display()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const INV: &str = "script|/var/lib/morpheus-certificate-install/runs/A.sh|2300|1000\n\
script|/var/lib/morpheus-certificate-install/runs/B.sh|2300|99000\n\
log|/var/log/morpheus-certificate-install/A.log|500|1000.5\n\
log|/var/log/morpheus-certificate-install/A.rc|2|1001\n\
log|/var/log/morpheus-certificate-install/B.log|90|99500\n\
backup|/var/lib/morpheus-certificate-install/backups/20261105-120000|9000|1000|2\n\
backup|/var/lib/morpheus-certificate-install/backups/20261106-090000|9100|2000|2\n\
backup|/etc/elsewhere/20261107-000000|1|1|0\n\
stage|/home/mcitest/.morpheus-certificate-install-stage|4096|3000\n";

    #[test]
    fn inventory_parses_and_marks_a_running_run() {
        let v = parse_inventory(INV, 100_000);
        assert_eq!(v.len(), 8, "the path outside our dirs is dropped: {v:?}");
        let b = v.iter().filter(|e| e.name.starts_with('B')).collect::<Vec<_>>();
        assert!(b.iter().all(|e| e.running), "B has no .rc and a recent log");
        assert!(v.iter().filter(|e| e.name.starts_with('A')).all(|e| !e.running));
        assert_eq!(v.iter().find(|e| e.kind == "backup").unwrap().keys, Some(2));
    }

    #[test]
    fn defaults_keep_the_newest_backup_and_running_runs() {
        let v = parse_inventory(INV, 100_000);
        let (rm, keep) = select(&v, Choices { runs: true, stage: true, old_backups: true, all_backups: false, unused_installed: false });
        let names: Vec<&str> = rm.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["20261105-120000", "A.log", "A.rc", "A.sh", "/home/mcitest/.morpheus-certificate-install-stage"]);
        assert!(keep.iter().any(|e| e.name == "20261106-090000") && keep.iter().any(|e| e.name == "B.sh"));
        let items = to_items(&rm);
        assert_eq!(items.len(), 4, "the staging dir isn't a sudo item");
        let (rm, _) = select(&v, Choices { runs: false, stage: false, old_backups: false, all_backups: true, unused_installed: false });
        assert_eq!(rm.iter().filter(|e| e.kind == "backup").count(), 2);
        let p = Plan { token: "t".into(), remove: rm.clone(), stage: false };
        assert!(plan_json(&p, &[], Choices { runs: false, stage: false, old_backups: false, all_backups: true, unused_installed: false })["warning"].as_str().unwrap().contains("rollback becomes impossible"));
        let (rm, _) = select(&v, Choices { runs: false, stage: false, old_backups: false, all_backups: false, unused_installed: false });
        assert!(rm.is_empty());
    }

    #[test]
    fn leave_no_trace_deletes_the_folder() {
        let d = std::env::temp_dir().join(format!("mci-lnt-{}", std::process::id()));
        std::fs::create_dir_all(d.join("webview/x")).unwrap();
        std::fs::write(d.join("settings.json"), "{}").unwrap();
        delete_data_dir(&d).unwrap();
        assert!(!d.exists());
        assert_eq!(retry_at_start(&d), None);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join(LNT_MARKER), "x").unwrap();
        assert!(retry_at_start(&d).unwrap().contains("It has been deleted now."));
        assert!(!d.exists());
    }
}

#[cfg(test)]
mod installed_tests {
    use super::*;

    #[test]
    fn only_ledger_files_morpheus_rb_no_longer_names_are_offered() {
        let ledger = vec!["/etc/morpheus/ssl/a.crt".to_string(), "/etc/morpheus/ssl/a.key".into(), "/etc/morpheus/ssl/b.crt".into(), "/etc/morpheus/ssl/b.key".into()];
        let stat = "/etc/morpheus/ssl/a.crt|2000|1\n/etc/morpheus/ssl/a.key|1700|1\n/etc/morpheus/ssl/b.crt|2000|2\n/etc/morpheus/ssl/b.key|1700|2\n/etc/morpheus/ssl/z.key|1|1\n";
        let named = vec!["/etc/morpheus/ssl/b.crt".to_string(), "/etc/morpheus/ssl/b.key".into()];
        let v = installed_entries(&ledger, stat, &named);
        assert_eq!(v.len(), 4, "z.key isn't in the ledger");
        let off = Choices { runs: false, stage: false, old_backups: false, all_backups: false, unused_installed: false };
        assert!(select(&v, off).0.is_empty(), "off by default");
        let (rm, keep) = select(&v, Choices { unused_installed: true, ..off });
        assert_eq!(installed_paths(&rm), ["/etc/morpheus/ssl/a.crt", "/etc/morpheus/ssl/a.key"]);
        assert!(keep.iter().all(|e| e.in_use));
        assert_eq!(list_json(&v)["defaults"]["unused_installed"], false);
    }
}
