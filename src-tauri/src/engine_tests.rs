//! morpheus-certificate-install 0.4.0 — engine tests with a recording transport (R7).
//!
//! `apply` sends the appliance exactly fixtures/golden/apply-command-sequence.json: the reference's
//! preflight + apply, recorded by make-cases.py with the same fake answers as `Rec` here.

use super::*;
use crate::transport::{DataOut, TResult};
use async_trait::async_trait;
use mci_core::appliance::SudoMode;
use std::path::PathBuf;
use std::sync::Mutex;

const STAMP: &str = "20261105-120000";
const RB: &str = "appliance_url 'https://198.51.100.20'\n";

/// The reference's `Rec` (make-cases.py command_goldens): records every operation and answers
/// as it did. `rb` is what `cat morpheus.rb` returns.
struct Rec {
    log: Mutex<Vec<Value>>,
    data: Mutex<Vec<(String, Vec<u8>)>>,
    rb: Mutex<String>,
    /// What `info()` says; the reference's Rec by default.
    info: Mutex<Value>,
}

impl Rec {
    fn new(rb: &str) -> Self {
        Rec { log: Mutex::new(vec![]), data: Mutex::new(vec![]), rb: Mutex::new(rb.into()),
              info: Mutex::new(json!({"kind": "fake", "label": "fake@appliance", "user": "mcitest", "sudo_mode": "password"})) }
    }
    fn answer(&self, cmd: &str, sudo: bool) -> (i32, String) {
        self.log.lock().unwrap().push(json!({"op": "run", "sudo": sudo, "cmd": cmd}));
        // morpheus.rb, or a backup's copy of it (rollback reads that first)
        if cmd.starts_with("cat ") && cmd.ends_with("/morpheus.rb") { return (0, self.rb.lock().unwrap().clone()); }
        if cmd.starts_with("stat -c %a") { return (0, "600\n".into()); }
        // The ledger: what was last written to it (0.3.19).
        if cmd.contains("installed.json ] && cat") {
            return (0, self.data.lock().unwrap().iter().rev().find(|(p, _)| p.ends_with("installed.json"))
                .map(|(_, d)| String::from_utf8_lossy(d).into_owned()).unwrap_or_default());
        }
        if cmd.starts_with("cat ") && cmd.ends_with("/manifest.json") {
            return (0, r#"{"stamp": "20261105-120000", "crt": "/etc/morpheus/ssl/m_cust_test.crt", "key": "/etc/morpheus/ssl/m_cust_test.key", "aliases": []}"#.into());
        }
        if cmd.starts_with("rc=0; if [ ! -e ") {
            return (0, "removed /etc/morpheus/ssl/m_cust_test.crt\nshredded /etc/morpheus/ssl/m_cust_test.key\n".into());
        }
        if cmd.contains("openssl s_client") { return (0, String::new()); }
        (0, "SYSTEMDRUN=yes\nMCTL=/usr/bin/morpheus-ctl\nRB=yes\nOPENSSL=OpenSSL 3.0.13\n".into())
    }
    fn ops(&self) -> Vec<Value> { self.log.lock().unwrap().clone() }
    fn written(&self, path: &str) -> Option<Vec<u8>> {
        self.data.lock().unwrap().iter().rev().find(|(p, _)| p == path).map(|(_, d)| d.clone())
    }
}

#[async_trait]
impl Transport for Rec {
    fn kind(&self) -> &'static str { "fake" }
    fn label(&self) -> String { "fake@appliance".into() }
    fn login_user(&self) -> String { "mcitest".into() }
    fn sudo_mode(&self) -> SudoMode { SudoMode::Password }
    fn info(&self) -> Value { self.info.lock().unwrap().clone() }
    async fn run(&self, cmd: &str, sudo: bool, _: Option<&[u8]>, _: u64) -> TResult<(i32, String)> { Ok(self.answer(cmd, sudo)) }
    async fn run_data(&self, cmd: &str, sudo: bool, _: Option<&[u8]>, _: u64) -> TResult<DataOut> {
        let (rc, stdout) = self.answer(cmd, sudo);
        Ok(DataOut { rc, stdout, stderr: String::new() })
    }
    async fn put_root(&self, path: &str, data: &[u8], mode: &str, dir_mode: &str) -> TResult<()> {
        let hashed = ![".key", ".sh", ".json", ".rb"].iter().any(|s| path.ends_with(s));
        self.log.lock().unwrap().push(json!({"op": "put_root", "path": path, "mode": mode, "dir_mode": dir_mode, "bytes": data.len(),
            "sha256": if hashed { json!(analyze::sha256_hex(data)) } else { Value::Null }}));
        self.data.lock().unwrap().push((path.into(), data.to_vec()));
        Ok(())
    }
    async fn follow(&self, log: &str, rc: &str, _: &(dyn Fn(String) + Send + Sync), _: watch::Receiver<bool>) -> TResult<Option<i32>> {
        self.log.lock().unwrap().push(json!({"op": "stream_file", "path": log, "rc_path": rc}));
        Ok(Some(0))
    }
}

fn corpus(f: &str) -> InputFile {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures/corpus").join(f);
    InputFile { name: f.into(), data: std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display())) }
}

fn golden_analysis() -> Analysis {
    let b = mci_core::formats::parse_files(&[corpus("chain.p7b"), corpus("leaf-pkcs1.key")], &Passwords::default());
    analyze::analyze(&b, "m.cust.test", "", now_unix())
}

fn collector() -> (Emit, Arc<Mutex<Vec<Event>>>) {
    let evs = Arc::new(Mutex::new(vec![]));
    let e2 = evs.clone();
    (Arc::new(move |e: Event| e2.lock().unwrap().push(e)), evs)
}

fn stamped(v: &Value) -> Value {
    let mut v = v.clone();
    for k in ["cmd", "path"] {
        if let Some(s) = v.get(k).and_then(Value::as_str) {
            v[k] = json!(s.replace(STAMP, "{STAMP}"));
        }
    }
    v
}

#[tokio::test]
async fn apply_sends_the_golden_sequence() {
    let golden: Value = serde_json::from_str(&std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures/golden/apply-command-sequence.json")).unwrap()).unwrap();
    // The reference's sequence with the recorded divergence applied (make-cases.py writes it):
    // apply's morpheus.rb read moves before the backup (PARITY divergence 19).
    let mut want_v = golden["sequence"].as_array().unwrap().clone();
    let ov = &golden["rust_expect_override"];
    let (from, to) = (ov["from_index"].as_u64().unwrap() as usize, ov["to_index"].as_u64().unwrap() as usize);
    assert_eq!(want_v[from], ov["move"], "the override names the read it moves");
    let moved = want_v.remove(from);
    want_v.insert(to, moved);
    // ... and the ledger read + write after the key/cert match (divergence 29).
    let prefix = ov["insert_after_cmd_prefix"].as_str().unwrap();
    let at = want_v.iter().position(|e| e["cmd"].as_str().is_some_and(|c| c.starts_with(prefix))).unwrap() + 1;
    for (i, op) in ov["insert"].as_array().unwrap().iter().enumerate() {
        want_v.insert(at + i, op.clone());
    }
    let want = &want_v;

    let t = Rec::new(RB);
    let an = golden_analysis();
    assert!(an.ok(), "{:?}", an.checks);
    let (emit, evs) = collector();
    let facts = run_preflight(&t, &emit).await.unwrap();
    let mut plan = build_plan(&an, &facts, &json!({"server": true, "trust": true, "restart_ui": true})).unwrap();
    plan.stamp = STAMP.into();
    let (_keep, stop) = watch::channel(false);
    let res = apply_steps(&t, &an, &facts, &plan, &emit, stop).await.unwrap();
    assert_eq!(res, json!({"ok": true, "run_id": STAMP, "backup": format!("{BACKUP_DIR}/{STAMP}")}));

    let got: Vec<Value> = t.ops().iter().map(stamped).collect();
    let ops = |v: &[Value]| v.iter().map(|e| format!("{} {}", e["op"].as_str().unwrap(), e["cmd"].as_str().or(e["path"].as_str()).unwrap_or("").lines().next().unwrap_or(""))).collect::<Vec<_>>();
    assert_eq!(ops(&got), ops(want), "operation order");
    // The version string is in the manifest ("tool") and the runner header, nowhere else.
    let ver_delta = mci_core::VERSION.len() as i64 - "0.2.1".len() as i64;
    for (i, (g, w)) in got.iter().zip(want).enumerate() {
        match w["op"].as_str().unwrap() {
            "run" => assert_eq!((&g["sudo"], &g["cmd"]), (&w["sudo"], &w["cmd"]), "step {i}"),
            "stream_file" => assert_eq!(g, w, "step {i}"),
            "put_root" => {
                assert_eq!((&g["path"], &g["mode"], &g["dir_mode"], &g["sha256"]), (&w["path"], &w["mode"], &w["dir_mode"], &w["sha256"]), "step {i}");
                let p = w["path"].as_str().unwrap();
                if let Some(b) = w["bytes"].as_i64() { // null: content stamped by the run (the ledger)
                    let wb = b + if p.ends_with("manifest.json") || p.ends_with(".sh") { ver_delta } else { 0 };
                    assert_eq!(g["bytes"].as_i64().unwrap(), wb, "step {i}: size of {p}");
                }
            }
            op => panic!("unexpected op {op}"),
        }
    }

    // What was written: the guarded morpheus.rb edit, the manifest's keys in the reference's order.
    let rb = String::from_utf8(t.written(MORPHEUS_RB).unwrap()).unwrap();
    assert_eq!(rb, morpheus_rb::transform(RB, "/etc/morpheus/ssl/m_cust_test.crt", "/etc/morpheus/ssl/m_cust_test.key", STAMP));
    let m = String::from_utf8(t.written(&format!("{BACKUP_DIR}/{STAMP}/manifest.json")).unwrap()).unwrap();
    let keys: Vec<&str> = m.lines().filter_map(|l| l.strip_prefix("  \"").and_then(|l| l.split('"').next())).collect();
    assert_eq!(keys, ["stamp", "tool", "fqdn", "crt", "key", "aliases", "leaf_sha256", "transport"]);
    assert!(m.contains(&format!("\"tool\": \"morpheus-certificate-install {}\"", mci_core::VERSION)));

    // Local steps, in order.
    let steps: Vec<String> = evs.lock().unwrap().iter().filter_map(|e| match e {
        Event::Step { id, status } => Some(format!("{id}:{}", serde_json::to_value(status).unwrap().as_str().unwrap())), _ => None }).collect();
    assert_eq!(steps, ["backup:running", "backup:ok", "files:running", "files:ok", "rb:running", "rb:ok", "match:running", "match:ok",
                       "trustfiles:running", "trustfiles:ok", "runner:running", "runner:ok"]);
    assert!(evs.lock().unwrap().contains(&Event::Run { id: STAMP.into(), watch: format!("tail -n +1 -F {LOG_DIR}/{STAMP}.log") }));
}

#[tokio::test]
async fn apply_refuses_a_morpheus_rb_without_appliance_url_and_never_writes_it() {
    let an = golden_analysis();
    // At plan time: the facts' morpheus.rb isn't one → no plan.
    let (emit, _) = collector();
    let t = Rec::new("We trust you have received the usual lecture\n");
    let facts = run_preflight(&t, &emit).await.unwrap();
    let e = build_plan(&an, &facts, &json!({"server": true})).unwrap_err();
    assert!(e.contains("no appliance_url line") && e.contains("Nothing was changed"), "{e}");
    // A trust-only plan doesn't touch morpheus.rb, so it isn't refused.
    assert!(build_plan(&an, &facts, &json!({"server": false, "trust": true})).is_ok());

    // At apply time: the file changed after the plan → refused before anything is written: no
    // backup, no certificate or key, no morpheus.rb, no runner (divergence 19, 0.3.16).
    let t = Rec::new(RB);
    let facts = run_preflight(&t, &emit).await.unwrap();
    let plan = build_plan(&an, &facts, &json!({"server": true, "trust": true})).unwrap();
    *t.rb.lock().unwrap() = String::new();
    let before = t.ops().len();
    let (emit, evs) = collector();
    let (_keep, stop) = watch::channel(false);
    let e = apply_steps(&t, &an, &facts, &plan, &emit, stop).await.unwrap_err();
    assert!(e.contains("no appliance_url line") && e.contains("Nothing was changed"), "{e}");
    let after: Vec<Value> = t.ops()[before..].to_vec();
    assert_eq!(after, vec![json!({"op": "run", "sudo": true, "cmd": "cat /etc/morpheus/morpheus.rb"})], "only the read happened");
    assert!(t.data.lock().unwrap().is_empty(), "something was written");
    let evs = evs.lock().unwrap();
    assert_eq!(*evs, vec![step("rb", StepStatus::Fail)], "no backup step started");
}

#[tokio::test]
async fn rollback_checks_the_backup_before_restoring() {
    let (emit, _) = collector();
    let (_keep, stop) = watch::channel(false);
    let t = Rec::new("");
    let e = run_rollback(&t, "20261105-120000", true, &emit, stop.clone()).await.unwrap_err();
    assert!(e.contains("the backup 20261105-120000") && e.contains("Nothing was changed"), "{e}");
    assert!(!t.ops().iter().any(|o| o["cmd"].as_str().is_some_and(|c| c.contains("cp -a"))), "something was restored");
    for bad in ["", "../x", ".hidden", "a/b"] {
        assert_eq!(run_rollback(&t, bad, true, &emit, stop.clone()).await.unwrap_err(), "bad backup id");
    }
    // A good backup: restore, then a rollback runner that deletes the manifest's aliases.
    let t = Rec::new(RB);
    let r = run_rollback(&t, "20261105-120000", true, &emit, stop).await.unwrap();
    assert_eq!(r["ok"], true);
    let cmds: Vec<String> = t.ops().iter().filter_map(|o| o["cmd"].as_str().map(String::from)).collect();
    assert!(cmds.iter().any(|c| c.contains("cp -a /var/lib/morpheus-certificate-install/backups/20261105-120000/morpheus.rb /etc/morpheus/morpheus.rb")));
}

#[test]
fn runs_and_backups_parse_like_the_reference() {
    let r = parse_runs("A|100|0\nB|300|\ngarbage\nC|200|2\n");
    assert_eq!(r, vec![json!({"id": "B", "mtime": 300, "rc": null}), json!({"id": "C", "mtime": 200, "rc": "2"}), json!({"id": "A", "mtime": 100, "rc": "0"})]);
    let b = parse_backups("@@B 20261105-1\n{\"fqdn\": \"m\"}\n\n@@B 20261106-1-pre-rollback\n{\"note\": \"x\"}\n\n@@B broken\n{nope\n\n");
    assert_eq!(b, vec![json!({"id": "broken"}), json!({"id": "20261106-1-pre-rollback", "note": "x"}), json!({"id": "20261105-1", "fqdn": "m"})]);
}

#[test]
fn plan_matches_the_reference_shape() {
    let an = golden_analysis();
    let facts = json!({"morpheus_rb": RB, "systemdrun": "yes"});
    let p = build_plan(&an, &facts, &json!({"server": true, "trust": true})).unwrap();
    assert!(p.restart_ui, "restart_ui defaults to trust");
    assert_eq!(p.storepass, "changeit");
    assert!(p.systemd);
    let ids: Vec<&str> = p.steps.iter().map(|s| s["id"].as_str().unwrap()).collect();
    assert_eq!(ids, ["backup", "files", "rb", "match", "trustfiles", "runner", "verify"]);
    assert_eq!(p.steps[1]["detail"], "/etc/morpheus/ssl/m_cust_test.crt (server + 1 intermediate, 0600 root)\n/etc/morpheus/ssl/m_cust_test.key (decrypted PKCS#8, 0600 root)");
    assert!(p.public().get("rb_new").is_none());
    assert!(p.rb_diff.contains("+nginx['ssl_certificate'] = '/etc/morpheus/ssl/m_cust_test.crt'"));
    let p = build_plan(&an, &facts, &json!({"server": true, "trust": false, "restart_ui": false})).unwrap();
    assert!(p.aliases.is_empty() && !p.restart_ui);
}

#[tokio::test]
async fn a_charon_session_that_asks_for_approval_gets_the_notice_with_the_watch_line() {
    let an = golden_analysis();
    for (tier, notice) in [("exec-approve", true), ("trusted", false)] {
        let t = Rec::new(RB);
        *t.info.lock().unwrap() = json!({"kind": "charon", "label": "Charon · mcitest@vm", "user": "mcitest", "sudo_mode": "charon", "tier": tier});
        let (emit, evs) = collector();
        let facts = run_preflight(&t, &emit).await.unwrap();
        let mut plan = build_plan(&an, &facts, &json!({"server": true})).unwrap();
        plan.stamp = STAMP.into();
        let (_keep, stop) = watch::channel(false);
        apply_steps(&t, &an, &facts, &plan, &emit, stop).await.unwrap();
        let logs: Vec<String> = evs.lock().unwrap().iter().filter_map(|e| match e { Event::Log { text } => Some(text.clone()), _ => None }).collect();
        let n = logs.iter().find(|l| l.contains("needs your approval in Charon"));
        assert_eq!(n.is_some(), notice, "{tier}: {logs:?}");
        if let Some(n) = n {
            assert!(n.starts_with("The Charon session is at the exec-approve tier"), "{n}");
            assert!(n.ends_with(&format!("\n  tail -n +1 -F {LOG_DIR}/{STAMP}.log\n")), "{n}");
        }
    }
}

#[tokio::test]
async fn apply_records_the_installed_files_and_rollback_removes_them() {
    let an = golden_analysis();
    let t = Rec::new(RB);
    let (emit, _) = collector();
    let facts = run_preflight(&t, &emit).await.unwrap();
    let mut plan = build_plan(&an, &facts, &json!({"server": true})).unwrap();
    plan.stamp = STAMP.into();
    let (_keep, stop) = watch::channel(false);
    apply_steps(&t, &an, &facts, &plan, &emit, stop.clone()).await.unwrap();
    let ledger: Value = serde_json::from_slice(&t.written(appliance::LEDGER).unwrap()).unwrap();
    let paths: Vec<&str> = ledger["files"].as_array().unwrap().iter().map(|e| e["path"].as_str().unwrap()).collect();
    assert_eq!(paths, ["/etc/morpheus/ssl/m_cust_test.crt", "/etc/morpheus/ssl/m_cust_test.key"]);
    assert_eq!(ledger["files"][1]["kind"], "key");
    // A second install of the same files doesn't duplicate them.
    apply_steps(&t, &an, &facts, &plan, &emit, stop.clone()).await.unwrap();
    let ledger: Value = serde_json::from_slice(&t.written(appliance::LEDGER).unwrap()).unwrap();
    assert_eq!(ledger["files"].as_array().unwrap().len(), 2);

    // Rollback: the manifest's crt/key that the backup lacks are removed, and leave the ledger.
    let (emit, evs) = collector();
    run_rollback(&t, STAMP, true, &emit, stop).await.unwrap();
    let cmds: Vec<String> = t.ops().iter().filter_map(|o| o["cmd"].as_str().map(String::from)).collect();
    let want = appliance::rollback_remove_installed(&format!("{BACKUP_DIR}/{STAMP}"),
        &["/etc/morpheus/ssl/m_cust_test.crt".to_string(), "/etc/morpheus/ssl/m_cust_test.key".to_string()]).unwrap();
    let restore_at = cmds.iter().position(|c| c.contains("echo restored")).unwrap();
    let remove_at = cmds.iter().position(|c| *c == want).expect("the removal ran");
    assert!(remove_at > restore_at, "after the restore");
    let ledger: Value = serde_json::from_slice(&t.written(appliance::LEDGER).unwrap()).unwrap();
    assert_eq!(ledger["files"], json!([]), "removed files leave the ledger");
    assert!(evs.lock().unwrap().iter().any(|e| matches!(e, Event::Log { text } if text.contains("shredded /etc/morpheus/ssl/m_cust_test.key"))));
}

#[test]
fn removed_paths_reads_the_command_output() {
    assert_eq!(removed_paths("removed /a.crt\nshredded /a.key\nnoise\n"), ["/a.crt", "/a.key"]);
}
