//! morpheus-certificate-install 0.4.1 — the Charon transport against tests/mock_charon.py (R6).
//!
//! The mock runs in SSH mode: a PTY session to the fake appliance, answering sudo the way Charon
//! does at the trusted tier, with real terminal output (CRLF, sudo's lecture and prompt) plus an
//! echoed command line, OSC 133 marks and a colour code. Ignored unless asked for:
//!   MCI_TEST_SSH=192.0.2.10:2222:mcitest:hunter2 MCI_PYTHON=<python with paramiko> \
//!     cargo test -p morpheus-certificate-install --test charon_mock -- --ignored --nocapture
//! (The mock's LOCAL mode — Linux, as root — is the reference's behaviour and isn't used here.)

mod common;

use mci_app::transport::charon_mcp;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Mock(Child);
impl Drop for Mock {
    fn drop(&mut self) { let _ = self.0.kill(); }
}

fn python() -> String {
    std::env::var("MCI_PYTHON").unwrap_or_else(|_| if cfg!(windows) { "python".into() } else { "python3".into() })
}

/// A charon.db shaped like the real one (nodes: id, parent_id, kind, name, sort, settings), with
/// secrets inside `settings` that must never come out.
fn make_db(path: &std::path::Path, host: &str, port: u16) {
    let con = rusqlite::Connection::open(path).unwrap();
    con.execute_batch("CREATE TABLE nodes (id TEXT PRIMARY KEY, parent_id TEXT, kind TEXT, name TEXT, sort INTEGER, settings TEXT);").unwrap();
    let rows = [
        ("f1", None, "folder", "Lab", r#"{"user":"mcitest","credential":"SECRET-FOLDER-PW","tags":["lab"]}"#.to_string()),
        ("h1", Some("f1"), "ssh", "fake-appliance", format!(r#"{{"host":"{host}","port":{port},"credential":"SECRET-HOST-PW","tags":["mci"]}}"#)),
        ("h2", Some("f1"), "ssh", "no-host", r#"{"user":"x"}"#.to_string()),
        ("l1", None, "local", "pwsh", "{}".to_string()),
    ];
    for (i, (id, parent, kind, name, settings)) in rows.iter().enumerate() {
        con.execute("INSERT INTO nodes VALUES (?1, ?2, ?3, ?4, ?5, ?6)", rusqlite::params![id, parent, kind, name, i as i64, settings]).unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs MCI_TEST_SSH (the fake appliance) and MCI_PYTHON with paramiko"]
async fn charon_transport_against_the_mock() {
    let Some(tg) = common::ssh_target() else { eprintln!("MCI_TEST_SSH not set"); return };
    let dir = std::env::temp_dir().join(format!("mci-r6-mock-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("charon.db");
    make_db(&db, &tg.host, tg.port);
    let db_before = std::fs::read(&db).unwrap();

    let mock = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/mock_charon.py");
    let child = Command::new(python())
        .arg(&mock).arg(&dir).arg("--ssh").arg(format!("{}:{}:{}:{}", tg.host, tg.port, tg.user, tg.password))
        .env("PYTHONUTF8", "1").stdout(Stdio::null()).stderr(Stdio::inherit())
        .spawn().expect("start tests/mock_charon.py (set MCI_PYTHON to a python with paramiko)");
    let _mock = Mock(child);
    let deadline = Instant::now() + Duration::from_secs(15);
    while !dir.join("mcp-endpoint.json").exists() {
        assert!(Instant::now() < deadline, "the mock didn't start");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // ---- discovery: endpoint, saved hosts (inherited, credentials never read), open sessions.
    let d = charon_mcp::discover(&dir.to_string_lossy()).await;
    assert_eq!(d.data_dir.as_deref(), Some(dir.as_path()));
    let j = d.to_json();
    eprintln!("[discovery] {}", serde_json::to_string(&j["hosts"]).unwrap());
    assert_eq!(j["endpoint"]["has_token"], true);
    let hosts = j["hosts"].as_array().unwrap();
    assert_eq!(hosts.len(), 1, "only ssh nodes with a host");
    assert_eq!(hosts[0]["name"], "fake-appliance");
    assert_eq!(hosts[0]["path"], "Lab");
    assert_eq!(hosts[0]["user"], "mcitest", "inherited from the folder");
    assert_eq!(hosts[0]["port"], tg.port);
    assert_eq!(hosts[0]["tags"], serde_json::json!(["mci"]), "the leaf's tags win");
    let all = j.to_string();
    assert!(!all.contains("SECRET") && !all.contains("credential"), "no credential reached discovery: {all}");
    assert!(j["sessions"].as_array().unwrap().iter().any(|s| s["id"] == "s1"));
    assert_eq!(std::fs::read(&db).unwrap(), db_before, "charon.db untouched (opened read-only)");

    // ---- connect and run the shared steps.
    let t = charon_mcp::connect(&dir, "s1").await.expect("connect through the mock");
    assert!(matches!(charon_mcp::connect(&dir, "gone").await, Err(e) if e.to_string().contains("no longer open")));
    assert!(matches!(charon_mcp::connect(&dir, "l1").await, Err(e) if e.to_string().contains("SSH session")));
    let reference = common::ssh_reference(&tg).await;
    common::charon_steps::exercise(&*t, &*reference, &tg.password).await;
    reference.close().await;

    // ---- follow is a long poll (0.3.16): a slow runner — a line every 8 s, rc after ~24 s — costs
    // one run_command per new output, not one every 2 s (about 12 + 4 with the old polling).
    use mci_core::appliance::LOG_DIR;
    let (log, rcf) = (format!("{LOG_DIR}/r6-slow.log"), format!("{LOG_DIR}/r6-slow.rc"));
    let ok = |cmd: String| { let t = &t; async move { let r = t.run_data(&cmd, true, None, 60).await.unwrap(); assert_eq!(r.rc, 0, "{cmd}: {}", r.complaint(300)); } };
    ok(format!("install -d -m 0755 {LOG_DIR} && rm -f {log} {rcf}")).await;
    ok(format!("setsid nohup bash -c 'for i in 1 2 3; do echo \"slow line $i\" >> {log}; sleep 8; done; echo 0 > {rcf}' >/dev/null 2>&1 < /dev/null & echo started")).await;
    let polls_before = polls(&dir);
    let seen = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let s2 = seen.clone();
    let (_keep, stop) = tokio::sync::watch::channel(false);
    let started = Instant::now();
    let rc = tokio::time::timeout(Duration::from_secs(120), t.follow(&log, &rcf, &move |s: String| s2.lock().unwrap().push_str(&s), stop))
        .await.expect("follow ended").unwrap();
    let took = started.elapsed();
    let n = polls(&dir) - polls_before;
    assert_eq!(rc, Some(0));
    assert_eq!(*seen.lock().unwrap(), "slow line 1\nslow line 2\nslow line 3\n");
    eprintln!("[charon] slow runner: followed to rc 0 in {took:?} with {n} long polls (the 2-second polling took about {})", took.as_secs() / 2 + 4);
    assert!(took >= Duration::from_secs(20), "the runner takes ~24 s: {took:?}");
    assert!((3..=6).contains(&n), "{n} polls for 3 lines and an rc file over {took:?}");
    ok(format!("rm -f {log} {rcf}")).await;
    drop(_mock);
    let _ = std::fs::remove_dir_all(&dir);
}

use std::path::Path;

/// How many follow long polls the mock has answered (tests/mock_charon.py writes run_command.log).
fn polls(dir: &Path) -> usize {
    std::fs::read_to_string(dir.join("run_command.log")).unwrap_or_default().lines().filter(|l| *l == "poll").count()
}
