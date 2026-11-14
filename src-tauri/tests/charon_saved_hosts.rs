//! morpheus-certificate-install 0.4.1 — Charon's saved hosts from charon.db, offline (no Charon, no
//! appliance), so it runs everywhere CI does. Added with the rusqlite 0.42 upgrade (RUSTSEC-2026-0459):
//! - only ssh nodes with a host come out, with user/port/tags inherited down the folder tree;
//! - no credential is ever read (it isn't even selected; the secrets below must not appear);
//! - the reader never writes: charon.db's bytes are identical afterwards, and a write through the
//!   same open flags is refused by SQLite;
//! - Charon keeps charon.db in WAL mode (PRAGMA journal_mode = WAL): read both with Charon closed
//!   and while Charon has it open with recent rows still only in the -wal file.

use mci_app::transport::charon_mcp::saved_hosts;
use rusqlite::{Connection, OpenFlags};
use std::path::{Path, PathBuf};

fn temp_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("mci-charon-db-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// The shape of Charon's `nodes` table, with secrets inside `settings` that must never come out.
fn make_db(path: &Path, wal: bool) -> Connection {
    let con = Connection::open(path).unwrap();
    if wal {
        let mode: String = con.query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0)).unwrap();
        assert_eq!(mode.to_lowercase(), "wal");
    }
    con.execute_batch("CREATE TABLE nodes (id TEXT PRIMARY KEY, parent_id TEXT, kind TEXT, name TEXT, sort INTEGER, settings TEXT);").unwrap();
    let rows = [
        ("f1", None, "folder", "Lab", r#"{"user":"mcitest","port":2222,"credential":"SECRET-FOLDER-PW","tags":["lab"]}"#),
        ("f2", Some("f1"), "folder", "Certs", r#"{"password":"SECRET-SUBFOLDER-PW"}"#),
        ("h1", Some("f2"), "ssh", "appliance-a", r#"{"host":"192.0.2.10","credential":"SECRET-HOST-PW","tags":["mci"]}"#),
        ("h2", Some("f1"), "ssh", "no-host", r#"{"user":"x"}"#),
        ("h3", None, "ssh", "appliance-b", r#"{"host":"appliance.example.com","port":22,"user":"admin","jump_host":"198.51.100.7","key_passphrase":"SECRET-PASSPHRASE"}"#),
        ("l1", None, "local", "pwsh", "{}"),
    ];
    for (i, (id, parent, kind, name, settings)) in rows.iter().enumerate() {
        con.execute("INSERT INTO nodes VALUES (?1, ?2, ?3, ?4, ?5, ?6)", rusqlite::params![id, parent, kind, name, i as i64, settings]).unwrap();
    }
    con
}

fn check_hosts(hosts: &[serde_json::Value]) {
    let all = serde_json::to_string(hosts).unwrap();
    assert!(!all.contains("SECRET") && !all.contains("credential") && !all.contains("password") && !all.contains("passphrase"),
        "no secret reached the result: {all}");
    assert_eq!(hosts.len(), 2, "only ssh nodes with a host: {all}");
    // Sorted by (path, name): "" < "Lab / Certs".
    let b = &hosts[0];
    assert_eq!((b["name"].as_str(), b["path"].as_str(), b["host"].as_str()), (Some("appliance-b"), Some(""), Some("appliance.example.com")));
    assert_eq!((b["port"].as_i64(), b["user"].as_str(), b["jump_host"].as_str()), (Some(22), Some("admin"), Some("198.51.100.7")));
    assert_eq!(b["tags"], serde_json::json!([]));
    let a = &hosts[1];
    assert_eq!((a["name"].as_str(), a["path"].as_str(), a["host"].as_str()), (Some("appliance-a"), Some("Lab / Certs"), Some("192.0.2.10")));
    assert_eq!(a["user"], "mcitest", "user inherited from the top folder");
    assert_eq!(a["port"], 2222, "port inherited from the top folder");
    assert_eq!(a["tags"], serde_json::json!(["mci"]), "the leaf's tags win");
}

#[test]
fn saved_hosts_reads_without_writing_charon_closed() {
    let dir = temp_dir("closed");
    let db = dir.join("charon.db");
    drop(make_db(&db, true)); // Charon closed: its last connection checkpoints and removes -wal/-shm
    let before = std::fs::read(&db).unwrap();
    let hosts = saved_hosts(&db).expect("read charon.db");
    check_hosts(&hosts);
    assert_eq!(std::fs::read(&db).unwrap(), before, "charon.db's bytes are unchanged by the read");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn saved_hosts_reads_while_charon_has_it_open() {
    let dir = temp_dir("open");
    let db = dir.join("charon.db");
    let charon = make_db(&db, true);
    // Keep "Charon" connected and make sure the newest row is only in the WAL, not the main file.
    charon.execute_batch("PRAGMA wal_autocheckpoint = 0;").unwrap();
    charon.execute("INSERT INTO nodes VALUES ('h4', NULL, 'ssh', 'appliance-c', 9, '{\"host\":\"198.51.100.9\",\"credential\":\"SECRET-NEW\"}')", []).unwrap();
    let main_before = std::fs::read(&db).unwrap();
    let hosts = saved_hosts(&db).expect("read charon.db while it's open in WAL mode");
    let all = serde_json::to_string(&hosts).unwrap();
    assert!(all.contains("appliance-c"), "a row still only in the -wal file is seen: {all}");
    assert!(!all.contains("SECRET"), "no secret reached the result: {all}");
    assert_eq!(hosts.len(), 3);
    assert_eq!(std::fs::read(&db).unwrap(), main_before, "charon.db's main file is unchanged by the read");
    drop(charon);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The flags the reader opens with (read-only, no mutex) can't write: SQLite refuses.
#[test]
fn the_reader_flags_refuse_writes() {
    let dir = temp_dir("flags");
    let db = dir.join("charon.db");
    drop(make_db(&db, true));
    let ro = Connection::open_with_flags(&db, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX).unwrap();
    let err = ro.execute("DELETE FROM nodes", []).unwrap_err().to_string();
    assert!(err.to_lowercase().contains("readonly") || err.to_lowercase().contains("read-only"), "write refused: {err}");
    drop(ro);
    let _ = std::fs::remove_dir_all(&dir);
}
