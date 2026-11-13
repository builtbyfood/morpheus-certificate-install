//! morpheus-certificate-install 0.4.0 — the Charon transport against the REAL Charon on this
//! machine (R6). Ignored unless MCI_TEST_CHARON is set.
//!
//! Needs, in Charon: the MCP server on; an SSH session open to the fake appliance as mcitest
//! (192.0.2.10:2222) at the **trusted** tier, so Charon answers sudo and no approval dialog
//! is needed. Then:
//!   MCI_TEST_CHARON=<session id, or user@host, e.g. mcitest@192.0.2.10> \
//!   MCI_TEST_SSH=192.0.2.10:2222:mcitest:hunter2 \
//!     cargo test -p morpheus-certificate-install --test charon_live -- --ignored --nocapture
//! MCI_TEST_SSH is the exec-channel reference for "exact bytes", and the password for the leak grep.
//! Charon's charon.db is only ever opened read-only; this test checks the main file is unchanged.

mod common;

use mci_app::transport::charon_mcp;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the real Charon with a trusted session to the fake appliance (MCI_TEST_CHARON, MCI_TEST_SSH)"]
async fn charon_transport_against_real_charon() {
    let (Ok(want), Some(tg)) = (std::env::var("MCI_TEST_CHARON"), common::ssh_target()) else {
        eprintln!("MCI_TEST_CHARON / MCI_TEST_SSH not set; nothing to do");
        return;
    };

    // ---- discovery against Charon's real data dir.
    let d = charon_mcp::discover("").await;
    let dir = d.data_dir.clone().unwrap_or_else(|| panic!("Charon's data dir not found; searched {:?}", d.searched));
    let db = dir.join("charon.db");
    let db_before = std::fs::read(&db).ok();
    let j = d.to_json();
    eprintln!("[discovery] data dir {}, endpoint {}, {} saved ssh hosts, {} open sessions",
              dir.display(), j["endpoint"], j["hosts"].as_array().map_or(0, Vec::len), j["sessions"].as_array().map_or(0, Vec::len));
    assert_eq!(j["endpoint"]["has_token"], true, "{j}");
    assert!(j.get("sessions_error").is_none(), "{}", j["sessions_error"]);
    assert!(!j["hosts"].as_array().unwrap().is_empty(), "no saved ssh hosts read from charon.db");
    for h in j["hosts"].as_array().unwrap() {
        let keys: Vec<&String> = h.as_object().unwrap().keys().collect();
        assert!(keys.iter().all(|k| ["id", "name", "path", "host", "port", "user", "jump_host", "tags"].contains(&k.as_str())), "{keys:?}");
    }
    assert!(!j.to_string().to_lowercase().contains("credential"));

    // ---- the session: MCI_TEST_CHARON is a session id, or user@host (user from the title, host
    // from the session's host field, so a title like "mcitest@192.0.2.10:2222" matches too).
    let sessions = j["sessions"].as_array().unwrap();
    let s = sessions.iter().find(|s| s["id"] == want.as_str()).or_else(|| {
        let (user, host) = want.split_once('@')?;
        sessions.iter().find(|s| {
            s["kind"] == "ssh"
                && s["host"].as_str() == Some(host)
                && s["title"].as_str().is_some_and(|t| t.starts_with(&format!("{user}@")))
        })
    });
    let Some(s) = s else {
        let mut listing = String::new();
        for s in sessions {
            listing.push_str(&format!("\n  id {}  title {}  host {}  kind {}  tier {}", s["id"], s["title"], s["host"], s["kind"], s["tier"]));
        }
        panic!("no Charon session matches MCI_TEST_CHARON={want:?} (a session id, or user@host). \
                list_sessions returned {} session(s):{listing}", sessions.len());
    };
    eprintln!("[charon] session {} {} tier {}", s["id"], s["title"], s["tier"]);
    assert_eq!(s["tier"], "trusted", "the session must be at the trusted tier (Charon answers sudo, no approval dialog)");

    let t = charon_mcp::connect(&dir, s["id"].as_str().unwrap()).await.expect("connect through Charon");
    let reference = common::ssh_reference(&tg).await;
    common::charon_steps::exercise(&*t, &*reference, &tg.password).await;
    reference.close().await;

    if let Some(before) = db_before {
        assert_eq!(std::fs::read(&db).unwrap(), before, "charon.db main file unchanged by discovery");
    }
}
