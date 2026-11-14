//! morpheus-certificate-install 0.4.1 — the Tauri commands on tauri's MockRuntime (R7): request and
//! response bodies as the Python /api/* routes, the events they emit on `mci`, jobs, settings.
//! No window and no appliance; `verify` runs against a TLS server started here.
//!   cargo test -p morpheus-certificate-install --test commands

mod common;

use common::app::{corpus_file, App};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const NOT_CONNECTED: &str = "Not connected. Connect to the appliance first.";

fn files() -> Value { json!([corpus_file("chain.p7b"), corpus_file("leaf-pkcs1.key")]) }

/// A TLS server on 127.0.0.1 serving the corpus leaf (m.cust.test) + its intermediate. Returns the port.
fn tls_server() -> u16 {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let b = mci_core::formats::parse_files(
        &[mci_core::formats::InputFile { name: "chain.p7b".into(), data: std::fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures/corpus/chain.p7b")).unwrap() },
          mci_core::formats::InputFile { name: "leaf-pkcs1.key".into(), data: std::fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures/corpus/leaf-pkcs1.key")).unwrap() }],
        &Default::default());
    let an = mci_core::analyze::analyze(&b, "m.cust.test", "", 0);
    let chain = vec![CertificateDer::from(an.leaf.as_ref().unwrap().der.clone()), CertificateDer::from(an.intermediates[0].der.clone())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(an.key_pkcs8.clone().unwrap()));
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions().unwrap().with_no_client_auth().with_single_cert(chain, key).unwrap();
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async move {
            l.set_nonblocking(true).unwrap();
            let l = tokio::net::TcpListener::from_std(l).unwrap();
            let acc = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
            loop {
                let (s, _) = l.accept().await.unwrap();
                let acc = acc.clone();
                tokio::spawn(async move { let _ = acc.accept(s).await; });
            }
        });
    });
    port
}

/// Accepts connections and never answers: a TLS handshake against it times out.
fn silent_server() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let mut keep = vec![];
        for s in l.incoming() { keep.push(s); }
    });
    port
}

#[test]
fn certificate_commands_and_settings() {
    let saved_to: Arc<Mutex<Option<PathBuf>>> = Arc::new(Mutex::new(None));
    let s2 = saved_to.clone();
    let app = App::new("cmd-cert", Some(Arc::new(move |name: String| s2.lock().unwrap().clone().map(|d| d.join(name)))));

    let st = app.ok("state", Value::Null);
    assert_eq!(st["version"], mci_core::VERSION);
    assert_eq!((&st["connected"], &st["busy"], &st["transport"], &st["analysis"]), (&json!(false), &json!(false), &Value::Null, &Value::Null));
    assert_eq!(st["has_morpheus_token"], false);

    assert_eq!(app.call("analyze", json!({"files": [], "pasted": ""})).unwrap_err(), "Add certificate files or paste PEM text first.");
    let a = app.ok("analyze", json!({"files": files(), "pasted": "", "pfx_password": "", "key_password": "", "fqdn": ""}));
    assert_eq!(a["ok"], true, "{a}");
    assert_eq!(a["fqdn"], "m.cust.test");
    assert_eq!(a["file_base"], "m_cust_test");
    assert_eq!(a["chain"].as_array().unwrap().iter().map(|c| c["role"].as_str().unwrap()).collect::<Vec<_>>(), ["server", "intermediate", "root"]);
    assert_eq!(a["inputs"].as_array().unwrap().len(), 2);
    assert_eq!(app.settings(), json!({"fqdn": "m.cust.test"}), "only allowed keys are saved");
    assert_eq!(app.ok("state", Value::Null)["analysis"], a, "state carries the analysis");

    // export: the dialog cancelled → saved null; a path → the zip is written there.
    let ex = app.ok("export_zip", json!({"include_root": false}));
    assert_eq!(ex["saved"], Value::Null);
    let names: Vec<&str> = ex["files"].as_array().unwrap().iter().map(|f| f.as_str().unwrap()).collect();
    assert!(names.contains(&"m_cust_test.crt") && names.contains(&"m_cust_test.key") && names.contains(&"INSTALL.txt"), "{names:?}");
    *saved_to.lock().unwrap() = Some(app.data_dir.clone());
    let ex = app.ok("export_zip", json!({"include_root": true}));
    let zip = PathBuf::from(ex["saved"].as_str().unwrap());
    assert_eq!(zip, app.data_dir.join("m_cust_test-morpheus.zip"));
    assert_eq!(&std::fs::read(&zip).unwrap()[..2], b"PK");

    // plan needs preflight facts; clear_files resets.
    assert_eq!(app.call("plan", json!({"server": true})).unwrap_err(), "Run the appliance check on the Connect step first.");
    assert_eq!(app.ok("clear_files", json!({})), json!({"ok": true}));
    assert_eq!(app.ok("state", Value::Null)["analysis"], Value::Null);
    assert_eq!(app.call("plan", json!({})).unwrap_err(), "Load a valid certificate first (the Certificate step shows what's wrong).");
    assert_eq!(app.call("export_zip", json!({})).unwrap_err(), "Check the certificate first.");
    assert_eq!(app.call("fetch_chain", json!({})).unwrap_err(), "Load the certificate first.");
}

#[test]
fn appliance_commands_need_a_connection() {
    let app = App::new("cmd-conn", None);
    for cmd in ["preflight", "runs", "backups", "apply", "rollback", "reattach", "shell_open", "shell_input", "shell_resize"] {
        assert_eq!(app.call(cmd, json!({"id": "x"})).unwrap_err(), NOT_CONNECTED, "{cmd}");
    }
    assert_eq!(app.call("connect", json!({"mode": "ssh", "host": " ", "user": "mcitest"})).unwrap_err(), "Enter the appliance's host and the user to log in as.");
    assert!(app.call("connect", json!({"mode": "ssh", "host": "h", "user": "u", "port": "x"})).unwrap_err().contains("isn't a port number"));
    assert_eq!(app.ok("stop", json!({})), json!({"ok": true, "note": "Stopped following. Anything already running on the appliance carries on."}));
    let m = app.mark();
    assert_eq!(app.ok("disconnect", json!({})), json!({"ok": true}));
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(app.events_since(m), vec![json!({"type": "disconnected"})]);
    assert_eq!(app.call("set_appliance_url", json!({"new_url": "https://x/"})).unwrap_err(), "Check the Morpheus API first.");
    assert_eq!(app.call("morpheus_check", json!({"url": "", "token": ""})).unwrap_err(), "Enter the Morpheus URL and an API token.");
}

#[test]
fn verify_is_a_job_with_events() {
    let port = tls_server();
    let app = App::new("cmd-verify", None);
    app.ok("analyze", json!({"files": files()}));

    let m = app.mark();
    let v = app.job("verify", "verify", json!({"fqdn": "m.cust.test", "port": port.to_string(), "connect_addr": "127.0.0.1"}), Duration::from_secs(30));
    let local = &v["local"];
    assert_eq!(v["remote"], Value::Null, "not connected: no appliance-side check");
    assert_eq!((&local["ok"], &local["verified"], &local["matches_new"]), (&json!(true), &json!(true), &json!(true)), "{v}");
    assert_eq!(local["summary"], "TLSv1.3, chain verifies for m.cust.test (using the supplied root); serving the new certificate");
    assert_eq!(local["addr"], format!("127.0.0.1:{port}"));
    let evs = app.events_since(m);
    let kinds: Vec<String> = evs.iter().map(|e| format!("{}{}", e["type"].as_str().unwrap(), e["status"].as_str().map(|s| format!(":{s}")).unwrap_or_default())).collect();
    assert_eq!(kinds, ["job:running", "log", "verify", "job:done"], "{evs:#?}");
    assert_eq!(evs[1]["text"], format!("From this machine (127.0.0.1:{port}): {}\n", local["summary"].as_str().unwrap()));
    assert_eq!(evs[2]["result"], v);
    assert_eq!(app.settings()["connect_addr"], "127.0.0.1");
    assert_eq!(app.settings()["tls_port"], port);

    // Without the supplied root (no analysis), the built-in store doesn't know Cust Root.
    app.ok("clear_files", json!({}));
    let v = app.job("verify", "verify", json!({"fqdn": "m.cust.test", "port": port, "connect_addr": "127.0.0.1"}), Duration::from_secs(30));
    assert_eq!((&v["local"]["ok"], &v["local"]["verified"], &v["local"]["matches_new"]), (&json!(false), &json!(false), &json!(false)));
    assert!(v["local"]["summary"].as_str().unwrap().starts_with("TLSv1.3, verification failed: the chain doesn't lead to a trusted root (unknown issuer)"), "{v}");
    assert_eq!(app.call("verify", json!({"fqdn": ""})).unwrap_err(), "Enter the FQDN to check.");

    // One job at a time: a verify stuck on a silent server blocks a second one.
    let silent = silent_server();
    let m = app.mark();
    assert_eq!(app.ok("verify", json!({"fqdn": "m.cust.test", "port": silent, "connect_addr": "127.0.0.1"})), json!({"ok": true}));
    assert!(app.ok("state", Value::Null)["busy"] == true);
    assert_eq!(app.call("verify", json!({"fqdn": "m.cust.test"})).unwrap_err(), "Another operation is running. Wait for it, or stop following it first.");
    assert_eq!(app.call("connect", json!({"mode": "ssh"})).unwrap_err(), "An operation is running; connect after it finishes.");
    let e = app.wait_job("verify", m, Duration::from_secs(30));
    assert!(e["result"]["local"]["summary"].as_str().unwrap().starts_with("could not connect: timed out after 8 s"), "{e}");
    assert_eq!(app.ok("state", Value::Null)["busy"], false);
}

#[test]
fn the_api_token_stays_in_memory() {
    let app = App::new("cmd-token", None);
    let token = "SECRET-TOKEN-R7-4d2a";
    let m = app.mark();
    let r = app.ok("morpheus_check", json!({"url": "https://127.0.0.1:1", "token": token}));
    assert_eq!(r["url"], "https://127.0.0.1:1");
    assert!(r["error"].as_str().unwrap().starts_with("could not reach https://127.0.0.1:1: "), "{r}");
    let st = app.ok("state", Value::Null);
    assert_eq!((&st["morpheus_url"], &st["has_morpheus_token"]), (&json!("https://127.0.0.1:1"), &json!(true)));
    assert!(!st.to_string().contains(token));
    assert_eq!(app.settings(), json!({"morpheus_url": "https://127.0.0.1:1"}));
    for f in std::fs::read_dir(&app.data_dir).unwrap() {
        let p = f.unwrap().path();
        if p.is_file() { assert!(!String::from_utf8_lossy(&std::fs::read(&p).unwrap()).contains(token), "{} has the token", p.display()); }
    }
    assert!(!serde_json::to_string(&app.events_since(m)).unwrap().contains(token), "an event carried the token");
    assert_eq!(app.call("set_appliance_url", json!({"new_url": "http://x/"})).unwrap_err(), "The Appliance URL should start with https://");
}

#[test]
fn a_wildcard_certificate_needs_a_real_fqdn_and_the_trust_default_comes_from_the_root() {
    let app = App::new("cmd-wild", Some(Arc::new(|n: String| Some(std::env::temp_dir().join(n)))));
    let wild = json!([corpus_file("leaf-wildcard.crt"), corpus_file("leaf-wildcard.key"), corpus_file("wildcard-root.crt")]);
    // Not connected, no FQDN: the wildcard isn't used; an error asks for the name; export and plan stay blocked.
    let a = app.ok("analyze", json!({"files": wild, "fqdn": ""}));
    assert_eq!((&a["ok"], &a["fqdn"], &a["file_base"]), (&json!(false), &json!(""), &json!("")), "{a}");
    assert!(a["checks"].as_array().unwrap().iter().any(|c| c["level"] == "error" && c["text"] == "Wildcard certificate: enter the appliance's FQDN."));
    assert!(app.call("export_zip", json!({})).is_err(), "export is blocked");
    assert_eq!(app.call("plan", json!({})).unwrap_err(), "Load a valid certificate first (the Certificate step shows what's wrong).");
    assert!(app.call("verify", json!({"fqdn": "*.wild.test"})).unwrap_err().contains("is a wildcard"));
    // Typing the wildcard is the same as leaving it empty.
    assert_eq!(app.ok("analyze", json!({"files": [], "fqdn": "*.wild.test"}))["ok"], false);
    // A covered name: fine, and it's what INSTALL.txt and the file names use.
    let a = app.ok("analyze", json!({"files": [], "fqdn": "morpheus.wild.test"}));
    assert_eq!((&a["ok"], &a["fqdn"], &a["file_base"]), (&json!(true), &json!("morpheus.wild.test"), &json!("morpheus_wild_test")));
    let ex = app.ok("export_zip", json!({}));
    assert!(ex["files"].as_array().unwrap().contains(&json!("morpheus_wild_test.crt")));
    let _ = std::fs::remove_file(ex["saved"].as_str().unwrap());
    // The trust default: the root (Wild Test Root) is private, so ticked, with the reason.
    assert_eq!((&a["trust_default"], &a["trust_reason"], &a["trust_store"]),
               (&json!(true), &json!("Private CA: Morpheus' Java won't trust it until it's imported."), &Value::Null));
    assert_eq!(app.ok("state", Value::Null)["analysis"]["trust_default"], true, "state carries it too");
}

#[test]
fn forget_this_appliance_removes_its_settings_and_host_key() {
    let app = App::new("cmd-forget", None);
    std::fs::write(app.data_dir.join("settings.json"), serde_json::to_string(&json!({
        "host": "appliance.example.com", "port": 2222, "user": "mcitest", "key_path": "", "fqdn": "morpheus.example.com",
        "connect_addr": "192.0.2.10", "tls_port": 443, "morpheus_url": "https://morpheus.example.com", "mode": "ssh", "charon_dir": ""})).unwrap()).unwrap();
    std::fs::write(app.data_dir.join("known_hosts"),
        "[appliance.example.com]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n\
         [other.example.com]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n").unwrap();
    let r = app.ok("forget_appliance", json!({}));
    assert_eq!(r["known_hosts_removed"], 1, "{r}");
    assert_eq!(app.settings(), json!({"mode": "ssh", "charon_dir": ""}), "only this computer's settings are left");
    let kh = std::fs::read_to_string(app.data_dir.join("known_hosts")).unwrap();
    assert!(!kh.contains("appliance.example.com") && kh.contains("other.example.com"), "{kh}");
    assert!(app.call("forget_appliance", json!({})).unwrap_err().starts_with("No appliance to forget"));
}

#[test]
fn leave_no_trace_is_portable_only_and_saves_nothing() {
    let app = App::new("cmd-lnt", None);
    assert!(app.call("set_leave_no_trace", json!({"on": true})).unwrap_err().starts_with("Leave no trace is for the portable app"));
    assert_eq!(app.ok("state", Value::Null)["portable"], false);
    let app = App::new_with("cmd-lnt-p", None, true);
    let st = app.ok("state", Value::Null);
    assert_eq!((&st["portable"], &st["leave_no_trace"]), (&json!(true), &json!(false)));
    assert_eq!(app.ok("set_leave_no_trace", json!({"on": true}))["leave_no_trace"], true);
    app.ok("analyze", json!({"files": files(), "fqdn": ""}));
    assert!(!app.data_dir.join("settings.json").exists(), "nothing saved to settings");
    assert_eq!(app.ok("state", Value::Null)["leave_no_trace"], true);
    app.ok("set_leave_no_trace", json!({"on": false}));
    app.ok("analyze", json!({"files": [], "fqdn": ""}));
    assert_eq!(app.settings(), json!({"fqdn": "m.cust.test"}), "saved again once it's off");
}

#[test]
fn cleanup_needs_a_connection() {
    let app = App::new("cmd-clean", None);
    for c in ["cleanup_list", "cleanup_plan", "cleanup"] {
        assert_eq!(app.call(c, json!({})).unwrap_err(), NOT_CONNECTED, "{c}");
    }
}
