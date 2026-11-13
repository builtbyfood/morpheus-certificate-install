//! morpheus-certificate-install 0.4.0 — the engine end to end against the fake appliance (R7; moved
//! here from R8). Drives the app's commands (tauri MockRuntime, no window, no UI) — connect,
//! preflight, analyze, plan, apply, verify, runs, backups, rollback, the Morpheus API check — and
//! checks the appliance afterwards through a separate SSH connection (the "reference").
//!
//!   MCI_TEST_SSH=192.0.2.10:2222:mcitest:hunter2 \
//!     cargo test -p morpheus-certificate-install --test engine_e2e -- --ignored --nocapture --test-threads=1
//!
//! Through Charon instead (the core: apply → verify → rollback), with a trusted Charon session to
//! the fake appliance as mcitest (see tests/charon_live.rs):
//!   MCI_TEST_E2E_CHARON=mcitest@192.0.2.10 MCI_TEST_SSH=… cargo test … --test engine_e2e -- --ignored --nocapture
//!
//! The fake appliance's state is reset first (test-only shell text, here and nowhere else): a
//! morpheus.rb with a legacy `sphragis` block pointing at the starting certificate, no mci-* CA
//! aliases or trusted_certs files, the fake API's Appliance URL back to morpheus.rb's. It ends
//! rolled back to that state.

mod common;

use common::app::{corpus_file, steps, App};
use mci_app::transport::Transport;
use mci_core::appliance::{BACKUP_DIR, LOG_DIR, MORPHEUS_RB, RUN_DIR, STATE_DIR, TRUST_DIR};
use mci_core::morpheus_rb::{LEGACY_BEGIN, LEGACY_END, MANAGED_BEGIN};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

/// fake-nginx.py's test token (tests/fake-appliance).
const API_TOKEN: &str = "mci-fake-api-token-7f3c9a1e";
const FQDN: &str = "m.cust.test";
const CRT: &str = "/etc/morpheus/ssl/m_cust_test.crt";
const KEY: &str = "/etc/morpheus/ssl/m_cust_test.key";
const START_CRT: &str = "/etc/morpheus/ssl/appliance.crt";
const START_KEY: &str = "/etc/morpheus/ssl/appliance.key";
const RUN_TIMEOUT: Duration = Duration::from_secs(240);
/// What these tests install (and the ledger), removed by the resets: test-only text.
const TEST_INSTALLED: &str = "/etc/morpheus/ssl/m_cust_test.crt /etc/morpheus/ssl/m_cust_test.key /etc/morpheus/ssl/10_0_0_5.crt /etc/morpheus/ssl/10_0_0_5.key /var/lib/morpheus-certificate-install/installed.json";
const IP_CRT: &str = "/etc/morpheus/ssl/10_0_0_5.crt";
const IP_KEY: &str = "/etc/morpheus/ssl/10_0_0_5.key";

fn planted_rb() -> String {
    format!("appliance_url 'https://198.51.100.20'\nelasticsearch['es_hosts'] = {{'127.0.0.1' => 9200}}\n\n{}\n# written 20250101-000000 by sphragis 0.2.0\nnginx['ssl_certificate'] = '{START_CRT}'\nnginx['ssl_server_key'] = '{START_KEY}'\n{}\n",
            LEGACY_BEGIN[0], LEGACY_END[0])
}

/// The reference connection: an exec channel to the same appliance, for setting up and checking.
struct Ref {
    rt: tokio::runtime::Runtime,
    t: Box<dyn Transport>,
}

impl Ref {
    fn sudo(&self, cmd: &str) -> String {
        let r = self.rt.block_on(self.t.run_data(cmd, true, None, 120)).unwrap();
        assert_eq!(r.rc, 0, "{cmd}: {}", r.complaint(400));
        r.stdout
    }
    fn sudo_rc(&self, cmd: &str) -> (i32, String) {
        let r = self.rt.block_on(self.t.run_data(cmd, true, None, 120)).unwrap();
        (r.rc, r.stdout)
    }
    fn put(&self, path: &str, data: &[u8], mode: &str) {
        self.rt.block_on(self.t.put_root(path, data, mode, "0700")).unwrap();
    }
    fn served_fp(&self) -> String {
        let v = self.rt.block_on(mci_app::engine::served_chain(&*self.t, "")).unwrap();
        assert_eq!(v["ok"], true, "{v}");
        v["fingerprints"][0].as_str().unwrap().to_string()
    }
    fn stat(&self, path: &str) -> String { self.sudo(&format!("stat -c '%a %U:%G' {path}")).trim().to_string() }
    fn aliases(&self) -> Vec<String> {
        self.sudo("cat /var/lib/fake-morpheus/keytool-aliases 2>/dev/null; true").lines().map(String::from).collect()
    }
}

fn say(s: &str) { eprintln!("[e2e] {s}"); }

/// The live tests share one appliance: never run two at once, even without --test-threads=1.
static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Connect through the app: SSH with the TOFU round trip, or a Charon session.
fn connect(app: &App, tg: &common::Target, charon: Option<&str>) -> Value {
    if let Some(want) = charon {
        let d = app.ok("charon_discover", json!({"charon_dir": ""}));
        let sessions = d["sessions"].as_array().cloned().unwrap_or_default();
        let s = sessions.iter().find(|s| s["id"] == want).or_else(|| {
            let (user, host) = want.split_once('@')?;
            sessions.iter().find(|s| s["kind"] == "ssh" && s["host"].as_str() == Some(host) && s["title"].as_str().is_some_and(|t| t.starts_with(&format!("{user}@"))))
        }).unwrap_or_else(|| panic!("no Charon session matches {want:?}: {d}"));
        assert_eq!(s["tier"], "trusted", "the Charon session must be at the trusted tier");
        let r = app.ok("connect", json!({"mode": "charon", "session": s["id"], "charon_dir": ""}));
        assert_eq!(r["ok"], true, "{r}");
        return r;
    }
    let args = |fp: &str| json!({"mode": "ssh", "host": tg.host, "port": tg.port.to_string(), "user": tg.user, "password": tg.password,
                                 "sudo_password": "", "key_path": "", "key_passphrase": "", "trust_fingerprint": fp});
    let r = app.ok("connect", args(""));
    assert_eq!(r["ok"], false, "a fresh known_hosts must ask about the host key: {r}");
    let hk = &r["hostkey"];
    assert_eq!(hk["mismatch"], false);
    let r = app.ok("connect", args(hk["fingerprint"].as_str().unwrap()));
    assert_eq!(r["ok"], true, "{r}");
    say(&format!("host key confirmed: {} {}", hk["type"], hk["fingerprint"]));
    r
}

#[test]
#[ignore = "needs the fake appliance: MCI_TEST_SSH=host:port:user:password (and MCI_TEST_E2E_CHARON for the Charon run)"]
fn engine_end_to_end() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|p| p.into_inner());
    let Some(tg) = common::ssh_target() else { eprintln!("MCI_TEST_SSH not set"); return };
    let charon = std::env::var("MCI_TEST_E2E_CHARON").ok().filter(|s| !s.is_empty());
    let full = charon.is_none();
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    let t = rt.block_on(common::ssh_reference(&tg));
    let r = Ref { rt, t };

    // ---- reset the fake appliance
    r.put(MORPHEUS_RB, planted_rb().as_bytes(), "0600");
    r.sudo(&format!("rm -f /etc/morpheus/ssl/trusted_certs/mci-*.pem /var/lib/fake-morpheus/appliance-url {TEST_INSTALLED}; \
            touch /var/lib/fake-morpheus/keytool-aliases; sed -i '/^mci-/d' /var/lib/fake-morpheus/keytool-aliases; \
            morpheus-ctl restart nginx >/dev/null"));
    std::thread::sleep(Duration::from_secs(1));
    let start_fp = r.served_fp();
    let start_files = r.sudo(&format!("sha256sum {START_CRT} {START_KEY}"));
    say(&format!("reset: legacy sphragis block planted, serving the starting certificate {}…", &start_fp[..23]));

    let out = std::env::temp_dir().join(format!("mci-r7-e2e-out-{}", std::process::id()));
    std::fs::create_dir_all(&out).unwrap();
    let out2 = out.clone();
    let app = App::new(if full { "e2e-ssh" } else { "e2e-charon" }, Some(Arc::new(move |n: String| Some(out2.join(n)))));

    // ---- convert: chain.p7b + leaf-pkcs1.key
    let a = app.ok("analyze", json!({"files": [corpus_file("chain.p7b"), corpus_file("leaf-pkcs1.key")], "pasted": "", "fqdn": ""}));
    assert_eq!((&a["ok"], &a["fqdn"]), (&json!(true), &json!(FQDN)), "{a}");
    let leaf_fp = a["chain"][0]["sha256"].as_str().unwrap().to_string();
    let aliases: Vec<String> = a["ca_aliases"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect();
    let ex = app.ok("export_zip", json!({"include_root": false}));
    assert!(std::fs::metadata(ex["saved"].as_str().unwrap()).unwrap().len() > 1000);
    say(&format!("convert: {} — {:?}", ex["saved"], ex["files"]));

    // ---- connect + preflight
    let c = connect(&app, &tg, charon.as_deref());
    say(&format!("connected: {} (sudo {})", c["transport"]["label"], c["transport"]["sudo_mode"]));
    let m = app.mark();
    app.job("preflight", "preflight", json!({}), Duration::from_secs(120));
    let facts = app.events_since(m).into_iter().find(|e| e["type"] == "facts").expect("facts event")["facts"].clone();
    assert_eq!(facts["systemdrun"], "yes");
    assert_eq!(facts["problems"], json!([]), "{facts}");
    assert_eq!(facts["nginx_ssl"]["ssl_certificate"], START_CRT, "the legacy block's lines are the active ones");
    assert_eq!(facts["served"]["leaf"]["cn"], "appliance");
    assert_eq!(facts["appliance_url_rb"], "https://198.51.100.20");
    assert!(facts.get("morpheus_rb").is_none(), "morpheus.rb text isn't sent to the page");
    say(&format!("preflight: {} / {} / runner systemd", facts["os"], facts["openssl"]));

    // ---- a wildcard certificate gets the appliance's own name, never "*" (0.3.17)
    let short = facts["host"].as_str().unwrap().split('.').next().unwrap().to_lowercase();
    app.ok("clear_files", json!({}));
    let w = app.ok("analyze", json!({"files": [corpus_file("leaf-wildcard.crt"), corpus_file("leaf-wildcard.key"), corpus_file("wildcard-root.crt")], "fqdn": ""}));
    assert_eq!((&w["ok"], &w["fqdn"]), (&json!(true), &json!(format!("{short}.wild.test"))), "{w}");
    say(&format!("wildcard certificate: suggested {} from the appliance's hostname {}", w["fqdn"], facts["host"]));
    app.ok("clear_files", json!({}));
    app.ok("analyze", json!({"files": [corpus_file("chain.p7b"), corpus_file("leaf-pkcs1.key")], "fqdn": ""}));

    // ---- verify before: saves connect_addr and tls_port; not the new certificate yet
    let v = app.job("verify", "verify", json!({"fqdn": FQDN, "port": "443", "connect_addr": tg.host}), Duration::from_secs(60));
    assert_eq!((&v["remote"]["matches_new"], &v["local"]["matches_new"]), (&json!(false), &json!(false)), "{v}");
    assert!(v["local"]["summary"].as_str().unwrap().contains("the appliance serves a self-signed certificate (\"appliance\")"), "{v}");
    say(&format!("verify before: {}", v["local"]["summary"]));

    // ---- plan + apply (server + trust + restart_ui)
    let apply = |label: &str| -> (Value, Vec<Value>) {
        let p = app.ok("plan", json!({"server": true, "include_root": false, "trust": true, "restart_ui": true}));
        let m = app.mark();
        let res = app.job("apply", "apply", json!({"confirm": p["stamp"]}), RUN_TIMEOUT);
        let evs = app.events_since(m);
        assert_eq!(res["ok"], true, "{label}: {res}\n{}", app.log_since(m));
        (json!({"plan": p, "result": res}), evs)
    };
    let (first, evs) = apply("first apply");
    let p = &first["plan"];
    let ids: Vec<&str> = p["steps"].as_array().unwrap().iter().map(|s| s["id"].as_str().unwrap()).collect();
    assert_eq!(ids, ["backup", "files", "rb", "match", "trustfiles", "runner", "verify"]);
    let diff = p["rb_diff"].as_str().unwrap();
    assert!(diff.contains(&format!("-{}", LEGACY_BEGIN[0])) && diff.contains(&format!("+nginx['ssl_certificate'] = '{CRT}'")), "{diff}");
    let res = &first["result"];
    let first_stamp = p["stamp"].as_str().unwrap().to_string();
    assert_eq!(res["backup"], format!("{BACKUP_DIR}/{first_stamp}"));
    let st = steps(&evs);
    for s in ["backup:ok", "files:ok", "rb:ok", "match:ok", "trustfiles:ok", "runner:running", "run:reconfigure:ok", "run:keytool:ok", "run:nginx:ok", "run:ui:ok", "runner:ok"] {
        assert!(st.contains(&s.to_string()), "missing step {s}: {st:?}");
    }
    assert!(evs.iter().any(|e| e["type"] == "run" && e["id"] == first_stamp.as_str() && e["watch"] == format!("tail -n +1 -F {LOG_DIR}/{first_stamp}.log")));
    let remote_text: String = evs.iter().filter(|e| e["type"] == "remote").filter_map(|e| e["text"].as_str()).collect();
    assert!(remote_text.contains("@@MCI done rc=0") && remote_text.contains("morpheus Reconfigured!"), "{remote_text}");
    // verify, run by apply
    let ver = &res["verify"];
    assert_eq!(ver["remote"]["matches_new"], true, "{ver}");
    assert_eq!(ver["remote"]["fingerprints"][0], leaf_fp.as_str());
    assert_eq!(ver["remote"]["chain_len"], 2, "leaf + intermediate (no root)");
    let local = &ver["local"];
    assert_eq!((&local["ok"], &local["verified"], &local["matches_new"]), (&json!(true), &json!(true), &json!(true)), "{local}");
    assert_eq!(local["summary"], format!("TLSv1.3, chain verifies for {FQDN} (using the supplied root); serving the new certificate"));
    assert_eq!(local["addr"], format!("{}:443", tg.host));
    assert!(evs.iter().any(|e| e["type"] == "verify" && e["result"] == *ver));
    say(&format!("apply {first_stamp}: rc 0; verify: {}", local["summary"]));
    let ledger = r.sudo(&format!("cat {}", mci_core::appliance::LEDGER));
    assert!(ledger.contains(CRT) && ledger.contains(KEY), "the ledger records the installed files: {ledger}");
    // The Run log has the key match's stdout, not sudo's lecture.
    let runlog = evs.iter().filter(|e| e["type"] == "log").filter_map(|e| e["text"].as_str()).collect::<String>();
    assert!(runlog.contains("cert=") && !runlog.contains("usual lecture"), "{runlog}");
    // what nginx serves, through the reference connection
    assert_eq!(r.served_fp(), leaf_fp, "the served fingerprint is the new certificate's");
    say("served fingerprint matches the new certificate");

    if full {
        // ---- the Morpheus API (fake-nginx.py), with the test token
        let url = format!("https://{}", tg.host);
        let api = app.ok("morpheus_check", json!({"url": url, "token": API_TOKEN}));
        assert_eq!((&api["user"], &api["build"]), (&json!("mci-api-tester"), &json!("8.0.0-fake")), "{api}");
        // By IP the name can't match the certificate (m.cust.test, 10.0.0.5), so TLS doesn't verify and it retries unverified.
        assert_eq!(api["verified_tls"], false, "{api}");
        assert!(api["tls_error"].as_str().unwrap().contains("isn't valid for this name"), "{api}");
        assert_eq!((&api["appliance_url"], &api["appliance_url_covered"]), (&json!("https://198.51.100.20"), &json!(false)), "{api}");
        let api = app.ok("set_appliance_url", json!({"new_url": format!("https://{FQDN}/")}));
        assert_eq!((&api["appliance_url"], &api["appliance_url_covered"]), (&json!(format!("https://{FQDN}/")), &json!(true)), "{api}");
        let bad = app.ok("morpheus_check", json!({"url": url, "token": "wrong-token"}));
        assert_eq!(bad["error"], "HTTP 401 from /api/whoami — check the API token.");
        assert!(!std::fs::read_to_string(app.data_dir.join("settings.json")).unwrap().contains(API_TOKEN));
        r.sudo("rm -f /var/lib/fake-morpheus/appliance-url");
        say("Morpheus API: whoami, appliance-settings GET and PUT with the test token; a wrong token gets 401");

        // ---- permissions (CLAUDE.md)
        let bdir = format!("{BACKUP_DIR}/{first_stamp}");
        let want = [
            (CRT.to_string(), "600 root:root"), (KEY.to_string(), "600 root:root"), (MORPHEUS_RB.to_string(), "600 root:root"),
            (TRUST_DIR.to_string(), "755 root:root"),
            (format!("{RUN_DIR}/{first_stamp}.sh"), "700 root:root"),
            (STATE_DIR.to_string(), "700 root:root"), (BACKUP_DIR.to_string(), "700 root:root"), (bdir.clone(), "700 root:root"),
            (format!("{bdir}/manifest.json"), "600 root:root"),
        ];
        for (path, mode) in &want { assert_eq!(r.stat(path), *mode, "{path}"); }
        for a in &aliases { assert_eq!(r.stat(&format!("{TRUST_DIR}/{a}.pem")), "644 root:root", "{a}"); }
        let log = r.stat(&format!("{LOG_DIR}/{first_stamp}.log"));
        assert!(log.starts_with(&format!("600 {}:", tg.user)), "run log {log}");
        assert!(r.stat(&format!("{LOG_DIR}/{first_stamp}.rc")).contains(&format!(" {}:", tg.user)));
        say("permissions: cert/key 0600 root, CA PEMs 0644 in a 0755 trusted_certs, runner 0700, backups 0700, run log 0600 mcitest");

        // ---- the sudo password is nowhere in the app's files; a planted copy is found
        let pattern = "/root/mci-r7-leak-pattern";
        r.put(pattern, format!("{}\n", tg.password).as_bytes(), "0600");
        let (rc, hits) = r.sudo_rc(&format!("grep -r -l -F -s -f {pattern} /etc/morpheus {STATE_DIR} {LOG_DIR}"));
        assert_eq!((rc, hits.as_str()), (1, ""), "the sudo password was found in: {hits}");
        r.put(&format!("{STATE_DIR}/r7-canary/x"), format!("x{}x\n", tg.password).as_bytes(), "0600");
        let (rc, hits) = r.sudo_rc(&format!("grep -r -l -F -s -f {pattern} {STATE_DIR}"));
        assert_eq!((rc, hits.trim()), (0, format!("{STATE_DIR}/r7-canary/x").as_str()));
        r.sudo(&format!("rm -rf {STATE_DIR}/r7-canary; shred -u {pattern}"));
        say("leak grep: no hits; planted copy found");

        // ---- a second apply leaves exactly one managed block
        app.job("preflight", "preflight", json!({}), Duration::from_secs(120));
        let (second, _) = apply("second apply");
        let rb = r.sudo(&format!("cat {MORPHEUS_RB}"));
        assert_eq!(rb.matches(MANAGED_BEGIN).count(), 1, "{rb}");
        assert!(!rb.contains("sphragis"), "the legacy block was replaced: {rb}");
        assert_eq!(rb.lines().filter(|l| l.starts_with("nginx['ssl_certificate']")).count(), 1, "{rb}");
        let al = r.aliases();
        for a in &aliases { assert_eq!(al.iter().filter(|x| *x == a).count(), 1, "{a} in {al:?}"); }
        say(&format!("second apply {}: one managed block, legacy block gone, each alias once", second["plan"]["stamp"]));
    }

    // ---- runs and backups
    let runs = app.ok("runs", json!({}));
    assert!(runs["runs"].as_array().unwrap().iter().any(|x| x["id"] == first_stamp.as_str() && x["rc"] == "0"), "{runs}");
    let b = app.ok("backups", json!({}));
    let first_b = b["backups"].as_array().unwrap().iter().find(|x| x["id"] == first_stamp.as_str()).unwrap_or_else(|| panic!("{b}"));
    assert_eq!((&first_b["fqdn"], &first_b["crt"]), (&json!(FQDN), &json!(CRT)));
    assert_eq!(first_b["aliases"], json!(aliases));

    // ---- rollback to the first backup: the starting certificate again, the CA aliases removed
    let m = app.mark();
    let rb_res = app.job("rollback", "rollback", json!({"id": first_stamp}), RUN_TIMEOUT);
    assert_eq!(rb_res["ok"], true, "{rb_res}\n{}", app.log_since(m));
    let st = steps(&app.events_since(m));
    for s in ["restore:running", "restore:ok", "runner:running", "run:reconfigure:ok", "run:nginx:ok", "run:ui:ok", "runner:ok"] {
        assert!(st.contains(&s.to_string()), "missing step {s}: {st:?}");
    }
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(r.served_fp(), start_fp, "serving the starting certificate again");
    assert_eq!(r.sudo(&format!("cat {MORPHEUS_RB}")), planted_rb(), "morpheus.rb as it was");
    let al = r.aliases();
    for a in &aliases {
        assert!(!al.contains(a), "{a} still in the keystore: {al:?}");
        assert_eq!(r.sudo_rc(&format!("test -e {TRUST_DIR}/{a}.pem")).0, 1, "{a}.pem still there");
    }
    assert_eq!(r.stat(rb_res["saved_current"].as_str().unwrap()), "700 root:root");
    // /etc/morpheus/ssl is exactly the backup's again (0.3.19): the installed .crt/.key are gone
    // (the key shredded), the earlier files untouched, and the ledger no longer lists them.
    for f in [CRT, KEY] { assert_eq!(r.sudo_rc(&format!("test -e {f}")).0, 1, "{f} still there after the rollback"); }
    assert!(app.log_since(m).contains(&format!("shredded {KEY}")), "{}", app.log_since(m));
    assert_eq!(r.sudo(&format!("sha256sum {START_CRT} {START_KEY}")), start_files, "the earlier files are untouched");
    assert_eq!(r.stat(mci_core::appliance::LEDGER), "600 root:root");
    let ledger = r.sudo(&format!("cat {}", mci_core::appliance::LEDGER));
    assert!(!ledger.contains(CRT) && !ledger.contains(KEY), "{ledger}");
    say(&format!("rollback {}: starting certificate served again, CA aliases and PEMs removed, installed .crt/.key gone (key shredded), the earlier files untouched", rb_res["run_id"]));

    if full {
        // ---- the morpheus.rb guard: refused, nothing written to morpheus.rb
        let backups_before = app.ok("backups", json!({}))["backups"].as_array().unwrap().len();
        let bad = "nginx['ssl_certificate'] = '/etc/morpheus/ssl/x.crt'\n";
        // (a) at plan time
        r.put(MORPHEUS_RB, bad.as_bytes(), "0600");
        app.job("preflight", "preflight", json!({}), Duration::from_secs(120));
        let e = app.call("plan", json!({"server": true, "trust": true})).unwrap_err();
        assert!(e.contains("no appliance_url line") && e.contains("Nothing was changed"), "{e}");
        assert_eq!(app.ok("backups", json!({}))["backups"].as_array().unwrap().len(), backups_before, "no backup was taken");
        assert_eq!(r.sudo(&format!("cat {MORPHEUS_RB}")), bad);
        // (b) at apply time: morpheus.rb lost its appliance_url after the plan
        r.put(MORPHEUS_RB, planted_rb().as_bytes(), "0600");
        app.job("preflight", "preflight", json!({}), Duration::from_secs(120));
        let p = app.ok("plan", json!({"server": true, "trust": true}));
        r.put(MORPHEUS_RB, bad.as_bytes(), "0600");
        let files_before = r.sudo(&format!("stat -c '%n %Y %s' {CRT} {KEY} 2>/dev/null; true"));
        let m = app.mark();
        assert_eq!(app.ok("apply", json!({"confirm": p["stamp"]})), json!({"ok": true}));
        let e = app.wait_job("apply", m, RUN_TIMEOUT);
        assert_eq!(e["status"], "error");
        assert!(e["error"].as_str().unwrap().contains("no appliance_url line"), "{e}");
        assert!(steps(&app.events_since(m)).contains(&"rb:fail".to_string()));
        assert_eq!(r.sudo(&format!("cat {MORPHEUS_RB}")), bad, "morpheus.rb not written");
        assert_eq!(r.sudo_rc(&format!("test -e {LOG_DIR}/{}.log", p["stamp"].as_str().unwrap())).0, 1, "no runner started");
        assert_eq!(r.served_fp(), start_fp, "nginx untouched");
        // Refused before anything was written (divergence 19, 0.3.16): no backup, no certificate or key.
        assert_eq!(app.ok("backups", json!({}))["backups"].as_array().unwrap().len(), backups_before, "no backup was taken");
        assert_eq!(r.sudo_rc(&format!("test -e {BACKUP_DIR}/{}", p["stamp"].as_str().unwrap())).0, 1);
        assert_eq!(r.sudo(&format!("stat -c '%n %Y %s' {CRT} {KEY} 2>/dev/null; true")), files_before, "the .crt/.key were written");
        assert!(!steps(&app.events_since(m)).iter().any(|s| s.starts_with("backup:")), "the backup step started");
        r.put(MORPHEUS_RB, planted_rb().as_bytes(), "0600");
        say("guard: plan refused a morpheus.rb without appliance_url; apply refused one that lost it after the plan, before writing anything (no backup, no .crt/.key, no morpheus.rb)");
    }

    app.ok("disconnect", json!({}));
    rt_close(r);
    let _ = std::fs::remove_dir_all(&out);
    let _ = std::fs::remove_dir_all(&app.data_dir);
    say("done");
}

/// Everything under the paths cleanup could reach, and their parents' entries, as a sorted list.
fn listing(r: &Ref, home: &str) -> std::collections::BTreeSet<String> {
    r.sudo(&format!("find {STATE_DIR} {LOG_DIR} /etc/morpheus {home} -xdev 2>/dev/null; ls -1d /var/lib/* /var/log/* 2>/dev/null; true"))
        .lines().map(String::from).collect()
}

/// "Clean up this appliance" over SSH (0.3.17): two installs leave runs, logs and backups; a
/// staging dir is planted. Defaults remove scripts, logs, the staging dir and every backup but the
/// newest; then "all backups". Listings before and after prove only our own paths went, and the
/// backups' private keys were shredded.
#[test]
#[ignore = "needs the fake appliance: MCI_TEST_SSH=host:port:user:password"]
fn cleanup_end_to_end() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|p| p.into_inner());
    let Some(tg) = common::ssh_target() else { eprintln!("MCI_TEST_SSH not set"); return };
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    let t = rt.block_on(common::ssh_reference(&tg));
    let r = Ref { rt, t };
    let home = format!("/home/{}", tg.user);
    let stage = format!("{home}/{}", mci_core::appliance::CHARON_STAGE);

    // ---- set up: the starting state, two installs, a staging dir with a file in it
    r.put(MORPHEUS_RB, planted_rb().as_bytes(), "0600");
    r.sudo(&format!("rm -f /etc/morpheus/ssl/trusted_certs/mci-*.pem {TEST_INSTALLED}; touch /var/lib/fake-morpheus/keytool-aliases; sed -i '/^mci-/d' /var/lib/fake-morpheus/keytool-aliases; morpheus-ctl restart nginx >/dev/null"));
    let app = App::new("e2e-cleanup", None);
    connect(&app, &tg, None);
    app.job("preflight", "preflight", json!({}), Duration::from_secs(120));
    // The first install for the leaf's IP SAN (files 10_0_0_5.*), the second for m.cust.test: so the
    // ledger then lists files morpheus.rb no longer names.
    for fqdn in ["10.0.0.5", ""] {
        app.ok("clear_files", json!({}));
        app.ok("analyze", json!({"files": [corpus_file("chain.p7b"), corpus_file("leaf-pkcs1.key")], "fqdn": fqdn}));
        let p = app.ok("plan", json!({"server": true, "trust": false, "restart_ui": false}));
        let res = app.job("apply", "apply", json!({"confirm": p["stamp"]}), RUN_TIMEOUT);
        assert_eq!(res["ok"], true, "{res}");
        std::thread::sleep(Duration::from_secs(1)); // distinct stamps
    }
    let (rc, _) = r.rt.block_on(r.t.run(&format!("umask 077; mkdir -p {stage} && printf 'staged copy' > {stage}/mci-staged-test"), false, None, 30)).unwrap();
    assert_eq!(rc, 0);
    let before = listing(&r, &home);

    // ---- what the tool left
    let l = app.ok("cleanup_list", json!({}));
    let items = l["items"].as_array().unwrap().clone();
    let count = |k: &str| items.iter().filter(|e| e["kind"] == k).count();
    assert!(count("script") >= 2 && count("log") >= 4 && count("backup") >= 2 && count("stage") == 1, "{l}");
    assert_eq!(l["defaults"], json!({"runs": true, "stage": true, "old_backups": true, "all_backups": false, "unused_installed": false}));
    let installed: Vec<(String, bool)> = items.iter().filter(|e| e["kind"] == "installed")
        .map(|e| (e["path"].as_str().unwrap().to_string(), e["in_use"] == true)).collect();
    assert_eq!(installed.len(), 4, "{installed:?}");
    assert!(installed.iter().all(|(p, used)| *used == p.contains("m_cust_test")), "m_cust_test in use, 10_0_0_5 not: {installed:?}");
    let newest = l["newest_backup"].as_str().unwrap().to_string();
    say(&format!("cleanup list: {} scripts, {} logs, {} backups, the staging dir; newest backup {newest}", count("script"), count("log"), count("backup")));

    // ---- defaults: everything but the newest backup
    let p = app.ok("cleanup_plan", json!({"runs": true, "stage": true, "old_backups": true, "all_backups": false}));
    assert!(p.get("warning").is_none());
    let removed: Vec<String> = p["remove"].as_array().unwrap().iter().map(|e| e["path"].as_str().unwrap().to_string()).collect();
    assert!(!removed.iter().any(|x| x.ends_with(&newest)), "the newest backup stays");
    let keys: Vec<String> = removed.iter().filter(|x| x.starts_with(BACKUP_DIR))
        .flat_map(|b| r.sudo(&format!("find {b} -type f -name '*.key'")).lines().map(String::from).collect::<Vec<_>>()).collect();
    assert!(!keys.is_empty(), "the removed backups hold keys");
    assert_eq!(app.call("cleanup", json!({"confirm": "wrong"})).unwrap_err(), "The list changed; review it again.");
    let m = app.mark();
    let res = app.job("cleanup", "cleanup", json!({"confirm": p["token"]}), Duration::from_secs(300));
    assert_eq!(res["ok"], true, "{res}
{}", app.log_since(m));
    let text = app.log_since(m);
    for k in &keys {
        assert!(text.contains(&format!("shredded {k}")), "{k} wasn't shredded:
{text}");
        assert_eq!(r.sudo_rc(&format!("test -e {k}")).0, 1, "{k} still there");
    }
    let after = listing(&r, &home);
    let gone: Vec<&String> = before.difference(&after).collect();
    let added: Vec<&String> = after.difference(&before).collect();
    let ours = |x: &str| removed.iter().any(|rm| x == rm || x.starts_with(&format!("{rm}/")))
        || [format!("{RUN_DIR}"), format!("{LOG_DIR}")].contains(&x.to_string()); // emptied dirs may go too
    assert!(gone.iter().all(|x| ours(x)), "something else went: {:?}", gone.iter().filter(|x| !ours(x)).collect::<Vec<_>>());
    assert!(added.is_empty(), "something appeared: {added:?}");
    assert!(removed.iter().all(|x| !after.contains(x)), "everything planned went");
    assert!(after.contains(&format!("{BACKUP_DIR}/{newest}")), "the newest backup stays");
    assert!(after.contains(IP_CRT) && after.contains(IP_KEY), "unused installed files stay unless asked (default off)");
    say(&format!("cleanup (defaults): {} paths removed, {} keys shredded, nothing else changed; {newest} kept", gone.len(), keys.len()));

    // ---- all backups: the warning, then nothing of ours left but the newest's removal
    let p = app.ok("cleanup_plan", json!({"runs": true, "stage": true, "old_backups": true, "all_backups": true, "unused_installed": true}));
    assert!(p["warning"].as_str().unwrap().contains("rollback becomes impossible"), "{p}");
    let before = after;
    let m = app.mark();
    let res = app.job("cleanup", "cleanup", json!({"confirm": p["token"]}), Duration::from_secs(300));
    assert_eq!(res["ok"], true, "{res}");
    let text = app.log_since(m);
    assert!(text.contains(&format!("shredded {IP_KEY}")) && text.contains(&format!("removed {IP_CRT}")), "{text}");
    assert!(!text.contains("usual lecture"), "stdout only on success: {text}");
    let after = listing(&r, &home);
    let gone: Vec<&String> = before.difference(&after).collect();
    assert!(gone.iter().all(|x| x.starts_with(STATE_DIR) || x.starts_with(LOG_DIR) || *x == IP_CRT || *x == IP_KEY), "{gone:?}");
    assert!(!after.iter().any(|x| x.starts_with(&format!("{BACKUP_DIR}/"))), "no backups left");
    assert!(after.contains(CRT) && after.contains(KEY), "the files morpheus.rb names stay");
    assert!(after.contains(START_CRT) && after.contains(START_KEY), "files the ledger doesn't list are never touched");
    assert_eq!(app.ok("cleanup_list", json!({}))["items"].as_array().unwrap().iter().filter(|e| e["kind"] != "log" && e["kind"] != "installed").count(), 0);
    assert!(app.call("cleanup_plan", json!({"runs": false, "stage": false, "old_backups": false, "all_backups": true})).unwrap_err().starts_with("Nothing to remove"));
    say("cleanup (all backups): warned, every backup gone, nothing outside our paths touched");

    // ---- leave the appliance in its starting state; then m_cust_test.* are no longer named, and
    // "unused installed files" alone removes them, keys shredded.
    r.put(MORPHEUS_RB, planted_rb().as_bytes(), "0600");
    r.sudo("morpheus-ctl restart nginx >/dev/null");
    let p = app.ok("cleanup_plan", json!({"runs": false, "stage": false, "old_backups": false, "all_backups": false, "unused_installed": true}));
    let paths: Vec<&str> = p["remove"].as_array().unwrap().iter().map(|e| e["path"].as_str().unwrap()).collect();
    assert_eq!(paths, [CRT, KEY], "{p}");
    let m = app.mark();
    app.job("cleanup", "cleanup", json!({"confirm": p["token"]}), Duration::from_secs(120));
    assert!(app.log_since(m).contains(&format!("shredded {KEY}")));
    for f in [CRT, KEY] { assert_eq!(r.sudo_rc(&format!("test -e {f}")).0, 1, "{f}"); }
    assert!(!r.sudo(&format!("cat {}", mci_core::appliance::LEDGER)).contains("/etc/morpheus/ssl/"), "the ledger is empty again");
    say("cleanup (unused installed files): 10_0_0_5.* and later m_cust_test.* shredded/removed once morpheus.rb stopped naming them; the starting files untouched");
    app.ok("disconnect", json!({}));
    rt_close(r);
    say("done");
}

fn rt_close(r: Ref) {
    let Ref { rt, t } = r;
    rt.block_on(t.close());
}
