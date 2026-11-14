//! morpheus-certificate-install 0.4.2 — the SSH transport against the fake appliance (R5).
//!
//! Ignored unless asked for, because it needs a live host:
//!   MCI_TEST_SSH=host:port:user:password cargo test -p morpheus-certificate-install --test ssh_fake_appliance -- --ignored --nocapture
//! The fake appliance is tests/fake-appliance (user mcitest / hunter2, sudo asks for the password):
//! normally an Ubuntu VM (24.04 or 26.04; 26.04's sudo-rs prints no lecture) set up by install-on-vm.sh (real systemd, so a runner goes through
//! systemd-run); on a host without systemd, also set MCI_TEST_NO_SYSTEMD=1.
//! docs/FAKE-APPLIANCE.md.
//!
//! Two tests: the main one below, and `rotated_host_key_is_refused`, which rotates the fake's host
//! keys for good and so runs only with MCI_TEST_ROTATE=1.
//!
//! Covers the SSH transport's definition of done — connect with the TOFU round trip, password sudo
//! detected, put_root, a sudo command, follow a run to its rc — plus the password-leak check the
//! Python e2e test did: afterwards nothing under /etc/morpheus, /var/lib/morpheus-certificate-install
//! or /var/log/morpheus-certificate-install contains the sudo password.
//!
//! Test-only shell text lives here (runner stand-ins, stat, cleanup); the app's own commands come
//! from mci_core::appliance, as everywhere else.

use mci_app::transport::ssh::{connect, SshParams};
use mci_app::transport::{Transport, TransportError};
use mci_core::appliance::SudoMode;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::watch;

struct Target { host: String, port: u16, user: String, password: String }

fn target() -> Option<Target> {
    let v = std::env::var("MCI_TEST_SSH").ok()?;
    let mut it = v.splitn(4, ':');
    Some(Target {
        host: it.next()?.to_string(),
        port: it.next()?.parse().ok()?,
        user: it.next()?.to_string(),
        password: it.next()?.to_string(),
    })
}

fn params(t: &Target, known_hosts: &std::path::Path, trust: &str) -> SshParams {
    SshParams {
        host: t.host.clone(),
        port: t.port,
        user: t.user.clone(),
        password: t.password.clone(),
        key_path: String::new(),
        key_passphrase: String::new(),
        sudo_password: String::new(), // defaults to the login password, as in the app
        trust_fingerprint: trust.to_string(),
        known_hosts: known_hosts.to_path_buf(),
    }
}

const TEST_DIR: &str = "/var/lib/morpheus-certificate-install/r5-test";
const LOG_DIR: &str = "/var/log/morpheus-certificate-install";
const CERT: &str = "/etc/morpheus/ssl/trusted_certs/mci-r5-test.pem";

/// A sudo data read: stdout only (the fake appliance prints sudo's lecture on stderr every time).
async fn sudo_out(t: &dyn Transport, cmd: &str) -> String {
    let r = t.run_data(cmd, true, None, 30).await.unwrap();
    assert_eq!(r.rc, 0, "{cmd}: {}", r.complaint(400));
    r.stdout.trim().to_string()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs MCI_TEST_SSH=host:port:user:password (the fake appliance)"]
async fn ssh_transport_against_the_fake_appliance() {
    let Some(tg) = target() else {
        eprintln!("MCI_TEST_SSH not set; nothing to do");
        return;
    };
    let dir = std::env::temp_dir().join(format!("mci-r5-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let kh = dir.join("known_hosts");

    // ---- 1. First contact: an unknown key is a HostKey error carrying its fingerprint, nothing is saved.
    let fp = match connect(params(&tg, &kh, "")).await {
        Err(TransportError::HostKey { fingerprint, mismatch: false, key_type, .. }) => {
            assert!(fingerprint.starts_with("SHA256:"), "{fingerprint}");
            eprintln!("host key: {key_type} {fingerprint}");
            fingerprint
        }
        Err(e) => panic!("expected an unknown-host-key prompt, got: {e}"),
        Ok(_) => panic!("connected to an unknown host without confirming its key"),
    };
    assert!(!kh.exists() || std::fs::read_to_string(&kh).unwrap().lines().all(|l| l.starts_with('#')), "nothing trusted yet");
    // A wrong confirmation doesn't trust it either.
    assert!(matches!(connect(params(&tg, &kh, "SHA256:not-this-one")).await, Err(TransportError::HostKey { mismatch: false, .. })));

    // ---- 2. Confirmed: connects, saves the key; the next connect needs no confirmation.
    let t = connect(params(&tg, &kh, &fp)).await.expect("connect with the confirmed fingerprint");
    assert!(std::fs::read_to_string(&kh).unwrap().contains("ssh-"), "key saved to our known_hosts");
    t.close().await;
    let t: Arc<dyn Transport> = Arc::from(connect(params(&tg, &kh, "")).await.expect("known host, no prompt"));
    assert_eq!(t.info()["fingerprint"], fp.as_str());

    // ---- 3. Password sudo detected (mcitest needs a password for sudo on the fake appliance).
    assert_eq!(t.sudo_mode(), SudoMode::Password, "{}", t.info());
    assert_eq!(t.info()["sudo_mode"], "password");

    // ---- 4. A sudo command runs as root. The fake keeps sudo's lecture on for every prompt
    // (Defaults lecture=always): `run` shows it with the output, `run_data` returns stdout only.
    assert_eq!(sudo_out(&*t, "id -un").await, "root");
    let (rc, merged) = t.run("id -un", true, None, 30).await.unwrap();
    assert_eq!(rc, 0);
    let d = t.run_data("id -un", true, None, 30).await.unwrap();
    assert_eq!(d.stdout, "root\n", "run_data returns stdout only");
    // Merged = both streams. What sudo puts on stderr depends on the implementation: classic sudo
    // with lecture=always prints the lecture; sudo-rs (Ubuntu 26.04's default) prints no lecture,
    // only a newline after reading the password. Either way it must not reach run_data's stdout.
    assert_eq!(merged.len(), d.stdout.len() + d.stderr.len(), "merged {merged:?} vs stdout {:?} + stderr {:?}", d.stdout, d.stderr);
    assert!(merged.trim_end().ends_with("root"), "merged output: {merged:?}");
    eprintln!("sudo stderr on this appliance: {:?} ({})", d.stderr,
        if d.stderr.contains("usual lecture") { "classic sudo, lecture on" } else { "no lecture: sudo-rs, or lecture off" });
    // A command that reads stdin gets end-of-input instead of hanging.
    let started = Instant::now();
    let (rc, out) = t.run("cat; echo done", false, None, 20).await.unwrap();
    assert_eq!((rc, out.trim()), (0, "done"));
    assert!(started.elapsed() < Duration::from_secs(10));

    // ---- 5. put_root: root-owned, the asked-for modes, the parent created with dir_mode.
    sudo_out(&*t, &format!("rm -rf {TEST_DIR} {CERT}")).await;
    t.put_root(&format!("{TEST_DIR}/secret.key"), b"not really a key\n", "0600", "0700").await.unwrap();
    t.put_root(CERT, b"-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n", "0644", "0755").await.unwrap();
    assert_eq!(sudo_out(&*t, &format!("stat -c '%a %U:%G' {TEST_DIR}/secret.key")).await, "600 root:root");
    assert_eq!(sudo_out(&*t, &format!("stat -c '%a %U:%G' {TEST_DIR}")).await, "700 root:root");
    assert_eq!(sudo_out(&*t, &format!("stat -c '%a %U:%G' {CERT}")).await, "644 root:root");
    assert_eq!(sudo_out(&*t, &format!("cat {TEST_DIR}/secret.key")).await, "not really a key");
    // No temp file left behind.
    assert_eq!(sudo_out(&*t, &format!("ls -A {TEST_DIR}")).await, "secret.key");

    // ---- 6. Follow a run to its rc. A stand-in runner appends lines, then writes the rc file.
    let (log, rc_file) = (format!("{LOG_DIR}/r5-test.log"), format!("{LOG_DIR}/r5-test.rc"));
    sudo_out(&*t, &format!("mkdir -p {LOG_DIR} && rm -f {log} {rc_file}")).await;
    sudo_out(&*t, &format!(
        "setsid nohup bash -c 'for i in 1 2 3; do echo \"run line $i\" >> {log}; sleep 1; done; echo 7 > {rc_file}' >/dev/null 2>&1 < /dev/null & echo started")).await;
    let seen = Arc::new(Mutex::new(String::new()));
    let s2 = seen.clone();
    let (_tx, stop) = watch::channel(false);
    let rc = tokio::time::timeout(Duration::from_secs(60), t.follow(&log, &rc_file, &move |s: String| s2.lock().unwrap().push_str(&s), stop))
        .await.expect("follow ended").unwrap();
    assert_eq!(rc, Some(7));
    let text = seen.lock().unwrap().clone();
    assert!(text.contains("run line 1") && text.contains("run line 3"), "{text}");
    assert!(!text.contains("@@RC="), "the marker isn't shown: {text}");

    // Stop: follow returns None promptly and the run carries on to its rc on the appliance.
    sudo_out(&*t, &format!("rm -f {log} {rc_file}")).await;
    sudo_out(&*t, &format!(
        "setsid nohup bash -c 'echo slow >> {log}; sleep 6; echo 3 > {rc_file}' >/dev/null 2>&1 < /dev/null & echo started")).await;
    let (tx, stop) = watch::channel(false);
    tokio::spawn(async move { tokio::time::sleep(Duration::from_secs(2)).await; let _ = tx.send(true); });
    let started = Instant::now();
    let rc = t.follow(&log, &rc_file, &|_s: String| {}, stop).await.unwrap();
    assert_eq!(rc, None, "stopped");
    assert!(started.elapsed() < Duration::from_secs(5), "stop is prompt: {:?}", started.elapsed());
    tokio::time::sleep(Duration::from_secs(7)).await;
    assert_eq!(sudo_out(&*t, &format!("cat {rc_file}")).await, "3", "the run finished without us");

    // ---- 6b. systemd: the VM fake has real systemd, so preflight says SYSTEMDRUN=yes and a runner
    // goes through `systemd-run --collect` (appliance::launch_runner). Set MCI_TEST_NO_SYSTEMD=1
    // on a host without systemd.
    let facts = mci_app::reads::preflight(&*t).await.expect("preflight");
    let want_systemd = std::env::var("MCI_TEST_NO_SYSTEMD").map(|v| v != "1").unwrap_or(true);
    assert_eq!(facts.get("systemdrun").map(String::as_str), Some(if want_systemd { "yes" } else { "no" }), "preflight facts: {facts:?}");
    assert_eq!(facts.get("rb").map(String::as_str), Some("yes"));
    if want_systemd {
        let run_id = "r5-systemd-test";
        let unit = format!("{}-{run_id}.service", mci_core::SLUG);
        let (script, slog, src) = mci_core::appliance::run_paths(run_id);
        sudo_out(&*t, &format!("rm -f {slog} {src}")).await;
        // A stand-in runner. $INVOCATION_ID is set only for a process systemd started as a unit.
        let body = format!(
            "#!/bin/bash\necho \"invocation=${{INVOCATION_ID:-none}}\" >> {slog}\nfor i in 1 2 3; do echo \"systemd line $i\" >> {slog}; sleep 1; done\necho 0 > {src}\n");
        t.put_root(&script, body.as_bytes(), "0700", "0700").await.unwrap();
        let (rc, out) = t.run(&mci_core::appliance::launch_runner(run_id, &script, true), true, None, 30).await.unwrap();
        assert_eq!(rc, 0, "systemd-run: {out}");
        let seen = Arc::new(Mutex::new(String::new()));
        let s3 = seen.clone();
        let (_tx, stop) = watch::channel(false);
        let rc = tokio::time::timeout(Duration::from_secs(60), t.follow(&slog, &src, &move |s: String| s3.lock().unwrap().push_str(&s), stop))
            .await.expect("follow ended").unwrap();
        assert_eq!(rc, Some(0));
        let text = seen.lock().unwrap().clone();
        assert!(text.contains("systemd line 3"), "{text}");
        assert!(text.contains("invocation=") && !text.contains("invocation=none"), "not started by systemd: {text}");
        // --collect: once the script has exited, systemd unloads the unit.
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let st = t.run_data(&format!("systemctl show -p LoadState --value {unit}"), false, None, 30).await.unwrap();
            if st.stdout.trim() == "not-found" { break; }
            assert!(Instant::now() < deadline, "unit {unit} still loaded: {}", st.stdout.trim());
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        eprintln!("systemd-run runner: followed to rc 0, unit {unit} gone");
        sudo_out(&*t, &format!("rm -f {script} {slog} {src}")).await;
    }

    // A timeout is an error, and the transport is still usable after it.
    let e = t.run("sleep 20", false, None, 2).await.unwrap_err().to_string();
    assert!(e.contains("timed out after 2s"), "{e}");
    assert_eq!(sudo_out(&*t, "id -un").await, "root");

    // ---- 7. Shell on demand; closing it leaves the connection up; it can be reopened.
    for round in 0..2 {
        let got = Arc::new(Mutex::new(Vec::<u8>::new()));
        let g2 = got.clone();
        t.shell_open(80, 24, Box::new(move |d| g2.lock().unwrap().extend(d)), Box::new(|| {})).await.unwrap();
        t.shell_input(format!("echo shell-{round}-ok\n").as_bytes()).await.unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !String::from_utf8_lossy(&got.lock().unwrap()).contains(&format!("shell-{round}-ok\r\n")) {
            assert!(Instant::now() < deadline, "no shell output: {}", String::from_utf8_lossy(&got.lock().unwrap()));
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        t.shell_resize(120, 40).await.unwrap();
        t.shell_input(b"exit\n").await.unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(sudo_out(&*t, "id -un").await, "root", "connection survives the shell");
    }

    // ---- 7b. The keytool stand-in keeps a keystore's state (docs/FAKE-APPLIANCE.md).
    let kt = "/opt/morpheus/embedded/java/bin/keytool";
    let ks = "-keystore /opt/morpheus/embedded/java/lib/security/cacerts -storepass changeit";
    let ktool = |args: String| { let t = t.clone(); async move { t.run_data(&args, true, None, 30).await.unwrap().rc } };
    let _ = ktool(format!("{kt} -delete -alias mci-r5-test {ks}")).await;
    assert_eq!(ktool(format!("{kt} -delete -alias mci-r5-test {ks}")).await, 1, "delete of an absent alias fails");
    assert_eq!(ktool(format!("{kt} -importcert -noprompt -trustcacerts -alias mci-r5-test -file {CERT} {ks}")).await, 0);
    assert_eq!(ktool(format!("{kt} -importcert -noprompt -trustcacerts -alias mci-r5-test -file {CERT} {ks}")).await, 1, "import over an existing alias fails");
    assert_eq!(ktool(format!("{kt} -delete -alias mci-r5-test {ks}")).await, 0);

    // ---- 8. The password-leak check (the Python e2e test's grep), run with sudo. The password is
    // the grep *pattern*, read from stdin (-f -) after sudo has consumed its own line, so it is
    // never on a command line. Exit 1 with no output = no file contains it.
    let r = t.run_data(
        &format!("grep -r -l -F -s -f - /etc/morpheus /var/lib/morpheus-certificate-install {LOG_DIR}"),
        true, Some(format!("{}\n", tg.password).as_bytes()), 60).await.unwrap();
    assert_eq!((r.rc, r.stdout.trim()), (1, ""), "the sudo password was found on the appliance in: {}", r.stdout);
    // And the check can find it when it is there (so a silent grep isn't passing by accident).
    t.put_root(&format!("{TEST_DIR}/canary"), format!("x{}x\n", tg.password).as_bytes(), "0600", "0700").await.unwrap();
    let r = t.run_data(&format!("grep -r -l -F -s -f - {TEST_DIR}"), true, Some(format!("{}\n", tg.password).as_bytes()), 60).await.unwrap();
    assert_eq!((r.rc, r.stdout.trim().to_string()), (0, format!("{TEST_DIR}/canary")), "the leak check must detect a planted copy");

    // ---- cleanup
    sudo_out(&*t, &format!("rm -rf {TEST_DIR} {CERT} {log} {rc_file}")).await;
    t.close().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// A host whose key changed since we trusted it is refused with HostKey { mismatch: true }, and
/// confirming the new fingerprint doesn't override that. Rotates the fake appliance's host keys
/// (`sudo rotate-host-keys`, docs/FAKE-APPLIANCE.md) **for good**: the old key is deleted, so a
/// Charon session or an ssh known_hosts entry for the VM sees a changed key afterwards. So it runs
/// only with MCI_TEST_ROTATE=1, even when the test file runs unfiltered (0.3.16).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs MCI_TEST_SSH=host:port:user:password and MCI_TEST_ROTATE=1; changes the fake appliance's host key for good"]
async fn rotated_host_key_is_refused() {
    if std::env::var("MCI_TEST_ROTATE").as_deref() != Ok("1") {
        eprintln!("skipped: rotates the fake appliance's host key for good; set MCI_TEST_ROTATE=1 to run it");
        return;
    }
    let Some(tg) = target() else {
        eprintln!("MCI_TEST_SSH not set; nothing to do");
        return;
    };
    let dir = std::env::temp_dir().join(format!("mci-r5-rot-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let kh = dir.join("known_hosts");
    let old = match connect(params(&tg, &kh, "")).await {
        Err(TransportError::HostKey { fingerprint, .. }) => fingerprint,
        Err(e) => panic!("{e}"),
        Ok(_) => panic!("connected without a confirmation"),
    };
    let t = connect(params(&tg, &kh, &old)).await.expect("trusted the current key");
    let r = t.run_data("rotate-host-keys", true, None, 60).await.unwrap();
    assert_eq!(r.rc, 0, "rotate-host-keys: {}", r.complaint(400));
    t.close().await;

    // sshd restarts within a second or two; retry until it answers with the new key.
    let deadline = Instant::now() + Duration::from_secs(20);
    let (new_fp, key_type) = loop {
        match connect(params(&tg, &kh, "")).await {
            Err(TransportError::HostKey { fingerprint, key_type, mismatch: true, .. }) => break (fingerprint, key_type),
            Err(TransportError::HostKey { mismatch: false, .. }) => panic!("a changed key was treated as unknown"),
            Ok(_) => panic!("connected although the host key changed"),
            Err(e) if Instant::now() < deadline => {
                eprintln!("waiting for sshd: {e}");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(e) => panic!("sshd didn't come back: {e}"),
        }
    };
    assert_ne!(new_fp, old);
    eprintln!("changed key refused: {key_type} {new_fp} (was {old})");
    // Confirming the new fingerprint doesn't override a change: still refused, nothing learned.
    let before = std::fs::read_to_string(&kh).unwrap();
    assert!(matches!(connect(params(&tg, &kh, &new_fp)).await, Err(TransportError::HostKey { mismatch: true, .. })));
    assert_eq!(std::fs::read_to_string(&kh).unwrap(), before, "known_hosts untouched");
    let _ = std::fs::remove_dir_all(&dir);
}
