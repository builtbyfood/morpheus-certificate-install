//! morpheus-certificate-install 0.4.0 — the steps both Charon-transport tests run (mock and live).
//!
//! `t` is the Charon transport under test. `reference` is the SSH transport (an exec channel: no
//! terminal in the way) to the same appliance, used for the "exact bytes" comparison. `password`
//! is mcitest's sudo password on the fake appliance, for the leak grep.

use mci_app::transport::Transport;
use mci_core::appliance;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::watch;

pub const TEST_DIR: &str = "/var/lib/morpheus-certificate-install/r6-test";
pub const LOG_DIR: &str = "/var/log/morpheus-certificate-install";
const PATTERN: &str = "/root/mci-r6-leak-pattern";

async fn data(t: &dyn Transport, cmd: &str, sudo: bool) -> String {
    let r = t.run_data(cmd, sudo, None, 60).await.unwrap_or_else(|e| panic!("{cmd}: {e}"));
    assert_eq!(r.rc, 0, "{cmd}: {}", r.complaint(400));
    r.stdout
}

pub async fn exercise(t: &dyn Transport, reference: &dyn Transport, password: &str) {
    // ---- sudo: mcitest needs a password, so Charon answers it (mode "charon"), not NOPASSWD.
    eprintln!("[charon] {} — user {}, sudo {}", t.label(), t.login_user(), t.info()["sudo_mode"]);
    assert_eq!(t.login_user(), "mcitest");
    assert_eq!(t.info()["sudo_mode"], "charon", "{}", t.info());
    assert_eq!(data(t, "id -un", true).await, "root\n");

    // ---- run_data returns exact bytes; run_command's own output is a terminal's.
    // `sudo -k` first, so this read's sudo really prompts (the fake appliance has lecture=always):
    // the prompt and the lecture are on the terminal, and must stay outside the data.
    data(t, "sudo -k", false).await;
    let via_charon = data(t, &appliance::cat_morpheus_rb(), true).await;
    let r = reference.run_data(&appliance::cat_morpheus_rb(), true, None, 60).await.unwrap();
    assert_eq!(r.rc, 0);
    assert_eq!(via_charon.as_bytes(), r.stdout.as_bytes(), "morpheus.rb through Charon == through an exec channel, byte for byte");
    assert!(via_charon.starts_with("appliance_url "), "{via_charon:?}");
    data(t, "sudo -k", false).await;
    let (rc, shown) = t.run(&appliance::cat_morpheus_rb(), true, None, 60).await.unwrap();
    assert_eq!(rc, 0);
    assert!(!shown.contains('\r'), "run (display) has CR stripped");
    eprintln!("[charon] run (display) of the same read is {} bytes vs {} of data; it {} the sudo lecture",
              shown.len(), via_charon.len(), if shown.contains("usual lecture") { "includes" } else { "doesn't include" });
    // Tricky bytes survive: CRLF, tabs, trailing spaces, no final newline, UTF-8, a NUL-free binary-ish mix.
    let tricky = b"line1\r\n\tindented  \r\nZo\xc3\xab \xe2\x86\x92 ok\nno newline at end ";
    data(t, &format!("rm -rf {TEST_DIR}"), true).await;
    t.put_root(&format!("{TEST_DIR}/tricky.txt"), tricky, "0600", "0700").await.unwrap();
    assert_eq!(data(t, &format!("cat {TEST_DIR}/tricky.txt"), true).await.as_bytes(), tricky);
    // stderr and rc come through separately.
    let e = t.run_data("echo out; echo err >&2; exit 4", false, None, 60).await.unwrap();
    assert_eq!((e.rc, e.stdout.as_str(), e.stderr.as_str()), (4, "out\n", "err\n"));

    // ---- put_root: root-owned, the modes asked for; nothing left in the staging dir.
    // What's in the staging dir besides this read's own stderr file (a framed read's stderr goes to
    // `mci-err-<nonce>` there until it exits). Anything else left behind is a leak.
    let stage_ls = || async {
        let all = data(t, "ls -A \"$HOME/.morpheus-certificate-install-stage\"", false).await;
        let errs = all.lines().filter(|l| l.starts_with("mci-err-")).count();
        assert_eq!(errs, 1, "exactly one stderr file — this read's own: {all:?}");
        all.lines().filter(|l| !l.starts_with("mci-err-")).map(|l| format!("{l}\n")).collect::<String>()
    };
    t.put_root(&format!("{TEST_DIR}/sub/ca.pem"), b"-----BEGIN CERTIFICATE-----\nr6\n-----END CERTIFICATE-----\n", "0644", "0755").await.unwrap();
    assert_eq!(data(t, &format!("stat -c '%a %U:%G' {TEST_DIR}/sub/ca.pem"), true).await, "644 root:root\n");
    assert_eq!(data(t, &format!("stat -c '%a %U:%G' {TEST_DIR}/sub"), true).await, "755 root:root\n");
    assert_eq!(data(t, &format!("stat -c '%a %U:%G' {TEST_DIR}/tricky.txt"), true).await, "600 root:root\n");
    assert_eq!(stage_ls().await, "", "staged copies and stderr files are all gone");
    assert_eq!(data(t, "stat -c %a \"$HOME/.morpheus-certificate-install-stage\"", false).await, "700\n");
    // The install step fails (the parent is a file) — the staged copy is shredded anyway.
    let err = t.put_root("/etc/morpheus/morpheus.rb/not-a-dir/x.pem", b"never installed", "0644", "0755").await.unwrap_err().to_string();
    assert!(err.contains("install /etc/morpheus/morpheus.rb/not-a-dir/x.pem failed"), "{err}");
    assert_eq!(stage_ls().await, "", "the staged copy was shredded although the install failed");

    // ---- follow a runner to its rc (polls are framed data reads).
    let (log, rcf) = (format!("{LOG_DIR}/r6-test.log"), format!("{LOG_DIR}/r6-test.rc"));
    // install -d sets the mode on an existing dir too: the follow below reads as the session user.
    data(t, &format!("install -d -m 0755 {LOG_DIR} && rm -f {log} {rcf}"), true).await;
    data(t, &format!("setsid nohup bash -c 'for i in 1 2 3; do echo \"charon line $i\" >> {log}; sleep 1; done; echo 5 > {rcf}' >/dev/null 2>&1 < /dev/null & echo started"), true).await;
    let seen = Arc::new(Mutex::new(String::new()));
    let s2 = seen.clone();
    let (_keep, stop) = watch::channel(false);
    let started = Instant::now();
    let rc = tokio::time::timeout(Duration::from_secs(90), t.follow(&log, &rcf, &move |s: String| s2.lock().unwrap().push_str(&s), stop))
        .await.expect("follow ended").unwrap();
    assert_eq!(rc, Some(5));
    let text = seen.lock().unwrap().clone();
    assert_eq!(text, "charon line 1\ncharon line 2\ncharon line 3\n", "exactly the log, nothing from the terminal");
    eprintln!("[charon] follow: {} bytes to rc 5 in {:?}", text.len(), started.elapsed());

    // ---- the password-leak grep, with a planted copy to prove it can find one. The pattern is a
    // root-only file outside the searched dirs (Charon has no stdin, and a command line would put
    // the password into Charon's history); it is shredded afterwards.
    t.put_root(PATTERN, format!("{password}\n").as_bytes(), "0600", "0700").await.unwrap();
    let grep = |dirs: String| async move {
        t.run_data(&format!("grep -r -l -F -s -f {PATTERN} {dirs}"), true, None, 120).await.unwrap()
    };
    let r = grep(format!("/etc/morpheus /var/lib/morpheus-certificate-install {LOG_DIR}")).await;
    assert_eq!((r.rc, r.stdout.as_str()), (1, ""), "the sudo password was found in: {}", r.stdout);
    t.put_root(&format!("{TEST_DIR}/canary"), format!("x{password}x\n").as_bytes(), "0600", "0700").await.unwrap();
    let r = grep(TEST_DIR.to_string()).await;
    assert_eq!((r.rc, r.stdout.trim().to_string()), (0, format!("{TEST_DIR}/canary")), "the leak check must find a planted copy");
    eprintln!("[charon] leak grep: no hits; planted copy found");

    // ---- cleanup
    data(t, &format!("rm -rf {TEST_DIR} {log} {rcf}; {}", appliance::shred(PATTERN)), true).await;
    assert_eq!(stage_ls().await, "");
}
