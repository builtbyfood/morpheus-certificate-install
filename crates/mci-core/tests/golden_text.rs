//! morpheus-certificate-install 0.4.0 — the ported text is byte-identical to the Python reference.
//! Goldens: fixtures/golden/ (regenerate with `python3 fixtures/make-cases.py`). Passes from day one.

use mci_core::appliance::{self as a, SudoMode};
use mci_core::export::{install_text, ExportInfo};
use mci_core::quote::q;
use mci_core::runner::{parse_marker, runner_script, Marker, Mode, RunnerPlan};
use mci_core::{morpheus_rb, VERSION};

// The bash tests below run appliance command lines locally. Appliances have GNU coreutils; macOS's BSD
// tools (stat -c, base64 -w, no timeout) behave differently, so the tests need GNU and skip without it
// (macOS, 0.4.0-rc2). Git Bash on Windows and Linux qualify.
const GNU_PROBE: &str = "base64 --version 2>/dev/null | grep -q 'GNU coreutils'";
const GNU_PROBE_TIMEOUT: &str = "base64 --version 2>/dev/null | grep -q 'GNU coreutils' && timeout --version && find --version && touch --version";
const GNU_PROBE_STAT: &str = "base64 --version 2>/dev/null | grep -q 'GNU coreutils' && stat --version 2>/dev/null | grep -q 'GNU coreutils'";
use std::path::PathBuf;

fn fx(p: &str) -> PathBuf { PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures").join(p) }
fn read(p: &str) -> String { std::fs::read_to_string(fx(p)).unwrap_or_else(|e| panic!("{p}: {e}")) }
fn json(p: &str) -> serde_json::Value { serde_json::from_str(&read(p)).unwrap() }
const STAMP: &str = "20261105-120000";

#[test]
fn morpheus_rb_transform() {
    for case in ["rb-fresh", "rb-existing-lines", "rb-own-block", "rb-legacy-sphragis-block"] {
        let input = read(&format!("golden/{case}.in.rb"));
        let want = read(&format!("golden/{case}.out.rb"));
        let got = morpheus_rb::transform(&input, "/etc/morpheus/ssl/m_cust_test.crt", "/etc/morpheus/ssl/m_cust_test.key", STAMP);
        assert_eq!(got, want, "{case}");
    }
    let cur = morpheus_rb::current_nginx_ssl(&read("golden/rb-existing-lines.out.rb"));
    assert_eq!(cur[0].1, "/etc/morpheus/ssl/m_cust_test.crt");
}

#[test]
fn runner_scripts() {
    let p = |server, trust, ui, aliases: &[&str]| RunnerPlan {
        server, trust, restart_ui: ui, storepass: "changeit".into(), aliases: aliases.iter().map(|s| s.to_string()).collect(),
    };
    let roots = ["mci-cust-root-0a1b2c3d", "mci-cust-issuing-4e5f6a7b"];
    let cases = [
        ("runner-apply-server", runner_script(STAMP, "mcitest", &p(true, false, false, &[]), Mode::Apply, &[])),
        ("runner-apply-server-trust", runner_script(STAMP, "mcitest", &p(true, true, true, &roots), Mode::Apply, &[])),
        ("runner-apply-trust-only", runner_script(STAMP, "mcitest", &p(false, true, true, &roots[..1]), Mode::Apply, &[])),
        ("runner-rollback", runner_script(STAMP, "mcitest", &p(true, false, true, &[]), Mode::Rollback, &["mci-cust-root-0a1b2c3d".to_string()])),
    ];
    for (name, got) in cases {
        let want = read(&format!("golden/{name}.sh")).replace("{VERSION}", VERSION);
        assert_eq!(got, want, "{name}");
    }
}

#[test]
fn apply_sequence_commands() {
    let seq = json("golden/apply-command-sequence.json");
    let runs: Vec<String> = seq["sequence"].as_array().unwrap().iter()
        .filter(|e| e["op"] == "run").map(|e| e["cmd"].as_str().unwrap().to_string()).collect();
    let s = |x: String| x.replace(STAMP, "{STAMP}");
    assert_eq!(runs[0], a::PREFLIGHT_SCRIPT);
    assert_eq!(runs[1], a::cat_morpheus_rb());
    assert_eq!(runs[2], a::served_chain(""));
    assert_eq!(runs[3], s(a::backup(&format!("{}/{STAMP}", a::BACKUP_DIR))));
    assert_eq!(runs[4], a::cat_morpheus_rb());
    assert_eq!(runs[5], a::stat_mode_morpheus_rb());
    assert_eq!(runs[6], a::key_matches_cert("/etc/morpheus/ssl/m_cust_test.crt", "/etc/morpheus/ssl/m_cust_test.key"));
    let (script, _, _) = a::run_paths(STAMP);
    assert_eq!(runs[7], s(a::launch_runner(STAMP, &script, true)));
}

#[test]
fn transport_commands() {
    let g = json("golden/transport-commands.json");
    let one = |k: &str| g["commands"][k][0].as_str().unwrap().to_string();
    let wrap = |c: &str, sudo, m| a::ssh_wrap(c, sudo, m).0;
    assert_eq!(one("ssh_put_root"), wrap(&a::put_root_from_stdin("/etc/morpheus/ssl/m_cust_test.key", "0600", "0700"), true, SudoMode::Nopasswd));
    assert_eq!(one("ssh_put_root_trust"), wrap(&a::put_root_from_stdin("/etc/morpheus/ssl/trusted_certs/a.pem", "0644", "0755"), true, SudoMode::Nopasswd));
    let (log, rc) = ("/var/log/morpheus-certificate-install/R.log", "/var/log/morpheus-certificate-install/R.rc");
    assert_eq!(one("ssh_stream_file"), wrap(&a::ssh_follow(log, rc), false, SudoMode::Nopasswd));
    assert_eq!(one("ssh_sudo_wrap_nopasswd"), wrap("id -un", true, SudoMode::Nopasswd));
    assert_eq!(one("ssh_sudo_wrap_password"), wrap("id -un", true, SudoMode::Password));
    assert!(a::ssh_wrap("id -un", true, SudoMode::Password).1, "password mode must feed the sudo password on stdin");
    assert_eq!(wrap("id -un", true, SudoMode::Root), "bash -c 'id -un'");
    assert_eq!(one("list_runs"), wrap(&a::list_runs(), true, SudoMode::Password));
    assert_eq!(one("list_backups"), wrap(&a::list_backups(), true, SudoMode::Password));
    assert_eq!(one("charon_sudo_wrap"), format!("[run_command] {}", a::charon_wrap("id -un", true)));
    assert_eq!(one("charon_poll_first"), format!("[run_command] {}", a::charon_wrap(&a::charon_poll(log, rc, 0), false)));
}

#[test]
fn install_txt_matches_reference_except_the_last_line() {
    let info: ExportInfo = serde_json::from_str(&read("golden/export-p7b-pkcs1.info.json")).unwrap();
    let want = read("golden/export-p7b-pkcs1/INSTALL.txt").replace("{VERSION}", VERSION);
    let got = install_text(&info);
    let body = |s: &str| { let mut v: Vec<&str> = s.split('\n').collect(); v.truncate(v.len() - 2); v.join("\n") };
    assert_eq!(body(&got), body(&want));
    assert!(got.ends_with(&format!("{}\n", mci_core::export::INSTALL_CTA)));
    assert_eq!(mci_core::export::morpheus_rb_snippet("m_cust_test"), read("golden/export-p7b-pkcs1/morpheus.rb.snippet"));
}

#[test]
fn runner_markers() {
    assert_eq!(parse_marker("@@MCI step=reconfigure"), Some(Marker::Step("reconfigure".into())));
    assert_eq!(parse_marker("@@MCI rc=0 step=nginx"), Some(Marker::Rc { step: "nginx".into(), rc: 0 }));
    assert_eq!(parse_marker("@@MCI done rc=3"), Some(Marker::Done(3)));
    assert_eq!(parse_marker("@@MCI start 2026-11-05T12:00:00+00:00 on vm"), None);
    assert_eq!(q("{STAMP}"), "'{STAMP}'"); // why goldens are rendered with a real stamp, then substituted
}

#[test]
fn backup_reads() {
    // cat_manifest is the reference's rollback read, verbatim (engine.py rollback: f"cat {q(bdir)}/manifest.json").
    assert_eq!(a::cat_manifest("/var/lib/morpheus-certificate-install/backups/20261105-120000"),
               "cat /var/lib/morpheus-certificate-install/backups/20261105-120000/manifest.json");
    // cat_backup_morpheus_rb is new (divergence 19), quoted the same way.
    assert_eq!(a::cat_backup_morpheus_rb("/var/lib/morpheus-certificate-install/backups/a b"),
               "cat '/var/lib/morpheus-certificate-install/backups/a b'/morpheus.rb");
}

#[test]
fn charon_data_read_command() {
    // New in 0.3.11 (R6); no reference equivalent (the reference believed run_command's merged output).
    let got = a::charon_data_read("cat /etc/morpheus/morpheus.rb", true, "/home/mcitest/.morpheus-certificate-install-stage", "0123abcd");
    let want = r#"bash -c 'find /home/mcitest/.morpheus-certificate-install-stage -maxdepth 1 -name '"'"'mci-err-*'"'"' -mmin +10 -delete 2>/dev/null; e=/home/mcitest/.morpheus-certificate-install-stage/mci-err-0123abcd; trap '"'"'rm -f "$e"'"'"' EXIT; trap '"'"'exit 129'"'"' HUP; trap '"'"'exit 130'"'"' INT; trap '"'"'exit 143'"'"' TERM; (umask 077; : >"$e"); o=$({ sudo bash -c '"'"'cat /etc/morpheus/morpheus.rb'"'"'; } 2>"$e" </dev/null | base64 -w0; exit "${PIPESTATUS[0]}"); rc=$?; printf '"'"'\n@@MCI-%s-OUT\n%s\n@@MCI-%s-ERR\n'"'"' 0123abcd "$o" 0123abcd; base64 -w0 "$e"; printf '"'"'\n@@MCI-%s-RC=%s\n'"'"' 0123abcd "$rc"'"#;
    assert_eq!(got, want);
    // The marker text never appears literally in the command (a terminal may echo the command line).
    assert!(!got.contains("@@MCI-0123abcd"));
    assert!(a::charon_data_read("x", false, "/s", "n1").contains("{ bash -c x; }"));
}

#[test]
fn charon_data_read_parsing_ignores_terminal_noise() {
    use base64::Engine;
    let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    let rb = b"appliance_url 'https://198.51.100.20'\r\nkeep\tthe\x00bytes\n";
    let n = "77aa";
    // An echoed command line (printf, never the marker itself), OSC 133 marks, the lecture and the
    // prompt, CRLF everywhere, a colour code, and the payload split across a terminal wrap.
    let enc = b64(rb);
    let (p1, p2) = enc.split_at(10);
    let output = format!(
        "\x1b]133;C\x07travis@m:~$ bash -c 'printf ...@@MCI-%s-OUT ... 77aa'\r\n\r\nWe trust you have received the usual lecture...\r\n[sudo] password for mcitest: \r\n\
         @@MCI-{n}-OUT\r\n{p1}\r\n{p2}\r\n@@MCI-{n}-ERR\r\n{}\r\n\x1b[0m@@MCI-{n}-RC=0\r\n\x1b]133;D;0\x07travis@m:~$ ",
        b64(b"cat: warning\n"));
    let d = a::parse_charon_data_read(&output, n).unwrap();
    assert_eq!(d.stdout, rb, "byte for byte, the CRLF inside the data kept");
    assert_eq!(d.stderr, b"cat: warning\n");
    assert_eq!(d.rc, 0);
    // Errors: no frame at all; junk inside the frame; another read's nonce doesn't match.
    assert!(a::parse_charon_data_read("Permission denied\r\n", n).unwrap_err().contains("start marker"));
    let junk = format!("@@MCI-{n}-OUT\r\nnot base64!\r\n@@MCI-{n}-ERR\r\n\r\n@@MCI-{n}-RC=1\r\n");
    assert!(a::parse_charon_data_read(&junk, n).unwrap_err().contains("garbled"));
    assert!(a::parse_charon_data_read(&output, "other").is_err());
    let empty = format!("@@MCI-{n}-OUT\n\n@@MCI-{n}-ERR\n\n@@MCI-{n}-RC=2\n");
    assert_eq!(a::parse_charon_data_read(&empty, n).unwrap(), a::DataRead { rc: 2, stdout: vec![], stderr: vec![] });
    assert_eq!(a::strip_cr("a\r\nb\rc\n"), "a\nbc\n");
}

/// The stderr file is removed when the read is cut short — a timeout's HUP/INT/TERM — and a file
/// left by SIGKILL (untrappable) is swept by a later read once it is 10 minutes old, while another
/// read's fresh file is left alone. Skipped where there's no bash with timeout/find/touch.
#[test]
fn charon_data_read_cleans_up_on_timeout_and_kill() {
    let ok = std::process::Command::new("bash").args(["-c", GNU_PROBE_TIMEOUT])
        .output().map(|o| o.status.success()).unwrap_or(false);
    if !ok {
        eprintln!("no bash with base64/timeout/find/touch here; skipped");
        return;
    }
    let stage = std::env::temp_dir().join(format!("mci-frame-kill-{}", std::process::id()));
    std::fs::create_dir_all(&stage).unwrap();
    let stage_s = bash_path(&stage);
    let ls = || -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(&stage).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        v.sort();
        v
    };
    let run = |sh: &str| std::process::Command::new("bash").args(["-c", sh]).output().unwrap();
    // A read cut short by a timeout's signal: the file must not outlive it.
    for (sig, code) in [("HUP", 129), ("INT", 130), ("TERM", 143)] {
        let line = a::charon_data_read("sleep 3", false, &stage_s, &format!("sig{sig}"));
        let out = run(&format!("timeout --preserve-status -s {sig} 1 {line}"));
        assert_eq!(out.status.code(), Some(code), "{sig}: {}", String::from_utf8_lossy(&out.stderr));
        assert!(ls().is_empty(), "{sig}: stderr file left behind: {:?}", ls());
    }
    // SIGKILL can't be trapped: the file stays…
    let line = a::charon_data_read("sleep 3", false, &stage_s, "killed");
    let _ = run(&format!("timeout -s KILL 1 {line}"));
    assert_eq!(ls(), vec!["mci-err-killed".to_string()], "SIGKILL leaves the file (nothing can run)");
    // …until a later read finds it 10+ minutes old. A fresh file (another read in flight) stays.
    run(&format!("touch -d '20 minutes ago' {stage_s}/mci-err-killed; : > {stage_s}/mci-err-inflight"));
    let out = run(&a::charon_data_read("echo hi", false, &stage_s, "sweeper"));
    let d = a::parse_charon_data_read(&String::from_utf8_lossy(&out.stdout), "sweeper").unwrap();
    assert_eq!(d.stdout, b"hi\n");
    assert_eq!(ls(), vec!["mci-err-inflight".to_string()], "old leftover swept, in-flight file kept, own file removed");
    let _ = std::fs::remove_dir_all(&stage);
}

/// A Windows temp path as Git Bash sees it (C:\x → /c/x); unchanged elsewhere.
fn bash_path(p: &std::path::Path) -> String {
    let s = p.to_string_lossy().replace('\\', "/");
    if s.len() > 1 && &s[1..2] == ":" { format!("/{}{}", s[..1].to_lowercase(), &s[2..]) } else { s }
}

/// The frame really works in bash: run it (sudo off) on bytes with CRLF, NUL and non-ASCII, plus
/// stderr and an exit code, and decode. Skipped where there's no bash with base64.
#[test]
fn charon_data_read_round_trip_in_bash() {
    let ok = std::process::Command::new("bash").args(["-c", GNU_PROBE]).output().map(|o| o.status.success()).unwrap_or(false);
    if !ok {
        eprintln!("no bash/base64 here; skipped");
        return;
    }
    let stage = std::env::temp_dir().join(format!("mci-frame-{}", std::process::id()));
    std::fs::create_dir_all(&stage).unwrap();
    let stage_s = stage.to_string_lossy().replace('\\', "/");
    let stage_s = if stage_s.len() > 1 && &stage_s[1..2] == ":" {
        // Git Bash on Windows: C:/x → /c/x
        format!("/{}{}", stage_s[..1].to_lowercase(), &stage_s[2..])
    } else { stage_s };
    let cmd = r#"printf 'line1\r\nnul:\000:end\nZo\303\253\n'; echo 'on stderr' >&2; exit 3"#;
    let line = a::charon_data_read(cmd, false, &stage_s, "feed01");
    let out = std::process::Command::new("bash").args(["-c", &line]).output().unwrap();
    let d = a::parse_charon_data_read(&String::from_utf8_lossy(&out.stdout), "feed01").unwrap();
    assert_eq!(d.stdout, b"line1\r\nnul:\x00:end\nZo\xc3\xab\n");
    assert_eq!(d.stderr, b"on stderr\n");
    assert_eq!(d.rc, 3);
    assert!(std::fs::read_dir(&stage).unwrap().next().is_none(), "the stderr file is removed");
    // The frame doesn't change the command's umask (0.3.11 first draft set 077 for everything).
    let line = a::charon_data_read("umask", false, &stage_s, "feed02");
    let out = std::process::Command::new("bash").args(["-c", &format!("umask 022; {line}")]).output().unwrap();
    let d = a::parse_charon_data_read(&String::from_utf8_lossy(&out.stdout), "feed02").unwrap();
    assert_eq!(String::from_utf8_lossy(&d.stdout).trim(), "0022");
    let _ = std::fs::remove_dir_all(&stage);
}

/// The Charon long poll (0.3.16): waits on the appliance, then the reference's poll unchanged.
#[test]
fn charon_long_poll_command() {
    let (log, rc) = ("/var/log/morpheus-certificate-install/R.log", "/var/log/morpheus-certificate-install/R.rc");
    let want = "f=/var/log/morpheus-certificate-install/R.log; r=/var/log/morpheus-certificate-install/R.rc; end=$((SECONDS+90)); \
                while [ \"$SECONDS\" -lt \"$end\" ]; do \
                [ \"$(stat -c %s \"$f\" 2>/dev/null || echo 0)\" -gt 42 ] && break; [ -s \"$r\" ] && break; sleep 0.5; done; ";
    let got = a::charon_long_poll(log, rc, 42, 90);
    assert_eq!(got, format!("{want}{}", a::charon_poll(log, rc, 42)));
    // Paths are quoted like everywhere else.
    assert!(a::charon_long_poll("/tmp/a b.log", "/tmp/a b.rc", 0, 5).starts_with("f='/tmp/a b.log'; r='/tmp/a b.rc'; end=$((SECONDS+5));"));
}

/// The long poll in real bash: returns at once when the log is already past the offset, as soon
/// as it grows (or the rc file appears) while waiting, and after `wait_s` when nothing happens.
#[test]
fn charon_long_poll_in_bash() {
    let ok = std::process::Command::new("bash").args(["-c", GNU_PROBE_STAT]).output().map(|o| o.status.success()).unwrap_or(false);
    if !ok {
        eprintln!("no bash/base64/stat here; skipped");
        return;
    }
    let dir = std::env::temp_dir().join(format!("mci-lp-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (log, rcf) = (dir.join("R.log"), dir.join("R.rc"));
    let (lb, rb) = (bash_path(&log), bash_path(&rcf));
    let run = |pre: &str, off: u64, wait: u32| {
        let t = std::time::Instant::now();
        let out = std::process::Command::new("bash").args(["-c", &format!("{pre}{}", a::charon_long_poll(&lb, &rb, off, wait))]).output().unwrap();
        (String::from_utf8_lossy(&out.stdout).into_owned(), t.elapsed())
    };
    std::fs::write(&log, b"line 1\n").unwrap();
    let (out, took) = run("", 0, 10);
    assert!(out.starts_with("SIZE=7\nRC=\n") && out.contains("bGluZSAxCg=="), "{out:?}");
    assert!(took < std::time::Duration::from_secs(2), "data already there: at once ({took:?})");
    let (out, took) = run("", 7, 2);
    assert_eq!(out, "SIZE=7\nRC=\n\n", "nothing new");
    // $SECONDS ticks in whole seconds, so "2 s" is between 1 and 2 s of waiting.
    assert!(took >= std::time::Duration::from_secs(1) && took < std::time::Duration::from_secs(5), "waited about 2 s ({took:?})");
    let (out, took) = run(&format!("( sleep 1; echo 'line 2' >> '{lb}' ) & "), 7, 20);
    assert!(out.starts_with("SIZE=14\n") && out.contains("bGluZSAyCg=="), "{out:?}");
    assert!(took < std::time::Duration::from_secs(4), "returned when the log grew, not after 20 s ({took:?})");
    let (out, took) = run(&format!("( sleep 1; echo 0 > '{rb}' ) & "), 14, 20);
    assert!(out.starts_with("SIZE=14\nRC=0\n"), "{out:?}");
    assert!(took < std::time::Duration::from_secs(4), "returned when the rc file appeared ({took:?})");
    let _ = std::fs::remove_dir_all(&dir);
}

// ------------------------------------------------------------------ cleanup (0.3.17)
mod cleanup {
    use super::{a, bash_path};
    use a::CleanupItem as I;

    #[test]
    fn builders_are_pinned() {
        assert_eq!(a::cleanup_inventory(), include_str!("golden_cleanup/inventory.sh").trim_end());
        assert_eq!(a::cleanup_stage_inventory(), include_str!("golden_cleanup/stage_inventory.sh").trim_end());
        let items = [I::Script("20261105-120000.sh".into()), I::Log("20261105-120000.log".into()), I::Log("20261105-120000.rc".into()),
                     I::Backup("20261105-120000".into())];
        assert_eq!(a::cleanup_remove(&items).unwrap(), include_str!("golden_cleanup/remove.sh").trim_end());
        assert_eq!(a::cleanup_remove_stage(), include_str!("golden_cleanup/remove_stage.sh").trim_end());
    }

    #[test]
    fn nothing_outside_our_dirs_can_be_named() {
        for bad in [I::Script("../x.sh".into()), I::Script("x".into()), I::Script(".sh".into()), I::Log("a/b.log".into()), I::Log("x.txt".into()),
                    I::Backup("".into()), I::Backup("..".into()), I::Backup(".hidden".into()), I::Backup("a b".into()), I::Backup("x;rm -rf /".into()),
                    I::Backup("*".into())] {
            let e = a::cleanup_remove(&[I::Backup("20261105-120000".into()), bad.clone()]).unwrap_err();
            assert!(e.contains("Nothing was removed"), "{bad:?}: {e}");
        }
    }

    /// The commands in real bash, against a temp tree standing in for /var/lib and /var/log.
    #[test]
    fn removes_exactly_what_it_names_in_bash() {
        let ok = std::process::Command::new("bash").args(["-c", "shred --version && find --version && du --version"]).output().map(|o| o.status.success()).unwrap_or(false);
        if !ok { eprintln!("no bash/shred/find here; skipped"); return; }
        let t = std::env::temp_dir().join(format!("mci-clean-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&t);
        let (lib, log, home, outside) = (t.join("lib/mci"), t.join("log/mci"), t.join("home"), t.join("outside"));
        for d in [lib.join("runs"), lib.join("backups/B1/ssl"), lib.join("backups/B2"), log.clone(), home.join(".morpheus-certificate-install-stage"), outside.clone()] {
            std::fs::create_dir_all(d).unwrap();
        }
        let w = |p: std::path::PathBuf, s: &str| std::fs::write(p, s).unwrap();
        w(lib.join("runs/R1.sh"), "#!/bin/bash\n");
        w(lib.join("runs/R2.sh"), "#!/bin/bash\n");
        w(log.join("R1.log"), "log\n"); w(log.join("R1.rc"), "0\n"); w(log.join("other.txt"), "not ours\n");
        w(lib.join("backups/B1/ssl/old.key"), "-----BEGIN PRIVATE KEY-----\n"); w(lib.join("backups/B1/morpheus.rb"), "appliance_url 'x'\n");
        w(lib.join("backups/B2/manifest.json"), "{}\n");
        w(outside.join("keep.key"), "outside\n");
        w(home.join(".morpheus-certificate-install-stage/mci-err-1"), "x");
        let (lb, gb, hb) = (bash_path(&lib), bash_path(&log), bash_path(&home));
        let sub = |s: String| s.replace("/var/lib/morpheus-certificate-install", &lb).replace("/var/log/morpheus-certificate-install", &gb);
        let run = |cmd: String| {
            let o = std::process::Command::new("bash").args(["-c", &cmd]).env("HOME", &hb).output().unwrap();
            (o.status.code(), String::from_utf8_lossy(&o.stdout).into_owned())
        };
        // A symlink named like a backup, pointing outside: not followed, nothing outside touched.
        let _ = run(format!("ln -s {} {}/backups/LINK", bash_path(&outside), lb));
        let (_, inv) = run(sub(a::cleanup_inventory()));
        let kinds: Vec<&str> = inv.lines().map(|l| l.split('|').next().unwrap()).collect();
        assert_eq!(kinds.iter().filter(|k| **k == "script").count(), 2, "{inv}");
        assert_eq!(kinds.iter().filter(|k| **k == "log").count(), 2, "only *.log and *.rc: {inv}");
        assert!(inv.lines().any(|l| l.starts_with(&format!("backup|{lb}/backups/B1|")) && l.ends_with("|1")), "B1 has one .key: {inv}");
        let (_, sinv) = run(a::cleanup_stage_inventory());
        assert!(sinv.starts_with(&format!("stage|{hb}/.morpheus-certificate-install-stage|")), "{sinv}");

        let items = [I::Script("R1.sh".into()), I::Log("R1.log".into()), I::Log("R1.rc".into()), I::Backup("B1".into()), I::Backup("LINK".into())];
        let (rc, out) = run(sub(a::cleanup_remove(&items).unwrap()));
        assert_eq!(rc, Some(0), "{out}");
        assert!(out.contains(&format!("shredded {lb}/backups/B1/ssl/old.key")) && out.contains(&format!("removed {lb}/backups/B1/")), "{out}");
        assert!(!lib.join("runs/R1.sh").exists() && !log.join("R1.log").exists() && !lib.join("backups/B1").exists());
        assert!(lib.join("runs/R2.sh").exists() && log.join("other.txt").exists() && lib.join("backups/B2/manifest.json").exists(), "only what was named");
        assert!(outside.join("keep.key").exists(), "the symlink wasn't followed");
        let (_, out) = run(a::cleanup_remove_stage());
        assert!(out.contains("shredded ") && !home.join(".morpheus-certificate-install-stage").exists(), "{out}");
        // Everything else removed too: the empty dirs go, the one with someone else's file stays.
        let _ = run(format!("rm -f {lb}/backups/LINK"));
        let (rc, _) = run(sub(a::cleanup_remove(&[I::Script("R2.sh".into()), I::Backup("B2".into())]).unwrap()));
        assert_eq!(rc, Some(0));
        assert!(!lib.exists(), "STATE_DIR removed once empty");
        assert!(log.join("other.txt").exists(), "LOG_DIR kept: not empty");
        let _ = std::fs::remove_dir_all(&t);
    }
}

// ------------------------------------------------------------------ installed-files ledger (0.3.19)
mod ledger {
    use super::{a, bash_path};

    fn v(x: &[&str]) -> Vec<String> { x.iter().map(|s| s.to_string()).collect() }

    #[test]
    fn builders_are_pinned() {
        assert_eq!(a::LEDGER, "/var/lib/morpheus-certificate-install/installed.json");
        assert_eq!(a::cat_ledger(), "[ -f /var/lib/morpheus-certificate-install/installed.json ] && cat /var/lib/morpheus-certificate-install/installed.json; true");
        let p = v(&["/etc/morpheus/ssl/m_cust_test.crt", "/etc/morpheus/ssl/m_cust_test.key"]);
        assert_eq!(a::remove_installed(&p).unwrap(), include_str!("golden_cleanup/remove_installed.sh").trim_end());
        assert_eq!(a::rollback_remove_installed("/var/lib/morpheus-certificate-install/backups/20261105-120000", &p).unwrap(),
                   include_str!("golden_cleanup/rollback_remove_installed.sh").trim_end());
        assert_eq!(a::stat_installed(&p).unwrap(), "stat -c '%n|%s|%Y' /etc/morpheus/ssl/m_cust_test.crt /etc/morpheus/ssl/m_cust_test.key 2>/dev/null; true");
    }

    #[test]
    fn only_crt_and_key_files_directly_in_the_ssl_dir() {
        for bad in ["/etc/morpheus/ssl/../morpheus.rb", "/etc/morpheus/morpheus.rb", "/etc/morpheus/ssl/trusted_certs/x.crt", "/etc/morpheus/ssl/x.pem",
                    "/etc/morpheus/ssl/.crt", "/etc/morpheus/ssl/a b.key", "/etc/morpheus/ssl/x.key;rm", "/etc/morpheus/sslx/a.key", "relative/a.key"] {
            assert!(a::remove_installed(&v(&[bad])).unwrap_err().contains("Nothing was removed"), "{bad}");
            assert!(a::rollback_remove_installed("/b", &v(&[bad])).is_err(), "{bad}");
        }
    }

    #[test]
    fn rollback_removes_only_what_the_backup_lacks_in_bash() {
        let ok = std::process::Command::new("bash").args(["-c", "shred --version"]).output().map(|o| o.status.success()).unwrap_or(false);
        if !ok { eprintln!("no bash/shred here; skipped"); return; }
        let t = std::env::temp_dir().join(format!("mci-ledger-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&t);
        let (ssl, bk) = (t.join("ssl"), t.join("backup"));
        std::fs::create_dir_all(bk.join("ssl")).unwrap();
        std::fs::create_dir_all(&ssl).unwrap();
        for n in ["old.crt", "old.key", "new.crt", "new.key", "other.key"] { std::fs::write(ssl.join(n), n).unwrap(); }
        for n in ["old.crt", "old.key"] { std::fs::write(bk.join("ssl").join(n), n).unwrap(); }
        let paths = v(&["/etc/morpheus/ssl/old.crt", "/etc/morpheus/ssl/old.key", "/etc/morpheus/ssl/new.crt", "/etc/morpheus/ssl/new.key"]);
        let cmd = a::rollback_remove_installed("/BDIR", &paths).unwrap().replace("/etc/morpheus/ssl", &bash_path(&ssl)).replace("/BDIR", &bash_path(&bk));
        let o = std::process::Command::new("bash").args(["-c", &cmd]).output().unwrap();
        let out = String::from_utf8_lossy(&o.stdout);
        assert_eq!(o.status.code(), Some(0), "{out}");
        assert!(out.contains("shredded ") && out.contains("new.key") && out.contains("removed ") && out.contains("new.crt"), "{out}");
        assert!(!ssl.join("new.crt").exists() && !ssl.join("new.key").exists(), "what the backup lacks goes");
        assert!(ssl.join("old.crt").exists() && ssl.join("old.key").exists(), "what the backup has stays");
        assert!(ssl.join("other.key").exists(), "what isn't named is never touched");
        let _ = std::fs::remove_dir_all(&t);
    }
}
