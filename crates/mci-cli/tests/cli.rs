//! morpheus-certificate-install 0.4.1 — the CLI end to end: `convert` on corpus sets, the output
//! tree compared byte for byte with fixtures/golden/export-p7b-pkcs1/ (INSTALL.txt: all but line 1,
//! the last line and the "Converted from" lines, which name each set's own inputs).

use std::path::{Path, PathBuf};
use std::process::Command;

fn root() -> PathBuf { PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..") }
fn corpus(f: &str) -> PathBuf { root().join("fixtures/corpus").join(f) }

fn tree(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    fn walk(base: &Path, d: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        for e in std::fs::read_dir(d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() { walk(base, &p, out); } else {
                out.push((p.strip_prefix(base).unwrap().to_string_lossy().replace('\\', "/"), std::fs::read(&p).unwrap()));
            }
        }
    }
    walk(dir, dir, &mut out);
    out.sort();
    out
}

/// INSTALL.txt without line 1, the "Converted from:" block and the last line.
fn install_body(s: &str) -> Vec<String> {
    let lines: Vec<&str> = s.split('\n').collect();
    let mut out = Vec::new();
    let mut in_inputs = false;
    for l in &lines[1..lines.len() - 2] {
        if *l == "Converted from:" { in_inputs = true; continue; }
        if in_inputs && l.starts_with("  ") { continue; }
        in_inputs = false;
        out.push(l.to_string());
    }
    out
}

fn run(name: &str, files: &[&str], pfx_pw: &str) -> (std::process::Output, PathBuf) {
    let dir = std::env::temp_dir().join(format!("mci-cli-test-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_morpheus-certificate-install-cli"))
        .arg("convert").args(files.iter().map(|f| corpus(f)))
        .env("MCI_PFX_PASSWORD", pfx_pw).env_remove("MCI_KEY_PASSWORD")
        .current_dir(&dir).output().unwrap();
    (out, dir)
}

#[test]
fn three_sets_produce_the_golden_tree() {
    let gold = tree(&root().join("fixtures/golden/export-p7b-pkcs1"));
    let gold_install = String::from_utf8(gold.iter().find(|(n, _)| n == "INSTALL.txt").unwrap().1.clone()).unwrap();
    for (name, files, pw) in [("p7b", &["chain.p7b", "leaf-pkcs1.key"][..], ""), ("pfx", &["modern.pfx"][..], "pp"),
                              ("pem", &["leaf.crt", "leaf.key", "bundle.crt"][..], "")] {
        let (out, dir) = run(name, files, pw);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert_eq!(out.status.code(), Some(0), "{name}: {stdout}");
        assert!(stdout.starts_with(&format!("Morpheus Certificate Install {} convert\n", env!("CARGO_PKG_VERSION"))), "{stdout}");
        assert!(stdout.contains("Wrote m_cust_test-morpheus:\n  INSTALL.txt\n  ca-chain.pem\n  m_cust_test.crt\n  m_cust_test.key\n"), "{stdout}");
        let got = tree(&dir.join("m_cust_test-morpheus"));
        assert_eq!(got.iter().map(|(n, _)| n).collect::<Vec<_>>(), gold.iter().map(|(n, _)| n).collect::<Vec<_>>(), "{name}: file list");
        for ((n, g), (_, w)) in got.iter().zip(&gold) {
            if n == "INSTALL.txt" {
                assert_eq!(install_body(&String::from_utf8_lossy(g)), install_body(&gold_install), "{name}: INSTALL.txt body");
            } else {
                assert_eq!(g, w, "{name}: {n}");
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(dir.join("m_cust_test-morpheus/m_cust_test.key")).unwrap().permissions().mode();
            assert_eq!(m & 0o777, 0o600, "{name}: key mode");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn errors_exit_2_and_write_nothing() {
    let (out, dir) = run("wrongkey", &["leaf.crt", "other.key", "bundle.crt"], "");
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stdout).ends_with("Not converted — fix the errors above.\n"));
    assert!(!dir.join("m_cust_test-morpheus").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn version_goes_to_stdout_and_usage_errors_to_stderr() {
    let exe = env!("CARGO_BIN_EXE_morpheus-certificate-install-cli");
    let v = Command::new(exe).arg("--version").output().unwrap();
    assert!(v.status.success());
    assert_eq!(String::from_utf8_lossy(&v.stdout).trim(), format!("morpheus-certificate-install-cli {}", mci_core::VERSION));
    assert!(v.stderr.is_empty(), "nothing on stderr: {}", String::from_utf8_lossy(&v.stderr));
    let u = Command::new(exe).args(["convert", "--bogus"]).output().unwrap();
    assert_eq!(u.status.code(), Some(64));
    assert!(u.stdout.is_empty() && String::from_utf8_lossy(&u.stderr).contains("unknown option --bogus"));
}
