//! morpheus-certificate-install 0.4.0 — conversion parity with the Python reference.
//! RED until Round 1 (R1–R4) is done; GREEN is the definition of done. Cases: fixtures/cases.json.

use mci_core::formats::{parse_files, InputFile, Passwords};
use mci_core::{aia, analyze};
use serde_json::Value;
use std::path::PathBuf;

/// The instant make-cases.py froze the reference's clock at (cases.json `generated_at_unix`).
fn generated_at(cases: &Value) -> i64 { cases["generated_at_unix"].as_i64().expect("cases.json has generated_at_unix") }

fn fx(p: &str) -> PathBuf { PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures").join(p) }

/// AIA URLs in the corpus point at http://127.0.0.1:18080/<file>; serve them from disk.
fn corpus_fetch(url: &str) -> Result<Vec<u8>, String> {
    let name = url.rsplit('/').next().ok_or("bad url")?;
    std::fs::read(fx("corpus").join(name)).map_err(|e| e.to_string())
}

/// R1's definition of done: for every case, each input's kind, cert count, key count and level
/// equal the reference's (`expect.inputs`), straight from parsing — before chain analysis.
#[test]
fn every_input_parses_like_the_reference() {
    let cases: Value = serde_json::from_str(&std::fs::read_to_string(fx("cases.json")).unwrap()).unwrap();
    let mut failures = Vec::new();
    let mut checked = 0;
    for c in cases["cases"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let files: Vec<InputFile> = c["files"].as_array().unwrap().iter().map(|f| {
            let n = f.as_str().unwrap();
            InputFile { name: n.into(), data: std::fs::read(fx("corpus").join(n)).unwrap() }
        }).collect();
        let pw = Passwords { pfx: c["pfx_password"].as_str().unwrap().into(), key: c["key_password"].as_str().unwrap().into(), extra: vec![] };
        let b = parse_files(&files, &pw);
        let want = c["expect"]["inputs"].as_array().unwrap();
        if b.reports.len() != want.len() { failures.push(format!("{name}: {} reports, want {}", b.reports.len(), want.len())); continue; }
        for (r, w) in b.reports.iter().zip(want) {
            checked += 1;
            let got = (r.name.as_str(), r.kind.as_str(), r.certs as u64, r.keys as u64, serde_json::to_value(r.level).unwrap());
            let exp = (w["name"].as_str().unwrap(), w["kind"].as_str().unwrap(), w["certs"].as_u64().unwrap(), w["keys"].as_u64().unwrap(), w["level"].clone());
            if got != exp {
                failures.push(format!("{name}: {got:?} vs reference {exp:?} (reference format: {})", w["reference_format"]));
            } else if r.format != w["reference_format"].as_str().unwrap() {
                failures.push(format!("{name}/{}: format {:?} vs reference {}", r.name, r.format, w["reference_format"]));
            }
        }
        // The key the bundle ends up with is there exactly when the reference had one.
        if b.key.is_some() != c["expect"]["key_present"].as_bool().unwrap() {
            failures.push(format!("{name}: key present {} vs reference {}", b.key.is_some(), c["expect"]["key_present"]));
        }
    }
    assert!(checked > 60, "only {checked} inputs checked");
    assert!(failures.is_empty(), "{} mismatches:\n{}", failures.len(), failures.join("\n"));
}

#[test]
fn every_case_matches_the_reference() {
    let cases: Value = serde_json::from_str(&std::fs::read_to_string(fx("cases.json")).unwrap()).unwrap();
    let now = generated_at(&cases);
    let mut failures = Vec::new();
    for c in cases["cases"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let mut exp = c["expect"].clone();
        if let Some(o) = c.get("rust_expect_override") {
            for (k, v) in o.as_object().unwrap() { if k != "why" { exp[k] = v.clone(); } }
        }
        let files: Vec<InputFile> = c["files"].as_array().unwrap().iter().map(|f| {
            let n = f.as_str().unwrap();
            InputFile { name: n.into(), data: std::fs::read(fx("corpus").join(n)).unwrap() }
        }).collect();
        let pw = Passwords { pfx: c["pfx_password"].as_str().unwrap().into(), key: c["key_password"].as_str().unwrap().into(), extra: vec![] };
        let mut b = parse_files(&files, &pw);
        if c["fetch_chain"].as_bool().unwrap() {
            aia::complete_chain(&mut b, &corpus_fetch);
        }
        let an = analyze::analyze(&b, c["fqdn"].as_str().unwrap(), c["appliance_url"].as_str().unwrap(), now);
        let mut check = |what: &str, ok: bool| if !ok { failures.push(format!("{name}: {what}")) };
        check("ok", an.ok() == exp["ok"].as_bool().unwrap());
        check("fqdn", an.fqdn == exp["fqdn"].as_str().unwrap());
        check("leaf", an.leaf.as_ref().map(|l| l.fp256()) == exp["leaf_sha256"].as_str().map(String::from));
        let ints: Vec<String> = an.intermediates.iter().map(|i| i.fp256()).collect();
        let want_ints: Vec<String> = exp["intermediates_sha256"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().into()).collect();
        check("intermediates", ints == want_ints);
        check("root", an.root.as_ref().map(|r| r.fp256()) == exp["root_sha256"].as_str().map(String::from));
        check("key_present", an.key_pkcs8.is_some() == exp["key_present"].as_bool().unwrap());
        let has = |lvl| an.checks.iter().any(|x| x.level == lvl);
        check("has_error", has(mci_core::model::Level::Error) == exp["has_error"].as_bool().unwrap());
        check("appliance_url_warn", an.checks.iter().any(|x| x.level == mci_core::model::Level::Warn && x.text.contains("Appliance URL"))
              == exp["appliance_url_warn"].as_bool().unwrap());
        let kinds: Vec<String> = an.reports.iter().map(|r| r.kind.clone()).collect();
        let want_kinds: Vec<String> = exp["inputs"].as_array().unwrap().iter().map(|i| i["kind"].as_str().unwrap().into()).collect();
        check(&format!("input kinds {kinds:?} vs {want_kinds:?}"), kinds == want_kinds);
        let aliases: Vec<String> = an.ca_certs().iter().map(|c| mci_core::names::alias_for(&c.cn, &c.fp256_hex())).collect();
        let want_aliases: Vec<String> = exp["ca_aliases"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().into()).collect();
        if an.leaf.is_some() { check("ca_aliases", aliases == want_aliases); }
        // Every check, level and text, verbatim and in order (the UI shows them).
        let got_checks = serde_json::to_value(&an.checks).unwrap();
        if got_checks != exp["reference_checks"] {
            failures.push(format!("{name}: checks
    rust:      {got_checks}
    reference: {}", exp["reference_checks"]));
        }
        // The whole UI contract (to_json), apart from "inputs" (compared by every_input_parses_like_the_reference).
        let mut j = serde_json::to_value(an.to_json()).unwrap();
        j.as_object_mut().unwrap().remove("inputs");
        if j != exp["to_json"] {
            let (g, w) = (j.as_object().unwrap(), exp["to_json"].as_object().unwrap());
            let keys: Vec<&String> = g.keys().chain(w.keys()).filter(|k| g.get(*k) != w.get(*k)).collect();
            failures.push(format!("{name}: to_json differs in {keys:?}
    rust:      {}
    reference: {}",
                keys.iter().map(|k| format!("{k}={}", g.get(*k).unwrap_or(&Value::Null))).collect::<Vec<_>>().join("; "),
                keys.iter().map(|k| format!("{k}={}", w.get(*k).unwrap_or(&Value::Null))).collect::<Vec<_>>().join("; ")));
        }
    }
    assert!(failures.is_empty(), "{} mismatches:\n{}", failures.len(), failures.join("\n"));
}

#[test]
fn export_layout_matches_reference() {
    let files = vec![
        InputFile { name: "chain.p7b".into(), data: std::fs::read(fx("corpus/chain.p7b")).unwrap() },
        InputFile { name: "leaf-pkcs1.key".into(), data: std::fs::read(fx("corpus/leaf-pkcs1.key")).unwrap() },
    ];
    let b = parse_files(&files, &Passwords::default());
    let cases: Value = serde_json::from_str(&std::fs::read_to_string(fx("cases.json")).unwrap()).unwrap();
    // At the frozen instant, so validity checks can't fail on the day the tests run.
    let an = analyze::analyze(&b, "m.cust.test", "", generated_at(&cases));
    let out = mci_core::export::build_files(&an, false, "2026-11-05 12:00").unwrap();
    let gold = fx("golden/export-p7b-pkcs1");
    // Same set of files as the reference wrote.
    let mut want: Vec<String> = Vec::new();
    for e in std::fs::read_dir(&gold).unwrap() {
        let e = e.unwrap();
        if e.file_type().unwrap().is_dir() {
            for f in std::fs::read_dir(e.path()).unwrap() { want.push(format!("{}/{}", e.file_name().to_string_lossy(), f.unwrap().file_name().to_string_lossy())); }
        } else {
            want.push(e.file_name().to_string_lossy().into());
        }
    }
    let mut got: Vec<String> = out.iter().map(|(r, _)| r.clone()).collect();
    want.sort();
    got.sort();
    assert_eq!(got, want);
    for (rel, data) in &out {
        let gold_bytes = std::fs::read(gold.join(rel)).unwrap();
        if rel == "INSTALL.txt" {
            // Line 1 carries the clock and version; the last line is divergence 2 (PARITY.md).
            let (g, w) = (String::from_utf8(data.clone()).unwrap(), String::from_utf8(gold_bytes).unwrap());
            let (g, w): (Vec<&str>, Vec<&str>) = (g.split('\n').collect(), w.split('\n').collect());
            assert_eq!(g.len(), w.len(), "INSTALL.txt line count");
            assert_eq!(g[1..g.len() - 2], w[1..w.len() - 2], "INSTALL.txt body");
            assert_eq!(g[0], "Converted by Morpheus Certificate Install {VERSION} on 2026-11-05 12:00".replace("{VERSION}", mci_core::VERSION));
            assert_eq!(g[g.len() - 2], mci_core::export::INSTALL_CTA);
            continue;
        }
        // Everything else byte for byte, the decrypted key included (same PKCS#8 PEM as the reference).
        assert_eq!(data, &gold_bytes, "{rel}");
    }
}
