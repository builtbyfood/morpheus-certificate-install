//! morpheus-certificate-install 0.4.0 — the `/etc/morpheus/morpheus.rb` edit. Byte-identical to the reference.

use regex::Regex;

pub const MANAGED_BEGIN: &str = "# >>> morpheus-certificate-install managed block (do not edit by hand) >>>";
pub const MANAGED_END: &str = "# <<< morpheus-certificate-install managed block <<<";
/// Written by 0.2.0 when the tool was called Sphragis; replaced on the next install.
pub const LEGACY_BEGIN: &[&str] = &["# >>> sphragis managed block (do not edit by hand) >>>"];
pub const LEGACY_END: &[&str] = &["# <<< sphragis managed block <<<"];

fn nginx_line() -> Regex {
    Regex::new(r#"^\s*nginx\s*\[\s*['"](ssl_certificate|ssl_server_key)['"]\s*\]\s*="#).unwrap()
}

/// Lines the way Python's `str.splitlines()` splits a config file (\n, \r\n, \r).
fn split_lines(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = text;
    while !rest.is_empty() {
        match rest.find(['\n', '\r']) {
            Some(i) => {
                out.push(&rest[..i]);
                let skip = if rest[i..].starts_with("\r\n") { 2 } else { 1 };
                rest = &rest[i + skip..];
            }
            None => {
                out.push(rest);
                break;
            }
        }
    }
    out
}

/// Comment out active `nginx['ssl_certificate'|'ssl_server_key']` lines, drop a previous
/// managed block (ours or the legacy one), append a fresh block. Idempotent.
pub fn transform(text: &str, cert_path: &str, key_path: &str, stamp: &str) -> String {
    let pat = nginx_line();
    let mut out: Vec<String> = Vec::new();
    let mut skipping = false;
    for ln in split_lines(text) {
        let t = ln.trim();
        if t == MANAGED_BEGIN || LEGACY_BEGIN.contains(&t) {
            skipping = true;
            continue;
        }
        if skipping {
            if t == MANAGED_END || LEGACY_END.contains(&t) {
                skipping = false;
            }
            continue;
        }
        if pat.is_match(ln) {
            out.push(format!("# [morpheus-certificate-install {stamp}] {ln}"));
        } else {
            out.push(ln.to_string());
        }
    }
    while out.last().map(|l| l.trim().is_empty()).unwrap_or(false) {
        out.pop();
    }
    out.push(String::new());
    out.push(MANAGED_BEGIN.into());
    out.push(format!("# written {stamp} — previous values (if any) are commented above"));
    out.push(format!("nginx['ssl_certificate'] = '{cert_path}'"));
    out.push(format!("nginx['ssl_server_key'] = '{key_path}'"));
    out.push(MANAGED_END.into());
    out.join("\n") + "\n"
}

/// Current active values: `ssl_certificate` / `ssl_server_key` → path (last one wins).
pub fn current_nginx_ssl(text: &str) -> Vec<(String, String)> {
    let pat = Regex::new(r#"^\s*nginx\s*\[\s*['"](ssl_certificate|ssl_server_key)['"]\s*\]\s*=\s*['"]([^'"]+)['"]"#).unwrap();
    let mut cert = None;
    let mut key = None;
    for ln in split_lines(text) {
        if let Some(m) = pat.captures(ln) {
            if &m[1] == "ssl_certificate" { cert = Some(m[2].to_string()) } else { key = Some(m[2].to_string()) }
        }
    }
    let mut v = Vec::new();
    if let Some(c) = cert { v.push(("ssl_certificate".into(), c)); }
    if let Some(k) = key { v.push(("ssl_server_key".into(), k)); }
    v
}

/// Unified diff for the Plan view (display only — hunk layout may differ slightly from difflib).
pub fn unified_diff(old: &str, new: &str, path: &str) -> String {
    similar::TextDiff::from_lines(old, new)
        .unified_diff()
        .context_radius(3)
        .header(&format!("{path} (now)"), &format!("{path} (after)"))
        .to_string()
}

// ------------------------------------------------------------------ write guard (0.3.6)

/// Does `text` look like a real morpheus.rb? True when some line, once leading whitespace is
/// trimmed, starts with `appliance_url` and isn't a comment — the line Morpheus itself requires,
/// and the same test the reference's preflight uses to read the Appliance URL.
pub fn has_appliance_url(text: &str) -> bool {
    split_lines(text).iter().map(|l| l.trim()).any(|l| l.starts_with("appliance_url") && !l.starts_with('#'))
}

/// Refuse to write morpheus.rb from text that isn't one (docs/PARITY.md, divergence 19).
///
/// A read can return something other than the file — an empty string after a failed `cat`, sudo's
/// lecture or an error message, a truncated transfer — and writing a transform of *that* would
/// replace the appliance's configuration with a few nginx lines. `source` says where the text came
/// from (`/etc/morpheus/morpheus.rb`, `the backup 20261105-120000`) for the message.
pub fn guard(text: &str, source: &str) -> Result<(), String> {
    if has_appliance_url(text) {
        return Ok(());
    }
    Err(format!(
        "Not writing /etc/morpheus/morpheus.rb: the text read from {source} has no appliance_url line, so it \
         isn't a complete morpheus.rb (the read may have failed or returned something else). Nothing was \
         changed. Check it on the appliance with: sudo grep -n appliance_url /etc/morpheus/morpheus.rb"
    ))
}

/// `transform`, but only for text that passes [`guard`]. What apply uses.
pub fn transform_checked(text: &str, cert_path: &str, key_path: &str, stamp: &str) -> Result<String, String> {
    guard(text, crate::appliance::MORPHEUS_RB)?;
    Ok(transform(text, cert_path, key_path, stamp))
}

#[cfg(test)]
mod guard_tests {
    use super::*;

    #[test]
    fn real_files_pass() {
        assert!(has_appliance_url("appliance_url 'https://x'\n"));
        assert!(has_appliance_url("# comment\n  appliance_url \"https://x\"\r\nnginx['x'] = 1\n"));
        assert!(transform_checked("appliance_url 'https://x'\n", "/a.crt", "/a.key", "s").unwrap().contains("ssl_certificate"));
    }

    #[test]
    fn anything_else_is_refused_and_nothing_is_produced() {
        for bad in [
            "",
            "\n\n",
            "# appliance_url 'https://x'\n",
            "#appliance_url 'https://x'\n",
            "We trust you have received the usual lecture from the local System Administrator.\n",
            "cat: /etc/morpheus/morpheus.rb: No such file or directory\n",
            "nginx['ssl_certificate'] = '/etc/morpheus/ssl/a.crt'\n",
        ] {
            let e = transform_checked(bad, "/a.crt", "/a.key", "s").unwrap_err();
            assert!(e.contains("Nothing was changed") && e.contains("/etc/morpheus/morpheus.rb"), "{bad:?}: {e}");
        }
        assert!(guard("", "the backup 20261105-120000").unwrap_err().contains("the backup 20261105-120000"));
    }
}
