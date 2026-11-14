//! morpheus-certificate-install 0.4.1 — complete a chain from AIA "CA Issuers" URLs. **Round 1, R3.**
//!
//! Port of reference certs.complete_chain(): from the top of the current chain, follow its CA Issuers
//! URLs, at most [`MAX_HOPS`] times, stopping as soon as a hop adds nothing new (so a certificate
//! whose AIA points at itself can't loop). Responses may be DER, PEM or PKCS#7 (parsed with
//! formats::parse_one). Fetched certificates only join the pool: `analyze()` still decides, by Name
//! and signature, whether they belong in the chain.
//!
//! Differences from the reference (docs/PARITY.md, divergence 15):
//! - every URL attempted gets a log line, including one that answered with nothing new;
//! - non-http(s) URLs (ldap:, file:, …) are skipped with a log line instead of silently, and when a
//!   certificate offers only those, the log says to export the chain from the issuing Windows CA.
//!
//! The core stays I/O-free: the HTTP request is a caller-supplied [`Fetch`].

use crate::formats::{parse_one, Passwords};
use crate::model::Bundle;

/// Fetch one URL and return the response body, or an error string for the log.
///
/// Contract every implementation must keep (src-tauri and mci-cli; the parity test serves files):
/// - **http and https only.** complete_chain never passes anything else, but refuse other schemes anyway.
/// - **10 s timeout** for the whole request.
/// - **1 MiB cap** on the body: stop reading and return an error beyond it.
/// - **At most 3 redirects**, each one also http/https.
/// - **No cookies, no credentials, no client certificates**; a plain GET with a product User-Agent.
/// - On any failure, an error string that says what happened (`HTTP 404`, `timed out after 10 s`, …):
///   it is shown to the user after the URL.
pub type Fetch<'a> = &'a dyn Fn(&str) -> Result<Vec<u8>, String>;

/// Hops followed at most (the reference's `max_hops`).
pub const MAX_HOPS: usize = 4;
/// Largest response accepted, enforced here too in case a fetcher doesn't.
pub const MAX_RESPONSE: usize = 1024 * 1024;

fn is_http(u: &str) -> bool {
    let l = u.trim().to_ascii_lowercase();
    l.starts_with("http://") || l.starts_with("https://")
}

fn scheme(u: &str) -> String {
    match u.split_once(':') {
        Some((s, _)) if !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c)) => format!("{}:", s.to_ascii_lowercase()),
        _ => "an unknown scheme".into(),
    }
}

/// Returns a human log, one line per action (shown under "Fetch missing chain").
pub fn complete_chain(b: &mut Bundle, fetch: Fetch) -> Vec<String> {
    let mut log = Vec::new();
    for _ in 0..MAX_HOPS {
        // Only the chain's shape is used here; the clock doesn't affect it.
        let an = crate::analyze::analyze(b, "", "", 0);
        let Some(leaf) = &an.leaf else {
            log.push("No server certificate to start from.".into());
            break;
        };
        let top = an.intermediates.last().unwrap_or(leaf).clone();
        if an.root.is_some() || crate::analyze::self_signed(&top) {
            log.push("Chain is complete.".into());
            break;
        }
        if top.aia_ca_issuers.is_empty() {
            log.push(format!("\"{}\" has no CA Issuers URL to follow; ask the CA for its intermediate/root bundle.", top.cn));
            break;
        }
        let mut got = false;
        let mut tried_http = false;
        let mut skipped: Vec<String> = Vec::new();
        for u in &top.aia_ca_issuers {
            if !is_http(u) {
                log.push(format!("Skipped {u}: only http and https CA Issuers URLs can be fetched."));
                let s = scheme(u);
                if !skipped.contains(&s) { skipped.push(s); }
                continue;
            }
            tried_http = true;
            let body = match fetch(u) {
                Ok(b) if b.len() > MAX_RESPONSE => { log.push(format!("{u}: the response is larger than 1 MiB, so it isn't a certificate.")); continue; }
                Ok(b) => b,
                Err(e) => { log.push(format!("{u}: {e}")); continue; }
            };
            let mut tmp = Bundle::default();
            let rep = parse_one(u, &body, &Passwords::default(), &mut tmp);
            if tmp.certs.is_empty() {
                log.push(format!("{u}: no certificate in the response (it read as {}).", rep.format));
                continue;
            }
            let have: std::collections::HashSet<String> = b.certs.iter().map(|c| c.fp256_hex()).collect();
            let mut added = 0;
            for mut c in tmp.certs {
                if have.contains(&c.fp256_hex()) || b.certs.iter().any(|x| x.fp256_hex() == c.fp256_hex()) { continue; }
                c.source = format!("fetched from {u}");
                log.push(format!("Fetched \"{}\" from {u}", c.cn));
                b.certs.push(c);
                added += 1;
            }
            if added > 0 {
                got = true;
                break;
            }
            log.push(format!("{u}: nothing new (the certificate there is already in the set)."));
        }
        if !tried_http && !skipped.is_empty() {
            log.push(format!(
                "\"{}\" only offers CA Issuers URLs that can't be fetched from here ({}). Export the full chain from the issuing \
                 Windows CA (for example certutil -ca.chain, or the CA's web enrollment page), or ask the CA for its bundle.",
                top.cn, skipped.join(", ")));
            break;
        }
        if !got {
            log.push("Nothing new could be fetched.".into());
            break;
        }
    }
    log
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::{parse_files, InputFile};
    use std::cell::RefCell;

    fn corpus(f: &str) -> Vec<u8> {
        let p: std::path::PathBuf = [env!("CARGO_MANIFEST_DIR"), "..", "..", "fixtures", "corpus", f].iter().collect();
        std::fs::read(p).unwrap()
    }
    fn bundle(files: &[&str]) -> Bundle {
        let f: Vec<InputFile> = files.iter().map(|n| InputFile { name: n.to_string(), data: corpus(n) }).collect();
        parse_files(&f, &Passwords::default())
    }
    /// Serves fixtures/corpus like make-cases.py's http server, and records every URL asked for.
    fn run(files: &[&str]) -> (Bundle, Vec<String>, Vec<String>) {
        let asked = RefCell::new(Vec::new());
        let fetch = |u: &str| -> Result<Vec<u8>, String> {
            asked.borrow_mut().push(u.to_string());
            assert!(is_http(u), "fetch called with {u}");
            std::fs::read([env!("CARGO_MANIFEST_DIR"), "..", "..", "fixtures", "corpus", u.rsplit('/').next().unwrap()].iter().collect::<std::path::PathBuf>())
                .map_err(|_| "HTTP 404".to_string())
        };
        let mut b = bundle(files);
        let log = complete_chain(&mut b, &fetch);
        (b, log, asked.into_inner())
    }

    #[test]
    fn ldap_first_is_skipped_and_logged() {
        let (b, log, asked) = run(&["leaf-aia-ldap-first.crt", "leaf.key"]);
        assert_eq!(asked, ["http://127.0.0.1:18080/aia-int.der", "http://127.0.0.1:18080/aia-root.cer"]);
        assert!(log[0].starts_with("Skipped ldap:///CN=Cust%20AIA%20Issuing") && log[0].ends_with("only http and https CA Issuers URLs can be fetched."), "{log:?}");
        assert_eq!(&log[1..], ["Fetched \"Cust AIA Issuing\" from http://127.0.0.1:18080/aia-int.der",
                               "Fetched \"Cust AIA Root\" from http://127.0.0.1:18080/aia-root.cer", "Chain is complete."]);
        assert_eq!(b.certs.len(), 3);
        assert_eq!(b.certs[1].source, "fetched from http://127.0.0.1:18080/aia-int.der");
    }

    #[test]
    fn ldap_only_gives_the_windows_ca_advice() {
        let (b, log, asked) = run(&["leaf-aia-ldap-only.crt", "leaf.key"]);
        assert!(asked.is_empty());
        assert_eq!(log.len(), 2, "{log:?}");
        assert!(log[0].starts_with("Skipped ldap:"));
        assert!(log[1].starts_with("\"m.cust.test\" only offers CA Issuers URLs that can't be fetched from here (ldap:). Export the full chain from the issuing Windows CA"), "{}", log[1]);
        assert!(log[1].ends_with("or ask the CA for its bundle."));
        assert_eq!(b.certs.len(), 1);
        let an = crate::analyze::analyze(&b, "", "", 0);
        assert!(an.to_json().can_fetch_chain);
    }

    #[test]
    fn pem_response_and_a_failing_first_url() {
        let (b, log, _) = run(&["leaf-aia-pem.crt", "leaf.key"]);
        assert_eq!(log[0], "Fetched \"Cust AIA Issuing\" from http://127.0.0.1:18080/aia-int.crt");
        assert_eq!(b.certs.len(), 3);
        let (b, log, asked) = run(&["leaf-aia-fallback.crt", "leaf.key"]);
        assert_eq!(log[0], "http://127.0.0.1:18080/aia-missing.der: HTTP 404");
        assert_eq!(log[1], "Fetched \"Cust AIA Issuing\" from http://127.0.0.1:18080/aia-int.der");
        assert_eq!(asked.len(), 3);
        assert_eq!(b.certs.len(), 3);
    }

    #[test]
    fn a_hop_that_adds_nothing_stops_the_walk() {
        // The response is the leaf itself (an AIA pointing back at the same certificate): one try, then stop.
        let mut b = bundle(&["leaf-aia-pem.crt", "leaf.key"]);
        let calls = RefCell::new(0);
        let leaf = corpus("leaf-aia-pem.crt");
        let fetch = |_: &str| -> Result<Vec<u8>, String> { *calls.borrow_mut() += 1; Ok(leaf.clone()) };
        let log = complete_chain(&mut b, &fetch);
        assert_eq!(*calls.borrow(), 1);
        assert_eq!(log, ["http://127.0.0.1:18080/aia-int.crt: nothing new (the certificate there is already in the set).", "Nothing new could be fetched."]);
        // Garbage and oversized responses are logged, never fatal.
        let mut b = bundle(&["leaf-aia-pem.crt", "leaf.key"]);
        let log = complete_chain(&mut b, &|_| Ok(b"<html>not found</html>".to_vec()));
        assert!(log[0].contains("no certificate in the response"), "{log:?}");
        let log = complete_chain(&mut b, &|_| Ok(vec![0u8; MAX_RESPONSE + 1]));
        assert!(log[0].contains("larger than 1 MiB"), "{log:?}");
    }

    #[test]
    fn hops_are_capped() {
        // Every fetch returns a certificate not seen before but unrelated to the chain, so each hop "adds
        // something" and the top never changes: only MAX_HOPS ends the walk.
        let unrelated = ["other.crt", "root.crt", "ec-root.crt", "pss-root.crt", "aia-root.crt", "ed448-root.crt"];
        let n = RefCell::new(0usize);
        let fetch = |_: &str| -> Result<Vec<u8>, String> { let i = *n.borrow(); *n.borrow_mut() += 1; Ok(corpus(unrelated[i])) };
        let mut b = bundle(&["leaf-aia-pem.crt", "leaf.key"]);
        let log = complete_chain(&mut b, &fetch);
        assert_eq!(*n.borrow(), MAX_HOPS, "{log:?}");
        assert_eq!(b.certs.len(), 1 + MAX_HOPS);
    }
}
