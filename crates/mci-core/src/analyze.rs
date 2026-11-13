//! morpheus-certificate-install 0.4.0 — chain building and checks. **Round 1, R2.**
//!
//! Port of reference certs.analyze(), CertInfo.summary() and Analysis.to_json(). Leaf = the cert
//! whose SPKI equals the key's (else the first non-CA cert). Walk issuers by Name equality (parsed
//! attributes, as cryptography compares Names) AND signature verification ([`sig::verify`]), up to
//! 10 hops; a self-signed parent is the root. Check texts and levels are the reference's, word for
//! word (the UI shows them); intentional divergences are in docs/PARITY.md:
//! - an unusable extra input (a PVK) is a warning when the leaf and its key are there (1);
//! - RSA-PSS is verified (6); Ed448 isn't (7);
//! - when an issuer is supplied but its signature algorithm can't be checked, the warning says
//!   which certificate and which algorithm instead of "an issuer that wasn't supplied" (13).
//!
//! `now` is Unix seconds, passed in so results don't depend on the day the tests run.

pub mod sig;

use crate::model::{AnalysisJson, Bundle, Cert, CertSummary, Check, FileReport, Level};
use sig::Verdict;

pub struct Analysis {
    pub leaf: Option<Cert>,
    pub intermediates: Vec<Cert>,
    pub root: Option<Cert>,
    pub extra: Vec<Cert>,
    pub key_pkcs8: Option<Vec<u8>>,
    pub key_desc: Option<String>,
    pub checks: Vec<Check>,
    pub fqdn: String,
    pub reports: Vec<FileReport>,
    /// The instant the analysis was made for (Unix seconds); summaries count days from it.
    pub now: i64,
}

impl Analysis {
    pub fn ok(&self) -> bool {
        self.leaf.is_some() && self.key_pkcs8.is_some() && !self.checks.iter().any(|c| c.level == Level::Error)
    }
    /// Root first, then intermediates — truststore import order.
    pub fn ca_certs(&self) -> Vec<&Cert> {
        self.root.iter().chain(self.intermediates.iter()).collect()
    }
    /// Leaf + intermediates (+ root): what nginx serves.
    pub fn fullchain_pem(&self, include_root: bool) -> String {
        let mut s = String::new();
        if let Some(l) = &self.leaf { s.push_str(&l.pem()); }
        for i in &self.intermediates { s.push_str(&i.pem()); }
        if include_root { if let Some(r) = &self.root { s.push_str(&r.pem()); } }
        s
    }
    pub fn key_pem(&self) -> Option<String> {
        self.key_pkcs8.as_ref().map(|d| pem_encode("PRIVATE KEY", d))
    }
    /// The reference's `Analysis.to_json()`: the UI's contract.
    pub fn to_json(&self) -> AnalysisJson {
        let mut chain = Vec::new();
        if let Some(l) = &self.leaf { chain.push(summary(l, "server", self.now)); }
        chain.extend(self.intermediates.iter().map(|i| summary(i, "intermediate", self.now)));
        if let Some(r) = &self.root { chain.push(summary(r, "root", self.now)); }
        let can_fetch_chain = match &self.leaf {
            Some(l) => self.root.is_none() && !self_signed(l) && !self.intermediates.last().unwrap_or(l).aia_ca_issuers.is_empty(),
            None => false,
        };
        AnalysisJson {
            ok: self.ok(),
            fqdn: self.fqdn.clone(),
            file_base: if self.fqdn.is_empty() { String::new() } else { crate::names::safe_name(&self.fqdn) },
            chain,
            unused: self.extra.iter().map(|c| summary(c, "unused", self.now)).collect(),
            checks: self.checks.clone(),
            key: self.key_desc.clone(),
            ca_aliases: self.ca_certs().iter().map(|c| crate::names::alias_for(&c.cn, &c.fp256_hex())).collect(),
            inputs: self.reports.clone(),
            can_fetch_chain,
        }
    }
}

/// Python's `timedelta.days` for a difference in seconds: rounds towards negative infinity.
pub fn days(seconds: i64) -> i64 { seconds.div_euclid(86_400) }

/// (year, month, day, hour, minute, second) in UTC for Unix seconds (proleptic Gregorian).
pub fn civil(t: i64) -> (i64, u32, u32, u32, u32, u32) {
    let (d, s) = (t.div_euclid(86_400), t.rem_euclid(86_400));
    // Howard Hinnant's days_from_civil inverse.
    let z = d + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
    (year, month, day, (s / 3600) as u32, (s % 3600 / 60) as u32, (s % 60) as u32)
}

/// `datetime.isoformat()` of an aware UTC datetime with whole seconds: `2027-12-07T06:12:06+00:00`.
pub fn iso(t: i64) -> String {
    let (y, mo, d, h, mi, s) = civil(t);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}+00:00")
}

/// `%Y-%m-%d`.
pub fn ymd(t: i64) -> String {
    let (y, mo, d, ..) = civil(t);
    format!("{y:04}-{mo:02}-{d:02}")
}

/// Is `c` self-signed (subject == issuer, and its own key verifies it)?
pub fn self_signed(c: &Cert) -> bool {
    c.self_issued() && sig::verify(&c.der, &c.spki_der) == Verdict::Valid
}

/// Does `parent`'s public key verify `child`'s signature? (RSA PKCS#1 v1.5 and PSS, ECDSA, Ed25519.)
pub fn signed_by(child: &Cert, parent: &Cert) -> bool {
    sig::verify(&child.der, &parent.spki_der) == Verdict::Valid
}

/// `CertInfo.summary(role)` at `now`.
pub fn summary(c: &Cert, role: &str, now: i64) -> CertSummary {
    CertSummary {
        role: role.to_string(),
        cn: c.cn.clone(),
        subject: c.subject.clone(),
        issuer: c.issuer.clone(),
        san_dns: c.san_dns.clone(),
        san_ip: c.san_ip.clone(),
        not_before: iso(c.not_before),
        not_after: iso(c.not_after),
        days_left: days(c.not_after - now),
        lifetime_days: days(c.not_after - c.not_before).max(1),
        used_days: days(now - c.not_before),
        is_ca: c.is_ca,
        self_signed: self_signed(c),
        sha256: c.fp256(),
        sig_alg: if c.sig_hash.is_empty() { "?".into() } else { c.sig_hash.clone() },
        key: c.key_desc.clone(),
        source: c.source.clone(),
    }
}

/// `urlparse(url if "://" in url else "https://" + url).hostname or ""`.
fn url_host(url: &str) -> String {
    let rest = match url.find("://") { Some(i) => &url[i + 3..], None => url };
    let netloc = rest.split(['/', '?', '#']).next().unwrap_or("");
    let hostport = netloc.rsplit('@').next().unwrap_or("");
    let host = if let Some(r) = hostport.strip_prefix('[') {
        r.split(']').next().unwrap_or("")
    } else {
        hostport.split(':').next().unwrap_or("")
    };
    host.to_lowercase()
}

/// `appliance_url` may be empty; `fqdn` empty means "derive from the leaf" as the reference does.
/// `now` is Unix seconds.
pub fn analyze(b: &Bundle, fqdn: &str, appliance_url: &str, now: i64) -> Analysis {
    analyze_with_hosts(b, fqdn, appliance_url, now, &[])
}

/// For a wildcard leaf, the name to suggest as the FQDN: from the appliance's own names (`hosts`,
/// best first — the app passes preflight's `hostname -f`), the first non-wildcard one the
/// certificate covers: the name itself, else its first label + the domain of each wildcard SAN.
pub fn wildcard_suggestion(hosts: &[String], dns: &[String], ips: &[String]) -> Option<String> {
    let mut cands = Vec::new();
    for h in hosts {
        let h = h.trim().trim_end_matches('.').to_lowercase();
        if h.is_empty() || h.contains('*') { continue; }
        if h.contains('.') { cands.push(h.clone()); }
        let short = h.split('.').next().unwrap_or("").to_string();
        for d in dns {
            if let Some(domain) = d.to_lowercase().strip_prefix("*.") {
                cands.push(format!("{short}.{domain}"));
            }
        }
    }
    cands.into_iter().find(|c| !c.contains('*') && crate::names::host_matches(c, dns, ips))
}

/// [`analyze`], knowing the appliance's own names (`hosts`, e.g. preflight's `hostname -f`): used
/// only to suggest an FQDN for a wildcard certificate.
pub fn analyze_with_hosts(b: &Bundle, fqdn: &str, appliance_url: &str, now: i64, hosts: &[String]) -> Analysis {
    let mut checks: Vec<Check> = Vec::new();
    let chk = |checks: &mut Vec<Check>, level: Level, text: String| checks.push(Check { level, text });
    let mut fqdn = fqdn.to_string();
    let key_pkcs8 = b.key.as_ref().map(|k| k.pkcs8_der.clone());
    let key_desc = b.key.as_ref().map(|k| k.desc.clone());
    let done = |checks, leaf, intermediates, root, extra, fqdn| Analysis {
        leaf, intermediates, root, extra, key_pkcs8: key_pkcs8.clone(), key_desc: key_desc.clone(), checks, fqdn,
        reports: b.reports.clone(), now,
    };

    // Problems from parsing come first. Those from inputs that are explained but not used (a PVK)
    // may be downgraded below, once we know whether the rest of the set is complete.
    let unusable: Vec<String> = b.reports.iter().filter(|r| r.kind == "pvk").map(|r| format!("{}: ", r.name)).collect();
    let mut extra_input_problems = Vec::new();
    for (lvl, p) in &b.problems {
        if unusable.iter().any(|u| p.starts_with(u)) { extra_input_problems.push(checks.len()); }
        chk(&mut checks, *lvl, p.clone());
    }

    if b.certs.is_empty() {
        chk(&mut checks, Level::Error, "No certificates found. Add the server certificate (and the CA bundle if it came separately).".into());
        return done(checks, None, vec![], None, vec![], fqdn);
    }

    // Leaf: the cert whose public key matches the private key; otherwise the first non-CA cert.
    let mut leaf_idx: Option<usize> = None;
    match &b.key {
        Some(k) => {
            leaf_idx = b.certs.iter().position(|c| c.spki_der == k.spki_der);
            if leaf_idx.is_none() {
                chk(&mut checks, Level::Error, "The private key does not match any of the certificates supplied. nginx will refuse to start with a mismatched pair.".into());
            }
        }
        None => chk(&mut checks, Level::Error, "No private key found. Add the .key file (or a PFX that contains it).".into()),
    }
    let key_matches_leaf = leaf_idx.is_some();
    if leaf_idx.is_none() {
        leaf_idx = b.certs.iter().position(|c| !c.is_ca);
    }
    let Some(li) = leaf_idx else {
        chk(&mut checks, Level::Error, "Every certificate supplied is a CA certificate — the server certificate is missing.".into());
        return done(checks, None, vec![], None, b.certs.clone(), fqdn);
    };
    let leaf = b.certs[li].clone();

    // Divergence 1: with the leaf and its key in hand, a PVK alongside is only a warning.
    if key_matches_leaf {
        for i in extra_input_problems { checks[i].level = Level::Warn; }
    }

    // Walk issuers: Name match + signature verification.
    let mut pool: Vec<Cert> = b.certs.iter().enumerate().filter(|(i, _)| *i != li).map(|(_, c)| c.clone()).collect();
    let mut chain: Vec<Cert> = Vec::new();
    let mut root: Option<Cert> = None;
    let mut cant_verify: Option<(String, String)> = None; // (cn, algorithm)
    let leaf_self_signed = self_signed(&leaf);
    let mut cur = leaf.clone();
    for _ in 0..10 {
        if self_signed(&cur) { break; }
        if cur.self_issued() {
            if let Verdict::Unsupported(alg) = sig::verify(&cur.der, &cur.spki_der) {
                cant_verify = Some((cur.cn.clone(), alg));
                break;
            }
        }
        let mut found = None;
        let mut unsupported = None;
        for (i, p) in pool.iter().enumerate() {
            if p.subject_name != cur.issuer_name { continue; }
            match sig::verify(&cur.der, &p.spki_der) {
                Verdict::Valid => { found = Some(i); break; }
                Verdict::Unsupported(alg) => { unsupported.get_or_insert(alg); }
                Verdict::Invalid => {}
            }
        }
        let Some(i) = found else {
            if let Some(alg) = unsupported { cant_verify = Some((cur.cn.clone(), alg)); }
            break;
        };
        let parent = pool.remove(i);
        if self_signed(&parent) {
            root = Some(parent);
            break;
        }
        chain.push(parent.clone());
        cur = parent;
    }
    let extra = pool;

    if leaf_self_signed {
        chk(&mut checks, Level::Warn, "The server certificate is self-signed — browsers won't trust it without importing it.".into());
    } else if let (None, Some((cn, alg))) = (&root, &cant_verify) {
        chk(&mut checks, Level::Warn, format!(
            "The issuer of \"{cn}\" was supplied, but \"{cn}\" is signed with {alg}, which this app can't verify — \
             so the chain stops there. Check the chain with another tool, or ask the CA for an RSA or ECDSA chain."));
    } else if let Some(r) = &root {
        chk(&mut checks, Level::Ok, format!("Chain complete: server → {} intermediate(s) → root \"{}\".", chain.len(), r.cn));
    } else {
        let last = chain.last().unwrap_or(&leaf);
        chk(&mut checks, Level::Warn, format!(
            "The chain stops at an issuer that wasn't supplied: {}. Fine for a public CA (browsers already have the root); \
             for a private CA, add the root so it can be trusted and verified{}",
            last.issuer, if last.aia_ca_issuers.is_empty() { "." } else { " — or use Fetch missing chain." }));
    }
    if chain.is_empty() && root.is_none() && !leaf_self_signed && cant_verify.is_none() {
        chk(&mut checks, Level::Warn, "No intermediate certificates supplied. If your CA uses an intermediate, nginx must serve it or clients will fail to verify.".into());
    }
    if !extra.is_empty() {
        chk(&mut checks, Level::Warn, format!("{} certificate(s) supplied that aren't part of this chain; they'll be ignored.", extra.len()));
    }
    if let Some(k) = &b.key {
        if k.spki_der == leaf.spki_der {
            chk(&mut checks, Level::Ok, "Private key matches the server certificate.".into());
            if k.was_encrypted {
                chk(&mut checks, Level::Ok, "Key was encrypted; a decrypted copy will be written (Morpheus requires it), root-only readable.".into());
            }
        }
    }

    let roles: Vec<(&Cert, &str)> = std::iter::once((&leaf, "Server certificate"))
        .chain(chain.iter().map(|c| (c, "Intermediate")))
        .chain(root.iter().map(|r| (r, "Root")))
        .collect();
    for (c, role) in roles {
        if c.not_before > now {
            chk(&mut checks, Level::Error, format!("{role} \"{}\" isn't valid until {}.", c.cn, ymd(c.not_before)));
        } else if c.not_after < now {
            chk(&mut checks, Level::Error, format!("{role} \"{}\" expired on {}.", c.cn, ymd(c.not_after)));
        } else if days(c.not_after - now) < 30 {
            chk(&mut checks, Level::Warn, format!("{role} \"{}\" expires in {} days.", c.cn, days(c.not_after - now)));
        }
        let is_root = root.as_ref().is_some_and(|r| std::ptr::eq(r, c));
        if (c.sig_hash == "sha1" || c.sig_hash == "md5") && !is_root {
            chk(&mut checks, Level::Warn, format!("{role} \"{}\" is signed with {}; modern clients reject it.", c.cn, c.sig_hash.to_uppercase()));
        }
    }
    if let Some(bits) = leaf.rsa_bits {
        if bits < 2048 {
            chk(&mut checks, Level::Error, format!("RSA {bits} key is too small; use 2048 or larger."));
        }
    }

    let (dns, ips) = (&leaf.san_dns, &leaf.san_ip);
    if dns.is_empty() && ips.is_empty() {
        chk(&mut checks, Level::Warn, "The certificate has no Subject Alternative Names. Browsers ignore the CN; they'll reject it.".into());
    }
    if fqdn.is_empty() {
        let from_san = match dns.first() {
            Some(d) if !d.starts_with("*.") => d.trim_start_matches(['*', '.']).to_string(),
            _ => String::new(),
        };
        fqdn = if from_san.is_empty() { leaf.cn.clone() } else { from_san };
    }
    // A wildcard is never the FQDN (verify, SNI, file names, INSTALL.txt): PARITY divergence 27.
    // Suggest the appliance's own name when the caller knows it and the certificate covers it.
    if fqdn.contains('*') {
        fqdn = String::new();
        match wildcard_suggestion(hosts, dns, ips) {
            Some(s) => {
                chk(&mut checks, Level::Warn, format!(
                    "Wildcard certificate: using {s}, the appliance's own name. Enter the FQDN Morpheus is reached by if that's a different one."));
                fqdn = s;
            }
            None => chk(&mut checks, Level::Error, "Wildcard certificate: enter the appliance's FQDN.".into()),
        }
    }
    if !fqdn.is_empty() {
        if crate::names::host_matches(&fqdn, dns, ips) {
            chk(&mut checks, Level::Ok, format!("Covers {fqdn}."));
        } else {
            let all: Vec<&str> = dns.iter().chain(ips.iter()).map(String::as_str).collect();
            chk(&mut checks, Level::Error, format!("The certificate does not cover {fqdn}. SANs: {}.", if all.is_empty() { "none".to_string() } else { all.join(", ") }));
        }
    }
    if !appliance_url.is_empty() {
        let host = url_host(appliance_url);
        if !host.is_empty() && !crate::names::host_matches(&host, dns, ips) {
            chk(&mut checks, Level::Warn, format!(
                "Morpheus' Appliance URL uses {host}, which this certificate doesn't cover. Hosts, agents and browsers that use \
                 that URL will see a name mismatch. Either add it as a SAN or change the Appliance URL to the FQDN (agents follow \
                 that setting — plan it)."));
        } else if !host.is_empty() {
            chk(&mut checks, Level::Ok, format!("Appliance URL host {host} is covered."));
        }
    }

    done(checks, Some(leaf), chain, root, extra, fqdn)
}

/// Lowercase hex SHA-256, no separators.
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write;
    Sha256::digest(data).iter().fold(String::with_capacity(64), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}
pub fn sha256_colon(data: &[u8]) -> String {
    sha256_hex(data).to_uppercase().as_bytes().chunks(2).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join(":")
}

/// PEM with 64-column base64 lines and a trailing newline (what Python's cryptography emits).
pub fn pem_encode(label: &str, der: &[u8]) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut s = String::with_capacity(b64.len() + b64.len() / 64 + 2 * label.len() + 40);
    s.push_str("-----BEGIN ");
    s.push_str(label);
    s.push_str("-----\n");
    for line in b64.as_bytes().chunks(64) {
        s.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        s.push('\n');
    }
    s.push_str("-----END ");
    s.push_str(label);
    s.push_str("-----\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::{parse_files, InputFile, Passwords};

    fn corpus(f: &str) -> Vec<u8> {
        let p: std::path::PathBuf = [env!("CARGO_MANIFEST_DIR"), "..", "..", "fixtures", "corpus", f].iter().collect();
        std::fs::read(p).unwrap()
    }
    fn bundle(files: &[&str]) -> Bundle {
        let f: Vec<InputFile> = files.iter().map(|n| InputFile { name: n.to_string(), data: corpus(n) }).collect();
        parse_files(&f, &Passwords::default())
    }

    #[test]
    fn sha256_known_vectors() {
        assert_eq!(sha256_hex(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(sha256_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(&sha256_colon(b"abc")[..11], "BA:78:16:BF");
    }

    #[test]
    fn leaf_fingerprint_matches_cases_json() {
        // fixtures/cases.json → pem-set-plain → expect.leaf_sha256 (read, not copied: the corpus is regenerated)
        let p: std::path::PathBuf = [env!("CARGO_MANIFEST_DIR"), "..", "..", "fixtures", "cases.json"].iter().collect();
        let cases: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
        let case = cases["cases"].as_array().unwrap().iter().find(|c| c["name"] == "pem-set-plain").unwrap();
        assert_eq!(sha256_colon(&corpus("leaf.cer")), case["expect"]["leaf_sha256"].as_str().unwrap());
    }

    #[test]
    fn pem_encode_round_trips_the_reference_bytes() {
        // leaf.cer is the DER of leaf.crt; both written by OpenSSL, the same layout cryptography emits.
        for (der, pem) in [("leaf.cer", "leaf.crt"), ("int.der", "int.crt")] {
            let want = String::from_utf8(corpus(pem)).unwrap();
            assert_eq!(pem_encode("CERTIFICATE", &corpus(der)), want, "{pem}");
        }
    }

    #[test]
    fn pem_encode_line_shape() {
        assert_eq!(pem_encode("X", &[]), "-----BEGIN X-----\n-----END X-----\n");
        // 48 bytes → exactly one 64-char line; 49 → a 64-char line and a 4-char line.
        let one = pem_encode("X", &[0u8; 48]);
        assert_eq!(one.lines().nth(1).unwrap().len(), 64);
        assert_eq!(one.lines().count(), 3);
        let two = pem_encode("X", &[0u8; 49]);
        assert_eq!(two.lines().map(str::len).collect::<Vec<_>>(), vec![17, 64, 4, 15]);
        assert!(two.ends_with("-----END X-----\n"));
    }

    #[test]
    fn days_round_towards_negative_infinity_like_timedelta() {
        assert_eq!(days(86_399), 0);
        assert_eq!(days(86_400), 1);
        assert_eq!(days(-1), -1); // timedelta(seconds=-1).days == -1
        assert_eq!(days(-86_400), -1);
        assert_eq!(days(-86_401), -2);
    }

    #[test]
    fn civil_dates() {
        assert_eq!(iso(0), "1970-01-01T00:00:00+00:00");
        assert_eq!(iso(951_782_400), "2000-02-29T00:00:00+00:00");
        assert_eq!(iso(1_767_225_600), "2026-01-01T00:00:00+00:00");
        assert_eq!(ymd(4_102_444_799), "2099-12-31");
    }

    #[test]
    fn expired_certificate() {
        let b = bundle(&["leaf.crt", "leaf.key", "bundle.crt"]);
        let leaf = b.certs[0].clone();
        // 10.5 days after the leaf expired.
        let now = leaf.not_after + 10 * 86_400 + 43_200;
        let an = analyze(&b, "", "", now);
        assert!(!an.ok());
        assert!(an.checks.iter().any(|c| c.level == Level::Error && c.text == format!("Server certificate \"m.cust.test\" expired on {}.", ymd(leaf.not_after))));
        let s = summary(&leaf, "server", now);
        assert_eq!(s.days_left, -11); // -10.5 days → -11, as Python's timedelta.days
        assert_eq!(s.used_days, days(now - leaf.not_before));
        // And one second before expiry: 0 days left, a warning, not an error.
        let an = analyze(&b, "", "", leaf.not_after - 1);
        assert!(an.checks.iter().any(|c| c.level == Level::Warn && c.text == "Server certificate \"m.cust.test\" expires in 0 days."));
        assert_eq!(summary(&leaf, "server", leaf.not_after - 1).days_left, 0);
        // Not yet valid.
        let an = analyze(&b, "", "", leaf.not_before - 1);
        assert!(an.checks.iter().any(|c| c.level == Level::Error && c.text.contains("isn't valid until")));
    }

    #[test]
    fn signature_algorithms() {
        let c = |f: &str| bundle(&[f]).certs.remove(0);
        let (int, root) = (c("int.crt"), c("root.crt"));
        for f in ["leaf.crt", "leaf-sha384.crt", "leaf-sha512.crt"] { assert!(signed_by(&c(f), &int), "{f}"); }
        assert!(!signed_by(&c("leaf.crt"), &root));
        assert!(signed_by(&c("ec-sha384.crt"), &c("ec-root.crt")));
        assert!(self_signed(&c("ec-root.crt")));
        let (pi, pr) = (c("pss-int.crt"), c("pss-root.crt"));
        assert!(signed_by(&c("leaf-pss.crt"), &pi));
        assert!(signed_by(&pi, &pr));
        assert!(self_signed(&pr));
        assert!(!signed_by(&c("leaf-pss.crt"), &pr));
        assert!(!signed_by(&c("ec-sha384.crt"), &int)); // EC sig, RSA key
    }

    #[test]
    fn url_hosts() {
        assert_eq!(url_host("https://10.0.0.5/"), "10.0.0.5");
        assert_eq!(url_host("M.Cust.Test:8443/x"), "m.cust.test");
        assert_eq!(url_host("https://user@[fe80::1]:443/"), "fe80::1");
        assert_eq!(url_host("https://"), "");
    }
}

#[cfg(test)]
mod wildcard_tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> { v.iter().map(|x| x.to_string()).collect() }

    #[test]
    fn suggestion_prefers_the_full_hostname_then_short_name_plus_wildcard_domain() {
        let dns = s(&["*.wild.test", "wild.test"]);
        assert_eq!(wildcard_suggestion(&s(&["morpheus.wild.test"]), &dns, &[]).as_deref(), Some("morpheus.wild.test"));
        // hostname -f in another domain: short name + the wildcard's domain
        assert_eq!(wildcard_suggestion(&s(&["morpheus.corp.internal"]), &dns, &[]).as_deref(), Some("morpheus.wild.test"));
        assert_eq!(wildcard_suggestion(&s(&["MORPHEUS"]), &dns, &[]).as_deref(), Some("morpheus.wild.test"));
        // a wildcard covers one level only, so a.b.wild.test isn't covered; its short name is
        assert_eq!(wildcard_suggestion(&s(&["a.b.wild.test"]), &dns, &[]).as_deref(), Some("a.wild.test"));
        assert_eq!(wildcard_suggestion(&[], &dns, &[]), None);
        assert_eq!(wildcard_suggestion(&s(&["", "*.wild.test"]), &dns, &[]), None);
    }

    #[test]
    fn a_wildcard_leaf_gets_the_suggestion_when_connected_and_an_error_otherwise() {
        let corpus = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/corpus");
        let rd = |n: &str| crate::formats::InputFile { name: n.into(), data: std::fs::read(corpus.join(n)).unwrap() };
        let b = crate::formats::parse_files(&[rd("leaf-wildcard.crt"), rd("leaf-wildcard.key"), rd("wildcard-root.crt")], &Default::default());
        let now = b.certs[0].not_before + 86_400;
        let an = analyze_with_hosts(&b, "", "", now, &s(&["morpheus.lab.local"]));
        assert_eq!(an.fqdn, "morpheus.wild.test");
        assert!(an.ok(), "{:?}", an.checks);
        assert!(an.checks.iter().any(|c| c.level == Level::Warn && c.text.starts_with("Wildcard certificate: using morpheus.wild.test")));
        assert!(an.checks.iter().any(|c| c.text == "Covers morpheus.wild.test."));
        let an = analyze_with_hosts(&b, "*.wild.test", "", now, &[]);
        assert_eq!((an.fqdn.as_str(), an.ok()), ("", false));
        assert!(an.to_json().file_base.is_empty());
        let an = analyze_with_hosts(&b, "elsewhere.example.com", "", now, &s(&["morpheus.wild.test"]));
        assert!(!an.ok(), "a typed FQDN the certificate doesn't cover is still an error");
    }
}
