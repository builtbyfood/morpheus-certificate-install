//! morpheus-certificate-install 0.4.2 — read whatever a CA or customer sends. **Round 1, R1.**
//!
//! Port of reference/python/morpheus_certificate_install/formats.py (`parse_one`, `parse_all`) and
//! certs.parse_files. Detection is by content, never by extension. Order for non-PEM input:
//! JKS/JCEKS magic → PVK magic (explain) → DER cert → DER PKCS#7 → PFX (try NULL, "", then every
//! password) → DER private key → base64 without armour (one level of recursion). PEM: every block,
//! labels CERTIFICATE / TRUSTED CERTIFICATE / X509 CERTIFICATE / PKCS7 / *PRIVATE KEY* /
//! OPENSSH PRIVATE KEY / CERTIFICATE REQUEST / X509 CRL / PUBLIC KEY. UTF-8 BOM and UTF-16 (with
//! or without BOM) are normalised first.
//!
//! Every password supplied is tried on every locked item (customers put the PFX password in the
//! key box). Keys are normalised to unencrypted PKCS#8 (`PrivateKey.pkcs8_der`) — the same bytes
//! the reference writes.
//!
//! `FileReport.format` follows the reference wording (it shows in the UI and INSTALL.txt);
//! `FileReport.kind` is derived from it exactly as fixtures/make-cases.py does:
//! pem | der-cert | pkcs7-der | pfx | pfx-locked | jks | der-key | der-key-locked | base64 | pvk | unknown
//!
//! Submodules: [`tlv`] (bounds-checked BER/DER walker), [`x509`], [`keys`], [`pbe`], [`pfx`],
//! [`p7`], [`jks`], [`openssh`].

pub mod jks;
pub mod keys;
pub mod openssh;
pub mod p7;
pub mod pbe;
pub mod pfx;
pub mod tlv;
pub mod x509;

use crate::model::{Bundle, Cert, FileReport, Level, PrivateKey};
use keys::KeyError;
use pbe::Pw;

#[derive(Clone)]
pub struct InputFile {
    pub name: String,
    pub data: Vec<u8>,
}

#[derive(Default, Clone)]
pub struct Passwords {
    pub pfx: String,
    pub key: String,
    pub extra: Vec<String>,
}

impl Passwords {
    /// Non-empty, de-duplicated, in order: pfx, key, extra.
    pub fn all(&self) -> Vec<String> {
        let mut v: Vec<String> = Vec::new();
        for p in std::iter::once(&self.pfx).chain(std::iter::once(&self.key)).chain(self.extra.iter()) {
            if !p.is_empty() && !v.contains(p) {
                v.push(p.clone());
            }
        }
        v
    }
}

const PVK_MAGIC: [u8; 4] = [0x1e, 0xf1, 0xb5, 0xb0];
const LOCKED_KEY: &str = "The private key is encrypted — enter its passphrase.";
const CONVERT_JKS: &str = "keytool -importkeystore -srckeystore in.jks -destkeystore out.p12 -deststoretype PKCS12";

/// What the inputs yielded, before de-duplication (the reference's `Parsed`).
#[derive(Default)]
struct Parsed {
    certs: Vec<Cert>,
    keys: Vec<PrivateKey>,
}

/// Parse every input into one Bundle (certs de-duplicated by SHA-256; first key wins,
/// a second different key is a warning). One FileReport per input, in input order.
pub fn parse_files(files: &[InputFile], pw: &Passwords) -> Bundle {
    let pws = pw.all();
    let mut parsed = Parsed::default();
    let mut b = Bundle::default();
    for f in files {
        let r = parse_inner(&f.name, &f.data, &pws, &mut parsed, 0);
        b.reports.push(r);
    }
    let mut seen = std::collections::HashSet::new();
    for c in parsed.certs {
        if seen.insert(c.fp256_hex()) {
            b.certs.push(c);
        }
    }
    for k in parsed.keys {
        match &b.key {
            None => b.key = Some(k),
            Some(first) if first.spki_der != k.spki_der => {
                let p = format!("More than one private key supplied; using the one from {}, ignoring {}.", first.source, k.source);
                b.problems.push((problem_level(&p), p));
            }
            Some(_) => {}
        }
    }
    for r in &b.reports {
        if r.level == Level::Error {
            for n in &r.notes {
                let p = format!("{}: {n}", r.name);
                b.problems.push((problem_level(&p), p));
            }
        }
    }
    b
}

/// The level the reference's analyze() gives a bundle problem (by its wording).
pub fn problem_level(p: &str) -> Level {
    const ERR: [&str; 8] = ["encrypted", "password", "passphrase", "not recognised", "Not a certificate", "keystore", "PVK", "unreadable"];
    if ERR.iter().any(|w| p.contains(w)) { Level::Error } else { Level::Warn }
}

/// Parse a single input (used by AIA fetch, which accepts DER, PEM or PKCS#7 responses).
/// Certificates are appended as found (not de-duplicated); a key is kept only if `into` has none.
pub fn parse_one(name: &str, data: &[u8], pw: &Passwords, into: &mut Bundle) -> FileReport {
    let mut parsed = Parsed::default();
    let r = parse_inner(name, data, &pw.all(), &mut parsed, 0);
    into.certs.extend(parsed.certs);
    if into.key.is_none() {
        into.key = parsed.keys.into_iter().next();
    }
    r
}

/// make-cases.py `kind()`.
pub fn kind_of(format: &str) -> &'static str {
    let f = format.to_lowercase();
    if f.starts_with("base64 without pem headers") { return "base64"; }
    if f.starts_with("pem") { return "pem"; }
    if f.starts_with("der certificate") { return "der-cert"; }
    if f.starts_with("pkcs#7 bundle, der") { return "pkcs7-der"; }
    if f.contains("pfx") { return if f.contains("locked") { "pfx-locked" } else { "pfx" }; }
    if f.starts_with("java keystore") { return "jks"; }
    if f.contains("der private key") { return if f.contains("locked") { "der-key-locked" } else { "der-key" }; }
    if f.contains("pvk") { return "pvk"; }
    "unknown"
}

fn plural(n: u32, one: &str, many: &str) -> String { format!("{n} {}", if n == 1 { one } else { many }) }

// ------------------------------------------------------------------ text normalisation

/// Strip BOMs and turn UTF-16 text (Windows "Unicode" saves) into UTF-8 bytes.
pub fn normalize_text(data: &[u8]) -> Vec<u8> {
    fn utf16(b: &[u8], le: bool) -> Option<Vec<u8>> {
        if b.len() % 2 != 0 { return None; }
        let units: Vec<u16> = b.chunks(2).map(|c| if le { u16::from_le_bytes([c[0], c[1]]) } else { u16::from_be_bytes([c[0], c[1]]) }).collect();
        String::from_utf16(&units).ok().map(String::into_bytes)
    }
    if data.starts_with(&[0xef, 0xbb, 0xbf]) { return data[3..].to_vec(); }
    if data.starts_with(&[0xff, 0xfe]) { return utf16(&data[2..], true).unwrap_or_else(|| data.to_vec()); }
    if data.starts_with(&[0xfe, 0xff]) { return utf16(&data[2..], false).unwrap_or_else(|| data.to_vec()); }
    // UTF-16 without BOM: every other byte NUL in the first chunk.
    let head = &data[..data.len().min(200)];
    if head.len() > 20 {
        let zeros = head.iter().skip(1).step_by(2).filter(|b| **b == 0).count();
        if zeros > head.len() / 3 && head.windows(4).any(|w| w == b"-\0-\0") {
            if let Some(u) = utf16(data, true) { return u; }
        }
    }
    data.to_vec()
}

// ------------------------------------------------------------------ PEM

struct Block<'a> {
    label: String,
    /// BEGIN line through END-----, as the reference's `m.group(0)`.
    text: &'a [u8],
}

/// Every `-----BEGIN X-----\s*\r?\n … -----END X-----` block (the reference's PEM_BLOCK regex).
fn pem_blocks(data: &[u8]) -> Vec<Block<'_>> {
    const BEGIN: &[u8] = b"-----BEGIN ";
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(p) = find(&data[i..], BEGIN) {
        let start = i + p;
        let mut j = start + BEGIN.len();
        let ls = j;
        while j < data.len() && (data[j].is_ascii_uppercase() || data[j].is_ascii_digit() || data[j] == b' ') { j += 1; }
        let label = &data[ls..j];
        let ok_head = !label.is_empty() && data[j..].starts_with(b"-----");
        if !ok_head { i = start + 1; continue; }
        j += 5;
        // \s*\r?\n — whitespace containing at least one newline.
        let mut k = j;
        let mut nl = false;
        while k < data.len() && matches!(data[k], b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c) {
            nl |= data[k] == b'\n';
            k += 1;
        }
        if !nl { i = start + 1; continue; }
        let end_marker = [b"-----END ".as_slice(), label, b"-----"].concat();
        match find(&data[k..], &end_marker) {
            Some(e) => {
                let stop = k + e + end_marker.len();
                out.push(Block { label: String::from_utf8_lossy(label).into_owned(), text: &data[start..stop] });
                i = stop;
            }
            None => i = start + 1,
        }
    }
    out
}

/// The certificates in some text — `openssl s_client -showcerts` output — in order; blocks that
/// aren't certificates or don't parse are skipped (the reference's `certs_from_pem_text`).
pub fn certs_from_pem_text(text: &str, source: &str) -> Vec<Cert> {
    pem_blocks(text.as_bytes())
        .into_iter()
        .filter(|b| b.label == "CERTIFICATE")
        .filter_map(|b| pem_decode(b.text).ok())
        .filter_map(|(_, der)| x509::cert_from_der(&der, source).ok())
        .collect()
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() { return None; }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// RFC 1421 headers (name, value) of a PEM block.
type PemHeaders = Vec<(String, String)>;

/// (RFC 1421 headers, decoded body) of a PEM block.
fn pem_decode(text: &[u8]) -> Result<(PemHeaders, Vec<u8>), String> {
    use base64::Engine;
    let s = String::from_utf8_lossy(text);
    let mut lines = s.lines().skip(1); // BEGIN line
    let mut headers = Vec::new();
    let mut b64 = String::new();
    let mut in_headers = true;
    for l in lines.by_ref() {
        let l = l.trim();
        if l.starts_with("-----END ") { break; }
        if in_headers {
            if let Some((k, v)) = l.split_once(':') {
                headers.push((k.trim().to_string(), v.trim().to_string()));
                continue;
            }
            if l.is_empty() { continue; }
            in_headers = false;
        }
        b64.extend(l.chars().filter(|c| !c.is_whitespace()));
    }
    let engine = base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true)
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
    );
    engine.decode(b64.as_bytes()).map(|d| (headers, d)).map_err(|e| format!("bad base64 ({e})"))
}

fn key_label(label: &str) -> String {
    match label {
        "RSA PRIVATE KEY" => "RSA key (PKCS#1)".into(),
        "EC PRIVATE KEY" => "EC key (SEC1)".into(),
        "DSA PRIVATE KEY" => "DSA key".into(),
        "PRIVATE KEY" | "ENCRYPTED PRIVATE KEY" => "private key (PKCS#8)".into(),
        "OPENSSH PRIVATE KEY" => "OpenSSH private key".into(),
        other => other.to_lowercase(),
    }
}

/// "2× certificate", first-seen order.
fn count_kinds(kinds: &[String]) -> Vec<String> {
    let mut seen: Vec<(String, u32)> = Vec::new();
    for k in kinds {
        match seen.iter_mut().find(|(s, _)| s == k) {
            Some(e) => e.1 += 1,
            None => seen.push((k.clone(), 1)),
        }
    }
    seen.into_iter().map(|(k, n)| if n > 1 { format!("{n}× {k}") } else { k }).collect()
}

enum PemKey {
    Ok(keys::Key, bool),
    Locked,
    Failed(String),
}

/// The reference's `_try_key_pem`.
fn pem_key(label: &str, text: &[u8], pws: &[String]) -> PemKey {
    let (headers, body) = match pem_decode(text) {
        Ok(x) => x,
        Err(e) => return PemKey::Failed(e),
    };
    if label == "OPENSSH PRIVATE KEY" {
        let mut last = KeyError::NeedPassword;
        for pw in std::iter::once(None).chain(pws.iter().map(|p| Some(p.as_str()))) {
            match openssh::parse(&body, pw) {
                Ok(k) => return PemKey::Ok(k, pw.is_some()),
                Err(e @ (KeyError::NeedPassword | KeyError::WrongPassword)) => last = e,
                Err(e) => return PemKey::Failed(e.text()),
            }
        }
        let _ = last;
        return PemKey::Locked;
    }
    let legacy = headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("Proc-Type") && v.replace(' ', "").eq_ignore_ascii_case("4,ENCRYPTED"));
    if label == "ENCRYPTED PRIVATE KEY" || legacy {
        for pw in pws {
            let r = if legacy { keys::from_legacy_pem(label, &headers, &body, pw) } else { keys::from_encrypted_pkcs8(&body, Pw::Text(pw)) };
            match r {
                Ok(k) => return PemKey::Ok(k, true),
                Err(KeyError::WrongPassword | KeyError::NeedPassword) => continue,
                Err(e) => return PemKey::Failed(e.text()),
            }
        }
        return PemKey::Locked;
    }
    let r = match label {
        "PRIVATE KEY" => keys::from_pkcs8(&body),
        "RSA PRIVATE KEY" => keys::from_pkcs1(&body),
        "EC PRIVATE KEY" => keys::from_sec1(&body, None),
        "DSA PRIVATE KEY" => keys::from_dsa_traditional(&body),
        _ => keys::from_der_any(&body),
    };
    match r {
        Ok(k) => PemKey::Ok(k, false),
        Err(e) => PemKey::Failed(e.text()),
    }
}

// ------------------------------------------------------------------ the parser

struct Ctx<'a> {
    name: &'a str,
    rep: FileReport,
    out: &'a mut Parsed,
}

impl Ctx<'_> {
    fn add_cert(&mut self, c: Cert) {
        self.out.certs.push(c);
        self.rep.certs += 1;
    }
    fn cert_der(&mut self, der: &[u8], how: &str) -> Result<(), String> {
        let c = x509::cert_from_der(der, &format!("{} ({how})", self.name))?;
        self.add_cert(c);
        Ok(())
    }
    fn add_key(&mut self, k: keys::Key, enc: bool) {
        self.out.keys.push(PrivateKey { pkcs8_der: k.pkcs8, spki_der: k.spki, desc: k.desc, source: self.name.to_string(), was_encrypted: enc });
        self.rep.keys += 1;
    }
    fn error(&mut self, note: impl Into<String>) {
        self.rep.notes.push(note.into());
        self.rep.level = Level::Error;
    }
    fn done(mut self, format: impl Into<String>) -> FileReport {
        self.rep.format = format.into();
        self.rep.kind = kind_of(&self.rep.format).to_string();
        self.rep
    }
}

fn parse_inner(name: &str, raw: &[u8], pws: &[String], out: &mut Parsed, depth: u8) -> FileReport {
    let rep = FileReport { name: name.to_string(), format: "unknown".into(), kind: String::new(), certs: 0, keys: 0, notes: vec![], level: Level::Ok };
    let mut cx = Ctx { name, rep, out };
    let data = normalize_text(raw);

    let blocks = pem_blocks(&data);
    if !blocks.is_empty() {
        let mut kinds: Vec<String> = Vec::new();
        for b in &blocks {
            let label = b.label.as_str();
            if matches!(label, "CERTIFICATE" | "TRUSTED CERTIFICATE" | "X509 CERTIFICATE") {
                let r = pem_decode(b.text).and_then(|(_, der)| {
                    // TRUSTED CERTIFICATE carries OpenSSL trust settings after the certificate.
                    let first = if label == "TRUSTED CERTIFICATE" { tlv::read(&der).map(|t| t.whole.to_vec()).unwrap_or(der) } else { der };
                    cx.cert_der(&first, "PEM")
                });
                match r {
                    Ok(()) => kinds.push("certificate".into()),
                    Err(e) => { cx.rep.notes.push(format!("unreadable certificate block: {e}")); cx.rep.level = Level::Warn; }
                }
            } else if label == "PKCS7" {
                let r = pem_decode(b.text).and_then(|(_, der)| p7_certs(&der, name));
                match r {
                    Ok(cs) => {
                        let n = cs.len();
                        for c in cs { cx.add_cert(c); }
                        kinds.push(format!("PKCS#7 bundle ({n})"));
                    }
                    Err(e) => { cx.rep.notes.push(format!("unreadable PKCS#7 block: {e}")); cx.rep.level = Level::Warn; }
                }
            } else if label.contains("PRIVATE KEY") {
                match pem_key(label, b.text, pws) {
                    PemKey::Ok(k, enc) => {
                        cx.add_key(k, enc);
                        kinds.push(format!("{}{}", if enc { "encrypted " } else { "" }, key_label(label)));
                    }
                    PemKey::Locked => {
                        cx.error(LOCKED_KEY);
                        kinds.push("encrypted private key (locked)".into());
                    }
                    PemKey::Failed(e) => cx.error(format!("private key could not be read: {e}")),
                }
            } else if label.contains("CERTIFICATE REQUEST") {
                cx.rep.notes.push("This is a CSR (the request you sent to the CA), not a certificate. It isn't needed here.".into());
                if cx.rep.level == Level::Ok { cx.rep.level = Level::Warn; }
                kinds.push("CSR".into());
            } else if label == "X509 CRL" {
                cx.rep.notes.push("A revocation list (CRL) — not needed.".into());
                kinds.push("CRL".into());
            } else if label == "PUBLIC KEY" || label == "RSA PUBLIC KEY" {
                cx.rep.notes.push("A bare public key — the private key is what's needed.".into());
                kinds.push("public key".into());
            } else {
                cx.rep.notes.push(format!("Ignored a {label} block."));
            }
        }
        let f = if kinds.is_empty() { "PEM (nothing usable)".to_string() } else { format!("PEM: {}", count_kinds(&kinds).join(", ")) };
        return cx.done(f);
    }

    // ---- binary containers
    if data.starts_with(&jks::JKS_MAGIC) {
        return parse_jks(cx, &data, pws);
    }
    if data.starts_with(&jks::JCEKS_MAGIC) {
        cx.error(format!("JCEKS keystores aren't read by this version. Convert it first: {CONVERT_JKS}"));
        return cx.done("Java keystore (JCEKS)");
    }
    if data.starts_with(&PVK_MAGIC) {
        cx.error("PVK is Microsoft's legacy key format. Convert on Windows with `pvk2pfx -pvk key.pvk -spc cert.spc -pfx out.pfx`, then load the PFX.");
        return cx.done("Microsoft PVK private key");
    }

    // DER certificate
    if let Ok(c) = x509::cert_from_der(&data, &format!("{name} (DER)")) {
        cx.add_cert(c);
        return cx.done("DER certificate");
    }
    // DER PKCS#7
    if let Ok(cs) = p7_certs(&data, name) {
        let n = cs.len() as u32;
        for c in cs { cx.add_cert(c); }
        return cx.done(format!("PKCS#7 bundle, DER ({})", plural(n, "certificate", "certificates")));
    }
    // PFX / P12
    if data.first() == Some(&0x30) {
        let mut wrong_pw = false;
        let mut truncated = None;
        let tries: Vec<Pw<'_>> = [Pw::Null, Pw::Text("")].into_iter().chain(pws.iter().map(|p| Pw::Text(p))).collect();
        for pw in tries {
            match pfx::open(&data, pw) {
                Ok(c) => return pfx_report(cx, c, !matches!(pw, Pw::Null | Pw::Text(""))),
                Err(pfx::PfxError::WrongPassword) => wrong_pw = true,
                Err(pfx::PfxError::NotPfx) => break,
                Err(pfx::PfxError::Truncated { have, need }) => { truncated = Some((have, need)); break; }
                Err(pfx::PfxError::Limit(m) | pfx::PfxError::Unsupported(m) | pfx::PfxError::Damaged(m)) => {
                    cx.error(m);
                    return cx.done("PFX / PKCS#12 (unreadable)");
                }
            }
        }
        // Not a PFX we could open — maybe a DER key.
        match keys::from_der_any(&data) {
            Ok(k) => {
                cx.add_key(k, false);
                return cx.done("DER private key");
            }
            Err(KeyError::NotAKey) if keys::looks_encrypted(&data) => {
                for pw in pws {
                    match keys::from_encrypted_pkcs8(&data, Pw::Text(pw)) {
                        Ok(k) => {
                            cx.add_key(k, true);
                            return cx.done("encrypted DER private key");
                        }
                        Err(KeyError::WrongPassword | KeyError::NeedPassword | KeyError::NotAKey) => continue,
                        Err(e) => {
                            cx.error(format!("private key could not be read: {}", e.text()));
                            return cx.done("encrypted DER private key (unreadable)");
                        }
                    }
                }
                cx.error(LOCKED_KEY);
                return cx.done("encrypted DER private key (locked)");
            }
            Err(KeyError::NotAKey) => {}
            Err(e) => {
                cx.error(format!("private key could not be read: {}", e.text()));
                return cx.done("DER private key (unreadable)");
            }
        }
        let lname = name.to_lowercase();
        let pfx_name = lname.ends_with(".pfx") || lname.ends_with(".p12");
        if let (Some((have, need)), true) = (truncated, pfx_name) {
            cx.error(format!("The file is cut short: it has {have} of the {need} bytes its header promises. Copy it again, or export it again."));
            return cx.done("PFX / PKCS#12 (damaged)");
        }
        if wrong_pw || pfx_name {
            cx.error("Wrong or missing PFX password.");
            return cx.done("PFX / PKCS#12 (locked)");
        }
    }

    // Base64 with the PEM armour stripped (pasted from an email or a portal).
    if depth == 0 {
        let text: Vec<u8> = data.iter().copied().filter(|b| !matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)).collect();
        if text.len() > 100 && text.iter().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=')) {
            use base64::Engine;
            let engine = base64::engine::GeneralPurpose::new(
                &base64::alphabet::STANDARD,
                base64::engine::GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
            );
            if let Ok(inner) = engine.decode(&text) {
                if !inner.is_empty() {
                    let Ctx { out, .. } = cx;
                    let mut sub = parse_inner(name, &inner, pws, out, 1);
                    sub.format = format!("base64 without PEM headers → {}", sub.format);
                    sub.kind = kind_of(&sub.format).to_string();
                    return sub;
                }
            }
        }
    }

    cx.error("Not a certificate, key, PFX, PKCS#7 or keystore that Morpheus Certificate Install can read.");
    if data.first() == Some(&0x30) {
        if let Some(need) = tlv::declared_len(&data) {
            if need > data.len() {
                cx.rep.notes.push(format!("It looks cut short: it has {} of the {need} bytes its header promises.", data.len()));
            }
        }
    }
    cx.done("not recognised")
}

/// Every certificate of a PKCS#7, parsed; any unreadable one fails the bundle (as the reference's loader does).
fn p7_certs(der: &[u8], name: &str) -> Result<Vec<Cert>, String> {
    p7::certificates(der)?.iter().map(|d| x509::cert_from_der(d, &format!("{name} (PKCS#7)"))).collect()
}

fn pfx_report(mut cx: Ctx<'_>, c: pfx::Contents, enc: bool) -> FileReport {
    // OpenSSL's PKCS12_parse: the first key; the cert that matches it first, then the rest in bag order.
    let key = match c.keys.first().map(|k| keys::from_pkcs8(k)) {
        None => None,
        Some(Ok(k)) => Some(k),
        Some(Err(e)) => {
            cx.error(format!("The private key in this PFX can't be used: {}", e.text()));
            return cx.done("PFX / PKCS#12 (unreadable)");
        }
    };
    let mut certs = Vec::new();
    for d in &c.certs {
        match x509::cert_from_der(d, &format!("{} (PFX)", cx.name)) {
            Ok(x) => certs.push(x),
            Err(e) => {
                cx.error(format!("A certificate in this PFX can't be read: {e}"));
                return cx.done("PFX / PKCS#12 (unreadable)");
            }
        }
    }
    if let Some(k) = &key {
        if let Some(i) = certs.iter().position(|x| x.spki_der == k.spki) {
            let m = certs.remove(i);
            certs.insert(0, m);
        }
    }
    let has_key = key.is_some();
    if let Some(k) = key { cx.add_key(k, enc); }
    for x in certs { cx.add_cert(x); }
    let n = cx.rep.certs;
    let f = format!("PFX / PKCS#12 ({}, {} private key)", plural(n, "certificate", "certificates"), if has_key { "with" } else { "no" });
    if !has_key {
        cx.rep.notes.push("This PFX has no private key in it — export it again from the machine that made the CSR, with 'export the private key' ticked.".into());
        cx.rep.level = Level::Warn;
    }
    cx.done(f)
}

fn parse_jks(mut cx: Ctx<'_>, data: &[u8], pws: &[String]) -> FileReport {
    let base = "Java keystore (JKS)";
    let mut opened = None;
    for pw in pws.iter().map(String::as_str).chain(["changeit", ""]) {
        match jks::open(data, pw) {
            Ok(s) => { opened = Some((s, pw.to_string())); break; }
            Err(jks::JksError::WrongPassword) => continue,
            Err(jks::JksError::Damaged(m)) => {
                cx.error(format!("The keystore can't be read: {m}."));
                return cx.done(base);
            }
        }
    }
    let Some((store, store_pw)) = opened else {
        cx.error("Wrong keystore password (tried the passwords given and 'changeit').");
        return cx.done(base);
    };
    for e in &store.keys {
        let pk8 = pws.iter().map(String::as_str).chain([store_pw.as_str()]).find_map(|pw| jks::decrypt_key(&e.protected, pw));
        let Some(pk8) = pk8 else {
            cx.error(format!("Key entry '{}' has its own password — enter it as the key passphrase.", e.alias));
            continue;
        };
        match keys::from_pkcs8(&pk8) {
            Ok(k) => cx.add_key(k, true),
            Err(err) => { cx.rep.notes.push(format!("Key entry '{}' unreadable: {}", e.alias, err.text())); continue; }
        }
        for d in &e.chain {
            if let Err(err) = cx.cert_der(d, &format!("JKS:{}", e.alias)) {
                cx.rep.notes.push(format!("A certificate under '{}' can't be read: {err}", e.alias));
            }
        }
    }
    for (alias, d) in &store.trusted {
        let _ = cx.cert_der(d, &format!("JKS:{alias}"));
    }
    let nk = store.keys.len();
    let nt = store.trusted.len();
    cx.done(format!(
        "{base} — {nk} key entr{}, {nt} trusted cert{}",
        if nk == 1 { "y" } else { "ies" },
        if nt != 1 { "s" } else { "" }
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus(f: &str) -> Vec<u8> {
        let p: std::path::PathBuf = [env!("CARGO_MANIFEST_DIR"), "..", "..", "fixtures", "corpus", f].iter().collect();
        std::fs::read(p).unwrap()
    }

    fn one(f: &str, pfx: &str, key: &str) -> (Bundle, FileReport) {
        let b = parse_files(&[InputFile { name: f.into(), data: corpus(f) }], &Passwords { pfx: pfx.into(), key: key.into(), extra: vec![] });
        let r = b.reports[0].clone();
        (b, r)
    }

    #[test]
    fn pem_block_scanner_matches_the_regex() {
        let d = b"junk\n-----BEGIN CERTIFICATE-----   \r\nAAAA\n-----END CERTIFICATE-----\n-----BEGIN X-----no newline-----END X-----";
        let b = pem_blocks(d);
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].label, "CERTIFICATE");
        assert!(b[0].text.ends_with(b"-----END CERTIFICATE-----"));
        // END must carry the same label.
        assert!(pem_blocks(b"-----BEGIN A-----\nx\n-----END B-----").is_empty());
    }

    #[test]
    fn reference_wording() {
        assert_eq!(one("bundle.crt", "", "").1.format, "PEM: 2× certificate");
        assert_eq!(one("leaf-legacy-enc.key", "", "lg").1.format, "PEM: encrypted RSA key (PKCS#1)");
        assert_eq!(one("leaf-pkcs8-enc.key", "", "").1.format, "PEM: encrypted private key (locked)");
        assert_eq!(one("chain-der.p7b", "", "").1.format, "PKCS#7 bundle, DER (3 certificates)");
        assert_eq!(one("chain.p7b", "", "").1.format, "PEM: PKCS#7 bundle (3)");
        assert_eq!(one("modern.pfx", "pp", "").1.format, "PFX / PKCS#12 (3 certificates, with private key)");
        assert_eq!(one("nokey.pfx", "x", "").1.format, "PFX / PKCS#12 (1 certificate, no private key)");
        assert_eq!(one("keystore.jks", "storepw", "").1.format, "Java keystore (JKS) — 1 key entry, 1 trusted cert");
        assert_eq!(one("int-headerless.txt", "", "").1.format, "base64 without PEM headers → DER certificate");
        assert_eq!(one("leaf-der-enc.key", "", "").1.format, "encrypted DER private key (locked)");
    }

    #[test]
    fn p7b_keeps_file_order() {
        let (b, _) = one("chain.p7b", "", "");
        let cns: Vec<&str> = b.certs.iter().map(|c| c.cn.as_str()).collect();
        assert_eq!(cns, ["m.cust.test", "Cust Issuing", "Cust Root"]);
    }

    #[test]
    fn every_key_form_normalises_to_the_same_pkcs8() {
        let reference = one("leaf.key", "", "").0.key.unwrap();
        for (f, pw) in [("leaf-pkcs1.key", ""), ("leaf-der.key", ""), ("leaf-der-enc.key", "dk"), ("leaf-pkcs8-enc.key", "pk"),
                        ("leaf-legacy-enc.key", "lg"), ("modern.pfx", "pp"), ("legacy.pfx", "old"), ("keystore.jks", "storepw")] {
            let k = one(f, pw, "").0.key.unwrap_or_else(|| panic!("{f}: no key"));
            assert_eq!(k.pkcs8_der, reference.pkcs8_der, "{f}");
            assert_eq!(k.spki_der, reference.spki_der, "{f}");
        }
        let leaf = one("leaf.crt", "", "").0.certs.remove(0);
        assert_eq!(leaf.spki_der, reference.spki_der);
        assert_eq!(reference.desc, "RSA 2048");
        let ec = one("ec.key", "", "").0.key.unwrap();
        assert_eq!(ec.spki_der, one("ec.crt", "", "").0.certs[0].spki_der);
        assert_eq!(ec.desc, "EC secp256r1");
    }

    #[test]
    fn signature_variant_certs_parse() {
        for (f, h, key) in [("leaf-sha384.crt", "sha384", "RSA 2048"), ("leaf-sha512.crt", "sha512", "RSA 2048"),
                            ("ec-sha384.crt", "sha384", "EC secp256r1"), ("ec-root.crt", "sha384", "EC secp256r1"),
                            ("leaf-pss.crt", "sha256", "RSA 2048"), ("pss-int.crt", "sha256", "RSA 2048"), ("pss-root.crt", "sha256", "RSA 2048")] {
            let (b, r) = one(f, "", "");
            assert_eq!((r.kind.as_str(), r.certs), ("pem", 1), "{f}");
            assert_eq!((b.certs[0].sig_hash.as_str(), b.certs[0].key_desc.as_str()), (h, key), "{f}");
        }
    }

    #[test]
    fn hostile_pfx_inputs_give_error_reports() {
        for f in ["legacy.pfx", "modern.pfx"] {
            let d = corpus(f);
            for n in [1, 2, 3, 10, 100, d.len() / 2, d.len() - 1] {
                for name in [f, "upload.bin"] {
                    let b = parse_files(&[InputFile { name: name.into(), data: d[..n].to_vec() }], &Passwords { pfx: "pp".into(), ..Default::default() });
                    assert_eq!(b.reports[0].level, Level::Error, "{name} cut to {n}: {:?}", b.reports[0]);
                    assert!(b.certs.is_empty() && b.key.is_none());
                }
            }
            let (_, r) = one(f, "", "");
            assert_eq!(r.kind, "pfx-locked");
        }
        let d = corpus("legacy.pfx");
        let b = parse_files(&[InputFile { name: "legacy.pfx".into(), data: d[..d.len() / 2].to_vec() }], &Passwords::default());
        assert_eq!(b.reports[0].format, "PFX / PKCS#12 (damaged)");
        assert!(b.reports[0].notes[0].contains("cut short"), "{:?}", b.reports[0].notes);
    }

    #[test]
    fn utf16_without_bom() {
        let pem = corpus("leaf.crt");
        let le: Vec<u8> = String::from_utf8(pem.clone()).unwrap().encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        assert_eq!(normalize_text(&le), pem);
    }
}
