//! morpheus-certificate-install 0.4.0 — PFX / PKCS#12 reader (decrypt-only, hardened).
//!
//! Order of operations, for each password tried:
//! 1. Walk the outer structure (bounds-checked, BER-aware: [`super::tlv`]). Not a PFX → [`PfxError::NotPfx`];
//!    the declared length runs past the end of the file → [`PfxError::Truncated`].
//! 2. **Verify the MAC before anything is decrypted.** The MAC's iteration count is checked against
//!    [`pbe::MAX_ITERATIONS`] first; a mismatch is [`PfxError::WrongPassword`].
//! 3. Only then decrypt the safes and shrouded key bags (their own work factors are capped in `pbe`).
//!
//! Passwords: OpenSSL treats "no password" as both NULL and "" (they differ in the PKCS#12 KDF), so
//! the caller tries [`Pw::Null`], then `Pw::Text("")`, then every password given — like the reference's
//! `[None, b""] + pws`.

use super::pbe::{self, PbeError, Pw};
use super::tlv::{self, Tlv, TlvError};
use const_oid::ObjectIdentifier as Oid;
use hmac::Mac;

const ID_DATA: Oid = Oid::new_unwrap("1.2.840.113549.1.7.1");
const ID_ENCRYPTED_DATA: Oid = Oid::new_unwrap("1.2.840.113549.1.7.6");
const ID_ENVELOPED_DATA: Oid = Oid::new_unwrap("1.2.840.113549.1.7.3");
const KEY_BAG: Oid = Oid::new_unwrap("1.2.840.113549.1.12.10.1.1");
const SHROUDED_KEY_BAG: Oid = Oid::new_unwrap("1.2.840.113549.1.12.10.1.2");
const CERT_BAG: Oid = Oid::new_unwrap("1.2.840.113549.1.12.10.1.3");
const SAFE_CONTENTS_BAG: Oid = Oid::new_unwrap("1.2.840.113549.1.12.10.1.6");
const X509_CERT: Oid = Oid::new_unwrap("1.2.840.113549.1.9.22.1");
const PBMAC1: Oid = Oid::new_unwrap("1.2.840.113549.1.5.14");
/// Nested SafeContents bags followed at most this deep.
const MAX_SAFE_DEPTH: usize = 4;

#[derive(Debug, Default)]
pub struct Contents {
    /// Unencrypted PKCS#8 DER, bag order.
    pub keys: Vec<Vec<u8>>,
    /// Certificate DER, bag order.
    pub certs: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PfxError {
    NotPfx,
    /// The file is shorter than its own header says.
    Truncated { have: usize, need: usize },
    WrongPassword,
    Limit(String),
    Unsupported(String),
    Damaged(String),
}

impl From<TlvError> for PfxError {
    fn from(e: TlvError) -> Self { PfxError::Damaged(e.to_string()) }
}

impl From<PbeError> for PfxError {
    fn from(e: PbeError) -> Self {
        match e {
            PbeError::WrongPassword => PfxError::WrongPassword,
            PbeError::Limit(m) => PfxError::Limit(m),
            PbeError::Unsupported(m) => PfxError::Unsupported(m),
            PbeError::Bad(m) => PfxError::Damaged(m),
        }
    }
}

struct Outer<'a> {
    auth_safe: Vec<u8>,
    mac: Option<MacData<'a>>,
}

struct MacData<'a> {
    alg: Oid,
    /// The MAC AlgorithmIdentifier's parameters (PBMAC1 carries its KDF and HMAC here).
    params: Option<Tlv<'a>>,
    digest: &'a [u8],
    salt: Vec<u8>,
    iterations: u64,
}

/// Step 1: is this a PFX at all, and where are its parts?
fn outer(data: &[u8]) -> Result<Outer<'_>, PfxError> {
    if data.first() != Some(&0x30) { return Err(PfxError::NotPfx); }
    if let Some(need) = tlv::declared_len(data) {
        if need > data.len() { return Err(PfxError::Truncated { have: data.len(), need }); }
    }
    let top = match tlv::read(data) {
        Ok(t) if t.whole.len() == data.len() => t,
        Ok(_) => return Err(PfxError::NotPfx),
        Err(TlvError::Truncated { .. }) => return Err(PfxError::Truncated { have: data.len(), need: data.len() + 1 }),
        Err(_) => return Err(PfxError::NotPfx),
    };
    let parts = top.children().map_err(|_| PfxError::NotPfx)?;
    // version INTEGER 3, authSafe ContentInfo, macData OPTIONAL
    if parts.len() < 2 || parts.len() > 3 || tlv::uint(&parts[0]).ok() != Some(3) || parts[1].tag != 0x30 { return Err(PfxError::NotPfx); }
    let ci = parts[1].children().map_err(|_| PfxError::NotPfx)?;
    let ctype = ci.first().map(tlv::oid).transpose().map_err(|_| PfxError::NotPfx)?;
    if ctype != Some(ID_DATA) {
        return Err(PfxError::Unsupported("public-key protected PFX files aren't supported; export it again with a password.".into()));
    }
    let auth_safe = data_content(&ci)?;
    let mac = match parts.get(2) {
        None => None,
        Some(m) => {
            let mc = m.children()?;
            let di = mc.first().ok_or_else(|| PfxError::Damaged("MAC data is empty".into()))?.children()?;
            let algid = di.first().ok_or_else(|| PfxError::Damaged("MAC algorithm missing".into()))?.children()?;
            let alg = tlv::oid(algid.first().ok_or_else(|| PfxError::Damaged("MAC algorithm missing".into()))?)?;
            let params = algid.get(1).copied();
            let digest = di.get(1).filter(|t| t.tag == 0x04).ok_or_else(|| PfxError::Damaged("MAC value missing".into()))?.content;
            let salt = tlv::octets(mc.get(1).ok_or_else(|| PfxError::Damaged("MAC salt missing".into()))?)?;
            let iterations = match mc.get(2) { Some(t) => tlv::uint(t)?, None => 1 };
            Some(MacData { alg, params, digest, salt, iterations })
        }
    };
    Ok(Outer { auth_safe, mac })
}

/// ContentInfo { id-data, [0] EXPLICIT OCTET STRING } → the octets.
fn data_content(ci: &[Tlv<'_>]) -> Result<Vec<u8>, PfxError> {
    let explicit = ci.get(1).filter(|t| t.tag == 0xA0).ok_or_else(|| PfxError::Damaged("content missing".into()))?;
    let os = explicit.children()?.into_iter().next().ok_or_else(|| PfxError::Damaged("content missing".into()))?;
    if os.tag & !0x20 != 0x04 { return Err(PfxError::Damaged("content isn't an OCTET STRING".into())); }
    Ok(tlv::octets(&os)?)
}

/// Step 2: HMAC over the authSafe octets with the RFC 7292 MAC key.
fn verify_mac(o: &Outer<'_>, pw: Pw<'_>) -> Result<(), PfxError> {
    let Some(m) = &o.mac else { return Ok(()) };
    if m.alg == PBMAC1 {
        return verify_pbmac1(m, &o.auth_safe, pw);
    }
    pbe::check_iterations("MAC iterations", m.iterations)?;
    let pass = pw.bmp();
    let it = m.iterations as i32;
    use pkcs12::kdf::{derive_key, Pkcs12KeyType::Mac as K};
    macro_rules! check {
        ($d:ty, $n:expr) => {{
            let key = derive_key::<$d>(&pass, &m.salt, K, it, $n);
            let mut h = hmac::Hmac::<$d>::new_from_slice(&key).expect("any key length");
            h.update(&o.auth_safe);
            h.verify_slice(m.digest).map_err(|_| PfxError::WrongPassword)
        }};
    }
    match crate::formats::x509::hash_name(&m.alg) {
        "sha1" => check!(sha1::Sha1, 20),
        "sha224" => check!(sha2::Sha224, 28),
        "sha256" => check!(sha2::Sha256, 32),
        "sha384" => check!(sha2::Sha384, 48),
        "sha512" => check!(sha2::Sha512, 64),
        _ => Err(PfxError::Unsupported(format!("PFX MAC algorithm {} isn't supported. Export it again with AES-256 and SHA-256.", m.alg))),
    }
}

const PBKDF2: Oid = Oid::new_unwrap("1.2.840.113549.1.5.12");

/// HMAC PRF OIDs (RFC 8018 B.1.2) → hash name.
fn hmac_hash(o: &Oid) -> &'static str {
    match o.to_string().as_str() {
        "1.2.840.113549.2.7" => "sha1",
        "1.2.840.113549.2.8" => "sha224",
        "1.2.840.113549.2.9" => "sha256",
        "1.2.840.113549.2.10" => "sha384",
        "1.2.840.113549.2.11" => "sha512",
        _ => "",
    }
}

/// RFC 9579 PBMAC1 in a PFX: key = PBKDF2(password as UTF-8, salt, iterations, keyLength, PRF),
/// MAC = HMAC(messageAuthScheme, key, authSafe). MacData's own salt and iterations are ignored.
fn verify_pbmac1(m: &MacData<'_>, auth_safe: &[u8], pw: Pw<'_>) -> Result<(), PfxError> {
    let bad = |what: &str| PfxError::Damaged(format!("PBMAC1 parameters: {what}"));
    let p = m.params.ok_or_else(|| bad("missing"))?.children()?;
    let (kdf, mac) = match p.as_slice() { [k, a] => (k.children()?, a.children()?), _ => return Err(bad("malformed")) };
    if kdf.first().map(tlv::oid).transpose()? != Some(PBKDF2) {
        return Err(PfxError::Unsupported("this PFX's PBMAC1 uses a key derivation other than PBKDF2. Export it again.".into()));
    }
    let kp = kdf.get(1).ok_or_else(|| bad("PBKDF2 parameters missing"))?.children()?;
    let salt = tlv::octets(kp.first().ok_or_else(|| bad("salt"))?)?;
    let iterations = tlv::uint(kp.get(1).ok_or_else(|| bad("iterations"))?)?;
    pbe::check_iterations("MAC iterations", iterations)?;
    let mut key_len = None;
    let mut prf = "sha1";
    for t in &kp[2..] {
        match t.tag {
            0x02 => key_len = Some(tlv::uint(t)?),
            0x30 => prf = hmac_hash(&tlv::oid(t.children()?.first().ok_or_else(|| bad("PRF"))?)?),
            _ => return Err(bad("unexpected field")),
        }
    }
    // RFC 9579 §3: keyLength MUST be present; capped at a sane size.
    let key_len = key_len.filter(|n| (1..=128).contains(n)).ok_or_else(|| bad("keyLength missing or out of range"))? as usize;
    let mac_hash = hmac_hash(&tlv::oid(mac.first().ok_or_else(|| bad("MAC scheme"))?)?);
    let mut key = vec![0u8; key_len];
    let it = iterations as u32;
    let pass = pw.utf8();
    match prf {
        "sha1" => pbkdf2::pbkdf2_hmac::<sha1::Sha1>(pass, &salt, it, &mut key),
        "sha224" => pbkdf2::pbkdf2_hmac::<sha2::Sha224>(pass, &salt, it, &mut key),
        "sha256" => pbkdf2::pbkdf2_hmac::<sha2::Sha256>(pass, &salt, it, &mut key),
        "sha384" => pbkdf2::pbkdf2_hmac::<sha2::Sha384>(pass, &salt, it, &mut key),
        "sha512" => pbkdf2::pbkdf2_hmac::<sha2::Sha512>(pass, &salt, it, &mut key),
        _ => return Err(PfxError::Unsupported("this PFX's PBMAC1 uses an unsupported PRF. Export it again.".into())),
    }
    macro_rules! hm {
        ($d:ty) => {{
            let mut h = hmac::Hmac::<$d>::new_from_slice(&key).expect("any key length");
            h.update(auth_safe);
            h.verify_slice(m.digest).map_err(|_| PfxError::WrongPassword)
        }};
    }
    match mac_hash {
        "sha1" => hm!(sha1::Sha1),
        "sha224" => hm!(sha2::Sha224),
        "sha256" => hm!(sha2::Sha256),
        "sha384" => hm!(sha2::Sha384),
        "sha512" => hm!(sha2::Sha512),
        _ => Err(PfxError::Unsupported("this PFX's PBMAC1 uses an unsupported MAC. Export it again.".into())),
    }
}

/// Open with one password. Errors other than WrongPassword are the same for every password.
pub fn open(data: &[u8], pw: Pw<'_>) -> Result<Contents, PfxError> {
    let o = outer(data)?;
    verify_mac(&o, pw)?;
    // Step 3, only after the MAC matched (or there is none).
    let mut out = Contents::default();
    let after_mac = |e: PfxError| match e {
        // With a verified MAC the password is right, so a decrypt failure means a damaged file.
        PfxError::WrongPassword if o.mac.is_some() => PfxError::Damaged("an encrypted part didn't decrypt although the password is right".into()),
        other => other,
    };
    let safes = tlv::read_exact(&o.auth_safe)?.children()?;
    for ci in safes {
        let ci = ci.children()?;
        let ctype = tlv::oid(ci.first().ok_or_else(|| PfxError::Damaged("empty ContentInfo".into()))?)?;
        let contents = if ctype == ID_DATA {
            data_content(&ci)?
        } else if ctype == ID_ENCRYPTED_DATA {
            // [0] EXPLICIT EncryptedData { version, EncryptedContentInfo { type, alg, [0] IMPLICIT octets } }
            let ed = ci.get(1).filter(|t| t.tag == 0xA0).ok_or_else(|| PfxError::Damaged("encrypted safe missing".into()))?
                .children()?.into_iter().next().ok_or_else(|| PfxError::Damaged("encrypted safe missing".into()))?.children()?;
            let eci = ed.get(1).ok_or_else(|| PfxError::Damaged("encrypted safe malformed".into()))?.children()?;
            let alg = eci.get(1).ok_or_else(|| PfxError::Damaged("encrypted safe without algorithm".into()))?;
            let ct = eci.get(2).filter(|t| t.tag & !0x20 == 0x80).ok_or_else(|| PfxError::Damaged("encrypted safe without content".into()))?;
            pbe::decrypt(alg.whole, &tlv::octets(ct)?, pw).map_err(PfxError::from).map_err(after_mac)?
        } else if ctype == ID_ENVELOPED_DATA {
            return Err(PfxError::Unsupported("public-key protected PFX safes aren't supported; export it again with a password.".into()));
        } else {
            return Err(PfxError::Damaged(format!("unknown safe type {ctype}")));
        };
        bags(&contents, pw, &mut out, 0).map_err(after_mac)?;
    }
    Ok(out)
}

fn bags(safe_contents: &[u8], pw: Pw<'_>, out: &mut Contents, depth: usize) -> Result<(), PfxError> {
    if depth > MAX_SAFE_DEPTH { return Err(PfxError::Damaged("SafeContents nested too deeply".into())); }
    let list = match tlv::read_exact(safe_contents) {
        Ok(t) => t,
        // Undecryptable garbage without a MAC to vouch for the password.
        Err(_) => return Err(PfxError::WrongPassword),
    };
    for bag in list.children()? {
        let b = bag.children()?;
        let id = tlv::oid(b.first().ok_or_else(|| PfxError::Damaged("empty SafeBag".into()))?)?;
        let val = b.get(1).filter(|t| t.tag == 0xA0).ok_or_else(|| PfxError::Damaged("SafeBag without value".into()))?
            .children()?.into_iter().next().ok_or_else(|| PfxError::Damaged("SafeBag without value".into()))?;
        if id == CERT_BAG {
            let cb = val.children()?;
            if cb.first().map(tlv::oid).transpose()? != Some(X509_CERT) { continue; }
            let os = cb.get(1).filter(|t| t.tag == 0xA0).ok_or_else(|| PfxError::Damaged("CertBag without value".into()))?
                .children()?.into_iter().next().ok_or_else(|| PfxError::Damaged("CertBag without value".into()))?;
            out.certs.push(tlv::octets(&os)?);
        } else if id == SHROUDED_KEY_BAG {
            let e = val.children()?;
            let (alg, ct) = match e.as_slice() {
                [a, c] if c.tag & !0x20 == 0x04 => (a.whole, tlv::octets(c)?),
                _ => return Err(PfxError::Damaged("shrouded key bag malformed".into())),
            };
            out.keys.push(pbe::decrypt(alg, &ct, pw)?);
        } else if id == KEY_BAG {
            out.keys.push(val.whole.to_vec());
        } else if id == SAFE_CONTENTS_BAG {
            bags(val.whole, pw, out, depth + 1)?;
        }
        // CRL and secret bags are ignored, as OpenSSL does.
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus(f: &str) -> Vec<u8> {
        let p: std::path::PathBuf = [env!("CARGO_MANIFEST_DIR"), "..", "..", "fixtures", "corpus", f].iter().collect();
        std::fs::read(p).unwrap()
    }

    /// Re-encode a definite-length DER tree, replacing every node whose bytes equal `from`, also
    /// inside OCTET STRINGs that hold DER (PFX nests DER in octets). Lengths are recomputed.
    fn rewrite(der: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
        fn node(t: &Tlv<'_>, from: &[u8], to: &[u8]) -> Vec<u8> {
            if t.whole == from { return to.to_vec(); }
            if t.constructed() {
                let kids: Vec<u8> = t.children().unwrap().iter().flat_map(|c| node(c, from, to)).collect();
                return tlv::encode(t.tag, &kids);
            }
            if t.tag == 0x04 {
                if let Ok(inner) = tlv::read_exact(t.content) {
                    if inner.constructed() && !t.content.is_empty() {
                        return tlv::encode(0x04, &node(&inner, from, to));
                    }
                }
            }
            t.whole.to_vec()
        }
        node(&tlv::read_exact(der).unwrap(), from, to)
    }

    /// Recompute the MAC of a (modified) PFX for `pw`, keeping its salt, iterations and algorithm.
    fn remac(pfx: &[u8], pw: &str) -> Vec<u8> {
        let o = outer(pfx).unwrap();
        let m = o.mac.as_ref().unwrap();
        use pkcs12::kdf::{derive_key, Pkcs12KeyType::Mac as K};
        let pass = Pw::Text(pw).bmp();
        let digest = match crate::formats::x509::hash_name(&m.alg) {
            "sha1" => { let k = derive_key::<sha1::Sha1>(&pass, &m.salt, K, m.iterations as i32, 20);
                let mut h = hmac::Hmac::<sha1::Sha1>::new_from_slice(&k).unwrap(); h.update(&o.auth_safe); h.finalize().into_bytes().to_vec() }
            _ => { let k = derive_key::<sha2::Sha256>(&pass, &m.salt, K, m.iterations as i32, 32);
                let mut h = hmac::Hmac::<sha2::Sha256>::new_from_slice(&k).unwrap(); h.update(&o.auth_safe); h.finalize().into_bytes().to_vec() }
        };
        let old = tlv::encode(0x04, m.digest);
        rewrite(pfx, &old, &tlv::encode(0x04, &digest))
    }

    const ITER_2048: [u8; 4] = [0x02, 0x02, 0x08, 0x00];
    const ITER_2E9: [u8; 6] = [0x02, 0x04, 0x77, 0x35, 0x94, 0x00];

    #[test]
    fn opens_the_corpus() {
        for (f, pw, certs, keys) in [("legacy.pfx", "old", 2, 1), ("modern.pfx", "pp", 3, 1), ("nokey.pfx", "x", 1, 0), ("pbmac1.pfx", "pm", 3, 1)] {
            let c = open(&corpus(f), Pw::Text(pw)).unwrap();
            assert_eq!((c.certs.len(), c.keys.len()), (certs, keys), "{f}");
        }
        assert_eq!(open(&corpus("modern.pfx"), Pw::Text("nope")).unwrap_err(), PfxError::WrongPassword);
        assert_eq!(open(&corpus("modern.pfx"), Pw::Null).unwrap_err(), PfxError::WrongPassword);
        assert_eq!(open(&corpus("pbmac1.pfx"), Pw::Text("nope")).unwrap_err(), PfxError::WrongPassword);
        assert_eq!(open(b"\x30\x03\x02\x01\x05", Pw::Null).unwrap_err(), PfxError::NotPfx);
    }

    #[test]
    fn truncated_files_are_errors() {
        for f in ["legacy.pfx", "modern.pfx"] {
            let d = corpus(f);
            for n in [0, 1, 2, 3, 4, 10, 50, 100, d.len() / 3, d.len() / 2, d.len() - 100, d.len() - 21, d.len() - 2, d.len() - 1] {
                match open(&d[..n], Pw::Text("pp")) {
                    Err(PfxError::Truncated { .. } | PfxError::NotPfx) => {}
                    other => panic!("{f} cut to {n}: {other:?}"),
                }
            }
        }
    }

    #[test]
    fn flipped_mac_byte_is_wrong_password() {
        for (f, pw) in [("legacy.pfx", "old"), ("modern.pfx", "pp")] {
            let mut d = corpus(f);
            let o = outer(&d).unwrap();
            let at = d.windows(o.mac.as_ref().unwrap().digest.len()).position(|w| w == o.mac.as_ref().unwrap().digest).unwrap();
            d[at + 3] ^= 0x01;
            assert_eq!(open(&d, Pw::Text(pw)).unwrap_err(), PfxError::WrongPassword, "{f}");
        }
    }

    #[test]
    fn huge_mac_iterations_refused_quickly() {
        let d = corpus("modern.pfx");
        // The MAC's iteration INTEGER is the last child of the outer SEQUENCE.
        let top = tlv::read_exact(&d).unwrap();
        let mac = top.children().unwrap()[2];
        let mc = mac.children().unwrap();
        let new_mac = tlv::encode(0x30, &[mc[0].whole, mc[1].whole, &ITER_2E9].concat());
        let crafted = rewrite(&d, mac.whole, &new_mac);
        let t = std::time::Instant::now();
        match open(&crafted, Pw::Text("pp")) {
            Err(PfxError::Limit(m)) => assert!(m.contains("2,000,000,000"), "{m}"),
            other => panic!("{other:?}"),
        }
        assert!(t.elapsed().as_millis() < 500);
    }

    #[test]
    fn mac_is_checked_before_any_decryption() {
        // Every inner work factor made huge. Without fixing the MAC, the answer must be "wrong
        // password" (the MAC failed first); with the MAC recomputed, the inner limit is reached.
        for (f, pw) in [("modern.pfx", "pp"), ("legacy.pfx", "old")] {
            let d = corpus(f);
            let top = tlv::read_exact(&d).unwrap();
            let [ver, auth, mac] = top.children().unwrap()[..] else { panic!() };
            let auth2 = rewrite(auth.whole, &ITER_2048, &ITER_2E9);
            assert_ne!(auth2, auth.whole, "{f}: no 2048 iteration count found to replace");
            let crafted = tlv::encode(0x30, &[ver.whole, &auth2, mac.whole].concat());
            assert_eq!(open(&crafted, Pw::Text(pw)).unwrap_err(), PfxError::WrongPassword, "{f}");
            let t = std::time::Instant::now();
            match open(&remac(&crafted, pw), Pw::Text(pw)) {
                Err(PfxError::Limit(m)) => assert!(m.contains("2,000,000,000"), "{f}: {m}"),
                other => panic!("{f}: {other:?}"),
            }
            assert!(t.elapsed().as_millis() < 2000);
        }
    }

    #[test]
    fn garbage_never_panics() {
        // Every single-byte corruption of the first 300 bytes of a real PFX: an error or a result, never a panic.
        let d = corpus("legacy.pfx");
        for i in 0..300.min(d.len()) {
            for x in [0x01u8, 0x80, 0xff] {
                let mut c = d.clone();
                c[i] ^= x;
                let _ = open(&c, Pw::Text("old"));
            }
        }
    }
}
