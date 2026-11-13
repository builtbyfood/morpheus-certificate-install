//! morpheus-certificate-install 0.4.0 — does a parent's public key verify a child's signature?
//!
//! Always over the TBSCertificate bytes exactly as they appear in the child (never re-encoded).
//! - RSA PKCS#1 v1.5 with SHA-1, -224, -256, -384, -512;
//! - RSASSA-PSS with the hash, MGF1 hash and salt length read from the certificate's parameters
//!   (the reference only tried PKCS#1 v1.5: docs/PARITY.md);
//! - ECDSA on P-256, P-384 and P-521 with any of those hashes (prehash, so P-256 + SHA-384 works);
//! - Ed25519.
//!
//! Anything else (Ed448, DSA, MD5, other curves) is [`Verdict::Unsupported`] with a readable name, so
//! the caller can say *why* a chain stops instead of claiming the issuer wasn't supplied.

use crate::formats::{keys, tlv, x509::hash_name};
use const_oid::ObjectIdentifier as Oid;
use sha2::Digest;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Valid,
    /// The key doesn't verify this signature (wrong issuer, wrong key type, tampered).
    Invalid,
    /// This app can't check this algorithm; the string names it for the user ("Ed448", "RSA-PSS with …").
    Unsupported(String),
}

struct Signed<'a> {
    tbs: &'a [u8],
    alg: Oid,
    params: Option<tlv::Tlv<'a>>,
    sig: &'a [u8],
}

fn split(cert_der: &[u8]) -> Option<Signed<'_>> {
    let top = tlv::read_exact(cert_der).ok()?;
    let parts = top.children().ok()?;
    let [tbs, alg, bits] = parts.as_slice() else { return None };
    let a = alg.children().ok()?;
    let oid = tlv::oid(a.first()?).ok()?;
    let params = a.get(1).copied().filter(|p| p.tag != 0x05); // NULL = absent
    if bits.tag != 0x03 || bits.content.first() != Some(&0) { return None; }
    Some(Signed { tbs: tbs.whole, alg: oid, params, sig: &bits.content[1..] })
}

/// A readable name for a signature algorithm OID (for the "can't verify" warning).
pub fn alg_name(oid: &Oid) -> String {
    match oid.to_string().as_str() {
        "1.3.101.113" => "Ed448".into(),
        "1.3.101.112" => "Ed25519".into(),
        "1.2.840.113549.1.1.4" => "RSA with MD5".into(),
        "1.2.840.113549.1.1.2" => "RSA with MD2".into(),
        "1.2.840.10040.4.3" | "2.16.840.1.101.3.4.3.1" | "2.16.840.1.101.3.4.3.2" | "2.16.840.1.101.3.4.3.3" | "2.16.840.1.101.3.4.3.4" => "DSA".into(),
        s if s.starts_with("2.16.840.1.101.3.4.3.") => "a SHA-3 signature".into(),
        s => format!("signature algorithm {s}"),
    }
}

/// Hash for a PKCS#1 v1.5 / ECDSA signature OID.
fn sig_hash(oid: &Oid) -> Option<&'static str> {
    Some(match oid.to_string().as_str() {
        "1.2.840.113549.1.1.5" | "1.2.840.10045.4.1" => "sha1",
        "1.2.840.113549.1.1.14" | "1.2.840.10045.4.3.1" => "sha224",
        "1.2.840.113549.1.1.11" | "1.2.840.10045.4.3.2" => "sha256",
        "1.2.840.113549.1.1.12" | "1.2.840.10045.4.3.3" => "sha384",
        "1.2.840.113549.1.1.13" | "1.2.840.10045.4.3.4" => "sha512",
        _ => return None,
    })
}

fn is_ecdsa(oid: &Oid) -> bool { oid.to_string().starts_with("1.2.840.10045.4.") }
fn is_rsa_pkcs1(oid: &Oid) -> bool { oid.to_string().starts_with("1.2.840.113549.1.1.") && *oid != keys::RSA_PSS }

fn digest(name: &str, data: &[u8]) -> Option<Vec<u8>> {
    Some(match name {
        "sha1" => sha1::Sha1::digest(data).to_vec(),
        "sha224" => sha2::Sha224::digest(data).to_vec(),
        "sha256" => sha2::Sha256::digest(data).to_vec(),
        "sha384" => sha2::Sha384::digest(data).to_vec(),
        "sha512" => sha2::Sha512::digest(data).to_vec(),
        _ => return None,
    })
}

/// Verify `child_der`'s signature with the public key in `parent_spki` (DER SubjectPublicKeyInfo).
pub fn verify(child_der: &[u8], parent_spki: &[u8]) -> Verdict {
    let Some(s) = split(child_der) else { return Verdict::Invalid };
    let Ok(spki) = <spki::SubjectPublicKeyInfoRef<'_> as der::Decode>::from_der(parent_spki) else { return Verdict::Invalid };
    let key_alg = spki.algorithm.oid;
    let key = spki.subject_public_key.raw_bytes();

    if is_rsa_pkcs1(&s.alg) || s.alg == keys::RSA_PSS {
        if key_alg != keys::RSA_ENC && key_alg != keys::RSA_PSS { return Verdict::Invalid; }
        let Ok(k) = <pkcs1::RsaPublicKey<'_> as der::Decode>::from_der(key) else { return Verdict::Invalid };
        let n = rsa::BigUint::from_bytes_be(k.modulus.as_bytes());
        let e = rsa::BigUint::from_bytes_be(k.public_exponent.as_bytes());
        let Ok(pk) = rsa::RsaPublicKey::new_with_max_size(n, e, 16384) else { return Verdict::Invalid };
        if s.alg == keys::RSA_PSS { return verify_pss(&s, &pk); }
        let Some(h) = sig_hash(&s.alg) else { return Verdict::Unsupported(alg_name(&s.alg)) };
        let hashed = digest(h, s.tbs).expect("known hash");
        let scheme = match h {
            "sha1" => rsa::Pkcs1v15Sign::new::<sha1::Sha1>(),
            "sha224" => rsa::Pkcs1v15Sign::new::<sha2::Sha224>(),
            "sha256" => rsa::Pkcs1v15Sign::new::<sha2::Sha256>(),
            "sha384" => rsa::Pkcs1v15Sign::new::<sha2::Sha384>(),
            _ => rsa::Pkcs1v15Sign::new::<sha2::Sha512>(),
        };
        return if pk.verify(scheme, &hashed, s.sig).is_ok() { Verdict::Valid } else { Verdict::Invalid };
    }

    if is_ecdsa(&s.alg) {
        let Some(h) = sig_hash(&s.alg) else { return Verdict::Unsupported(alg_name(&s.alg)) };
        if key_alg != keys::EC_PUB { return Verdict::Invalid; }
        let Some(curve) = spki.algorithm.parameters.and_then(|p| p.decode_as::<Oid>().ok()) else { return Verdict::Invalid };
        let prehash = digest(h, s.tbs).expect("known hash");
        use ecdsa::signature::hazmat::PrehashVerifier;
        macro_rules! ec {
            ($c:ident) => {{
                let Ok(vk) = $c::ecdsa::VerifyingKey::from_sec1_bytes(key) else { return Verdict::Invalid };
                let Ok(sig) = $c::ecdsa::Signature::from_der(s.sig) else { return Verdict::Invalid };
                vk.verify_prehash(&prehash, &sig).is_ok()
            }};
        }
        let ok = if curve == keys::P256 { ec!(p256) } else if curve == keys::P384 { ec!(p384) } else if curve == keys::P521 { ec!(p521) } else {
            let name = keys::curve_name(&curve).map(str::to_string).unwrap_or_else(|| curve.to_string());
            return Verdict::Unsupported(format!("ECDSA on {name}"));
        };
        return if ok { Verdict::Valid } else { Verdict::Invalid };
    }

    if s.alg == keys::ED25519 {
        if key_alg != keys::ED25519 { return Verdict::Invalid; }
        let Ok(k) = <[u8; 32]>::try_from(key) else { return Verdict::Invalid };
        let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&k) else { return Verdict::Invalid };
        let Ok(sig) = ed25519_dalek::Signature::from_slice(s.sig) else { return Verdict::Invalid };
        use ed25519_dalek::Verifier;
        return if vk.verify(s.tbs, &sig).is_ok() { Verdict::Valid } else { Verdict::Invalid };
    }

    Verdict::Unsupported(alg_name(&s.alg))
}

/// RSASSA-PSS-params ::= SEQUENCE { [0] hashAlgorithm DEFAULT sha1, [1] maskGenAlgorithm DEFAULT
/// mgf1SHA1, [2] saltLength DEFAULT 20, [3] trailerField DEFAULT 1 }
fn verify_pss(s: &Signed<'_>, pk: &rsa::RsaPublicKey) -> Verdict {
    const MGF1: Oid = Oid::new_unwrap("1.2.840.113549.1.1.8");
    let (mut hash, mut mgf_hash, mut salt, mut trailer) = ("sha1".to_string(), "sha1".to_string(), 20u64, 1u64);
    let parsed = (|| -> Option<()> {
        let Some(p) = s.params else { return Some(()) };
        for f in p.children().ok()? {
            let inner = tlv::read_exact(f.content).ok()?;
            match f.tag {
                0xA0 => hash = hash_name(&tlv::oid(inner.children().ok()?.first()?).ok()?).to_string(),
                0xA1 => {
                    let m = inner.children().ok()?;
                    if tlv::oid(m.first()?).ok()? != MGF1 { mgf_hash = "?".into(); continue; }
                    mgf_hash = hash_name(&tlv::oid(m.get(1)?.children().ok()?.first()?).ok()?).to_string();
                }
                0xA2 => salt = tlv::uint(&inner).ok()?,
                0xA3 => trailer = tlv::uint(&inner).ok()?,
                _ => return None,
            }
        }
        Some(())
    })();
    if parsed.is_none() { return Verdict::Invalid; }
    if hash.is_empty() || mgf_hash != hash || trailer != 1 || salt > 1024 {
        let mgf = if mgf_hash.is_empty() || mgf_hash == "?" { "an unknown mask function".to_string() } else { format!("MGF1-{}", mgf_hash.to_uppercase()) };
        return Verdict::Unsupported(format!("RSA-PSS with {} and {mgf}", if hash.is_empty() { "an unknown hash".into() } else { hash.to_uppercase() }));
    }
    let salt = salt as usize;
    let Some(hashed) = digest(&hash, s.tbs) else { return Verdict::Unsupported(format!("RSA-PSS with {}", hash.to_uppercase())) };
    let scheme = match hash.as_str() {
        "sha1" => rsa::Pss::new_with_salt::<sha1::Sha1>(salt),
        "sha224" => rsa::Pss::new_with_salt::<sha2::Sha224>(salt),
        "sha256" => rsa::Pss::new_with_salt::<sha2::Sha256>(salt),
        "sha384" => rsa::Pss::new_with_salt::<sha2::Sha384>(salt),
        _ => rsa::Pss::new_with_salt::<sha2::Sha512>(salt),
    };
    if pk.verify(scheme, &hashed, s.sig).is_ok() { Verdict::Valid } else { Verdict::Invalid }
}
