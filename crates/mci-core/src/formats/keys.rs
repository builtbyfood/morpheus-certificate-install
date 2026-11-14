//! morpheus-certificate-install 0.4.2 — private keys, normalised the way the reference writes them.
//!
//! Whatever the input (PKCS#8, PKCS#1, SEC1, DSA, encrypted PKCS#8, OpenSSL "traditional"
//! encrypted PEM, OpenSSH), the result is the unencrypted PKCS#8 DER that Python's
//! `private_bytes(DER, PKCS8, NoEncryption())` produces, plus the SubjectPublicKeyInfo that
//! `public_key().public_bytes(DER, SubjectPublicKeyInfo)` produces. The R0 spike checked both
//! byte-for-byte against the reference for RSA and EC.
//!
//! - RSA: PKCS#8 { rsaEncryption NULL, RSAPrivateKey re-encoded canonically }.
//! - EC: PKCS#8 { ecPublicKey namedCurve, ECPrivateKey { 1, d padded to the field size, **no** [0]
//!   parameters, [1] public key } }, as OpenSSL writes it.
//! - Ed25519: PKCS#8 v1 with the 32-byte seed.
//! - DSA: PKCS#8 { dsa Dss-Parms, INTEGER x }.
//! - Ed448 and X25519/X448: not supported (docs/PARITY.md).

use super::pbe::{self, PbeError, Pw};
use super::tlv;
use const_oid::ObjectIdentifier as Oid;
use der::{asn1::{AnyRef, BitStringRef, UintRef}, Decode, Encode};

pub const RSA_ENC: Oid = Oid::new_unwrap("1.2.840.113549.1.1.1");
pub const RSA_PSS: Oid = Oid::new_unwrap("1.2.840.113549.1.1.10");
pub const EC_PUB: Oid = Oid::new_unwrap("1.2.840.10045.2.1");
pub const ED25519: Oid = Oid::new_unwrap("1.3.101.112");
pub const ED448: Oid = Oid::new_unwrap("1.3.101.113");
pub const DSA: Oid = Oid::new_unwrap("1.2.840.10040.4.1");
pub const P256: Oid = Oid::new_unwrap("1.2.840.10045.3.1.7");
pub const P384: Oid = Oid::new_unwrap("1.3.132.0.34");
pub const P521: Oid = Oid::new_unwrap("1.3.132.0.35");

/// A normalised private key.
#[derive(Debug, Clone)]
pub struct Key {
    pub pkcs8: Vec<u8>,
    pub spki: Vec<u8>,
    pub desc: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    /// Not a private key in the form tried.
    NotAKey,
    /// Encrypted and no password was given.
    NeedPassword,
    WrongPassword,
    Unsupported(String),
    Limit(String),
    Bad(String),
}

impl From<PbeError> for KeyError {
    fn from(e: PbeError) -> Self {
        match e {
            PbeError::WrongPassword => KeyError::WrongPassword,
            PbeError::Limit(m) => KeyError::Limit(m),
            PbeError::Unsupported(m) => KeyError::Unsupported(m),
            PbeError::Bad(m) => KeyError::Bad(m),
        }
    }
}

impl KeyError {
    /// The note shown for this key (for errors that aren't "locked").
    pub fn text(&self) -> String {
        match self {
            KeyError::NotAKey => "it isn't a private key in any format this app reads.".into(),
            KeyError::NeedPassword | KeyError::WrongPassword => "wrong or missing passphrase.".into(),
            KeyError::Unsupported(m) | KeyError::Limit(m) | KeyError::Bad(m) => m.clone(),
        }
    }
}

fn bad<E: std::fmt::Display>(what: &str) -> impl Fn(E) -> KeyError + '_ { move |e| KeyError::Bad(format!("{what}: {e}")) }

/// Curve name as cryptography's `curve.name`.
pub fn curve_name(oid: &Oid) -> Option<&'static str> {
    Some(match oid.to_string().as_str() {
        "1.2.840.10045.3.1.7" => "secp256r1",
        "1.3.132.0.34" => "secp384r1",
        "1.3.132.0.35" => "secp521r1",
        "1.3.132.0.10" => "secp256k1",
        "1.3.132.0.33" => "secp224r1",
        "1.2.840.10045.3.1.1" => "secp192r1",
        "1.3.36.3.3.2.8.1.1.7" => "brainpoolP256r1",
        "1.3.36.3.3.2.8.1.1.11" => "brainpoolP384r1",
        "1.3.36.3.3.2.8.1.1.13" => "brainpoolP512r1",
        _ => return None,
    })
}

/// Private-scalar length OpenSSL pads `d` to.
fn field_len(oid: &Oid) -> Option<usize> {
    Some(match curve_name(oid)? {
        "secp256r1" | "secp256k1" | "brainpoolP256r1" => 32,
        "secp384r1" | "brainpoolP384r1" => 48,
        "secp521r1" => 66,
        "brainpoolP512r1" => 64,
        "secp224r1" => 28,
        "secp192r1" => 24,
        _ => return None,
    })
}

/// Uncompressed public point for a private scalar (P-256/384/521 only).
fn ec_point_from_secret(curve: &Oid, d: &[u8]) -> Option<Vec<u8>> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    if *curve == P256 {
        Some(p256::SecretKey::from_slice(d).ok()?.public_key().to_encoded_point(false).as_bytes().to_vec())
    } else if *curve == P384 {
        Some(p384::SecretKey::from_slice(d).ok()?.public_key().to_encoded_point(false).as_bytes().to_vec())
    } else if *curve == P521 {
        Some(p521::SecretKey::from_slice(d).ok()?.public_key().to_encoded_point(false).as_bytes().to_vec())
    } else {
        None
    }
}

/// Compressed → uncompressed point (P-256/384/521); anything else unchanged.
fn ec_uncompressed(curve: &Oid, point: &[u8]) -> Vec<u8> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    if point.first().map_or(true, |b| *b == 0x04) { return point.to_vec(); }
    let up = if *curve == P256 {
        p256::PublicKey::from_sec1_bytes(point).ok().map(|k| k.to_encoded_point(false).as_bytes().to_vec())
    } else if *curve == P384 {
        p384::PublicKey::from_sec1_bytes(point).ok().map(|k| k.to_encoded_point(false).as_bytes().to_vec())
    } else if *curve == P521 {
        p521::PublicKey::from_sec1_bytes(point).ok().map(|k| k.to_encoded_point(false).as_bytes().to_vec())
    } else {
        None
    };
    up.unwrap_or_else(|| point.to_vec())
}

fn spki_der(oid: Oid, params: Option<AnyRef<'_>>, key: &[u8]) -> Vec<u8> {
    spki::SubjectPublicKeyInfoRef {
        algorithm: spki::AlgorithmIdentifierRef { oid, parameters: params },
        subject_public_key: BitStringRef::from_bytes(key).expect("byte-aligned"),
    }
    .to_der()
    .expect("SPKI encodes")
}

fn pkcs8_der(oid: Oid, params: Option<AnyRef<'_>>, inner: &[u8]) -> Vec<u8> {
    pkcs8::PrivateKeyInfo { algorithm: spki::AlgorithmIdentifierRef { oid, parameters: params }, private_key: inner, public_key: None }
        .to_der()
        .expect("PKCS#8 encodes")
}

fn bits(be: &[u8]) -> u32 {
    let s: &[u8] = { let i = be.iter().position(|b| *b != 0).unwrap_or(be.len()); &be[i..] };
    match s.first() { None => 0, Some(f) => (s.len() as u32 - 1) * 8 + (8 - f.leading_zeros()) }
}

/// `RSA 2048`, `EC secp256r1`, `Ed25519`, … from a SubjectPublicKeyInfo (as the reference's key_desc),
/// plus the RSA modulus size.
pub fn describe_spki(spki_der: &[u8]) -> (String, Option<u32>) {
    let Ok(s) = spki::SubjectPublicKeyInfoRef::from_der(spki_der) else { return ("unknown key".into(), None) };
    let oid = s.algorithm.oid;
    if oid == RSA_ENC || oid == RSA_PSS {
        if let Ok(k) = pkcs1::RsaPublicKey::from_der(s.subject_public_key.raw_bytes()) {
            let b = bits(k.modulus.as_bytes());
            return (format!("RSA {b}"), Some(b));
        }
        return ("RSA".into(), None);
    }
    if oid == EC_PUB {
        let curve = s.algorithm.parameters.and_then(|p| p.decode_as::<Oid>().ok());
        return (format!("EC {}", curve.as_ref().and_then(curve_name).unwrap_or("unknown curve")), None);
    }
    if oid == ED25519 { return ("Ed25519".into(), None); }
    if oid == ED448 { return ("Ed448".into(), None); }
    if oid == DSA { return ("DSAPublicKey".into(), None); }
    (oid.to_string(), None)
}

/// SPKI in the canonical form cryptography re-serialises to (RSA with NULL parameters, EC points
/// uncompressed), so a key and a certificate compare equal exactly when the reference says so.
pub fn normalize_spki(spki_der_in: &[u8]) -> Vec<u8> {
    let Ok(s) = spki::SubjectPublicKeyInfoRef::from_der(spki_der_in) else { return spki_der_in.to_vec() };
    let oid = s.algorithm.oid;
    if oid == RSA_ENC {
        if let Ok(k) = pkcs1::RsaPublicKey::from_der(s.subject_public_key.raw_bytes()) {
            let pk = pkcs1::RsaPublicKey { modulus: k.modulus, public_exponent: k.public_exponent }.to_der().expect("encodes");
            return spki_der(RSA_ENC, Some(AnyRef::NULL), &pk);
        }
    }
    if oid == EC_PUB {
        if let Some(curve) = s.algorithm.parameters.and_then(|p| p.decode_as::<Oid>().ok()) {
            let point = ec_uncompressed(&curve, s.subject_public_key.raw_bytes());
            return spki_der(EC_PUB, Some(AnyRef::from(&curve)), &point);
        }
    }
    spki_der_in.to_vec()
}

// ------------------------------------------------------------------ unencrypted forms

pub fn from_pkcs1(der: &[u8]) -> Result<Key, KeyError> {
    let k = pkcs1::RsaPrivateKey::from_der(der).map_err(|_| KeyError::NotAKey)?;
    let canon = k.to_der().map_err(bad("RSA key"))?;
    let pk = pkcs1::RsaPublicKey { modulus: k.modulus, public_exponent: k.public_exponent }.to_der().map_err(bad("RSA key"))?;
    Ok(Key {
        pkcs8: pkcs8_der(RSA_ENC, Some(AnyRef::NULL), &canon),
        spki: spki_der(RSA_ENC, Some(AnyRef::NULL), &pk),
        desc: format!("RSA {}", bits(k.modulus.as_bytes())),
    })
}

/// SEC1 ECPrivateKey; `curve` comes from the PKCS#8 AlgorithmIdentifier when wrapped.
pub fn from_sec1(der: &[u8], curve: Option<Oid>) -> Result<Key, KeyError> {
    let k = sec1::EcPrivateKey::from_der(der).map_err(|_| KeyError::NotAKey)?;
    let curve = curve.or_else(|| k.parameters.and_then(|p| p.named_curve()))
        .ok_or_else(|| KeyError::Unsupported("EC key with explicit curve parameters; only named curves are supported.".into()))?;
    let name = curve_name(&curve).ok_or_else(|| KeyError::Unsupported(format!("EC curve {curve} isn't supported.")))?;
    let mut d = k.private_key.to_vec();
    if let Some(n) = field_len(&curve) {
        while d.len() > n && d[0] == 0 { d.remove(0); }
        while d.len() < n { d.insert(0, 0); }
    }
    let point = match k.public_key {
        Some(p) => ec_uncompressed(&curve, p),
        None => ec_point_from_secret(&curve, &d)
            .ok_or_else(|| KeyError::Unsupported(format!("EC key on {name} without its public part; re-export it with the public key included.")))?,
    };
    let inner = sec1::EcPrivateKey { private_key: &d, parameters: None, public_key: Some(&point) }.to_der().map_err(bad("EC key"))?;
    Ok(Key {
        pkcs8: pkcs8_der(EC_PUB, Some(AnyRef::from(&curve)), &inner),
        spki: spki_der(EC_PUB, Some(AnyRef::from(&curve)), &point),
        desc: format!("EC {name}"),
    })
}

pub fn from_ed25519_seed(seed: &[u8]) -> Result<Key, KeyError> {
    let seed: [u8; 32] = seed.try_into().map_err(|_| KeyError::Bad("Ed25519 key: the private key must be 32 bytes".into()))?;
    let public = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    Ok(Key {
        pkcs8: pkcs8_der(ED25519, None, &tlv::encode(0x04, &seed)),
        spki: spki_der(ED25519, None, &public),
        desc: "Ed25519".into(),
    })
}

/// DSA from (p, q, g, y?, x) big-endian integers; y is computed when absent.
pub fn from_dsa_parts(p: &[u8], q: &[u8], g: &[u8], y: Option<&[u8]>, x: &[u8]) -> Result<Key, KeyError> {
    let int = |b: &[u8]| -> Result<Vec<u8>, KeyError> { UintRef::new(b).and_then(|u| u.to_der()).map_err(bad("DSA key")) };
    let y = match y {
        Some(y) => y.to_vec(),
        None => {
            let (pb, gb, xb) = (rsa::BigUint::from_bytes_be(p), rsa::BigUint::from_bytes_be(g), rsa::BigUint::from_bytes_be(x));
            if pb.bits() == 0 || pb.bits() > 4096 { return Err(KeyError::Bad("DSA key: bad modulus".into())); }
            gb.modpow(&xb, &pb).to_bytes_be()
        }
    };
    let params = tlv::encode(0x30, &[int(p)?, int(q)?, int(g)?].concat());
    let params_any = AnyRef::from_der(&params).map_err(bad("DSA key"))?;
    Ok(Key {
        pkcs8: pkcs8_der(DSA, Some(params_any), &int(x)?),
        spki: spki_der(DSA, Some(params_any), &int(&y)?),
        desc: "DSAPublicKey".into(),
    })
}

/// OpenSSL "traditional" DSA: SEQUENCE { 0, p, q, g, y, x }.
pub fn from_dsa_traditional(der: &[u8]) -> Result<Key, KeyError> {
    let t = tlv::read_exact(der).map_err(|_| KeyError::NotAKey)?;
    let c = t.children().map_err(|_| KeyError::NotAKey)?;
    if t.tag != 0x30 || c.len() != 6 || c.iter().any(|x| x.tag != 0x02) || c[0].content != [0] { return Err(KeyError::NotAKey); }
    let v = |i: usize| c[i].content;
    from_dsa_parts(v(1), v(2), v(3), Some(v(4)), v(5))
}

pub fn from_pkcs8(der: &[u8]) -> Result<Key, KeyError> {
    let info = pkcs8::PrivateKeyInfo::try_from(der).map_err(|_| KeyError::NotAKey)?;
    let oid = info.algorithm.oid;
    if oid == RSA_ENC || oid == RSA_PSS {
        return from_pkcs1(info.private_key).map_err(|e| if e == KeyError::NotAKey { KeyError::Bad("RSA key: the inner RSAPrivateKey is malformed".into()) } else { e });
    }
    if oid == EC_PUB {
        let curve = info.algorithm.parameters.and_then(|p| p.decode_as::<Oid>().ok());
        return from_sec1(info.private_key, curve).map_err(|e| if e == KeyError::NotAKey { KeyError::Bad("EC key: the inner ECPrivateKey is malformed".into()) } else { e });
    }
    if oid == ED25519 {
        let seed = der::asn1::OctetStringRef::from_der(info.private_key).map_err(bad("Ed25519 key"))?;
        return from_ed25519_seed(seed.as_bytes());
    }
    if oid == DSA {
        let params = info.algorithm.parameters.ok_or_else(|| KeyError::Bad("DSA key without parameters".into()))?;
        // AnyRef::value() is the Dss-Parms SEQUENCE content: p, q, g.
        let pc = tlv::children(params.value()).map_err(bad("DSA key"))?;
        let x = tlv::read_exact(info.private_key).map_err(bad("DSA key"))?;
        if pc.len() != 3 || x.tag != 0x02 { return Err(KeyError::Bad("DSA key: malformed parameters".into())); }
        return from_dsa_parts(pc[0].content, pc[1].content, pc[2].content, None, x.content);
    }
    if oid == ED448 {
        return Err(KeyError::Unsupported("Ed448 keys aren't supported by this app. Use an RSA or ECDSA (P-256/P-384) certificate and key.".into()));
    }
    Err(KeyError::Unsupported(format!("key type {oid} can't be used for a web server certificate here.")))
}

/// Any unencrypted DER private key: PKCS#8, PKCS#1, SEC1 or traditional DSA.
pub fn from_der_any(der: &[u8]) -> Result<Key, KeyError> {
    for f in [from_pkcs8 as fn(&[u8]) -> Result<Key, KeyError>, from_pkcs1, |d| from_sec1(d, None), from_dsa_traditional] {
        match f(der) {
            Err(KeyError::NotAKey) => continue,
            other => return other,
        }
    }
    Err(KeyError::NotAKey)
}

/// Is this DER an EncryptedPrivateKeyInfo (SEQUENCE { AlgorithmIdentifier, OCTET STRING })?
pub fn looks_encrypted(der: &[u8]) -> bool {
    epki_parts(der).is_some()
}

fn epki_parts(der: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let t = tlv::read_exact(der).ok()?;
    if t.tag != 0x30 { return None; }
    let c = t.children().ok()?;
    if c.len() != 2 || c[0].tag != 0x30 || c[1].tag & !0x20 != 0x04 { return None; }
    let alg = c[0].children().ok()?;
    if alg.first().map(|a| a.tag) != Some(0x06) { return None; }
    Some((c[0].whole.to_vec(), tlv::octets(&c[1]).ok()?))
}

/// Decrypt an EncryptedPrivateKeyInfo and normalise the key.
pub fn from_encrypted_pkcs8(der: &[u8], pw: Pw<'_>) -> Result<Key, KeyError> {
    let (alg, ct) = epki_parts(der).ok_or(KeyError::NotAKey)?;
    let pt = pbe::decrypt(&alg, &ct, pw)?;
    match from_pkcs8(&pt) {
        Ok(k) => Ok(k),
        // Bad padding is caught in pbe; a wrong password that happens to unpad gives garbage here.
        Err(KeyError::NotAKey) => Err(KeyError::WrongPassword),
        Err(e) => Err(e),
    }
}

// ------------------------------------------------------------------ OpenSSL traditional encrypted PEM

/// `Proc-Type: 4,ENCRYPTED` + `DEK-Info: CIPHER,IV`: EVP_BytesToKey(MD5, salt = IV[..8], 1 round),
/// CBC with PKCS#7 padding. `label` decides the inner format (RSA / EC / DSA PRIVATE KEY).
pub fn from_legacy_pem(label: &str, headers: &[(String, String)], body: &[u8], pw: &str) -> Result<Key, KeyError> {
    use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
    use md5::Digest;
    let dek = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("DEK-Info")).map(|(_, v)| v.trim())
        .ok_or_else(|| KeyError::Bad("encrypted PEM without a DEK-Info header".into()))?;
    let (cipher, ivhex) = dek.split_once(',').ok_or_else(|| KeyError::Bad("malformed DEK-Info header".into()))?;
    let cipher = cipher.trim().to_ascii_uppercase();
    let (klen, ivlen) = match cipher.as_str() {
        "AES-128-CBC" => (16, 16), "AES-192-CBC" => (24, 16), "AES-256-CBC" => (32, 16),
        "DES-EDE3-CBC" => (24, 8), "DES-CBC" => (8, 8),
        c => return Err(KeyError::Unsupported(format!("PEM encryption {c} isn't supported. Convert the key: openssl pkey -in key.pem -out key-plain.pem"))),
    };
    let ivhex = ivhex.trim();
    if ivhex.len() != ivlen * 2 || !ivhex.bytes().all(|b| b.is_ascii_hexdigit()) { return Err(KeyError::Bad("malformed DEK-Info IV".into())); }
    let iv: Vec<u8> = (0..ivlen).map(|i| u8::from_str_radix(&ivhex[2 * i..2 * i + 2], 16).expect("hex checked")).collect();
    let mut key = Vec::with_capacity(klen + 16);
    let mut prev: Vec<u8> = Vec::new();
    while key.len() < klen {
        let mut h = md5::Md5::new();
        h.update(&prev);
        h.update(pw.as_bytes());
        h.update(&iv[..8]);
        prev = h.finalize().to_vec();
        key.extend_from_slice(&prev);
    }
    key.truncate(klen);
    let wrong = |_| KeyError::WrongPassword;
    let pt = match cipher.as_str() {
        "AES-128-CBC" => cbc::Decryptor::<aes::Aes128>::new_from_slices(&key, &iv).expect("sizes").decrypt_padded_vec_mut::<Pkcs7>(body).map_err(wrong)?,
        "AES-192-CBC" => cbc::Decryptor::<aes::Aes192>::new_from_slices(&key, &iv).expect("sizes").decrypt_padded_vec_mut::<Pkcs7>(body).map_err(wrong)?,
        "AES-256-CBC" => cbc::Decryptor::<aes::Aes256>::new_from_slices(&key, &iv).expect("sizes").decrypt_padded_vec_mut::<Pkcs7>(body).map_err(wrong)?,
        "DES-EDE3-CBC" => cbc::Decryptor::<des::TdesEde3>::new_from_slices(&key, &iv).expect("sizes").decrypt_padded_vec_mut::<Pkcs7>(body).map_err(wrong)?,
        _ => cbc::Decryptor::<des::Des>::new_from_slices(&key, &iv).expect("sizes").decrypt_padded_vec_mut::<Pkcs7>(body).map_err(wrong)?,
    };
    let r = match label {
        "RSA PRIVATE KEY" => from_pkcs1(&pt),
        "EC PRIVATE KEY" => from_sec1(&pt, None),
        "DSA PRIVATE KEY" => from_dsa_traditional(&pt),
        _ => from_der_any(&pt),
    };
    r.map_err(|e| if e == KeyError::NotAKey { KeyError::WrongPassword } else { e })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_bits_and_desc() {
        assert_eq!(bits(&[0x00, 0x80, 0, 0]), 24);
        assert_eq!(bits(&[0x01]), 1);
        assert_eq!(bits(&[]), 0);
    }

    #[test]
    fn ed25519_matches_rfc8410_example() {
        // RFC 8410 §10.3 private key and its public key.
        let seed = [0xd4, 0xee, 0x72, 0xdb, 0xf9, 0x13, 0x58, 0x4a, 0xd5, 0xb6, 0xd8, 0xf1, 0xf7, 0x69, 0xf8, 0xad,
                    0x3a, 0xfe, 0x7c, 0x28, 0xcb, 0xf1, 0xd4, 0xfb, 0xe0, 0x97, 0xa8, 0x8f, 0x44, 0x75, 0x58, 0x42];
        let k = from_ed25519_seed(&seed).unwrap();
        assert_eq!(&k.pkcs8[..16], &[0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]);
        assert_eq!(from_pkcs8(&k.pkcs8).unwrap().spki, k.spki);
        assert_eq!(k.spki.len(), 44);
        assert_eq!(describe_spki(&k.spki).0, "Ed25519");
    }

    #[test]
    fn garbage_is_not_a_key() {
        for d in [&b""[..], b"\x30\x00", b"\x30\x03\x02\x01\x00", b"hello"] {
            assert_eq!(from_der_any(d).unwrap_err(), KeyError::NotAKey);
        }
    }
}
