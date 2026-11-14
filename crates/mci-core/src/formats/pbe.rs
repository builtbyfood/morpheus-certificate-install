//! morpheus-certificate-install 0.4.1 — password-based decryption for PKCS#8 keys and PKCS#12 safes.
//!
//! Two families, both decrypt-only:
//! - **PKCS#12 PBE** (RFC 7292 App. B KDF, `pbeWithSHAAnd…`): RC2-40/128 and 2-/3-key 3DES, as in
//!   legacy Windows and `openssl pkcs12 -legacy` exports. The password is a NUL-terminated BMPString;
//!   OpenSSL's NULL password is zero bytes, which is different from "" (two NUL bytes).
//! - **PBES2** (RFC 8018: PBKDF2 or scrypt, then AES/3DES/DES-CBC) via `pkcs5`. The password is
//!   its UTF-8 bytes (what OpenSSL does inside a PFX too).
//!
//! Every work factor is checked against a limit *before* any derivation runs, so a hostile file
//! can't make the app spin: see [`MAX_ITERATIONS`].

use super::tlv;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, InnerIvInit, KeyIvInit};
use const_oid::ObjectIdentifier as Oid;

/// Upper bound for PBKDF2 / PKCS#12 KDF iteration counts (and the PKCS#12 MAC). Real exports
/// use 1–600,000; RFC 8018 suggests 10,000,000 as the top end for very critical keys.
pub const MAX_ITERATIONS: u64 = 10_000_000;
/// scrypt: refuse N > 2^20 or more than 64 MiB of working memory (OpenSSL's own default cap is 32 MiB).
const MAX_SCRYPT_LOG_N: u32 = 20;
const MAX_SCRYPT_MEM: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug)]
pub enum Pw<'a> {
    /// No password at all (OpenSSL's NULL). Differs from "" only for the PKCS#12 KDF.
    Null,
    Text(&'a str),
}

impl Pw<'_> {
    pub fn utf8(&self) -> &[u8] {
        match self { Pw::Null => b"", Pw::Text(s) => s.as_bytes() }
    }
    /// RFC 7292 §B.1: BMPString (UTF-16BE) with a two-byte NUL terminator; NULL → no bytes.
    pub fn bmp(&self) -> Vec<u8> {
        match self {
            Pw::Null => Vec::new(),
            Pw::Text(s) => {
                let mut v: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_be_bytes()).collect();
                v.extend_from_slice(&[0, 0]);
                v
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PbeError {
    /// Decryption produced garbage (bad padding): almost always the wrong password.
    WrongPassword,
    /// A work factor is above our limit; the message says which and what to do.
    Limit(String),
    Unsupported(String),
    Bad(String),
}

pub const PBE_SHA1_RC4_128: Oid = Oid::new_unwrap("1.2.840.113549.1.12.1.1");
pub const PBE_SHA1_RC4_40: Oid = Oid::new_unwrap("1.2.840.113549.1.12.1.2");
pub const PBE_SHA1_3DES: Oid = Oid::new_unwrap("1.2.840.113549.1.12.1.3");
pub const PBE_SHA1_2DES: Oid = Oid::new_unwrap("1.2.840.113549.1.12.1.4");
pub const PBE_SHA1_RC2_128: Oid = Oid::new_unwrap("1.2.840.113549.1.12.1.5");
pub const PBE_SHA1_RC2_40: Oid = Oid::new_unwrap("1.2.840.113549.1.12.1.6");
pub const PBES2: Oid = Oid::new_unwrap("1.2.840.113549.1.5.13");

pub fn limit_msg(what: &str, n: u64) -> String {
    format!(
        "It asks for {} {what}; the most this app will run is {}. A normal export never needs that many,          so the file is damaged or wasn't made by a certificate tool. Export it again.",
        grouped(n), grouped(MAX_ITERATIONS)
    )
}

/// 2000000000 → "2,000,000,000"
fn grouped(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 { out.push(','); }
        out.push(c);
    }
    out
}

pub fn check_iterations(what: &str, n: u64) -> Result<(), PbeError> {
    if n == 0 { return Err(PbeError::Bad(format!("{what}: an iteration count of 0 is invalid"))); }
    if n > MAX_ITERATIONS { return Err(PbeError::Limit(limit_msg(what, n))); }
    Ok(())
}

/// Decrypt `ct` with the AlgorithmIdentifier `alg_der` (its complete DER).
pub fn decrypt(alg_der: &[u8], ct: &[u8], pw: Pw<'_>) -> Result<Vec<u8>, PbeError> {
    let bad = |e: tlv::TlvError| PbeError::Bad(format!("encryption parameters: {e}"));
    let alg = tlv::read_exact(alg_der).map_err(bad)?;
    let parts = alg.children().map_err(bad)?;
    let oid = parts.first().map(tlv::oid).transpose().map_err(bad)?.ok_or_else(|| PbeError::Bad("encryption algorithm missing".into()))?;
    if [PBE_SHA1_3DES, PBE_SHA1_2DES, PBE_SHA1_RC2_128, PBE_SHA1_RC2_40].contains(&oid) {
        // pkcs-12PbeParams ::= SEQUENCE { salt OCTET STRING, iterations INTEGER }
        let p = parts.get(1).ok_or_else(|| PbeError::Bad("PBE parameters missing".into()))?;
        let pc = p.children().map_err(bad)?;
        let (salt, iters) = match pc.as_slice() {
            [s, i] => (tlv::octets(s).map_err(bad)?, tlv::uint(i).map_err(bad)?),
            _ => return Err(PbeError::Bad("PBE parameters malformed".into())),
        };
        check_iterations("key-derivation iterations", iters)?;
        return pkcs12_pbe(oid, &salt, iters as i32, ct, &pw.bmp());
    }
    if oid == PBE_SHA1_RC4_128 || oid == PBE_SHA1_RC4_40 {
        return Err(PbeError::Unsupported("RC4 encryption (pbeWithSHAAnd…RC4) isn't supported. Export it again with AES (or 3DES).".into()));
    }
    if oid == PBES2 {
        let scheme = pkcs5::EncryptionScheme::try_from(alg_der)
            .map_err(|e| PbeError::Unsupported(format!("PBES2 parameters this app can't use ({e}). Export it again with AES-256.")))?;
        if let pkcs5::EncryptionScheme::Pbes2(params) = &scheme {
            match &params.kdf {
                pkcs5::pbes2::Kdf::Pbkdf2(k) => check_iterations("PBKDF2 iterations", k.iteration_count as u64)?,
                pkcs5::pbes2::Kdf::Scrypt(s) => {
                    let n = s.cost_parameter;
                    let mem = 128u64.saturating_mul(s.block_size as u64).saturating_mul(n.saturating_add(s.parallelization as u64));
                    if n == 0 || !n.is_power_of_two() || n.trailing_zeros() > MAX_SCRYPT_LOG_N || mem > MAX_SCRYPT_MEM {
                        return Err(PbeError::Limit(format!(
                            "It asks for scrypt with N={n}, r={}, p={}; that's more work or memory than this app will run. Export it again.",
                            s.block_size, s.parallelization)));
                    }
                }
                _ => return Err(PbeError::Unsupported("PBES2 key derivation this app can't use. Export it again with AES-256.".into())),
            }
        }
        return scheme.decrypt(pw.utf8(), ct).map_err(|e| match e {
            pkcs5::Error::DecryptFailed => PbeError::WrongPassword,
            other => PbeError::Unsupported(format!("PBES2 cipher this app can't use ({other}). Export it again with AES-256.")),
        });
    }
    Err(PbeError::Unsupported(format!("encryption algorithm {oid} isn't supported. Export it again with AES-256.")))
}

fn pkcs12_pbe(oid: Oid, salt: &[u8], iters: i32, ct: &[u8], pass: &[u8]) -> Result<Vec<u8>, PbeError> {
    use pkcs12::kdf::{derive_key, Pkcs12KeyType};
    let klen = if oid == PBE_SHA1_3DES { 24 } else if oid == PBE_SHA1_2DES || oid == PBE_SHA1_RC2_128 { 16 } else { 5 };
    let key = derive_key::<sha1::Sha1>(pass, salt, Pkcs12KeyType::EncryptionKey, iters, klen);
    let iv = derive_key::<sha1::Sha1>(pass, salt, Pkcs12KeyType::Iv, iters, 8);
    let wrong = |_| PbeError::WrongPassword;
    if oid == PBE_SHA1_3DES {
        cbc::Decryptor::<des::TdesEde3>::new_from_slices(&key, &iv).map_err(|_| PbeError::Bad("3DES key".into()))?
            .decrypt_padded_vec_mut::<Pkcs7>(ct).map_err(wrong)
    } else if oid == PBE_SHA1_2DES {
        cbc::Decryptor::<des::TdesEde2>::new_from_slices(&key, &iv).map_err(|_| PbeError::Bad("2DES key".into()))?
            .decrypt_padded_vec_mut::<Pkcs7>(ct).map_err(wrong)
    } else {
        let rc2 = rc2::Rc2::new_with_eff_key_len(&key, klen * 8);
        cbc::Decryptor::<rc2::Rc2>::inner_iv_slice_init(rc2, &iv).map_err(|_| PbeError::Bad("RC2 IV".into()))?
            .decrypt_padded_vec_mut::<Pkcs7>(ct).map_err(wrong)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_encodings() {
        assert_eq!(Pw::Null.bmp(), Vec::<u8>::new());
        assert_eq!(Pw::Text("").bmp(), vec![0, 0]);
        assert_eq!(Pw::Text("pé").bmp(), vec![0, b'p', 0, 0xe9, 0, 0]);
        assert_eq!(Pw::Text("pé").utf8(), "pé".as_bytes());
    }

    #[test]
    fn huge_pkcs12_pbe_iterations_are_refused_before_any_work() {
        // pbeWithSHAAnd3-KeyTripleDES-CBC { salt 8 bytes, iterations 2,000,000,000 }
        let params = [tlv::encode(0x04, &[1u8; 8]), tlv::encode(0x02, &[0x77, 0x35, 0x94, 0x00])].concat();
        let alg = [tlv::encode(0x06, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x03]), tlv::encode(0x30, &params)].concat();
        let alg = tlv::encode(0x30, &alg);
        let t = std::time::Instant::now();
        match decrypt(&alg, &[0u8; 16], Pw::Text("x")) {
            Err(PbeError::Limit(m)) => assert!(m.contains("2,000,000,000") && m.contains("10,000,000"), "{m}"),
            other => panic!("{other:?}"),
        }
        assert!(t.elapsed().as_millis() < 100);
    }
}
