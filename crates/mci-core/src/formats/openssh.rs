//! morpheus-certificate-install 0.4.2 — `-----BEGIN OPENSSH PRIVATE KEY-----` (openssh-key-v1).
//!
//! Layout (PROTOCOL.key in OpenSSH): "openssh-key-v1\0", string cipher, string kdf, string kdfoptions,
//! u32 nkeys, string pubkey…, string private-section. The private section (decrypted if needed)
//! is u32 check, u32 check, then per key: string type + type-specific fields + string comment.
//! Ciphers: none, aes{128,192,256}-ctr (ssh-keygen's default), aes{128,256}-cbc. KDF: bcrypt.
//! Key types: ssh-rsa, ssh-ed25519, ecdsa-sha2-nistp{256,384,521}, ssh-dss.

use super::keys::{self, Key, KeyError};
use const_oid::ObjectIdentifier as Oid;

const MAGIC: &[u8] = b"openssh-key-v1\0";
/// bcrypt rounds are far heavier than PBKDF2 iterations; ssh-keygen's default is 16, `-a 100` is
/// already slow. Anything above this is refused rather than run.
pub const MAX_BCRYPT_ROUNDS: u32 = 1_000;

struct R<'a>(&'a [u8]);

impl<'a> R<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], KeyError> {
        if self.0.len() < n { return Err(KeyError::Bad("OpenSSH key: cut short".into())); }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u32(&mut self) -> Result<u32, KeyError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn string(&mut self) -> Result<&'a [u8], KeyError> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    /// mpint as unsigned big-endian (leading zero stripped).
    fn mpint(&mut self) -> Result<&'a [u8], KeyError> {
        let s = self.string()?;
        if s.first().is_some_and(|b| b & 0x80 != 0) { return Err(KeyError::Bad("OpenSSH key: negative integer".into())); }
        Ok(if s.first() == Some(&0) { &s[1..] } else { s })
    }
}

/// Parse an OpenSSH private key. `pw` None means "try without a passphrase".
pub fn parse(blob: &[u8], pw: Option<&str>) -> Result<Key, KeyError> {
    let mut r = R(blob);
    if r.take(MAGIC.len())? != MAGIC { return Err(KeyError::Bad("OpenSSH key: bad magic".into())); }
    let cipher = std::str::from_utf8(r.string()?).unwrap_or("?").to_string();
    let kdf = r.string()?.to_vec();
    let kdfopts = r.string()?.to_vec();
    if r.u32()? != 1 { return Err(KeyError::Unsupported("OpenSSH key files with more than one key aren't supported.".into())); }
    let _public = r.string()?;
    let section = r.string()?;
    let plain: Vec<u8> = if cipher == "none" {
        if kdf != b"none" { return Err(KeyError::Bad("OpenSSH key: KDF without a cipher".into())); }
        section.to_vec()
    } else {
        let Some(pw) = pw else { return Err(KeyError::NeedPassword) };
        if kdf != b"bcrypt" { return Err(KeyError::Unsupported(format!("OpenSSH key KDF {} isn't supported.", String::from_utf8_lossy(&kdf)))); }
        let mut o = R(&kdfopts);
        let salt = o.string()?;
        let rounds = o.u32()?;
        if rounds == 0 { return Err(KeyError::Bad("OpenSSH key: 0 bcrypt rounds".into())); }
        if rounds > MAX_BCRYPT_ROUNDS {
            return Err(KeyError::Limit(format!("It asks for {rounds} bcrypt rounds; the most this app will run is {MAX_BCRYPT_ROUNDS}. Re-save it with ssh-keygen -p -a 16, or convert it: ssh-keygen -p -m PKCS8 -f key")));
        }
        let (klen, ivlen) = match cipher.as_str() {
            "aes128-ctr" | "aes128-cbc" => (16, 16),
            "aes192-ctr" => (24, 16),
            "aes256-ctr" | "aes256-cbc" => (32, 16),
            c => return Err(KeyError::Unsupported(format!(
                "OpenSSH key cipher {c} isn't supported. Convert it: ssh-keygen -p -m PKCS8 -f key (keeps a passphrase) and load that."))),
        };
        if section.len() % 16 != 0 { return Err(KeyError::Bad("OpenSSH key: private section isn't a whole number of blocks".into())); }
        let mut kiv = vec![0u8; klen + ivlen];
        bcrypt_pbkdf::bcrypt_pbkdf(pw.as_bytes(), salt, rounds, &mut kiv).map_err(|_| KeyError::Bad("OpenSSH key: bcrypt parameters".into()))?;
        let (k, iv) = kiv.split_at(klen);
        let mut buf = section.to_vec();
        decrypt(&cipher, k, iv, &mut buf);
        buf
    };
    let mut p = R(&plain);
    let (c1, c2) = (p.u32()?, p.u32()?);
    if c1 != c2 { return Err(if cipher == "none" { KeyError::Bad("OpenSSH key: check bytes differ".into()) } else { KeyError::WrongPassword }); }
    let kind = p.string()?.to_vec();
    match kind.as_slice() {
        b"ssh-rsa" => {
            let (n, e, d, iqmp, pp, q) = (p.mpint()?, p.mpint()?, p.mpint()?, p.mpint()?, p.mpint()?, p.mpint()?);
            rsa_from_parts(n, e, d, iqmp, pp, q)
        }
        b"ssh-ed25519" => {
            let _pk = p.string()?;
            let sk = p.string()?;
            if sk.len() != 64 { return Err(KeyError::Bad("OpenSSH Ed25519 key: private part must be 64 bytes".into())); }
            keys::from_ed25519_seed(&sk[..32])
        }
        b"ecdsa-sha2-nistp256" | b"ecdsa-sha2-nistp384" | b"ecdsa-sha2-nistp521" => {
            let curve: Oid = match p.string()? {
                b"nistp256" => keys::P256,
                b"nistp384" => keys::P384,
                b"nistp521" => keys::P521,
                _ => return Err(KeyError::Bad("OpenSSH ECDSA key: unknown curve".into())),
            };
            let q = p.string()?;
            let d = p.mpint()?;
            let sec1 = sec1::EcPrivateKey { private_key: d, parameters: Some(sec1::EcParameters::NamedCurve(curve)), public_key: Some(q) };
            let der = der::Encode::to_der(&sec1).map_err(|e| KeyError::Bad(format!("OpenSSH ECDSA key: {e}")))?;
            keys::from_sec1(&der, Some(curve))
        }
        b"ssh-dss" => {
            let (pp, q, g, y, x) = (p.mpint()?, p.mpint()?, p.mpint()?, p.mpint()?, p.mpint()?);
            keys::from_dsa_parts(pp, q, g, Some(y), x)
        }
        other => Err(KeyError::Unsupported(format!("OpenSSH key type {} isn't supported.", String::from_utf8_lossy(other)))),
    }
}

fn decrypt(cipher: &str, k: &[u8], iv: &[u8], buf: &mut [u8]) {
    use aes::cipher::{BlockDecryptMut, KeyIvInit, StreamCipher};
    match cipher {
        "aes128-ctr" => ctr::Ctr128BE::<aes::Aes128>::new_from_slices(k, iv).expect("sizes").apply_keystream(buf),
        "aes192-ctr" => ctr::Ctr128BE::<aes::Aes192>::new_from_slices(k, iv).expect("sizes").apply_keystream(buf),
        "aes256-ctr" => ctr::Ctr128BE::<aes::Aes256>::new_from_slices(k, iv).expect("sizes").apply_keystream(buf),
        "aes128-cbc" => { let _ = cbc::Decryptor::<aes::Aes128>::new_from_slices(k, iv).expect("sizes").decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(buf); }
        _ => { let _ = cbc::Decryptor::<aes::Aes256>::new_from_slices(k, iv).expect("sizes").decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(buf); }
    }
}

/// PKCS#1 from OpenSSH's (n, e, d, iqmp, p, q): dp = d mod (p-1), dq = d mod (q-1); iqmp is
/// already q⁻¹ mod p, the PKCS#1 coefficient.
fn rsa_from_parts(n: &[u8], e: &[u8], d: &[u8], iqmp: &[u8], p: &[u8], q: &[u8]) -> Result<Key, KeyError> {
    use der::{asn1::UintRef, Encode};
    use rsa::BigUint;
    if n.len() > 2048 { return Err(KeyError::Bad("OpenSSH RSA key: modulus too large".into())); }
    let one = BigUint::from(1u32);
    let (bd, bp, bq) = (BigUint::from_bytes_be(d), BigUint::from_bytes_be(p), BigUint::from_bytes_be(q));
    if bp <= one || bq <= one { return Err(KeyError::Bad("OpenSSH RSA key: bad primes".into())); }
    let dp = (&bd % (&bp - &one)).to_bytes_be();
    let dq = (&bd % (&bq - &one)).to_bytes_be();
    fn u(b: &[u8]) -> Result<UintRef<'_>, KeyError> { UintRef::new(b).map_err(|e| KeyError::Bad(format!("OpenSSH RSA key: {e}"))) }
    let k = pkcs1::RsaPrivateKey {
        modulus: u(n)?, public_exponent: u(e)?, private_exponent: u(d)?,
        prime1: u(p)?, prime2: u(q)?, exponent1: u(&dp)?, exponent2: u(&dq)?, coefficient: u(iqmp)?,
        other_prime_infos: None,
    };
    keys::from_pkcs1(&k.to_der().map_err(|e| KeyError::Bad(format!("OpenSSH RSA key: {e}")))?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::sha256_hex;

    fn body(pem: &str) -> Vec<u8> {
        use base64::Engine;
        let b: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        base64::engine::general_purpose::STANDARD.decode(b).unwrap()
    }

    // Throwaway test keys made with ssh-keygen (OpenSSH for Windows / Git). Expected values are
    // sha256(PKCS#8)[:16] and sha256(SPKI)[:16] from the reference's cryptography 50.0.2:
    //   load_ssh_private_key(..).private_bytes(DER, PKCS8, NoEncryption()) / public_bytes(DER, SPKI)
    const ED25519: &str = include_str!("testdata/ossh-ed25519");
    const EC_ENC: &str = include_str!("testdata/ossh-ec-enc"); // passphrase "sshpw", bcrypt -a 4, aes256-ctr
    const RSA: &str = include_str!("testdata/ossh-rsa");

    #[test]
    fn same_bytes_as_the_reference() {
        for (pem, pw, pk8, spki, desc) in [
            (ED25519, None, "caf4648a3a39da38", "c320516d8de8cd47", "Ed25519"),
            (EC_ENC, Some("sshpw"), "b0f41dd735bcfb4c", "f6b08c4209aa59ec", "EC secp256r1"),
            (RSA, None, "b915f03a5f6b7feb", "3176e7739f5904cd", "RSA 1024"),
        ] {
            let k = parse(&body(pem), pw).unwrap();
            assert_eq!((&sha256_hex(&k.pkcs8)[..16], &sha256_hex(&k.spki)[..16], k.desc.as_str()), (pk8, spki, desc));
        }
    }

    #[test]
    fn passphrase_handling() {
        assert_eq!(parse(&body(EC_ENC), None).unwrap_err(), KeyError::NeedPassword);
        assert_eq!(parse(&body(EC_ENC), Some("nope")).unwrap_err(), KeyError::WrongPassword);
        // An unencrypted key ignores a passphrase (the caller tries None first, as the reference does).
        assert!(parse(&body(ED25519), Some("x")).is_ok());
    }

    #[test]
    fn truncated_never_panics() {
        let b = body(EC_ENC);
        for n in 0..b.len() {
            assert!(parse(&b[..n], Some("sshpw")).is_err());
        }
    }
}
