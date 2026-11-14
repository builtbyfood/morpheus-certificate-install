//! morpheus-certificate-install 0.4.2 — Java KeyStore (JKS), read natively (no Java, no crate).
//!
//! Format: magic 0xFEEDFEED, version 2, entry count; entries are
//! tag 1 (private key: alias, timestamp, EncryptedPrivateKeyInfo, certificate chain) or
//! tag 2 (trusted certificate). The last 20 bytes are SHA-1(password as UTF-16BE ‖
//! "Mighty Aphrodite" ‖ everything before them): that is how a wrong store password is detected.
//! Keys are protected with Sun's proprietary SHA-1 keystream (OID 1.3.6.1.4.1.42.2.17.1.1).
//! JCEKS (0xCECECECE) is recognised but not read (docs/PARITY.md).

use super::tlv;
use sha1::{Digest, Sha1};

pub const JKS_MAGIC: [u8; 4] = [0xFE, 0xED, 0xFE, 0xED];
pub const JCEKS_MAGIC: [u8; 4] = [0xCE, 0xCE, 0xCE, 0xCE];
const SUN_KEY_PROTECTOR: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x2a, 0x02, 0x11, 0x01, 0x01];

#[derive(Debug)]
pub struct KeyEntry {
    pub alias: String,
    /// EncryptedPrivateKeyInfo DER.
    pub protected: Vec<u8>,
    pub chain: Vec<Vec<u8>>,
}

#[derive(Debug, Default)]
pub struct Store {
    pub keys: Vec<KeyEntry>,
    pub trusted: Vec<(String, Vec<u8>)>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum JksError {
    WrongPassword,
    Damaged(String),
}

fn utf16be(pw: &str) -> Vec<u8> { pw.encode_utf16().flat_map(|u| u.to_be_bytes()).collect() }

/// Does `pw` open the store (integrity hash matches)?
pub fn password_ok(data: &[u8], pw: &str) -> bool {
    if data.len() < 12 + 20 { return false; }
    let (body, tag) = data.split_at(data.len() - 20);
    let mut h = Sha1::new();
    h.update(utf16be(pw));
    h.update(b"Mighty Aphrodite");
    h.update(body);
    h.finalize().as_slice() == tag
}

struct R<'a>(&'a [u8]);
impl<'a> R<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], JksError> {
        if self.0.len() < n { return Err(JksError::Damaged("the keystore is cut short".into())); }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u16(&mut self) -> Result<u16, JksError> { let b = self.take(2)?; Ok(u16::from_be_bytes([b[0], b[1]])) }
    fn u32(&mut self) -> Result<u32, JksError> { let b = self.take(4)?; Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]])) }
    /// Java modified UTF-8 (u16 length + bytes); fine to read as lossy UTF-8 for aliases and types.
    fn utf(&mut self) -> Result<String, JksError> { let n = self.u16()? as usize; Ok(String::from_utf8_lossy(self.take(n)?).into_owned()) }
    fn blob(&mut self) -> Result<&'a [u8], JksError> { let n = self.u32()? as usize; self.take(n) }
}

/// Parse a JKS after checking `store_pw` against its integrity hash.
pub fn open(data: &[u8], store_pw: &str) -> Result<Store, JksError> {
    if !password_ok(data, store_pw) { return Err(JksError::WrongPassword); }
    let mut r = R(&data[..data.len() - 20]);
    if r.take(4)? != JKS_MAGIC { return Err(JksError::Damaged("not a JKS keystore".into())); }
    let version = r.u32()?;
    if version != 2 && version != 1 { return Err(JksError::Damaged(format!("JKS version {version} isn't supported"))); }
    let count = r.u32()?;
    let mut store = Store::default();
    for _ in 0..count {
        let tag = r.u32()?;
        let alias = r.utf()?;
        r.take(8)?; // timestamp
        match tag {
            1 => {
                let protected = r.blob()?.to_vec();
                let n = r.u32()?;
                let mut chain = Vec::new();
                for _ in 0..n {
                    let typ = if version == 2 { r.utf()? } else { "X.509".into() };
                    let der = r.blob()?;
                    if typ == "X.509" { chain.push(der.to_vec()); }
                }
                store.keys.push(KeyEntry { alias, protected, chain });
            }
            2 => {
                let typ = if version == 2 { r.utf()? } else { "X.509".into() };
                let der = r.blob()?;
                if typ == "X.509" { store.trusted.push((alias, der.to_vec())); }
            }
            t => return Err(JksError::Damaged(format!("unknown keystore entry type {t}"))),
        }
    }
    if !r.0.is_empty() { return Err(JksError::Damaged("extra bytes after the last entry".into())); }
    Ok(store)
}

/// Undo Sun's key protector: returns the PKCS#8 DER, or None for a wrong password.
pub fn decrypt_key(protected: &[u8], pw: &str) -> Option<Vec<u8>> {
    let t = tlv::read_exact(protected).ok()?;
    let c = t.children().ok()?;
    let alg = c.first()?.children().ok()?;
    if alg.first()?.tag != 0x06 || alg.first()?.content != SUN_KEY_PROTECTOR { return None; }
    let enc = tlv::octets(c.get(1)?).ok()?;
    if enc.len() < 40 { return None; }
    let (salt, rest) = enc.split_at(20);
    let (ct, check) = rest.split_at(rest.len() - 20);
    let pwb = utf16be(pw);
    let mut pt = Vec::with_capacity(ct.len());
    let mut d: Vec<u8> = salt.to_vec();
    for chunk in ct.chunks(20) {
        let mut h = Sha1::new();
        h.update(&pwb);
        h.update(&d);
        d = h.finalize().to_vec();
        pt.extend(chunk.iter().zip(&d).map(|(a, b)| a ^ b));
    }
    let mut h = Sha1::new();
    h.update(&pwb);
    h.update(&pt);
    (h.finalize().as_slice() == check).then_some(pt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> Vec<u8> {
        let p: std::path::PathBuf = [env!("CARGO_MANIFEST_DIR"), "..", "..", "fixtures", "corpus", "keystore.jks"].iter().collect();
        std::fs::read(p).unwrap()
    }

    #[test]
    fn opens_the_corpus_keystore() {
        let d = store();
        assert_eq!(open(&d, "nope").unwrap_err(), JksError::WrongPassword);
        let s = open(&d, "storepw").unwrap();
        assert_eq!((s.keys.len(), s.keys[0].chain.len(), s.trusted.len()), (1, 2, 1));
        assert_eq!(s.keys[0].alias, "tomcat");
        assert!(decrypt_key(&s.keys[0].protected, "nope").is_none());
        let pk8 = decrypt_key(&s.keys[0].protected, "storepw").unwrap();
        assert!(crate::formats::keys::from_pkcs8(&pk8).is_ok());
    }

    #[test]
    fn truncated_never_panics() {
        let d = store();
        for n in 0..d.len() {
            let _ = open(&d[..n], "storepw");
        }
    }
}
