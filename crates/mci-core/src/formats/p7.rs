//! morpheus-certificate-install 0.4.2 — certificates out of a PKCS#7 / CMS SignedData (.p7b, .p7c).
//!
//! Walks ContentInfo → [0] → SignedData → `certificates [0] IMPLICIT` element by element, so the
//! certificates come back in the order the file holds them (what the reference returns; der 0.7's
//! SET OF decoding would re-sort them). BER indefinite lengths, as Windows writes, are accepted.

use super::tlv;
use const_oid::ObjectIdentifier as Oid;

const SIGNED_DATA: Oid = Oid::new_unwrap("1.2.840.113549.1.7.2");

/// DER of every certificate, in file order. Errors when this isn't SignedData or holds no
/// certificates (the reference raises "has no certificate data" then too).
pub fn certificates(data: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let e = |e: tlv::TlvError| e.to_string();
    let ci = tlv::read(data).map_err(e)?;
    if ci.whole.len() != data.len() || ci.tag != 0x30 { return Err("not a PKCS#7 structure".into()); }
    let parts = ci.children().map_err(e)?;
    if parts.first().map(tlv::oid).transpose().map_err(e)? != Some(SIGNED_DATA) { return Err("not PKCS#7 SignedData".into()); }
    let explicit = parts.get(1).filter(|t| t.tag == 0xA0).ok_or("PKCS#7 without content")?;
    let sd = explicit.children().map_err(e)?.into_iter().next().ok_or("PKCS#7 without SignedData")?;
    let mut out = Vec::new();
    for field in sd.children().map_err(e)? {
        if field.tag == 0xA0 {
            for c in field.children().map_err(e)? {
                if c.tag == 0x30 { out.push(c.whole.to_vec()); } // other CertificateChoices are skipped
            }
        }
    }
    if out.is_empty() { return Err("The provided PKCS7 has no certificate data".into()); }
    Ok(out)
}
