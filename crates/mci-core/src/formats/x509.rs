//! morpheus-certificate-install 0.4.1 — X.509 certificate → `model::Cert`, every field precomputed.
//!
//! Parsing and validation use `x509-cert`; names are rendered from the raw DER by our own
//! [`rfc4514`], which mirrors cryptography's `Name.rfc4514_string()` (RDNs reversed, multi-valued
//! RDNs joined with '+', short names only for CN/L/ST/O/OU/C/STREET/DC/UID, `_escape_dn_value`
//! escaping). The R0 spike checked it against Python on a certificate built to hit every trap.

use super::keys;
use super::tlv::{self, Tlv};
use crate::model::Cert;
use const_oid::ObjectIdentifier as Oid;
use der::Decode;

const CN: &str = "2.5.4.3";
const EXT_BASIC: Oid = Oid::new_unwrap("2.5.29.19");
const EXT_SAN: Oid = Oid::new_unwrap("2.5.29.17");
const EXT_AIA: Oid = Oid::new_unwrap("1.3.6.1.5.5.7.1.1");
const AIA_CA_ISSUERS: Oid = Oid::new_unwrap("1.3.6.1.5.5.7.48.2");

/// Parse one DER certificate (exactly one, no trailing bytes) into a Cert.
pub fn cert_from_der(der_bytes: &[u8], source: &str) -> Result<Cert, String> {
    let c = x509_cert::Certificate::from_der(der_bytes).map_err(|e| e.to_string())?;
    // Raw pieces of the TBSCertificate, exactly as encoded.
    let top = tlv::read_exact(der_bytes).map_err(|e| e.to_string())?;
    let parts = top.children().map_err(|e| e.to_string())?;
    let tbs = parts.first().ok_or("no TBSCertificate")?.children().map_err(|e| e.to_string())?;
    let off = if tbs.first().map(|t| t.tag) == Some(0xA0) { 1 } else { 0 };
    let field = |i: usize| tbs.get(off + i).ok_or_else(|| "TBSCertificate is short".to_string());
    let issuer_raw = field(2)?;
    let subject_raw = field(4)?;
    let spki_raw = field(5)?;

    let subject = rfc4514(subject_raw)?;
    let issuer = rfc4514(issuer_raw)?;
    let cn = first_cn(subject_raw)?.unwrap_or_else(|| subject.clone());
    let spki_der = keys::normalize_spki(spki_raw.whole);
    let (key_desc, rsa_bits) = keys::describe_spki(&spki_der);

    let (mut is_ca, mut san_dns, mut san_ip, mut aia) = (false, vec![], vec![], vec![]);
    for ext in c.tbs_certificate.extensions.iter().flatten() {
        let v = ext.extn_value.as_bytes();
        if ext.extn_id == EXT_BASIC {
            if let Ok(b) = x509_cert::ext::pkix::BasicConstraints::from_der(v) { is_ca = b.ca; }
        } else if ext.extn_id == EXT_SAN {
            if let Ok(san) = x509_cert::ext::pkix::SubjectAltName::from_der(v) {
                for g in san.0 {
                    match g {
                        x509_cert::ext::pkix::name::GeneralName::DnsName(d) => san_dns.push(d.as_str().to_string()),
                        x509_cert::ext::pkix::name::GeneralName::IpAddress(o) => {
                            let b = o.as_bytes();
                            if let Ok(a) = <[u8; 4]>::try_from(b) { san_ip.push(std::net::Ipv4Addr::from(a).to_string()); }
                            else if let Ok(a) = <[u8; 16]>::try_from(b) { san_ip.push(std::net::Ipv6Addr::from(a).to_string()); }
                        }
                        _ => {}
                    }
                }
            }
        } else if ext.extn_id == EXT_AIA {
            if let Ok(a) = x509_cert::ext::pkix::AuthorityInfoAccessSyntax::from_der(v) {
                for d in a.0 {
                    if d.access_method != AIA_CA_ISSUERS { continue; }
                    if let x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(u) = d.access_location {
                        // Every scheme is kept (ldap: too); aia.rs fetches only http(s) and explains the rest.
                        aia.push(u.as_str().to_string());
                    }
                }
            }
        }
    }
    let v = &c.tbs_certificate.validity;
    Ok(Cert {
        der: der_bytes.to_vec(),
        spki_der,
        subject,
        issuer,
        subject_raw: subject_raw.whole.to_vec(),
        issuer_raw: issuer_raw.whole.to_vec(),
        subject_name: name_key(subject_raw)?,
        issuer_name: name_key(issuer_raw)?,
        cn,
        san_dns,
        san_ip,
        not_before: v.not_before.to_unix_duration().as_secs() as i64,
        not_after: v.not_after.to_unix_duration().as_secs() as i64,
        is_ca,
        sig_hash: sig_hash(&c.signature_algorithm),
        key_desc,
        rsa_bits,
        aia_ca_issuers: aia,
        source: source.to_string(),
    })
}

/// Python's `signature_hash_algorithm.name`; empty when there is none (Ed25519/Ed448) or unknown.
pub fn sig_hash(alg: &spki::AlgorithmIdentifierOwned) -> String {
    let s = alg.oid.to_string();
    let h = match s.as_str() {
        "1.2.840.113549.1.1.4" => "md5",
        "1.2.840.113549.1.1.5" | "1.2.840.10045.4.1" | "1.2.840.10040.4.3" => "sha1",
        "1.2.840.113549.1.1.14" | "1.2.840.10045.4.3.1" | "2.16.840.1.101.3.4.3.1" => "sha224",
        "1.2.840.113549.1.1.11" | "1.2.840.10045.4.3.2" | "2.16.840.1.101.3.4.3.2" => "sha256",
        "1.2.840.113549.1.1.12" | "1.2.840.10045.4.3.3" | "2.16.840.1.101.3.4.3.3" => "sha384",
        "1.2.840.113549.1.1.13" | "1.2.840.10045.4.3.4" | "2.16.840.1.101.3.4.3.4" => "sha512",
        "2.16.840.1.101.3.4.3.13" | "2.16.840.1.101.3.4.3.9" => "sha3-224",
        "2.16.840.1.101.3.4.3.14" | "2.16.840.1.101.3.4.3.10" => "sha3-256",
        "2.16.840.1.101.3.4.3.15" | "2.16.840.1.101.3.4.3.11" => "sha3-384",
        "2.16.840.1.101.3.4.3.16" | "2.16.840.1.101.3.4.3.12" => "sha3-512",
        "1.2.840.113549.1.1.10" => return pss_hash(alg),
        _ => "",
    };
    h.to_string()
}

/// RSASSA-PSS-params hashAlgorithm [0] (default SHA-1).
fn pss_hash(alg: &spki::AlgorithmIdentifierOwned) -> String {
    let Some(p) = &alg.parameters else { return "sha1".into() };
    let inner = || -> Option<String> {
        for c in tlv::children(p.value()).ok()? {
            if c.tag == 0xA0 {
                let a = tlv::read(c.content).ok()?;
                let o = tlv::oid(a.children().ok()?.first()?).ok()?;
                return Some(hash_name(&o).to_string());
            }
        }
        Some("sha1".into())
    };
    inner().unwrap_or_default()
}

pub fn hash_name(o: &Oid) -> &'static str {
    match o.to_string().as_str() {
        "1.3.14.3.2.26" => "sha1",
        "2.16.840.1.101.3.4.2.4" => "sha224",
        "2.16.840.1.101.3.4.2.1" => "sha256",
        "2.16.840.1.101.3.4.2.2" => "sha384",
        "2.16.840.1.101.3.4.2.3" => "sha512",
        "1.2.840.113549.2.5" => "md5",
        _ => "",
    }
}

fn short_name(oid: &str) -> Option<&'static str> {
    Some(match oid {
        "2.5.4.3" => "CN", "2.5.4.7" => "L", "2.5.4.8" => "ST", "2.5.4.10" => "O",
        "2.5.4.11" => "OU", "2.5.4.6" => "C", "2.5.4.9" => "STREET",
        "0.9.2342.19200300.100.1.25" => "DC", "0.9.2342.19200300.100.1.1" => "UID",
        _ => return None,
    })
}

enum Val { Text(String), Bytes(Vec<u8>) }

/// Attribute value as cryptography decodes it.
fn value(t: &Tlv<'_>) -> Val {
    let c = t.content;
    let latin1 = || c.iter().map(|b| *b as char).collect::<String>();
    match t.tag {
        0x0C => Val::Text(String::from_utf8_lossy(c).into_owned()),
        0x13 | 0x16 | 0x1A | 0x12 | 0x14 => Val::Text(latin1()),
        0x1E => Val::Text(String::from_utf16_lossy(&c.chunks(2).map(|p| u16::from_be_bytes([p[0], *p.get(1).unwrap_or(&0)])).collect::<Vec<_>>())),
        0x1C => Val::Text(c.chunks(4).filter_map(|p| if p.len() == 4 { char::from_u32(u32::from_be_bytes([p[0], p[1], p[2], p[3]])) } else { None }).collect()),
        0x03 => Val::Bytes(c.get(1..).unwrap_or_default().to_vec()),
        _ => Val::Bytes(c.to_vec()),
    }
}

fn escape(v: &Val) -> String {
    match v {
        Val::Bytes(b) if b.is_empty() => String::new(),
        Val::Bytes(b) => format!("#{}", b.iter().map(|x| format!("{x:02x}")).collect::<String>()),
        Val::Text(t) if t.is_empty() => String::new(),
        Val::Text(t) => {
            let mut s = t.replace('\\', "\\\\").replace('"', "\\\"").replace('+', "\\+").replace(',', "\\,")
                .replace(';', "\\;").replace('<', "\\<").replace('>', "\\>").replace('\0', "\\00");
            if s.starts_with('#') || s.starts_with(' ') { s.insert(0, '\\'); }
            if s.ends_with(' ') { s.pop(); s.push_str("\\ "); }
            s
        }
    }
}

/// (oid, value) for every attribute, RDN by RDN in encoded order.
fn rdns<'a>(name: &Tlv<'a>) -> Result<Vec<Vec<(String, Tlv<'a>)>>, String> {
    let e = |e: tlv::TlvError| format!("name: {e}");
    let mut out = vec![];
    for rdn in name.children().map_err(e)? {
        let mut atvs = vec![];
        for atv in rdn.children().map_err(e)? {
            let p = atv.children().map_err(e)?;
            if p.len() != 2 { return Err("name: malformed attribute".into()); }
            atvs.push((tlv::oid(&p[0]).map_err(e)?.to_string(), p[1]));
        }
        out.push(atvs);
    }
    Ok(out)
}

/// The comparison key for `Name.__eq__` (see `model::NameKey`).
pub fn name_key(name: &Tlv<'_>) -> Result<crate::model::NameKey, String> {
    Ok(rdns(name)?.into_iter().map(|rdn| {
        let mut set: Vec<(String, String)> = rdn.into_iter().map(|(oid, v)| (oid, match value(&v) {
            Val::Text(t) => format!("T:{t}"),
            Val::Bytes(b) => format!("B:{}", b.iter().map(|x| format!("{x:02x}")).collect::<String>()),
        })).collect();
        set.sort();
        set.dedup();
        set
    }).collect())
}

/// `Name.rfc4514_string()`.
pub fn rfc4514(name: &Tlv<'_>) -> Result<String, String> {
    Ok(rdns(name)?.iter().rev().map(|rdn| {
        rdn.iter().map(|(oid, v)| format!("{}={}", short_name(oid).map(str::to_string).unwrap_or_else(|| oid.clone()), escape(&value(v))))
            .collect::<Vec<_>>().join("+")
    }).collect::<Vec<_>>().join(","))
}

/// The first commonName in encoded order (`get_attributes_for_oid(CN)[0].value`).
fn first_cn(name: &Tlv<'_>) -> Result<Option<String>, String> {
    for rdn in rdns(name)? {
        for (oid, v) in rdn {
            if oid == CN {
                return Ok(Some(match value(&v) { Val::Text(t) => t, Val::Bytes(b) => String::from_utf8_lossy(&b).into_owned() }));
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Self-signed P-256 cert with every RFC 4514 trap: 9 RDNs, a multi-valued RDN, emailAddress,
    /// serialNumber, an unknown OID, leading '#', trailing space, ,;<>+"\ and U+00EB (from R0).
    const MULTI_PEM: &str = "MIICdzCCAh2gAwIBAgIBBzAKBggqhkjOPQQDAjCBxDELMAkGA1UEBhMCVVMxETAP
BgNVBAgMCE5ldyBZb3JrMRowGAYDVQQKDBFBY21lLCBJbmMuICJXZXN0IjEYMAkG
A1UECwwCSVQwCwYDVQQDDARtdit4MRcwFQYJKoZIhvcNAQkBFghhQGIudGVzdDEQ
MA4GBCoDBAUMBmN1c3RvbTELMAkGA1UEBRMCNDIxFDASBgoJkiaJk/IsZAEZFgR0
ZXN0MR4wHAYDVQQDDBUjbGVhZDsgcTx4Pj15IFwgWm/DqyAwHhcNMjYwMTAxMDAw
MDAwWhcNMjYwMTMxMDAwMDAwWjCBxDELMAkGA1UEBhMCVVMxETAPBgNVBAgMCE5l
dyBZb3JrMRowGAYDVQQKDBFBY21lLCBJbmMuICJXZXN0IjEYMAkGA1UECwwCSVQw
CwYDVQQDDARtdit4MRcwFQYJKoZIhvcNAQkBFghhQGIudGVzdDEQMA4GBCoDBAUM
BmN1c3RvbTELMAkGA1UEBRMCNDIxFDASBgoJkiaJk/IsZAEZFgR0ZXN0MR4wHAYD
VQQDDBUjbGVhZDsgcTx4Pj15IFwgWm/DqyAwWTATBgcqhkjOPQIBBggqhkjOPQMB
BwNCAATHw8aA3QELRNnKlpYnMC9ZFQrNMzM7ulv5sGmG0sXPQCtk+KKvOHKzVvBV
O4jmvoxFImxugunnDut/jY4uHJYRMAoGCCqGSM49BAMCA0gAMEUCICR8pDLPtykr
ScCnXbiFIdy66PAybT9BUfYChcF7uO1gAiEA7pDNywDUBsk+q46SwSztUHV/SDKm
lbpkXXUFipRHdEk=";
    /// Python: `cert.subject.rfc4514_string()` and `get_attributes_for_oid(CN)[0].value`.
    const MULTI_RFC4514: &str = "CN=\\#lead\\; q\\<x\\>=y \\\\ Zo\u{eb}\\ ,DC=test,2.5.4.5=42,1.2.3.4.5=custom,1.2.840.113549.1.9.1=a@b.test,OU=IT+CN=mv\\+x,O=Acme\\, Inc. \\\"West\\\",ST=New York,C=US";

    #[test]
    fn rfc4514_and_cn_match_python() {
        use base64::Engine;
        let der = base64::engine::general_purpose::STANDARD.decode(MULTI_PEM.replace('\n', "")).unwrap();
        let c = cert_from_der(&der, "t").unwrap();
        assert_eq!(c.subject, MULTI_RFC4514);
        assert_eq!(c.issuer, MULTI_RFC4514);
        assert_eq!(c.cn, "mv+x"); // first CN in encoded order is the one in the multi-valued RDN
        assert_eq!(c.key_desc, "EC secp256r1");
        assert_eq!(c.sig_hash, "sha256");
        assert!(c.self_issued());
        assert_eq!(c.not_before, 1767225600); // 2026-01-01T00:00:00Z
    }
}
