//! morpheus-certificate-install 0.4.2 — crate-agnostic data model.
//!
//! Parsing (formats.rs) fills these from whatever crypto crate R0 picks; everything after
//! that (chain building, checks, export, JSON for the UI) works on these types only.
//! The JSON shapes match the Python reference's `to_json()` exactly — the UI depends on them.

use serde::{Deserialize, Serialize};

/// A parsed X.509 certificate, with everything the rest of the app needs precomputed.
#[derive(Debug, Clone)]
pub struct Cert {
    pub der: Vec<u8>,
    /// SubjectPublicKeyInfo DER — compared against the private key's to find the leaf.
    pub spki_der: Vec<u8>,
    /// RFC 4514 strings, same rendering as Python `Name.rfc4514_string()` (e.g. `CN=Cust Root`).
    pub subject: String,
    pub issuer: String,
    /// Raw DER of subject/issuer Names.
    pub subject_raw: Vec<u8>,
    pub issuer_raw: Vec<u8>,
    /// Parsed Names for issuer↔subject matching, compared the way cryptography's `Name.__eq__` does:
    /// the same RDNs in the same order, each RDN the same *set* of (attribute OID, decoded value).
    /// So a PrintableString "Cust" equals a UTF8String "Cust", where raw DER would differ.
    pub subject_name: NameKey,
    pub issuer_name: NameKey,
    pub cn: String,
    pub san_dns: Vec<String>,
    pub san_ip: Vec<String>,
    /// Unix seconds.
    pub not_before: i64,
    pub not_after: i64,
    pub is_ca: bool,
    /// e.g. `sha256` (lowercase, as Python's `signature_hash_algorithm.name`).
    pub sig_hash: String,
    /// `RSA 2048`, `EC secp256r1`, `Ed25519` — same strings as the reference `key_desc`.
    pub key_desc: String,
    pub rsa_bits: Option<u32>,
    /// AIA caIssuers URIs, every scheme, in certificate order (aia.rs fetches only http/https).
    pub aia_ca_issuers: Vec<String>,
    /// Where it came from, for the UI: `chain.p7b (PKCS#7)`, `fetched from http://…`.
    pub source: String,
}

impl Cert {
    /// `AA:BB:…` uppercase colon-separated, as the reference prints it.
    pub fn fp256(&self) -> String { crate::analyze::sha256_colon(&self.der) }
    pub fn fp256_hex(&self) -> String { crate::analyze::sha256_hex(&self.der) }
    pub fn self_issued(&self) -> bool { self.subject_name == self.issuer_name }
    pub fn pem(&self) -> String { crate::analyze::pem_encode("CERTIFICATE", &self.der) }
}

/// RDNs in encoded order; each RDN's (OID, value) pairs sorted and de-duplicated (a set).
/// Text values are prefixed `T:`, byte values (BIT STRING, unknown types) `B:` + hex.
pub type NameKey = Vec<Vec<(String, String)>>;

/// A private key, normalised to unencrypted PKCS#8 at parse time.
#[derive(Debug, Clone)]
pub struct PrivateKey {
    pub pkcs8_der: Vec<u8>,
    pub spki_der: Vec<u8>,
    pub desc: String,
    pub source: String,
    pub was_encrypted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level { Ok, Warn, Error }

/// One input file: what it turned out to be. `format` is human prose (shown in the UI and
/// INSTALL.txt); `kind` is the stable category the parity tests compare.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileReport {
    pub name: String,
    pub format: String,
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub kind: String,
    pub certs: u32,
    pub keys: u32,
    pub notes: Vec<String>,
    pub level: Level,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Check { pub level: Level, pub text: String }

#[derive(Debug, Default)]
pub struct Bundle {
    pub certs: Vec<Cert>,
    pub key: Option<PrivateKey>,
    pub problems: Vec<(Level, String)>,
    pub reports: Vec<FileReport>,
}

/// One chain entry as the UI renders it (`role`: server | intermediate | root | unused).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertSummary {
    pub role: String,
    pub cn: String,
    pub subject: String,
    pub issuer: String,
    pub san_dns: Vec<String>,
    pub san_ip: Vec<String>,
    /// ISO 8601 with offset, e.g. `2027-12-07T06:12:06+00:00`.
    pub not_before: String,
    pub not_after: String,
    pub days_left: i64,
    pub lifetime_days: i64,
    pub used_days: i64,
    pub is_ca: bool,
    pub self_signed: bool,
    pub sha256: String,
    pub sig_alg: String,
    pub key: String,
    pub source: String,
}

/// `Analysis::to_json()` in the reference — the UI's contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisJson {
    pub ok: bool,
    pub fqdn: String,
    pub file_base: String,
    pub chain: Vec<CertSummary>,
    pub unused: Vec<CertSummary>,
    pub checks: Vec<Check>,
    pub key: Option<String>,
    pub ca_aliases: Vec<String>,
    pub inputs: Vec<FileReport>,
    pub can_fetch_chain: bool,
}
