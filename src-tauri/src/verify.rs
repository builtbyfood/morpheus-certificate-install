//! morpheus-certificate-install 0.4.1 — TLS check from this machine (R7).
//!
//! Port of reference engine.local_tls(). Two connections to connect_addr (or the host) with SNI = host:
//!   1. no verification → the served leaf's SHA-256 → matches_new?
//!   2. verifying, with the hostname check, against three trust stores tried in order (0.3.16):
//!      the supplied root from the analysis, the OS certificate store (rustls-platform-verifier: the OS builds the chain, so
//!      Windows can fetch a root it hasn't cached yet), and the
//!      Mozilla roots built into the app (webpki-roots). The first that verifies the chain is reported
//!      in the summary and as `trust_store`: "supplied root" | "os" | "built-in".
//! Summaries as in the reference: "TLSv1.3, chain verifies for <host> (using the supplied root);
//! serving the new certificate", "… (OS trust store) …", and new "… (built-in trust store) …";
//! "…, verification failed: <reason>" / "could not connect: <err>".
//! Divergences (docs/PARITY.md 23): the reason is in words (`describe`), not OpenSSL's text, and the
//! built-in store is tried after the OS one.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

pub const TIMEOUT: Duration = Duration::from_secs(8);

fn provider() -> Arc<rustls::crypto::CryptoProvider> { Arc::new(rustls::crypto::ring::default_provider()) }

/// Accepts any certificate: the first connection only reads what is served.
#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(&self, _: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime)
        -> Result<ServerCertVerified, rustls::Error> { Ok(ServerCertVerified::assertion()) }
    fn verify_tls12_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> { self.0.signature_verification_algorithms.supported_schemes() }
}

/// One trust store: its label for `trust_store` and the summary, and its verifier.
type Store = (&'static str, Arc<dyn ServerCertVerifier>);

/// Verifies against each store in turn; remembers which one accepted. On failure, the first
/// store's error (the supplied root's, when there is one) is the one reported.
#[derive(Debug)]
pub struct Stores {
    stores: Vec<Store>,
    pub used: Mutex<Option<&'static str>>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for Stores {
    fn verify_server_cert(&self, ee: &CertificateDer<'_>, im: &[CertificateDer<'_>], name: &ServerName<'_>, ocsp: &[u8], now: UnixTime)
        -> Result<ServerCertVerified, rustls::Error> {
        let mut first = None;
        for (label, v) in &self.stores {
            match v.verify_server_cert(ee, im, name, ocsp, now) {
                Ok(ok) => {
                    *self.used.lock().unwrap_or_else(|p| p.into_inner()) = Some(label);
                    return Ok(ok);
                }
                Err(e) => { first.get_or_insert(e); }
            }
        }
        Err(first.unwrap_or_else(|| rustls::Error::General("no trust store to verify against".into())))
    }
    fn verify_tls12_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.provider.signature_verification_algorithms)
    }
    fn verify_tls13_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.provider.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> { self.provider.signature_verification_algorithms.supported_schemes() }
}

fn store(label: &'static str, roots: Arc<RootCertStore>, p: &Arc<rustls::crypto::CryptoProvider>) -> Option<Store> {
    if roots.is_empty() { return None; }
    WebPkiServerVerifier::builder_with_provider(roots, p.clone()).build().ok().map(|v| (label, v as Arc<dyn ServerCertVerifier>))
}

/// Supplied root (if any), then the OS store, then the built-in roots.
fn trust_stores(root_der: Option<&[u8]>, p: &Arc<rustls::crypto::CryptoProvider>) -> Arc<Stores> {
    let mut stores = vec![];
    if let Some(r) = root_der {
        let mut rs = RootCertStore::empty();
        let _ = rs.add(CertificateDer::from(r.to_vec()));
        stores.extend(store("supplied root", Arc::new(rs), p));
    }
    if let Ok(v) = rustls_platform_verifier::Verifier::new(p.clone()) {
        stores.push(("os", Arc::new(v) as Arc<dyn ServerCertVerifier>));
    }
    let mut builtin = RootCertStore::empty();
    builtin.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    stores.extend(store("built-in", Arc::new(builtin), p));
    Arc::new(Stores { stores, used: Mutex::new(None), provider: p.clone() })
}

/// A client config that verifies against the stores (supplied root, OS, built-in), and the
/// verifier, which says afterwards which store accepted. Also used by the Morpheus API check.
pub fn verifying_config(root_der: Option<&[u8]>) -> Result<(ClientConfig, Arc<Stores>), rustls::Error> {
    let p = provider();
    let stores = trust_stores(root_der, &p);
    let cfg = ClientConfig::builder_with_provider(p).with_safe_default_protocol_versions()?
        .dangerous().with_custom_certificate_verifier(stores.clone()).with_no_client_auth();
    Ok((cfg, stores))
}

/// A client config that accepts any certificate (reading what's served; the API's unverified retry).
pub fn no_verify_config() -> Result<ClientConfig, rustls::Error> {
    let p = provider();
    Ok(ClientConfig::builder_with_provider(p.clone()).with_safe_default_protocol_versions()?
        .dangerous().with_custom_certificate_verifier(Arc::new(NoVerify(p))).with_no_client_auth())
}

/// When what the server sends is itself the problem, say so in plain words (0.3.19): a
/// self-signed certificate, or a CA certificate sent as the server's own.
pub fn served_problem(leaf_der: &[u8]) -> Option<String> {
    let c = mci_core::formats::x509::cert_from_der(leaf_der, "served").ok()?;
    if mci_core::analyze::self_signed(&c) {
        Some(format!("the appliance serves a self-signed certificate (\"{}\"): browsers, agents and hosts won't trust it. Install a CA-signed certificate (steps 2 and 3).", c.cn))
    } else if c.is_ca {
        Some(format!("the appliance serves a CA certificate (\"{}\") as its own: clients reject that. Install the server certificate the CA issued for this appliance (steps 2 and 3).", c.cn))
    } else {
        None
    }
}

fn store_words(label: &str) -> &'static str {
    match label {
        "supplied root" => " (using the supplied root)",
        "os" => " (OS trust store)",
        _ => " (built-in trust store)",
    }
}

fn version_name(v: Option<rustls::ProtocolVersion>) -> String {
    match v {
        Some(rustls::ProtocolVersion::TLSv1_3) => "TLSv1.3".into(),
        Some(rustls::ProtocolVersion::TLSv1_2) => "TLSv1.2".into(),
        Some(o) => format!("{o:?}"),
        None => "TLS".into(),
    }
}

/// Connect and handshake within [`TIMEOUT`]; returns (protocol, served leaf DER).
async fn handshake(cfg: ClientConfig, addr: &str, port: u16, host: &str) -> std::io::Result<(String, Option<Vec<u8>>)> {
    let name = ServerName::try_from(host.to_string())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("{host:?} isn't a valid host name")))?;
    let fut = async {
        let tcp = TcpStream::connect((addr, port)).await?;
        let tls = TlsConnector::from(Arc::new(cfg)).connect(name, tcp).await?;
        let (_, conn) = tls.get_ref();
        Ok::<_, std::io::Error>((version_name(conn.protocol_version()), conn.peer_certificates().and_then(|c| c.first()).map(|c| c.to_vec())))
    };
    tokio::time::timeout(TIMEOUT, fut).await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, format!("timed out after {} s", TIMEOUT.as_secs())))?
}

/// The rustls error inside an I/O error (however deeply io::Errors are nested), if there is one.
pub fn rustls_in_io(e: &std::io::Error) -> Option<&rustls::Error> {
    let mut inner = e.get_ref()?;
    loop {
        if let Some(r) = inner.downcast_ref::<rustls::Error>() {
            return Some(r);
        }
        inner = inner.downcast_ref::<std::io::Error>()?.get_ref()?;
    }
}

/// Why a certificate didn't verify, in words (the reference showed OpenSSL's text).
pub fn describe(e: &rustls::Error) -> String {
    use rustls::CertificateError as C;
    let rustls::Error::InvalidCertificate(why) = e else { return e.to_string() };
    match why {
        C::UnknownIssuer => "the chain doesn't lead to a trusted root (unknown issuer)".into(),
        C::NotValidForName | C::NotValidForNameContext { .. } => format!("the certificate isn't valid for this name ({why:?})"),
        C::Expired | C::ExpiredContext { .. } => "the certificate has expired".into(),
        C::NotValidYet | C::NotValidYetContext { .. } => "the certificate isn't valid yet".into(),
        C::Revoked => "the certificate has been revoked".into(),
        C::BadSignature => "a signature in the chain doesn't verify".into(),
        C::Other(o) if format!("{o:?}").contains("CaUsedAsEndEntity") =>
            "the server's certificate is a CA certificate, as self-signed ones often are".into(),
        other => format!("{other:?}"),
    }
}

/// `host`: name to verify and send as SNI. `connect_addr`: where to connect (empty → host).
/// `new_leaf_sha256`: the analysis leaf's fingerprint (colon hex). `root_der`: the supplied root.
pub async fn local_tls(host: &str, port: u16, connect_addr: &str, new_leaf_sha256: Option<&str>, root_der: Option<&[u8]>) -> Value {
    let addr = if connect_addr.is_empty() { host } else { connect_addr };
    let mut out = json!({"addr": format!("{addr}:{port}"), "ok": null});
    let raw = match no_verify_config() {
        Ok(c) => c,
        Err(e) => { out["ok"] = json!(false); out["summary"] = json!(format!("could not connect: {e}")); return out; }
    };
    let (tls, der) = match handshake(raw, addr, port, host).await {
        Ok((v, Some(der))) => (v, der),
        Ok((_, None)) => { out["ok"] = json!(false); out["summary"] = json!("could not connect: the server sent no certificate"); return out; }
        Err(e) => { out["ok"] = json!(false); out["summary"] = json!(format!("could not connect: {e}")); return out; }
    };
    let served = mci_core::analyze::sha256_colon(&der);
    let matches_new = new_leaf_sha256.is_some_and(|w| w == served);
    out["tls"] = json!(tls);
    out["served_sha256"] = json!(served);
    out["matches_new"] = json!(matches_new);

    let (verifying, stores) = match verifying_config(root_der) {
        Ok(x) => x,
        Err(e) => { out["verified"] = json!(false); out["ok"] = json!(false); out["summary"] = json!(format!("verification connect failed: {e}")); return out; }
    };
    let serving = if matches_new { "; serving the new certificate" } else { "; NOT the new certificate" };
    match handshake(verifying, addr, port, host).await {
        Ok(_) => {
            out["verified"] = json!(true);
            out["ok"] = json!(true);
            let used = stores.used.lock().unwrap_or_else(|p| p.into_inner()).unwrap_or("built-in");
            out["trust_store"] = json!(used);
            out["summary"] = json!(format!("{tls}, chain verifies for {host}{}{serving}", store_words(used)));
        }
        Err(e) => {
            out["verified"] = json!(false);
            out["ok"] = json!(false);
            out["summary"] = json!(match rustls_in_io(&e) {
                Some(r @ rustls::Error::InvalidCertificate(_)) => match served_problem(&der) {
                    Some(plain) => format!("{tls}, {plain}"),
                    None => format!("{tls}, verification failed: {}{}", describe(r), if matches_new { "; serving the new certificate" } else { "" }),
                },
                _ => format!("verification connect failed: {e}"),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_are_tried_supplied_root_then_os_then_built_in() {
        let p = provider();
        let root = std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/corpus/root.crt")).unwrap();
        let der = mci_core::formats::certs_from_pem_text(&String::from_utf8_lossy(&root), "t").remove(0).der;
        let s = trust_stores(Some(&der), &p);
        let labels: Vec<&str> = s.stores.iter().map(|(l, _)| *l).collect();
        assert_eq!(labels, ["supplied root", "os", "built-in"], "the OS store must have roots on this machine");
        let s = trust_stores(None, &p);
        assert_eq!(s.stores.iter().map(|(l, _)| *l).collect::<Vec<_>>(), ["os", "built-in"]);
        assert_eq!((store_words("supplied root"), store_words("os"), store_words("built-in")),
                   (" (using the supplied root)", " (OS trust store)", " (built-in trust store)"));
    }

    /// A public site verifies through the OS store, which is tried before the built-in roots.
    /// Needs the internet: MCI_TEST_NET=1.
    #[tokio::test]
    #[ignore = "needs the internet (MCI_TEST_NET=1)"]
    async fn a_public_site_verifies_with_the_os_store() {
        if std::env::var("MCI_TEST_NET").as_deref() != Ok("1") { return; }
        let v = local_tls("www.example.com", 443, "", None, None).await;
        assert_eq!((&v["ok"], &v["trust_store"]), (&json!(true), &json!("os")), "{v}");
        assert!(v["summary"].as_str().unwrap().contains("chain verifies for www.example.com (OS trust store)"), "{v}");
        eprintln!("{}", v["summary"]);
    }
}

#[cfg(test)]
mod served_tests {
    fn der(rel: &str) -> Vec<u8> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
        let b = mci_core::formats::parse_files(&[mci_core::formats::InputFile { name: "x".into(), data: std::fs::read(p).unwrap() }], &Default::default());
        b.certs[0].der.clone()
    }

    #[test]
    fn self_signed_and_ca_leaves_are_said_plainly() {
        let s = super::served_problem(&der("../fixtures/corpus/root.crt")).unwrap();
        assert!(s.starts_with("the appliance serves a self-signed certificate (\"Cust Root\")"), "{s}");
        let s = super::served_problem(&der("../fixtures/corpus/int.crt")).unwrap();
        assert!(s.starts_with("the appliance serves a CA certificate (\"Cust Issuing\") as its own"), "{s}");
        assert_eq!(super::served_problem(&der("../fixtures/corpus/leaf.crt")), None, "an ordinary server certificate");
    }
}
