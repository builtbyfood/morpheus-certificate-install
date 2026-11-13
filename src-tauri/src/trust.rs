//! morpheus-certificate-install 0.4.0 — should "Trust this CA inside Morpheus" start ticked?
//!
//! Decided from the actual certificates, not their names (PARITY divergence 28; the reference page
//! matched the top CN against a list of CA brands). The CAs looked at: the chain (intermediates and
//! root) plus every supplied CA certificate that is another form of one of them (same subject and
//! key — a cross-signed copy, which the chain walk leaves among the unused certificates when it
//! ends at the self-signed form). Each is compared with the trust anchors by **subject and public
//! key**, both taken raw from the certificate's own DER (trust anchors aren't whole certificates);
//! a CA whose issuer is an anchor counts too, when its signature verifies with that anchor's key.
//! 1. ANY match among the Mozilla roots built into the app (webpki-roots), which is what Java's
//!    cacerts largely holds: "Publicly trusted", off. A cross-signed root ("GoDaddy TLS Root CA – R1"
//!    under "Go Daddy Root Certificate Authority – G2") is public because G2 is.
//! 2. otherwise any match only in this computer's certificate store (rustls-native-certs): on — most
//!    likely the organisation's own CA, which managed machines get and Morpheus' Java doesn't have;
//! 3. otherwise a private CA: on.
//! Without a server certificate there's no chain: every supplied CA certificate is looked at (0.3.20).
//! `morpheus-ui` restart follows the checkbox on the page.
//!
//! 0.3.17–0.3.18 looked only at the root (or the top CA's issuer by name): a chain that ends at a
//! self-signed root Mozilla doesn't list ("GoDaddy TLS Root CA – R1"), with the public root (G2) or
//! the copy cross-signed by it supplied too, came out "private" and ticked.

use mci_core::analyze::Analysis;
use mci_core::formats::tlv;
use mci_core::model::Cert;
use serde_json::{json, Value};
use std::sync::OnceLock;

pub const PUBLIC: &str = "Publicly trusted: Morpheus' Java already trusts it.";
pub const IN_OS_STORE: &str = "Only in this computer's trust store, not in the public roots: likely your organisation's own CA, which Morpheus' Java doesn't have. Untick it if Morpheus already trusts this CA.";
pub const PRIVATE: &str = "Private CA: Morpheus' Java won't trust it until it's imported.";
pub const NO_CA: &str = "No CA certificates were supplied, so there's nothing to import.";

/// The raw pieces of a certificate, as trust anchors store them: the contents (without tag and
/// length) of its subject Name, its SubjectPublicKeyInfo and its issuer Name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Raw { pub subject: Vec<u8>, pub spki: Vec<u8>, pub issuer: Vec<u8> }

pub fn raw(der: &[u8]) -> Option<Raw> {
    let top = tlv::read_exact(der).ok()?;
    let parts = top.children().ok()?;
    let tbs = parts.first()?.children().ok()?;
    let off = if tbs.first().map(|t| t.tag) == Some(0xA0) { 1 } else { 0 };
    let f = |i: usize| tbs.get(off + i).map(|t| t.content.to_vec());
    Some(Raw { issuer: f(2)?, subject: f(4)?, spki: f(5)? })
}

/// SEQUENCE { contents } — an anchor's SPKI back into a whole SubjectPublicKeyInfo, for a signature check.
fn seq(contents: &[u8]) -> Vec<u8> { tlv::encode(0x30, contents) }

/// The OS store's certificates, raw, read once per process.
fn os_store() -> &'static [Raw] {
    static S: OnceLock<Vec<Raw>> = OnceLock::new();
    S.get_or_init(|| rustls_native_certs::load_native_certs().certs.iter().filter_map(|c| raw(c.as_ref())).collect())
}

/// Is `c` itself one of `anchors` (subject + key), or — when `top` — issued by one (subject = its
/// issuer, and its signature verifies with that anchor's key)?
fn matches<'a>(c: &Cert, anchors: impl Iterator<Item = (&'a [u8], &'a [u8])>) -> bool {
    let Some(r) = raw(&c.der) else { return false };
    anchors.into_iter().any(|(subj, spki)| {
        (subj == r.subject && spki == r.spki)
            || (subj == r.issuer
                && mci_core::analyze::sig::verify(&c.der, &seq(spki)) == mci_core::analyze::sig::Verdict::Valid)
    })
}

fn builtin_anchors() -> impl Iterator<Item = (&'static [u8], &'static [u8])> {
    webpki_roots::TLS_SERVER_ROOTS.iter().map(|a| (a.subject.as_ref(), a.subject_public_key_info.as_ref()))
}

/// Where the chain's trust comes from: "built-in" if ANY CA is a Mozilla root or is issued by one,
/// else "os" if any is or is issued by a certificate in this computer's store, else None.
pub fn classify(cas: &[&Cert], os: &[Raw]) -> Option<&'static str> {
    if cas.iter().any(|c| matches(c, builtin_anchors())) {
        return Some("built-in");
    }
    if cas.iter().any(|c| matches(c, os.iter().map(|r| (r.subject.as_slice(), r.spki.as_slice())))) {
        return Some("os");
    }
    None
}

/// The CAs to look at: the chain, plus supplied CA certificates that are other forms (same raw
/// subject and key) of a chain CA — cross-signed copies.
fn cas_of(an: &Analysis) -> Vec<&Cert> {
    // No server certificate (0.3.20): there's no chain to walk, and every CA supplied sits among the
    // unused certificates. Those are the CAs the user means; judge them all.
    if an.leaf.is_none() {
        return an.intermediates.iter().chain(an.root.iter()).chain(an.extra.iter().filter(|e| e.is_ca)).collect();
    }
    let chain: Vec<&Cert> = an.intermediates.iter().chain(an.root.iter()).collect();
    let keys: Vec<(Vec<u8>, Vec<u8>)> = chain.iter().filter_map(|c| raw(&c.der)).map(|r| (r.subject, r.spki)).collect();
    let alt = an.extra.iter().filter(|e| e.is_ca && raw(&e.der).is_some_and(|r| keys.contains(&(r.subject, r.spki))));
    chain.iter().copied().chain(alt).collect()
}

/// `{trust_default, trust_reason, trust_store}` for the analysis JSON (`trust_store`: "built-in",
/// "os" or null).
pub fn trust_default(an: &Analysis) -> Value {
    trust_default_with(an, os_store())
}

fn trust_default_with(an: &Analysis, os: &[Raw]) -> Value {
    let cas = cas_of(an);
    if cas.is_empty() {
        return json!({"trust_default": false, "trust_reason": NO_CA, "trust_store": null});
    }
    verdict(classify(&cas, os))
}

/// Off only for a Mozilla root; on for one only in this computer's store, and for a private CA.
fn verdict(store: Option<&str>) -> Value {
    match store {
        Some("built-in") => json!({"trust_default": false, "trust_reason": PUBLIC, "trust_store": "built-in"}),
        Some(_) => json!({"trust_default": true, "trust_reason": IN_OS_STORE, "trust_store": "os"}),
        None => json!({"trust_default": true, "trust_reason": PRIVATE, "trust_store": null}),
    }
}

/// The analysis as the page gets it: `Analysis::to_json` plus the trust default.
pub fn analysis_json(an: &Analysis) -> Value {
    let mut v = serde_json::to_value(an.to_json()).unwrap_or_default();
    if let (Some(o), Value::Object(t)) = (v.as_object_mut(), trust_default(an)) {
        o.extend(t);
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use mci_core::formats::{parse_files, InputFile};
    use std::path::PathBuf;

    fn file(rel: &str) -> InputFile {
        let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
        InputFile { name: p.file_name().unwrap().to_string_lossy().into(), data: std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display())) }
    }
    fn corpus(n: &str) -> InputFile { file(&format!("../fixtures/corpus/{n}")) }
    /// Real public roots (public data): testdata/public-roots/.
    fn public_root(n: &str) -> Cert {
        let b = parse_files(&[file(&format!("testdata/public-roots/{n}"))], &Default::default());
        b.certs.into_iter().next().unwrap()
    }
    fn an(files: Vec<InputFile>) -> Analysis {
        let b = parse_files(&files, &Default::default());
        let now = b.certs[0].not_before + 86_400;
        mci_core::analyze::analyze(&b, "", "", now)
    }

    #[test]
    fn real_public_roots_are_found_in_the_built_in_store() {
        for n in ["isrg-root-x1.pem", "go-daddy-root-g2.pem"] {
            let r = public_root(n);
            assert_eq!(classify(&[&r], &[]), Some("built-in"), "{n}");
        }
        // An unrelated private root isn't.
        let a = an(vec![corpus("chain.p7b"), corpus("leaf-pkcs1.key")]);
        assert_eq!(classify(&[a.root.as_ref().unwrap()], &[]), None);
    }

    #[test]
    fn any_public_ca_makes_the_chain_public() {
        // A private chain with a public root anywhere in it (as a cross-signed chain has G2 on top
        // of a root Mozilla doesn't list): public, off.
        let mut a = an(vec![corpus("chain.p7b"), corpus("leaf-pkcs1.key")]);
        assert_eq!(trust_default_with(&a, &[])["trust_default"], true, "private as is");
        a.intermediates.push(public_root("go-daddy-root-g2.pem"));
        assert_eq!(trust_default_with(&a, &[]), json!({"trust_default": false, "trust_reason": PUBLIC, "trust_store": "built-in"}));
        // The public root among the unused certificates doesn't count by itself (it's unrelated
        // to this chain): only another form of a chain CA does.
        let mut a = an(vec![corpus("chain.p7b"), corpus("leaf-pkcs1.key")]);
        a.extra.push(public_root("isrg-root-x1.pem"));
        assert_eq!(trust_default_with(&a, &[])["trust_default"], true);
        // A cross-signed copy of the chain's root (same subject and key) among the unused
        // certificates, issued by a CA in the store: the chain is that store's.
        let mut a = an(vec![corpus("chain.p7b"), corpus("leaf-pkcs1.key")]);
        let mut cross = a.root.clone().unwrap();
        cross.subject = "cross-signed copy".into();
        a.extra.push(cross);
        let os = vec![raw(&a.root.as_ref().unwrap().der).unwrap()];
        assert_eq!(cas_of(&a).len(), 3, "the copy is looked at");
        assert_eq!(trust_default_with(&a, &os)["trust_store"], "os");
        // Root missing, top intermediate issued by a Mozilla root: needs the signature to verify.
        // Cust Issuing names Cust Root, not ISRG: still private.
        let a = an(vec![corpus("leaf.crt"), corpus("leaf.key"), corpus("int.crt")]);
        assert_eq!(trust_default_with(&a, &[])["trust_default"], true);
    }

    #[test]
    fn the_corpus_private_root_is_ticked() {
        let v = trust_default_with(&an(vec![corpus("chain.p7b"), corpus("leaf-pkcs1.key")]), &[]);
        assert_eq!(v, json!({"trust_default": true, "trust_reason": PRIVATE, "trust_store": null}));
        let v = trust_default_with(&an(vec![corpus("leaf.crt"), corpus("leaf.key")]), &[]);
        assert_eq!(v, json!({"trust_default": false, "trust_reason": NO_CA, "trust_store": null}));
    }

    #[test]
    fn a_root_only_in_the_os_store_is_ticked() {
        // The corpus root "in this computer's store" (a stand-in OS store holding it): on, with its reason.
        let a = an(vec![corpus("chain.p7b"), corpus("leaf-pkcs1.key")]);
        let os = vec![raw(&a.root.as_ref().unwrap().der).unwrap()];
        assert_eq!(trust_default_with(&a, &os), json!({"trust_default": true, "trust_reason": IN_OS_STORE, "trust_store": "os"}));
        // And with the real store: a root Windows has and Mozilla doesn't, when this machine has one.
        if let Some(r) = os_store().iter().find(|r| !builtin_anchors().any(|(s, k)| s == r.subject && k == r.spki)) {
            assert_eq!(classify_raw(r), Some("os"));
        }
    }

    /// classify() for a raw OS-store entry (its own DER isn't kept): same rules, on the raw pieces.
    fn classify_raw(r: &Raw) -> Option<&'static str> {
        if builtin_anchors().any(|(s, k)| s == r.subject && k == r.spki) { return Some("built-in"); }
        os_store().iter().any(|o| o == r).then_some("os")
    }

    #[test]
    fn without_a_server_certificate_the_supplied_cas_decide() {
        // Only CA certificates (the leaf is missing): they're all among the unused certificates.
        let g2 = file("testdata/public-roots/go-daddy-root-g2.pem");
        let a = mci_core::analyze::analyze(&parse_files(&[g2], &Default::default()), "", "", 1_900_000_000);
        assert!(a.leaf.is_none() && a.root.is_none() && a.intermediates.is_empty(), "nothing on the chain");
        assert_eq!(trust_default_with(&a, &[]), json!({"trust_default": false, "trust_reason": PUBLIC, "trust_store": "built-in"}));
        let a = an(vec![corpus("int.crt"), corpus("root.crt")]);
        assert!(a.leaf.is_none());
        assert_eq!(trust_default_with(&a, &[]), json!({"trust_default": true, "trust_reason": PRIVATE, "trust_store": null}));
        // No certificate at all is still "nothing to import".
        let a = an(vec![corpus("leaf.key"), corpus("int.crt")]);
        assert!(a.leaf.is_none());
        let a = Analysis { extra: vec![], ..a };
        assert_eq!(trust_default_with(&a, &[])["trust_reason"], NO_CA);
    }

    /// The real GoDaddy DV bundle (public CA certificates, testdata/public-roots/gd_bundle_dv-r1-g2.crt.pem):
    /// "GoDaddy TLS Intermediate CA DV - R1v1", "GoDaddy TLS Root CA - R1" cross-signed by G2, and G2.
    /// Mozilla lists G2, not R1: the chain is public through the cross-signed R1.
    #[test]
    fn the_godaddy_bundle_is_publicly_trusted() {
        let bundle = file("testdata/public-roots/gd_bundle_dv-r1-g2.crt.pem");
        let text = String::from_utf8(bundle.data.clone()).unwrap();
        let blocks: Vec<String> = text.split_inclusive("-----END CERTIFICATE-----").filter(|b| b.contains("BEGIN")).map(|b| b.trim().to_string() + "\n").collect();
        assert_eq!(blocks.len(), 3);
        let one = |i: usize, n: &str| InputFile { name: n.into(), data: blocks[i].clone().into_bytes() };
        let analyze = |files: Vec<InputFile>| mci_core::analyze::analyze(&parse_files(&files, &Default::default()), "", "", 1_900_000_000);
        let subjects = |a: &Analysis| cas_of(a).iter().map(|c| c.subject.clone()).collect::<Vec<_>>();

        // The intermediate and the cross-signed R1, without G2: R1's issuer is G2 and its signature
        // verifies with G2's key from the built-in roots.
        let a = analyze(vec![one(0, "gd-intermediate.crt"), one(1, "gd-r1-cross.crt")]);
        assert!(a.leaf.is_none());
        assert!(subjects(&a).iter().any(|s| s.contains("GoDaddy TLS Root CA - R1")) && subjects(&a).iter().any(|s| s.contains("Intermediate CA DV")), "{:?}", subjects(&a));
        assert_eq!(trust_default_with(&a, &[]), json!({"trust_default": false, "trust_reason": PUBLIC, "trust_store": "built-in"}));

        // The whole bundle as it comes from GoDaddy.
        let a = analyze(vec![bundle.clone()]);
        assert_eq!(cas_of(&a).len(), 3);
        assert_eq!(trust_default_with(&a, &[]), json!({"trust_default": false, "trust_reason": PUBLIC, "trust_store": "built-in"}));

        // The intermediate alone: R1 (its issuer) is in neither store, so it can't be shown public.
        let a = analyze(vec![one(0, "gd-intermediate.crt")]);
        assert_eq!(trust_default_with(&a, &[])["trust_default"], true);
    }

    #[test]
    fn analysis_json_adds_the_three_keys() {
        let v = analysis_json(&an(vec![corpus("chain.p7b"), corpus("leaf-pkcs1.key")]));
        assert_eq!(v["trust_default"], true);
        assert!(v["chain"].is_array() && v.get("trust_reason").is_some() && v.get("trust_store").is_some());
    }
}

