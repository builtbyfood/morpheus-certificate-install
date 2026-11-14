//! morpheus-certificate-install 0.4.1 — files in the layout Morpheus expects.
//!
//!   <base>.crt  <base>.key  ca-chain.pem  trusted_certs/<alias>.pem  morpheus.rb.snippet  INSTALL.txt
//!
//! Port of reference export.py: `build_files` (R4), `install_text` (golden-tested), `to_zip`.
//! Writing to disk is the caller's job (mci-cli writes a folder with the key 0600; src-tauri saves the zip).

use crate::analyze::Analysis;
use crate::{PRODUCT, VERSION};
use serde::Deserialize;

/// Everything INSTALL.txt needs — filled from an Analysis in R4, from a golden JSON in tests.
#[derive(Debug, Clone, Deserialize)]
pub struct ExportInfo {
    pub fqdn: String,
    pub file_base: String,
    pub leaf_cn: String,
    pub sans: Vec<String>,
    /// `YYYY-MM-DD`
    pub not_after: String,
    pub leaf_sha256: String,
    pub intermediates: usize,
    pub root_cn: Option<String>,
    pub key_desc: String,
    /// (file name, detected format prose)
    pub inputs: Vec<InputLine>,
    pub ca_aliases: Vec<String>,
    pub include_root: bool,
    /// `YYYY-MM-DD HH:MM`, local time
    pub now: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InputLine { pub name: String, pub format: String }

/// Final line differs from the Python reference on purpose (it pointed at `python -m …`).
pub const INSTALL_CTA: &str = "Or run morpheus-certificate-install to do all of it, with a backup and rollback.";

pub fn install_text(i: &ExportInfo) -> String {
    let base = &i.file_base;
    let mut l: Vec<String> = vec![
        format!("Converted by {PRODUCT} {VERSION} on {}", i.now),
        String::new(),
        format!("Server certificate : {}", i.leaf_cn),
        format!("  SANs             : {}", if i.sans.is_empty() { "none".to_string() } else { i.sans.join(", ") }),
        format!("  valid until      : {}", i.not_after),
        format!("  SHA-256          : {}", i.leaf_sha256),
        format!("Chain              : {} intermediate(s){}", i.intermediates,
                match &i.root_cn { Some(r) => format!(", root \"{r}\""), None => ", root not supplied".into() }),
        format!("Private key        : {}, decrypted, PKCS#8 PEM", i.key_desc),
        String::new(),
        "Converted from:".into(),
    ];
    for r in &i.inputs {
        l.push(format!("  {}: {}", r.name, r.format));
    }
    l.push(String::new());
    l.push(format!("{base}.crt holds the server certificate followed by the intermediates{} — the order nginx needs.",
                   if i.include_root && i.root_cn.is_some() { " and the root" } else { "" }));
    l.push(format!("{base}.key is NOT encrypted (Morpheus requires that). Keep it off shared drives and email."));
    l.push(String::new());
    l.push("Manual install (on the Morpheus appliance, after copying these files to your home directory):".into());
    l.push(String::new());
    l.push(format!("  sudo install -o root -g root -m 0600 ~/{base}.crt /etc/morpheus/ssl/{base}.crt"));
    l.push(format!("  sudo install -o root -g root -m 0600 ~/{base}.key /etc/morpheus/ssl/{base}.key"));
    l.push("  sudo cp -a /etc/morpheus/morpheus.rb /etc/morpheus/morpheus.rb.bak-$(date +%Y%m%d-%H%M%S)".into());
    l.push("  sudoedit /etc/morpheus/morpheus.rb      # add the two lines from morpheus.rb.snippet".into());
    l.push("  sudo morpheus-ctl reconfigure".into());
    l.push("  sudo morpheus-ctl restart nginx".into());
    l.push(format!("  echo | openssl s_client -connect 127.0.0.1:443 -servername {} 2>/dev/null | openssl x509 -noout -subject -enddate -fingerprint -sha256", i.fqdn));
    if !i.ca_aliases.is_empty() {
        l.push(String::new());
        l.push("Optional — make Morpheus itself trust this CA (private CAs):".into());
        l.push(String::new());
        l.push("  sudo mkdir -p /etc/morpheus/ssl/trusted_certs".into());
        l.push("  sudo install -o root -g root -m 0644 ~/trusted_certs/*.pem /etc/morpheus/ssl/trusted_certs/".into());
        l.push("  sudo morpheus-ctl reconfigure".into());
        l.push("  KT=$(sudo find /opt/morpheus/embedded -type f -name keytool | head -1)".into());
        l.push("  CA=$(sudo find /opt/morpheus/embedded -type f -name cacerts -path '*security*' | head -1)".into());
        for a in &i.ca_aliases {
            l.push(format!("  sudo \"$KT\" -importcert -noprompt -trustcacerts -alias {a} -file /etc/morpheus/ssl/trusted_certs/{a}.pem -keystore \"$CA\" -storepass changeit"));
        }
        l.push("  sudo morpheus-ctl restart morpheus-ui     # UI is down while it starts".into());
    }
    l.push(String::new());
    l.push(INSTALL_CTA.into());
    l.push(String::new());
    l.join("\n")
}

pub fn morpheus_rb_snippet(base: &str) -> String {
    format!("nginx['ssl_certificate'] = '/etc/morpheus/ssl/{base}.crt'\nnginx['ssl_server_key'] = '/etc/morpheus/ssl/{base}.key'\n")
}

impl ExportInfo {
    /// What INSTALL.txt says about `an`. `now` is local time, `YYYY-MM-DD HH:MM`.
    pub fn from_analysis(an: &Analysis, include_root: bool, now: &str) -> Result<Self, String> {
        let leaf = an.leaf.as_ref().ok_or(NOT_READY)?;
        Ok(ExportInfo {
            fqdn: an.fqdn.clone(),
            file_base: crate::names::safe_name(&an.fqdn),
            leaf_cn: leaf.cn.clone(),
            sans: leaf.san_dns.iter().chain(leaf.san_ip.iter()).cloned().collect(),
            not_after: crate::analyze::ymd(leaf.not_after),
            leaf_sha256: leaf.fp256(),
            intermediates: an.intermediates.len(),
            root_cn: an.root.as_ref().map(|r| r.cn.clone()),
            key_desc: an.key_desc.clone().ok_or(NOT_READY)?,
            inputs: an.reports.iter().map(|r| InputLine { name: r.name.clone(), format: r.format.clone() }).collect(),
            ca_aliases: an.ca_certs().iter().map(|c| crate::names::alias_for(&c.cn, &c.fp256_hex())).collect(),
            include_root,
            now: now.to_string(),
        })
    }
}

/// The reference's error text when the set isn't exportable.
pub const NOT_READY: &str = "The certificate set has errors; fix them before exporting.";

/// (relative path, bytes), in the reference's order: `<base>.crt`, `<base>.key`, `ca-chain.pem`,
/// `trusted_certs/<alias>.pem` (root first), `morpheus.rb.snippet`, `INSTALL.txt`.
/// `.key` must be written 0600 / zipped with 0600 (see [`to_zip`]). `now`: local `YYYY-MM-DD HH:MM`.
pub fn build_files(an: &Analysis, include_root: bool, now: &str) -> Result<Vec<(String, Vec<u8>)>, String> {
    if !an.ok() {
        return Err(NOT_READY.into());
    }
    let base = crate::names::safe_name(&an.fqdn);
    let key = an.key_pem().ok_or(NOT_READY)?;
    let mut files: Vec<(String, Vec<u8>)> = vec![
        (format!("{base}.crt"), an.fullchain_pem(include_root).into_bytes()),
        (format!("{base}.key"), key.into_bytes()),
    ];
    let cas = an.ca_certs();
    if !cas.is_empty() {
        files.push(("ca-chain.pem".into(), cas.iter().map(|c| c.pem()).collect::<String>().into_bytes()));
        for c in &cas {
            files.push((format!("trusted_certs/{}.pem", crate::names::alias_for(&c.cn, &c.fp256_hex())), c.pem().into_bytes()));
        }
    }
    files.push(("morpheus.rb.snippet".into(), morpheus_rb_snippet(&base).into_bytes()));
    files.push(("INSTALL.txt".into(), install_text(&ExportInfo::from_analysis(an, include_root, now)?).into_bytes()));
    Ok(files)
}

/// Local date and time stamped on zip entries: (year, month, day, hour, minute, second).
pub type ZipTime = (u16, u8, u8, u8, u8, u8);

/// A .zip with every file under `<folder>/`, deflated; the `.key` gets Unix mode 0600, everything
/// else 0644 (regular-file external attributes, as the reference's `to_zip`). Entries are always
/// marked as made by Unix, so the modes survive a zip built on Windows (docs/PARITY.md, divergence 16).
pub fn to_zip(files: &[(String, Vec<u8>)], folder: &str, mtime: ZipTime) -> Result<Vec<u8>, String> {
    use std::io::Write;
    use zip::write::SimpleFileOptions;
    let (y, mo, d, h, mi, s) = mtime;
    let when = zip::DateTime::from_date_and_time(y, mo, d, h, mi, s).unwrap_or_default();
    let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (name, data) in files {
        let mode = if name.ends_with(".key") { 0o600 } else { 0o644 };
        let opts = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .last_modified_time(when)
            // "Made by Unix" on every OS: unzip tools only honour the mode bits on Unix-made entries,
            // and zip defaults to DOS on Windows (so the key would unpack 0664 from a Windows-made zip).
            .system(zip::System::Unix)
            .unix_permissions(mode);
        z.start_file(format!("{folder}/{name}"), opts).map_err(|e| format!("zip: {e}"))?;
        z.write_all(data).map_err(|e| format!("zip: {e}"))?;
    }
    Ok(z.finish().map_err(|e| format!("zip: {e}"))?.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zip_layout_and_modes() {
        let files = vec![("m_x.crt".to_string(), b"crt".to_vec()), ("m_x.key".to_string(), b"key".to_vec()),
                         ("trusted_certs/a.pem".to_string(), b"pem".to_vec())];
        let z = to_zip(&files, "m_x-morpheus", (2026, 11, 5, 12, 0, 0)).unwrap();
        let mut a = zip::ZipArchive::new(std::io::Cursor::new(z)).unwrap();
        let mut seen = Vec::new();
        for i in 0..a.len() {
            let f = a.by_index(i).unwrap();
            seen.push((f.name().unwrap().to_string(), f.unix_mode().unwrap() & 0o177777, f.compression()));
        }
        assert_eq!(seen, vec![
            ("m_x-morpheus/m_x.crt".to_string(), 0o100644, zip::CompressionMethod::Deflated),
            ("m_x-morpheus/m_x.key".to_string(), 0o100600, zip::CompressionMethod::Deflated),
            ("m_x-morpheus/trusted_certs/a.pem".to_string(), 0o100644, zip::CompressionMethod::Deflated),
        ]);
        let mut s = String::new();
        std::io::Read::read_to_string(&mut a.by_name("m_x-morpheus/m_x.key").unwrap(), &mut s).unwrap();
        assert_eq!(s, "key");
    }
}
