//! morpheus-certificate-install 0.4.1 — file names, truststore aliases and SAN matching.

use std::net::IpAddr;

/// `morpheus.example.com` → `morpheus_example_com` (the docs' `your_fqdn_name`).
pub fn safe_name(fqdn: &str) -> String {
    let lower = fqdn.trim().to_lowercase();
    let mut out = String::new();
    let mut in_run = false;
    for c in lower.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c);
            in_run = false;
        } else if !in_run {
            out.push('_');
            in_run = true;
        }
    }
    let s = out.trim_matches('_').to_string();
    if s.is_empty() { "morpheus".into() } else { s }
}

/// Java truststore alias: `mci-<cn slug, ≤40>-<first 8 hex of the cert's SHA-256>`.
/// `sha256_hex` is the lowercase hex fingerprint without separators.
pub fn alias_for(cn: &str, sha256_hex: &str) -> String {
    let lower = cn.to_lowercase();
    let mut base = String::new();
    let mut in_run = false;
    for c in lower.chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            base.push(c);
            in_run = false;
        } else if !in_run {
            base.push('-');
            in_run = true;
        }
    }
    let base: String = base.trim_matches('-').chars().take(40).collect();
    let base = if base.is_empty() { "ca".to_string() } else { base };
    format!("mci-{}-{}", base, &sha256_hex.to_lowercase()[..8])
}

/// RFC 6125 name check, same rules as the reference: IPs compare against IP SANs only;
/// a wildcard is the whole left-most label and covers exactly one level.
pub fn host_matches(host: &str, dns: &[String], ips: &[String]) -> bool {
    let host = host.trim().to_lowercase();
    let host = host.trim_end_matches('.');
    if let Ok(ip) = host.parse::<IpAddr>() {
        return ips.iter().any(|i| i.parse::<IpAddr>().map(|x| x == ip).unwrap_or(false));
    }
    for name in dns {
        let name = name.to_lowercase();
        let name = name.trim_end_matches('.');
        if name == host {
            return true;
        }
        if let Some(rest) = name.strip_prefix('*') {
            if rest.starts_with('.') && host.matches('.').count() == name.matches('.').count() && host.ends_with(rest) {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    fn v(x: &[&str]) -> Vec<String> { x.iter().map(|s| s.to_string()).collect() }
    #[test]
    fn safe_names() {
        assert_eq!(safe_name("morpheus.example.com"), "morpheus_example_com");
        assert_eq!(safe_name(" Appliance.Example.Test. "), "appliance_example_test");
        assert_eq!(safe_name("..."), "morpheus");
    }
    #[test]
    fn aliases_match_reference() {
        // From fixtures/cases.json (pfx-modern / jks): the reference computed these.
        assert_eq!(alias_for("DeLuca Home Root CA", "e93e24b7aa"), "mci-deluca-home-root-ca-e93e24b7");
        assert_eq!(alias_for("  ", "0123456789"), "mci-ca-01234567");
    }
    #[test]
    fn san_rules() {
        assert!(host_matches("a.example.com", &v(&["*.example.com"]), &[]));
        assert!(!host_matches("a.b.example.com", &v(&["*.example.com"]), &[]));
        assert!(!host_matches("example.com", &v(&["*.example.com"]), &[]));
        assert!(host_matches("10.0.0.5", &[], &v(&["10.0.0.5"])));
        assert!(!host_matches("10.0.0.5", &v(&["10.0.0.5"]), &[]));
        assert!(host_matches("M.Cust.Test.", &v(&["m.cust.test"]), &[]));
    }
}
