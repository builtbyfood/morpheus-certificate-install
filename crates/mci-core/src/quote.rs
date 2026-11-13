//! morpheus-certificate-install 0.4.0 — POSIX shell quoting, byte-identical to Python's `shlex.quote`.

/// `shlex.quote`: unchanged if every char is in `[A-Za-z0-9_@%+=:,./-]`, `''` if empty,
/// otherwise single-quoted with each `'` written as `'"'"'`.
pub fn q(s: &str) -> String {
    if s.is_empty() {
        return "''".to_string();
    }
    let safe = s.chars().all(|c| c.is_ascii_alphanumeric() || "_@%+=:,./-".contains(c));
    if safe {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\"'\"'"))
    }
}

#[cfg(test)]
mod tests {
    use super::q;
    #[test]
    fn matches_python_shlex_quote() {
        assert_eq!(q(""), "''");
        assert_eq!(q("/etc/morpheus/ssl/a_b.crt"), "/etc/morpheus/ssl/a_b.crt");
        assert_eq!(q("id -un"), "'id -un'");
        assert_eq!(q("a'b"), "'a'\"'\"'b'");
        assert_eq!(q("$HOME"), "'$HOME'");
        assert_eq!(q("changeit"), "changeit");
    }
}
