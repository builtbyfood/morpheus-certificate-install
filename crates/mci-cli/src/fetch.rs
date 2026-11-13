//! morpheus-certificate-install 0.4.0 — the CLI's `--fetch-chain` HTTP getter.
//!
//! Keeps the contract documented on `mci_core::aia::Fetch`: http/https only, 10 s timeout for the
//! whole request, a 1 MiB body cap, at most 3 redirects, no cookies, no credentials, no proxy taken
//! from the environment. Errors come back as text the log shows after the URL.

use std::io::Read;
use std::time::Duration;

pub const TIMEOUT: Duration = Duration::from_secs(10);
pub const MAX_BODY: usize = 1024 * 1024;
pub const MAX_REDIRECTS: u32 = 3;

fn is_http(u: &str) -> bool {
    let l = u.to_ascii_lowercase();
    l.starts_with("http://") || l.starts_with("https://")
}

pub fn fetch(url: &str) -> Result<Vec<u8>, String> {
    if !is_http(url) {
        return Err("only http and https URLs are fetched".into());
    }
    let agent = ureq::AgentBuilder::new()
        .timeout(TIMEOUT)
        .redirects(MAX_REDIRECTS)
        .user_agent(&format!("morpheus-certificate-install/{}", mci_core::VERSION))
        .build();
    match agent.get(url).call() {
        Ok(resp) => {
            let mut body = Vec::new();
            resp.into_reader()
                .take(MAX_BODY as u64 + 1)
                .read_to_end(&mut body)
                .map_err(|e| format!("reading the response failed: {e}"))?;
            if body.len() > MAX_BODY {
                return Err("the response is larger than 1 MiB, so it isn't a certificate".into());
            }
            Ok(body)
        }
        Err(ureq::Error::Status(code, _)) => Err(format!("HTTP {code}")),
        Err(ureq::Error::Transport(t)) => Err(match t.kind() {
            ureq::ErrorKind::TooManyRedirects => format!("more than {MAX_REDIRECTS} redirects"),
            ureq::ErrorKind::Io if t.to_string().to_lowercase().contains("timed out") => format!("timed out after {} s", TIMEOUT.as_secs()),
            _ => t.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;

    /// A one-thread HTTP/1.1 server: `route(path) -> (status line, extra headers, body)`.
    fn serve(route: fn(&str) -> (&'static str, String, Vec<u8>)) -> String {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = format!("http://{}", l.local_addr().unwrap());
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(mut s) = s else { continue };
                let mut buf = [0u8; 4096];
                let n = s.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
                let (status, headers, body) = route(&path);
                let _ = write!(s, "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n", body.len());
                let _ = s.write_all(&body);
            }
        });
        addr
    }

    #[test]
    fn contract() {
        let base = serve(|p| match p {
            "/ok" => ("200 OK", String::new(), b"DER".to_vec()),
            "/big" => ("200 OK", String::new(), vec![0u8; MAX_BODY + 10]),
            "/r1" => ("302 Found", "Location: /ok\r\n".into(), vec![]),
            p if p.starts_with("/loop") => {
                let n: u32 = p[5..].parse().unwrap_or(0);
                ("302 Found", format!("Location: /loop{}\r\n", n + 1), vec![])
            }
            _ => ("404 Not Found", String::new(), b"nope".to_vec()),
        });
        assert_eq!(fetch(&format!("{base}/ok")).unwrap(), b"DER");
        assert_eq!(fetch(&format!("{base}/r1")).unwrap(), b"DER");
        assert_eq!(fetch(&format!("{base}/missing")).unwrap_err(), "HTTP 404");
        assert!(fetch(&format!("{base}/big")).unwrap_err().contains("larger than 1 MiB"));
        assert_eq!(fetch(&format!("{base}/loop0")).unwrap_err(), "more than 3 redirects");
        assert!(fetch("ldap:///CN=x").unwrap_err().contains("only http and https"));
        assert!(fetch("file:///etc/passwd").is_err());
    }
}
