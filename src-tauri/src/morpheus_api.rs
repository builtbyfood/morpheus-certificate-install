//! morpheus-certificate-install 0.4.1 — optional Morpheus API check (R7).
//!
//! Port of reference engine.morpheus_check / set_appliance_url. Bearer token header only
//! (`?access_token=` is ignored by Morpheus). GET /api/whoami → user.username, appliance.buildVersion;
//! GET /api/appliance-settings → applianceSettings.applianceUrl; PUT the same with {applianceSettings:{applianceUrl}}.
//! TLS is verified first (the supplied root, the OS store, the built-in roots, as `verify`); on a TLS error it retries
//! unverified and reports verified_tls=false with the reason.
//! Response JSON keys as the reference: url, verified_tls, tls_error?, user, build, appliance_url,
//! appliance_url_covered?, appliance_url_error?, error?
//!
//! The token is only ever in the Authorization header: never logged, never in an event.

use mci_core::analyze::Analysis;
use serde_json::{json, Value};
use std::time::Duration;

pub const TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug)]
pub enum ApiError {
    /// The TLS handshake failed (certificate not trusted, wrong name, …).
    Tls(String),
    /// The server answered with a non-2xx status.
    Http(u16),
    /// Couldn't reach it, or the answer wasn't JSON.
    Other(String),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::Tls(e) => write!(f, "TLS: {e}"),
            ApiError::Http(c) => write!(f, "HTTP {c}"),
            ApiError::Other(e) => f.write_str(e),
        }
    }
}

/// The rustls error somewhere in reqwest's error chain, if the failure was the TLS handshake.
/// (hyper wraps it as io::Error(Other, io::Error(InvalidData, rustls::Error)), and io::Error's
/// `source()` skips the error it wraps, so each io::Error is opened with `get_ref`.)
fn tls_cause(e: &reqwest::Error) -> Option<String> {
    let mut src: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(s) = src {
        if let Some(r) = s.downcast_ref::<rustls::Error>() {
            return Some(crate::verify::describe(r));
        }
        if let Some(r) = s.downcast_ref::<std::io::Error>().and_then(crate::verify::rustls_in_io) {
            return Some(crate::verify::describe(r));
        }
        src = s.source();
    }
    None
}

/// The innermost cause, for "could not reach" messages (reqwest's own text is generic).
fn root_cause(e: &reqwest::Error) -> String {
    let mut last = e.to_string();
    let mut src = std::error::Error::source(e);
    while let Some(s) = src {
        last = s.to_string();
        src = s.source();
    }
    last
}

/// `ca_der`: the supplied root. Verified requests use the same stores as `verify` (supplied root,
/// OS store, built-in roots); unverified ones accept any certificate.
pub async fn api(url: &str, token: &str, path: &str, ca_der: Option<&[u8]>, method: reqwest::Method, body: Option<&Value>, verify: bool) -> Result<Value, ApiError> {
    let mut cfg = if verify {
        crate::verify::verifying_config(ca_der).map(|(c, _)| c)
    } else {
        crate::verify::no_verify_config()
    }.map_err(|e| ApiError::Other(e.to_string()))?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let client = reqwest::Client::builder().use_preconfigured_tls(cfg).timeout(TIMEOUT)
        .build().map_err(|e| ApiError::Other(e.to_string()))?;
    let mut req = client
        .request(method, format!("{}{path}", url.trim_end_matches('/')))
        .header("Authorization", format!("Bearer {token}"))
        .header("Accept", "application/json")
        .header("Content-Type", "application/json");
    if let Some(body) = body {
        req = req.body(body.to_string());
    }
    let resp = req.send().await.map_err(|e| match tls_cause(&e) {
        Some(t) => ApiError::Tls(t),
        None => ApiError::Other(root_cause(&e)),
    })?;
    let status = resp.status();
    if !status.is_success() {
        return Err(ApiError::Http(status.as_u16()));
    }
    let text = resp.text().await.map_err(|e| ApiError::Other(root_cause(&e)))?;
    if text.trim().is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_str(&text).map_err(|_| ApiError::Other(format!("{path} didn't answer with JSON; is {url} the Morpheus UI?")))
}

fn root_der(an: Option<&Analysis>) -> Option<Vec<u8>> {
    an.and_then(|a| a.root.as_ref()).map(|r| r.der.clone())
}

pub async fn morpheus_check(url: &str, token: &str, an: Option<&Analysis>) -> Value {
    let ca = root_der(an);
    let mut out = json!({"url": url});
    let who = match api(url, token, "/api/whoami", ca.as_deref(), reqwest::Method::GET, None, true).await {
        Ok(w) => { out["verified_tls"] = json!(true); w }
        Err(ApiError::Tls(e)) => {
            out["verified_tls"] = json!(false);
            out["tls_error"] = json!(e);
            match api(url, token, "/api/whoami", ca.as_deref(), reqwest::Method::GET, None, false).await {
                Ok(w) => w,
                Err(ApiError::Http(c)) => return json!({"url": url, "error": format!("HTTP {c} from /api/whoami — check the API token.")}),
                Err(e) => return json!({"url": url, "error": format!("could not reach {url}: {e}")}),
            }
        }
        Err(ApiError::Http(c)) => return json!({"url": url, "error": format!("HTTP {c} from /api/whoami — check the API token.")}),
        Err(e) => return json!({"url": url, "error": format!("could not reach {url}: {e}")}),
    };
    out["user"] = who.pointer("/user/username").cloned().unwrap_or(Value::Null);
    out["build"] = who.pointer("/appliance/buildVersion").cloned().unwrap_or(Value::Null);
    let verified = out["verified_tls"] == json!(true);
    match api(url, token, "/api/appliance-settings", ca.as_deref(), reqwest::Method::GET, None, verified).await {
        Ok(s) => out["appliance_url"] = s.pointer("/applianceSettings/applianceUrl").cloned().unwrap_or(Value::Null),
        Err(e) => out["appliance_url_error"] = json!(e.to_string()), // permissions vary
    }
    if let (Some(leaf), Some(au)) = (an.and_then(|a| a.leaf.as_ref()), out["appliance_url"].as_str()) {
        if !au.is_empty() {
            let host = url_hostname(au);
            out["appliance_url_covered"] = json!(mci_core::names::host_matches(&host, &leaf.san_dns, &leaf.san_ip));
        }
    }
    out
}

/// PUT the Appliance URL. TLS as for the check: verified first, unverified on a TLS error.
pub async fn set_appliance_url(url: &str, token: &str, new_url: &str, an: Option<&Analysis>) -> Result<Value, String> {
    let ca = root_der(an);
    let body = json!({"applianceSettings": {"applianceUrl": new_url}});
    let put = |verify: bool| {
        let (ca, body) = (ca.clone(), body.clone());
        async move { api(url, token, "/api/appliance-settings", ca.as_deref(), reqwest::Method::PUT, Some(&body), verify).await }
    };
    let r = match put(true).await {
        Err(ApiError::Tls(_)) => put(false).await,
        r => r,
    };
    r.map_err(|e| match e {
        ApiError::Http(c) => format!("Morpheus refused the change (HTTP {c} from PUT /api/appliance-settings). The token's user needs permission to edit appliance settings."),
        e => format!("Couldn't change the Appliance URL: {e}. Nothing was changed; check the Morpheus URL and try again."),
    })
}

/// `urlparse(u).hostname`: lowercased, without userinfo, port or IPv6 brackets.
fn url_hostname(u: &str) -> String {
    let rest = u.split_once("://").map(|(_, r)| r).unwrap_or("");
    let netloc = rest.split(['/', '?', '#']).next().unwrap_or("");
    let hp = netloc.rsplit('@').next().unwrap_or("");
    let h = if let Some(r) = hp.strip_prefix('[') { r.split(']').next().unwrap_or("") } else { hp.split(':').next().unwrap_or("") };
    h.to_lowercase()
}

#[cfg(test)]
mod tests {
    #[test]
    fn hostname() {
        assert_eq!(super::url_hostname("https://M.Cust.Test:8443/x"), "m.cust.test");
        assert_eq!(super::url_hostname("https://u:p@[::1]:443/"), "::1");
        assert_eq!(super::url_hostname("https://198.51.100.20"), "198.51.100.20");
        assert_eq!(super::url_hostname("m.cust.test"), "");
    }
}

