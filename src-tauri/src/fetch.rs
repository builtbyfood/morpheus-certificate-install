//! morpheus-certificate-install 0.4.2 — the app's AIA getter for fetch_chain (blocking; call it
//! from `spawn_blocking`).
//!
//! The same contract as the CLI's (crates/mci-cli/src/fetch.rs), documented on
//! `mci_core::aia::Fetch`: http/https only, 10 s for the whole request, a 1 MiB body cap, at most
//! 3 redirects, no cookies, no credentials, no proxy taken from the environment.

use std::io::Read;
use std::time::Duration;

pub const TIMEOUT: Duration = Duration::from_secs(10);
pub const MAX_BODY: usize = 1024 * 1024;
pub const MAX_REDIRECTS: usize = 3;

pub fn fetch(url: &str) -> Result<Vec<u8>, String> {
    let l = url.to_ascii_lowercase();
    if !(l.starts_with("http://") || l.starts_with("https://")) {
        return Err("only http and https URLs are fetched".into());
    }
    let client = reqwest::blocking::Client::builder()
        .timeout(TIMEOUT)
        .redirect(reqwest::redirect::Policy::limited(MAX_REDIRECTS))
        .no_proxy()
        .user_agent(format!("morpheus-certificate-install/{}", mci_core::VERSION))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client.get(url).send().map_err(|e| {
        if e.is_redirect() { format!("more than {MAX_REDIRECTS} redirects") }
        else if e.is_timeout() { format!("timed out after {} s", TIMEOUT.as_secs()) }
        else { e.to_string() }
    })?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status().as_u16()));
    }
    let mut body = Vec::new();
    resp.take(MAX_BODY as u64 + 1).read_to_end(&mut body).map_err(|e| format!("reading the response failed: {e}"))?;
    if body.len() > MAX_BODY {
        return Err("the response is larger than 1 MiB, so it isn't a certificate".into());
    }
    Ok(body)
}
