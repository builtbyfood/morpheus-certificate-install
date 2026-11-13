//! morpheus-certificate-install 0.4.0 — helpers shared by the live/mock transport tests.
#![allow(dead_code)]

pub mod app;
pub mod charon_steps;

use mci_app::transport::ssh::{connect, SshParams};
use mci_app::transport::{Transport, TransportError};

pub struct Target { pub host: String, pub port: u16, pub user: String, pub password: String }

/// MCI_TEST_SSH=host:port:user:password
pub fn ssh_target() -> Option<Target> {
    let v = std::env::var("MCI_TEST_SSH").ok()?;
    let mut it = v.splitn(4, ':');
    Some(Target {
        host: it.next()?.to_string(),
        port: it.next()?.parse().ok()?,
        user: it.next()?.to_string(),
        password: it.next()?.to_string(),
    })
}

/// An SSH transport to the target, trusting its host key on first use into a temp known_hosts.
pub async fn ssh_reference(tg: &Target) -> Box<dyn Transport> {
    let kh = std::env::temp_dir().join(format!("mci-ref-{}-{}", std::process::id(), tg.port)).join("known_hosts");
    let p = |trust: &str| SshParams {
        host: tg.host.clone(), port: tg.port, user: tg.user.clone(), password: tg.password.clone(),
        key_path: String::new(), key_passphrase: String::new(), sudo_password: String::new(),
        trust_fingerprint: trust.to_string(), known_hosts: kh.clone(),
    };
    match connect(p("")).await {
        Ok(t) => t,
        Err(TransportError::HostKey { fingerprint, mismatch: false, .. }) => connect(p(&fingerprint)).await.expect("ssh reference"),
        Err(e) => panic!("ssh reference: {e}"),
    }
}
