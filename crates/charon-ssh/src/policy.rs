//! Who gets asked about an unknown host key.
//!
//! This is the seam that makes the crate reusable. In charon the answer comes
//! from a Tauri event round-trip to a Svelte dialog; in hvm-desk it comes from
//! somewhere else entirely; in a test it is a constant. None of that belongs in
//! the transport, so the transport asks a trait object and waits.
//!
//! The trait is only consulted for `Verdict::Unknown`. A key that is already
//! known is accepted without asking, and a key that has *changed* is refused
//! without asking — that decision is not the application's to make, and a
//! policy object cannot override it.

use async_trait::async_trait;
use serde::Serialize;

/// What the user needs to see to answer sensibly.
#[derive(Debug, Clone, Serialize)]
pub struct HostKeyPrompt {
    pub host: String,
    pub port: u16,
    /// e.g. `ssh-ed25519`.
    pub key_type: String,
    /// `SHA256:…`, as ssh-keygen prints it.
    pub fingerprint: String,
    /// Where the key will be written if it is accepted.
    pub known_hosts: String,
}

#[async_trait]
pub trait HostKeyPolicy: Send + Sync {
    /// `true` accepts the key and records it in known_hosts; `false` refuses
    /// and drops the connection. Taking too long is the implementation's
    /// problem: whatever timeout is appropriate belongs on this side, and
    /// returning `false` is how it reports one.
    async fn approve_unknown(&self, prompt: &HostKeyPrompt) -> bool;
}

/// Refuses every unknown host. The right default for anything unattended: a
/// host must have been learned deliberately before a connection will succeed.
pub struct RefuseUnknown;

#[async_trait]
impl HostKeyPolicy for RefuseUnknown {
    async fn approve_unknown(&self, _prompt: &HostKeyPrompt) -> bool {
        false
    }
}

/// Accepts every unknown host. **Tests only** — it is trust-on-first-use with
/// the trust part removed. Named so that it is obvious in a diff.
pub struct AcceptUnknownForTesting;

#[async_trait]
impl HostKeyPolicy for AcceptUnknownForTesting {
    async fn approve_unknown(&self, _prompt: &HostKeyPrompt) -> bool {
        true
    }
}
