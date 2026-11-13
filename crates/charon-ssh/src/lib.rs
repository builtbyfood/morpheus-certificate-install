//! SSH transport, PTY sessions and host-key trust-on-first-use.
//!
//! Extracted from [charon](https://github.com/) so that more than one
//! application can share a single SSH implementation instead of each growing
//! its own. The rule that makes that work: **nothing in here knows what a UI
//! is.** Output arrives on a channel, unknown host keys are referred to a
//! [`policy::HostKeyPolicy`], and errors are values. An application decides
//! what to do with all three.
//!
//! ```no_run
//! # async fn example() -> anyhow::Result<()> {
//! use charon_ssh::{Auth, HostKeys, RefuseUnknown, SshParams, SshSession, Output};
//! use std::sync::Arc;
//!
//! let keys = Arc::new(HostKeys::new(std::path::Path::new("/var/lib/myapp"), "myapp"));
//! let (session, mut out) = SshSession::connect(
//!     keys,
//!     Arc::new(RefuseUnknown),
//!     SshParams::new("appliance.example.com", "root", Auth::Password("…".into())),
//! )
//! .await?;
//!
//! session.write(b"uptime\n").await?;
//! while let Some(item) = out.recv().await {
//!     match item {
//!         Output::Data(bytes) => print!("{}", String::from_utf8_lossy(&bytes)),
//!         Output::Closed(why) => { eprintln!("closed: {why:?}"); break }
//!     }
//! }
//! # Ok(()) }
//! ```

pub mod client;
pub mod exec;
pub mod hostkeys;
pub mod policy;

pub use client::{Auth, Closed, HostKeyChanged, Output, Shell, SshError, SshParams, SshSession};
pub use exec::{ExecHandle, ExecOut, Exited, RemoteFile, Sftp};
pub use russh::ChannelStream;
pub use hostkeys::{fingerprint, host_pattern, HostKeys, Verdict};
pub use policy::{AcceptUnknownForTesting, HostKeyPolicy, HostKeyPrompt, RefuseUnknown};
