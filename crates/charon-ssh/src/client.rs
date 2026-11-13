//! An SSH connection with an interactive shell on it.
//!
//! Adapted from charon's `ssh.rs`, with two things taken out and one put in.
//! Out: the Tauri event emission (output is an `mpsc::Receiver` the caller
//! owns) and the hidden-capture machinery behind charon's MCP tooling, which is
//! charon's feature and not a transport concern. In: `HostKeyPolicy`, so the
//! question "do you trust this host" is answered by whoever is on top.
//!
//! What is kept, because it was paid for: the host-key verdicts including the
//! hard refusal on a changed key, keepalive rather than an inactivity timeout
//! (an idle session is not a dead one), and per-hop errors that name the host
//! that actually failed.

use crate::hostkeys::{fingerprint, key_type, HostKeys, Verdict};
use crate::policy::{HostKeyPolicy, HostKeyPrompt};
use anyhow::{anyhow, Context, Result};
use russh::client::{self, Handle};
use russh::keys::{PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate};
use russh::{ChannelMsg, Disconnect};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

/// How to reach a host.
pub struct SshParams {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: Auth,
    pub cols: u16,
    pub rows: u16,
    /// Server-alive interval. `None` disables keepalive; otherwise russh gives
    /// up after roughly three missed replies, which is how a peer that went
    /// away without closing the socket is noticed.
    pub keepalive: Option<std::time::Duration>,
}

impl SshParams {
    /// Sensible defaults for an interactive shell: port 22, 80x24, a 30-second
    /// keepalive. Callers override what they care about.
    pub fn new(host: impl Into<String>, user: impl Into<String>, auth: Auth) -> Self {
        Self {
            host: host.into(),
            port: 22,
            user: user.into(),
            auth,
            cols: 80,
            rows: 24,
            keepalive: Some(std::time::Duration::from_secs(30)),
        }
    }
}

/// How to authenticate.
#[derive(Clone)]
pub enum Auth {
    Password(String),
    /// `key` is a path to a private key file or the PEM text itself.
    Key {
        key: String,
        passphrase: Option<String>,
    },
    /// The keys held by the running SSH agent: `SSH_AUTH_SOCK` on Unix; on
    /// Windows the OpenSSH agent service (`\\.\pipe\openssh-ssh-agent`), then
    /// Pageant. Fails if no agent is running.
    Agent,
    /// What `ssh` does with no options, and paramiko with `allow_agent` and
    /// `look_for_keys`: the agent's keys if one is running, then
    /// `~/.ssh/id_ed25519`, `id_ecdsa`, `id_rsa` (skipping any that need a
    /// passphrase).
    Auto,
}

impl Auth {
    fn load_key(key: &str, passphrase: Option<&str>) -> Result<russh::keys::PrivateKey> {
        // Key text has a recognisable first line; anything else is a path.
        let text = if key.trim_start().starts_with("-----") {
            key.to_string()
        } else if Path::new(key).is_file() {
            std::fs::read_to_string(key).with_context(|| format!("read private key {key}"))?
        } else {
            return Err(anyhow!("private key file not found: {key}"));
        };
        russh::keys::decode_secret_key(&text, passphrase)
            .with_context(|| format!("decode private key {key}"))
    }
}

/// Details of a host key mismatch, kept structured so the application can offer
/// the right fix rather than printing a wall of text.
#[derive(Debug, Clone)]
pub struct HostKeyChanged {
    pub host: String,
    pub port: u16,
    pub key_type: String,
    pub fingerprint: String,
    /// File holding the stale entry, and its 1-based line.
    pub file: String,
    pub line: usize,
    /// True when the stale entry is in our own known_hosts, which we can
    /// rewrite; false for the user's `~/.ssh/known_hosts`, which is read-only
    /// here and has to be fixed with `ssh-keygen -R`.
    pub own: bool,
}

impl std::fmt::Display for HostKeyChanged {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "HOST KEY CHANGED for {}:{} — the {} key the server presented ({}) does not match \
             the one recorded in {} line {}. Someone could be intercepting this connection.",
            self.host, self.port, self.key_type, self.fingerprint, self.file, self.line
        )
    }
}

/// Handler errors. russh requires `From<russh::Error>`; the extra variants
/// carry the host-key outcome so the caller gets a sentence, not a code.
#[derive(Debug)]
pub enum SshError {
    Russh(russh::Error),
    HostKeyChanged(HostKeyChanged),
    HostKeyRejected,
    /// The server refused the credentials (password, key or agent). Reaches
    /// the caller inside the `anyhow::Error` from `connect`, so
    /// `err.downcast_ref::<SshError>()` tells "wrong password" from "couldn't
    /// reach the host" without matching on message text. The text itself is
    /// unchanged from before this variant existed.
    AuthRejected { user: String, host: String },
}

impl From<russh::Error> for SshError {
    fn from(e: russh::Error) -> Self {
        Self::Russh(e)
    }
}

impl std::fmt::Display for SshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Russh(e) => write!(f, "{e}"),
            Self::HostKeyChanged(d) => write!(f, "{d}"),
            Self::HostKeyRejected => f.write_str("host key rejected"),
            Self::AuthRejected { user, host } => write!(f, "authentication rejected for {user}@{host}"),
        }
    }
}

impl std::error::Error for SshError {}

struct Handler {
    host: String,
    port: u16,
    keys: Arc<HostKeys>,
    policy: Arc<dyn HostKeyPolicy>,
    /// (key type, fingerprint) of the host key the server presented.
    seen: Arc<std::sync::Mutex<Option<(String, String)>>>,
}

impl client::Handler for Handler {
    type Error = SshError;

    async fn check_server_key(
        &mut self,
        server_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        // A host *certificate* is checked by the key inside it, exactly like a
        // plain host key: this crate has no CA trust, so known_hosts decides.
        let owned;
        let key: &PublicKey = match server_key {
            PublicKeyOrCertificate::PublicKey { key, .. } => key,
            PublicKeyOrCertificate::Certificate(cert) => {
                owned = PublicKey::new(cert.public_key().clone(), "");
                &owned
            }
        };
        if let Ok(mut s) = self.seen.lock() {
            *s = Some((key_type(key), fingerprint(key)));
        }
        let verdict = self.keys.check(&self.host, self.port, key);
        tracing::info!(
            host = %self.host, port = self.port, key_type = %key_type(key),
            fingerprint = %fingerprint(key), ?verdict, "host key check"
        );
        match verdict {
            Verdict::Known => Ok(true),
            // Never negotiable, and never routed through the policy: a changed
            // key is the one case where asking the user is the wrong thing to do.
            Verdict::Changed { file, line } => Err(SshError::HostKeyChanged(HostKeyChanged {
                host: self.host.clone(),
                port: self.port,
                key_type: key_type(key),
                fingerprint: fingerprint(key),
                own: self.keys.is_own(&file),
                file: file.display().to_string(),
                line,
            })),
            Verdict::Unknown => {
                let prompt = HostKeyPrompt {
                    host: self.host.clone(),
                    port: self.port,
                    key_type: key_type(key),
                    fingerprint: fingerprint(key),
                    known_hosts: self.keys.own_path().display().to_string(),
                };
                if !self.policy.approve_unknown(&prompt).await {
                    tracing::info!(host = %self.host, "unknown host key refused");
                    return Err(SshError::HostKeyRejected);
                }
                // Recording it is what makes the *next* connection a Known
                // verdict. Failing to record is not fatal to this connection.
                match self.keys.learn(&self.host, self.port, key) {
                    Ok(()) => tracing::info!(host = %self.host, "host key accepted and recorded"),
                    Err(e) => {
                        tracing::warn!(host = %self.host, "host key accepted but not recorded: {e:#}")
                    }
                }
                Ok(true)
            }
        }
    }
}

/// Commands for the task that owns the channel.
enum Cmd {
    Write(Vec<u8>),
    Resize(u16, u16),
    Close,
}

/// Why a session's output stream ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Closed {
    /// The remote shell exited with this status.
    Exit(u32),
    /// EOF or channel close without a status.
    Eof,
}

/// What a caller reads from a live session.
pub enum Output {
    /// Bytes from the remote shell, to be fed to a terminal as they arrive.
    Data(Vec<u8>),
    /// The shell is gone. Always the last item.
    Closed(Closed),
}

pub struct SshSession {
    handle: Mutex<Handle<Handler>>,
    /// The shell `connect` opened; `None` for `connect_exec`.
    tx: Option<mpsc::Sender<Cmd>>,
    server_key: Option<(String, String)>,
}

async fn authenticate(
    handle: &mut Handle<Handler>,
    user: &str,
    host: &str,
    auth: &Auth,
) -> Result<()> {
    let accepted = match auth {
        Auth::Key { key, passphrase } => {
            let key = Auth::load_key(key, passphrase.as_deref())?;
            key_auth(handle, user, key).await?
        }
        Auth::Password(pw) => handle.authenticate_password(user, pw).await?.success(),
        Auth::Agent => agent_auth(handle, user).await?,
        Auth::Auto => {
            // paramiko's allow_agent + look_for_keys: the agent if one is
            // running, then the usual key files. An agent that isn't there is
            // not an error here; it's just one fewer thing to try.
            let by_agent = match agent_auth(handle, user).await {
                Ok(ok) => ok,
                Err(e) => {
                    tracing::info!("no SSH agent to try: {e:#}");
                    false
                }
            };
            by_agent || default_key_auth(handle, user).await?
        }
    };
    if !accepted {
        return Err(SshError::AuthRejected { user: user.to_string(), host: host.to_string() }.into());
    }
    Ok(())
}

/// Public-key auth with a key in hand.
async fn key_auth(handle: &mut Handle<Handler>, user: &str, key: russh::keys::PrivateKey) -> Result<bool> {
    // RSA keys sign with the best hash the server accepts (rsa-sha2-512/256),
    // not legacy SHA-1, which current OpenSSH servers refuse.
    let hash = handle.best_supported_rsa_hash().await?.flatten();
    Ok(handle
        .authenticate_publickey(user, PrivateKeyWithHashAlg::new(Arc::new(key), hash))
        .await?
        .success())
}

/// Offer each identity the running agent holds, in its order, until one is
/// accepted. `Err` only when there is no agent to ask.
async fn agent_auth(handle: &mut Handle<Handler>, user: &str) -> Result<bool> {
    #[cfg(unix)]
    {
        let agent = russh::keys::agent::client::AgentClient::connect_env()
            .await
            .context("no SSH agent (SSH_AUTH_SOCK isn't set or the agent isn't running)")?;
        agent_try_all(handle, user, agent).await
    }
    #[cfg(windows)]
    {
        // The OpenSSH for Windows agent service first, then PuTTY's Pageant.
        use russh::keys::agent::client::AgentClient;
        match AgentClient::connect_named_pipe(r"\\.\pipe\openssh-ssh-agent").await {
            Ok(agent) => agent_try_all(handle, user, agent).await,
            Err(pipe_err) => {
                let agent = AgentClient::connect_pageant().await.map_err(|e| {
                    anyhow!("no SSH agent (the OpenSSH agent service isn't running: {pipe_err}; nor is Pageant: {e})")
                })?;
                agent_try_all(handle, user, agent).await
            }
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (handle, user);
        Err(anyhow!("SSH agent support isn't available on this platform"))
    }
}

async fn agent_try_all<S>(
    handle: &mut Handle<Handler>,
    user: &str,
    mut agent: russh::keys::agent::client::AgentClient<S>,
) -> Result<bool>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use russh::keys::agent::AgentIdentity;
    let ids = agent.request_identities().await.context("asking the SSH agent for its keys")?;
    let hash = handle.best_supported_rsa_hash().await?.flatten();
    for id in ids {
        let r = match &id {
            AgentIdentity::PublicKey { key, .. } => handle.authenticate_publickey_with(user, key.clone(), hash, &mut agent).await,
            AgentIdentity::Certificate { certificate, .. } => {
                handle.authenticate_certificate_with(user, certificate.clone(), hash, &mut agent).await
            }
        };
        match r {
            Ok(res) if res.success() => return Ok(true),
            Ok(_) => {}
            // One key the agent can't sign with (a hardware key that's
            // unplugged, say) shouldn't stop the others being tried.
            Err(e) => tracing::info!("agent key not usable: {e:?}"),
        }
    }
    Ok(false)
}

/// The key files OpenSSH and paramiko look for, in their order. Keys that
/// need a passphrase are skipped (there's nobody to ask), as are files that
/// aren't there.
async fn default_key_auth(handle: &mut Handle<Handler>, user: &str) -> Result<bool> {
    let Some(home) = dirs::home_dir() else { return Ok(false) };
    for name in ["id_ed25519", "id_ecdsa", "id_rsa"] {
        let path = home.join(".ssh").join(name);
        let Ok(text) = std::fs::read_to_string(&path) else { continue };
        let key = match russh::keys::decode_secret_key(&text, None) {
            Ok(k) => k,
            Err(e) => {
                tracing::info!(file = %path.display(), "default key skipped: {e}");
                continue;
            }
        };
        if key_auth(handle, user, key).await? {
            return Ok(true);
        }
    }
    Ok(false)
}

impl SshSession {
    /// Connect, authenticate, and open an interactive shell.
    ///
    /// Returns the session and the stream of everything the shell says. The
    /// receiver must be drained — it is bounded, and a caller that stops
    /// reading will eventually stall the shell rather than grow without limit.
    pub async fn connect(
        keys: Arc<HostKeys>,
        policy: Arc<dyn HostKeyPolicy>,
        p: SshParams,
    ) -> Result<(Arc<Self>, mpsc::Receiver<Output>)> {
        let (handle, server_key) = establish(keys, policy, &p).await?;
        let (tx, out_rx) = start_shell(&handle, p.cols, p.rows).await?;
        Ok((
            Arc::new(Self {
                handle: Mutex::new(handle),
                tx: Some(tx),
                server_key,
            }),
            out_rx,
        ))
    }

    /// Connect and authenticate, without opening a shell.
    ///
    /// For callers that run commands ([`exec`](Self::exec) and friends) and
    /// open a terminal only when someone asks for one ([`open_shell`](Self::open_shell)).
    /// Host-key checking, keepalive and errors are exactly as in [`connect`](Self::connect);
    /// `cols`/`rows` in the params are unused until a shell is opened.
    /// [`write`](Self::write) and [`resize`](Self::resize) on such a session
    /// report that it has no shell.
    pub async fn connect_exec(
        keys: Arc<HostKeys>,
        policy: Arc<dyn HostKeyPolicy>,
        p: SshParams,
    ) -> Result<Arc<Self>> {
        let (handle, server_key) = establish(keys, policy, &p).await?;
        Ok(Arc::new(Self { handle: Mutex::new(handle), tx: None, server_key }))
    }

    /// Open an interactive PTY shell (`xterm-256color`, `cols`x`rows`) on
    /// this connection.
    ///
    /// Any number may be opened, one after another or side by side. Each
    /// [`Shell`] closes only its own channel, so closing a terminal leaves
    /// the connection — and anything running on it — alone, and a new shell
    /// can be opened after the user typed `exit` in the last one. The
    /// receiver must be drained, as with `connect`.
    pub async fn open_shell(&self, cols: u16, rows: u16) -> Result<(Shell, mpsc::Receiver<Output>)> {
        let handle = self.handle.lock().await;
        let (tx, out_rx) = start_shell(&handle, cols, rows).await?;
        Ok((Shell { tx }, out_rx))
    }
}

/// Connect and authenticate: everything `connect` does before the shell.
async fn establish(
    keys: Arc<HostKeys>,
    policy: Arc<dyn HostKeyPolicy>,
    p: &SshParams,
) -> Result<(Handle<Handler>, Option<(String, String)>)> {
    let seen = Arc::new(std::sync::Mutex::new(None));
    // No inactivity timeout: it dropped idle sessions, which is exactly
    // what a terminal left open overnight looks like. Keepalive detects a
    // genuinely dead peer instead.
    let config = Arc::new(client::Config {
        inactivity_timeout: None,
        keepalive_interval: p.keepalive,
        keepalive_max: 3,
        ..Default::default()
    });

    let handler = Handler {
        host: p.host.clone(),
        port: p.port,
        keys,
        policy,
        seen: seen.clone(),
    };

    let mut handle = client::connect(config, (p.host.as_str(), p.port), handler)
        .await
        .with_context(|| format!("connect {}:{}", p.host, p.port))?;
    authenticate(&mut handle, &p.user, &p.host, &p.auth).await?;
    let server_key = seen.lock().ok().and_then(|s| s.clone());
    Ok((handle, server_key))
}

/// Open a PTY shell channel and start the task that owns it.
async fn start_shell(handle: &Handle<Handler>, cols: u16, rows: u16) -> Result<(mpsc::Sender<Cmd>, mpsc::Receiver<Output>)> {
    let mut channel = handle.channel_open_session().await?;
    channel
        .request_pty(
            false,
            "xterm-256color",
            cols as u32,
            rows as u32,
            0,
            0,
            &[],
        )
        .await?;
    channel.request_shell(true).await?;

    let (tx, mut rx) = mpsc::channel::<Cmd>(256);
    let (out_tx, out_rx) = mpsc::channel::<Output>(256);

    // One task owns the channel: nothing else may write to it, which is
    // what keeps interleaving impossible without a lock on the hot path.
    tokio::spawn(async move {
        loop {
            tokio::select! {
                msg = channel.wait() => match msg {
                    Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => {
                        if out_tx.send(Output::Data(data.to_vec())).await.is_err() {
                            break; // nobody is listening any more
                        }
                    }
                    Some(ChannelMsg::ExitStatus { exit_status }) => {
                        let _ = out_tx.send(Output::Closed(Closed::Exit(exit_status))).await;
                    }
                    Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => {
                        let _ = out_tx.send(Output::Closed(Closed::Eof)).await;
                        break;
                    }
                    _ => {}
                },
                cmd = rx.recv() => match cmd {
                    Some(Cmd::Write(b)) => { let _ = channel.data(&b[..]).await; }
                    Some(Cmd::Resize(c, r)) => { let _ = channel.window_change(c as u32, r as u32, 0, 0).await; }
                    Some(Cmd::Close) | None => {
                        let _ = channel.eof().await;
                        let _ = channel.close().await;
                        let _ = out_tx.send(Output::Closed(Closed::Eof)).await;
                        break;
                    }
                },
            }
        }
    });
    Ok((tx, out_rx))
}

/// One interactive shell from [`SshSession::open_shell`].
pub struct Shell {
    tx: mpsc::Sender<Cmd>,
}

impl Shell {
    /// Send keystrokes. Errors only once this shell is gone.
    pub async fn write(&self, bytes: &[u8]) -> Result<()> {
        self.tx.send(Cmd::Write(bytes.to_vec())).await.map_err(|_| anyhow!("shell closed"))
    }

    pub async fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        self.tx.send(Cmd::Resize(cols, rows)).await.map_err(|_| anyhow!("shell closed"))
    }

    /// Close this shell's channel only; the connection stays up. Idempotent.
    pub async fn close(&self) {
        let _ = self.tx.send(Cmd::Close).await;
    }
}

impl SshSession {
    /// A channel forwarded to `host:port` *as seen from the remote end*.
    ///
    /// This is what `ssh -L` is underneath. The originator fields are
    /// advertisory — sshd logs them and some policies filter on them — so
    /// they say loopback and a port of zero rather than inventing a plausible
    /// client address.
    pub(crate) async fn open_forward(
        &self,
        host: &str,
        port: u32,
    ) -> Result<russh::Channel<client::Msg>> {
        let handle = self.handle.lock().await;
        Ok(handle
            .channel_open_direct_tcpip(host, port, "127.0.0.1", 0)
            .await?)
    }

    /// A fresh channel on this connection, for exec and SFTP.
    ///
    /// The handle itself stays private — a caller holding it could open
    /// channels this session knows nothing about, and the point of the type
    /// is that one task owns the shell. This hands out the channel and keeps
    /// the connection, so the sanctioned second channels
    /// ([`exec`](crate::exec) and SFTP) need no more than they use.
    pub(crate) async fn open_channel(&self) -> Result<russh::Channel<client::Msg>> {
        let handle = self.handle.lock().await;
        Ok(handle.channel_open_session().await?)
    }

    /// Has the connection gone — the peer hung up, keepalive gave up, or
    /// `close()` ran? A caller can check this before an operation to say
    /// "the connection is closed, reconnect" instead of surfacing whatever
    /// raw error opening a channel on a dead connection produces.
    pub async fn is_closed(&self) -> bool {
        self.handle.lock().await.is_closed()
    }

    /// The host key this connection was made with: (`ssh-ed25519`, `SHA256:…`).
    /// Known hosts aren't put through the policy, so this is the only place a
    /// caller can learn which key it is talking to after a silent connect.
    pub fn server_key(&self) -> Option<(&str, &str)> {
        self.server_key.as_ref().map(|(t, f)| (t.as_str(), f.as_str()))
    }

    fn shell_tx(&self) -> Result<&mpsc::Sender<Cmd>> {
        self.tx.as_ref().ok_or_else(|| anyhow!("this session has no shell (connected with connect_exec); use open_shell"))
    }

    /// Send keystrokes. Errors only once the session is gone.
    pub async fn write(&self, bytes: &[u8]) -> Result<()> {
        self.shell_tx()?
            .send(Cmd::Write(bytes.to_vec()))
            .await
            .map_err(|_| anyhow!("session closed"))
    }

    pub async fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        self.shell_tx()?
            .send(Cmd::Resize(cols, rows))
            .await
            .map_err(|_| anyhow!("session closed"))
    }

    /// Close the shell and disconnect. Idempotent: closing a session that has
    /// already gone is success, because the caller wanted it gone.
    pub async fn close(&self) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(Cmd::Close).await;
        }
        let handle = self.handle.lock().await;
        let _ = handle
            .disconnect(Disconnect::ByApplication, "", "English")
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_rejected_is_typed_and_reads_as_before() {
        let e: anyhow::Error = SshError::AuthRejected { user: "jsmith".into(), host: "h".into() }.into();
        assert_eq!(e.to_string(), "authentication rejected for jsmith@h");
        assert!(matches!(e.downcast_ref::<SshError>(), Some(SshError::AuthRejected { .. })));
    }
}
