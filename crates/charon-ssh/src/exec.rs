//! Running one command on its own channel, and SFTP over the same connection.
//!
//! Both open a fresh channel on the handle an [`SshSession`] already holds,
//! rather than opening a second connection. One authentication, one host-key
//! check, one thing to close — and, more to the point, a second connection
//! would need the password again, which for an interactive session the user
//! typed once is not something the application still has.
//!
//! ## Why exec is not the shell channel
//!
//! The shell is a PTY: it echoes, it merges stderr into stdout, and it hands
//! back whatever the prompt happens to print alongside the answer. Scraping a
//! command's output off it means guessing where the echo ends and the output
//! begins, and there is no exit status at all. An exec channel gives the
//! output and the status, separately and unambiguously, which is what
//! anything deciding "did that work" needs.
//!
//! ## Why stdout and stderr stay apart
//!
//! Progress meters go to stderr. `curl` writes its transfer table there while
//! the payload — or, with `-o`, the file — is elsewhere entirely, and a
//! caller wanting to show progress needs the one without the other. The PTY
//! session merges them because a terminal should; this must not.

use crate::client::SshSession;
use anyhow::{Context, Result};
use russh::ChannelMsg;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::{mpsc, Notify};

/// One piece of a running command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecOut {
    Stdout(Vec<u8>),
    /// Where progress meters live.
    Stderr(Vec<u8>),
    /// The command finished with this status. Always the last item when the
    /// remote sent one.
    Exit(u32),
    /// The channel closed without a status.
    Eof,
}

/// A command that ran to completion.
#[derive(Debug, Clone)]
pub struct Exited {
    /// `None` when the channel closed without one — a killed process, say.
    pub code: Option<u32>,
    pub stdout: String,
    pub stderr: String,
}

impl Exited {
    pub fn ok(&self) -> bool {
        match self.code {
            Some(c) => c == 0,
            // ⚠ No status, but it said something and complained about
            // nothing: that is a command that worked on a server which
            // did not send `exit-status`, not a failure. Treating it as
            // one reported `printf $HOME` as broken while holding
            // `/home/admin` in `stdout`.
            //
            // Output on stderr is the other way round — something went
            // wrong and nobody said how — so that stays a failure.
            None => !self.stdout.trim().is_empty() && self.stderr.trim().is_empty(),
        }
    }

    /// Did the far end actually say how the command ended?
    ///
    /// Distinct from `ok()`: a command can be believed without this, but
    /// only a command with nothing else to go on should be *reported*
    /// as having no status.
    pub fn had_status(&self) -> bool {
        self.code.is_some()
    }

    /// The output, or an error naming the command, the status and stderr.
    ///
    /// The status alone is never enough to act on: "exit 1" tells a user
    /// nothing, and the reason is almost always the first line of stderr.
    pub fn require(&self, what: &str) -> Result<&str> {
        if self.ok() {
            return Ok(self.stdout.trim_end());
        }
        let why = if self.stderr.trim().is_empty() {
            self.stdout.trim()
        } else {
            self.stderr.trim()
        };
        // "no exit status" is only worth saying when it is the whole
        // story. `ok()` already lets through a command that said
        // something and complained about nothing, so reaching here with
        // no status means there was no output either — and *that* is
        // the thing to report, rather than a bare "exit ?".
        let ending = match self.code {
            Some(c) => format!("exit {c}"),
            // Two different silences. Nothing at all is worth naming as
            // such; a missing status *with* a complaint on stderr is a
            // failure the complaint already explains, and claiming
            // "no output" beside the output would be a plain lie.
            None if why.is_empty() => "no exit status, and no output".into(),
            None => "no exit status".into(),
        };
        Err(anyhow::anyhow!(
            "{what} failed on the remote host ({ending}){}{}",
            if why.is_empty() { "" } else { ": " },
            why.chars().take(400).collect::<String>()
        ))
    }
}

/// The number behind an SSH exit-signal name.
///
/// RFC 4254 sends a name, not a number; a caller wanting a shell's
/// `128 + n` needs the translation. Anything unrecognised is 0, which
/// makes the status 128 — "killed by something" — rather than a
/// confident wrong number.
fn signal_number(sig: &russh::Sig) -> u32 {
    use russh::Sig;
    match sig {
        Sig::HUP => 1,
        Sig::INT => 2,
        Sig::QUIT => 3,
        Sig::ILL => 4,
        Sig::ABRT => 6,
        Sig::FPE => 8,
        Sig::KILL => 9,
        Sig::SEGV => 11,
        Sig::PIPE => 13,
        Sig::ALRM => 14,
        Sig::TERM => 15,
        Sig::USR1 => 10,
        Sig::Custom(_) => 0,
    }
}

impl SshSession {
    /// Run a command, streaming its output as it arrives.
    ///
    /// The receiver must be drained; it is bounded, and a caller that stops
    /// reading stalls the command rather than buffering without limit.
    pub async fn exec(&self, command: &str) -> Result<mpsc::Receiver<ExecOut>> {
        self.exec_stdin(command, None).await
    }

    /// Run a command, writing `stdin` to it and closing the stream.
    ///
    /// The reason this exists is `sudo -S`, which reads a password from
    /// standard input rather than from a terminal — an exec channel has
    /// no terminal, and `sudo` without one refuses with "a terminal is
    /// required". A password cannot go on the command line: that is the
    /// process table, and on many systems anyone can read it.
    ///
    /// **The bytes are never logged.** `with_context` on the exec below
    /// carries the command, which is why the secret goes here and not
    /// there. EOF is sent as soon as the write completes, so nothing is
    /// left holding a channel open waiting for input that will not come.
    ///
    /// With `None`, EOF is sent straight away: the command's stdin is empty
    /// rather than open forever. (Before this, `None` sent nothing, so a
    /// command that read stdin — `cat`, `sudo -S` with no password, a
    /// `read` in a script — waited until the channel was torn down. Nothing
    /// can write to the stdin of an exec started here later, so leaving it
    /// open never helped.) `ssh host cmd </dev/null` is the shell equivalent.
    pub async fn exec_stdin(
        &self,
        command: &str,
        stdin: Option<&[u8]>,
    ) -> Result<mpsc::Receiver<ExecOut>> {
        self.start_exec(command, stdin, None).await
    }

    /// `exec_stdin`, plus a way to stop it.
    ///
    /// [`ExecHandle::close`] — or dropping the receiver — closes the channel
    /// straight away, even while the command is silent; sshd then hangs up
    /// the remote process. That is what a "Stop" button or a timeout needs:
    /// with `exec_stdin` a dropped receiver is only noticed at the command's
    /// next output, so `tail -F` on a quiet file, or anything past its
    /// deadline, keeps the channel and the process alive. After a close the
    /// stream ends with [`ExecOut::Eof`].
    pub async fn exec_cancellable(
        &self,
        command: &str,
        stdin: Option<&[u8]>,
    ) -> Result<(ExecHandle, mpsc::Receiver<ExecOut>)> {
        let cancel = Arc::new(Notify::new());
        let rx = self.start_exec(command, stdin, Some(cancel.clone())).await?;
        Ok((ExecHandle { cancel }, rx))
    }

    async fn start_exec(
        &self,
        command: &str,
        stdin: Option<&[u8]>,
        cancel: Option<Arc<Notify>>,
    ) -> Result<mpsc::Receiver<ExecOut>> {
        let mut channel = self.open_channel().await?;
        channel
            .exec(true, command.as_bytes())
            .await
            .with_context(|| format!("exec {command:?}"))?;
        if let Some(bytes) = stdin {
            // No context string here, and none below: it would be the
            // one place a password could reach a log.
            channel.data(bytes).await.context("writing to the command's stdin")?;
        }
        channel.eof().await.context("closing the command's stdin")?;

        let (tx, rx) = mpsc::channel::<ExecOut>(256);
        tokio::spawn(async move {
            let mut status = None;
            loop {
                // Without a cancel handle this is exactly the old loop: wait
                // for the next message. With one, a close() or a dropped
                // receiver also wakes it, and the channel is closed at once.
                enum Ev { Msg(Option<ChannelMsg>), Stop }
                let ev = match &cancel {
                    None => Ev::Msg(channel.wait().await),
                    Some(stop) => tokio::select! {
                        m = channel.wait() => Ev::Msg(m),
                        _ = stop.notified() => Ev::Stop,
                        _ = tx.closed() => Ev::Stop,
                    },
                };
                let msg = match ev {
                    Ev::Msg(m) => m,
                    Ev::Stop => {
                        let _ = channel.close().await;
                        let _ = tx.send(ExecOut::Eof).await;
                        break;
                    }
                };
                match msg {
                    Some(ChannelMsg::Data { data }) => {
                        if tx.send(ExecOut::Stdout(data.to_vec())).await.is_err() {
                            break;
                        }
                    }
                    // ext_code 1 is stderr; anything else is vendor noise and
                    // is treated the same, because dropping it loses the only
                    // explanation some servers give.
                    Some(ChannelMsg::ExtendedData { data, .. }) => {
                        if tx.send(ExecOut::Stderr(data.to_vec())).await.is_err() {
                            break;
                        }
                    }
                    Some(ChannelMsg::ExitStatus { exit_status }) => status = Some(exit_status),
                    // A signal is how the far end says "killed", and it
                    // arrives instead of a status, not alongside one.
                    // Reported as 128 + n, which is what a shell would
                    // have reported.
                    Some(ChannelMsg::ExitSignal { ref signal_name, .. }) => {
                        status = Some(128 + signal_number(signal_name));
                    }
                    // ⚠ **Eof does not end this loop.** The exit status is
                    // its own channel request and it very often arrives
                    // *after* the far end has closed stdout — returning
                    // here left the status unknown, and a caller that
                    // treated unknown as failure reported a command that
                    // had worked, with its output sitting right there.
                    // `printf $HOME` did exactly that.
                    //
                    // Close, or the channel ending, is what finishes it:
                    // after either there is nothing more coming.
                    Some(ChannelMsg::Eof) => {}
                    Some(ChannelMsg::Close) | None => {
                        let _ = tx
                            .send(match status {
                                Some(c) => ExecOut::Exit(c),
                                None => ExecOut::Eof,
                            })
                            .await;
                        break;
                    }
                    _ => {}
                }
            }
        });
        Ok(rx)
    }

    /// Run a command and collect everything it said.
    ///
    /// `on_stderr` is called with each chunk as it arrives, so a caller can
    /// show a progress meter without giving up the convenience of getting the
    /// whole result back at the end.
    pub async fn exec_collect(
        &self,
        command: &str,
        on_stderr: impl FnMut(&[u8]) + Send,
    ) -> Result<Exited> {
        self.exec_collect_stdin(command, None, on_stderr).await
    }

    /// `exec_collect`, with something written to the command's stdin.
    ///
    /// See `exec_stdin`: this is how a password reaches `sudo -S` without
    /// going near a command line, a log line or an error message.
    pub async fn exec_collect_stdin(
        &self,
        command: &str,
        stdin: Option<&[u8]>,
        mut on_stderr: impl FnMut(&[u8]) + Send,
    ) -> Result<Exited> {
        let mut rx = self.exec_stdin(command, stdin).await?;
        let (mut out, mut err, mut code) = (Vec::new(), Vec::new(), None);
        while let Some(item) = rx.recv().await {
            match item {
                ExecOut::Stdout(b) => out.extend_from_slice(&b),
                ExecOut::Stderr(b) => {
                    on_stderr(&b);
                    err.extend_from_slice(&b);
                }
                ExecOut::Exit(c) => code = Some(c),
                ExecOut::Eof => {}
            }
        }
        Ok(Exited {
            code,
            stdout: String::from_utf8_lossy(&out).into_owned(),
            stderr: String::from_utf8_lossy(&err).into_owned(),
        })
    }

    /// Open a forwarded connection to `host:port` on the far side.
    ///
    /// The returned stream reads and writes the remote socket, so a caller
    /// can put anything it likes on top — a VNC display, a database port,
    /// an HTTP service bound to the remote loopback. This is `ssh -L`
    /// without a second SSH stack: the alternative is shelling out to the
    /// system `ssh`, which means a second set of host keys, a second idea
    /// of which credentials to use, and a child process to supervise.
    ///
    /// `host` is resolved by the *remote* end. `127.0.0.1` therefore means
    /// the remote machine's loopback, which is exactly what a hypervisor
    /// binds a guest's VNC display to.
    pub async fn forward(
        &self,
        host: &str,
        port: u16,
    ) -> Result<russh::ChannelStream<russh::client::Msg>> {
        let channel = self
            .open_forward(host, port as u32)
            .await
            .with_context(|| format!("forward to {host}:{port} through the remote host"))?;
        Ok(channel.into_stream())
    }

    /// Open an SFTP session on this connection.
    pub async fn sftp(&self) -> Result<Sftp> {
        let channel = self.open_channel().await?;
        channel
            .request_subsystem(true, "sftp")
            .await
            .context("the remote host refused the sftp subsystem")?;
        let inner = russh_sftp::client::SftpSession::new(channel.into_stream())
            .await
            .context("sftp handshake")?;
        Ok(Sftp { inner })
    }
}

/// Stops a command started with [`SshSession::exec_cancellable`].
///
/// Dropping the handle does *not* stop the command (drop the receiver for
/// that); it only gives up the ability to.
#[derive(Clone)]
pub struct ExecHandle {
    cancel: Arc<Notify>,
}

impl ExecHandle {
    /// Close the command's channel now. Idempotent, and harmless after the
    /// command has finished.
    pub fn close(&self) {
        self.cancel.notify_one();
    }
}

// ------------------------------------------------------------------- sftp

/// One entry in a remote directory.
#[derive(Debug, Clone)]
pub struct RemoteFile {
    pub name: String,
    pub size: u64,
    /// Seconds since the epoch, when the server reported one.
    pub modified: Option<u64>,
    pub is_dir: bool,
}

/// SFTP over an existing SSH connection.
pub struct Sftp {
    inner: russh_sftp::client::SftpSession,
}

/// Transfers are chunked, and progress is reported per chunk.
///
/// 32 KiB rather than something larger: each chunk is a round trip, and a
/// progress callback that only fires twice on a 1 GB file is not progress.
const CHUNK: usize = 32 * 1024;

impl Sftp {
    /// Upload, reporting `(sent, total)` as it goes.
    ///
    /// Returns the number of bytes written, which the caller should check
    /// against the local size: an upload that stops early and reports success
    /// is the failure worth catching here.
    pub async fn put(
        &self,
        local: &Path,
        remote: &str,
        mut progress: impl FnMut(u64, u64) + Send,
    ) -> Result<u64> {
        let mut src = tokio::fs::File::open(local)
            .await
            .with_context(|| format!("open {}", local.display()))?;
        let total = src.metadata().await.map(|m| m.len()).unwrap_or(0);
        let mut dst = self
            .inner
            .create(remote)
            .await
            .with_context(|| format!("create {remote} on the remote host"))?;

        let mut buf = vec![0u8; CHUNK];
        let mut sent = 0u64;
        loop {
            let n = src.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            dst.write_all(&buf[..n]).await?;
            sent += n as u64;
            progress(sent, total);
        }
        // Flushed and closed explicitly: dropping the handle leaves the last
        // chunk in flight, and the size check that follows would then race it.
        dst.flush().await?;
        dst.shutdown().await?;
        Ok(sent)
    }

    /// Download, reporting `(received, total)`.
    ///
    /// `resume_from` skips that many bytes and appends, for a transfer that
    /// was interrupted. Zero starts over.
    pub async fn get(
        &self,
        remote: &str,
        local: &Path,
        resume_from: u64,
        mut progress: impl FnMut(u64, u64) + Send,
    ) -> Result<u64> {
        let total = self.size(remote).await?.unwrap_or(0);
        let mut src = self
            .inner
            .open(remote)
            .await
            .with_context(|| format!("open {remote} on the remote host"))?;
        let mut dst = if resume_from > 0 {
            src.seek(std::io::SeekFrom::Start(resume_from)).await?;
            tokio::fs::OpenOptions::new()
                .append(true)
                .open(local)
                .await?
        } else {
            tokio::fs::File::create(local).await?
        };

        let mut buf = vec![0u8; CHUNK];
        let mut got = resume_from;
        loop {
            let n = src.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            dst.write_all(&buf[..n]).await?;
            got += n as u64;
            progress(got, total);
        }
        dst.flush().await?;
        Ok(got)
    }

    pub async fn list(&self, dir: &str) -> Result<Vec<RemoteFile>> {
        let entries = self
            .inner
            .read_dir(dir)
            .await
            .with_context(|| format!("list {dir} on the remote host"))?;
        Ok(entries
            .map(|e| {
                let meta = e.metadata();
                RemoteFile {
                    name: e.file_name(),
                    size: meta.size.unwrap_or(0),
                    modified: meta.mtime.map(u64::from),
                    is_dir: meta.is_dir(),
                }
            })
            .filter(|f| f.name != "." && f.name != "..")
            .collect())
    }

    /// The size of one file, or `None` when it is not there.
    ///
    /// Not-there is deliberately not an error: "is it already staged" is a
    /// question, and the answer "no" is not a failure.
    pub async fn size(&self, path: &str) -> Result<Option<u64>> {
        match self.inner.metadata(path).await {
            Ok(m) => Ok(Some(m.size.unwrap_or(0))),
            Err(_) => Ok(None),
        }
    }

    /// Remove a file. Removing one that is already gone is success.
    pub async fn remove(&self, path: &str) -> Result<()> {
        match self.inner.remove_file(path).await {
            Ok(()) => Ok(()),
            Err(_) if self.size(path).await?.is_none() => Ok(()),
            Err(e) => Err(anyhow::anyhow!("could not remove {path}: {e}")),
        }
    }

    /// `mkdir -p`. Each component in turn, because SFTP has no recursive form
    /// and an existing component is not an error.
    pub async fn mkdir_p(&self, dir: &str) -> Result<()> {
        let mut path = String::new();
        for part in dir.split('/').filter(|p| !p.is_empty()) {
            path.push('/');
            path.push_str(part);
            let _ = self.inner.create_dir(&path).await;
        }
        match self.inner.metadata(dir).await {
            Ok(m) if m.is_dir() => Ok(()),
            Ok(_) => Err(anyhow::anyhow!("{dir} exists and is not a directory")),
            Err(e) => Err(anyhow::anyhow!("could not create {dir}: {e}")),
        }
    }

    pub async fn close(self) {
        let _ = self.inner.close().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exited(code: Option<u32>, out: &str, err: &str) -> Exited {
        Exited { code, stdout: out.into(), stderr: err.into() }
    }

    #[test]
    fn a_command_that_answered_is_not_a_failure_for_want_of_a_status() {
        // The live defect. `printf $HOME` returned `/home/admin` and the
        // exit status arrived after EOF, so it was never seen — and a
        // caller treating unknown as failure reported a command that had
        // plainly worked, with its answer sitting in stdout.
        let e = exited(None, "/home/admin\n", "");
        assert!(e.ok());
        assert_eq!(e.require("asking for the home directory").unwrap(), "/home/admin");
        assert!(!e.had_status(), "believed, but we still know we were not told");
    }

    #[test]
    fn silence_with_no_status_is_still_a_failure_and_says_which() {
        // Nothing to go on at all: no status and nothing said. This is
        // the only case that should mention the missing status.
        let e = exited(None, "", "");
        assert!(!e.ok());
        let msg = e.require("asking for the home directory").unwrap_err().to_string();
        assert!(msg.contains("no exit status, and no output"), "{msg}");

        // ...but a missing status alongside a complaint must not claim
        // there was no output, with the output quoted right after it.
        let noisy = exited(None, "", "curl: (28) timed out
");
        let msg = noisy.require("the download").unwrap_err().to_string();
        assert!(msg.contains("no exit status"), "{msg}");
        assert!(!msg.contains("no output"), "the stderr is right there: {msg}");
        assert!(msg.contains("timed out"), "{msg}");
    }

    #[test]
    fn a_complaint_with_no_status_is_a_failure() {
        // Something went wrong and nobody said how. Believing this
        // because a status was missing would be the opposite mistake.
        let e = exited(None, "", "mkdir: Permission denied\n");
        assert!(!e.ok());
        let msg = e.require("creating the directory").unwrap_err().to_string();
        assert!(msg.contains("Permission denied"), "{msg}");

        // Output *and* a complaint: still a failure, and the complaint
        // is what gets shown.
        let both = exited(None, "partial\n", "warning: truncated\n");
        assert!(!both.ok());
        assert!(both.require("x").unwrap_err().to_string().contains("truncated"));
    }

    #[test]
    fn a_real_status_always_wins_over_the_guess() {
        assert!(exited(Some(0), "", "").ok(), "zero is success even in silence");
        assert!(!exited(Some(1), "lots of output\n", "").ok(), "one is failure even so");
        let msg = exited(Some(2), "", "nope\n").require("x").unwrap_err().to_string();
        assert!(msg.contains("exit 2"), "{msg}");
        assert!(!msg.contains("no exit status"), "{msg}");
    }

    #[test]
    fn a_signal_reads_as_a_shell_would_report_it() {
        assert_eq!(signal_number(&russh::Sig::TERM), 15);
        assert_eq!(signal_number(&russh::Sig::KILL), 9);
        // Unknown names give 128 rather than a confident wrong number.
        assert_eq!(signal_number(&russh::Sig::Custom("WHAT".into())), 0);
    }
}
