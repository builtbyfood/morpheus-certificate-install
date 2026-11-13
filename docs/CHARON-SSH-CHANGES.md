# charon-ssh changes — morpheus-certificate-install 0.4.0

> **This repository carries its own copy of `charon-ssh`** in `crates/charon-ssh` (decision D1 = A, 0.3.21). It is charon-ssh 0.1.0 (`e9f97f5`) plus the patches 0001–0009 below, and was copied from Travis's local publish repo (the same code as the rev `e7f7fd1` the workspace used to pin, with one test's user name made generic).
>
> **This copy and Charon's must be kept in sync by hand.** Nothing does it automatically:
> - a change made here is listed below and saved as the next numbered patch in [`docs/charon-ssh-patches/`](charon-ssh-patches/) (0010 next), for Travis to apply to Charon's crate;
> - a change made in Charon is copied into `crates/charon-ssh` and listed below the same way.

This file records each change to `charon-ssh`, so Travis can carry it to the Charon repo.

**History (0.3.7–0.3.20):** the workspace depended on `charon-ssh` at rev `e7f7fd1e060d774b678bd1ca9e5c1d2d6ed9cb40` in Travis's local publish repo, which is `e9f97f5` + patches 0001–0009 below; from 0.3.17 through the future public URL with a gitignored source replacement. Both are gone since 0.3.21.

**Where the crate was developed:** `…\Documents\charon\charon-skeleton\charon\crates\charon-ssh`. It is its own git repository nested inside the Charon checkout: Charon's `.gitignore` has `crates/`, so nothing under it is in builtbyfood/charon. Its only commit is `e9f97f5` ("charon-ssh 0.1.0", 2026-10-14), with no remote. All changes below are uncommitted on top of it.

## Changes made (R5, 2026-11-06) — commit them in this order

Each change is also a ready patch in [`docs/charon-ssh-patches/`](charon-ssh-patches/), made with `git format-patch` against `e9f97f5`.

- **Apply:** from the crate's directory, `git am <mci>/docs/charon-ssh-patches/*.patch` (with `core.autocrlf=true`, as on this machine). It gives one commit per row.
- **Already checked:** applied in order to a fresh clone of `e9f97f5`, they reproduce the dev tree exactly (10 files, line endings aside).
- **Gate after each change:** `cargo test` for the crate, then `cargo check` for hvm-desk `--features appliance-ops`, hvm-desk's `tests/click/sshd`, and this app.
  - Every gate passed.
  - The Charon app was checked too; it doesn't depend on the crate.

| # | Patch | Change | Behaviour for Charon / hvm-desk |
|---|---|---|---|
| 1 | `0001-Upgrade-russh-…` | **russh 0.45 → 0.65.1** (RUSTSEC-2026-0153, -0154; see below).<br>• `russh-keys` is folded into `russh::keys`.<br>• Crypto backend `ring` instead of the default `aws-lc-rs`, which needs NASM on Windows. Features: `ring`, `rsa`, `flate2`.<br>• Host keys are `ssh_key::PublicKey`. `fingerprint()` still returns `SHA256:…`; new `key_type()`.<br>• Host *certificates* are checked by their inner key against known_hosts.<br>• RSA key auth uses the server's best `rsa-sha2` hash.<br>• `russh-sftp` stays on 2.x (it doesn't depend on russh). | Same public API apart from the `PublicKey` type in `HostKeys::check/learn` and `fingerprint`, which neither app uses. |
| 2 | `0002-Add-SshSession-is_closed` | `SshSession::is_closed()`. | Additive. |
| 3 | `0003-Typed-authentication-rejection-…` | `SshError::AuthRejected { user, host }` instead of a bare `anyhow!` string. Display text unchanged: "authentication rejected for user@host". | Additive variant; neither app matches on `SshError`. |
| 4 | `0004-HostKeys-with_label` | `HostKeys::with_label(…)` names the header of a new known_hosts file (`with_paths` hard-coded "charon-ssh"). | Additive builder. |
| 5 | `0005-exec_stdin-cmd-None-sends-end-of-input` | **The stdin fix:** `exec_stdin(cmd, None)`, and so `exec()`, now sends end-of-input, like `ssh host cmd </dev/null` and paramiko's `shutdown_write`. | **The one change to existing behaviour.** A command that reads stdin used to wait until the channel was torn down; it now gets EOF. Nothing could write to that stdin later, so nothing relied on it being open. hvm-desk's `stream_as_root` passes `None` only for follow commands, which don't read stdin. |
| 6 | `0006-Add-SshSession-exec_cancellable-…` | `exec_cancellable(cmd, stdin) -> (ExecHandle, Receiver)`. `ExecHandle::close()`, or dropping the receiver, closes the channel at once, even while the command is silent. The stream then ends with `ExecOut::Eof`. | Additive. `exec_stdin` and friends share the pump but keep their exact old behaviour. |
| 7 | `0007-Add-SshSession-connect_exec-open_shell-and-Shell` | `connect_exec()` authenticates without a shell. `open_shell(cols, rows) -> (Shell, Receiver)` opens a PTY on demand. `Shell::write/resize/close` act on that channel only, so the connection stays up and a shell can be reopened. | `connect()` is rebuilt from the same parts and behaves exactly as before. `write`/`resize` on a `connect_exec` session say it has no shell. |
| 8 | `0008-Add-Auth-Agent-and-Auth-Auto` | `Auth::Agent`: the running agent's identities. That's `SSH_AUTH_SOCK` on Unix; on Windows the OpenSSH agent pipe `\\.\pipe\openssh-ssh-agent`, then Pageant. `Auth::Auto`: agent, then `~/.ssh/id_ed25519`, `id_ecdsa`, `id_rsa`, skipping keys that need a passphrase (paramiko's `allow_agent` + `look_for_keys`). | Additive variants; neither app matches on `Auth`. **The Unix branch is not compiled on Windows** (no Linux C toolchain here for `ring`), so a first Linux build should be watched. |
| 9 | `0009-Add-SshSession-server_key` | `SshSession::server_key()` returns the presented host key's type and fingerprint. A known key is accepted without the policy being asked, so before this a caller couldn't learn which key it connected with. | Additive. |

**Side effects in hvm-desk's repo** (not committed): running the gate rewrote `src-tauri/Cargo.lock` and `tests/click/sshd/Cargo.lock`, because both build the path-dependent crate. Any build after these changes does the same.

## RUSTSEC-2026-0154 and RUSTSEC-2026-0153 — who is affected

Both share CVE-2026-46673 / GHSA-g9f8-wqj9-fjw5: denial of service, CVSS 7.5, no confidentiality or integrity impact. **Both are fixed in russh 0.60.3.** charon-ssh now uses 0.65.1.

- **RUSTSEC-2026-0153 (`russh-cryptovec`): clients and servers.**
  - In russh before 0.58, remote SSH traffic grew a `CryptoVec` through two paths: transport packet reads and zlib decompression output. A malicious peer (for a client, the *server*) can make it allocate without bound and, under memory pressure, abort the process.
  - charon-ssh on 0.45 was exposed as a client, and so is anything else on 0.45.
- **RUSTSEC-2026-0154 (`russh`): agent client and agent server.**
  - Agent frame lengths were trusted before allocation. That's reachable only by talking to an SSH agent, or by serving one (agent forwarding).
  - charon-ssh couldn't talk to an agent before change 8. With change 8 it can, and 0.65 has the 256 KiB frame cap.

**What this means outside this project:**

- **The Charon app uses russh 0.45 directly** (`src-tauri/Cargo.toml`: `russh = "0.45"`, `russh-keys = "0.45"`). It doesn't use this crate. It is an SSH *client* and is affected by RUSTSEC-2026-0153: a hostile or compromised server can crash it. It needs the same upgrade in Charon's repo, separately from these patches.
- **hvm-desk's click-test server** (`tests/click/sshd`) also pins `russh = "0.45"` directly. It's a local test fixture, so the exposure is small, but `cargo audit` on hvm-desk will keep flagging it until it moves too.

## R0.1 — gap list (2026-11-05), with R5 status

| Need | R0 status | R5 |
|---|---|---|
| Connect: password; key file + passphrase | present | unchanged |
| Connect: agent / default keys | missing | **added** (change 8) |
| Connect: timeout | caller | the transport wraps `connect_exec` in a 45 s timeout |
| Connect: auth failure vs network failure | needs change | **typed** (change 3) |
| Host-key prompt: type + SHA256 fingerprint | present | unchanged; the fingerprint is now computed by `ssh-key` with the same `SHA256:` + unpadded base64 output (unit-tested) |
| Changed host key never auto-trusted | present | unchanged |
| TOFU store at our path | present (`with_paths`) | plus `with_label` (change 4) |
| Exec: stdin, then EOF | present, with a trap | **trap removed** (change 5) |
| Exec: stdout / stderr | present | Correction to R0: they are **separate** (`ExecOut::Stdout` / `Stderr`), not merged. The transport merges them in arrival order, as paramiko's `set_combine_stderr` did. |
| Exec: exit status (signals as 128 + n) | present | unchanged |
| Exec: incremental output | present | unchanged |
| Exec: cancellation | missing | **added** (change 6) |
| PTY on demand, reopenable, close ≠ disconnect | needs change | **added** (change 7) |
| Keepalive | present | unchanged |
| Clear error when the connection drops | missing | **added** (change 2) |
| Which host key this connection used | (not in R0) | **added** (change 9) |

Not needed from the crate, as before: SFTP (the transport writes through `cat` on stdin), port forwarding, `forget`.
