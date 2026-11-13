//! morpheus-certificate-install 0.4.0 — every shell string sent to the appliance.
//!
//! The transports (src-tauri) only wrap these for sudo and send them; nothing else builds
//! shell text. All of it is byte-identical to the Python reference — see tests/golden_text.rs.
//!
//! HPE procedures followed (docs: "SSL Certificates", "Import Trusted Certificates"):
//!   server cert → /etc/morpheus/ssl/<fqdn>.crt|.key, root-only; morpheus.rb nginx['ssl_certificate'|'ssl_server_key'];
//!                 morpheus-ctl reconfigure; morpheus-ctl restart nginx
//!   trust a CA  → /etc/morpheus/ssl/trusted_certs/*.pem; reconfigure; keytool -import into embedded cacerts
//!                 (storepass changeit); restart morpheus-ui (added by this tool so the JVM reloads it)

use crate::quote::q;
use crate::{PRODUCT, SLUG};

pub const SSL_DIR: &str = "/etc/morpheus/ssl";
pub const TRUST_DIR: &str = "/etc/morpheus/ssl/trusted_certs";
pub const MORPHEUS_RB: &str = "/etc/morpheus/morpheus.rb";
pub const STATE_DIR: &str = "/var/lib/morpheus-certificate-install";
pub const BACKUP_DIR: &str = "/var/lib/morpheus-certificate-install/backups";
pub const RUN_DIR: &str = "/var/lib/morpheus-certificate-install/runs";
pub const LOG_DIR: &str = "/var/log/morpheus-certificate-install";
/// Suffix for atomic writes (`<path>.mci-tmp` then `mv -f`).
pub const TMP_SUFFIX: &str = ".mci-tmp";
/// Charon transport staging dir, under the login user's $HOME (created 0700).
pub const CHARON_STAGE: &str = ".morpheus-certificate-install-stage";

/// Facts gathered as KEY=VALUE lines (run with sudo). Keys are lowercased by the caller.
pub const PREFLIGHT_SCRIPT: &str = r#"
echo "HOST=$(hostname -f 2>/dev/null || hostname)"
echo "OS=$(. /etc/os-release 2>/dev/null; echo "$PRETTY_NAME")"
MC=$(command -v morpheus-ctl || ls /opt/morpheus/bin/morpheus-ctl /usr/bin/morpheus-ctl 2>/dev/null | head -1)
echo "MCTL=$MC"
echo "RB=$( [ -f /etc/morpheus/morpheus.rb ] && echo yes || echo no )"
echo "SSLDIR=$( [ -d /etc/morpheus/ssl ] && echo yes || echo no )"
echo "SYSTEMDRUN=$(command -v systemd-run >/dev/null 2>&1 && [ -d /run/systemd/system ] && echo yes || echo no)"
echo "OPENSSL=$(command -v openssl >/dev/null && openssl version | cut -d' ' -f1-2)"
echo "VER=$(dpkg-query -W -f='${Version}' morpheus-appliance 2>/dev/null || rpm -q --qf '%{VERSION}-%{RELEASE}' morpheus-appliance 2>/dev/null)"
KT=$(ls /opt/morpheus/embedded/java/bin/keytool /opt/morpheus/embedded/java/jre/bin/keytool 2>/dev/null | head -1)
[ -n "$KT" ] || KT=$(find /opt/morpheus/embedded -maxdepth 6 -type f -name keytool 2>/dev/null | head -1)
echo "KEYTOOL=$KT"
CA=$(find /opt/morpheus/embedded -maxdepth 8 -type f -name cacerts -path '*security*' 2>/dev/null | head -1)
echo "CACERTS=$CA"
echo "FREE_ETC_KB=$(df -Pk /etc | awk 'NR==2{print $4}')"
echo "FREE_VAR_KB=$(df -Pk /var | awk 'NR==2{print $4}')"
"#;

pub fn cat_morpheus_rb() -> String { format!("cat {MORPHEUS_RB}") }
pub fn stat_mode_morpheus_rb() -> String { format!("stat -c %a {MORPHEUS_RB}") }

/// What nginx serves locally (no sudo). Note the double space when `sni` is empty — kept for parity.
pub fn served_chain(sni: &str) -> String {
    let sni_arg = if sni.is_empty() { String::new() } else { format!("-servername {}", q(sni)) };
    format!("echo | timeout 10 openssl s_client -connect 127.0.0.1:443 {sni_arg} -showcerts 2>/dev/null")
}

pub fn backup(bdir: &str) -> String {
    format!("set -e; umask 077; mkdir -p {b}; cp -a {SSL_DIR} {b}/ssl; cp -a {MORPHEUS_RB} {b}/morpheus.rb; \
             chmod 700 {STATE_DIR} {BACKUP_DIR} 2>/dev/null; echo done", b = q(bdir))
}

pub fn key_matches_cert(crt: &str, key: &str) -> String {
    format!("a=$(openssl x509 -noout -pubkey -in {} | sha256sum | cut -c1-64); \
             b=$(openssl pkey -pubout -in {} | sha256sum | cut -c1-64); \
             echo \"cert=$a key=$b\"; [ \"$a\" = \"$b\" ]", q(crt), q(key))
}

/// Inner command (before sudo wrapping) that writes stdin to `path` atomically, root-owned.
pub fn put_root_from_stdin(path: &str, mode: &str, dir_mode: &str) -> String {
    let tmp = format!("{path}{TMP_SUFFIX}");
    format!("set -e; umask 077; d=$(dirname {p}); [ -d \"$d\" ] || {{ mkdir -p \"$d\"; chmod {dir_mode} \"$d\"; }}; cat > {t}; \
             chown root:root {t}; chmod {mode} {t}; mv -f {t} {p}", p = q(path), t = q(&tmp))
}

/// Charon variant: the data was sftp_put to `staged` first.
pub fn put_root_from_staged(staged: &str, path: &str, mode: &str, dir_mode: &str) -> String {
    let tmp = format!("{path}{TMP_SUFFIX}");
    format!("set -e; umask 077; d=$(dirname {p}); [ -d \"$d\" ] || {{ mkdir -p \"$d\"; chmod {dir_mode} \"$d\"; }}; cat {s} > {t}; \
             chown root:root {t}; chmod {mode} {t}; mv -f {t} {p}", p = q(path), t = q(&tmp), s = q(staged))
}

pub fn charon_make_stage() -> String {
    format!("umask 077; mkdir -p \"$HOME/{CHARON_STAGE}\" && chmod 700 \"$HOME/{CHARON_STAGE}\" && cd \"$HOME/{CHARON_STAGE}\" && pwd")
}

pub fn shred(path: &str) -> String { format!("shred -u {p} 2>/dev/null || rm -f {p}", p = q(path)) }

pub fn launch_runner(run_id: &str, script_path: &str, systemd: bool) -> String {
    if systemd {
        format!("systemd-run --unit={SLUG}-{run_id} --collect -p KillMode=process --description='{PRODUCT} {run_id}' /bin/bash {}", q(script_path))
    } else {
        format!("setsid nohup /bin/bash {} >/dev/null 2>&1 < /dev/null & echo launched", q(script_path))
    }
}

pub fn run_paths(run_id: &str) -> (String, String, String) {
    (format!("{RUN_DIR}/{run_id}.sh"), format!("{LOG_DIR}/{run_id}.log"), format!("{LOG_DIR}/{run_id}.rc"))
}

/// SSH: follow the log until the rc file appears; prints `@@RC=<n>` last. Sent as `bash -c <q(script)>`.
pub fn ssh_follow(log: &str, rc: &str) -> String {
    format!("f={}; r={}; i=0; while [ ! -e \"$f\" ] && [ $i -lt 30 ]; do sleep 1; i=$((i+1)); done; \
             tail -n +1 -F \"$f\" 2>/dev/null & T=$!; \
             while [ ! -s \"$r\" ]; do sleep 1; done; sleep 2; kill $T 2>/dev/null; wait $T 2>/dev/null; \
             echo; echo \"@@RC=$(cat \"$r\")\"", q(log), q(rc))
}

/// Charon: one poll from byte offset `off` — prints SIZE=, RC=, then ≤256 KiB of new log as base64.
pub fn charon_poll(log: &str, rc: &str, off: u64) -> String {
    format!("f={}; r={}; s=$(stat -c %s \"$f\" 2>/dev/null || echo 0); echo \"SIZE=$s\"; \
             echo \"RC=$(cat \"$r\" 2>/dev/null)\"; \
             [ \"$s\" -gt {off} ] && tail -c +{} \"$f\" | head -c $(( s - {off} > 262144 ? 262144 : s - {off} )) | base64 -w0; echo",
            q(log), q(rc), off + 1)
}

/// Charon long poll (0.3.16): wait on the appliance until the log has grown past `off`, the rc
/// file has content, or `wait_s` seconds have passed, checking every half second; then run
/// [`charon_poll`] (unchanged, so its output is the same). At the exec-approve tier each command
/// is an approval in Charon, so this asks once per update instead of once every 2 s. `wait_s`
/// stays under Charon's 120 s command limit (the transport uses 90).
pub fn charon_long_poll(log: &str, rc: &str, off: u64, wait_s: u32) -> String {
    format!("f={}; r={}; end=$((SECONDS+{wait_s})); \
             while [ \"$SECONDS\" -lt \"$end\" ]; do \
             [ \"$(stat -c %s \"$f\" 2>/dev/null || echo 0)\" -gt {off} ] && break; [ -s \"$r\" ] && break; sleep 0.5; done; {}",
            q(log), q(rc), charon_poll(log, rc, off))
}

pub fn list_runs() -> String {
    format!("cd {LOG_DIR} 2>/dev/null && for f in *.log; do [ -e \"$f\" ] || continue; r=${{f%.log}}; \
             echo \"$r|$(stat -c %Y \"$f\")|$(cat \"$r.rc\" 2>/dev/null)\"; done")
}

pub fn list_backups() -> String {
    format!("cd {BACKUP_DIR} 2>/dev/null && for d in */; do d=${{d%/}}; echo \"@@B $d\"; cat \"$d/manifest.json\" 2>/dev/null; echo; done")
}

/// A backup's manifest (the reference's rollback read, verbatim).
pub fn cat_manifest(bdir: &str) -> String { format!("cat {}/manifest.json", q(bdir)) }

/// The morpheus.rb a rollback is about to restore, read first so it can be checked with
/// `morpheus_rb::guard` (new in 0.3.6; docs/PARITY.md divergence 19 — the reference restored blind).
pub fn cat_backup_morpheus_rb(bdir: &str) -> String { format!("cat {}/morpheus.rb", q(bdir)) }

/// Rollback: save current state to `pre`, restore `bdir`, remove our trusted_certs files.
pub fn rollback_restore(bdir: &str, pre: &str, backup_id: &str, aliases: &[String]) -> String {
    let mut s = format!("set -e; umask 077; mkdir -p {p}; cp -a {SSL_DIR} {p}/ssl; cp -a {MORPHEUS_RB} {p}/morpheus.rb; \
                         echo '{{\"note\": \"state before rollback to {backup_id}\"}}' > {p}/manifest.json; \
                         cp -a {b}/morpheus.rb {MORPHEUS_RB}; cp -a {b}/ssl/. {SSL_DIR}/; ", p = q(pre), b = q(bdir));
    for a in aliases {
        s.push_str(&format!("rm -f {}; ", q(&format!("{TRUST_DIR}/{a}.pem"))));
    }
    s.push_str("echo restored");
    s
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SudoMode {
    Root,
    Nopasswd,
    Password,
    /// Charon answers the sudo prompt itself (tier-gated).
    Charon,
}

/// Wrap a command for the SSH transport. Returns the exec line and whether the sudo password
/// line must be prepended to stdin. Password mode uses `-k` so sudo ALWAYS consumes that line:
/// with a cached timestamp it would otherwise flow into the command (e.g. into the key file).
pub fn ssh_wrap(cmd: &str, sudo: bool, mode: SudoMode) -> (String, bool) {
    let inner = format!("bash -c {}", q(cmd));
    if !sudo || mode == SudoMode::Root {
        return (inner, false);
    }
    match mode {
        SudoMode::Nopasswd => (format!("sudo -n {inner}"), false),
        _ => (format!("sudo -k -S -p '' {inner}"), true),
    }
}

/// Wrap for Charon's run_command: plain `sudo`, Charon answers the prompt.
pub fn charon_wrap(cmd: &str, sudo: bool) -> String {
    let inner = format!("bash -c {}", q(cmd));
    if sudo { format!("sudo {inner}") } else { inner }
}

/// Probe used to classify sudo: `id -u` (0 → Root), then this (exit 0 → Nopasswd, else Password).
pub const SUDO_PROBE: &str = "sudo -k -n true";

// ------------------------------------------------------------------ Charon data reads (0.3.11, R6)

/// A data read through Charon's `run_command`, whose output comes from a terminal: stdout and
/// stderr merged, CRLF, escape sequences, sudo's lecture and prompt, maybe the echoed command line.
/// So the command's own streams are framed, and only what's inside the frame is believed:
/// - stdout, base64 on one line, after `@@MCI-<nonce>-OUT`;
/// - stderr — sent to `<stage>/mci-err-<nonce>` (the 0700 staging dir) — base64 after `@@MCI-<nonce>-ERR`;
/// - the exit code last, as `@@MCI-<nonce>-RC=<n>`;
/// - the stderr file removed on every exit path the shell sees: normal exit, and HUP/INT/TERM (a
///   timeout's interrupt or terminate), which are turned into exits so the EXIT trap runs;
/// - SIGKILL can't be trapped, so each read first deletes `mci-err-*` files older than 10 minutes
///   from the staging dir: a file left by a killed read is gone by the next read after that.
///
/// stdout is never written to a file: it is held in a shell variable until the command has ended.
///
/// The markers are printed with `printf '@@MCI-%s-…' <nonce>`, so the marker text itself never
/// appears in the command line a terminal may echo. `sudo` is Charon's plain sudo (it answers the
/// prompt on the terminal). The command runs *first*, its base64 kept in a shell variable, and the
/// frame is printed only after it has finished: sudo writes its lecture and prompt straight to the
/// tty while the command runs, so they always land before the frame, never inside it. Decode with
/// [`parse_charon_data_read`].
pub fn charon_data_read(cmd: &str, sudo: bool, stage: &str, nonce: &str) -> String {
    let err = format!("{stage}/mci-err-{nonce}");
    let script = format!(
        // The umask is for the stderr file only (in a subshell): the command keeps the session's
        // own umask, so whatever it creates gets the modes it would without the frame.
        // Signals become exits (128+n) so the EXIT trap runs for them too.
        "find {s} -maxdepth 1 -name 'mci-err-*' -mmin +10 -delete 2>/dev/null; \
         e={e}; trap 'rm -f \"$e\"' EXIT; trap 'exit 129' HUP; trap 'exit 130' INT; trap 'exit 143' TERM; \
         (umask 077; : >\"$e\"); \
         o=$({{ {inner}; }} 2>\"$e\" </dev/null | base64 -w0; exit \"${{PIPESTATUS[0]}}\"); rc=$?; \
         printf '\\n@@MCI-%s-OUT\\n%s\\n@@MCI-%s-ERR\\n' {n} \"$o\" {n}; base64 -w0 \"$e\"; printf '\\n@@MCI-%s-RC=%s\\n' {n} \"$rc\"",
        s = q(stage),
        e = q(&err),
        n = q(nonce),
        inner = charon_wrap(cmd, sudo),
    );
    format!("bash -c {}", q(&script))
}

/// What a [`charon_data_read`] returned: the command's exact stdout and stderr bytes, and its rc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataRead {
    pub rc: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Decode a [`charon_data_read`]'s terminal output. Everything outside the frame is ignored;
/// inside it, only base64 is accepted (whitespace and CR, which a terminal adds, are dropped).
pub fn parse_charon_data_read(output: &str, nonce: &str) -> Result<DataRead, String> {
    use base64::Engine;
    let text = strip_terminal(output);
    let (out_m, err_m, rc_m) = (format!("@@MCI-{nonce}-OUT"), format!("@@MCI-{nonce}-ERR"), format!("@@MCI-{nonce}-RC="));
    let missing = |what: &str| {
        let head: String = text.trim().chars().take(200).collect();
        format!("The read through Charon came back without its {what} marker, so the command may not have run. Output began: {head:?}")
    };
    let o = text.find(&out_m).ok_or_else(|| missing("start"))? + out_m.len();
    let e = o + text[o..].find(&err_m).ok_or_else(|| missing("stderr"))?;
    let after_err = e + err_m.len();
    let r = after_err + text[after_err..].find(&rc_m).ok_or_else(|| missing("exit-code"))?;
    let decode = |seg: &str, what: &str| -> Result<Vec<u8>, String> {
        let b64: String = seg.split_whitespace().collect();
        if !b64.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=') {
            return Err(format!("The {what} read through Charon was garbled (something other than base64 inside its frame)."));
        }
        base64::engine::general_purpose::STANDARD
            .decode(b64.as_bytes())
            .map_err(|err| format!("The {what} read through Charon didn't decode ({err})."))
    };
    let stdout = decode(&text[o..e], "output")?;
    let stderr = decode(&text[after_err..r], "error output")?;
    let rc_text: String = text[r + rc_m.len()..].chars().take_while(|c| c.is_ascii_digit() || *c == '-').collect();
    let rc = rc_text.parse().map_err(|_| missing("exit-code"))?;
    Ok(DataRead { rc, stdout, stderr })
}

/// Terminal output without escape sequences (CSI `ESC [ … final`, OSC/DCS/APC/PM up to BEL or
/// `ESC \`, and two-byte `ESC x`) and without CR. For parsing Charon's output, never for display.
pub fn strip_terminal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        match c {
            '\r' => {}
            '\u{1b}' => match it.next() {
                Some('[') => {
                    // parameters and intermediates, then one final byte 0x40–0x7E
                    for d in it.by_ref() {
                        if ('\u{40}'..='\u{7e}').contains(&d) {
                            break;
                        }
                    }
                }
                Some(']') | Some('P') | Some('_') | Some('^') => {
                    while let Some(d) = it.next() {
                        if d == '\u{7}' {
                            break;
                        }
                        if d == '\u{1b}' && it.peek() == Some(&'\\') {
                            it.next();
                            break;
                        }
                    }
                }
                _ => {}
            },
            c => out.push(c),
        }
    }
    out
}

/// Charon `run` output for display: CR removed (`\r\n` → `\n`, a lone `\r` dropped).
pub fn strip_cr(s: &str) -> String {
    s.replace("\r\n", "\n").replace('\r', "")
}

// ------------------------------------------------------------------ cleanup (0.3.17)
//
// "Clean up this appliance": what the tool left, and removing it. Only ever these paths: runner
// scripts RUN_DIR/*.sh, run logs LOG_DIR/*.log|*.rc, backups BACKUP_DIR/<id>/, and the Charon
// staging dir $HOME/CHARON_STAGE (the login user's). Every removal names its paths one by one,
// validated by [`CleanupItem::check`]; nothing is removed by pattern.

/// What the tool left under its root-owned dirs (run with sudo). One line per item:
/// `script|<path>|<bytes>|<mtime>`, `log|<path>|<bytes>|<mtime>`,
/// `backup|<dir>|<bytes>|<mtime>|<number of .key files>`. Data, read with run_data.
pub fn cleanup_inventory() -> String {
    format!(r#"[ -d {RUN_DIR} ] && find {RUN_DIR} -maxdepth 1 -type f -name '*.sh' -printf 'script|%p|%s|%T@\n'; [ -d {LOG_DIR} ] && find {LOG_DIR} -maxdepth 1 -type f \( -name '*.log' -o -name '*.rc' \) -printf 'log|%p|%s|%T@\n'; [ -d {BACKUP_DIR} ] && for d in {BACKUP_DIR}/*/; do [ -d "$d" ] || continue; d=${{d%/}}; printf 'backup|%s|%s|%s|%s\n' "$d" "$(du -sb "$d" | cut -f1)" "$(stat -c %Y "$d")" "$(find "$d" -type f -name '*.key' | wc -l)"; done; true"#)
}

/// The Charon staging dir of the login user (no sudo): `stage|<dir>|<bytes>|<mtime>`, or nothing.
pub fn cleanup_stage_inventory() -> String {
    format!(r#"s="$HOME/{CHARON_STAGE}"; [ -d "$s" ] && printf 'stage|%s|%s|%s\n' "$s" "$(du -sb "$s" | cut -f1)" "$(stat -c %Y "$s")"; true"#)
}

/// One thing cleanup may remove. Names are file or directory names inside our dirs, never paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CleanupItem {
    /// RUN_DIR/<name>, a `*.sh` runner script.
    Script(String),
    /// LOG_DIR/<name>, a `*.log` or `*.rc` file.
    Log(String),
    /// BACKUP_DIR/<id>/, every file in it shredded first (backups hold previous private keys).
    Backup(String),
}

impl CleanupItem {
    /// Refuses anything that could leave our directories: a name with `/`, a leading `.`, an
    /// empty name, characters outside `[A-Za-z0-9._-]`, or the wrong extension for its kind.
    pub fn check(&self) -> Result<(), String> {
        let (name, ext): (&str, &[&str]) = match self {
            CleanupItem::Script(n) => (n, &[".sh"]),
            CleanupItem::Log(n) => (n, &[".log", ".rc"]),
            CleanupItem::Backup(n) => (n, &[]),
        };
        let ok_chars = !name.is_empty() && !name.starts_with('.') && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
        if !ok_chars || (!ext.is_empty() && !ext.iter().any(|e| name.ends_with(e) && name.len() > e.len())) {
            return Err(format!("Refusing to clean up {name:?}: not one of this tool's files. Nothing was removed."));
        }
        Ok(())
    }
    pub fn path(&self) -> String {
        match self {
            CleanupItem::Script(n) => format!("{RUN_DIR}/{n}"),
            CleanupItem::Log(n) => format!("{LOG_DIR}/{n}"),
            CleanupItem::Backup(n) => format!("{BACKUP_DIR}/{n}"),
        }
    }
}

/// Remove exactly `items` (run with sudo), printing one line per path; then remove our dirs if
/// they're empty (`rmdir` only removes empty ones). Backups: every regular file shredded
/// (`shred -u`), then the directory removed. Symlinks are never followed. Errors if any item fails
/// [`CleanupItem::check`], before anything is built.
pub fn cleanup_remove(items: &[CleanupItem]) -> Result<String, String> {
    for it in items { it.check()?; }
    let mut s = String::from("rc=0; ");
    for it in items {
        let (path, p) = (it.path(), q(&it.path()));
        s.push_str(&match it {
            CleanupItem::Backup(_) => format!(
                r#"if [ -d {p} ] && [ ! -L {p} ]; then find {p} -type f -exec sh -c 'for f; do shred -u "$f" && echo "shredded $f"; done' sh {{}} + || rc=1; rm -rf -- {p} && echo {msg} || rc=1; fi; "#,
                msg = q(&format!("removed {path}/"))),
            _ => format!(r#"if [ -f {p} ] && [ ! -L {p} ]; then rm -f -- {p} && echo {msg} || rc=1; fi; "#, msg = q(&format!("removed {path}"))),
        });
    }
    s.push_str(&format!("rmdir {RUN_DIR} {BACKUP_DIR} {LOG_DIR} 2>/dev/null; rmdir {STATE_DIR} 2>/dev/null; exit $rc"));
    Ok(s)
}

// ------------------------------------------------------------------ installed-files ledger (0.3.19)
//
// Every certificate and key file the tool installs is recorded in LEDGER (root 0600), which
// survives backup removal. Rollback removes what the rolled-back install wrote and the backup
// didn't have; cleanup may remove ledger files morpheus.rb no longer names. Nothing the ledger
// doesn't list is ever removed, and only `SSL_DIR/<name>.crt|.key` can be named.

/// Where the ledger lives.
pub const LEDGER: &str = "/var/lib/morpheus-certificate-install/installed.json";

/// The ledger's text, or nothing when there's none yet (run with sudo; a data read).
pub fn cat_ledger() -> String { format!("[ -f {LEDGER} ] && cat {LEDGER}; true") }

/// An installed file's name (`<name>.crt|.key` directly in SSL_DIR) from its path, or an error.
pub fn installed_name(path: &str) -> Result<&str, String> {
    let bad = || format!("Refusing to remove {path:?}: only certificate and key files directly in {SSL_DIR} that this tool installed can be removed. Nothing was removed.");
    let name = path.strip_prefix(SSL_DIR).and_then(|r| r.strip_prefix('/')).ok_or_else(bad)?;
    let ok = !name.is_empty() && !name.starts_with('.') && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        && (name.ends_with(".crt") || name.ends_with(".key")) && name.len() > 4;
    if ok { Ok(name) } else { Err(bad()) }
}

fn remove_one(path: &str) -> String {
    let p = q(path);
    if path.ends_with(".key") {
        format!(r#"if [ -f {p} ] && [ ! -L {p} ]; then shred -u {p} && echo {m} || rc=1; fi; "#, m = q(&format!("shredded {path}")))
    } else {
        format!(r#"if [ -f {p} ] && [ ! -L {p} ]; then rm -f -- {p} && echo {m} || rc=1; fi; "#, m = q(&format!("removed {path}")))
    }
}

/// Remove installed files (run with sudo): keys shredded, certificates removed; one line per file.
pub fn remove_installed(paths: &[String]) -> Result<String, String> {
    for p in paths { installed_name(p)?; }
    let mut s = String::from("rc=0; ");
    for p in paths { s.push_str(&remove_one(p)); }
    s.push_str("exit $rc");
    Ok(s)
}

/// After a rollback's restore: remove each of `paths` (what the rolled-back install wrote, from its
/// manifest) that the backup at `bdir` didn't have, so /etc/morpheus/ssl is exactly the backup's.
/// Keys shredded. Run with sudo.
pub fn rollback_remove_installed(bdir: &str, paths: &[String]) -> Result<String, String> {
    let mut s = String::from("rc=0; ");
    for p in paths {
        let name = installed_name(p)?;
        s.push_str(&format!("if [ ! -e {} ]; then {}fi; ", q(&format!("{bdir}/ssl/{name}")), remove_one(p)));
    }
    s.push_str("exit $rc");
    Ok(s)
}

/// `path|bytes|mtime` for each of `paths` that exists (no sudo needed for stat on /etc/morpheus/ssl
/// entries' metadata, but run with sudo for a 0700 dir). Paths are checked like [`remove_installed`].
pub fn stat_installed(paths: &[String]) -> Result<String, String> {
    for p in paths { installed_name(p)?; }
    if paths.is_empty() { return Ok("true".into()); }
    let list: Vec<String> = paths.iter().map(|p| q(p)).collect();
    Ok(format!("stat -c '%n|%s|%Y' {} 2>/dev/null; true", list.join(" ")))
}

/// Remove the login user's Charon staging dir (no sudo): its files shredded (they can be staged
/// copies of keys), then the directory. Prints what it did.
pub fn cleanup_remove_stage() -> String {
    format!(r#"s="$HOME/{CHARON_STAGE}"; if [ -d "$s" ] && [ ! -L "$s" ]; then find "$s" -type f -exec sh -c 'for f; do shred -u "$f" && echo "shredded $f"; done' sh {{}} + ; rm -rf -- "$s" && echo "removed $s/"; fi; true"#)
}

