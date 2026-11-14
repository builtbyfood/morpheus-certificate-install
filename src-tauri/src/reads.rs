//! morpheus-certificate-install 0.4.1 — reads from the appliance whose output is data.
//!
//! Every one goes through `Transport::run_data`, so only the command's **stdout** is parsed.
//! Anything on stderr — sudo's first-use lecture (the fake appliance keeps it on purpose),
//! `cat: …: No such file`, warnings — appears only in error messages. With merged output the
//! lecture would have been read as the first lines of morpheus.rb and written back into it.
//!
//! The commands come from `mci_core::appliance`; the engine (R7) calls these instead of `run`.

use crate::transport::{TResult, Transport, TransportError};
use mci_core::{appliance, morpheus_rb};
use std::collections::BTreeMap;

/// `/etc/morpheus/morpheus.rb`, exactly as on disk (the reference's `cat`, run with sudo).
pub async fn morpheus_rb(t: &dyn Transport) -> TResult<String> {
    let r = t.run_data(&appliance::cat_morpheus_rb(), true, None, 120).await?;
    if r.rc != 0 {
        return Err(TransportError::Msg(format!(
            "Couldn't read {} (exit {}): {}", appliance::MORPHEUS_RB, r.rc, r.complaint(400))));
    }
    Ok(r.stdout)
}

/// morpheus.rb for preflight: `None` when the read fails (the reference's `rb if rc == 0 else ""`).
pub async fn morpheus_rb_opt(t: &dyn Transport) -> TResult<Option<String>> {
    let r = t.run_data(&appliance::cat_morpheus_rb(), true, None, 120).await?;
    Ok((r.rc == 0).then_some(r.stdout))
}

/// morpheus.rb read for writing back: the read must succeed *and* pass `morpheus_rb::guard`.
pub async fn morpheus_rb_for_edit(t: &dyn Transport) -> TResult<String> {
    let text = morpheus_rb(t).await?;
    morpheus_rb::guard(&text, appliance::MORPHEUS_RB).map_err(TransportError::Msg)?;
    Ok(text)
}

/// The file's permission bits (`stat -c %a`), or "600" when they can't be read, as the reference.
pub async fn morpheus_rb_mode(t: &dyn Transport) -> String {
    match t.run_data(&appliance::stat_mode_morpheus_rb(), true, None, 120).await {
        Ok(r) if r.rc == 0 => {
            let m = r.stdout.trim();
            if (3..=4).contains(&m.len()) && m.bytes().all(|b| (b'0'..=b'7').contains(&b)) { m.to_string() } else { "600".into() }
        }
        _ => "600".into(),
    }
}

/// The preflight facts: `KEY=VALUE` lines, keys lowercased and both sides trimmed, as the reference.
pub async fn preflight(t: &dyn Transport) -> TResult<BTreeMap<String, String>> {
    let r = t.run_data(appliance::PREFLIGHT_SCRIPT, true, None, 60).await?;
    if r.rc != 0 {
        return Err(TransportError::Msg(format!("preflight failed (exit {}): {}", r.rc, r.complaint(600))));
    }
    Ok(parse_key_values(&r.stdout))
}

pub fn parse_key_values(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_lowercase(), v.trim().to_string()))
        .collect()
}

/// `appliance_url` from morpheus.rb, the way the reference's preflight reads it.
pub fn appliance_url_from_rb(rb: &str) -> Option<String> {
    let mut found = None;
    for l in rb.lines() {
        let s = l.trim();
        if s.starts_with("appliance_url") && !s.starts_with('#') {
            found = Some(match s.split_once(char::is_whitespace) {
                Some((_, v)) => v.trim().trim_matches(|c| c == '\'' || c == '"').to_string(),
                None => String::new(),
            });
        }
    }
    found
}

/// What nginx serves on 127.0.0.1:443 (`openssl s_client -showcerts`), as text to parse. Not sudo.
pub async fn served_chain(t: &dyn Transport, sni: &str) -> TResult<(i32, String)> {
    let r = t.run_data(&appliance::served_chain(sni), false, None, 30).await?;
    Ok((r.rc, r.stdout))
}

/// `id|mtime|rc` lines for the runs in the log directory (parsed by the engine).
pub async fn list_runs(t: &dyn Transport) -> TResult<String> {
    Ok(t.run_data(&appliance::list_runs(), true, None, 120).await?.stdout)
}

/// `@@B <id>` + manifest blocks for the backups (parsed by the engine).
pub async fn list_backups(t: &dyn Transport) -> TResult<String> {
    Ok(t.run_data(&appliance::list_backups(), true, None, 120).await?.stdout)
}

/// A backup's manifest.json; `None` when it is missing or isn't JSON (the reference used `{}`).
pub async fn manifest(t: &dyn Transport, bdir: &str) -> TResult<Option<serde_json::Value>> {
    let r = t.run_data(&appliance::cat_manifest(bdir), true, None, 120).await?;
    Ok(if r.rc == 0 { serde_json::from_str(&r.stdout).ok() } else { None })
}

/// The morpheus.rb a rollback would restore, checked with `morpheus_rb::guard` first.
pub async fn backup_morpheus_rb_checked(t: &dyn Transport, bdir: &str, backup_id: &str) -> TResult<()> {
    let r = t.run_data(&appliance::cat_backup_morpheus_rb(bdir), true, None, 120).await?;
    let source = format!("the backup {backup_id}");
    if r.rc != 0 {
        return Err(TransportError::Msg(format!(
            "Not restoring from {source}: its morpheus.rb couldn't be read (exit {}): {}. Nothing was changed.",
            r.rc, r.complaint(300))));
    }
    morpheus_rb::guard(&r.stdout, &source).map_err(TransportError::Msg)
}

/// The installed-files ledger's text (empty when there's none yet), 0.3.19.
pub async fn ledger(t: &dyn Transport) -> TResult<String> {
    let r = t.run_data(&appliance::cat_ledger(), true, None, 60).await?;
    if r.rc != 0 {
        return Err(TransportError::Msg(format!("Couldn't read {} (exit {}): {}", appliance::LEDGER, r.rc, r.complaint(300))));
    }
    Ok(r.stdout)
}

/// What the tool left on the appliance: the root-owned inventory (sudo) and the login user's
/// Charon staging dir (no sudo), as `kind|path|bytes|mtime[|keys]` lines (0.3.17).
pub async fn cleanup_inventory(t: &dyn Transport) -> TResult<String> {
    let r = t.run_data(&appliance::cleanup_inventory(), true, None, 120).await?;
    if r.rc != 0 {
        return Err(TransportError::Msg(format!("Couldn't list what this tool left on the appliance (exit {}): {}", r.rc, r.complaint(300))));
    }
    let s = t.run_data(&appliance::cleanup_stage_inventory(), false, None, 60).await?;
    Ok(format!("{}{}", r.stdout, if s.rc == 0 { s.stdout } else { String::new() }))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::transport::DataOut;
    use async_trait::async_trait;
    use mci_core::appliance::SudoMode;
    use serde_json::Value;
    use std::sync::Mutex;
    use tokio::sync::watch;

    /// sudo's first-use lecture, word for word, as it lands on stderr with `sudo -S`.
    pub const LECTURE: &str = "\nWe trust you have received the usual lecture from the local System\nAdministrator. It usually boils down to these three things:\n\n    #1) Respect the privacy of others.\n    #2) Think before you type.\n    #3) With great power comes great responsibility.\n\n";

    /// A transport that answers by command, always with noise on stderr before stdout.
    pub struct NoisyFake {
        pub answers: Vec<(String, i32, String, String)>, // (cmd, rc, stdout, stderr)
        pub calls: Mutex<Vec<String>>,
    }

    impl NoisyFake {
        fn answer(&self, cmd: &str) -> (i32, String, String) {
            self.calls.lock().unwrap().push(cmd.to_string());
            self.answers.iter().find(|a| a.0 == cmd).map(|a| (a.1, a.2.clone(), a.3.clone()))
                .unwrap_or((127, String::new(), format!("bash: {cmd}: not in the fake\n")))
        }
    }

    #[async_trait]
    impl Transport for NoisyFake {
        fn kind(&self) -> &'static str { "fake" }
        fn label(&self) -> String { "fake".into() }
        fn login_user(&self) -> String { "mcitest".into() }
        fn sudo_mode(&self) -> SudoMode { SudoMode::Password }
        fn info(&self) -> Value { Value::Null }
        async fn run(&self, cmd: &str, _: bool, _: Option<&[u8]>, _: u64) -> TResult<(i32, String)> {
            let (rc, out, err) = self.answer(cmd);
            Ok((rc, format!("{err}{out}"))) // merged, the lecture first, as on the wire
        }
        async fn run_data(&self, cmd: &str, _: bool, _: Option<&[u8]>, _: u64) -> TResult<DataOut> {
            let (rc, stdout, stderr) = self.answer(cmd);
            Ok(DataOut { rc, stdout, stderr })
        }
        async fn put_root(&self, _: &str, _: &[u8], _: &str, _: &str) -> TResult<()> { Ok(()) }
        async fn follow(&self, _: &str, _: &str, _: &(dyn Fn(String) + Send + Sync), _: watch::Receiver<bool>) -> TResult<Option<i32>> { Ok(None) }
    }

    const RB: &str = "appliance_url 'https://198.51.100.20'\nelasticsearch['es_hosts'] = {'127.0.0.1' => 9200}\n";

    fn fake() -> NoisyFake {
        let bdir = "/var/lib/morpheus-certificate-install/backups/20261105-120000";
        NoisyFake {
            answers: vec![
                (appliance::cat_morpheus_rb(), 0, RB.into(), LECTURE.into()),
                (appliance::stat_mode_morpheus_rb(), 0, "640\n".into(), LECTURE.into()),
                (appliance::PREFLIGHT_SCRIPT.into(), 0, "HOST=m.cust.test\nRB=yes\nOPENSSL=OpenSSL 3.0.13\n".into(),
                 format!("{LECTURE}df: /var: warning=ignored\n")),
                (appliance::cat_manifest(bdir), 0, "{\"stamp\": \"20261105-120000\", \"aliases\": [\"mci-a\"]}\n".into(), LECTURE.into()),
                (appliance::cat_backup_morpheus_rb(bdir), 0, RB.into(), LECTURE.into()),
                (appliance::list_runs(), 0, "R1|1793880000|0\n".into(), LECTURE.into()),
            ],
            calls: Mutex::new(vec![]),
        }
    }

    #[tokio::test]
    async fn data_reads_ignore_stderr_noise() {
        let t = fake();
        assert_eq!(morpheus_rb(&t).await.unwrap(), RB, "morpheus.rb exactly as on disk");
        assert_eq!(morpheus_rb_for_edit(&t).await.unwrap(), RB);
        assert_eq!(morpheus_rb_mode(&t).await, "640");
        let f = preflight(&t).await.unwrap();
        assert_eq!(f.get("host").map(String::as_str), Some("m.cust.test"));
        assert_eq!(f.get("openssl").map(String::as_str), Some("OpenSSL 3.0.13"));
        assert_eq!(f.len(), 3, "nothing from stderr became a fact: {f:?}");
        assert_eq!(appliance_url_from_rb(RB).as_deref(), Some("https://198.51.100.20"));
        let m = manifest(&t, "/var/lib/morpheus-certificate-install/backups/20261105-120000").await.unwrap().unwrap();
        assert_eq!(m["aliases"][0], "mci-a");
        assert_eq!(list_runs(&t).await.unwrap(), "R1|1793880000|0\n");
        backup_morpheus_rb_checked(&t, "/var/lib/morpheus-certificate-install/backups/20261105-120000", "20261105-120000").await.unwrap();
    }

    #[tokio::test]
    async fn the_same_reads_through_merged_output_would_be_wrong() {
        // Why run_data exists: with merged output the lecture is part of "morpheus.rb", the
        // preflight picks up a bogus fact, the manifest isn't JSON and the mode isn't a mode.
        let t = fake();
        let (_, rb) = t.run(&appliance::cat_morpheus_rb(), true, None, 120).await.unwrap();
        assert!(rb.starts_with("\nWe trust you have received the usual lecture"));
        let (_, pf) = t.run(appliance::PREFLIGHT_SCRIPT, true, None, 60).await.unwrap();
        assert!(parse_key_values(&pf).contains_key("df: /var: warning"));
        let (_, man) = t.run(&appliance::cat_manifest("/var/lib/morpheus-certificate-install/backups/20261105-120000"), true, None, 120).await.unwrap();
        assert!(serde_json::from_str::<Value>(&man).is_err());
    }

    #[tokio::test]
    async fn errors_carry_stderr_and_the_guard_stops_bad_writes() {
        let bdir = "/var/lib/morpheus-certificate-install/backups/gone";
        let t = NoisyFake {
            answers: vec![
                (appliance::cat_morpheus_rb(), 0, String::new(), LECTURE.into()), // read "succeeded", empty
                (appliance::cat_backup_morpheus_rb(bdir), 1, String::new(), format!("{LECTURE}cat: {bdir}/morpheus.rb: No such file or directory\n")),
                (appliance::stat_mode_morpheus_rb(), 0, "We trust\n".into(), String::new()),
            ],
            calls: Mutex::new(vec![]),
        };
        let e = morpheus_rb_for_edit(&t).await.unwrap_err().to_string();
        assert!(e.contains("no appliance_url line") && e.contains("Nothing was changed"), "{e}");
        let e = backup_morpheus_rb_checked(&t, bdir, "gone").await.unwrap_err().to_string();
        assert!(e.contains("No such file or directory") && e.contains("Nothing was changed"), "{e}");
        assert_eq!(morpheus_rb_mode(&t).await, "600", "garbage isn't a mode");
        let e = preflight(&t).await.unwrap_err().to_string();
        assert!(e.starts_with("preflight failed (exit 127)"), "{e}");
    }
}
