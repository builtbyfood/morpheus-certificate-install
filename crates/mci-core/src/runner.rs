//! morpheus-certificate-install 0.4.2 — the detached runner script. Byte-identical to the reference
//! (`engine.runner_script`) apart from the version in the header line.

use crate::appliance::{LOG_DIR, TRUST_DIR};
use crate::quote::q;
use crate::{PRODUCT, VERSION};

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct RunnerPlan {
    pub server: bool,
    pub trust: bool,
    pub restart_ui: bool,
    pub storepass: String,
    /// Truststore aliases to import (apply), in import order: root first, then intermediates.
    pub aliases: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Apply,
    Rollback,
}

impl Mode {
    fn as_str(&self) -> &'static str {
        match self { Mode::Apply => "apply", Mode::Rollback => "rollback" }
    }
}

const KT_FIND: &str = r#"KT=$(ls /opt/morpheus/embedded/java/bin/keytool /opt/morpheus/embedded/java/jre/bin/keytool 2>/dev/null | head -1)"#;
const KT_FALLBACK: &str = r#"[ -n "$KT" ] || KT=$(find /opt/morpheus/embedded -maxdepth 6 -type f -name keytool | head -1)"#;
const CA_FIND: &str = r#"CA=$(find /opt/morpheus/embedded -maxdepth 8 -type f -name cacerts -path '*security*' | head -1)"#;

pub fn runner_script(run_id: &str, op_user: &str, plan: &RunnerPlan, mode: Mode, aliases_to_delete: &[String]) -> String {
    let log = format!("{LOG_DIR}/{run_id}.log");
    let rcf = format!("{LOG_DIR}/{run_id}.rc");
    let sp = if plan.storepass.is_empty() { "changeit".to_string() } else { plan.storepass.clone() };
    let mut l: Vec<String> = vec![
        "#!/bin/bash".into(),
        format!("# {PRODUCT} {VERSION} runner {run_id} ({})", mode.as_str()),
        format!("LOG={}; RCF={}; OPU={}", q(&log), q(&rcf), q(op_user)),
        format!("mkdir -p {LOG_DIR}; chmod 755 {LOG_DIR}"),
        r#": > "$LOG"; chmod 600 "$LOG"; [ -n "$OPU" ] && chown "$OPU" "$LOG" 2>/dev/null"#.into(),
        r#"exec >>"$LOG" 2>&1"#.into(),
        "export PATH=/opt/morpheus/bin:/opt/morpheus/sbin:/opt/morpheus/embedded/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
        r#"finish(){ echo "@@MCI done rc=$1"; echo "$1" > "$RCF"; [ -n "$OPU" ] && chown "$OPU" "$RCF" 2>/dev/null; exit "$1"; }"#.into(),
        r#"step(){ echo; echo "@@MCI step=$1"; echo "\$ $2"; }"#.into(),
        r#"ok(){ echo "@@MCI rc=$1 step=$2"; [ "$1" -eq 0 ] || finish "$1"; }"#.into(),
        r#"echo "@@MCI start $(date -Is) on $(hostname)""#.into(),
        "step reconfigure 'morpheus-ctl reconfigure'".into(),
        "morpheus-ctl reconfigure; ok $? reconfigure".into(),
    ];
    if mode == Mode::Apply && plan.trust {
        l.push(KT_FIND.into());
        l.push(KT_FALLBACK.into());
        l.push(CA_FIND.into());
        l.push(r#"if [ -z "$KT" ] || [ -z "$CA" ]; then echo "keytool or cacerts not found under /opt/morpheus/embedded"; finish 3; fi"#.into());
        l.push(r#"echo "keytool: $KT"; echo "cacerts: $CA""#.into());
        for a in &plan.aliases {
            let f = format!("{TRUST_DIR}/{a}.pem");
            l.push(format!("step keytool 'keytool -importcert -alias {a}'"));
            l.push(format!(r#""$KT" -delete -alias {} -keystore "$CA" -storepass {} >/dev/null 2>&1"#, q(a), q(&sp)));
            l.push(format!(r#""$KT" -importcert -noprompt -trustcacerts -alias {} -file {} -keystore "$CA" -storepass {}; ok $? keytool"#, q(a), q(&f), q(&sp)));
        }
    }
    if mode == Mode::Rollback && !aliases_to_delete.is_empty() {
        l.push(KT_FIND.into());
        l.push(KT_FALLBACK.into());
        l.push(CA_FIND.into());
        for a in aliases_to_delete {
            l.push(format!("step keytool 'keytool -delete -alias {a}'"));
            l.push(format!(r#"[ -n "$KT" ] && "$KT" -delete -alias {} -keystore "$CA" -storepass {}; echo "(rc $?)""#, q(a), q(&sp)));
        }
    }
    if plan.server || mode == Mode::Rollback {
        l.push("step nginx 'morpheus-ctl restart nginx'".into());
        l.push("morpheus-ctl restart nginx; ok $? nginx".into());
    }
    if plan.restart_ui {
        l.push("step ui 'morpheus-ctl restart morpheus-ui'".into());
        l.push("morpheus-ctl restart morpheus-ui; ok $? ui".into());
    }
    l.push("step status 'morpheus-ctl status'".into());
    l.push("morpheus-ctl status; true".into());
    l.push("finish 0".into());
    l.push(String::new());
    l.join("\n")
}

/// Parse one runner log line into a step event: `("reconfigure", Running)` etc.
#[derive(Debug, PartialEq, Eq)]
pub enum Marker {
    Step(String),
    Rc { step: String, rc: i32 },
    Done(i32),
}

pub fn parse_marker(line: &str) -> Option<Marker> {
    let rest = line.strip_prefix("@@MCI ")?;
    if let Some(s) = rest.strip_prefix("step=") {
        return Some(Marker::Step(s.trim().to_string()));
    }
    if let Some(s) = rest.strip_prefix("done rc=") {
        return s.trim().parse().ok().map(Marker::Done);
    }
    if rest.starts_with("rc=") {
        let mut rc = None;
        let mut step = None;
        for p in rest.split_whitespace() {
            if let Some(v) = p.strip_prefix("rc=") { rc = v.parse().ok(); }
            if let Some(v) = p.strip_prefix("step=") { step = Some(v.to_string()); }
        }
        return Some(Marker::Rc { step: step?, rc: rc? });
    }
    None
}
