//! morpheus-certificate-install 0.4.2 — events to the UI on channel "mci".
//! Same JSON as the Python app's SSE stream (`type` tag + fields), so ui/index.html handles them unchanged.
//!
//! Not kept: the reference's `ts` field (the page never reads it) and its replay history (an SSE
//! client reconnecting after a reload; the app's page is loaded once per window).

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const CHANNEL: &str = "mci";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    /// Tool narration (cyan in the Run log).
    Log { text: String },
    /// Raw runner output from the appliance (ANSI kept).
    Remote { text: String },
    /// `id`: local step ids (backup, files, rb, match, trustfiles, runner, restore) or `run:<runner step>`.
    Step { id: String, status: StepStatus },
    /// Interactive shell bytes, base64.
    Shell { data: String },
    ShellClosed,
    /// A runner started or was re-attached; `watch` is the tail command for any terminal.
    Run { id: String, watch: String },
    /// name: preflight | apply | verify | reattach | rollback; status: running | done | error.
    Job { name: String, status: String, #[serde(default, skip_serializing_if = "Option::is_none")] result: Option<Value>, #[serde(default, skip_serializing_if = "Option::is_none")] error: Option<String> },
    Facts { facts: Value },
    Verify { result: Value },
    Connected { transport: Value },
    Disconnected,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum StepStatus { Running, Ok, Fail }

pub fn log(text: impl Into<String>) -> Event { Event::Log { text: text.into() } }
pub fn step(id: &str, status: StepStatus) -> Event { Event::Step { id: id.to_string(), status } }
