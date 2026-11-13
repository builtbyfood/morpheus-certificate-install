//! morpheus-certificate-install 0.4.0 — where data lives.
//!
//! - **Windows and Linux:** portable mode wins if `portable.flag` sits beside the exe (same rule as
//!   Charon's paths.rs): config, known_hosts and the webview profile all go in `./data/`. Otherwise
//!   `<config_dir>/morpheus-certificate-install/` (`%APPDATA%\…`, `~/.config/…`).
//! - **macOS:** never portable (the exe sits inside a signed-or-quarantined `.app` bundle, where
//!   writing beside it isn't possible or wanted). Always
//!   `~/Library/Application Support/morpheus-certificate-install/`, and "Leave no trace" isn't
//!   offered, because the page shows it only in portable mode (0.4.0-rc2).
//!
//! Contents: settings.json (no secrets), known_hosts (host keys, via charon-ssh's hostkeys).
//! Secrets are never written: SSH/sudo passwords, key passphrases, the Morpheus API token.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

pub const APP_DIR: &str = "morpheus-certificate-install";

#[derive(Debug, Clone)]
pub struct AppPaths {
    pub portable: bool,
    pub data_dir: PathBuf,
}

/// Which platform rules apply; a parameter so the macOS rule is testable on every OS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    MacOs,
    Other,
}

impl Platform {
    pub fn current() -> Self {
        if cfg!(target_os = "macos") { Platform::MacOs } else { Platform::Other }
    }
}

/// The pure decision: (portable, data dir). `config_dir` is `dirs::config_dir()`, which on macOS is
/// `~/Library/Application Support`.
pub fn resolve(platform: Platform, exe_dir: &Path, flag_present: bool, config_dir: Option<&Path>) -> Result<(bool, PathBuf)> {
    if platform == Platform::Other && flag_present {
        return Ok((true, exe_dir.join("data")));
    }
    let base = config_dir.context("This system has no per-user configuration folder (HOME isn't set?). Set HOME, or use the portable build on Windows or Linux.")?;
    Ok((false, base.join(APP_DIR)))
}

impl AppPaths {
    pub fn detect() -> Result<Self> {
        let exe = std::env::current_exe().context("current_exe")?;
        let exe_dir = exe.parent().context("exe has no parent dir")?.to_path_buf();
        let config = dirs::config_dir();
        let (portable, data_dir) = resolve(Platform::current(), &exe_dir, exe_dir.join("portable.flag").exists(), config.as_deref())?;
        std::fs::create_dir_all(&data_dir).context("create data dir")?;
        Ok(Self { portable, data_dir })
    }
    pub fn settings(&self) -> PathBuf { self.data_dir.join("settings.json") }
    pub fn known_hosts(&self) -> PathBuf { self.data_dir.join("known_hosts") }
    /// Portable: keep the WebView2/webkit profile beside the data too (nothing in %LOCALAPPDATA%).
    pub fn webview_data_dir(&self) -> Option<PathBuf> {
        if self.portable { Some(self.data_dir.join("webview")) } else { None }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macos_is_never_portable_and_uses_application_support() {
        let app = Path::new("/Applications/Morpheus Certificate Install.app/Contents/MacOS");
        let support = Path::new("/Users/mcitest/Library/Application Support");
        for flag in [false, true] {
            let (portable, dir) = resolve(Platform::MacOs, app, flag, Some(support)).unwrap();
            assert!(!portable, "portable.flag (present: {flag}) is ignored on macOS");
            assert_eq!(dir, Path::new("/Users/mcitest/Library/Application Support/morpheus-certificate-install"));
        }
        assert!(resolve(Platform::MacOs, app, true, None).unwrap_err().to_string().contains("HOME"));
    }

    #[test]
    fn windows_and_linux_are_portable_with_the_flag() {
        let exe = Path::new("/opt/mci");
        assert_eq!(resolve(Platform::Other, exe, true, Some(Path::new("/home/mcitest/.config"))).unwrap(), (true, exe.join("data")));
        // the flag needs no config dir at all
        assert_eq!(resolve(Platform::Other, exe, true, None).unwrap(), (true, exe.join("data")));
        assert_eq!(
            resolve(Platform::Other, exe, false, Some(Path::new("/home/mcitest/.config"))).unwrap(),
            (false, Path::new("/home/mcitest/.config").join(APP_DIR))
        );
    }

    #[test]
    fn this_platform_matches_cfg() {
        assert_eq!(Platform::current() == Platform::MacOs, cfg!(target_os = "macos"));
    }
}
