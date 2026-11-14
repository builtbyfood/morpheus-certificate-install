//! morpheus-certificate-install 0.4.2 — `morpheus-certificate-install-cli convert …`
//!
//! Same behaviour and output as the Python reference's `convert` subcommand (reference/python app.convert_main):
//!   convert FILE... [--fqdn X] [--out DIR | --zip] [--include-root] [--fetch-chain] [--ask]
//! Passwords: --ask prompts (no echo); otherwise MCI_PFX_PASSWORD / MCI_KEY_PASSWORD.
//! Exit codes: 0 converted, 2 the certificate set has errors, 64 usage, 1 an input or output file
//! couldn't be read or written.

mod fetch;

use mci_core::formats::{parse_files, InputFile, Passwords};
use mci_core::model::Level;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Default, Debug)]
struct Args {
    files: Vec<PathBuf>,
    fqdn: String,
    out: Option<PathBuf>,
    zip: bool,
    include_root: bool,
    fetch_chain: bool,
    ask: bool,
}

const USAGE: &str = "usage: morpheus-certificate-install-cli convert FILE... [--fqdn FQDN] [--out DIR] [--zip] \
[--include-root] [--fetch-chain] [--ask]\n\nConvert whatever the CA sent into the files a Morpheus appliance needs.";

fn parse(mut it: impl Iterator<Item = String>) -> Result<Args, String> {
    match it.next().as_deref() {
        Some("convert") => {}
        Some("--version") | Some("-V") => return Err(format!("morpheus-certificate-install-cli {}", mci_core::VERSION)),
        _ => return Err(USAGE.into()),
    }
    let mut a = Args::default();
    while let Some(x) = it.next() {
        match x.as_str() {
            "--fqdn" => a.fqdn = it.next().ok_or("--fqdn needs a value")?,
            "--out" => a.out = Some(it.next().ok_or("--out needs a value")?.into()),
            "--zip" => a.zip = true,
            "--include-root" => a.include_root = true,
            "--fetch-chain" => a.fetch_chain = true,
            "--ask" => a.ask = true,
            "-h" | "--help" => return Err(USAGE.into()),
            s if s.starts_with("--") => return Err(format!("unknown option {s}\n\n{USAGE}")),
            f => a.files.push(f.into()),
        }
    }
    if a.files.is_empty() {
        return Err(USAGE.into());
    }
    Ok(a)
}

/// println! that never panics: when stdout is closed early (`… | head`), stop quietly instead.
macro_rules! say {
    ($($t:tt)*) => {{
        use std::io::Write;
        if writeln!(std::io::stdout().lock(), $($t)*).is_err() {
            std::process::exit(0);
        }
    }};
}

fn main() -> ExitCode {
    // Local time first, while the process is single-threaded (time's local-offset requirement on Unix).
    let local = time::OffsetDateTime::now_local().unwrap_or_else(|_| time::OffsetDateTime::now_utc());
    let args = match parse(std::env::args().skip(1)) {
        Ok(a) => a,
        Err(msg) => {
            // --version goes to stdout with exit 0, as argparse does in the Python reference (0.3.21);
            // usage errors go to stderr with 64.
            if msg.starts_with("morpheus-certificate-install-cli ") {
                println!("{msg}");
                return ExitCode::SUCCESS;
            }
            eprintln!("{msg}");
            return ExitCode::from(64);
        }
    };
    match run(&args, local) {
        Ok(code) => ExitCode::from(code),
        Err(msg) => {
            eprintln!("{msg}");
            ExitCode::from(1)
        }
    }
}

/// The reference's `convert_main`, line for line. Returns the exit code (0 written, 2 not converted).
fn run(args: &Args, local: time::OffsetDateTime) -> Result<u8, String> {
    let pw = if args.ask {
        let ask = |prompt: &str| rpassword::prompt_password(prompt).map_err(|e| format!("Couldn't read a password from the terminal ({e}). Set MCI_PFX_PASSWORD / MCI_KEY_PASSWORD instead of --ask."));
        Passwords { pfx: ask("PFX / keystore password (Enter for none): ")?, key: ask("Key passphrase (Enter for none): ")?, extra: vec![] }
    } else {
        Passwords {
            pfx: std::env::var("MCI_PFX_PASSWORD").unwrap_or_default(),
            key: std::env::var("MCI_KEY_PASSWORD").unwrap_or_default(),
            extra: vec![],
        }
    };
    let mut files = Vec::new();
    for p in &args.files {
        let data = std::fs::read(p).map_err(|e| format!("Couldn't read {}: {e}. Check the path and try again.", p.display()))?;
        files.push(InputFile { name: p.file_name().unwrap_or_default().to_string_lossy().into(), data });
    }
    let mut bundle = parse_files(&files, &pw);
    if args.fetch_chain {
        for line in mci_core::aia::complete_chain(&mut bundle, &fetch::fetch) {
            say!("  chain: {line}");
        }
    }
    let now_unix = local.unix_timestamp();
    let an = mci_core::analyze::analyze(&bundle, &args.fqdn, "", now_unix);
    say!("{} {} convert", mci_core::PRODUCT, mci_core::VERSION);
    for r in &an.reports {
        say!("  {}: {}", r.name, r.format);
        for n in &r.notes {
            say!("      {n}");
        }
    }
    for c in &an.checks {
        let mark = match c.level { Level::Ok => "✓", Level::Warn => "!", Level::Error => "✗" };
        say!("  {mark} {}", c.text);
    }
    if !an.ok() {
        say!("Not converted — fix the errors above.");
        return Ok(2);
    }
    let stamp = format!("{:04}-{:02}-{:02} {:02}:{:02}", local.year(), local.month() as u8, local.day(), local.hour(), local.minute());
    let out = mci_core::export::build_files(&an, args.include_root, &stamp)?;
    let folder = match &args.out {
        Some(o) => o.to_string_lossy().into_owned(),
        None => format!("{}-morpheus", mci_core::names::safe_name(&an.fqdn)),
    };
    let dest = if args.zip {
        let dest = PathBuf::from(if folder.ends_with(".zip") { folder.clone() } else { format!("{folder}.zip") });
        // Python's Path(folder).stem: the last component without its last extension.
        let inner = Path::new(&folder).file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| folder.clone());
        let when = (local.year() as u16, local.month() as u8, local.day(), local.hour(), local.minute(), local.second());
        let z = mci_core::export::to_zip(&out, &inner, when)?;
        std::fs::write(&dest, z).map_err(|e| format!("Couldn't write {}: {e}. Choose another place with --out.", dest.display()))?;
        dest
    } else {
        let dest = PathBuf::from(&folder);
        write_dir(&out, &dest)?;
        dest
    };
    say!("Wrote {}:", dest.display());
    let mut names: Vec<&str> = out.iter().map(|(n, _)| n.as_str()).collect();
    names.sort();
    for n in names {
        say!("  {n}");
    }
    Ok(0)
}

/// The reference's `to_dir`: the key is created 0600 (and chmod-ed if it already existed) on Unix.
fn write_dir(files: &[(String, Vec<u8>)], out: &Path) -> Result<(), String> {
    let err = |p: &Path, e: std::io::Error| format!("Couldn't write {}: {e}. Choose another place with --out.", p.display());
    std::fs::create_dir_all(out).map_err(|e| err(out, e))?;
    for (name, data) in files {
        let p = out.join(name);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).map_err(|e| err(parent, e))?;
        }
        if name.ends_with(".key") {
            let mut o = std::fs::OpenOptions::new();
            o.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                o.mode(0o600);
            }
            let mut f = o.open(&p).map_err(|e| err(&p, e))?;
            std::io::Write::write_all(&mut f, data).map_err(|e| err(&p, e))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
            }
        } else {
            std::fs::write(&p, data).map_err(|e| err(&p, e))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn p(v: &[&str]) -> Result<Args, String> { parse(v.iter().map(|s| s.to_string())) }
    #[test]
    fn args() {
        let a = p(&["convert", "a.p7b", "b.key", "--fqdn", "m.x", "--zip", "--fetch-chain"]).unwrap();
        assert_eq!(a.files.len(), 2);
        assert!(a.zip && a.fetch_chain && !a.ask);
        assert_eq!(a.fqdn, "m.x");
        assert!(p(&["convert"]).is_err());
        assert!(p(&["convert", "x", "--bogus"]).unwrap_err().contains("unknown option"));
        assert!(p(&["--version"]).unwrap_err().contains(mci_core::VERSION));
    }
}
