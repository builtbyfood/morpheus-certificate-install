# Changelog

## 0.4.2 — 2026-11-14

**Security update.** A host key of a different type from the one saved for an appliance now counts as a changed key, and the app refuses the connection with its changed-key warning. Before, if an appliance's ed25519 key was on file and the connection was offered an RSA or ECDSA key, the app showed the normal first-connection prompt instead. You still had to confirm the fingerprint, so nothing was trusted without you, but it was the wrong warning. The SSH client, charon-ssh, is now 0.2.1, which has the fix.

This release also carries 0.4.1's SQLite security update (RUSTSEC-2026-0459). The 0.4.1 source on GitHub was incomplete, so no 0.4.1 binaries were built.

<!-- end of release notes -->

## 0.4.1 — 2026-11-13

**Security update.** The SQLite library built into the app is updated, fixing RUSTSEC-2026-0459 in the bundled SQLite (libsqlite3-sys 0.30.1 → 0.40.0).

The app uses SQLite for one thing only: when you choose a Charon session on the Connect step, it reads the saved hosts from Charon's local database (`charon.db`) on your computer. It opens that file **read-only**, reads only host, port, user, jump host and tags, and never reads saved credentials. Nothing else in the app uses SQLite, and no data from an appliance or the network goes through it. If you don't use Charon, the app never opens it. Updating is still recommended.

Nothing else in the app changed. The repository also gets back what was missing from the 0.4.0 source tree: the Python reference (`reference/`), the charon-ssh patches, the build, parity, verification and release documents, and the fake appliance for contributors (`tests/fake-appliance/`, `docs/FAKE-APPLIANCE.md`). Text files are now stored with LF line endings on every platform.

<!-- end of release notes -->

## 0.4.0 — 2026-11-13

The first release of Morpheus Certificate Install as a standalone desktop app. It takes whatever certificate files a CA or a customer sends and turns them into the files an HPE Morpheus appliance needs. Then, if you want, it installs them over SSH with a backup first, a live view of `morpheus-ctl reconfigure`, a check of what nginx serves, and rollback.

**Downloads:**

- Windows: portable zip, installer, CLI;
- Linux: portable tar.gz, deb, rpm, AppImage, CLI;
- macOS: a .dmg and a CLI for Apple Silicon (`arm64`) and for Intel (`x64`). **The macOS builds aren't tested on a Mac yet; reports are welcome.**

Check every download against `SHA256SUMS`. The binaries aren't signed, so Windows SmartScreen warns the first time, and on macOS you open the app once with right-click → Open (see the README).

### What's new since the Python 0.2.x

- **A desktop app instead of a local web server.** Nothing listens on a port any more. There's nothing to `pip install`; the portable builds run from a folder and keep everything beside them in `data\`.
  - **Leave no trace:** with this ticked, the portable app saves nothing, and deletes its data folder when it closes.
- **A command-line converter on its own,** `morpheus-certificate-install-cli convert …`, with the same options as before.
- **Reads more, and says more clearly what's wrong:**
  - RSA-PSS-signed chains link;
  - a password-protected PFX whose integrity check passes but which won't decrypt is reported as damaged, not as a wrong password;
  - broken files get an explanation instead of a crypto library's message;
  - a stray CSR, CRL or public key next to a complete set is a warning, not an error;
  - absurd key-derivation work factors are refused before they run.
- **Wildcard certificates:** a wildcard is never used as the FQDN. You're asked for the real name, and it must be covered by the certificate.
- **"Trust this CA"** is now based on the certificates themselves. It starts unticked for a publicly trusted chain, ticked for a private CA, and the page says why.
- **Safer on the appliance:**
  - rollback restores `/etc/morpheus/ssl` exactly, removing the files the rolled-back install wrote, including its key;
  - `morpheus.rb` is never written unless the result still has an `appliance_url`;
  - the Run log no longer shows sudo's chatter.
- **Clean up this appliance:** lists everything the app left on an appliance (run scripts and logs, old backups, certificates no longer in use) and removes what you tick. Keys are shredded first, and a run that's still going is always kept.
- **Forget this appliance** removes its host key and settings from this computer.
- **Verify from this machine** reports which trust store it used (the supplied root, the OS store or the bundled public roots) and gives readable reasons on failure.
- **Charon:** the Charon transport reads only what it needs from Charon's saved hosts, and frames its reads, so terminal noise can't get into a file.
- **Exported zips keep the key at 0600** when unpacked on Linux or macOS, even when the zip was built on Windows.

Not supported: Ed448 keys, JCEKS keystores (convert with `keytool` first), and a few legacy key encryptions (PBES1, RC4, OpenSSH chacha20/AES-GCM). The app tells you how to convert each one. Portable mode and **Leave no trace** are for Windows and Linux; the macOS app keeps its data in `~/Library/Application Support/morpheus-certificate-install/`.

<!-- end of release notes -->

## Earlier

0.3.x were development builds and weren't released. The Python app, 0.2.1 and earlier: see `reference/python/CHANGELOG.md`.
