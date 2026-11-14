# Changelog

## 0.4.1 — 2026-11-13

**Security update.** The SQLite library built into the app is updated, fixing RUSTSEC-2026-0459 in the bundled SQLite (libsqlite3-sys 0.30.1 → 0.40.0).

The app uses SQLite for one thing only: when you choose a Charon session on the Connect step, it reads the saved hosts from Charon's local database (`charon.db`) on your computer. It opens that file **read-only**, reads only host, port, user, jump host and tags, and never reads saved credentials. Nothing else in the app uses SQLite, and no data from an appliance or the network goes through it. If you don't use Charon, the app never opens it. Updating is still recommended.

Nothing else in the app changed. The repository also gets back what was missing from the 0.4.0 source tree: the Python reference (`reference/`), the charon-ssh patches, the build, parity, verification and release documents, and the fake appliance for contributors (`tests/fake-appliance/`, `docs/FAKE-APPLIANCE.md`). Text files are now stored with LF line endings on every platform.

<!-- end of release notes -->

### Maintainer notes: 0.4.1

- **rusqlite 0.32 → 0.42** (`src-tauri/Cargo.toml`, `bundled` kept), which brings libsqlite3-sys 0.30.1 → 0.40.0 (the fix is in ≥ 0.39.0).
  - Lock changes from the same update: hashlink 0.9 → 0.12, ahash removed, and `sqlite-wasm-rs` / `rsqlite-vfs` added. Those two are wasm32-only dependencies of libsqlite3-sys, so they're never built here.
  - rusqlite 0.42 needs Rust ≥ 1.89, and CI uses stable.
  - `charon_mcp::saved_hosts` compiled unchanged: `open_with_flags(READ_ONLY | NO_MUTEX)`, `busy_timeout`, `prepare`, `query_map` and `types::Value` have the same API. It stays read-only, selecting only the `json_extract` keys.
- **New offline test `src-tauri/tests/charon_saved_hosts.rs`,** run in CI on every platform. Until now the "charon.db unchanged" check lived only in the ignored live tests (`charon_mock`, `charon_live`). It covers:
  - inheritance down two folder levels, the sort order, and no secret in the output (credential, password and key passphrase fields planted);
  - the main file's bytes unchanged, both with Charon closed and while Charon holds it open in WAL mode (Charon uses `journal_mode = WAL`), with a row still only in the `-wal` file, which the reader still sees;
  - the reader's open flags refuse a write.
- **`cargo audit`** on the whole workspace: clean. Only the two allowed warnings remain, `proc-macro-error` (unmaintained) and `glib` 0.18 (unsound), from the Linux GTK stack.
- **New `.github/workflows/audit.yml`:** `cargo audit` every Monday at 06:17 UTC, and on demand. GitHub disables scheduled workflows after 60 days without repository activity; the file says how to re-enable it.
- **Public 0.4.0 was missing 32 files that should be public:** all of `reference/` (18), `docs/charon-ssh-patches/` (9), and `docs/` BUILD-LINUX, BUILD-MACOS, PARITY, RELEASE-CHECKLIST and VERIFY-ON-APPLIANCE.
  - **Cause:** the export was complete; the 249 files in the publish folder included all of them, and every file in the GitHub checkout is byte-identical to its copy there. Between the copy (08:54) and the `v0.4.0` commit, they were deleted by hand from the GitHub checkout: the Recycle Bin holds `reference`, `tests/fake-appliance` and six docs from that folder, deleted 08:57–09:11. The patches folder isn't there (likely Shift+Delete). Git ignore rules weren't involved: there's no `.git/info/exclude`, the global ignore file only names `.claude/settings.local.json`, and git adds all 249 files of a fresh export.
  - **Also found:** `tracked-files.mjs` read only the root `.gitignore`. `reference/python/.pytest_cache/` has its own (`*`), so the export copied 4 cache files that git then left out. Every `.gitignore` now counts, scoped to its folder, as in git. A `.gitignore` using `!` or `**` (unsupported) makes the scripts stop instead of guessing. The lists are sorted.
  - 0.4.1 restores them all: the publish commit is a full export of the published tree.
- **export-tree manifest check:** after copying, it lists the folder (except `.git`) and fails on any file missing, extra or not byte-identical to the source. `npm run export-tree -- --list` prints the published list. The release checklist's new section "The file list" has a PowerShell one-liner to run after `git add -A`, which compares `git ls-files` with that list, so a hand deletion or a machine-local ignore rule shows up before the commit. Tested on a scratch repo: OK on a clean export, and it listed all 10 files after deleting `docs/PARITY.md` and `docs/charon-ssh-patches/`.
- **Link check, `scripts/check-links.mjs`** (`npm run check-links`, plus `--self-test`), run in CI's `test` job:
  - every relative link and image in every published `.md` must resolve, along with reference definitions and HTML `href`/`src`;
  - the target must be in the **published** tree, so a link to a local-only file fails;
  - `#anchors` must match a heading, slugged as GitHub does;
  - code is skipped, and `reference/python/` (frozen) isn't checked.

  Against the public 0.4.0 it reports the 8 broken links: six in README and CONTRIBUTING, plus two to `docs/charon-ssh-patches/` in CHARON-SSH-CHANGES. The 0.4.1 tree has none.
- **The fake appliance is published again; the Claude Code material stays local** (Travis, before the 0.4.1 commit).
  - `LOCAL_ONLY` in `tracked-files.mjs` now lists only `CLAUDE.md` and `docs/development/`. `tests/fake-appliance/` and `docs/FAKE-APPLIANCE.md` are exported: 256 files in all.
  - The README's "fake appliance, for contributors" section, CONTRIBUTING rule 2 and the pointers in the live tests, the click README, `run.mjs`, `bridge.cjs` and BUILD-MACOS link to them again.
  - No published file links to `CLAUDE.md` or `docs/development/`; the release checklist's gate step B names the manual check without a link. `check-links` enforces it.
  - The README section and FAKE-APPLIANCE.md now say to use a throwaway VM: the installer creates `mcitest` with password `hunter2` and sudo rights.
- **export-tree also checks the exported folder,** after the manifest check:
  - its Markdown links (`check-links`, reading the exported files);
  - its `.gitattributes` against its files (`check-gitattributes`).

  Either failing fails the export.
- **Line endings.** Travis saw about 115 files "modified" in a fresh clone of 0.4.0 and suspected CRLF in the repository. It isn't:
  - `git ls-files --eol` in the clone shows 192 files `i/lf` and 21 `i/-text`. The only `i/crlf` is `fixtures/corpus/win.cer`, which is CRLF on purpose.
  - The modifications are 0.4.1's real changes: `git diff --stat` and `git diff --stat --ignore-cr-at-eol` both give the same 103 files, +320/−185.
  - The real gap: 36 text files had no line-ending rule (`.gitignore`, LICENSE, NOTICE, Cargo.lock, the .css, .txt, .pem, .py, .xml, .svg and .patch files, and `reference/`). With Git for Windows' system `core.autocrlf=true`, they were checked out CRLF, hence git's "LF will be replaced by CRLF" warnings.
  - **`.gitattributes` rewritten:** a `* text=auto eol=lf` default, an explicit `text eol=lf` line for every text type in the tree, explicit `binary` for .png, .ico, .icns, .der, .cer, .pfx, .p12, .jks, .p7c and .pvk, and the byte-exact `fixtures/**` and `formats/testdata/**` (`-text`) last, so they win.
- **New `scripts/check-gitattributes.mjs`** (`npm run check-gitattributes`), run in CI's `test` job with `--git`, and its rules part by export-tree:
  - every text file needs an explicit `text eol=lf` line (the default doesn't count, so a new type fails until it's listed) and must hold no CR;
  - a binary file must not be marked text;
  - byte-exact files are left alone;
  - `--git` stages the published files in a temp repo with `core.autocrlf=true` and requires `git ls-files --eol` to show every text file stored LF.

  Result: 179 text files, 62 byte-exact, 21 binary, all stored LF. Against the old `.gitattributes` it reports the 36 uncovered files.
- **Release checklist section D:** a later release in the public repository. It clones the repository if needed, exports, checks the file list, then makes a normal commit and tag (no amend, no force-push).


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

### Maintainer notes: 0.4.0 (the seal, the bump, the screenshots)

- **The seal is centred.** The 12-point outline was drawn by hand in the first scaffold, and its centre sat at about (31, 28.5) in the 68×68 viewBox. It's replaced by a symmetric outline centred at (34, 34), in both places it's drawn: `src-tauri/icons/icon.svg` and `sealSvg()` in `ui/index.html`. The inner ring and the glyphs were already centred and are unchanged. The header mark (a 26×26 circle seal) is centred too, also unchanged.
- **Icons regenerated** with `npx tauri icon` (gitignored; CI and the fresh-clone check generate them from the SVG).
- **Test `src-tauri/tests/seal_outline.rs`:**
  - it parses the outline in both files (M/L/H/V/Z, absolute and relative) and asserts 24 vertices and a bounding-box centre of (34, 34) ± 0.1;
  - it asserts the two outlines are identical;
  - it checks that the parser finds the old outline off-centre, at about (31, 28.5).
- **The bump to 0.4.0** is done here, so the checklist's C1 is now a check.
- **The README screenshots** were taken again (`tests/click`, suite `screenshots`, against the fake VM), so they show the new seal and v0.4.0.
- **Fixed: `chain.png` didn't show the chain.** The suite typed into step 4's address field just before that capture, which scrolled the page to steps 3–5, so the R8 image never showed the chain or its seals. The suite now scrolls the chain into view and waits until it's fully visible.
- **The Claude Code material isn't published.** `CLAUDE.md` and `docs/development/` (KICKOFF, ROUND1, MANUAL-CHECK-R7, PUBLISH-BRIEF) stay in the development folder but are left out of the publish tree. `LOCAL_ONLY` and `publishedFiles()` in `scripts/tracked-files.mjs` drive `export-tree` and `fresh-clone-check`, and `check-private` still scans them. Published files no longer point at them: code comments in `mci-core`, `src-tauri` and the tests, plus DECISIONS.md, BUILD-LINUX.md, the click README and the release checklist. The older entries in this changelog still name them, as history.
- **The fake appliance isn't published either:** `tests/fake-appliance/` and `docs/FAKE-APPLIANCE.md` are local-only too. README, CONTRIBUTING, BUILD-MACOS and the test headers now speak of a disposable test machine, and say that the maintainer runs the live tests before each release. The live tests stay in the repository (ignored without `MCI_TEST_SSH`).

## 0.4.0-rc2 — 2026-11-13

macOS in CI, and the publish package. Its release notes became 0.4.0's.

### Maintainer notes: macOS (0.4.0-rc2)

The release notes, which had moved here from 0.4.0-rc1 (never tagged), gained macOS.

- **CI, job `macos`**, as in Charon's workflow: one job per architecture on `macos-latest`, arm64 native and Intel cross-compiled (`--target x86_64-apple-darwin`).
  - It runs `cargo test --locked --workspace` natively; the x64 job also compiles the tests for Intel (`--no-run`), since the runner can't be relied on to run x86_64 binaries.
  - It builds the app and the .dmg (`--bundles app,dmg`) and the CLI, and checks each binary's arch with `lipo -archs`.
  - Assets: `morpheus-certificate-install_<ver>_macos-arm64.dmg` / `…_macos-x64.dmg` and `morpheus-certificate-install-cli-macos-arm64.tar.gz` / `…-x64.tar.gz`. `release` now needs `bundle` and `macos`, so they're in `SHA256SUMS`: 13 assets in all (the checklist says so).
  - The click tests stay Windows-only.
- **tauri.conf.json:** targets `app` and `dmg` added, and `macOS.minimumSystemVersion` set to 11.0. `bundle.icon` already lists `icons/icon.icns`, which `tauri icon` generates; CI generates the icons before building.
- **paths.rs:** the decision is now a pure `resolve(platform, exe_dir, flag, config_dir)`. On macOS `portable.flag` is ignored and the data is in `~/Library/Application Support/morpheus-certificate-install`. The page already hides **Leave no trace** unless the app is portable. `set_leave_no_trace`'s refusal now says it's for Windows and Linux. Tests: `paths::tests::macos_is_never_portable_and_uses_application_support`, `windows_and_linux_are_portable_with_the_flag`, `this_platform_matches_cfg`.
- **Code that compiles for macOS for the first time,** checked by reading it. No Mac and no Apple cross toolchain here: `ring` and `libsqlite3-sys` need a C compiler for `cargo check --target aarch64-apple-darwin`, so this is compile-level reasoning, and the CI `macos` jobs are the first real compile.
  - **charon-ssh's agent login** is `#[cfg(unix)]` (`AgentClient::connect_env`, `SSH_AUTH_SOCK`), which covers macOS; no change.
  - **rustls-platform-verifier 0.6.2:** `Verifier::new(provider)` has the same signature in its Apple module (Security.framework) as on Windows and Linux; **rustls-native-certs** reads the keychains on macOS. Their Apple dependencies (security-framework, core-foundation) are already in `Cargo.lock`, so `--locked` holds. No change.
  - **Charon discovery** already searches `~/Library/Application Support/charon` under `cfg!(target_os = "macos")`. No change.
  - `WebviewWindowBuilder::data_directory` isn't cfg-gated in tauri 2.12.5, and it's only called in portable mode. Every `std::os::unix` use is under `#[cfg(unix)]`.
  - **One test-level fix:** three tests in `mci-core/tests/golden_text.rs` run appliance command lines in local bash. They probed only `base64 --version` (and `stat`/`timeout`), which macOS's BSD tools could pass before failing on GNU options. The probes now require GNU coreutils, so on macOS these tests skip, as they do where there's no bash.
- **Docs:**
  - README: downloads per chip, a macOS section (Gatekeeper's right-click → Open, `xattr -dr com.apple.quarantine`, the data location, "not yet tested, reports welcome").
  - New `docs/BUILD-MACOS.md`: tools, build, Intel cross-build, what to send back.
  - SECURITY.md: the macOS data location, and a section on unsigned binaries.
  - The bug template asks for macOS version and chip.
  - The release checklist is for `v0.4.0-rc2`, with 13 assets, the macOS jobs, and a note that private-repo macOS minutes count 10×, with a step that cancels the duplicate `main` run.
- **check-private `--root <folder>`:** checks every file in another folder, such as the export, with this repo's denylist. A `.private-denylist` found there is itself a hit.

## 0.4.0-rc1 — 2026-11-13

Never tagged; its release notes became 0.4.0-rc2's.

### Maintainer notes: R10 (publication docs and the release candidate)

- **D3 = move:** `KICKOFF.md`, `docs/ROUND1.md`, `docs/MANUAL-CHECK-R7.md` and `docs/PUBLISH-BRIEF.md` are now in `docs/development/`, with a README there. Every reference to them is updated (code comments in `mci-core`, `src-tauri`, `DECISIONS.md`, the docs themselves). The older entries in this changelog keep the old paths, as history.
- **LICENSE** is the full Apache-2.0 text with the copyright notice. **NOTICE** covers xterm.js (MIT) and `crates/charon-ssh`.
- **README.md** is rewritten for users: download, portable use, convert only, install, what's written on the appliance, backups, rollback and cleanup, Charon, platforms, SmartScreen, building, the fake appliance.
- **New:**
  - `SECURITY.md`: reporting, what's stored locally, what's written on an appliance, the decrypted key in exports, host keys;
  - `CONTRIBUTING.md`: the four rules and every test tier;
  - `.github/ISSUE_TEMPLATE/`: a bug report and a feature request, blank issues off;
  - `reference/README.md`: the frozen 0.2.1 spec, not for production. It's outside `reference/python/`, which stays untouched.
- **docs/RELEASE-CHECKLIST.md** (PowerShell), with Travis's change: CI is tested first in a private repository with `v0.4.0-rc1`, whose draft release is then deleted. Only after the Linux build, manual section B and the real-appliance check does it bump to 0.4.0, amend the single commit, tag `v0.4.0`, make the repository public and publish.
- **Release workflow:**
  - a tag with a `-` (`v0.4.0-rc1`) makes a prerelease draft; the tag must still equal `v` + the app's version;
  - asset names have no spaces. Tauri names bundles "Morpheus Certificate Install_…", and GitHub would turn the spaces into dots, so they no longer matched `SHA256SUMS`;
  - `scripts/release-notes.mjs` stops at `<!-- end of release notes -->`, so these maintainer notes stay out of the release.
- **`npm run export-tree -- <folder>`** (`scripts/export-tree.mjs`): copies the tracked tree into the publish folder. When that folder is a git checkout, it clears everything except `.git` first, so `git add -A` also records removed files.
- **`npm run bump`:**
  - now refreshes `Cargo.lock`'s workspace entries (`cargo update --workspace --offline`). Before, a bump left the lock stale, which `--locked` (CI, the fresh-clone check) rejects;
  - the stamp pattern no longer swallows a full stop after a prerelease version ("0.4.0-rc1." lost its "." in one file).
- `.gitignore`: the comment no longer mentions the charon-ssh source replacement.
- The version is `0.4.0-rc1`, so the rc tag matches it. The NSIS installer builds with it locally (`Morpheus Certificate Install_0.4.0-rc1_x64-setup.exe`, file version 0.4.0-rc1). Whether the rpm bundler accepts a `-` in the version is first tested by the CI rc run.

## 0.3.21 — 2026-11-12

Before R9 (Travis's list), then R9: packaging and CI. Decisions D1 = A (copy charon-ssh in), D2 = drop the Dockerfile, D3 = move the dev docs (R10).

- **The GoDaddy bundle as test data:** `gd_bundle_dv-r1-g2.crt.pem` moved from the repo root to `src-tauri/testdata/public-roots/` (public CA certificates). `trust::tests::the_godaddy_bundle_is_publicly_trusted` checks two cases, both "Publicly trusted", unticked:
  - the intermediate plus "GoDaddy TLS Root CA – R1" cross-signed by G2, without G2 itself;
  - the whole bundle.

  The intermediate alone comes out private, because its issuer (R1) is in neither store.
- **check-private reads certificates.** Before, names inside base64 were invisible to it (the real certificate left in the repo root passed).
  - It decodes every PEM block of any type, and every base64 run of 120+ characters (a certificate in JSON), and checks the bytes.
  - It parses every certificate it finds (a PEM block, a DER file, or one inside base64) and checks the subject, issuer and SAN, reporting the certificate by its subject.
  - `npm run check-private:self-test` builds certificates in-process that name a denylist entry in the subject, the issuer or the SAN. Each is caught as PEM, as PEM inside a JSON string, and as base64 in JSON. A certificate with only example names passes, and so do the public GoDaddy, Go Daddy G2 and ISRG files.
  - Also tested by planting a DER `.crt` and a PEM in the tree: both were caught by the SAN, then removed.
  - The `.gitignore` walk is now shared with the fresh-clone check (`scripts/tracked-files.mjs`).
- **charon-ssh is part of this repository (D1 = A):** `crates/charon-ssh`, a workspace member, `charon-ssh = { path = … }`.
  - It's the code of rev `e7f7fd1` (0.1.0 + patches 0001–0009), taken from the local publish repo's HEAD (`f22312c`, the same commits rewritten). The only difference is one test's user name, made generic there. The crate's own `Cargo.lock` and `.gitignore` were left out, and line endings are LF.
  - Its 13 unit tests and the doctest run in the workspace (`cargo test -p charon-ssh`).
  - `npm run bump` leaves it at 0.1.0.
  - The source-replacement mechanism is gone: `.cargo/config.toml.example`, the local `.cargo/config.toml`, and the git URL and rev in `Cargo.toml`/`Cargo.lock`.
  - `docs/CHARON-SSH-CHANGES.md` starts with the rule that this copy and Charon's are kept in sync by hand. CLAUDE.md's charon-ssh rule now says to change `crates/charon-ssh` and record a patch, instead of "don't fork the crate into this repo".
- **Fresh-clone check** (`npm run fresh-clone-check`): copies the tracked files into a temp folder (no `target`, `node_modules`, `.cargo/config.toml` or generated icons), then runs `npm ci`, `npx tauri icon …` and `cargo build --locked --workspace` there. The icons step is needed because the icons are gitignored, as the README's build steps already said.
- **Dockerfile dropped (D2):**
  - `tests/fake-appliance/Dockerfile` and `entrypoint.sh` are removed, along with the Docker section and mentions in `docs/FAKE-APPLIANCE.md`, the README layout line and the bump script's file list.
  - `rotate-host-keys` lost its Docker branch.
  - Comments in `install-on-vm.sh`, `morpheus-ctl` and `ssh_fake_appliance.rs` were reworded; `MCI_TEST_NO_SYSTEMD` stays for a host without systemd.
  - No need to rerun `install-on-vm.sh`: the VM's behaviour doesn't change.
- **Portable smoke test** (`npm run portable-smoke`, after `npm run portable`):
  - unpacks the archive into a temp folder and starts the exe;
  - on Windows, over CDP: the page loads, shows this version and reports portable mode;
  - `data/` and `data/webview/` appear beside the exe;
  - nothing new or changed at the top of `%APPDATA%` / `%LOCALAPPDATA%`, or inside the installed app's own folders there;
  - closes the window;
  - runs the CLI's `--version` and one `convert`.
- **Fixed: the CLI's `--version` printed to stderr.** It exited 0 but printed to stderr, so `$(… --version)` came back empty; the smoke test caught it. It now prints to stdout, as the Python reference's argparse does. Usage errors still go to stderr with exit 64. Test: `cli::version_goes_to_stdout_and_usage_errors_to_stderr`.
- **docs/BUILD-LINUX.md:** Fedora packages, build, smoke tests (portable, AppImage, rpm, deb), and what to send back.
- **CI** (`.github/workflows/build.yml`):
  - `test`: `cargo audit` on the whole workspace's lock; `cargo test --locked --workspace`; the unzip-mode check (key 600); the UI contract.
  - `bundle`, no longer gated: Windows NSIS, the portable zip and the CLI; Linux deb, rpm, AppImage, the portable tar.gz and the CLI. Both generate the icons first.
  - `release`, on tags `v*`: checks the tag matches the version, builds `SHA256SUMS`, and creates a **draft** release whose notes are that version's CHANGELOG section (`scripts/release-notes.mjs`).
  - check-private doesn't run in CI (the denylist is local).

## 0.3.20 — 2026-11-12

R8: click tests, the real app driven through its page. They found three bugs in the page, fixed here.

- **Click tests** (`tests/click/`, `npm run test:click`, Windows; see `tests/click/README.md`).
  - The debug exe runs from a fresh temp portable folder per suite (its own settings, known_hosts and WebView2 profile), and is driven over CDP (`WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--remote-debugging-port=…`): real mouse clicks and typing, files through the page's own file input, dialogs answered by clicking. Plain Node, no packages, no browser download.
  - A suite fails if the page logs a browser error (a CSP violation, an uncaught exception).
  - Without an appliance: `convert`, `wildcard`, `public-chain`, `errors-and-watch`, `leave-no-trace`, `release-hooks`.
  - Against the fake VM (`MCI_TEST_SSH`): `vm-install` (TOFU dialog → plan → install → verify green → rollback), `vm-hostkey-mismatch` (pre-seeded wrong keys; the VM's key isn't rotated), `vm-cleanup` (a run still going is kept), and the opt-in `screenshots`.
  - The VM is checked over a separate SSH connection: `src-tauri/tests/click_ref.rs`, an ignored test that runs the harness's script as root.
- **Test-only hook** (debug and test builds only, `cfg(debug_assertions)`): `MCI_TEST_SAVE_DIR` makes the zip export write there without the save dialog. Nothing else skips a confirmation. `release-hooks` checks that the release exe doesn't contain it.
- **Fixed: the Tauri build's CSP blocked every inline style.** Tauri adds a nonce to `style-src`, and a nonce makes the browser ignore `'unsafe-inline'`. As a result:
  - the Run log ignored its terminal theme. Its text took the page's colour, which on a light Windows theme is dark grey on the dark terminal, nearly unreadable, and no ANSI colour showed (cyan steps, red failures, green ✓);
  - the chain view's lifetime bars were always full;
  - the dialog title's margin was lost.

  `tauri.conf.json` now sets `dangerousDisableAssetCspModification: ["style-src"]`: Tauri leaves `style-src` as written (`'self' 'unsafe-inline'`), and scripts keep their nonces and hashes. The CSP itself is unchanged.
- **Fixed: "Trust this CA" kept a stale value** (PARITY 28, 31).
  - An analysis without a server certificate never set the box, so after Clear files it kept the previous chain's tick and reason.
  - The trust default for that case said "No CA certificates were supplied", although CA certificates had been supplied.
  - Now every analysis sets the box and its reason. Clear files unticks the box and clears the reason. With no leaf, every supplied CA is judged (`trust.rs`), so the Go Daddy G2 root alone comes out "Publicly trusted", unticked.
- **Fixed: the changed-host-key message** told the user to edit `~/.morpheus-certificate-install/known_hosts`. This app doesn't keep known_hosts there. It now says: check the fingerprint on the appliance, click "Forget this appliance", and connect again. The suite follows that advice and gets the TOFU dialog again.
- **Seen, left as is:**
  - A wrong PFX password shows on the file's row and as an error check, not as a toast, the same as the Python page. The suite tests it that way.
  - The plan's "Verify" step never gets a done/failed mark (the Python doesn't emit one either); the verify result shows in step 4.
- **Screenshots** for the README: `docs/screenshots/{connect,chain,plan,run,verify,cleanup}.png`, 1320×860, light theme, corpus certificates.
  - The lab address and hostname are swapped for `192.0.2.10` / `appliance.example.com` in the page's text just for each capture, then put back.
  - Before each capture the page's visible text is checked against `.private-denylist`.
- **Tests:** `trust::tests::without_a_server_certificate_the_supplied_cas_decide`.

## 0.3.19 — 2026-11-08

Fixes from the manual check (section A, partly done).

- **"Trust this CA" default** (PARITY 28, `src-tauri/src/trust.rs`):
  - A chain is public if ANY CA in it is a Mozilla root or is issued by one. "Any CA" covers the chain plus supplied CA certificates that are other forms of a chain CA (same subject and key, i.e. cross-signed copies). The comparison uses subject and key, both raw from the certificate's DER; "issued by" needs a verified signature.
  - The GoDaddy chain was ticked because the chain walk ended at the self-signed "GoDaddy TLS Root CA – R1", which Mozilla doesn't list. 0.3.17–0.3.18 looked only at that root, and G2 (or R1 cross-signed by G2) was never consulted.
  - This is my reconstruction: the old code does match G2 when G2 is the root. Confirm with your chain (see the report).
  - Tests use real public roots, ISRG Root X1 and Go Daddy G2, as test data in `src-tauri/testdata/public-roots/` (taken from Mozilla's list via the `webpki-root-certs` crate): off. The corpus private root: on. A stand-in OS-store root, and on Windows a real OS-only root (GlobalSign Root CA): on.
- **Rollback restores /etc/morpheus/ssl exactly** (PARITY 29). After the restore it removes the `.crt`/`.key` the rolled-back install wrote (from its manifest) that the backup lacks, shredding the key (`appliance::rollback_remove_installed`).
  - New ledger `/var/lib/morpheus-certificate-install/installed.json` (root 0600) records every certificate and key file installed, and survives backup removal. In the golden sequence that's a read and a write after the key match, recorded as an `insert` in make-cases.py's override.
  - Cleanup has a new option, off by default: remove ledger files morpheus.rb no longer names, keys shredded. Only `/etc/morpheus/ssl/<name>.crt|.key` the ledger lists can be named.
- **Run log** (PARITY 30): tool steps (backup, key match, runner launch, restore, cleanup) show stdout only, and stderr only when they fail. sudo's lecture no longer appears on a successful run.
- **Verify wording:** a self-signed certificate, or a CA certificate served as the leaf, is said in plain words ("the appliance serves a self-signed certificate (…): browsers, agents and hosts won't trust it. Install a CA-signed certificate (steps 2 and 3)."). The appliance-side line marks "(self-signed)".
- **Tests:**
  - mci-core: ledger goldens and a bash run.
  - src-tauri: trust with real roots, the ledger plus rollback removal (`engine::tests`), unused installed files, the plain-words verify.
  - `engine_e2e`: after rollback the installed `.crt`/`.key` are gone, the key shredded, the earlier files byte-identical, and the ledger updated. The Run log has the key match's stdout and no lecture. Verify-before says "self-signed".
  - `cleanup_end_to_end`: an install for the IP SAN, then one for the name; unused installed files go only when asked; files the ledger doesn't list are untouched.
- **Live** over SSH against the cleaned fake VM:
  - `engine_end_to_end` passed (35 s).
  - `cleanup_end_to_end` passed (38 s). Built in a separate target dir, because the app's exe was running (your manual check).
- `install-on-vm.sh` only got its version stamp; no need to rerun it.

## 0.3.18 — 2026-11-08

- **"Trust this CA" default (PARITY 28):** a root found only in this computer's certificate store now defaults to **on**. It's most likely the organisation's own CA, which Morpheus' Java doesn't have. The box is off only for a root among the built-in Mozilla roots. The reason under the checkbox says which case applies: "Only in this computer's trust store, not in the public roots: likely your organisation's own CA …".
- **Tests:** `trust::tests::a_root_only_in_the_os_store_is_ticked` checks the three cases. On this machine it also ran against a real root that Windows has and Mozilla doesn't (GlobalSign Root CA), which comes out ticked.
- **Live, over SSH, against the refreshed fake VM** (user `mcitest`):
  - `engine_end_to_end` passed (34 s). It now includes the wildcard suggestion: the VM's hostname plus `.wild.test`.
  - `cleanup_end_to_end` passed (25 s). The inventory found 5 scripts, 10 logs, 5 backups and the staging dir. The defaults removed 56 paths and shredded 7 keys, kept the newest backup, and touched nothing else. "All backups" warned, then removed every backup.

## 0.3.17 — 2026-11-08

The fixes from the manual check (section A), the repo scrubbed of my lab environment, and cleanup for customers.

- **Manual-check fixes:**
  - **Wildcard leaf** (PARITY 27). A name containing `*` is never the FQDN: not for verify, SNI, file names or INSTALL.txt.
    - Connected: `analyze_with_hosts` suggests the preflight `hostname -f` if the certificate covers it, else the short hostname plus the wildcard's domain, with an amber note.
    - Otherwise: the error "Wildcard certificate: enter the appliance's FQDN." blocks export and plan until a covered name is entered. `verify` refuses a wildcard name.
    - Corpus: `leaf-wildcard.crt` (`*.wild.test` plus the apex), its key and `wildcard-root.crt`, added additively. Cases `wildcard-leaf` and `wildcard-fqdn-typed` carry overrides; `wildcard-fqdn-given` matches the reference.
  - **"Trust this CA" default from the actual root** (PARITY 28, `src-tauri/src/trust.rs`). The default checks the chain's root, or the top CA's issuer when the root is missing:
    - in the built-in Mozilla roots: off, "Publicly trusted: Morpheus' Java already trusts it.";
    - only in this computer's store: off, with a note that it may be the organisation's own CA;
    - otherwise on, "Private CA: …".
    - The analysis JSON gets `trust_default`, `trust_reason` and `trust_store`. The page shows the reason under the checkbox, and the CA-name regex is gone.
  - **Chain view:** links shrink to fit, with smaller seals when there are more than three; no sideways scroll.
  - **Watch bar:** `[hidden]` now always hides. `.watch{display:flex}` had overridden it, and the reference page has the same bug.
- **Scrub (A):**
  - Lab names, addresses, the local user, paths, host-key fingerprints, Charon session ids and the e-mail in the patch headers are replaced throughout: code, UI placeholders, docs, tests, fixtures, the fake appliance and the reference copy. Replacements: `morpheus.example.com` / `appliance.example.com`, `192.0.2.10` / `198.51.100.x`, test user `mcitest`, the starting certificate `appliance`.
  - The fixtures were regenerated from the scrubbed reference. Changes beyond the names: `generated_at` and the day counts; `file_base` `appliance_cust_test`; the morpheus.rb goldens and the apply sequence's sizes (`198.51.100.20` is one character shorter); the runner goldens' `OPU=mcitest`. The reference's own tests pass (23), and so do parity and goldens.
  - **charon-ssh pin.** `Cargo.toml` and `Cargo.lock` name `https://github.com/builtbyfood/charon-ssh` at the same rev. A gitignored `.cargo/config.toml` (template: `.cargo/config.toml.example`) replaces that source with the local clone; Cargo's source replacement keeps the public URL in the lock.
    - A fresh copy (no `target`, no local files) builds with `--locked` once the config is copied in.
    - Without the config, Cargo stops trying to reach the not-yet-public repository.
    - The lock's source line was rewritten by hand: Cargo can't write it while the URL doesn't resolve.
  - **`npm run check-private`** (`scripts/check-private.mjs`) fails on any entry from the gitignored `.private-denylist` (example: `.private-denylist.example`). It checks file names and contents, binaries included, and skips gitignored paths. It reports clean now, and a planted hit made it fail.
  - **CLAUDE.md:** example names to use, the check before every report, and patches stored without the author e-mail.
- **Cleanup for customers (B):**
  - **Step 5, "Clean up this appliance".** It lists runner scripts, run logs, backups (with how many key files each holds) and the Charon staging dir, with sizes and dates.
    - Defaults: scripts and logs on, staging dir on, backups except the newest on; all backups off, with the rollback warning.
    - One confirm dialog lists exactly what will go. It runs as a job, and the Run log shows each "shredded …" and "removed …".
    - Every file in a removed backup is shredded, and so is everything in the staging dir.
    - A run that may still be going (no `.rc`, log written in the last 15 minutes) is never removed.
    - Commands come from `mci_core::appliance::cleanup_*`. They name each path, refuse names that could leave our dirs, don't follow symlinks, and only `rmdir` our own dirs when empty. Golden strings are in `tests/golden_cleanup/`, plus a real-bash test on a temp tree.
  - **"Forget this appliance"** (step 1) removes its known_hosts line (charon-ssh's `HostKeys::forget`) and its settings; `mode` and `charon_dir` stay. If connected to it over SSH, it disconnects first.
  - **Portable "Leave no trace"** (step 1, off by default, only shown in portable mode).
    - While it's on, nothing is written to settings.
    - At exit the data folder (settings, known_hosts, webview profile) is deleted, retrying for 5 s.
    - If that fails, a marker is left; the next start deletes the folder before the webview starts and shows a message either way.
  - New commands: `cleanup_list`, `cleanup_plan`, `cleanup`, `forget_appliance`, `set_leave_no_trace`. `state` adds `portable`, `leave_no_trace` and `notice`. `ui/bridge.js` and `tests/ui-contract/bridge.cjs` are updated.
- **Tests:**
  - mci-core: wildcard suggestion; cleanup goldens and the bash run.
  - src-tauri: trust default, cleanup selection and parsing, leave-no-trace deletion.
  - `tests/commands.rs`: wildcard flow, trust fields, forget, leave no trace, cleanup without a connection.
  - `engine_e2e`: a live wildcard suggestion check, and a new `cleanup_end_to_end`. The two live tests take a lock so they never run at once.

## 0.3.16 — 2026-11-08

R7 fixes before the manual check.

- **Charon follow is a long poll.**
  - `appliance::charon_long_poll(log, rc, off, wait_s)` waits on the appliance, checking every 0.5 s, until the log grows past the offset, the rc file has content, or `wait_s` pass. Then it runs the reference's `charon_poll` unchanged.
  - The transport uses 90 s (`LONG_POLL_S`, under Charon's 120 s limit) and polls again at once. A stop request abandons the poll in flight.
  - Golden tests: `charon_long_poll_command` checks the exact string. `charon_long_poll_in_bash` checks timing in real bash: it returns at once on existing data and within about a second when the log grows or the rc appears; with nothing new it waits the full time.
  - Mock test: a 24 s runner (a line every 8 s) is followed with **4 polls**. The 2-second polling would have made about 16. The mock now counts its polls in `run_command.log`.
- **Notice when Charon asks for approval.**
  - At any tier other than trusted, connecting logs that every command needs approval in Charon.
  - Each run (apply, rollback, re-attach) logs that each update needs approval, with the `tail -n +1 -F …` line to use in the Charon tab.
  - These are log events, so the page is unchanged. Tested in `engine::tests` (exec-approve gets the notice, trusted doesn't).
- **apply reads morpheus.rb and runs the guard before writing anything.** On refusal nothing is written: no backup, no `.crt`/`.key`, no morpheus.rb, no runner.
  - The edit is made from that text, and the later re-read is gone.
  - The golden sequence carries the change as `rust_expect_override`: make-cases.py records it, and the fixtures were regenerated. Only that file's new key and `cases.json`'s `generated_at` and day counts changed.
  - The e2e checks for no new backup and an untouched `.crt`/`.key`. PARITY divergence 19 is updated.
- **verify uses the OS store too.**
  - Stores are tried in this order: the supplied root, the OS store (`rustls-platform-verifier`, so the OS builds the chain), then the built-in roots.
  - The result reports which one verified, as `trust_store` and in the summary: "(using the supplied root)", "(OS trust store)" or "(built-in trust store)".
  - The Morpheus API check uses the same stores.
  - I tried `rustls-native-certs` first. It couldn't verify www.example.com, because Windows' ROOT store only fills as roots are fetched.
  - Divergence 23 is updated; 24–26 needed no change.
  - New dependency: `rustls-platform-verifier` 0.6 (no aws-lc).
- **`rotated_host_key_is_refused` runs only with `MCI_TEST_ROTATE=1`,** even unfiltered. README and FAKE-APPLIANCE.md say so.
- **CLAUDE.md:** ask Travis which session and tier to use before any live test through Charon, and never use a session just because it's open.
- **`MANUAL-CHECK-R7.md`:** the Charon sections now have the read before the backup, one dialog per update and the notice. There is an optional OS-store check against www.example.com.
- **Verified:**
  - `cargo test --workspace`, `npm run test:ui-contract`, the network-gated OS-store test, and `charon_mock` (4 polls).
  - `engine_e2e` over SSH against fake-appliance.
  - Through Charon (session mcitest@192.0.2.10): the first try found it at exec-approve, so both tests stopped at their tier check before sending anything. After you set trusted, `charon_live` passed (follow to rc 5 in 3.1 s with long polls), and so did the `engine_e2e` Charon core (apply → verify → rollback).
  - The rotation test skips without the variable.

## 0.3.15 — 2026-11-08

**R7: commands, jobs, verify, the Morpheus API.** It was tested live over SSH and through the real Charon. The click-through for you is in `docs/MANUAL-CHECK-R7.md`.

- **Before R7:**
  - `charon_live` runs `sudo -k` before the morpheus.rb read, so that read really prompts. The fake has lecture=always. The exact-bytes check now passes through real sudo noise: the display read is 695 bytes with the lecture, and the data read is still the file's 347 bytes.
  - `docs/DECISIONS.md` and `.cargo/audit.toml`: RUSTSEC-2023-0071 is closed as accepted, and it covers `rsa` 0.10-rc in russh too.
- **`src-tauri/src/engine.rs`** is a port of `app.py`'s handlers and `engine.py`'s preflight, plan, apply, verify, runs, backups and rollback. Request and response bodies are the Python's, and events are `events.rs`.
  - **Jobs:**
    - one job at a time ("Another operation is running…");
    - `stop` stops following, not the remote run;
    - job running, done and error go on `mci`;
    - a panicking job still clears busy and reports.
  - **Data reads** all go through `reads.rs` (`run_data`). New: `reads::morpheus_rb_opt` for preflight.
  - **The morpheus.rb guard is on every write:**
    - plan builds the new text with `transform_checked`;
    - apply re-reads with `morpheus_rb_for_edit`;
    - rollback checks the backup's copy first.
  - **Settings** keep only the ten allowed keys. Secrets stay in memory.
- **`verify.rs`:** the local TLS check uses rustls with `ring`. It makes two connections: one that only reads the served leaf, then a verifying one (built-in roots plus the supplied root, with the name check). Failure reasons are in words.
- **`morpheus_api.rs`:**
  - `whoami` and `appliance-settings` GET and PUT, with the token in a Bearer header only;
  - TLS verified first, then unverified on a TLS error;
  - hyper's nested io::Errors are opened to find the rustls cause.
- **`fetch.rs`:** the app's AIA getter has the same contract as the CLI's.
- **`mci_core::formats::certs_from_pem_text`** reads the served chain (`openssl s_client -showcerts` output). `InputFile` derives Clone.
- **App setup (`lib.rs`):**
  - `configure()` builds the app for any runtime, the real one or MockRuntime;
  - state is made in a small plugin, because the app's own `.setup` only runs with an event loop;
  - the window is built in code (`"create": false` in tauri.conf.json), so portable mode can give the webview its own profile under `./data/webview`;
  - `export_zip` takes its path from the save dialog, or from a test hook.
- **`build.rs` + `windows-app-manifest.xml`:** the comctl32 v6 manifest is embedded in every binary of the package. Without it, the tauri::test binaries fail on Windows with STATUS_ENTRYPOINT_NOT_FOUND.
- **Dependencies:**
  - `rustls` and `tokio-rustls` without default features, on `ring`. This drops `aws-lc-rs`/`aws-lc-sys` from the tree.
  - dev-dependency `tauri` with `test`.
- **Tests:**
  - `engine::tests`: apply against `fixtures/golden/apply-command-sequence.json` with a recording transport. That covers op order, sudo, commands, paths, modes, dir modes, sizes and hashes; manifest and runner sizes are allowed the version-length difference. A mutation, the trust dir mode set to 0700, fails it. Also the guard at plan and at apply, rollback's backup check, plan shape, and runs/backups parsing.
  - `tests/commands.rs`: every command on MockRuntime with its events, against a local TLS server. Covers analyze, export (saved and cancelled), settings keys, errors before connecting, verify as a job (event order, supplied root, unknown issuer, the 8 s timeout), one job at a time, and the API token never reaching disk or events.
  - `tests/engine_e2e.rs` (from R8): the whole flow through the commands against fake-appliance, listed under Verified.
- **Fake appliance:**
  - `fake-nginx.py` now also answers `GET /api/whoami` and `GET` and `PUT /api/appliance-settings` for the test token `mci-fake-api-token-7f3c9a1e`. It answers 401 with no token or a wrong one. The TLS handshake runs in the handler thread.
  - `install-on-vm.sh` checks 200 with the token and 401 without, installs curl, and retries the 443 check for up to 10 s; that check failed once on a slow start.
  - The Dockerfile installs curl and notes the API.
  - It is deployed to fake-appliance.
- **`scripts/bump-version.mjs`** also stamps `.py`, `.xml` and the fake appliance's extensionless scripts (keytool, morpheus-ctl and the Dockerfile still said 0.3.13).
- **Docs:**
  - `PARITY.md`: the status table; divergence 19 extended to plan and to the apply-time case; new divergences 23–26 (trust store and reasons, the Appliance URL PUT error, no `ts` or replay, port checks).
  - `FAKE-APPLIANCE.md`: the fake API, the e2e commands, a warning about the rotation test.
  - README test commands.
  - ROUND1 (engine e2e done in R7).
  - New: `MANUAL-CHECK-R7.md`.
- **Verified:**
  - `cargo test --workspace` passes, and so does `npm run test:ui-contract`.
  - Live against fake-appliance:
    - `engine_e2e` over SSH. It covers convert, connect with TOFU, preflight, verify before, plan and apply to rc 0, the served fingerprint, local verify with SNI m.cust.test and the supplied root, and the API with the test token (GET and PUT, 401 for a wrong one). Then permissions, the leak grep, a second apply leaving one managed block, the legacy sphragis block replaced, rollback (starting certificate back, CA aliases and PEMs gone), and the guard at plan and at apply.
    - `engine_e2e` through Charon (apply → verify → rollback).
    - `charon_live`, `charon_mock`, and `ssh_fake_appliance` (the transport test).
- **Not verified:**
  - the window itself: nothing was clicked (`MANUAL-CHECK-R7.md`);
  - Charon at exec-approve, approve and deny;
  - portable mode;
  - the Docker image (no Docker here);
  - a Mac.
- **Host key:** `rotated_host_key_is_refused` ran by accident, so fake-appliance's SSH host key is now `SHA256:<the VM's rotated host key>`.

## 0.3.14 — 2026-11-08

**R6 closed.** The live run against the real Charon passed. The session was `mcitest@192.0.2.10` (<session id>), opened from Charon's connection list at the trusted tier. No code changes this round.

- **`charon_live` passed every step (5.97 s):**
  - discovery found 17 saved ssh hosts with no credential field and 8 open sessions;
  - sudo mode is `charon`, and `id -un` under sudo is `root`;
  - `morpheus.rb` read through Charon matches the exec-channel read byte for byte, and the tricky bytes survive;
  - stderr and rc come back separately;
  - put_root sets the modes (644/755/600, root:root), and the staged copy is shredded even when the install fails;
  - follow reads the log to rc 5 in 4.1 s, with nothing from the terminal;
  - the leak grep finds no password, and does find a planted copy;
  - `charon.db` is unchanged.
- The earlier `mcitest@fake-appliance` prompt was an ssh inside the `admin` tab, so Charon couldn't see it as a mcitest session. Then the new session was at exec-approve, and the test stopped at the tier check before running any command.

## 0.3.13 — 2026-11-08

R6 still open: Charon has no SSH session logged in as `mcitest` (see the report).

- **`charon_live.rs`:**
  - `MCI_TEST_CHARON` is a session id, or `user@host`, which matches the session's host field and the user at the start of its title (so `mcitest@192.0.2.10:2222` titles match too);
  - on a miss it prints everything `list_sessions` returned (id, title, host, kind, tier for each).
- **Finding:** the `mcitest@fake-appliance` prompt is inside the `admin` Charon session. The VM's only connection from this machine on port 22 is that session, and a VM-to-itself SSH connection exists. Charon lists no mcitest session.

## 0.3.12 — 2026-11-08

R6 follow-up. R6 is **still open**: the live run against the real Charon can't find the trusted `mcitest@192.0.2.10:2222` session (see the report).

- **Framed reads clean up on every exit path the shell can see:**
  - stdout is held in a shell variable, never a file;
  - the stderr file (0700 staging dir) was removed only by `trap … EXIT`, which bash skips when killed by SIGHUP or SIGTERM;
  - HUP/INT/TERM, what a timeout sends, now become exits (129/130/143), so the EXIT trap runs.
  - SIGKILL can't be trapped, so each read first deletes `mci-err-*` files older than 10 minutes in the staging dir. A fresh file belonging to another read in flight is left alone.
- **New test `charon_data_read_cleans_up_on_timeout_and_kill`,** in real bash:
  - a framed `sleep 3` cut off after 1 s with each of HUP, INT and TERM leaves nothing behind;
  - SIGKILL leaves the file, and the next read sweeps it once it is 10 minutes old while keeping a fresh one.
  - With the signal traps taken out, the test fails.
- The Charon mock test passes again against the VM with the new frame.
- Removed three temp folders my failed mock runs had left in `%LOCALAPPDATA%\Temp`.

## 0.3.11 — 2026-11-08

R6: the Charon MCP transport, plus housekeeping. The live run against the real Charon has done discovery only: Charon has no trusted session to `mcitest@192.0.2.10:2222` open yet.

- **Housekeeping:**
  - CLAUDE.md: no transport or engine round closes without a live run against the fake appliance.
  - FAKE-APPLIANCE.md: fake-appliance is Ubuntu 26.04 switched to classic sudo; the suite also passed on sudo-rs. `update-alternatives` commands for both directions.
- **The rc -2 fix is pinned by a unit test.** The read loop moved into `pump()`, tested with a channel. The output arrives late on purpose, because with everything queued `select!` could hide the bug. With the old behaviour put back, the test fails 3/3.
- **`transport/charon_mcp.rs`:**
  - JSON-RPC to Charon's MCP server;
  - discovery (data dirs in the reference's order, endpoint, open sessions);
  - saved hosts from `charon.db`, read-only, using only `json_extract` of host/port/user/jump_host/tags, so a credential never reaches the app (divergence 22);
  - `run` with CR stripped; sudo detection;
  - `put_root` through the 0700 staging dir, with the staged copy shredded whatever happens;
  - `follow`.
- **Framed data reads** (`appliance::charon_data_read` and `parse_charon_data_read`, golden-tested, divergence 21):
  - stdout as base64 between `@@MCI-<nonce>` markers;
  - stderr via a file in the staging dir, always removed;
  - the exit code last.
  - The frame is printed after the command finishes, so sudo's tty output can't get inside it. Markers are printed with `printf` so a terminal's echo of the command can't fake them, and the command keeps the session's umask.
  - A real bash round trip checks exact bytes (CRLF, NUL, UTF-8), stderr, rc, file cleanup and the umask.
  - Follow's polls use the frame too.
- **`tests/mock_charon.py`** is a copy of the frozen reference mock, extended:
  - an `--ssh` mode that behaves like Charon (a PTY to the fake VM, answering sudo, SFTP for `sftp_put`);
  - terminal noise in both modes: CRLF, an echoed command, OSC 133 marks, a colour code, and in local mode the sudo lecture and prompt.
- **`tests/charon_mock.rs` passes in 8.5 s:**
  - discovery (hosts inherited, no credential, `charon.db` unchanged);
  - morpheus.rb through Charon equals the exec-channel read byte for byte (89 bytes, against 598 of terminal text with the lecture);
  - tricky bytes, and stderr/rc kept apart;
  - `put_root` modes and owners, with the staging dir empty after, **including when the install fails**;
  - follow to rc 5 with exactly the log text;
  - the leak grep, which finds the planted copy. Its pattern is a root-only file, never a command line, so the password can't reach Charon's history.
- **`tests/charon_live.rs`** runs the same steps against the real Charon. Discovery passed against this machine's Charon: 17 saved hosts with only whitelisted keys, 8 sessions. The session steps need a trusted session.
- **Fixed during the round** (each one found by the mock):
  - the frame was first printed before the command, so sudo's lecture landed inside it;
  - the frame's `umask 077` leaked into the wrapped command.
- **The SSH live test passed again** after the `pump` refactor, now with classic sudo's lecture on stderr and exact stdout.

## 0.3.10 — 2026-11-08

- **`install-on-vm.sh`: the password-login check works under `set -o pipefail`.**
  - The 0.3.9 probe piped `ssh` into `grep`. The refusal it looks for makes `ssh` exit 255, and under `pipefail` that failed the pipeline even when `grep` matched. On the VM, the same probe returned 0 without `pipefail` and 255 with it, while `ssh` showed `Permission denied (publickey,password,keyboard-interactive)` on both ports.
  - The probe now captures the output and then greps it. Checked here under `set -euo pipefail` with an `ssh` stand-in that exits 255.
- **The SSH transport bug the first live run found (fixed):** `raw()` created its stop channel as `let (_, stop) = …`, which drops the sender at once. `raw_stream` read the dropped sender as "stop", so **every `run`/`run_data` ended immediately as stopped (rc -2)**. Sudo detection only reported "password" by accident: both of its probes "failed".
  - Now the sender is held for the call (`_keep`), and a dropped sender only disables the stop branch.
  - `follow` was unaffected: its stop comes from the caller.
  - This had shipped since 0.3.5; no unit test could reach it without a server.
- **The fake VM is Ubuntu 26.04, whose `sudo` is sudo-rs 0.2.13.** sudo-rs prints no lecture (only a newline on stderr), so `lecture=always` has no effect there. The transport works with it unchanged: password detection, `sudo -k -S -p ''`, and stdout kept apart.
  - The live test now checks `run_data` stdout is exactly the data and merged = stdout + stderr, whatever sudo prints, and logs which kind of sudo it found.
  - `install-on-vm.sh` points out sudo-rs and the `update-alternatives` command for classic sudo; it doesn't switch.
  - The docs say 24.04 or 26.04.
- **Live tests against fake-appliance (192.0.2.10:2222), both passing:**
  - `ssh_transport_against_the_fake_appliance`: 25.7 s, then 25.4 s again after the key rotation;
  - `rotated_host_key_is_refused`: 0.6 s.
  - Afterwards the VM had no test files, units or aliases left.

## 0.3.9 — 2026-11-08

`install-on-vm.sh` fix after its first run on the VM (`fake-appliance`, 192.0.2.10). The check "sshd accepts passwords" failed. On the VM I found:

- **The drop-in was already first.** It's `00-mci-fake.conf`, which sorts before `50-cloud-init.conf`, so it wins. Password login *was* on: a key-less login to `mcitest` on 22 and 2222 was offered `publickey,password,keyboard-interactive`.
- **The check was broken.** It ran `sshd -T`, which refuses to run without `/run/sshd`, and that directory had just been removed:
  - the script stopped `ssh.service` right after restarting `ssh.socket`;
  - stopping the service deletes `/run/sshd`;
  - the socket restart had already started the service again, so the stop killed it mid-start, and `ssh.service` was left `failed` (journal: `Control process exited, code=killed, status=15/TERM`). sshd still started on the next connection.

Fixed in the script:

- No more `systemctl stop ssh.service`. `systemctl reset-failed ssh.service` first, so a rerun clears 0.3.8's failed state.
- `/run/sshd` is created before `sshd -t`. Without it, a rerun on the current VM would have stopped at `sshd -t` under `set -e`.
- The check asks the running server, on **both** ports, which login methods it offers. A key-less `ssh -o BatchMode=yes` never tries a password. A new check also makes sure `ssh.service` isn't failed.
- Any earlier drop-in of ours with another name is removed, so only `00-mci-fake.conf` remains. None exists today; this is just so reruns stay tidy.

## 0.3.8 — 2026-11-07

The fake appliance as an Ubuntu VM (the ESXi host has no Docker). Nothing has been run on a VM yet: no VM exists so far.

- **`tests/fake-appliance/install-on-vm.sh`** turns a fresh Ubuntu 24.04 VM into the fake appliance. Run it with `sudo` from the copied folder; it's safe to run twice.
  - The same stand-ins as the Dockerfile: `morpheus-ctl`, `keytool` with alias state, fake nginx on 443 as the systemd service `mci-fake-nginx`, the `/etc/morpheus` layout, `mcitest`/`hunter2` in sudo with `lecture=always`.
  - The VM keeps its own host keys.
  - sshd listens on 22 **and 2222**, so `MCI_TEST_SSH=<vm>:2222:…` is the same as for Docker. That's done through Ubuntu 24.04's `ssh.socket` generator, with a drop-in that wins over cloud-init's `PasswordAuthentication no`.
  - It keeps existing state (morpheus.rb, the certificate, aliases, runs, backups), warns about a NOPASSWD rule, and ends with a checklist, the host-key fingerprint and the test line.
- **`rotate-host-keys`** works on both:
  - VM: regenerates `/etc/ssh` keys and restarts only `ssh.service`;
  - Docker: the volume and the listener, as before.
- **`morpheus-ctl restart nginx`** restarts the systemd service on the VM.
- **Live test:**
  - preflight must report `SYSTEMDRUN=yes` (`MCI_TEST_NO_SYSTEMD=1` for Docker);
  - a stand-in runner is launched with the app's own `launch_runner(…, systemd=true)` and followed to rc 0;
  - it proves it ran as a unit (`$INVOCATION_ID`), and the unit is gone afterwards (`--collect`, `LoadState=not-found`).
- **`docs/FAKE-APPLIANCE.md`** puts the VM first (create, copy the folder, `sudo bash install-on-vm.sh`, snapshot, tests, rotation, reset by snapshot), then Docker. The Dockerfile is kept.

## 0.3.7 — 2026-11-07

charon-ssh pinned to a commit. The live SSH run is **still pending**: the message carried `<appliance IP>` as a literal placeholder.

- **Workspace dependency:** `charon-ssh = { git = "file:///path/to/charon-ssh-publish", rev = "e7f7fd1e060d774b678bd1ca9e5c1d2d6ed9cb40" }`.
  - The rev is HEAD of `charon-ssh-publish`: `e9f97f5` + patches 0001–0009. Its 10 files are identical to the dev tree the R5 gates ran on.
  - `Cargo.lock` records it: `source = "git+file:///…/charon-ssh-publish?rev=e7f7fd1e…#e7f7fd1e060d774b678bd1ca9e5c1d2d6ed9cb40"`. No path entry is left.
  - The app builds from it.
- **README → charon-ssh:**
  - it's a local-only pin;
  - how to move to a new rev (`git am`, new `rev`, `cargo update -p charon-ssh`, check `Cargo.lock`);
  - the `[patch."file:///…/charon-ssh-publish"]` override for working on the crate. Tested: with it, cargo uses the dev tree and the app builds; without it, the pinned rev.
- **Future crate changes** are patches in `docs/charon-ssh-patches/` numbered from 0010 (CHARON-SSH-CHANGES.md, CLAUDE.md).
- **DECISIONS.md, under the `crypto-bigint` entry:**
  - russh 0.65 brings in the newer RustCrypto generation (`der` 0.8, `elliptic-curve` 0.14 with `crypto-bigint` 0.7.10).
  - Only `rsa`, `pkcs1` and `ssh-key` there are still pre-release.
  - Revisit moving mci-core to it once `rsa` 0.10 is stable. That drops the duplicate stack and the RUSTSEC-2026-0387 ignore.
- **CI:** unchanged. The bundle job stays off (`CHARON_SSH_PUBLISHED` unset), and the core job builds only mci-core and mci-cli.

## 0.3.6 — 2026-11-06

R5 follow-ups that need neither the charon-ssh commit nor the appliance.

- **Data reads use stdout only.**
  - `Transport::run_data` returns `DataOut { rc, stdout, stderr }`. stdout is the data; stderr is kept for error messages only.
  - It's implemented for SSH; Charon is R6.
  - `src-tauri/src/reads.rs` has the reads the engine will use (R7): morpheus.rb, its stat mode, preflight `KEY=VALUE`, `served_chain`, `list_runs`, `list_backups`, manifests and the backup's morpheus.rb.
  - Unit-tested with a fake transport that puts sudo's real lecture on stderr, including a test showing the same reads through merged output would be wrong.
  - `Transport::run` keeps merged output for display.
  - The SSH transport now decodes each stream separately.
- **morpheus.rb write guard** (divergence 19):
  - `morpheus_rb::guard` / `transform_checked` refuse text without a non-comment `appliance_url` line, with a clear message and nothing written.
  - Apply uses `reads::morpheus_rb_for_edit`. Rollback reads the backup's morpheus.rb first (`appliance::cat_backup_morpheus_rb`, new) and refuses to restore a bad one.
  - `appliance::cat_manifest` is the reference's manifest read, verbatim (golden-tested).
- **Divergence 20 recorded:** the reference merged stderr into every read.
- **Fake appliance:**
  - sudo's lecture on every prompt, on purpose;
  - a stateful `keytool` (import adds, delete exits 0/1 like the real one), tested locally;
  - host keys made by the entrypoint only if missing, in a `/etc/ssh/keys` volume;
  - `rotate-host-keys` replaces them and restarts only the sshd listener.
- **New ignored test `rotated_host_key_is_refused`** expects `HostKey { mismatch: true }`, even when the new fingerprint is offered.
- **The main SSH test** now checks `run` vs `run_data` against the lecture, and the keytool stand-in.
- **`docs/FAKE-APPLIANCE.md`:** build and run (each command with its own `sudo`), the host-key volume, rotation, reset, and where to look.

## 0.3.5 — 2026-11-06

R5: the SSH transport, on an upgraded charon-ssh. The live test against the fake appliance is written but **not yet run**: its address didn't resolve.

- **charon-ssh, nine changes in Charon's dev tree**, each gated and exported as a patch in `docs/charon-ssh-patches/` (apply in order onto `e9f97f5`; details in `docs/CHARON-SSH-CHANGES.md`):
  1. russh 0.45 → 0.65.1 with the `ring` backend;
  2. `is_closed()`;
  3. `SshError::AuthRejected`;
  4. `HostKeys::with_label()`;
  5. `exec_stdin(cmd, None)` sends end-of-input;
  6. `exec_cancellable()` / `ExecHandle`;
  7. `connect_exec()` / `open_shell()` / `Shell`;
  8. `Auth::Agent` / `Auth::Auto`;
  9. `server_key()`.
- Only change 5 alters existing behaviour, as asked. hvm-desk (`appliance-ops`), its click-test sshd and this app build after every change.
- **Advisories:**
  - RUSTSEC-2026-0153 affects SSH **clients** as well as servers on russh < 0.58.
  - RUSTSEC-2026-0154 affects agent clients and servers.
  - Both are fixed in 0.60.3.
  - The Charon app (russh 0.45, directly) and hvm-desk's click-test sshd need the upgrade in their own repos.
- **`transport/ssh.rs`** ports `SshTransport`:
  - host-key TOFU against our own known_hosts, with a changed key never trusted;
  - key, password or agent/default-key auth;
  - sudo detection;
  - `run`, with every exec line from `appliance::ssh_wrap` and the sudo password only on stdin;
  - `put_root`;
  - `follow` until `@@RC=`, where stop leaves the run alone;
  - a shell on demand that doesn't drop the connection.
  - Unit tests check the exec lines against the reference's transport goldens, plus marker and UTF-8 splitting across reads.
- **`tests/ssh_fake_appliance.rs`** (ignored unless `MCI_TEST_SSH` is set):
  - the TOFU round trip, password sudo, `put_root` modes and ownership, a sudo command, stdin EOF;
  - follow to the rc, and stop without killing the run;
  - timeout, and shell reopen;
  - **the password-leak check:** `sudo grep` over `/etc/morpheus`, `/var/lib/morpheus-certificate-install` and `/var/log/morpheus-certificate-install`, with the password read from stdin as the pattern, then a planted canary to prove the check can find it.
- **CI:** the core job builds an export zip with the CLI, unpacks it with Info-ZIP `unzip`, and fails unless the key is 600 and every other file 644.
- **Workspace:** charon-ssh stays a path dependency until the crate is pushed inside builtbyfood/charon. The README documents the `git` + `rev` form and the `[patch]` for local work.

## 0.3.4 — 2026-11-05

Audit follow-ups, R3 (fetch missing chain) and R4 (export files, zip and the CLI). Conversion is now complete: `cargo test -p mci-core` is fully green, and the CLI produces the reference's files.

- **Audit:**
  - `zip` moved 2 → 9, which clears its four extraction advisories. `src-tauri` no longer depends on `zip` at all; the core builds the archive.
  - The RUSTSEC-2026-0387 (`crypto-bigint`) ignore is recorded as a decision in DECISIONS.md.
  - The full-workspace `cargo audit` now fails only on `russh`/`russh-cryptovec` (R5). The core-only audit that CI runs is clean.
- **R3 — `aia::complete_chain`:**
  - follows CA Issuers URLs for at most 4 hops, and stops as soon as a hop adds nothing new;
  - fetched certificates only join the pool, and `analyze()` decides by Name and signature whether they belong;
  - every URL tried gets a log line;
  - ldap:/file: and other non-http URLs are skipped with a line. When those are all a certificate offers, the log says to export the chain from the issuing Windows CA or ask the CA for its bundle.
  - The fetcher contract (http/https, 10 s, 1 MiB, ≤ 3 redirects, no cookies or credentials) is documented on `aia::Fetch`.
- **Four AIA cases**, added the additive way. A new small CA (`aia-root` → `aia-int`) signs four variants of the leaf:
  - ldap first, then http;
  - ldap only;
  - a PEM response;
  - a 404 followed by a working URL.
  - `aia-ldap-only` carries a computed override: `can_fetch_chain` counts URLs of any scheme (divergence 15).
- **R4 — `export::build_files` and `export::to_zip`:**
  - the reference's files and order;
  - zip entries under `<base>-morpheus/`, the key 0600 and the rest 0644, always made-by-Unix so the modes survive a Windows-built zip (divergence 16).
- **R4 — `mci-cli convert`:**
  - the reference's output, ✓ ! ✗ marks, "Wrote …" list and exit 2;
  - `--ask` (rpassword);
  - `--fetch-chain` (ureq, keeping the contract; tested against a local HTTP server for 404, redirect limit, 1 MiB cap and non-http schemes);
  - folder output with the key 0600 on Unix;
  - a closed pipe no longer panics.
  - New `tests/cli.rs` runs three corpus sets and compares the output tree with the golden.
- **Fixes:**
  - `make-cases.py` now rebuilds `fixtures/golden/export-p7b-pkcs1/` from scratch. Stale `trusted_certs/*.pem` from earlier corpora had piled up there, including two in your git checkout from 0.3.1.
  - `parity.rs` export test runs at the frozen `generated_at` instead of a fixed date.

## 0.3.3 — 2026-11-05

Repo hygiene, then R2: chain building and checks (`mci_core::analyze`). Nothing user-visible yet.

- **`.gitattributes`:**
  - fixtures and unit-test vectors are byte-exact (`-text`); source is LF.
  - Patterns are one per line: git rejects several on one line ("`*.toml` is not a valid attribute name").
  - Checked from a throwaway `core.autocrlf=true` clone:
    - with the file, nothing is converted and the core tests pass;
    - without it, 82 files are converted and a golden test fails.
- **Fixture generation split:**
  - `gen-corpus.sh` only creates missing files; `--force` regenerates everything.
  - The base set (whose CA keys aren't kept) is one unit, and the script refuses to half-rebuild it.
  - New files are guarded blocks at the end.
  - `make-cases.py` always reads the corpus as it is.
  - This round's corpus diff is new files only: `pbmac1.pfx`, `ed448-root.crt`, `leaf-ed448.crt`. All 35 existing files are byte-identical.
- **`make-cases.py`:**
  - runs the reference with its clock frozen at `generated_at`, which `cases.json` records;
  - records each case's `to_json()`;
  - computes the `csr-and-pvk-explained` override from the reference's own checks instead of typing it.
- **PBMAC1 PFX** (`pfx-pbmac1`): the reference reads it, so the port does too (RFC 9579: PBKDF2 over the UTF-8 password, then HMAC). No override needed.
- **CI:** the core job runs `cargo audit` on the core crates.
  - `.cargo/audit.toml` also ignores RUSTSEC-2026-0387 (`crypto-bigint` 0.5), with the reason.
  - The fix exists only in the der 0.8 generation. **Needs your OK.**
- **R2: `analyze(bundle, fqdn, appliance_url, now)`**, with `CertSummary` and `to_json`.
  - Issuer matching uses parsed Names, as the reference's `Name.__eq__` does, and then signature verification:
    - PKCS#1 v1.5 with SHA-1/224/256/384/512;
    - RSA-PSS with its hash, MGF1 hash and salt length;
    - ECDSA P-256/384/521 with any of those hashes (prehash);
    - Ed25519.
  - Day counts round down like Python's `timedelta.days`, with a unit test on an expired certificate.
  - Every check text is the reference's, word for word.
  - New divergence 13: when an issuer is supplied but its algorithm can't be checked (Ed448, DSA, …), the warning names the certificate and the algorithm. New case `ed448-chain` covers it.
- **`parity.rs`:**
  - passes `generated_at`;
  - compares every check (level and text, in order) and the whole `to_json`;
  - reports an unported AIA fetch as a per-case failure instead of a panic.
  - Result: 31 of 32 cases green. The one failure is `leaf-only-aia-fetch` (R3), and `export_layout` waits for R4.

## 0.3.2 — 2026-11-05

R1: reading every input format (`mci_core::formats`). Nothing user-visible yet; the app commands arrive in R7.

- **`formats` ported** (`parse_files`, `parse_one`, the reference's `parse_all` + `certs.parse_files`).
  - Every corpus input matches the reference's kind, certificate count, key count, level **and** exact `format` text: all 30 cases, checked by the new `parity.rs::every_input_parses_like_the_reference`.
  - PEM (any label, CRLF, BOM, UTF-16 with or without BOM, "Bag Attributes" noise), DER certificates, PKCS#7 (PEM and DER; file order kept, BER accepted), base64 without armour.
  - Keys: PKCS#8, PKCS#1, SEC1, DSA, encrypted PKCS#8 (PBES2 and PKCS#12 PBE), OpenSSL legacy encrypted PEM, and OpenSSH (plain and bcrypt/AES). Each is normalised to the exact PKCS#8 bytes the reference writes.
  - PFX/P12, legacy and modern.
  - **JKS read natively:** store integrity hash, Sun key protector, "changeit"/"" fallbacks.
  - **JCEKS** is recognised and answered with the keytool conversion command (not read; PARITY.md).
  - New submodules: `tlv` (bounds-checked BER/DER walker), `x509`, `keys`, `pbe`, `pfx`, `p7`, `jks`, `openssh`.
- **PFX reader hardening:**
  - the MAC is verified before anything is decrypted;
  - every iteration count is capped at 10,000,000, with an error that names the number (scrypt and OpenSSH bcrypt are capped too);
  - every length is bounds-checked;
  - a cut-short file says so.
  - Negative tests, each giving an error report and never a panic or hang:
    - `legacy.pfx` and `modern.pfx` truncated at 14 offsets;
    - one flipped MAC byte;
    - a 2,000,000,000-iteration MAC;
    - huge inner iteration counts, with and without a recomputed MAC (which proves the MAC runs first);
    - 900 single-byte corruptions.
- **Corpus extended** via `gen-corpus.sh` and `make-cases.py` only:
  - `leaf-sha384.crt` and `leaf-sha512.crt` (RSA);
  - `ec-sha384.crt` (a P-256 leaf signed with ECDSA-SHA384) and `ec-root.crt`;
  - an RSA-PSS chain: `pss-root.crt` → `pss-int.crt` → `leaf-pss.crt`.
  - Four new cases (30 in all).
  - `rsa-pss-chain` carries a `rust_expect_override` that `make-cases.py` *computes*: it runs the reference's `analyze()` with a PSS-aware `signed_by()`.
  - The whole corpus was regenerated (new keys, so new fingerprints). Every existing case and golden is otherwise identical to 0.3.1.
  - The scripts now run under Git Bash on Windows: `MSYS_NO_PATHCONV`, a `PYTHON` override, LF line endings, and LF goldens from `make-cases.py`.
- **Divergences recorded** in `docs/PARITY.md`:
  - PSS verified;
  - Ed448 not supported;
  - work-factor limits;
  - MAC-first;
  - clearer errors on broken files;
  - `TRUSTED CERTIFICATE`.
  - PBES1, RC4 PBE, JCEKS and ChaCha/GCM OpenSSH keys are listed as not ported.
- **Dependencies:**
  - `cms` dropped;
  - `bcrypt-pbkdf` 0.10 and `ctr` 0.9 added;
  - `pkcs5` gains the decrypt-only `des-insecure` and `sha1-insecure` features;
  - the R0 spike (`tests/spike.rs`) and its dev-dependencies (including `p12-keystore`) are removed.
- **`.cargo/audit.toml`** ignores RUSTSEC-2023-0071 (`rsa` Marvin), with the reason: `rsa` only verifies signatures and never uses a private key.
- **Icons:**
  - `npx tauri icon src-tauri/icons/icon.svg` is now in the README;
  - generated icons stay git-ignored, including the new `android/` and `ios/` folders.
  - `cargo check -p morpheus-certificate-install` now passes. That needed one fix in `src-tauri/src/lib.rs`: a local `stop` shadowed the `stop` command.
- **Tests:**
  - `analyze.rs`'s fingerprint test reads `cases.json` instead of a copied value;
  - the UI contract harness sets `PYTHONUNBUFFERED` so it sees the reference's start-up line on Windows.

## 0.3.1 — 2026-11-05

R0: prerequisites and the crypto decision. Nothing user-visible changes yet.

- **Crypto stack chosen: pure Rust, RustCrypto `der` 0.7 generation** (`docs/DECISIONS.md`).
  - The spike (`crates/mci-core/tests/spike.rs`, throwaway, removed in R1) passes every R0 corpus file against reference values:
    - legacy RC2-40/3DES and modern AES-256 PFX;
    - PEM and DER P7B;
    - PBES2 and `Proc-Type: 4,ENCRYPTED` keys;
    - PKCS#1 and SEC1 keys;
    - RSA and ECDSA signature checks;
    - the RFC 4514 rendering.
  - "Against reference values" means cases.json fingerprints, Python's PKCS#8/SPKI bytes, and Python's `rfc4514_string()`.
  - About +650 KB in a release exe; no C toolchain.
  - The vendored-OpenSSL fallback doesn't build on this machine (it needs Strawberry Perl), so it's unverified.
  - p12-keystore was rejected: it pins pre-release crates, brings a second ASN.1 generation (+445 KB), and its keystore import policies drop bags.
- **The spike found one trap that behaves differently from what we expected.** `der` 0.7 doesn't reject OpenSSL's unsorted PKCS#7 SET OF; it silently *re-orders* it. R1 walks `certificates [0]` itself to keep file order.
- **`mci-core` dependencies:** the real crypto dependencies are now declared in `crates/mci-core/Cargo.toml`.
- **Two functions implemented in `mci-core`:**
  - `analyze::sha256_hex` (sha2);
  - `analyze::pem_encode` (64-column lines, trailing newline). It reproduces the corpus PEM files byte for byte.
  - 4 new unit tests.
- **charon-ssh checked** (`docs/CHARON-SSH-CHANGES.md`).
  - Present: password and key auth, host-key TOFU with a typed "changed" refusal, exec with stdin, exit status and streamed output, keepalive.
  - Missing or needing change:
    - on-demand PTY shells, separate from the connection (today `close()` drops the whole connection);
    - exec cancellation;
    - `is_closed()`;
    - agent / default-key auth;
    - a typed auth error.
  - Proposed as small, backwards-compatible crate changes for R5. No crate changes made yet.
- **Build fixes:**
  - The workspace `charon-ssh` path is now `../../charon/…`; this checkout sits one level deeper than the old path assumed.
  - `[profile.release]` moved from `src-tauri/Cargo.toml` to the workspace root; cargo ignored it in a member crate, so LTO, size optimisation and strip weren't being applied.

## 0.3.0 — 2026-11-05

Start of the Rust / Tauri 2 port. The app is a standalone portable build that reuses `charon-ssh`.

- **Workspace:** `crates/mci-core`, `crates/mci-cli` and `src-tauri`. The Python 0.2.1 is kept as the frozen spec in `reference/python/`.
- **`mci-core`, ported and golden-tested byte-for-byte against the Python (10 tests, passing):**
  - `shlex.quote`, file names, truststore aliases, SAN matching;
  - the morpheus.rb edit (including the legacy sphragis block);
  - the runner script and its markers;
  - every appliance command string;
  - INSTALL.txt.
- **`fixtures/`:** a 28-file corpus covering every input format the Python reads, 26 parity cases, the recorded apply command sequence, and transport command goldens. All generated by `fixtures/gen-corpus.sh` and `fixtures/make-cases.py` from the reference.
- **`tests/parity.rs`:** the definition of done for conversion. It's red until R1–R4.
- **`mci-cli`:** argument parsing, tested.
- **`src-tauri` skeleton:**
  - the command list (same JSON as the Python `/api/*` routes);
  - the event enum;
  - the `Transport` trait and its SSH and Charon MCP contracts;
  - portable paths;
  - Tauri config with drag-drop handled by the page.
- **`ui/`:** the existing page with `bridge.js` (invoke/listen instead of fetch/SSE; the save dialog handles export). `tests/ui-contract/bridge.cjs` passes against the reference.
- **`tests/fake-appliance/`:** a Dockerfile wrapping the stand-in appliance used to test 0.2.x (the Dockerfile itself is untested).
- **Tooling and docs:**
  - `scripts/bump-version.mjs` (versions and file stamps) and `scripts/portable.mjs`;
  - CI that tests the core crates in isolation until `charon-ssh` is published;
  - KICKOFF, CLAUDE.md, and docs for architecture, rounds R0–R9, parity, decisions and on-appliance verification.

## 0.2.1 and earlier

Python. See `reference/python/CHANGELOG.md`.
