# Building on Linux (Fedora) — morpheus-certificate-install 0.4.2

Build the app, the bundles and the portable tar.gz on Fedora, smoke-test them, and record the results (section 4). CI builds the same bundles on Ubuntu 22.04 (`.github/workflows/build.yml`).

Every command that needs root carries its own `sudo`.

## 1. Packages

```bash
sudo dnf install -y @c-development webkit2gtk4.1-devel openssl-devel curl wget file \
  libappindicator-gtk3-devel librsvg2-devel libxdo-devel nodejs npm python3-pip unzip fuse-libs
```

- `@c-development` is the compiler group (on Fedora 40 and older: `sudo dnf group install "C Development Tools and Libraries"`).
- `fuse-libs` is only needed to run the AppImage.
- Node must be 22 or later: `node --version`. If Fedora's is older, `sudo dnf install -y nodejs22` and use `node-22`/`npm-22`.

Rust, from rustup (as your user, not root):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
rustc --version
```

## 2. Build

From a copy of the repository (the tracked files are enough; no `.cargo/config.toml` is needed; cargo fetches charon-ssh from GitHub at the pinned commit):

```bash
npm ci
npx tauri icon src-tauri/icons/icon.svg     # the generated icons are gitignored
cargo test --locked --workspace             # everything except the live tests (those are ignored)
npm run tauri build                         # deb, rpm and AppImage → target/release/bundle/
npm run portable                            # dist-portable/morpheus-certificate-install-linux-portable-x64.tar.gz
```

## 3. Smoke test

Run these in a graphical session (the app opens a window).

**Portable tar.gz** — the same checks as on Windows: it unpacks into a temp folder, starts the app, checks `data/` (with `webview/`) appears beside it and that nothing appears in `~/.config` or `~/.local/share`, closes it, and runs the CLI's `--version` and one `convert`:

```bash
npm run portable-smoke
```

Linux has no CDP in webkit2gtk, so this checks the page by the data folder only. Then look at the window yourself once:

```bash
mkdir -p /tmp/mci-portable && tar -xzf dist-portable/morpheus-certificate-install-linux-portable-*.tar.gz -C /tmp/mci-portable
/tmp/mci-portable/morpheus-certificate-install/morpheus-certificate-install
```

In the window: the title bar shows the version being built (the one in `src-tauri/tauri.conf.json`). Drop `fixtures/corpus/chain.p7b` and `fixtures/corpus/leaf-pkcs1.key` on step 2, click **Check certificate**, and see three seals and a coloured Run log line. Close the window; `/tmp/mci-portable/morpheus-certificate-install/data/` is there, and nothing new is in `~/.config`.

**AppImage** (not portable: it keeps its data in `~/.config/morpheus-certificate-install`):

```bash
chmod +x target/release/bundle/appimage/*.AppImage
target/release/bundle/appimage/*.AppImage
```

The same quick check in the window, then close it.

**rpm** (installs system-wide; removed again at the end):

```bash
rpm -qip target/release/bundle/rpm/*.rpm
sudo dnf install -y ./target/release/bundle/rpm/*.rpm
morpheus-certificate-install
sudo dnf remove -y morpheus-certificate-install
```

**deb:** Fedora can't install it; check that it's well-formed:

```bash
ar t target/release/bundle/deb/*.deb
```

**Optional, against your fake VM** (the SSH transport and the engine end to end):

```bash
MCI_TEST_SSH=<vm>:2222:mcitest:hunter2 cargo test -p morpheus-certificate-install --test ssh_fake_appliance ssh_transport_against_the_fake_appliance -- --ignored --nocapture
MCI_TEST_SSH=<vm>:2222:mcitest:hunter2 cargo test -p morpheus-certificate-install --test engine_e2e -- --ignored --nocapture
```

## 4. What to record

Keep the output of these with the release (or attach it to an issue if something failed):

```bash
cat /etc/os-release | head -3; rustc --version; node --version
cargo test --locked --workspace 2>&1 | grep -E "test result|FAILED"
npm run portable-smoke
ls -l target/release/bundle/*/ dist-portable/
sha256sum target/release/bundle/deb/*.deb target/release/bundle/rpm/*.rpm target/release/bundle/appimage/*.AppImage dist-portable/*.tar.gz
rpm -qip target/release/bundle/rpm/*.rpm | head -12
ar t target/release/bundle/deb/*.deb
```

And note, for each of the portable app, the AppImage and the installed rpm, whether the window opened, showed that version, and checked the corpus files. Mention anything that printed errors in the terminal.
