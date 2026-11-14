# Building on macOS — morpheus-certificate-install 0.4.1

**Not yet tested on a Mac.** CI builds and tests the macOS app on GitHub's Apple Silicon runner (`.github/workflows/build.yml`, job `macos`): arm64 natively, and Intel cross-compiled. Nobody has run the result on a Mac yet. If you do, please open an issue with what you found, using the list in section 4.

## 1. Tools

- **Xcode Command Line Tools:** `xcode-select --install`.
- **Rust**, from rustup:

  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  source "$HOME/.cargo/env"
  ```

- **Node 22 or later**, for example with Homebrew: `brew install node`.

Nothing else is needed: the app uses the system WebKit.

## 2. Build

From a copy of the repository:

```bash
npm ci
npx tauri icon src-tauri/icons/icon.svg      # the generated icons (icon.icns too) aren't in git
cargo test --locked --workspace              # everything except the live tests (ignored) and the click tests (Windows only)
npm run tauri build -- --bundles app,dmg     # → target/release/bundle/macos/*.app and bundle/dmg/*.dmg
cargo build --release -p mci-cli             # → target/release/morpheus-certificate-install-cli
```

To build for the other chip, add its target first. Intel on Apple Silicon:

```bash
rustup target add x86_64-apple-darwin
npm run tauri build -- --target x86_64-apple-darwin --bundles app,dmg   # → target/x86_64-apple-darwin/release/bundle/
```

Some tests in `crates/mci-core/tests/golden_text.rs` run the appliance's shell commands in local bash. They need GNU coreutils, and skip on macOS's BSD tools; that's expected. To run them anyway, `brew install coreutils` and put its `gnubin` folder first on `PATH`.

## 3. Run

```bash
open target/release/bundle/macos/*.app
```

A build you made yourself isn't quarantined, so Gatekeeper doesn't ask. For a downloaded build, see the README's macOS section.

Data goes in `~/Library/Application Support/morpheus-certificate-install/`. There's no portable mode on macOS, so `portable.flag` is ignored, and the Connect step doesn't offer **Leave no trace**.

## 4. What to check, and send back

- `sw_vers`, and `uname -m` (arm64 or x86_64);
- `cargo test --locked --workspace 2>&1 | grep -E "test result|FAILED"`;
- the window opens and its title shows the version;
- drop `fixtures/corpus/chain.p7b` and `fixtures/corpus/leaf-pkcs1.key` on step 2, click **Check certificate**: three seals and a coloured Run log line;
- **Download files for Morpheus (.zip)** saves through the save dialog;
- the Connect step has no **Leave no trace**, and after a connection `~/Library/Application Support/morpheus-certificate-install/` holds `settings.json` and `known_hosts`;
- optional: connect to a fake appliance (`docs/FAKE-APPLIANCE.md`) with a password, then with a key through the SSH agent (`ssh-add` first);
- optional: Verify against a site with a publicly trusted certificate reports the OS store (the macOS keychain).
