# Contributing — morpheus-certificate-install 0.4.2

Bug reports and pull requests are welcome. Please open an issue before a large change, so we can agree on the approach first. Security problems go through [SECURITY.md](SECURITY.md), not an issue.

## Four rules

1. **Fixtures come only from the reference.** `reference/python/` is the frozen Python 0.2.1, and it is the specification. Everything in `fixtures/` is generated from it:

   ```bash
   fixtures/gen-corpus.sh          # creates missing corpus files only (--force regenerates all, and changes every fingerprint)
   python3 fixtures/make-cases.py  # rebuilds cases.json and the goldens from the corpus
   ```

   Never hand-edit `fixtures/cases.json` or `fixtures/golden/*`. A new corpus file is a new guarded block at the end of `gen-corpus.sh`. Any intended difference from the Python goes in [docs/PARITY.md](docs/PARITY.md) under *Divergences*.
2. **A change to a transport or to the engine needs a live run** against the fake appliance ([docs/FAKE-APPLIANCE.md](docs/FAKE-APPLIANCE.md)), not just unit tests and mocks. Say in the pull request which live tests you ran.
3. **No private strings.** Examples use `morpheus.example.com`, `appliance.example.com`, `192.0.2.10`, `198.51.100.x` and the user `mcitest`. Never commit a real hostname, address, path or e-mail, or a real customer certificate. Copy `.private-denylist.example` to `.private-denylist` (gitignored), list your own names in it, and run:

   ```bash
   npm run check-private            # also reads names inside certificates (PEM, DER, base64)
   ```
4. **Appliance shell text lives only in `crates/mci-core` (`appliance` and `runner`).** Each command string has a golden test. Transports only wrap and deliver commands.

The SSH client is [charon-ssh](https://github.com/builtbyfood/charon-ssh), shared with [Charon](https://github.com/builtbyfood/charon) and pinned to one commit in `Cargo.toml`. Changes to it go to that repository first; this one then moves the pin.

## Test tiers

Start with `npm ci` and `npx tauri icon src-tauri/icons/icon.svg` (the generated icons aren't in git).

| Tier | Command | Needs |
|---|---|---|
| Unit, golden and parity tests, the CLI, the app's commands | `cargo test --locked --workspace` | nothing |
| UI contract: the page against the Python reference | `npm run test:ui-contract` | Python with `reference/python/requirements.txt` and `pyjks`; set `PYTHON` if it isn't on `PATH` |
| Click tests: the real app, driven through its page | `npm run test:click` | Windows (WebView2 over CDP); [tests/click/README.md](tests/click/README.md) |
| Portable build smoke test | `npm run portable`, then `npm run portable-smoke` | a desktop session |
| Fresh clone builds | `npm run fresh-clone-check` | network for `npm ci` and crates |
| Links in the Markdown files resolve (CI runs it too) | `npm run check-links` | nothing |
| Every text file is LF in git; .gitattributes names every text type (CI runs it too) | `npm run check-gitattributes` | git |
| SSH transport, live | `cargo test -p morpheus-certificate-install --test ssh_fake_appliance ssh_transport_against_the_fake_appliance -- --ignored --nocapture` | `MCI_TEST_SSH` |
| The whole engine, live | `cargo test -p morpheus-certificate-install --test engine_e2e -- --ignored --nocapture` | `MCI_TEST_SSH` |
| Click tests against the VM | `npm run test:click` | `MCI_TEST_SSH` (adds the install, host-key and cleanup suites) |
| Charon transport vs a mock | `cargo test -p morpheus-certificate-install --test charon_mock -- --ignored --nocapture` | `MCI_TEST_SSH`, and `MCI_PYTHON` with paramiko |

`MCI_TEST_SSH` is `host:port:user:password` for your fake appliance (a disposable VM, never a real appliance), for example `192.0.2.10:2222:mcitest:hunter2`. In PowerShell, set it with `$env:MCI_TEST_SSH = "192.0.2.10:2222:mcitest:hunter2"`.

**Don't run `ssh_fake_appliance` unfiltered without meaning to.** Its host-key rotation test changes the VM's host key for good, so it only runs with `MCI_TEST_ROTATE=1`.

Live tests install certificates, run `morpheus-ctl`, and delete what they wrote, on the machine they're pointed at. Through a real Charon session (`charon_live`, `engine_e2e` with `MCI_TEST_E2E_CHARON`), they drive whatever that session is connected to. Only point any of them at a fake appliance.

## Versions

One version everywhere: `npm run bump -- X.Y.Z` updates every manifest and the stamp at the top of each file. Add a `CHANGELOG.md` entry with it.
