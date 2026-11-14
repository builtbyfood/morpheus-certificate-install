# Parity with the Python reference — morpheus-certificate-install 0.4.2

The reference is `reference/python/`, frozen at 0.2.1.

## Status per feature

| Feature | Python | Rust home | Test |
|---|---|---|---|
| Shell quoting (`shlex.quote`) | transport.q | `mci_core::quote` | ✅ unit |
| File base name, truststore alias, SAN match | certs | `mci_core::names` | ✅ unit |
| morpheus.rb edit (+ legacy sphragis block) | certs.transform_morpheus_rb | `mci_core::morpheus_rb` | ✅ golden |
| Runner script + marker parsing | engine.runner_script / follow | `mci_core::runner` | ✅ golden |
| Every appliance command string | engine / transport | `mci_core::appliance` | ✅ golden |
| INSTALL.txt | export.install_text | `mci_core::export` | ✅ golden (bar the last line) |
| Read every input format | formats, certs.parse_files | `mci_core::formats` | ✅ parity.rs `every_input_parses_like_the_reference` (kind, counts, level and format text for all 30 cases) + unit tests |
| Chain + checks + to_json | certs.analyze, CertInfo.summary, Analysis.to_json | `mci_core::analyze` | ✅ parity.rs `every_case_matches_the_reference`: every check (level + text, in order) and the whole `to_json` (bar `inputs`) for 31 of 32 cases at the frozen `generated_at`; the AIA case waits for R3 |
| AIA completion | certs.complete_chain | `mci_core::aia` | ✅ parity.rs (`leaf-only-aia-fetch` + 4 AIA cases: ldap first, ldap only, PEM response, failing first URL) + unit tests on the log, hop cap and loop stop |
| Export files / zip, CLI convert | export, app.convert_main | `mci_core::export`, `mci-cli` | ✅ parity.rs `export_layout` (every file byte for byte, key included) + `mci-cli/tests/cli.rs` (3 sets vs the golden tree) + manual run against the reference's own `convert` (console output, tree and INSTALL.txt identical bar line 1 and the last line) |
| SSH transport | transport.SshTransport | `src-tauri/transport/ssh.rs` | ✅ unit (exec lines = transport goldens, `@@RC=` split across chunks, UTF-8 split across chunks) · ✅ `tests/ssh_fake_appliance.rs` live against the fake appliance VM |
| Charon transport + discovery | transport.CharonTransport, charon_discover | `src-tauri/transport/charon_mcp.rs` | ✅ golden (framed read command, long poll) + bash round trip and long-poll timing + parser unit tests · ✅ `tests/charon_mock.rs` against `tests/mock_charon.py` (SSH mode, real PTY to the fake VM) · ✅ `tests/charon_live.rs` against the real Charon (trusted mcitest session; `sudo -k` first, so the exact-bytes read goes through a real sudo prompt and lecture) |
| Handlers, jobs, verify, API | app.py, engine.py | `src-tauri/src/engine.rs`, `verify.rs`, `morpheus_api.rs` | ✅ apply's appliance operations = `apply-command-sequence.json` (recording transport, `engine::tests`) · ✅ `tests/commands.rs` (every command on tauri's MockRuntime, with its events) · ✅ `tests/engine_e2e.rs` live: over SSH (everything) and through the real Charon (apply → verify → rollback) |
| UI | web/index.html | `ui/` + `bridge.js` | ✅ ui-contract (against the Python) |

## Divergences (intentional)

1. **An extra unusable input doesn't fail the set.** A CSR, PVK, CRL or bare public key alongside an otherwise complete set is a *warning*; the reference made it an error.
   - Rule in `analyze`: a bundle problem that comes from an input reported as `pvk` is downgraded from error to warning when the private key matches a supplied certificate. (CSRs, CRLs and public keys never were errors.)
   - Encoded as `rust_expect_override` on `csr-and-pvk-explained`, computed by `make-cases.py` (`extras_override`) from the reference's own checks.
2. **INSTALL.txt last line.** It reads "Or run morpheus-certificate-install to do all of it, with a backup and rollback." — the reference pointed at `python -m …`.
3. **Export goes through a save dialog.** The Python app downloaded through the browser; Tauri asks where to save, and `export_zip` returns `{saved, files}` instead of a base64 body.
4. **No local web server.** The Python app needed a per-launch token and a Host-header check on 127.0.0.1. Tauri IPC replaces both — there's no listening socket.
5. **Version and product strings** come from the Rust crate (`0.3.x`). Goldens use `{VERSION}` placeholders.
6. **RSA-PSS signatures are verified.** The reference's `signed_by()` only tries PKCS#1 v1.5 for RSA, so a PSS-signed chain never links and the root is reported missing. The Rust port verifies PSS (R2).
   - Encoded as `rust_expect_override` on `rsa-pss-chain`. The override is computed, not typed: `make-cases.py` runs the reference's `analyze()` with a PSS-aware `signed_by()` and keeps every field that changes.
7. **Ed448 is not supported.** There is no mature pure-Rust Ed448 implementation. An Ed448 private key is reported as unusable ("Ed448 keys aren't supported by this app…"), and Ed448 signatures aren't verified, so such a chain doesn't link (see 13 for what the user is told). The reference handled both.
   - Case `ed448-chain` (0.3.3): an Ed448 root and a leaf it signed. Its `rust_expect_override` is computed: the reference's `analyze()` with Ed448 unverifiable, plus divergence 13's wording.
8. **Work-factor limits.** PBKDF2 and PKCS#12 KDF iteration counts (including the PFX MAC) above 10,000,000, scrypt above N=2^20 / 64 MiB, and OpenSSH bcrypt above 1,000 rounds are refused with an error that names the number, before any derivation runs. The reference would run them, however long they took.
9. **PFX integrity order.** The MAC is verified before anything is decrypted; with a verified MAC, a part that fails to decrypt is reported as damaged ("PFX / PKCS#12 (unreadable)") instead of as a wrong password.
10. **Clearer errors on broken files.** Where the reference said "Wrong or missing PFX password." or gave a crypto library's message, the port says what happened:
    - a `.pfx`/`.p12` shorter than its own header says → "PFX / PKCS#12 (damaged)": "The file is cut short: it has N of the M bytes its header promises…";
    - any other cut-short DER file gets an extra note saying so after "Not a certificate, key, PFX…";
    - a PFX whose key or certificate can't be used, or that uses RC4 or public-key protection → "PFX / PKCS#12 (unreadable)" with the reason;
    - a DER key that is a key but can't be used (e.g. Ed448, an unsupported cipher) → "DER private key (unreadable)" / "encrypted DER private key (unreadable)" instead of falling through to "not recognised";
    - a malformed OpenSSH key gets its real error instead of "The private key is encrypted — enter its passphrase."
    - The `kind` the parity tests compare is unchanged for every corpus case.
11. **`TRUSTED CERTIFICATE` blocks** (OpenSSL's certificate + trust settings) are read by taking the certificate and ignoring the trust settings that follow it. The reference relabelled the block and could reject the trailing data.
12. **Exact `format` text.** It matches the reference for every corpus input. Error notes from the crypto library (`private key could not be read: …`, `unreadable certificate block: …`) have our own wording after the colon, because the reference's came from OpenSSL.

13. **"Can't verify", not "not supplied".** When a certificate's issuer *is* in the set (its Name matches) but the signature uses an algorithm the port can't check, the warning says so instead of the reference's "The chain stops at an issuer that wasn't supplied":
    `The issuer of "<cn>" was supplied, but "<cn>" is signed with <algorithm>, which this app can't verify — so the chain stops there. Check the chain with another tool, or ask the CA for an RSA or ECDSA chain.`
    - "No intermediate certificates supplied…" is not added in that situation.
    - Applies to Ed448, DSA, MD5/MD2 with RSA, SHA-3 signatures, ECDSA on curves other than P-256/384/521, and RSA-PSS whose MGF1 hash differs from its hash. What the reference did instead (its `signed_by` hands any RSA key PKCS#1 v1.5 with the certificate's hash, any EC key ECDSA with it, and Ed25519/Ed448 their own verify): it **linked** Ed448 chains, ECDSA on other curves OpenSSL knows (secp256k1, brainpool), SHA-3 signatures, and RSA-MD5 where its OpenSSL allowed it — those now stop with this warning. It never verified DSA or PSS, and said "not supplied" for them.
    - A self-issued certificate whose own signature can't be checked gets the same warning (the reference would have called it self-signed only if it could verify it).
14. **Issuer matching is by parsed Name**, as the reference's `Name.__eq__` (same RDNs in order, each RDN the same set of attribute OID + decoded value). This is parity, recorded because it differs from comparing raw DER: a PrintableString and a UTF8String with the same text match.

15. **Fetch missing chain (AIA).**
    - Every URL tried gets a log line. That includes one that answered with certificates already in the set, or with no certificate at all. The reference logged only failures and new certificates.
    - Non-http(s) CA Issuers URLs (ldap:, file:, …) are skipped with a log line, and the next URL is tried. When a certificate offers only those, the log says to export the full chain from the issuing Windows CA or ask the CA for its bundle. The reference dropped them silently, then said "has no CA Issuers URL to follow".
    - `can_fetch_chain` and the "— or use Fetch missing chain." hint count CA Issuers URLs of any scheme, so the button appears and explains the ldap: case. The reference counted only http(s), so the button never appeared. Encoded as `rust_expect_override` on `aia-ldap-only`, computed by `make-cases.py` from the reference's `analyze()` seeing every URL.
    - A response over 1 MiB is refused in the core as well as in the fetcher. The fetcher contract (http/https, 10 s, 1 MiB, ≤ 3 redirects, no cookies or credentials) is documented on `mci_core::aia::Fetch`.
    - The chain itself is unchanged for every case: fetched certificates only join the pool, and `analyze()` links them by Name and signature as the reference did.
16. **Zip entries are always "made by Unix"**, so the key's 0600 and everyone else's 0644 survive a zip built on Windows. Checked: the reference's `to_zip` run on Windows writes the right mode bits (0o100600 for the key) but marks every entry as made by DOS (`create_system = 0`), and Info-ZIP `unzip` restores Unix mode bits only for Unix-made entries, so its key would unpack with the default umask (that last step is Info-ZIP's documented behaviour, not run here: no Linux). On Linux both write Unix entries.
17. **CLI edges.**
    - An input file that can't be read gives "Couldn't read <path>: <reason>. Check the path and try again." and exit 1. The reference gave a Python traceback.
    - Bad arguments exit 64 with the usage text (argparse used 2, which the reference also used for "not converted").
    - Output cut short by a closed pipe (`… | head`) ends quietly instead of with an error.
    - The program is `morpheus-certificate-install-cli convert`; the reference was `python -m morpheus_certificate_install convert`.

18. **SSH transport details.**
    - Connect has one 45 s deadline for the whole handshake. The reference had 15 s connect, 20 s banner and 20 s auth.
    - With a key file *and* a password, the key is tried first, then the password on a fresh connection. paramiko tried both on one connection.
    - With neither, `Auth::Auto` tries the agent and then `~/.ssh/id_ed25519`, `id_ecdsa`, `id_rsa`, as paramiko's `allow_agent` + `look_for_keys` did.
    - An authentication failure says "Authentication failed for u@h: the server didn't accept the password or key. Check them on the Connect step." The reference appended paramiko's own message.
    - A new `known_hosts` file starts with a `# morpheus-certificate-install known_hosts` header line. paramiko wrote none. Entries are OpenSSH format either way.
    - In `follow`, the `@@RC=` marker is found even when it arrives split across two reads. The reference looked for it within one chunk.
    - Output is decoded as UTF-8 across chunk boundaries; invalid bytes become U+FFFD, as `decode(errors="replace")`.
    - The exit code without a status (-1), a stopped command (-2), the timeout message, the "connection is closed" message and the sudo-password messages are the reference's.

19. **morpheus.rb write guard.** Apply and rollback refuse to write `/etc/morpheus/morpheus.rb` unless the text they would write from contains a non-comment `appliance_url` line. The error says why and that nothing was changed, and nothing is written. The reference had no such check.
    - **Apply:** checks the text it just read back (`reads::morpheus_rb_for_edit`, `morpheus_rb::transform_checked`).
    - **Rollback:** first reads the backup's morpheus.rb (`appliance::cat_backup_morpheus_rb`, a new command) and refuses to restore if it fails the check (`reads::backup_morpheus_rb_checked`). The reference copied it into place blind.
    - **Why:** a read that returns something other than the file (empty after a failed `cat`, an error message, sudo's lecture) would otherwise become the appliance's configuration.
    - **Plan (0.3.15):** the plan's new morpheus.rb is built with `transform_checked` too, so a server-certificate plan for a morpheus.rb without `appliance_url` is refused before anything happens (no backup, no files). A trust-only plan doesn't touch morpheus.rb and isn't refused.
    - **Apply reads first (0.3.16):** apply reads morpheus.rb and runs the guard *before it writes anything*, the backup and the new `.crt`/`.key` included; the edit is made from that text, and the reference's later re-read (after the key) is gone. So when the file loses its `appliance_url` between plan and apply, nothing at all is written and no runner starts. In the operation sequence that's one move: `cat /etc/morpheus/morpheus.rb` from after the key to just before the backup, recorded as `rust_expect_override` in `fixtures/golden/apply-command-sequence.json` by make-cases.py and applied by `engine::tests`. (0.3.15 kept the reference's order, so backup, `.crt` and `.key` were written before the refusal.)
    - Tested: mci-core `morpheus_rb::guard_tests`, src-tauri `reads::tests` and `engine::tests` (on refusal the only operation is the read), and live in `tests/engine_e2e.rs` (at plan and at apply: no backup, `.crt`/`.key` untouched, morpheus.rb unchanged on disk).
20. **Data reads use stdout only.** The reference read everything with `set_combine_stderr(True)`. Anything on stderr — sudo's first-use lecture, `cat: … No such file`, warnings — became part of morpheus.rb's text, the preflight facts, a manifest or a stat mode. Now:
    - `Transport::run_data` returns stdout as the data and keeps stderr for error messages. It's used for morpheus.rb, its stat mode, `served_chain`, `list_runs`, `list_backups`, manifests and the preflight `KEY=VALUE` facts (`src-tauri/src/reads.rs`).
    - `Transport::run` still returns merged output for what is shown to the user (logs, runner output, errors).
    - The fake appliance prints sudo's lecture on every prompt so the live test exercises this.

21. **Charon data reads are framed; display output has CR stripped.** The reference trusted `run_command`'s output, which comes from a terminal: merged streams, CRLF, escape sequences, sudo's lecture and prompt.
    - `run_data` sends the command wrapped by `appliance::charon_data_read`:
      - stdout as base64 between `@@MCI-<nonce>` markers;
      - stderr via a file in the 0700 staging dir, then base64 after its own marker;
      - the exit code last.
    - The frame is printed only after the command has finished, so sudo's tty output can't land inside it.
    - stdout is held in a shell variable, never a file. The stderr file (0700 staging dir) is removed on every exit path the shell sees: normal exit, and HUP/INT/TERM from a timeout (turned into exits so the EXIT trap runs). SIGKILL can't be trapped, so each read first deletes `mci-err-*` files older than 10 minutes. Tested in real bash with each signal.
    - The session's umask is left alone.
    - Everything outside the frame is ignored.
    - Follow's polls go through the same frame. So the exact `run_command` line differs from the reference's `charon_poll_first` golden, which still pins the inner poll command.
    - **Follow is a long poll (0.3.16).** The reference polled every 2 s; at the exec-approve tier that's an approval dialog every 2 s. `appliance::charon_long_poll` waits on the appliance (checking every 0.5 s) until the log grows past the offset, the rc file has content, or 90 s pass (under Charon's 120 s limit), then runs the reference's poll unchanged. One command per update: the mock test follows a 24 s runner with 4 polls. Golden: `charon_long_poll_command`, and `charon_long_poll_in_bash` for the timing.
    - **The approval notice (0.3.16).** When the Charon session isn't at the trusted tier, connecting logs that every command needs approval in Charon, and each run (apply, rollback, re-attach) logs that each update of the log needs approval, with the `tail -n +1 -F …` line to follow it in the Charon tab instead. These are `log` events, so the page is unchanged. The reference had neither.
    - Login user detection uses a framed read: the reference took the last line of the terminal output.
    - `run` (display) strips CR.
22. **Saved hosts from charon.db.** Only `json_extract(settings, '$.host' | '$.port' | '$.user' | '$.jump_host' | '$.tags')` is asked of SQLite, so nothing else of a node's settings is ever read; the reference loaded the whole settings JSON into Python. The output is the same, and the database is opened read-only either way.
23. **Local TLS check and the Morpheus API: three trust stores, the one used is reported, readable reasons.** The reference verified against the OS trust store (Python `ssl.create_default_context()`) plus the supplied root, and showed OpenSSL's reason (`… (18)`).
    - Now (0.3.16): three stores, tried in order with the name check: the supplied root; the **OS store** through `rustls-platform-verifier` (the OS builds the chain — on Windows that fetches a root the machine hasn't cached yet, which reading the ROOT store with rustls-native-certs missed for www.example.com); then Mozilla's roots built into the app (`webpki-roots`). The first that verifies is reported: the summary says "(using the supplied root)", "(OS trust store)" (the reference's words for both) or "(built-in trust store)", and the result has `trust_store`: `supplied root` | `os` | `built-in` (a new key; the page doesn't read it). The API check uses the same stores. 0.3.15 had no OS store.
    - A failure gives the reason in words (`verify::describe`): "the chain doesn't lead to a trusted root (unknown issuer)", "the certificate isn't valid for this name (…)", "the server's certificate is a CA certificate, as self-signed ones often are", and so on. The API check's `tls_error` uses the same words.
    - When no store verifies, the reason given is the first store's (the supplied root's when there is one, else the OS store's).
    - **What the server sends, in plain words (0.3.19):** when the served certificate is self-signed, the summary says "the appliance serves a self-signed certificate ("…"): browsers, agents and hosts won't trust it. Install a CA-signed certificate (steps 2 and 3)."; when it's a CA certificate sent as the server's own, it says that. The appliance-side line marks a self-signed certificate "(self-signed)".
    - Connection errors are rustls/tokio's text, not Python's `[Errno …]`.
24. **Morpheus API: changing the Appliance URL.** The reference let an HTTP error from `PUT /api/appliance-settings` escape as a 500 (`HTTPError: …`). Now it's an error that says Morpheus refused the change, with the status, and that the token's user needs permission to edit appliance settings.
25. **Events carry no `ts`, and there's no replay history.** The reference stamped every SSE event and replayed the last 400 to a reconnecting browser. The page never reads `ts`, and the app's page listens for its whole life, so neither is kept (`events.rs`).
26. **Ports from the page are checked.** `port`, `tls_port`, `cols`, `rows` arrive as text; a value that isn't a number is an error that says so ("… isn't a port number"), where the reference raised `ValueError` (a 500).

27. **A wildcard is never the FQDN (0.3.17).** The reference derived the FQDN from the first SAN, or the CN when that SAN was a wildcard, so a wildcard certificate (`CN=*.example.com`) got the FQDN `*.example.com`, which then went into verify's SNI, the file names and INSTALL.txt. Now a name containing `*`, derived or typed, is never used:
    - connected (preflight ran): `analyze_with_hosts` suggests the appliance's `hostname -f` if the certificate covers it, else its short name + the wildcard's domain if covered, with a warning that says where the name came from;
    - otherwise, or when nothing is covered: the FQDN stays empty and an error says "Wildcard certificate: enter the appliance's FQDN.", so export and plan are blocked until a covered, non-wildcard name is entered; `verify` refuses a wildcard name.
    - Corpus: `leaf-wildcard.crt` (`*.wild.test` + `wild.test`), its key and `wildcard-root.crt`, added as a guarded block in gen-corpus.sh. Cases `wildcard-leaf` and `wildcard-fqdn-typed` carry a `rust_expect_override` (make-cases.py `wildcard_override`); `wildcard-fqdn-given` (a covered name) matches the reference as is. Unit tests for the suggestion in `analyze::wildcard_tests`; the commands in `tests/commands.rs`.
28. **"Trust this CA" starts from the actual certificates (0.3.17; reworked 0.3.19).** The reference page ticked it when the chain had a root whose CN didn't match a list of CA brands (DigiCert, Sectigo, GoDaddy …). Now the app decides (`src-tauri/src/trust.rs`) and the analysis JSON carries `trust_default`, `trust_reason` and `trust_store` (new keys; the page shows the reason under the checkbox, and the name list is gone from the page):
    - **Which CAs:** the chain (intermediates and root), plus every supplied CA certificate that is another form of a chain CA (same subject and key: a cross-signed copy the chain walk left unused). Each is compared with the trust anchors by **subject and public key, taken raw from the certificate's DER** (trust anchors aren't whole certificates); a CA also counts when its issuer is an anchor and its signature verifies with that anchor's key.
    - **ANY** of them among the Mozilla roots built into the app: off, "Publicly trusted: Morpheus' Java already trusts it." (A chain ending at "GoDaddy TLS Root CA – R1", which Mozilla doesn't list, is public through "Go Daddy Root Certificate Authority – G2".)
    - otherwise any in this computer's certificate store: **on** (0.3.18), "Only in this computer's trust store, not in the public roots: likely your organisation's own CA …";
    - otherwise: on, "Private CA: Morpheus' Java won't trust it until it's imported."; no CA certificates at all: off.
    - 0.3.17–0.3.18 looked only at the chain's root (or the top CA's issuer, by name), so a public chain ending at a root Mozilla doesn't list came out "private" and ticked (the manual check's GoDaddy chain).
    - Tested with real public roots committed as test data (`src-tauri/testdata/public-roots/`: ISRG Root X1, Go Daddy G2 — public certificates, taken from Mozilla's list via the `webpki-root-certs` crate), the corpus private root, and a stand-in OS store; on Windows also a real root the OS has and Mozilla doesn't.
    - "Restart morpheus-ui" follows the checkbox, as before.
    - **No server certificate (0.3.20):** with only CA certificates supplied there's no chain; every supplied CA (they sit among the unused certificates) is judged, so the Go Daddy G2 root alone is "Publicly trusted", off. Before, it said "No CA certificates were supplied" and the page didn't touch the box at all.
29. **Rollback restores /etc/morpheus/ssl exactly; an installed-files ledger (0.3.19).** The reference's rollback copied the backup's `ssl/` over the live one, so the certificate and key the rolled-back install had written stayed behind (a private key left on the appliance for good, copied into every later backup).
    - After the restore, rollback removes the `.crt`/`.key` the rolled-back install wrote (its manifest's `crt`, `key`) that the backup doesn't have; the key is shredded (`appliance::rollback_remove_installed`).
    - Apply records every certificate and key file it installs in `/var/lib/morpheus-certificate-install/installed.json` (root 0600; kept when backups are removed). In the operation sequence that's a read and a write after the key/cert match, recorded in the golden's `rust_expect_override` (`insert`).
    - Cleanup has an option, off by default, to remove ledger files morpheus.rb no longer names (keys shredded). Only `/etc/morpheus/ssl/<name>.crt|.key` the ledger lists can be named (`appliance::installed_name`); nothing else is ever touched.
    - Tested: mci-core goldens + a bash run (only what the backup lacks goes; unnamed files untouched), `engine::tests`, and live in `engine_e2e` (after rollback the installed files are gone, the earlier ones byte-identical) and `cleanup_end_to_end` (unused installed files removed only when asked).
30. **The Run log shows a step's stdout, and its stderr only when it fails (0.3.19).** Tool steps (backup, key match, launching the runner, the restore, cleanup) went through `run`, whose merged output carried sudo's lecture into the Run log. They now use `run_data`: stdout on success; on failure the error quotes stderr first.
31. **Page fixes found by the click tests (0.3.20).** `ui/index.html` only; no command or JSON changed.
    - **Every analysis sets "Trust this CA" and its reason**, with or without a chain, and **Clear files** unticks it, clears the reason and the step's done mark. The reference page set the box only when a chain was drawn, so after Clear files a leaf-less analysis kept the previous chain's tick (and here its reason).
    - **The changed-host-key message** ends "If the appliance was rebuilt, check this fingerprint on the appliance, then click "Forget this appliance" and connect again." The reference said to remove a line from `~/.morpheus-certificate-install/known_hosts`, a path this app doesn't use (its known_hosts is in the data folder, and Forget removes the line).
    - Not from the reference: the Tauri build's CSP blocked every inline style (see CHANGELOG 0.3.20, `dangerousDisableAssetCspModification`); the Python page had no such CSP.

## Not ported (decide later)

- **JCEKS keystores** (`0xCECECECE`). Recognised and reported as the reference did without `pyjks`: "JCEKS keystores aren't read by this version. Convert it first: keytool -importkeystore …". JKS is read natively.
- **PBES1 key encryption** (`pbeWithMD5AndDES-CBC` and friends, pre-2000 `openssl pkcs8 -v1`) and **RC4 PKCS#12 PBE**. Reported as unsupported with "export it again with AES-256". PKCS#12 PBE with 3DES/RC2 and PBES2 (PBKDF2 or scrypt; AES, 3DES, DES) are supported.
- **OpenSSH keys encrypted with `chacha20-poly1305@openssh.com` or AES-GCM.** ssh-keygen's default (aes256-ctr) and AES-CBC are supported; the others get "convert it: ssh-keygen -p -m PKCS8".

- **The 0.2.0 `/var/lib/sphragis` and `/var/log/sphragis` paths.** Old runs and backups there aren't listed (same as 0.2.1).
