# Architecture — morpheus-certificate-install 0.4.0

```
ui/index.html ──bridge.js──► Tauri invoke("<command>", {args})      ◄── events on "mci"
                                     │
src-tauri (mci_app)                  ▼
  lib.rs      command list (one JSON arg in, JSON or error string out)
  engine.rs   handlers + jobs: preflight · plan · apply · verify · rollback · runs/backups · shell
  verify.rs   TLS from this machine (rustls)        morpheus_api.rs   whoami / appliance-settings
  transport/  trait Transport ─┬─ ssh.rs         (charon-ssh: TOFU host keys, sudo detect, PTY)
                               └─ charon_mcp.rs  (Charon's MCP server: run_command, sftp_put)
  paths.rs    portable.flag → ./data/ , else <config>/morpheus-certificate-install/
                                     │
crates/mci-core (no Tauri, no I/O)   ▼
  formats.rs  any input → Cert / PrivateKey / FileReport
  analyze.rs  leaf, chain, root, checks, to_json (the UI's contract)
  aia.rs      complete the chain (fetch closure supplied by caller)
  export.rs   <base>.crt/.key, ca-chain.pem, trusted_certs/, morpheus.rb.snippet, INSTALL.txt
  morpheus_rb.rs · runner.rs · appliance.rs · quote.rs · names.rs   ← ported, golden-tested
crates/mci-cli   morpheus-certificate-install-cli convert …
```

## Commands

Every command takes `{args}` and returns the same JSON as the Python route it replaces.

| Command | Python route | Notes |
|---|---|---|
| `state` | GET `/api/state` | version, connected, transport info, facts, analysis, plan, busy, settings |
| `connect` | `/api/connect` | `{mode:"ssh",host,port,user,password,sudo_password,key_path,key_passphrase,trust_fingerprint}` or `{mode:"charon",session,charon_dir}`. Can return `{ok:false, hostkey:{host,type,fingerprint,mismatch}}` |
| `disconnect` | `/api/disconnect` | |
| `charon_discover` | `/api/charon` | `{searched,data_dir,endpoint,hosts,sessions?,sessions_error?}` |
| `preflight` | `/api/preflight` | job; emits `facts` |
| `analyze` | `/api/analyze` | `{files:[{name,b64}], pasted, pfx_password, key_password, fqdn, appliance_url?}` → AnalysisJson |
| `clear_files` | `/api/clear-files` | |
| `fetch_chain` | `/api/fetch-chain` | → `{log, analysis}` |
| `export_zip` | `/api/export` | **differs:** save dialog in Rust → `{saved: path\|null, files}` |
| `plan` | `/api/plan` | `{server, include_root, trust, restart_ui}` → steps, rb_diff, stamp, … |
| `apply` | `/api/apply` | `{confirm: <plan stamp>}`; job |
| `verify` | `/api/verify` | `{fqdn, port, connect_addr}`; job; emits `verify` |
| `runs` / `reattach` / `stop` | same | |
| `backups` / `rollback` | same | `rollback {id}` is a job |
| `morpheus_check` / `set_appliance_url` | `/api/morpheus`, `/api/morpheus/appliance-url` | |
| `shell_open` / `shell_input` / `shell_resize` | `/api/shell/*` | SSH transport only; output arrives as `shell` events (base64) |

## Events (`mci` channel)

The event types are `log`, `remote`, `step`, `shell`, `shell_closed`, `run`, `job`, `facts`, `verify`, `connected` and `disconnected`; see `src-tauri/src/events.rs` for the fields. Step ids:

- local steps: `backup`, `files`, `rb`, `match`, `trustfiles`, `runner`, `restore`;
- runner steps: `run:<step>`, parsed from `@@MCI step=` / `@@MCI rc=` lines.

## On the appliance

| Path | What |
|---|---|
| `/etc/morpheus/ssl/<base>.crt`, `.key` | 0600 root; full chain; decrypted PKCS#8 |
| `/etc/morpheus/ssl/trusted_certs/mci-*.pem` | 0644, in a 0755 dir |
| `/etc/morpheus/morpheus.rb` | one managed block; earlier `nginx[...]` lines commented with a stamp |
| `/var/lib/morpheus-certificate-install/backups/<stamp>/` | `ssl/`, `morpheus.rb`, `manifest.json` (0700 tree) |
| `/var/lib/morpheus-certificate-install/runs/<run>.sh` | 0700 runner script |
| `/var/log/morpheus-certificate-install/<run>.log`, `.rc` | log 0600, owned by the operator |

The runner is a transient systemd unit `morpheus-certificate-install-<run>` (or setsid where there's no systemd). Its steps are reconfigure → keytool imports → restart nginx → restart morpheus-ui → status.
