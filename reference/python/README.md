# Morpheus Certificate Install

*Version 0.2.1.*

Morpheus Certificate Install takes whatever certificate files a CA or a customer sends you and turns them into the files an HPE Morpheus appliance needs. It can then install them on the appliance:

- with a backup taken first;
- watching `morpheus-ctl reconfigure` live as it runs;
- checking what nginx actually serves afterwards;
- with one-click rollback.

It's a small local web app (Python + paramiko). It runs on Windows, Linux and macOS and listens only on 127.0.0.1.

## Run it

```bash
pip install -r requirements.txt        # paramiko, cryptography, pyjks (optional, for .jks)
python -m morpheus_certificate_install   # opens the browser on http://127.0.0.1:8765/#t=<token>
```

Or install it with `pip install .[jks]` and run `morpheus-certificate-install`. Secrets are held in memory only: SSH and sudo passwords, key passphrases, the Morpheus API token. Non-secret settings are kept in `~/.morpheus-certificate-install/settings.json`, and trusted host keys in `~/.morpheus-certificate-install/known_hosts`.

## Just convert

The Certificate step works without connecting to anything. Drop the files in, then use **Download files for Morpheus (.zip)**. From the command line:

```bash
morpheus-certificate-install convert cert.p7b private.key                   # writes ./<fqdn>-morpheus/
morpheus-certificate-install convert customer.pfx --ask --zip               # prompts for the PFX password
morpheus-certificate-install convert leaf-only.cer leaf.key --fetch-chain   # downloads the intermediates via AIA
```

The output layout matches HPE's docs:

| File | Goes to | What it is |
|---|---|---|
| `<fqdn>.crt` | `/etc/morpheus/ssl/` | server cert + intermediates, PEM, in nginx order |
| `<fqdn>.key` | `/etc/morpheus/ssl/` | private key, **decrypted** PKCS#8 PEM (Morpheus requires it) |
| `ca-chain.pem` | VME hosts / clients | root + intermediates |
| `trusted_certs/*.pem` | `/etc/morpheus/ssl/trusted_certs/` | one CA cert per file, for Morpheus' Java truststore |
| `morpheus.rb.snippet` | `/etc/morpheus/morpheus.rb` | the `nginx['ssl_certificate']` / `nginx['ssl_server_key']` lines |
| `INSTALL.txt` | — | what was converted from what, plus the manual commands |

### Formats it reads

Inputs are detected by content, so file extensions don't matter.

| What customers send | Read as |
|---|---|
| `.pem` `.crt` `.cer` `.txt` — PEM, CRLF, BOM, "Bag Attributes", UTF-16 | certificates / keys |
| `.cer` `.der` — binary | DER certificate |
| `.p7b` `.p7c` — PEM or DER | PKCS#7 chain |
| `.pfx` `.p12` — including legacy RC2/3DES Windows exports | key + cert + chain |
| `.jks` `.jceks` (needs `pyjks`) | key entries + trusted certs |
| `.key`: PKCS#8, PKCS#1 `RSA PRIVATE KEY`, `EC PRIVATE KEY`, encrypted PEM (both kinds), DER, OpenSSH | private key |
| base64 pasted without the `-----BEGIN` lines | decoded and re-detected |
| CSR, CRL, public key, `.pvk` | recognised and explained, not used |

These are checked before anything is written:

- the key matches the certificate;
- the chain is complete and in order;
- expiry and signature algorithm;
- the FQDN is covered by the SANs;
- the Appliance URL host is covered (for example, a Morpheus Appliance URL that is still an IP).

## Install on the appliance

1. **Connect.** Use Morpheus Certificate Install's own SSH, or an SSH session already open in [Charon](https://github.com/builtbyfood/charon), through its MCP server.
   - With Charon at the `exec-approve` tier, each step shows up in Charon's approval dialog.
   - Charon's saved hosts can fill the SSH form. Credentials are never read.
2. **Load and convert**, as above.
3. **Review and install.** You see the step list and the exact `morpheus.rb` diff first. Then Morpheus Certificate Install:
   1. backs up `/etc/morpheus/ssl` and `morpheus.rb` to `/var/lib/morpheus-certificate-install/backups/<stamp>/`;
   2. writes the cert and key (root-owned, 0600);
   3. edits `morpheus.rb` idempotently, commenting out old lines and keeping one managed block;
   4. checks that the key matches the cert on the appliance;
   5. starts a **detached runner** with `systemd-run`, or `setsid` without systemd. The runner does `morpheus-ctl reconfigure`, then keytool imports if trusting the CA, then `morpheus-ctl restart nginx`, and optionally `restart morpheus-ui`.

   The runner logs to `/var/log/morpheus-certificate-install/<run>.log`, owned by you with mode 0600. It keeps going if your laptop drops. Morpheus Certificate Install streams the log live and shows a `tail -F` command so you can watch from any terminal.
4. **Verify.** This step:
   - compares the fingerprint served on `127.0.0.1:443` with the new cert;
   - checks the chain and hostname from your machine against the supplied root;
   - optionally calls `/api/whoami` and `/api/appliance-settings`.
5. **Runs and backups.** Reattach to any run, or roll back to any backup. Rolling back saves the current state as a backup first.

The Shell tab is an interactive terminal to the appliance over the same SSH connection.

### Why not a Morpheus plugin?

- The final `restart nginx` drops any page served by Morpheus partway through the run.
- Plugins can't get decrypted credentials on current builds (see hvm-updater's notes).

Running outside the appliance avoids both problems.

## Security notes

- The HTTP server binds to 127.0.0.1 only. Every API call needs the per-launch token, and the Host header must be `127.0.0.1` or `localhost`, which blocks DNS rebinding.
- sudo is detected as root, NOPASSWD, or password. Password-mode commands run as `sudo -k -S`, so the password line is always consumed by sudo and can never reach a file. The tests check this.
- The exported `.key` is unencrypted, because Morpheus needs it that way. Hand it over like a password.

## Tests

```bash
pip install .[test]
python -m pytest -q          # 22 tests: conversion formats, chain building, AIA fetch, export layout, morpheus.rb edits
```

`tests/mock_charon.py` stands in for Charon's MCP server, speaking the same JSON-RPC and tool contract. It's for exercising the Charon transport without the app.

## License

Apache-2.0. xterm.js is vendored under `sphragis/web/vendor/` and is MIT-licensed (see `LICENSE-xterm.txt`).
