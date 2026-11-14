# Changelog

## 0.2.1 — 2026-11-05

### Changed
- Renamed from Sphragis to **morpheus-certificate-install**:
  - Python package `morpheus_certificate_install`
  - command `morpheus-certificate-install` (`python -m morpheus_certificate_install`)
  - UI title "Morpheus Certificate Install"
- Paths on the appliance: `/var/lib/morpheus-certificate-install/` (backups, runner scripts) and `/var/log/morpheus-certificate-install/` (run logs). The systemd unit is `morpheus-certificate-install-<run>`.
- The `morpheus.rb` block marker now reads `morpheus-certificate-install managed block`. A block written by 0.2.0 (`sphragis managed block`) is recognised and replaced, so it isn't duplicated.
- Java truststore aliases are now `mci-<cn>-<fp8>`.
- Local config dir is `~/.morpheus-certificate-install/` (override: `MCI_HOME`).
- Environment variables for the converter are `MCI_PFX_PASSWORD` and `MCI_KEY_PASSWORD`.

## 0.2.0 — 2026-11-05

First delivered build (as Sphragis).

### Added
- **Format conversion.** Reads whatever a CA or customer sends, by content rather than extension:
  - PEM in any label variant, including CRLF, BOM, and Windows "Bag Attributes" noise
  - DER certificates
  - PKCS#7 `.p7b`/`.p7c` (PEM or DER)
  - PFX/P12, including legacy RC2/3DES Windows exports
  - Java keystores JKS/JCEKS (optional `pyjks`)
  - UTF-16 text files, and base64 with the PEM headers stripped
  - Every private-key encoding: PKCS#8, PKCS#1, SEC1, DSA, legacy OpenSSL-encrypted, DER plain/encrypted, OpenSSH
  - CSRs, CRLs, bare public keys and Microsoft `.pvk` are recognised and explained rather than rejected.
- Every password given is tried on every locked item, so typing the PFX password into the key box still works.
- A per-file report shows what each input turned out to be.
- **Fetch missing chain.** Follows AIA "CA Issuers" URLs to download intermediates and the root when only the leaf was supplied.
- **Download for Morpheus (.zip)** contains:
  - `<fqdn>.crt` (leaf + intermediates) and `<fqdn>.key` (decrypted PKCS#8, mode 0600)
  - `ca-chain.pem` and `trusted_certs/<alias>.pem`
  - `morpheus.rb.snippet`
  - `INSTALL.txt` with the manual commands (each root command carries its own `sudo`)
- `morpheus-certificate-install convert FILE… [--fqdn] [--out|--zip] [--fetch-chain] [--include-root] [--ask]` for the same conversion from the command line. Passwords can be given with `--ask`, or with `MCI_PFX_PASSWORD` / `MCI_KEY_PASSWORD`.
- Pasted-PEM box in the Certificate step. Conversion works without connecting to an appliance.

### Fixed
- If xterm.js fails to initialise, the Run log and Shell tabs fall back to plain text instead of taking the page script down with them.

## 0.1.0 — 2026-11-04 (built, not delivered)

- Local web GUI bound to 127.0.0.1 with a per-launch token and a Host-header check.
- SSH transport (paramiko): host-key trust on first use, sudo detection (root / NOPASSWD / password), interactive Shell tab.
- Charon transport: drives an open Charon SSH session through its MCP server (`run_command`, `sftp_put`); fills the SSH form from Charon's saved hosts.
- Installs the server certificate per HPE's "SSL Certificates" doc and trusts the CA per "Import Trusted Certificates":
  - backup first
  - a detached runner on the appliance (systemd-run or setsid) that streams live and can be reattached
  - fingerprint and chain verification
  - Morpheus API check and optional Appliance URL change
  - rollback that saves the current state first
