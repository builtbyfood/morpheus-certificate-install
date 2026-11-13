# Security policy — morpheus-certificate-install 0.4.0

## Reporting a vulnerability

Please report security problems privately, not in a public issue. On this repository's GitHub page, open **Security → Report a vulnerability** (GitHub's private vulnerability reporting). Only the maintainers see the report.

Include what you can of:

- the version (the window's title bar, or `morpheus-certificate-install-cli --version`) and platform (Windows, Linux or macOS; installed or portable; on a Mac, Apple Silicon or Intel);
- the transport (SSH or a Charon session);
- what an attacker needs (a hostile appliance or SSH server, a local user, a crafted certificate file…) and what they get;
- steps or a proof of concept.

You should get an answer within a week. Please give us a reasonable time to ship a fix before publishing details.

### Scope

In scope, for example:

- a secret (an SSH or sudo password, a key passphrase, the Morpheus API token) reaching disk, a log, the Run log, an event or a host it wasn't meant for;
- connecting despite a changed host key, or trusting a host key without the user's confirmation;
- a crafted input file making the app write outside the folder or zip the user chose, or run anything;
- a file on the appliance written with wider permissions than listed below;
- anything that gets past Charon's approval dialog when the Charon transport is used.

Out of scope: what an appliance you log in to as an administrator can already do, and attacks that need control of your own user account.

### Supported versions

Only the latest release gets fixes.

## What the app stores on your computer

There are no secrets on disk. Passwords, key passphrases and the Morpheus API token are held in memory only, for as long as the window is open.

| File | What |
|---|---|
| `settings.json` | only: host, port, user, key file path, FQDN, connect address, Morpheus URL, transport mode, Charon data folder and TLS port |
| `known_hosts` | the host keys you confirmed, one per appliance |
| `webview/` (portable only) | the window's browser profile |

On Windows and Linux they live in `data\` beside the app when `portable.flag` is there, and otherwise in `%APPDATA%\morpheus-certificate-install\` (Windows) or `~/.config/morpheus-certificate-install/` (Linux). On macOS they're always in `~/Library/Application Support/morpheus-certificate-install/`, because there's no portable mode there. With **Leave no trace** ticked (portable, Windows and Linux), nothing is saved, and `data\` is deleted when the window closes. **Forget this appliance** removes one appliance's host key and settings.

The private key you load is read in memory and is never written anywhere you didn't choose.

## What it writes on an appliance

Every file is root-owned unless the table says otherwise.

| Path | Mode |
|---|---|
| `/etc/morpheus/ssl/<fqdn>.crt`, `<fqdn>.key` | 0600 |
| `/etc/morpheus/ssl/trusted_certs/mci-*.pem` | 0644, in a 0755 directory |
| `/etc/morpheus/morpheus.rb` | edited, not replaced: one managed block is added and older `nginx['ssl_…']` lines are commented out |
| `/var/lib/morpheus-certificate-install/backups/<stamp>/` | a 0700 tree; it holds the previous key |
| `/var/lib/morpheus-certificate-install/runs/<run>.sh` | 0700 |
| `/var/log/morpheus-certificate-install/<run>.log` | 0600, owned by the SSH user, so they can follow it without sudo |

With password sudo, every command runs as `sudo -k -S -p ''`. sudo always reads the password line itself, so it can never flow into a file the command writes. The tests check the appliance for the password after an install.

**Clean up this appliance** shreds key files before removing them, including those in old backups.

## Exported files hold a decrypted key

The zip and folder from **Download files for Morpheus** (and the CLI's `convert`) contain `<fqdn>.key` **unencrypted**, because Morpheus needs it that way. Treat them like a password. Delete them once the certificate is installed, and don't send them by e-mail or chat. On Linux and macOS the CLI writes the key with mode 0600, and inside the zip it's marked 0600.

## Unsigned binaries

The release binaries aren't code-signed on Windows, and aren't signed or notarized on macOS. As a result:

- Windows SmartScreen warns on first run;
- macOS Gatekeeper won't open the app until you allow it (README → macOS).

Only the checksum shows that a download came from this project. Download only from this repository's Releases page, and compare every file with that release's `SHA256SUMS` before running it.

## Host keys

The first connection shows the appliance's key fingerprint and waits for you to confirm it. Later connections must match it exactly. A changed key is refused, never accepted automatically. If the appliance really was rebuilt, choose **Forget this appliance** and connect again to check the new fingerprint.
