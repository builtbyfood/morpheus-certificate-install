# The fake appliance — morpheus-certificate-install 0.4.1

`tests/fake-appliance/` turns a machine into a stand-in for an HPE Morpheus appliance, good enough for the SSH transport tests (R5), the engine end-to-end test (R7) and the click tests (R8). **It is not Morpheus.** It has an SSH server, a user whose `sudo` asks for a password, and stand-ins for `morpheus-ctl`, `keytool` and nginx.

It runs on **an Ubuntu 24.04 or 26.04 VM**, set up by `install-on-vm.sh` (here `fake-appliance`, 192.0.2.10, **Ubuntu 26.04 with sudo switched to classic sudo**, as on appliances, on an ESXi host). systemd is real, so runners go through `systemd-run`, as on a real appliance. (A Docker image existed until 0.3.20; it was dropped, untested, in 0.3.21.)

> **Use a throwaway VM, never a real server or appliance.** The installer creates the user `mcitest` with the password `hunter2` and sudo rights, installs stand-ins named `morpheus-ctl` and `keytool`, and writes under `/etc/morpheus` and `/opt/morpheus`. The tests then install, roll back and delete files there.

> The VM is driven from the Windows dev machine over SSH (the live tests, and `install-on-vm.sh` copied across and run as `mcitest` with `sudo`). Every command that needs root carries its own `sudo`.

## What it fakes

| Part | Behaviour |
|---|---|
| Login | user `mcitest`, password `hunter2`, password authentication on. Ports 22 **and 2222**; the test line is `<vm>:2222:mcitest:hunter2`. |
| sudo | `mcitest` is in `sudo` and must type the password. **sudo's lecture is printed on every prompt** (`Defaults:mcitest lecture=always`). That's on purpose: it puts text on stderr of every password sudo (and, through Charon, into the terminal), which tests that data reads use only the command's stdout (`Transport::run_data`). See "sudo on Ubuntu 26.04" below. |
| Host keys | The VM's own keys in `/etc/ssh`. `rotate-host-keys` replaces them on request (see below). |
| `/etc/morpheus/morpheus.rb` | `appliance_url 'https://198.51.100.20'` plus one Elasticsearch line, mode 0600. |
| `/etc/morpheus/ssl` | a self-signed `appliance` certificate and key, served until an install points nginx elsewhere. |
| `morpheus-ctl` | must run as root. `reconfigure` prints Chef-like output and fails if morpheus.rb names a certificate file that isn't there. `restart nginx` restarts the fake nginx (the `mci-fake-nginx` service on the VM). `status` lists it. |
| `keytool` (`/opt/morpheus/embedded/java/bin/keytool`) | Keeps a keystore's state in `/var/lib/fake-morpheus/keytool-aliases`. `-importcert` adds an alias and fails (exit 1) if it already exists. `-delete` removes it (exit 0) and fails (exit 1) if it doesn't exist. `-list [-alias A]` works too. These are real keytool's exit codes. Calls are logged to `/var/log/fake-morpheus/keytool.log` with the store password masked. |
| nginx (`fake-nginx.py`) | serves, on 443, the certificate and key that morpheus.rb's `nginx['ssl_certificate']` / `nginx['ssl_server_key']` name. VM: the systemd service `mci-fake-nginx`. |
| Morpheus API (`fake-nginx.py`, 0.3.15) | on the same 443: `GET /api/whoami` (user `mci-api-tester`, build `8.0.0-fake`), `GET` and `PUT /api/appliance-settings` (`applianceSettings.applianceUrl`), answered only for the **test token** `mci-fake-api-token-7f3c9a1e` as `Authorization: Bearer …`. No token or a wrong one: 401. The Appliance URL setting starts as morpheus.rb's `appliance_url` and is kept in `/var/lib/fake-morpheus/appliance-url`. Anything else on 443: 200 `ok`. The token is a test fixture, written in the script; it opens nothing but this stand-in. |
| systemd | real, so preflight reports `SYSTEMDRUN=yes` and runners use `systemd-run --collect`. On a host without systemd, set `MCI_TEST_NO_SYSTEMD=1` for the transport test. |

## VM

### Create it

1. On the ESXi host, create a VM from the Ubuntu Server 24.04 or 26.04 ISO: 2 vCPU, 2 GB RAM and a 16 GB disk are plenty.
   - Install OpenSSH server when the installer offers it.
   - Create any first user; the script adds `mcitest`.
2. Give it an address you can reach from the machine running the tests (DHCP reservation or static).
3. Copy the folder over (from the repo root, on the machine with the checkout):

   ```bash
   scp -r tests/fake-appliance <you>@<vm>:~/fake-appliance
   ```

4. On the VM:

   ```bash
   cd ~/fake-appliance
   sudo bash install-on-vm.sh
   ```

   It ends with a checklist (`ok` / `FAIL`), the SSH host key fingerprint, and the test line to use.
   - It's safe to run again: after changing files in the folder, copy them over and re-run.
   - It keeps existing state: morpheus.rb, the certificate, keystore aliases, the app's runs and backups.
   - If it warns that `mcitest` has a NOPASSWD sudo rule (some cloud images add one), remove that rule. Otherwise the app sees `nopasswd` sudo and the test, which expects password sudo, fails.
5. **Take a snapshot now** (e.g. `fake-appliance-clean`). Resetting is reverting to it.

### sudo on Ubuntu 26.04

Ubuntu 26.04's default `sudo` is **sudo-rs** (0.2.13), which prints no lecture, only a newline on stderr. Classic sudo is installed beside it as `/usr/bin/sudo.ws`.

- **fake-appliance runs classic sudo**, as on current appliances, so the lecture shows. The 0.3.10 live run passed on sudo-rs as well.
- `install-on-vm.sh` says so when it finds sudo-rs, but doesn't switch.

To classic sudo (lecture on):

```bash
sudo update-alternatives --set sudo /usr/bin/sudo.ws
```

Back to sudo-rs:

```bash
sudo update-alternatives --set sudo /usr/lib/cargo/bin/sudo
```

Check which one is active with `sudo --version | head -1`: classic says `Sudo version 1.9…`, the other `sudo-rs …`.

### Run the tests against it

From the repo root on the machine with the checkout:

```bash
MCI_TEST_SSH=<vm>:2222:mcitest:hunter2 cargo test -p morpheus-certificate-install --test ssh_fake_appliance -- --ignored --nocapture
```

- **`ssh_transport_against_the_fake_appliance`** covers:
  - the TOFU round trip;
  - password sudo;
  - `run` vs `run_data` with the lecture;
  - `put_root` modes and ownership;
  - follow to rc, and stop;
  - preflight `SYSTEMDRUN=yes` and a runner launched through `systemd-run`, followed to its rc, with its unit gone afterwards (`--collect`);
  - timeout;
  - reopening the shell;
  - the keytool stand-in;
  - the password-leak grep.
- **`rotated_host_key_is_refused`** rotates the host keys, then expects `HostKey { mismatch: true }`, even when the new fingerprint is offered. **It runs only with `MCI_TEST_ROTATE=1`** (since 0.3.16), even when the file runs unfiltered; without it, it prints "skipped" and passes.

Each test starts from its own empty `known_hosts` in the temp directory. To run only one, put its name after `--test ssh_fake_appliance`.

> **`rotated_host_key_is_refused` changes the VM's host key for good** (the old key is deleted). A Charon session or an `ssh` known_hosts entry for the VM then sees a changed key. That's why it needs `MCI_TEST_ROTATE=1`:
>
> ```bash
> MCI_TEST_ROTATE=1 MCI_TEST_SSH=<vm>:2222:mcitest:hunter2 cargo test -p morpheus-certificate-install --test ssh_fake_appliance rotated_host_key_is_refused -- --ignored --nocapture
> ```

The engine end to end (R7) drives the app's commands — convert, connect, preflight, plan, apply, verify, the API check, runs, backups, rollback — and checks the VM over a second SSH connection. It resets the VM's morpheus.rb, CA aliases and API setting first, and ends rolled back:

```bash
MCI_TEST_SSH=<vm>:2222:mcitest:hunter2 cargo test -p morpheus-certificate-install --test engine_e2e -- --ignored --nocapture
```

"Clean up this appliance" (0.3.17): two installs, then the cleanup with its defaults and with "all backups"; listings before and after show only the tool's own paths went, and the backups' keys were shredded:

```bash
MCI_TEST_SSH=<vm>:2222:mcitest:hunter2 cargo test -p morpheus-certificate-install --test engine_e2e cleanup_end_to_end -- --ignored --nocapture
```

The two live tests in `engine_e2e` never run at the same time (they share the appliance).

The click tests (R8, `tests/click/README.md`) drive the real app's page against the VM: install → verify → rollback, a host-key mismatch (from a pre-seeded `known_hosts`; the VM's key isn't rotated), and cleanup while a run is still going. They reset the VM first and leave it rolled back and cleaned up:

```bash
MCI_TEST_SSH=<vm>:2222:mcitest:hunter2 npm run test:click
```

Through Charon (apply → verify → rollback), with a **trusted** Charon session to the VM as `mcitest`:

```bash
MCI_TEST_E2E_CHARON=mcitest@<vm> MCI_TEST_SSH=<vm>:2222:mcitest:hunter2 cargo test -p morpheus-certificate-install --test engine_e2e -- --ignored --nocapture
```

### Rotate the host key

```bash
sudo rotate-host-keys
```

Run it on the VM, or over SSH as `mcitest`. It regenerates the VM's ed25519, ECDSA and RSA host keys in `/etc/ssh` and restarts only `ssh.service`. Open SSH sessions stay up, and the next connection gets the new key.

**What to expect:**
- Anything that trusted the old key now refuses: the app says "The host key for … has CHANGED", and `ssh` warns too.
- To trust the new key on purpose, remove the host's line from the app's `known_hosts` (`<data dir>/known_hosts`), and with `ssh-keygen -R '[<vm>]:2222'` for OpenSSH.
- `rotated_host_key_is_refused` does this itself. Reverting to the snapshot brings the original key back.

### Reset

Revert the VM to the snapshot taken after `install-on-vm.sh`. That restores morpheus.rb, `/etc/morpheus/ssl`, the keystore aliases, the app's runs, backups and logs, and the original host key.

Without a snapshot, these reset part of it:

| To reset | Commands (on the VM) |
|---|---|
| The keystore aliases | `sudo rm -f /var/lib/fake-morpheus/keytool-aliases` |
| morpheus.rb and the starting certificate | `sudo rm -f /etc/morpheus/morpheus.rb /etc/morpheus/ssl/appliance.crt /etc/morpheus/ssl/appliance.key`, then `sudo bash ~/fake-appliance/install-on-vm.sh` |
| The app's runs, backups and logs | `sudo rm -rf /var/lib/morpheus-certificate-install /var/log/morpheus-certificate-install` |
| The fake nginx | `sudo systemctl restart mci-fake-nginx` |
| The fake API's Appliance URL setting | `sudo rm -f /var/lib/fake-morpheus/appliance-url` |

### Where to look (VM)

| What | Where |
|---|---|
| sshd | `sudo journalctl -u ssh` |
| fake nginx | `sudo journalctl -u mci-fake-nginx` and `/var/log/fake-morpheus/nginx.log` |
| keytool calls | `/var/log/fake-morpheus/keytool.log` |
| runners started by the app | `systemctl list-units 'morpheus-certificate-install-*'` while running; `sudo journalctl -u 'morpheus-certificate-install-*'` |
| the app's runs and backups | `/var/log/morpheus-certificate-install`, `/var/lib/morpheus-certificate-install` |
