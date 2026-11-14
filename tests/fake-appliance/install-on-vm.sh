#!/bin/bash
# morpheus-certificate-install 0.4.2 — turn a fresh Ubuntu 24.04 or 26.04 VM into the fake appliance.
#
#   sudo bash install-on-vm.sh        (from this folder, copied to the VM)
#
# The stand-ins: morpheus-ctl, keytool with alias state, fake nginx on 443 with a
# sliver of the Morpheus API (here a systemd service), the /etc/morpheus layout, user mcitest / hunter2 in sudo with lecture=always.
# The VM keeps its own SSH host keys. systemd is real, so the app's preflight
# reports SYSTEMDRUN=yes and runners go through systemd-run.
# Safe to run twice: packages, users, files and the service are only (re)installed; existing state —
# morpheus.rb, /etc/morpheus/ssl, keystore aliases, the app's runs and backups — is left as it is.
# docs/FAKE-APPLIANCE.md has the whole procedure, including resetting by snapshot.
set -euo pipefail

[ "$(id -u)" = 0 ] || { echo "Run it with sudo: sudo bash install-on-vm.sh"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
for f in morpheus-ctl keytool fake-nginx.py rotate-host-keys; do
  [ -f "$HERE/$f" ] || { echo "Missing $HERE/$f. Copy the whole tests/fake-appliance folder to the VM and run the script from it."; exit 1; }
done
. /etc/os-release
[ "${ID:-}" = ubuntu ] || echo "warning: written for Ubuntu 24.04; this is ${PRETTY_NAME:-unknown}. Carrying on."

echo "== packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends openssh-server sudo openssl python3 procps coreutils curl >/dev/null

echo "== user mcitest (password hunter2, sudo with a password)"
id mcitest >/dev/null 2>&1 || useradd -m -s /bin/bash mcitest
echo 'mcitest:hunter2' | chpasswd
usermod -aG sudo mcitest
# A NOPASSWD rule anywhere would make the app see "nopasswd" instead of "password"; say so.
if sudo -l -U mcitest 2>/dev/null | grep -q NOPASSWD; then
  echo "warning: mcitest has a NOPASSWD sudo rule (cloud-init?). The tests expect password sudo; remove it."
fi
# sudo's lecture on every prompt, on purpose (tests that data reads use stdout only).
# Ubuntu 26.04's default sudo is sudo-rs, which has no lecture: the setting is accepted but nothing
# is printed. Classic sudo is installed beside it as sudo.ws. Say so; switching is the tester's call.
if sudo --version 2>/dev/null | head -1 | grep -q '^sudo-rs'; then
  echo "note: sudo here is sudo-rs: no lecture, so sudo writes only a newline to stderr."
  echo "      For classic sudo (lecture on, like current appliances): sudo update-alternatives --set sudo /usr/bin/sudo.ws"
fi
printf "Defaults:mcitest lecture=always\n" > /etc/sudoers.d/mci-fake-lecture
chmod 0440 /etc/sudoers.d/mci-fake-lecture
visudo -cq -f /etc/sudoers.d/mci-fake-lecture

echo "== sshd: password logins on, ports 22 and 2222"
# sshd uses the first value it reads; sshd_config.d is read first and cloud images ship
# 50-cloud-init.conf with "PasswordAuthentication no", so ours is named 00-… to sort before it.
# Port 2222 as well as 22: the tests' MCI_TEST_SSH line uses <vm>:2222:…
DROPIN=/etc/ssh/sshd_config.d/00-mci-fake.conf
# Only one drop-in of ours, whatever an earlier version called it.
for f in /etc/ssh/sshd_config.d/*mci-fake*.conf; do [ -e "$f" ] && [ "$f" != "$DROPIN" ] && rm -f "$f" && echo "   removed old $f"; done
printf "# morpheus-certificate-install fake appliance\nPort 22\nPort 2222\nPasswordAuthentication yes\nKbdInteractiveAuthentication yes\n" > "$DROPIN"
# sshd -t/-T refuse to run without the privilege-separation directory, which systemd removes
# whenever ssh.service is stopped (as it is between socket-activated starts).
install -d -m 0755 /run/sshd
sshd -t
# Ubuntu 24.04 starts sshd from ssh.socket; its listening ports come from sshd_config via
# sshd-socket-generator, so reload the generators and restart the socket. Restarting the socket
# restarts ssh.service by itself — don't stop it afterwards: that kills it mid-start and leaves the
# unit "failed" (0.3.8 did this). reset-failed clears that state on a rerun.
systemctl daemon-reload
systemctl reset-failed ssh.service 2>/dev/null || true
if systemctl is-enabled ssh.socket >/dev/null 2>&1; then
  systemctl restart ssh.socket
else
  systemctl enable --now ssh >/dev/null 2>&1 || true
  systemctl restart ssh 2>/dev/null || systemctl restart sshd
fi

echo "== Morpheus layout"
mkdir -p /etc/morpheus/ssl /opt/morpheus/embedded/java/bin /opt/morpheus/embedded/java/lib/security /var/log/fake-morpheus /var/lib/fake-morpheus
[ -e /opt/morpheus/embedded/java/lib/security/cacerts ] || touch /opt/morpheus/embedded/java/lib/security/cacerts
if [ ! -e /etc/morpheus/morpheus.rb ]; then
  printf "appliance_url 'https://198.51.100.20'\nelasticsearch['es_hosts'] = {'127.0.0.1' => 9200}\n" > /etc/morpheus/morpheus.rb
  chmod 600 /etc/morpheus/morpheus.rb
  echo "   wrote /etc/morpheus/morpheus.rb"
else
  echo "   kept the existing /etc/morpheus/morpheus.rb"
fi
if [ ! -e /etc/morpheus/ssl/appliance.crt ] || [ ! -e /etc/morpheus/ssl/appliance.key ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -keyout /etc/morpheus/ssl/appliance.key -out /etc/morpheus/ssl/appliance.crt \
    -days 3650 -subj "/CN=appliance" 2>/dev/null
  chmod 600 /etc/morpheus/ssl/appliance.key
  echo "   made the starting certificate appliance"
fi

echo "== stand-ins"
install -m 0755 "$HERE/morpheus-ctl" /usr/bin/morpheus-ctl
install -m 0755 "$HERE/keytool" /opt/morpheus/embedded/java/bin/keytool
install -m 0644 "$HERE/fake-nginx.py" /usr/local/bin/fake-nginx.py
install -m 0755 "$HERE/rotate-host-keys" /usr/local/sbin/rotate-host-keys

echo "== fake nginx as a systemd service on 443"
cat > /etc/systemd/system/mci-fake-nginx.service <<'UNIT'
[Unit]
Description=morpheus-certificate-install fake appliance: stand-in nginx on 443
After=network.target

[Service]
ExecStart=/usr/bin/python3 /usr/local/bin/fake-nginx.py
Restart=always
RestartSec=1
StandardOutput=append:/var/log/fake-morpheus/nginx.log
StandardError=append:/var/log/fake-morpheus/nginx.log

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable mci-fake-nginx.service >/dev/null 2>&1
systemctl restart mci-fake-nginx.service

echo "== check"
fail=0
check() { if eval "$2" >/dev/null 2>&1; then echo "   ok   $1"; else echo "   FAIL $1"; fail=1; fi; }
# Ask the running server what it offers (not `sshd -T`, which reads files and needs /run/sshd): a
# key-less BatchMode login is refused with the list of methods, and never tries a password.
# The refusal makes ssh exit 255, so capture its output first: piping it into grep fails under
# `set -o pipefail` (0.3.9 did, and reported FAIL while password login worked).
offers_password() {
  local out
  out=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 \
            -p "$1" mcitest@127.0.0.1 true 2>&1) || true
  grep -q 'Permission denied (.*password' <<<"$out"
}
check "sshd listens on 22 and 2222"      "sleep 1; ss -ltn | grep -q ':22 ' && ss -ltn | grep -q ':2222 '"
check "sshd offers password login on 22"   "offers_password 22"
check "sshd offers password login on 2222" "offers_password 2222"
check "ssh.service isn't failed"         "! systemctl is-failed --quiet ssh.service"
check "mcitest is in sudo"                "id -nG mcitest | tr ' ' '\n' | grep -qx sudo"
check "systemd-run is usable (SYSTEMDRUN=yes)" "command -v systemd-run && [ -d /run/systemd/system ]"
check "morpheus-ctl runs as root"        "morpheus-ctl status"
# The server takes a moment to start after the restart above: try for up to 10 s.
serving_443() {
  local i out
  for i in 1 2 3 4 5 6 7 8 9 10; do
    out=$(echo | timeout 5 openssl s_client -connect 127.0.0.1:443 2>/dev/null) || true
    grep -q 'BEGIN CERTIFICATE' <<<"$out" && return 0
    sleep 1
  done
  return 1
}
check "fake nginx is serving on 443"     "serving_443"
check "keytool stand-in"                 "/opt/morpheus/embedded/java/bin/keytool -list -keystore x -storepass changeit"
# The fake Morpheus API (fake-nginx.py): the test token gets in, no token gets 401. -k: the cert is
# whatever the app last installed.
API_TOKEN=$(sed -n 's/^TOKEN = "\(.*\)"$/\1/p' /usr/local/bin/fake-nginx.py)
api_code() { curl -sk -o /dev/null -w '%{http_code}' "$@" https://127.0.0.1/api/whoami; }
check "fake Morpheus API answers the test token" "[ \"\$(api_code -H 'Authorization: Bearer $API_TOKEN')\" = 200 ]"
check "fake Morpheus API refuses no token (401)" "[ \"\$(api_code)\" = 401 ]"
echo
echo "SSH host key to confirm on first connect:"
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
echo "Address: $(hostname -I | awk '{print $1}')  port 22 or 2222  user mcitest  password hunter2"
echo "Test line: MCI_TEST_SSH=$(hostname -I | awk '{print $1}'):2222:mcitest:hunter2"
echo "Fake Morpheus API token (test only): $API_TOKEN"
[ "$fail" = 0 ] && echo "The fake appliance is ready." || { echo "Some checks failed (above)."; exit 1; }
