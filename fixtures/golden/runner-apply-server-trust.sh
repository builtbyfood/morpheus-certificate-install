#!/bin/bash
# Morpheus Certificate Install {VERSION} runner 20261105-120000 (apply)
LOG=/var/log/morpheus-certificate-install/20261105-120000.log; RCF=/var/log/morpheus-certificate-install/20261105-120000.rc; OPU=mcitest
mkdir -p /var/log/morpheus-certificate-install; chmod 755 /var/log/morpheus-certificate-install
: > "$LOG"; chmod 600 "$LOG"; [ -n "$OPU" ] && chown "$OPU" "$LOG" 2>/dev/null
exec >>"$LOG" 2>&1
export PATH=/opt/morpheus/bin:/opt/morpheus/sbin:/opt/morpheus/embedded/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
finish(){ echo "@@MCI done rc=$1"; echo "$1" > "$RCF"; [ -n "$OPU" ] && chown "$OPU" "$RCF" 2>/dev/null; exit "$1"; }
step(){ echo; echo "@@MCI step=$1"; echo "\$ $2"; }
ok(){ echo "@@MCI rc=$1 step=$2"; [ "$1" -eq 0 ] || finish "$1"; }
echo "@@MCI start $(date -Is) on $(hostname)"
step reconfigure 'morpheus-ctl reconfigure'
morpheus-ctl reconfigure; ok $? reconfigure
KT=$(ls /opt/morpheus/embedded/java/bin/keytool /opt/morpheus/embedded/java/jre/bin/keytool 2>/dev/null | head -1)
[ -n "$KT" ] || KT=$(find /opt/morpheus/embedded -maxdepth 6 -type f -name keytool | head -1)
CA=$(find /opt/morpheus/embedded -maxdepth 8 -type f -name cacerts -path '*security*' | head -1)
if [ -z "$KT" ] || [ -z "$CA" ]; then echo "keytool or cacerts not found under /opt/morpheus/embedded"; finish 3; fi
echo "keytool: $KT"; echo "cacerts: $CA"
step keytool 'keytool -importcert -alias mci-cust-root-0a1b2c3d'
"$KT" -delete -alias mci-cust-root-0a1b2c3d -keystore "$CA" -storepass changeit >/dev/null 2>&1
"$KT" -importcert -noprompt -trustcacerts -alias mci-cust-root-0a1b2c3d -file /etc/morpheus/ssl/trusted_certs/mci-cust-root-0a1b2c3d.pem -keystore "$CA" -storepass changeit; ok $? keytool
step keytool 'keytool -importcert -alias mci-cust-issuing-4e5f6a7b'
"$KT" -delete -alias mci-cust-issuing-4e5f6a7b -keystore "$CA" -storepass changeit >/dev/null 2>&1
"$KT" -importcert -noprompt -trustcacerts -alias mci-cust-issuing-4e5f6a7b -file /etc/morpheus/ssl/trusted_certs/mci-cust-issuing-4e5f6a7b.pem -keystore "$CA" -storepass changeit; ok $? keytool
step nginx 'morpheus-ctl restart nginx'
morpheus-ctl restart nginx; ok $? nginx
step ui 'morpheus-ctl restart morpheus-ui'
morpheus-ctl restart morpheus-ui; ok $? ui
step status 'morpheus-ctl status'
morpheus-ctl status; true
finish 0
