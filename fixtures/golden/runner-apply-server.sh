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
step nginx 'morpheus-ctl restart nginx'
morpheus-ctl restart nginx; ok $? nginx
step status 'morpheus-ctl status'
morpheus-ctl status; true
finish 0
