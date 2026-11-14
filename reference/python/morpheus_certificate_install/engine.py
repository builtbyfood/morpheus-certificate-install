"""Morpheus Certificate Install 0.2.1 — what actually happens on the appliance.

The documented HPE Morpheus procedures this follows:

Server certificate (docs: "SSL Certificates"):
  1. key + cert in /etc/morpheus/ssl/<fqdn>.key / .crt, root-owned and root-only
     readable; the .crt carries the signing chain; the key must be decrypted
  2. /etc/morpheus/morpheus.rb:
       nginx['ssl_certificate'] = '<crt>'
       nginx['ssl_server_key']  = '<key>'
  3. morpheus-ctl reconfigure, then morpheus-ctl restart nginx

Trusted CA (docs: "Import Trusted Certificates"):
  1. chain PEMs in /etc/morpheus/ssl/trusted_certs
  2. morpheus-ctl reconfigure
  3. keytool -import ... -keystore <embedded java>/lib/security/cacerts
     -storepass changeit  (once per certificate; root answered yes)
  4. restart morpheus-ui so the JVM reloads its truststore (Morpheus Certificate Install adds this)

Long work (reconfigure / restarts / keytool) runs in a detached runner on the
appliance — a transient systemd unit, or setsid when there is no systemd — so a
dropped laptop connection cannot kill a half-finished reconfigure. The runner
logs to /var/log/morpheus-certificate-install/<run>.log (owned by the operator, mode 0600) and
writes the exit code to <run>.rc; Morpheus Certificate Install follows the log live and can
re-attach to any run later.
"""
from __future__ import annotations

import datetime as _dt
import json
import socket
import ssl
import tempfile
import os
import threading
import urllib.request
from typing import Callable, Dict, List, Optional
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from . import __version__
from . import certs as C
from .transport import Transport, TransportError, q

SSL_DIR = "/etc/morpheus/ssl"
TRUST_DIR = "/etc/morpheus/ssl/trusted_certs"
MORPHEUS_RB = "/etc/morpheus/morpheus.rb"
STATE_DIR = "/var/lib/morpheus-certificate-install"
BACKUP_DIR = "/var/lib/morpheus-certificate-install/backups"
RUN_DIR = "/var/lib/morpheus-certificate-install/runs"
LOG_DIR = "/var/log/morpheus-certificate-install"

Emit = Callable[[dict], None]


def stamp() -> str:
    return _dt.datetime.now().strftime("%Y%m%d-%H%M%S")


# ------------------------------------------------------------------ preflight

def preflight(t: Transport, emit: Emit) -> dict:
    facts: Dict[str, object] = {"transport": t.info()}
    script = r"""
echo "HOST=$(hostname -f 2>/dev/null || hostname)"
echo "OS=$(. /etc/os-release 2>/dev/null; echo "$PRETTY_NAME")"
MC=$(command -v morpheus-ctl || ls /opt/morpheus/bin/morpheus-ctl /usr/bin/morpheus-ctl 2>/dev/null | head -1)
echo "MCTL=$MC"
echo "RB=$( [ -f /etc/morpheus/morpheus.rb ] && echo yes || echo no )"
echo "SSLDIR=$( [ -d /etc/morpheus/ssl ] && echo yes || echo no )"
echo "SYSTEMDRUN=$(command -v systemd-run >/dev/null 2>&1 && [ -d /run/systemd/system ] && echo yes || echo no)"
echo "OPENSSL=$(command -v openssl >/dev/null && openssl version | cut -d' ' -f1-2)"
echo "VER=$(dpkg-query -W -f='${Version}' morpheus-appliance 2>/dev/null || rpm -q --qf '%{VERSION}-%{RELEASE}' morpheus-appliance 2>/dev/null)"
KT=$(ls /opt/morpheus/embedded/java/bin/keytool /opt/morpheus/embedded/java/jre/bin/keytool 2>/dev/null | head -1)
[ -n "$KT" ] || KT=$(find /opt/morpheus/embedded -maxdepth 6 -type f -name keytool 2>/dev/null | head -1)
echo "KEYTOOL=$KT"
CA=$(find /opt/morpheus/embedded -maxdepth 8 -type f -name cacerts -path '*security*' 2>/dev/null | head -1)
echo "CACERTS=$CA"
echo "FREE_ETC_KB=$(df -Pk /etc | awk 'NR==2{print $4}')"
echo "FREE_VAR_KB=$(df -Pk /var | awk 'NR==2{print $4}')"
"""
    emit({"type": "log", "text": "Checking the appliance…\n"})
    rc, out = t.run(script, sudo=True, timeout=60)
    if rc != 0:
        raise TransportError(f"preflight failed (exit {rc}): {out.strip()[-600:]}")
    for ln in out.splitlines():
        if "=" in ln:
            k, _, v = ln.partition("=")
            facts[k.strip().lower()] = v.strip()
    rc, rb = t.run(f"cat {MORPHEUS_RB}", sudo=True)
    facts["morpheus_rb"] = rb if rc == 0 else ""
    facts["nginx_ssl"] = C.current_nginx_ssl(rb) if rc == 0 else {}
    # Appliance URL from morpheus.rb (the line Morpheus itself reads at install).
    for ln in (rb or "").splitlines():
        s = ln.strip()
        if s.startswith("appliance_url") and not s.startswith("#"):
            facts["appliance_url_rb"] = s.split(None, 1)[1].strip().strip("'\"") if " " in s else ""
    served = served_chain(t, "")
    facts["served"] = served
    problems = []
    if not facts.get("mctl"):
        problems.append("morpheus-ctl not found — is this a Morpheus appliance (Manager)?")
    if facts.get("rb") != "yes":
        problems.append(f"{MORPHEUS_RB} is missing.")
    if not facts.get("openssl"):
        problems.append("openssl is not installed on the appliance; verification steps will be skipped.")
    facts["problems"] = problems
    return facts


def served_chain(t: Transport, sni: str) -> dict:
    sni_arg = f"-servername {q(sni)}" if sni else ""
    rc, out = t.run(f"echo | timeout 10 openssl s_client -connect 127.0.0.1:443 {sni_arg} -showcerts 2>/dev/null", timeout=30)
    chain = C.certs_from_pem_text(out)
    if not chain:
        return {"ok": False, "error": "nothing answered TLS on 127.0.0.1:443"}
    leaf = C.CertInfo(chain[0], "served")
    s = leaf.summary("served")
    return {"ok": True, "leaf": s, "chain_len": len(chain), "fingerprints": [C.sha256_fp(c) for c in chain]}


# ------------------------------------------------------------------ plan

def build_plan(an: C.Analysis, facts: dict, opts: dict) -> dict:
    base = C.safe_name(an.fqdn)
    crt = f"{SSL_DIR}/{base}.crt"
    key = f"{SSL_DIR}/{base}.key"
    do_server = bool(opts.get("server", True))
    do_trust = bool(opts.get("trust", False)) and bool(an.ca_certs())
    restart_ui = bool(opts.get("restart_ui", do_trust))
    st = stamp()
    rb_old = facts.get("morpheus_rb", "")
    rb_new = C.transform_morpheus_rb(rb_old, crt, key, st) if do_server else rb_old
    steps = [{"id": "backup", "title": "Back up /etc/morpheus/ssl and morpheus.rb",
              "detail": f"{BACKUP_DIR}/{st}/ (root-only)"}]
    if do_server:
        steps += [
            {"id": "files", "title": "Write certificate and key",
             "detail": f"{crt} (server + {len(an.intermediates)} intermediate{'s' if len(an.intermediates) != 1 else ''}"
                       f"{' + root' if opts.get('include_root') and an.root else ''}, 0600 root)\n{key} (decrypted PKCS#8, 0600 root)"},
            {"id": "rb", "title": "Point nginx at them in morpheus.rb", "detail": "nginx['ssl_certificate'] / nginx['ssl_server_key']"},
            {"id": "match", "title": "Check the key matches the certificate on the appliance", "detail": "openssl pubkey compare"},
        ]
    if do_trust:
        steps.append({"id": "trustfiles", "title": "Copy the CA chain to trusted_certs",
                      "detail": "\n".join(f"{TRUST_DIR}/{C.alias_for(c)}.pem  ({c.cn})" for c in an.ca_certs())})
    runner = ["morpheus-ctl reconfigure"]
    if do_trust:
        runner.append(f"keytool -importcert for {len(an.ca_certs())} CA cert(s) into the embedded Java cacerts")
    if do_server:
        runner.append("morpheus-ctl restart nginx")
    if restart_ui:
        runner.append("morpheus-ctl restart morpheus-ui (UI unavailable while it starts, often 5–10 min)")
    steps.append({"id": "runner", "title": "Run on the appliance (detached, streamed live)", "detail": "\n".join(runner)})
    steps.append({"id": "verify", "title": "Verify what nginx serves", "detail": "fingerprint compare on 127.0.0.1:443 + chain check from here"})
    return {
        "stamp": st, "crt": crt, "key": key, "server": do_server, "trust": do_trust, "restart_ui": restart_ui,
        "include_root": bool(opts.get("include_root")), "storepass": opts.get("storepass") or "changeit",
        "steps": steps, "rb_diff": C.unified_diff(rb_old, rb_new, MORPHEUS_RB) if do_server else "",
        "rb_new": rb_new, "aliases": [C.alias_for(c) for c in an.ca_certs()] if do_trust else [],
        "systemd": facts.get("systemdrun") == "yes",
    }


# ------------------------------------------------------------------ runner

def runner_script(run_id: str, op_user: str, plan: dict, mode: str = "apply", aliases_to_delete: Optional[List[str]] = None) -> str:
    log, rcf = f"{LOG_DIR}/{run_id}.log", f"{LOG_DIR}/{run_id}.rc"
    sp = plan.get("storepass", "changeit")
    L = [
        "#!/bin/bash",
        f"# Morpheus Certificate Install {__version__} runner {run_id} ({mode})",
        f"LOG={q(log)}; RCF={q(rcf)}; OPU={q(op_user)}",
        "mkdir -p /var/log/morpheus-certificate-install; chmod 755 /var/log/morpheus-certificate-install",
        ': > "$LOG"; chmod 600 "$LOG"; [ -n "$OPU" ] && chown "$OPU" "$LOG" 2>/dev/null',
        'exec >>"$LOG" 2>&1',
        "export PATH=/opt/morpheus/bin:/opt/morpheus/sbin:/opt/morpheus/embedded/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        'finish(){ echo "@@MCI done rc=$1"; echo "$1" > "$RCF"; [ -n "$OPU" ] && chown "$OPU" "$RCF" 2>/dev/null; exit "$1"; }',
        'step(){ echo; echo "@@MCI step=$1"; echo "\\$ $2"; }',
        'ok(){ echo "@@MCI rc=$1 step=$2"; [ "$1" -eq 0 ] || finish "$1"; }',
        'echo "@@MCI start $(date -Is) on $(hostname)"',
        "step reconfigure 'morpheus-ctl reconfigure'",
        "morpheus-ctl reconfigure; ok $? reconfigure",
    ]
    if mode == "apply" and plan.get("trust"):
        L += [
            'KT=$(ls /opt/morpheus/embedded/java/bin/keytool /opt/morpheus/embedded/java/jre/bin/keytool 2>/dev/null | head -1)',
            '[ -n "$KT" ] || KT=$(find /opt/morpheus/embedded -maxdepth 6 -type f -name keytool | head -1)',
            "CA=$(find /opt/morpheus/embedded -maxdepth 8 -type f -name cacerts -path '*security*' | head -1)",
            'if [ -z "$KT" ] || [ -z "$CA" ]; then echo "keytool or cacerts not found under /opt/morpheus/embedded"; finish 3; fi',
            'echo "keytool: $KT"; echo "cacerts: $CA"',
        ]
        for a in plan.get("aliases", []):
            f = f"{TRUST_DIR}/{a}.pem"
            L += [
                f"step keytool 'keytool -importcert -alias {a}'",
                f'"$KT" -delete -alias {q(a)} -keystore "$CA" -storepass {q(sp)} >/dev/null 2>&1',
                f'"$KT" -importcert -noprompt -trustcacerts -alias {q(a)} -file {q(f)} -keystore "$CA" -storepass {q(sp)}; ok $? keytool',
            ]
    if mode == "rollback" and aliases_to_delete:
        L += [
            'KT=$(ls /opt/morpheus/embedded/java/bin/keytool /opt/morpheus/embedded/java/jre/bin/keytool 2>/dev/null | head -1)',
            '[ -n "$KT" ] || KT=$(find /opt/morpheus/embedded -maxdepth 6 -type f -name keytool | head -1)',
            "CA=$(find /opt/morpheus/embedded -maxdepth 8 -type f -name cacerts -path '*security*' | head -1)",
        ]
        for a in aliases_to_delete:
            L += [f"step keytool 'keytool -delete -alias {a}'",
                  f'[ -n "$KT" ] && "$KT" -delete -alias {q(a)} -keystore "$CA" -storepass {q(sp)}; echo "(rc $?)"']
    if plan.get("server") or mode == "rollback":
        L += ["step nginx 'morpheus-ctl restart nginx'", "morpheus-ctl restart nginx; ok $? nginx"]
    if plan.get("restart_ui"):
        L += ["step ui 'morpheus-ctl restart morpheus-ui'", "morpheus-ctl restart morpheus-ui; ok $? ui"]
    L += ["step status 'morpheus-ctl status'", "morpheus-ctl status; true", "finish 0", ""]
    return "\n".join(L)


def launch_runner(t: Transport, run_id: str, script: str, systemd: bool) -> str:
    path = f"{RUN_DIR}/{run_id}.sh"
    t.put_root(path, script.encode(), "0700")
    if systemd:
        cmd = (f"systemd-run --unit=morpheus-certificate-install-{run_id} --collect -p KillMode=process "
               f"--description='Morpheus Certificate Install {run_id}' /bin/bash {q(path)}")
    else:
        cmd = f"setsid nohup /bin/bash {q(path)} >/dev/null 2>&1 < /dev/null & echo launched"
    t.check(cmd, sudo=True, what="start runner")
    return f"{LOG_DIR}/{run_id}.log"


def follow(t: Transport, run_id: str, emit: Emit, stop: threading.Event) -> Optional[int]:
    log, rcf = f"{LOG_DIR}/{run_id}.log", f"{LOG_DIR}/{run_id}.rc"
    buf = {"s": ""}

    def on_text(txt: str):
        emit({"type": "remote", "text": txt})
        buf["s"] = (buf["s"] + txt)[-4000:]
        while "\n" in buf["s"]:
            line, _, rest = buf["s"].partition("\n")
            buf["s"] = rest
            if line.startswith("@@MCI step="):
                emit({"type": "step", "id": "run:" + line.split("=", 1)[1].strip(), "status": "running"})
            elif line.startswith("@@MCI rc="):
                parts = dict(p.split("=", 1) for p in line.split()[1:] if "=" in p)
                emit({"type": "step", "id": "run:" + parts.get("step", "?"), "status": "ok" if parts.get("rc") == "0" else "fail"})

    return t.stream_file(log, rcf, on_text, stop)


def list_runs(t: Transport) -> List[dict]:
    rc, out = t.run(f"cd {LOG_DIR} 2>/dev/null && for f in *.log; do [ -e \"$f\" ] || continue; r=${{f%.log}}; "
                    f"echo \"$r|$(stat -c %Y \"$f\")|$(cat \"$r.rc\" 2>/dev/null)\"; done", sudo=True)
    runs = []
    for ln in out.splitlines():
        p = ln.split("|")
        if len(p) == 3:
            runs.append({"id": p[0], "mtime": int(p[1] or 0), "rc": p[2] or None})
    runs.sort(key=lambda r: r["mtime"], reverse=True)
    return runs


# ------------------------------------------------------------------ apply

def apply(t: Transport, an: C.Analysis, facts: dict, plan: dict, emit: Emit, stop: threading.Event) -> dict:
    st = plan["stamp"]
    run_id = st
    bdir = f"{BACKUP_DIR}/{st}"

    def step(sid, status, text=""):
        emit({"type": "step", "id": sid, "status": status})
        if text:
            emit({"type": "log", "text": text + "\n"})

    # 1. backup
    step("backup", "running", f"Backing up to {bdir}")
    t.check(f"set -e; umask 077; mkdir -p {q(bdir)}; cp -a {SSL_DIR} {q(bdir)}/ssl; cp -a {MORPHEUS_RB} {q(bdir)}/morpheus.rb; "
            f"chmod 700 {STATE_DIR} {BACKUP_DIR} 2>/dev/null; echo done", sudo=True, what="backup")
    manifest = {"stamp": st, "tool": f"morpheus-certificate-install {__version__}", "fqdn": an.fqdn, "crt": plan["crt"] if plan["server"] else None,
                "key": plan["key"] if plan["server"] else None, "aliases": plan["aliases"],
                "leaf_sha256": an.leaf.fp256 if an.leaf else None, "transport": t.info().get("label")}
    t.put_root(f"{bdir}/manifest.json", json.dumps(manifest, indent=2).encode(), "0600")
    step("backup", "ok")
    if stop.is_set():
        return {"ok": False, "stopped": True}

    # 2. files + morpheus.rb
    if plan["server"]:
        step("files", "running", f"Writing {plan['crt']} and {plan['key']}")
        t.put_root(plan["crt"], an.fullchain_pem(plan["include_root"]), "0600")
        t.put_root(plan["key"], an.key_pem(), "0600")
        step("files", "ok")
        step("rb", "running", f"Updating {MORPHEUS_RB}")
        rc, cur = t.run(f"cat {MORPHEUS_RB}", sudo=True)
        if rc != 0:
            raise TransportError("could not read morpheus.rb")
        if cur != facts.get("morpheus_rb", ""):
            emit({"type": "log", "text": "morpheus.rb changed since the plan was made; applying the edit to the current file.\n"})
        new = C.transform_morpheus_rb(cur, plan["crt"], plan["key"], st)
        rc, mode = t.run(f"stat -c %a {MORPHEUS_RB}", sudo=True)
        t.put_root(MORPHEUS_RB, new.encode(), (mode.strip() or "600") if rc == 0 else "0600")
        step("rb", "ok")
        step("match", "running")
        out = t.check(f"a=$(openssl x509 -noout -pubkey -in {q(plan['crt'])} | sha256sum | cut -c1-64); "
                      f"b=$(openssl pkey -pubout -in {q(plan['key'])} | sha256sum | cut -c1-64); "
                      f"echo \"cert=$a key=$b\"; [ \"$a\" = \"$b\" ]", sudo=True, what="key/cert match on the appliance")
        step("match", "ok", out.strip())
    if plan["trust"]:
        step("trustfiles", "running")
        for c, a in zip(an.ca_certs(), plan["aliases"]):
            t.put_root(f"{TRUST_DIR}/{a}.pem", c.pem(), "0644", dir_mode="0755")
            emit({"type": "log", "text": f"  {TRUST_DIR}/{a}.pem  ({c.cn})\n"})
        step("trustfiles", "ok")
    if stop.is_set():
        return {"ok": False, "stopped": True, "backup": bdir}

    # 3. runner
    step("runner", "running", "Starting the runner on the appliance. Output below is live; it keeps running if this window closes.")
    script = runner_script(run_id, t.login_user, plan, "apply")
    launch_runner(t, run_id, script, plan["systemd"])
    emit({"type": "run", "id": run_id, "watch": watch_cmd(run_id, plan["systemd"])})
    rc = follow(t, run_id, emit, stop)
    if rc is None:
        step("runner", "fail", "Stopped following. The run continues on the appliance — re-attach from Runs.")
        return {"ok": False, "run_id": run_id, "backup": bdir, "detached": True}
    step("runner", "ok" if rc == 0 else "fail", f"Runner finished with exit {rc}.")
    if rc != 0:
        return {"ok": False, "run_id": run_id, "backup": bdir, "rc": rc}
    return {"ok": True, "run_id": run_id, "backup": bdir}


def watch_cmd(run_id: str, systemd: bool) -> str:
    return f"tail -n +1 -F {LOG_DIR}/{run_id}.log"


# ------------------------------------------------------------------ verify

def verify(t: Optional[Transport], an: Optional[C.Analysis], target: str, port: int, connect_addr: str, emit: Emit) -> dict:
    res = {"remote": None, "local": None}
    want = an.leaf.fp256 if an and an.leaf else None
    sni = target
    if t is not None:
        served = served_chain(t, sni)
        res["remote"] = served
        if served.get("ok"):
            match = want is not None and served["fingerprints"][0] == want
            served["matches_new"] = match
            emit({"type": "log", "text": f"Appliance (127.0.0.1:443, SNI {sni}): serving \"{served['leaf']['cn']}\" "
                                        f"{served['leaf']['sha256'][:23]}…, {served['chain_len']} cert(s) in chain — "
                                        f"{'matches the new certificate' if match else 'NOT the new certificate'}\n"})
    res["local"] = local_tls(target, port, connect_addr, an)
    loc = res["local"]
    if loc.get("ok") is not None:
        emit({"type": "log", "text": f"From this machine ({loc.get('addr')}): {loc.get('summary')}\n"})
    return res


def local_tls(host: str, port: int, connect_addr: str, an: Optional[C.Analysis]) -> dict:
    addr = connect_addr or host
    out = {"addr": f"{addr}:{port}", "ok": None}
    try:
        raw = ssl.create_default_context()
        raw.check_hostname = False
        raw.verify_mode = ssl.CERT_NONE
        with socket.create_connection((addr, port), timeout=8) as s:
            with raw.wrap_socket(s, server_hostname=host) as ss:
                der = ss.getpeercert(binary_form=True)
                out["tls"] = ss.version()
        leaf = x509.load_der_x509_certificate(der)
        out["served_sha256"] = C.sha256_fp(leaf)
        out["matches_new"] = bool(an and an.leaf and out["served_sha256"] == an.leaf.fp256)
    except OSError as e:
        out.update(ok=False, summary=f"could not connect: {e}")
        return out
    # Chain + hostname validation: OS trust store plus the supplied root.
    ctx = ssl.create_default_context()
    tmp = None
    if an and an.root:
        fd, tmp = tempfile.mkstemp(suffix=".pem")
        with os.fdopen(fd, "wb") as f:
            f.write(an.root.pem())
        ctx.load_verify_locations(tmp)
    try:
        with socket.create_connection((addr, port), timeout=8) as s:
            with ctx.wrap_socket(s, server_hostname=host):
                pass
        out["verified"] = True
        out["ok"] = True
        out["summary"] = (f"{out['tls']}, chain verifies for {host}"
                          + (" (using the supplied root)" if an and an.root else " (OS trust store)")
                          + ("; serving the new certificate" if out["matches_new"] else "; NOT the new certificate"))
    except ssl.SSLCertVerificationError as e:
        out.update(verified=False, ok=False, summary=f"{out.get('tls')}, verification failed: {e.verify_message} ({e.verify_code})"
                   + ("; serving the new certificate" if out["matches_new"] else ""))
    except OSError as e:
        out.update(verified=False, ok=False, summary=f"verification connect failed: {e}")
    finally:
        if tmp:
            os.remove(tmp)
    return out


# ------------------------------------------------------------------ backups / rollback

def list_backups(t: Transport) -> List[dict]:
    rc, out = t.run(f"cd {BACKUP_DIR} 2>/dev/null && for d in */; do d=${{d%/}}; echo \"@@B $d\"; cat \"$d/manifest.json\" 2>/dev/null; echo; done", sudo=True)
    items, cur, buf = [], None, []
    for ln in out.splitlines() + ["@@B __end__"]:
        if ln.startswith("@@B "):
            if cur:
                try:
                    m = json.loads("\n".join(buf)) if "".join(buf).strip() else {}
                except ValueError:
                    m = {}
                items.append({"id": cur, **m})
            cur, buf = ln[4:].strip(), []
            if cur == "__end__":
                break
        else:
            buf.append(ln)
    items.sort(key=lambda b: b["id"], reverse=True)
    return items


def rollback(t: Transport, backup_id: str, systemd: bool, emit: Emit, stop: threading.Event) -> dict:
    if not backup_id or "/" in backup_id or backup_id.startswith("."):
        raise TransportError("bad backup id")
    bdir = f"{BACKUP_DIR}/{backup_id}"
    rc, man = t.run(f"cat {q(bdir)}/manifest.json", sudo=True)
    try:
        m = json.loads(man) if rc == 0 else {}
    except ValueError:
        m = {}
    emit({"type": "step", "id": "restore", "status": "running"})
    # Save the current state too, so a rollback is itself reversible.
    pre = f"{BACKUP_DIR}/{stamp()}-pre-rollback"
    t.check(f"set -e; umask 077; mkdir -p {q(pre)}; cp -a {SSL_DIR} {q(pre)}/ssl; cp -a {MORPHEUS_RB} {q(pre)}/morpheus.rb; "
            f"echo '{{\"note\": \"state before rollback to {backup_id}\"}}' > {q(pre)}/manifest.json; "
            f"cp -a {q(bdir)}/morpheus.rb {MORPHEUS_RB}; cp -a {q(bdir)}/ssl/. {SSL_DIR}/; "
            + "".join(f"rm -f {q(TRUST_DIR + '/' + a + '.pem')}; " for a in m.get("aliases") or [])
            + "echo restored", sudo=True, what="restore")
    emit({"type": "log", "text": f"Restored morpheus.rb and {SSL_DIR} from {bdir} (current state saved to {pre}).\n"})
    emit({"type": "step", "id": "restore", "status": "ok"})
    run_id = stamp() + "-rollback"
    plan = {"server": True, "restart_ui": bool(m.get("aliases")), "storepass": "changeit"}
    emit({"type": "step", "id": "runner", "status": "running"})
    launch_runner(t, run_id, runner_script(run_id, t.login_user, plan, "rollback", m.get("aliases") or []), systemd)
    emit({"type": "run", "id": run_id, "watch": watch_cmd(run_id, systemd)})
    rc = follow(t, run_id, emit, stop)
    emit({"type": "step", "id": "runner", "status": "ok" if rc == 0 else "fail"})
    return {"ok": rc == 0, "run_id": run_id, "saved_current": pre}


# ------------------------------------------------------------------ Morpheus API

def morpheus_api(url: str, token: str, path: str, ca_pem: Optional[bytes], method: str = "GET", body: Optional[dict] = None,
                 verify: bool = True) -> dict:
    base = url.rstrip("/")
    ctx = ssl.create_default_context()
    tmp = None
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    elif ca_pem:
        fd, tmp = tempfile.mkstemp(suffix=".pem")
        with os.fdopen(fd, "wb") as f:
            f.write(ca_pem)
        ctx.load_verify_locations(tmp)
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method, headers={
        "Authorization": f"Bearer {token}", "Accept": "application/json", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20, context=ctx) as r:
            return json.loads(r.read().decode() or "{}")
    finally:
        if tmp:
            os.remove(tmp)


def morpheus_check(url: str, token: str, an: Optional[C.Analysis]) -> dict:
    ca = an.root.pem() if an and an.root else None
    out = {"url": url}
    try:
        who = morpheus_api(url, token, "/api/whoami", ca)
        out["verified_tls"] = True
    except ssl.SSLError as e:
        out["verified_tls"] = False
        out["tls_error"] = str(e)
        who = morpheus_api(url, token, "/api/whoami", ca, verify=False)
    except urllib.error.HTTPError as e:
        return {"url": url, "error": f"HTTP {e.code} from /api/whoami — check the API token."}
    except OSError as e:
        return {"url": url, "error": f"could not reach {url}: {e}"}
    out["user"] = (who.get("user") or {}).get("username")
    out["build"] = (who.get("appliance") or {}).get("buildVersion")
    try:
        s = morpheus_api(url, token, "/api/appliance-settings", ca, verify=out["verified_tls"])
        out["appliance_url"] = (s.get("applianceSettings") or {}).get("applianceUrl")
    except Exception as e:  # permissions vary
        out["appliance_url_error"] = str(e)
    if an and an.leaf and out.get("appliance_url"):
        dns, ips = an.leaf.sans()
        host = urlparse(out["appliance_url"]).hostname or ""
        out["appliance_url_covered"] = C.host_matches(host, dns, ips)
    return out


def set_appliance_url(url: str, token: str, new_url: str, an: Optional[C.Analysis]) -> dict:
    ca = an.root.pem() if an and an.root else None
    try:
        return morpheus_api(url, token, "/api/appliance-settings", ca, "PUT", {"applianceSettings": {"applianceUrl": new_url}})
    except ssl.SSLError:
        return morpheus_api(url, token, "/api/appliance-settings", ca, "PUT", {"applianceSettings": {"applianceUrl": new_url}}, verify=False)
