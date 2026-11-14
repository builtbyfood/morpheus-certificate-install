"""Morpheus Certificate Install 0.2.1 — local web app.

Binds to 127.0.0.1 only, requires a per-launch token on every API call (header
X-MCI-Token; the event stream takes ?t=), and checks the Host header so a
web page can't reach it by DNS rebinding. Secrets (SSH/sudo passwords, Morpheus
API token, key passphrases) live only in memory for this process.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import sys
import json
import os
import queue
import secrets
import socket
import threading
import time
import traceback
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import __version__
from . import certs as C
from . import engine as E
from . import export as X
from .transport import (CONFIG_DIR, CharonTransport, HostKeyPrompt, SshTransport, TransportError,
                        charon_discover)

WEB = Path(__file__).parent / "web"
SETTINGS = CONFIG_DIR / "settings.json"


class Bus:
    def __init__(self):
        self.clients = []
        self.lock = threading.Lock()
        self.history = []  # last events, replayed to a reconnecting browser

    def subscribe(self):
        qq = queue.Queue(maxsize=5000)
        with self.lock:
            self.clients.append(qq)
            for ev in self.history[-400:]:
                qq.put(ev)
        return qq

    def unsubscribe(self, qq):
        with self.lock:
            if qq in self.clients:
                self.clients.remove(qq)

    def emit(self, ev: dict):
        ev = dict(ev, ts=time.time())
        with self.lock:
            if ev.get("type") != "shell":
                self.history.append(ev)
                self.history = self.history[-2000:]
            for qq in list(self.clients):
                try:
                    qq.put_nowait(ev)
                except queue.Full:
                    pass


class State:
    def __init__(self):
        self.token = secrets.token_urlsafe(24)
        self.bus = Bus()
        self.t = None
        self.facts = None
        self.analysis = None
        self.files = []
        self.plan = None
        self.job = None
        self.stop = threading.Event()
        self.morpheus = {"url": "", "token": ""}
        self.lock = threading.Lock()

    def need_t(self):
        if self.t is None:
            raise TransportError("Not connected. Connect to the appliance first.")
        return self.t

    def busy(self):
        return self.job is not None and self.job.is_alive()


S = State()


def load_settings() -> dict:
    try:
        return json.loads(SETTINGS.read_text())
    except Exception:
        return {}


def save_settings(d: dict):
    cur = load_settings()
    cur.update({k: v for k, v in d.items() if k in ("host", "port", "user", "key_path", "fqdn", "connect_addr", "morpheus_url", "mode", "charon_dir", "tls_port")})
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    SETTINGS.write_text(json.dumps(cur, indent=2))


def start_job(name: str, fn):
    if S.busy():
        raise TransportError("Another operation is running. Wait for it, or stop following it first.")
    S.stop.clear()

    def wrap():
        S.bus.emit({"type": "job", "name": name, "status": "running"})
        try:
            res = fn()
            S.bus.emit({"type": "job", "name": name, "status": "done", "result": res})
        except TransportError as e:
            S.bus.emit({"type": "log", "text": f"\n✖ {e}\n"})
            S.bus.emit({"type": "job", "name": name, "status": "error", "error": str(e)})
        except Exception as e:  # pragma: no cover
            S.bus.emit({"type": "log", "text": f"\n✖ {e}\n{traceback.format_exc()}\n"})
            S.bus.emit({"type": "job", "name": name, "status": "error", "error": str(e)})

    S.job = threading.Thread(target=wrap, daemon=True)
    S.job.start()


# ------------------------------------------------------------------ handlers

def api_state(_):
    return {
        "version": __version__,
        "connected": S.t is not None,
        "transport": S.t.info() if S.t else None,
        "facts": _public_facts(S.facts),
        "analysis": S.analysis.to_json() if S.analysis else None,
        "plan": _public_plan(S.plan),
        "busy": S.busy(),
        "settings": load_settings(),
        "morpheus_url": S.morpheus["url"],
        "has_morpheus_token": bool(S.morpheus["token"]),
    }


def _public_facts(f):
    if not f:
        return None
    return {k: v for k, v in f.items() if k != "morpheus_rb"}


def _public_plan(p):
    if not p:
        return None
    return {k: v for k, v in p.items() if k not in ("rb_new",)}


def api_connect(b):
    if S.busy():
        raise TransportError("An operation is running; connect after it finishes.")
    if S.t:
        S.t.close()
        S.t = None
    S.facts = None
    S.plan = None
    mode = b.get("mode", "ssh")
    if mode == "charon":
        disc = charon_discover(b.get("charon_dir", ""))
        if not disc.get("data_dir") or not disc.get("endpoint"):
            raise TransportError("Charon's MCP server isn't running (no mcp-endpoint.json). In Charon: MCP panel → Start.")
        t = CharonTransport.from_discovery(disc["data_dir"], b["session"])
        save_settings({"mode": "charon", "charon_dir": b.get("charon_dir", "")})
    else:
        try:
            t = SshTransport(b["host"].strip(), int(b.get("port") or 22), b["user"].strip(), b.get("password", ""),
                             b.get("key_path", "").strip(), b.get("key_passphrase", ""), b.get("sudo_password", ""),
                             b.get("trust_fingerprint", ""))
        except HostKeyPrompt as e:
            return {"ok": False, "hostkey": {"host": e.host, "type": e.key_type, "fingerprint": e.fingerprint, "mismatch": e.mismatch}}
        save_settings({"mode": "ssh", "host": b["host"].strip(), "port": int(b.get("port") or 22), "user": b["user"].strip(),
                       "key_path": b.get("key_path", "").strip()})
    S.t = t
    S.bus.emit({"type": "connected", "transport": t.info()})
    S.bus.emit({"type": "log", "text": f"Connected: {t.info().get('label')} (sudo: {t.info().get('sudo_mode')})\n"})
    return {"ok": True, "transport": t.info()}


def api_disconnect(_):
    if S.busy():
        S.stop.set()
    if S.t:
        S.t.close()
    S.t = None
    S.facts = None
    S.plan = None
    S.bus.emit({"type": "disconnected"})
    return {"ok": True}


def api_charon(b):
    disc = charon_discover(b.get("charon_dir", ""))
    if disc.get("endpoint"):
        try:
            v = json.loads((Path(disc["data_dir"]) / "mcp-endpoint.json").read_text())
            disc["sessions"] = [s for s in CharonTransport.list_sessions(v["port"], v["token"])]
        except Exception as e:
            disc["sessions_error"] = str(e)
    return disc


def api_preflight(_):
    t = S.need_t()

    def run():
        S.facts = E.preflight(t, S.bus.emit)
        f = _public_facts(S.facts)
        S.bus.emit({"type": "facts", "facts": f})
        if S.facts.get("problems"):
            for p in S.facts["problems"]:
                S.bus.emit({"type": "log", "text": f"! {p}\n"})
        else:
            S.bus.emit({"type": "log", "text": "Appliance looks right: morpheus-ctl, morpheus.rb and /etc/morpheus/ssl present.\n"})
        return {"ok": True}

    start_job("preflight", run)
    return {"ok": True}


def _incoming(b):
    files = [(f["name"], base64.b64decode(f["b64"])) for f in b.get("files", [])]
    if (b.get("pasted") or "").strip():
        files.append(("pasted text", b["pasted"].encode()))
    if files:
        names = {n for n, _ in files}
        # New uploads replace same-named ones; earlier files and fetched chain certs stay.
        S.files = [f for f in S.files if f[0] not in names] + files


def _bundle(b):
    return C.parse_files(S.files, b.get("pfx_password", ""), b.get("key_password", ""))


def api_analyze(b):
    _incoming(b)
    if not S.files:
        raise TransportError("Add certificate files or paste PEM text first.")
    bundle = _bundle(b)
    appliance_url = b.get("appliance_url") or (S.facts or {}).get("appliance_url_rb", "")
    S.analysis = C.analyze(bundle, b.get("fqdn", "").strip(), appliance_url)
    S.plan = None
    save_settings({"fqdn": S.analysis.fqdn})
    return S.analysis.to_json()


def api_fetch_chain(b):
    if not S.files:
        raise TransportError("Load the certificate first.")
    bundle = _bundle(b)
    before = len(bundle.certs)
    log = C.complete_chain(bundle)
    for ci in bundle.certs[before:]:
        S.files.append((f"fetched: {ci.cn}.crt", ci.pem()))
    appliance_url = b.get("appliance_url") or (S.facts or {}).get("appliance_url_rb", "")
    S.analysis = C.analyze(_bundle(b), b.get("fqdn", "").strip(), appliance_url)
    S.plan = None
    return {"log": log, "analysis": S.analysis.to_json()}


def api_export(b):
    if not S.analysis:
        raise TransportError("Check the certificate first.")
    try:
        files = X.build_files(S.analysis, bool(b.get("include_root")))
    except ValueError as e:
        raise TransportError(str(e))
    folder = C.safe_name(S.analysis.fqdn) + "-morpheus"
    return {"filename": folder + ".zip", "b64": base64.b64encode(X.to_zip(files, folder)).decode(),
            "files": sorted(files)}


def api_clear_files(_):
    S.files, S.analysis, S.plan = [], None, None
    return {"ok": True}


def api_plan(b):
    if not S.analysis or not S.analysis.ok:
        raise TransportError("Load a valid certificate first (the Certificate step shows what's wrong).")
    if not S.facts:
        raise TransportError("Run the appliance check on the Connect step first.")
    if not b.get("server", True) and not b.get("trust"):
        raise TransportError("Pick at least one: install the server certificate, or trust the CA chain.")
    S.plan = E.build_plan(S.analysis, S.facts, b)
    return _public_plan(S.plan)


def api_apply(b):
    t = S.need_t()
    if not S.plan:
        raise TransportError("Review the plan first.")
    if b.get("confirm") != S.plan["stamp"]:
        raise TransportError("Plan changed; review it again.")
    plan, an, facts = S.plan, S.analysis, S.facts

    def run():
        res = E.apply(t, an, facts, plan, S.bus.emit, S.stop)
        if res.get("ok"):
            S.bus.emit({"type": "log", "text": "\nInstalled. Verifying…\n"})
            port = int(load_settings().get("tls_port") or 443)
            v = E.verify(t, an, an.fqdn, port, load_settings().get("connect_addr", ""), S.bus.emit)
            res["verify"] = v
            S.bus.emit({"type": "verify", "result": v})
        S.plan = None
        return res

    start_job("apply", run)
    return {"ok": True}


def api_verify(b):
    target = (b.get("fqdn") or (S.analysis.fqdn if S.analysis else "")).strip()
    if not target:
        raise TransportError("Enter the FQDN to check.")
    port = int(b.get("port") or 443)
    addr = (b.get("connect_addr") or "").strip()
    save_settings({"connect_addr": addr, "tls_port": port})
    t, an = S.t, S.analysis

    def run():
        v = E.verify(t, an, target, port, addr, S.bus.emit)
        S.bus.emit({"type": "verify", "result": v})
        return v

    start_job("verify", run)
    return {"ok": True}


def api_runs(_):
    return {"runs": E.list_runs(S.need_t())}


def api_reattach(b):
    t = S.need_t()
    rid = b.get("id", "")
    if not rid or "/" in rid:
        raise TransportError("bad run id")

    def run():
        S.bus.emit({"type": "run", "id": rid, "watch": E.watch_cmd(rid, True)})
        rc = E.follow(t, rid, S.bus.emit, S.stop)
        return {"rc": rc}

    start_job("reattach", run)
    return {"ok": True}


def api_stop(_):
    S.stop.set()
    return {"ok": True, "note": "Stopped following. Anything already running on the appliance carries on."}


def api_backups(_):
    return {"backups": E.list_backups(S.need_t())}


def api_rollback(b):
    t = S.need_t()
    bid = b.get("id", "")
    systemd = (S.facts or {}).get("systemdrun") == "yes"

    def run():
        return E.rollback(t, bid, systemd, S.bus.emit, S.stop)

    start_job("rollback", run)
    return {"ok": True}


def api_morpheus(b):
    url = (b.get("url") or "").strip()
    if b.get("token"):
        S.morpheus["token"] = b["token"].strip()
    if url:
        S.morpheus["url"] = url
        save_settings({"morpheus_url": url})
    if not S.morpheus["url"] or not S.morpheus["token"]:
        raise TransportError("Enter the Morpheus URL and an API token.")
    return E.morpheus_check(S.morpheus["url"], S.morpheus["token"], S.analysis)


def api_set_appliance_url(b):
    if not S.morpheus["url"] or not S.morpheus["token"]:
        raise TransportError("Check the Morpheus API first.")
    new = (b.get("new_url") or "").strip()
    if not new.startswith("https://"):
        raise TransportError("The Appliance URL should start with https://")
    E.set_appliance_url(S.morpheus["url"], S.morpheus["token"], new, S.analysis)
    return E.morpheus_check(S.morpheus["url"], S.morpheus["token"], S.analysis)


def api_shell_open(b):
    t = S.need_t()
    if not hasattr(t, "open_shell"):
        raise TransportError("The Shell tab needs Morpheus Certificate Install's own SSH connection. With Charon, use the Charon tab itself.")
    t.open_shell(int(b.get("cols") or 120), int(b.get("rows") or 32),
                 lambda d: S.bus.emit({"type": "shell", "data": base64.b64encode(d).decode()}),
                 lambda: S.bus.emit({"type": "shell_closed"}))
    return {"ok": True}


def api_shell_input(b):
    S.need_t().shell_input(base64.b64decode(b.get("b64", "")))
    return {"ok": True}


def api_shell_resize(b):
    t = S.need_t()
    if hasattr(t, "shell_resize"):
        t.shell_resize(int(b.get("cols") or 120), int(b.get("rows") or 32))
    return {"ok": True}


ROUTES = {
    "/api/state": api_state, "/api/connect": api_connect, "/api/disconnect": api_disconnect,
    "/api/charon": api_charon, "/api/preflight": api_preflight, "/api/analyze": api_analyze,
    "/api/clear-files": api_clear_files, "/api/fetch-chain": api_fetch_chain, "/api/export": api_export, "/api/plan": api_plan, "/api/apply": api_apply,
    "/api/verify": api_verify, "/api/runs": api_runs, "/api/reattach": api_reattach, "/api/stop": api_stop,
    "/api/backups": api_backups, "/api/rollback": api_rollback, "/api/morpheus": api_morpheus,
    "/api/morpheus/appliance-url": api_set_appliance_url, "/api/shell/open": api_shell_open,
    "/api/shell/input": api_shell_input, "/api/shell/resize": api_shell_resize,
}


class Handler(BaseHTTPRequestHandler):
    server_version = f"morpheus-certificate-install/{__version__}"

    def log_message(self, fmt, *args):  # keep the console quiet (no request logging of secrets)
        pass

    def _host_ok(self):
        host = (self.headers.get("Host") or "").split(":")[0]
        return host in ("127.0.0.1", "localhost")

    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if not self._host_ok():
            return self._send(403, {"error": "bad host"})
        u = urlparse(self.path)
        if u.path in ("/", "/index.html"):
            html = (WEB / "index.html").read_bytes().replace(b"__MCI_VERSION__", __version__.encode())
            return self._send(200, html, "text/html; charset=utf-8")
        if u.path.startswith("/vendor/"):
            name = u.path[len("/vendor/"):]
            f = WEB / "vendor" / name
            if "/" in name or ".." in name or not f.is_file():
                return self._send(404, {"error": "not found"})
            ctype = {"js": "text/javascript", "css": "text/css"}.get(name.rsplit(".", 1)[-1], "application/octet-stream")
            return self._send(200, f.read_bytes(), ctype + "; charset=utf-8")
        if u.path == "/api/events":
            if parse_qs(u.query).get("t", [""])[0] != S.token:
                return self._send(401, {"error": "token"})
            return self._sse()
        if u.path.startswith("/api/"):
            return self._api(u.path, {})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._host_ok():
            return self._send(403, {"error": "bad host"})
        n = int(self.headers.get("Content-Length") or 0)
        if n > 64 * 1024 * 1024:
            return self._send(413, {"error": "too large"})
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return self._send(400, {"error": "bad json"})
        self._api(urlparse(self.path).path, body)

    def _api(self, path, body):
        if self.headers.get("X-MCI-Token") != S.token:
            return self._send(401, {"error": "Missing or wrong session token — reopen Morpheus Certificate Install from the link it printed."})
        fn = ROUTES.get(path)
        if not fn:
            return self._send(404, {"error": "no such endpoint"})
        try:
            return self._send(200, fn(body))
        except TransportError as e:
            return self._send(400, {"error": str(e)})
        except KeyError as e:
            return self._send(400, {"error": f"missing field {e}"})
        except Exception as e:
            traceback.print_exc()
            return self._send(500, {"error": f"{type(e).__name__}: {e}"})

    def _sse(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        qq = S.bus.subscribe()
        try:
            while True:
                try:
                    ev = qq.get(timeout=15)
                    self.wfile.write(b"data: " + json.dumps(ev).encode() + b"\n\n")
                except queue.Empty:
                    self.wfile.write(b": ping\n\n")
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            S.bus.unsubscribe(qq)


def free_port(start: int) -> int:
    for p in range(start, start + 50):
        with socket.socket() as s:
            try:
                s.bind(("127.0.0.1", p))
                return p
            except OSError:
                continue
    raise SystemExit("no free port")


def convert_main(argv):
    ap = argparse.ArgumentParser(prog="morpheus-certificate-install convert",
                                 description="Convert whatever the CA sent into the files a Morpheus appliance needs.")
    ap.add_argument("files", nargs="+", help="certificate, key, bundle, PFX/P12, P7B or JKS files")
    ap.add_argument("--fqdn", default="", help="appliance FQDN (default: from the certificate)")
    ap.add_argument("--out", default="", help="output folder (default: ./<fqdn>-morpheus)")
    ap.add_argument("--zip", action="store_true", help="write a .zip instead of a folder")
    ap.add_argument("--include-root", action="store_true", help="append the root to the served chain")
    ap.add_argument("--fetch-chain", action="store_true", help="download missing intermediates from the CA Issuers URL")
    ap.add_argument("--ask", action="store_true", help="prompt for PFX / key / keystore passwords")
    a = ap.parse_args(argv)
    pws = [os.environ.get("MCI_PFX_PASSWORD", ""), os.environ.get("MCI_KEY_PASSWORD", "")]
    if a.ask:
        pws = [getpass.getpass("PFX / keystore password (Enter for none): "), getpass.getpass("Key passphrase (Enter for none): ")]
    files = [(Path(f).name, Path(f).read_bytes()) for f in a.files]
    bundle = C.parse_files(files, pws[0], pws[1])
    if a.fetch_chain:
        for line in C.complete_chain(bundle):
            print("  chain:", line)
    an = C.analyze(bundle, a.fqdn)
    print(f"Morpheus Certificate Install {__version__} convert")
    for r in an.reports:
        print(f"  {r.name}: {r.format}")
        for n in r.notes:
            print(f"      {n}")
    mark = {"ok": "✓", "warn": "!", "error": "✗"}
    for c in an.checks:
        print(f"  {mark[c['level']]} {c['text']}")
    if not an.ok:
        print("Not converted — fix the errors above.")
        return 2
    files_out = X.build_files(an, a.include_root)
    folder = a.out or (C.safe_name(an.fqdn) + "-morpheus")
    if a.zip:
        dest = Path(folder if folder.endswith(".zip") else folder + ".zip")
        dest.write_bytes(X.to_zip(files_out, Path(folder).stem))
    else:
        dest = Path(folder)
        X.to_dir(files_out, dest)
    print(f"Wrote {dest}:")
    for n in sorted(files_out):
        print(f"  {n}")
    return 0


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "convert":
        raise SystemExit(convert_main(sys.argv[2:]))
    ap = argparse.ArgumentParser(prog="morpheus-certificate-install", description="Install CA-signed certificates on an HPE Morpheus appliance. "
                                 "`morpheus-certificate-install convert --help` for the command-line converter.")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--version", action="version", version=f"morpheus-certificate-install {__version__}")
    a = ap.parse_args()
    port = free_port(a.port)
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    srv.daemon_threads = True
    url = f"http://127.0.0.1:{port}/#t={S.token}"
    print(f"Morpheus Certificate Install {__version__}\nOpen: {url}\n(Ctrl+C to quit — secrets are kept in memory only)")
    if not a.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if S.t:
            S.t.close()


if __name__ == "__main__":
    main()
