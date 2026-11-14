"""Morpheus Certificate Install 0.2.1 — a stand-in for Charon's MCP HTTP server (tests only).

Speaks the same contract as builtbyfood/charon src-tauri/src/mcp: POST JSON-RPC
with `Authorization: Bearer <token>`, tools list_sessions / run_command /
sftp_put, results as {content:[{type:text,text}], isError?}. Commands run
locally: a leading `sudo ` runs as root (as if Charon answered the sudo prompt),
anything else runs as the session user. Writes mcp-endpoint.json like Charon.
"""
import json, os, secrets, shutil, subprocess, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

USER = os.environ.get("MOCK_USER", "mcitest")
TOKEN = secrets.token_hex(16)
LOG = []

def run(cmd):
    if cmd.startswith("sudo "):
        argv = ["bash", "-c", cmd[5:]]
    else:
        argv = ["runuser", "-u", USER, "--", "bash", "-c", cmd]
    p = subprocess.run(argv, capture_output=True, timeout=120, cwd="/tmp")
    return p.returncode, (p.stdout + p.stderr).decode(errors="replace")

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            self.send_response(401); self.end_headers(); return
        m, p = body["method"], body.get("params", {})
        if m == "initialize": res = {"protocolVersion": "2024-11-05"}
        elif m == "tools/call":
            name, a = p["name"], p.get("arguments", {})
            LOG.append((name, a.get("command") or a.get("remote")))
            try:
                if name == "list_sessions":
                    out = [{"id": "s1", "title": "appliance", "kind": "ssh", "host": "127.0.0.1", "tier": "trusted"},
                           {"id": "l1", "title": "local", "kind": "local", "host": "me", "tier": "read"}]
                elif name == "run_command":
                    rc, o = run(a["command"]); out = {"output": o, "exit_code": rc}
                elif name == "sftp_put":
                    shutil.copyfile(a["local"], a["remote"]); shutil.chown(a["remote"], USER); out = {"ok": True}
                else: raise RuntimeError("unknown tool")
                res = {"content": [{"type": "text", "text": json.dumps(out)}]}
            except Exception as e:
                res = {"content": [{"type": "text", "text": str(e)}], "isError": True}
        else: res = {}
        data = json.dumps({"jsonrpc": "2.0", "id": body.get("id"), "result": res}).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)

if __name__ == "__main__":
    d = sys.argv[1]; os.makedirs(d, exist_ok=True)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    json.dump({"port": srv.server_address[1], "token": TOKEN}, open(os.path.join(d, "mcp-endpoint.json"), "w"))
    srv.serve_forever()
