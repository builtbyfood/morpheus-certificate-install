"""morpheus-certificate-install 0.4.0 — a stand-in for Charon's MCP HTTP server (tests only).

Started from reference/python/tests/mock_charon.py (frozen, unchanged). Same contract as
builtbyfood/charon src-tauri/src/mcp: POST JSON-RPC with `Authorization: Bearer <token>`, tools
list_sessions / run_command / sftp_put, results as {content:[{type:text,text}], isError?}.
Writes mcp-endpoint.json into the data dir, like Charon.

Two ways to run commands:
  python mock_charon.py <data_dir>
      LOCAL (Linux, as root): a leading `sudo ` runs as root, anything else as $MOCK_USER — the
      reference's behaviour.
  python mock_charon.py <data_dir> --ssh host:port:user:password
      SSH (any OS, needs paramiko): like real Charon, an SSH session to the fake appliance. Each
      run_command gets a PTY; when sudo prompts, the mock types the password (Charon answers sudo at
      the trusted tier); sftp_put copies over SFTP.

run_command output is made ugly the way a real terminal's is (MOCK_CLEAN=1 turns that off):
CRLF line endings, the command line echoed after a prompt, OSC 133 marks and a colour code around
it, and — in LOCAL mode, where there's no real sudo to print them — sudo's lecture and prompt
mixed in. In SSH mode the PTY and the appliance's sudo provide the real thing.
"""
import json, os, re, secrets, shutil, subprocess, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

USER = os.environ.get("MOCK_USER", "mcitest")
TOKEN = secrets.token_hex(16)
UGLY = os.environ.get("MOCK_CLEAN") != "1"
SSH = None  # (host, port, user, password) in SSH mode
DATA_DIR = "."  # the data dir given on the command line (run_command.log goes there)
LECTURE = ("\nWe trust you have received the usual lecture from the local System\nAdministrator. "
           "It usually boils down to these three things:\n\n    #1) Respect the privacy of others.\n"
           "    #2) Think before you type.\n    #3) With great power comes great responsibility.\n\n")


def crlf(s):
    return s.replace("\r\n", "\n").replace("\n", "\r\n")


def dress(cmd, body, rc):
    """What a terminal shows for one command: prompt + echoed command, output, end mark."""
    if not UGLY:
        return body
    prompt = f"\x1b]133;A\x07\x1b[01;32m{USER}@appliance\x1b[00m:~$ \x1b]133;B\x07"
    return f"{prompt}{cmd}\r\n\x1b]133;C\x07{crlf(body)}\x1b]133;D;{rc}\x07{prompt}"


# ------------------------------------------------------------------ LOCAL mode (the reference's)

def run_local(cmd, timeout):
    sudo = "sudo " in cmd
    if cmd.startswith("sudo "):
        argv = ["bash", "-c", cmd[5:]]
    else:
        # A `sudo` inside the command (e.g. a framed data read) runs as root too, as if Charon
        # had answered the prompt; the rest as the session user.
        argv = ["runuser", "-u", USER, "--", "bash", "-c", cmd.replace("sudo bash -c", "bash -c")] \
            if not sudo else ["bash", "-c", cmd.replace("sudo bash -c", "bash -c")]
    p = subprocess.run(argv, capture_output=True, timeout=timeout, cwd="/tmp")
    body = (p.stdout + p.stderr).decode(errors="replace")
    if UGLY and sudo and "-n true" not in cmd:
        body = LECTURE + f"[sudo] password for {USER}: \n" + body
    return p.returncode, body


# ------------------------------------------------------------------ SSH mode (like real Charon)

_ssh_lock = threading.Lock()
_ssh_client = None


def ssh_client():
    global _ssh_client
    import paramiko
    with _ssh_lock:
        if _ssh_client is None or not _ssh_client.get_transport() or not _ssh_client.get_transport().is_active():
            c = paramiko.SSHClient()
            c.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # a test stand-in, not the app
            host, port, user, pw = SSH
            c.connect(host, port=port, username=user, password=pw, look_for_keys=False, allow_agent=False, timeout=15)
            _ssh_client = c
        return _ssh_client


def run_ssh(cmd, timeout):
    host, port, user, pw = SSH
    ch = ssh_client().get_transport().open_session()
    ch.get_pty(term="xterm-256color", width=200, height=50)
    ch.settimeout(1.0)
    ch.exec_command(cmd)
    buf, answered, deadline = b"", 0, time.time() + timeout
    while True:
        try:
            data = ch.recv(65536)
            if not data:
                break
            buf += data
            # Charon answers sudo's prompt itself at the trusted tier.
            tail = buf[-200:].decode(errors="replace")
            if re.search(r"(\[sudo\] password for [^:]*|Password): ?$", tail) and buf.count(b"password for") + buf.count(b"Password:") > answered:
                answered += 1
                ch.sendall((pw + "\n").encode())
        except Exception:  # socket.timeout
            if ch.exit_status_ready() and not ch.recv_ready():
                break
        if time.time() > deadline:
            ch.close()
            raise RuntimeError(f"timed out after {timeout}s")
    rc = ch.recv_exit_status()
    ch.close()
    return rc, buf.decode(errors="replace")


def sftp_put_ssh(local, remote):
    sftp = ssh_client().open_sftp()
    try:
        sftp.put(local, remote)
    finally:
        sftp.close()


# ------------------------------------------------------------------ the MCP server

LOG = []


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            self.send_response(401); self.end_headers(); return
        m, p = body["method"], body.get("params", {})
        if m == "initialize":
            res = {"protocolVersion": "2024-11-05", "serverInfo": {"name": "mock-charon"}}
        elif m == "tools/call":
            name, a = p["name"], p.get("arguments", {})
            LOG.append((name, a.get("command") or a.get("remote")))
            try:
                if name == "list_sessions":
                    host = SSH[0] if SSH else "127.0.0.1"
                    port = SSH[1] if SSH else 22
                    out = [{"id": "s1", "title": f"{USER}@{host}" + (f":{port}" if port != 22 else ""), "kind": "ssh",
                            "host": host, "shell": "bash", "cwd": f"/home/{USER}", "tier": "trusted"},
                           {"id": "l1", "title": "local", "kind": "local", "host": "me", "tier": "read"}]
                elif name == "run_command":
                    if a.get("session") != "s1":
                        raise RuntimeError(f"no open session {a.get('session')!r}")
                    cmd, t = a["command"], int(a.get("timeout_s") or 120)
                    # For the tests: one line per run_command, "poll" for a follow long poll
                    # (appliance::charon_long_poll), "cmd" otherwise. No command text (0.3.16).
                    with open(os.path.join(DATA_DIR, "run_command.log"), "a") as f:
                        f.write(("poll" if "end=$((SECONDS+" in cmd else "cmd") + "\n")
                    rc, o = run_ssh(cmd, t) if SSH else run_local(cmd, t)
                    out = {"output": dress(cmd, o, rc), "exit_code": rc}
                elif name == "sftp_put":
                    if SSH:
                        sftp_put_ssh(a["local"], a["remote"])
                    else:
                        shutil.copyfile(a["local"], a["remote"]); shutil.chown(a["remote"], USER)
                    out = {"ok": True}
                else:
                    raise RuntimeError("unknown tool")
                res = {"content": [{"type": "text", "text": json.dumps(out)}]}
            except Exception as e:
                res = {"content": [{"type": "text", "text": str(e)}], "isError": True}
        else:
            res = {}
        data = json.dumps({"jsonrpc": "2.0", "id": body.get("id"), "result": res}).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)


if __name__ == "__main__":
    d = sys.argv[1]
    DATA_DIR = d
    if "--ssh" in sys.argv:
        h, port, user, pw = sys.argv[sys.argv.index("--ssh") + 1].split(":", 3)
        SSH = (h, int(port), user, pw)
        USER = user
    os.makedirs(d, exist_ok=True)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    with open(os.path.join(d, "mcp-endpoint.json"), "w") as f:
        json.dump({"port": srv.server_address[1], "token": TOKEN}, f)
    print(f"mock-charon on 127.0.0.1:{srv.server_address[1]} ({'ssh ' + SSH[0] if SSH else 'local'})", flush=True)
    srv.serve_forever()
