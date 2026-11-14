"""Transports for Morpheus Certificate Install 0.2.1.

SshTransport   — Morpheus Certificate Install's own SSH connection (paramiko): exec channels for the
                 steps, an interactive PTY for the Shell tab, live log streaming.
CharonTransport — drive a session that is already open in Charon through its
                 MCP server (run_command / sftp_put). Every step shows up in
                 Charon's approval dialog at the exec-approve tier.

Both expose the same small surface the plan engine uses:
    run(cmd, sudo=False, stdin=None, timeout=120) -> (rc, text)
    put_root(path, data, mode)                     -> None   (root-owned file)
    stream_file(path, rc_path, on_text, stop)      -> rc     (follow a log)
"""
from __future__ import annotations

import base64
import json
import os
import shlex
import socket
import sqlite3
import tempfile
import threading
import time
import urllib.request
from pathlib import Path
from typing import Callable, List, Optional, Tuple

import paramiko

from . import __version__

CONFIG_DIR = Path(os.environ.get("MCI_HOME") or (Path.home() / ".morpheus-certificate-install"))
KNOWN_HOSTS = CONFIG_DIR / "known_hosts"


class TransportError(Exception):
    pass


class HostKeyPrompt(TransportError):
    def __init__(self, host: str, key_type: str, fingerprint: str, mismatch: bool = False):
        self.host, self.key_type, self.fingerprint, self.mismatch = host, key_type, fingerprint, mismatch
        super().__init__(f"{'CHANGED' if mismatch else 'unknown'} host key for {host}: {key_type} {fingerprint}")


def q(s: str) -> str:
    return shlex.quote(s)


def fp_sha256(key: paramiko.PKey) -> str:
    return "SHA256:" + base64.b64encode(__import__("hashlib").sha256(key.asbytes()).digest()).decode().rstrip("=")


class _Policy(paramiko.MissingHostKeyPolicy):
    def __init__(self, trust_fp: Optional[str]):
        self.trust_fp = trust_fp

    def missing_host_key(self, client, hostname, key):
        fp = fp_sha256(key)
        if self.trust_fp and self.trust_fp == fp:
            client.get_host_keys().add(hostname, key.get_name(), key)
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            client.save_host_keys(str(KNOWN_HOSTS))
            return
        raise HostKeyPrompt(hostname, key.get_name(), fp)


class Transport:
    kind = "base"
    login_user = ""
    label = ""

    def run(self, cmd: str, sudo: bool = False, stdin: Optional[bytes] = None, timeout: int = 120) -> Tuple[int, str]:
        raise NotImplementedError

    def put_root(self, path: str, data: bytes, mode: str = "0600", dir_mode: str = "0700") -> None:
        """Write a root-owned file atomically. A missing parent dir is created with dir_mode."""
        raise NotImplementedError

    def stream_file(self, path: str, rc_path: str, on_text: Callable[[str], None], stop: threading.Event) -> Optional[int]:
        raise NotImplementedError

    def close(self) -> None:
        pass

    def info(self) -> dict:
        return {"kind": self.kind, "label": self.label, "user": self.login_user}

    def check(self, cmd: str, sudo: bool = False, what: str = "") -> str:
        rc, out = self.run(cmd, sudo=sudo)
        if rc != 0:
            raise TransportError(f"{what or cmd} failed (exit {rc}): {out.strip()[-800:]}")
        return out


# ------------------------------------------------------------------ SSH

class SshTransport(Transport):
    kind = "ssh"

    def __init__(self, host: str, port: int, user: str, password: str = "", key_path: str = "",
                 key_passphrase: str = "", sudo_password: str = "", trust_fp: str = ""):
        self.host, self.port, self.user = host, int(port or 22), user
        self.password = password
        self.sudo_password = sudo_password or password
        self.client = paramiko.SSHClient()
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        if KNOWN_HOSTS.exists():
            try:
                self.client.load_host_keys(str(KNOWN_HOSTS))
            except Exception:
                pass
        self.client.set_missing_host_key_policy(_Policy(trust_fp or None))
        kw = dict(hostname=host, port=self.port, username=user, timeout=15, banner_timeout=20, auth_timeout=20)
        if key_path:
            kw["key_filename"] = os.path.expanduser(key_path)
            if key_passphrase:
                kw["passphrase"] = key_passphrase
        if password:
            kw["password"] = password
        kw["allow_agent"] = not password and not key_path
        kw["look_for_keys"] = not password and not key_path
        try:
            self.client.connect(**kw)
        except HostKeyPrompt:
            raise
        except paramiko.BadHostKeyException as e:
            raise HostKeyPrompt(host, e.key.get_name(), fp_sha256(e.key), mismatch=True)
        except paramiko.AuthenticationException as e:
            raise TransportError(f"Authentication failed for {user}@{host}: {e}")
        except (socket.error, paramiko.SSHException) as e:
            raise TransportError(f"Could not connect to {host}:{self.port}: {e}")
        self.login_user = user
        self.label = f"{user}@{host}" + (f":{self.port}" if self.port != 22 else "")
        self.fingerprint = fp_sha256(self.client.get_transport().get_remote_server_key())
        self.sudo_mode = self._detect_sudo()
        self._shell = None

    def _raw(self, cmd: str, stdin: Optional[bytes], timeout: int, on_chunk=None, stop=None) -> Tuple[int, str]:
        tr = self.client.get_transport()
        if tr is None or not tr.is_active():
            raise TransportError("SSH connection is closed. Reconnect on the Connect step.")
        ch = tr.open_session()
        ch.set_combine_stderr(True)
        ch.settimeout(1.0)
        ch.exec_command(cmd)
        if stdin:
            ch.sendall(stdin)
        ch.shutdown_write()
        buf = bytearray()
        deadline = time.time() + timeout if timeout else None
        while True:
            if stop is not None and stop.is_set():
                ch.close()
                return -2, buf.decode(errors="replace")
            try:
                data = ch.recv(65536)
                if not data:
                    break
                buf += data
                if on_chunk:
                    on_chunk(data.decode(errors="replace"))
            except socket.timeout:
                pass
            if deadline and time.time() > deadline:
                ch.close()
                raise TransportError(f"timed out after {timeout}s: {cmd[:120]}")
        rc = ch.recv_exit_status()
        ch.close()
        return rc, buf.decode(errors="replace")

    def _detect_sudo(self) -> str:
        rc, out = self._raw("id -u", None, 15)
        if rc == 0 and out.strip() == "0":
            return "root"
        # -k: ignore any cached sudo timestamp, so success here really means NOPASSWD.
        rc, _ = self._raw("sudo -k -n true", None, 15)
        if rc == 0:
            return "nopasswd"
        return "password"

    def _wrap(self, cmd: str, sudo: bool, stdin: Optional[bytes]) -> Tuple[str, Optional[bytes]]:
        inner = f"bash -c {q(cmd)}"
        if not sudo or self.sudo_mode == "root":
            return inner, stdin
        if self.sudo_mode == "nopasswd":
            return f"sudo -n {inner}", stdin
        if not self.sudo_password:
            raise TransportError("sudo needs a password for this account. Enter it in the Connect step (Sudo password).")
        # -k forces sudo to read the password line every time, so the password
        # is never passed through to the command's stdin by a cached timestamp.
        return f"sudo -k -S -p '' {inner}", self.sudo_password.encode() + b"\n" + (stdin or b"")

    def run(self, cmd, sudo=False, stdin=None, timeout=120):
        full, data = self._wrap(cmd, sudo, stdin)
        rc, out = self._raw(full, data, timeout)
        if sudo and self.sudo_mode == "password" and rc != 0 and ("incorrect password" in out or "Sorry, try again" in out):
            raise TransportError("sudo rejected the password. Fix the Sudo password on the Connect step.")
        return rc, out

    def put_root(self, path, data, mode="0600", dir_mode="0700"):
        tmp = f"{path}.mci-tmp"
        cmd = (f"set -e; umask 077; d=$(dirname {q(path)}); [ -d \"$d\" ] || {{ mkdir -p \"$d\"; chmod {dir_mode} \"$d\"; }}; cat > {q(tmp)}; "
               f"chown root:root {q(tmp)}; chmod {mode} {q(tmp)}; mv -f {q(tmp)} {q(path)}")
        rc, out = self.run(cmd, sudo=True, stdin=data)
        if rc != 0:
            raise TransportError(f"writing {path} failed (exit {rc}): {out.strip()[-400:]}")

    def stream_file(self, path, rc_path, on_text, stop):
        # Follow until the runner writes its rc file, then drain and print it.
        script = (f"f={q(path)}; r={q(rc_path)}; i=0; while [ ! -e \"$f\" ] && [ $i -lt 30 ]; do sleep 1; i=$((i+1)); done; "
                  f"tail -n +1 -F \"$f\" 2>/dev/null & T=$!; "
                  f"while [ ! -s \"$r\" ]; do sleep 1; done; sleep 2; kill $T 2>/dev/null; wait $T 2>/dev/null; "
                  f"echo; echo \"@@RC=$(cat \"$r\")\"")
        rc_holder = {}

        def chunk(t):
            if "@@RC=" in t:
                pre, _, post = t.partition("@@RC=")
                if pre:
                    on_text(pre)
                try:
                    rc_holder["rc"] = int(post.strip().split()[0])
                except (ValueError, IndexError):
                    pass
            else:
                on_text(t)

        self._raw(f"bash -c {q(script)}", None, 0, on_chunk=chunk, stop=stop)
        return rc_holder.get("rc")

    # ---- interactive shell (Shell tab)
    def open_shell(self, cols: int, rows: int, on_data: Callable[[bytes], None], on_close: Callable[[], None]):
        self.close_shell()
        ch = self.client.get_transport().open_session()
        ch.get_pty(term="xterm-256color", width=cols, height=rows)
        ch.invoke_shell()
        self._shell = ch

        def pump():
            try:
                while True:
                    data = ch.recv(32768)
                    if not data:
                        break
                    on_data(data)
            except Exception:
                pass
            finally:
                on_close()

        threading.Thread(target=pump, daemon=True).start()

    def shell_input(self, data: bytes):
        if self._shell is None or self._shell.closed:
            raise TransportError("No shell open.")
        self._shell.sendall(data)

    def shell_resize(self, cols: int, rows: int):
        if self._shell is not None and not self._shell.closed:
            self._shell.resize_pty(width=cols, height=rows)

    def close_shell(self):
        if self._shell is not None:
            try:
                self._shell.close()
            except Exception:
                pass
            self._shell = None

    def close(self):
        self.close_shell()
        try:
            self.client.close()
        except Exception:
            pass

    def info(self):
        d = super().info()
        d.update(host=self.host, port=self.port, sudo_mode=self.sudo_mode, fingerprint=self.fingerprint, shell=True)
        return d


# ------------------------------------------------------------------ Charon

def charon_data_dirs() -> List[Path]:
    dirs = []
    if os.environ.get("CHARON_DATA"):
        dirs.append(Path(os.environ["CHARON_DATA"]))
    home = Path.home()
    if os.name == "nt":
        appdata = os.environ.get("APPDATA")
        if appdata:
            dirs.append(Path(appdata) / "charon")
    elif os.uname().sysname == "Darwin":
        dirs.append(home / "Library" / "Application Support" / "charon")
    dirs.append(Path(os.environ.get("XDG_CONFIG_HOME") or (home / ".config")) / "charon")
    # Portable builds keep data/ beside the exe; the user can point at it.
    seen, out = set(), []
    for d in dirs:
        if str(d) not in seen:
            seen.add(str(d))
            out.append(d)
    return out


def charon_discover(extra_dir: str = "") -> dict:
    """Find Charon's MCP endpoint and saved SSH hosts (never credentials)."""
    dirs = ([Path(os.path.expanduser(extra_dir))] if extra_dir else []) + charon_data_dirs()
    result = {"searched": [str(d) for d in dirs], "data_dir": None, "endpoint": None, "hosts": []}
    for d in dirs:
        if not d.is_dir():
            continue
        if (d / "mcp-endpoint.json").exists() or (d / "charon.db").exists():
            result["data_dir"] = str(d)
            ep = d / "mcp-endpoint.json"
            if ep.exists():
                try:
                    v = json.loads(ep.read_text())
                    result["endpoint"] = {"port": int(v["port"]), "has_token": bool(v.get("token"))}
                except Exception:
                    pass
            db = d / "charon.db"
            if db.exists():
                result["hosts"] = _charon_hosts(db)
            break
    return result


def _charon_hosts(db: Path) -> List[dict]:
    try:
        con = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True, timeout=2)
        rows = con.execute("SELECT id, parent_id, kind, name, settings FROM nodes").fetchall()
        con.close()
    except sqlite3.Error:
        return []
    nodes = {}
    for nid, parent, kind, name, settings in rows:
        try:
            s = json.loads(settings or "{}")
        except ValueError:
            s = {}
        nodes[nid] = (parent, kind, name, s)

    def effective(nid):
        chain, cur, guard = [], nid, 0
        while cur and cur in nodes and guard < 50:
            chain.append(nodes[cur])
            cur = nodes[cur][0]
            guard += 1
        eff, path = {}, []
        for parent, kind, name, s in reversed(chain):
            path.append(name)
            for k, v in s.items():
                if v is not None:
                    eff[k] = v
        return eff, path

    out = []
    for nid, (parent, kind, name, s) in nodes.items():
        if kind != "ssh":
            continue
        eff, path = effective(nid)
        if not eff.get("host"):
            continue
        out.append({"id": nid, "name": name, "path": " / ".join(path[:-1]), "host": eff.get("host"),
                    "port": eff.get("port") or 22, "user": eff.get("user") or "", "jump_host": eff.get("jump_host"),
                    "tags": eff.get("tags") or []})
    out.sort(key=lambda h: (h["path"], h["name"]))
    return out


class CharonTransport(Transport):
    kind = "charon"

    def __init__(self, port: int, token: str, session: str, sudo: bool = True):
        self.url = f"http://127.0.0.1:{int(port)}/"
        self.token = token
        self.session = session
        self._id = 0
        self._call_rpc("initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                                      "clientInfo": {"name": "morpheus-certificate-install", "version": __version__}})
        sessions = self.tool("list_sessions", {})
        match = next((s for s in sessions if s.get("id") == session), None)
        if not match:
            raise TransportError("That Charon session is no longer open. Refresh the session list.")
        if match.get("kind") != "ssh":
            raise TransportError("Pick an SSH session in Charon (this one is local/serial).")
        self.label = f"Charon · {match.get('title') or match.get('host')}"
        self.tier = match.get("tier")
        rc, out = self.run("id -un")
        if rc != 0:
            raise TransportError(f"Charon could not run a command in that session: {out}")
        self.login_user = out.strip().splitlines()[-1] if out.strip() else ""
        rc, _ = self.run("sudo -k -n true")
        self.sudo_mode = "nopasswd" if rc == 0 else "charon"
        self.stage_dir = None

    @staticmethod
    def from_discovery(data_dir: str, session: str) -> "CharonTransport":
        v = json.loads((Path(data_dir) / "mcp-endpoint.json").read_text())
        return CharonTransport(int(v["port"]), v["token"], session)

    @staticmethod
    def list_sessions(port: int, token: str) -> list:
        t = CharonTransport.__new__(CharonTransport)
        t.url, t.token, t._id = f"http://127.0.0.1:{int(port)}/", token, 0
        t._call_rpc("initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                                   "clientInfo": {"name": "morpheus-certificate-install", "version": __version__}})
        return t.tool("list_sessions", {})

    def _call_rpc(self, method: str, params: dict, timeout: int = 700):
        self._id += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}).encode()
        req = urllib.request.Request(self.url, data=body, method="POST", headers={
            "Content-Type": "application/json", "Authorization": f"Bearer {self.token}"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                resp = json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 401:
                raise TransportError("Charon rejected the MCP token. Restart the MCP server in Charon and rediscover.")
            raise TransportError(f"Charon MCP HTTP {e.code}")
        except OSError as e:
            raise TransportError(f"Could not reach Charon's MCP server at {self.url} — is it enabled? ({e})")
        if "error" in resp:
            raise TransportError(f"Charon: {resp['error'].get('message')}")
        return resp.get("result")

    def tool(self, name: str, args: dict, timeout: int = 700):
        res = self._call_rpc("tools/call", {"name": name, "arguments": args}, timeout)
        text = "".join(c.get("text", "") for c in (res or {}).get("content", []))
        if (res or {}).get("isError"):
            raise TransportError(f"Charon {name}: {text}")
        try:
            return json.loads(text)
        except ValueError:
            return text

    def run(self, cmd, sudo=False, stdin=None, timeout=110):
        if stdin is not None:
            raise TransportError("internal: Charon transport passes data through files, not stdin")
        line = f"bash -c {q(cmd)}"
        if sudo and self.sudo_mode != "root":
            # Charon answers `[sudo] password for <you>:` itself when the tier allows it.
            line = f"sudo {line}"
        try:
            res = self.tool("run_command", {"session": self.session, "command": line, "timeout_s": min(int(timeout), 600)})
        except TransportError as e:
            msg = str(e)
            if "denied" in msg.lower():
                raise TransportError("Denied in Charon's approval dialog.")
            raise
        return int(res.get("exit_code", -1) if isinstance(res, dict) else -1), (res.get("output", "") if isinstance(res, dict) else str(res))

    def _stage(self) -> str:
        if not self.stage_dir:
            out = self.check("umask 077; mkdir -p \"$HOME/.morpheus-certificate-install-stage\" && chmod 700 \"$HOME/.morpheus-certificate-install-stage\" && cd \"$HOME/.morpheus-certificate-install-stage\" && pwd",
                             what="create staging dir")
            self.stage_dir = out.strip().splitlines()[-1]
        return self.stage_dir

    def put_root(self, path, data, mode="0600", dir_mode="0700"):
        stage = self._stage()
        name = f"put-{int(time.time()*1000)}"
        fd, local = tempfile.mkstemp(prefix="mci-")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            os.chmod(local, 0o600)
            remote = f"{stage}/{name}"
            self.tool("sftp_put", {"session": self.session, "local": local, "remote": remote})
        finally:
            try:
                os.remove(local)
            except OSError:
                pass
        tmp = f"{path}.mci-tmp"
        cmd = (f"set -e; umask 077; d=$(dirname {q(path)}); [ -d \"$d\" ] || {{ mkdir -p \"$d\"; chmod {dir_mode} \"$d\"; }}; cat {q(remote)} > {q(tmp)}; "
               f"chown root:root {q(tmp)}; chmod {mode} {q(tmp)}; mv -f {q(tmp)} {q(path)}")
        try:
            self.check(cmd, sudo=True, what=f"install {path}")
        finally:
            self.run(f"shred -u {q(remote)} 2>/dev/null || rm -f {q(remote)}")

    def stream_file(self, path, rc_path, on_text, stop):
        off = 0
        while not stop.is_set():
            script = (f"f={q(path)}; r={q(rc_path)}; s=$(stat -c %s \"$f\" 2>/dev/null || echo 0); echo \"SIZE=$s\"; "
                      f"echo \"RC=$(cat \"$r\" 2>/dev/null)\"; "
                      f"[ \"$s\" -gt {off} ] && tail -c +{off + 1} \"$f\" | head -c $(( s - {off} > 262144 ? 262144 : s - {off} )) | base64 -w0; echo")
            rc, out = self.run(script, timeout=60)
            lines = out.strip().splitlines()
            rcv = next((l[3:] for l in lines if l.startswith("RC=")), "")
            payload = lines[-1] if lines and not lines[-1].startswith(("SIZE=", "RC=")) else ""
            if payload:
                try:
                    chunk = base64.b64decode(payload)
                    off += len(chunk)
                    on_text(chunk.decode(errors="replace"))
                    continue  # more may be waiting; poll again straight away
                except ValueError:
                    pass
            if rcv.strip():
                try:
                    return int(rcv.strip())
                except ValueError:
                    return -1
            stop.wait(2.0)
        return None

    def info(self):
        d = super().info()
        d.update(tier=self.tier, sudo_mode=self.sudo_mode, shell=False, session=self.session)
        return d
