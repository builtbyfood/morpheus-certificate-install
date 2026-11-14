# morpheus-certificate-install 0.4.1 — test stand-in for nginx + a sliver of the Morpheus API.
#
# Serves, on :443, the certificate and key that morpheus.rb names (the last active
# nginx['ssl_certificate'] / nginx['ssl_server_key'] lines), so install / verify / rollback can be
# checked end to end. Re-read on every start: `morpheus-ctl restart nginx` restarts this.
#
# The Morpheus API, as far as the app reads it (reference engine.morpheus_check / set_appliance_url),
# with a fixed test token as a Bearer header ("Authorization: Bearer <TOKEN>"):
#   GET /api/whoami              -> {"user": {"username": ...}, "appliance": {"buildVersion": ...}}
#   GET /api/appliance-settings  -> {"applianceSettings": {"applianceUrl": ...}}
#   PUT /api/appliance-settings  {"applianceSettings": {"applianceUrl": "https://..."}} -> stored, echoed
# No token, or a wrong one: 401, as Morpheus answers. `?access_token=` is ignored, as Morpheus does.
# The Appliance URL setting starts as morpheus.rb's appliance_url and is kept in STATE across restarts.
# Anything else: 200 "ok".
import json, os, re, ssl, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN = "mci-fake-api-token-7f3c9a1e"
STATE = "/var/lib/fake-morpheus/appliance-url"
USER = "mci-api-tester"
BUILD = "8.0.0-fake"

rb = open('/etc/morpheus/morpheus.rb').read()
c = re.findall(r"^nginx\['ssl_certificate'\]\s*=\s*'([^']+)'", rb, re.M)
k = re.findall(r"^nginx\['ssl_server_key'\]\s*=\s*'([^']+)'", rb, re.M)
crt = c[-1] if c else '/etc/morpheus/ssl/appliance.crt'
key = k[-1] if k else '/etc/morpheus/ssl/appliance.key'
u = re.findall(r"^\s*appliance_url\s+['\"]([^'\"]+)['\"]", rb, re.M)
RB_URL = u[-1] if u else "https://localhost"
lock = threading.Lock()


def appliance_url():
    try:
        with open(STATE) as f:
            return f.read().strip() or RB_URL
    except OSError:
        return RB_URL


def set_appliance_url(v):
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    with open(STATE + ".tmp", "w") as f:
        f.write(v + "\n")
    os.replace(STATE + ".tmp", STATE)


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = "nginx"

    def setup(self):
        self.request.settimeout(15)
        self.request.do_handshake()  # in this handler's thread (see the wrap_socket below)
        super().setup()

    def log_message(self, *a):  # quiet; and never log headers (the token)
        pass

    def send_json(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def authed(self):
        if self.headers.get("Authorization", "") == "Bearer " + TOKEN:
            return True
        self.send_json(401, {"error": "invalid_token", "error_description": "Invalid access token"})
        return False

    def route(self):
        return self.path.split("?", 1)[0].rstrip("/")

    def do_GET(self):
        p = self.route()
        if p == "/api/whoami":
            if self.authed():
                self.send_json(200, {"user": {"id": 1, "username": USER}, "appliance": {"buildVersion": BUILD}})
        elif p == "/api/appliance-settings":
            if self.authed():
                with lock:
                    self.send_json(200, {"applianceSettings": {"applianceUrl": appliance_url()}})
        else:
            b = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

    def do_PUT(self):
        if self.route() != "/api/appliance-settings":
            return self.send_json(404, {"error": "not found"})
        if not self.authed():
            return
        try:
            n = int(self.headers.get("Content-Length") or 0)
            v = json.loads(self.rfile.read(n) or b"{}")["applianceSettings"]["applianceUrl"]
            assert isinstance(v, str) and v
        except Exception:
            return self.send_json(400, {"success": False, "msg": "applianceSettings.applianceUrl is required"})
        with lock:
            set_appliance_url(v)
            self.send_json(200, {"success": True, "applianceSettings": {"applianceUrl": appliance_url()}})


class S(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        pass  # TLS probes that close after the handshake, scanners: not interesting


ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(crt, key)
srv = S(("0.0.0.0", 443), H)
# The handshake happens on the handler's first read, in its own thread, so a client that
# connects and says nothing never blocks the accept loop.
srv.socket = ctx.wrap_socket(srv.socket, server_side=True, do_handshake_on_connect=False)
print("serving", crt, "| api token", TOKEN[:8] + "…", flush=True)
srv.serve_forever()
