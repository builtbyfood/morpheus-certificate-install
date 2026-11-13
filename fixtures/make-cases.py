#!/usr/bin/env python3
"""morpheus-certificate-install 0.3.0 — write fixtures/cases.json and fixtures/golden/* from the
Python reference (reference/python, 0.2.1). The Rust port must reproduce these exactly.

Run from the repo root:  python3 fixtures/make-cases.py   (after fixtures/gen-corpus.sh; reads the corpus as it is)
The reference runs with its clock frozen at `generated_at` (recorded in cases.json); parity.rs passes the
same instant to the Rust analyze(), so results never depend on the day the tests run.
Needs: pip install cryptography pyjks paramiko   (paramiko only because the package imports it)
The AIA case needs fixtures/corpus served on http://127.0.0.1:18080/ — this script starts that itself.
"""
import datetime as dt, functools, http.server, json, sys, threading, types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "reference" / "python"))
from morpheus_certificate_install import certs as C, engine as E, export as X, formats as F  # noqa: E402

CORPUS = ROOT / "fixtures" / "corpus"
GENERATED_AT = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


class _FrozenDatetime(dt.datetime):
    """datetime whose now() is GENERATED_AT (certs.analyze and CertInfo.summary read the clock)."""
    @classmethod
    def now(cls, tz=None):
        return GENERATED_AT.astimezone(tz) if tz else GENERATED_AT.replace(tzinfo=None)


C._dt = types.SimpleNamespace(datetime=_FrozenDatetime, timezone=dt.timezone, timedelta=dt.timedelta, date=dt.date)
GOLD = ROOT / "fixtures" / "golden"


def write_lf(path: Path, text: str) -> None:
    """UTF-8 with LF line ends on every OS (Path.write_text would write CRLF on Windows)."""
    path.write_bytes(text.encode("utf-8"))

CASES = [
    # name, files, pfx_pw, key_pw, fqdn, appliance_url, fetch_chain
    ("pem-set-plain",          ["leaf.crt", "leaf.key", "bundle.crt"], "", "", "", "", False),
    ("pem-set-appliance-ip",   ["leaf.crt", "leaf.key", "bundle.crt"], "", "", "", "https://10.0.0.5/", False),
    ("pem-set-appliance-miss", ["leaf.crt", "leaf.key", "bundle.crt"], "", "", "", "https://198.51.100.20/", False),
    ("fqdn-not-covered",       ["leaf.crt", "leaf.key", "bundle.crt"], "", "", "appliance.cust.test", "", False),
    ("p7b-pem-pkcs1",          ["chain.p7b", "leaf-pkcs1.key"], "", "", "", "", False),
    ("p7b-der-der-key",        ["chain-der.p7b", "leaf-der.key"], "", "", "", "", False),
    ("der-cert-enc-der-key",   ["leaf.cer", "leaf-der-enc.key", "int.crt"], "", "dk", "", "", False),
    ("der-key-locked",         ["leaf.cer", "leaf-der-enc.key"], "", "", "", "", False),
    ("pkcs8-encrypted-pem",    ["leaf.crt", "leaf-pkcs8-enc.key", "int.crt"], "", "pk", "", "", False),
    ("legacy-encrypted-pem",   ["leaf.crt", "leaf-legacy-enc.key", "int.crt"], "", "lg", "", "", False),
    ("pem-key-locked",         ["leaf.crt", "leaf-pkcs8-enc.key"], "", "", "", "", False),
    ("pfx-modern",             ["modern.pfx"], "pp", "", "", "", False),
    ("pfx-legacy-windows",     ["legacy.pfx"], "old", "", "", "", False),
    ("pfx-pw-in-key-box",      ["legacy.pfx"], "", "old", "", "", False),
    ("pfx-wrong-password",     ["modern.pfx"], "nope", "", "", "", False),
    ("pfx-no-key",             ["nokey.pfx"], "x", "", "", "", False),
    ("jks",                    ["keystore.jks"], "storepw", "", "", "", False),
    ("jks-wrong-password",     ["keystore.jks"], "nope", "", "", "", False),
    ("windows-text",           ["win.cer", "leaf.key", "int-headerless.txt"], "", "", "", "", False),
    ("utf16",                  ["utf16.cer", "leaf.key", "int.crt"], "", "", "", "", False),
    ("ec-pair",                ["ec.crt", "ec.key", "int.crt", "root.crt"], "", "", "", "", False),
    ("wrong-key",              ["leaf.crt", "other.key", "bundle.crt"], "", "", "", "", False),
    # 0.3.17: a wildcard leaf (*.wild.test + wild.test). Divergence: the reference used "*.wild.test" as the FQDN.
    ("wildcard-leaf",          ["leaf-wildcard.crt", "leaf-wildcard.key", "wildcard-root.crt"], "", "", "", "", False),
    ("wildcard-fqdn-typed",    ["leaf-wildcard.crt", "leaf-wildcard.key", "wildcard-root.crt"], "", "", "*.wild.test", "", False),
    ("wildcard-fqdn-given",    ["leaf-wildcard.crt", "leaf-wildcard.key", "wildcard-root.crt"], "", "", "morpheus.wild.test", "", False),
    ("csr-and-pvk-explained",  ["leaf.crt", "leaf.key", "leaf.csr", "fake.pvk", "int.crt"], "", "", "", "", False),
    ("leaf-only-no-fetch",     ["leaf.crt", "leaf.key"], "", "", "", "", False),
    ("leaf-only-aia-fetch",    ["leaf.crt", "leaf.key"], "", "", "", "", True),
    ("shuffled-chain-order",   ["root.crt", "leaf.key", "int.crt", "leaf.crt"], "", "", "", "", False),
    # Signature-algorithm variants (0.3.2): R1 parses them, R2 verifies their chains.
    ("rsa-sha384-leaf",        ["leaf-sha384.crt", "leaf.key", "bundle.crt"], "", "", "", "", False),
    ("rsa-sha512-leaf",        ["leaf-sha512.crt", "leaf.key", "bundle.crt"], "", "", "", "", False),
    ("ec-p256-sha384",         ["ec-sha384.crt", "ec.key", "ec-root.crt"], "", "", "", "", False),
    ("rsa-pss-chain",          ["leaf-pss.crt", "leaf.key", "pss-int.crt", "pss-root.crt"], "", "", "", "", False),
    # 0.3.3
    ("pfx-pbmac1",             ["pbmac1.pfx"], "pm", "", "", "", False),
    ("ed448-chain",            ["leaf-ed448.crt", "leaf.key", "ed448-root.crt"], "", "", "", "", False),
    # 0.3.4: AIA chain completion (R3)
    ("aia-ldap-then-http",     ["leaf-aia-ldap-first.crt", "leaf.key"], "", "", "", "", True),
    ("aia-ldap-only",          ["leaf-aia-ldap-only.crt", "leaf.key"], "", "", "", "", True),
    ("aia-pem-response",       ["leaf-aia-pem.crt", "leaf.key"], "", "", "", "", True),
    ("aia-first-url-fails",    ["leaf-aia-fallback.crt", "leaf.key"], "", "", "", "", True),
]

# Cases where the Rust port offers "Fetch missing chain" for any CA Issuers URL, not only http(s):
# the fetch then explains what to do with an ldap: URL instead of the button never appearing.
ANY_AIA_CASES = {"aia-ldap-only"}

# Cases signed with an algorithm the Rust port can't verify (Ed448: no mature pure-Rust implementation).
UNVERIFIABLE_CASES = {"ed448-chain"}

# Cases where the Rust port deliberately verifies more than the reference does. The override is
# computed, not typed: the same reference analyze() runs with signed_by() also accepting the listed
# signature schemes, and every expect field that changes becomes the override.
PSS_CASES = {"rsa-pss-chain"}


def signed_by_with_pss(child, parent, _plain=C.signed_by):
    """Reference signed_by(), plus RSASSA-PSS (the reference only tries PKCS#1 v1.5 for RSA)."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import SignatureAlgorithmOID
    if child.signature_algorithm_oid != SignatureAlgorithmOID.RSASSA_PSS:
        return _plain(child, parent)
    pub = parent.public_key()
    if not isinstance(pub, rsa.RSAPublicKey):
        return False
    try:
        pub.verify(child.signature, child.tbs_certificate_bytes, child.signature_algorithm_parameters,
                   child.signature_hash_algorithm)
        return True
    except Exception:
        return False


def all_ca_issuers(cert):
    """Every caIssuers URI, any scheme (the reference's aia_urls() keeps only http/https)."""
    from cryptography import x509
    try:
        ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
    except x509.ExtensionNotFound:
        return []
    return [d.access_location.value for d in ext if d.access_method == x509.oid.AuthorityInformationAccessOID.CA_ISSUERS
            and isinstance(d.access_location, x509.UniformResourceIdentifier)]


def expect_for(files, pfx, keypw, fqdn, aurl, fetch, any_aia=False):
    b = C.parse_files([(f, (CORPUS / f).read_bytes()) for f in files], pfx, keypw)
    log = C.complete_chain(b) if fetch else []
    if not any_aia:
        return _expect(b, log, fqdn, aurl)
    # Only analyze()/to_json() see every URL; the fetch above ran as the reference does.
    orig = F.aia_urls
    F.aia_urls = all_ca_issuers
    try:
        return _expect(b, log, fqdn, aurl)
    finally:
        F.aia_urls = orig


def _expect(b, log, fqdn, aurl):
    an = C.analyze(b, fqdn, aurl)
    return {
        # For information: what the reference's complete_chain() logged (the port logs more; see aia.rs tests).
        "reference_fetch_log": log,
        "ok": an.ok,
        "fqdn": an.fqdn,
        "leaf_sha256": an.leaf.fp256 if an.leaf else None,
        "intermediates_sha256": [i.fp256 for i in an.intermediates],
        "root_sha256": an.root.fp256 if an.root else None,
        "key_present": an.key is not None,
        "has_error": any(c["level"] == "error" for c in an.checks),
        "has_warn": any(c["level"] == "warn" for c in an.checks),
        "appliance_url_warn": any(c["level"] == "warn" and "Appliance URL" in c["text"] for c in an.checks),
        "inputs": [{"name": r.name, "kind": kind(r.format), "certs": r.certs, "keys": r.keys,
                    "level": r.level, "reference_format": r.format, "reference_notes": r.notes} for r in an.reports],
        "ca_aliases": [C.alias_for(c) for c in an.ca_certs()] if an.leaf else [],
        "reference_checks": an.checks,
        # The UI contract (Analysis.to_json), minus "inputs" (compared above, notes aside) — at GENERATED_AT.
        "to_json": {k: v for k, v in an.to_json().items() if k != "inputs"},
    }


def extras_override(exp):
    """Divergence 1 (docs/PARITY.md): a problem from an input that is explained but not used (a PVK)
    is a warning, not an error, when the leaf and its key are there. Computed from the reference's checks."""
    unusable = {i["name"] for i in exp["inputs"] if i["kind"] == "pvk"}
    checks = [dict(c, level="warn") if c["level"] == "error" and c["text"].split(":")[0] in unusable else c
              for c in exp["reference_checks"]]
    ok = exp["leaf_sha256"] is not None and exp["key_present"] and not any(c["level"] == "error" for c in checks)
    new = dict(exp, reference_checks=checks, ok=ok,
               has_error=any(c["level"] == "error" for c in checks), has_warn=any(c["level"] == "warn" for c in checks),
               to_json=dict(exp["to_json"], ok=ok, checks=checks))
    diff = {k: v for k, v in new.items() if v != exp[k]}
    assert diff, "extras_override changed nothing"
    return diff


def signed_by_without_ed448(child, parent, _plain=C.signed_by):
    """Reference signed_by(), except an Ed448 signature can't be verified (what the Rust port does)."""
    from cryptography.x509.oid import SignatureAlgorithmOID
    if child.signature_algorithm_oid == SignatureAlgorithmOID.ED448:
        return False
    return _plain(child, parent)


def unverifiable_override(case):
    """Divergences 7 and 13: run the reference with Ed448 unverifiable, then put in the Rust port's
    wording: instead of "an issuer that wasn't supplied" it says the issuer *was* supplied but its
    signature algorithm can't be checked, and it drops "No intermediate certificates supplied"."""
    name, files, pfx, keypw, fqdn, aurl, fetch = case
    plain = expect_for(files, pfx, keypw, fqdn, aurl, fetch)
    orig = C.signed_by
    C.signed_by = signed_by_without_ed448
    try:
        new = expect_for(files, pfx, keypw, fqdn, aurl, fetch)
        b = C.parse_files([(f, (CORPUS / f).read_bytes()) for f in files], pfx, keypw)
        an = C.analyze(b, fqdn, aurl)
        cn = an.leaf.cn
    finally:
        C.signed_by = orig
    checks = []
    for c in new["reference_checks"]:
        if c["text"].startswith("The chain stops at an issuer that wasn't supplied"):
            c = {"level": "warn", "text": f'The issuer of "{cn}" was supplied, but "{cn}" is signed with Ed448, which this app '
                                          "can't verify — so the chain stops there. Check the chain with another tool, "
                                          "or ask the CA for an RSA or ECDSA chain."}
        elif c["text"].startswith("No intermediate certificates supplied"):
            continue
        checks.append(c)
    new = dict(new, reference_checks=checks, to_json=dict(new["to_json"], checks=checks),
               has_warn=any(c["level"] == "warn" for c in checks), has_error=any(c["level"] == "error" for c in checks))
    diff = {k: v for k, v in new.items() if v != plain[k]}
    assert diff, f"{name}: no difference"
    diff["why"] = ("The Rust port can't verify Ed448 signatures (no mature pure-Rust Ed448). Where the reference links the "
                   "chain, the port stops at the Ed448-signed certificate and says so. Computed by make-cases.py: the "
                   "reference's analyze() with Ed448 unverifiable, plus the port's wording for that one warning.")
    return diff


def any_aia_override(case):
    """Divergence 15: can_fetch_chain and the "— or use Fetch missing chain." hint count every CA Issuers
    URL, not only http(s). Computed: the reference's analyze() with aia_urls() returning all of them."""
    name, files, pfx, keypw, fqdn, aurl, fetch = case
    plain = expect_for(files, pfx, keypw, fqdn, aurl, fetch)
    new = expect_for(files, pfx, keypw, fqdn, aurl, fetch, any_aia=True)
    diff = {k: v for k, v in new.items() if v != plain[k]}
    assert diff, f"{name}: no difference"
    diff["why"] = ("The port offers Fetch missing chain whenever the top certificate has any CA Issuers URL; for an "
                   "ldap: URL the fetch then says to export the chain from the Windows CA. The reference only "
                   "counted http(s) URLs, so the button never appeared. Computed by make-cases.py with the reference's "
                   "analyze() seeing every CA Issuers URL.")
    return diff


def pss_override(case):
    name, files, pfx, keypw, fqdn, aurl, fetch = case
    plain = expect_for(files, pfx, keypw, fqdn, aurl, fetch)
    orig = C.signed_by
    C.signed_by = signed_by_with_pss
    try:
        pss = expect_for(files, pfx, keypw, fqdn, aurl, fetch)
    finally:
        C.signed_by = orig
    diff = {k: v for k, v in pss.items() if v != plain[k]}
    assert diff, f"{name}: the reference already verifies this chain; drop it from PSS_CASES"
    diff["why"] = ("The Rust port verifies RSASSA-PSS signatures; the reference's signed_by() only tries "
                   "PKCS#1 v1.5 for RSA, so it can't link a PSS-signed chain. Values computed by make-cases.py "
                   "with the reference's analyze() and a PSS-aware signed_by().")
    return diff


WILDCARD_CASES = {"wildcard-leaf", "wildcard-fqdn-typed"}
WILDCARD_ERROR = "Wildcard certificate: enter the appliance's FQDN."


def wildcard_override(exp):
    """Divergence 27 (docs/PARITY.md, 0.3.17): a name containing '*' is never used as the FQDN (verify,
    SNI, file names, INSTALL.txt). Without a name from the appliance to suggest, the FQDN stays empty
    and an error asks for it, where the reference used the wildcard and said "Covers *.wild.test."."""
    checks = [{"level": "error", "text": WILDCARD_ERROR} if c["text"].startswith("Covers *") else c for c in exp["reference_checks"]]
    assert checks != exp["reference_checks"], "wildcard_override changed nothing"
    new = dict(exp, reference_checks=checks, ok=False, fqdn="", has_error=True,
               to_json=dict(exp["to_json"], ok=False, fqdn="", file_base="", checks=checks))
    diff = {k: v for k, v in new.items() if v != exp[k]}
    diff["why"] = ("A wildcard is never the FQDN: the Rust port leaves it empty and asks for the appliance's name "
                   "(or suggests the appliance's own hostname when connected); the reference used the wildcard.")
    return diff


def kind(fmt: str) -> str:
    f = fmt.lower()
    if f.startswith("base64 without pem headers"): return "base64"
    if f.startswith("pem"): return "pem"
    if f.startswith("der certificate"): return "der-cert"
    if f.startswith("pkcs#7 bundle, der"): return "pkcs7-der"
    if "pfx" in f: return "pfx-locked" if "locked" in f else "pfx"
    if f.startswith("java keystore"): return "jks"
    if "der private key" in f: return "der-key-locked" if "locked" in f else "der-key"
    if "pvk" in f: return "pvk"
    return "unknown"


def serve():
    h = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(CORPUS))
    http.server.SimpleHTTPRequestHandler.log_message = lambda *a: None
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 18080), h)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def main():
    srv = serve()
    out = []
    for name, files, pfx, keypw, fqdn, aurl, fetch in CASES:
        out.append({
            "name": name, "files": files, "pfx_password": pfx, "key_password": keypw,
            "fqdn": fqdn, "appliance_url": aurl, "fetch_chain": fetch,
            "expect": expect_for(files, pfx, keypw, fqdn, aurl, fetch),
        })
    srv.shutdown()
    # Deliberate divergences: the Rust port fixes these reference quirks.
    overrides = {}
    for c in out:
        if c["name"] == "csr-and-pvk-explained":
            overrides[c["name"]] = dict(extras_override(c["expect"]),
                why="An unusable extra file (PVK, CSR) should be a warning when the rest of the set is complete; "
                    "the Python reference marks the whole set as failed.")
    for case in CASES:
        if case[0] in PSS_CASES:
            overrides[case[0]] = pss_override(case)
        if case[0] in UNVERIFIABLE_CASES:
            overrides[case[0]] = unverifiable_override(case)
        if case[0] in ANY_AIA_CASES:
            overrides[case[0]] = any_aia_override(case)
    for c in out:
        if c["name"] in WILDCARD_CASES:
            overrides[c["name"]] = wildcard_override(c["expect"])
    for c in out:
        if c["name"] in overrides:
            c["rust_expect_override"] = overrides[c["name"]]
    write_lf(ROOT / "fixtures" / "cases.json", json.dumps({"generated_by": "reference/python 0.2.1", "generated_at": GENERATED_AT.isoformat(),
                "generated_at_unix": int(GENERATED_AT.timestamp()), "cases": out}, indent=2))

    # ---- byte-exact goldens for the pure-text parts
    GOLD.mkdir(exist_ok=True)
    rb_cases = {
        "rb-fresh": "appliance_url 'https://198.51.100.20'\nelasticsearch['es_hosts'] = {'127.0.0.1' => 9200}\n",
        "rb-existing-lines": "appliance_url 'https://x'\nnginx['ssl_certificate'] = '/etc/morpheus/ssl/old.crt'\n  nginx[\"ssl_server_key\"] = \"/etc/morpheus/ssl/old.key\"\n\n\n",
        "rb-own-block": None,  # filled from rb-fresh output below (re-run must replace, not append)
        "rb-legacy-sphragis-block": "appliance_url 'https://x'\n\n# >>> sphragis managed block (do not edit by hand) >>>\nnginx['ssl_certificate'] = '/old.crt'\nnginx['ssl_server_key'] = '/old.key'\n# <<< sphragis managed block <<<\n",
    }
    first = C.transform_morpheus_rb(rb_cases["rb-fresh"], "/etc/morpheus/ssl/a_test.crt", "/etc/morpheus/ssl/a_test.key", "20260101-000000")
    rb_cases["rb-own-block"] = first
    for k, src in rb_cases.items():
        write_lf(GOLD / f"{k}.in.rb", src)
        write_lf(GOLD / f"{k}.out.rb", C.transform_morpheus_rb(src, "/etc/morpheus/ssl/m_cust_test.crt", "/etc/morpheus/ssl/m_cust_test.key", "20261105-120000"))

    plans = {
        "runner-apply-server": ({"server": True, "trust": False, "restart_ui": False, "storepass": "changeit", "aliases": []}, "apply", None),
        "runner-apply-server-trust": ({"server": True, "trust": True, "restart_ui": True, "storepass": "changeit",
                                       "aliases": ["mci-cust-root-0a1b2c3d", "mci-cust-issuing-4e5f6a7b"]}, "apply", None),
        "runner-apply-trust-only": ({"server": False, "trust": True, "restart_ui": True, "storepass": "changeit",
                                     "aliases": ["mci-cust-root-0a1b2c3d"]}, "apply", None),
        "runner-rollback": ({"server": True, "restart_ui": True, "storepass": "changeit"}, "rollback", ["mci-cust-root-0a1b2c3d"]),
    }
    for k, (plan, mode, dele) in plans.items():
        write_lf(GOLD / f"{k}.sh", E.runner_script("20261105-120000", "mcitest", plan, mode, dele).replace(
            "morpheus-certificate-install 0.2.1", "morpheus-certificate-install {VERSION}").replace(
            "Morpheus Certificate Install 0.2.1", "Morpheus Certificate Install {VERSION}"))

    # INSTALL.txt: first line normalised to a fixed clock and a version placeholder
    b = C.parse_files([(f, (CORPUS / f).read_bytes()) for f in ["chain.p7b", "leaf-pkcs1.key"]])
    an = C.analyze(b, "m.cust.test")
    files = X.build_files(an)
    # Rebuilt from scratch: aliases carry fingerprints, so a stale trusted_certs/*.pem would linger.
    import shutil
    shutil.rmtree(GOLD / "export-p7b-pkcs1", ignore_errors=True)
    for fname, data in files.items():
        p = GOLD / "export-p7b-pkcs1" / fname
        p.parent.mkdir(parents=True, exist_ok=True)
        if fname == "INSTALL.txt":
            lines = data.decode().split("\n")
            lines[0] = "Converted by Morpheus Certificate Install {VERSION} on 2026-11-05 12:00"
            data = "\n".join(lines).encode()
        p.write_bytes(data)
    # Data behind INSTALL.txt, so the Rust install_text() can be tested before X.509 parsing exists.
    write_lf(GOLD / "export-p7b-pkcs1.info.json", json.dumps({
        "fqdn": an.fqdn, "file_base": C.safe_name(an.fqdn), "leaf_cn": an.leaf.cn,
        "sans": an.leaf.sans()[0] + an.leaf.sans()[1], "not_after": f"{an.leaf.not_after():%Y-%m-%d}",
        "leaf_sha256": an.leaf.fp256, "intermediates": len(an.intermediates), "root_cn": an.root.cn if an.root else None,
        "key_desc": C.key_desc(an.key.public_key()),
        "inputs": [{"name": r.name, "format": r.format} for r in an.reports],
        "ca_aliases": [C.alias_for(c) for c in an.ca_certs()], "include_root": False,
        "now": "2026-11-05 12:00"}, indent=2))

    # The exact command sequence the engine sends to the appliance, via a recording fake transport.
    command_goldens(an)
    transport_goldens()
    print(f"cases.json: {len(out)} cases; goldens in {GOLD}")


def transport_goldens():
    """Shell strings built inside the transports and list/rollback helpers."""
    from morpheus_certificate_install import transport as T
    rec = []

    class FakeSsh(T.SshTransport):
        def __init__(self):
            self.sudo_mode, self.sudo_password, self.login_user = "nopasswd", "", "mcitest"
        def _raw(self, cmd, stdin, timeout, on_chunk=None, stop=None):
            rec.append(cmd); return 0, "@@RC=0"

    class FakeCharon(T.CharonTransport):
        def __init__(self):
            self.sudo_mode, self.stage_dir, self.session, self.login_user = "charon", "/home/mcitest/.morpheus-certificate-install-stage", "s1", "mcitest"
        def tool(self, name, args, timeout=700):
            rec.append(f"[{name}] " + (args.get("command") or f"{args.get('local')} -> {args.get('remote')}"))
            if name == "run_command":
                return {"output": "SIZE=0\nRC=0\n", "exit_code": 0}
            return {"ok": True}

    out = {}
    s = FakeSsh()
    rec.clear(); s.put_root("/etc/morpheus/ssl/m_cust_test.key", b"x", "0600"); out["ssh_put_root"] = list(rec)
    rec.clear(); s.put_root("/etc/morpheus/ssl/trusted_certs/a.pem", b"x", "0644", dir_mode="0755"); out["ssh_put_root_trust"] = list(rec)
    rec.clear(); s.stream_file("/var/log/morpheus-certificate-install/R.log", "/var/log/morpheus-certificate-install/R.rc", lambda t: None, threading.Event()); out["ssh_stream_file"] = list(rec)
    rec.clear(); s.run("id -un", sudo=True); out["ssh_sudo_wrap_nopasswd"] = list(rec)
    s.sudo_mode, s.sudo_password = "password", "PW"
    rec.clear(); s.run("id -un", sudo=True); out["ssh_sudo_wrap_password"] = list(rec)
    rec.clear(); E.list_runs(s); out["list_runs"] = list(rec)
    rec.clear(); E.list_backups(s); out["list_backups"] = list(rec)
    c = FakeCharon()
    rec.clear(); c.run("id -un", sudo=True); out["charon_sudo_wrap"] = list(rec)
    rec.clear(); c.stream_file("/var/log/morpheus-certificate-install/R.log", "/var/log/morpheus-certificate-install/R.rc", lambda t: None, threading.Event()); out["charon_poll_first"] = list(rec)
    write_lf(GOLD / "transport-commands.json", json.dumps(
        {"note": "Exact strings the Python transports send. ssh_* entries are the full exec line (after sudo wrapping); "
                 "charon_* entries are prefixed with the MCP tool name. Charon put_root uses a timestamped stage name, so it is described in docs/PARITY.md instead.",
         "commands": out}, indent=2))


def command_goldens(an):
    from morpheus_certificate_install.transport import Transport
    import hashlib

    class Rec(Transport):
        kind, label, login_user = "fake", "fake@appliance", "mcitest"
        def __init__(self): self.log = []
        def info(self): return {"kind": "fake", "label": self.label, "user": self.login_user, "sudo_mode": "password"}
        def run(self, cmd, sudo=False, stdin=None, timeout=120):
            self.log.append({"op": "run", "sudo": sudo, "cmd": cmd})
            if cmd.startswith("cat /etc/morpheus/morpheus.rb"): return 0, "appliance_url 'https://198.51.100.20'\n"
            if cmd.startswith("stat -c %a"): return 0, "600\n"
            if "openssl s_client" in cmd: return 0, ""
            return 0, "SYSTEMDRUN=yes\nMCTL=/usr/bin/morpheus-ctl\nRB=yes\nOPENSSL=OpenSSL 3.0.13\n"
        def put_root(self, path, data, mode="0600", dir_mode="0700"):
            self.log.append({"op": "put_root", "path": path, "mode": mode, "dir_mode": dir_mode,
                             "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest() if not path.endswith((".key", ".sh", ".json", ".rb")) else None})
        def stream_file(self, path, rc_path, on_text, stop):
            self.log.append({"op": "stream_file", "path": path, "rc_path": rc_path}); return 0

    t = Rec()
    facts = E.preflight(t, lambda e: None)
    plan = E.build_plan(an, facts, {"server": True, "trust": True, "restart_ui": True})
    plan["stamp"] = "20261105-120000"
    stop = threading.Event()
    E.apply(t, an, facts, plan, lambda e: None, stop)
    for entry in t.log:  # stamp-independent
        for k in ("cmd", "path"):
            if k in entry and entry[k]:
                entry[k] = entry[k].replace(plan["stamp"], "{STAMP}")
    # Divergence 19 (docs/PARITY.md, 0.3.16): the Rust apply reads morpheus.rb and runs the
    # appliance_url guard before it writes anything, so its `cat morpheus.rb` comes just before the
    # backup instead of after the key; the later re-read is dropped. Nothing else moves.
    rb_reads = [i for i, e in enumerate(t.log) if e.get("cmd") == "cat /etc/morpheus/morpheus.rb"]
    backup_at = next(i for i, e in enumerate(t.log) if e.get("cmd", "").startswith("set -e; umask 077; mkdir -p "))
    # Divergence 29 (0.3.19): after the key/cert match, the Rust apply records the installed .crt
    # and .key in the ledger: one read of it and one write.
    override = {"move": {"op": "run", "sudo": True, "cmd": "cat /etc/morpheus/morpheus.rb"},
                "from_index": rb_reads[-1], "to_index": backup_at,
                "insert_after_cmd_prefix": "a=$(openssl x509 -noout -pubkey",
                "insert": [{"op": "run", "sudo": True, "cmd": "[ -f /var/lib/morpheus-certificate-install/installed.json ] && "
                                                             "cat /var/lib/morpheus-certificate-install/installed.json; true"},
                           {"op": "put_root", "path": "/var/lib/morpheus-certificate-install/installed.json", "mode": "0600",
                            "dir_mode": "0700", "bytes": None, "sha256": None}],
                "why": "PARITY divergence 19: apply reads morpheus.rb and runs the appliance_url guard before writing anything; "
                       "divergence 29: after the key match it records the installed files in the ledger (read + write)"}
    write_lf(GOLD / "apply-command-sequence.json", json.dumps(
        {"note": "Recorded from reference/python apply() with server+trust+restart_ui on chain.p7b + leaf-pkcs1.key "
                 "(fqdn m.cust.test). put_root data is summarised; secrets and stamped files carry no hash.",
         "sequence": t.log, "rust_expect_override": override}, indent=2))


if __name__ == "__main__":
    main()
