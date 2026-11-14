"""Certificate handling for Morpheus Certificate Install 0.2.1.

Everything here is local and pure: parse whatever the user dropped in (PEM, DER,
PFX/P12, bundles, encrypted keys), find the leaf that matches the private key,
order the chain, run the checks Morpheus' docs and nginx care about, and produce
the exact bytes that will be written to the appliance.
"""
from __future__ import annotations

import datetime as _dt
import difflib
import fnmatch
import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, padding, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

PEM_BLOCK = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----\r?\n.*?-----END \1-----", re.S)

MANAGED_BEGIN = "# >>> morpheus-certificate-install managed block (do not edit by hand) >>>"
MANAGED_END = "# <<< morpheus-certificate-install managed block <<<"
NGINX_KEYS = ("ssl_certificate", "ssl_server_key")
# Blocks written by 0.2.0 and earlier, when the tool was called Sphragis — replaced on the next install.
LEGACY_BEGIN = ("# >>> sphragis managed block (do not edit by hand) >>>",)
LEGACY_END = ("# <<< sphragis managed block <<<",)


class CertError(Exception):
    pass


@dataclass
class CertInfo:
    cert: x509.Certificate
    source: str

    @property
    def fp256(self) -> str:
        return self.cert.fingerprint(hashes.SHA256()).hex(":").upper()

    @property
    def subject(self) -> str:
        return self.cert.subject.rfc4514_string()

    @property
    def issuer(self) -> str:
        return self.cert.issuer.rfc4514_string()

    @property
    def cn(self) -> str:
        attrs = self.cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return attrs[0].value if attrs else self.subject

    @property
    def is_ca(self) -> bool:
        try:
            return bool(self.cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca)
        except x509.ExtensionNotFound:
            return False

    @property
    def self_signed(self) -> bool:
        return self.cert.subject == self.cert.issuer and signed_by(self.cert, self.cert)

    def sans(self) -> Tuple[List[str], List[str]]:
        try:
            ext = self.cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        except x509.ExtensionNotFound:
            return [], []
        return ext.get_values_for_type(x509.DNSName), [str(i) for i in ext.get_values_for_type(x509.IPAddress)]

    def not_before(self) -> _dt.datetime:
        return _utc(getattr(self.cert, "not_valid_before_utc", None) or self.cert.not_valid_before)

    def not_after(self) -> _dt.datetime:
        return _utc(getattr(self.cert, "not_valid_after_utc", None) or self.cert.not_valid_after)

    def pem(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.PEM)

    def summary(self, role: str) -> dict:
        dns, ips = self.sans()
        now = _dt.datetime.now(_dt.timezone.utc)
        return {
            "role": role,
            "cn": self.cn,
            "subject": self.subject,
            "issuer": self.issuer,
            "san_dns": dns,
            "san_ip": ips,
            "not_before": self.not_before().isoformat(),
            "not_after": self.not_after().isoformat(),
            "days_left": (self.not_after() - now).days,
            "lifetime_days": max(1, (self.not_after() - self.not_before()).days),
            "used_days": (now - self.not_before()).days,
            "is_ca": self.is_ca,
            "self_signed": self.self_signed,
            "sha256": self.fp256,
            "sig_alg": getattr(self.cert.signature_hash_algorithm, "name", "?"),
            "key": key_desc(self.cert.public_key()),
            "source": self.source,
        }


def _utc(d: _dt.datetime) -> _dt.datetime:
    return d if d.tzinfo else d.replace(tzinfo=_dt.timezone.utc)


def key_desc(pub) -> str:
    if isinstance(pub, rsa.RSAPublicKey):
        return f"RSA {pub.key_size}"
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return f"EC {pub.curve.name}"
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(pub, ed448.Ed448PublicKey):
        return "Ed448"
    return type(pub).__name__


def signed_by(child: x509.Certificate, parent: x509.Certificate) -> bool:
    """True if `parent`'s key verifies `child`'s signature."""
    pub = parent.public_key()
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            pub.verify(child.signature, child.tbs_certificate_bytes, padding.PKCS1v15(), child.signature_hash_algorithm)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(child.signature_hash_algorithm))
        elif isinstance(pub, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            pub.verify(child.signature, child.tbs_certificate_bytes)
        else:
            return False
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def pub_der(pub) -> bytes:
    return pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def safe_name(fqdn: str) -> str:
    """morpheus.example.com -> morpheus_example_com (matches the docs' your_fqdn_name)."""
    s = re.sub(r"[^A-Za-z0-9]+", "_", fqdn.strip().lower()).strip("_")
    return s or "morpheus"


def alias_for(info: CertInfo) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", info.cn.lower()).strip("-")[:40] or "ca"
    return f"mci-{base}-{info.cert.fingerprint(hashes.SHA256()).hex()[:8]}"


def host_matches(host: str, dns: List[str], ips: List[str]) -> bool:
    host = host.strip().lower().rstrip(".")
    try:
        ip = ipaddress.ip_address(host)
        return any(ipaddress.ip_address(i) == ip for i in ips)
    except ValueError:
        pass
    for name in dns:
        name = name.lower().rstrip(".")
        if name == host:
            return True
        # RFC 6125: wildcard only as the whole left-most label, one level deep.
        if name.startswith("*.") and host.count(".") == name.count(".") and fnmatch.fnmatchcase(host, name):
            return True
    return False


@dataclass
class Bundle:
    certs: List[CertInfo] = field(default_factory=list)
    key: object = None
    key_source: str = ""
    key_was_encrypted: bool = False
    problems: List[str] = field(default_factory=list)
    reports: list = field(default_factory=list)  # formats.FileReport per input file


def parse_files(files: List[Tuple[str, bytes]], pfx_password: str = "", key_password: str = "",
                extra_passwords: Optional[List[str]] = None) -> Bundle:
    """Read every input (any format formats.py knows) into one Bundle. Every
    password given is tried on every locked item: customers mix them up."""
    from . import formats as F
    pws = [p for p in [pfx_password, key_password] + list(extra_passwords or []) if p]
    parsed = F.parse_all(files, pws)
    b = Bundle(reports=parsed.reports)
    seen = set()
    for c, src in parsed.certs:
        fp = c.fingerprint(hashes.SHA256())
        if fp not in seen:
            seen.add(fp)
            b.certs.append(CertInfo(c, src))
    for k, src, enc in parsed.keys:
        if b.key is None:
            b.key, b.key_source, b.key_was_encrypted = k, src, enc
        elif pub_der(b.key.public_key()) != pub_der(k.public_key()):
            b.problems.append(f"More than one private key supplied; using the one from {b.key_source}, ignoring {src}.")
    for r in parsed.reports:
        for n in r.notes:
            if r.level == "error":
                b.problems.append(f"{r.name}: {n}")
    return b


def complete_chain(b: Bundle, getter=None, max_hops: int = 4) -> List[str]:
    """Follow AIA 'CA Issuers' URLs from the top of the chain to fetch missing
    intermediates (and the root, if the CA publishes it). Returns a log."""
    from . import formats as F
    log: List[str] = []
    for _ in range(max_hops):
        an = analyze(b)
        if an.leaf is None:
            log.append("No server certificate to start from.")
            break
        top = (an.intermediates[-1] if an.intermediates else an.leaf)
        if an.root is not None or top.self_signed:
            log.append("Chain is complete.")
            break
        urls = F.aia_urls(top.cert)
        if not urls:
            log.append(f'"{top.cn}" has no CA Issuers URL to follow; ask the CA for its intermediate/root bundle.')
            break
        got = False
        for u in urls:
            try:
                certs = F.fetch_issuer(u, getter)
            except Exception as e:
                log.append(f"{u}: {e}")
                continue
            have = {c.cert.fingerprint(hashes.SHA256()) for c in b.certs}
            for c in certs:
                if c.fingerprint(hashes.SHA256()) not in have:
                    b.certs.append(CertInfo(c, f"fetched from {u}"))
                    log.append(f'Fetched "{CertInfo(c, u).cn}" from {u}')
                    got = True
            if got:
                break
        if not got:
            log.append("Nothing new could be fetched.")
            break
    return log


@dataclass
class Analysis:
    leaf: Optional[CertInfo]
    intermediates: List[CertInfo]
    root: Optional[CertInfo]
    extra: List[CertInfo]
    key: object
    checks: List[dict]
    fqdn: str
    reports: list = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.leaf is not None and self.key is not None and not any(c["level"] == "error" for c in self.checks)

    def fullchain_pem(self, include_root: bool = False) -> bytes:
        parts = [self.leaf.pem()] + [i.pem() for i in self.intermediates]
        if include_root and self.root:
            parts.append(self.root.pem())
        return b"".join(parts)

    def key_pem(self) -> bytes:
        return self.key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )

    def ca_certs(self) -> List[CertInfo]:
        """What goes into the Java truststore: root first, then intermediates."""
        return ([self.root] if self.root else []) + list(self.intermediates)

    def ca_bundle_pem(self) -> bytes:
        return b"".join(c.pem() for c in self.ca_certs())

    def to_json(self) -> dict:
        chain = []
        if self.leaf:
            chain.append(self.leaf.summary("server"))
        chain += [i.summary("intermediate") for i in self.intermediates]
        if self.root:
            chain.append(self.root.summary("root"))
        return {
            "ok": self.ok,
            "fqdn": self.fqdn,
            "file_base": safe_name(self.fqdn) if self.fqdn else "",
            "chain": chain,
            "unused": [c.summary("unused") for c in self.extra],
            "checks": self.checks,
            "key": key_desc(self.key.public_key()) if self.key else None,
            "ca_aliases": [alias_for(c) for c in self.ca_certs()],
            "inputs": [r.to_json() for r in self.reports],
            "can_fetch_chain": bool(self.leaf) and self.root is None and not (self.leaf.self_signed) and bool(_aia(self.intermediates[-1] if self.intermediates else self.leaf)),
        }


def _aia(c: CertInfo) -> List[str]:
    from . import formats as F
    return F.aia_urls(c.cert)


def analyze(b: Bundle, fqdn: str = "", appliance_url: str = "") -> Analysis:
    checks: List[dict] = []

    def chk(level, text):
        checks.append({"level": level, "text": text})

    for p in b.problems:
        chk("error" if ("encrypted" in p or "password" in p or "passphrase" in p or "not recognised" in p
                        or "Not a certificate" in p or "keystore" in p or "PVK" in p or "unreadable" in p) else "warn", p)

    if not b.certs:
        chk("error", "No certificates found. Add the server certificate (and the CA bundle if it came separately).")
        return Analysis(None, [], None, [], b.key, checks, fqdn, b.reports)

    # Leaf: the cert whose public key matches the private key; otherwise the
    # non-CA cert that nothing else was issued by.
    leaf = None
    if b.key is not None:
        kp = pub_der(b.key.public_key())
        for c in b.certs:
            if pub_der(c.cert.public_key()) == kp:
                leaf = c
                break
        if leaf is None:
            chk("error", "The private key does not match any of the certificates supplied. nginx will refuse to start with a mismatched pair.")
    else:
        chk("error", "No private key found. Add the .key file (or a PFX that contains it).")
    if leaf is None:
        non_ca = [c for c in b.certs if not c.is_ca]
        leaf = non_ca[0] if non_ca else None
    if leaf is None:
        chk("error", "Every certificate supplied is a CA certificate — the server certificate is missing.")
        return Analysis(None, [], None, list(b.certs), b.key, checks, fqdn, b.reports)

    # Walk issuers using subject match + signature verification.
    pool = [c for c in b.certs if c is not leaf]
    chain: List[CertInfo] = []
    cur = leaf
    root = None
    for _ in range(10):
        if cur.self_signed:
            break
        parent = next((p for p in pool if p.cert.subject == cur.cert.issuer and signed_by(cur.cert, p.cert)), None)
        if parent is None:
            break
        pool.remove(parent)
        if parent.self_signed:
            root = parent
            break
        chain.append(parent)
        cur = parent
    extra = pool

    if leaf.self_signed:
        chk("warn", "The server certificate is self-signed — browsers won't trust it without importing it.")
    elif root is None:
        last = chain[-1] if chain else leaf
        chk("warn", f"The chain stops at an issuer that wasn't supplied: {last.issuer}. "
                    "Fine for a public CA (browsers already have the root); for a private CA, add the root so it can be trusted and verified"
                    + (" — or use Fetch missing chain." if _aia(last) else "."))
    else:
        chk("ok", f"Chain complete: server → {len(chain)} intermediate(s) → root \"{root.cn}\".")
    if not chain and root is None and not leaf.self_signed:
        chk("warn", "No intermediate certificates supplied. If your CA uses an intermediate, nginx must serve it or clients will fail to verify.")
    if extra:
        chk("warn", f"{len(extra)} certificate(s) supplied that aren't part of this chain; they'll be ignored.")
    if b.key is not None and leaf is not None and pub_der(b.key.public_key()) == pub_der(leaf.cert.public_key()):
        chk("ok", "Private key matches the server certificate.")
        if b.key_was_encrypted:
            chk("ok", "Key was encrypted; a decrypted copy will be written (Morpheus requires it), root-only readable.")

    now = _dt.datetime.now(_dt.timezone.utc)
    for c, role in [(leaf, "Server certificate")] + [(i, "Intermediate") for i in chain] + ([(root, "Root")] if root else []):
        if c.not_before() > now:
            chk("error", f"{role} \"{c.cn}\" isn't valid until {c.not_before():%Y-%m-%d}.")
        elif c.not_after() < now:
            chk("error", f"{role} \"{c.cn}\" expired on {c.not_after():%Y-%m-%d}.")
        elif (c.not_after() - now).days < 30:
            chk("warn", f"{role} \"{c.cn}\" expires in {(c.not_after() - now).days} days.")
        if c.cert.signature_hash_algorithm is not None and c.cert.signature_hash_algorithm.name in ("sha1", "md5") and c is not root:
            chk("warn", f"{role} \"{c.cn}\" is signed with {c.cert.signature_hash_algorithm.name.upper()}; modern clients reject it.")
    pub = leaf.cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey) and pub.key_size < 2048:
        chk("error", f"RSA {pub.key_size} key is too small; use 2048 or larger.")

    dns, ips = leaf.sans()
    if not dns and not ips:
        chk("warn", "The certificate has no Subject Alternative Names. Browsers ignore the CN; they'll reject it.")
    if not fqdn:
        fqdn = (dns[0].lstrip("*.") if dns and not dns[0].startswith("*.") else "") or leaf.cn
    if fqdn:
        if host_matches(fqdn, dns, ips):
            chk("ok", f"Covers {fqdn}.")
        else:
            chk("error", f"The certificate does not cover {fqdn}. SANs: {', '.join(dns + ips) or 'none'}.")
    if appliance_url:
        host = urlparse(appliance_url if "://" in appliance_url else "https://" + appliance_url).hostname or ""
        if host and not host_matches(host, dns, ips):
            chk("warn", f"Morpheus' Appliance URL uses {host}, which this certificate doesn't cover. "
                        "Hosts, agents and browsers that use that URL will see a name mismatch. "
                        "Either add it as a SAN or change the Appliance URL to the FQDN (agents follow that setting — plan it).")
        elif host:
            chk("ok", f"Appliance URL host {host} is covered.")

    return Analysis(leaf, chain, root, extra, b.key, checks, fqdn, b.reports)


# ---------------------------------------------------------------- morpheus.rb

def transform_morpheus_rb(text: str, cert_path: str, key_path: str, stamp: str) -> str:
    """Comment out any active nginx['ssl_certificate'|'ssl_server_key'] lines,
    drop a previous Morpheus Certificate Install block, and append a fresh one. Idempotent."""
    lines = text.splitlines()
    out: List[str] = []
    skipping = False
    pat = re.compile(r"""^\s*nginx\s*\[\s*['"](%s)['"]\s*\]\s*=""" % "|".join(NGINX_KEYS))
    for ln in lines:
        if ln.strip() == MANAGED_BEGIN or ln.strip() in LEGACY_BEGIN:
            skipping = True
            continue
        if skipping:
            if ln.strip() == MANAGED_END or ln.strip() in LEGACY_END:
                skipping = False
            continue
        if pat.match(ln):
            out.append(f"# [morpheus-certificate-install {stamp}] {ln}")
        else:
            out.append(ln)
    while out and not out[-1].strip():
        out.pop()
    out += [
        "",
        MANAGED_BEGIN,
        f"# written {stamp} — previous values (if any) are commented above",
        f"nginx['ssl_certificate'] = '{cert_path}'",
        f"nginx['ssl_server_key'] = '{key_path}'",
        MANAGED_END,
    ]
    return "\n".join(out) + "\n"


def current_nginx_ssl(text: str) -> Dict[str, str]:
    found = {}
    pat = re.compile(r"""^\s*nginx\s*\[\s*['"](%s)['"]\s*\]\s*=\s*['"]([^'"]+)['"]""" % "|".join(NGINX_KEYS))
    for ln in text.splitlines():
        m = pat.match(ln)
        if m:
            found[m.group(1)] = m.group(2)
    return found


def unified_diff(old: str, new: str, path: str) -> str:
    return "".join(difflib.unified_diff(old.splitlines(True), new.splitlines(True), f"{path} (now)", f"{path} (after)"))


def certs_from_pem_text(text: str) -> List[x509.Certificate]:
    out = []
    for m in PEM_BLOCK.finditer(text.encode()):
        if m.group(1) == b"CERTIFICATE":
            try:
                out.append(x509.load_pem_x509_certificate(m.group(0)))
            except ValueError:
                pass
    return out


def sha256_fp(c: x509.Certificate) -> str:
    return c.fingerprint(hashes.SHA256()).hex(":").upper()


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()
