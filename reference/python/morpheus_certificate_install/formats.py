"""Morpheus Certificate Install 0.2.1 — read whatever a CA (or a customer) hands over.

Detection is by content, never by file extension: a ".cer" is as often PEM as
DER, ".crt" files are sometimes PKCS#7, and Windows tools love UTF-16.

Supported inputs
  Certificates   PEM (any label variant, CRLF, BOM, "Bag Attributes" noise),
                 DER (.cer/.crt/.der), PKCS#7 bundles (.p7b/.p7c, PEM or DER),
                 base64 with the PEM header lines missing, UTF-16 text files
  Private keys   PEM PKCS#8, PKCS#1 (RSA), SEC1 (EC), DSA, encrypted PKCS#8,
                 legacy OpenSSL-encrypted PEM, DER PKCS#8/PKCS#1 (plain or
                 encrypted), OpenSSH-format private keys
  Containers     PFX/P12 (incl. legacy RC2/3DES from older Windows exports),
                 Java keystores JKS/JCEKS (needs the optional `pyjks` package)
  Recognised and explained, not used: CSRs, CRLs, bare public keys,
                 Microsoft .pvk/.spc pairs

Every file gets a one-line report of what it turned out to be.
"""
from __future__ import annotations

import base64
import binascii
import re
import warnings
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12

PEM_BLOCK = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----\s*\r?\n.*?-----END \1-----", re.S)
CERT_LABELS = (b"CERTIFICATE", b"TRUSTED CERTIFICATE", b"X509 CERTIFICATE")
JKS_MAGIC = b"\xfe\xed\xfe\xed"
JCEKS_MAGIC = b"\xce\xce\xce\xce"
PVK_MAGIC = b"\x1e\xf1\xb5\xb0"


@dataclass
class FileReport:
    name: str
    format: str = "unknown"
    certs: int = 0
    keys: int = 0
    notes: List[str] = field(default_factory=list)
    level: str = "ok"  # ok | warn | error

    def to_json(self):
        return {"name": self.name, "format": self.format, "certs": self.certs, "keys": self.keys,
                "notes": self.notes, "level": self.level}


@dataclass
class Parsed:
    certs: List[Tuple[x509.Certificate, str]] = field(default_factory=list)
    keys: List[Tuple[object, str, bool]] = field(default_factory=list)  # (key, source, was_encrypted)
    reports: List[FileReport] = field(default_factory=list)


class NeedPassword(Exception):
    pass


def _passwords(pws: List[str]) -> List[Optional[bytes]]:
    out: List[Optional[bytes]] = []
    for p in pws:
        if p and p.encode() not in out:
            out.append(p.encode())
    return out


def normalize_text(data: bytes) -> bytes:
    """Strip BOMs and turn UTF-16 text (Windows 'Unicode' saves) into bytes we can regex."""
    if data[:3] == b"\xef\xbb\xbf":
        return data[3:]
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            return data.decode("utf-16").encode("utf-8")
        except UnicodeDecodeError:
            return data
    # UTF-16 without BOM: every other byte NUL in the first chunk.
    head = data[:200]
    if len(head) > 20 and head[1::2].count(0) > len(head) // 3 and b"-\x00-\x00" in head:
        try:
            return data.decode("utf-16-le").encode("utf-8")
        except UnicodeDecodeError:
            pass
    return data


def _try_key_pem(blk: bytes, pws):
    encrypted = blk.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY") or b"Proc-Type: 4,ENCRYPTED" in blk
    if blk.startswith(b"-----BEGIN OPENSSH PRIVATE KEY"):
        for pw in [None] + pws:
            try:
                return serialization.load_ssh_private_key(blk, pw), pw is not None
            except (ValueError, TypeError):
                continue
        raise NeedPassword()
    if not encrypted:
        return serialization.load_pem_private_key(blk, None), False
    for pw in pws:
        try:
            return serialization.load_pem_private_key(blk, pw), True
        except (ValueError, TypeError):
            continue
    raise NeedPassword()


def _try_key_der(data: bytes, pws):
    try:
        return serialization.load_der_private_key(data, None), False
    except TypeError:
        pass  # encrypted
    except ValueError:
        return None, False
    for pw in pws:
        try:
            return serialization.load_der_private_key(data, pw), True
        except (ValueError, TypeError):
            continue
    raise NeedPassword()


def parse_one(name: str, raw: bytes, passwords: List[str], out: Parsed, depth: int = 0) -> FileReport:
    rep = FileReport(name)
    pws = _passwords(passwords)
    data = normalize_text(raw)

    def add_cert(c, how):
        out.certs.append((c, f"{name} ({how})"))
        rep.certs += 1

    def add_key(k, enc):
        out.keys.append((k, name, enc))
        rep.keys += 1

    blocks = list(PEM_BLOCK.finditer(data))
    if blocks:
        kinds = []
        for m in blocks:
            label, blk = m.group(1), m.group(0)
            if label in CERT_LABELS:
                try:
                    norm = re.sub(rb"(TRUSTED|X509) CERTIFICATE", b"CERTIFICATE", blk)
                    add_cert(x509.load_pem_x509_certificate(norm), "PEM")
                    kinds.append("certificate")
                except ValueError as e:
                    rep.notes.append(f"unreadable certificate block: {e}")
                    rep.level = "warn"
            elif label == b"PKCS7":
                try:
                    cs = _p7(pkcs7.load_pem_pkcs7_certificates, blk)
                    for c in cs:
                        add_cert(c, "PKCS#7")
                    kinds.append(f"PKCS#7 bundle ({len(cs)})")
                except ValueError as e:
                    rep.notes.append(f"unreadable PKCS#7 block: {e}")
                    rep.level = "warn"
            elif b"PRIVATE KEY" in label:
                try:
                    k, enc = _try_key_pem(blk, pws)
                    add_key(k, enc)
                    kinds.append(("encrypted " if enc else "") + _key_label(label))
                except NeedPassword:
                    rep.notes.append("The private key is encrypted — enter its passphrase.")
                    rep.level = "error"
                    kinds.append("encrypted private key (locked)")
                except ValueError as e:
                    rep.notes.append(f"private key could not be read: {e}")
                    rep.level = "error"
            elif b"CERTIFICATE REQUEST" in label:
                rep.notes.append("This is a CSR (the request you sent to the CA), not a certificate. It isn't needed here.")
                rep.level = "warn" if rep.level == "ok" else rep.level
                kinds.append("CSR")
            elif label == b"X509 CRL":
                rep.notes.append("A revocation list (CRL) — not needed.")
                kinds.append("CRL")
            elif label in (b"PUBLIC KEY", b"RSA PUBLIC KEY"):
                rep.notes.append("A bare public key — the private key is what's needed.")
                kinds.append("public key")
            else:
                rep.notes.append(f"Ignored a {label.decode()} block.")
        rep.format = "PEM: " + ", ".join(_count(kinds)) if kinds else "PEM (nothing usable)"
        return rep

    # ---- binary containers
    if data[:4] in (JKS_MAGIC, JCEKS_MAGIC):
        return _parse_jks(name, data, passwords, out, rep, add_cert, add_key)
    if data[:4] == PVK_MAGIC:
        rep.format = "Microsoft PVK private key"
        rep.level = "error"
        rep.notes.append("PVK is Microsoft's legacy key format. Convert on Windows with `pvk2pfx -pvk key.pvk -spc cert.spc -pfx out.pfx`, then load the PFX.")
        return rep

    # DER certificate
    try:
        add_cert(x509.load_der_x509_certificate(data), "DER")
        rep.format = "DER certificate"
        return rep
    except ValueError:
        pass
    # DER PKCS#7
    try:
        cs = _p7(pkcs7.load_der_pkcs7_certificates, data)
        for c in cs:
            add_cert(c, "PKCS#7")
        rep.format = f"PKCS#7 bundle, DER ({len(cs)} certificate{'s' if len(cs) != 1 else ''})"
        return rep
    except ValueError:
        pass
    # PFX / P12
    if data[:1] == b"\x30":
        pfx_ok, wrong_pw = False, False
        for pw in [None, b""] + pws:
            try:
                k, c, extra = pkcs12.load_key_and_certificates(data, pw)
            except ValueError as e:
                wrong_pw = wrong_pw or "password" in str(e).lower() or "mac" in str(e).lower()
                continue
            except TypeError:
                continue
            pfx_ok = True
            if k is not None:
                add_key(k, pw not in (None, b""))
            if c is not None:
                add_cert(c, "PFX")
            for e in extra or []:
                add_cert(e, "PFX")
            rep.format = f"PFX / PKCS#12 ({rep.certs} certificate{'s' if rep.certs != 1 else ''}, {'with' if rep.keys else 'no'} private key)"
            if not rep.keys:
                rep.notes.append("This PFX has no private key in it — export it again from the machine that made the CSR, with 'export the private key' ticked.")
                rep.level = "warn"
            break
        if pfx_ok:
            return rep
        # Not a PFX we could open — maybe a DER key.
        try:
            k, enc = _try_key_der(data, pws)
            if k is not None:
                add_key(k, enc)
                rep.format = ("encrypted " if enc else "") + "DER private key"
                return rep
        except NeedPassword:
            rep.format = "encrypted DER private key (locked)"
            rep.level = "error"
            rep.notes.append("The private key is encrypted — enter its passphrase.")
            return rep
        if wrong_pw or name.lower().endswith((".pfx", ".p12")):
            rep.format = "PFX / PKCS#12 (locked)"
            rep.level = "error"
            rep.notes.append("Wrong or missing PFX password.")
            return rep

    # Base64 with the PEM armour stripped (pasted from an email or a portal).
    if depth == 0:
        text = re.sub(rb"\s+", b"", data)
        if len(text) > 100 and re.fullmatch(rb"[A-Za-z0-9+/=]+", text or b"-"):
            try:
                inner = base64.b64decode(text, validate=True)
            except (binascii.Error, ValueError):
                inner = b""
            if inner:
                sub = parse_one(name, inner, passwords, out, depth=1)
                sub.format = f"base64 without PEM headers → {sub.format}"
                return sub

    rep.format = "not recognised"
    rep.level = "error"
    rep.notes.append("Not a certificate, key, PFX, PKCS#7 or keystore that Morpheus Certificate Install can read.")
    return rep


def _parse_jks(name, data, passwords, out, rep, add_cert, add_key):
    kind = "JKS" if data[:4] == JKS_MAGIC else "JCEKS"
    rep.format = f"Java keystore ({kind})"
    try:
        import jks  # pyjks
    except ImportError:
        rep.level = "error"
        rep.notes.append("Java keystores need the optional pyjks package: pip install pyjks. "
                         "Or convert it first: keytool -importkeystore -srckeystore in.jks -destkeystore out.p12 -deststoretype PKCS12")
        return rep
    store = None
    for pw in [p for p in passwords if p] + ["changeit", ""]:
        try:
            store = jks.KeyStore.loads(data, pw, try_decrypt_keys=False)
            store_pw = pw
            break
        except Exception:
            continue
    if store is None:
        rep.level = "error"
        rep.notes.append("Wrong keystore password (tried the passwords given and 'changeit').")
        return rep
    for alias, pk in store.private_keys.items():
        if not pk.is_decrypted():
            for pw in [p for p in passwords if p] + [store_pw]:
                try:
                    pk.decrypt(pw)
                    break
                except Exception:
                    continue
        if not pk.is_decrypted():
            rep.level = "error"
            rep.notes.append(f"Key entry '{alias}' has its own password — enter it as the key passphrase.")
            continue
        try:
            add_key(serialization.load_der_private_key(pk.pkey_pkcs8, None), True)
        except ValueError as e:
            rep.notes.append(f"Key entry '{alias}' unreadable: {e}")
            continue
        for _typ, der in pk.cert_chain:
            add_cert(x509.load_der_x509_certificate(der), f"JKS:{alias}")
    for alias, tc in store.certs.items():
        try:
            add_cert(x509.load_der_x509_certificate(tc.cert), f"JKS:{alias}")
        except ValueError:
            pass
    rep.format += f" — {len(store.private_keys)} key entr{'y' if len(store.private_keys) == 1 else 'ies'}, {len(store.certs)} trusted cert{'s' if len(store.certs) != 1 else ''}"
    return rep


def _p7(loader, data):
    # openssl crl2pkcs7 and Windows both emit BER-ish SET ordering; the fallback is fine.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return loader(data)


def _key_label(label: bytes) -> str:
    return {b"RSA PRIVATE KEY": "RSA key (PKCS#1)", b"EC PRIVATE KEY": "EC key (SEC1)", b"DSA PRIVATE KEY": "DSA key",
            b"PRIVATE KEY": "private key (PKCS#8)", b"ENCRYPTED PRIVATE KEY": "private key (PKCS#8)",
            b"OPENSSH PRIVATE KEY": "OpenSSH private key"}.get(label, label.decode().lower())


def _count(kinds: List[str]) -> List[str]:
    seen = {}
    for k in kinds:
        seen[k] = seen.get(k, 0) + 1
    return [f"{n}× {k}" if n > 1 else k for k, n in seen.items()]


def parse_all(files: List[Tuple[str, bytes]], passwords: List[str]) -> Parsed:
    out = Parsed()
    for name, data in files:
        out.reports.append(parse_one(name, data, passwords, out))
    return out


# ------------------------------------------------------------------ AIA chain completion

def aia_urls(cert: x509.Certificate) -> List[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
    except x509.ExtensionNotFound:
        return []
    return [d.access_location.value for d in ext
            if d.access_method == x509.oid.AuthorityInformationAccessOID.CA_ISSUERS
            and isinstance(d.access_location, x509.UniformResourceIdentifier)
            and d.access_location.value.lower().startswith(("http://", "https://"))]


def fetch_issuer(url: str, getter: Optional[Callable[[str], bytes]] = None) -> List[x509.Certificate]:
    """Download a caIssuers URL (DER cert, PEM, or PKCS#7 — CAs use all three)."""
    import urllib.request
    if getter is None:
        def getter(u):
            req = urllib.request.Request(u, headers={"User-Agent": "morpheus-certificate-install"})
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.read(1024 * 1024)
    data = getter(url)
    tmp = Parsed()
    parse_one(url, data, [], tmp)
    return [c for c, _ in tmp.certs]
