"""Morpheus Certificate Install 0.2.1 — write the converted files in the layout Morpheus expects.

Output (base = the FQDN with dots → underscores, as in the HPE docs' your_fqdn_name):
  <base>.crt                server certificate + intermediates, PEM   → /etc/morpheus/ssl/
  <base>.key                decrypted PKCS#8 PEM private key          → /etc/morpheus/ssl/
  ca-chain.pem              root + intermediates (for clients / hosts to trust)
  trusted_certs/<alias>.pem one CA cert per file                      → /etc/morpheus/ssl/trusted_certs/
  morpheus.rb.snippet       the two nginx lines
  INSTALL.txt               what was converted from what, and the manual commands
"""
from __future__ import annotations

import datetime as _dt
import io
import os
import stat
import zipfile
from pathlib import Path
from typing import Dict

from . import __version__
from . import certs as C


def build_files(an: C.Analysis, include_root: bool = False) -> Dict[str, bytes]:
    if not an.ok:
        raise ValueError("The certificate set has errors; fix them before exporting.")
    base = C.safe_name(an.fqdn)
    files: Dict[str, bytes] = {
        f"{base}.crt": an.fullchain_pem(include_root),
        f"{base}.key": an.key_pem(),
    }
    cas = an.ca_certs()
    if cas:
        files["ca-chain.pem"] = an.ca_bundle_pem()
        for c in cas:
            files[f"trusted_certs/{C.alias_for(c)}.pem"] = c.pem()
    files["morpheus.rb.snippet"] = (
        f"nginx['ssl_certificate'] = '/etc/morpheus/ssl/{base}.crt'\n"
        f"nginx['ssl_server_key'] = '/etc/morpheus/ssl/{base}.key'\n").encode()
    files["INSTALL.txt"] = install_text(an, base, include_root).encode()
    return files


def install_text(an: C.Analysis, base: str, include_root: bool) -> str:
    leaf = an.leaf
    dns, ips = leaf.sans()
    lines = [
        f"Converted by Morpheus Certificate Install {__version__} on {_dt.datetime.now():%Y-%m-%d %H:%M}",
        "",
        f"Server certificate : {leaf.cn}",
        f"  SANs             : {', '.join(dns + ips) or 'none'}",
        f"  valid until      : {leaf.not_after():%Y-%m-%d}",
        f"  SHA-256          : {leaf.fp256}",
        f"Chain              : {len(an.intermediates)} intermediate(s)" + (f", root \"{an.root.cn}\"" if an.root else ", root not supplied"),
        f"Private key        : {C.key_desc(an.key.public_key())}, decrypted, PKCS#8 PEM",
        "",
        "Converted from:",
    ]
    for r in an.reports:
        lines.append(f"  {r.name}: {r.format}")
    lines += [
        "",
        f"{base}.crt holds the server certificate followed by the intermediates"
        + (" and the root" if include_root and an.root else "") + " — the order nginx needs.",
        f"{base}.key is NOT encrypted (Morpheus requires that). Keep it off shared drives and email.",
        "",
        "Manual install (on the Morpheus appliance, after copying these files to your home directory):",
        "",
        f"  sudo install -o root -g root -m 0600 ~/{base}.crt /etc/morpheus/ssl/{base}.crt",
        f"  sudo install -o root -g root -m 0600 ~/{base}.key /etc/morpheus/ssl/{base}.key",
        "  sudo cp -a /etc/morpheus/morpheus.rb /etc/morpheus/morpheus.rb.bak-$(date +%Y%m%d-%H%M%S)",
        "  sudoedit /etc/morpheus/morpheus.rb      # add the two lines from morpheus.rb.snippet",
        "  sudo morpheus-ctl reconfigure",
        "  sudo morpheus-ctl restart nginx",
        f"  echo | openssl s_client -connect 127.0.0.1:443 -servername {an.fqdn} 2>/dev/null | openssl x509 -noout -subject -enddate -fingerprint -sha256",
    ]
    if an.ca_certs():
        lines += [
            "",
            "Optional — make Morpheus itself trust this CA (private CAs):",
            "",
            "  sudo mkdir -p /etc/morpheus/ssl/trusted_certs",
            "  sudo install -o root -g root -m 0644 ~/trusted_certs/*.pem /etc/morpheus/ssl/trusted_certs/",
            "  sudo morpheus-ctl reconfigure",
            "  KT=$(sudo find /opt/morpheus/embedded -type f -name keytool | head -1)",
            "  CA=$(sudo find /opt/morpheus/embedded -type f -name cacerts -path '*security*' | head -1)",
        ]
        for c in an.ca_certs():
            a = C.alias_for(c)
            lines.append(f'  sudo "$KT" -importcert -noprompt -trustcacerts -alias {a} -file /etc/morpheus/ssl/trusted_certs/{a}.pem -keystore "$CA" -storepass changeit')
        lines += ["  sudo morpheus-ctl restart morpheus-ui     # UI is down while it starts"]
    lines += ["", "Or let Morpheus Certificate Install do all of it, with a backup and rollback: python -m morpheus_certificate_install", ""]
    return "\n".join(lines)


def to_zip(files: Dict[str, bytes], folder: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files.items():
            zi = zipfile.ZipInfo(f"{folder}/{name}", date_time=_dt.datetime.now().timetuple()[:6])
            zi.compress_type = zipfile.ZIP_DEFLATED
            mode = 0o600 if name.endswith(".key") else 0o644
            zi.external_attr = (stat.S_IFREG | mode) << 16
            z.writestr(zi, data)
    return buf.getvalue()


def to_dir(files: Dict[str, bytes], out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        p = out / name
        p.parent.mkdir(parents=True, exist_ok=True)
        if name.endswith(".key"):
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            try:
                os.chmod(p, 0o600)
            except OSError:
                pass
        else:
            p.write_bytes(data)
