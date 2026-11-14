"""Morpheus Certificate Install 0.2.1 — format conversion tests (pytest). Builds its own PKI with openssl."""
import base64, pathlib, subprocess, tempfile, threading, functools, http.server, zipfile, io
import pytest
from morpheus_certificate_install import certs as C, export as X

def sh(cmd, cwd):
    subprocess.run(cmd, shell=True, check=True, cwd=cwd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

@pytest.fixture(scope="module")
def pki():
    d = tempfile.mkdtemp()
    P = pathlib.Path(d)
    # AIA server: leaf points at int.der, int points at root.p7c
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(http.server.SimpleHTTPRequestHandler, directory=d))
    srv.RequestHandlerClass.log_message = lambda *a: None
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    sh('openssl req -x509 -newkey rsa:2048 -nodes -keyout root.key -out root.crt -days 3650 -subj "/CN=Cust Root" -addext "basicConstraints=critical,CA:TRUE"', d)
    sh('openssl req -newkey rsa:2048 -nodes -keyout int.key -out int.csr -subj "/CN=Cust Issuing"', d)
    (P / "int.ext").write_text(f"basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nauthorityInfoAccess=caIssuers;URI:http://127.0.0.1:{port}/root.p7c\n")
    sh("openssl x509 -req -in int.csr -CA root.crt -CAkey root.key -CAcreateserial -out int.crt -days 1825 -extfile int.ext", d)
    sh("openssl req -newkey rsa:2048 -nodes -keyout leaf.key -out leaf.csr -subj /CN=m.cust.test", d)
    (P / "leaf.ext").write_text(f"subjectAltName=DNS:m.cust.test\nauthorityInfoAccess=caIssuers;URI:http://127.0.0.1:{port}/int.der\n")
    sh("openssl x509 -req -in leaf.csr -CA int.crt -CAkey int.key -CAcreateserial -out leaf.crt -days 397 -extfile leaf.ext", d)
    sh("openssl x509 -in int.crt -outform der -out int.der", d)
    sh("openssl crl2pkcs7 -nocrl -certfile root.crt -outform der -out root.p7c", d)
    # Variants
    sh("openssl crl2pkcs7 -nocrl -certfile leaf.crt -certfile int.crt -certfile root.crt -out chain.p7b", d)            # PEM PKCS7
    sh("openssl crl2pkcs7 -nocrl -certfile leaf.crt -certfile int.crt -certfile root.crt -outform der -out chain-der.p7b", d)
    sh("openssl rsa -in leaf.key -traditional -out leaf-pkcs1.key", d)                                                     # BEGIN RSA PRIVATE KEY
    sh("openssl x509 -in leaf.crt -outform der -out leaf.cer", d)                                                          # DER cert
    sh("openssl pkcs8 -topk8 -nocrypt -in leaf.key -outform der -out leaf-der.key", d)                                     # DER PKCS8
    sh("openssl pkcs8 -topk8 -v2 aes256 -passout pass:dk -in leaf.key -outform der -out leaf-der-enc.key", d)              # encrypted DER
    sh("openssl rsa -in leaf.key -aes256 -passout pass:lg -traditional -out leaf-legacy-enc.key", d)                       # Proc-Type ENCRYPTED
    sh("openssl pkcs12 -export -legacy -out legacy.pfx -inkey leaf.key -in leaf.crt -certfile int.crt -passout pass:old", d)
    sh("openssl pkcs12 -export -out nokey.pfx -nokeys -in leaf.crt -passout pass:x", d)
    # EC pair
    sh("openssl ecparam -name prime256v1 -genkey -noout -out ec.key", d)
    sh("openssl req -new -key ec.key -out ec.csr -subj /CN=ec.cust.test", d)
    (P / "ec.ext").write_text("subjectAltName=DNS:ec.cust.test\n")
    sh("openssl x509 -req -in ec.csr -CA int.crt -CAkey int.key -CAcreateserial -out ec.crt -days 300 -extfile ec.ext", d)
    # Windows-flavoured PEM: Bag Attributes, CRLF, saved as UTF-16 with BOM
    pem = b"Bag Attributes\r\n    friendlyName: m.cust.test\r\n" + (P / "leaf.crt").read_bytes().replace(b"\n", b"\r\n")
    (P / "win.cer").write_bytes(pem)
    (P / "utf16.cer").write_bytes(b"\xff\xfe" + (P / "leaf.crt").read_text().encode("utf-16-le"))
    body = b"".join(l for l in (P / "int.crt").read_bytes().splitlines(True) if not l.startswith(b"-----"))
    (P / "int-headerless.txt").write_bytes(body)
    # JKS made with pyjks
    import jks
    from cryptography.hazmat.primitives import serialization
    from cryptography import x509
    key = serialization.load_pem_private_key((P / "leaf.key").read_bytes(), None)
    pk8 = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    der = lambda f: x509.load_pem_x509_certificate((P / f).read_bytes()).public_bytes(serialization.Encoding.DER)
    pke = jks.PrivateKeyEntry.new("tomcat", [der("leaf.crt"), der("int.crt")], pk8, "pkcs8")
    tce = jks.TrustedCertEntry.new("root", der("root.crt"))
    jks.KeyStore.new("jks", [pke, tce]).save(str(P / "keystore.jks"), "storepw")
    (P / "fake.pvk").write_bytes(b"\x1e\xf1\xb5\xb0" + b"\x00" * 60)
    yield d
    srv.shutdown()

def run(d, names, **kw):
    files = [(n, pathlib.Path(d, n).read_bytes()) for n in names]
    b = C.parse_files(files, kw.pop("pfx", ""), kw.pop("keypw", ""))
    return b, C.analyze(b, kw.pop("fqdn", ""))

def fmt(b, name):
    return next(r.format for r in b.reports if r.name == name)

def test_p7b_pem_plus_pkcs1_key(pki):
    b, an = run(pki, ["chain.p7b", "leaf-pkcs1.key"])
    assert an.ok and an.root and len(an.intermediates) == 1
    assert "PKCS#7" in fmt(b, "chain.p7b") and "PKCS#1" in fmt(b, "leaf-pkcs1.key")

def test_p7b_der_plus_der_key(pki):
    b, an = run(pki, ["chain-der.p7b", "leaf-der.key"])
    assert an.ok and fmt(b, "chain-der.p7b").startswith("PKCS#7 bundle, DER (3")
    assert fmt(b, "leaf-der.key") == "DER private key"

def test_der_cert_encrypted_der_key(pki):
    b, an = run(pki, ["leaf.cer", "leaf-der-enc.key", "int.crt"], keypw="dk")
    assert an.ok and fmt(b, "leaf-der-enc.key") == "encrypted DER private key"
    b, an = run(pki, ["leaf.cer", "leaf-der-enc.key"])
    assert not an.ok and "locked" in fmt(b, "leaf-der-enc.key")

def test_legacy_encrypted_pem(pki):
    b, an = run(pki, ["leaf.crt", "leaf-legacy-enc.key", "int.crt"], keypw="lg")
    assert an.ok and b"ENCRYPTED" not in an.key_pem()

def test_legacy_windows_pfx(pki):
    b, an = run(pki, ["legacy.pfx"], pfx="old")
    assert an.ok and "PFX" in fmt(b, "legacy.pfx")

def test_password_in_wrong_box_still_works(pki):
    b, an = run(pki, ["legacy.pfx"], keypw="old")   # typed the PFX password into the key field
    assert an.ok

def test_pfx_without_key(pki):
    b, an = run(pki, ["nokey.pfx"], pfx="x")
    assert not an.ok and any("no private key" in n for r in b.reports for n in r.notes)

def test_jks(pki):
    b, an = run(pki, ["keystore.jks"], pfx="storepw")
    assert an.ok and an.root is not None, an.checks
    assert "JKS" in fmt(b, "keystore.jks")

def test_jks_wrong_password(pki):
    b, an = run(pki, ["keystore.jks"], pfx="nope")
    assert not an.ok

def test_windows_text_variants(pki):
    b, an = run(pki, ["win.cer", "leaf.key", "int-headerless.txt"])
    assert an.ok and len(an.intermediates) == 1, an.checks
    assert fmt(b, "int-headerless.txt").startswith("base64 without PEM headers")
    b, an = run(pki, ["utf16.cer", "leaf.key", "int.crt"])
    assert an.ok

def test_ec_pair(pki):
    b, an = run(pki, ["ec.crt", "ec.key", "int.crt", "root.crt"])
    assert an.ok and "EC" in fmt(b, "ec.key")

def test_csr_and_pvk_are_explained(pki):
    b, an = run(pki, ["leaf.crt", "leaf.key", "leaf.csr", "fake.pvk", "int.crt"])
    assert any("CSR" in n for r in b.reports for n in r.notes)
    assert any("pvk2pfx" in n for r in b.reports for n in r.notes)

def test_fetch_chain_via_aia(pki):
    b, an = run(pki, ["leaf.crt", "leaf.key"])
    assert an.root is None and not an.intermediates and an.to_json()["can_fetch_chain"]
    log = C.complete_chain(b)
    an = C.analyze(b)
    assert an.ok and an.root is not None and len(an.intermediates) == 1, log

def test_export_layout(pki):
    b, an = run(pki, ["chain.p7b", "leaf-pkcs1.key"], fqdn="m.cust.test")
    files = X.build_files(an)
    assert set(files) >= {"m_cust_test.crt", "m_cust_test.key", "ca-chain.pem", "morpheus.rb.snippet", "INSTALL.txt"}
    assert files["m_cust_test.crt"].count(b"BEGIN CERTIFICATE") == 2
    assert files["m_cust_test.key"].startswith(b"-----BEGIN PRIVATE KEY")
    assert len([f for f in files if f.startswith("trusted_certs/")]) == 2
    txt = files["INSTALL.txt"].decode()
    for ln in txt.splitlines():
        if "/etc/morpheus" in ln and ln.strip().startswith(("install", "cp", "morpheus-ctl")):
            pytest.fail("root command without sudo: " + ln)
    z = zipfile.ZipFile(io.BytesIO(X.to_zip(files, "m_cust_test-morpheus")))
    assert (z.getinfo("m_cust_test-morpheus/m_cust_test.key").external_attr >> 16) & 0o777 == 0o600
