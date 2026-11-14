"""Morpheus Certificate Install 0.2.1 — certificate analysis tests (pytest). Builds its own PKI with openssl."""
import subprocess, tempfile, os, pathlib, pytest
from morpheus_certificate_install import certs as C

def sh(cmd, cwd):
    subprocess.run(cmd, shell=True, check=True, cwd=cwd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

@pytest.fixture(scope="module")
def pki():
    d = tempfile.mkdtemp()
    sh('openssl req -x509 -newkey rsa:2048 -nodes -keyout root.key -out root.crt -days 3650 -subj "/CN=Test Root" -addext "basicConstraints=critical,CA:TRUE"', d)
    sh('openssl req -newkey rsa:2048 -nodes -keyout int.key -out int.csr -subj "/CN=Test Issuing"', d)
    pathlib.Path(d, "int.ext").write_text("basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n")
    sh("openssl x509 -req -in int.csr -CA root.crt -CAkey root.key -CAcreateserial -out int.crt -days 1825 -extfile int.ext", d)
    sh('openssl req -newkey rsa:2048 -keyout leaf.key -passout pass:kp -out leaf.csr -subj "/CN=morpheus.example.test"', d)
    pathlib.Path(d, "leaf.ext").write_text("subjectAltName=DNS:morpheus.example.test,IP:10.0.0.5\n")
    sh("openssl x509 -req -in leaf.csr -CA int.crt -CAkey int.key -CAcreateserial -out leaf.crt -days 397 -extfile leaf.ext", d)
    sh("cat int.crt root.crt > bundle.crt", d)
    sh("openssl pkcs12 -export -out leaf.pfx -inkey leaf.key -passin pass:kp -in leaf.crt -certfile bundle.crt -passout pass:pp", d)
    sh('openssl req -x509 -newkey rsa:2048 -nodes -keyout other.key -out other.crt -days 30 -subj "/CN=other"', d)
    return d

def rd(d, *names):
    return [(n, pathlib.Path(d, n).read_bytes()) for n in names]

def levels(an):
    return [c["level"] for c in an.checks]

def test_pem_set_with_encrypted_key(pki):
    an = C.analyze(C.parse_files(rd(pki, "bundle.crt", "leaf.key", "leaf.crt"), key_password="kp"), "", "https://10.0.0.5")
    assert an.ok, an.checks
    assert an.leaf.cn == "morpheus.example.test" and an.fqdn == "morpheus.example.test"
    assert [i.cn for i in an.intermediates] == ["Test Issuing"] and an.root.cn == "Test Root"
    assert an.fullchain_pem().count(b"BEGIN CERTIFICATE") == 2
    assert b"BEGIN PRIVATE KEY" in an.key_pem() and b"ENCRYPTED" not in an.key_pem()

def test_encrypted_key_without_passphrase_is_an_error(pki):
    an = C.analyze(C.parse_files(rd(pki, "leaf.crt", "leaf.key")))
    assert not an.ok and "error" in levels(an)

def test_pfx(pki):
    an = C.analyze(C.parse_files(rd(pki, "leaf.pfx"), pfx_password="pp"))
    assert an.ok and an.root is not None and len(an.intermediates) == 1

def test_wrong_key(pki):
    an = C.analyze(C.parse_files(rd(pki, "leaf.crt", "other.key", "bundle.crt")))
    assert not an.ok
    assert any("does not match" in c["text"] for c in an.checks)

def test_fqdn_not_covered(pki):
    an = C.analyze(C.parse_files(rd(pki, "leaf.pfx"), pfx_password="pp"), "appliance.example.test")
    assert not an.ok

def test_appliance_url_ip_san_and_mismatch(pki):
    an = C.analyze(C.parse_files(rd(pki, "leaf.pfx"), pfx_password="pp"), "", "https://10.0.0.5/")
    assert any("Appliance URL host 10.0.0.5 is covered" in c["text"] for c in an.checks)
    an = C.analyze(C.parse_files(rd(pki, "leaf.pfx"), pfx_password="pp"), "", "https://198.51.100.20/")
    assert an.ok and any(c["level"] == "warn" and "Appliance URL" in c["text"] for c in an.checks)

def test_wildcard():
    assert C.host_matches("a.example.com", ["*.example.com"], [])
    assert not C.host_matches("a.b.example.com", ["*.example.com"], [])
    assert not C.host_matches("example.com", ["*.example.com"], [])

def test_morpheus_rb_transform_is_idempotent():
    rb = "appliance_url 'https://x'\nnginx['ssl_certificate'] = '/etc/morpheus/ssl/old.crt'\nnginx['ssl_server_key'] = '/etc/morpheus/ssl/old.key'\n"
    one = C.transform_morpheus_rb(rb, "/a.crt", "/a.key", "s1")
    two = C.transform_morpheus_rb(one, "/b.crt", "/b.key", "s2")
    assert C.current_nginx_ssl(two) == {"ssl_certificate": "/b.crt", "ssl_server_key": "/b.key"}
    assert two.count(C.MANAGED_BEGIN) == 1 and "/a.crt" not in two
    assert "# [morpheus-certificate-install s1] nginx['ssl_certificate'] = '/etc/morpheus/ssl/old.crt'" in two


def test_replaces_block_written_under_the_old_name():
    old = ("appliance_url 'https://x'\n\n# >>> sphragis managed block (do not edit by hand) >>>\n"
           "nginx['ssl_certificate'] = '/old.crt'\nnginx['ssl_server_key'] = '/old.key'\n# <<< sphragis managed block <<<\n")
    new = C.transform_morpheus_rb(old, "/n.crt", "/n.key", "s3")
    assert "sphragis" not in new and new.count(C.MANAGED_BEGIN) == 1
    assert C.current_nginx_ssl(new) == {"ssl_certificate": "/n.crt", "ssl_server_key": "/n.key"}
