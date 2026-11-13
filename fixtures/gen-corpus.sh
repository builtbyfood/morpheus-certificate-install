#!/bin/bash
# morpheus-certificate-install 0.3.0 — create the test corpus (needs openssl 3.4+ and python3 with pyjks).
#
#   bash fixtures/gen-corpus.sh           create only the files that are missing (the normal case)
#   bash fixtures/gen-corpus.sh --force   delete everything and regenerate it all (new keys: every
#                                         fingerprint changes; only when the leaf has expired)
#
# Then always: python3 fixtures/make-cases.py (it reads the corpus as it is).
#
# The base set below is one unit: its CA keys are deleted at the end, so it can only be made whole.
# Additions go after it, one guarded block each, built only from files the corpus keeps (leaf.key,
# leaf.crt, bundle.crt, ec.key …), so adding a case never changes an existing file.
# AIA URLs point at http://127.0.0.1:18080/ — the parity tests serve fixtures/corpus/ there.
# The leaf is valid ~397 days from generation; regenerate with --force (and re-run make-cases.py) when it expires.
# Windows (Git Bash): works with Git's OpenSSL 3; point PYTHON at a python that has pyjks, e.g.
#   PYTHON=/c/path/to/venv/Scripts/python.exe bash fixtures/gen-corpus.sh
set -euo pipefail
export MSYS_NO_PATHCONV=1   # Git Bash would otherwise rewrite -subj "/CN=..." into a Windows path
PYTHON=${PYTHON:-python3}
FORCE=0
case "${1:-}" in
  --force) FORCE=1 ;;
  "") ;;
  *) echo "usage: $0 [--force]" >&2; exit 2 ;;
esac
cd "$(dirname "$0")/corpus"
[ "$FORCE" = 1 ] && rm -f ./*
# LF line ends everywhere: Git for Windows' OpenSSL writes PEM with CRLF, Linux with LF.
lf() { for f in "$@"; do sed -i 's/\r$//' "$f"; done; }

BASE="bundle.crt chain-der.p7b chain.p7b ec-root.crt ec-sha384.crt ec.crt ec.key fake.pvk int-headerless.txt int.crt int.der keystore.jks leaf-der-enc.key leaf-der.key leaf-legacy-enc.key leaf-pkcs1.key leaf-pkcs8-enc.key leaf-pss.crt leaf-sha384.crt leaf-sha512.crt leaf.cer leaf.crt leaf.csr leaf.key legacy.pfx modern.pfx nokey.pfx other.crt other.key pss-int.crt pss-root.crt root.crt root.p7c utf16.cer win.cer"
missing=""
for f in $BASE; do [ -e "$f" ] || missing="$missing $f"; done
if [ -n "$missing" ]; then
  if [ -n "$(ls -A)" ] && [ "$(echo $missing | wc -w)" != "$(echo $BASE | wc -w)" ]; then
    echo "The base corpus is incomplete (missing:$missing)." >&2
    echo "Its CA keys aren't kept, so it can only be regenerated as a whole: $0 --force (changes every fingerprint)." >&2
    exit 1
  fi
  echo "creating the base corpus"
  AIA=http://127.0.0.1:18080
  openssl req -x509 -newkey rsa:2048 -nodes -keyout root.key -out root.crt -days 3650 -subj "/CN=Cust Root" -addext "basicConstraints=critical,CA:TRUE" 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -keyout int.key -out int.csr -subj "/CN=Cust Issuing" 2>/dev/null
  printf "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nauthorityInfoAccess=caIssuers;URI:$AIA/root.p7c\n" > int.ext
  openssl x509 -req -in int.csr -CA root.crt -CAkey root.key -CAcreateserial -out int.crt -days 1825 -extfile int.ext 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -keyout leaf.key -out leaf.csr -subj /CN=m.cust.test 2>/dev/null
  printf "subjectAltName=DNS:m.cust.test,IP:10.0.0.5\nauthorityInfoAccess=caIssuers;URI:$AIA/int.der\n" > leaf.ext
  openssl x509 -req -in leaf.csr -CA int.crt -CAkey int.key -CAcreateserial -out leaf.crt -days 397 -extfile leaf.ext 2>/dev/null
  openssl x509 -in int.crt -outform der -out int.der
  openssl crl2pkcs7 -nocrl -certfile root.crt -outform der -out root.p7c
  openssl crl2pkcs7 -nocrl -certfile leaf.crt -certfile int.crt -certfile root.crt -out chain.p7b
  openssl crl2pkcs7 -nocrl -certfile leaf.crt -certfile int.crt -certfile root.crt -outform der -out chain-der.p7b
  cat int.crt root.crt > bundle.crt
  openssl rsa -in leaf.key -traditional -out leaf-pkcs1.key 2>/dev/null
  openssl x509 -in leaf.crt -outform der -out leaf.cer
  openssl pkcs8 -topk8 -nocrypt -in leaf.key -outform der -out leaf-der.key
  openssl pkcs8 -topk8 -v2 aes256 -passout pass:dk -in leaf.key -outform der -out leaf-der-enc.key
  openssl pkcs8 -topk8 -v2 aes256 -passout pass:pk -in leaf.key -out leaf-pkcs8-enc.key
  openssl rsa -in leaf.key -aes256 -passout pass:lg -traditional -out leaf-legacy-enc.key 2>/dev/null
  openssl pkcs12 -export -out modern.pfx -inkey leaf.key -in leaf.crt -certfile bundle.crt -passout pass:pp
  openssl pkcs12 -export -legacy -out legacy.pfx -inkey leaf.key -in leaf.crt -certfile int.crt -passout pass:old
  openssl pkcs12 -export -out nokey.pfx -nokeys -in leaf.crt -passout pass:x
  openssl ecparam -name prime256v1 -genkey -noout -out ec.key
  openssl req -new -key ec.key -out ec.csr -subj /CN=ec.cust.test 2>/dev/null
  printf "subjectAltName=DNS:ec.cust.test\n" > ec.ext
  openssl x509 -req -in ec.csr -CA int.crt -CAkey int.key -CAcreateserial -out ec.crt -days 300 -extfile ec.ext 2>/dev/null
  # Signature-algorithm variants (0.3.2). Same leaf key and name as leaf.crt, different signatures:
  # RSA SHA-384 / SHA-512 by the RSA intermediate; a P-256 leaf signed ECDSA-SHA384 by a P-256 root;
  # and an RSA-PSS chain (root -> intermediate -> leaf, every signature RSASSA-PSS, SHA-256, salt 32).
  openssl x509 -req -in leaf.csr -CA int.crt -CAkey int.key -CAcreateserial -sha384 -out leaf-sha384.crt -days 397 -extfile leaf.ext 2>/dev/null
  openssl x509 -req -in leaf.csr -CA int.crt -CAkey int.key -CAcreateserial -sha512 -out leaf-sha512.crt -days 397 -extfile leaf.ext 2>/dev/null
  openssl ecparam -name prime256v1 -genkey -noout -out ecroot.key
  openssl req -x509 -new -key ecroot.key -sha384 -out ec-root.crt -days 3650 -subj "/CN=Cust EC Root" -addext "basicConstraints=critical,CA:TRUE" 2>/dev/null
  openssl x509 -req -in ec.csr -CA ec-root.crt -CAkey ecroot.key -CAcreateserial -sha384 -out ec-sha384.crt -days 300 -extfile ec.ext 2>/dev/null
  PSS="-sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32"
  openssl req -x509 -newkey rsa:2048 -nodes -keyout pssroot.key -out pss-root.crt -days 3650 -subj "/CN=Cust PSS Root" -addext "basicConstraints=critical,CA:TRUE" $PSS 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -keyout pssint.key -out pssint.csr -subj "/CN=Cust PSS Issuing" 2>/dev/null
  printf "basicConstraints=critical,CA:TRUE,pathlen:0
  keyUsage=critical,keyCertSign,cRLSign
  " > pssint.ext
  openssl x509 -req -in pssint.csr -CA pss-root.crt -CAkey pssroot.key -CAcreateserial -out pss-int.crt -days 1825 -extfile pssint.ext $PSS 2>/dev/null
  printf "subjectAltName=DNS:m.cust.test
  " > leafpss.ext
  openssl x509 -req -in leaf.csr -CA pss-int.crt -CAkey pssint.key -CAcreateserial -out leaf-pss.crt -days 397 -extfile leafpss.ext $PSS 2>/dev/null
  openssl req -x509 -newkey rsa:2048 -nodes -keyout other.key -out other.crt -days 30 -subj /CN=other 2>/dev/null
  lf ./*.crt ./*.key ./*.csr chain.p7b   # (win.cer below adds its own CRLF)
  "$PYTHON" - <<'PY'
from pathlib import Path
P = Path(".")
pem = b"Bag Attributes\r\n    friendlyName: m.cust.test\r\n" + (P/"leaf.crt").read_bytes().replace(b"\n", b"\r\n")
(P/"win.cer").write_bytes(pem)
(P/"utf16.cer").write_bytes(b"\xff\xfe" + (P/"leaf.crt").read_text().encode("utf-16-le"))
(P/"int-headerless.txt").write_bytes(b"".join(l for l in (P/"int.crt").read_bytes().splitlines(True) if not l.startswith(b"-----")))
(P/"fake.pvk").write_bytes(b"\x1e\xf1\xb5\xb0" + b"\x00" * 60)
import jks
from cryptography.hazmat.primitives import serialization
from cryptography import x509
key = serialization.load_pem_private_key((P/"leaf.key").read_bytes(), None)
pk8 = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
der = lambda f: x509.load_pem_x509_certificate((P/f).read_bytes()).public_bytes(serialization.Encoding.DER)
jks.KeyStore.new("jks", [jks.PrivateKeyEntry.new("tomcat", [der("leaf.crt"), der("int.crt")], pk8, "pkcs8"),
                         jks.TrustedCertEntry.new("root", der("root.crt"))]).save("keystore.jks", "storepw")
PY
  rm -f ./*.ext ./*.srl int.csr ec.csr root.key int.key ecroot.key pssroot.key pssint.key pssint.csr
fi

# ---- additions (each only if missing; never touch an existing file) ----

# 0.3.3: PFX with PBMAC1 integrity (RFC 9579; OpenSSL 3.4+ -pbmac1_pbkdf2), leaf + key + bundle, password "pm".
[ -e pbmac1.pfx ] || openssl pkcs12 -export -pbmac1_pbkdf2 -out pbmac1.pfx -inkey leaf.key -in leaf.crt -certfile bundle.crt -passout pass:pm

# 0.3.3: an Ed448 chain (self-signed Ed448 root → leaf.csr signed by it). The reference verifies it;
# the Rust port can't verify Ed448 and says so (docs/PARITY.md). The root key is not kept.
if [ ! -e ed448-root.crt ] || [ ! -e leaf-ed448.crt ]; then
  openssl genpkey -algorithm ed448 -out ed448root.key
  openssl req -x509 -new -key ed448root.key -out ed448-root.crt -days 3650 -subj "/CN=Cust Ed448 Root" -addext "basicConstraints=critical,CA:TRUE" 2>/dev/null
  printf "subjectAltName=DNS:m.cust.test
" > leafed448.ext
  openssl x509 -req -in leaf.csr -CA ed448-root.crt -CAkey ed448root.key -CAcreateserial -out leaf-ed448.crt -days 397 -extfile leafed448.ext 2>/dev/null
  lf ed448-root.crt leaf-ed448.crt
  rm -f ed448root.key leafed448.ext ./*.srl
fi

# 0.3.4: AIA chain completion (R3). A separate small CA (its keys aren't kept): aia-root → aia-int,
# both served from the corpus; aia-int's own AIA points at aia-root.cer. Four leaves for leaf.csr
# (so leaf.key matches), differing only in their caIssuers URLs:
#   leaf-aia-ldap-first.crt  ldap:///… first, then http://…/aia-int.der  (the fetch must skip ldap)
#   leaf-aia-ldap-only.crt   ldap:///… only                              (advice, nothing fetched)
#   leaf-aia-pem.crt         http://…/aia-int.crt                        (the response is PEM)
#   leaf-aia-fallback.crt    http://…/aia-missing.der (404), then …/aia-int.der
AIA_FILES="aia-root.crt aia-root.cer aia-int.crt aia-int.der leaf-aia-ldap-first.crt leaf-aia-ldap-only.crt leaf-aia-pem.crt leaf-aia-fallback.crt"
aia_missing=""
for f in $AIA_FILES; do [ -e "$f" ] || aia_missing="$aia_missing $f"; done
if [ -n "$aia_missing" ]; then
  AIA=http://127.0.0.1:18080
  LDAP='ldap:///CN=Cust%20AIA%20Issuing%2CCN=AIA%2CCN=Public%20Key%20Services%2CCN=Services%2CCN=Configuration%2CDC=cust%2CDC=test?cACertificate?base?objectClass=certificationAuthority'
  rm -f $AIA_FILES
  openssl req -x509 -newkey rsa:2048 -nodes -keyout aiaroot.key -out aia-root.crt -days 3650 -subj "/CN=Cust AIA Root" -addext "basicConstraints=critical,CA:TRUE" 2>/dev/null
  openssl x509 -in aia-root.crt -outform der -out aia-root.cer
  openssl req -newkey rsa:2048 -nodes -keyout aiaint.key -out aiaint.csr -subj "/CN=Cust AIA Issuing" 2>/dev/null
  printf "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nauthorityInfoAccess=caIssuers;URI:$AIA/aia-root.cer\n" > aiaint.ext
  openssl x509 -req -in aiaint.csr -CA aia-root.crt -CAkey aiaroot.key -CAcreateserial -out aia-int.crt -days 1825 -extfile aiaint.ext 2>/dev/null
  openssl x509 -in aia-int.crt -outform der -out aia-int.der
  for v in ldap-first ldap-only pem fallback; do
    case $v in
      ldap-first) urls="caIssuers;URI:$LDAP,caIssuers;URI:$AIA/aia-int.der" ;;
      ldap-only)  urls="caIssuers;URI:$LDAP" ;;
      pem)        urls="caIssuers;URI:$AIA/aia-int.crt" ;;
      fallback)   urls="caIssuers;URI:$AIA/aia-missing.der,caIssuers;URI:$AIA/aia-int.der" ;;
    esac
    printf "subjectAltName=DNS:m.cust.test\nauthorityInfoAccess=%s\n" "$urls" > leafaia.ext   # %s: the URLs contain %20
    openssl x509 -req -in leaf.csr -CA aia-int.crt -CAkey aiaint.key -CAcreateserial -out leaf-aia-$v.crt -days 397 -extfile leafaia.ext 2>/dev/null
  done
  lf aia-root.crt aia-int.crt leaf-aia-*.crt
  rm -f aiaroot.key aiaint.key aiaint.csr aiaint.ext leafaia.ext ./*.srl
fi

# 0.3.17: a wildcard server certificate (manual check with a real wildcard chain). Its own small CA
# (the root's key isn't kept); the leaf's names are *.wild.test and the apex wild.test, CN *.wild.test.
WILD_FILES="wildcard-root.crt leaf-wildcard.crt leaf-wildcard.key"
wild_missing=""
for f in $WILD_FILES; do [ -e "$f" ] || wild_missing="$wild_missing $f"; done
if [ -n "$wild_missing" ]; then
  rm -f $WILD_FILES
  openssl req -x509 -newkey rsa:2048 -nodes -keyout wildroot.key -out wildcard-root.crt -days 3650 -subj "/CN=Wild Test Root" -addext "basicConstraints=critical,CA:TRUE" 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -keyout leaf-wildcard.key -out wildleaf.csr -subj "/CN=*.wild.test" 2>/dev/null
  printf "subjectAltName=DNS:*.wild.test,DNS:wild.test
extendedKeyUsage=serverAuth
" > wildleaf.ext
  openssl x509 -req -in wildleaf.csr -CA wildcard-root.crt -CAkey wildroot.key -CAcreateserial -out leaf-wildcard.crt -days 397 -extfile wildleaf.ext 2>/dev/null
  lf wildcard-root.crt leaf-wildcard.crt leaf-wildcard.key
  rm -f wildroot.key wildleaf.csr wildleaf.ext ./*.srl
fi

echo "corpus: $(ls | wc -l) files"
