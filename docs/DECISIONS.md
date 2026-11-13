# Decisions — morpheus-certificate-install 0.4.0

| Date | Decision | Why |
|---|---|---|
| 2026-11-05 | Standalone Tauri 2 app, portable (GUI exe + CLI exe + portable.flag) | Travis's choice; same pattern as Charon |
| 2026-11-05 | SSH via the `charon-ssh` crate | Reuse; it already carries host keys, exec and SFTP for hvm-desk |
| 2026-11-05 | The Python 0.2.1 is the frozen spec; fixtures and goldens are generated from it | Port by parity, not redesign |
| 2026-11-05 | **Crypto: pure Rust, RustCrypto `der` 0.7 generation.** We write our own PKCS#12 container reader, lenient PKCS#7 walker, legacy-PEM decrypt and RFC 4514 renderer. No OpenSSL, no p12-keystore. | Every corpus file passes against reference values. No C toolchain. About 650 KB in a release exe. Only stable crate releases. See below. |
| 2026-11-05 | charon-ssh gaps: add them to the crate in R5 rather than wrap russh directly | The changes are small and backwards-compatible; see `CHARON-SSH-CHANGES.md` |
| 2026-11-05 | **Accept RUSTSEC-2026-0387** (`crypto-bigint` 0.5, timing variability in operations meant to be constant-time), ignored in `.cargo/audit.toml`. Revisit on the move to `der` 0.8. | The fix (`crypto-bigint` ≥ 0.7.6) exists only in the `der` 0.8 / `elliptic-curve` 0.14 generation. Our exposure: ECDSA signature *verification* over public data, plus a one-off local derivation of an EC public key from a private key that was saved without one. Neither is remotely timeable: no signing, no ECDH, no network-facing secret operation. Approved by Travis after R2. |
| 2026-11-08 | **Closed — accepted: RUSTSEC-2023-0071 (`rsa` Marvin) also for `rsa` 0.10.0-rc in russh**, which *signs* during SSH login with an RSA key. The one `.cargo/audit.toml` ignore covers both versions. Decided by Travis after R6. | Client-side signing, once per login; only the server we are connecting to sees that signature and could time it. No decryption anywhere. mci-core's `rsa` 0.9 only verifies. ed25519/ECDSA keys don't use this code. Revisit when a constant-time `rsa` is released. |
| 2026-11-07 | **Note on the above: two RustCrypto generations are now in the app.** Revisit moving mci-core to the newer one; that drops the duplicate stack and the RUSTSEC-2026-0387 ignore. | russh 0.65 (charon-ssh, since 0.3.5) brings in the newer generation: `der` 0.8.3, `spki` 0.8.1, `pkcs8` 0.11.0, `elliptic-curve` 0.14.3 with `crypto-bigint` 0.7.10 (which has the 0387 fix). Of these only `rsa` 0.10.0-rc.18, `pkcs1` 0.8-rc and `ssh-key` 0.7.0-rc.11 are pre-release; the rest is stable. mci-core stays on `der` 0.7 (R0 decision), so the app carries both stacks and `crypto-bigint` 0.5.5 for mci-core's EC verification. **Revisit when `rsa` 0.10 is stable** (mci-core needs it for RSA signature verification). That move would drop the duplicate stack, `crypto-bigint` 0.5 and this ignore. It means re-running the parity suite on the new crates; the readers are our own TLV code, so most of mci-core doesn't change. |
| 2026-11-06 | **charon-ssh on russh 0.65.1 with the `ring` backend** (`default-features = false`, features `ring`, `rsa`, `flate2`) | 0.60.3 is the first release with RUSTSEC-2026-0153/0154 fixed. 0.65.1 pulls 3 pre-release crates (`pkcs1`, `rsa`, `ssh-key` RCs), against 0.60.3's 20+. The default `aws-lc-rs` backend needs NASM to build on Windows; `ring` builds with the normal toolchain and is already in the tree through rustls. |
| 2026-11-05 | **`zip` 2 → 9** in `src-tauri` | Clears RUSTSEC-2026-0367/0368/0369/0429 (all about extraction; we only create archives). An upgrade was available, so no ignore was needed. The full-workspace `cargo audit` now fails only on `russh`/`russh-cryptovec`, which R5 deals with |

---

## R0.2 — crypto stack spike

**Method:** `crates/mci-core/tests/spike.rs` (throwaway; delete it in R1). Run it with `cargo test -p mci-core --test spike -- --nocapture`.

A PASS means the result matched a **reference value**, not just that the file parsed:

- certificate SHA-256 fingerprints from `fixtures/cases.json`;
- SHA-256 of the PKCS#8 and SPKI bytes Python's `cryptography` 50.0.2 produces for the same key;
- Python's `Name.rfc4514_string()` for a deliberately awkward subject (below).

Reference values came from a scratch venv built from `reference/python/requirements.txt`.

### Results

Two stacks: **pure Rust** is `der` 0.7 / `x509-cert` 0.2 / `cms` 0.2 / `pkcs8` 0.10 / `pkcs12` 0.1 / `rsa` 0.9 / `p256` 0.13; **OpenSSL** is `openssl` 0.10 with `vendored`.

| File / check | Pure Rust | OpenSSL vendored |
|---|---|---|
| `leaf.crt`, `int.der`, `leaf.cer`: fingerprints = cases.json | ✅ x509-cert | not run (see below) |
| `chain.p7b` (PEM), with `cms` SignedData (strict) | ⚠ parses, but the order comes back **root, leaf, int** | not run |
| `chain.p7b`, lenient walker over `certificates [0]` | ✅ 3 certs, order leaf, int, root = file = Python | not run |
| `chain-der.p7b`, strict / lenient | ⚠ re-ordered / ✅ file order | not run |
| `root.p7c` (DER, the AIA response), lenient | ✅ 1 cert = root | not run |
| `legacy.pfx` `old`: RC2-40 certs, 3DES key, SHA-1 MAC | ✅ composed reader: 2 certs; key bytes = Python's PKCS#8 | not run |
| `legacy.pfx`, wrong password | ✅ rejected by the MAC check | not run |
| `modern.pfx` `pp`: PBES2 / PBKDF2 / AES-256, SHA-256 MAC | ✅ composed reader: 3 certs; key = Python's PKCS#8 | not run |
| `nokey.pfx` `x` | ✅ composed reader: 1 cert, no key | not run |
| `legacy.pfx` / `modern.pfx` / `nokey.pfx` via **p12-keystore 0.4.1** | ✅ ✅ ✅, but only with `Pkcs12ImportPolicy::Raw`. `Relaxed` returned **0 certs** for `nokey.pfx` | n/a |
| `leaf-der-enc.key` `dk` (PBES2 AES-256, DER) | ✅ `pkcs8` → bytes = Python's | not run |
| `leaf-pkcs8-enc.key` `pk` (PEM) | ✅ `pkcs8` → bytes = Python's | not run |
| `leaf-legacy-enc.key` `lg` (`Proc-Type: 4,ENCRYPTED`, AES-256-CBC) | ✅ our EVP_BytesToKey + CBC → bytes = Python's; wrong password rejected | not run |
| `leaf-pkcs1.key` → PKCS#8 | ✅ wrapping the PKCS#1 bytes gives Python's PKCS#8 exactly | not run |
| `ec.key` (SEC1) → PKCS#8 | ✅ bytes = Python's (138 B), once the inner `[0]` curve parameters are dropped and `[1]` publicKey kept, as cryptography does | not run |
| SPKI(key) == SPKI(cert), RSA and EC | ✅ byte-equal, and equal to Python's SPKI | not run |
| Signature: leaf ← int, int ← root, root ← root | ✅ `rsa` 0.9 PKCS#1 v1.5 / SHA-256 over the raw TBS bytes | not run |
| Signature: `ec.crt` ← int (EC key, RSA-signed) | ✅ | not run |
| Signature: leaf ← root (must be false) | ✅ false | not run |
| Signature: ECDSA P-256 self-signed (`multi.crt`, generated) | ✅ `p256` | not run |
| RFC 4514: own renderer vs Python on `multi.crt` | ✅ identical | n/a |
| RFC 4514: `x509-cert`'s `Display` | ❌ `EMAIL=`, `SERIALNUMBER=` and `1.2.3.4.5=#0c06…` where Python prints dotted OIDs and the value | n/a |

`multi.crt` is a throwaway self-signed P-256 cert, generated with `cryptography`. It has 9 RDNs, including:

- a multi-valued RDN (`OU=IT+CN=mv+x`);
- emailAddress, serialNumber and DC attributes, plus an unknown OID;
- a leading `#` and a trailing space;
- each of `, ; < > + " \`;
- `ë`.

Its PEM and Python's expected string are embedded in the spike.

**OpenSSL fallback: not run.** `openssl-src` failed on this machine at `perl ./Configure … VC-WIN64A` (exit 2).

- OpenSSL's MSVC build needs a native Windows perl (Strawberry); the only perl here is MSYS's.
- There's no WSL or Docker here to try the Linux build.
- So I haven't verified that the legacy provider loads in a static vendored build, and I didn't measure its size. The scratch crate is at `…\scratchpad\ossl-spike` and reproduces the failure.
- What this shows: the fallback would add Strawberry Perl plus a C toolchain to every Windows build machine and to CI.

### Binary size

Measured with the workspace release profile (LTO, `opt-level = "s"`, `codegen-units = 1`, `panic = "abort"`, stripped) on Windows x64 MSVC, running the spike's own code in a scratch binary:

| Build | Size | Delta |
|---|---|---|
| Empty `main` | 104 KB | — |
| Pure-Rust stack, every spike path exercised | 774 KB | **+ ~650 KB**. An upper bound: it includes the spike's own reporting code |
| …plus p12-keystore 0.4.1 | 1,228 KB | + ~445 KB more (a second ASN.1 generation, plus `x509-parser`/nom) |
| OpenSSL vendored | not measured | build failed here |

### Choice and reasons

**Pure Rust, `der` 0.7 generation**, as now declared in `crates/mci-core/Cargo.toml`.

- **Every corpus file and check passes**, matched to Python's bytes, including the two traps:
  - legacy RC2-40 PFX;
  - `Proc-Type: 4,ENCRYPTED` PEM.
- **No C toolchain.** `cargo build` works on a stock Windows machine and in CI. The vendored-OpenSSL fallback doesn't even build here without extra tools.
- **Stable releases only.**
  - The newer `der` 0.8 generation still has `cms 0.3.0-rc` and `rsa 0.10.0-rc`.
  - p12-keystore 0.4.1 depends on `cms 0.3.0-pre.1` and `pkcs12 0.2.0-pre.0`.
  - Pre-releases can break between versions; this tool handles customer private keys.
- **One ASN.1 parser in the binary.** Mixing generations duplicates `der`, `spki`, `pkcs8`, `digest` and the ciphers. Adding p12-keystore also pulls in `x509-parser`/nom, which costs about 445 KB.

**Why compose our own PKCS#12 reader instead of using p12-keystore:**

- It's about 120 lines, on `pkcs12` 0.1 types and its RFC 7292 KDF, `cms` 0.2 `EncryptedData`, `rc2`/`des`/`cbc`, and `pkcs5` (PBES2).
- p12-keystore models a Java-style keystore, not a file reader:
  - its default import policies drop certificates without the "trusted" attribute, and keys without `localKeyId`;
  - `Relaxed` lost the only certificate in `nokey.pfx`;
  - the reference reads every bag.

**What R1 has to carry forward** (these are why the stack isn't simply "use the crates"):

1. **PKCS#7: walk `certificates [0]` element by element.** The trap is real: Python logs "PKCS#7 certificates could not be parsed as DER, falling back to parsing as BER" for both p7b files. But `der` 0.7 doesn't reject them: `SetOfVec` decoding runs `der_sort` and **silently re-orders** the certificates (root, leaf, int). The walker keeps file order. Each element still goes through `x509_cert::Certificate::from_der`, and its original bytes are kept for fingerprints. The spike's walker handles definite lengths only; R1 must add BER indefinite lengths (Windows and Java tools emit them).
2. **Legacy encrypted PEM:**
   - EVP_BytesToKey(MD5, salt = IV[..8], 1 iteration), then CBC, then PKCS#7 unpadding;
   - AES-128/192/256-CBC and DES-EDE3-CBC;
   - a wrong password shows up as bad padding or an unparseable key.
3. **Key normalisation to Python's PKCS#8 bytes:**
   - RSA: wrap the PKCS#1 bytes (`rsaEncryption`, NULL parameters);
   - EC: the curve goes in the AlgorithmIdentifier, and the inner ECPrivateKey **drops `[0]` and keeps `[1]`**;
   - this matters because R4 compares the exported `.key` byte for byte.
4. **Signatures over the raw TBS bytes**, sliced from the original DER, never re-encoded.
5. **Our own RFC 4514 renderer**, a port of cryptography's `rfc4514_string()` (spike's `rfc4514()`):
   - RDNs in reverse order;
   - `+` joins a multi-valued RDN;
   - short names only for CN, L, ST, O, OU, C, STREET, DC, UID; dotted OID for everything else;
   - cryptography's `_escape_dn_value` escaping;
   - BMPString values decoded;
   - other non-string values as `#hex`.
6. **PBES2 passwords inside a PFX are UTF-8 bytes; the PKCS#12 PBE / KDF uses BMPString + NUL**, matching OpenSSL.

### Known gaps and risks

| Item | Effect | Plan |
|---|---|---|
| **Ed448** has no mature pure-Rust verifier | The reference verifies Ed448 signatures in `signed_by`; without one, an Ed448-signed chain wouldn't link | R2 (0.3.3): not verified. The chain stops with a warning that names the certificate and the algorithm (PARITY.md divergences 7 and 13; case `ed448-chain`). Ed448 certificates from CAs are vanishingly rare |
| **ECDSA with a non-default hash** (for example P-256 with SHA-384) | `VerifyingKey::verify` assumes the curve's default hash | Done in R2 (0.3.3): prehash with the signature algorithm's hash, P-256/384/521; case `ec-p256-sha384` |
| **SHA-1 / SHA-224 / SHA-384 / SHA-512 RSA signatures** | The corpus was all SHA-256 | Done in R2 (0.3.3): PKCS#1 v1.5 for each, and RSA-PSS with its parameters; cases `rsa-sha384-leaf`, `rsa-sha512-leaf`, `rsa-pss-chain` |
| `crypto-bigint` 0.5: RUSTSEC-2026-0387 (timing variability) | `cargo audit` fails; the fix is in crypto-bigint 0.7.6+, the der 0.8 generation | Accepted (decision table above): ignored in `.cargo/audit.toml` with the reason. Resolved properly by the der 0.8 move |
| `rsa` 0.9: RUSTSEC-2023-0071 (Marvin) | `cargo audit` would flag it | The advisory is a timing side channel in RSA private-key *decryption*; we only verify. Accepted and ignored in `.cargo/audit.toml` (0.3.2), with the reason. Revisit when `rsa` 0.10 is stable |
| PBES1 (`pbeWithMD5AndDES` and so on) in PKCS#8 | `pkcs8` 0.10 doesn't decrypt PBES1; OpenSSL, and so the Python, does | R1 (0.3.2): reported clearly ("export it again with AES-256"), not implemented; listed under *Not ported* in PARITY.md |
| JCEKS private keys (PBEWithMD5AndTripleDES) | Optional in R1 per docs/development/ROUND1.md | R1 (0.3.2): skipped; reported with the keytool conversion command, as the reference did without `pyjks` |
| Strict DER in certificates | `x509-cert` rejects non-DER certificates; so does Python's `cryptography`, so parity holds | none |
| OpenSSL fallback unverified | If the pure stack ever falls short, we'd be choosing the fallback without knowing whether the legacy provider works | Low risk: every corpus case already passes without it |

## R1 — what the reader is built from (0.3.2)

- **One walker for every container.** `formats/tlv.rs` reads tag-length-value with checked arithmetic and a nesting cap of 40. It accepts BER indefinite lengths and constructed OCTET STRINGs, and never allocates by a declared length. PKCS#7 (`p7.rs`), PKCS#12 (`pfx.rs`) and the JKS key protector all sit on it. Certificates still go through `x509-cert`; PKCS#8, PKCS#1 and SEC1 go through their crates.
- **`cms` dropped.** With our own SignedData walker nothing used it.
- **PFX hardening** (`pfx.rs`, `pbe.rs`):
  - the MAC is verified before any decryption;
  - every work factor is checked before any derivation: PBKDF2, PKCS#12 KDF and MAC iterations at most 10,000,000; scrypt at most N=2^20 and 64 MiB; OpenSSH bcrypt at most 1,000 rounds;
  - a header that promises more bytes than the file has is reported as "cut short".
  - Tests: truncation at 14 offsets of `legacy.pfx` and `modern.pfx`; one flipped MAC byte; a 2,000,000,000-iteration MAC; huge inner PBKDF2/PBE counts without the MAC fixed (→ wrong password, so the MAC ran first) and with it recomputed (→ the limit); 900 single-byte corruptions. Each ends in an error report, never a panic or a hang.
- **Added:** `bcrypt-pbkdf` 0.10 and `ctr` 0.9 for OpenSSH private keys. Both are RustCrypto and on the same generation.
- **`pkcs5` features:** `des-insecure` and `sha1-insecure`, decrypt-only, for DES-CBC and the HMAC-SHA1 PRF that older OpenSSL, Java and Windows exports use.
- **Unit-test vectors outside `fixtures/`:** `formats/testdata/ossh-*` are three throwaway OpenSSH keys made with ssh-keygen. The expected PKCS#8/SPKI hashes in the test were produced by the reference's `cryptography` 50.0.2. They're unit-test data, not parity fixtures; the reference corpus has no OpenSSH key.
