#!/usr/bin/env node
// morpheus-certificate-install 0.4.1 — fail if the repo contains anything from .private-denylist.
//   node scripts/check-private.mjs              (npm run check-private)
//   node scripts/check-private.mjs --self-test  proves the certificate check with planted certificates
//   node scripts/check-private.mjs --root DIR   check every file in another folder (an export) with this denylist
//
// .private-denylist sits in the repo root, is gitignored and is never committed: it lists the
// strings that must not appear in anything that is (your hostnames, addresses, user names, local
// paths, e-mail, domains). Format: one entry per line; blank lines and lines starting with # are ignored.
//   text          matched as is (case-sensitive)
//   i:text        matched ignoring case
//   re:pattern    a JavaScript regular expression
// See .private-denylist.example.
//
// Checked: every file under the repo root except what .gitignore excludes (simple patterns: names,
// `dir/`, `*.ext`, `/rooted/path`), the .git directory, and the denylist itself.
// - File names, and contents as text. Binary files are read as Latin-1, so a name stored plainly
//   inside a DER certificate, a PKCS#7 or a zip is found.
// - Encoded content (0.3.20): base64 hides names, so every PEM block (any type) and every long
//   base64 run (≥ 120 characters, e.g. a certificate inside JSON) is decoded and checked as well.
// - Certificates (0.3.20): every certificate found — a PEM CERTIFICATE block, a DER certificate
//   file, or one inside a decoded base64 run — is parsed, and its subject, issuer and
//   subjectAltName are checked, reported with the certificate's subject.
// Exit 1 on any hit, listing file:line and the entry; exit 2 when there's no denylist.
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { trackedFiles } from "./tracked-files.mjs";
import { fileURLToPath } from "node:url";
import { X509Certificate, generateKeyPairSync, randomBytes } from "node:crypto";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const listPath = join(root, ".private-denylist");
if (!existsSync(listPath)) {
  console.error("check-private: no .private-denylist in the repo root. Copy .private-denylist.example and fill it in.");
  process.exit(2);
}

const entries = readFileSync(listPath, "utf8").split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#")).map((l) => {
  if (l.startsWith("re:")) return { label: l, re: new RegExp(l.slice(3), "g") };
  if (l.startsWith("i:")) return { label: l, literal: l.slice(2), re: new RegExp(l.slice(2).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi") };
  return { label: l, literal: l, re: new RegExp(l.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g") };
});
if (!entries.length) {
  console.error("check-private: .private-denylist has no entries.");
  process.exit(2);
}

const test = (e, s) => { e.re.lastIndex = 0; const r = e.re.test(s); e.re.lastIndex = 0; return r; };
const lineOf = (text, index) => text.slice(0, index).split("\n").length;
let certCount = 0;

/** Subject, issuer and SAN of a certificate (PEM text or DER bytes), or null if it isn't one. */
function certNames(data) {
  let c;
  try { c = new X509Certificate(data); } catch { return null; }
  return { subject: c.subject.replace(/\n/g, ", "), fields: [["subject", c.subject], ["issuer", c.issuer], ["SAN", c.subjectAltName || ""]] };
}
function checkCert(hits, where, data) {
  const n = certNames(data);
  if (!n) return false;
  certCount++;
  for (const [field, value] of n.fields) for (const e of entries) if (test(e, value)) hits.push(`${where}: certificate "${n.subject}", ${field}: ${e.label}`);
  return true;
}
/** Decoded bytes (any PEM type, a base64 run): checked as Latin-1 text, and as a certificate if it is one. */
function checkDecoded(hits, where, bytes, isCertBlock) {
  const asText = bytes.toString("latin1");
  for (const e of entries) if (test(e, asText)) hits.push(`${where} (decoded base64): ${e.label}`);
  if (isCertBlock || (bytes[0] === 0x30 && bytes.length > 200)) checkCert(hits, where, bytes);
}

/** Every check for one file; returns the hits. */
export function scan(rel, buf) {
  const hits = [];
  const text = buf.toString("latin1");
  for (const e of entries) {
    if (test(e, rel)) hits.push(`${rel} (file name): ${e.label}`);
    const lines = text.split("\n");
    for (let i = 0; i < lines.length; i++) if (test(e, lines[i])) hits.push(`${rel}:${i + 1}: ${e.label}`);
  }
  // A DER certificate file.
  if (buf[0] === 0x30 && buf.length > 200 && buf.length < 64 * 1024) checkCert(hits, rel, buf);
  // PEM blocks: in JSON or code they may sit in a string with literal "\n" escapes.
  const pemText = text.replace(/\\r\\n|\\n/g, "\n");
  const covered = [];
  for (const m of pemText.matchAll(/-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/g)) {
    const at = `${rel}:${lineOf(pemText, m.index)}`;
    const body = m[2].replace(/^[A-Za-z-]+:.*$/gm, "").replace(/[^A-Za-z0-9+/=]/g, "");
    checkDecoded(hits, at, Buffer.from(body, "base64"), m[1] === "CERTIFICATE" || m[1] === "TRUSTED CERTIFICATE" || m[1] === "X509 CERTIFICATE");
    covered.push([m.index, m.index + m[0].length]);
  }
  // Long base64 runs outside PEM blocks (base64url too).
  for (const m of pemText.matchAll(/[A-Za-z0-9+/_-]{120,}={0,2}/g)) {
    if (covered.some(([a, b]) => m.index >= a && m.index < b)) continue;
    checkDecoded(hits, `${rel}:${lineOf(pemText, m.index)}`, Buffer.from(m[0].replace(/-/g, "+").replace(/_/g, "/"), "base64"), false);
  }
  return hits;
}

// --root <folder> (0.4.0-rc1): check another folder, e.g. the export made by `npm run export-tree`,
// with this repo's denylist. Every file there is checked (no .gitignore filtering, only .git skipped),
// and a .private-denylist found there is itself a hit: it must never be exported.
const rootArg = process.argv.indexOf("--root");
const scanRoot = rootArg > 0 ? process.argv[rootArg + 1] : null;
if (rootArg > 0 && (!scanRoot || !existsSync(scanRoot))) { console.error(`check-private: --root needs an existing folder (got ${scanRoot ?? "nothing"}).`); process.exit(64); }
function allFiles(dir, base = dir, out = []) {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (e.name === ".git") continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) allFiles(p, base, out); else out.push(p.slice(base.length + 1).split("\\").join("/"));
  }
  return out;
}
function walk(hits) {
  if (scanRoot) {
    for (const rel of allFiles(scanRoot)) {
      if (rel === ".private-denylist") { hits.push(".private-denylist: the denylist itself is in the folder"); continue; }
      hits.push(...scan(rel, readFileSync(join(scanRoot, rel))));
    }
    return;
  }
  for (const rel of trackedFiles(root, (r) => r === ".private-denylist")) hits.push(...scan(rel, readFileSync(join(root, rel))));
}

// ------------------------------------------------------------------ self-test
// A certificate is built here (DER by hand, a random signature: parsing doesn't verify it), so
// the test needs no openssl. It names a denylist entry in its subject, its issuer or its SAN.
const tlv = (tag, ...parts) => {
  const c = Buffer.concat(parts.map((p) => Buffer.isBuffer(p) ? p : Buffer.from(p)));
  const len = c.length < 128 ? Buffer.from([c.length]) : c.length < 256 ? Buffer.from([0x81, c.length]) : Buffer.from([0x82, c.length >> 8, c.length & 255]);
  return Buffer.concat([Buffer.from([tag]), len, c]);
};
const name = (cn) => tlv(0x30, tlv(0x31, tlv(0x30, Buffer.from([6, 3, 0x55, 4, 3]), tlv(0x0c, Buffer.from(cn, "utf8")))));
export function plantedCert({ subject = "planted.example.com", issuer = "Planted Test CA", san = "planted.example.com" } = {}) {
  const spki = generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "der" });
  const sigAlg = tlv(0x30, Buffer.from([6, 8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3, 2]));
  const ext = tlv(0xa3, tlv(0x30, tlv(0x30, Buffer.from([6, 3, 0x55, 0x1d, 0x11]), tlv(0x04, tlv(0x30, tlv(0x82, Buffer.from(san, "ascii")))))));
  const tbs = tlv(0x30, tlv(0xa0, tlv(2, [2])), tlv(2, [1]), sigAlg, name(issuer),
    tlv(0x30, tlv(0x17, "250101000000Z"), tlv(0x17, "350101000000Z")), name(subject), spki, ext);
  return tlv(0x30, tbs, sigAlg, tlv(3, Buffer.concat([Buffer.from([0]), randomBytes(64)])));
}
const pem = (der) => `-----BEGIN CERTIFICATE-----\n${der.toString("base64").match(/.{1,64}/g).join("\n")}\n-----END CERTIFICATE-----\n`;

function selfTest() {
  const e = entries.find((x) => x.literal && /^[\x20-\x7e]+$/.test(x.literal));
  if (!e) { console.error("check-private --self-test: needs a plain-text entry in .private-denylist to plant."); process.exit(2); }
  const v = e.literal;
  const ok = [];
  // want: the certificate field that must be reported by name (a "certificate …, <field>:" hit), or false for none.
  const expect = (what, hits, want) => {
    const certHit = want && hits.find((h) => h.includes(`, ${want}: `));
    const pass = want ? !!certHit : hits.length === 0;
    ok.push(pass);
    console.log(`  ${pass ? "ok  " : "FAIL"} ${what}: ${hits.length} hit(s)${certHit ? " — " + certHit : hits.length ? " — " + hits[0] : ""}`);
  };
  const cases = [
    ["subject", plantedCert({ subject: `host.${v}` })],
    ["issuer", plantedCert({ issuer: `CA ${v}` })],
    ["SAN", plantedCert({ san: `san.${v}` })],
  ];
  for (const [field, der] of cases) {
    const p = pem(der);
    if (test(e, p)) { console.error("self-test: the PEM shows the entry in plain text; the check wouldn't be needed"); process.exit(2); }
    expect(`PEM certificate naming the entry in its ${field}`, scan("planted/cert.pem", Buffer.from(p)), field);
    expect(`the same, inside a JSON string with \\n escapes`, scan("planted/cert.json", Buffer.from(JSON.stringify({ pem: p }))), field);
    expect(`the same, as a base64 run in JSON`, scan("planted/b64.json", Buffer.from(JSON.stringify({ b64: der.toString("base64") }))), field);
  }
  expect("a planted certificate with only example names", scan("planted/clean.pem", Buffer.from(pem(plantedCert()))), false);
  for (const f of readdirSync(join(root, "src-tauri", "testdata", "public-roots"))) {
    const rel = `src-tauri/testdata/public-roots/${f}`;
    const buf = readFileSync(join(root, rel));
    const before = certCount;
    expect(`${rel} (public CAs)`, scan(rel, buf), false);
    console.log(`       ${certCount - before} certificate(s) parsed`);
  }
  const all = ok.every(Boolean);
  console.log(all ? "check-private self-test: OK" : "check-private self-test: FAILED");
  process.exit(all ? 0 : 1);
}

if (process.argv.includes("--self-test")) selfTest();
const hits = [];
walk(hits);
if (hits.length) {
  console.error(`check-private: ${hits.length} hit(s) for entries in .private-denylist:`);
  for (const h of hits) console.error("  " + h);
  process.exit(1);
}
console.log(`check-private: no hits for ${entries.length} entr${entries.length === 1 ? "y" : "ies"} (${certCount} certificate(s) decoded and checked).`);
