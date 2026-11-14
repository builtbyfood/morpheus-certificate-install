#!/usr/bin/env node
// morpheus-certificate-install 0.4.2 — one version everywhere. src-tauri/tauri.conf.json is canonical.
//   node scripts/bump-version.mjs          # propagate tauri.conf.json's version
//   node scripts/bump-version.mjs 0.3.1    # set it everywhere (npm run bump -- 0.3.1)
// Updates: tauri.conf.json, package.json, every Cargo.toml [package] version, Cargo.lock, and the
// "morpheus-certificate-install X.Y.Z" stamp at the top of each source/doc file.
// Leaves reference/python (frozen 0.2.1), fixtures, CHANGELOG.md and vendor/ alone.
import { readFileSync, writeFileSync, readdirSync, statSync } from "node:fs";
import { join, dirname, relative } from "node:path";
import { execSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const SEMVER = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
const arg = process.argv[2];
if (arg && !SEMVER.test(arg)) { console.error(`bump-version: "${arg}" is not semver`); process.exit(1); }

const confPath = join(root, "src-tauri", "tauri.conf.json");
const TOP = /^(  "version":\s*")([^"]*)(")/m;
let conf = readFileSync(confPath, "utf8");
const version = arg ?? JSON.parse(conf).version;
const changed = [];
const write = (p, before, after) => { if (before !== after) { writeFileSync(p, after); changed.push(relative(root, p)); } };

write(confPath, conf, conf.replace(TOP, `$1${version}$3`));
const pkg = join(root, "package.json");
write(pkg, readFileSync(pkg, "utf8"), readFileSync(pkg, "utf8").replace(TOP, `$1${version}$3`));

const SKIP = new Set(["node_modules", "target", ".git", "reference", "fixtures", "vendor", "gen", "dist-portable"]);
const EXT = /\.(rs|toml|mjs|js|cjs|html|md|json|yml|sh|svg|py|xml)$/;
// Files without an extension that carry the stamp (tests/fake-appliance).
const NAMES = new Set(["keytool", "morpheus-ctl", "rotate-host-keys"]);
// A prerelease is dot-separated identifiers; a "." after the version is the sentence's full stop.
const STAMP = /morpheus-certificate-install \d+\.\d+\.\d+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?/;
function walk(dir) {
  for (const name of readdirSync(dir)) {
    if (SKIP.has(name)) continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) { walk(p); continue; }
    if (!(EXT.test(name) || NAMES.has(name)) || name === "CHANGELOG.md" || p === confPath || p === pkg) continue;
    const before = readFileSync(p, "utf8");
    let after = before;
    // first stamp only (the header line), so prose mentioning other versions survives
    after = after.replace(STAMP, `morpheus-certificate-install ${version}`);
    if (name === "Cargo.toml") after = after.replace(/^version = "[^"]*"/m, `version = "${version}"`);
    write(p, before, after);
  }
}
walk(root);
console.log(`version ${version}: ${changed.length} file(s) updated`);
for (const c of changed) console.log(`  ${c}`);
// Cargo.lock records the workspace crates' versions; CI builds with --locked, so refresh those entries
// now (only the workspace members; no dependency changes, no network). 0.4.0-rc1.
try {
  execSync("cargo update --workspace --offline", { cwd: root, stdio: ["ignore", "ignore", "pipe"] });
  console.log("  Cargo.lock (workspace members)");
} catch (e) {
  console.error(`bump-version: cargo update --workspace --offline failed (${String(e.stderr || e.message).trim()}). Run it by hand before building with --locked.`);
  process.exit(1);
}
console.log("Now add a CHANGELOG.md entry.");
