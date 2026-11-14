#!/usr/bin/env node
// morpheus-certificate-install 0.4.1 — does a fresh clone build? (npm run fresh-clone-check)
// Copies the tracked files (scripts/tracked-files.mjs: no target/, node_modules/, .cargo/config.toml,
// generated icons or other gitignored files) to a new temp folder, then runs there what a fresh
// checkout needs, as README → Build says:
//   npm ci
//   npx tauri icon src-tauri/icons/icon.svg      (the generated icons are gitignored)
//   cargo build --locked --workspace
// with its own CARGO_TARGET_DIR inside the temp folder. The first build compiles everything (several
// minutes). The temp folder is removed afterwards unless --keep. Exit 1 if any step fails.
import { execSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { publishedFiles } from "./tracked-files.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const keep = process.argv.includes("--keep");
const dir = mkdtempSync(join(tmpdir(), "mci-fresh-clone-"));
const files = publishedFiles(root);
for (const rel of files) {
  mkdirSync(dirname(join(dir, rel)), { recursive: true });
  cpSync(join(root, rel), join(dir, rel));
}
console.log(`fresh-clone-check: ${files.length} tracked files copied to ${dir}`);
for (const p of ["target", "node_modules", ".cargo/config.toml", "src-tauri/icons/icon.ico"]) {
  if (existsSync(join(dir, p))) { console.error(`fresh-clone-check: ${p} was copied; it's not part of a clone`); process.exit(1); }
}

const env = { ...process.env, CARGO_TARGET_DIR: join(dir, "target") };
let failed = null;
for (const cmd of ["npm ci", "npx tauri icon src-tauri/icons/icon.svg", "cargo build --locked --workspace"]) {
  console.log(`\n> ${cmd}`);
  try { execSync(cmd, { cwd: dir, env, stdio: "inherit" }); } catch (e) { failed = `${cmd} (exit ${e.status})`; break; }
}
if (!keep) {
  try { rmSync(dir, { recursive: true, force: true }); } catch (e) { console.log(`(couldn't remove ${dir}: ${e.message})`); }
}
if (failed) { console.error(`\nfresh-clone-check: FAILED at ${failed}`); process.exit(1); }
console.log("\nfresh-clone-check: OK (npm ci, icons, cargo build --locked --workspace)");
