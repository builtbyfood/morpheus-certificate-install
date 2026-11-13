#!/usr/bin/env node
// morpheus-certificate-install 0.4.0 — copy the tracked tree into a publish folder
// (docs/RELEASE-CHECKLIST.md). `npm run export-tree -- <folder>`
//   - the folder doesn't exist or is empty: the tracked files are copied in;
//   - the folder is a git checkout (has .git): everything in it except .git is deleted first, then the
//     tracked files are copied in, so `git add -A` there records added, changed and removed files alike.
// Anything else (a non-empty folder without .git) is refused. "Tracked" is scripts/tracked-files.mjs:
// everything .gitignore doesn't exclude, minus the local .private-denylist and .cargo/config.toml.
import { cpSync, existsSync, mkdirSync, readdirSync, rmSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { trackedFiles } from "./tracked-files.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const arg = process.argv[2];
if (!arg) { console.error("usage: npm run export-tree -- <folder>"); process.exit(64); }
const dest = resolve(arg);
if (dest === resolve(root) || dest.startsWith(resolve(root) + (process.platform === "win32" ? "\\" : "/"))) {
  console.error(`export-tree: ${dest} is inside this working folder. Choose a folder outside it.`);
  process.exit(64);
}
if (existsSync(dest)) {
  const entries = readdirSync(dest);
  if (entries.length && !entries.includes(".git")) {
    console.error(`export-tree: ${dest} is not empty and isn't a git checkout. Choose a new folder, or the publish folder made earlier.`);
    process.exit(1);
  }
  for (const e of entries) if (e !== ".git") rmSync(join(dest, e), { recursive: true, force: true });
} else {
  mkdirSync(dest, { recursive: true });
}
const files = trackedFiles(root, (rel) => rel === ".private-denylist" || rel === ".cargo/config.toml");
for (const rel of files) {
  mkdirSync(dirname(join(dest, rel)), { recursive: true });
  cpSync(join(root, rel), join(dest, rel));
}
console.log(`export-tree: ${files.length} tracked files copied to ${dest}`);
