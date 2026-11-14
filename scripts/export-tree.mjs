#!/usr/bin/env node
// morpheus-certificate-install 0.4.1 — copy the published tree into a publish folder
// (docs/RELEASE-CHECKLIST.md).
//   npm run export-tree -- <folder>   copy, then verify (the manifest check below)
//   npm run export-tree -- --list     print the published file list, one path per line (forward
//                                     slashes, sorted), to compare with `git ls-files` there
// The folder:
//   - doesn't exist or is empty: the files are copied in;
//   - is a git checkout (has .git): everything in it except .git is deleted first, then the files are
//     copied in, so `git add -A` there records added, changed and removed files alike.
// Anything else (a non-empty folder without .git) is refused. "Published" is publishedFiles() in
// tracked-files.mjs: everything the .gitignore files don't exclude, minus the local .private-denylist,
// .cargo/config.toml and LOCAL_ONLY.
//
// Manifest check (0.4.1): after copying, every file in the folder (except .git) is listed and compared
// with the published list, and each file's bytes with the source. Any file missing, extra or different
// fails the export with the list, so nothing that should be public can go missing without a failure.
// Then (0.4.1) the exported folder's own Markdown links are checked (scripts/check-links.mjs, reading
// the exported files, not the dev folder's), and its .gitattributes against its files
// (scripts/check-gitattributes.mjs). Any broken relative link or uncovered text file fails the export.
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { publishedFiles } from "./tracked-files.mjs";
import { check as checkLinks } from "./check-links.mjs";
import { checkAttributes } from "./check-gitattributes.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const arg = process.argv[2];
if (arg === "--list") {
  process.stdout.write(publishedFiles(root).join("\n") + "\n");
  process.exit(0);
}
if (!arg) { console.error("usage: npm run export-tree -- <folder>   |   npm run export-tree -- --list"); process.exit(64); }
const dest = resolve(arg);
if (dest === resolve(root) || dest.startsWith(resolve(root) + (process.platform === "win32" ? "\\" : "/"))) {
  console.error(`export-tree: ${dest} is inside this working folder. Choose a folder outside it.`);
  process.exit(64);
}
if (existsSync(dest)) {
  const entries = readdirSync(dest);
  if (entries.length && !entries.includes(".git")) {
    console.error(`export-tree: ${dest} is not empty and isn't a git checkout. Choose a new folder, or a clone of the repository.`);
    process.exit(1);
  }
  for (const e of entries) if (e !== ".git") rmSync(join(dest, e), { recursive: true, force: true });
} else {
  mkdirSync(dest, { recursive: true });
}
const files = publishedFiles(root);
for (const rel of files) {
  mkdirSync(dirname(join(dest, rel)), { recursive: true });
  cpSync(join(root, rel), join(dest, rel));
}

// ---- manifest check
const present = [];
const walk = (dir) => {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (dir === dest && e.name === ".git") continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) walk(p); else present.push(relative(dest, p).split(sep).join("/"));
  }
};
walk(dest);
const want = new Set(files), have = new Set(present);
const missing = files.filter((f) => !have.has(f));
const extra = present.filter((f) => !want.has(f)).sort();
const differ = files.filter((f) => have.has(f) && !readFileSync(join(root, f)).equals(readFileSync(join(dest, f))));
if (missing.length || extra.length || differ.length) {
  console.error(`export-tree: the folder doesn't match the published list (${files.length} files):`);
  for (const f of missing) console.error(`  missing:   ${f}`);
  for (const f of extra) console.error(`  extra:     ${f}`);
  for (const f of differ) console.error(`  different: ${f}`);
  console.error("Nothing is committed by this script; fix the cause and export again before `git add`.");
  process.exit(1);
}
const broken = checkLinks(present.sort(), (f) => readFileSync(join(dest, f), "utf8"));
if (broken.length) {
  console.error(`export-tree: ${broken.length} broken link(s) in the exported Markdown:`);
  for (const b of broken) console.error("  " + b);
  process.exit(1);
}
const attr = checkAttributes(dest, present);
if (attr.problems.length) {
  console.error(`export-tree: .gitattributes doesn't cover the exported files:`);
  for (const b of attr.problems) console.error("  " + b);
  process.exit(1);
}
console.log(`export-tree: ${files.length} files copied to ${dest}; manifest check OK (every file present, none extra, all identical)`);
console.log(`export-tree: links OK (every relative link in the exported Markdown resolves); .gitattributes OK (${attr.text} text files LF, ${attr.exact} kept byte-exact, ${attr.binary} binary)`);
console.log("After `git add -A` there, compare git's list with this one (docs/RELEASE-CHECKLIST.md, \"The file list\").");
