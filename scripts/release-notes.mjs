#!/usr/bin/env node
// morpheus-certificate-install 0.4.0 — print CHANGELOG.md's section for one version (the release
// notes). `node scripts/release-notes.mjs 0.4.0` (or v0.4.0). Exit 1 if the section is missing.
// The notes stop at the next "## " heading, or earlier at a line `<!-- end of release notes -->`, below
// which a section can keep notes for the maintainers (0.4.0-rc1).
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const v = (process.argv[2] || "").replace(/^v/, "");
if (!/^\d+\.\d+\.\d+/.test(v)) { console.error("usage: release-notes.mjs <version>"); process.exit(64); }
const text = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "CHANGELOG.md"), "utf8");
const lines = text.split(/\r?\n/);
const start = lines.findIndex((l) => l.startsWith(`## ${v} `) || l === `## ${v}`);
if (start < 0) { console.error(`release-notes: CHANGELOG.md has no "## ${v}" section`); process.exit(1); }
let end = lines.findIndex((l, i) => i > start && (l.startsWith("## ") || l.trim() === "<!-- end of release notes -->"));
if (end < 0) end = lines.length;
console.log(lines.slice(start + 1, end).join("\n").trim());
