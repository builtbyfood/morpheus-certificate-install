#!/usr/bin/env node
// morpheus-certificate-install 0.4.2 — every relative link in every published .md file must resolve.
//   npm run check-links            (CI runs it in the `test` job)
//   node scripts/check-links.mjs --self-test
//
// Checked: Markdown links and images `[t](x)` / `![a](x)` (with an optional "title"), reference
// definitions `[t]: x`, and HTML `href="x"` / `src="x"`. Code blocks and `inline code` are skipped.
// - External links (`https:`, `mailto:` …) aren't fetched.
// - A relative target (relative to the file, or to the repository root when it starts with "/") must
//   be a PUBLISHED file, or a folder holding one (publishedFiles() in tracked-files.mjs). A link to a
//   local-only file (listed in .local-only) therefore fails although the file exists here.
// - `#anchor` (alone, or after a .md target) must match a heading there, slugged as GitHub does:
//   lower case, punctuation dropped, spaces to "-", repeats numbered -1, -2 …
// reference/python/ is the frozen Python 0.2.1 (its README describes that project's own layout), so
// it isn't checked. Exit 1 listing file:line → target and why, for every broken link.
import { readFileSync } from "node:fs";
import { dirname, join, posix } from "node:path";
import { fileURLToPath } from "node:url";
import { publishedFiles } from "./tracked-files.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const SKIP = (f) => f.startsWith("reference/python/");

/** GitHub's heading anchor for a heading's text. */
export function slug(text) {
  return text
    .replace(/!?\[([^\]]*)\]\([^)]*\)/g, "$1") // links → their text
    .replace(/<[^>]+>/g, "")                   // inline HTML tags
    .replace(/[`*_~]/g, (c) => (c === "_" ? "_" : "")) // emphasis and code marks (GitHub keeps "_")
    .trim().toLowerCase()
    .replace(/[^\p{L}\p{N}\s_-]/gu, "")
    .replace(/\s/g, "-");
}

/** Lines outside fenced code blocks, with inline code blanked out; [lineNo, text]. */
function proseLines(text) {
  const out = [];
  let fence = null;
  text.split(/\r?\n/).forEach((line, i) => {
    const m = line.match(/^\s*(`{3,}|~{3,})/);
    if (m) { if (!fence) fence = m[1][0]; else if (m[1][0] === fence) fence = null; return; }
    if (fence) return;
    out.push([i + 1, line.replace(/`+[^`]*`+/g, (s) => " ".repeat(s.length))]);
  });
  return out;
}

export function anchorsOf(text) {
  const seen = new Map(), out = new Set();
  for (const [, line] of proseLines(text)) {
    const m = line.match(/^\s{0,3}#{1,6}\s+(.*?)\s*#*\s*$/);
    if (!m) continue;
    const base = slug(m[1]);
    const n = seen.get(base) ?? 0;
    seen.set(base, n + 1);
    out.add(n ? `${base}-${n}` : base);
  }
  // explicit anchors: <a name="x"> / id="x"
  for (const m of text.matchAll(/<a\s+(?:name|id)="([^"]+)"/g)) out.add(m[1]);
  return out;
}

export function linksOf(text) {
  const out = [];
  for (const [n, line] of proseLines(text)) {
    for (const m of line.matchAll(/!?\[(?:[^\]\[]|\[[^\]]*\])*\]\(\s*<?([^)\s>]+)>?(?:\s+"[^"]*")?\s*\)/g)) out.push([n, m[1]]);
    const def = line.match(/^\s{0,3}\[[^\]]+\]:\s*<?(\S+?)>?(?:\s+"[^"]*")?\s*$/);
    if (def) out.push([n, def[1]]);
    for (const m of line.matchAll(/\s(?:href|src)="([^"]+)"/g)) out.push([n, m[1]]);
  }
  return out;
}

export function check(files, read) {
  const set = new Set(files);
  const dirs = new Set();
  for (const f of files) { let d = posix.dirname(f); while (d !== ".") { dirs.add(d); d = posix.dirname(d); } }
  const anchors = new Map();
  const anchorsFor = (f) => { if (!anchors.has(f)) anchors.set(f, anchorsOf(read(f))); return anchors.get(f); };
  const bad = [];
  for (const f of files.filter((x) => x.endsWith(".md") && !SKIP(x))) {
    for (const [line, raw] of linksOf(read(f))) {
      if (/^[a-z][a-z0-9+.-]*:/i.test(raw)) continue; // https:, mailto:, …
      const [pathPart, anchor] = raw.split("#", 2);
      let target = f;
      if (pathPart) {
        let p;
        try { p = decodeURIComponent(pathPart); } catch { p = pathPart; }
        target = p.startsWith("/") ? posix.normalize(p.slice(1)) : posix.normalize(posix.join(posix.dirname(f), p));
        target = target.replace(/\/$/, "");
        if (target.startsWith("..")) { bad.push(`${f}:${line} → ${raw}: points outside the repository`); continue; }
        if (!set.has(target) && !dirs.has(target)) { bad.push(`${f}:${line} → ${raw}: ${target} isn't in the published tree`); continue; }
      }
      if (anchor && target.endsWith(".md") && set.has(target) && !anchorsFor(target).has(anchor.toLowerCase())) {
        bad.push(`${f}:${line} → ${raw}: no heading "#${anchor}" in ${target}`);
      }
    }
  }
  return bad;
}

function selfTest() {
  const docs = {
    "README.md": "# Title\n## Quick start: convert only\n## macOS\n## macOS\nSee [a](docs/A.md#the-b-section), [b](#quick-start-convert-only), [c](#macos-1), ![i](docs/shot.png), [d](docs/), [e](https://example.com), [f](/LICENSE)\n```\n[not checked](nowhere.md)\n```\n`[inline](nowhere.md)`\n",
    "docs/A.md": "# A\n## The **B** section\n[up](../README.md#title) [bad](../NOTES.md) [gone](missing.md) [anchor](#nope) [out](../../x.md)\n<img src=\"shot.png\"> <a href=\"../NOTICE\">n</a>\n[ref]: ./A.md#a\n",
    "docs/shot.png": "", "LICENSE": "", "NOTICE": "",
  };
  const bad = check(Object.keys(docs), (f) => docs[f]);
  const want = [
    "docs/A.md:3 → ../NOTES.md: NOTES.md isn't in the published tree",
    "docs/A.md:3 → missing.md: docs/missing.md isn't in the published tree",
    "docs/A.md:3 → #nope: no heading \"#nope\" in docs/A.md",
    "docs/A.md:3 → ../../x.md: points outside the repository",
  ];
  // Not reported, because they resolve: README's anchors (including the repeated "macOS" heading's
  // "-1"), the image, the folder link, the root-relative /LICENSE, A.md's <img src="shot.png"> and
  // <a href="../NOTICE">, the reference definition, and everything inside code.
  const missing = want.filter((w) => !bad.includes(w)), unexpected = bad.filter((b) => !want.includes(b));
  if (missing.length || unexpected.length) {
    console.error("check-links self-test FAILED");
    for (const m of missing) console.error("  not reported: " + m);
    for (const u of unexpected) console.error("  wrongly reported: " + u);
    process.exit(1);
  }
  console.log(`check-links self-test: OK (${want.length} broken links found, nothing else)`);
  process.exit(0);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  if (process.argv.includes("--self-test")) selfTest();
  const files = publishedFiles(root);
  const bad = check(files, (f) => readFileSync(join(root, f), "utf8"));
  const n = files.filter((x) => x.endsWith(".md") && !SKIP(x)).length;
  if (bad.length) {
    console.error(`check-links: ${bad.length} broken link(s) in ${n} Markdown files:`);
    for (const b of bad) console.error("  " + b);
    process.exit(1);
  }
  console.log(`check-links: every relative link resolves (${n} Markdown files, published tree only).`);
}
