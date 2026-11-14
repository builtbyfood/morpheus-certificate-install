#!/usr/bin/env node
// morpheus-certificate-install 0.4.1 — .gitattributes covers every file in the published tree.
//   npm run check-gitattributes             the rules, read here (fast; also run by export-tree)
//   node scripts/check-gitattributes.mjs --git   the same files committed by real git in a temp repository
//                                            with core.autocrlf=true (Git for Windows' default), and
//                                            `git ls-files --eol` checked: every text file stored LF
//
// A file is text when it has no NUL byte and is valid UTF-8; otherwise binary. For each published file:
// - text: it needs an explicit `text eol=lf` line (the `* text=auto eol=lf` default doesn't count, so
//   a new kind of text file fails until it gets its own line), unless it's byte-exact (`-text`, the
//   fixtures); and it must not contain CR (what's committed is what's in the folder);
// - binary: it must not be marked `text`.
// Patterns understood: `*`, `?`, `**`, a name without "/" (matched at any depth), and a path with "/"
// (from the root). The last matching line wins, per attribute, as in git. `binary` = -text -diff -merge.
import { execFileSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { publishedFiles } from "./tracked-files.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

function globRe(p) {
  let re = "";
  for (let i = 0; i < p.length; i++) {
    const c = p[i];
    if (c === "*" && p[i + 1] === "*") { re += ".*"; i++; if (p[i + 1] === "/") i++; }
    else if (c === "*") re += "[^/]*";
    else if (c === "?") re += "[^/]";
    else re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp("^" + re + "$");
}

export function parseAttributes(text) {
  const rules = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const [pat, ...attrs] = line.split(/\s+/);
    const set = {};
    for (const a of attrs) {
      if (a === "binary") { set.text = "unset"; continue; }
      if (a === "text") set.text = "set";
      else if (a === "-text") set.text = "unset";
      else if (a === "text=auto") set.text = "auto";
      else if (a.startsWith("eol=")) set.eol = a.slice(4);
    }
    const anchored = pat.includes("/");
    rules.push({ pat, re: globRe(pat.replace(/^\//, "")), anchored, set });
  }
  return rules;
}

/** {text, eol, textFrom}: the attributes git would give `rel`, and the pattern that set `text`. */
export function attributesFor(rules, rel) {
  const out = {};
  const name = rel.split("/").pop();
  for (const r of rules) {
    if (!(r.anchored ? r.re.test(rel) : r.re.test(name))) continue;
    if (r.set.text) { out.text = r.set.text; out.textFrom = r.pat; }
    if (r.set.eol) out.eol = r.set.eol;
  }
  return out;
}

const isText = (buf) => {
  if (buf.includes(0)) return false;
  try { new TextDecoder("utf-8", { fatal: true }).decode(buf); return true; } catch { return false; }
};

/** Check `files` (relative, forward slashes) under `dir` against `dir`'s .gitattributes. */
export function checkAttributes(dir, files) {
  const rules = parseAttributes(readFileSync(join(dir, ".gitattributes"), "utf8"));
  const problems = [];
  let text = 0, exact = 0, binary = 0;
  for (const f of files) {
    const buf = readFileSync(join(dir, f));
    const a = attributesFor(rules, f);
    if (!isText(buf)) {
      binary++;
      if (a.text === "set") problems.push(`${f}: binary, but marked text by "${a.textFrom}" (git would rewrite its bytes)`);
      continue;
    }
    if (a.text === "unset") { exact++; continue; }
    text++;
    if (a.text !== "set" || a.eol !== "lf") {
      problems.push(`${f}: text, but no explicit "text eol=lf" line covers it (it gets text=${a.text ?? "unset"}${a.eol ? " eol=" + a.eol : ""} from "${a.textFrom ?? "nothing"}"); add a line for its type to .gitattributes`);
    } else if (buf.includes(13)) {
      problems.push(`${f}: contains CR (CRLF line endings); convert it to LF`);
    }
  }
  return { problems, text, exact, binary };
}

/** Real git: commit `files` from `dir` in a temp repo with core.autocrlf=true; every text-attr file must be stored LF. */
export function checkWithGit(dir, files) {
  const tmp = mkdtempSync(join(tmpdir(), "mci-gitattr-"));
  try {
    for (const f of files) { mkdirSync(dirname(join(tmp, f)), { recursive: true }); cpSync(join(dir, f), join(tmp, f)); }
    const git = (...a) => execFileSync("git", ["-c", "core.autocrlf=true", "-c", "core.safecrlf=false", ...a], { cwd: tmp, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    git("init", "-q", "-b", "main");
    git("add", "-A");
    const problems = [];
    const rows = git("ls-files", "--eol").trim().split("\n");
    for (const row of rows) {
      const m = row.match(/^i\/(\S*)\s+w\/(\S*)\s+attr\/(.*?)\s*\t(.*)$/);
      if (!m) { problems.push(`unparsed: ${row}`); continue; }
      const [, idx, , attr, f] = m;
      if (attr.includes("-text")) continue;          // byte-exact or binary: stored as is
      if (idx === "crlf" || idx === "mixed") problems.push(`${f}: git stores it with ${idx} line endings (attr: ${attr || "none"})`);
    }
    if (rows.length !== files.length) problems.push(`git staged ${rows.length} files, expected ${files.length}`);
    return { problems, staged: rows.length };
  } finally { rmSync(tmp, { recursive: true, force: true }); }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const files = publishedFiles(root);
  const r = checkAttributes(root, files);
  if (r.problems.length) {
    console.error(`check-gitattributes: ${r.problems.length} problem(s):`);
    for (const p of r.problems) console.error("  " + p);
    process.exit(1);
  }
  console.log(`check-gitattributes: OK (${r.text} text files with an explicit "text eol=lf", ${r.exact} byte-exact, ${r.binary} binary)`);
  if (process.argv.includes("--git")) {
    const g = checkWithGit(root, files);
    if (g.problems.length) {
      console.error(`check-gitattributes --git: ${g.problems.length} problem(s):`);
      for (const p of g.problems) console.error("  " + p);
      process.exit(1);
    }
    console.log(`check-gitattributes --git: OK (git with core.autocrlf=true staged ${g.staged} files; every text file stored LF)`);
  }
}
