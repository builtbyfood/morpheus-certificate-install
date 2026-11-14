// morpheus-certificate-install 0.4.2 — the files a clone of the repository would hold: everything
// under the root except .git and what the .gitignore files exclude. Used by check-private.mjs,
// fresh-clone-check.mjs, export-tree.mjs and check-links.mjs (this folder isn't a git checkout, so
// `git ls-files` isn't available).
//
// Patterns: the simple ones this repo uses — names, `dir/`, `*.ext`, `?`, and `path/with/slash`
// anchored at the .gitignore's own folder. Every .gitignore counts, not just the root one (0.4.1: a
// tool's own `.gitignore` containing `*`, like reference/python/.pytest_cache/, hides its folder, as
// git does; before, those cache files were exported and git then left them out). Negation (`!`) and
// `**` aren't supported, and a .gitignore using them is refused, so a rule can't be misread silently.
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";

/** The rules of one .gitignore, as a test on a path relative to that file's folder. */
function rulesOf(file) {
  const lines = readFileSync(file, "utf8").split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
  for (const l of lines) {
    if (l.startsWith("!") || l.includes("**")) throw new Error(`${file}: "${l}" uses ! or **, which scripts/tracked-files.mjs doesn't support`);
  }
  const globRe = (g) => new RegExp("^" + g.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, "[^/]*").replace(/\?/g, "[^/]") + "$");
  const rules = lines.map((p) => {
    const dirOnly = p.endsWith("/");
    const pat = p.replace(/\/$/, "");
    return { re: globRe(pat.replace(/^\//, "")), dirOnly, anchored: pat.includes("/") };
  });
  return (rel, isDir) => {
    const name = rel.split("/").pop();
    return rules.some((r) => (!r.dirOnly || isDir) && (r.anchored ? r.re.test(rel) : r.re.test(name)));
  };
}

/** The root .gitignore's rules (paths relative to the root). */
export function ignoreRules(root) {
  return rulesOf(join(root, ".gitignore"));
}

/** Repo-relative paths (forward slashes) of every tracked file. `skip(rel)` drops more. */
export function trackedFiles(root, skip = () => false) {
  const out = [];
  // `scopes`: the .gitignore files in effect, each with the folder (relative to root) it sits in.
  const walk = (dir, scopes) => {
    const here = relative(root, dir).split(sep).join("/");
    const gi = join(dir, ".gitignore");
    const own = existsSync(gi) ? [...scopes, { base: here, test: rulesOf(gi) }] : scopes;
    for (const name of readdirSync(dir)) {
      const p = join(dir, name);
      const rel = relative(root, p).split(sep).join("/");
      if (name === ".git" || skip(rel)) continue;
      const isDir = statSync(p).isDirectory();
      const ignored = own.some(({ base, test }) => test(base ? rel.slice(base.length + 1) : rel, isDir));
      if (ignored) continue;
      if (isDir) walk(p, own); else out.push(rel);
    }
  };
  walk(root, []);
  return out.sort();
}

/** The maintainer's notes kept in the development folder but never published are listed, one path
 *  per line (# comments allowed), in the gitignored `.local-only` file at the root, beside
 *  `.private-denylist`. An entry is a file path, or a folder path ending in "/". A clone of the
 *  repository has no such file, and nothing to leave out. check-private still scans these files;
 *  check-links fails on any published link to them. export-tree refuses to run without the list. */
export const LOCAL_ONLY_FILE = ".local-only";
export function localOnlyList(root) {
  const f = join(root, LOCAL_ONLY_FILE);
  if (!existsSync(f)) return [];
  return readFileSync(f, "utf8").split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
}

/** The files that go into the published repository: tracked, minus the local-only list, the
 *  private-strings list and a machine-specific cargo config. Sorted, forward slashes. */
export function publishedFiles(root) {
  const list = localOnlyList(root);
  const localOnly = (rel) => list.some((p) => (p.endsWith("/") ? rel.startsWith(p) : rel === p));
  return trackedFiles(root, (rel) => rel === ".private-denylist" || rel === LOCAL_ONLY_FILE || rel === ".cargo/config.toml" || localOnly(rel) || localOnly(rel + "/"));
}
