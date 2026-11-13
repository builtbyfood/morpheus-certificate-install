// morpheus-certificate-install 0.4.0 — the files a clone of the repository would hold: everything
// under the root except .git and what .gitignore excludes (the simple patterns this repo uses:
// names, `dir/`, `*.ext`, `path/with/slash` anchored at the root). Used by check-private.mjs and
// fresh-clone-check.mjs (this folder isn't a git checkout, so `git ls-files` isn't available).
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";

export function ignoreRules(root) {
  const lines = readFileSync(join(root, ".gitignore"), "utf8").split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
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

/** Repo-relative paths (forward slashes) of every tracked file. `skip(rel)` drops more. */
export function trackedFiles(root, skip = () => false) {
  const ignored = ignoreRules(root);
  const out = [];
  const walk = (dir) => {
    for (const name of readdirSync(dir)) {
      const p = join(dir, name);
      const rel = relative(root, p).split(sep).join("/");
      if (name === ".git" || skip(rel)) continue;
      const isDir = statSync(p).isDirectory();
      if (ignored(rel, isDir)) continue;
      if (isDir) walk(p); else out.push(rel);
    }
  };
  walk(root);
  return out;
}
