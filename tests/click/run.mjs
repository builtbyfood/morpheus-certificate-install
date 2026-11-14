#!/usr/bin/env node
// morpheus-certificate-install 0.4.1 — click tests: the real app (debug build), driven over CDP.
//   npm run test:click                       every suite (fake-VM ones skip without MCI_TEST_SSH)
//   npm run test:click -- convert wildcard   only these suites (names or name prefixes)
//   MCI_TEST_SSH=<vm>:2222:mcitest:hunter2 npm run test:click
// Windows only for now (WebView2's CDP). Plain Node 22+, no browser download. See tests/click/README.md.
//
// Environment:
//   MCI_TEST_SSH        the fake appliance (docs/FAKE-APPLIANCE.md); without it the VM suites skip.
//   MCI_CLICK_NO_BUILD  =1: don't run `cargo build` first (use target/debug as it is).
//   MCI_CLICK_KEEP      =1: keep the temp folders (the suites' portable folders) for a look afterwards.
import { execSync } from "node:child_process";
import { readdirSync } from "node:fs";
import { join } from "node:path";
import { ROOT, RUN_ROOT, launched, rmrf } from "./lib/app.mjs";

if (process.platform !== "win32") {
  console.error("test:click drives WebView2 over CDP and runs on Windows only (Linux: see tests/click/README.md).");
  process.exit(2);
}
if (!process.env.MCI_CLICK_NO_BUILD) {
  console.log("> cargo build -p morpheus-certificate-install");
  execSync("cargo build -p morpheus-certificate-install", { cwd: ROOT, stdio: "inherit" });
}

const dir = join(import.meta.dirname, "suites");
const all = [];
for (const f of readdirSync(dir).filter((f) => f.endsWith(".mjs")).sort()) {
  const m = await import(`./suites/${f}`);
  all.push({ file: f, ...m.default });
}
const want = process.argv.slice(2);
const suites = want.length ? all.filter((s) => want.some((w) => s.name === w || s.name.startsWith(w))) : all.filter((s) => !s.optIn);
if (!suites.length) { console.error(`no suite matches ${want.join(" ")}; suites: ${all.map((s) => s.name).join(", ")}`); process.exit(2); }

if (process.env.MCI_TEST_SSH && suites.some((s) => s.needsVm)) {
  const { buildRef } = await import("./lib/vm.mjs");
  console.log("> cargo test --test click_ref --no-run   (the reference connection to the fake VM)");
  buildRef();
}

const results = [];
for (const s of suites) {
  if (s.needsVm && !process.env.MCI_TEST_SSH) { results.push([s.name, "skip", "MCI_TEST_SSH not set"]); console.log(`\n── ${s.name}: skipped (MCI_TEST_SSH not set)`); continue; }
  console.log(`\n── ${s.name}${s.needsVm ? " (fake VM)" : ""}`);
  const t0 = Date.now();
  const say = (m) => console.log(`   ${m}`);
  try {
    launched.length = 0;
    await s.run({ say });
    const errs = [...new Set(launched.flatMap((p) => p.browserErrors).map((e) => e.slice(0, 240)))];
    if (errs.length) throw new Error(`the page logged ${errs.length} browser error(s) (a CSP violation, an uncaught exception):\n     ${errs.join("\n     ")}`);
    results.push([s.name, "pass", `${((Date.now() - t0) / 1000).toFixed(1)} s`]);
    console.log(`   PASS (${((Date.now() - t0) / 1000).toFixed(1)} s)`);
  } catch (e) {
    results.push([s.name, "FAIL", e.message.split("\n")[0]]);
    console.log(`   FAIL: ${e.stack || e.message}`);
  }
}
if (!process.env.MCI_CLICK_KEEP) await rmrf(RUN_ROOT).catch((e) => console.log(`(couldn't remove ${RUN_ROOT}: ${e.message})`));
console.log("\nsummary:");
for (const [n, r, d] of results) console.log(`  ${r.padEnd(4)}  ${n.padEnd(22)} ${d}`);
process.exit(results.some(([, r]) => r === "FAIL") ? 1 : 0);
