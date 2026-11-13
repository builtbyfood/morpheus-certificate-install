#!/usr/bin/env node
// morpheus-certificate-install 0.4.0 — smoke-test the portable build (npm run portable-smoke).
// Run `npm run portable` first. Windows: dist-portable/…-windows-portable.zip; Linux: the tar.gz.
//
//  1. Unpack it into a new temp folder.
//  2. Start the GUI exe with a CDP port (WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS on Windows) and check
//     the page loads and shows this version.
//  3. Check data/ and data/webview/ appear beside the exe, and that nothing is written to the
//     per-user folders the installed app would use: no new entry at the top of %APPDATA% and
//     %LOCALAPPDATA% (Linux: ~/.config, ~/.local/share), and nothing changed inside the installed
//     app's folders (%APPDATA%\morpheus-certificate-install, %LOCALAPPDATA%\<identifier>).
//  4. Close the window (WM_CLOSE) and wait for the exit.
//  5. Run the CLI from the folder: --version, and one convert of corpus files.
// Linux has no CDP in webkit2gtk: there step 2 only waits for data/ to appear (needs a display).
import { execFileSync, spawn } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const win = process.platform === "win32";
const conf = JSON.parse(readFileSync(join(root, "src-tauri", "tauri.conf.json"), "utf8"));
const version = conf.version, identifier = conf.identifier;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const fail = (m) => { console.error(`portable-smoke: FAIL: ${m}`); process.exit(1); };
const ok = (m) => console.log(`  ok  ${m}`);

const dist = join(root, "dist-portable");
const archive = existsSync(dist) && readdirSync(dist).find((f) => win ? f.endsWith("-windows-portable.zip") : /-linux-portable-.*\.tar\.gz$/.test(f));
if (!archive) fail(`no portable archive in ${dist}; run npm run portable first`);

// ---- 1. unpack
const dir = mkdtempSync(join(tmpdir(), "mci-portable-smoke-"));
if (win) execFileSync("powershell", ["-NoProfile", "-Command", `Expand-Archive -LiteralPath '${join(dist, archive)}' -DestinationPath '${dir}'`]);
else execFileSync("tar", ["-xzf", join(dist, archive), "-C", dir]);
const app = existsSync(join(dir, "morpheus-certificate-install", "portable.flag")) ? join(dir, "morpheus-certificate-install") : dir;
const exe = join(app, win ? "morpheus-certificate-install.exe" : "morpheus-certificate-install");
const cli = join(app, win ? "morpheus-certificate-install-cli.exe" : "morpheus-certificate-install-cli");
for (const f of [exe, cli, join(app, "portable.flag")]) if (!existsSync(f)) fail(`${f} missing from ${archive}`);
ok(`${archive}: ${readdirSync(app).join(", ")}`);
if (existsSync(join(app, "data"))) fail("the archive already holds a data/ folder");

// ---- the per-user folders, before
const userRoots = win ? [process.env.APPDATA, process.env.LOCALAPPDATA] : [join(homedir(), ".config"), join(homedir(), ".local", "share")];
const appDirs = win ? [join(process.env.APPDATA, "morpheus-certificate-install"), join(process.env.LOCALAPPDATA, identifier)]
  : [join(homedir(), ".config", "morpheus-certificate-install"), join(homedir(), ".local", "share", identifier), join(homedir(), ".config", identifier)];
function snapshot() {
  const s = new Map();
  for (const r of userRoots) for (const n of readdirSync(r)) s.set(join(r, n), "top");
  const walk = (p) => { let st; try { st = statSync(p); } catch { return; } if (st.isDirectory()) { for (const n of readdirSync(p)) walk(join(p, n)); } else s.set(p, `${st.size}:${st.mtimeMs}`); };
  for (const d of appDirs) walk(d);
  return s;
}
const before = snapshot();

// ---- 2. start it
const port = 9390;
const proc = spawn(exe, [], { cwd: app, env: { ...process.env, WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS: `--remote-debugging-port=${port}` }, stdio: "ignore" });
const exited = new Promise((r) => proc.on("exit", r));
try {
  if (win) {
    const { Cdp, findPage } = await import(pathToFileURL(join(root, "tests", "click", "lib", "cdp.mjs")).href);
    const page = await findPage(port, 30000);
    const cdp = await Cdp.connect(page.webSocketDebuggerUrl);
    let shown = "";
    for (let i = 0; i < 60 && shown !== `v${version}`; i++) { shown = await cdp.eval(`(document.getElementById("ver") || {}).textContent || ""`).catch(() => ""); await sleep(250); }
    if (shown !== `v${version}`) fail(`the page shows ${JSON.stringify(shown)}, not v${version}`);
    const portable = await cdp.eval(`api("/api/state").then((s) => s.portable)`);
    if (portable !== true) fail("the app doesn't report portable mode");
    ok(`the page loaded: ${await cdp.eval("document.title")} ${shown}, portable mode`);
    cdp.close();
  }
  for (let i = 0; i < 80 && !existsSync(join(app, "data", "webview")); i++) await sleep(250);
  if (!existsSync(join(app, "data", "webview"))) fail("data/webview didn't appear beside the exe");
  ok(`data/ beside the exe: ${readdirSync(join(app, "data")).join(", ")}`);

  // ---- 3. nothing in the per-user folders
  const after = snapshot();
  const changed = [...after].filter(([k, v]) => before.get(k) !== v).map(([k]) => k);
  if (changed.length) fail(`written outside the portable folder:\n    ${changed.join("\n    ")}`);
  ok(`nothing new or changed in ${userRoots.join(" or ")} (${appDirs.length} app folders checked)`);
} finally {
  // ---- 4. close it
  if (win) {
    try {
      execFileSync("powershell", ["-NoProfile", "-NonInteractive", "-Command", `
        Add-Type -Namespace Mci -Name W -MemberDefinition '[DllImport("user32.dll")] public static extern bool PostMessage(System.IntPtr h, uint m, System.IntPtr w, System.IntPtr l);';
        $h = (Get-Process -Id ${proc.pid}).MainWindowHandle; [void][Mci.W]::PostMessage($h, 0x0010, [System.IntPtr]::Zero, [System.IntPtr]::Zero)`]);
    } catch { proc.kill(); }
  } else proc.kill("SIGTERM");
  const code = await Promise.race([exited, sleep(20000).then(() => "timeout")]);
  if (code === "timeout") { proc.kill(); fail("the app didn't exit after its window closed"); }
  ok(`closed; exit code ${code}`);
}

// ---- 5. the CLI
const v = execFileSync(cli, ["--version"], { encoding: "utf8" }).trim();
if (v !== `morpheus-certificate-install-cli ${version}`) fail(`cli --version printed ${JSON.stringify(v)}`);
ok(`cli --version: ${v}`);
const out = join(dir, "converted");
const c = join(root, "fixtures", "corpus");
execFileSync(cli, ["convert", join(c, "chain.p7b"), join(c, "leaf-pkcs1.key"), "--out", out], { encoding: "utf8" });
const files = readdirSync(out).sort();
for (const f of ["m_cust_test.crt", "m_cust_test.key", "INSTALL.txt"]) if (!files.includes(f)) fail(`convert didn't write ${f}: ${files.join(", ")}`);
ok(`cli convert chain.p7b + leaf-pkcs1.key: ${files.join(", ")}`);

await sleep(1000);
try { rmSync(dir, { recursive: true, force: true }); } catch (e) { console.log(`(couldn't remove ${dir}: ${e.message})`); }
console.log("portable-smoke: OK");
