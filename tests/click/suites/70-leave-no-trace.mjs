// morpheus-certificate-install 0.4.2 — portable "Leave no trace" at a real exit. The debug exe
// runs from a temp portable folder; the window is closed the way the user closes it (WM_CLOSE).
//  1. Turned on (and, with MCI_TEST_SSH, connected, so known_hosts is written): data/ is gone
//     after the exit.
//  2. data/ can't be deleted at exit (a file in it held open, no sharing): it stays with a
//     marker; the next start deletes it before the webview starts, and says so.
import { spawn } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { freshFolder, launch, listDir, sleep } from "../lib/app.mjs";
import { eq, ok } from "../lib/assert.mjs";
import { connectSsh } from "../lib/flows.mjs";
import { target } from "../lib/vm.mjs";

const MARKER = ".leave-no-trace-incomplete";

async function turnOn(p, f) {
  eq(await p.visible("#lntRow"), true, "Leave no trace is offered in portable mode");
  eq(await p.checked("#optLnt"), false, "off by default");
  const m = await p.toastMark();
  await p.click("#optLnt");
  const t = await p.toast(/^Leave no trace:/, m);
  ok(t.includes(f.dataDir) && /deleted when the app closes/.test(t), `the toast names the folder: ${t}`);
}

/** Hold `file` open with no sharing (so it can't be deleted) until the returned function is called. */
async function holdOpen(file) {
  const ps = spawn("powershell", ["-NoProfile", "-NonInteractive", "-Command",
    `$f = [System.IO.File]::Open('${file.replace(/'/g, "''")}', 'OpenOrCreate', 'ReadWrite', 'None'); Write-Output held; [Console]::In.ReadLine() | Out-Null; $f.Close()`], { stdio: ["pipe", "pipe", "inherit"] });
  await new Promise((res, rej) => { ps.stdout.on("data", (d) => /held/.test(d) && res()); ps.on("exit", (c) => rej(new Error(`holder exited ${c}`))); });
  return async () => { ps.stdin.end("\n"); await new Promise((r) => ps.on("exit", r)); };
}

export default {
  name: "leave-no-trace",
  async run({ say }) {
    // ---- 1: a normal exit deletes data/
    const f = freshFolder("leave-no-trace");
    let p = await launch(f);
    await turnOn(p, f);
    if (process.env.MCI_TEST_SSH) {
      const tg = target();
      await connectSsh(p, tg, { say });
      ok(existsSync(join(f.dataDir, "known_hosts")), "connecting wrote data/known_hosts");
      const s = existsSync(join(f.dataDir, "settings.json")) ? readFileSync(join(f.dataDir, "settings.json"), "utf8") : "";
      ok(!s.includes(tg.host), `nothing about the appliance went into settings while it's on: ${s}`);
    } else say("MCI_TEST_SSH not set: not connecting (known_hosts isn't written)");
    ok(existsSync(join(f.dataDir, "webview")), "the webview profile is in data/webview");
    say(`before closing, data/ holds: ${listDir(f.dataDir).join(", ")}`);
    const code = await p.closeWindow();
    eq(code, 0, "the app exits cleanly after its window closes");
    eq(listDir(f.dataDir), null, "data/ is gone after the exit");
    eq(listDir(f.appDir).sort(), [f.exe.split(/[\\/]/).pop(), "portable.flag"].sort(), "only the exe and portable.flag are left beside it");
    say("closed: data/ deleted, nothing else left");

    // ---- 2: data/ held open at exit → the next start deletes it and says so
    const g = freshFolder("leave-no-trace-held");
    p = await launch(g);
    await turnOn(p, g);
    const held = join(g.dataDir, "held-open.txt");
    const release = await holdOpen(held);
    let code2;
    try { code2 = await p.closeWindow(); } catch (e) { await release(); throw e; }
    eq(code2, 0, "the app still exits cleanly");
    ok(existsSync(join(g.dataDir, MARKER)), `data/ is left with the marker: ${listDir(g.dataDir)}`);
    say(`exit couldn't delete data/: marker says "${readFileSync(join(g.dataDir, MARKER), "utf8").trim()}"`);
    await release();
    await sleep(300);
    p = await launch(g);
    try {
      const t = await p.toast(/^Leave no trace: the last session's data folder/, 0, 15000);
      ok(t.includes(g.dataDir) && /It has been deleted now\.$/.test(t), `the start says it deleted the folder: ${t}`);
      ok(!existsSync(join(g.dataDir, MARKER)) && !existsSync(held), "the marker and the held file are gone");
      eq(await p.checked("#optLnt"), false, "Leave no trace starts off again");
      say(`next start: "${t}"`);
    } finally { await p.kill(); }
  },
};
