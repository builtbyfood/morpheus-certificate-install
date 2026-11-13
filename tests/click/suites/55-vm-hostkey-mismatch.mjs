// morpheus-certificate-install 0.4.0 — a changed host key is refused, from the page. The VM's
// key is NOT rotated: this suite's known_hosts is pre-seeded with wrong keys for the VM (one per
// key type), so the real key looks changed. No dialog may offer to trust it.
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { freshFolder, launch, sleep } from "../lib/app.mjs";
import { eq, ok } from "../lib/assert.mjs";
import { wrongKeyLines } from "../lib/hostkey.mjs";
import { target } from "../lib/vm.mjs";

export default {
  name: "vm-hostkey-mismatch",
  needsVm: true,
  async run({ say }) {
    const tg = target();
    const f = freshFolder("vm-hostkey-mismatch");
    mkdirSync(f.dataDir, { recursive: true });
    const kh = join(f.dataDir, "known_hosts");
    writeFileSync(kh, wrongKeyLines(tg.host, tg.port));
    const seeded = readFileSync(kh);
    const p = await launch(f);
    try {
      await p.type("#host", tg.host);
      await p.type("#port", String(tg.port));
      await p.type("#user", tg.user);
      await p.type("#password", tg.password);
      for (let attempt = 1; attempt <= 2; attempt++) {
        const m = await p.toastMark();
        await p.click("#btnConnect");
        const t = await p.toast(/CHANGED/, m, 30000);
        ok(t.startsWith(`The host key for ${tg.host}`) && /won't connect/.test(t), `the refusal says what happened: ${t}`);
        ok(/click "Forget this appliance" and connect again\.$/.test(t), `the refusal says what to do (0.3.20: it named a known_hosts path the app doesn't use): ${t}`);
        eq(await p.eval(`document.getElementById("dlg").open`), false, "no dialog offers to trust the changed key");
        eq(await p.text("#chipText"), "Not connected", "still not connected");
        eq(await p.eval(`document.getElementById("btnPreflight").disabled`), true, "the appliance check stays disabled");
        if (attempt === 1) say(`refused: "${t}"`);
        await sleep(300);
      }
      eq(readFileSync(kh).equals(seeded), true, "known_hosts is left exactly as it was");
      ok(!(await p.eval(`window.__clickEvents.some((e) => e.type === "connected")`)), "no connected event");
      say("asked twice: refused both times, known_hosts unchanged");

      // What the message says to do: Forget this appliance, then Connect asks about the key afresh.
      await p.click("#btnForget");
      const fd = await p.dialog(/^Forget this appliance\?$/);
      ok(fd.body.includes(`${tg.host}:${tg.port}`), `the forget dialog names the appliance: ${fd.body}`);
      let m = await p.toastMark();
      await p.dialogOk();
      const ft = await p.toast(/^Forgot /, m);
      eq(ft, `Forgot ${tg.host}: 3 host key line(s) and its saved settings removed.`, "all three wrong lines removed");
      ok(!/\[.*\]:\d+ ssh-/.test(readFileSync(kh, "utf8")), "no key for the VM left in known_hosts");
      // Forget empties the form; fill it again and connect: now it's a first connection.
      await p.type("#host", tg.host);
      await p.type("#port", String(tg.port));
      await p.type("#user", tg.user);
      await p.type("#password", tg.password);
      await p.click("#btnConnect");
      const d = await p.dialog(/^New host key$/);
      ok(/SHA256:/.test(d.body), "the TOFU dialog shows the real key's fingerprint");
      await p.click(`#dlg button[value=cancel]`);
      await p.waitFor(`!document.getElementById("dlg").open`, 5000, "the dialog to close");
      await sleep(500);
      eq(await p.text("#chipText"), "Not connected", "cancelled: not connected");
      say("Forget this appliance → Connect asks about the key as a first connection (cancelled)");
    } finally { await p.kill(); }
  },
};
