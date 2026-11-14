// morpheus-certificate-install 0.4.1 — the README's screenshots, from the real app against the
// fake VM, at a fixed size (1320×860 CSS px, the app's default window; light theme), with corpus
// certificates only. Opt-in (it rewrites docs/screenshots/): npm run test:click -- screenshots
//
// Real names never reach a PNG: just before each capture, the VM's address, its hostname, this
// computer's name and user, and every literal .private-denylist entry are swapped for example
// names in the page's text (Page.mask), and put back right after. Before writing, the page's
// visible text is checked against every denylist entry (regexes too); any hit and nothing is
// written. The PNGs themselves aren't OCR'd. File names are plain (check-private reads them).
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { hostname, userInfo } from "node:os";
import { join } from "node:path";
import { ROOT, freshFolder, launch } from "../lib/app.mjs";
import { eq, ok } from "../lib/assert.mjs";
import { connectSsh, loadCorpusChain } from "../lib/flows.mjs";
import { resetAppliance, target } from "../lib/vm.mjs";

const W = 1320, H = 860;
const OUT = join(ROOT, "docs", "screenshots");

function denylist() {
  const p = join(ROOT, ".private-denylist");
  if (!existsSync(p)) throw new Error("screenshots need .private-denylist (see .private-denylist.example): it's how they're checked for real names");
  return readFileSync(p, "utf8").split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#")).map((l) => {
    if (l.startsWith("re:")) return { literal: null, re: new RegExp(l.slice(3), "g") };
    const lit = l.startsWith("i:") ? l.slice(2) : l;
    return { literal: l.startsWith("i:") ? null : lit, re: new RegExp(lit.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), l.startsWith("i:") ? "gi" : "g") };
  });
}

export default {
  name: "screenshots",
  needsVm: true,
  optIn: true,
  async run({ say }) {
    const tg = target();
    const deny = denylist();
    resetAppliance();
    mkdirSync(OUT, { recursive: true });
    const f = freshFolder("screenshots");
    const p = await launch(f);
    let pairs = [];
    const shot = async (name) => {
      await p.setViewport(W, H);
      const unmask = await p.mask(pairs);
      try {
        const text = await p.allText();
        const hits = deny.filter((d) => { d.re.lastIndex = 0; return d.re.test(text); }).length + pairs.filter(([from]) => text.includes(from)).length;
        ok(hits === 0, `${name}: ${hits} private string(s) still visible after masking; nothing written`);
        writeFileSync(join(OUT, `${name}.png`), await p.capture());
        say(`docs/screenshots/${name}.png`);
      } finally { await unmask(); }
    };
    try {
      await connectSsh(p, tg);
      const st = await p.eval(`api("/api/state")`);
      const vmName = String(st.facts?.host || "");
      // Longest first, so a full name is replaced before a part of it.
      pairs = [[tg.host, "192.0.2.10"], ...(vmName ? [[vmName, "appliance.example.com"]] : []), [hostname(), "workstation"], [userInfo().username, "operator"],
        ...deny.filter((d) => d.literal).map((d) => [d.literal, "redacted"])]
        .filter(([from]) => from && from.length > 2).sort((a, b) => b[0].length - a[0].length);
      await shot("connect");

      await loadCorpusChain(p);
      await p.type("#vAddr", tg.host);
      await p.eval(`(document.querySelector("#chainOut details") || {}).open = false, true`);
      // Typing in step 4's address field scrolled the page there; the chain (its seals) is in step 2
      // (0.4.0: chain.png showed steps 3–5 until now).
      await p.eval(`document.activeElement && document.activeElement.blur(), document.getElementById("chainOut").scrollIntoView({block: "center"}), true`);
      await p.waitFor(`(() => { const r = document.querySelector("#chainOut .chain").getBoundingClientRect(); return r.top >= 0 && r.bottom <= innerHeight; })()`, 5000, "the chain in view");
      await shot("chain");

      await p.click("#btnPlan");
      await p.waitFor(`document.querySelectorAll("#planOut ol.plan li").length > 0`, 15000, "the plan");
      await p.eval(`document.getElementById("s3").scrollIntoView({block: "start"}), true`);
      await shot("plan");

      const m = await p.mark();
      await p.click("#btnApply");
      await p.dialog(/^Install on /);
      await p.dialogOk();
      await p.waitFor(`!document.getElementById("watch").hidden && document.querySelectorAll("#tracker span").length >= 2`, 60000, "the run under way");
      await shot("run");
      const job = await p.waitJob("apply", m, 300000);
      eq(job.status, "done", `apply: ${job.error || ""}`);

      const mv = await p.mark();
      await p.click("#btnVerify");
      await p.waitJob("verify", mv, 120000);
      await p.waitFor(`document.getElementById("s4").classList.contains("done")`, 10000, "verify green");
      await p.eval(`document.getElementById("s4").scrollIntoView({block: "start"}), true`);
      await shot("verify");

      // Leave the VM as it was: roll back to this install's backup, then the cleanup list.
      await p.click("#btnBackups");
      await p.waitFor(`document.querySelectorAll("#runsOut button[data-id]").length > 0`, 30000, "the backups");
      const id = await p.eval(`[...document.querySelectorAll("#runsOut tr")].filter((tr) => /before installing m\\.cust\\.test/.test(tr.textContent)).map((tr) => tr.querySelector("button").dataset.id).sort().pop()`);
      const mr = await p.mark();
      await p.click(`#runsOut button[data-id="${id}"]`);
      await p.dialog(/^Roll back\?$/);
      await p.dialogOk();
      eq((await p.waitJob("rollback", mr, 300000)).status, "done", "rollback");
      await p.click("#btnCleanup");
      await p.waitFor(`document.getElementById("btnCleanGo")`, 60000, "the cleanup list");
      await p.eval(`document.getElementById("s5").scrollIntoView({block: "start"}), true`);
      await shot("cleanup");
      // And clean up for real (defaults), so the VM doesn't collect the screenshots' runs.
      const mc = await p.mark();
      await p.click("#btnCleanGo");
      await p.dialog(/^Clean up this appliance\?$/);
      await p.dialogOk();
      eq((await p.waitJob("cleanup", mc, 300000)).status, "done", "cleanup");
    } finally { await p.kill(); }
  },
};
