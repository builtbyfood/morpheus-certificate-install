// morpheus-certificate-install 0.4.0 — errors: empty input and a rejected command show toasts; a bad
// PFX password shows inline on the file's row (as in the Python page). The watch bar stays hidden
// until a run starts (here: never, no appliance).
import { join } from "node:path";
import { CORPUS, freshFolder, launch } from "../lib/app.mjs";
import { eq, ok } from "../lib/assert.mjs";

export default {
  name: "errors-and-watch",
  async run({ say }) {
    const f = freshFolder("errors-and-watch");
    const p = await launch(f);
    try {
      eq(await p.visible("#watch"), false, "watch bar hidden at start");
      eq(await p.eval(`document.getElementById("watch").hidden`), true, "watch bar [hidden] at start");

      // Nothing loaded.
      let m = await p.toastMark();
      await p.click("#btnAnalyze");
      const t1 = await p.toast(/./, m);
      eq(t1, "Add the certificate files or paste the PEM text first.", "empty input → toast");
      say(`empty input: "${t1}"`);

      // A PFX with the wrong password: analyze succeeds and reports it per file, as the Python page
      // does — on the file's row in the input table and as an error check, not as a toast.
      await p.setFiles("#fileIn", [join(CORPUS, "modern.pfx")]);
      await p.type("#pfxPw", "not-the-password");
      await p.click("#btnAnalyze");
      await p.waitFor(`document.querySelector("#chainOut table.inputs tr")`, 15000, "the input table");
      const row = await p.eval(`(() => { const r = document.querySelector("#chainOut table.inputs tr"); return {cls: r.className, name: r.cells[0].textContent, what: r.cells[1].textContent}; })()`);
      eq([row.cls, row.name], ["error", "modern.pfx"], "the PFX's row is in error");
      ok(/Wrong or missing PFX password\./.test(row.what), `the row says why: ${row.what}`);
      const errs = await p.eval(`[...document.querySelectorAll("#chainOut p.msg.error")].map((e) => e.textContent)`);
      ok(errs.includes("modern.pfx: Wrong or missing PFX password."), `an error check names the file: ${errs.join(" | ")}`);
      eq(await p.count("#chainOut .chain .link"), 0, "no chain shown");
      eq(await p.visible("#btnExport"), false, "nothing to export");
      say(`bad PFX password: inline, "${row.what}"`);

      // A rejected command surfaces as a toast: plan without a valid certificate.
      m = await p.toastMark();
      await p.click("#btnPlan");
      const t3 = await p.toast(/./, m);
      eq(t3, "Load a valid certificate first (the Certificate step shows what's wrong).", "plan without a valid certificate → toast");
      say(`plan without a certificate: "${t3}"`);

      eq(await p.visible("#watch"), false, "watch bar still hidden: no run has started");
    } finally { await p.kill(); }
  },
};
