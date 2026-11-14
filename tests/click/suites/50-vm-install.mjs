// morpheus-certificate-install 0.4.2 — the whole install, clicked in the page against the fake
// VM: connect with the TOFU dialog → plan → install → verify green → rollback. The VM is put in
// its starting state first (tests/click/lib/vm.mjs) and checked over the reference connection.
import { freshFolder, launch, listDir } from "../lib/app.mjs";
import { eq, ok, match } from "../lib/assert.mjs";
import { connectSsh, loadCorpusChain } from "../lib/flows.mjs";
import { inventory, ref, resetAppliance, target } from "../lib/vm.mjs";

export default {
  name: "vm-install",
  needsVm: true,
  async run({ say }) {
    const tg = target();
    resetAppliance();
    const servedBefore = ref(`openssl x509 -noout -fingerprint -sha256 -in /etc/morpheus/ssl/appliance.crt`).stdout.trim();
    const f = freshFolder("vm-install");
    const p = await launch(f);
    try {
      eq(await p.visible("#watch"), false, "watch bar hidden before any run");
      await connectSsh(p, tg, { say });
      ok((listDir(f.dataDir) || []).includes("known_hosts"), "the confirmed key is saved in this suite's data/known_hosts");
      await loadCorpusChain(p);
      eq(await p.visible("#watch"), false, "connected and loaded, still no run: watch bar hidden");

      // Plan: defaults (serve the certificate; private CA → trust it and restart morpheus-ui).
      eq([await p.checked("#optServer"), await p.checked("#optTrust"), await p.checked("#optUi")], [true, true, true], "the plan's defaults for a private CA");
      await p.click("#btnPlan");
      await p.waitFor(`document.querySelectorAll("#planOut ol.plan li").length > 0`, 15000, "the plan");
      const steps = await p.eval(`[...document.querySelectorAll("#planOut ol.plan li")].map((li) => li.dataset.id)`);
      ok(steps.includes("verify") && steps.length >= 4, `plan steps: ${steps.join(", ")}`);
      ok(/ssl_certificate/.test(await p.text("#planOut .diff")), "the morpheus.rb diff is shown");
      say(`plan: ${steps.join(" → ")}`);

      // Install, confirmed in the dialog.
      const m = await p.mark();
      await p.click("#btnApply");
      const d = await p.dialog(/^Install on /);
      ok(/A backup is taken first/.test(d.body), "the install dialog mentions the backup");
      await p.dialogOk();
      await p.waitFor(`!document.getElementById("watch").hidden`, 60000, "the watch bar once the run starts");
      match(await p.text("#watchCmd"), /tail|morpheus-certificate-install/, "the watch command");
      const job = await p.waitJob("apply", m, 300000);
      eq(job.status, "done", `apply: ${job.error || ""}`);
      eq(job.result.ok, true, "the install finished cleanly");
      await p.waitLog(/✓ Certificate installed\./, 10000);
      ok(await p.eval(`document.getElementById("s3").classList.contains("done")`), "step 3 marked done");
      eq(await p.count("#planOut #btnApply"), 0, "the Install button is gone after the run");
      const st = await p.eval(`Object.fromEntries([...document.querySelectorAll("#planOut ol.plan li")].map((li) => [li.dataset.id, li.dataset.status || ""]))`);
      say(`installed; plan steps: ${JSON.stringify(st)}; run ${job.result.run_id || ""}`);
      const servedNow = ref(`echo | openssl s_client -connect 127.0.0.1:443 -servername m.cust.test 2>/dev/null | openssl x509 -noout -subject`).stdout;
      match(servedNow, /m\.cust\.test/, "the VM serves the new certificate");

      // Verify from here, to the VM's address.
      await p.type("#vAddr", tg.host);
      const mv = await p.mark();
      await p.click("#btnVerify");
      const vj = await p.waitJob("verify", mv, 120000);
      eq(vj.status, "done", `verify: ${vj.error || ""}`);
      await p.waitFor(`document.querySelectorAll("#verifyOut p.msg").length >= 2`, 10000, "the verify result");
      const v = await p.eval(`[...document.querySelectorAll("#verifyOut p.msg")].map((e) => ({cls: e.className, text: e.textContent}))`);
      ok(v.every((x) => x.cls === "msg ok"), `verify is green: ${JSON.stringify(v)}`);
      ok(/the new certificate\./.test(v[0].text), "the appliance serves the new certificate");
      ok(await p.eval(`document.getElementById("s4").classList.contains("done")`), "step 4 marked done");
      say(`verify: ${v.map((x) => x.text).join(" | ")}`);

      // Roll back to the backup this install took.
      await p.click("#btnBackups");
      await p.waitFor(`document.querySelectorAll("#runsOut table.list tr").length > 0`, 30000, "the backups list");
      const backups = await p.eval(`[...document.querySelectorAll("#runsOut table.list tr")].map((tr) => ({id: tr.querySelector("b").textContent, note: tr.querySelector("small").textContent}))`);
      const mine = backups.filter((b) => /before installing m\.cust\.test/.test(b.note)).map((b) => b.id).sort().pop();
      ok(mine, `a backup from this install: ${JSON.stringify(backups)}`);
      const mr = await p.mark();
      eq(await p.text(`#runsOut button[data-id="${mine}"]`), "Roll back to this", "each backup has its button");
      await p.click(`#runsOut button[data-id="${mine}"]`);
      const rd = await p.dialog(/^Roll back\?$/);
      ok(rd.body.includes(mine), `the rollback dialog names ${mine}: ${rd.body}`);
      await p.dialogOk();
      const rj = await p.waitJob("rollback", mr, 300000);
      eq(rj.status, "done", `rollback: ${rj.error || ""}`);
      eq(rj.result.ok, true, "the rollback finished cleanly");
      await p.waitLog(/✓ Rolled back\./, 10000);
      const after = ref(`echo | openssl s_client -connect 127.0.0.1:443 2>/dev/null | openssl x509 -noout -fingerprint -sha256; test ! -e /etc/morpheus/ssl/m_cust_test.key && echo key-gone`).stdout;
      ok(after.includes(servedBefore.split("=").pop()), `the starting certificate is served again: ${after}`);
      ok(after.includes("key-gone"), "the installed key is gone after rollback");
      say(`rolled back to ${mine}; the starting certificate is served again`);

      // Verify again: the page now says the appliance doesn't serve the certificate loaded in step 2.
      const mv2 = await p.mark();
      await p.click("#btnVerify");
      await p.waitJob("verify", mv2, 120000);
      await p.waitFor(`/not the certificate loaded in step 2/.test(document.getElementById("verifyOut").textContent)`, 10000, "verify after rollback");
      const inv = inventory();
      say(`on the VM now: ${inv.runs.length} runner script(s), ${inv.logs.length} log file(s), ${inv.backups.length} backup(s)`);
    } finally { await p.kill(); }
  },
};
