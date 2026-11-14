// morpheus-certificate-install 0.4.1 — "Clean up this appliance" from the page, with its
// defaults, while a run is still going: a runner-shaped run that sleeps (started over the
// reference connection) keeps its script and log; finished runs go; the newest backup stays.
import { freshFolder, launch } from "../lib/app.mjs";
import { eq, ok } from "../lib/assert.mjs";
import { connectSsh } from "../lib/flows.mjs";
import { LOG_DIR, RUN_DIR, inventory, ref, removeSleepingRun, startSleepingRun, target } from "../lib/vm.mjs";

const SLEEP_S = 75;

export default {
  name: "vm-cleanup",
  needsVm: true,
  async run({ say }) {
    const tg = target();
    // A finished run for certain (any from vm-install count too): script, log and .rc, two hours old.
    const done = `click-done-${Date.now()}`;
    ref(`set -e; mkdir -p ${RUN_DIR} ${LOG_DIR}; printf '#!/bin/bash\\ntrue\\n' > ${RUN_DIR}/${done}.sh; chmod 0700 ${RUN_DIR}/${done}.sh
echo finished > ${LOG_DIR}/${done}.log; echo 0 > ${LOG_DIR}/${done}.rc; chmod 0600 ${LOG_DIR}/${done}.log ${LOG_DIR}/${done}.rc
touch -d '2 hours ago' ${RUN_DIR}/${done}.sh ${LOG_DIR}/${done}.log ${LOG_DIR}/${done}.rc`);
    const sleeper = startSleepingRun(SLEEP_S);
    const t0 = Date.now();
    say(`planted finished run ${done}; started ${sleeper} (sleeps ${SLEEP_S} s)`);
    const before = inventory();
    const f = freshFolder("vm-cleanup");
    const p = await launch(f);
    try {
      await connectSsh(p, tg, { say });
      await p.click("#btnCleanup");
      await p.waitFor(`document.getElementById("btnCleanGo")`, 60000, "the cleanup list");
      const rows = await p.eval(`[...document.querySelectorAll("#runsOut table.list tr")].map((tr) => tr.cells[0].textContent)`);
      const row = (name) => rows.find((r) => r.includes(`/${name}`)) || "";
      for (const n of [`${sleeper}.sh`, `${sleeper}.log`]) ok(/\(a run that may still be going: kept\)/.test(row(n)), `${n} is listed as still going: ${row(n)}`);
      ok(row(`${done}.sh`) && !/may still be going/.test(row(`${done}.sh`)), "the finished run is listed, not as running");
      eq([await p.checked("#clRuns"), await p.checked("#clOld"), await p.checked("#clAll")], [true, true, false], "the defaults: runs and old backups on, all backups off");
      say(`listed ${rows.length} item(s); the sleeper is marked "still going"`);

      await p.click("#btnCleanGo");
      const d = await p.dialog(/^Clean up this appliance\?$/);
      const listed = await p.eval(`[...document.querySelectorAll("#dlgBody ul.cleanList li code")].map((c) => c.textContent)`);
      ok(!listed.some((x) => x.includes(sleeper)), `the running run isn't in the confirm list: ${listed.join(", ")}`);
      for (const x of [`${RUN_DIR}/${done}.sh`, `${LOG_DIR}/${done}.log`, `${LOG_DIR}/${done}.rc`]) ok(listed.includes(x), `${x} is in the confirm list`);
      ok(/Exactly these \d+ item\(s\)/.test(d.body), "the dialog counts the items");
      eq(d.ok, "Remove them", "the dialog's button");
      const m = await p.mark();
      await p.dialogOk();
      const job = await p.waitJob("cleanup", m, 300000);
      eq(job.status, "done", `cleanup: ${job.error || ""}`);
      eq(job.result.ok, true, "cleanup finished cleanly");
      await p.waitLog(/✓ Cleaned up: \d+ item\(s\) removed\./, 10000);
      const elapsed = (Date.now() - t0) / 1000;
      ok(elapsed < SLEEP_S, `cleanup ran while the sleeper was still going (${elapsed.toFixed(0)} s < ${SLEEP_S} s)`);

      // On the VM: the sleeper's files stay, every finished run's go, the newest backup stays.
      const still = ref(`test -e ${RUN_DIR}/${sleeper}.sh && test -e ${LOG_DIR}/${sleeper}.log && test ! -e ${LOG_DIR}/${sleeper}.rc && echo kept`).stdout;
      eq(still.trim(), "kept", "the running run's script and log survive (and it's still running)");
      const after = inventory();
      eq(after.runs, [`${sleeper}.sh`], "only the running run's script is left");
      eq(after.logs, [`${sleeper}.log`], "only the running run's log is left");
      const newest = before.backups.slice().sort().pop();
      if (newest) eq(after.backups, [newest], "only the newest backup is left");
      say(`removed ${before.runs.length - 1} finished script(s), ${before.logs.length - 1} log file(s), ${Math.max(0, before.backups.length - 1)} backup(s); kept ${sleeper} and ${newest || "no backup"}`);

      // Listing again: the sleeper is still there, still marked.
      await p.click("#btnCleanup");
      await p.waitFor(`document.getElementById("btnCleanGo") && [...document.querySelectorAll("#runsOut table.list tr")].some((tr) => tr.textContent.includes(${JSON.stringify(sleeper)}))`, 60000, "the second listing");
      const again = await p.eval(`[...document.querySelectorAll("#runsOut table.list tr")].filter((tr) => tr.textContent.includes(${JSON.stringify(sleeper)})).map((tr) => tr.cells[0].textContent)`);
      ok(again.length === 2 && again.every((r) => /may still be going: kept/.test(r)), `listed again as still going: ${again.join(" | ")}`);
    } finally {
      await p.kill();
      removeSleepingRun(sleeper);
      ref(`rm -f ${RUN_DIR}/${done}.sh ${LOG_DIR}/${done}.log ${LOG_DIR}/${done}.rc; true`);
    }
  },
};
