// morpheus-certificate-install 0.4.2 — a wildcard certificate with no connection: the FQDN is
// required, and export stays blocked until a name the certificate covers is entered (PARITY 27).
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { CORPUS, freshFolder, launch, listDir, zipNames } from "../lib/app.mjs";
import { eq, ok } from "../lib/assert.mjs";

const NEED_FQDN = "Wildcard certificate: enter the appliance's FQDN.";

export default {
  name: "wildcard",
  async run({ say }) {
    const f = freshFolder("wildcard");
    const p = await launch(f);
    const errors = () => p.eval(`[...document.querySelectorAll("#chainOut p.msg.error")].map((e) => e.textContent)`);
    const exportShown = () => p.visible("#btnExport");
    try {
      await p.setFiles("#fileIn", [join(CORPUS, "leaf-wildcard.crt"), join(CORPUS, "leaf-wildcard.key"), join(CORPUS, "wildcard-root.crt")]);
      await p.click("#btnAnalyze");
      await p.waitFor(`document.querySelectorAll("#chainOut .chain .link").length > 0`, 15000, "the chain view");
      eq(await p.text("#chainOut .chain .link .cn"), "*.wild.test", "the leaf is the wildcard");
      ok((await errors()).includes(NEED_FQDN), `the FQDN is asked for: ${JSON.stringify(await errors())}`);
      eq(await exportShown(), false, "export blocked without an FQDN");
      eq(await p.eval(`document.getElementById("s2").classList.contains("done")`), false, "step 2 not done");
      say("no FQDN: asked for, export blocked");

      // The wildcard itself isn't a name.
      await p.type("#fqdn", "*.wild.test");
      await p.click("#btnAnalyze");
      await p.waitFor(`[...document.querySelectorAll("#chainOut p.msg.error")].some((e) => e.textContent === ${JSON.stringify(NEED_FQDN)})`, 10000, "the FQDN request again");
      eq(await exportShown(), false, "export blocked for *.wild.test");

      // A name the certificate doesn't cover: still blocked.
      await p.type("#fqdn", "morpheus.example.com");
      await p.click("#btnAnalyze");
      await p.waitFor(`!document.querySelector("#chainOut p.msg.error") || ![...document.querySelectorAll("#chainOut p.msg.error")].some((e) => e.textContent === ${JSON.stringify(NEED_FQDN)})`, 10000, "a new check");
      const uncovered = await errors();
      ok(uncovered.length > 0, "an uncovered name is an error");
      eq(await exportShown(), false, `export blocked for an uncovered name (${uncovered.join(" | ")})`);
      say(`uncovered name: ${uncovered.join(" | ")}`);

      // A covered name: fine, and it's what the files are named after.
      await p.type("#fqdn", "morpheus.wild.test");
      await p.click("#btnAnalyze");
      await p.waitFor(`document.getElementById("s2").classList.contains("done")`, 10000, "step 2 done");
      eq(await errors(), [], "no errors with a covered name");
      eq(await exportShown(), true, "export offered");
      ok(/morpheus_wild_test\.crt/.test(await p.text("#chainOut")), "the files on the appliance are named after it");
      await p.click("#btnExport");
      await p.waitFor(`/^Saved /.test(document.getElementById("convOut").textContent)`, 15000, "the Saved message");
      eq(listDir(f.saveDir), ["morpheus_wild_test-morpheus.zip"], "the zip is named after the FQDN");
      const names = zipNames(readFileSync(join(f.saveDir, "morpheus_wild_test-morpheus.zip"))).map((e) => e.name);
      ok(names.includes("morpheus_wild_test-morpheus/morpheus_wild_test.crt") && names.includes("morpheus_wild_test-morpheus/morpheus_wild_test.key"), `zip entries: ${names.join(", ")}`);
      say("morpheus.wild.test: export works, files named morpheus_wild_test.*");
    } finally { await p.kill(); }
  },
};
