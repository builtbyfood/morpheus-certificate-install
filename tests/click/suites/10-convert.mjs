// morpheus-certificate-install 0.4.2 — convert only, no appliance: corpus chain.p7b + leaf-pkcs1.key.
// Seals, the input table, the Trust default and its reason, and the exported zip's file list.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { CORPUS, freshFolder, launch, listDir, zipNames } from "../lib/app.mjs";
import { eq, ok } from "../lib/assert.mjs";

const PRIVATE = "Private CA: Morpheus' Java won't trust it until it's imported.";

export default {
  name: "convert",
  async run({ say }) {
    const f = freshFolder("convert");
    const p = await launch(f);
    try {
      eq(await p.text("#chipText"), "Not connected", "starts disconnected");
      eq(await p.visible("#convBtns"), false, "no export button before a check");
      await p.setFiles("#fileIn", [join(CORPUS, "chain.p7b"), join(CORPUS, "leaf-pkcs1.key")]);
      await p.click("#btnAnalyze");
      await p.waitFor(`document.querySelectorAll("#chainOut .chain .link").length > 0`, 15000, "the chain view");

      // Seals: server → intermediate → root, each with its seal and lifetime bar.
      const links = await p.eval(`[...document.querySelectorAll("#chainOut .chain .link")].map((l) => ({cn: l.querySelector(".cn").textContent, role: l.querySelector(".role").textContent, seal: !!l.querySelector(".seal svg"), life: !!l.querySelector(".life i"), exp: l.querySelector(".exp").textContent}))`);
      eq(links.map((l) => l.role), ["server", "intermediate", "root"], "three links in order");
      eq(links[0].cn, "m.cust.test", "the leaf's CN");
      ok(links.every((l) => l.seal && l.life && /days left$/.test(l.exp)), `every link has a seal, a lifetime bar and days left: ${JSON.stringify(links)}`);
      eq(await p.eval(`document.querySelector("#chainOut .chain").classList.contains("many")`), false, "three links: full-size seals");
      say(`chain: ${links.map((l) => `${l.cn} (${l.role})`).join(" → ")}`);

      // Styles the page sets inline take effect (0.3.20: Tauri's style-src nonce had blocked them all):
      // each lifetime bar is as wide as its style says, and the Run log has its terminal theme's colours.
      const bars = await p.eval(`[...document.querySelectorAll("#chainOut .life i")].map((i) => ({want: parseFloat(i.style.width), got: 100 * i.getBoundingClientRect().width / i.parentElement.getBoundingClientRect().width}))`);
      ok(bars.length === 3 && bars.every((b) => Math.abs(b.want - b.got) < 2), `lifetime bars follow their width: ${JSON.stringify(bars)}`);
      ok(bars.some((b) => b.want < 100), `at least one bar shows time used: ${JSON.stringify(bars)}`);
      eq(await p.eval(`getComputedStyle(document.querySelector("#xtRun .xterm-rows")).color`), "rgb(215, 221, 231)", "the Run log uses its theme's foreground (#d7dde7), not the page's text colour");

      // Input table: one row per input, what it turned out to be.
      const rows = await p.eval(`[...document.querySelectorAll("#chainOut table.inputs tr")].map((r) => ({cls: r.className, name: r.cells[0].textContent, what: r.cells[1].textContent}))`);
      eq(rows.map((r) => r.name), ["chain.p7b", "leaf-pkcs1.key"], "input table names");
      ok(/PKCS#7/i.test(rows[0].what) && /key/i.test(rows[1].what), `input table formats: ${JSON.stringify(rows)}`);
      ok(rows.every((r) => r.cls !== "error"), "no input in error");
      say(`inputs: ${rows.map((r) => `${r.name} = ${r.what}`).join(" | ")}`);

      // Trust default from the actual root: the corpus root is private → ticked, with the reason.
      eq(await p.checked("#optTrust"), true, "Trust this CA is ticked for the private corpus root");
      eq(await p.text("#trustWhy"), PRIVATE, "the reason under the checkbox");
      eq(await p.checked("#optUi"), true, "restart morpheus-ui follows Trust");
      ok(await p.eval(`document.getElementById("s2").classList.contains("done")`), "step 2 marked done");
      eq(await p.eval(`[...document.querySelectorAll("#chainOut p.msg.error")].map((e) => e.textContent)`), [], "no error checks");

      // Export: the zip lands in MCI_TEST_SAVE_DIR (the debug-only hook); the page says where and what.
      eq(await p.visible("#btnExport"), true, "export offered");
      await p.click("#btnExport");
      const saved = await p.waitFor(`(() => { const t = document.getElementById("convOut").textContent; return /^Saved /.test(t) ? t : null; })()`, 15000, "the Saved message");
      eq(listDir(f.saveDir), ["m_cust_test-morpheus.zip"], "one zip in the save dir");
      const entries = zipNames(readFileSync(join(f.saveDir, "m_cust_test-morpheus.zip")));
      const names = entries.map((e) => e.name).filter((n) => !n.endsWith("/"));
      const want = await p.eval(`(() => { const m = document.getElementById("convOut").textContent.match(/\\.zip: (.*)\\.The \\.key/); return m ? m[1].split(", ") : null; })()`);
      ok(want && want.length >= 4, `the page lists the files: ${saved}`);
      eq(names.map((n) => n.replace(/^m_cust_test-morpheus\//, "")).sort(), [...want].sort(), "the zip holds exactly the files the page lists");
      eq(want, ["INSTALL.txt", "ca-chain.pem", "m_cust_test.crt", "m_cust_test.key", "morpheus.rb.snippet",
        "trusted_certs/mci-cust-issuing-e1707df2.pem", "trusted_certs/mci-cust-root-f88fb6be.pem"], "the exported file list (root left out of the served chain, CAs for the truststore)");
      eq(entries.find((e) => e.name.endsWith("m_cust_test.key")).mode, 0o600, "the key is 0600 in the zip");
      say(`zip: ${want.join(", ")}`);
      eq(await p.visible("#watch"), false, "no run: the watch bar stays hidden");
    } finally { await p.kill(); }
  },
};
