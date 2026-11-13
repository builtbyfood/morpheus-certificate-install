// morpheus-certificate-install 0.4.0 — a public CA leaves "Trust this CA" unticked, with the
// "Publicly trusted" reason (PARITY 28). The private corpus chain first (ticked), then, after Clear
// files, a leaf-less analysis of the real Go Daddy G2 root (src-tauri/testdata/public-roots/).
import { join } from "node:path";
import { CORPUS, PUBLIC_ROOTS, freshFolder, launch } from "../lib/app.mjs";
import { eq, ok } from "../lib/assert.mjs";

const PUBLIC = "Publicly trusted: Morpheus' Java already trusts it.";

export default {
  name: "public-chain",
  async run({ say }) {
    const f = freshFolder("public-chain");
    const p = await launch(f);
    try {
      await p.setFiles("#fileIn", [join(CORPUS, "chain.p7b"), join(CORPUS, "leaf-pkcs1.key")]);
      await p.click("#btnAnalyze");
      await p.waitFor(`document.querySelectorAll("#chainOut .chain .link").length === 3`, 15000, "the private chain");
      eq(await p.checked("#optTrust"), true, "the private chain ticks Trust");

      await p.click("#btnClear");
      await p.waitFor(`document.getElementById("chainOut").innerHTML === ""`, 5000, "the cleared chain view");
      // Nothing of the cleared analysis stays (0.3.20: the box and its reason were left over).
      eq([await p.checked("#optTrust"), await p.text("#trustWhy")], [false, ""], "Clear files resets Trust and its reason");
      await p.setFiles("#fileIn", [join(PUBLIC_ROOTS, "go-daddy-root-g2.pem")]);
      await p.click("#btnAnalyze");
      await p.waitFor(`document.getElementById("trustWhy").textContent !== ""`, 15000, "the Go Daddy analysis");
      const checks = await p.eval(`[...document.querySelectorAll("#chainOut p.msg")].map((e) => e.textContent)`);
      ok(checks.some((c) => /server certificate is missing/.test(c)), `the analysis says the leaf is missing: ${checks.join(" | ")}`);
      eq(await p.count("#chainOut .chain .link"), 0, "no chain to draw without a leaf");
      eq(await p.text("#trustWhy"), PUBLIC, "the reason under the checkbox");
      eq(await p.checked("#optTrust"), false, "Trust this CA is unticked for a public root");
      eq(await p.checked("#optUi"), false, "restart morpheus-ui follows Trust");
      eq(await p.visible("#btnExport"), false, "nothing to export without a leaf");
      say(`Trust unticked: "${PUBLIC}"`);
    } finally { await p.kill(); }
  },
};
