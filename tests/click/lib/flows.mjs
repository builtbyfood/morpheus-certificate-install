// morpheus-certificate-install 0.4.0 — steps several suites click through the same way.
import { join } from "node:path";
import { CORPUS } from "./app.mjs";
import { eq, ok } from "./assert.mjs";

/** Step 1 over SSH: fill the form, Connect, confirm the new host key in the dialog, wait for the
 *  appliance check (it starts by itself after connecting). Returns the confirmed fingerprint. */
export async function connectSsh(p, tg, { say = () => {} } = {}) {
  await p.type("#host", tg.host);
  await p.type("#port", String(tg.port));
  await p.type("#user", tg.user);
  await p.type("#password", tg.password);
  const m = await p.mark();
  await p.click("#btnConnect");
  const d = await p.dialog(/^New host key$/);
  eq(d.ok, "Trust and connect", "the TOFU dialog's button");
  const fp = (d.body.match(/SHA256:[A-Za-z0-9+/=]+/) || [])[0];
  ok(fp, `the dialog shows the fingerprint: ${d.body}`);
  ok(d.body.includes(tg.host), "the dialog names the host");
  await p.dialogOk();
  await p.waitFor(`document.getElementById("chipText").textContent.startsWith(${JSON.stringify(tg.user + "@")})`, 30000, "the connected chip");
  const pre = await p.waitJob("preflight", m, 120000);
  eq(pre.status, "done", `preflight: ${pre.error || ""}`);
  await p.waitFor(`document.getElementById("s1").classList.contains("done") && document.querySelectorAll("#factsOut dt").length > 0`, 10000, "the appliance facts");
  say(`connected after confirming ${fp}; chip "${await p.text("#chipText")}"`);
  return fp;
}

/** Step 2 with the corpus chain and key (m.cust.test). */
export async function loadCorpusChain(p) {
  await p.setFiles("#fileIn", [join(CORPUS, "chain.p7b"), join(CORPUS, "leaf-pkcs1.key")]);
  await p.click("#btnAnalyze");
  await p.waitFor(`document.getElementById("s2").classList.contains("done")`, 15000, "the certificate check");
}

/** Facts the page shows in step 1, as {label: value}. */
export function facts(p) {
  return p.eval(`Object.fromEntries([...document.querySelectorAll("#factsOut dt")].map((dt) => [dt.textContent, dt.nextElementSibling.textContent]))`);
}
