// morpheus-certificate-install 0.4.2 — UI contract test (npm run test:ui-contract). Needs: npm i, pip install -r reference/python/requirements.txt
const {JSDOM, VirtualConsole} = require("jsdom");
const fs = require("fs");
// Starts the Python reference (reference/python) and drives ui/index.html through ui/bridge.js with a fake
// window.__TAURI__ that forwards invoke() to the reference's /api/* routes and listen() to its event stream.
// If this passes, the Rust commands only have to return the same JSON. SSH steps need an appliance:
// set MCI_TEST_SSH=host:port:user:password (e.g. the fake appliance in tests/fake-appliance).
const { spawn } = require("child_process");
let url;
let base, tok;
const path = require("path");
const ROOT = path.resolve(__dirname, "../..");
const R = ROOT + "/ui/";
const errors = [], saved = [];
const vc = new VirtualConsole(); vc.on("jsdomError", e => errors.push(String(e.message||e)));
const wait = ms => new Promise(r => setTimeout(r, ms));
const ROUTE = {state:"/api/state",connect:"/api/connect",disconnect:"/api/disconnect",charon_discover:"/api/charon",preflight:"/api/preflight",analyze:"/api/analyze",clear_files:"/api/clear-files",fetch_chain:"/api/fetch-chain",export_zip:"/api/export",plan:"/api/plan",apply:"/api/apply",verify:"/api/verify",runs:"/api/runs",reattach:"/api/reattach",stop:"/api/stop",backups:"/api/backups",rollback:"/api/rollback",morpheus_check:"/api/morpheus",set_appliance_url:"/api/morpheus/appliance-url",shell_open:"/api/shell/open",shell_input:"/api/shell/input",shell_resize:"/api/shell/resize",
  // 0.3.17 commands the Python reference doesn't have (the contract run doesn't click them):
  cleanup_list:"/api/cleanup/list",cleanup_plan:"/api/cleanup/plan",cleanup:"/api/cleanup",forget_appliance:"/api/forget",set_leave_no_trace:"/api/leave-no-trace"};
(async () => {
  const py = spawn(process.env.PYTHON || "python3", ["-m", "morpheus_certificate_install", "--no-browser", "--port", "8870"],
                   { cwd: ROOT + "/reference/python", env: { ...process.env, PYTHONUNBUFFERED: "1", MCI_HOME: require("os").tmpdir() + "/mci-ui-contract" } });
  url = await new Promise((res, rej) => { let b = ""; py.stdout.on("data", (d) => { b += d; const m = b.match(/http:\/\/127\.0\.0\.1:\d+\/#t=\S+/); if (m) res(m[0]); });
    setTimeout(() => rej(new Error("reference did not start: " + b)), 15000); });
  process.on("exit", () => py.kill());
  base = url.split("/#")[0]; tok = url.split("#t=")[1];
  let html = fs.readFileSync(R + "index.html", "utf8");
  // inline the local scripts (jsdom has no file server here)
  for (const f of ["vendor/xterm.js", "vendor/addon-fit.js", "bridge.js"]) html = html.replace(`<script src="${f}"></script>`, `<script>${fs.readFileSync(R + f, "utf8").replace(/<\/script>/g, "<\\/script>")}</script>`);
  const dom = new JSDOM(html, {url: "http://tauri.localhost/", runScripts: "dangerously", pretendToBeVisual: true, virtualConsole: vc,
    beforeParse(w) {
      const listeners = [];
      w.__TAURI__ = {
        core: { invoke: async (cmd, {args}) => {
          const r = await fetch(base + ROUTE[cmd], {method: args === null && cmd === "state" ? "GET" : "POST",
            headers: {"X-MCI-Token": tok, "Content-Type": "application/json"}, body: args === null && cmd === "state" ? undefined : JSON.stringify(args ?? {})});
          const j = await r.json(); if (!r.ok) throw j.error;   // Tauri rejects with the error string
          if (cmd === "export_zip") { saved.push(j.filename); return {saved: "/home/mcitest/" + j.filename, files: j.files}; }
          return j; } },
        event: { listen: async (ch, cb) => { listeners.push(cb); (async () => {
          const r = await fetch(`${base}/api/events?t=${tok}`); const rd = r.body.getReader(); let buf = "";
          for (;;) { const {value, done} = await rd.read(); if (done) break; buf += Buffer.from(value).toString();
            let i; while ((i = buf.indexOf("\n\n")) >= 0) { const chunk = buf.slice(0, i); buf = buf.slice(i + 2);
              if (chunk.startsWith("data: ")) cb({payload: JSON.parse(chunk.slice(6))}); } } })(); } },
        app: { getVersion: async () => "0.3.0" },
      };
      w.navigator.clipboard = {writeText(){}};
      w.HTMLDialogElement.prototype.showModal = function(){ this.open = true; setTimeout(()=>{ this.returnValue="ok"; this.onclose && this.onclose(); }, 10); };
    }});
  await wait(1200);
  const w = dom.window, d = w.document, $ = id => d.getElementById(id);
  const click = id => $(id).dispatchEvent(new w.MouseEvent("click", {bubbles:true}));
  console.log("version label:", $("ver").textContent, "| run log:", d.querySelector("#xtRun pre.fallback") ? "plain fallback" : "xterm");
  w.eval(`files=[{name:"chain.p7b",b64:"${fs.readFileSync(ROOT + "/fixtures/corpus/chain.p7b").toString("base64")}"},{name:"leaf-pkcs1.key",b64:"${fs.readFileSync(ROOT + "/fixtures/corpus/leaf-pkcs1.key").toString("base64")}"}]`);
  click("btnAnalyze"); await wait(1200);
  console.log("chain links:", d.querySelectorAll(".chain .link").length, "| inputs:", [...d.querySelectorAll("table.inputs td:last-child")].map(t=>t.textContent).join(" | "));
  click("btnExport"); await wait(1000);
  console.log("export:", $("convOut").textContent.slice(0, 80));
  const convertOk = d.querySelectorAll(".chain .link").length === 3 && /Saved/.test($("convOut").textContent);
  if (process.env.MCI_TEST_SSH) {
    const [h, p, u, pw] = process.env.MCI_TEST_SSH.split(":");
    $("host").value = h; $("port").value = p; $("user").value = u; $("password").value = pw;
    click("btnConnect"); await wait(5000);
    console.log("chip:", $("chipText").textContent, "| facts via event:", d.querySelectorAll("#factsOut dt").length, "rows");
  }
  // error path: a rejected invoke must surface as a toast
  $("pfxPw").value = ""; w.eval(`files=[{name:"x.pfx",b64:"MAA="}]`); click("btnClear"); await wait(400); click("btnAnalyze"); await wait(800);
  console.log("error toast:", $("toast").textContent.slice(0, 70));
  const errorOk = /Add the certificate files/.test($("toast").textContent);
  const real = errors.filter(e => !/getContext|matchMedia/.test(e));
  const ok = convertOk && errorOk && !real.length;
  console.log(ok ? "UI contract OK" : "UI contract FAILED", real.length ? real : "");
  process.exit(ok ? 0 : 1);
})();
