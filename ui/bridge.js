// morpheus-certificate-install 0.4.0 — Tauri bridge for ui/index.html.
// The page was written against the Python app's HTTP API; this maps each route to a Tauri command
// with the same request/response bodies, and the SSE stream to the "mci" event channel.
"use strict";
(function () {
  const T = window.__TAURI__;
  const CMD = {
    "/api/state": "state", "/api/connect": "connect", "/api/disconnect": "disconnect",
    "/api/charon": "charon_discover", "/api/preflight": "preflight", "/api/analyze": "analyze",
    "/api/clear-files": "clear_files", "/api/fetch-chain": "fetch_chain", "/api/export": "export_zip",
    "/api/plan": "plan", "/api/apply": "apply", "/api/verify": "verify", "/api/runs": "runs",
    "/api/reattach": "reattach", "/api/stop": "stop", "/api/backups": "backups", "/api/rollback": "rollback",
    "/api/morpheus": "morpheus_check", "/api/morpheus/appliance-url": "set_appliance_url",
    "/api/shell/open": "shell_open", "/api/shell/input": "shell_input", "/api/shell/resize": "shell_resize",
    // 0.3.17, not in the Python reference:
    "/api/cleanup/list": "cleanup_list", "/api/cleanup/plan": "cleanup_plan", "/api/cleanup": "cleanup",
    "/api/forget": "forget_appliance", "/api/leave-no-trace": "set_leave_no_trace",
  };
  window.api = async function api(path, body) {
    const cmd = CMD[path];
    if (!cmd) throw new Error(`no command for ${path}`);
    if (!T) throw new Error("Not running inside the app (window.__TAURI__ missing).");
    try {
      return await T.core.invoke(cmd, { args: body === undefined ? null : body });
    } catch (e) {
      throw new Error(typeof e === "string" ? e : (e && e.message) || JSON.stringify(e));
    }
  };
  window.mciListen = function (handler) {
    if (!T) return;
    T.event.listen("mci", (e) => { try { handler(e.payload); } catch (err) { console.error("[mci]", err); } });
  };
  window.mciVersion = async function () {
    try { return T ? await T.app.getVersion() : null; } catch (_) { return null; }
  };
})();
