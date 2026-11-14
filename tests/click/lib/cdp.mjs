// morpheus-certificate-install 0.4.2 — a minimal Chrome DevTools Protocol client (Node's built-in
// WebSocket and fetch; no dependencies). WebView2 exposes CDP when the app is started with
// WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--remote-debugging-port=<port>.

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** The page target of the app's webview (http://tauri.localhost/ on Windows), once it's up. */
export async function findPage(port, timeoutMs = 30000) {
  const deadline = Date.now() + timeoutMs;
  let last = "";
  while (Date.now() < deadline) {
    try {
      const list = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
      const page = list.find((t) => t.type === "page" && /tauri\.localhost|tauri:\/\/localhost/.test(t.url));
      if (page) return page;
      last = JSON.stringify(list.map((t) => [t.type, t.url]));
    } catch (e) { last = String(e.message || e); }
    await sleep(250);
  }
  throw new Error(`no app page on the CDP port ${port} within ${timeoutMs} ms (last: ${last})`);
}

export class Cdp {
  static async connect(wsUrl) {
    const ws = new WebSocket(wsUrl);
    await new Promise((res, rej) => { ws.onopen = res; ws.onerror = (e) => rej(new Error(`CDP connect: ${e.message || "error"}`)); });
    return new Cdp(ws);
  }
  constructor(ws) {
    this.ws = ws; this.id = 0; this.pending = new Map(); this.handlers = [];
    ws.onmessage = (m) => {
      const msg = JSON.parse(typeof m.data === "string" ? m.data : Buffer.from(m.data).toString());
      if (msg.id && this.pending.has(msg.id)) {
        const { res, rej, method } = this.pending.get(msg.id); this.pending.delete(msg.id);
        msg.error ? rej(new Error(`${method}: ${msg.error.message}`)) : res(msg.result);
      } else if (msg.method) for (const h of this.handlers) h(msg);
    };
    ws.onclose = () => { for (const { rej, method } of this.pending.values()) rej(new Error(`${method}: CDP connection closed`)); this.pending.clear(); };
  }
  send(method, params = {}) {
    const id = ++this.id;
    return new Promise((res, rej) => { this.pending.set(id, { res, rej, method }); this.ws.send(JSON.stringify({ id, method, params })); });
  }
  on(fn) { this.handlers.push(fn); }
  /** Evaluate an expression in the page; returns its value (promises awaited). Throws on a page exception. */
  async eval(expr) {
    const r = await this.send("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true });
    if (r.exceptionDetails) throw new Error(`page: ${r.exceptionDetails.exception?.description || r.exceptionDetails.text}`);
    return r.result.value;
  }
  close() { try { this.ws.close(); } catch (_) {} }
}
