// morpheus-certificate-install 0.4.1 — the real app (debug build) in its own portable folder,
// driven over CDP. Every suite gets a fresh folder: <tmp>/mci-click-<pid>/<suite>/app/ holds a copy
// of the debug exe and portable.flag, so settings, known_hosts and the webview profile all land in
// that folder's data/ and no two suites share them.
//
// Clicks and typing go through CDP's Input domain (real mouse and keyboard events at the element's
// position), files through DOM.setFileInputFiles on the page's own <input type=file>. The page is
// read, never changed — except Page.mask() in the screenshot suite, which swaps lab names for
// example ones just for the capture and puts them back.
import { spawn, execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, writeFileSync, existsSync, rmSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { Cdp, findPage } from "./cdp.mjs";

export const ROOT = resolve(import.meta.dirname, "../../..");
export const DEBUG_EXE = join(ROOT, "target", "debug", process.platform === "win32" ? "morpheus-certificate-install.exe" : "morpheus-certificate-install");
export const CORPUS = join(ROOT, "fixtures", "corpus");
export const PUBLIC_ROOTS = join(ROOT, "src-tauri", "testdata", "public-roots");
export const RUN_ROOT = join(tmpdir(), `mci-click-${process.pid}`);
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let nextPort = 9320;
/** Every page launched (run.mjs fails a suite whose pages logged a browser error: a CSP violation, an uncaught exception). */
export const launched = [];

/** Retry rmSync: the webview's helper processes can hold files for a moment after the app exits. */
export async function rmrf(p, tries = 40) {
  for (let i = 0; ; i++) {
    try { rmSync(p, { recursive: true, force: true }); return; } catch (e) { if (i >= tries) throw e; await sleep(250); }
  }
}

/** A fresh portable folder for one suite: { dir, appDir, dataDir, saveDir, exe }. */
export function freshFolder(suite) {
  const dir = join(RUN_ROOT, suite);
  rmSync(dir, { recursive: true, force: true });
  const appDir = join(dir, "app"), saveDir = join(dir, "saved");
  mkdirSync(appDir, { recursive: true }); mkdirSync(saveDir, { recursive: true });
  const exe = join(appDir, DEBUG_EXE.split(/[\\/]/).pop());
  copyFileSync(DEBUG_EXE, exe);
  writeFileSync(join(appDir, "portable.flag"), "");
  return { dir, appDir, dataDir: join(appDir, "data"), saveDir, exe };
}

/** Start the exe in `folder` and attach to its page. */
export async function launch(folder, { env = {} } = {}) {
  const port = nextPort++;
  const proc = spawn(folder.exe, [], {
    cwd: folder.appDir,
    env: { ...process.env, WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS: `--remote-debugging-port=${port}`, MCI_TEST_SAVE_DIR: folder.saveDir, ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let out = "";
  proc.stdout.on("data", (d) => { out += d; }); proc.stderr.on("data", (d) => { out += d; });
  const exited = new Promise((res) => proc.on("exit", (code) => res(code)));
  let page;
  try { page = await findPage(port); } catch (e) { proc.kill(); throw new Error(`${e.message}\napp output:\n${out}`); }
  const cdp = await Cdp.connect(page.webSocketDebuggerUrl);
  const p = new Page(cdp, proc, exited, () => out);
  launched.push(p);
  // Browser-side errors (CSP violations, uncaught exceptions); Log.enable replays what came before.
  cdp.on((m) => {
    if (m.method === "Log.entryAdded" && m.params.entry.level === "error") p.browserErrors.push(m.params.entry.text);
    if (m.method === "Runtime.exceptionThrown") p.browserErrors.push(m.params.exceptionDetails.exception?.description || m.params.exceptionDetails.text);
  });
  await cdp.send("Log.enable");
  await cdp.send("Runtime.enable");
  await p.ready();
  return p;
}

export class Page {
  constructor(cdp, proc, exited, output) { this.cdp = cdp; this.proc = proc; this.exited = exited; this.output = output; this.browserErrors = []; }

  /** The page has run its script and its first refresh(); start recording the `mci` events. */
  async ready() {
    await this.waitFor(`document.readyState === "complete" && typeof refresh === "function" && !!window.__TAURI__`, 20000, "the page to load");
    // Record (never change): the `mci` events, and each toast the page shows (toast() replaces its text).
    await this.cdp.eval(`(async () => { window.__clickEvents = []; await window.__TAURI__.event.listen("mci", (e) => window.__clickEvents.push(e.payload));
      const t = document.getElementById("toast"); window.__clickToasts = t.style.display === "block" ? [t.textContent] : [];
      new MutationObserver(() => window.__clickToasts.push(t.textContent)).observe(t, {childList: true, characterData: true, subtree: true}); return true; })()`);
    // refresh() has filled the form from settings (or nothing) by the time the chip has its text.
    await this.waitFor(`document.getElementById("chipText").textContent.length > 0`, 5000, "the first refresh");
  }

  eval(expr) { return this.cdp.eval(expr); }

  /** Poll a page expression until it's truthy; returns its value. */
  async waitFor(expr, timeoutMs = 15000, what = expr) {
    const deadline = Date.now() + timeoutMs;
    let last;
    for (;;) {
      try { last = await this.cdp.eval(expr); if (last) return last; } catch (e) { last = e.message; }
      if (Date.now() > deadline) throw new Error(`timed out after ${timeoutMs} ms waiting for ${what} (last: ${JSON.stringify(last)})`);
      await sleep(150);
    }
  }

  /** Wait for the `job` event of `name` to finish (done/error), counting only events after `mark`. */
  async waitJob(name, mark, timeoutMs = 240000) {
    const ev = await this.waitFor(`window.__clickEvents.slice(${mark}).find((e) => e.type === "job" && e.name === ${JSON.stringify(name)} && (e.status === "done" || e.status === "error"))`, timeoutMs, `job ${name}`);
    return ev;
  }
  mark() { return this.cdp.eval(`window.__clickEvents.length`); }
  events(mark = 0) { return this.cdp.eval(`window.__clickEvents.slice(${mark})`); }

  /** Is the element there and shown (no [hidden] ancestor, has a box)? */
  visible(sel) {
    return this.cdp.eval(`(() => { const e = document.querySelector(${JSON.stringify(sel)}); if (!e) return false; const r = e.getBoundingClientRect(); return !!(e.offsetParent || getComputedStyle(e).position === "fixed") && r.width > 0 && r.height > 0; })()`);
  }

  /** A real mouse click at the element's centre (scrolled into view first). Refuses a disabled or hidden element. */
  async click(sel) {
    const box = await this.waitFor(`(() => { const e = document.querySelector(${JSON.stringify(sel)}); if (!e || e.disabled) return null;
      e.scrollIntoView({block: "center", inline: "nearest"}); const r = e.getBoundingClientRect();
      if (!r.width || !r.height) return null; return {x: r.left + r.width / 2, y: r.top + r.height / 2}; })()`, 10000, `${sel} to be clickable`);
    for (const type of ["mouseMoved", "mousePressed", "mouseReleased"]) {
      await this.cdp.send("Input.dispatchMouseEvent", { type, x: box.x, y: box.y, button: type === "mouseMoved" ? "none" : "left", clickCount: 1 });
    }
  }

  /** Click the first element matching `sel` whose text matches `re`. */
  async clickText(sel, re) {
    const id = await this.waitFor(`(() => { const all = [...document.querySelectorAll(${JSON.stringify(sel)})]; const i = all.findIndex((e) => ${re}.test(e.textContent) && !e.disabled && e.getBoundingClientRect().width > 0);
      if (i < 0) return null; all[i].setAttribute("data-click", "t" + Date.now()); return all[i].getAttribute("data-click"); })()`, 10000, `${sel} with text ${re}`);
    await this.click(`[data-click="${id}"]`);
  }

  /** Focus a text field, select what's in it, and type over it (insertText = what an IME/paste does). */
  async type(sel, text) {
    await this.click(sel);
    await this.cdp.eval(`document.querySelector(${JSON.stringify(sel)}).select()`);
    if (text === "") await this.cdp.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Delete", code: "Delete", windowsVirtualKeyCode: 46 }),
      await this.cdp.send("Input.dispatchKeyEvent", { type: "keyUp", key: "Delete", code: "Delete", windowsVirtualKeyCode: 46 });
    else await this.cdp.send("Input.insertText", { text });
  }

  /** Choose files in the page's file input, as the file picker would. */
  async setFiles(sel, paths) {
    const { root } = await this.cdp.send("DOM.getDocument", { depth: 0 });
    const { nodeId } = await this.cdp.send("DOM.querySelector", { nodeId: root.nodeId, selector: sel });
    if (!nodeId) throw new Error(`no ${sel}`);
    await this.cdp.send("DOM.setFileInputFiles", { nodeId, files: paths });
    const names = paths.map((p) => p.split(/[\\/]/).pop());
    await this.waitFor(`(() => { const t = document.getElementById("fileList").textContent; return ${JSON.stringify(names)}.every((n) => t.includes(n)); })()`, 5000, "the file list");
  }

  text(sel) { return this.cdp.eval(`(document.querySelector(${JSON.stringify(sel)}) || {}).textContent ?? null`); }
  value(sel) { return this.cdp.eval(`(document.querySelector(${JSON.stringify(sel)}) || {}).value ?? null`); }
  checked(sel) { return this.cdp.eval(`!!(document.querySelector(${JSON.stringify(sel)}) || {}).checked`); }
  count(sel) { return this.cdp.eval(`document.querySelectorAll(${JSON.stringify(sel)}).length`); }

  /** How many toasts the page has shown so far (pass it to toast() to wait for a new one). */
  toastMark() { return this.cdp.eval(`window.__clickToasts.length`); }
  /** Wait for a toast matching `re` shown after `mark` (default: any since the page loaded); returns its text. */
  async toast(re, mark = 0, timeoutMs = 10000) {
    return this.waitFor(`(() => { const t = document.getElementById("toast"); return t.style.display === "block" ? window.__clickToasts.slice(${mark}).find((s) => ${re}.test(s)) || null : null; })()`, timeoutMs, `a toast matching ${re}`);
  }

  /** The open <dialog>'s title and body text, once it's open. */
  async dialog(re = /./) {
    return this.waitFor(`(() => { const d = document.getElementById("dlg"); return d.open && ${re}.test(document.getElementById("dlgTitle").textContent) ? {title: document.getElementById("dlgTitle").textContent, body: document.getElementById("dlgBody").textContent, ok: document.getElementById("dlgOk").textContent} : null; })()`, 15000, `a dialog ${re}`);
  }
  async dialogOk() { await this.click("#dlgOk"); await this.waitFor(`!document.getElementById("dlg").open`, 5000, "the dialog to close"); }

  /** The Run log's text (xterm's buffer, or the plain fallback). */
  runLog() {
    return this.cdp.eval(`(() => { const pre = document.querySelector("#xtRun pre.fallback"); if (pre) return pre.textContent;
      const b = runT.buffer.active; const out = []; for (let i = 0; i < b.length; i++) { const l = b.getLine(i); if (l) out.push(l.translateToString(true)); } return out.join("\\n"); })()`);
  }
  async waitLog(re, timeoutMs = 30000) {
    return this.waitFor(`(() => { const pre = document.querySelector("#xtRun pre.fallback"); let t; if (pre) t = pre.textContent; else { const b = runT.buffer.active; const out = []; for (let i = 0; i < b.length; i++) { const l = b.getLine(i); if (l) out.push(l.translateToString(true)); } t = out.join("\\n"); } return ${re}.test(t); })()`, timeoutMs, `the Run log to match ${re}`);
  }

  /** Lay the page out at a fixed CSS size (device scale 1, light theme), whatever the real window's size. */
  async setViewport(width, height) {
    await this.cdp.send("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: 1, mobile: false });
    await this.cdp.send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: "light" }] });
    await sleep(400); // layout, then xterm's fit
    await this.cdp.eval(`(() => { runT.fit(); return true; })()`);
    await sleep(300);
  }
  /** A PNG of the viewport as it is now. */
  async capture() {
    const { data } = await this.cdp.send("Page.captureScreenshot", { format: "png", captureBeyondViewport: false });
    return Buffer.from(data, "base64");
  }

  /** Replace each [from, to] in every text node and form value; returns a function that puts them back. */
  async mask(pairs) {
    await this.cdp.eval(`(() => {
      const pairs = ${JSON.stringify(pairs)}; const undo = [];
      const sub = (s) => pairs.reduce((a, [f, t]) => a.split(f).join(t), s);
      const w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
      for (let n; (n = w.nextNode());) { const v = sub(n.nodeValue); if (v !== n.nodeValue) { undo.push([n, "nodeValue", n.nodeValue]); n.nodeValue = v; } }
      for (const e of document.querySelectorAll("input,textarea")) { const v = sub(e.value); if (v !== e.value) { undo.push([e, "value", e.value]); e.value = v; } }
      window.__clickUnmask = () => { for (const [n, k, v] of undo.reverse()) n[k] = v; };
      return true; })()`);
    return () => this.cdp.eval(`(window.__clickUnmask && window.__clickUnmask(), true)`);
  }
  /** All the page's visible text plus form values, for the "no real names" check before a capture. */
  allText() {
    return this.cdp.eval(`document.body.innerText + "\\n" + [...document.querySelectorAll("input,textarea")].map((e) => e.value).join("\\n")`);
  }

  /** Close the window the way the user does (WM_CLOSE to the main window), then wait for the process to exit. */
  async closeWindow(timeoutMs = 30000) {
    this.cdp.close();
    if (process.platform === "win32") {
      execFileSync("powershell", ["-NoProfile", "-NonInteractive", "-Command", `
        Add-Type -Namespace Mci -Name W -MemberDefinition '[DllImport("user32.dll")] public static extern bool PostMessage(System.IntPtr h, uint m, System.IntPtr w, System.IntPtr l);';
        $p = Get-Process -Id ${this.proc.pid}; $h = $p.MainWindowHandle;
        if ($h -eq [System.IntPtr]::Zero) { throw "the app has no main window" }
        [void][Mci.W]::PostMessage($h, 0x0010, [System.IntPtr]::Zero, [System.IntPtr]::Zero)`], { stdio: "pipe" });
    } else {
      this.proc.kill("SIGTERM");
    }
    const code = await Promise.race([this.exited, sleep(timeoutMs).then(() => "timeout")]);
    if (code === "timeout") { this.proc.kill(); throw new Error(`the app didn't exit within ${timeoutMs} ms of closing its window`); }
    return code;
  }

  /** End of a suite: kill the app (no exit handlers needed). */
  async kill() {
    this.cdp.close();
    if (this.proc.exitCode === null) { this.proc.kill(); await Promise.race([this.exited, sleep(10000)]); }
  }
}

/** Names of the files in a zip (central directory), in order. */
export function zipNames(buf) {
  let eocd = -1;
  for (let i = buf.length - 22; i >= 0; i--) if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  if (eocd < 0) throw new Error("not a zip (no end of central directory)");
  const n = buf.readUInt16LE(eocd + 10); let off = buf.readUInt32LE(eocd + 16); const names = [];
  for (let k = 0; k < n; k++) {
    if (buf.readUInt32LE(off) !== 0x02014b50) throw new Error("bad central directory entry");
    const nl = buf.readUInt16LE(off + 28), el = buf.readUInt16LE(off + 30), cl = buf.readUInt16LE(off + 32);
    const ext = buf.readUInt32LE(off + 38); // external attributes: Unix mode in the high 16 bits
    names.push({ name: buf.toString("utf8", off + 46, off + 46 + nl), mode: (ext >>> 16) & 0o777 });
    off += 46 + nl + el + cl;
  }
  return names;
}

export function listDir(p) { return existsSync(p) ? readdirSync(p) : null; }
