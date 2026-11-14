// morpheus-certificate-install 0.4.1 — the fake appliance for the click suites: its address
// (MCI_TEST_SSH) and a reference connection to set it up and check it, independent of the app
// under test (src-tauri/tests/click_ref.rs, over its own SSH session).
//
// The shell text below is test-only and lives here and in src-tauri/tests/engine_e2e.rs, nowhere
// else: the app's own appliance commands are in mci_core::appliance and mci_core::runner.
import { execFileSync } from "node:child_process";
import { ROOT } from "./app.mjs";

/** MCI_TEST_SSH=host:port:user:password */
export function target() {
  const v = process.env.MCI_TEST_SSH || "";
  const [host, port, user, ...pw] = v.split(":");
  if (!host || !port || !user || !pw.length) throw new Error("MCI_TEST_SSH=host:port:user:password");
  return { host, port: Number(port), user, password: pw.join(":") };
}

export const STATE_DIR = "/var/lib/morpheus-certificate-install";
export const RUN_DIR = `${STATE_DIR}/runs`;
export const BACKUP_DIR = `${STATE_DIR}/backups`;
export const LOG_DIR = "/var/log/morpheus-certificate-install";

const ARGS = ["test", "-q", "-p", "morpheus-certificate-install", "--test", "click_ref", "--", "--ignored", "--exact", "click_ref", "--nocapture"];

/** Build the reference test once (so the first suite doesn't time out compiling it). */
export function buildRef() {
  execFileSync("cargo", ["test", "-p", "morpheus-certificate-install", "--test", "click_ref", "--no-run"], { cwd: ROOT, stdio: "inherit" });
}

/** Run `script` on the VM (as root unless asUser); returns { stdout, rc }. Throws on rc != 0 unless allowFail. */
export function ref(script, { asUser = false, allowFail = false } = {}) {
  let out;
  try {
    out = execFileSync("cargo", ARGS, { cwd: ROOT, env: { ...process.env, MCI_CLICK_REF: script, MCI_CLICK_REF_USER: asUser ? "1" : "0" }, stdio: ["ignore", "pipe", "pipe"], encoding: "utf8", maxBuffer: 64 << 20 });
  } catch (e) {
    throw new Error(`reference connection failed: ${e.message}\n${e.stdout || ""}\n${e.stderr || ""}`);
  }
  const m = out.match(/@@CLICKREF-BEGIN\n([\s\S]*?)@@CLICKREF-END rc=(-?\d+)/);
  if (!m) throw new Error(`reference connection: no result in\n${out}`);
  const r = { stdout: m[1], rc: Number(m[2]) };
  if (r.rc !== 0 && !allowFail) throw new Error(`on the VM (rc ${r.rc}): ${script}\n${r.stdout}`);
  return r;
}

/** Back to the starting state engine_e2e uses: morpheus.rb without ssl lines, the starting
 *  self-signed `appliance` certificate served, no mci-* CA aliases, nothing the tests installed. */
export function resetAppliance() {
  const rb = "appliance_url 'https://198.51.100.20'\\nelasticsearch['es_hosts'] = {'127.0.0.1' => 9200}\\n";
  ref(`umask 077; printf "${rb}" > /etc/morpheus/morpheus.rb && chmod 0600 /etc/morpheus/morpheus.rb
rm -f /etc/morpheus/ssl/trusted_certs/mci-*.pem /etc/morpheus/ssl/m_cust_test.crt /etc/morpheus/ssl/m_cust_test.key ${STATE_DIR}/installed.json
touch /var/lib/fake-morpheus/keytool-aliases; sed -i '/^mci-/d' /var/lib/fake-morpheus/keytool-aliases
morpheus-ctl restart nginx >/dev/null`);
}

/** The run ids under RUN_DIR / LOG_DIR, and the backup ids. */
export function inventory() {
  const { stdout } = ref(`ls -1 ${RUN_DIR} 2>/dev/null; echo @@; ls -1 ${LOG_DIR} 2>/dev/null; echo @@; ls -1 ${BACKUP_DIR} 2>/dev/null; true`);
  const [runs, logs, backups] = stdout.split("@@\n").map((s) => s.split("\n").filter(Boolean));
  return { runs, logs, backups };
}

/** A runner-shaped run that sleeps `secs` and then writes its .rc: script in RUN_DIR, log in
 *  LOG_DIR, started through systemd-run like the app's runners. Returns its id. */
export function startSleepingRun(secs = 60) {
  const id = `click-sleep-${Date.now()}`;
  ref(`set -e; mkdir -p ${RUN_DIR} ${LOG_DIR}; chmod 0700 ${RUN_DIR}
printf '#!/bin/bash\\necho "click test: a run that sleeps ${secs} s"\\nsleep ${secs}\\necho 0 > ${LOG_DIR}/${id}.rc\\n' > ${RUN_DIR}/${id}.sh
chmod 0700 ${RUN_DIR}/${id}.sh
systemd-run --unit=mci-${id} --collect --description='click test sleeper' /bin/bash -c '/bin/bash ${RUN_DIR}/${id}.sh >> ${LOG_DIR}/${id}.log 2>&1' >/dev/null 2>&1
for i in 1 2 3 4 5 6 7 8 9 10; do [ -s ${LOG_DIR}/${id}.log ] && break; sleep 0.5; done; test -s ${LOG_DIR}/${id}.log`);
  return id;
}

/** Stop the sleeper and remove its files. */
export function removeSleepingRun(id) {
  ref(`systemctl stop mci-${id} 2>/dev/null; rm -f ${RUN_DIR}/${id}.sh ${LOG_DIR}/${id}.log ${LOG_DIR}/${id}.rc; true`);
}
