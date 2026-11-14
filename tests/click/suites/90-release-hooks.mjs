// morpheus-certificate-install 0.4.2 — the test-only hooks exist in debug builds only. Builds the
// release exe (as `tauri build` does: cargo --release with tauri/custom-protocol) and checks the
// hook's name is in the debug exe (so the search works) and nowhere in the release exe.
// Set MCI_CLICK_NO_RELEASE_BUILD=1 to check target/release as it is.
import { execSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { DEBUG_EXE, ROOT } from "../lib/app.mjs";
import { ok } from "../lib/assert.mjs";

const HOOKS = ["MCI_TEST_SAVE_DIR"];
const RELEASE_EXE = join(ROOT, "target", "release", process.platform === "win32" ? "morpheus-certificate-install.exe" : "morpheus-certificate-install");

export default {
  name: "release-hooks",
  async run({ say }) {
    if (!process.env.MCI_CLICK_NO_RELEASE_BUILD) {
      say("cargo build --release -p morpheus-certificate-install --features tauri/custom-protocol (a few minutes the first time)");
      execSync("cargo build --release -p morpheus-certificate-install --features tauri/custom-protocol", { cwd: ROOT, stdio: ["ignore", "ignore", "inherit"] });
    }
    ok(existsSync(RELEASE_EXE), `${RELEASE_EXE} exists`);
    const dbg = readFileSync(DEBUG_EXE), rel = readFileSync(RELEASE_EXE);
    for (const h of HOOKS) {
      ok(dbg.includes(Buffer.from(h)), `the debug exe has ${h} (the search works)`);
      ok(!rel.includes(Buffer.from(h)), `the release exe has no ${h}`);
    }
    ok(!rel.includes(Buffer.from("MCI_TEST_")), "the release exe names no MCI_TEST_ variable at all");
    say(`${HOOKS.join(", ")}: in the debug exe (${(dbg.length / 1e6).toFixed(0)} MB), not in the release exe (${(rel.length / 1e6).toFixed(1)} MB)`);
  },
};
