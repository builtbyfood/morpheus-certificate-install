// morpheus-certificate-install 0.4.2 — `npm run portable`: release build, then a portable bundle:
// the GUI exe + the CLI exe + an empty portable.flag (data then lives in ./data/ beside them).
// Windows → dist-portable/morpheus-certificate-install-windows-portable.zip
// Linux   → dist-portable/morpheus-certificate-install-linux-portable-<arch>.tar.gz (needs webkit2gtk-4.1 on the host)
import { execSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const root = new URL("..", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");
const out = join(root, "dist-portable");
const win = process.platform === "win32";
const exe = (n) => join(root, "target", "release", win ? `${n}.exe` : n);
const run = (cmd) => { console.log(`> ${cmd}`); execSync(cmd, { cwd: root, stdio: "inherit" }); };

run("npm run tauri build -- --no-bundle");
run("cargo build --release -p mci-cli");
for (const n of ["morpheus-certificate-install", "morpheus-certificate-install-cli"]) {
  if (!existsSync(exe(n))) { console.error(`missing ${exe(n)}`); process.exit(1); }
}
rmSync(out, { recursive: true, force: true });
const stage = join(out, "morpheus-certificate-install");
mkdirSync(stage, { recursive: true });
for (const n of ["morpheus-certificate-install", "morpheus-certificate-install-cli"]) cpSync(exe(n), join(stage, win ? `${n}.exe` : n));
writeFileSync(join(stage, "portable.flag"), "");
if (win) {
  run(`powershell -NoProfile -Command "Compress-Archive -Path '${stage}\\*' -DestinationPath '${join(out, "morpheus-certificate-install-windows-portable.zip")}' -Force"`);
} else {
  run(`tar -C "${out}" -czf "${join(out, `morpheus-certificate-install-linux-portable-${process.arch}.tar.gz`)}" morpheus-certificate-install`);
}
console.log(`\nportable build in ${out}`);
