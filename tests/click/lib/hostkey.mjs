// morpheus-certificate-install 0.4.0 — known_hosts lines with WRONG keys for a host, one per key
// type the fake appliance may offer (ed25519, ECDSA P-256, RSA): freshly generated, so they can't
// be the VM's. Pre-seeding them tests the host-key mismatch without rotating the VM's real key
// (never MCI_TEST_ROTATE from the click tests).
import { generateKeyPairSync } from "node:crypto";

const str = (b) => { const n = Buffer.alloc(4); n.writeUInt32BE(b.length); return Buffer.concat([n, b]); };
const mpint = (b) => { let i = 0; while (i < b.length - 1 && b[i] === 0) i++; b = b.subarray(i); return str(b[0] & 0x80 ? Buffer.concat([Buffer.from([0]), b]) : b); };
const b64u = (s) => Buffer.from(s, "base64url");

export function wrongKeyLines(host, port) {
  const pat = port === 22 ? host : `[${host}]:${port}`;
  const ed = generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" });
  const ec = generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey.export({ format: "jwk" });
  const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey.export({ format: "jwk" });
  const blobs = [
    ["ssh-ed25519", Buffer.concat([str(Buffer.from("ssh-ed25519")), str(b64u(ed.x))])],
    ["ecdsa-sha2-nistp256", Buffer.concat([str(Buffer.from("ecdsa-sha2-nistp256")), str(Buffer.from("nistp256")), str(Buffer.concat([Buffer.from([4]), b64u(ec.x), b64u(ec.y)]))])],
    ["ssh-rsa", Buffer.concat([str(Buffer.from("ssh-rsa")), mpint(b64u(rsa.e)), mpint(b64u(rsa.n))])],
  ];
  return "# morpheus-certificate-install known_hosts: SSH host keys accepted in the app\n" + blobs.map(([t, b]) => `${pat} ${t} ${b.toString("base64")}`).join("\n") + "\n";
}
