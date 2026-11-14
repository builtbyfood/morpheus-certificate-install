// morpheus-certificate-install 0.4.2 — assertions for the click suites.
import { isDeepStrictEqual, inspect } from "node:util";

export function ok(cond, msg) { if (!cond) throw new Error(`assertion failed: ${msg}`); }
export function eq(actual, expected, msg) {
  if (!isDeepStrictEqual(actual, expected)) throw new Error(`${msg}\n  expected ${inspect(expected, { depth: 5 })}\n  got      ${inspect(actual, { depth: 5 })}`);
}
export function match(s, re, msg) { if (!re.test(String(s))) throw new Error(`${msg}: ${JSON.stringify(s)} doesn't match ${re}`); }
