import { spawnSync } from "node:child_process";
import { createPrivateKey, createPublicKey } from "node:crypto";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";
import { policyKeyId } from "../src/policy/signature.js";

// Runs scripts/generate-policy-signing-key.mjs against a MOCK gcloud only.
// GCLOUD_BIN points at the mock and PATH holds only the mock and node, so
// the real gcloud can never run from this test.
const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "scripts", "generate-policy-signing-key.mjs");
const work = mkdtempSync(join(tmpdir(), "ar-keyscript-"));
afterAll(() => rmSync(work, { recursive: true, force: true }));

const MOCK = `#!${process.execPath}
const fs = require("node:fs");
const args = process.argv.slice(2);
let stdin = "";
try { stdin = fs.readFileSync(0, "utf8"); } catch {}
const rec = { args, stdin };
const df = args.find((a) => a.startsWith("--data-file="));
if (df && df !== "--data-file=-") {
  const p = df.slice("--data-file=".length);
  rec.file = p;
  rec.fileMode = fs.statSync(p).mode & 0o777;
  rec.fileContent = fs.readFileSync(p, "utf8");
}
fs.appendFileSync(process.env.MOCK_LOG, JSON.stringify(rec) + "\\n");
if (args[0] === "secrets" && args[1] === "describe") process.exit(process.env.MOCK_EXISTS === "1" ? 0 : 1);
if (process.env.MOCK_FAIL === "1") { process.stderr.write("mock failure\\n"); process.exit(1); }
process.stdout.write("Created version [1] of the secret [POLICY_SIGNING_PRIVATE_KEY].\\n");
`;

let n = 0;
function run(args: string[], env: Record<string, string> = {}) {
  const dir = mkdtempSync(join(work, `r${n++}-`));
  const mock = join(dir, "gcloud");
  writeFileSync(mock, MOCK);
  chmodSync(mock, 0o755);
  const log = join(dir, "calls.jsonl");
  writeFileSync(log, "");
  const res = spawnSync(process.execPath, [SCRIPT, ...args], {
    encoding: "utf8",
    env: { PATH: `${dir}:${dirname(process.execPath)}`, GCLOUD_BIN: mock, MOCK_LOG: log, TMPDIR: dir, ...env },
  });
  const calls = readFileSync(log, "utf8")
    .split("\n")
    .filter(Boolean)
    .map((l) => JSON.parse(l) as { args: string[]; stdin: string; file?: string; fileMode?: number; fileContent?: string });
  return { status: res.status, stdout: res.stdout, stderr: res.stderr, calls, dir };
}

/** Every encoding of the private key that must never appear in output. */
function secretForms(pem: string): string[] {
  const der = createPrivateKey(pem).export({ format: "der", type: "pkcs8" });
  const seed = der.subarray(der.length - 32);
  const body = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  return [
    "PRIVATE KEY",
    body,
    body.slice(0, 24),
    seed.toString("hex"),
    seed.toString("base64"),
    seed.toString("base64url"),
    der.toString("base64"),
    der.toString("hex"),
  ];
}

function expectNoSecret(out: string, pem: string) {
  for (const s of secretForms(pem)) expect(out.includes(s), `output contains private key material (${s.slice(0, 8)}...)`).toBe(false);
}

describe("scripts/generate-policy-signing-key.mjs (mock gcloud only)", () => {
  it("default: sends the PEM on gcloud stdin and prints only the key id and public key", () => {
    const r = run(["--project", "agentreel-test"]);
    expect(r.status).toBe(0);
    const create = r.calls.find((c) => c.args[1] === "create");
    expect(create?.args).toEqual([
      "secrets",
      "create",
      "POLICY_SIGNING_PRIVATE_KEY",
      "--replication-policy=automatic",
      "--data-file=-",
      "--project=agentreel-test",
    ]);
    const pem = create!.stdin;
    expect(pem).toMatch(/^-----BEGIN PRIVATE KEY-----\n/);
    // stdout is exactly two lines: key_id and public_key.
    const lines = r.stdout.trim().split("\n");
    expect(lines).toHaveLength(2);
    const keyId = lines[0]!.replace(/^key_id=/, "");
    const pub = lines[1]!.replace(/^public_key=/, "");
    expect(lines[0]).toMatch(/^key_id=ed25519-[0-9a-f]{16}$/);
    expect(lines[1]).toMatch(/^public_key=[A-Za-z0-9_-]{43}$/);
    // The printed public key and key id belong to the stored private key.
    const derivedPub = createPublicKey(createPrivateKey(pem)).export({ format: "jwk" }).x;
    expect(pub).toBe(derivedPub);
    expect(policyKeyId(Buffer.from(pub, "base64url"))).toBe(keyId);
    expectNoSecret(r.stdout, pem);
    expectNoSecret(r.stderr, pem);
    // Nothing besides gcloud stdin ever saw the key: no file argument.
    expect(r.calls.some((c) => c.file)).toBe(false);
  });

  it("--via-temp-file: a 0600 temp file is used and deleted, and output has no private key", () => {
    const r = run(["--project=agentreel-test", "--via-temp-file"]);
    expect(r.status).toBe(0);
    const create = r.calls.find((c) => c.args[1] === "create")!;
    expect(create.file).toBeTruthy();
    expect(create.fileMode).toBe(0o600);
    expect(create.stdin).toBe("");
    expect(existsSync(create.file!)).toBe(false);
    expect(existsSync(dirname(create.file!))).toBe(false);
    expectNoSecret(r.stdout, create.fileContent!);
    expectNoSecret(r.stderr, create.fileContent!);
    expect(r.stdout).toMatch(/^key_id=ed25519-[0-9a-f]{16}\npublic_key=[A-Za-z0-9_-]{43}\n$/);
  });

  it("a gcloud failure prints no key at all and deletes the temp file", () => {
    for (const extra of [[], ["--via-temp-file"]]) {
      const r = run(["--project", "agentreel-test", ...extra], { MOCK_FAIL: "1" });
      expect(r.status).toBe(1);
      expect(r.stdout).toBe("");
      const create = r.calls.find((c) => c.args[1] === "create")!;
      expectNoSecret(r.stderr, create.stdin || create.fileContent!);
      if (create.file) expect(existsSync(create.file)).toBe(false);
    }
  });

  it("refuses to add a version to an existing secret unless --add-version", () => {
    const r = run(["--project", "agentreel-test"], { MOCK_EXISTS: "1" });
    expect(r.status).toBe(3);
    expect(r.stdout).toBe("");
    expect(r.calls.map((c) => c.args[1])).toEqual(["describe"]);
    const rot = run(["--project", "agentreel-test", "--add-version"], { MOCK_EXISTS: "1" });
    expect(rot.status).toBe(0);
    const add = rot.calls.find((c) => c.args[1] === "versions")!;
    expect(add.args.slice(0, 4)).toEqual(["secrets", "versions", "add", "POLICY_SIGNING_PRIVATE_KEY"]);
    expectNoSecret(rot.stdout + rot.stderr, add.stdin);
  });

  it("requires a project id and calls nothing without one", () => {
    const r = run([]);
    expect(r.status).toBe(2);
    expect(r.calls).toEqual([]);
    expect(r.stdout).toBe("");
  });
});
