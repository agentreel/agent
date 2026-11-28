#!/usr/bin/env node
// Generates the production Ed25519 policy signing key (agentreel/web
// govern-api.md section 7.2) and stores the private key in GCP Secret
// Manager as POLICY_SIGNING_PRIVATE_KEY (PKCS#8 PEM). Navjot runs this by
// hand; CI and agents never run it against GCP.
//
// The private key is never printed, logged, or written anywhere except:
//   - gcloud's stdin (default), or
//   - with --via-temp-file, a 0600 file in a fresh 0700 temp directory that
//     is overwritten and deleted as soon as gcloud returns, whatever happens.
// Stdout carries only the key id and the public key, to pin in
// apps/local-agent/src/policy/pinned-keys.ts. gcloud's own output goes to
// stderr. See docs/policy-signing-key.md.
//
// Usage:
//   node scripts/generate-policy-signing-key.mjs --project <gcp-project> [--via-temp-file] [--add-version]
//
// GCLOUD_BIN overrides the gcloud binary (tests use a mock).

import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import { closeSync, mkdtempSync, openSync, rmSync, writeSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const SECRET_NAME = "POLICY_SIGNING_PRIVATE_KEY";

function usage(msg) {
  if (msg) process.stderr.write(`error: ${msg}\n`);
  process.stderr.write(
    "usage: node scripts/generate-policy-signing-key.mjs --project <gcp-project> [--via-temp-file] [--add-version]\n",
  );
  process.exit(2);
}

function parseArgs(argv) {
  const opts = { project: null, viaTempFile: false, addVersion: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--project") opts.project = argv[++i] ?? null;
    else if (a.startsWith("--project=")) opts.project = a.slice("--project=".length);
    else if (a === "--via-temp-file") opts.viaTempFile = true;
    else if (a === "--add-version") opts.addVersion = true;
    else if (a === "-h" || a === "--help") usage();
    else usage(`unknown argument ${a}`);
  }
  if (!opts.project || !/^[a-z][a-z0-9-]{4,61}[a-z0-9]$/.test(opts.project)) usage("--project <gcp-project-id> is required");
  return opts;
}

const opts = parseArgs(process.argv.slice(2));
const gcloud = process.env.GCLOUD_BIN || "gcloud";

/** Runs gcloud; its stdout and stderr go to our stderr so stdout stays clean. */
function runGcloud(args, input) {
  const res = spawnSync(gcloud, [...args, `--project=${opts.project}`], {
    input: input ?? "",
    stdio: ["pipe", "pipe", "pipe"],
    encoding: "utf8",
  });
  if (res.stdout) process.stderr.write(res.stdout);
  if (res.stderr) process.stderr.write(res.stderr);
  if (res.error) return { ok: false, detail: res.error.message };
  return { ok: res.status === 0, detail: `gcloud exited ${res.status}` };
}

// Refuse to replace a live key unless asked: a new version switches every
// policy response to the new key at once, which locks out CLIs that do not
// pin it yet (rotation order: pin first, then switch the secret).
const exists = runGcloud(["secrets", "describe", SECRET_NAME, "--format=value(name)"]).ok;
if (exists && !opts.addVersion) {
  process.stderr.write(
    `error: secret ${SECRET_NAME} already exists in ${opts.project}. Nothing was generated or written.\n` +
      "Pass --add-version only for a rotation, after a CLI release pins the new public key.\n",
  );
  process.exit(3);
}
if (!exists && opts.addVersion) {
  process.stderr.write(`error: --add-version given but ${SECRET_NAME} does not exist in ${opts.project}.\n`);
  process.exit(3);
}

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const pem = privateKey.export({ format: "pem", type: "pkcs8" });
const x = publicKey.export({ format: "jwk" }).x;
const keyId = `ed25519-${createHash("sha256").update(Buffer.from(x, "base64url")).digest("hex").slice(0, 16)}`;

const baseArgs = exists
  ? ["secrets", "versions", "add", SECRET_NAME]
  : ["secrets", "create", SECRET_NAME, "--replication-policy=automatic"];

let stored;
if (!opts.viaTempFile) {
  stored = runGcloud([...baseArgs, "--data-file=-"], pem);
} else {
  const dir = mkdtempSync(join(tmpdir(), "agentreel-policy-key-"));
  const file = join(dir, "key.pem");
  try {
    const fd = openSync(file, "wx", 0o600);
    try {
      writeSync(fd, pem);
    } finally {
      closeSync(fd);
    }
    stored = runGcloud([...baseArgs, `--data-file=${file}`]);
  } finally {
    try {
      const fd = openSync(file, "r+");
      try {
        writeSync(fd, Buffer.alloc(Buffer.byteLength(pem)), 0, Buffer.byteLength(pem), 0);
      } finally {
        closeSync(fd);
      }
    } catch {
      // Already gone or never written.
    }
    rmSync(dir, { recursive: true, force: true });
  }
}

if (!stored.ok) {
  process.stderr.write(`error: storing ${SECRET_NAME} failed (${stored.detail}). The generated key was discarded.\n`);
  process.exit(1);
}

process.stderr.write(`Stored a new version of ${SECRET_NAME} in ${opts.project}. Pin this key in the CLI:\n`);
process.stdout.write(`key_id=${keyId}\npublic_key=${x}\n`);
