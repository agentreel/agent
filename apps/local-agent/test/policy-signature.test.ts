import { createPrivateKey, sign } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeEach, describe, expect, it } from "vitest";

const testHome = mkdtempSync(join(tmpdir(), "ar-policy-sig-"));
process.env.HOME = testHome;

const sig = await import("../src/policy/signature.js");
const pinned = await import("../src/policy/pinned-keys.js");
const cache = await import("../src/policy/cache.js");
const fetchMod = await import("../src/policy/fetch.js");
const enforce = await import("../src/policy/enforce.js");

// Published web contract test vector (agentreel/web PR #49). TEST KEY ONLY.
const VECTOR = JSON.parse(
  readFileSync(new URL("./fixtures/policy-signature-vector.json", import.meta.url), "utf8"),
) as {
  seed_hex: string;
  public_key_b64url: string;
  key_id: string;
  signing_input: string;
  signed_policy: Record<string, unknown> & { signature: Record<string, string> };
};
const TEST_KEY = { keyId: VECTOR.key_id, publicKey: VECTOR.public_key_b64url };
const privateKey = createPrivateKey({
  key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(VECTOR.seed_hex, "hex")]),
  format: "der",
  type: "pkcs8",
});

const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;

/** Signs a policy body the way the server does. */
function signBody(body: Record<string, unknown>, signedAt = "2026-11-27T23:05:00.000Z", keyId = VECTOR.key_id) {
  const out: Record<string, unknown> = { ...clone(body), signature: { alg: "Ed25519", key_id: keyId, signed_at: signedAt } };
  const value = sign(null, Buffer.from(sig.policySigningInput(out), "utf8"), privateKey).toString("base64url");
  (out.signature as Record<string, string>).value = value;
  return out;
}

function unsignedBase(overrides: Record<string, unknown> = {}) {
  const { signature: _s, ...rest } = clone(VECTOR.signed_policy);
  return { ...rest, ...overrides };
}

beforeEach(() => {
  pinned._setSignedPolicyRequiredForTests(true);
  pinned._setPinnedPolicyKeysForTests([TEST_KEY]);
});
afterEach(() => {
  pinned._setPinnedPolicyKeysForTests(null);
  pinned._setSignedPolicyRequiredForTests(false);
});
afterAll(() => rmSync(testHome, { recursive: true, force: true }));

describe("web contract test vector", () => {
  it("rebuilds the exact signing input", () => {
    expect(sig.policySigningInput(VECTOR.signed_policy)).toBe(VECTOR.signing_input);
  });

  it("derives the published key id from the public key", () => {
    expect(sig.policyKeyId(Buffer.from(VECTOR.public_key_b64url, "base64url"))).toBe(VECTOR.key_id);
  });

  it("verifies the published signature", () => {
    const res = sig.verifyPolicySignature(VECTOR.signed_policy, [TEST_KEY]);
    expect(res).toEqual({ ok: true, keyId: VECTOR.key_id, signedAt: "2026-11-27T23:05:00.000Z" });
  });

  it("our signer reproduces the published (deterministic) signature", () => {
    const resigned = signBody(unsignedBase());
    expect((resigned.signature as Record<string, string>).value).toBe(VECTOR.signed_policy.signature.value);
  });

  it("the shipped CLI does not pin the test key", () => {
    expect(pinned.PINNED_POLICY_KEYS.some((k) => k.keyId === VECTOR.key_id)).toBe(false);
  });
});

describe("verifyPolicySignature denials", () => {
  const tamper: Array<[string, (b: Record<string, unknown>) => void]> = [
    ["mode downgraded to observe", (b) => (b.mode = "observe")],
    ["builtin rule disabled", (b) => ((b.builtin as Record<string, { enabled: boolean }>).GIT001!.enabled = false)],
    ["allowlist widened", (b) => ((b.allow as { commands: string[] }).commands = ["*"])],
    ["org swapped", (b) => (b.org_id = "22222222-2222-4222-8222-222222222222")],
    ["fetched_at changed", (b) => (b.fetched_at = "2026-11-28T00:00:00.000Z")],
    ["field injected", (b) => (b.extra = true)],
    ["signed_at changed", (b) => ((b.signature as Record<string, string>).signed_at = "2026-11-28T00:00:00.000Z")],
  ];
  for (const [label, edit] of tamper) {
    it(`rejects a tampered body: ${label}`, () => {
      const body = clone(VECTOR.signed_policy) as Record<string, unknown>;
      edit(body);
      const res = sig.verifyPolicySignature(body, [TEST_KEY]);
      expect(res.ok).toBe(false);
      if (!res.ok) expect(res.reason).toBe("bad_signature");
    });
  }

  it("rejects an unknown key id (nothing pinned)", () => {
    const res = sig.verifyPolicySignature(VECTOR.signed_policy, []);
    expect(res.ok === false && res.reason).toBe("unknown_key_id");
  });

  it("rejects a pinned key that does not hash to its key id", () => {
    const wrong = { keyId: VECTOR.key_id, publicKey: Buffer.alloc(32, 7).toString("base64url") };
    const res = sig.verifyPolicySignature(VECTOR.signed_policy, [wrong]);
    expect(res.ok === false && res.reason).toBe("key_id_mismatch");
  });

  it("rejects malformed signatures", () => {
    const cases: Array<(s: Record<string, unknown>) => void> = [
      (s) => (s.alg = "RS256"),
      (s) => (s.value = "abc"),
      (s) => (s.key_id = "ed25519-XYZ"),
      (s) => (s.signed_at = "yesterday"),
      (s) => (s.extra = 1),
      (s) => delete s.value,
    ];
    for (const edit of cases) {
      const body = clone(VECTOR.signed_policy) as Record<string, unknown>;
      edit(body.signature as Record<string, unknown>);
      const res = sig.verifyPolicySignature(body, [TEST_KEY]);
      expect(res.ok === false && res.reason).toBe("malformed_signature");
    }
  });

  it("reports a missing signature", () => {
    const res = sig.verifyPolicySignature(unsignedBase(), [TEST_KEY]);
    expect(res.ok === false && res.reason).toBe("missing_signature");
  });

  it("never throws on hostile input", () => {
    expect(sig.verifyPolicySignature(null, [TEST_KEY]).ok).toBe(false);
    const body = clone(VECTOR.signed_policy) as Record<string, unknown>;
    body.bad = "\ud800";
    expect(sig.verifyPolicySignature(body, [TEST_KEY]).ok).toBe(false);
  });
});

// ---------------------------------------------------------------- fetch and cache

let n = 0;
function cachePathFor() {
  const dir = mkdtempSync(join(testHome, `c${n++}-`));
  return join(dir, "policy.json");
}

const config = {
  apiBaseUrl: "http://policy.invalid",
  apiKey: "ar_live_test",
  installedHookTimeouts: { claude: 130, cursor: 130 },
  schemaVersion: 1,
} as never;

function respond(body: unknown, etag?: string | null, status = 200) {
  const headers: Record<string, string> = { "content-type": "application/json" };
  const tag = etag === undefined ? (body as { etag?: string })?.etag : etag;
  if (tag) headers.etag = `"${tag}"`;
  if (status === 304) return (async () => new Response(null, { status: 304, headers })) as unknown as typeof fetch;
  return (async () => new Response(JSON.stringify(body), { status, headers })) as unknown as typeof fetch;
}

async function fetchWith(cachePath: string, fetchImpl: typeof fetch) {
  return fetchMod.fetchPolicy({ config, cachePath, fetchImpl, log: () => {} });
}

describe("fetchPolicy verifies signed policies", () => {
  it("installs a signed enforcing policy and stores the raw signed body", async () => {
    const cachePath = cachePathFor();
    const res = await fetchWith(cachePath, respond(VECTOR.signed_policy));
    expect(res.status).toBe("updated");
    const file = JSON.parse(readFileSync(cachePath, "utf8"));
    expect(file.signed_body).toEqual(VECTOR.signed_policy);
    expect(cache.readCachedPolicy(cachePath)?.policy.mode).toBe("enforce");
    expect(cache.loadEffectivePolicy({ cachePath, guardConfigPath: join(testHome, "none.json") }).source).toBe("server_cache");
  });

  it("rejects an unsigned enforcing org policy and installs nothing", async () => {
    const cachePath = cachePathFor();
    const res = await fetchWith(cachePath, respond(unsignedBase()));
    expect(res.status).toBe("invalid_policy");
    expect(cache.readCachedPolicy(cachePath)).toBeNull();
    expect(cache.readPolicyRejection(cachePath)?.reason).toBe("invalid_signature");
  });

  it("accepts an unsigned observe policy (it never blocks)", async () => {
    const res = await fetchWith(cachePathFor(), respond(unsignedBase({ mode: "observe" })));
    expect(res.status).toBe("updated");
  });

  it("rejects an unknown key id and keeps the last verified cache", async () => {
    const cachePath = cachePathFor();
    await fetchWith(cachePath, respond(VECTOR.signed_policy));
    pinned._setPinnedPolicyKeysForTests([]);
    const newer = signBody(unsignedBase({ etag: "p2-newer", mode: "observe" }), "2026-11-28T00:00:00.000Z");
    const res = await fetchWith(cachePath, respond(newer));
    expect(res.status).toBe("invalid_policy");
    pinned._setPinnedPolicyKeysForTests([TEST_KEY]);
    expect(cache.readCachedPolicy(cachePath)?.policy.etag).toBe(VECTOR.signed_policy.etag);
  });

  it("rejects a tampered body even when the signature field is present", async () => {
    const body = clone(VECTOR.signed_policy) as Record<string, unknown>;
    body.mode = "observe";
    const res = await fetchWith(cachePathFor(), respond(body));
    expect(res.status).toBe("invalid_policy");
  });

  it("rejects when the ETag header does not match the body etag", async () => {
    expect((await fetchWith(cachePathFor(), respond(VECTOR.signed_policy, "other"))).status).toBe("invalid_policy");
    expect((await fetchWith(cachePathFor(), respond(VECTOR.signed_policy, null))).status).toBe("invalid_policy");
  });

  it("rejects a rollback to an older signed_at for the same org", async () => {
    const cachePath = cachePathFor();
    await fetchWith(cachePath, respond(VECTOR.signed_policy));
    const older = signBody(unsignedBase({ etag: "p0-older", mode: "observe" }), "2026-11-27T22:00:00.000Z");
    const res = await fetchWith(cachePath, respond(older));
    expect(res.status).toBe("invalid_policy");
    if (res.status === "invalid_policy") expect(res.error).toContain("rollback");
    const newer = signBody(unsignedBase({ etag: "p2-newer" }), "2026-11-28T01:00:00.000Z");
    expect((await fetchWith(cachePath, respond(newer))).status).toBe("updated");
  });

  it("a 304 keeps the signed body, which still verifies", async () => {
    const cachePath = cachePathFor();
    await fetchWith(cachePath, respond(VECTOR.signed_policy));
    const res = await fetchWith(cachePath, respond(null, VECTOR.signed_policy.etag as string, 304));
    expect(res.status).toBe("not_modified");
    expect(JSON.parse(readFileSync(cachePath, "utf8")).signed_body).toEqual(VECTOR.signed_policy);
    expect(cache.readCachedPolicy(cachePath)).not.toBeNull();
  });
});

describe("cached policy is re-verified on every load", () => {
  async function signedCache() {
    const cachePath = cachePathFor();
    await fetchWith(cachePath, respond(VECTOR.signed_policy));
    return cachePath;
  }
  const edit = (cachePath: string, fn: (f: Record<string, any>) => void) => {
    const f = JSON.parse(readFileSync(cachePath, "utf8"));
    fn(f);
    writeFileSync(cachePath, JSON.stringify(f), "utf8");
  };

  it("an edited signed body fails verification", async () => {
    const cachePath = await signedCache();
    edit(cachePath, (f) => (f.signed_body.mode = "observe"));
    expect(cache.readCachedPolicy(cachePath)).toBeNull();
  });

  it("an edited normalized copy is ignored: the policy is rebuilt from the signed body", async () => {
    const cachePath = await signedCache();
    edit(cachePath, (f) => {
      f.policy.mode = "observe";
      f.policy.builtin = {};
    });
    const read = cache.readCachedPolicy(cachePath);
    expect(read?.policy.mode).toBe("enforce");
    expect(read?.policy.builtin.GIT001?.action).toBe("block");
  });

  it("an enforcing cache with the signed body removed is rejected", async () => {
    const cachePath = await signedCache();
    edit(cachePath, (f) => delete f.signed_body);
    expect(cache.readCachedPolicy(cachePath)).toBeNull();
  });

  it("a cache signed by a key this CLI no longer pins is rejected (revocation)", async () => {
    const cachePath = await signedCache();
    pinned._setPinnedPolicyKeysForTests([]);
    expect(cache.readCachedPolicy(cachePath)).toBeNull();
  });
});

describe("explicit auth and enforcement with a signed policy", () => {
  it("agentreel link installs the signed body so the cache verifies afterwards", async () => {
    const { createServer } = await import("node:http");
    const srv = createServer((req, res) => {
      const path = new URL(req.url ?? "/", "http://x").pathname;
      if (path === "/api/v1/sessions/ingest") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true }));
        return;
      }
      if (path === "/api/v1/policy") {
        res.writeHead(200, { "content-type": "application/json", etag: `"${VECTOR.signed_policy.etag}"` });
        res.end(JSON.stringify(VECTOR.signed_policy));
        return;
      }
      res.writeHead(404);
      res.end();
    });
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    const port = (srv.address() as { port: number }).port;
    const cachePath = cachePathFor();
    const quiet = { log: console.log, error: console.error };
    console.log = () => {};
    console.error = () => {};
    try {
      const { linkCommand } = await import("../src/commands/auth.js");
      await linkCommand("ar_live_signed_key", { api: `http://127.0.0.1:${port}`, cachePath });
    } finally {
      console.log = quiet.log;
      console.error = quiet.error;
      await new Promise((r) => srv.close(r));
    }
    expect(JSON.parse(readFileSync(cachePath, "utf8")).signed_body).toEqual(VECTOR.signed_policy);
    expect(cache.readCachedPolicy(cachePath)?.policy.mode).toBe("enforce");
  });

  it("a verified cache blocks; a tampered one is not used as the server policy", async () => {
    const enforce = await import("../src/policy/enforce.js");
    const cachePath = cachePathFor();
    await fetchWith(cachePath, respond(VECTOR.signed_policy));
    const deps = {
      cachePath,
      guardConfigPath: join(testHome, "none.json"),
      config: { apiBaseUrl: "http://127.0.0.1:1", installedHookTimeouts: { claude: 130, cursor: 130 }, schemaVersion: 1 } as never,
      recordDecision: () => {},
    };
    const req = { sessionId: "s", tool: "claude-code" as const, toolName: "Bash", command: "git push --force origin main" };
    expect((await enforce.enforcePreExec(req, deps)).permitted).toBe(false);

    const f = JSON.parse(readFileSync(cachePath, "utf8"));
    f.signed_body.builtin.GIT001.enabled = false;
    writeFileSync(cachePath, JSON.stringify(f), "utf8");
    expect(cache.loadEffectivePolicy({ cachePath, guardConfigPath: deps.guardConfigPath }).source).not.toBe("server_cache");
  });
});

describe("fail closed while no key is pinned", () => {
  const run = (cachePath: string, command = "git push --force origin main") =>
    enforce.enforcePreExec(
      { sessionId: "s", tool: "claude-code", toolName: "Bash", command },
      {
        cachePath,
        guardConfigPath: join(testHome, "none.json"),
        config: {
          apiBaseUrl: "http://127.0.0.1:1",
          installedHookTimeouts: { claude: 130, cursor: 130 },
          schemaVersion: 1,
        } as never,
        recordDecision: () => {},
      },
    );

  it("fresh machine: a rejected signed enforcing policy writes the marker and denies", async () => {
    pinned._setPinnedPolicyKeysForTests([]);
    const cachePath = cachePathFor();
    const res = await fetchWith(cachePath, respond(VECTOR.signed_policy));
    expect(res.status).toBe("invalid_policy");
    expect(cache.readCachedPolicy(cachePath)).toBeNull();
    expect(cache.readEnforcementMarker(cachePath)).not.toBeNull();
    const loaded = cache.loadEffectivePolicy({ cachePath, guardConfigPath: join(testHome, "none.json") });
    expect(loaded.source).toBe("enforced_lockdown");
    expect((await run(cachePath)).permitted).toBe(false);
    expect((await run(cachePath, "ls -la")).permitted).toBe(true);
  });

  it("upgrade without a marker: an unsigned enforcing cache locks down and denies", async () => {
    pinned._setPinnedPolicyKeysForTests([]);
    const cachePath = cachePathFor();
    const unsigned = unsignedBase();
    writeFileSync(
      cachePath,
      JSON.stringify({ policy: unsigned, etag: unsigned.etag, fetched_at: Date.now() }),
      "utf8",
    );
    expect(cache.readEnforcementMarker(cachePath)).toBeNull();
    expect(cache.readCachedPolicy(cachePath)).toBeNull();
    expect(cache.readEnforcementMarker(cachePath)).not.toBeNull();
    const loaded = cache.loadEffectivePolicy({ cachePath, guardConfigPath: join(testHome, "none.json") });
    expect(loaded.source).toBe("enforced_lockdown");
    expect(loaded.lockdownReason).toBe("policy_invalid");
    expect((await run(cachePath)).permitted).toBe(false);
  });
});
