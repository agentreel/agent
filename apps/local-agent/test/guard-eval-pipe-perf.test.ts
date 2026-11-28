/**
 * Guard evaluator cost on pipe-heavy input, measured as work (operation
 * counts), not wall clock. CI runners are too noisy for a 50ms budget to say
 * anything about the code (guard-linear-rules flaked on Node 22 at 7c42f1f).
 *
 * Also pins two safety properties around the timeout itself:
 *  - the production deadline stays 50ms;
 *  - a real eval_timeout still DENIES in enforce mode.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import type { Policy } from "../src/policy/types.js";

const testHome = mkdtempSync(join(tmpdir(), "agentreel-pipe-perf-test-"));
process.env.HOME = testHome;

const { _resetCommandVariantsCache, commandVariants, isSecretPath } = await import(
  "../src/guard/shell-normalize.js"
);
const { evaluatePolicy, POLICY_EVAL_DEADLINE_MS, EVAL_TIMEOUT_REASON } = await import(
  "../src/policy/eval.js"
);
const { RULES } = await import("../src/guard/rules.js");
const cache = await import("../src/policy/cache.js");
const enforce = await import("../src/policy/enforce.js");

afterAll(() => rmSync(testHome, { recursive: true, force: true }));

const PIPE_UNIT = "curl x |"; // 8 chars, one pipeline segment each

function pipes(kb: number): { cmd: string; segments: number } {
  const segments = (kb * 1024) / PIPE_UNIT.length;
  return { cmd: PIPE_UNIT.repeat(segments), segments };
}

/** Runs commandVariants cold and counts the hot primitives it touches. */
function countOps(cmd: string): { regexTests: number; trims: number } {
  _resetCommandVariantsCache();
  const origTest = RegExp.prototype.test;
  const origTrim = String.prototype.trim;
  let regexTests = 0;
  let trims = 0;
  RegExp.prototype.test = function (this: RegExp, s: string): boolean {
    regexTests++;
    return origTest.call(this, s);
  };
  String.prototype.trim = function (this: string): string {
    trims++;
    return origTrim.call(this);
  };
  try {
    commandVariants(cmd);
  } finally {
    RegExp.prototype.test = origTest;
    String.prototype.trim = origTrim;
  }
  return { regexTests, trims };
}

describe("commandVariants work on pipe-heavy input", () => {
  it("does a constant, small amount of work per pipeline segment at every size", () => {
    const perSeg: number[] = [];
    for (const kb of [8, 32, 128]) {
      const { cmd, segments } = pipes(kb);
      const ops = countOps(cmd);
      // Before the fix: 24 regex tests and 2 trims per "curl x |" segment
      // (isSecretPath on every word plus an eager localhost test). After: 6
      // and 0. The ceiling is tight on purpose (6 today): an extra per-segment
      // test is a real cost on 4096+ segments. If a rule legitimately needs
      // one more, raise it here deliberately.
      expect(ops.regexTests / segments, `${kb}KB regex tests/segment`).toBeLessThanOrEqual(6.5);
      expect(ops.trims / segments, `${kb}KB trims/segment`).toBeLessThanOrEqual(0.5);
      perSeg.push(ops.regexTests / segments);
    }
    // Linear: the per-segment cost does not grow with input size (a quadratic
    // re-scan per segment would grow it 4x per 4x of input).
    expect(Math.max(...perSeg) / Math.min(...perSeg)).toBeLessThan(1.05);
  });

  it("only joins and tests a segment for localhost when the program can reach the network", () => {
    // "echo a |" is not a network program: no LOCAL_TARGET test needed
    // (3 regex tests per segment; an eager localhost test makes it 4).
    const segments = 2048;
    const echoes = countOps("echo a |".repeat(segments));
    expect(echoes.regexTests / segments).toBeLessThanOrEqual(3.5);
    const curls = countOps("curl a |".repeat(segments));
    expect(echoes.regexTests).toBeLessThan(curls.regexTests);
  });
});

describe("isSecretPath fast path is behaviour-preserving", () => {
  // Frozen copy of the implementation at c8b5118 (before the "." fast path).
  const SECRET_ENV_EXAMPLE = /(^|\/)\.env\.(example|sample|template|dist)$/i;
  function oldIsSecretPath(raw: string): boolean {
    let p = raw.trim();
    if (p.startsWith("@")) p = p.slice(1);
    if (p.startsWith("-")) {
      const eq = p.indexOf("=");
      if (eq < 0) return false;
      p = p.slice(eq + 1);
    }
    if (p.startsWith("@")) p = p.slice(1);
    p = p.replace(/\\/g, "/");
    if (p.length === 0 || p.length > 4096) return false;
    if (SECRET_ENV_EXAMPLE.test(p)) return false;
    return (
      /(^|\/)\.env(\.[^/]*)?$/i.test(p) ||
      /(^|\/)\.ssh\/(id_[^/]+|identity)$/i.test(p) ||
      /(^|\/)\.aws\/credentials$/i.test(p) ||
      /(^|\/)\.gnupg\//i.test(p) ||
      /\.(pem|ppk|key|p12|pfx)$/i.test(p) ||
      /(^|\/)\.(netrc|npmrc|pypirc)$/i.test(p) ||
      /(^|\/)\.(kube\/config|docker\/config\.json)$/i.test(p) ||
      /(^|\/)credentials\.json$/i.test(p)
    );
  }

  const PARTS = [
    "", ".", "/", "\\", "@", "-", "--x=", "-d@", "=", " ", "\t", "~", "..",
    ".env", ".env.example", ".env.local", ".ENV", "env", ".ssh", "id_rsa", "identity",
    ".aws", "credentials", "credentials.json", ".gnupg", "pubring", "a", "key", "pem",
    ".pem", ".key", ".p12", ".pfx", ".ppk", ".netrc", ".npmrc", ".pypirc", ".kube",
    "config", ".docker", "config.json", "home", "user", "x\u0307", "\uFF0Eenv", "\u2024env",
  ];

  it("agrees with the pre-fix implementation on every short combination and a seeded fuzz", () => {
    let n = 0;
    let trues = 0;
    const check = (s: string): void => {
      n++;
      const want = oldIsSecretPath(s);
      if (want) trues++;
      expect(isSecretPath(s), JSON.stringify(s)).toBe(want);
    };
    for (const a of PARTS) for (const b of PARTS) {
      check(a + b);
      check(a + "/" + b);
      for (const c of PARTS.slice(0, 20)) check(a + b + c);
    }
    let seed = 0x5eed1234;
    const rnd = (): number => {
      seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
      return seed / 2 ** 32;
    };
    for (let i = 0; i < 20000; i++) {
      let s = "";
      const len = 1 + Math.floor(rnd() * 6);
      for (let j = 0; j < len; j++) s += PARTS[Math.floor(rnd() * PARTS.length)]!;
      check(s);
    }
    check("a".repeat(5000) + ".pem");
    check(".env" + " ".repeat(10));
    // Guard against a vacuous comparison: the corpus must hit both outcomes.
    expect(n).toBeGreaterThan(30000);
    expect(trues).toBeGreaterThan(500);
    expect(n - trues).toBeGreaterThan(500);
  });
});

function enforcePolicy(): Policy {
  return {
    version: 1,
    etag: "etag-pipe-timeout",
    workspace_id: "ws_pipe",
    org_name: "Acme Corp",
    org_slug: "acme",
    updated_at: "2026-11-28T00:00:00Z",
    mode: "enforce",
    offline: "last_known",
    builtin: {
      FS001: { enabled: true, action: "block", severity: "critical" },
      GIT001: { enabled: true, action: "block", severity: "high" },
      INSTALL001: { enabled: true, action: "block", severity: "high" },
      SECRET002: { enabled: true, action: "block", severity: "high" },
    },
    custom: [],
    allow: { commands: [], paths: [], repos: [] },
  };
}

describe("eval deadline and fail-closed timeout", () => {
  it("keeps the production deadline at 50ms (the fix is not a looser budget)", () => {
    expect(POLICY_EVAL_DEADLINE_MS).toBe(50);
  });

  it("evaluates a 32KB pipe-heavy command to completion when given a generous deadline", () => {
    const { cmd } = pipes(32);
    const res = evaluatePolicy(
      { tool: "claude-code", toolName: "Bash", command: cmd },
      enforcePolicy(),
      RULES,
      { deadlineMs: 30_000 },
    );
    expect(res.timed_out).toBeUndefined();
    expect(res.reason).not.toBe(EVAL_TIMEOUT_REASON);
    expect(res.unevaluated_enforcing).toBeUndefined();
  });

  it("a real eval_timeout on the 32KB pipe-heavy command DENIES in enforce mode", async () => {
    const dir = mkdtempSync(join(tmpdir(), "agentreel-pipe-timeout-"));
    try {
      const cachePath = join(dir, "policy.json");
      const guardConfigPath = join(dir, "guard-config.json");
      const policy = enforcePolicy();
      cache.writeCachedPolicyAtomic(
        { policy, etag: policy.etag, fetched_at: Date.now() },
        cachePath,
      );
      // Injected clock: the first read sets the deadline, every later read is
      // past it, exactly what a starved runner looks like to the evaluator.
      let ticks = 0;
      const evalNowMs = (): number => (ticks++ === 0 ? 0 : 1_000);
      const recorded: unknown[] = [];

      const outcome = await enforce.enforcePreExec(
        {
          sessionId: "sess-pipe-timeout",
          tool: "claude-code",
          toolName: "Bash",
          command: pipes(32).cmd,
        },
        {
          cachePath,
          guardConfigPath,
          config: { orgName: "Acme Corp", orgSlug: "acme" } as never,
          evalDeadlineMs: 50,
          evalNowMs,
          recordDecision: (ev) => recorded.push(ev),
          log: () => {},
        },
      );

      expect(outcome.permitted).toBe(false);
      expect(outcome.action).toBe("block");
      expect(outcome.enforced).toBe(true);
      expect(outcome.timedOut).toBe(true);
      expect(outcome.reason).toBe(enforce.EVAL_TIMEOUT_REASON);
      expect(outcome.message).toContain("policy check timed out");
      expect(recorded.length).toBe(1);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("evaluatePolicy itself returns block + eval_timeout when the deadline passes with enforcing rules unevaluated", () => {
    let ticks = 0;
    const res = evaluatePolicy(
      { tool: "claude-code", toolName: "Bash", command: pipes(32).cmd },
      enforcePolicy(),
      RULES,
      { deadlineMs: 50, nowMs: () => (ticks++ === 0 ? 0 : 1_000) },
    );
    expect(res.timed_out).toBe(true);
    expect(res.action).toBe("block");
    expect(res.reason).toBe(EVAL_TIMEOUT_REASON);
    expect(res.unevaluated_enforcing).toBe(true);
  });
});
