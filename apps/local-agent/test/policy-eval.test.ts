import { existsSync, readFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";
import { RULES } from "../src/guard/rules.js";
import {
  EVAL_TIMEOUT_REASON,
  evaluatePolicy,
  INVALID_RULE_REASON,
  matchGlob,
  POLICY_EVAL_DEADLINE_MS,
  type PolicyEvalInput,
} from "../src/policy/eval.js";
import {
  clearRegexCache,
  compileSafeRegex,
  getRegexCacheSize,
  isRe2SafePattern,
  MAX_REGEX_CACHE_SIZE,
  MAX_REGEX_LENGTH,
  testSafeRegex,
} from "../src/policy/regex.js";
import { validatePolicy, type Policy, type PolicyDecisionAction } from "../src/policy/types.js";

interface PolicyFixtureCase {
  name: string;
  expected_valid?: boolean;
  expected_rejected_rule_id?: string;
  expected_rejected_condition_index?: number;
  policy: Policy;
  input: PolicyEvalInput;
  expected: {
    action: PolicyDecisionAction;
    rule_ids: string[];
    reason?: string;
    invalid_rule_ids?: string[];
  };
}

interface PolicyFixturesFile {
  _note: string;
  cases: PolicyFixtureCase[];
}

const here = dirname(fileURLToPath(import.meta.url));
const fixturesPath = join(here, "fixtures", "policy-fixtures.json");
const fixtures = JSON.parse(
  readFileSync(fixturesPath, "utf8"),
) as PolicyFixturesFile;

describe("shared policy-fixtures.json parity", () => {
  it("is marked provisional and has at least 25 valid cases", () => {
    expect(typeof fixtures._note).toBe("string");
    expect(fixtures._note.toUpperCase()).toContain("PROVISIONAL");
    expect(fixtures.cases.length).toBeGreaterThanOrEqual(25);
  });

  it.each(fixtures.cases)("$name", (fixtureCase) => {
    const validated = validatePolicy(fixtureCase.policy);
    if (fixtureCase.expected_valid === false) {
      expect(validated.ok).toBe(false);
      if (!validated.ok) {
        if (fixtureCase.expected_rejected_rule_id) {
          expect(validated.error).toContain(fixtureCase.expected_rejected_rule_id);
          expect(validated.rejectedRuleId).toBe(
            fixtureCase.expected_rejected_rule_id,
          );
        }
        if (fixtureCase.expected_rejected_condition_index !== undefined) {
          expect(validated.error).toContain(
            `when[${fixtureCase.expected_rejected_condition_index}]`,
          );
          expect(validated.rejectedConditionIndex).toBe(
            fixtureCase.expected_rejected_condition_index,
          );
        }
      }
    } else {
      expect(validated.ok).toBe(true);
    }

    const result = evaluatePolicy(fixtureCase.input, fixtureCase.policy);
    expect(result.action).toBe(fixtureCase.expected.action);
    expect(result.rule_ids).toEqual(fixtureCase.expected.rule_ids);
    if (fixtureCase.expected.reason !== undefined) {
      expect(result.reason).toBe(fixtureCase.expected.reason);
    }
    if (fixtureCase.expected.invalid_rule_ids !== undefined) {
      expect(result.invalid_rule).toBe(true);
      expect(result.invalid_rule_ids).toEqual(
        fixtureCase.expected.invalid_rule_ids,
      );
    }

    // Every match carries rule_id and name/message
    expect(result.matches.length).toBe(fixtureCase.expected.rule_ids.length);
    for (const m of result.matches) {
      expect(m.rule_id.length).toBeGreaterThan(0);
      expect(m.name.length).toBeGreaterThan(0);
      expect(m.message.length).toBeGreaterThan(0);
    }

    if (fixtureCase.policy.mode === "observe") {
      expect(result.action).not.toBe("block");
      expect(result.action).not.toBe("require_approval");
    }
  });
});

describe("observe mode never blocks or requires approval", () => {
  it("downgrades block and require_approval to flag and sets downgraded=true", () => {
    const basePolicy: Policy = {
      version: 1,
      etag: "etag-obs",
      workspace_id: "ws_1",
      updated_at: "2026-11-25T00:00:00Z",
      mode: "observe",
      offline: "last_known",
      builtin: {
        CLOUD001: { enabled: true, action: "block" },
        GIT001: { enabled: true, action: "require_approval" },
      },
      custom: [
        {
          id: "c_flag",
          name: "Flag echo",
          enabled: true,
          version: 1,
          message: "Just flagging",
          when: [{ field: "command", op: "equals", value: "echo flagged" }],
          action: "flag",
          severity: "info",
          scope: {},
        },
      ],
      allow: { commands: [], paths: [], repos: [] },
    };

    const blocked = evaluatePolicy(
      { tool: "claude-code", toolName: "Bash", command: "terraform destroy" },
      basePolicy,
    );
    expect(blocked.action).toBe("flag");
    expect(blocked.downgraded).toBe(true);
    expect(blocked.original_action).toBe("block");
    expect(blocked.rule_ids).toEqual(["CLOUD001"]);

    const approval = evaluatePolicy(
      {
        tool: "cursor",
        toolName: "Shell",
        command: "git push --force origin main",
      },
      basePolicy,
    );
    expect(approval.action).toBe("flag");
    expect(approval.downgraded).toBe(true);
    expect(approval.original_action).toBe("require_approval");
    expect(approval.rule_ids).toEqual(["GIT001"]);

    const flagged = evaluatePolicy(
      { tool: "claude-code", toolName: "Bash", command: "echo flagged" },
      basePolicy,
    );
    expect(flagged.action).toBe("flag");
    expect(flagged.downgraded).toBe(false);
    expect(flagged.original_action).toBeUndefined();
  });
});

describe("RE2-safe regex compiler, cache, and timeout guard", () => {
  it("accepts safe RE2 patterns up to 300 chars and benign alternations without repeating quantifiers", () => {
    const pat = "a".repeat(MAX_REGEX_LENGTH);
    expect(isRe2SafePattern(pat)).toBe(true);
    const re = compileSafeRegex(pat);
    expect(re).toBeInstanceOf(RegExp);
    expect(testSafeRegex(re!, pat)).toBe(true);

    expect(isRe2SafePattern("^https://(api|admin)\\.example\\.com")).toBe(true);
    expect(isRe2SafePattern("(foo|bar)?baz")).toBe(true);
    expect(compileSafeRegex("^https://(api|admin)\\.example\\.com")).toBeInstanceOf(RegExp);
  });

  it("statically rejects over-length, invalid, lookaround, backreference, nested-quantifier, and alternation-plus-quantifier patterns", () => {
    expect(compileSafeRegex("a".repeat(MAX_REGEX_LENGTH + 1))).toBeNull();
    expect(compileSafeRegex("[unclosed(")).toBeNull();
    expect(compileSafeRegex("foo(?=bar)")).toBeNull();
    expect(compileSafeRegex("foo(?!bar)")).toBeNull();
    expect(compileSafeRegex("(?<=foo)bar")).toBeNull();
    expect(compileSafeRegex("(?<!foo)bar")).toBeNull();
    expect(compileSafeRegex("(foo)\\1")).toBeNull();
    expect(compileSafeRegex("(?<w>foo)\\k<w>")).toBeNull();
    expect(compileSafeRegex("(a+)+b")).toBeNull();
    expect(compileSafeRegex("([a-z]*)*$")).toBeNull();
    expect(compileSafeRegex("a{1,500}")).toBeNull();
    // Alternation-plus-quantifier ReDoS patterns statically rejected
    expect(isRe2SafePattern("(a|aa)+$")).toBe(false);
    expect(isRe2SafePattern("(a|a?)+")).toBe(false);
    expect(isRe2SafePattern("(x|xy)*")).toBe(false);
    expect(isRe2SafePattern("((a|aa))+$")).toBe(false);
    expect(isRe2SafePattern("(foo|foobar){2,10}")).toBe(false);
    expect(compileSafeRegex("(a|aa)+$")).toBeNull();
    expect(compileSafeRegex("(a|a?)+")).toBeNull();
    expect(compileSafeRegex("(x|xy)*")).toBeNull();
  });

  it("statically rejects optional-quantifier-in-repeating-group ReDoS while allowing safe optional patterns", () => {
    expect(isRe2SafePattern("(a?a)+$")).toBe(false);
    expect(isRe2SafePattern("(a{0,1}a)+$")).toBe(false);
    expect(isRe2SafePattern("(\\w+-?)+$")).toBe(false);
    expect(isRe2SafePattern("https?://example\\.com")).toBe(true);
    expect(isRe2SafePattern("(foo|bar)?")).toBe(true);
    expect(isRe2SafePattern("(https?://[a-z]+)?")).toBe(true);
  });

  it("statically rejects overlapping multiple unbounded quantifiers while accepting disjoint-separated org patterns", () => {
    const rejected = [
      // Round 4 existing rejects (all preserved)
      "a.*a.*b",
      "a.*a.*a.*a.*a.*a.*a.*a.*b",
      "(a+)+",
      ".*x.*y",
      "a+b+",
      "a{1,}b{1,}",
      "a.*b{2,}",
      ".*?foo.*?bar",
      "\\w+.*\\w+",
      // Round 5 required overlapping rejects
      "curl.*\\|\\s*(ba)?sh",
      ".*passwd.*",
      "kubectl\\s+delete\\s+.*prod",
      "\\w+\\s*\\w+",
      // Leading-literal rejects (2+ unbounded without mandatory leading literal
      // or where the last char of the leading literal overlaps the first unbounded atom)
      "\\w+\\s+\\w+",
      "\\S+\\s+\\S+",
      "[a-z]+@[a-z]+",
      "a+\\s+b+",
      "[a-z]\\s+foo\\s+bar",
      "(DROP|)\\s+TABLE\\s+\\w+",
      "a?\\s+foo\\s+bar",
      "(ba)?\\s+foo\\s+bar",
      "A\\w+\\s+\\w+",
      "a\\w+\\s+\\w+",
      "(?:a)\\w+\\s+\\w+",
      "\\x41\\w+\\s+\\w+",
      "a[a-z]+\\s+\\w+",
      "(DROP|TRUNCATE)\\w+\\s+\\w+",
      "(:|DROP)\\w+\\s+\\w+",
      "curl[^|]*\\|\\s*(ba)?sh",
      "(curl|wget)[^|]*\\|\\s*(ba|z)?sh",
      "foo[\\x41-\\x5A]+@[\\x41-\\x5A]+",
      // Non-ASCII literals are universal in the disjointness model, so a
      // Kelvin / long-s leading literal or separator is never disjoint.
      // "\\u{1F600}\\s+\\w+" was accepted before this rule.
      "\\u212A\\w+\\s+\\w+\\u{1F600}?",
      "\\u017F\\w+\\s+\\w+\\u{1F600}?",
      "\\u212A\\w+\\s+\\w+",
      "\\w+\\u212A\\w+",
      "x\\u212A[a-z]+\\s+\\w+",
      "\\u{1F600}\\s+\\w+",
      // Extra conservative boundary rejects
      "\\s+[a-z]*\\s+",
      "a+x?a+",
      "a+Ab+",
      "\\s+\\s+",
      "a+^a+",
      "a+\\ba+",
    ];
    for (const pat of rejected) {
      expect(isRe2SafePattern(pat), `expected reject: ${pat}`).toBe(false);
      expect(compileSafeRegex(pat), `expected null compile: ${pat}`).toBeNull();
    }

    const accepted = [
      // Single-unbounded legitimate fixtures (unaffected by leading-literal rule)
      "^https://[a-z0-9-]+\\.internal\\.corp/admin",
      "^deploy-service-0 --env=(prod|staging) --region=[a-z0-9-]+$",
      "https?://example\\.com/[a-z0-9/_-]+",
      "[a*+]+",
      "a\\*b\\+.*c",
      "^rule_1_[0-9]{1,4}_[a-z]+$",
      "\\w+",
      "[a-z]+",
      ".*foo",
      "curl[^|]*\\|",
      // Multi-quantifier org patterns with mandatory disjoint leading literal + disjoint barriers
      "rm\\s+-rf\\s+/",
      "curl\\s+\\|\\s*sh",
      "curl\\s*\\|\\s*(ba)?sh",
      "curl\\s+\\S+\\s+\\|\\s*(ba)?sh",
      "(curl|wget)\\s+\\S+\\s+\\|\\s*(ba|z)?sh",
      "git\\s+\\w+\\s+--force",
      "rm\\s+\\S+\\s+/",
      "(DROP|TRUNCATE)\\s+TABLE\\s+\\w+",
      "(?:DROP|TRUNCATE)\\s+TABLE\\s+\\w+",
      "aws\\s+s3\\s+rb",
      "^git\\s+push\\s+--force",
      "^deploy-service-0\\s+--env=(prod|staging)\\s+--region=[a-z0-9-]+$",
    ];
    for (const pat of accepted) {
      expect(isRe2SafePattern(pat), `expected accept: ${pat}`).toBe(true);
      expect(compileSafeRegex(pat), `expected compiled: ${pat}`).toBeInstanceOf(
        RegExp,
      );
    }
  });

  it("records that the Kelvin Unicode case-fold repro is quadratic under /iu", () => {
    // compileSafeRegex now rejects this pattern. Time a raw /iu RegExp to
    // show why: U+212A folds to "k", so the leading literal does not pin
    // the two unbounded \\w+ quantifiers on a long run of "k".
    const source = "\\u212A\\w+\\s+\\w+\\u{1F600}?";
    expect(isRe2SafePattern(source)).toBe(false);
    expect(compileSafeRegex(source)).toBeNull();
    const re = new RegExp(source, "iu");
    const input = "k".repeat(32_768);
    const t0 = performance.now();
    const matched = re.test(input);
    const elapsed = performance.now() - t0;
    expect(matched).toBe(false);
    expect(
      elapsed,
      `expected Kelvin /iu repro to be slow on 32KB of k, got ${elapsed.toFixed(2)}ms`,
    ).toBeGreaterThan(50);
  });

  it("decodes \\xHH, \\uHHHH, and \\u{H...} escapes and rejects forbidden, octal, or malformed escapes", () => {
    const rejected = [
      // Escape-encoded overlapping/adjacent unbounded quantifiers
      "\\x41+\\x42+",
      "\\u0041+\\u0042+",
      "\\u{41}+\\u{42}+",
      "[\\x41]+[\\x42]+",
      "x\\x41+\\x42+",
      "x\\u0041+\\u0042+",
      "x\\u{41}+\\u{42}+",
      "x[\\x41]+[\\x42]+",
      // Octal escapes (\0 followed by any digit, outside and inside [...])
      "\\012+\\s+\\w+",
      "\\01+\\s+\\w+",
      "\\07+\\s+\\w+",
      "[\\012]+\\s+\\w+",
      "a\\00b",
      // Forbidden \p, \P, \c escapes anywhere
      "\\p{L}+",
      "\\P{L}+",
      "[\\p{L}]+",
      "\\cA",
      "[\\cA]",
      // Malformed hex and unicode escapes (bad hex or > 0x10FFFF)
      "\\x",
      "\\x4",
      "\\xZZ",
      "[\\xZZ]",
      "\\u",
      "\\u004",
      "\\uGGGG",
      "[\\uGGGG]",
      "\\u{}",
      "\\u{41",
      "\\u{ZZZZ}",
      "\\u{110000}",
      "[\\u{110000}]",
    ];
    for (const pat of rejected) {
      expect(isRe2SafePattern(pat), `expected reject: ${pat}`).toBe(false);
      expect(compileSafeRegex(pat), `expected null compile: ${pat}`).toBeNull();
    }

    const accepted: Array<{ pattern: string; sampleMatch: string }> = [
      { pattern: "curl\\x20\\|\\x20sh", sampleMatch: "curl | sh" },
      { pattern: "a\\x2Db", sampleMatch: "a-b" },
      { pattern: "a\\u002Db", sampleMatch: "a-b" },
      { pattern: "a\\u{2D}b", sampleMatch: "a-b" },
      { pattern: "a\\0b", sampleMatch: "a\0b" },
      { pattern: "rm\\x20+-rf\\x20+/", sampleMatch: "rm   -rf  /" },
      { pattern: "foo:[\\x41-\\x5A]+@[\\x41-\\x5A]+", sampleMatch: "foo:ABC@XYZ" },
    ];
    for (const c of accepted) {
      expect(isRe2SafePattern(c.pattern), `expected accept: ${c.pattern}`).toBe(
        true,
      );
      const re = compileSafeRegex(c.pattern);
      expect(re, `expected compiled: ${c.pattern}`).toBeInstanceOf(RegExp);
      expect(
        testSafeRegex(re!, c.sampleMatch),
        `expected match for ${c.pattern} on ${c.sampleMatch}`,
      ).toBe(true);
    }
  });

  it("evaluates every accepted multi-quantifier org pattern against adversarial 32KB inputs under 5ms", () => {
    clearRegexCache();
    const patterns = [
      "rm\\s+-rf\\s+/",
      "curl\\s+\\|\\s*sh",
      "curl\\s*\\|\\s*(ba)?sh",
      "curl\\s+\\S+\\s+\\|\\s*(ba)?sh",
      "(DROP|TRUNCATE)\\s+TABLE\\s+\\w+",
      "(?:DROP|TRUNCATE)\\s+TABLE\\s+\\w+",
      "aws\\s+s3\\s+rb",
      "^git\\s+push\\s+--force",
      "rm\\x20+-rf\\x20+/",
      "foo:[\\x41-\\x5A]+@[\\x41-\\x5A]+",
      "^deploy-service-0\\s+--env=(prod|staging)\\s+--region=[a-z0-9-]+$",
    ];
    const adversarialInputs = [
      { label: "a*32768", value: "a".repeat(32_768) },
      { label: "space*32768", value: " ".repeat(32_768) },
      { label: "rm+space*32768", value: "rm" + " ".repeat(32_768) },
      { label: "A+a*32767", value: "A" + "a".repeat(32_767) },
      { label: "nl*32768", value: "\n".repeat(32_768) },
    ];

    // Pre-warm VM script once so per-pattern timings measure regex matching rather than V8 cold-start JIT.
    const warmupRe = compileSafeRegex("rm\\s+-rf\\s+/")!;
    testSafeRegex(warmupRe, "rm" + " ".repeat(16), POLICY_EVAL_DEADLINE_MS);

    for (const pattern of patterns) {
      const re = compileSafeRegex(pattern);
      expect(re, `expected compiled: ${pattern}`).toBeInstanceOf(RegExp);
      for (const adv of adversarialInputs) {
        let timedOut = false;
        const t0 = performance.now();
        const matched = testSafeRegex(
          re!,
          adv.value,
          POLICY_EVAL_DEADLINE_MS,
          () => {
            timedOut = true;
          },
        );
        const elapsed = performance.now() - t0;
        expect(matched, `should not match ${pattern} on ${adv.label}`).toBe(
          false,
        );
        expect(timedOut, `should not time out ${pattern} on ${adv.label}`).toBe(
          false,
        );
        expect(
          elapsed,
          `too slow (${elapsed.toFixed(2)}ms) for ${pattern} on ${adv.label}`,
        ).toBeLessThan(5);
      }
    }
  });

  it("caches compiled regexes by pattern+flags and bounds cache size at 256 entries", () => {
    clearRegexCache();
    const r1 = compileSafeRegex("^deploy-[a-z]+$", { caseSensitive: false });
    const r2 = compileSafeRegex("^deploy-[a-z]+$", { caseSensitive: false });
    const r3 = compileSafeRegex("^deploy-[a-z]+$", { caseSensitive: true });
    expect(r1).toBe(r2);
    expect(r1).not.toBe(r3);

    for (let i = 0; i < MAX_REGEX_CACHE_SIZE + 50; i++) {
      compileSafeRegex(`^rule_${i}_[0-9]+$`);
    }
    expect(getRegexCacheSize()).toBe(MAX_REGEX_CACHE_SIZE);
  });

  it("interrupts slow backtracking patterns via VM timeout without throwing", () => {
    const slowRe = new RegExp("(a+)+$");
    const t0 = performance.now();
    const matched = testSafeRegex(slowRe, "a".repeat(30) + "b", 30);
    const elapsed = performance.now() - t0;
    expect(matched).toBe(false);
    expect(elapsed).toBeLessThan(250);
  });
});

describe("evaluation deadline, ordering, and fail-closed timeout semantics", () => {
  it("keeps p95 evaluation under 50ms with 20 regex custom rules", () => {
    clearRegexCache();
    const customRules = Array.from({ length: 20 }, (_, i) => ({
      id: `regex_rule_${i}`,
      name: `Regex Rule ${i}`,
      enabled: true,
      version: 1,
      message: `Matched regex rule ${i}`,
      when: [
        {
          field: "command" as const,
          op: "regex" as const,
          value: `^deploy-service-${i} --env=(prod|staging) --region=[a-z0-9-]+$`,
        },
      ],
      action: "block" as const,
      severity: "high" as const,
    }));

    const policy: Policy = {
      version: 1,
      etag: "etag-latency",
      workspace_id: "ws_perf",
      updated_at: "2026-11-25T00:00:00Z",
      mode: "enforce",
      offline: "last_known",
      builtin: {},
      custom: customRules,
      allow: { commands: [], paths: [], repos: [] },
    };

    const input: PolicyEvalInput = {
      tool: "claude-code",
      toolName: "Bash",
      command: "pnpm vitest run test/policy-eval.test.ts --reporter=verbose",
    };

    const samples: number[] = [];
    for (let i = 0; i < 40; i++) {
      const t0 = performance.now();
      const res = evaluatePolicy(input, policy);
      const dt = performance.now() - t0;
      expect(res.action).toBe("allow");
      expect(res.timed_out).toBeUndefined();
      samples.push(dt);
    }

    samples.sort((a, b) => a - b);
    const p95 = samples[Math.floor(samples.length * 0.95)]!;
    expect(p95).toBeLessThan(POLICY_EVAL_DEADLINE_MS);
  });

  it("repro: preserves GIT001 block match when a later regex rule is pathological or times out", () => {
    clearRegexCache();
    const pathological = "a.*a.*a.*a.*a.*a.*a.*a.*b";
    const reproCommand = "git push --force " + "a".repeat(35) + "z";

    // 1. Pathological regex is statically rejected and GIT001 block still fires immediately
    const policyPathological: Policy = {
      version: 1,
      etag: "etag-repro-static",
      workspace_id: "ws_perf",
      updated_at: "2026-11-25T00:00:00Z",
      mode: "enforce",
      offline: "last_known",
      builtin: {
        GIT001: { enabled: true, action: "block" },
      },
      custom: [
        {
          id: "slow_regex",
          name: "Pathological regex",
          enabled: true,
          version: 1,
          message: "Slow",
          when: [{ field: "command", op: "regex", value: pathological }],
          action: "flag",
          severity: "high",
        },
      ],
      allow: { commands: [], paths: [], repos: [] },
    };

    const staticRes = evaluatePolicy(
      { tool: "claude-code", toolName: "Bash", command: reproCommand },
      policyPathological,
    );
    expect(staticRes.action).toBe("block");
    expect(staticRes.rule_ids).toContain("GIT001");
    expect(staticRes.matches.some((m) => m.rule_id === "GIT001")).toBe(true);

    // 2. Deterministic timeout via injectable clock after GIT001 matches and before a later regex rule finishes
    const enabledBuiltinCount = RULES.filter((r) => {
      const ov = r.id === "GIT001" ? { enabled: true } : undefined;
      return ov !== undefined ? ov.enabled : r.enabled;
    }).length;
    let tick = 0;
    const stepClock = (): number => {
      tick += 1;
      // Call 1 sets deadline (0 + 50). Builtins consume 2 ticks each; expire right before custom regex.
      if (tick === 1) return 0;
      return tick <= 1 + enabledBuiltinCount * 2 ? 10 : 100;
    };

    const policyTimeout: Policy = {
      version: 1,
      etag: "etag-repro-timeout",
      workspace_id: "ws_perf",
      updated_at: "2026-11-25T00:00:00Z",
      mode: "enforce",
      offline: "last_known",
      builtin: {
        GIT001: { enabled: true, action: "block" },
      },
      custom: [
        {
          id: "later_regex",
          name: "Later regex rule",
          enabled: true,
          version: 1,
          message: "Later regex",
          when: [{ field: "command", op: "regex", value: "^deploy-[a-z]+$" }],
          action: "flag",
          severity: "warn",
        },
      ],
      allow: { commands: [], paths: [], repos: [] },
    };

    const timedRes = evaluatePolicy(
      { tool: "claude-code", toolName: "Bash", command: reproCommand },
      policyTimeout,
      undefined,
      { deadlineMs: 50, nowMs: stepClock },
    );
    expect(timedRes.timed_out).toBe(true);
    expect(timedRes.action).toBe("block");
    expect(timedRes.rule_ids).toContain("GIT001");
    expect(timedRes.matches.some((m) => m.rule_id === "GIT001")).toBe(true);
    expect(timedRes.reason).toBe(EVAL_TIMEOUT_REASON);
  });

  it("evaluates builtins and cheap custom matchers before regex rules, and enforcing regex before flag regex", () => {
    clearRegexCache();
    // Policy intentionally lists regex flag FIRST, then regex block, then cheap contains block.
    const policy: Policy = {
      version: 1,
      etag: "etag-order",
      workspace_id: "ws_order",
      updated_at: "2026-11-25T00:00:00Z",
      mode: "enforce",
      offline: "last_known",
      builtin: {
        GIT001: { enabled: true, action: "block" },
      },
      custom: [
        {
          id: "regex_flag_first_in_list",
          name: "Regex flag listed first",
          enabled: true,
          version: 1,
          message: "Regex flag",
          when: [{ field: "command", op: "regex", value: "git push.*" }],
          action: "flag",
          severity: "warn",
        },
        {
          id: "regex_block_second_in_list",
          name: "Regex block listed second",
          enabled: true,
          version: 1,
          message: "Regex block",
          when: [{ field: "command", op: "regex", value: "push --force" }],
          action: "block",
          severity: "high",
        },
        {
          id: "cheap_contains_last_in_list",
          name: "Cheap contains listed last",
          enabled: true,
          version: 1,
          message: "Cheap block",
          when: [{ field: "command", op: "contains", value: "--force" }],
          action: "block",
          severity: "high",
        },
      ],
      allow: { commands: [], paths: [], repos: [] },
    };

    const full = evaluatePolicy(
      { tool: "claude-code", toolName: "Bash", command: "git push --force origin main" },
      policy,
    );
    expect(full.action).toBe("block");
    // Builtins first, then cheap custom, then enforcing regex, then flag regex.
    const idxBuiltin = full.rule_ids.indexOf("GIT001");
    const idxCheap = full.rule_ids.indexOf("cheap_contains_last_in_list");
    const idxRegexBlock = full.rule_ids.indexOf("regex_block_second_in_list");
    const idxRegexFlag = full.rule_ids.indexOf("regex_flag_first_in_list");
    expect(idxBuiltin).toBeGreaterThanOrEqual(0);
    expect(idxCheap).toBeGreaterThan(idxBuiltin);
    expect(idxRegexBlock).toBeGreaterThan(idxCheap);
    expect(idxRegexFlag).toBeGreaterThan(idxRegexBlock);
  });

  it("fails closed with eval_timeout when a block or require_approval rule is unevaluated on timeout", () => {
    clearRegexCache();
    for (const enforcingAction of ["block", "require_approval"] as const) {
      let calls = 0;
      // First call sets deadline = 0 + 50 = 50; next call immediately expires (60 >= 50)
      const instantTimeoutClock = (): number => (calls++ === 0 ? 0 : 60);

      const policy: Policy = {
        version: 1,
        etag: `etag-uneval-${enforcingAction}`,
        workspace_id: "ws_timeout",
        updated_at: "2026-11-25T00:00:00Z",
        mode: "enforce",
        offline: "last_known",
        builtin: {},
        custom: [
          {
            id: `uneval_${enforcingAction}`,
            name: `Unevaluated ${enforcingAction}`,
            enabled: true,
            version: 1,
            message: "Must fail closed if not evaluated",
            when: [{ field: "command", op: "regex", value: "^never-matches-[0-9]+$" }],
            action: enforcingAction,
            severity: "high",
          },
        ],
        allow: { commands: [], paths: [], repos: [] },
      };

      const res = evaluatePolicy(
        { tool: "claude-code", toolName: "Bash", command: "echo safe" },
        policy,
        [],
        { deadlineMs: 50, nowMs: instantTimeoutClock },
      );

      expect(res.timed_out).toBe(true);
      expect(res.action).toBe("block");
      expect(res.reason).toBe(EVAL_TIMEOUT_REASON);
      expect(res.unevaluated_enforcing).toBe(true);
    }
  });

  it("returns strictest result so far plus eval_timeout flag when only flag rules remain unevaluated", () => {
    clearRegexCache();
    // Case A: no prior matches, only a flag rule remains unevaluated -> flag + eval_timeout
    let callsA = 0;
    const clockA = (): number => (callsA++ === 0 ? 0 : 60);
    const policyFlagOnly: Policy = {
      version: 1,
      etag: "etag-flag-only",
      workspace_id: "ws_timeout",
      updated_at: "2026-11-25T00:00:00Z",
      mode: "enforce",
      offline: "last_known",
      builtin: {},
      custom: [
        {
          id: "uneval_flag",
          name: "Unevaluated flag",
          enabled: true,
          version: 1,
          message: "Flag only",
          when: [{ field: "command", op: "regex", value: "^audit-[a-z]+$" }],
          action: "flag",
          severity: "warn",
        },
      ],
      allow: { commands: [], paths: [], repos: [] },
    };

    const resA = evaluatePolicy(
      { tool: "claude-code", toolName: "Bash", command: "echo safe" },
      policyFlagOnly,
      [],
      { deadlineMs: 50, nowMs: clockA },
    );
    expect(resA.timed_out).toBe(true);
    expect(resA.action).toBe("flag");
    expect(resA.reason).toBe(EVAL_TIMEOUT_REASON);
    expect(resA.unevaluated_enforcing).toBe(false);

    // Case B: cheap require_approval rule matches, then clock expires before remaining flag regex
    let callsB = 0;
    // Call 1 sets deadline=50. Calls 2..6 evaluate cheap_approval; call 7 expires right before later_flag_regex.
    const clockB = (): number => {
      callsB += 1;
      if (callsB === 1) return 0;
      return callsB <= 6 ? 10 : 60;
    };
    const policyApprovalThenFlag: Policy = {
      version: 1,
      etag: "etag-approval-then-flag",
      workspace_id: "ws_timeout",
      updated_at: "2026-11-25T00:00:00Z",
      mode: "enforce",
      offline: "last_known",
      builtin: {},
      custom: [
        {
          id: "cheap_approval",
          name: "Cheap approval",
          enabled: true,
          version: 1,
          message: "Needs approval",
          when: [{ field: "command", op: "contains", value: "deploy" }],
          action: "require_approval",
          severity: "high",
        },
        {
          id: "later_flag_regex",
          name: "Later flag regex",
          enabled: true,
          version: 1,
          message: "Flag regex",
          when: [{ field: "command", op: "regex", value: "^audit-[a-z]+$" }],
          action: "flag",
          severity: "warn",
        },
      ],
      allow: { commands: [], paths: [], repos: [] },
    };

    const resB = evaluatePolicy(
      { tool: "claude-code", toolName: "Bash", command: "deploy staging" },
      policyApprovalThenFlag,
      [],
      { deadlineMs: 50, nowMs: clockB },
    );
    expect(resB.timed_out).toBe(true);
    expect(resB.action).toBe("require_approval");
    expect(resB.rule_ids).toEqual(["cheap_approval"]);
    expect(resB.reason).toBe(EVAL_TIMEOUT_REASON);
    expect(resB.unevaluated_enforcing).toBe(false);
  });

  it("downgrades eval_timeout fail-closed block to flag in observe mode", () => {
    clearRegexCache();
    let calls = 0;
    const clock = (): number => (calls++ === 0 ? 0 : 60);
    const policyObserve: Policy = {
      version: 1,
      etag: "etag-observe-timeout",
      workspace_id: "ws_timeout",
      updated_at: "2026-11-25T00:00:00Z",
      mode: "observe",
      offline: "last_known",
      builtin: {},
      custom: [
        {
          id: "uneval_block",
          name: "Unevaluated block",
          enabled: true,
          version: 1,
          message: "Would block in enforce mode",
          when: [{ field: "command", op: "regex", value: "^deploy-[a-z]+$" }],
          action: "block",
          severity: "high",
        },
      ],
      allow: { commands: [], paths: [], repos: [] },
    };

    const res = evaluatePolicy(
      { tool: "claude-code", toolName: "Bash", command: "echo safe" },
      policyObserve,
      [],
      { deadlineMs: 50, nowMs: clock },
    );
    expect(res.timed_out).toBe(true);
    expect(res.action).toBe("flag");
    expect(res.downgraded).toBe(true);
    expect(res.original_action).toBe("block");
    expect(res.reason).toBe(EVAL_TIMEOUT_REASON);
  });
});

describe("linear-time glob matching", () => {
  it("handles path-aware globs and adversarial non-matching patterns quickly", () => {
    expect(matchGlob("a/b/c.pem", "**/*.pem", true, true)).toBe(true);
    expect(matchGlob("server.pem", "**/*.pem", true, true)).toBe(true);
    expect(matchGlob("src/app.ts", "src/*.ts", true, true)).toBe(true);
    expect(matchGlob("src/sub/app.ts", "src/*.ts", true, true)).toBe(false);
    expect(
      matchGlob("curl https://example.com/install.sh | bash", "curl * | bash", false, false),
    ).toBe(true);

    const t0 = performance.now();
    const adversarial = matchGlob(
      "a".repeat(100) + "z",
      "*a*a*a*a*a*a*a*a*a*b",
      true,
      false,
    );
    expect(adversarial).toBe(false);
    expect(performance.now() - t0).toBeLessThan(50);
  });
});

describe("transitive hook import graph network isolation", () => {
  const srcRoot = resolve(here, "..", "src");
  const APPROVAL_CLIENT_REL = "policy/approval.ts";
  const ENFORCE_REL = "policy/enforce.ts";

  interface ImportEdge {
    from: string;
    specifier: string;
    resolvedRel: string | null;
    dynamic: boolean;
  }

  function resolveLocalTs(fromAbs: string, specifier: string): string | null {
    if (!specifier.startsWith(".")) return null;
    const raw = resolve(dirname(fromAbs), specifier);
    const candidates = [
      raw.replace(/\.js$/, ".ts"),
      raw.replace(/\.mjs$/, ".mts"),
      `${raw}.ts`,
      join(raw, "index.ts"),
    ];
    for (const c of candidates) {
      if (existsSync(c)) return relative(srcRoot, c).replace(/\\/g, "/");
    }
    return null;
  }

  function analyzeFile(relPath: string): {
    edges: ImportEdge[];
    referencesFetch: boolean;
  } {
    const absPath = join(srcRoot, relPath);
    const sourceText = readFileSync(absPath, "utf8");
    const sf = ts.createSourceFile(
      absPath,
      sourceText,
      ts.ScriptTarget.Latest,
      true,
      ts.ScriptKind.TS,
    );

    const edges: ImportEdge[] = [];
    let referencesFetch = false;

    const visit = (node: ts.Node): void => {
      if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
        const isTypeOnly = Boolean(node.importClause?.isTypeOnly);
        if (!isTypeOnly) {
          const spec = node.moduleSpecifier.text;
          edges.push({
            from: relPath,
            specifier: spec,
            resolvedRel: resolveLocalTs(absPath, spec),
            dynamic: false,
          });
        }
      } else if (
        ts.isExportDeclaration(node) &&
        node.moduleSpecifier &&
        ts.isStringLiteral(node.moduleSpecifier) &&
        !node.isTypeOnly
      ) {
        const spec = node.moduleSpecifier.text;
        edges.push({
          from: relPath,
          specifier: spec,
          resolvedRel: resolveLocalTs(absPath, spec),
          dynamic: false,
        });
      } else if (ts.isCallExpression(node)) {
        // Dynamic import("...")
        if (
          node.expression.kind === ts.SyntaxKind.ImportKeyword &&
          node.arguments.length > 0 &&
          ts.isStringLiteral(node.arguments[0]!)
        ) {
          const spec = node.arguments[0]!.text;
          edges.push({
            from: relPath,
            specifier: spec,
            resolvedRel: resolveLocalTs(absPath, spec),
            dynamic: true,
          });
        }
        // require("...")
        if (
          ts.isIdentifier(node.expression) &&
          node.expression.text === "require" &&
          node.arguments.length > 0 &&
          ts.isStringLiteral(node.arguments[0]!)
        ) {
          const spec = node.arguments[0]!.text;
          edges.push({
            from: relPath,
            specifier: spec,
            resolvedRel: resolveLocalTs(absPath, spec),
            dynamic: true,
          });
        }
      }

      // Detect runtime references to global `fetch` (direct call or globalThis.fetch)
      if (ts.isIdentifier(node) && node.text === "fetch") {
        const parent = node.parent;
        const isTypeNode =
          ts.isTypeQueryNode(parent) ||
          ts.isTypeReferenceNode(parent) ||
          ts.isPropertySignature(parent);
        const isPropertyKey =
          (ts.isPropertyAccessExpression(parent) &&
            parent.name === node &&
            !(
              ts.isIdentifier(parent.expression) &&
              parent.expression.text === "globalThis"
            )) ||
          (ts.isPropertyAssignment(parent) && parent.name === node);
        if (!isTypeNode && !isPropertyKey) {
          referencesFetch = true;
        }
      }

      ts.forEachChild(node, visit);
    };

    visit(sf);
    return { edges, referencesFetch };
  }

  it("walks the full transitive import graph from hooks/handler.ts, cursor/hook-runner.ts, and cursor/hook-normalize.ts", () => {
    const entrypoints = [
      "hooks/handler.ts",
      "cursor/hook-runner.ts",
      "cursor/hook-normalize.ts",
    ];
    const visited = new Set<string>();
    const allEdges: ImportEdge[] = [];
    const filesReferencingFetch: string[] = [];
    const queue = [...entrypoints];

    while (queue.length > 0) {
      const current = queue.shift()!;
      if (visited.has(current)) continue;
      visited.add(current);

      const { edges, referencesFetch } = analyzeFile(current);
      if (referencesFetch) {
        filesReferencingFetch.push(current);
      }
      for (const edge of edges) {
        allEdges.push(edge);
        if (edge.resolvedRel && !visited.has(edge.resolvedRel)) {
          queue.push(edge.resolvedRel);
        }
      }
    }

    // Sanity check: confirm the walker traversed the real hook and policy modules
    expect(visited.has("hooks/handler.ts")).toBe(true);
    expect(visited.has("cursor/hook-runner.ts")).toBe(true);
    expect(visited.has("cursor/hook-normalize.ts")).toBe(true);
    expect(visited.has("policy/eval.ts")).toBe(true);
    expect(visited.has("policy/cache.ts")).toBe(true);
    expect(visited.has("policy/types.ts")).toBe(true);
    expect(visited.has("policy/regex.ts")).toBe(true);
    expect(visited.has(ENFORCE_REL)).toBe(true);

    // policy/fetch.ts must never be reachable from any hook
    expect(visited.has("policy/fetch.ts")).toBe(false);

    // No reachable module may import http, https, or net (node:* or bare)
    const forbiddenBuiltins = new Set([
      "http",
      "node:http",
      "https",
      "node:https",
      "net",
      "node:net",
    ]);
    for (const edge of allEdges) {
      expect(forbiddenBuiltins.has(edge.specifier)).toBe(false);
    }

    // Only the approval client may reference fetch
    expect(filesReferencingFetch).toEqual([APPROVAL_CLIENT_REL]);

    // Documented single allowed edge into the approval client:
    // policy/enforce.ts dynamically imports ./approval.js solely on the require_approval branch.
    const approvalEdges = allEdges.filter(
      (e) => e.resolvedRel === APPROVAL_CLIENT_REL,
    );
    expect(approvalEdges).toEqual([
      {
        from: ENFORCE_REL,
        specifier: "./approval.js",
        resolvedRel: APPROVAL_CLIENT_REL,
        dynamic: true,
      },
    ]);
  });
});

describe("validatePolicy regex safety and eval invalid_rule defense in depth", () => {
  it("validatePolicy rejects fixture 33 shape naming rule id and condition index", () => {
    const fixture33 = fixtures.cases.find((c) => c.policy.etag === "etag-33");
    expect(fixture33).toBeDefined();
    const res = validatePolicy(fixture33!.policy);
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.error).toContain("cust_multi_unbounded_regex");
      expect(res.error).toContain("when[0]");
      expect(res.rejectedRuleId).toBe("cust_multi_unbounded_regex");
      expect(res.rejectedConditionIndex).toBe(0);
    }
  });

  it("validatePolicy reports the exact condition index for multi-condition rules", () => {
    const policy: Policy = {
      version: 1,
      etag: "etag-cond-idx",
      workspace_id: "ws_1",
      updated_at: "2026-11-25T00:00:00Z",
      mode: "enforce",
      offline: "last_known",
      builtin: {},
      custom: [
        {
          id: "cust_second_cond_bad",
          name: "Second condition has unsupported regex",
          enabled: true,
          version: 1,
          message: "Bad second condition",
          when: [
            { field: "command", op: "contains", value: "curl" },
            { field: "command", op: "regex", value: "curl.*\\|\\s*(ba)?sh" },
          ],
          action: "block",
          severity: "high",
          scope: {},
        },
      ],
      allow: { commands: [], paths: [], repos: [] },
    };
    const res = validatePolicy(policy);
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.error).toContain("cust_second_cond_bad");
      expect(res.error).toContain("when[1]");
      expect(res.rejectedRuleId).toBe("cust_second_cond_bad");
      expect(res.rejectedConditionIndex).toBe(1);
    }
  });

  it("evaluatePolicy treats uncompilable regex in a flag rule as flag with invalid_rule", () => {
    const policy: Policy = {
      version: 1,
      etag: "etag-bad-flag",
      workspace_id: "ws_1",
      updated_at: "2026-11-25T00:00:00Z",
      mode: "enforce",
      offline: "last_known",
      builtin: {},
      custom: [
        {
          id: "cust_bad_flag",
          name: "Bad flag regex",
          enabled: true,
          version: 1,
          message: "Bad flag",
          when: [{ field: "command", op: "regex", value: "(a+)+" }],
          action: "flag",
          severity: "warn",
          scope: {},
        },
      ],
      allow: { commands: [], paths: [], repos: [] },
    };

    const result = evaluatePolicy(
      { tool: "claude-code", toolName: "Bash", command: "echo hi" },
      policy,
    );
    expect(result.action).toBe("flag");
    expect(result.invalid_rule).toBe(true);
    expect(result.invalid_rule_ids).toEqual(["cust_bad_flag"]);
    expect(result.reason).toBe(INVALID_RULE_REASON);
    expect(result.unevaluated_enforcing).toBe(false);
  });

  it("evaluatePolicy fails closed with invalid_rule for block and require_approval rules, downgraded in observe mode", () => {
    const makePolicy = (
      action: "block" | "require_approval",
      mode: "enforce" | "observe",
    ): Policy => ({
      version: 1,
      etag: `etag-bad-${action}-${mode}`,
      workspace_id: "ws_1",
      updated_at: "2026-11-25T00:00:00Z",
      mode,
      offline: "last_known",
      builtin: {},
      custom: [
        {
          id: `cust_bad_${action}`,
          name: "Bad enforcing regex",
          enabled: true,
          version: 1,
          message: "Bad enforcing",
          when: [{ field: "command", op: "regex", value: "(a+)+" }],
          action,
          severity: "critical",
          scope: {},
        },
      ],
      allow: { commands: [], paths: [], repos: [] },
    });

    const blockRes = evaluatePolicy(
      { tool: "claude-code", toolName: "Bash", command: "echo hi" },
      makePolicy("block", "enforce"),
    );
    expect(blockRes.action).toBe("block");
    expect(blockRes.reason).toBe(INVALID_RULE_REASON);
    expect(blockRes.invalid_rule_ids).toEqual(["cust_bad_block"]);
    expect(blockRes.unevaluated_enforcing).toBe(true);

    const approvalRes = evaluatePolicy(
      { tool: "claude-code", toolName: "Bash", command: "echo hi" },
      makePolicy("require_approval", "enforce"),
    );
    expect(approvalRes.action).toBe("block");
    expect(approvalRes.reason).toBe(INVALID_RULE_REASON);
    expect(approvalRes.invalid_rule_ids).toEqual(["cust_bad_require_approval"]);
    expect(approvalRes.unevaluated_enforcing).toBe(true);

    const observeRes = evaluatePolicy(
      { tool: "claude-code", toolName: "Bash", command: "echo hi" },
      makePolicy("block", "observe"),
    );
    expect(observeRes.action).toBe("flag");
    expect(observeRes.downgraded).toBe(true);
    expect(observeRes.original_action).toBe("block");
    expect(observeRes.reason).toBe(INVALID_RULE_REASON);
  });
});

describe("C1 additive evaluation: no-org, scope.teams, and approval_defaults merging", () => {
  it("evaluates org_id null (no-org) policy as allow with no enforcement or builtin flags", () => {
    const noOrg: Policy = {
      version: 1,
      etag: "etag-no-org",
      org_id: null,
      workspace_id: null,
      updated_at: "2026-11-26T00:00:00Z",
      mode: "observe",
      offline: "last_known",
      builtin: {},
      custom: [],
      allow: { commands: [], paths: [], repos: [] },
    };

    const res = evaluatePolicy(
      { tool: "claude-code", toolName: "Bash", command: "rm -rf ~" },
      noOrg,
    );
    expect(res.action).toBe("allow");
    expect(res.matches).toEqual([]);
    expect(res.rule_ids).toEqual([]);
  });

  it("treats scope.teams as display-only (always applies subject to other scope fields) and ignores unknown current_user_teams", () => {
    const rawPayload = {
      version: 1,
      etag: "etag-teams",
      workspace_id: "ws_1",
      updated_at: "2026-11-26T00:00:00Z",
      mode: "enforce",
      offline: "last_known",
      current_user_teams: ["other-team"],
      builtin: {},
      custom: [
        {
          id: "cust_team_scoped",
          name: "Team x deploy block",
          enabled: true,
          version: 1,
          message: "Blocked for team x",
          when: [{ field: "command", op: "contains", value: "deploy-prod" }],
          action: "block",
          severity: "high",
          scope: { teams: ["x"] },
        },
        {
          id: "cust_team_and_repo",
          name: "Team x prod-repo block",
          enabled: true,
          version: 1,
          message: "Blocked for team x in prod repo",
          when: [{ field: "command", op: "contains", value: "migrate-db" }],
          action: "block",
          severity: "high",
          scope: { teams: ["x"], repos: ["acme/prod-*"] },
        },
      ],
      allow: { commands: [], paths: [], repos: [] },
    };

    const validated = validatePolicy(rawPayload);
    expect(validated.ok).toBe(true);
    if (!validated.ok) return;
    // Unknown current_user_teams field is ignored and not stored on Policy
    expect(
      (validated.value as unknown as Record<string, unknown>).current_user_teams,
    ).toBeUndefined();

    // Rule with scope.teams ['x'] applies even though current_user_teams did not include 'x'
    const applied = evaluatePolicy(
      { tool: "claude-code", toolName: "Bash", command: "deploy-prod now" },
      validated.value,
    );
    expect(applied.action).toBe("block");
    expect(applied.rule_ids).toEqual(["cust_team_scoped"]);

    // Other scope fields (e.g. repos) still apply normally alongside scope.teams
    const wrongRepo = evaluatePolicy(
      {
        tool: "claude-code",
        toolName: "Bash",
        command: "migrate-db",
        repo: "acme/staging",
      },
      validated.value,
    );
    expect(wrongRepo.action).toBe("allow");

    const rightRepo = evaluatePolicy(
      {
        tool: "claude-code",
        toolName: "Bash",
        command: "migrate-db",
        repo: "acme/prod-api",
      },
      validated.value,
    );
    expect(rightRepo.action).toBe("block");
    expect(rightRepo.rule_ids).toEqual(["cust_team_and_repo"]);
  });

  it("merges effective approval config as rule.approval over approval_defaults over (120, deny) for builtin and custom rules", () => {
    const policy: Policy = {
      version: 1,
      etag: "etag-approval-merge",
      workspace_id: "ws_1",
      updated_at: "2026-11-26T00:00:00Z",
      mode: "enforce",
      offline: "last_known",
      approval_defaults: { expires_s: 90, offline_fallback: "allow" },
      builtin: {
        GIT001: { enabled: true, action: "require_approval" },
        FS001: {
          enabled: true,
          action: "require_approval",
          approval: { offline_fallback: "deny" },
        },
      },
      custom: [
        {
          id: "cust_partial_approval",
          name: "Partial custom approval",
          enabled: true,
          version: 1,
          message: "Approve release",
          when: [{ field: "command", op: "contains", value: "release-prod" }],
          action: "require_approval",
          severity: "high",
          approval: { expires_s: 45 },
        },
      ],
      allow: { commands: [], paths: [], repos: [] },
    };

    // Builtin without rule.approval inherits approval_defaults
    const builtinInherited = evaluatePolicy(
      { tool: "claude-code", toolName: "Bash", command: "git push --force origin main" },
      policy,
    );
    expect(builtinInherited.action).toBe("require_approval");
    expect(builtinInherited.matches[0]?.approval).toEqual({
      expires_s: 90,
      offline_fallback: "allow",
    });

    // Builtin with partial rule.approval merges over approval_defaults
    const builtinOverride = evaluatePolicy(
      { tool: "claude-code", toolName: "Bash", command: "rm -rf ~" },
      policy,
    );
    expect(builtinOverride.action).toBe("require_approval");
    expect(builtinOverride.matches[0]?.approval).toEqual({
      expires_s: 90,
      offline_fallback: "deny",
    });

    // Custom with partial rule.approval merges over approval_defaults
    const customPartial = evaluatePolicy(
      { tool: "claude-code", toolName: "Bash", command: "release-prod v1" },
      policy,
    );
    expect(customPartial.action).toBe("require_approval");
    expect(customPartial.matches[0]?.approval).toEqual({
      expires_s: 45,
      offline_fallback: "allow",
    });

    // Without approval_defaults, falls back to built-in (120, deny)
    const noDefaultsPolicy: Policy = { ...policy, approval_defaults: undefined };
    const builtinDefault = evaluatePolicy(
      { tool: "claude-code", toolName: "Bash", command: "git push --force origin main" },
      noDefaultsPolicy,
    );
    expect(builtinDefault.matches[0]?.approval).toEqual({
      expires_s: 120,
      offline_fallback: "deny",
    });
  });
});
