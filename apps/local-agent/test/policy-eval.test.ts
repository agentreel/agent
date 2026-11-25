import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  evaluatePolicy,
  matchGlob,
  type PolicyEvalInput,
} from "../src/policy/eval.js";
import {
  compileSafeRegex,
  isRe2SafePattern,
  MAX_REGEX_LENGTH,
  testSafeRegex,
} from "../src/policy/regex.js";
import { validatePolicy, type Policy, type PolicyDecisionAction } from "../src/policy/types.js";

interface PolicyFixtureCase {
  name: string;
  policy: Policy;
  input: PolicyEvalInput;
  expected: {
    action: PolicyDecisionAction;
    rule_ids: string[];
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
    expect(validated.ok).toBe(true);

    const result = evaluatePolicy(fixtureCase.input, fixtureCase.policy);
    expect(result.action).toBe(fixtureCase.expected.action);
    expect(result.rule_ids).toEqual(fixtureCase.expected.rule_ids);

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

describe("RE2-safe regex compiler and timeout guard", () => {
  it("accepts safe RE2 patterns up to 300 chars", () => {
    const pat = "a".repeat(MAX_REGEX_LENGTH);
    expect(isRe2SafePattern(pat)).toBe(true);
    const re = compileSafeRegex(pat);
    expect(re).toBeInstanceOf(RegExp);
    expect(testSafeRegex(re!, pat)).toBe(true);
  });

  it("rejects over-length, invalid, lookaround, backreference, and nested-quantifier patterns without throwing", () => {
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
  });

  it("interrupts slow backtracking patterns via VM timeout without throwing", () => {
    const re = compileSafeRegex("(a|aa)+$");
    expect(re).not.toBeNull();
    const t0 = performance.now();
    const matched = testSafeRegex(re!, "a".repeat(30) + "b", 40);
    const elapsed = performance.now() - t0;
    expect(matched).toBe(false);
    expect(elapsed).toBeLessThan(500);
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

describe("hook network isolation for policy modules", () => {
  const srcRoot = join(here, "..", "src");

  it("hooks and local policy modules do not import policy/fetch.ts", () => {
    const filesToCheck = [
      join(srcRoot, "hooks", "handler.ts"),
      join(srcRoot, "cursor", "hook-runner.ts"),
      join(srcRoot, "policy", "eval.ts"),
      join(srcRoot, "policy", "cache.ts"),
      join(srcRoot, "policy", "types.ts"),
      join(srcRoot, "policy", "regex.ts"),
    ];

    for (const file of filesToCheck) {
      const content = readFileSync(file, "utf8");
      expect(content).not.toMatch(/policy\/fetch/);
      expect(content).not.toMatch(/\.\/fetch\.js/);
      expect(content).not.toMatch(/\bfetch\s*\(/);
    }
  });
});
