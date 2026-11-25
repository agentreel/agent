import { matchRule } from "../guard/matcher.js";
import { RULES } from "../guard/rules.js";
import type { MatchContext, Rule, Severity } from "../guard/types.js";
import { compileSafeRegex, testSafeRegex } from "./regex.js";
import type {
  CustomRule,
  CustomRuleCondition,
  CustomRuleScope,
  Policy,
  PolicyAction,
  PolicyDecisionAction,
  PolicyTool,
  RuleApprovalConfig,
} from "./types.js";

export const POLICY_EVAL_DEADLINE_MS = 50;

export interface PolicyEvalInput {
  tool: PolicyTool;
  toolName: string;
  command?: string;
  file_path?: string;
  url?: string;
  mcp_tool?: string;
  toolInput?: unknown;
  repo?: string;
  branch?: string;
  member?: string;
}

export interface PolicyRuleMatch {
  rule_id: string;
  name: string;
  message: string;
  action: PolicyAction;
  severity: Severity;
  source: "builtin" | "custom";
  approval?: RuleApprovalConfig;
}

export interface PolicyEvalResult {
  action: PolicyDecisionAction;
  rule_ids: string[];
  matches: PolicyRuleMatch[];
  downgraded: boolean;
  original_action?: PolicyAction;
  timed_out?: boolean;
}

export interface PolicyEvalOptions {
  deadlineMs?: number;
  nowMs?: () => number;
}

const ACTION_RANK: Record<PolicyDecisionAction, number> = {
  allow: 0,
  flag: 1,
  require_approval: 2,
  block: 3,
};

interface GlobToken {
  kind: "char" | "any_char" | "star" | "globstar" | "globstar_slash";
  char?: string;
}

function tokenizeGlob(pattern: string, pathAware: boolean): GlobToken[] {
  const tokens: GlobToken[] = [];
  let i = 0;
  while (i < pattern.length) {
    const ch = pattern[i]!;
    if (ch === "*") {
      let stars = 0;
      while (i < pattern.length && pattern[i] === "*") {
        stars++;
        i++;
      }
      if (pathAware && stars >= 2) {
        if (pattern[i] === "/") {
          tokens.push({ kind: "globstar_slash" });
          i++;
        } else {
          tokens.push({ kind: "globstar" });
        }
      } else if (pathAware) {
        tokens.push({ kind: "star" });
      } else {
        tokens.push({ kind: "globstar" });
      }
    } else if (ch === "?") {
      tokens.push({ kind: "any_char" });
      i++;
    } else {
      tokens.push({ kind: "char", char: ch });
      i++;
    }
  }
  return tokens;
}

/**
 * Linear-time glob matcher (no regex backtracking).
 * When pathAware is true: "*" matches non-"/" chars, "**" matches any chars,
 * "**\/" matches zero or more path segments, and "?" matches one non-"/" char.
 * When pathAware is false: "*" and "**" match any chars and "?" matches one char.
 */
export function matchGlob(
  text: string,
  pattern: string,
  caseSensitive: boolean = true,
  pathAware: boolean = true,
): boolean {
  const s = caseSensitive ? text : text.toLowerCase();
  const p = caseSensitive ? pattern : pattern.toLowerCase();
  const tokens = tokenizeGlob(p, pathAware);

  const m = tokens.length;
  const n = s.length;

  let prev = new Uint8Array(n + 1);
  prev[0] = 1;

  for (let ti = 0; ti < m; ti++) {
    const tok = tokens[ti]!;
    const curr = new Uint8Array(n + 1);

    if (tok.kind === "globstar") {
      let matched = false;
      for (let j = 0; j <= n; j++) {
        if (prev[j]) matched = true;
        if (matched) curr[j] = 1;
      }
    } else if (tok.kind === "globstar_slash") {
      let seenPrefix = false;
      for (let j = 0; j <= n; j++) {
        if (prev[j]) {
          curr[j] = 1;
          seenPrefix = true;
        }
        if (seenPrefix && j > 0 && s[j - 1] === "/") {
          curr[j] = 1;
        }
      }
    } else if (tok.kind === "star") {
      let matched = false;
      for (let j = 0; j <= n; j++) {
        if (j > 0 && s[j - 1] === "/") {
          matched = false;
        }
        if (prev[j]) matched = true;
        if (matched) curr[j] = 1;
      }
    } else if (tok.kind === "any_char") {
      for (let j = 1; j <= n; j++) {
        if (prev[j - 1] && (!pathAware || s[j - 1] !== "/")) {
          curr[j] = 1;
        }
      }
    } else {
      for (let j = 1; j <= n; j++) {
        if (prev[j - 1] && s[j - 1] === tok.char) {
          curr[j] = 1;
        }
      }
    }

    prev = curr;
  }

  return prev[n] === 1;
}

function hasGlobChars(s: string): boolean {
  return s.includes("*") || s.includes("?");
}

function isRepoAllowed(repo: string | undefined, allowedRepos: string[]): boolean {
  if (!repo || allowedRepos.length === 0) return false;
  for (const allowed of allowedRepos) {
    if (!allowed) continue;
    if (hasGlobChars(allowed)) {
      if (matchGlob(repo, allowed, true, true)) return true;
    } else if (repo === allowed) {
      return true;
    }
  }
  return false;
}

function isCommandAllowed(
  command: string | undefined,
  allowedCommands: string[],
): boolean {
  if (!command || allowedCommands.length === 0) return false;
  for (const allowed of allowedCommands) {
    if (!allowed) continue;
    if (hasGlobChars(allowed)) {
      if (matchGlob(command, allowed, true, false)) return true;
    } else if (command.includes(allowed)) {
      return true;
    }
  }
  return false;
}

function isPathAllowed(
  filePath: string | undefined,
  allowedPaths: string[],
): boolean {
  if (!filePath || allowedPaths.length === 0) return false;
  for (const allowed of allowedPaths) {
    if (!allowed) continue;
    if (hasGlobChars(allowed)) {
      if (matchGlob(filePath, allowed, true, true)) return true;
    } else if (allowed.endsWith("/")) {
      if (filePath.startsWith(allowed)) return true;
    } else if (filePath === allowed || filePath.startsWith(`${allowed}/`)) {
      return true;
    }
  }
  return false;
}

function isExemptByAllowLists(input: PolicyEvalInput, policy: Policy): boolean {
  if (isRepoAllowed(input.repo, policy.allow.repos)) return true;
  if (isCommandAllowed(input.command, policy.allow.commands)) return true;
  if (isPathAllowed(input.file_path, policy.allow.paths)) return true;
  return false;
}

function matchesScope(
  scope: CustomRuleScope | undefined,
  input: PolicyEvalInput,
): boolean {
  if (!scope) return true;

  if (scope.repos && scope.repos.length > 0) {
    if (!input.repo) return false;
    if (!scope.repos.some((g) => matchGlob(input.repo!, g, true, true))) {
      return false;
    }
  }

  if (scope.branches && scope.branches.length > 0) {
    if (!input.branch) return false;
    if (!scope.branches.some((g) => matchGlob(input.branch!, g, true, true))) {
      return false;
    }
  }

  if (scope.members && scope.members.length > 0) {
    if (!input.member) return false;
    if (!scope.members.includes(input.member)) {
      return false;
    }
  }

  if (scope.tools && scope.tools.length > 0) {
    if (!scope.tools.includes(input.tool)) {
      return false;
    }
  }

  return true;
}

interface FieldCandidate {
  value: string;
  pathAware: boolean;
}

interface EvalClock {
  deadline: number;
  nowMs: () => number;
  timedOut: boolean;
}

function checkExpired(clock: EvalClock): boolean {
  if (clock.timedOut) return true;
  if (clock.nowMs() >= clock.deadline) {
    clock.timedOut = true;
    return true;
  }
  return false;
}

function extractFieldCandidates(
  field: CustomRuleCondition["field"],
  input: PolicyEvalInput,
): FieldCandidate[] {
  switch (field) {
    case "command":
      return input.command !== undefined
        ? [{ value: input.command, pathAware: false }]
        : [];
    case "file_path":
      return input.file_path !== undefined
        ? [{ value: input.file_path, pathAware: true }]
        : [];
    case "tool":
      return input.toolName !== undefined
        ? [{ value: input.toolName, pathAware: false }]
        : [];
    case "url":
      return input.url !== undefined
        ? [{ value: input.url, pathAware: false }]
        : [];
    case "mcp_tool":
      return input.mcp_tool !== undefined
        ? [{ value: input.mcp_tool, pathAware: false }]
        : [];
    case "any": {
      const candidates: FieldCandidate[] = [];
      if (input.command !== undefined) {
        candidates.push({ value: input.command, pathAware: false });
      }
      if (input.file_path !== undefined) {
        candidates.push({ value: input.file_path, pathAware: true });
      }
      if (input.toolName !== undefined) {
        candidates.push({ value: input.toolName, pathAware: false });
      }
      if (input.url !== undefined) {
        candidates.push({ value: input.url, pathAware: false });
      }
      if (input.mcp_tool !== undefined) {
        candidates.push({ value: input.mcp_tool, pathAware: false });
      }
      return candidates;
    }
  }
}

function matchConditionAgainstCandidate(
  cond: CustomRuleCondition,
  candidate: FieldCandidate,
  clock: EvalClock,
): boolean {
  if (checkExpired(clock)) return false;

  const caseSensitive = cond.case_sensitive === true;
  const hay = caseSensitive ? candidate.value : candidate.value.toLowerCase();
  const needle = caseSensitive ? cond.value : cond.value.toLowerCase();

  switch (cond.op) {
    case "contains":
      return hay.includes(needle);
    case "starts_with":
      return hay.startsWith(needle);
    case "equals":
      return hay === needle;
    case "glob":
      return matchGlob(
        candidate.value,
        cond.value,
        caseSensitive,
        candidate.pathAware,
      );
    case "regex": {
      const remainingBeforeCompile = clock.deadline - clock.nowMs();
      if (remainingBeforeCompile <= 0) {
        clock.timedOut = true;
        return false;
      }
      const re = compileSafeRegex(cond.value, {
        caseSensitive,
        timeoutMs: Math.max(1, Math.floor(remainingBeforeCompile)),
        onTimeout: () => {
          clock.timedOut = true;
        },
      });
      if (checkExpired(clock)) return false;
      if (!re) return false;
      const remainingBeforeTest = clock.deadline - clock.nowMs();
      if (remainingBeforeTest <= 0) {
        clock.timedOut = true;
        return false;
      }
      const matched = testSafeRegex(
        re,
        candidate.value,
        Math.max(1, Math.floor(remainingBeforeTest)),
        () => {
          clock.timedOut = true;
        },
      );
      if (checkExpired(clock)) return false;
      return matched;
    }
  }
}

function matchesCondition(
  cond: CustomRuleCondition,
  input: PolicyEvalInput,
  clock: EvalClock,
): boolean {
  if (checkExpired(clock)) return false;
  const candidates = extractFieldCandidates(cond.field, input);
  if (candidates.length === 0) return false;
  for (const c of candidates) {
    if (checkExpired(clock)) return false;
    if (matchConditionAgainstCandidate(cond, c, clock)) return true;
    if (clock.timedOut) return false;
  }
  return false;
}

function matchesCustomRule(
  rule: CustomRule,
  input: PolicyEvalInput,
  clock: EvalClock,
): boolean {
  if (checkExpired(clock)) return false;
  if (!rule.enabled) return false;
  if (!rule.when || rule.when.length === 0) return false;
  if (!matchesScope(rule.scope, input)) return false;
  for (const cond of rule.when) {
    if (!matchesCondition(cond, input, clock)) return false;
    if (clock.timedOut) return false;
  }
  return true;
}

function buildBuiltinMatchContext(input: PolicyEvalInput): MatchContext {
  const payload: Record<string, unknown> = {};
  if (input.toolName) payload.tool_name = input.toolName;
  if (input.command !== undefined) payload.command = input.command;
  if (input.file_path !== undefined) payload.file_path = input.file_path;
  if (input.url !== undefined) payload.url = input.url;
  if (input.mcp_tool !== undefined) payload.mcp_tool = input.mcp_tool;
  if (input.toolInput !== undefined) payload.tool_input = input.toolInput;

  return {
    command: input.command,
    payload: Object.keys(payload).length > 0 ? payload : undefined,
    type: "tool_use_pre",
  };
}

function timedOutResult(): PolicyEvalResult {
  return {
    action: "allow",
    rule_ids: [],
    matches: [],
    downgraded: false,
    timed_out: true,
  };
}

/**
 * Pure, synchronous, network-free policy evaluator.
 * Evaluates built-in Guard rules with policy overrides first, then custom rules,
 * honoring allow lists, scope, strictest-wins precedence, observe mode, and
 * a total evaluation deadline (fail-open to allow when exceeded).
 */
export function evaluatePolicy(
  input: PolicyEvalInput,
  policy: Policy,
  builtinRules: Rule[] = RULES,
  opts: PolicyEvalOptions = {},
): PolicyEvalResult {
  const nowMs = opts.nowMs ?? (() => performance.now());
  const deadlineMs = opts.deadlineMs ?? POLICY_EVAL_DEADLINE_MS;
  const clock: EvalClock = {
    deadline: nowMs() + deadlineMs,
    nowMs,
    timedOut: false,
  };

  if (isExemptByAllowLists(input, policy)) {
    return {
      action: "allow",
      rule_ids: [],
      matches: [],
      downgraded: false,
    };
  }

  const matches: PolicyRuleMatch[] = [];
  const ctx = buildBuiltinMatchContext(input);

  for (const rule of builtinRules) {
    if (checkExpired(clock)) return timedOutResult();
    const override = policy.builtin[rule.id];
    const enabled = override !== undefined ? override.enabled : rule.enabled;
    if (!enabled) continue;

    const effectiveRule: Rule = rule.enabled ? rule : { ...rule, enabled: true };
    const finding = matchRule(effectiveRule, ctx);
    if (checkExpired(clock)) return timedOutResult();
    if (!finding) continue;

    const action: PolicyAction = override?.action ?? "flag";
    const severity: Severity = override?.severity ?? finding.severity;
    matches.push({
      rule_id: rule.id,
      name: rule.name,
      message: rule.description || rule.name,
      action,
      severity,
      source: "builtin",
      ...(override?.approval ? { approval: override.approval } : {}),
    });
  }

  for (const rule of policy.custom) {
    if (checkExpired(clock)) return timedOutResult();
    if (!matchesCustomRule(rule, input, clock)) {
      if (clock.timedOut) return timedOutResult();
      continue;
    }
    matches.push({
      rule_id: rule.id,
      name: rule.name,
      message: rule.message || rule.name,
      action: rule.action,
      severity: rule.severity,
      source: "custom",
      ...(rule.approval ? { approval: rule.approval } : {}),
    });
  }

  if (checkExpired(clock)) return timedOutResult();

  if (matches.length === 0) {
    return {
      action: "allow",
      rule_ids: [],
      matches: [],
      downgraded: false,
    };
  }

  let strictest: PolicyAction = matches[0]!.action;
  for (let i = 1; i < matches.length; i++) {
    const candidate = matches[i]!.action;
    if (ACTION_RANK[candidate] > ACTION_RANK[strictest]) {
      strictest = candidate;
    }
  }

  const ruleIds = matches.map((m) => m.rule_id);

  if (
    policy.mode === "observe" &&
    (strictest === "block" || strictest === "require_approval")
  ) {
    return {
      action: "flag",
      rule_ids: ruleIds,
      matches,
      downgraded: true,
      original_action: strictest,
    };
  }

  return {
    action: strictest,
    rule_ids: ruleIds,
    matches,
    downgraded: false,
  };
}
