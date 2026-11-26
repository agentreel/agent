import type { Rule, MatchContext, Finding } from "./types.js";
import type { GuardConfig } from "./types.js";
import { scrubString, scrubAny } from "../redact/scrubber.js";
import { runWithTimeout } from "../policy/regex.js";

export function matchRule(rule: Rule, context: MatchContext): Finding | null {
  if (!rule.enabled) return null;

  const { matcher } = rule;

  try {
    let matches = false;

    if (matcher.customMatcher) {
      matches = matcher.customMatcher(context);
    } else if (matcher.type === "command" && matcher.pattern) {
      const cmd = context.command || "";
      matches =
        typeof matcher.pattern === "string"
          ? cmd.includes(matcher.pattern)
          : matcher.pattern.test(cmd);
    } else if (
      matcher.type === "content-pattern" ||
      matcher.type === "db-operation" ||
      matcher.type === "url-pattern"
    ) {
      const text =
        (context.command || "") +
        " " +
        JSON.stringify(context.payload || {});
      if (matcher.pattern) {
        matches =
          typeof matcher.pattern === "string"
            ? text.includes(matcher.pattern)
            : matcher.pattern.test(text);
      }
      if (!matches && matcher.patterns) {
        matches = matcher.patterns.some((p) =>
          typeof p === "string" ? text.includes(p) : p.test(text)
        );
      }
    }

    if (!matches) return null;

    const scrubbedContext: MatchContext = {
      ...context,
      command: context.command ? scrubString(context.command) : undefined,
      payload: context.payload ? scrubAny(context.payload) : undefined,
    };

    const evidence = extractEvidence(scrubbedContext);

    return {
      ruleId: rule.id,
      severity: rule.severity,
      category: rule.category,
      timestamp: Date.now(),
      evidence,
      context: {
        command: scrubbedContext.command,
        file:
          typeof scrubbedContext.payload === "object" &&
          scrubbedContext.payload !== null &&
          "file" in scrubbedContext.payload
            ? String(scrubbedContext.payload.file)
            : undefined,
        location: context.cwd,
      },
    };
  } catch (err) {
    return null;
  }
}

function extractEvidence(context: MatchContext): string {
  if (context.command) {
    return context.command.slice(0, 500);
  }
  if (context.payload) {
    const payload = JSON.stringify(context.payload, null, 2);
    return payload.slice(0, 500);
  }
  return "No evidence available";
}

export function matchAllRules(
  rules: Rule[],
  context: MatchContext,
  config?: GuardConfig
): Finding[] {
  const findings: Finding[] = [];

  for (const rule of rules) {
    const ruleConfig = config?.rules?.[rule.id];
    if (ruleConfig?.enabled === false) continue;

    const finding = matchRule(rule, context);
    if (finding) {
      if (ruleConfig?.severity) {
        finding.severity = ruleConfig.severity;
      }

      if (isAllowlisted(finding, context, config)) {
        continue;
      }

      findings.push(finding);
    }
  }

  return findings;
}

export const SCAN_TIMEOUT_REASON = "scan_timeout";
export const SCAN_BUDGET_REASON = "scan_budget_exceeded";

export interface DeadlineMatchResult {
  findings: Finding[];
  /** True when the deadline preempted the rule pass before it finished. */
  timedOut: boolean;
  /** Rules that never finished and were reported as fail-closed findings. */
  timedOutRuleIds: string[];
}

/**
 * A resumable built-in rule pass. run() does the same work as matchAllRules
 * and records which rule it is on, so a caller can run it under a hard VM
 * deadline (runWithTimeout) together with other work in a single VM call.
 * finish(true) fails closed: the rule that was running and every enabled
 * rule after it are unevaluated, and each is reported as a finding at its
 * effective severity with reason "scan_timeout" (unknown counts as matched,
 * never clean). Findings from rules that finished are kept. Disabled rules
 * and the user's allowlists apply exactly as they do to real matches.
 */
export interface RulePass {
  run(): void;
  finish(timedOut: boolean): DeadlineMatchResult;
}

export function createRulePass(
  rules: Rule[],
  context: MatchContext,
  config: GuardConfig | undefined,
  deadlineMs: number
): RulePass {
  const findings: Finding[] = [];
  let next = 0;
  let done = false;

  return {
    run() {
      for (; next < rules.length; next++) {
        const rule = rules[next]!;
        const ruleConfig = config?.rules?.[rule.id];
        if (ruleConfig?.enabled === false) continue;

        const finding = matchRule(rule, context);
        if (!finding) continue;
        if (ruleConfig?.severity) finding.severity = ruleConfig.severity;
        if (isAllowlisted(finding, context, config)) continue;
        findings.push(finding);
      }
      done = true;
    },
    finish(timedOut) {
      if (!timedOut || done) {
        return { findings, timedOut: false, timedOutRuleIds: [] };
      }
      const timedOutRuleIds: string[] = [];
      for (let i = next; i < rules.length; i++) {
        const rule = rules[i]!;
        const ruleConfig = config?.rules?.[rule.id];
        if (ruleConfig?.enabled === false || !rule.enabled) continue;
        const finding = timeoutFinding(rule, context, deadlineMs);
        if (ruleConfig?.severity) finding.severity = ruleConfig.severity;
        if (isAllowlisted(finding, context, config)) continue;
        findings.push(finding);
        timedOutRuleIds.push(rule.id);
      }
      return { findings, timedOut: true, timedOutRuleIds };
    },
  };
}

/** createRulePass run alone under a hard deadline of deadlineMs. */
export function matchAllRulesWithDeadline(
  rules: Rule[],
  context: MatchContext,
  config: GuardConfig | undefined,
  deadlineMs: number
): DeadlineMatchResult {
  const pass = createRulePass(rules, context, config, deadlineMs);
  const run = runWithTimeout(() => pass.run(), deadlineMs);
  return pass.finish(!run.ok);
}

/**
 * Fail-closed findings for events the batch scan budget left unscanned.
 * Same style as scan_timeout: every enabled rule is reported at its
 * effective severity, because "not scanned" must never read as "clean".
 * One finding per rule per call rather than per event, so a batch of 500
 * unscanned events adds at most one finding per rule to a session. Config
 * overrides, disabled rules and the user's allowlists apply as for real
 * matches: a rule is skipped when every unscanned event is allowlisted.
 * No command text in the evidence (see timeoutFinding).
 */
export function budgetFindings(
  rules: Rule[],
  unscanned: MatchContext[],
  config: GuardConfig | undefined,
  budgetMs: number
): { findings: Finding[]; ruleIds: string[] } {
  const findings: Finding[] = [];
  const ruleIds: string[] = [];
  if (unscanned.length === 0) return { findings, ruleIds };
  for (const rule of rules) {
    const ruleConfig = config?.rules?.[rule.id];
    if (ruleConfig?.enabled === false || !rule.enabled) continue;
    const finding: Finding = {
      ruleId: rule.id,
      severity: rule.severity,
      category: rule.category,
      timestamp: Date.now(),
      reason: SCAN_BUDGET_REASON,
      evidence: `${SCAN_BUDGET_REASON}: ${unscanned.length} event(s) not scanned within the ${Math.floor(budgetMs)}ms batch scan budget; counted as a match`,
      context: { location: unscanned[0]?.cwd },
    };
    if (ruleConfig?.severity) finding.severity = ruleConfig.severity;
    if (unscanned.every((ctx) => isAllowlisted(finding, ctx, config))) continue;
    findings.push(finding);
    ruleIds.push(rule.id);
  }
  return { findings, ruleIds };
}

function timeoutFinding(
  rule: Rule,
  context: MatchContext,
  deadlineMs: number
): Finding {
  // No command text in the evidence: scrubbing a crafted input is itself
  // regex work that the deadline no longer bounds, and an unscrubbed slice
  // could leak part of a secret.
  const length = context.command?.length ?? 0;
  return {
    ruleId: rule.id,
    severity: rule.severity,
    category: rule.category,
    timestamp: Date.now(),
    reason: SCAN_TIMEOUT_REASON,
    evidence: `${SCAN_TIMEOUT_REASON}: rule not evaluated within ${Math.floor(deadlineMs)}ms on a ${length}-char command; counted as a match`,
    context: { location: context.cwd },
  };
}

function isAllowlisted(
  finding: Finding,
  context: MatchContext,
  config?: GuardConfig
): boolean {
  if (!config?.allowlists) return false;

  if (config.allowlists.commands && context.command) {
    for (const allowed of config.allowlists.commands) {
      if (context.command.includes(allowed)) return true;
    }
  }

  if (config.allowlists.paths && context.cwd) {
    for (const allowed of config.allowlists.paths) {
      if (context.cwd.startsWith(allowed)) return true;
    }
  }

  return false;
}

export function calculateRiskScore(findings: Finding[]): number {
  if (findings.length === 0) return 0;

  const severityWeights = {
    critical: 40,
    high: 20,
    warn: 5,
    info: 1,
  };

  let score = 0;
  for (const finding of findings) {
    score += severityWeights[finding.severity] || 0;
  }

  return Math.min(score, 100);
}
