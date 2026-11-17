import type { Rule, MatchContext, Finding } from "./types.js";
import type { GuardConfig } from "./types.js";
import { scrubString } from "../redact/scrubber.js";

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
      payload: context.payload ? JSON.parse(scrubString(JSON.stringify(context.payload))) : undefined,
    };

    const evidence = extractEvidence(scrubbedContext);
    const scrubbedEvidence = scrubString(evidence);

    return {
      ruleId: rule.id,
      severity: rule.severity,
      category: rule.category,
      timestamp: Date.now(),
      evidence: scrubbedEvidence,
      context: {
        command: scrubbedContext.command,
        file:
          typeof scrubbedContext.payload === "object" &&
          scrubbedContext.payload !== null &&
          "file" in scrubbedContext.payload
            ? scrubString(String(scrubbedContext.payload.file))
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
