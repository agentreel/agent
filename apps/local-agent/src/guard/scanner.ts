import type { AgentEvent, Session } from "@agentreel/shared-types";
import type { Finding, SessionSummary, MatchContext } from "./types.js";
import { RULES } from "./rules.js";
import { matchAllRules, calculateRiskScore } from "./matcher.js";
import { readGuardConfig } from "./config.js";

export function scanEvent(event: AgentEvent): Finding[] {
  if (event.type === "policy_decision") return [];
  const config = readGuardConfig();

  const context: MatchContext = {
    command: extractCommand(event),
    cwd: event.cwd,
    payload: event.payload,
    type: event.type,
  };

  return matchAllRules(RULES, context, config);
}

export function scanSession(
  sessionId: string,
  events: AgentEvent[],
  session?: Session
): SessionSummary {
  const allFindings: Finding[] = [];
  const commandsExecuted = new Set<string>();
  const filesAccessed = new Set<string>();
  const hostsContacted = new Set<string>();
  const criticalPaths = new Set<string>();

  for (let i = 0; i < events.length; i++) {
    const event = events[i];
    if (!event || event.type === "policy_decision") continue;

    const recentEvents = events
      .slice(Math.max(0, i - 10), i)
      .filter((e): e is AgentEvent => e !== undefined)
      .map((e) => ({
        type: e.type,
        ts: e.ts,
        payload: e.payload,
      }));

    const context: MatchContext = {
      command: extractCommand(event),
      cwd: event.cwd,
      payload: event.payload,
      type: event.type,
      recentEvents,
    };

    const findings = matchAllRules(RULES, context, readGuardConfig());
    allFindings.push(...findings);

    analyzeBlastRadius(event, {
      commandsExecuted,
      filesAccessed,
      hostsContacted,
      criticalPaths,
    });
  }

  const riskScore = calculateRiskScore(allFindings);
  const summary = generateSummary(allFindings, events.length, riskScore);

  const firstEvent = events[0];
  
  return {
    sessionId,
    tool: session?.tool || firstEvent?.tool || "unknown",
    startedAt: session?.startedAt || firstEvent?.ts || Date.now(),
    endedAt: session?.endedAt,
    findings: allFindings,
    riskScore,
    blastRadius: {
      filesAccessed: filesAccessed.size,
      commandsExecuted: commandsExecuted.size,
      hostsContacted: Array.from(hostsContacted),
      criticalPaths: Array.from(criticalPaths),
    },
    summary,
  };
}

function extractCommand(event: AgentEvent): string | undefined {
  const payload = (event.payload || {}) as Record<string, unknown>;

  if (typeof payload.command === "string") return payload.command;
  if (typeof payload.tool_input === "object" && payload.tool_input !== null) {
    const input = payload.tool_input as Record<string, unknown>;
    if (typeof input.command === "string") return input.command;
  }

  if (event.type === "tool_use_pre" || event.type === "tool_use_post") {
    const str = JSON.stringify(payload);
    const cmdMatch = /"command":\s*"([^"]+)"/.exec(str);
    if (cmdMatch && cmdMatch[1]) return cmdMatch[1];
  }

  return undefined;
}

function analyzeBlastRadius(
  event: AgentEvent,
  acc: {
    commandsExecuted: Set<string>;
    filesAccessed: Set<string>;
    hostsContacted: Set<string>;
    criticalPaths: Set<string>;
  }
): void {
  const payload = (event.payload || {}) as Record<string, unknown>;

  if (payload.command) acc.commandsExecuted.add(String(payload.command));

  const payloadStr = JSON.stringify(payload);

  const filePatterns = [
    /(?:reading|writing|editing|file):\s*([^\s"']+\.[a-z]{2,4})/gi,
    /"path":\s*"([^"]+)"/gi,
    /"file":\s*"([^"]+)"/gi,
  ];
  for (const pattern of filePatterns) {
    let match;
    while ((match = pattern.exec(payloadStr)) !== null) {
      const filePath = match[1];
      if (!filePath) continue;
      acc.filesAccessed.add(filePath);
      if (
        filePath.includes("env") ||
        filePath.includes("secret") ||
        filePath.includes(".ssh") ||
        filePath.includes(".aws")
      ) {
        acc.criticalPaths.add(filePath);
      }
    }
  }

  const urlPattern = /https?:\/\/([^\/\s"']+)/gi;
  let match;
  while ((match = urlPattern.exec(payloadStr)) !== null) {
    const host = match[1];
    if (host && host !== "localhost" && host !== "127.0.0.1") {
      acc.hostsContacted.add(host);
    }
  }
}

function generateSummary(
  findings: Finding[],
  eventCount: number,
  riskScore: number
): string {
  if (findings.length === 0) {
    return `Session clean: ${eventCount} events analyzed, no risky patterns detected.`;
  }

  const critical = findings.filter((f) => f.severity === "critical").length;
  const high = findings.filter((f) => f.severity === "high").length;
  const warn = findings.filter((f) => f.severity === "warn").length;
  const info = findings.filter((f) => f.severity === "info").length;

  const parts: string[] = [];
  if (critical > 0) parts.push(`${critical} critical`);
  if (high > 0) parts.push(`${high} high`);
  if (warn > 0) parts.push(`${warn} warnings`);
  if (info > 0) parts.push(`${info} info`);

  const categories = Array.from(new Set(findings.map((f) => f.category)));

  return `Risk score: ${riskScore}/100. Detected ${parts.join(", ")} across ${categories.length} categories: ${categories.join(", ")}.`;
}
