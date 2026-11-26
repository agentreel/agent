import { appendFileSync } from "node:fs";
import type { AgentEvent, Session } from "@agentreel/shared-types";
import type { Finding, SessionSummary, MatchContext } from "./types.js";
import { RULES } from "./rules.js";
import {
  calculateRiskScore,
  createRulePass,
  matchAllRulesWithDeadline,
  SCAN_TIMEOUT_REASON,
} from "./matcher.js";
import { readGuardConfig } from "./config.js";
import { runWithTimeout } from "../policy/regex.js";
import { LOG_PATH, ensureAgentreelDir } from "../paths.js";

/**
 * Hard per-event budget for the built-in rule pass (and, separately, the
 * blast-radius pass). Built-in rules run native regexes, some of which
 * backtrack superlinearly on crafted input (INSTALL001 is cubic on "curl"
 * plus spaces), so each pass runs under the same VM watchdog the policy
 * evaluator uses, which preempts a running match.
 *
 * The budget is 50ms plus 0.5ms per KB of scanned text (command plus JSON
 * payload), capped at 1000ms. The per-KB allowance keeps legitimate large
 * payloads clean: a 500KB Read result takes about 50ms through all rules,
 * linear in size, and gets a 300ms budget. Crafted superlinear inputs blow
 * far past it: "git push" plus 32KB of spaces took 3.3s natively and now
 * stops at its 66ms budget.
 */
export const SCAN_DEADLINE_BASE_MS = 50;
export const SCAN_DEADLINE_PER_KB_MS = 0.5;
export const SCAN_DEADLINE_MAX_MS = 1000;

export { SCAN_TIMEOUT_REASON };

export interface ScanOptions {
  /** Fixed per-event budget, overriding the size-scaled default. */
  deadlineMs?: number;
  /** Receives one line per scan that hit the deadline. */
  log?: (message: string) => void;
}

export function scanDeadlineMs(context: MatchContext): number {
  let size = context.command?.length ?? 0;
  try {
    size += JSON.stringify(context.payload ?? {}).length;
  } catch {
    // Unserializable payloads are not scanned by content rules either.
  }
  const budget =
    SCAN_DEADLINE_BASE_MS + Math.ceil(size / 1024) * SCAN_DEADLINE_PER_KB_MS;
  return Math.min(SCAN_DEADLINE_MAX_MS, budget);
}

function defaultLog(message: string): void {
  try {
    ensureAgentreelDir();
    appendFileSync(
      LOG_PATH,
      `[${new Date().toISOString()}] guard scan: ${message}\n`,
    );
  } catch {
    // Logging must never break a scan or an upload.
  }
}

export function scanEvent(event: AgentEvent, opts: ScanOptions = {}): Finding[] {
  if (event.type === "policy_decision") return [];
  const config = readGuardConfig();

  const context: MatchContext = {
    command: extractCommand(event),
    cwd: event.cwd,
    payload: event.payload,
    type: event.type,
  };

  const deadlineMs = opts.deadlineMs ?? scanDeadlineMs(context);
  const result = matchAllRulesWithDeadline(RULES, context, config, deadlineMs);
  if (result.timedOut) {
    (opts.log ?? defaultLog)(
      `${SCAN_TIMEOUT_REASON}: event ${event.id} exceeded ${Math.floor(deadlineMs)}ms; rule(s) ${result.timedOutRuleIds.join(", ") || "none"} failed closed as findings`,
    );
  }
  return result.findings;
}

export function scanSession(
  sessionId: string,
  events: AgentEvent[],
  session?: Session,
  opts: ScanOptions = {}
): SessionSummary {
  const allFindings: Finding[] = [];
  const timedOutRuleIds = new Set<string>();
  const timedOutEventIds: string[] = [];
  let blastRadiusTimeouts = 0;
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

    // One VM call per event (each costs about 80us): the rule pass first,
    // then the blast-radius stats, under one hard deadline.
    const deadlineMs = opts.deadlineMs ?? scanDeadlineMs(context);
    const pass = createRulePass(RULES, context, readGuardConfig(), deadlineMs);
    let blastPhase = false;
    const run = runWithTimeout(() => {
      pass.run();
      blastPhase = true;
      analyzeBlastRadius(event, {
        commandsExecuted,
        filesAccessed,
        hostsContacted,
        criticalPaths,
      });
    }, deadlineMs);
    // A timeout in the rule pass fails closed. A timeout in the blast-radius
    // pass (informational stats, not a verdict) keeps what was collected.
    const result = pass.finish(!run.ok && !blastPhase);
    allFindings.push(...result.findings);
    if (result.timedOut) {
      timedOutEventIds.push(event.id);
      for (const id of result.timedOutRuleIds) timedOutRuleIds.add(id);
    }
    if (!run.ok) blastRadiusTimeouts++;
  }

  if (timedOutEventIds.length > 0 || blastRadiusTimeouts > 0) {
    const parts: string[] = [];
    if (timedOutEventIds.length > 0) {
      parts.push(
        `${timedOutEventIds.length} event(s) exceeded the rule deadline (${timedOutEventIds.slice(0, 5).join(", ")}${timedOutEventIds.length > 5 ? ", ..." : ""}); rule(s) ${[...timedOutRuleIds].join(", ") || "none"} failed closed as findings`
      );
    }
    if (blastRadiusTimeouts > 0) {
      parts.push(`${blastRadiusTimeouts} event(s) did not finish blast-radius stats; stats are partial`);
    }
    (opts.log ?? defaultLog)(
      `${SCAN_TIMEOUT_REASON}: session ${sessionId}: ${parts.join("; ")}`
    );
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
    ...(timedOutEventIds.length > 0
      ? { timedOut: true, timedOutRuleIds: [...timedOutRuleIds] }
      : {}),
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
