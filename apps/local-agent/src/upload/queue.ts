import { getDb } from "../db.js";
import type { IngestEvent, IngestSession } from "./client.js";
import type { AgentEvent } from "@agentreel/shared-types";
import {
  ScanBudget,
  SCAN_BUDGET_REASON,
  logScan,
  scanSession,
} from "../guard/scanner.js";
import { capPayloadFields } from "./payload-caps.js";
import { readGuardConfig } from "../guard/config.js";
import type { PolicyDecisionRecord } from "../policy/enforce.js";
import { scrubAny } from "../redact/scrubber.js";

interface DBSessionRow {
  id: string;
  tool: string;
  started_at: number;
  ended_at: number | null;
  cwd: string | null;
  total_cost_cents: number | null;
  total_tokens: number | null;
  attribution: string | null;
}

interface DBEventRow {
  id: string;
  session_id: string;
  tool: string;
  type: string;
  ts: number;
  cwd: string | null;
  payload: string;
}

export interface PendingBatch {
  sessions: IngestSession[];
  events: IngestEvent[];
  eventIds: string[]; // for the post-write mark
  /** Parallel to eventIds: which session each event belongs to. */
  eventSessionIds: string[];
}

// Cloud cap is 5 MB; we stay well under that to leave room for JSON framing
// + auth headers and to keep individual round-trips snappy.
export const MAX_BATCH_BYTES = 1024 * 1024; // 1 MB
export const MAX_BATCH_EVENTS = 500;

export interface TakeBatchOptions {
  /**
   * Total scan budget shared by every session in this batch. Defaults to a
   * fresh ScanBudget(SCAN_BATCH_BUDGET_MS). Tests inject one with a fake clock.
   */
  scanBudget?: ScanBudget;
  /** Receives the one log line written when the budget ran out. */
  scanLog?: (message: string) => void;
}

export function takePendingBatch(
  maxEvents = MAX_BATCH_EVENTS,
  maxBytes = MAX_BATCH_BYTES,
  now = Date.now(),
  opts: TakeBatchOptions = {},
): PendingBatch {
  const db = getDb();
  // Skip sessions the server parked (plan limit) until their hold expires,
  // so one refused session can't block everything queued behind it.
  const candidateRows = db
    .prepare(
      `SELECT e.id, e.session_id, e.tool, e.type, e.ts, e.cwd, e.payload
       FROM events e
       LEFT JOIN sessions s ON s.id = e.session_id
       WHERE e.uploaded_at IS NULL
         AND (s.held_until IS NULL OR s.held_until <= ?)
       ORDER BY e.ts ASC
       LIMIT ?`,
    )
    .all(now, maxEvents) as DBEventRow[];

  if (candidateRows.length === 0) return { sessions: [], events: [], eventIds: [], eventSessionIds: [] };

  // Trim to byte budget. Always include at least one event so a single
  // oversized payload doesn't get stuck in the queue forever — the server
  // can reject it and we'll mark it uploaded to skip past.
  const eventRows: DBEventRow[] = [];
  let bytes = 0;
  for (const row of candidateRows) {
    const rowBytes = Buffer.byteLength(row.payload, "utf8");
    if (eventRows.length > 0 && bytes + rowBytes > maxBytes) break;
    eventRows.push(row);
    bytes += rowBytes;
  }

  const sessionIds = [...new Set(eventRows.map((e) => e.session_id))];
  const placeholders = sessionIds.map(() => "?").join(",");
  const sessionRows = db
    .prepare(
      `SELECT id, tool, started_at, ended_at, cwd, total_cost_cents, total_tokens, attribution
       FROM sessions WHERE id IN (${placeholders})`,
    )
    .all(...sessionIds) as DBSessionRow[];

  const guardConfig = readGuardConfig();
  const shouldScan = guardConfig.enabled;
  // One budget for the whole flush: bounds the time spent scanning no matter
  // how many events or sessions the batch holds, and on every retry.
  const scanBudget = opts.scanBudget ?? new ScanBudget();

  const sessions: IngestSession[] = sessionRows.map((s) => {
    const base: IngestSession = {
      id: s.id,
      tool: s.tool,
      started_at: s.started_at,
      ended_at: s.ended_at,
      cwd: s.cwd,
      total_cost_cents: s.total_cost_cents,
      total_tokens: s.total_tokens,
      ...(s.attribution ? { attribution: safeParse(s.attribution) } : {}),
    };

    const sessionEvents = eventRows.filter((e) => e.session_id === s.id);
    const nonDecisionEvents = sessionEvents.filter((e) => e.type !== "policy_decision");
    const decisionEvents = sessionEvents.filter((e) => e.type === "policy_decision");

    if (shouldScan && nonDecisionEvents.length > 0) {
      const parsedEvents: AgentEvent[] = nonDecisionEvents.map((e) => ({
        id: e.id,
        sessionId: e.session_id,
        tool: e.tool as "claude-code" | "cursor",
        type: e.type as AgentEvent["type"],
        ts: e.ts,
        cwd: e.cwd || undefined,
        payload: safeParse(e.payload),
      }));

      const summary = scanSession(s.id, parsedEvents, undefined, {
        budget: scanBudget,
      });

      base.guard_findings = {
        version: 1,
        risk_score: summary.riskScore,
        findings: summary.findings.map((f) => ({
          rule_id: f.ruleId,
          severity: f.severity,
          category: f.category,
          timestamp: f.timestamp,
          evidence: f.evidence,
        })),
      };
    }

    if (decisionEvents.length > 0) {
      const decisions: PolicyDecisionRecord[] = decisionEvents.map((e) => {
        const raw = safeParse(e.payload);
        const rawObj =
          raw && typeof raw === "object" && !Array.isArray(raw)
            ? (raw as Record<string, unknown>)
            : {};
        const obj = scrubAny(rawObj) as Record<string, unknown>;
        if (typeof rawObj.decided_by === "string") {
          obj.decided_by = rawObj.decided_by;
        }
        const ruleIds = Array.isArray(obj.rule_ids)
          ? obj.rule_ids.filter((r): r is string => typeof r === "string")
          : typeof obj.rule_id === "string"
            ? [obj.rule_id]
            : [];
        const ruleId =
          typeof obj.rule_id === "string" ? obj.rule_id : ruleIds[0] ?? "unknown";
        return {
          ...obj,
          id: typeof obj.id === "string" ? obj.id : e.id,
          ts: typeof obj.ts === "number" ? obj.ts : e.ts,
          session_id: typeof obj.session_id === "string" ? obj.session_id : e.session_id,
          rule_id: ruleId,
          rule_ids: ruleIds,
          action: (obj.action as PolicyDecisionRecord["action"]) ?? "flag",
          enforced: Boolean(obj.enforced),
          downgraded: Boolean(obj.downgraded),
          policy_etag:
            typeof obj.policy_etag === "string" ? obj.policy_etag : null,
          tool:
            obj.tool === "claude-code" || obj.tool === "cursor"
              ? obj.tool
              : (e.tool as PolicyDecisionRecord["tool"]),
        };
      });

      base.policy_decisions = {
        version: 2,
        decisions,
      };
    }

    return base;
  });

  if (scanBudget.unscannedEvents > 0) {
    (opts.scanLog ?? logScan)(
      `${SCAN_BUDGET_REASON}: batch scan budget of ${Math.floor(scanBudget.totalMs)}ms used up; ${scanBudget.unscannedEvents} event(s) in ${scanBudget.unscannedSessions} session(s) were not scanned and are counted as findings`,
    );
  }

  // Payload fields are capped here, after the guard scan above, which ran on
  // the full text. Truncating first would let a long payload hide a risky
  // command or secret behind the cut, and the scan evidence would no longer
  // match what the user did. The scan result (guard_findings) is computed
  // from the full payload and uploaded unchanged.
  const events: IngestEvent[] = eventRows.map((e) => ({
    id: e.id,
    session_id: e.session_id,
    ts: e.ts,
    type: e.type,
    tool: e.tool,
    cwd: e.cwd,
    payload: capPayloadFields(safeParse(e.payload)),
  }));

  return {
    sessions,
    events,
    eventIds: eventRows.map((r) => r.id),
    eventSessionIds: eventRows.map((r) => r.session_id),
  };
}

export function markUploaded(eventIds: string[]): void {
  if (eventIds.length === 0) return;
  const db = getDb();
  const now = Date.now();
  const stmt = db.prepare(`UPDATE events SET uploaded_at = ? WHERE id = ?`);
  const tx = db.transaction((ids: string[]) => {
    for (const id of ids) stmt.run(now, id);
  });
  tx(eventIds);
}

function safeParse(s: string): unknown {
  try {
    return JSON.parse(s);
  } catch {
    return s;
  }
}
