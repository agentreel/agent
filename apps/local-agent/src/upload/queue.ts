import { getDb } from "../db.js";
import type { IngestEvent, IngestSession } from "./client.js";

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

export function takePendingBatch(
  maxEvents = MAX_BATCH_EVENTS,
  maxBytes = MAX_BATCH_BYTES,
  now = Date.now(),
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

  const sessions: IngestSession[] = sessionRows.map((s) => ({
    id: s.id,
    tool: s.tool,
    started_at: s.started_at,
    ended_at: s.ended_at,
    cwd: s.cwd,
    total_cost_cents: s.total_cost_cents,
    total_tokens: s.total_tokens,
    ...(s.attribution ? { attribution: safeParse(s.attribution) } : {}),
  }));

  const events: IngestEvent[] = eventRows.map((e) => ({
    id: e.id,
    session_id: e.session_id,
    ts: e.ts,
    type: e.type,
    tool: e.tool,
    cwd: e.cwd,
    payload: safeParse(e.payload),
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
