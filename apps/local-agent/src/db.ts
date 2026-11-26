import Database from "better-sqlite3";
import type { Database as DB } from "better-sqlite3";
import { dbPath, ensureAgentreelDir } from "./paths.js";
import type { AgentEvent, Session, Tool } from "@agentreel/shared-types";

let _db: DB | null = null;

export function getDb(): DB {
  if (_db) return _db;
  ensureAgentreelDir();
  const db = new Database(dbPath());
  db.pragma("journal_mode = WAL");
  db.pragma("synchronous = NORMAL");
  migrate(db);
  _db = db;
  return db;
}

function migrate(db: DB): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      tool TEXT NOT NULL,
      started_at INTEGER NOT NULL,
      ended_at INTEGER,
      cwd TEXT,
      total_cost_cents INTEGER,
      total_tokens INTEGER
    );
    CREATE TABLE IF NOT EXISTS events (
      id TEXT PRIMARY KEY,
      session_id TEXT NOT NULL,
      tool TEXT NOT NULL,
      type TEXT NOT NULL,
      ts INTEGER NOT NULL,
      cwd TEXT,
      payload TEXT NOT NULL,
      uploaded_at INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id, ts);
    CREATE INDEX IF NOT EXISTS idx_events_pending ON events(uploaded_at) WHERE uploaded_at IS NULL;
    CREATE TABLE IF NOT EXISTS meta (
      key TEXT PRIMARY KEY,
      value TEXT
    );
  `);
  // v0.1.6: sessions the server refused (plan limit) are parked until
  // held_until so they don't block the queue or cause a retry loop.
  const cols = new Set(
    (db.prepare(`PRAGMA table_info(sessions)`).all() as Array<{ name: string }>).map((c) => c.name),
  );
  if (!cols.has("held_until")) db.exec(`ALTER TABLE sessions ADD COLUMN held_until INTEGER`);
  if (!cols.has("held_reason")) db.exec(`ALTER TABLE sessions ADD COLUMN held_reason TEXT`);
  // v0.1.7: who/where ran the agent (JSON, see attribution.ts).
  if (!cols.has("attribution")) db.exec(`ALTER TABLE sessions ADD COLUMN attribution TEXT`);
}

/** For tests: close and forget the cached handle. */
export function closeDb(): void {
  _db?.close();
  _db = null;
}

export function getMeta(key: string): string | null {
  const db = getDb();
  const row = db.prepare(`SELECT value FROM meta WHERE key = ?`).get(key) as
    | { value: string }
    | undefined;
  return row?.value ?? null;
}

export function setMeta(key: string, value: string | null): void {
  const db = getDb();
  if (value == null) {
    db.prepare(`DELETE FROM meta WHERE key = ?`).run(key);
    return;
  }
  db.prepare(
    `INSERT INTO meta (key, value) VALUES (?, ?)
     ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
  ).run(key, value);
}

/** Bytes waiting to upload, excluding sessions parked by the server. */
export function pendingByteSize(now = Date.now()): number {
  const db = getDb();
  const row = db
    .prepare(
      `SELECT COALESCE(SUM(LENGTH(e.payload)), 0) AS bytes
       FROM events e LEFT JOIN sessions s ON s.id = e.session_id
       WHERE e.uploaded_at IS NULL AND (s.held_until IS NULL OR s.held_until <= ?)`,
    )
    .get(now) as { bytes: number };
  return row.bytes;
}

export function upsertSession(s: Session): void {
  const db = getDb();
  db.prepare(
    `INSERT INTO sessions (id, tool, started_at, ended_at, cwd, total_cost_cents, total_tokens)
     VALUES (@id, @tool, @startedAt, @endedAt, @cwd, @totalCostCents, @totalTokens)
     ON CONFLICT(id) DO UPDATE SET
       ended_at = COALESCE(excluded.ended_at, sessions.ended_at),
       cwd = COALESCE(excluded.cwd, sessions.cwd),
       total_cost_cents = COALESCE(excluded.total_cost_cents, sessions.total_cost_cents),
       total_tokens = COALESCE(excluded.total_tokens, sessions.total_tokens)`,
  ).run({
    id: s.id,
    tool: s.tool,
    startedAt: s.startedAt,
    endedAt: s.endedAt ?? null,
    cwd: s.cwd ?? null,
    totalCostCents: s.totalCostCents ?? null,
    totalTokens: s.totalTokens ?? null,
  });
}

export function insertEvent(e: AgentEvent): void {
  const db = getDb();
  db.prepare(
    `INSERT OR IGNORE INTO events (id, session_id, tool, type, ts, cwd, payload)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
  ).run(e.id, e.sessionId, e.tool, e.type, e.ts, e.cwd ?? null, JSON.stringify(e.payload ?? {}));
}

export function countEvents(now = Date.now()): { total: number; pending: number; held: number } {
  const db = getDb();
  const total = db.prepare(`SELECT COUNT(*) AS c FROM events`).get() as { c: number };
  const pending = db
    .prepare(`SELECT COUNT(*) AS c FROM events WHERE uploaded_at IS NULL`)
    .get() as { c: number };
  const held = db
    .prepare(
      `SELECT COUNT(*) AS c FROM events e JOIN sessions s ON s.id = e.session_id
       WHERE e.uploaded_at IS NULL AND s.held_until IS NOT NULL AND s.held_until > ?`,
    )
    .get(now) as { c: number };
  return { total: total.c, pending: pending.c, held: held.c };
}

/** Park sessions the server rejected; their events are skipped until `until`. */
export function holdSessions(ids: string[], until: number, reason: string): void {
  if (ids.length === 0) return;
  const db = getDb();
  const stmt = db.prepare(`UPDATE sessions SET held_until = ?, held_reason = ? WHERE id = ?`);
  db.transaction((xs: string[]) => {
    for (const id of xs) stmt.run(until, reason, id);
  })(ids);
}

/** Make every held session eligible for upload again (e.g. after upgrading). */
export function releaseHeldSessions(): number {
  const db = getDb();
  return db.prepare(`UPDATE sessions SET held_until = NULL, held_reason = NULL WHERE held_until IS NOT NULL`).run()
    .changes;
}

export function listHeldSessions(now = Date.now()): Array<{ id: string; held_until: number; held_reason: string | null }> {
  const db = getDb();
  return db
    .prepare(
      `SELECT id, held_until, held_reason FROM sessions
       WHERE held_until IS NOT NULL AND held_until > ? ORDER BY started_at`,
    )
    .all(now) as Array<{ id: string; held_until: number; held_reason: string | null }>;
}

export function listRecentSessions(limit = 10): Array<{
  id: string;
  tool: Tool;
  started_at: number;
  ended_at: number | null;
  cwd: string | null;
}> {
  const db = getDb();
  return db
    .prepare(
      `SELECT id, tool, started_at, ended_at, cwd
       FROM sessions ORDER BY started_at DESC LIMIT ?`,
    )
    .all(limit) as Array<{
    id: string;
    tool: Tool;
    started_at: number;
    ended_at: number | null;
    cwd: string | null;
  }>;
}

export function getSessionAttribution<T = unknown>(id: string): T | null {
  const db = getDb();
  const row = db.prepare(`SELECT attribution FROM sessions WHERE id = ?`).get(id) as
    | { attribution: string | null }
    | undefined;
  if (!row?.attribution) return null;
  try {
    return JSON.parse(row.attribution) as T;
  } catch {
    return null;
  }
}

export function setSessionAttribution(id: string, value: unknown): void {
  const db = getDb();
  db.prepare(`UPDATE sessions SET attribution = ? WHERE id = ?`).run(
    value == null ? null : JSON.stringify(value),
    id,
  );
}
