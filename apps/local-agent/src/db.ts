import Database from "better-sqlite3";
import type { Database as DB } from "better-sqlite3";
import { DB_PATH, ensureAgentreelDir } from "./paths.js";
import type { AgentEvent, Session, Tool } from "@agentreel/shared-types";

let _db: DB | null = null;

export function getDb(): DB {
  if (_db) return _db;
  ensureAgentreelDir();
  const db = new Database(DB_PATH);
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

export function pendingByteSize(): number {
  const db = getDb();
  const row = db
    .prepare(
      `SELECT COALESCE(SUM(LENGTH(payload)), 0) AS bytes
       FROM events WHERE uploaded_at IS NULL`,
    )
    .get() as { bytes: number };
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

export function countEvents(): { total: number; pending: number } {
  const db = getDb();
  const total = db.prepare(`SELECT COUNT(*) AS c FROM events`).get() as { c: number };
  const pending = db
    .prepare(`SELECT COUNT(*) AS c FROM events WHERE uploaded_at IS NULL`)
    .get() as { c: number };
  return { total: total.c, pending: pending.c };
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
