/**
 * Transcript watcher and hook-gap alarm (re-audit item 3, gap G7).
 *
 * The hooks are the primary capture and block path, and they are user-level
 * files an agent can edit. The agent's own transcript is a second, independent
 * record: Claude Code appends every `tool_use` it makes to
 * `~/.claude/projects/**.jsonl`. This watcher tails those files and checks
 * that each tool call also reached the hooks (a `tool_use_pre` event with the
 * same `tool_use_id`). A tool call with no matching event after a grace period
 * is a **hook gap**: the hook was off, edited out or crashed.
 *
 * Detect-only and after the fact. It never blocks anything and never reads a
 * transcript to store its content: only the tool_use id, tool name, session id
 * and timestamp are kept. An agent can still edit or delete a transcript, but
 * the rotated/truncated counters and the missing line show up as a gap.
 */
import { createHash } from "node:crypto";
import { closeSync, openSync, readSync, readdirSync, statSync, type Stats } from "node:fs";
import { basename, join } from "node:path";
import type { Database as DB } from "better-sqlite3";
import { claudeDir } from "../paths.js";
import { getDb, getMeta, setMeta } from "../db.js";

export const META_WATCHER_STATE = "transcript_watcher_state";
export const META_WATCHER_TOTALS = "transcript_watcher_totals";

/** A tool call with no hook event this long after we first saw it is a gap. */
export const DEFAULT_GRACE_MS = 60_000;
/** At most this many bytes are read from one file per scan. */
export const MAX_READ_BYTES_PER_FILE = 4 * 1024 * 1024;
/** A single transcript line longer than this is skipped, not buffered. */
export const MAX_LINE_BYTES = 8 * 1024 * 1024;
export const MAX_FILES = 2000;
export const MAX_DEPTH = 4;
/** Matched rows are dropped after this long. */
const MATCHED_TTL_MS = 60 * 60_000;
/** Reported gaps are kept this long locally. */
const REPORTED_GAP_TTL_MS = 7 * 24 * 60 * 60_000;
/** Hard cap on gap rows kept locally. The oldest go first. */
const MAX_GAP_ROWS = 5000;
const HEAD_BYTES = 256;
/** Daemon scan cadence is 30 s. A scan older than this means it stopped. */
export const WATCHER_STALE_AFTER_MS = 5 * 60_000;

export type WatcherState = "running" | "idle" | "disabled" | "error";

export interface WatcherErrors {
  permission_denied: number;
  rotated_or_truncated: number;
  unreadable: number;
}

export interface WatcherStatus {
  state: WatcherState;
  files_watched: number;
  last_scan_at: number | null;
  errors: WatcherErrors;
  /** Why the state is not "running" (never contains a path). */
  reason?: string;
}

export interface WatcherTotals {
  tool_uses_seen: number;
  hook_gaps_total: number;
}

export interface HookGapRow {
  tool_use_id: string;
  session_id: string;
  tool_name: string;
  source: "claude-code";
  transcript_ts: number | null;
  detected_at: number;
}

/** File system access, injectable so tests can simulate EACCES and races. */
export interface WatcherIo {
  readdir(dir: string): Array<{ name: string; isDir: boolean; isFile: boolean; isSymlink: boolean }>;
  stat(path: string): Pick<Stats, "size" | "ino" | "mtimeMs">;
  /** Read up to `length` bytes at `position`. Returns fewer at EOF. */
  read(path: string, position: number, length: number): Buffer;
}

export const realIo: WatcherIo = {
  readdir(dir) {
    return readdirSync(dir, { withFileTypes: true }).map((d) => ({
      name: d.name,
      isDir: d.isDirectory(),
      isFile: d.isFile(),
      isSymlink: d.isSymbolicLink(),
    }));
  },
  stat: (p) => statSync(p),
  read(path, position, length) {
    const fd = openSync(path, "r");
    try {
      const buf = Buffer.alloc(length);
      const n = readSync(fd, buf, 0, length, position);
      return buf.subarray(0, n);
    } finally {
      closeSync(fd);
    }
  },
};

export interface TranscriptWatcherOptions {
  projectsDir?: string;
  graceMs?: number;
  now?: () => number;
  io?: WatcherIo;
  /** True while capture is paused. Nothing is evaluated and offsets move to EOF. */
  isPaused?: () => boolean;
  /** True when hooks are expected to be installed (`agentreel init` ran, not uninstalled). */
  hooksExpected?: () => boolean;
  /** Off switch (AGENTREEL_TRANSCRIPT_WATCH=0). */
  enabled?: () => boolean;
}

export function defaultProjectsDir(env: NodeJS.ProcessEnv = process.env): string {
  const override = env.AGENTREEL_CLAUDE_PROJECTS_DIR;
  if (override && override.trim()) return override;
  const cfgDir = env.CLAUDE_CONFIG_DIR;
  if (cfgDir && cfgDir.trim()) return join(cfgDir, "projects");
  return join(claudeDir(), "projects");
}

export function transcriptWatchEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  const v = env.AGENTREEL_TRANSCRIPT_WATCH;
  return !(v === "0" || v === "false" || v === "no" || v === "off");
}

let schemaReady: DB | null = null;

function ensureSchema(db: DB): void {
  if (schemaReady === db) return;
  db.exec(`
    CREATE TABLE IF NOT EXISTS transcript_files (
      path TEXT PRIMARY KEY,
      ino TEXT NOT NULL,
      offset INTEGER NOT NULL,
      head_sha TEXT,
      seen_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS transcript_tool_uses (
      tool_use_id TEXT PRIMARY KEY,
      session_id TEXT NOT NULL,
      tool_name TEXT NOT NULL,
      transcript_ts INTEGER,
      first_seen_at INTEGER NOT NULL,
      status TEXT NOT NULL,
      resolved_at INTEGER,
      reported_at INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_ttu_status ON transcript_tool_uses(status, first_seen_at);
    CREATE INDEX IF NOT EXISTS idx_events_tool_use_pre
      ON events(json_extract(payload, '$.tool_use_id')) WHERE type = 'tool_use_pre';
  `);
  schemaReady = db;
}

/** For tests: forget the schema flag after the db handle is closed. */
export function resetWatcherSchemaFlag(): void {
  schemaReady = null;
}

function readTotals(): WatcherTotals {
  try {
    const t = JSON.parse(getMeta(META_WATCHER_TOTALS) ?? "{}") as Partial<WatcherTotals>;
    return {
      tool_uses_seen: Number.isFinite(t.tool_uses_seen) ? Number(t.tool_uses_seen) : 0,
      hook_gaps_total: Number.isFinite(t.hook_gaps_total) ? Number(t.hook_gaps_total) : 0,
    };
  } catch {
    return { tool_uses_seen: 0, hook_gaps_total: 0 };
  }
}

export function getWatcherTotals(): WatcherTotals {
  return readTotals();
}

function writeTotals(t: WatcherTotals): void {
  setMeta(META_WATCHER_TOTALS, JSON.stringify(t));
}

/** Last persisted status (what the daemon last wrote). Null if it never scanned. */
export function readWatcherStatus(): WatcherStatus | null {
  try {
    const raw = getMeta(META_WATCHER_STATE);
    if (!raw) return null;
    const s = JSON.parse(raw) as WatcherStatus;
    if (!s || typeof s.state !== "string") return null;
    return s;
  } catch {
    return null;
  }
}

export interface WatcherHealth {
  /** ok: scanned recently. stale: the daemon stopped scanning. never: no scan yet. */
  freshness: "ok" | "stale" | "never";
  status: WatcherStatus | null;
  ageMs: number | null;
}

/** Pure check over the persisted status. A dead daemon shows up as `stale`. */
export function watcherHealth(now: number = Date.now(), status = readWatcherStatus()): WatcherHealth {
  if (!status || status.last_scan_at == null) return { freshness: "never", status, ageMs: null };
  const ageMs = Math.max(0, now - status.last_scan_at);
  return { freshness: ageMs > WATCHER_STALE_AFTER_MS ? "stale" : "ok", status, ageMs };
}

function errCode(err: unknown): string {
  return (err as NodeJS.ErrnoException)?.code ?? "UNKNOWN";
}

function isPermissionError(err: unknown): boolean {
  const c = errCode(err);
  return c === "EACCES" || c === "EPERM";
}

interface ToolUseSighting {
  id: string;
  name: string;
  sessionId: string;
  ts: number | null;
}

/** Pull tool_use blocks out of one transcript line. Malformed input yields []. */
export function extractToolUses(line: string, fallbackSessionId: string): ToolUseSighting[] | null {
  let obj: unknown;
  try {
    obj = JSON.parse(line);
  } catch {
    return null;
  }
  if (!obj || typeof obj !== "object") return null;
  const rec = obj as Record<string, unknown>;
  if (rec.type !== "assistant") return [];
  const msg = rec.message;
  if (!msg || typeof msg !== "object") return [];
  const content = (msg as Record<string, unknown>).content;
  if (!Array.isArray(content)) return [];
  const sessionId =
    typeof rec.sessionId === "string" && rec.sessionId.length > 0 && rec.sessionId.length <= 128
      ? rec.sessionId
      : fallbackSessionId;
  let ts: number | null = null;
  if (typeof rec.timestamp === "string") {
    const t = Date.parse(rec.timestamp);
    ts = Number.isFinite(t) ? t : null;
  }
  const out: ToolUseSighting[] = [];
  for (const block of content) {
    if (!block || typeof block !== "object") continue;
    const b = block as Record<string, unknown>;
    if (b.type !== "tool_use") continue;
    if (typeof b.id !== "string" || b.id.length === 0 || b.id.length > 128) continue;
    const name = typeof b.name === "string" && b.name.length > 0 ? b.name.slice(0, 128) : "unknown";
    out.push({ id: b.id, name, sessionId, ts });
  }
  return out;
}

const sha = (b: Buffer) => createHash("sha256").update(b).digest("hex");

export class TranscriptWatcher {
  private readonly opts: Required<Omit<TranscriptWatcherOptions, "projectsDir">> & { projectsDir: string };
  private firstScanDone = false;
  private errors: WatcherErrors = { permission_denied: 0, rotated_or_truncated: 0, unreadable: 0 };

  constructor(opts: TranscriptWatcherOptions = {}) {
    this.opts = {
      projectsDir: opts.projectsDir ?? defaultProjectsDir(),
      graceMs: opts.graceMs ?? DEFAULT_GRACE_MS,
      now: opts.now ?? Date.now,
      io: opts.io ?? realIo,
      isPaused: opts.isPaused ?? (() => false),
      hooksExpected: opts.hooksExpected ?? (() => true),
      enabled: opts.enabled ?? (() => transcriptWatchEnabled()),
    };
  }

  /** One pass: discover, tail, resolve. Never throws. Returns the persisted status. */
  scan(): WatcherStatus {
    const now = this.opts.now();
    let status: WatcherStatus;
    try {
      status = this.scanInner(now);
    } catch (err) {
      this.errors.unreadable += 1;
      status = {
        state: "error",
        files_watched: 0,
        last_scan_at: now,
        errors: { ...this.errors },
        reason: `scan failed: ${errCode(err)}`,
      };
    }
    try {
      setMeta(META_WATCHER_STATE, JSON.stringify(status));
    } catch {
      // The db may be locked. The next scan writes it again.
    }
    return status;
  }

  private scanInner(now: number): WatcherStatus {
    if (!this.opts.enabled()) {
      return this.status("disabled", 0, now, "AGENTREEL_TRANSCRIPT_WATCH is off");
    }
    const db = getDb();
    ensureSchema(db);

    const paused = this.opts.isPaused();
    const expected = this.opts.hooksExpected();
    // While paused, or while no hooks are expected, the hooks record nothing on
    // purpose. Move to the end of every file so none of that is judged later.
    const silent = paused || !expected;

    const found = this.discover();
    if (found.rootError) {
      return this.status("error", 0, now, found.rootError);
    }
    const files = found.files;
    const seenPaths = new Set<string>();
    for (const path of files) {
      seenPaths.add(path);
      this.tailFile(db, path, now, silent);
    }
    // Forget state for files that vanished (deleted or rotated away).
    const known = db.prepare(`SELECT path FROM transcript_files`).all() as Array<{ path: string }>;
    const del = db.prepare(`DELETE FROM transcript_files WHERE path = ?`);
    for (const k of known) {
      if (!seenPaths.has(k.path) && found.complete) {
        del.run(k.path);
        this.errors.rotated_or_truncated += 1;
      }
    }
    this.firstScanDone = true;

    this.resolve(db, now, silent);
    this.prune(db, now);

    if (paused) return this.status("idle", files.length, now, "capture is paused");
    if (!expected) return this.status("idle", files.length, now, "hooks are not installed");
    return this.status("running", files.length, now);
  }

  private status(state: WatcherState, files: number, now: number, reason?: string): WatcherStatus {
    return {
      state,
      files_watched: files,
      last_scan_at: now,
      errors: { ...this.errors },
      ...(reason ? { reason } : {}),
    };
  }

  private discover(): { files: string[]; complete: boolean; rootError?: string } {
    const io = this.opts.io;
    const out: string[] = [];
    let complete = true;
    const walk = (dir: string, depth: number, isRoot: boolean): string | undefined => {
      let entries;
      try {
        entries = io.readdir(dir);
      } catch (err) {
        const code = errCode(err);
        if (code === "ENOENT" || code === "ENOTDIR") {
          // No Claude Code projects dir yet is normal, not an error.
          if (!isRoot) complete = false;
          return undefined;
        }
        complete = false;
        if (isPermissionError(err)) this.errors.permission_denied += 1;
        else this.errors.unreadable += 1;
        return isRoot ? `projects dir unreadable (${code})` : undefined;
      }
      for (const e of entries) {
        if (e.isSymlink) continue; // never follow links out of the projects dir
        const p = join(dir, e.name);
        if (e.isDir && depth < MAX_DEPTH) walk(p, depth + 1, false);
        else if (e.isFile && e.name.endsWith(".jsonl")) {
          if (out.length >= MAX_FILES) {
            complete = false;
            return undefined;
          }
          out.push(p);
        }
      }
      return undefined;
    };
    const rootError = walk(this.opts.projectsDir, 0, true);
    return { files: out, complete, rootError };
  }

  private tailFile(db: DB, path: string, now: number, silent: boolean): void {
    const io = this.opts.io;
    let st: Pick<Stats, "size" | "ino" | "mtimeMs">;
    try {
      st = io.stat(path);
    } catch (err) {
      // Deleted between discover and stat, or unreadable.
      if (isPermissionError(err)) this.errors.permission_denied += 1;
      else if (errCode(err) !== "ENOENT") this.errors.unreadable += 1;
      return;
    }
    const ino = String(st.ino);
    const row = db.prepare(`SELECT ino, offset, head_sha FROM transcript_files WHERE path = ?`).get(path) as
      | { ino: string; offset: number; head_sha: string | null }
      | undefined;

    let offset: number;
    if (!row) {
      // The very first scan of the daemon does not judge history. A file that
      // appears later is new, so read it from the start.
      offset = this.firstScanDone ? 0 : st.size;
    } else {
      offset = row.offset;
      let replaced = row.ino !== ino || st.size < offset;
      if (!replaced && offset > 0 && row.head_sha) {
        try {
          const head = io.read(path, 0, Math.min(HEAD_BYTES, offset));
          if (sha(head) !== row.head_sha) replaced = true;
        } catch (err) {
          if (isPermissionError(err)) this.errors.permission_denied += 1;
          else this.errors.unreadable += 1;
          return;
        }
      }
      if (replaced) {
        this.errors.rotated_or_truncated += 1;
        offset = 0;
      }
    }

    if (silent) {
      this.saveFile(db, path, ino, st.size, io, now);
      return;
    }
    if (offset >= st.size) {
      this.saveFile(db, path, ino, offset, io, now);
      return;
    }

    const want = Math.min(st.size - offset, MAX_READ_BYTES_PER_FILE);
    let chunk: Buffer;
    try {
      chunk = io.read(path, offset, want);
    } catch (err) {
      if (isPermissionError(err)) this.errors.permission_denied += 1;
      else if (errCode(err) !== "ENOENT") this.errors.unreadable += 1;
      return;
    }
    const lastNl = chunk.lastIndexOf(0x0a);
    let consumed: number;
    if (lastNl === -1) {
      // No complete line yet. If the chunk is already huge, skip it so a
      // newline-free file cannot stall the watcher forever.
      if (chunk.length >= MAX_LINE_BYTES || chunk.length === MAX_READ_BYTES_PER_FILE) {
        this.errors.unreadable += 1;
        consumed = chunk.length;
      } else {
        this.saveFile(db, path, ino, offset, io, now);
        return;
      }
    } else {
      consumed = lastNl + 1;
      const text = chunk.subarray(0, consumed).toString("utf8");
      const fallbackSession = basename(path, ".jsonl");
      const insert = db.prepare(
        `INSERT OR IGNORE INTO transcript_tool_uses
           (tool_use_id, session_id, tool_name, transcript_ts, first_seen_at, status)
         VALUES (?, ?, ?, ?, ?, 'pending')`,
      );
      let added = 0;
      db.transaction(() => {
        for (const line of text.split("\n")) {
          if (!line) continue;
          if (line.length > MAX_LINE_BYTES) {
            this.errors.unreadable += 1;
            continue;
          }
          const uses = extractToolUses(line, fallbackSession);
          if (uses === null) continue; // malformed line, not an error
          for (const u of uses) {
            added += insert.run(u.id, u.sessionId, u.name, u.ts, now).changes;
          }
        }
      })();
      if (added > 0) {
        const t = readTotals();
        t.tool_uses_seen += added;
        writeTotals(t);
      }
    }
    this.saveFile(db, path, ino, offset + consumed, io, now);
  }

  private saveFile(db: DB, path: string, ino: string, offset: number, io: WatcherIo, now: number): void {
    let headSha: string | null = null;
    if (offset > 0) {
      try {
        headSha = sha(io.read(path, 0, Math.min(HEAD_BYTES, offset)));
      } catch {
        headSha = null;
      }
    }
    db.prepare(
      `INSERT INTO transcript_files (path, ino, offset, head_sha, seen_at) VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(path) DO UPDATE SET ino = excluded.ino, offset = excluded.offset,
         head_sha = excluded.head_sha, seen_at = excluded.seen_at`,
    ).run(path, ino, offset, headSha, now);
  }

  /** Decide pending tool calls whose grace period is over. */
  private resolve(db: DB, now: number, silent: boolean): void {
    const due = db
      .prepare(
        `SELECT tool_use_id FROM transcript_tool_uses
         WHERE status = 'pending' AND first_seen_at <= ? ORDER BY first_seen_at LIMIT 5000`,
      )
      .all(now - this.opts.graceMs) as Array<{ tool_use_id: string }>;
    if (due.length === 0) return;
    const hasEvent = db.prepare(
      `SELECT 1 FROM events WHERE type = 'tool_use_pre' AND json_extract(payload, '$.tool_use_id') = ? LIMIT 1`,
    );
    const mark = db.prepare(
      `UPDATE transcript_tool_uses SET status = ?, resolved_at = ? WHERE tool_use_id = ?`,
    );
    let gaps = 0;
    db.transaction(() => {
      for (const d of due) {
        if (silent) {
          mark.run("skipped", now, d.tool_use_id);
        } else if (hasEvent.get(d.tool_use_id)) {
          mark.run("matched", now, d.tool_use_id);
        } else {
          mark.run("gap", now, d.tool_use_id);
          gaps += 1;
        }
      }
    })();
    if (gaps > 0) {
      const t = readTotals();
      t.hook_gaps_total += gaps;
      writeTotals(t);
    }
  }

  private prune(db: DB, now: number): void {
    db.prepare(`DELETE FROM transcript_tool_uses WHERE status IN ('matched','skipped') AND resolved_at < ?`).run(
      now - MATCHED_TTL_MS,
    );
    db.prepare(`DELETE FROM transcript_tool_uses WHERE status = 'gap' AND reported_at IS NOT NULL AND reported_at < ?`).run(
      now - REPORTED_GAP_TTL_MS,
    );
    db.prepare(
      `DELETE FROM transcript_tool_uses WHERE status = 'gap' AND tool_use_id IN (
         SELECT tool_use_id FROM transcript_tool_uses WHERE status = 'gap'
         ORDER BY resolved_at DESC LIMIT -1 OFFSET ?)`,
    ).run(MAX_GAP_ROWS);
  }
}

/** Gaps not yet acknowledged by the server, oldest first. */
export function listUnreportedGaps(limit = 50): HookGapRow[] {
  const db = getDb();
  ensureSchema(db);
  const rows = db
    .prepare(
      `SELECT tool_use_id, session_id, tool_name, transcript_ts, resolved_at
       FROM transcript_tool_uses WHERE status = 'gap' AND reported_at IS NULL
       ORDER BY resolved_at, tool_use_id LIMIT ?`,
    )
    .all(limit) as Array<{
    tool_use_id: string;
    session_id: string;
    tool_name: string;
    transcript_ts: number | null;
    resolved_at: number;
  }>;
  return rows.map((r) => ({
    tool_use_id: r.tool_use_id,
    session_id: r.session_id,
    tool_name: r.tool_name,
    source: "claude-code" as const,
    transcript_ts: r.transcript_ts,
    detected_at: r.resolved_at,
  }));
}

export function countUnreportedGaps(): number {
  const db = getDb();
  ensureSchema(db);
  return (
    db.prepare(`SELECT COUNT(*) AS c FROM transcript_tool_uses WHERE status = 'gap' AND reported_at IS NULL`).get() as {
      c: number;
    }
  ).c;
}

export function markGapsReported(ids: string[], now: number = Date.now()): void {
  if (ids.length === 0) return;
  const db = getDb();
  ensureSchema(db);
  const stmt = db.prepare(`UPDATE transcript_tool_uses SET reported_at = ? WHERE tool_use_id = ? AND status = 'gap'`);
  db.transaction((xs: string[]) => {
    for (const id of xs) stmt.run(now, id);
  })(ids);
}
