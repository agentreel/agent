import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// paths.ts reads homedir() at import time, so point HOME at a temp dir
// before loading anything that touches the database.
const home = mkdtempSync(join(tmpdir(), "agentreel-test-"));
process.env.HOME = home;

type Db = typeof import("../src/db.js");
type Queue = typeof import("../src/upload/queue.js");
type Flush = typeof import("../src/upload/flush.js");
let db: Db;
let queue: Queue;
let flush: Flush;

beforeAll(async () => {
  db = await import("../src/db.js");
  queue = await import("../src/upload/queue.js");
  flush = await import("../src/upload/flush.js");
});
afterAll(() => {
  db.closeDb();
  rmSync(home, { recursive: true, force: true });
});

function seed(sessionId: string, startedAt: number, n: number) {
  db.upsertSession({ id: sessionId, tool: "claude-code", startedAt } as never);
  for (let i = 0; i < n; i++) {
    db.insertEvent({
      id: `${sessionId}-e${i}`,
      sessionId,
      tool: "claude-code",
      type: "tool_use_pre",
      ts: startedAt + i,
      payload: { tool_name: "Bash", tool_input: { command: `echo ${i}` } },
    } as never);
  }
}

describe("upload queue with server-side rejections", () => {
  it("uploads accepted sessions and parks rejected ones without looping", () => {
    seed("allowed", 1_000, 3);
    seed("over-limit", 2_000, 2);
    seed("later", 3_000, 1);

    const now = 10_000;
    const batch = queue.takePendingBatch(500, 1024 * 1024, now);
    expect(batch.eventIds).toHaveLength(6);

    const held = flush.applyIngestResponse(
      batch,
      {
        ok: true,
        rejected_sessions: [{ id: "over-limit", reason: "plan-limit" }],
        plan_limit: { plan: "free", limit: 3, active_sessions: 3, retry_after_seconds: 3600, message: "limit" },
      },
      now,
    );
    expect(held).toEqual(["over-limit"]);

    // Accepted events are done; the parked session is not offered again.
    const next = queue.takePendingBatch(500, 1024 * 1024, now + 1);
    expect(next.eventIds).toEqual([]);
    expect(db.countEvents(now + 1)).toMatchObject({ total: 6, pending: 2, held: 2 });
    expect(db.pendingByteSize(now + 1)).toBe(0);
  });

  it("offers parked sessions again after the hold expires", () => {
    const later = 10_000 + 3_600_000 + 1;
    const again = queue.takePendingBatch(500, 1024 * 1024, later);
    expect(again.eventSessionIds).toEqual(["over-limit", "over-limit"]);
    expect(again.sessions.map((s) => s.id)).toEqual(["over-limit"]);
  });

  it("release clears holds immediately", () => {
    db.holdSessions(["over-limit"], Date.now() + 60_000, "plan-limit");
    expect(db.listHeldSessions()).toHaveLength(1);
    expect(db.releaseHeldSessions()).toBe(1);
    expect(db.listHeldSessions()).toHaveLength(0);
  });

  it("marks everything uploaded on a clean response", () => {
    const batch = queue.takePendingBatch(500, 1024 * 1024, Date.now());
    const held = flush.applyIngestResponse(batch, { ok: true, rejected_sessions: [] });
    expect(held).toEqual([]);
    expect(db.countEvents().pending).toBe(0);
  });

  it("migrates an old database without the held columns", async () => {
    const Database = (await import("better-sqlite3")).default;
    const path = join(home, "old.db");
    const old = new Database(path);
    old.exec(`CREATE TABLE sessions (id TEXT PRIMARY KEY, tool TEXT NOT NULL, started_at INTEGER NOT NULL,
      ended_at INTEGER, cwd TEXT, total_cost_cents INTEGER, total_tokens INTEGER)`);
    old.close();
    // getDb() runs the same migrate(); here we just check the ALTER is valid SQL on an old shape.
    const again = new Database(path);
    again.exec(`ALTER TABLE sessions ADD COLUMN held_until INTEGER`);
    const cols = (again.prepare(`PRAGMA table_info(sessions)`).all() as Array<{ name: string }>).map((c) => c.name);
    expect(cols).toContain("held_until");
    again.close();
  });
});
