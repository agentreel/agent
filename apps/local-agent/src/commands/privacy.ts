import pc from "picocolors";
import { createInterface } from "node:readline";
import { readConfig, writeConfig } from "../config.js";
import { getDb } from "../db.js";

export function pauseCommand(): void {
  const cfg = readConfig();
  if (cfg.paused) {
    console.log(pc.dim("· already paused"));
    if (cfg.pausedAt) {
      console.log(pc.dim(`  since ${new Date(cfg.pausedAt).toLocaleString()}`));
    }
    return;
  }
  cfg.paused = true;
  cfg.pausedAt = Date.now();
  writeConfig(cfg);
  console.log(pc.yellow("⏸  capture paused"));
  console.log(
    pc.dim(
      "  Claude Code hooks and the Cursor watcher will no-op until you " +
        pc.cyan("agentreel resume") +
        pc.dim("."),
    ),
  );
  console.log(
    pc.dim(
      "  Existing local events stay put. They won't upload while paused (the daemon still runs, but the queue won't grow).",
    ),
  );
}

export function resumeCommand(): void {
  const cfg = readConfig();
  if (!cfg.paused) {
    console.log(pc.dim("· capture is already active"));
    return;
  }
  const pausedAt = cfg.pausedAt;
  cfg.paused = false;
  cfg.pausedAt = undefined;
  writeConfig(cfg);
  const duration = pausedAt ? fmtDuration(Date.now() - pausedAt) : null;
  console.log(pc.green("▶  capture resumed"));
  if (duration) {
    console.log(pc.dim(`  paused for ${duration}`));
  }
}

interface ForgetOpts {
  all?: boolean;
  force?: boolean;
}

/**
 * Delete captured sessions + events from the local SQLite buffer.
 * Without --all, requires session ids. The ON DELETE CASCADE on events
 * (events.session_id FK) means deleting a session row drops its events
 * automatically.
 */
export async function forgetCommand(
  ids: string[],
  opts: ForgetOpts,
): Promise<void> {
  const db = getDb();

  if (opts.all) {
    const total = (db.prepare(`SELECT COUNT(*) AS c FROM sessions`).get() as {
      c: number;
    }).c;
    if (total === 0) {
      console.log(pc.dim("· nothing to forget — local DB is empty"));
      return;
    }
    if (!opts.force && !(await confirm(`Delete all ${total} local sessions? `))) {
      console.log(pc.dim("· cancelled"));
      return;
    }
    db.transaction(() => {
      db.exec(`DELETE FROM events`);
      db.exec(`DELETE FROM sessions`);
      // Cost/offset meta keyed by session_id is now orphaned — wipe it too.
      db.exec(`DELETE FROM meta WHERE key LIKE 'cost_%'`);
    })();
    console.log(pc.green("✓") + ` forgot ${total} sessions and their events`);
    console.log(
      pc.dim(
        "  Cloud-side rows are untouched. Delete them from the dashboard if you also want them gone from agentreel.dev.",
      ),
    );
    return;
  }

  if (ids.length === 0) {
    console.error(
      pc.red("✗ provide one or more session ids, or --all to wipe everything"),
    );
    console.error(pc.dim(`  example: agentreel forget abcd1234`));
    process.exit(1);
  }

  // Allow short-id prefix matching for convenience (`agentreel forget ef194acc`).
  const stmt = db.prepare(
    `SELECT id FROM sessions WHERE id = ? OR id LIKE ?`,
  );
  const delEvents = db.prepare(`DELETE FROM events WHERE session_id = ?`);
  const delSession = db.prepare(`DELETE FROM sessions WHERE id = ?`);
  const delMeta = db.prepare(`DELETE FROM meta WHERE key LIKE ?`);

  const matched: string[] = [];
  for (const raw of ids) {
    const rows = stmt.all(raw, `${raw}%`) as Array<{ id: string }>;
    if (rows.length === 0) {
      console.error(pc.yellow(`· no session matched "${raw}"`));
      continue;
    }
    for (const r of rows) matched.push(r.id);
  }
  if (matched.length === 0) {
    console.error(pc.red("✗ nothing matched, nothing deleted"));
    process.exit(1);
  }
  if (!opts.force && !(await confirm(`Delete ${matched.length} session(s) and their events? `))) {
    console.log(pc.dim("· cancelled"));
    return;
  }
  db.transaction(() => {
    for (const id of matched) {
      delEvents.run(id);
      delSession.run(id);
      delMeta.run(`cost_%:${id}`);
    }
  })();
  console.log(pc.green("✓") + ` forgot ${matched.length} session(s)`);
}

function confirm(prompt: string): Promise<boolean> {
  return new Promise((resolve) => {
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    rl.question(prompt + "[y/N] ", (answer) => {
      rl.close();
      resolve(/^y(es)?$/i.test(answer.trim()));
    });
  });
}

function fmtDuration(ms: number): string {
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ${m % 60}m`;
  const d = Math.floor(h / 24);
  return `${d}d ${h % 24}h`;
}
