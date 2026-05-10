import pc from "picocolors";
import { spawn } from "node:child_process";
import {
  existsSync,
  openSync,
  readFileSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import {
  DAEMON_LOG_PATH,
  DAEMON_PID_PATH,
  ensureAgentreelDir,
} from "../paths.js";
import { pendingByteSize } from "../db.js";
import { flushOnce, nextAttemptAt } from "../upload/flush.js";
import { MAX_BATCH_BYTES } from "../upload/queue.js";
import { IngestError } from "../upload/client.js";
import { readConfig } from "../config.js";

const TICK_INTERVAL_MS = 30_000;
const EARLY_FLUSH_BYTES = MAX_BATCH_BYTES; // flush early once pending crosses 1 MB

export interface DaemonOpts {
  detach?: boolean;
}

export async function daemonCommand(opts: DaemonOpts = {}): Promise<void> {
  const cfg = readConfig();
  if (!cfg.apiKey) {
    console.error(pc.red("✗ Not linked. Run ") + pc.cyan("agentreel link <api-key>"));
    process.exit(1);
  }

  if (opts.detach) {
    spawnDetached();
    return;
  }

  if (!claimPidFile()) {
    process.exit(1);
  }

  const release = () => {
    try {
      unlinkSync(DAEMON_PID_PATH);
    } catch {
      /* ignore */
    }
  };

  let stopping = false;
  const stop = () => {
    if (stopping) return;
    stopping = true;
    console.log(pc.dim("\n  daemon stopping…"));
    release();
    process.exit(0);
  };
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
  process.on("beforeExit", release);

  console.log(pc.green("●") + " agentreel daemon running");
  console.log(pc.dim(`  api: ${cfg.apiBaseUrl}`));
  console.log(pc.dim(`  tick: every ${TICK_INTERVAL_MS / 1000}s, early flush at ${(EARLY_FLUSH_BYTES / 1024).toFixed(0)} KB`));
  console.log(pc.dim("  Ctrl-C to stop"));

  // Loop until killed. Each iteration:
  //   1. honor backoff (next_attempt_at) before doing anything
  //   2. drain the queue in batches as long as moreAvailable
  //   3. sleep up to 30s, but wake early if pending bytes cross 1 MB
  for (;;) {
    if (stopping) return;

    // Backoff: if a prior failure scheduled a retry in the future, wait.
    const nextAt = nextAttemptAt();
    const now = Date.now();
    if (nextAt > now) {
      await sleepInterruptible(nextAt - now, () => stopping);
      continue;
    }

    // Drain.
    try {
      for (;;) {
        const res = await flushOnce();
        if (res.uploadedEvents > 0) {
          console.log(
            pc.dim(`  [${ts()}]`) +
              pc.green(" ✓") +
              ` ${res.uploadedEvents} events · ${res.uploadedSessions} sessions`,
          );
        }
        if (!res.moreAvailable) break;
      }
    } catch (err) {
      const e = err as Error;
      if (err instanceof IngestError && err.isPermanent) {
        console.error(
          pc.dim(`  [${ts()}]`) + pc.red(" ✗ ") + e.message + pc.dim(" (5min backoff)"),
        );
      } else {
        console.error(pc.dim(`  [${ts()}]`) + pc.yellow(" · ") + e.message);
      }
      // flushOnce already recorded the backoff window.
    }

    // Wait for the next tick, but wake early if the queue hits 1 MB.
    await waitForTickOrPressure(TICK_INTERVAL_MS, EARLY_FLUSH_BYTES, () => stopping);
  }
}

function claimPidFile(): boolean {
  ensureAgentreelDir();
  if (existsSync(DAEMON_PID_PATH)) {
    const raw = readFileSync(DAEMON_PID_PATH, "utf8").trim();
    const pid = Number(raw);
    if (Number.isFinite(pid) && pid > 0 && isAlive(pid)) {
      console.error(pc.red(`✗ daemon already running (pid ${pid})`));
      console.error(pc.dim(`  if this is wrong, remove ${DAEMON_PID_PATH}`));
      return false;
    }
    // Stale pid file — overwrite.
  }
  writeFileSync(DAEMON_PID_PATH, String(process.pid), { encoding: "utf8", mode: 0o600 });
  return true;
}

function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function sleepInterruptible(ms: number, shouldStop: () => boolean): Promise<void> {
  return new Promise((resolve) => {
    if (ms <= 0) return resolve();
    const start = Date.now();
    const t = setInterval(() => {
      if (shouldStop() || Date.now() - start >= ms) {
        clearInterval(t);
        resolve();
      }
    }, 250);
  });
}

function spawnDetached(): void {
  ensureAgentreelDir();
  // If a live pid is already on disk, refuse — we'd just hit the same
  // claimPidFile check from inside the child and lose stderr to the log.
  if (existsSync(DAEMON_PID_PATH)) {
    const raw = readFileSync(DAEMON_PID_PATH, "utf8").trim();
    const pid = Number(raw);
    if (Number.isFinite(pid) && pid > 0 && isAlive(pid)) {
      console.error(pc.red(`✗ daemon already running (pid ${pid})`));
      console.error(pc.dim("  use ") + pc.cyan("agentreel stop") + pc.dim(" first"));
      process.exit(1);
    }
  }

  // Open the log in append mode so child stdout/stderr persist across
  // restarts. argv[0] is the same node binary; pass `daemon` (no
  // --detach) so the child runs the foreground loop.
  const out = openSync(DAEMON_LOG_PATH, "a");
  const err = openSync(DAEMON_LOG_PATH, "a");
  const child = spawn(process.execPath, [process.argv[1]!, "daemon"], {
    detached: true,
    stdio: ["ignore", out, err],
    env: process.env,
  });
  // Don't keep the parent alive waiting on the child; let it become
  // an orphan adopted by init. Releasing the IPC handle is necessary
  // even though we passed `ignore` — defensive.
  child.unref();
  console.log(pc.green("●") + ` daemon started (pid ${child.pid})`);
  console.log(pc.dim(`  log: ${DAEMON_LOG_PATH}`));
  console.log(pc.dim(`  stop: agentreel stop`));
}

export function stopCommand(): void {
  if (!existsSync(DAEMON_PID_PATH)) {
    console.log(pc.dim("· daemon not running"));
    return;
  }
  const raw = readFileSync(DAEMON_PID_PATH, "utf8").trim();
  const pid = Number(raw);
  if (!Number.isFinite(pid) || pid <= 0) {
    try {
      unlinkSync(DAEMON_PID_PATH);
    } catch {
      /* ignore */
    }
    console.log(pc.dim("· cleared stale pid file"));
    return;
  }
  if (!isAlive(pid)) {
    try {
      unlinkSync(DAEMON_PID_PATH);
    } catch {
      /* ignore */
    }
    console.log(pc.dim(`· no live daemon for pid ${pid} — cleared stale pid file`));
    return;
  }
  try {
    process.kill(pid, "SIGTERM");
    console.log(pc.green("✓") + ` sent SIGTERM to pid ${pid}`);
  } catch (err) {
    console.error(pc.red("✗ ") + (err as Error).message);
    process.exit(1);
  }
}

function waitForTickOrPressure(
  tickMs: number,
  pressureBytes: number,
  shouldStop: () => boolean,
): Promise<void> {
  return new Promise((resolve) => {
    const start = Date.now();
    const t = setInterval(() => {
      if (shouldStop()) {
        clearInterval(t);
        return resolve();
      }
      if (Date.now() - start >= tickMs) {
        clearInterval(t);
        return resolve();
      }
      // Pressure check: cheap COUNT/SUM query on the indexed pending column.
      try {
        if (pendingByteSize() >= pressureBytes) {
          clearInterval(t);
          return resolve();
        }
      } catch {
        // db locked / not initialized — let the tick handle it.
      }
    }, 1_000);
  });
}

function ts(): string {
  const d = new Date();
  return d.toTimeString().slice(0, 8);
}
