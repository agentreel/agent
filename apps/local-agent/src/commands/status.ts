import pc from "picocolors";
import { existsSync, readFileSync } from "node:fs";
import {
  CLAUDE_SETTINGS_PATH,
  DB_PATH,
  CONFIG_PATH,
  DAEMON_PID_PATH,
} from "../paths.js";
import { countEvents, getMeta, listRecentSessions, pendingByteSize } from "../db.js";
import { readConfig } from "../config.js";
import {
  META_LAST_ERROR_AT,
  META_LAST_ERROR_MSG,
  META_LAST_SYNC_AT,
  META_NEXT_ATTEMPT_AT,
  consecutiveFailures,
} from "../upload/flush.js";

function fmtDuration(ms: number): string {
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

function fmtAgo(ms: number): string {
  return fmtDuration(Date.now() - ms) + " ago";
}

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

function daemonStatus(): { running: boolean; pid: number | null } {
  if (!existsSync(DAEMON_PID_PATH)) return { running: false, pid: null };
  try {
    const pid = Number(readFileSync(DAEMON_PID_PATH, "utf8").trim());
    if (!Number.isFinite(pid) || pid <= 0) return { running: false, pid: null };
    process.kill(pid, 0);
    return { running: true, pid };
  } catch {
    return { running: false, pid: null };
  }
}

export async function statusCommand(): Promise<void> {
  const cfg = readConfig();
  console.log(pc.bold(pc.cyan("AgentReel status\n")));
  console.log("  config:        " + (existsSync(CONFIG_PATH) ? CONFIG_PATH : pc.red("missing")));
  console.log("  database:      " + (existsSync(DB_PATH) ? DB_PATH : pc.red("not initialized")));
  console.log(
    "  claude hooks:  " +
      (existsSync(CLAUDE_SETTINGS_PATH) ? CLAUDE_SETTINGS_PATH : pc.red("not installed")),
  );
  console.log("  api base:      " + cfg.apiBaseUrl);
  console.log("  authenticated: " + (cfg.apiKey ? pc.green("yes") : pc.yellow("no")));

  const d = daemonStatus();
  console.log(
    "  daemon:        " +
      (d.running ? pc.green(`running (pid ${d.pid})`) : pc.dim("stopped")),
  );
  console.log();

  if (!existsSync(DB_PATH)) {
    console.log(pc.yellow("Run `agentreel init` to install hooks."));
    return;
  }

  const { total, pending } = countEvents();
  const pendingBytes = pendingByteSize();
  console.log(`  events captured:  ${total}`);
  console.log(`  pending upload:   ${pending}` + (pending > 0 ? pc.dim(` (${fmtBytes(pendingBytes)})`) : ""));

  const lastSync = numMeta(META_LAST_SYNC_AT);
  const lastErr = numMeta(META_LAST_ERROR_AT);
  const lastErrMsg = getMeta(META_LAST_ERROR_MSG);
  const fails = consecutiveFailures();
  const nextAt = numMeta(META_NEXT_ATTEMPT_AT);

  console.log(
    `  last sync:        ` +
      (lastSync ? pc.green(fmtAgo(lastSync)) : pc.dim("never")),
  );
  if (lastErr) {
    console.log(
      `  last error:       ` +
        pc.red(fmtAgo(lastErr)) +
        pc.dim(` · ${fails} consecutive`),
    );
    if (lastErrMsg) console.log(pc.dim(`    ${lastErrMsg}`));
    if (nextAt && nextAt > Date.now()) {
      console.log(
        pc.dim(`    next attempt in ${fmtDuration(nextAt - Date.now())}`),
      );
    }
  }
  console.log();

  const sessions = listRecentSessions(5);
  if (sessions.length === 0) {
    console.log(pc.dim("  no sessions yet — start a Claude Code session to capture one."));
    return;
  }
  console.log(pc.bold("recent sessions:"));
  for (const s of sessions) {
    const dur = s.ended_at ? fmtDuration(s.ended_at - s.started_at) : pc.dim("active");
    const ts = new Date(s.started_at).toLocaleString();
    console.log(`  ${pc.dim(s.id.slice(0, 8))}  ${s.tool.padEnd(11)}  ${ts}  ${dur}`);
  }
}

function numMeta(key: string): number | null {
  const v = getMeta(key);
  if (!v) return null;
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? n : null;
}
