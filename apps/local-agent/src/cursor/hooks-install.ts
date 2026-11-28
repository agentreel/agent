import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { cursorHooksPath } from "../paths.js";
import {
  DEFAULT_HOOK_TIMEOUT_S,
  DEFAULT_PRE_EXEC_HOOK_TIMEOUT_S,
} from "../policy/types.js";
import {
  CURSOR_HOOK_EVENTS,
  CURSOR_HOOK_SUBCOMMAND,
  CURSOR_PRE_EXEC_HOOK_EVENTS,
  isCursorPreExecHook,
} from "./hook-normalize.js";

interface CursorHookDef {
  command: string;
  timeout?: number;
  [k: string]: unknown;
}
interface CursorHooksFile {
  version?: number;
  hooks?: Record<string, CursorHookDef[]>;
  [k: string]: unknown;
}

const isOurs = (d: CursorHookDef) => typeof d?.command === "string" && d.command.includes(` ${CURSOR_HOOK_SUBCOMMAND} `);

function read(path: string): CursorHooksFile {
  if (!existsSync(path)) return {};
  const raw = readFileSync(path, "utf8");
  return raw.trim() ? (JSON.parse(raw) as CursorHooksFile) : {};
}

function backup(path: string): string | null {
  if (!existsSync(path)) return null;
  const b = `${path}.agentreel-backup-${new Date().toISOString().replace(/[:.]/g, "-")}`;
  copyFileSync(path, b);
  return b;
}

export function cursorHookTimeoutForEvent(
  event: string,
  preExecTimeoutS: number = DEFAULT_PRE_EXEC_HOOK_TIMEOUT_S,
): number {
  return isCursorPreExecHook(event) ? preExecTimeoutS : DEFAULT_HOOK_TIMEOUT_S;
}

export interface InstallCursorHooksOptions {
  preExecTimeoutS?: number;
  /** System (enterprise) hooks file to check first; injectable for tests. */
  systemHooksPath?: string;
}

/**
 * Cursor's enterprise hooks file, written by `agentreel managed install` (or
 * MDM). Hooks there run for every user and rank above user hooks.
 */
export function systemCursorHooksPath(platform: NodeJS.Platform = process.platform): string {
  if (platform === "darwin") return "/Library/Application Support/Cursor/hooks.json";
  if (platform === "win32") return "C:\\ProgramData\\Cursor\\hooks.json";
  return "/etc/cursor/hooks.json";
}

/** True when the system hooks file already carries AgentReel entries. Never throws. */
export function systemCursorHooksOwnedByAgentreel(path: string = systemCursorHooksPath()): boolean {
  try {
    const file = read(path);
    return Object.values(file.hooks ?? {}).some((defs) => Array.isArray(defs) && defs.some(isOurs));
  } catch {
    return false;
  }
}

export type InstallCursorHooksResult =
  | { skipped: false; backup: string | null; installedEvents: string[]; path: string; preExecTimeoutS: number }
  /** The managed pack owns the Cursor hooks; nothing was written (avoids double capture). */
  | { skipped: true; managedPath: string; installedEvents: []; path: string; preExecTimeoutS: number };

/**
 * Add `<prefix> cursor-hook <event>` to ~/.cursor/hooks.json for every hook.
 * Pre-exec hooks receive the longer approval timeout (in seconds); other hooks
 * keep the default 5s timeout. Re-running replaces our previous entries idempotently.
 */
export function installCursorHooks(
  prefix: string,
  path = cursorHooksPath(),
  opts: InstallCursorHooksOptions = {},
): InstallCursorHooksResult {
  const preExecTimeoutS = opts.preExecTimeoutS ?? DEFAULT_PRE_EXEC_HOOK_TIMEOUT_S;
  const managedPath = opts.systemHooksPath ?? systemCursorHooksPath();
  if (systemCursorHooksOwnedByAgentreel(managedPath)) {
    return { skipped: true, managedPath, installedEvents: [], path, preExecTimeoutS };
  }
  mkdirSync(dirname(path), { recursive: true });
  const b = backup(path);
  const file = read(path);
  file.version ??= 1;
  file.hooks ??= {};
  for (const ev of CURSOR_HOOK_EVENTS) {
    const kept = (file.hooks[ev] ?? []).filter((d) => !isOurs(d));
    kept.push({
      command: `${prefix} ${CURSOR_HOOK_SUBCOMMAND} ${ev}`,
      timeout: cursorHookTimeoutForEvent(ev, preExecTimeoutS),
      // Pre-exec hooks only: a crash, timeout or missing binary denies the
      // action instead of allowing it (Cursor defaults to fail-open).
      ...(isCursorPreExecHook(ev) ? { failClosed: true } : {}),
    });
    file.hooks[ev] = kept;
  }
  writeFileSync(path, JSON.stringify(file, null, 2) + "\n", "utf8");
  return { skipped: false, backup: b, installedEvents: [...CURSOR_HOOK_EVENTS], path, preExecTimeoutS };
}

export function uninstallCursorHooks(path = cursorHooksPath()): { backup: string | null; removed: number } {
  if (!existsSync(path)) return { backup: null, removed: 0 };
  const b = backup(path);
  const file = read(path);
  let removed = 0;
  for (const ev of Object.keys(file.hooks ?? {})) {
    const before = file.hooks![ev]!;
    const kept = before.filter((d) => !isOurs(d));
    removed += before.length - kept.length;
    if (kept.length === 0) delete file.hooks![ev];
    else file.hooks![ev] = kept;
  }
  writeFileSync(path, JSON.stringify(file, null, 2) + "\n", "utf8");
  return { backup: b, removed };
}

export interface CursorPreExecHookEntryStatus {
  event: string;
  installed: boolean;
  timeoutS: number | null;
  /** True when our entry has failClosed: true. */
  failClosed: boolean;
}

export interface CursorPreExecHooksCheck {
  fileExists: boolean;
  hooks: CursorPreExecHookEntryStatus[];
}

export function inspectCursorPreExecHooks(
  path: string = cursorHooksPath(),
): CursorPreExecHooksCheck {
  if (!existsSync(path)) {
    return {
      fileExists: false,
      hooks: CURSOR_PRE_EXEC_HOOK_EVENTS.map((event) => ({
        event,
        installed: false,
        timeoutS: null,
        failClosed: false,
      })),
    };
  }
  try {
    const file = read(path);
    const hooks = CURSOR_PRE_EXEC_HOOK_EVENTS.map((event) => {
      const entry = (file.hooks?.[event] ?? []).find(isOurs);
      return {
        event,
        installed: Boolean(entry),
        timeoutS:
          entry && typeof entry.timeout === "number" && Number.isFinite(entry.timeout)
            ? entry.timeout
            : null,
        failClosed: entry?.failClosed === true,
      };
    });
    return { fileExists: true, hooks };
  } catch {
    return {
      fileExists: true,
      hooks: CURSOR_PRE_EXEC_HOOK_EVENTS.map((event) => ({
        event,
        installed: false,
        timeoutS: null,
        failClosed: false,
      })),
    };
  }
}
