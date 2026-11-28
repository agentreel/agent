import { copyFileSync, existsSync, lstatSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
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

export type SystemCursorHooksState = "absent" | "owned" | "not_owned" | "unreadable";

/**
 * Ownership of the system Cursor hooks file. Never throws.
 *
 * Fail-safe: if the file exists but cannot be read or parsed, the state is
 * `unreadable`, which is treated as managed. That way a permission error or
 * a truncated file cannot cause `agentreel init` to write a second copy of
 * the hooks under the user.
 */
export function inspectSystemCursorHooks(path: string = systemCursorHooksPath()): SystemCursorHooksState {
  try {
    if (!existsSync(path)) return "absent";
  } catch {
    return "unreadable";
  }
  try {
    const file = read(path);
    const owned = Object.values(file.hooks ?? {}).some(
      (defs) => Array.isArray(defs) && defs.some(isOurs),
    );
    return owned ? "owned" : "not_owned";
  } catch {
    return "unreadable";
  }
}

/** True when the system hooks file already carries AgentReel entries, or cannot be read. */
export function systemCursorHooksOwnedByAgentreel(path: string = systemCursorHooksPath()): boolean {
  const state = inspectSystemCursorHooks(path);
  return state === "owned" || state === "unreadable";
}

/**
 * The same rule as the managed installer's user-file cleanup
 * (`planCursorUserCleanup` in src/managed/install.ts): never write through a
 * symlink. If ~/.cursor or ~/.cursor/hooks.json is a symlink (for example to
 * the managed /etc/cursor/hooks.json), or the file is not a regular file,
 * the file is left alone. Returns the warning text, or null when it is safe
 * to edit or there is nothing there.
 */
function refuseUnsafeUserHooksFile(path: string): string | null {
  try {
    const dirIsLink = lstatSync(dirname(path)).isSymbolicLink();
    let fileState: "absent" | "regular" | "other" = "absent";
    try {
      fileState = lstatSync(path).isFile() ? "regular" : "other";
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") fileState = "other";
    }
    if (fileState === "absent" && !dirIsLink) return null;
    if (!dirIsLink && fileState === "regular") return null;
    if (dirIsLink && fileState === "absent") return null;
    return `${path} or its directory is a symlink or not a regular file, so AgentReel's entries were not removed from it.`;
  } catch {
    return null;
  }
}

/**
 * Remove this user's AgentReel entries from a per-user hooks file, leaving
 * everyone else's hooks, unknown keys, and the rest of the file intact.
 * Writes a backup first. No-ops (no backup, no write) when there is nothing
 * of ours to remove, or the file is missing or unreadable. Never throws.
 */
export function removeUserAgentreelCursorHooks(
  path: string = cursorHooksPath(),
): { backup: string | null; removed: number; refused?: string } {
  try {
    const refused = refuseUnsafeUserHooksFile(path);
    if (refused) return { backup: null, removed: 0, refused };
    if (!existsSync(path)) return { backup: null, removed: 0 };
    const file = read(path);
    let removed = 0;
    for (const ev of Object.keys(file.hooks ?? {})) {
      const before = file.hooks![ev]!;
      const kept = before.filter((d) => !isOurs(d));
      removed += before.length - kept.length;
      if (kept.length === 0) delete file.hooks![ev];
      else file.hooks![ev] = kept;
    }
    if (removed === 0) return { backup: null, removed: 0 };
    const b = backup(path);
    writeFileSync(path, JSON.stringify(file, null, 2) + "\n", "utf8");
    return { backup: b, removed };
  } catch {
    return { backup: null, removed: 0 };
  }
}

export type InstallCursorHooksResult =
  | { skipped: false; backup: string | null; installedEvents: string[]; path: string; preExecTimeoutS: number }
  /**
   * The managed pack owns the Cursor hooks (or the system file is
   * unreadable, which we treat as managed). Per-user hooks are not
   * written. Stale AgentReel entries in the user file, if any, are
   * removed after a backup; other tools' hooks are left intact.
   */
  | {
      skipped: true;
      managedPath: string;
      managedState: SystemCursorHooksState;
      installedEvents: [];
      path: string;
      preExecTimeoutS: number;
      backup: string | null;
      removed: number;
      /** Set when the user file was a symlink or not a regular file and was left untouched. */
      warning?: string;
    };

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
  const managedState = inspectSystemCursorHooks(managedPath);
  if (managedState === "owned" || managedState === "unreadable") {
    const cleaned = removeUserAgentreelCursorHooks(path);
    return {
      skipped: true,
      managedPath,
      managedState,
      installedEvents: [],
      path,
      preExecTimeoutS,
      backup: cleaned.backup,
      removed: cleaned.removed,
      ...(cleaned.refused ? { warning: cleaned.refused } : {}),
    };
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
