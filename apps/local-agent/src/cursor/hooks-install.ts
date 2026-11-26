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
}

/**
 * Add `<prefix> cursor-hook <event>` to ~/.cursor/hooks.json for every hook.
 * Pre-exec hooks receive the longer approval timeout (in seconds); other hooks
 * keep the default 5s timeout. Re-running replaces our previous entries idempotently.
 */
export function installCursorHooks(
  prefix: string,
  path = cursorHooksPath(),
  opts: InstallCursorHooksOptions = {},
): { backup: string | null; installedEvents: string[]; path: string; preExecTimeoutS: number } {
  const preExecTimeoutS = opts.preExecTimeoutS ?? DEFAULT_PRE_EXEC_HOOK_TIMEOUT_S;
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
    });
    file.hooks[ev] = kept;
  }
  writeFileSync(path, JSON.stringify(file, null, 2) + "\n", "utf8");
  return { backup: b, installedEvents: [...CURSOR_HOOK_EVENTS], path, preExecTimeoutS };
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
      })),
    };
  }
}
