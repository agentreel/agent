import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { CURSOR_HOOKS_PATH } from "../paths.js";
import { CURSOR_HOOK_EVENTS } from "./hook-normalize.js";
import { CURSOR_HOOK_SUBCOMMAND } from "./hook-runner.js";

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

/**
 * Add `<prefix> cursor-hook <event>` to ~/.cursor/hooks.json for every
 * observe-only hook. Other tools' hooks are left alone; re-running replaces
 * our previous entries, so it is idempotent.
 */
export function installCursorHooks(prefix: string, path = CURSOR_HOOKS_PATH): { backup: string | null; installedEvents: string[]; path: string } {
  mkdirSync(dirname(path), { recursive: true });
  const b = backup(path);
  const file = read(path);
  file.version ??= 1;
  file.hooks ??= {};
  for (const ev of CURSOR_HOOK_EVENTS) {
    const kept = (file.hooks[ev] ?? []).filter((d) => !isOurs(d));
    kept.push({ command: `${prefix} ${CURSOR_HOOK_SUBCOMMAND} ${ev}`, timeout: 5 });
    file.hooks[ev] = kept;
  }
  writeFileSync(path, JSON.stringify(file, null, 2) + "\n", "utf8");
  return { backup: b, installedEvents: [...CURSOR_HOOK_EVENTS], path };
}

export function uninstallCursorHooks(path = CURSOR_HOOKS_PATH): { backup: string | null; removed: number } {
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
