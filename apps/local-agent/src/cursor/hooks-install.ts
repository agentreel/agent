import {
  existsSync,
  mkdirSync,
  readFileSync,
} from "node:fs";
import * as fs from "node:fs";
import { randomBytes } from "node:crypto";
import { dirname } from "node:path";
import { cursorHooksPath } from "../paths.js";
import { buildHookCommand, isScrubbedHookCommand } from "../hooks/hook-command.js";
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

/**
 * Test seams for the per-user hooks file. `lstatSync` is the lstat used by
 * the safety check; `noFollow` is `O_NOFOLLOW` (undefined on Windows, where
 * the write falls back to an lstat right before the open); `beforeOpen`
 * runs after the checks and the backup and before the open, so a test can
 * swap the file or directory for a symlink there (a TOCTOU).
 */
export const _userHooksLstatForTests = { lstatSync: fs.lstatSync };
export const _userHooksWriteForTests: {
  noFollow: number | undefined;
  beforeOpen: ((path: string) => void) | undefined;
  /** Override the next backup path. Tests use this to force an EEXIST retry. */
  nextBackupPath: ((path: string) => string) | undefined;
  /** Replace the final rename. Tests use this to force a rename failure. */
  rename: ((from: string, to: string) => void) | undefined;
} = { noFollow: fs.constants.O_NOFOLLOW, beforeOpen: undefined, nextBackupPath: undefined, rename: undefined };

const OPEN_REFUSAL_CODES = new Set(["ELOOP", "EMLINK"]);

let backupSeq = 0;

/** Unique backup path: timestamp, pid, a monotonic counter and a short random suffix. */
function nextBackupPath(path: string): string {
  if (_userHooksWriteForTests.nextBackupPath) return _userHooksWriteForTests.nextBackupPath(path);
  backupSeq += 1;
  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  const rand = randomBytes(6).toString("hex");
  return `${path}.agentreel-backup-${ts}-${process.pid}-${backupSeq}-${rand}`;
}

/**
 * Copy the existing per-user hooks file to a unique backup, reading it
 * through an O_NOFOLLOW fd so a symlink is never followed. Returns the backup
 * path, or null when the file is missing, is a symlink or not a regular
 * file, or the copy failed for a real reason (EACCES, ENOSPC and the like).
 * Never overwrites an existing backup: the name is unique, the write uses
 * flag "wx", and a same-millisecond EEXIST is retried with a new suffix.
 * Callers that know the file exists must treat null as "do not write" and
 * must report the failure, not count it as a successful no-op.
 */
function backup(path: string): string | null {
  const noFollow = _userHooksWriteForTests.noFollow;
  let fd: number | null = null;
  try {
    if (noFollow === undefined) {
      const st = _userHooksLstatForTests.lstatSync(path);
      if (st.isSymbolicLink() || !st.isFile() || st.nlink !== 1) return null;
    }
    fd = fs.openSync(path, fs.constants.O_RDONLY | (noFollow ?? 0) | (fs.constants.O_NONBLOCK ?? 0));
    const st = fs.fstatSync(fd);
    // nlink !== 1: a hard link to another name. Reading it is safe, but we
    // refuse so a later write cannot be mistaken for a successful backup of
    // a unique file, and so install/cleanup/uninstall abort instead.
    if (!st.isFile() || st.nlink !== 1) return null;
    const data = fs.readFileSync(fd);
    const mode = st.mode & 0o777;
    for (let attempt = 0; attempt < 8; attempt++) {
      const b = nextBackupPath(path);
      try {
        fs.writeFileSync(b, data, { flag: "wx", mode });
        return b;
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === "EEXIST") continue;
        return null;
      }
    }
    return null;
  } catch {
    return null;
  } finally {
    if (fd !== null) {
      try {
        fs.closeSync(fd);
      } catch {
        // Ignore close failures.
      }
    }
  }
}

type UserHooksWrite = { ok: true; backup: string | null } | { ok: false; warning: string };

/**
 * The one way the per-user hooks file is written (install, cleanup and
 * uninstall all use it):
 *
 *  1. refuse a symlinked directory, a symlink or non-regular file, or any
 *     lstat error other than ENOENT;
 *  2. back up the existing file through an O_NOFOLLOW fd, and abort the
 *     write if the file exists and the backup could not be made;
 *  3. re-lstat the parent directory right before the open and refuse a
 *     symlink (a swap since step 1);
 *  4. if the file exists, open it with O_WRONLY|O_NOFOLLOW|O_NONBLOCK (no
 *     O_TRUNC, no O_CREAT), fstat, and refuse unless it is a regular file
 *     with nlink === 1 (a hard link to another name is never written
 *     through);
 *  5. write a temp file in the same directory (O_WRONLY|O_CREAT|O_EXCL,
 *     the original's mode, or 0600 for a new file), fsync it, then
 *     renameSync it over the destination. rename replaces a directory
 *     entry and does not write through a hard link or a symlink. ELOOP
 *     on the open is a refusal. Without O_NOFOLLOW (Windows) the file is
 *     lstat-ed immediately before the open instead.
 *
 * Never throws. A same-user swap of the file in the few instructions
 * between the last check and the open is closed by O_NOFOLLOW. A swap of
 * the parent directory still has a residual window between its lstat and
 * the open or rename; that is tracked as a follow-up (openat / O_DIRECTORY).
 */
function writeUserHooksFile(path: string, content: string): UserHooksWrite {
  const fail = (why: string): UserHooksWrite => ({
    ok: false,
    warning: `${path} or its directory is a symlink or not a regular file, or could not be inspected (${why}), so it was left untouched.`,
  });
  let origFd: number | null = null;
  let tmpFd: number | null = null;
  let tmpPath: string | null = null;
  try {
    const refused = refuseUnsafeUserHooksFile(path);
    if (refused) return { ok: false, warning: refused };

    let existingMode: number | null = null;
    try {
      const st = _userHooksLstatForTests.lstatSync(path);
      if (st.isSymbolicLink() || !st.isFile()) return fail("not a regular file");
      if (st.nlink !== 1) return fail("hard link");
      existingMode = st.mode & 0o777;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") return fail((err as NodeJS.ErrnoException).code ?? "lstat");
    }
    let b: string | null = null;
    if (existingMode !== null) {
      b = backup(path);
      if (b === null) {
        return {
          ok: false,
          warning: `${path} could not be backed up, so it was left untouched.`,
        };
      }
    }

    _userHooksWriteForTests.beforeOpen?.(path);

    const parent = _userHooksLstatForTests.lstatSync(dirname(path));
    if (parent.isSymbolicLink() || !parent.isDirectory()) return fail("directory changed");

    const noFollow = _userHooksWriteForTests.noFollow;
    const c = fs.constants;
    // Re-check the destination after beforeOpen: a swap to a symlink or a
    // hard link must be refused even when the path was missing at step 1.
    if (noFollow === undefined) {
      try {
        const st = _userHooksLstatForTests.lstatSync(path);
        if (st.isSymbolicLink() || !st.isFile()) return fail("not a regular file");
        if (st.nlink !== 1) return fail("hard link");
        existingMode = st.mode & 0o777;
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== "ENOENT") return fail((err as NodeJS.ErrnoException).code ?? "lstat");
      }
    }
    try {
      origFd = fs.openSync(path, c.O_WRONLY | (noFollow ?? 0) | (c.O_NONBLOCK ?? 0));
      const st = fs.fstatSync(origFd);
      if (!st.isFile() || st.nlink !== 1) return fail(st.nlink !== 1 ? "hard link" : "not a regular file");
      existingMode = st.mode & 0o777;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code ?? "open";
      if (code === "ENOENT") {
        // New file: write the temp and rename into place below.
        existingMode = existingMode ?? 0o600;
      } else {
        return fail(OPEN_REFUSAL_CODES.has(code) ? "symlink" : code);
      }
    }

    const mode = existingMode ?? 0o600;
    tmpPath = `${path}.agentreel-tmp-${process.pid}-${randomBytes(6).toString("hex")}`;
    try {
      // O_EXCL already refuses an existing name (a planted symlink included);
      // O_NOFOLLOW, where the platform has it, is a second guard.
      tmpFd = fs.openSync(tmpPath, c.O_WRONLY | c.O_CREAT | c.O_EXCL | (noFollow ?? 0), mode);
    } catch (err) {
      return fail((err as NodeJS.ErrnoException).code ?? "open");
    }
    try {
      fs.fchmodSync(tmpFd, mode);
    } catch {
      // Non-Unix filesystems without mode bits: best effort.
    }
    fs.writeFileSync(tmpFd, content, "utf8");
    fs.fsyncSync(tmpFd);
    fs.closeSync(tmpFd);
    tmpFd = null;
    (_userHooksWriteForTests.rename ?? fs.renameSync)(tmpPath, path);
    tmpPath = null;
    return { ok: true, backup: b };
  } catch (err) {
    return fail((err as NodeJS.ErrnoException).code ?? "error");
  } finally {
    if (origFd !== null) {
      try {
        fs.closeSync(origFd);
      } catch {
        // Ignore close failures.
      }
    }
    if (tmpFd !== null) {
      try {
        fs.closeSync(tmpFd);
      } catch {
        // Ignore close failures.
      }
    }
    if (tmpPath !== null) {
      try {
        fs.unlinkSync(tmpPath);
      } catch {
        // Already renamed or never created.
      }
    }
  }
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
 * or lstat fails with anything other than ENOENT (EACCES, ELOOP, ENOTDIR
 * and the rest), the path is left alone. Only a true ENOENT on the
 * directory or the file means there is nothing to clean (and a fresh
 * install may create it). Returns the warning text, or null when it is
 * safe to edit or there is nothing there. Fail closed: the outer catch
 * returns the warning, never null.
 */
function refuseUnsafeUserHooksFile(path: string): string | null {
  const warning =
    `${path} or its directory is a symlink or not a regular file, so it was left untouched.`;
  try {
    let dirStat: fs.Stats;
    try {
      dirStat = _userHooksLstatForTests.lstatSync(dirname(path));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw err;
    }
    if (dirStat.isSymbolicLink() || !dirStat.isDirectory()) return warning;

    let fileStat: fs.Stats;
    try {
      fileStat = _userHooksLstatForTests.lstatSync(path);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw err;
    }
    if (fileStat.isSymbolicLink() || !fileStat.isFile()) return warning;
    return null;
  } catch {
    return warning;
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
    const w = writeUserHooksFile(path, JSON.stringify(file, null, 2) + "\n");
    if (!w.ok) return { backup: null, removed: 0, refused: w.warning };
    return { backup: w.backup, removed };
  } catch {
    return { backup: null, removed: 0 };
  }
}

export type InstallCursorHooksResult =
  | { skipped: false; refused?: undefined; backup: string | null; installedEvents: string[]; path: string; preExecTimeoutS: number }
  /**
   * The user hooks path is a symlink, not a regular file, or could not be
   * inspected. Nothing was written or backed up.
   */
  | {
      skipped: false;
      refused: true;
      warning: string;
      backup: null;
      installedEvents: [];
      path: string;
      preExecTimeoutS: number;
    }
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
      refused?: true;
      /** Set when the user file was a symlink, a hard link, or not a regular file and was left untouched. */
      warning?: string;
    };

/**
 * Add `env -u NODE_OPTIONS <prefix> cursor-hook <event>` (Windows: the cmd form,
 * see hooks/hook-command.ts) to ~/.cursor/hooks.json for every hook.
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
      ...(cleaned.refused ? { refused: true as const, warning: cleaned.refused } : {}),
    };
  }
  const refused = refuseUnsafeUserHooksFile(path);
  if (refused) {
    return {
      skipped: false,
      refused: true,
      warning: refused,
      backup: null,
      installedEvents: [],
      path,
      preExecTimeoutS,
    };
  }
  mkdirSync(dirname(path), { recursive: true });
  const file = read(path);
  file.version ??= 1;
  file.hooks ??= {};
  for (const ev of CURSOR_HOOK_EVENTS) {
    const kept = (file.hooks[ev] ?? []).filter((d) => !isOurs(d));
    kept.push({
      command: buildHookCommand(prefix, CURSOR_HOOK_SUBCOMMAND, ev),
      timeout: cursorHookTimeoutForEvent(ev, preExecTimeoutS),
      // Pre-exec hooks only: a crash, timeout or missing binary denies the
      // action instead of allowing it (Cursor defaults to fail-open).
      ...(isCursorPreExecHook(ev) ? { failClosed: true } : {}),
    });
    file.hooks[ev] = kept;
  }
  const w = writeUserHooksFile(path, JSON.stringify(file, null, 2) + "\n");
  if (!w.ok) {
    return { skipped: false, refused: true, warning: w.warning, backup: null, installedEvents: [], path, preExecTimeoutS };
  }
  return { skipped: false, backup: w.backup, installedEvents: [...CURSOR_HOOK_EVENTS], path, preExecTimeoutS };
}

export function uninstallCursorHooks(
  path = cursorHooksPath(),
): { backup: string | null; removed: number; refused?: string } {
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
  const w = writeUserHooksFile(path, JSON.stringify(file, null, 2) + "\n");
  if (!w.ok) return { backup: null, removed: 0, refused: w.warning };
  return { backup: w.backup, removed };
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

export interface CursorHookScrubCheck {
  /** AgentReel hook entries found in the hooks file. */
  entries: number;
  /** Entries whose command does not drop NODE_OPTIONS first (installed before the scrub existed). */
  unscrubbed: number;
}

/** Counts AgentReel-managed Cursor hook commands that do not scrub NODE_OPTIONS. */
export function inspectCursorHookScrub(path: string = cursorHooksPath()): CursorHookScrubCheck {
  if (!existsSync(path)) return { entries: 0, unscrubbed: 0 };
  try {
    const file = read(path);
    let entries = 0;
    let unscrubbed = 0;
    for (const defs of Object.values(file.hooks ?? {})) {
      for (const d of Array.isArray(defs) ? defs : []) {
        if (!isOurs(d)) continue;
        entries += 1;
        if (!isScrubbedHookCommand(d.command)) unscrubbed += 1;
      }
    }
    return { entries, unscrubbed };
  } catch {
    return { entries: 0, unscrubbed: 0 };
  }
}
