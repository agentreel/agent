/**
 * Filesystem side of `agentreel managed install`. Plans first (read-only),
 * then applies: backs up any file it changes, writes atomically, and leaves
 * files that already match untouched. No network calls.
 */
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  chownSync,
  constants as fsConstants,
  lstatSync,
  readFileSync,
  renameSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { randomBytes } from "node:crypto";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { createTwoFilesPatch } from "diff";
import {
  MANAGED_PATHS,
  mergeClaudeManagedSettings,
  mergeCursorManagedHooks,
  removeCursorUserHooks,
  serializeJson,
  type BuildOptions,
  type ManagedPlatform,
} from "./pack.js";

/** `cursor-user` is the invoking user's ~/.cursor/hooks.json, where AgentReel's own entries are removed. */
export type ManagedTarget = "claude" | "cursor" | "cursor-user";

export interface ManagedInstallOptions extends BuildOptions {
  /** Directory the system paths are written under. "/" means the real system. */
  root?: string;
  platform?: ManagedPlatform;
  claude?: boolean;
  cursor?: boolean;
  /**
   * Absolute path of the invoking user's ~/.cursor/hooks.json (already placed
   * under the staging root when one is used). AgentReel-owned entries are
   * removed from it so Cursor does not run AgentReel twice. Skipped when unset.
   */
  cursorUserHooksPath?: string;
  onWarning?: (message: string) => void;
}

export interface ManagedFilePlan {
  target: ManagedTarget;
  /** The system path the tool reads, e.g. /etc/claude-code/managed-settings.json. */
  systemPath: string;
  /** Where this run reads and writes it (systemPath under root). */
  path: string;
  action: "create" | "update" | "unchanged";
  before: string | null;
  after: string;
  diff: string;
}

export interface ManagedFileResult extends ManagedFilePlan {
  backup: string | null;
}

export class ManagedInstallError extends Error {}

export function resolveManagedPlatform(platform: NodeJS.Platform = process.platform): ManagedPlatform {
  if (platform === "linux" || platform === "darwin") return platform;
  throw new ManagedInstallError(
    `agentreel managed install supports Linux, WSL and macOS. On ${platform}, deploy the template files from docs/managed-settings.md with your MDM.`,
  );
}

export function underRoot(root: string, systemPath: string): string {
  return root === "/" ? systemPath : join(resolve(root), systemPath);
}

function readJsonObject(path: string): { raw: string | null; value: Record<string, unknown> } {
  if (!existsSync(path)) return { raw: null, value: {} };
  const raw = readFileSync(path, "utf8");
  if (!raw.trim()) return { raw, value: {} };
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new ManagedInstallError(`${path} is not valid JSON. Fix or move it, then re-run. Nothing was written.`);
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new ManagedInstallError(`${path} is not a JSON object. Fix or move it, then re-run. Nothing was written.`);
  }
  return { raw, value: parsed as Record<string, unknown> };
}

/** Read-only: compute what each file would become. */
export function planManagedInstall(opts: ManagedInstallOptions): ManagedFilePlan[] {
  if (!opts.hookCommand.trim()) throw new ManagedInstallError("hook command is empty");
  const root = opts.root ?? "/";
  if (!isAbsolute(root)) throw new ManagedInstallError(`--root must be an absolute path, got ${root}`);
  const paths = MANAGED_PATHS[opts.platform ?? resolveManagedPlatform()];

  const targets: Array<{ target: ManagedTarget; systemPath: string }> = [];
  if (opts.claude !== false) targets.push({ target: "claude", systemPath: paths.claudeManagedSettings });
  if (opts.cursor !== false) targets.push({ target: "cursor", systemPath: paths.cursorHooks });

  const plans: ManagedFilePlan[] = targets.map(({ target, systemPath }) => {
    const path = underRoot(root, systemPath);
    const { raw, value } = readJsonObject(path);
    const build = { ...opts, platform: opts.platform ?? resolveManagedPlatform() };
    const merged =
      target === "claude" ? mergeClaudeManagedSettings(value, build) : mergeCursorManagedHooks(value, build);
    const after = serializeJson(merged);
    const action = raw === null ? "create" : raw === after ? "unchanged" : "update";
    const diff =
      action === "unchanged"
        ? ""
        : createTwoFilesPatch(systemPath, systemPath, raw ?? "", after, raw === null ? "(new file)" : "current", "agentreel");
    return { target, systemPath, path, action, before: raw, after, diff };
  });

  const userPath = opts.cursor !== false ? opts.cursorUserHooksPath : undefined;
  if (userPath !== undefined) {
    if (!isAbsolute(userPath)) throw new ManagedInstallError(`user hooks path must be absolute, got ${userPath}`);
    const plan = planCursorUserCleanup(userPath, opts.onWarning);
    if (plan) plans.push(plan);
  }
  return plans;
}

/** Plan removal of AgentReel's entries from a user-level Cursor hooks file. Null when there is nothing to do. */
function planCursorUserCleanup(path: string, onWarning?: (message: string) => void): ManagedFilePlan | null {
  if (!existsSync(path)) return null;
  // Root may be editing a file in a user-writable directory: refuse symlinks so
  // the backup copy and the rename can't be pointed at another file.
  if (lstatSync(dirname(path)).isSymbolicLink() || !lstatSync(path).isFile()) {
    onWarning?.(`${path} or its directory is a symlink or not a regular file, so AgentReel's entries were not removed from it.`);
    return null;
  }
  let parsed: { raw: string | null; value: Record<string, unknown> };
  try {
    parsed = readJsonObject(path);
  } catch (err) {
    // A broken user file must not block the system install; leave it alone.
    onWarning?.(`${path} could not be read as JSON, so AgentReel's entries were not removed from it. ${(err as Error).message}`);
    return null;
  }
  const { value, removed } = removeCursorUserHooks(parsed.value);
  if (removed === 0) return null;
  const after = serializeJson(value);
  return {
    target: "cursor-user",
    systemPath: path,
    path,
    action: "update",
    before: parsed.raw,
    after,
    diff: createTwoFilesPatch(path, path, parsed.raw ?? "", after, "current", "agentreel"),
  };
}

function backupPath(path: string, now: Date): string {
  return `${path}.agentreel-backup-${now.toISOString().replace(/[:.]/g, "-")}`;
}

/** Write the planned files. Unchanged files are not touched and get no backup. */
export function applyManagedInstall(plans: ManagedFilePlan[], now: Date = new Date()): ManagedFileResult[] {
  return plans.map((plan) => {
    if (plan.action === "unchanged") return { ...plan, backup: null };
    const dir = dirname(plan.path);
    mkdirSync(dir, { recursive: true, mode: 0o755 });
    // An existing file keeps its owner and mode, so a user's ~/.cursor/hooks.json
    // edited under sudo stays owned by that user.
    const prior = plan.before !== null && existsSync(plan.path) ? statSync(plan.path) : null;
    const mode = prior ? prior.mode & 0o777 : 0o644;
    let backup: string | null = null;
    if (prior) {
      backup = backupPath(plan.path, now);
      copyFileSync(plan.path, backup, fsConstants.COPYFILE_EXCL);
      keepOwner(backup, prior.uid, prior.gid);
    }
    const tmp = `${plan.path}.agentreel-tmp-${process.pid}-${randomBytes(6).toString("hex")}`;
    // "wx" fails if anything, including a symlink, already sits at the temp path.
    writeFileSync(tmp, plan.after, { encoding: "utf8", mode, flag: "wx" });
    chmodSync(tmp, mode);
    if (prior) keepOwner(tmp, prior.uid, prior.gid);
    renameSync(tmp, plan.path);
    return { ...plan, backup };
  });
}

function keepOwner(path: string, uid: number, gid: number): void {
  const st = statSync(path);
  if (st.uid === uid && st.gid === gid) return;
  if (typeof process.getuid !== "function" || process.getuid() !== 0) return;
  chownSync(path, uid, gid);
}

