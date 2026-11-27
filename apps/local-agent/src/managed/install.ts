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
  readFileSync,
  renameSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { createTwoFilesPatch } from "diff";
import {
  MANAGED_PATHS,
  mergeClaudeManagedSettings,
  mergeCursorManagedHooks,
  serializeJson,
  type BuildOptions,
  type ManagedPlatform,
} from "./pack.js";

export type ManagedTarget = "claude" | "cursor";

export interface ManagedInstallOptions extends BuildOptions {
  /** Directory the system paths are written under. "/" means the real system. */
  root?: string;
  platform?: ManagedPlatform;
  claude?: boolean;
  cursor?: boolean;
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

  return targets.map(({ target, systemPath }) => {
    const path = underRoot(root, systemPath);
    const { raw, value } = readJsonObject(path);
    const merged =
      target === "claude" ? mergeClaudeManagedSettings(value, opts) : mergeCursorManagedHooks(value, opts);
    const after = serializeJson(merged);
    const action = raw === null ? "create" : raw === after ? "unchanged" : "update";
    const diff =
      action === "unchanged"
        ? ""
        : createTwoFilesPatch(systemPath, systemPath, raw ?? "", after, raw === null ? "(new file)" : "current", "agentreel");
    return { target, systemPath, path, action, before: raw, after, diff };
  });
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
    let backup: string | null = null;
    if (plan.before !== null) {
      backup = backupPath(plan.path, now);
      copyFileSync(plan.path, backup);
    }
    const tmp = `${plan.path}.agentreel-tmp-${process.pid}`;
    writeFileSync(tmp, plan.after, { encoding: "utf8", mode: 0o644 });
    chmodSync(tmp, 0o644);
    renameSync(tmp, plan.path);
    return { ...plan, backup };
  });
}

/** Owner uid of the file a hook command points at, or null when it can't be read. */
export function hookBinaryOwnerUid(hookCommand: string): number | null {
  const unquoted = hookCommand.startsWith('"') ? hookCommand.slice(1, hookCommand.indexOf('"', 1)) : hookCommand.split(" ")[0]!;
  try {
    return statSync(unquoted).uid;
  } catch {
    return null;
  }
}
