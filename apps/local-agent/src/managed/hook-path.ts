/**
 * Tamper check for the hook binary path written into managed policy files.
 * A path fails if the binary is not safely root-owned, is group- or
 * world-writable, or any parent directory is writable by a non-root user.
 */
import { lstatSync, realpathSync } from "node:fs";
import { dirname, isAbsolute, resolve } from "node:path";
import { stripHookScrubWrapper } from "../hooks/hook-command.js";
import type { ManagedPlatform } from "./pack.js";
import { underRoot } from "./install.js";

/** macOS `admin` group (GID 80). root:admin 0755 prefixes such as /usr/local are accepted. */
export const DARWIN_ADMIN_GID = 80;

export interface PathIdentity {
  uid: number;
  gid: number;
  /** Permission bits only (e.g. 0o755). */
  mode: number;
}

export type StatPath = (path: string) => PathIdentity | null;
export type RealpathFn = (path: string) => string | null;

export interface HookPathIssue {
  path: string;
  reason: string;
}

export interface HookPathInspection {
  /** The path that was checked, after resolving quotes, --root and symlinks. */
  checkedPath: string | null;
  issues: HookPathIssue[];
  /** The hook command does not point at a readable file. */
  missing: boolean;
}

export interface InspectHookPathOptions {
  platform: ManagedPlatform;
  /** Staging root. Paths are checked as they will appear on the target. */
  root?: string;
  stat?: StatPath;
  realpath?: RealpathFn;
}

export function hookCommandBinaryPath(hookCommand: string): string | null {
  const trimmed = stripHookScrubWrapper(hookCommand).trim();
  if (!trimmed) return null;
  if (trimmed.startsWith('"')) {
    const end = trimmed.indexOf('"', 1);
    if (end <= 1) return null;
    const inside = trimmed.slice(1, end);
    return inside || null;
  }
  return trimmed.split(/\s+/)[0] ?? null;
}

function defaultStat(path: string): PathIdentity | null {
  try {
    const st = lstatSync(path);
    if (st.isSymbolicLink()) return null;
    return { uid: st.uid, gid: st.gid, mode: st.mode & 0o777 };
  } catch {
    return null;
  }
}

function defaultRealpath(path: string): string | null {
  try {
    return realpathSync(path);
  } catch {
    return null;
  }
}

function formatMode(mode: number): string {
  return mode.toString(8).padStart(4, "0");
}

/** uid 0, or on macOS an admin-group owner when the mode is not group-writable. */
export function isTrustedOwner(id: PathIdentity, platform: ManagedPlatform): boolean {
  if (id.uid === 0) return true;
  if (platform === "darwin" && id.gid === DARWIN_ADMIN_GID && (id.mode & 0o020) === 0) return true;
  return false;
}

export function isGroupOrWorldWritable(mode: number): boolean {
  return (mode & 0o022) !== 0;
}

/** A non-root user can create, replace or rename entries in this directory. */
export function isWritableByNonRoot(id: PathIdentity, platform: ManagedPlatform): boolean {
  if (id.mode & 0o002) return true;
  // Group-writable is never accepted, including root or admin group.
  if (id.mode & 0o020) return true;
  if (!isTrustedOwner(id, platform) && (id.mode & 0o200) !== 0) return true;
  return false;
}

function describeOwner(id: PathIdentity): string {
  return `owner uid ${id.uid}, group gid ${id.gid}, mode ${formatMode(id.mode)}`;
}

function binaryIssues(path: string, id: PathIdentity, platform: ManagedPlatform): HookPathIssue[] {
  const issues: HookPathIssue[] = [];
  if (!isTrustedOwner(id, platform)) {
    issues.push({
      path,
      reason:
        platform === "darwin"
          ? `is not owned by root or by the admin group (${describeOwner(id)})`
          : `is not owned by root (${describeOwner(id)})`,
    });
  }
  if (isGroupOrWorldWritable(id.mode)) {
    issues.push({
      path,
      reason: `is group- or world-writable (${describeOwner(id)}), so another user can overwrite it`,
    });
  }
  return issues;
}

function parentIssue(path: string, id: PathIdentity, platform: ManagedPlatform): HookPathIssue | null {
  if (!isWritableByNonRoot(id, platform)) return null;
  return {
    path,
    reason: `is writable by a non-root user (${describeOwner(id)}), so that user can replace the hook binary`,
  };
}

/**
 * Paths to inspect for a hook binary as it will appear on the target.
 * With --root, the binary is looked up under the staging root and parents
 * are walked up to (but not including) that root.
 */
export function hookPathChain(hookPath: string, root: string): { file: string; parents: string[]; stop: string } {
  const abs = isAbsolute(hookPath) ? hookPath : `/${hookPath}`;
  const file = root === "/" ? abs : abs === root || abs.startsWith(`${resolve(root)}/`) ? abs : underRoot(root, abs);
  const stop = root === "/" ? "/" : resolve(root);
  const parents: string[] = [];
  let dir = dirname(file);
  while (true) {
    if (dir === stop) break;
    parents.push(dir);
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return { file, parents, stop };
}

export function inspectHookCommandPath(hookCommand: string, opts: InspectHookPathOptions): HookPathInspection {
  const raw = hookCommandBinaryPath(hookCommand);
  if (!raw || !isAbsolute(raw)) {
    return {
      checkedPath: raw,
      missing: true,
      issues: [
        {
          path: raw ?? hookCommand,
          reason: "is not an absolute path to a hook binary, so its ownership cannot be verified",
        },
      ],
    };
  }

  const root = opts.root ?? "/";
  const staged = hookPathChain(raw, root);
  const live = hookPathChain(raw, "/");
  const realpath = opts.realpath ?? defaultRealpath;
  const stat = opts.stat ?? defaultStat;

  // Prefer the copy under --root when it exists (image builds). Otherwise
  // check the path as it will run on the machine (policy-file staging and
  // the default "this binary" path). A symlink into a user-writable tree
  // is resolved and inspected; parents are not walked above the staging root
  // when the file we checked lives there.
  const stagedResolved = realpath(staged.file);
  const liveResolved = root === "/" ? stagedResolved : realpath(live.file);
  const file = stagedResolved ?? liveResolved;
  if (!file) {
    return { checkedPath: staged.file, missing: true, issues: [] };
  }
  const checkedStaged = stagedResolved !== null && (file === staged.file || file.startsWith(`${staged.stop}/`));
  const parents = hookPathChain(file, checkedStaged ? root : "/").parents;

  const fileId = stat(file);
  if (!fileId) {
    return { checkedPath: file, missing: true, issues: [] };
  }

  const issues = [...binaryIssues(file, fileId, opts.platform)];
  for (const dir of parents) {
    const id = stat(dir);
    if (!id) continue;
    const issue = parentIssue(dir, id, opts.platform);
    if (issue) issues.push(issue);
  }
  return { checkedPath: file, missing: false, issues };
}

export function formatHookPathIssues(issues: HookPathIssue[]): string {
  return issues.map((i) => `${i.path} ${i.reason}`).join("\n");
}

export function hookPathRefusalMessage(issues: HookPathIssue[]): string {
  return (
    "Refusing to install hooks that point at a binary a non-root user can replace:\n" +
    issues.map((i) => `  ${i.path} ${i.reason}`).join("\n") +
    "\nPass --hook-command <path to a root-owned agentreel>, or --allow-user-writable-hook to accept the risk."
  );
}

export function hookPathWarningMessage(issues: HookPathIssue[]): string {
  return (
    "The hook binary is writable by a non-root user, so an agent running as that user could replace it:\n" +
    issues.map((i) => `  ${i.path} ${i.reason}`).join("\n")
  );
}
