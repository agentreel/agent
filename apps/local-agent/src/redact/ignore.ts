import { existsSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import ignore, { type Ignore } from "ignore";

const FILENAME = ".agentreelignore";
const TTL_MS = 5_000; // re-read the file at most every 5 seconds per workspace

interface CacheEntry {
  matcher: Ignore | null;
  loadedAt: number;
  fileMtime: number;
}

const cache = new Map<string, CacheEntry>();

function loadFor(workspace: string): Ignore | null {
  const path = join(workspace, FILENAME);
  if (!existsSync(path)) return null;
  try {
    const raw = readFileSync(path, "utf8");
    return ignore({ allowRelativePaths: true }).add(raw);
  } catch {
    return null;
  }
}

function getCached(workspace: string): Ignore | null {
  const entry = cache.get(workspace);
  const path = join(workspace, FILENAME);
  let mtime = 0;
  try {
    mtime = existsSync(path) ? statSync(path).mtimeMs : 0;
  } catch {
    mtime = 0;
  }
  const now = Date.now();
  if (entry && now - entry.loadedAt < TTL_MS && entry.fileMtime === mtime) {
    return entry.matcher;
  }
  const matcher = loadFor(workspace);
  cache.set(workspace, { matcher, loadedAt: now, fileMtime: mtime });
  return matcher;
}

/**
 * Returns true if `filePath` should be skipped because it matches a rule
 * in the workspace's `.agentreelignore`. Returns false when the workspace
 * has no ignore file or the path doesn't match.
 */
export function isIgnored(workspace: string | null | undefined, filePath: string): boolean {
  if (!workspace) return false;
  const matcher = getCached(workspace);
  if (!matcher) return false;
  const rel = relative(workspace, filePath);
  // ignore can't reason about paths that escape the workspace.
  if (!rel || rel.startsWith("..") || rel.startsWith(sep)) return false;
  // gitignore syntax expects forward slashes.
  return matcher.ignores(rel.split(sep).join("/"));
}
