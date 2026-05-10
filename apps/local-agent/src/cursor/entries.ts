import { readFile } from "node:fs/promises";
import { existsSync, statSync } from "node:fs";
import { join, dirname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

export interface HistoryEntry {
  id: string; // filename of the snapshot, e.g. "rEMc.ts"
  timestamp: number; // ms epoch
  source?: string; // e.g. "Cursor.Composer" for AI edits, "" for manual
}

export interface HistoryFile {
  version: number;
  resource: string; // file:///...
  entries: HistoryEntry[];
}

export async function readEntries(historyFolder: string): Promise<HistoryFile | null> {
  const path = join(historyFolder, "entries.json");
  if (!existsSync(path)) return null;
  try {
    const raw = await readFile(path, "utf8");
    return JSON.parse(raw) as HistoryFile;
  } catch {
    return null;
  }
}

export function resourceToPath(resource: string): string | null {
  if (!resource.startsWith("file://")) return null;
  try {
    return fileURLToPath(resource);
  } catch {
    return null;
  }
}

// Walk up from `path` looking for a directory that contains `.git`. That
// directory is the workspace root for the purposes of grouping events.
export function findWorkspaceRoot(path: string): string | null {
  let dir = dirname(resolve(path));
  while (dir && dir !== sep) {
    const git = join(dir, ".git");
    try {
      if (existsSync(git)) return dir;
    } catch {
      // ignore
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

export function isProbablyBinary(path: string): boolean {
  try {
    const s = statSync(path);
    if (s.size > 1024 * 1024) return true; // >1MB — skip diff
  } catch {
    return false;
  }
  // Lightweight extension allowlist for v1. Anything else, treat as binary
  // and skip diffing (we still record the event, just without a patch).
  const text =
    /\.(ts|tsx|js|jsx|mjs|cjs|json|jsonc|md|mdx|css|scss|html|xml|yaml|yml|toml|sh|bash|zsh|fish|py|rb|go|rs|java|kt|swift|c|cc|cpp|h|hpp|cs|php|sql|prisma|graphql|gql|env|gitignore|dockerfile|tf|hcl|lua|vue|svelte|astro|txt|csv|tsv|log|conf|ini)$/i;
  return !text.test(path);
}
