import chokidar, { type FSWatcher } from "chokidar";
import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import {
  findWorkspaceRoot,
  isProbablyBinary,
  readEntries,
  resourceToPath,
  type HistoryEntry,
} from "./entries.js";
import { computeDiff } from "./diff.js";
import { isIgnored } from "../redact/ignore.js";
import { scrubString } from "../redact/scrubber.js";

export interface SnapshotEvent {
  filePath: string;
  workspace: string | null;
  source: "cursor-ai" | "cursor-manual" | "unknown";
  timestamp: number;
  patch: string;
  added: number;
  removed: number;
  binary: boolean;
}

export type SnapshotHandler = (e: SnapshotEvent) => void | Promise<void>;

export interface WatcherOptions {
  /** Discard the very first entry for any tracked file (Cursor's "first observation" snapshot). Default true. */
  skipFirstObservation?: boolean;
}

export function startCursorWatcher(
  historyDir: string,
  onSnapshot: SnapshotHandler,
  opts: WatcherOptions = {},
): FSWatcher {
  const skipFirst = opts.skipFirstObservation ?? true;

  const watcher = chokidar.watch(historyDir, {
    ignoreInitial: true,
    depth: 2,
    persistent: true,
    awaitWriteFinish: { stabilityThreshold: 120, pollInterval: 40 },
  });

  watcher.on("add", async (path) => {
    try {
      const folder = dirname(path);
      const file = basename(path);
      // The folder name is the resource hash; siblings include entries.json
      // and one snapshot file per saved version.
      if (file === "entries.json") return;
      // Wait briefly for entries.json to mention this file — Cursor writes
      // the snapshot before updating the manifest in some versions.
      const ctx = await waitForEntry(folder, file, 2_000);
      if (!ctx) return;
      await processSnapshot(folder, ctx, skipFirst, onSnapshot);
    } catch (err) {
      // The watcher must never crash the host process.
      // eslint-disable-next-line no-console
      console.error("[agentreel] cursor watcher: error processing", path, err);
    }
  });

  return watcher;
}

interface SnapshotContext {
  resource: string;
  current: HistoryEntry;
  previous: HistoryEntry | null;
  currentIdx: number;
}

async function waitForEntry(
  folder: string,
  fileId: string,
  totalMs: number,
): Promise<SnapshotContext | null> {
  const start = Date.now();
  while (Date.now() - start < totalMs) {
    const file = await readEntries(folder);
    if (file) {
      const idx = file.entries.findIndex((e) => e.id === fileId);
      if (idx >= 0) {
        const current = file.entries[idx];
        if (!current) return null;
        const previous = idx > 0 ? (file.entries[idx - 1] ?? null) : null;
        return { resource: file.resource, current, previous, currentIdx: idx };
      }
    }
    await sleep(150);
  }
  return null;
}

async function processSnapshot(
  folder: string,
  ctx: SnapshotContext,
  skipFirst: boolean,
  onSnapshot: SnapshotHandler,
): Promise<void> {
  const filePath = resourceToPath(ctx.resource);
  if (!filePath) return;

  // Skip files inside common dependency / build dirs — high noise, low value.
  if (NOISY_PATH.test(filePath)) return;

  // Honor per-workspace .agentreelignore (gitignore syntax).
  const workspace = findWorkspaceRoot(filePath);
  if (isIgnored(workspace, filePath)) return;

  if (!ctx.previous) {
    // First time Cursor has seen this file — no diff to compute.
    if (skipFirst) return;
  }

  const newSnapshot = join(folder, ctx.current.id);
  let before = "";
  let after = "";
  if (ctx.previous) {
    const prevPath = join(folder, ctx.previous.id);
    if (existsSync(prevPath)) {
      before = await safeRead(prevPath);
    }
  }
  if (existsSync(newSnapshot)) {
    after = await safeRead(newSnapshot);
  }

  // No real change — chokidar can fire spurious "add" events on some
  // filesystems. Skip silently.
  if (before === after) return;

  const binary = isProbablyBinary(filePath);
  let patch = "";
  let added = 0;
  let removed = 0;
  if (!binary) {
    // Scrub BEFORE diffing so secrets never enter the patch text. We diff
    // the redacted versions instead — the dashboard will still show the
    // shape of the change, just with [REDACTED:*] in place of values.
    const beforeSafe = scrubString(before);
    const afterSafe = scrubString(after);
    const result = computeDiff(beforeSafe, afterSafe);
    patch = result.patch;
    added = result.added;
    removed = result.removed;
  }

  const source = classifySource(ctx.current.source);
  onSnapshot({
    filePath,
    workspace,
    source,
    timestamp: ctx.current.timestamp ?? Date.now(),
    patch,
    added,
    removed,
    binary,
  });
}

function classifySource(raw?: string): SnapshotEvent["source"] {
  if (!raw) return "cursor-manual";
  const s = raw.toLowerCase();
  if (s.includes("composer") || s.includes("ai") || s.includes("chat")) return "cursor-ai";
  return "cursor-manual";
}

async function safeRead(path: string): Promise<string> {
  try {
    return await readFile(path, "utf8");
  } catch {
    return "";
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

const NOISY_PATH =
  /[\\/](node_modules|\.next|\.turbo|dist|build|\.git|coverage|\.cache|\.venv|venv|target|out)[\\/]/;
