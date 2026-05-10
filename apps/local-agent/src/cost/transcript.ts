import { existsSync, statSync, openSync, readSync, closeSync } from "node:fs";
import { getDb, getMeta, setMeta } from "../db.js";
import { costCentsFor, ratesFor, type UsageBreakdown } from "./pricing.js";

interface TranscriptLine {
  type?: string;
  message?: {
    model?: string;
    usage?: Partial<{
      input_tokens: number;
      output_tokens: number;
      cache_read_input_tokens: number;
      cache_creation_input_tokens: number;
    }>;
  };
}

const KEY_OFFSET = (sid: string) => `cost_offset:${sid}`;
const KEY_TOKENS = (sid: string) => `cost_tokens:${sid}`;
const KEY_CENTS = (sid: string) => `cost_cents:${sid}`;
const KEY_PATH = (sid: string) => `cost_path:${sid}`;

interface SessionTotals {
  totalCostCents: number;
  totalTokens: number;
}

/**
 * Parse the tail of a session's transcript JSONL, sum every assistant
 * `message.usage` block we haven't seen yet, and update the session row
 * with running cost / token totals.
 *
 * Safe to call on every hook fire — incremental via byte offset, so a
 * 50 MB transcript on the 200th tool call only re-reads the last few KB.
 */
export function recomputeSessionCost(sessionId: string, transcriptPath: string | undefined): void {
  if (!transcriptPath) {
    // First call may not have the path; remember the last good one.
    transcriptPath = getMeta(KEY_PATH(sessionId)) ?? undefined;
  } else {
    setMeta(KEY_PATH(sessionId), transcriptPath);
  }
  if (!transcriptPath || !existsSync(transcriptPath)) return;

  const stat = statSync(transcriptPath);
  const totalSize = stat.size;
  const offset = Number(getMeta(KEY_OFFSET(sessionId)) ?? "0");
  if (offset >= totalSize) return; // nothing new

  const buf = Buffer.alloc(totalSize - offset);
  const fd = openSync(transcriptPath, "r");
  try {
    readSync(fd, buf, 0, buf.length, offset);
  } finally {
    closeSync(fd);
  }

  const text = buf.toString("utf8");
  // The tail may end mid-line if a writer is still flushing. Stash any
  // partial trailing line and only consume up through the last newline.
  const lastNewline = text.lastIndexOf("\n");
  if (lastNewline === -1) return; // no complete line yet
  const consumable = text.slice(0, lastNewline);
  const consumedBytes = Buffer.byteLength(consumable, "utf8") + 1; // include the \n

  let addedTokens = 0;
  let addedCents = 0;
  for (const raw of consumable.split("\n")) {
    if (!raw) continue;
    let line: TranscriptLine;
    try {
      line = JSON.parse(raw) as TranscriptLine;
    } catch {
      continue;
    }
    if (line.type !== "assistant") continue;
    const usage = line.message?.usage;
    if (!usage) continue;

    const u: UsageBreakdown = {
      inputTokens: usage.input_tokens ?? 0,
      outputTokens: usage.output_tokens ?? 0,
      cacheReadTokens: usage.cache_read_input_tokens ?? 0,
      cacheCreationTokens: usage.cache_creation_input_tokens ?? 0,
    };
    const rates = ratesFor(line.message?.model);
    addedCents += costCentsFor(u, rates);
    addedTokens +=
      u.inputTokens + u.outputTokens + u.cacheReadTokens + u.cacheCreationTokens;
  }

  const prevTokens = Number(getMeta(KEY_TOKENS(sessionId)) ?? "0");
  const prevCents = Number(getMeta(KEY_CENTS(sessionId)) ?? "0");
  const newTokens = prevTokens + addedTokens;
  const newCents = prevCents + addedCents;

  setMeta(KEY_OFFSET(sessionId), String(offset + consumedBytes));
  setMeta(KEY_TOKENS(sessionId), String(newTokens));
  setMeta(KEY_CENTS(sessionId), String(newCents));

  // Stamp the totals on the session row so the upload picks them up.
  // Use COALESCE-style write — if the row vanished (shouldn't happen),
  // the UPDATE is a noop.
  const db = getDb();
  db.prepare(
    `UPDATE sessions
       SET total_cost_cents = ?, total_tokens = ?
     WHERE id = ?`,
  ).run(newCents, newTokens, sessionId);
}

export function getSessionTotals(sessionId: string): SessionTotals {
  return {
    totalCostCents: Number(getMeta(KEY_CENTS(sessionId)) ?? "0"),
    totalTokens: Number(getMeta(KEY_TOKENS(sessionId)) ?? "0"),
  };
}
