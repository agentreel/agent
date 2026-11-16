import { nanoid } from "nanoid";
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import type { AgentEvent } from "@agentreel/shared-types";
import { insertEvent, upsertSession } from "../db.js";
import { CURSOR_HOOKS_PATH, LOG_PATH, ensureAgentreelDir } from "../paths.js";
import { scrubAny } from "../redact/scrubber.js";
import { isCapturePaused } from "../config.js";
import { applyIgnoreRules } from "../hooks/ignore-payload.js";
import { ensureSessionAttribution, recordSessionEndGit } from "../session-attribution.js";
import { readStdin } from "../util/stdin.js";
import {
  canonicalHookName,
  cursorHookResponse,
  normalizeCursorHook,
  type CursorHookInput,
} from "./hook-normalize.js";

export const CURSOR_HOOK_SUBCOMMAND = "cursor-hook";

function logError(err: unknown): void {
  try {
    ensureAgentreelDir();
    appendFileSync(
      LOG_PATH,
      `[${new Date().toISOString()}] cursor hook error: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`,
    );
  } catch {
    // never block Cursor
  }
}

/** True when ~/.cursor/hooks.json already points at `agentreel cursor-hook`. */
export function nativeCursorHooksInstalled(path = CURSOR_HOOKS_PATH): boolean {
  try {
    return existsSync(path) && readFileSync(path, "utf8").includes(` ${CURSOR_HOOK_SUBCOMMAND} `);
  } catch {
    return false;
  }
}

/** True when a hook payload came from Cursor (it always sends cursor_version). */
export function isCursorPayload(input: unknown): boolean {
  return !!input && typeof input === "object" && typeof (input as { cursor_version?: unknown }).cursor_version === "string";
}

/** Store one Cursor hook event. Pure of stdin/stdout so tests can drive it. */
export function recordCursorHook(eventArg: string | undefined, input: CursorHookInput, now = Date.now()): string | null {
  const n = normalizeCursorHook(eventArg, input, now);
  if (!n) return null;
  upsertSession({
    id: n.sessionId,
    tool: "cursor",
    startedAt: n.ts,
    ...(n.sessionEnd ? { endedAt: n.ts } : {}),
    cwd: n.cwd,
  });
  try {
    ensureSessionAttribution(n.sessionId, {
      cwd: n.cwd,
      tool: "cursor",
      toolVersion: input.cursor_version,
      model: input.model,
    });
    if (n.turnEnd) recordSessionEndGit(n.sessionId, n.cwd);
  } catch (err) {
    logError(err);
  }
  // .agentreelignore first (drops contents of ignored files), then scrub.
  const payload = scrubAny(applyIgnoreRules({ ...n.payload, cwd: n.cwd } as never));
  const event: AgentEvent = {
    id: nanoid(),
    sessionId: n.sessionId,
    tool: "cursor",
    type: n.type,
    ts: n.ts,
    cwd: n.cwd,
    payload,
  };
  insertEvent(event);
  return n.sessionId;
}

/** `agentreel cursor-hook <event>`: read JSON on stdin, record, answer. */
export async function runCursorHook(eventArg?: string): Promise<void> {
  let hook = canonicalHookName(eventArg);
  try {
    const raw = await readStdin().catch(() => "");
    if (!isCapturePaused() && raw.trim()) {
      const input = JSON.parse(raw) as CursorHookInput;
      hook = canonicalHookName(input.hook_event_name) ?? hook;
      recordCursorHook(eventArg, input);
    }
  } catch (err) {
    logError(err);
  } finally {
    // Always answer, even on errors: observe-only hooks never block Cursor.
    process.stdout.write(cursorHookResponse(hook) + "\n");
  }
}
