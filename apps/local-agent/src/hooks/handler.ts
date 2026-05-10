import { nanoid } from "nanoid";
import { appendFileSync } from "node:fs";
import type { AgentEvent, ClaudeCodeHookInput, EventType } from "@agentreel/shared-types";
import { insertEvent, upsertSession } from "../db.js";
import { LOG_PATH, ensureAgentreelDir } from "../paths.js";
import { scrubAny } from "../redact/scrubber.js";

const HOOK_EVENT_TO_TYPE: Record<string, EventType> = {
  SessionStart: "session_start",
  SessionEnd: "session_end",
  UserPromptSubmit: "user_prompt_submit",
  PreToolUse: "tool_use_pre",
  PostToolUse: "tool_use_post",
  Notification: "notification",
  Stop: "stop",
  SubagentStop: "subagent_stop",
  PreCompact: "pre_compact",
};

async function readStdin(): Promise<string> {
  if (process.stdin.isTTY) return "";
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function logError(err: unknown): void {
  try {
    ensureAgentreelDir();
    const line = `[${new Date().toISOString()}] hook error: ${
      err instanceof Error ? err.stack ?? err.message : String(err)
    }\n`;
    appendFileSync(LOG_PATH, line);
  } catch {
    // swallow — never block Claude Code
  }
}

export async function runHook(eventArg?: string): Promise<void> {
  // Hooks must never block or fail Claude Code. Wrap everything.
  try {
    const raw = await readStdin();
    if (!raw.trim()) return;
    const input = JSON.parse(raw) as ClaudeCodeHookInput;

    const hookEventName = input.hook_event_name ?? eventArg ?? "Unknown";
    const type: EventType = HOOK_EVENT_TO_TYPE[hookEventName] ?? "unknown";
    const ts = Date.now();
    const sessionId = input.session_id ?? "unknown-session";

    if (type === "session_start") {
      upsertSession({
        id: sessionId,
        tool: "claude-code",
        startedAt: ts,
        cwd: input.cwd,
      });
    } else if (type === "session_end") {
      upsertSession({
        id: sessionId,
        tool: "claude-code",
        startedAt: ts,
        endedAt: ts,
        cwd: input.cwd,
      });
    } else {
      // Make sure the session row exists so events have a parent.
      upsertSession({
        id: sessionId,
        tool: "claude-code",
        startedAt: ts,
        cwd: input.cwd,
      });
    }

    // Scrub the entire payload before persistence — never let raw secrets
    // touch SQLite, even briefly. scrubAny handles strings recursively and
    // also redacts values whose KEY name looks sensitive.
    const safePayload = scrubAny(input);
    const event: AgentEvent = {
      id: nanoid(),
      sessionId,
      tool: "claude-code",
      type,
      ts,
      cwd: input.cwd,
      payload: safePayload,
    };
    insertEvent(event);
  } catch (err) {
    logError(err);
  }
}
