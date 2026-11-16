import { nanoid } from "nanoid";
import { appendFileSync } from "node:fs";
import type { AgentEvent, ClaudeCodeHookInput, EventType } from "@agentreel/shared-types";
import { insertEvent, upsertSession } from "../db.js";
import { LOG_PATH, ensureAgentreelDir } from "../paths.js";
import { scrubAny } from "../redact/scrubber.js";
import { recomputeSessionCost } from "../cost/transcript.js";
import { isCapturePaused } from "../config.js";
import { applyIgnoreRules } from "./ignore-payload.js";
import { readStdin } from "../util/stdin.js";
import { claudeVersionFromTranscript } from "../attribution.js";
import { ensureSessionAttribution, recordSessionEndGit } from "../session-attribution.js";
import { isCursorPayload, nativeCursorHooksInstalled, recordCursorHook } from "../cursor/hook-runner.js";

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
    // Honor explicit opt-outs before reading the payload — env var for
    // single-shell suppression, persisted pause for "stop capturing
    // until I resume." Either way: silently consume stdin (Claude Code
    // streams hook input via pipe; not draining it could leave handles
    // dangling) and return cleanly.
    if (isCapturePaused()) {
      await readStdin().catch(() => "");
      return;
    }

    const raw = await readStdin();
    if (!raw.trim()) return;
    const input = JSON.parse(raw) as ClaudeCodeHookInput;

    // Cursor runs Claude Code hooks from ~/.claude/settings.json too
    // ("Third-party imports", on by default). Those payloads carry
    // cursor_version. Record them as Cursor, or skip them when the native
    // Cursor hooks are installed so nothing is captured twice.
    if (isCursorPayload(input)) {
      if (!nativeCursorHooksInstalled()) recordCursorHook(eventArg, input as never);
      return;
    }

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

    try {
      ensureSessionAttribution(sessionId, {
        cwd: input.cwd,
        tool: "claude-code",
        toolVersion: () => claudeVersionFromTranscript(input.transcript_path),
      });
      if (type === "stop" || type === "session_end") recordSessionEndGit(sessionId, input.cwd);
    } catch (err) {
      logError(err);
    }

    // Scrub the entire payload before persistence — never let raw secrets
    // touch SQLite, even briefly. scrubAny handles strings recursively and
    // also redacts values whose KEY name looks sensitive.
    // .agentreelignore first (drops contents of ignored files), then scrub.
    const safePayload = scrubAny(applyIgnoreRules(input as never) as typeof input);
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

    // After every hook fire, walk the transcript tail and update the
    // session's running cost / token totals. Incremental via offset
    // cache, so this stays cheap even on long sessions.
    try {
      recomputeSessionCost(sessionId, input.transcript_path);
    } catch (err) {
      // Cost is best-effort — never let a parse glitch break capture.
      logError(err);
    }
  } catch (err) {
    logError(err);
  }
}
