import { nanoid } from "nanoid";
import { appendFileSync } from "node:fs";
import type { AgentEvent, ClaudeCodeHookInput, EventType } from "@agentreel/shared-types";
import type { Attribution } from "../attribution.js";
import { claudeVersionFromTranscript } from "../attribution.js";
import {
  getInstalledPreExecTimeoutS,
  isCapturePaused,
  readConfig,
} from "../config.js";
import { recomputeSessionCost } from "../cost/transcript.js";
import { isCursorPayload, nativeCursorHooksInstalled, recordCursorHook } from "../cursor/hook-runner.js";
import { getSessionAttribution, insertEvent, upsertSession } from "../db.js";
import { logPath, ensureAgentreelDir } from "../paths.js";
import {
  enforcePreExec,
  repoSlugFromRemoteUrl,
  type PreExecDeps,
  type PreExecOutcome,
  type PreExecRequest,
} from "../policy/enforce.js";
import { computeHookDeadlineMs } from "../policy/types.js";
import { scrubAny } from "../redact/scrubber.js";
import { ensureSessionAttribution, recordSessionEndGit } from "../session-attribution.js";
import { readStdin } from "../util/stdin.js";
import { applyIgnoreRules } from "./ignore-payload.js";

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
    appendFileSync(logPath(), line);
  } catch {
    // swallow: never block Claude Code
  }
}

export function formatClaudePreToolUseDeny(reason: string): string {
  return JSON.stringify({
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: reason,
    },
  });
}

export function extractClaudePreExecRequest(
  input: ClaudeCodeHookInput,
  sessionId: string,
  ts: number,
  attribution?: Attribution | null,
): PreExecRequest {
  const toolName = input.tool_name ?? "unknown";
  const ti =
    input.tool_input && typeof input.tool_input === "object" && !Array.isArray(input.tool_input)
      ? (input.tool_input as Record<string, unknown>)
      : undefined;

  const command = typeof ti?.command === "string" ? ti.command : undefined;
  const filePath = [ti?.file_path, ti?.path, ti?.notebook_path, ti?.target_file, ti?.filePath, ti?.file].find(
    (v): v is string => typeof v === "string" && v.length > 0,
  );
  const url = typeof ti?.url === "string" ? ti.url : undefined;
  let mcpTool: string | undefined;
  if (toolName.startsWith("mcp__")) {
    mcpTool = toolName.slice(5);
  } else if (toolName.startsWith("MCP:")) {
    mcpTool = toolName.slice(4);
  }

  return {
    sessionId,
    tool: "claude-code",
    toolName,
    toolUseId: input.tool_use_id,
    cwd: input.cwd,
    command,
    file_path: filePath,
    url,
    mcp_tool: mcpTool,
    toolInput: input.tool_input,
    repo: repoSlugFromRemoteUrl(attribution?.git?.remote_url),
    branch: attribution?.git?.branch_end ?? attribution?.git?.branch_start,
    member: attribution?.git?.user_email ?? attribution?.os_user,
    ts,
  };
}

export interface HandleClaudeHookResult {
  stdout: string | null;
  outcome?: PreExecOutcome;
}

export async function handleClaudeHookInput(
  eventArg: string | undefined,
  input: ClaudeCodeHookInput,
  deps: PreExecDeps = {},
): Promise<HandleClaudeHookResult> {
  const hookEventName = input.hook_event_name ?? eventArg ?? "Unknown";
  const type: EventType = HOOK_EVENT_TO_TYPE[hookEventName] ?? "unknown";
  const ts = deps.now ? deps.now() : Date.now();
  const sessionId = input.session_id ?? "unknown-session";
  const capturePaused = isCapturePaused(deps.config ?? readConfig());

  if (!capturePaused) {
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
  }

  let stdout: string | null = null;
  let outcome: PreExecOutcome | undefined;

  if (type === "tool_use_pre") {
    try {
      let attribution: Attribution | null = null;
      if (!capturePaused) {
        try {
          attribution = getSessionAttribution<Attribution>(sessionId);
        } catch {
          attribution = null;
        }
      }
      const req = extractClaudePreExecRequest(input, sessionId, ts, attribution);
      outcome = await enforcePreExec(req, deps);
      if (!outcome.permitted && outcome.message) {
        stdout = formatClaudePreToolUseDeny(outcome.message);
      }
    } catch (err) {
      logError(err);
      stdout = null;
    }
  }

  if (!capturePaused) {
    try {
      recomputeSessionCost(sessionId, input.transcript_path);
    } catch (err) {
      logError(err);
    }
  }

  return { stdout, outcome };
}

export interface RunHookOptions {
  /** Hook start timestamp in ms (defaults to Date.now(); cli.ts passes process timeOrigin). */
  hookStartMs?: number;
  readStdin?: () => Promise<string>;
  writeStdout?: (text: string) => void;
}

export async function runHook(
  eventArg?: string,
  opts: RunHookOptions = {},
): Promise<void> {
  // Hooks must never block or fail Claude Code on internal errors. Wrap everything.
  const hookStartMs = opts.hookStartMs ?? Date.now();
  const readInput = opts.readStdin ?? readStdin;
  const writeOutput = opts.writeStdout ?? ((s: string) => process.stdout.write(s));
  try {
    const cfg = readConfig();
    const raw = await readInput();
    if (!raw.trim()) return;
    const input = JSON.parse(raw) as ClaudeCodeHookInput;

    // Cursor runs Claude Code hooks from ~/.claude/settings.json too
    // ("Third-party imports", on by default). Those payloads carry
    // cursor_version. Record them as Cursor, or skip them when the native
    // Cursor hooks are installed so nothing is captured twice.
    if (isCursorPayload(input)) {
      if (!isCapturePaused(cfg) && !nativeCursorHooksInstalled()) {
        recordCursorHook(eventArg, input as never);
      }
      return;
    }

    const installedTimeoutS = getInstalledPreExecTimeoutS(cfg, "claude");
    const hookDeadlineMs = computeHookDeadlineMs(installedTimeoutS, hookStartMs);
    const result = await handleClaudeHookInput(eventArg, input, {
      config: cfg,
      hookDeadlineMs,
      installedTimeoutS,
    });
    if (result.stdout) {
      writeOutput(result.stdout + "\n");
    }
  } catch (err) {
    logError(err);
  }
}
