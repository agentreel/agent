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
import { coerceCommand, cursorSessionId, parseMaybeJson } from "../cursor/hook-normalize.js";
import { insertEvent, upsertSession } from "../db.js";
import { logPath, ensureAgentreelDir } from "../paths.js";
import {
  enforcementExpected,
  enforcePreExec,
  failClosedOutcome,
  INTERNAL_ERROR_REASON,
  MALFORMED_INPUT_REASON,
  repoSlugFromRemoteUrl,
  type PreExecDeps,
  type PreExecOutcome,
  type PreExecRequest,
} from "../policy/enforce.js";

export { coerceCommand };
import { computeHookDeadlineMs } from "../policy/types.js";
import { scrubAny } from "../redact/scrubber.js";
import {
  ensureSessionAttribution,
  preExecAttribution,
  recordSessionEndGit,
} from "../session-attribution.js";
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
  // tool_input may arrive as a JSON string; parse it rather than skip it.
  const toolInput = parseMaybeJson(input.tool_input);
  const ti =
    toolInput && typeof toolInput === "object" && !Array.isArray(toolInput)
      ? (toolInput as Record<string, unknown>)
      : undefined;

  const command = coerceCommand(ti?.command);
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
    toolInput,
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

  let stdout: string | null = null;
  let outcome: PreExecOutcome | undefined;

  // Policy check first: no DB write may run before the decision.
  if (type === "tool_use_pre") {
    try {
      const attribution: Attribution | null = capturePaused
        ? null
        : preExecAttribution(sessionId, input.cwd);
      const req = extractClaudePreExecRequest(input, sessionId, ts, attribution);
      outcome = await enforcePreExec(req, deps);
      if (!outcome.permitted && outcome.message) {
        stdout = formatClaudePreToolUseDeny(outcome.message);
      }
    } catch (err) {
      logError(err);
      stdout = null;
      const { expected, policy } = enforcementExpected(deps);
      if (expected) {
        outcome = failClosedOutcome(
          INTERNAL_ERROR_REASON,
          "the policy check failed",
          policy,
          deps.config ?? readConfig(),
        );
        stdout = formatClaudePreToolUseDeny(outcome.message!);
      }
    }
  }

  // Record after the policy decision, and never let a DB error change it.
  // A corrupt or unusable sessions.db used to throw here before
  // enforcePreExec ran, which let blocked commands through.
  if (!capturePaused) {
    try {
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
    } catch (err) {
      logError(err);
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

function isPlainObject(v: unknown): v is object {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * The deny line for a PreToolUse hook whose input we couldn't use, when an
 * enforcing org policy is in effect. Null otherwise (fail open, as before).
 */
export function claudeFailClosedDeny(
  eventArg: string | undefined,
  reason: string,
  what: string,
  deps: PreExecDeps = {},
): string | null {
  if (eventArg !== "PreToolUse") return null;
  const { expected, policy } = enforcementExpected(deps);
  if (!expected) return null;
  let cfg;
  try {
    cfg = deps.config ?? readConfig();
  } catch {
    cfg = {} as NonNullable<PreExecDeps["config"]>;
  }
  logError(new Error(`PreToolUse failing closed (${reason}): ${what}`));
  return formatClaudePreToolUseDeny(failClosedOutcome(reason, what, policy, cfg).message!);
}

/**
 * Cursor runs Claude Code hooks too ("third-party imports"). Those payloads
 * carry cursor_version. When the native Cursor hooks are not installed, this
 * is the only hook that sees the call, so it has to enforce.
 */
async function enforceCursorPayloadOnClaudePath(
  eventArg: string | undefined,
  input: ClaudeCodeHookInput,
  deps: PreExecDeps,
): Promise<string | null> {
  const hookEventName = input.hook_event_name ?? eventArg;
  if (hookEventName !== "PreToolUse") return null;
  try {
    const sessionId = cursorSessionId(input as never);
    const ts = deps.now ? deps.now() : Date.now();
    const req = { ...extractClaudePreExecRequest(input, sessionId, ts, null), tool: "cursor" as const };
    const outcome = await enforcePreExec(req, deps);
    return !outcome.permitted && outcome.message ? formatClaudePreToolUseDeny(outcome.message) : null;
  } catch (err) {
    logError(err);
    return claudeFailClosedDeny("PreToolUse", INTERNAL_ERROR_REASON, "the policy check failed", deps);
  }
}

export async function runHook(
  eventArg?: string,
  opts: RunHookOptions = {},
): Promise<void> {
  // Hooks never block Claude Code on internal errors unless an enforcing org
  // policy is in effect, in which case a PreToolUse hook fails closed.
  const hookStartMs = opts.hookStartMs ?? Date.now();
  const readInput = opts.readStdin ?? readStdin;
  const writeOutput = opts.writeStdout ?? ((s: string) => process.stdout.write(s));
  let wrote = false;
  const write = (line: string) => {
    wrote = true;
    writeOutput(line + "\n");
  };
  try {
    const cfg = readConfig();
    const raw = await readInput();
    let parsed: unknown;
    let parseError = false;
    if (raw.trim()) {
      try {
        parsed = JSON.parse(raw);
      } catch {
        parseError = true;
      }
    }
    if (!isPlainObject(parsed)) {
      const what = parseError
        ? "the hook input is not valid JSON"
        : raw.trim()
          ? "the hook input is not a JSON object"
          : "the hook input is empty";
      const deny = claudeFailClosedDeny(eventArg, MALFORMED_INPUT_REASON, what, { config: cfg });
      if (deny) write(deny);
      return;
    }
    const input = parsed as ClaudeCodeHookInput;

    // Cursor runs Claude Code hooks from ~/.claude/settings.json too
    // ("Third-party imports", on by default). Those payloads carry
    // cursor_version. Enforce them here unless the native Cursor hooks are
    // installed (they enforce), then record them as Cursor.
    if (isCursorPayload(input)) {
      const native = nativeCursorHooksInstalled();
      if (!native) {
        const installedTimeoutS = getInstalledPreExecTimeoutS(cfg, "cursor");
        const deny = await enforceCursorPayloadOnClaudePath(eventArg, input, {
          config: cfg,
          hookDeadlineMs: computeHookDeadlineMs(installedTimeoutS, hookStartMs),
          installedTimeoutS,
        });
        if (deny) write(deny);
      }
      if (!isCapturePaused(cfg) && !native) {
        try {
          recordCursorHook(eventArg, input as never);
        } catch (err) {
          logError(err);
        }
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
      write(result.stdout);
    }
  } catch (err) {
    logError(err);
    if (!wrote) {
      const deny = claudeFailClosedDeny(eventArg, INTERNAL_ERROR_REASON, "the hook failed");
      if (deny) write(deny);
    }
  }
}
