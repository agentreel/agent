import { nanoid } from "nanoid";
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import type { AgentEvent } from "@agentreel/shared-types";
import type { Attribution } from "../attribution.js";
import {
  getInstalledPreExecTimeoutS,
  isCapturePaused,
  readConfig,
} from "../config.js";
import { getSessionAttribution, insertEvent, upsertSession } from "../db.js";
import { applyIgnoreRules } from "../hooks/ignore-payload.js";
import { CURSOR_HOOKS_PATH, LOG_PATH, ensureAgentreelDir } from "../paths.js";
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
import {
  CURSOR_HOOK_SUBCOMMAND,
  canonicalHookName,
  cursorCwd,
  cursorHookResponse,
  cursorSessionId,
  isCursorPreExecHook,
  normalizeCursorHook,
  parseMaybeJson,
  type CursorHookInput,
  type CursorPermissionDecision,
} from "./hook-normalize.js";

export { CURSOR_HOOK_SUBCOMMAND };

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

export function extractCursorPreExecRequest(
  hook: string,
  input: CursorHookInput,
  sessionId: string,
  ts: number,
  attribution?: Attribution | null,
): PreExecRequest {
  const cwd = cursorCwd(input);
  const parsedToolInput = parseMaybeJson(input.tool_input);
  const ti =
    parsedToolInput && typeof parsedToolInput === "object" && !Array.isArray(parsedToolInput)
      ? (parsedToolInput as Record<string, unknown>)
      : undefined;

  const repo = repoSlugFromRemoteUrl(attribution?.git?.remote_url);
  const branch = attribution?.git?.branch_end ?? attribution?.git?.branch_start;
  const member = attribution?.git?.user_email ?? attribution?.os_user;
  const toolUseId = input.tool_use_id ?? input.generation_id;

  if (hook === "beforeShellExecution") {
    return {
      sessionId,
      tool: "cursor",
      toolName: "Shell",
      toolUseId,
      cwd,
      command: input.command,
      toolInput: { command: input.command ?? "", cwd },
      repo,
      branch,
      member,
      ts,
    };
  }

  if (hook === "beforeReadFile") {
    return {
      sessionId,
      tool: "cursor",
      toolName: "Read",
      toolUseId,
      cwd,
      file_path: input.file_path,
      toolInput: { file_path: input.file_path },
      repo,
      branch,
      member,
      ts,
    };
  }

  if (hook === "beforeMCPExecution") {
    const rawName = input.tool_name ?? "unknown";
    const mcpTool =
      input.mcp_server_name && !rawName.includes("__")
        ? `${input.mcp_server_name}__${rawName}`
        : rawName;
    const filePath = [ti?.file_path, ti?.target_file, ti?.path, ti?.filePath, ti?.file].find(
      (v): v is string => typeof v === "string" && v.length > 0,
    );
    return {
      sessionId,
      tool: "cursor",
      toolName: `MCP:${rawName}`,
      toolUseId,
      cwd,
      command: typeof ti?.command === "string" ? ti.command : undefined,
      file_path: filePath,
      url:
        input.mcp_server_url ??
        input.url ??
        (typeof ti?.url === "string" ? ti.url : undefined),
      mcp_tool: mcpTool,
      toolInput: parsedToolInput,
      repo,
      branch,
      member,
      ts,
    };
  }

  // preToolUse
  const toolName = input.tool_name ?? "unknown";
  const filePath = [
    input.file_path,
    ti?.file_path,
    ti?.target_file,
    ti?.path,
    ti?.filePath,
    ti?.file,
  ].find((v): v is string => typeof v === "string" && v.length > 0);
  const command =
    typeof input.command === "string"
      ? input.command
      : typeof ti?.command === "string"
        ? ti.command
        : undefined;
  const url =
    input.mcp_server_url ??
    input.url ??
    (typeof ti?.url === "string" ? ti.url : undefined);
  let mcpTool: string | undefined;
  if (toolName.startsWith("MCP:")) {
    mcpTool = toolName.slice(4);
  } else if (toolName.startsWith("mcp__")) {
    mcpTool = toolName.slice(5);
  }

  return {
    sessionId,
    tool: "cursor",
    toolName,
    toolUseId,
    cwd,
    command,
    file_path: filePath,
    url,
    mcp_tool: mcpTool,
    toolInput: parsedToolInput,
    repo,
    branch,
    member,
    ts,
  };
}

export interface HandleCursorHookResult {
  response: string;
  decision?: CursorPermissionDecision;
  outcome?: PreExecOutcome;
}

export async function handleCursorHookInput(
  eventArg: string | undefined,
  input: CursorHookInput,
  deps: PreExecDeps = {},
): Promise<HandleCursorHookResult> {
  const hook = canonicalHookName(input.hook_event_name) ?? canonicalHookName(eventArg);
  const ts = deps.now ? deps.now() : Date.now();
  const capturePaused = isCapturePaused(deps.config ?? readConfig());
  const sessionId = capturePaused
    ? cursorSessionId(input)
    : (recordCursorHook(eventArg, input, ts) ?? cursorSessionId(input));

  let decision: CursorPermissionDecision | undefined;
  let outcome: PreExecOutcome | undefined;

  if (hook && isCursorPreExecHook(hook)) {
    try {
      let attribution: Attribution | null = null;
      if (!capturePaused) {
        try {
          attribution = getSessionAttribution<Attribution>(sessionId);
        } catch {
          attribution = null;
        }
      }
      const req = extractCursorPreExecRequest(hook, input, sessionId, ts, attribution);
      outcome = await enforcePreExec(req, deps);
      if (!outcome.permitted && outcome.message) {
        decision = {
          permission: "deny",
          user_message: outcome.message,
          agent_message: outcome.message,
        };
      } else {
        decision = { permission: "allow" };
      }
    } catch (err) {
      logError(err);
      decision = { permission: "allow" };
    }
  }

  return {
    response: cursorHookResponse(hook, decision),
    decision,
    outcome,
  };
}

export interface RunCursorHookOptions {
  /** Hook start timestamp in ms (defaults to Date.now(); cli.ts passes process timeOrigin). */
  hookStartMs?: number;
  readStdin?: () => Promise<string>;
  writeStdout?: (text: string) => void;
}

/** `agentreel cursor-hook <event>`: read JSON on stdin, record (unless paused), enforce if pre-exec, answer. */
export async function runCursorHook(
  eventArg?: string,
  opts: RunCursorHookOptions = {},
): Promise<void> {
  const hookStartMs = opts.hookStartMs ?? Date.now();
  const readInput = opts.readStdin ?? readStdin;
  const writeOutput = opts.writeStdout ?? ((s: string) => process.stdout.write(s));
  let hook = canonicalHookName(eventArg);
  let decision: CursorPermissionDecision | undefined;
  try {
    const raw = await readInput().catch(() => "");
    const cfg = readConfig();
    if (raw.trim()) {
      const input = JSON.parse(raw) as CursorHookInput;
      hook = canonicalHookName(input.hook_event_name) ?? hook;
      const installedTimeoutS = getInstalledPreExecTimeoutS(cfg, "cursor");
      const hookDeadlineMs = computeHookDeadlineMs(installedTimeoutS, hookStartMs);
      const handled = await handleCursorHookInput(eventArg, input, {
        config: cfg,
        hookDeadlineMs,
        installedTimeoutS,
      });
      decision = handled.decision;
    }
  } catch (err) {
    logError(err);
    decision = undefined;
  } finally {
    // Always answer, failing open to allow on pre-exec hooks if anything errored.
    writeOutput(cursorHookResponse(hook, decision) + "\n");
  }
}
