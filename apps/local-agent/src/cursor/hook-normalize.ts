import type { EventType } from "@agentreel/shared-types";

/**
 * Cursor agent hooks (`~/.cursor/hooks.json`, Cursor 1.7+; postToolUse and
 * friends in 2.x). Payload shapes follow https://cursor.com/docs/agent/hooks
 * (see test/fixtures/cursor-hooks/README.md for the exact fields we rely on).
 *
 * We normalize every hook into the same event vocabulary the Claude Code
 * hooks use (tool_use_pre / tool_use_post with tool_name / tool_input / tool_response)
 * so the replay renders both the same way. The original hook name is kept in
 * `cursor_hook` so the viewer can de-duplicate overlapping hooks.
 */

/** Pre-execution hooks that can enforce policy (block or require_approval). */
export const CURSOR_HOOK_SUBCOMMAND = "cursor-hook";

export const CURSOR_PRE_EXEC_HOOK_EVENTS = [
  "preToolUse",
  "beforeShellExecution",
  "beforeMCPExecution",
  "beforeReadFile",
] as const;

export type CursorPreExecHookEvent = (typeof CURSOR_PRE_EXEC_HOOK_EVENTS)[number];

/** Hooks `agentreel init` installs in ~/.cursor/hooks.json. */
export const CURSOR_HOOK_EVENTS = [
  "sessionStart",
  "sessionEnd",
  "beforeSubmitPrompt",
  "preToolUse",
  "beforeShellExecution",
  "beforeMCPExecution",
  "beforeReadFile",
  "postToolUse",
  "postToolUseFailure",
  "afterShellExecution",
  "afterMCPExecution",
  "afterFileEdit",
  "subagentStop",
  "stop",
] as const;

export interface CursorHookInput {
  hook_event_name?: string;
  conversation_id?: string;
  session_id?: string;
  generation_id?: string;
  model?: string;
  model_id?: string;
  cursor_version?: string;
  workspace_roots?: string[];
  transcript_path?: string | null;
  cwd?: string;
  // tool hooks
  tool_name?: string;
  tool_input?: unknown;
  tool_output?: unknown;
  tool_use_id?: string;
  duration?: number;
  error_message?: string;
  failure_type?: string;
  is_interrupt?: boolean;
  // shell / mcp
  command?: string;
  output?: string;
  sandbox?: boolean;
  mcp_server_name?: string;
  mcp_server_url?: string;
  url?: string;
  result_json?: unknown;
  // files
  file_path?: string;
  content?: string;
  edits?: Array<{ old_string?: string; new_string?: string }>;
  // prompt
  prompt?: string;
  attachments?: Array<{ type?: string; file_path?: string }>;
  // lifecycle
  status?: string;
  loop_count?: number;
  reason?: string;
  duration_ms?: number;
  final_status?: string;
  composer_mode?: string;
  is_background_agent?: boolean;
  subagent_type?: string;
  task?: string;
  description?: string;
  summary?: string;
  tool_call_count?: number;
  modified_files?: string[];
}

export interface NormalizedCursorEvent {
  sessionId: string;
  type: EventType;
  ts: number;
  cwd?: string;
  payload: Record<string, unknown>;
  /** Hook marks the end of a turn/session: refresh git HEAD. */
  turnEnd: boolean;
  sessionEnd: boolean;
}

export interface CursorPermissionDecision {
  permission: "allow" | "deny";
  user_message?: string;
  agent_message?: string;
}

/** Strings above this are cut so one huge Read/command output can't bloat the queue. */
export const MAX_FIELD_CHARS = 16_000;

const NAME_ALIASES: Record<string, string> = {
  sessionstart: "sessionStart",
  sessionend: "sessionEnd",
  beforesubmitprompt: "beforeSubmitPrompt",
  userpromptsubmit: "beforeSubmitPrompt",
  pretooluse: "preToolUse",
  beforeshellexecution: "beforeShellExecution",
  beforemcpexecution: "beforeMCPExecution",
  beforereadfile: "beforeReadFile",
  posttooluse: "postToolUse",
  posttoolusefailure: "postToolUseFailure",
  aftershellexecution: "afterShellExecution",
  aftermcpexecution: "afterMCPExecution",
  afterfileedit: "afterFileEdit",
  subagentstop: "subagentStop",
  stop: "stop",
};

const PRE_EXEC_SET = new Set<string>(CURSOR_PRE_EXEC_HOOK_EVENTS);

/** Accept Cursor names, Claude-style names (third-party import) and any casing. */
export function canonicalHookName(name: string | undefined): string | undefined {
  if (!name) return undefined;
  return NAME_ALIASES[name.toLowerCase()] ?? name;
}

export function isCursorPreExecHook(hook: string | undefined): boolean {
  const canonical = canonicalHookName(hook);
  return canonical !== undefined && PRE_EXEC_SET.has(canonical);
}

export function cursorSessionId(input: CursorHookInput): string {
  const id = input.conversation_id ?? input.session_id;
  return id ? `cursor-${id}` : "cursor-unknown";
}

export function cursorCwd(input: CursorHookInput, env: NodeJS.ProcessEnv = process.env): string | undefined {
  return input.cwd || input.workspace_roots?.[0] || env.CURSOR_PROJECT_DIR || undefined;
}

export function parseMaybeJson(v: unknown): unknown {
  if (typeof v !== "string") return v;
  const t = v.trim();
  if (!(t.startsWith("{") || t.startsWith("["))) return v;
  try {
    return JSON.parse(t);
  } catch {
    return v;
  }
}

/**
 * A hook payload's command as a string. Arrays (argv style) are joined with
 * spaces, and any other non-string value is serialized, so a malformed
 * command still reaches the rules instead of being skipped.
 */
export function coerceCommand(v: unknown): string | undefined {
  if (v === undefined || v === null) return undefined;
  if (typeof v === "string") return v;
  if (Array.isArray(v)) return v.map((x) => (typeof x === "string" ? x : JSON.stringify(x))).join(" ");
  try {
    return JSON.stringify(v);
  } catch {
    return String(v);
  }
}

export function clip(v: unknown, max = MAX_FIELD_CHARS): unknown {
  if (typeof v === "string") {
    return v.length > max ? `${v.slice(0, max)}\n… [truncated ${v.length - max} chars]` : v;
  }
  if (Array.isArray(v)) return v.map((x) => clip(x, max));
  if (v && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v)) out[k] = clip(x, max);
    return out;
  }
  return v;
}

/** Cursor tool inputs name the path differently per tool. */
function withFilePath(input: unknown): unknown {
  if (!input || typeof input !== "object" || Array.isArray(input)) return input;
  const ti = input as Record<string, unknown>;
  if (typeof ti.file_path === "string") return ti;
  const p = [ti.target_file, ti.path, ti.filePath, ti.file].find((x): x is string => typeof x === "string");
  return p ? { ...ti, file_path: p } : ti;
}

export function normalizeCursorHook(
  eventArg: string | undefined,
  input: CursorHookInput,
  now: number = Date.now(),
  env: NodeJS.ProcessEnv = process.env,
): NormalizedCursorEvent | null {
  const hook = canonicalHookName(input.hook_event_name) ?? canonicalHookName(eventArg);
  if (!hook) return null;
  const sessionId = cursorSessionId(input);
  const cwd = cursorCwd(input, env);
  const base = {
    cursor_hook: hook,
    source: "cursor-hooks",
    ...(input.generation_id ? { generation_id: input.generation_id } : {}),
    ...(input.model ? { model: input.model } : {}),
    ...(cwd ? { cwd } : {}),
  };
  const ev = (type: EventType, payload: Record<string, unknown>, extra: Partial<NormalizedCursorEvent> = {}) =>
    ({
      sessionId,
      type,
      ts: now,
      cwd,
      payload: clip({ ...base, ...payload }) as Record<string, unknown>,
      turnEnd: false,
      sessionEnd: false,
      ...extra,
    }) satisfies NormalizedCursorEvent;

  switch (hook) {
    case "sessionStart":
      return ev("session_start", {
        composer_mode: input.composer_mode,
        is_background_agent: input.is_background_agent,
      });
    case "sessionEnd":
      return ev(
        "session_end",
        {
          reason: input.reason,
          final_status: input.final_status,
          duration_ms: input.duration_ms,
          error_message: input.error_message,
        },
        { turnEnd: true, sessionEnd: true },
      );
    case "beforeSubmitPrompt":
      return ev("user_prompt_submit", {
        prompt: input.prompt ?? "",
        // Paths only: never copy attached file contents.
        attachments: (input.attachments ?? []).map((a) => ({ type: a.type, file_path: a.file_path })),
      });
    case "preToolUse":
      return ev("tool_use_pre", {
        tool_name: input.tool_name,
        tool_use_id: input.tool_use_id,
        tool_input: withFilePath(parseMaybeJson(input.tool_input)),
      });
    case "beforeShellExecution":
      return ev("tool_use_pre", {
        tool_name: "Shell",
        tool_input: { command: input.command ?? "", cwd },
      });
    case "beforeMCPExecution":
      return ev("tool_use_pre", {
        tool_name: `MCP:${input.tool_name ?? "unknown"}`,
        mcp_server_name: input.mcp_server_name,
        ...(input.mcp_server_url || input.url ? { mcp_server_url: input.mcp_server_url ?? input.url } : {}),
        tool_input: parseMaybeJson(input.tool_input),
      });
    case "beforeReadFile":
      return ev("tool_use_pre", {
        tool_name: "Read",
        // Path only: never copy file contents.
        tool_input: { file_path: input.file_path },
      });
    case "postToolUse":
      return ev("tool_use_post", {
        tool_name: input.tool_name,
        tool_use_id: input.tool_use_id,
        tool_input: withFilePath(parseMaybeJson(input.tool_input)),
        tool_response: parseMaybeJson(input.tool_output),
        duration_ms: input.duration,
      });
    case "postToolUseFailure":
      return ev("tool_use_post", {
        tool_name: input.tool_name,
        tool_use_id: input.tool_use_id,
        tool_input: withFilePath(parseMaybeJson(input.tool_input)),
        tool_response: {
          is_error: true,
          error: input.error_message,
          failure_type: input.failure_type,
          interrupted: input.is_interrupt === true,
        },
        duration_ms: input.duration,
      });
    case "afterShellExecution":
      return ev("tool_use_post", {
        tool_name: "Shell",
        tool_input: { command: input.command ?? "", cwd },
        tool_response: { output: input.output ?? "" },
        duration_ms: input.duration,
        sandbox: input.sandbox,
      });
    case "afterMCPExecution":
      return ev("tool_use_post", {
        tool_name: `MCP:${input.tool_name ?? "unknown"}`,
        mcp_server_name: input.mcp_server_name,
        ...(input.mcp_server_url || input.url ? { mcp_server_url: input.mcp_server_url ?? input.url } : {}),
        tool_input: parseMaybeJson(input.tool_input),
        tool_response: parseMaybeJson(input.result_json),
        duration_ms: input.duration,
      });
    case "afterFileEdit":
      return ev("tool_use_post", {
        tool_name: "Edit",
        tool_input: {
          file_path: input.file_path,
          edits: (input.edits ?? []).map((e) => ({ old_string: e.old_string ?? "", new_string: e.new_string ?? "" })),
        },
      });
    case "subagentStop":
      return ev("subagent_stop", {
        subagent_type: input.subagent_type,
        status: input.status,
        task: input.task,
        description: input.description,
        duration_ms: input.duration_ms,
        tool_call_count: input.tool_call_count,
        modified_files: input.modified_files,
      });
    case "stop":
      return ev("stop", { status: input.status, loop_count: input.loop_count }, { turnEnd: true });
    default:
      return null;
  }
}

/** What to print on stdout for Cursor hooks. */
export function cursorHookResponse(
  hook: string | undefined,
  decision?: CursorPermissionDecision,
): string {
  const canonical = canonicalHookName(hook);
  if (canonical === "beforeSubmitPrompt") return JSON.stringify({ continue: true });
  if (isCursorPreExecHook(canonical)) {
    if (!decision) {
      return JSON.stringify({ permission: "allow" });
    }
    const body: Record<string, unknown> = { permission: decision.permission };
    if (decision.user_message) body.user_message = decision.user_message;
    if (decision.agent_message && canonical !== "beforeReadFile") {
      body.agent_message = decision.agent_message;
    }
    return JSON.stringify(body);
  }
  return "{}";
}
