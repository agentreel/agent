export type Tool = "claude-code" | "cursor";

export type EventType =
  | "session_start"
  | "session_end"
  | "user_prompt_submit"
  | "tool_use_pre"
  | "tool_use_post"
  | "notification"
  | "stop"
  | "subagent_stop"
  | "pre_compact"
  | "unknown";

export interface AgentEvent {
  id: string;
  sessionId: string;
  tool: Tool;
  type: EventType;
  ts: number;
  cwd?: string;
  payload: unknown;
}

export interface Session {
  id: string;
  tool: Tool;
  startedAt: number;
  endedAt?: number;
  cwd?: string;
  totalCostCents?: number;
  totalTokens?: number;
}

export interface ClaudeCodeHookInput {
  session_id: string;
  transcript_path?: string;
  cwd?: string;
  hook_event_name: string;
  tool_name?: string;
  tool_input?: unknown;
  tool_response?: unknown;
  prompt?: string;
  message?: string;
  source?: string;
  trigger?: string;
  custom_instructions?: string;
  stop_hook_active?: boolean;
}
