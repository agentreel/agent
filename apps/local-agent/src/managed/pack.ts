/**
 * Enterprise managed-policy pack: pure builders for the system-wide Claude Code
 * managed settings file and the system-wide Cursor hooks file.
 *
 * Nothing here touches the filesystem or the network. `install.ts` does the I/O.
 *
 * Claude Code reads managed settings from:
 *   Linux and WSL: /etc/claude-code/managed-settings.json
 *   macOS:         /Library/Application Support/ClaudeCode/managed-settings.json
 * Cursor reads enterprise hooks from:
 *   Linux and WSL: /etc/cursor/hooks.json
 *   macOS:         /Library/Application Support/Cursor/hooks.json
 */
import { claudeHookTimeoutForEvent, CLAUDE_HOOK_MARKER } from "../hooks/install.js";
import { cursorHookTimeoutForEvent } from "../cursor/hooks-install.js";
import {
  CURSOR_HOOK_EVENTS,
  CURSOR_HOOK_SUBCOMMAND,
  isCursorPreExecHook,
} from "../cursor/hook-normalize.js";
import { DEFAULT_PRE_EXEC_HOOK_TIMEOUT_S } from "../policy/types.js";

export type ManagedPlatform = "linux" | "darwin";

export interface ManagedPaths {
  claudeManagedSettings: string;
  cursorHooks: string;
}

export const MANAGED_PATHS: Record<ManagedPlatform, ManagedPaths> = {
  linux: {
    claudeManagedSettings: "/etc/claude-code/managed-settings.json",
    cursorHooks: "/etc/cursor/hooks.json",
  },
  darwin: {
    claudeManagedSettings: "/Library/Application Support/ClaudeCode/managed-settings.json",
    cursorHooks: "/Library/Application Support/Cursor/hooks.json",
  },
};

/**
 * The Claude Code events `agentreel init` installs in ~/.claude/settings.json.
 * Kept in step with src/hooks/install.ts by test/managed-install.test.ts.
 * Under `allowManagedHooksOnly` the user-level hooks stop running, so the
 * managed file must carry every event or capture breaks.
 */
export const MANAGED_CLAUDE_HOOK_EVENTS = [
  "SessionStart",
  "SessionEnd",
  "UserPromptSubmit",
  "PreToolUse",
  "PostToolUse",
  "Notification",
  "Stop",
  "SubagentStop",
  "PreCompact",
] as const;

const CLAUDE_PRE_EXEC = new Set<string>(["PreToolUse"]);

export const CLAUDE_SETTINGS_SCHEMA_URL = "https://json.schemastore.org/claude-code-settings.json";

export interface ClaudeManagedHookEntry {
  type: "command";
  command: string;
  timeout: number;
  onFailure?: "block";
}

export interface ClaudeManagedHookGroup {
  matcher: string;
  hooks: ClaudeManagedHookEntry[];
  __agentreel: string;
}

export interface CursorManagedHookDef {
  command: string;
  timeout: number;
  failClosed?: true;
}

export interface BuildOptions {
  /** Absolute, root-owned path to the agentreel binary (quoted if it has spaces). */
  hookCommand: string;
  preExecTimeoutS?: number;
}

/** Hook groups for the managed Claude Code file. Pre-exec hooks block on failure. */
export function buildClaudeManagedHooks(opts: BuildOptions): Record<string, ClaudeManagedHookGroup[]> {
  const preExecTimeoutS = opts.preExecTimeoutS ?? DEFAULT_PRE_EXEC_HOOK_TIMEOUT_S;
  const hooks: Record<string, ClaudeManagedHookGroup[]> = {};
  for (const event of MANAGED_CLAUDE_HOOK_EVENTS) {
    const entry: ClaudeManagedHookEntry = {
      type: "command",
      command: `${opts.hookCommand} hook ${event}`,
      timeout: claudeHookTimeoutForEvent(event, preExecTimeoutS),
    };
    // onFailure "block" (Claude Code v2.1.295+) turns a crash, timeout or
    // missing binary into a block instead of a silent allow.
    if (CLAUDE_PRE_EXEC.has(event)) entry.onFailure = "block";
    hooks[event] = [{ matcher: ".*", __agentreel: CLAUDE_HOOK_MARKER, hooks: [entry] }];
  }
  return hooks;
}

/** Hook definitions for the enterprise Cursor file. Pre-exec hooks fail closed. */
export function buildCursorManagedHooks(opts: BuildOptions): Record<string, CursorManagedHookDef[]> {
  const preExecTimeoutS = opts.preExecTimeoutS ?? DEFAULT_PRE_EXEC_HOOK_TIMEOUT_S;
  const hooks: Record<string, CursorManagedHookDef[]> = {};
  for (const event of CURSOR_HOOK_EVENTS) {
    const def: CursorManagedHookDef = {
      command: `${opts.hookCommand} ${CURSOR_HOOK_SUBCOMMAND} ${event}`,
      timeout: cursorHookTimeoutForEvent(event, preExecTimeoutS),
    };
    if (isCursorPreExecHook(event)) def.failClosed = true;
    hooks[event] = [def];
  }
  return hooks;
}

type JsonObject = Record<string, unknown>;

function isObject(v: unknown): v is JsonObject {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function isOurClaudeGroup(g: unknown): boolean {
  return isObject(g) && g.__agentreel === CLAUDE_HOOK_MARKER;
}

function isOurCursorDef(d: unknown): boolean {
  return isObject(d) && typeof d.command === "string" && d.command.includes(` ${CURSOR_HOOK_SUBCOMMAND} `);
}

/**
 * Merge AgentReel's policy into an existing managed-settings.json object.
 * Keeps every key the organization already set, forces the keys this pack
 * owns, and replaces only AgentReel's hook groups. Pure and idempotent:
 * merge(merge(x)) deep-equals merge(x).
 */
export function mergeClaudeManagedSettings(existing: JsonObject, opts: BuildOptions): JsonObject {
  const out: JsonObject = { $schema: CLAUDE_SETTINGS_SCHEMA_URL, ...existing };

  // Only managed hooks run: the agent cannot add, edit or disable its own hooks
  // through user, project or local settings.
  out.allowManagedHooksOnly = true;

  const permissions = isObject(out.permissions) ? { ...out.permissions } : {};
  permissions.disableBypassPermissionsMode = "disable";
  out.permissions = permissions;

  // OS sandbox for Bash, forced on, no fallback and no unsandboxed retry.
  const sandbox = isObject(out.sandbox) ? { ...out.sandbox } : {};
  sandbox.enabled = true;
  sandbox.failIfUnavailable = true;
  sandbox.allowUnsandboxedCommands = false;
  out.sandbox = sandbox;

  const ours = buildClaudeManagedHooks(opts);
  const hooks: JsonObject = isObject(out.hooks) ? { ...out.hooks } : {};
  for (const [event, groups] of Object.entries(ours)) {
    const current = Array.isArray(hooks[event]) ? (hooks[event] as unknown[]) : [];
    hooks[event] = [...current.filter((g) => !isOurClaudeGroup(g)), ...groups];
  }
  out.hooks = hooks;
  return out;
}

/** Merge AgentReel's hooks into an existing enterprise Cursor hooks.json object. */
export function mergeCursorManagedHooks(existing: JsonObject, opts: BuildOptions): JsonObject {
  const out: JsonObject = { version: 1, ...existing };
  const ours = buildCursorManagedHooks(opts);
  const hooks: JsonObject = isObject(out.hooks) ? { ...out.hooks } : {};
  for (const [event, defs] of Object.entries(ours)) {
    const current = Array.isArray(hooks[event]) ? (hooks[event] as unknown[]) : [];
    hooks[event] = [...current.filter((d) => !isOurCursorDef(d)), ...defs];
  }
  out.hooks = hooks;
  return out;
}

export function serializeJson(value: unknown): string {
  return JSON.stringify(value, null, 2) + "\n";
}
