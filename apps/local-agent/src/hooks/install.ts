import { readFileSync, writeFileSync, existsSync, copyFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { claudeSettingsPath } from "../paths.js";
import {
  DEFAULT_HOOK_TIMEOUT_S,
  DEFAULT_PRE_EXEC_HOOK_TIMEOUT_S,
} from "../policy/types.js";

export const CLAUDE_HOOK_MARKER = "agentreel:v1";

export const CLAUDE_PRE_EXEC_HOOK_EVENTS = ["PreToolUse"] as const;
const CLAUDE_PRE_EXEC_SET = new Set<string>(CLAUDE_PRE_EXEC_HOOK_EVENTS);

const HOOK_EVENTS = [
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

type HookEntry = {
  type: "command";
  command: string;
  timeout?: number;
};

type HookGroup = {
  matcher?: string;
  hooks: HookEntry[];
  __agentreel?: string;
};

type ClaudeSettings = {
  hooks?: Record<string, HookGroup[]>;
  [key: string]: unknown;
};

function readSettings(settingsPath: string): ClaudeSettings {
  if (!existsSync(settingsPath)) return {};
  const raw = readFileSync(settingsPath, "utf8");
  if (!raw.trim()) return {};
  return JSON.parse(raw) as ClaudeSettings;
}

function backupSettings(settingsPath: string): string | null {
  if (!existsSync(settingsPath)) return null;
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const backup = `${settingsPath}.agentreel-backup-${stamp}`;
  copyFileSync(settingsPath, backup);
  return backup;
}

export function claudeHookTimeoutForEvent(
  event: string,
  preExecTimeoutS: number = DEFAULT_PRE_EXEC_HOOK_TIMEOUT_S,
): number {
  return CLAUDE_PRE_EXEC_SET.has(event) ? preExecTimeoutS : DEFAULT_HOOK_TIMEOUT_S;
}

function buildHookEntry(
  event: string,
  hookCommandPrefix: string,
  preExecTimeoutS: number,
): HookEntry {
  // Final command shape: `<prefix> hook <Event>`.
  // Claude Code settings.json uses `timeout` in seconds.
  return {
    type: "command",
    command: `${hookCommandPrefix} hook ${event}`,
    timeout: claudeHookTimeoutForEvent(event, preExecTimeoutS),
  };
}

export function quotePath(p: string): string {
  return /[\s'"$`\\]/.test(p) ? `"${p.replace(/"/g, '\\"')}"` : p;
}

export interface InstallClaudeHooksOptions {
  settingsPath?: string;
  preExecTimeoutS?: number;
}

export interface InstallResult {
  backup: string | null;
  installedEvents: string[];
  hookCommandPrefix: string;
  preExecTimeoutS: number;
}

export function installClaudeCodeHooks(
  hookCommandPrefix: string,
  opts: InstallClaudeHooksOptions = {},
): InstallResult {
  const settingsPath = opts.settingsPath ?? claudeSettingsPath();
  const preExecTimeoutS = opts.preExecTimeoutS ?? DEFAULT_PRE_EXEC_HOOK_TIMEOUT_S;

  mkdirSync(dirname(settingsPath), { recursive: true });
  const backup = backupSettings(settingsPath);

  const settings = readSettings(settingsPath);
  settings.hooks ??= {};

  for (const event of HOOK_EVENTS) {
    const groups = settings.hooks[event] ?? [];
    // Drop any prior agentreel-managed group so re-running is idempotent.
    const filtered = groups.filter((g) => g.__agentreel !== CLAUDE_HOOK_MARKER);
    filtered.push({
      matcher: ".*",
      __agentreel: CLAUDE_HOOK_MARKER,
      hooks: [buildHookEntry(event, hookCommandPrefix, preExecTimeoutS)],
    });
    settings.hooks[event] = filtered;
  }

  writeFileSync(settingsPath, JSON.stringify(settings, null, 2) + "\n", "utf8");
  return {
    backup,
    installedEvents: [...HOOK_EVENTS],
    hookCommandPrefix,
    preExecTimeoutS,
  };
}

export function uninstallClaudeCodeHooks(
  settingsPath: string = claudeSettingsPath(),
): { backup: string | null } {
  if (!existsSync(settingsPath)) return { backup: null };
  const backup = backupSettings(settingsPath);
  const settings = readSettings(settingsPath);
  if (settings.hooks) {
    for (const event of Object.keys(settings.hooks)) {
      const groups = settings.hooks[event] ?? [];
      const remaining = groups.filter((g) => g.__agentreel !== CLAUDE_HOOK_MARKER);
      if (remaining.length === 0) delete settings.hooks[event];
      else settings.hooks[event] = remaining;
    }
    if (Object.keys(settings.hooks).length === 0) delete settings.hooks;
  }
  writeFileSync(settingsPath, JSON.stringify(settings, null, 2) + "\n", "utf8");
  return { backup };
}

export interface ClaudePreExecHookCheck {
  fileExists: boolean;
  preToolUseInstalled: boolean;
  preToolUseTimeoutS: number | null;
}

export function inspectClaudePreExecHook(
  settingsPath: string = claudeSettingsPath(),
): ClaudePreExecHookCheck {
  if (!existsSync(settingsPath)) {
    return {
      fileExists: false,
      preToolUseInstalled: false,
      preToolUseTimeoutS: null,
    };
  }
  try {
    const settings = readSettings(settingsPath);
    const groups = settings.hooks?.PreToolUse ?? [];
    const ours = groups.find((g) => g.__agentreel === CLAUDE_HOOK_MARKER);
    const entry = ours?.hooks?.[0];
    if (!entry) {
      return {
        fileExists: true,
        preToolUseInstalled: false,
        preToolUseTimeoutS: null,
      };
    }
    return {
      fileExists: true,
      preToolUseInstalled: true,
      preToolUseTimeoutS:
        typeof entry.timeout === "number" && Number.isFinite(entry.timeout)
          ? entry.timeout
          : null,
    };
  } catch {
    return {
      fileExists: true,
      preToolUseInstalled: false,
      preToolUseTimeoutS: null,
    };
  }
}
