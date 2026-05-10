import { readFileSync, writeFileSync, existsSync, copyFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { CLAUDE_DIR, CLAUDE_SETTINGS_PATH } from "../paths.js";

const HOOK_MARKER = "agentreel:v1";

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

function readSettings(): ClaudeSettings {
  if (!existsSync(CLAUDE_SETTINGS_PATH)) return {};
  const raw = readFileSync(CLAUDE_SETTINGS_PATH, "utf8");
  if (!raw.trim()) return {};
  return JSON.parse(raw) as ClaudeSettings;
}

function backupSettings(): string | null {
  if (!existsSync(CLAUDE_SETTINGS_PATH)) return null;
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const backup = `${CLAUDE_SETTINGS_PATH}.agentreel-backup-${stamp}`;
  copyFileSync(CLAUDE_SETTINGS_PATH, backup);
  return backup;
}

function buildHookEntry(event: string, hookCommandPrefix: string): HookEntry {
  // Final command shape: `<prefix> hook <Event>`. The prefix can be an
  // absolute path to dist/cli.js (global / dev installs) or an `npx -y …`
  // form (when the user ran us via npx and we don't have a stable on-disk
  // location to point Claude Code at).
  return {
    type: "command",
    command: `${hookCommandPrefix} hook ${event}`,
    timeout: 5,
  };
}

export function quotePath(p: string): string {
  return /[\s'"$`\\]/.test(p) ? `"${p.replace(/"/g, '\\"')}"` : p;
}

export interface InstallResult {
  backup: string | null;
  installedEvents: string[];
  hookCommandPrefix: string;
}

export function installClaudeCodeHooks(hookCommandPrefix: string): InstallResult {
  mkdirSync(CLAUDE_DIR, { recursive: true });
  mkdirSync(dirname(CLAUDE_SETTINGS_PATH), { recursive: true });
  const backup = backupSettings();

  const settings = readSettings();
  settings.hooks ??= {};

  for (const event of HOOK_EVENTS) {
    const groups = settings.hooks[event] ?? [];
    // Drop any prior agentreel-managed group so re-running is idempotent.
    const filtered = groups.filter((g) => g.__agentreel !== HOOK_MARKER);
    filtered.push({
      matcher: ".*",
      __agentreel: HOOK_MARKER,
      hooks: [buildHookEntry(event, hookCommandPrefix)],
    });
    settings.hooks[event] = filtered;
  }

  writeFileSync(CLAUDE_SETTINGS_PATH, JSON.stringify(settings, null, 2) + "\n", "utf8");
  return { backup, installedEvents: [...HOOK_EVENTS], hookCommandPrefix };
}

export function uninstallClaudeCodeHooks(): { backup: string | null } {
  if (!existsSync(CLAUDE_SETTINGS_PATH)) return { backup: null };
  const backup = backupSettings();
  const settings = readSettings();
  if (settings.hooks) {
    for (const event of Object.keys(settings.hooks)) {
      const groups = settings.hooks[event] ?? [];
      const remaining = groups.filter((g) => g.__agentreel !== HOOK_MARKER);
      if (remaining.length === 0) delete settings.hooks[event];
      else settings.hooks[event] = remaining;
    }
    if (Object.keys(settings.hooks).length === 0) delete settings.hooks;
  }
  writeFileSync(CLAUDE_SETTINGS_PATH, JSON.stringify(settings, null, 2) + "\n", "utf8");
  return { backup };
}
