import { homedir } from "node:os";
import { join } from "node:path";
import { mkdirSync } from "node:fs";

// Every path is computed on each call, never at import time. os.homedir()
// reads the HOME environment variable, so a test or probe that sets HOME
// after this module was imported still gets its own directory instead of the
// real ~/.agentreel. Do not cache these in module-level constants.
export const homeDir = (): string => homedir();

export const agentreelDir = (): string => join(homeDir(), ".agentreel");
export const dbPath = (): string => join(agentreelDir(), "sessions.db");
export const configPath = (): string => join(agentreelDir(), "config.json");
export const policyPath = (): string => join(agentreelDir(), "policy.json");
export const guardConfigPath = (): string => join(agentreelDir(), "guard-config.json");
export const queueDir = (): string => join(agentreelDir(), "queue");
export const logPath = (): string => join(agentreelDir(), "agent.log");
export const daemonPidPath = (): string => join(agentreelDir(), "daemon.pid");
export const daemonLogPath = (): string => join(agentreelDir(), "daemon.log");

export const claudeDir = (): string => join(homeDir(), ".claude");
export const claudeSettingsPath = (): string => join(claudeDir(), "settings.json");

export const cursorDir = (): string => join(homeDir(), ".cursor");
export const cursorHooksPath = (): string => join(cursorDir(), "hooks.json");

export function ensureAgentreelDir(): void {
  mkdirSync(agentreelDir(), { recursive: true });
  mkdirSync(queueDir(), { recursive: true });
}
