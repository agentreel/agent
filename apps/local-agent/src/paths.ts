import { homedir } from "node:os";
import { join } from "node:path";
import { mkdirSync } from "node:fs";

export const HOME = homedir();
export const AGENTREEL_DIR = join(HOME, ".agentreel");
export const DB_PATH = join(AGENTREEL_DIR, "sessions.db");
export const CONFIG_PATH = join(AGENTREEL_DIR, "config.json");
export const QUEUE_DIR = join(AGENTREEL_DIR, "queue");
export const LOG_PATH = join(AGENTREEL_DIR, "agent.log");
export const DAEMON_PID_PATH = join(AGENTREEL_DIR, "daemon.pid");
export const DAEMON_LOG_PATH = join(AGENTREEL_DIR, "daemon.log");

export const CLAUDE_DIR = join(HOME, ".claude");
export const CLAUDE_SETTINGS_PATH = join(CLAUDE_DIR, "settings.json");

export function ensureAgentreelDir(): void {
  mkdirSync(AGENTREEL_DIR, { recursive: true });
  mkdirSync(QUEUE_DIR, { recursive: true });
}
