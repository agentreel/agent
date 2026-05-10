import { readFileSync, writeFileSync, existsSync, chmodSync } from "node:fs";
import { CONFIG_PATH, ensureAgentreelDir } from "./paths.js";

export interface AgentConfig {
  apiKey?: string;
  apiBaseUrl: string;
  workspaceId?: string;
  installedAt?: number;
  hooksInstalled?: boolean;
  /** When true, hooks + watcher no-op (don't capture). Toggled via
   *  `agentreel pause` / `agentreel resume`. Kept here so the state
   *  survives shell exits — pausing for an evening should hold until
   *  the user resumes, not until reboot. */
  paused?: boolean;
  pausedAt?: number;
  schemaVersion: 1;
}

/**
 * The user's explicit decision to skip capture for the current shell:
 *   AGENTREEL_DISABLE=1 claude
 * Or temporarily via:
 *   AGENTREEL_DISABLE=1 npx @agentreel/agent push
 * No state mutation — purely a process-level switch.
 */
export function isCaptureDisabledByEnv(): boolean {
  const v = process.env.AGENTREEL_DISABLE;
  return v === "1" || v === "true" || v === "yes";
}

/** True if capture should be skipped for ANY reason (env or persisted pause). */
export function isCapturePaused(cfg: AgentConfig = readConfig()): boolean {
  return isCaptureDisabledByEnv() || cfg.paused === true;
}

const DEFAULT: AgentConfig = {
  apiBaseUrl: "https://api.agentreel.dev",
  schemaVersion: 1,
};

export function readConfig(): AgentConfig {
  if (!existsSync(CONFIG_PATH)) return { ...DEFAULT };
  try {
    const raw = readFileSync(CONFIG_PATH, "utf8");
    return { ...DEFAULT, ...JSON.parse(raw) };
  } catch {
    return { ...DEFAULT };
  }
}

export function writeConfig(cfg: AgentConfig): void {
  ensureAgentreelDir();
  // mode 0o600 — config.json holds the API key; only the owning user
  // should ever be able to read it. chmod after write to be sure even
  // if the file already existed with looser perms.
  writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2) + "\n", {
    encoding: "utf8",
    mode: 0o600,
  });
  try {
    chmodSync(CONFIG_PATH, 0o600);
  } catch {
    // Non-Unix or filesystem without mode bits — best effort.
  }
}
