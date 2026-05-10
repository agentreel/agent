import { readFileSync, writeFileSync, existsSync, chmodSync } from "node:fs";
import { CONFIG_PATH, ensureAgentreelDir } from "./paths.js";

export interface AgentConfig {
  apiKey?: string;
  apiBaseUrl: string;
  workspaceId?: string;
  installedAt?: number;
  hooksInstalled?: boolean;
  schemaVersion: 1;
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
