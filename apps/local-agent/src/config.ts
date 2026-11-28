import { readFileSync, writeFileSync, existsSync, chmodSync } from "node:fs";
import { configPath, ensureAgentreelDir } from "./paths.js";
import { DEFAULT_HOOK_TIMEOUT_S, type HookHost } from "./policy/types.js";

export type HostnameMode = "plain" | "hash" | "omit";

export interface InstalledHookTimeouts {
  claude?: number;
  cursor?: number;
}

export interface AgentConfig {
  apiKey?: string;
  apiBaseUrl: string;
  workspaceId?: string;
  orgName?: string;
  orgSlug?: string;
  installedAt?: number;
  hooksInstalled?: boolean;
  /** Pre-exec hook timeout (seconds) recorded by `agentreel init` per host. */
  installedHookTimeouts?: InstalledHookTimeouts;
  /** When true, hooks + watcher no-op (don't capture). Toggled via
   *  `agentreel pause` / `agentreel resume`. Kept here so the state
   *  survives shell exits — pausing for an evening should hold until
   *  the user resumes, not until reboot. */
  paused?: boolean;
  pausedAt?: number;
  /** How the machine name is recorded on sessions: "plain" (default),
   *  "hash" (salted SHA-256, stable per install) or "omit". */
  hostnameMode?: HostnameMode;
  /** Daemon heartbeat choice. `true` opts a personal install in, `false` opts
   *  out. Unset means the default: on only when linked to an org workspace.
   *  `AGENTREEL_HEARTBEAT=0` always wins. See docs/heartbeat.md. */
  heartbeat?: boolean;
  /** Set false to stop recording who/where (user, host, git) entirely. */
  attribution?: boolean;
  /** Random per-install salt used when hostnameMode is "hash". */
  installSalt?: string;
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
  if (!existsSync(configPath())) return { ...DEFAULT };
  try {
    const raw = readFileSync(configPath(), "utf8");
    return { ...DEFAULT, ...JSON.parse(raw) };
  } catch {
    return { ...DEFAULT };
  }
}

/**
 * Returns the recorded pre-exec hook timeout (seconds) for a host, or null if
 * init has not recorded one yet (e.g. hooks installed by an older agent).
 */
export function getRecordedPreExecTimeoutS(
  cfg: AgentConfig,
  host: HookHost,
): number | null {
  const val = cfg.installedHookTimeouts?.[host];
  if (typeof val === "number" && Number.isFinite(val) && val > 0) {
    return val;
  }
  return null;
}

/**
 * Returns the effective installed pre-exec hook timeout (seconds) for a host.
 * Missing values default to 5s (the legacy pre-C3 hook timeout).
 */
export function getInstalledPreExecTimeoutS(
  cfg: AgentConfig,
  host: HookHost,
): number {
  return getRecordedPreExecTimeoutS(cfg, host) ?? DEFAULT_HOOK_TIMEOUT_S;
}

export function writeConfig(cfg: AgentConfig): void {
  ensureAgentreelDir();
  // mode 0o600 — config.json holds the API key; only the owning user
  // should ever be able to read it. chmod after write to be sure even
  // if the file already existed with looser perms.
  writeFileSync(configPath(), JSON.stringify(cfg, null, 2) + "\n", {
    encoding: "utf8",
    mode: 0o600,
  });
  try {
    chmodSync(configPath(), 0o600);
  } catch {
    // Non-Unix or filesystem without mode bits — best effort.
  }
}
