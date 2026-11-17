import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { AGENTREEL_DIR } from "../paths.js";
import type { GuardConfig } from "./types.js";

const GUARD_CONFIG_PATH = join(AGENTREEL_DIR, "guard-config.json");

const DEFAULT_CONFIG: GuardConfig = {
  enabled: true,
  policyMode: "warn",
  rules: {},
  allowlists: {
    commands: [],
    paths: [],
    hosts: [],
  },
};

export function readGuardConfig(): GuardConfig {
  if (!existsSync(GUARD_CONFIG_PATH)) {
    return { ...DEFAULT_CONFIG };
  }

  try {
    const raw = readFileSync(GUARD_CONFIG_PATH, "utf8");
    const parsed = JSON.parse(raw) as Partial<GuardConfig>;
    return { ...DEFAULT_CONFIG, ...parsed };
  } catch {
    return { ...DEFAULT_CONFIG };
  }
}

export function writeGuardConfig(config: GuardConfig): void {
  writeFileSync(GUARD_CONFIG_PATH, JSON.stringify(config, null, 2) + "\n", {
    encoding: "utf8",
  });
}

export function updateGuardConfig(
  updates: Partial<GuardConfig>
): GuardConfig {
  const current = readGuardConfig();
  const updated = { ...current, ...updates };
  writeGuardConfig(updated);
  return updated;
}
