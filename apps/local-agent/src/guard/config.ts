import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { guardConfigPath } from "../paths.js";
import type { GuardConfig } from "./types.js";

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
  if (!existsSync(guardConfigPath())) {
    return { ...DEFAULT_CONFIG };
  }

  try {
    const raw = readFileSync(guardConfigPath(), "utf8");
    const parsed = JSON.parse(raw) as Partial<GuardConfig>;
    return { ...DEFAULT_CONFIG, ...parsed };
  } catch {
    return { ...DEFAULT_CONFIG };
  }
}

export function writeGuardConfig(config: GuardConfig): void {
  writeFileSync(guardConfigPath(), JSON.stringify(config, null, 2) + "\n", {
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
