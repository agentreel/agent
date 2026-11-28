/**
 * Runtime self-check of the process NODE_OPTIONS value (SELF005).
 *
 * The command-text scanner is a best-effort guard. This module is the
 * backstop on the value Node actually applied to this process: it runs at
 * CLI startup (before any other application module is loaded) and at
 * hook-runner startup (before stdin is read). Unset or empty values pass;
 * allow-listed flags pass; anything else, including unparseable input,
 * fails closed.
 */

import { appendFileSync } from "node:fs";
import { isAllowedNodeOptionsValue } from "./node-options.js";
import { ensureAgentreelDir, logPath } from "../paths.js";

export const RUNTIME_SELF005_RULE = "SELF005";

export const RUNTIME_SELF005_MESSAGE =
  "Blocked by self-protection, SELF005: process NODE_OPTIONS is not on the allow list";

export interface EnvNodeOptionsEnforceDeps {
  /** When omitted, `process.env.NODE_OPTIONS` is read. Pass `undefined` to test unset. */
  value?: string | undefined;
  /** When true, `value` is used even if it is undefined (unset). */
  valueProvided?: boolean;
  log?: (line: string) => void;
  exit?: (code: number) => void;
}

/** True when the effective NODE_OPTIONS value is outside the allow list. */
export function envNodeOptionsIsDisallowed(value: string | undefined): boolean {
  if (value === undefined || value === "") return false;
  return !isAllowedNodeOptionsValue(value.normalize("NFKC"));
}

function defaultLog(line: string): void {
  try {
    ensureAgentreelDir();
    appendFileSync(logPath(), line);
  } catch {
    // never throw from the self-check logger
  }
}

export function logRuntimeSelf005(deps: EnvNodeOptionsEnforceDeps = {}): void {
  const line = `[${new Date().toISOString()}] ${RUNTIME_SELF005_RULE}: process NODE_OPTIONS is not on the allow list\n`;
  (deps.log ?? defaultLog)(line);
}

function effectiveValue(deps: EnvNodeOptionsEnforceDeps): string | undefined {
  if (deps.valueProvided || "value" in deps) return deps.value;
  return process.env.NODE_OPTIONS;
}

/**
 * CLI startup: log and exit non-zero when the process NODE_OPTIONS is
 * disallowed. Returns true when it denied.
 */
export function enforceCliEnvNodeOptions(deps: EnvNodeOptionsEnforceDeps = {}): boolean {
  if (!envNodeOptionsIsDisallowed(effectiveValue(deps))) return false;
  logRuntimeSelf005(deps);
  (deps.exit ?? ((code: number) => process.exit(code)))(1);
  return true;
}

/**
 * Hook-runner startup: log when the process NODE_OPTIONS is disallowed.
 * Returns true when the hook must deny and stop. The caller writes the deny
 * response so Claude and Cursor keep their usual output shape.
 */
export function enforceHookEnvNodeOptions(deps: EnvNodeOptionsEnforceDeps = {}): boolean {
  if (!envNodeOptionsIsDisallowed(effectiveValue(deps))) return false;
  logRuntimeSelf005(deps);
  return true;
}
