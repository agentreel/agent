/**
 * Runtime self-check of the process NODE_OPTIONS value and execArgv (SELF005).
 *
 * DETECTION ONLY. This runs inside the Node process it is checking, and Node
 * applies NODE_OPTIONS (--require, -r, --import, --loader) and execArgv
 * preloads before any application code. A preload can therefore run first,
 * `delete process.env.NODE_OPTIONS`, and leave this check with nothing to
 * see (confirmed on the built bundle for --require, -r and --import). What
 * this check does:
 *
 *  - catches a disallowed NODE_OPTIONS or a preload flag in execArgv that is
 *    still visible when the bundle's own code starts;
 *  - runs before the CLI's commander, telemetry, hook and database code
 *    (the bundle still evaluates its third-party imports, better-sqlite3,
 *    picocolors, ignore and diff, first, so it is not "before anything else");
 *  - turns a visible violation into a visible failure: a nonzero exit, and
 *    for `hook` and `cursor-hook` a deny with exit 2 (see cli-start.ts).
 *
 * What prevents the bypass is the installed hook command, which starts with
 * `env -u NODE_OPTIONS -u npm_config_node_options` (Claude on Windows: the
 * same form with `shell: "bash"`; Cursor on Windows: PowerShell
 * `Remove-Item Env:NODE_OPTIONS` / `Env:npm_config_node_options`). See
 * hooks/hook-command.ts. A preload never loads there, so there is nothing
 * to hide. Hooks installed before that change keep the weaker,
 * detection-only behaviour until `agentreel init` is run again; `agentreel
 * doctor` reports them.
 *
 * Unset or empty NODE_OPTIONS passes; allow-listed flags pass; anything
 * else, including unparseable input, fails closed. This check is always on.
 * It does not depend on an org policy being loaded or enforcing, unlike the
 * command-text SELF rules in self-protect.ts.
 */

import { appendFileSync } from "node:fs";
import { isAllowedNodeOptionsValue } from "./node-options.js";
import { ensureAgentreelDir, logPath } from "../paths.js";

export const RUNTIME_SELF005_RULE = "SELF005";

export const RUNTIME_SELF005_MESSAGE =
  "Blocked by self-protection, SELF005: process NODE_OPTIONS is not on the allow list";

export const RUNTIME_SELF005_EXEC_ARGV_MESSAGE =
  "Blocked by self-protection, SELF005: node was started with a preload or loader flag";

export interface EnvNodeOptionsEnforceDeps {
  /** When omitted, `process.env.NODE_OPTIONS` is read. Pass `undefined` to test unset. */
  value?: string | undefined;
  /** When true, `value` is used even if it is undefined (unset). */
  valueProvided?: boolean;
  /**
   * Node's own flags for this process. Defaults to `process.execArgv`, or to
   * none when `value` is injected (so a unit test of the NODE_OPTIONS path
   * does not inherit the test runner's flags).
   */
  execArgv?: readonly string[];
  log?: (line: string) => void;
  exit?: (code: number) => void;
}

/** True when the effective NODE_OPTIONS value is outside the allow list. */
export function envNodeOptionsIsDisallowed(value: string | undefined): boolean {
  if (value === undefined || value === "") return false;
  return !isAllowedNodeOptionsValue(value.normalize("NFKC"));
}

/**
 * Flags that make Node load code before, or instead of, the script. These
 * are checked by name in execArgv rather than against the NODE_OPTIONS allow
 * list, because ordinary runners add harmless flags (`--conditions`).
 */
const PRELOAD_FLAGS = new Set([
  "--require",
  "-r",
  "--import",
  "--loader",
  "--experimental-loader",
  "--eval",
  "-e",
  "--print",
  "-p",
  "--inspect",
  "--inspect-brk",
  "--inspect-wait",
  "--inspect-port",
]);

function flagName(arg: string): string {
  const eq = arg.indexOf("=");
  const raw = eq >= 0 ? arg.slice(0, eq) : arg;
  return raw.normalize("NFKC").toLowerCase().replace(/_/g, "-");
}

/** True when execArgv carries a preload, loader, eval or inspector flag. */
export function execArgvIsDisallowed(execArgv: readonly string[]): boolean {
  for (const arg of execArgv) {
    if (typeof arg !== "string") return true;
    const name = flagName(arg);
    if (PRELOAD_FLAGS.has(name)) return true;
    // `-rfoo.js` style attached short flag value.
    if (/^-[rep]./.test(name) && !name.startsWith("--")) return true;
  }
  return false;
}

export type RuntimeViolation = "node_options" | "exec_argv";

function injected(deps: EnvNodeOptionsEnforceDeps): boolean {
  return Boolean(deps.valueProvided) || "value" in deps;
}

function effectiveValue(deps: EnvNodeOptionsEnforceDeps): string | undefined {
  if (injected(deps)) return deps.value;
  return process.env.NODE_OPTIONS;
}

function effectiveExecArgv(deps: EnvNodeOptionsEnforceDeps): readonly string[] {
  if (deps.execArgv) return deps.execArgv;
  return injected(deps) ? [] : process.execArgv;
}

/** Which check fails for this process, or null when both pass. */
export function runtimeSelfCheckViolation(
  deps: EnvNodeOptionsEnforceDeps = {},
): RuntimeViolation | null {
  if (envNodeOptionsIsDisallowed(effectiveValue(deps))) return "node_options";
  if (execArgvIsDisallowed(effectiveExecArgv(deps))) return "exec_argv";
  return null;
}

export function runtimeSelf005Message(violation: RuntimeViolation): string {
  return violation === "exec_argv"
    ? RUNTIME_SELF005_EXEC_ARGV_MESSAGE
    : RUNTIME_SELF005_MESSAGE;
}

function defaultLog(line: string): void {
  try {
    ensureAgentreelDir();
    appendFileSync(logPath(), line);
  } catch {
    // never throw from the self-check logger
  }
}

export function logRuntimeSelf005(
  deps: EnvNodeOptionsEnforceDeps = {},
  violation: RuntimeViolation = "node_options",
): void {
  const what =
    violation === "exec_argv"
      ? "node was started with a preload or loader flag"
      : "process NODE_OPTIONS is not on the allow list";
  const line = `[${new Date().toISOString()}] ${RUNTIME_SELF005_RULE}: ${what}\n`;
  (deps.log ?? defaultLog)(line);
}

/**
 * CLI startup: log and exit non-zero when the process NODE_OPTIONS or execArgv
 * is disallowed. Returns true when it denied. `hook` and `cursor-hook` are
 * handled by cli-start.ts first, which emits a host-shaped deny and exit 2.
 */
export function enforceCliEnvNodeOptions(deps: EnvNodeOptionsEnforceDeps = {}): boolean {
  const violation = runtimeSelfCheckViolation(deps);
  if (!violation) return false;
  logRuntimeSelf005(deps, violation);
  (deps.exit ?? ((code: number) => process.exit(code)))(1);
  return true;
}

/**
 * Hook-runner startup: log when the process NODE_OPTIONS or execArgv is
 * disallowed. Returns the violation when the hook must deny and stop, or null.
 * The caller writes the deny response so Claude and Cursor keep their usual
 * output shape. Kept as defense in depth: in the shipped CLI the entry check
 * in cli-start.ts answers first.
 */
export function enforceHookEnvNodeOptions(
  deps: EnvNodeOptionsEnforceDeps = {},
): RuntimeViolation | null {
  const violation = runtimeSelfCheckViolation(deps);
  if (!violation) return null;
  logRuntimeSelf005(deps, violation);
  return violation;
}
