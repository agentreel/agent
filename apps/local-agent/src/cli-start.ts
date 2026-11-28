import {
  enforceCliEnvNodeOptions,
  type EnvNodeOptionsEnforceDeps,
} from "./policy/node-options-runtime.js";

/**
 * CLI entry: fail closed on a disallowed process NODE_OPTIONS, then load the
 * rest of the CLI. The check runs before the dynamic import so commander,
 * telemetry, hooks and the database are not loaded first.
 */
export async function startAgentreelCli(deps?: EnvNodeOptionsEnforceDeps): Promise<void> {
  if (enforceCliEnvNodeOptions(deps)) return;
  await import("./cli.js");
}
