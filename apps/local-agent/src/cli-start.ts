import { writeSync } from "node:fs";
import { claudeDenyForEvent } from "./hooks/claude-deny.js";
import {
  canonicalHookName,
  CURSOR_HOOK_EVENTS,
  cursorHookResponse,
  isCursorPreExecHook,
} from "./cursor/hook-normalize.js";
import {
  logRuntimeSelf005,
  runtimeSelf005Message,
  runtimeSelfCheckViolation,
  type EnvNodeOptionsEnforceDeps,
} from "./policy/node-options-runtime.js";

export interface StartDeps extends EnvNodeOptionsEnforceDeps {
  /** Arguments after `node script`; defaults to `process.argv.slice(2)`. */
  argv?: readonly string[];
  writeStdout?: (text: string) => void;
  writeStderr?: (text: string) => void;
}

/** Exit code for a blocked hook call. Claude Code and Cursor both read 2 as "block". */
export const HOOK_DENY_EXIT_CODE = 2;

function writeFd(fd: 1 | 2, text: string): void {
  try {
    // Synchronous, so the deny is on the pipe before process.exit.
    writeSync(fd, text);
  } catch {
    (fd === 1 ? process.stdout : process.stderr).write(text);
  }
}

/** `hook <Event>` or `cursor-hook <event>` from the argument list, else null. */
function hookInvocation(argv: readonly string[]): { sub: "hook" | "cursor-hook"; event?: string } | null {
  const positional = argv.filter((a) => !a.startsWith("-"));
  const sub = positional[0];
  if (sub !== "hook" && sub !== "cursor-hook") return null;
  return { sub, ...(positional[1] !== undefined ? { event: positional[1] } : {}) };
}

/**
 * CLI entry: fail closed on a disallowed process NODE_OPTIONS or a preload
 * flag in execArgv, then load the rest of the CLI.
 *
 * Detection only: a preload that deletes NODE_OPTIONS runs before this and
 * hides the value. The installed hook commands scrub NODE_OPTIONS before Node
 * starts (hooks/hook-command.ts); this is the second layer.
 *
 * `hook` and `cursor-hook` must not just exit 1 with nothing printed: Claude
 * Code treats a non-2 exit as non-blocking, and Cursor needs its own shape.
 * For those the entry writes the host's deny JSON on stdout, the reason on
 * stderr, and exits 2. Events with no deny shape (Claude lifecycle events,
 * Cursor capture-only hooks) get the stderr line and exit 1, as before.
 *
 * This code runs before commander, telemetry, hooks and the database load.
 * The bundle still evaluates its third-party imports first.
 */
export async function startAgentreelCli(deps: StartDeps = {}): Promise<void> {
  const violation = runtimeSelfCheckViolation(deps);
  if (violation) {
    const hook = hookInvocation(deps.argv ?? process.argv.slice(2));
    logRuntimeSelf005(deps, violation);
    const message = runtimeSelf005Message(violation);
    const out = deps.writeStdout ?? ((t: string) => writeFd(1, t));
    const err = deps.writeStderr ?? ((t: string) => writeFd(2, t));
    const exit = deps.exit ?? ((code: number) => process.exit(code));
    let deny: string | null = null;
    if (!hook) {
      // Not a hook call: a visible failure instead of a silent exit 1.
    } else if (hook.sub === "hook") {
      deny = claudeDenyForEvent(hook.event, message);
    } else {
      const canonical = canonicalHookName(hook.event);
      const known = canonical !== undefined && (CURSOR_HOOK_EVENTS as readonly string[]).includes(canonical);
      // An unknown or missing cursor event fails closed with the pre-exec shape.
      const preExec = !known || isCursorPreExecHook(canonical);
      deny = preExec
        ? cursorHookResponse(known ? canonical : "beforeShellExecution", {
            permission: "deny",
            user_message: message,
            agent_message: message,
          })
        : null;
    }
    err(`agentreel: ${message}\n`);
    if (deny !== null) out(deny + "\n");
    exit(deny !== null ? HOOK_DENY_EXIT_CODE : 1);
    return;
  }
  await import("./cli.js");
}
