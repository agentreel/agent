/**
 * Builds the command string installed into Claude Code and Cursor hook files,
 * including the managed pack (src/managed/pack.ts).
 *
 * Every installed hook command starts by removing NODE_OPTIONS from the
 * environment of the process that runs AgentReel:
 *
 *   POSIX:   env -u NODE_OPTIONS <prefix> <subcommand> <event>
 *   Windows: cmd /d /s /c "set NODE_OPTIONS=&& <prefix> <subcommand> <event>"
 *
 * This is the only place the preload bypass can be closed. Node applies
 * NODE_OPTIONS (--require, -r, --import, --loader) before any application
 * code runs, so nothing inside the AgentReel process can stop a preload from
 * running, and a preload can `delete process.env.NODE_OPTIONS` to blind the
 * in-process check (see policy/node-options-runtime.ts, which is detection
 * only). Scrubbing in the command, in a program that is not Node, means the
 * preload never loads.
 *
 * Failure is closed: if `env` (or `cmd`) cannot be started, the hook command
 * fails. Claude PreToolUse entries carry `onFailure: "block"` and Cursor
 * pre-exec entries carry `failClosed: true`, so the tool call is denied.
 */

export const SCRUBBED_ENV_VAR = "NODE_OPTIONS";

const POSIX_WRAPPER = `env -u ${SCRUBBED_ENV_VAR} `;
const WINDOWS_WRAPPER_HEAD = `cmd /d /s /c "set ${SCRUBBED_ENV_VAR}=&& `;

export type HookPlatform = NodeJS.Platform;

/** `<prefix> <subcommand> <event>` wrapped so NODE_OPTIONS is dropped first. */
export function buildHookCommand(
  prefix: string,
  subcommand: string,
  event: string,
  platform: HookPlatform = process.platform,
): string {
  const inner = `${prefix} ${subcommand} ${event}`;
  if (isScrubbedHookCommand(inner)) return inner;
  return platform === "win32"
    ? `${WINDOWS_WRAPPER_HEAD}${inner}"`
    : `${POSIX_WRAPPER}${inner}`;
}

/** True when the command starts by dropping NODE_OPTIONS (either platform form). */
export function isScrubbedHookCommand(command: string): boolean {
  const c = command.trimStart();
  return c.startsWith(POSIX_WRAPPER) || c.startsWith(WINDOWS_WRAPPER_HEAD);
}

/**
 * The command without the scrub wrapper, so callers that look for the hook
 * binary (self-protect, managed path checks) see the program path first.
 * Commands that are not wrapped are returned unchanged.
 */
export function stripHookScrubWrapper(command: string): string {
  const c = command.trimStart();
  if (c.startsWith(POSIX_WRAPPER)) return c.slice(POSIX_WRAPPER.length);
  if (c.startsWith(WINDOWS_WRAPPER_HEAD)) {
    const rest = c.slice(WINDOWS_WRAPPER_HEAD.length);
    return rest.endsWith('"') ? rest.slice(0, -1) : rest;
  }
  return command;
}
