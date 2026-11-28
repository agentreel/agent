/**
 * Builds the command string (and, for Claude Code, the `shell` field)
 * installed into Claude Code and Cursor hook files, including the managed
 * pack (src/managed/pack.ts).
 *
 * Every installed hook command starts by removing NODE_OPTIONS and
 * npm_config_node_options from the environment of the process that runs
 * AgentReel, in a program that is not Node:
 *
 *   POSIX / Claude on Windows (shell: "bash"):
 *     env -u NODE_OPTIONS -u npm_config_node_options <prefix> <sub> <event>
 *     When <prefix> is npx or bunx, also pass --node-options= so npm/bun
 *     cannot inject NODE_OPTIONS from ~/.npmrc or npm_config_node_options
 *     after the env -u.
 *
 *   Cursor on Windows (Cursor runs hook commands through PowerShell; it
 *   has no shell field):
 *     Remove-Item Env:NODE_OPTIONS / Env:npm_config_node_options, then
 *     the prefix and subcommand.
 *
 * This is the only place the preload bypass can be closed. Node applies
 * NODE_OPTIONS (--require, -r, --import, --loader) before any application
 * code runs, so nothing inside the AgentReel process can stop a preload,
 * and a preload can `delete process.env.NODE_OPTIONS` to blind the
 * in-process check (see policy/node-options-runtime.ts, which is detection
 * only).
 *
 * Claude Code on Windows defaults to Git Bash for shell-form hooks. A
 * cmd.exe form is mis-tokenized there, so Claude entries set
 * `"shell": "bash"` and use the POSIX env -u form. Cursor's desktop app
 * on Windows runs hooks through PowerShell, so Cursor entries use the
 * PowerShell form.
 *
 * Failure is closed: if `env` (or PowerShell) cannot be started, the hook
 * command fails. Claude PreToolUse entries carry `onFailure: "block"` and
 * Cursor pre-exec entries carry `failClosed: true`, so the tool call is
 * denied.
 */

export const SCRUBBED_ENV_VAR = "NODE_OPTIONS";
export const SCRUBBED_NPM_CONFIG_VAR = "npm_config_node_options";

const POSIX_WRAPPER = `env -u ${SCRUBBED_ENV_VAR} -u ${SCRUBBED_NPM_CONFIG_VAR} -u NPM_CONFIG_NODE_OPTIONS `;
const POSIX_WRAPPER_LEGACY = `env -u ${SCRUBBED_ENV_VAR} `;
const WINDOWS_CMD_WRAPPER_HEAD = `cmd /d /s /c "set ${SCRUBBED_ENV_VAR}=&& `;
/** UTF-8 with no BOM, so non-ASCII hook JSON is not decoded as the system ANSI code page. */
const PS_ENCODING =
  "$OutputEncoding = [Console]::InputEncoding = [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false; ";
const PS_UNSET =
  "Remove-Item Env:NODE_OPTIONS -ErrorAction SilentlyContinue; Remove-Item Env:npm_config_node_options -ErrorAction SilentlyContinue; Remove-Item Env:NPM_CONFIG_NODE_OPTIONS -ErrorAction SilentlyContinue; ";
const PS_UNSET_LEGACY =
  "Remove-Item Env:NODE_OPTIONS -ErrorAction SilentlyContinue; Remove-Item Env:npm_config_node_options -ErrorAction SilentlyContinue; ";
const PS_WRAPPER = `${PS_ENCODING}${PS_UNSET}`;

export type HookPlatform = NodeJS.Platform;
export type HookHost = "claude" | "cursor";
export type ClaudeHookShell = "bash" | "powershell";

export interface HookInvocation {
  command: string;
  /** Claude Code only. Set on Windows so Git Bash (the default) runs the POSIX form. */
  shell?: ClaudeHookShell;
}

export function hookHostForSubcommand(subcommand: string): HookHost {
  return subcommand === "cursor-hook" ? "cursor" : "claude";
}

/** End index of the first prefix token in the original string, including quotes. */
function firstTokenEnd(input: string): number {
  let i = 0;
  while (i < input.length && /\s/.test(input[i]!)) i++;
  let inQuote = false;
  let escaped = false;
  for (; i < input.length; i++) {
    const ch = input[i]!;
    if (escaped) {
      escaped = false;
      continue;
    }
    if (ch === "\\") {
      escaped = true;
      continue;
    }
    if (ch === '"') {
      inQuote = !inQuote;
      continue;
    }
    if (!inQuote && /\s/.test(ch)) break;
  }
  return i;
}

/** Insert `--node-options=` after the first token, keeping that token's quoting. */
export function applyNpxNodeOptionsFlag(prefix: string): string {
  const tokens = tokenize(prefix);
  if (tokens.length === 0) return prefix;
  if (tokens.some((t) => t === "--node-options=" || t.startsWith("--node-options="))) return prefix;
  const base = basename(tokens[0]!);
  if (!/^(npx|bunx)(\.cmd|\.exe)?$/i.test(base)) return prefix;
  const end = firstTokenEnd(prefix);
  return `${prefix.slice(0, end)} --node-options=${prefix.slice(end)}`;
}

function basename(p: string): string {
  const cleaned = p.replace(/\\/g, "/");
  const i = cleaned.lastIndexOf("/");
  return i >= 0 ? cleaned.slice(i + 1) : cleaned;
}

/** Split a hook prefix on whitespace, respecting double quotes and backslash escapes. */
export function tokenize(input: string): string[] {
  const out: string[] = [];
  let cur = "";
  let inQuote = false;
  let escaped = false;
  for (const ch of input) {
    if (escaped) {
      // Keep a backslash that is not escaping a quoting character so
      // Windows paths like "C:\Program Files\..." stay intact. quotePath
      // writes \\ for a real backslash, which still collapses to \.
      if (ch !== "\\" && ch !== '"' && ch !== "$" && ch !== "`") cur += "\\";
      cur += ch;
      escaped = false;
      continue;
    }
    if (ch === "\\") {
      escaped = true;
      continue;
    }
    if (ch === '"') {
      inQuote = !inQuote;
      continue;
    }
    if (!inQuote && /\s/.test(ch)) {
      if (cur) out.push(cur);
      cur = "";
      continue;
    }
    cur += ch;
  }
  if (escaped) cur += "\\";
  if (cur) out.push(cur);
  return out;
}

/** PowerShell single-quote a string. ASCII and typographic single quotes
 * (U+2018, U+2019, U+201A, U+201B) are doubled because PowerShell treats
 * them all as string delimiters. */
export function psSingleQuote(s: string): string {
  return `'${s.replace(/['\u2018\u2019\u201A\u201B]/g, (ch) => ch + ch)}'`;
}

function toPowerShellCommand(prefix: string, subcommand: string, event: string): string {
  const launched = applyNpxNodeOptionsFlag(prefix);
  const tokens = tokenize(launched);
  if (tokens.length === 0) return `${PS_WRAPPER}$input | ${subcommand} ${event}`;
  const base = basename(tokens[0]!);
  const isLauncher = /^(npx|bunx)(\.cmd|\.exe)?$/i.test(base);
  // Launchers stay a command line; everything else is invoked with & and
  // single-quoted so spaces and PowerShell metacharacters are literal.
  // `& node` does not inherit PowerShell's stdin, so pipe `$input` into
  // the process. Run this string with pwsh 7 -File (or a runspace) and
  // a real stdin (the windows-latest job opens the hook JSON as a file
  // descriptor). Windows PowerShell 5.1 hangs when stdin is redirected
  // until the hook timeout (130s for pre-exec), then fails closed.
  // `powershell -Command` and Node `spawnSync` `input` hang too.
  const head = isLauncher
    ? tokens.map((t) => (/^[A-Za-z0-9_./:=@-]+$/.test(t) ? t : psSingleQuote(t))).join(" ")
    : tokens.map((t, i) => (i === 0 ? `& ${psSingleQuote(t)}` : psSingleQuote(t))).join(" ");
  return `${PS_WRAPPER}$input | ${head} ${subcommand} ${event}`;
}

function toPosixCommand(prefix: string, subcommand: string, event: string): string {
  const inner = `${applyNpxNodeOptionsFlag(prefix)} ${subcommand} ${event}`;
  if (isScrubbedHookCommand(inner)) return inner;
  return `${POSIX_WRAPPER}${inner}`;
}

/**
 * The command (and optional Claude `shell` field) installed for one hook
 * event. `host` defaults from the subcommand (`cursor-hook` -> cursor).
 */
export function buildHookInvocation(
  prefix: string,
  subcommand: string,
  event: string,
  platform: HookPlatform = process.platform,
  host: HookHost = hookHostForSubcommand(subcommand),
): HookInvocation {
  if (platform === "win32" && host === "cursor") {
    return { command: toPowerShellCommand(prefix, subcommand, event) };
  }
  // Claude on Windows uses Git Bash by default; set shell: "bash" so a
  // machine without Git Bash does not silently fall back to PowerShell and
  // misread the POSIX form. PreToolUse carries onFailure: "block", so a
  // missing bash fails closed.
  const command = toPosixCommand(prefix, subcommand, event);
  if (platform === "win32" && host === "claude") {
    return { command, shell: "bash" };
  }
  return { command };
}

/** `<prefix> <subcommand> <event>` wrapped so NODE_OPTIONS is dropped first. */
export function buildHookCommand(
  prefix: string,
  subcommand: string,
  event: string,
  platform: HookPlatform = process.platform,
  host: HookHost = hookHostForSubcommand(subcommand),
): string {
  return buildHookInvocation(prefix, subcommand, event, platform, host).command;
}

function isPowerShellScrub(command: string): boolean {
  const c = command.replace(/^\s+/, "");
  return (
    c.startsWith(PS_ENCODING) &&
    c.includes("UTF8Encoding") &&
    c.includes("Remove-Item Env:NODE_OPTIONS") &&
    c.includes("Remove-Item Env:npm_config_node_options")
  );
}

function isPosixScrub(command: string): boolean {
  const c = command.trimStart();
  // Must drop NODE_OPTIONS, npm_config_node_options, and the uppercase
  // NPM_CONFIG_NODE_OPTIONS form. Legacy wrappers without the uppercase
  // unset are not enough on case-sensitive hosts.
  return c.startsWith(POSIX_WRAPPER);
}

function isNpxPrefixCommand(command: string): boolean {
  const tokens = tokenize(stripHookScrubWrapper(command));
  const base = tokens[0] ? basename(tokens[0]) : "";
  return /^(npx|bunx)(\.cmd|\.exe)?$/i.test(base);
}

function hasNodeOptionsFlag(command: string): boolean {
  return tokenize(stripHookScrubWrapper(command)).some(
    (t) => t === "--node-options=" || t.startsWith("--node-options="),
  );
}

/** True when the command drops NODE_OPTIONS and npm_config_node_options first. */
export function isScrubbedHookCommand(command: string): boolean {
  if (!isPosixScrub(command) && !isPowerShellScrub(command)) return false;
  if (isNpxPrefixCommand(command) && !hasNodeOptionsFlag(command)) return false;
  return true;
}

/**
 * The command without the scrub wrapper, so callers that look for the hook
 * binary (self-protect, managed path checks) see the program path first.
 * Commands that are not wrapped are returned unchanged.
 */
export function stripHookScrubWrapper(command: string): string {
  const raw = command.trimStart();
  if (raw.startsWith(POSIX_WRAPPER)) return raw.slice(POSIX_WRAPPER.length);
  if (raw.startsWith(`env -u ${SCRUBBED_ENV_VAR} -u ${SCRUBBED_NPM_CONFIG_VAR} `)) {
    return raw.slice(`env -u ${SCRUBBED_ENV_VAR} -u ${SCRUBBED_NPM_CONFIG_VAR} `.length);
  }
  if (raw.startsWith(`env -u ${SCRUBBED_NPM_CONFIG_VAR} -u ${SCRUBBED_ENV_VAR} `)) {
    return raw.slice(`env -u ${SCRUBBED_NPM_CONFIG_VAR} -u ${SCRUBBED_ENV_VAR} `.length);
  }
  if (raw.startsWith(POSIX_WRAPPER_LEGACY)) return raw.slice(POSIX_WRAPPER_LEGACY.length);
  if (raw.startsWith(WINDOWS_CMD_WRAPPER_HEAD)) {
    const rest = raw.slice(WINDOWS_CMD_WRAPPER_HEAD.length);
    return rest.endsWith('"') ? rest.slice(0, -1) : rest;
  }
  let rest = raw;
  if (rest.startsWith(PS_ENCODING)) rest = rest.slice(PS_ENCODING.length);
  if (rest.startsWith(PS_UNSET) || rest.startsWith(PS_UNSET_LEGACY)) {
    const head = rest.startsWith(PS_UNSET) ? PS_UNSET : PS_UNSET_LEGACY;
    return rest
      .slice(head.length)
      .replace(/^\$input\s*\|\s*/, "")
      .replace(/^&\s+/, "");
  }
  return command;
}
