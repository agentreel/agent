import { readFileSync } from "node:fs";
import { systemCursorHooksPath } from "../cursor/hooks-install.js";
import { hookCommandBinaryPath } from "../managed/hook-path.js";
import { claudeSettingsPath, cursorHooksPath } from "../paths.js";

/**
 * Self-protection: while an org policy is enforcing, block the agent from
 * turning AgentReel off. These checks are not Guard rules (the Guard catalog
 * stays at 31) and a policy can't disable them. They cover:
 *
 * - SELF001: shell writes to AgentReel state (`~/.agentreel/**`), Claude Code
 *   settings (`.claude/settings.json`, `.claude/settings.local.json`), Cursor
 *   hooks (`.cursor/hooks.json`), and the managed files
 *   (`/etc/claude-code/managed-settings.json`, `/etc/cursor/hooks.json`, and
 *   `/etc/cursor/`, `/etc/claude-code/`, and the macOS and Windows
 *   equivalents, as whole directories). The hook binary (basename
 *   `agentreel`, `node_modules/@agentreel/agent`, and the path taken from
 *   the managed hook command at match time) is also protected.
 * - SELF002: Write/Edit-style tool calls to any of those paths.
 * - SELF003: `agentreel uninstall`, `logout` or `pause` (also through npx,
 *   pnpm dlx, bunx), removing the @agentreel/agent package, and
 *   `agentreel managed ...` other than `--dry-run`. This match is on the
 *   command text only; it does not depend on CLAUDECODE or CURSOR_AGENT
 *   being set, so it still holds when sudo has stripped them.
 * - SELF004: `disableAllHooks`, and `claude --settings` / `--setting-sources`.
 * - SELF005: unsetting or overriding HOME, CLAUDE_CONFIG_DIR, CLAUDECODE,
 *   CLAUDE_CODE_CHILD_SESSION, CURSOR_AGENT or AGENTREEL_* (`unset`,
 *   `env -u`, `env -i`, `export HOME=`, `HOME=... claude`).
 *
 * Best effort against string tricks: input is NFKC-normalized and quotes and
 * backslashes are stripped before matching. Every check is a single linear
 * pass (no backtracking regex over user input).
 */

export interface SelfProtectMatch {
  rule_id: "SELF001" | "SELF002" | "SELF003" | "SELF004" | "SELF005";
  name: string;
}

export const SELF_PROTECT_NAMES: Record<SelfProtectMatch["rule_id"], string> = {
  SELF001: "changes to AgentReel, Claude Code or Cursor hook and policy files",
  SELF002: "edits to AgentReel, Claude Code or Cursor hook and policy files",
  SELF003: "uninstalling, pausing, logging out of AgentReel, or running agentreel managed",
  SELF004: "disabling hooks (disableAllHooks or claude --settings)",
  SELF005: "unsetting or overriding HOME, CLAUDE_CONFIG_DIR, CLAUDECODE, CURSOR_AGENT or AGENTREEL_* variables",
};

/** Lowercased path fragments that mark a protected file or directory.
 * Directory fragments end with "/" and match with or without a trailing
 * slash on the input (`isProtectedPath` appends one before searching).
 * Matching is case-insensitive (required for macOS paths).
 */
const PROTECTED_FRAGMENTS = [
  ".claude/settings.json",
  ".claude/settings.local.json",
  ".cursor/hooks.json",
  "/etc/claude-code/",
  "/etc/cursor/",
  "/library/application support/claudecode/",
  "/library/application support/cursor/",
  "programdata/cursor/",
  "program files/claudecode/",
  "node_modules/@agentreel/agent",
];

/** Programs that only read, so naming a protected path with them is fine. */
const READ_ONLY_PROGRAMS = new Set([
  "cat", "less", "more", "head", "tail", "grep", "egrep", "fgrep", "rg", "ag",
  "jq", "ls", "stat", "file", "wc", "diff", "cmp", "test", "[", "md5sum",
  "sha256sum", "shasum", "bat", "readlink", "realpath", "dirname", "basename",
  "echo", "printf", "true",
]);

/** Prefix words that run the next word as the program. */
const WRAPPERS = new Set(["sudo", "doas", "command", "exec", "nohup", "time", "nice", "builtin", "xargs"]);

const READ_TOOLS = /^(read|read_file|readfile|view|cat|beforereadfile|grep|glob|ls|list_dir|search)$/i;

const ENV_NAMES = /^(HOME|CLAUDE_CONFIG_DIR|CLAUDECODE|CLAUDE_CODE_CHILD_SESSION|CURSOR_AGENT|NODE_OPTIONS|AGENTREEL_[A-Z0-9_]*)$/;

/** NFKC, then drop quotes and backslash escapes (keeping the escaped char). */
export function dequoteShell(s: string): string {
  const n = s.normalize("NFKC");
  let out = "";
  for (let i = 0; i < n.length; i++) {
    const c = n[i]!;
    if (c === "'" || c === '"') continue;
    if (c === "\\") {
      const next = n[i + 1];
      if (next === undefined) continue;
      if (next === "\n") {
        i++;
        continue;
      }
      // Keep Windows path separators as "/" so fragments match either way.
      out += next === "\\" ? "/" : next;
      i++;
      continue;
    }
    out += c;
  }
  return out;
}

/** Split into simple command segments on ; & | newline ( ) and backticks. */
export function shellSegments(s: string): string[] {
  const segs: string[] = [];
  let cur = "";
  for (let i = 0; i < s.length; i++) {
    const c = s[i]!;
    if (c === ";" || c === "&" || c === "|" || c === "\n" || c === "(" || c === ")" || c === "`") {
      if (cur.trim()) segs.push(cur);
      cur = "";
      continue;
    }
    // $( starts a subshell; drop the $ so the inner command is its own segment.
    if (c === "$" && s[i + 1] === "(") continue;
    cur += c;
  }
  if (cur.trim()) segs.push(cur);
  return segs;
}

function tokens(seg: string): string[] {
  return seg.split(/\s+/).filter(Boolean);
}

function basename(tok: string): string {
  const i = tok.lastIndexOf("/");
  return (i >= 0 ? tok.slice(i + 1) : tok).toLowerCase();
}

/** Index of the program token, skipping VAR=value prefixes and wrappers. */
function programIndex(toks: string[]): number {
  let i = 0;
  while (i < toks.length) {
    const t = toks[i]!;
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(t)) {
      i++;
      continue;
    }
    const b = basename(t);
    if (WRAPPERS.has(b)) {
      i++;
      // Skip the wrapper's own flags (sudo -u root, nice -n 5).
      while (i < toks.length && toks[i]!.startsWith("-")) i++;
      continue;
    }
    if (b === "env") {
      i++;
      while (i < toks.length && (toks[i]!.startsWith("-") || /^[A-Za-z_][A-Za-z0-9_]*=/.test(toks[i]!))) i++;
      continue;
    }
    return i;
  }
  return -1;
}

/** Default hook-config files whose `command` values name the hook binary. */
function defaultHookConfigPaths(): string[] {
  return [
    systemCursorHooksPath(),
    cursorHooksPath(),
    claudeSettingsPath(),
    "/etc/claude-code/managed-settings.json",
    "/Library/Application Support/ClaudeCode/managed-settings.json",
  ];
}

let hookConfigPathsOverride: string[] | null = null;

/** Test hook: replace the hook-config files used to discover the binary. */
export function _setHookConfigPathsForTests(paths: string[] | null): void {
  hookConfigPathsOverride = paths;
}

function hookConfigPaths(): string[] {
  return hookConfigPathsOverride ?? defaultHookConfigPaths();
}

/** Walk a JSON value and collect every string `command` field, depth-capped. */
function collectCommandStrings(value: unknown, out: string[], depth = 0): void {
  if (depth > 8 || value === null || value === undefined) return;
  if (Array.isArray(value)) {
    for (const item of value) collectCommandStrings(item, out, depth + 1);
    return;
  }
  if (typeof value === "object") {
    const rec = value as Record<string, unknown>;
    if (typeof rec.command === "string") out.push(rec.command);
    for (const item of Object.values(rec)) collectCommandStrings(item, out, depth + 1);
  }
}

/**
 * Hook binary paths taken from managed and user hook files at match time.
 * An unreadable file is skipped (the other sources and the fixed fragments
 * still apply). Never throws.
 */
let cachedHookBinaries: string[] | null = null;

function hookBinariesFromConfig(): string[] {
  if (cachedHookBinaries) return cachedHookBinaries;
  const out: string[] = [];
  for (const path of hookConfigPaths()) {
    try {
      const raw = readFileSync(path, "utf8");
      const commands: string[] = [];
      collectCommandStrings(JSON.parse(raw) as unknown, commands);
      for (const cmd of commands) {
        const bin = hookCommandBinaryPath(cmd);
        if (bin) out.push(bin);
      }
    } catch {
      // Unreadable or invalid: ignore this file.
    }
  }
  cachedHookBinaries = out;
  return out;
}

function resetHookBinaryCache(): void {
  cachedHookBinaries = null;
}

/** True when the path's final component is the `agentreel` binary. */
function isAgentreelBasename(lower: string): boolean {
  // Require a path separator so running `agentreel doctor` is not a write
  // to the binary; `rm /usr/local/bin/agentreel` still matches.
  if (!lower.includes("/") && !lower.includes("~")) return false;
  const base = (lower.split("/").pop() ?? "").split("?")[0]!;
  return base === "agentreel" || base === "agentreel.exe";
}

/** Replace `$(which agentreel)` and `` `which agentreel` `` with a dummy path. */
export function rewriteWhichAgentreel(s: string): string {
  let out = "";
  let i = 0;
  const n = s.length;
  while (i < n) {
    if (s.startsWith("$(", i)) {
      const end = s.indexOf(")", i + 2);
      if (end >= 0 && isWhichAgentreel(s.slice(i + 2, end))) {
        out += "/bin/agentreel";
        i = end + 1;
        continue;
      }
    } else if (s[i] === "`") {
      const end = s.indexOf("`", i + 1);
      if (end >= 0 && isWhichAgentreel(s.slice(i + 1, end))) {
        out += "/bin/agentreel";
        i = end + 1;
        continue;
      }
    }
    out += s[i];
    i++;
  }
  return out;
}

function isWhichAgentreel(inner: string): boolean {
  const t = inner.trim().split(/\s+/).filter(Boolean);
  return t.length === 2 && t[0] === "which" && t[1]!.toLowerCase() === "agentreel";
}

export function isProtectedPath(p: string): boolean {
  const lower = p.replace(/\\/g, "/").toLowerCase();
  if (hasAgentreelDir(lower)) return true;
  if (isAgentreelBasename(lower)) return true;
  // Trailing "/" so a bare directory (/etc/cursor) matches its fragment.
  const withSlash = `${lower}/`;
  if (PROTECTED_FRAGMENTS.some((f) => withSlash.includes(f) || lower.includes(f))) return true;
  for (const bin of hookBinariesFromConfig()) {
    const b = bin.replace(/\\/g, "/").toLowerCase();
    if (lower === b || withSlash.startsWith(`${b}/`)) return true;
  }
  return false;
}

function spacedProtectedHit(seg: string): boolean {
  const segSlash = `${seg.toLowerCase()}/`;
  if (PROTECTED_FRAGMENTS.some((f) => f.includes(" ") && segSlash.includes(f))) return true;
  for (const bin of hookBinariesFromConfig()) {
    const b = bin.replace(/\\/g, "/").toLowerCase();
    if (b.includes(" ") && segSlash.includes(b)) return true;
  }
  return false;
}

/** `.agentreel` as a whole path component (~/.agentreel, $HOME/.agentreel/x). */
function hasAgentreelDir(lower: string): boolean {
  let from = 0;
  for (;;) {
    const i = lower.indexOf(".agentreel", from);
    if (i < 0) return false;
    const before = i === 0 ? "" : lower[i - 1]!;
    const after = lower[i + 10] ?? "";
    const startOk = i === 0 || before === "/" || before === "~" || /[\s=<>:]/.test(before);
    const endOk = after === "" || after === "/" || /[\s;|&)]/.test(after);
    if (startOk && endOk) return true;
    from = i + 1;
  }
}

/** `2>>file` to `file`, `--out=file` to `file`; one linear pass. */
function stripRedirectAndFlag(t: string): string {
  let k = 0;
  while (k < t.length && "<>&0123456789".includes(t[k]!)) k++;
  let rest = t.slice(k);
  if (rest.startsWith("-")) {
    const eq = rest.indexOf("=");
    if (eq > 0) rest = rest.slice(eq + 1);
  }
  return rest;
}

function segmentHasOutputRedirect(seg: string): boolean {
  return seg.includes(">");
}

/** `node` itself (node, nodejs, node.exe, any path-qualified form). */
function isNodeProgram(prog: string): boolean {
  return prog === "node" || prog === "nodejs" || prog === "node.exe";
}

/** Node flags that take no value and cannot run other code, so the script is the next word. */
const NODE_PLAIN_FLAGS = new Set(["--no-warnings", "--trace-warnings", "--enable-source-maps", "--no-deprecation"]);

/**
 * The AgentReel CLI entry point as installed by npm:
 * `.../node_modules/@agentreel/agent/dist/cli.js`. The path must hold no `..`
 * segment, so it names the installed package and not a file reached through it.
 */
function isAgentreelCliScript(tok: string): boolean {
  const t = tok.toLowerCase();
  if (!t.endsWith("/node_modules/@agentreel/agent/dist/cli.js")) return false;
  return !t.split("/").includes("..");
}

/**
 * Index of the script `node` runs, when it is the AgentReel CLI and nothing
 * else in the node command line can run other code: the first argument must
 * be the script, optionally after a few value-less flags. `-e`, `-p`,
 * `-r`, `--require`, `--import` and any other flag mean no skip, so the path
 * is checked like any other token.
 */
function nodeAgentreelScriptIndex(toks: string[], pi: number): number {
  if (pi < 0 || !isNodeProgram(basename(toks[pi]!))) return -1;
  for (let i = pi + 1; i < toks.length; i++) {
    const t = toks[i]!;
    if (t.startsWith("-")) {
      if (NODE_PLAIN_FLAGS.has(t)) continue;
      return -1;
    }
    return isAgentreelCliScript(t) ? i : -1;
  }
  return -1;
}

function checkCommand(command: string): SelfProtectMatch | null {
  const clean = rewriteWhichAgentreel(dequoteShell(command));
  const segs = shellSegments(clean);
  for (const seg of segs) {
    const toks = tokens(seg);
    const pi = programIndex(toks);
    const prog = pi >= 0 ? basename(toks[pi]!) : "";
    const args = pi >= 0 ? toks.slice(pi + 1) : [];
    const readOnly = READ_ONLY_PROGRAMS.has(prog) && !segmentHasOutputRedirect(seg);
    // `node .../@agentreel/agent/dist/cli.js doctor` runs the CLI; it does not
    // write to the package. Its script path is skipped for SELF001 only.
    const cliIdx = nodeAgentreelScriptIndex(toks, pi);

    // SELF005: env tampering.
    // Any NODE_OPTIONS= assignment before the program (bare, env, sudo,
    // sudo -E env) is SELF005, whatever the program: it can preload
    // (--require, --import) into agentreel, npx, node and the rest.
    if (pi >= 0 && toks.slice(0, pi).some((t) => /^NODE_OPTIONS=/i.test(t))) {
      return m("SELF005");
    }
    if (prog === "unset" && args.some((a) => ENV_NAMES.test(a))) return m("SELF005");
    if (prog === "export" || prog === "declare" || prog === "typeset") {
      if (args.some((a) => ENV_NAMES.test(a.split("=")[0]!) && a.includes("="))) return m("SELF005");
      if (args.includes("-n") && args.some((a) => ENV_NAMES.test(a))) return m("SELF005");
    }
    for (let i = 0; i < toks.length; i++) {
      const t = toks[i]!;
      if (basename(t) !== "env") continue;
      for (let j = i + 1; j < toks.length; j++) {
        const a = toks[j]!;
        if (a === "-i" || a === "--ignore-environment" || a === "-") return m("SELF005");
        if ((a === "-u" || a === "--unset") && ENV_NAMES.test(toks[j + 1] ?? "")) return m("SELF005");
        if (a.startsWith("--unset=") && ENV_NAMES.test(a.slice(8))) return m("SELF005");
        if (a.startsWith("-u") && a.length > 2 && ENV_NAMES.test(a.slice(2))) return m("SELF005");
        if (!a.startsWith("-") && !a.includes("=")) break;
      }
    }
    if (pi > 0 && ["claude", "cursor", "cursor-agent", "code"].includes(prog)) {
      for (let i = 0; i < pi; i++) {
        const name = toks[i]!.split("=")[0]!;
        if (toks[i]!.includes("=") && ENV_NAMES.test(name)) return m("SELF005");
      }
    }

    // SELF003: uninstall, logout, pause.
    const agentIdx = toks.findIndex(
      (t, i) => basename(t) === "agentreel" || /^@agentreel\/agent(@|$)/.test(t) || i === cliIdx,
    );
    if (agentIdx >= 0) {
      const rest = toks.slice(agentIdx + 1).map((t) => t.toLowerCase());
      if (rest.some((t) => t === "uninstall" || t === "logout" || t === "pause")) return m("SELF003");
      // `managed` is blocked unless the invocation is a dry run. The check
      // is on the command text, so it still holds when sudo has stripped
      // CLAUDECODE / CURSOR_AGENT (the installer's own session refusal
      // would otherwise miss).
      if (rest[0] === "managed" && !rest.includes("--dry-run")) return m("SELF003");
      if (["npm", "pnpm", "yarn", "bun"].includes(prog) && args.some((a) => ["uninstall", "un", "remove", "rm", "r", "unlink"].includes(a))) {
        return m("SELF003");
      }
    }

    // SELF004: disableAllHooks and claude --settings.
    if (seg.includes("disableAllHooks") && !readOnly) return m("SELF004");
    if (prog === "claude" && args.some((a) => a === "--settings" || a.startsWith("--settings=") || a.startsWith("--setting-sources"))) {
      return m("SELF004");
    }

    // SELF001: a protected path in a segment that may write. Running
    // `agentreel doctor` is not a write to the binary, so skip a program
    // token whose basename is agentreel. Other tokens, and a path that is
    // the only word in a segment (`open(.../.cursor/hooks.json...)` after
    // splitting on parentheses), are still checked.
    if (
      !readOnly &&
      toks.some((t, i) => {
        if (i === cliIdx) return false;
        if (i === pi) {
          const b = basename(t);
          if (b === "agentreel" || b === "agentreel.exe") return false;
        }
        return isProtectedPath(stripRedirectAndFlag(t));
      })
    ) {
      return m("SELF001");
    }
    // Paths with spaces (macOS "Application Support") survive as one string only on the segment.
    // Append "/" so `/Library/Application Support/Cursor` matches the directory fragment.
    if (!readOnly && spacedProtectedHit(seg)) return m("SELF001");
  }
  return null;
}

function m(rule_id: SelfProtectMatch["rule_id"]): SelfProtectMatch {
  return { rule_id, name: SELF_PROTECT_NAMES[rule_id] };
}

export interface SelfProtectInput {
  toolName: string;
  command?: string;
  file_path?: string;
  toolInput?: unknown;
}

/** Returns the self-protect check that matches, or null. Never throws. */
export function matchSelfProtect(input: SelfProtectInput): SelfProtectMatch | null {
  resetHookBinaryCache();
  try {
    if (input.command) {
      const hit = checkCommand(input.command);
      if (hit) return hit;
    }
    const tool = input.toolName.toLowerCase();
    if (input.file_path && !READ_TOOLS.test(tool) && isProtectedPath(input.file_path.normalize("NFKC"))) {
      return m("SELF002");
    }
    // Content written by a tool that turns hooks off.
    const ti = input.toolInput;
    if (!READ_TOOLS.test(tool) && ti && typeof ti === "object" && !Array.isArray(ti)) {
      const rec = ti as Record<string, unknown>;
      for (const k of ["content", "new_string", "contents", "text"]) {
        const v = rec[k];
        if (typeof v === "string" && v.includes("disableAllHooks")) return m("SELF004");
      }
    }
    return null;
  } catch {
    return null;
  }
}
