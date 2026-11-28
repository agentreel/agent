/**
 * Self-protection: while an org policy is enforcing, block the agent from
 * turning AgentReel off. These checks are not Guard rules (the Guard catalog
 * stays at 31) and a policy can't disable them. They cover:
 *
 * - SELF001: shell writes to AgentReel state (`~/.agentreel/**`), Claude Code
 *   settings (`.claude/settings.json`, `.claude/settings.local.json`), Cursor
 *   hooks (`.cursor/hooks.json`), and the managed files
 *   (`/etc/claude-code/managed-settings.json`, `/etc/cursor/hooks.json`, and
 *   the macOS and Windows equivalents).
 * - SELF002: Write/Edit-style tool calls to any of those paths.
 * - SELF003: `agentreel uninstall`, `logout` or `pause` (also through npx,
 *   pnpm dlx, bunx), and removing the @agentreel/agent package.
 * - SELF004: `disableAllHooks`, and `claude --settings` / `--setting-sources`.
 * - SELF005: unsetting or overriding HOME, CLAUDE_CONFIG_DIR or AGENTREEL_*
 *   (`unset`, `env -u`, `env -i`, `export HOME=`, `HOME=... claude`).
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
  SELF003: "uninstalling, pausing or logging out of AgentReel",
  SELF004: "disabling hooks (disableAllHooks or claude --settings)",
  SELF005: "unsetting or overriding HOME, CLAUDE_CONFIG_DIR or AGENTREEL_* variables",
};

/** Lowercased path fragments that mark a protected file. */
const PROTECTED_FRAGMENTS = [
  ".claude/settings.json",
  ".claude/settings.local.json",
  ".cursor/hooks.json",
  "/etc/claude-code/",
  "/etc/cursor/hooks.json",
  "/library/application support/claudecode/",
  "/library/application support/cursor/hooks.json",
  "programdata/cursor/hooks.json",
  "program files/claudecode/",
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

const ENV_NAMES = /^(HOME|CLAUDE_CONFIG_DIR|AGENTREEL_[A-Z0-9_]*)$/;

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

export function isProtectedPath(p: string): boolean {
  const lower = p.replace(/\\/g, "/").toLowerCase();
  if (hasAgentreelDir(lower)) return true;
  // Trailing "/" so a bare directory (/etc/claude-code) matches its fragment.
  const withSlash = `${lower}/`;
  return PROTECTED_FRAGMENTS.some((f) => withSlash.includes(f));
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

function checkCommand(command: string): SelfProtectMatch | null {
  const clean = dequoteShell(command);
  const segs = shellSegments(clean);
  for (const seg of segs) {
    const toks = tokens(seg);
    const pi = programIndex(toks);
    const prog = pi >= 0 ? basename(toks[pi]!) : "";
    const args = pi >= 0 ? toks.slice(pi + 1) : [];
    const readOnly = READ_ONLY_PROGRAMS.has(prog) && !segmentHasOutputRedirect(seg);

    // SELF005: env tampering.
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
    const agentIdx = toks.findIndex((t) => basename(t) === "agentreel" || /^@agentreel\/agent(@|$)/.test(t));
    if (agentIdx >= 0) {
      const rest = toks.slice(agentIdx + 1).map((t) => t.toLowerCase());
      if (rest.some((t) => t === "uninstall" || t === "logout" || t === "pause")) return m("SELF003");
      if (["npm", "pnpm", "yarn", "bun"].includes(prog) && args.some((a) => ["uninstall", "un", "remove", "rm", "r", "unlink"].includes(a))) {
        return m("SELF003");
      }
    }

    // SELF004: disableAllHooks and claude --settings.
    if (seg.includes("disableAllHooks") && !readOnly) return m("SELF004");
    if (prog === "claude" && args.some((a) => a === "--settings" || a.startsWith("--settings=") || a.startsWith("--setting-sources"))) {
      return m("SELF004");
    }

    // SELF001: a protected path in a segment that may write.
    if (!readOnly && toks.some((t) => isProtectedPath(stripRedirectAndFlag(t)))) {
      return m("SELF001");
    }
    // Paths with spaces (macOS "Application Support") survive as one string only on the segment.
    if (!readOnly && PROTECTED_FRAGMENTS.some((f) => f.includes(" ") && seg.toLowerCase().includes(f))) return m("SELF001");
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
