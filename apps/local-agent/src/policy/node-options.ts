/**
 * NODE_OPTIONS allow list for self-protect (SELF005).
 *
 * NODE_OPTIONS can preload code into every Node process, including the
 * AgentReel hook binary and CLI (`--require`, `--import`, `--loader`,
 * `--inspect`, `--env-file`, ...). Any assignment of NODE_OPTIONS in a
 * command, in any form (bare prefix, `env`, `sudo`, `sudo -E env`,
 * `export`, `declare`, inside `sh -c "..."` or `eval`), must use only the
 * flags below. Everything else fails closed: unknown flags, a bad value,
 * an unparseable value (unterminated quote, `$VAR`, `$(...)`, backticks),
 * or a NODE_OPTIONS value that cannot be seen (`read`, `printf -v`,
 * `export NODE_OPTIONS` with no value).
 *
 * The scan is one linear pass per nesting level, with a fixed depth limit.
 */

/** Flags that take a value: name -> value check. */
const VALUE_FLAGS: Record<string, (v: string) => boolean> = {
  "--max-old-space-size": (v) => /^[0-9]{1,7}$/.test(v),
  "--max-semi-space-size": (v) => /^[0-9]{1,7}$/.test(v),
  "--dns-result-order": (v) => v === "ipv4first" || v === "ipv6first" || v === "verbatim",
};

/** Flags that take no value. */
const BARE_FLAGS = new Set(["--enable-source-maps", "--no-warnings", "--trace-warnings"]);

/** Every flag name allowed in NODE_OPTIONS. */
export const NODE_OPTIONS_ALLOWED_FLAGS: readonly string[] = [
  ...Object.keys(VALUE_FLAGS),
  ...BARE_FLAGS,
];

/** Commands whose arguments can set a variable without a visible `NAME=value`. */
const SETTER_COMMANDS = new Set([
  "export", "declare", "typeset", "local", "readonly", "read", "printf", "mapfile", "readarray",
]);

const MAX_DEPTH = 3;

interface Word {
  text: string;
  /** True when the word holds an expansion or quoting we cannot evaluate. */
  dynamic: boolean;
}

/**
 * Split a command into statements of words with shell quoting removed.
 * Separators are unquoted whitespace and `; | & ( ) < >` and newlines (which
 * also end a statement, except whitespace). An unterminated quote, `$` before
 * a name, `{` or `(`, `$'...'` and backticks mark the word dynamic.
 */
function splitStatements(cmd: string): Word[][] {
  const statements: Word[][] = [];
  let words: Word[] = [];
  let cur = "";
  let started = false;
  let dynamic = false;
  const endWord = () => {
    if (started) words.push({ text: cur, dynamic });
    cur = "";
    started = false;
    dynamic = false;
  };
  const endStatement = () => {
    endWord();
    if (words.length) statements.push(words);
    words = [];
  };
  let i = 0;
  const n = cmd.length;
  while (i < n) {
    const c = cmd[i]!;
    if (c === " " || c === "\t") {
      endWord();
      i++;
      continue;
    }
    if (c === "\n" || c === ";" || c === "|" || c === "&" || c === "(" || c === ")" || c === "<" || c === ">") {
      endStatement();
      i++;
      continue;
    }
    started = true;
    if (c === "\\") {
      if (i + 1 < n) {
        if (cmd[i + 1] !== "\n") cur += cmd[i + 1];
        i += 2;
      } else {
        i++;
      }
      continue;
    }
    if (c === "'") {
      const end = cmd.indexOf("'", i + 1);
      if (end < 0) {
        dynamic = true;
        cur += cmd.slice(i + 1);
        i = n;
      } else {
        cur += cmd.slice(i + 1, end);
        i = end + 1;
      }
      continue;
    }
    if (c === '"') {
      let j = i + 1;
      let closed = false;
      while (j < n) {
        const d = cmd[j]!;
        if (d === "\\" && j + 1 < n && '$`"\\\n'.includes(cmd[j + 1]!)) {
          if (cmd[j + 1] !== "\n") cur += cmd[j + 1];
          j += 2;
          continue;
        }
        if (d === '"') {
          closed = true;
          break;
        }
        if (d === "`" || (d === "$" && j + 1 < n && /[A-Za-z_{(0-9@*#?$!-]/.test(cmd[j + 1]!))) dynamic = true;
        cur += d;
        j++;
      }
      if (!closed) dynamic = true;
      i = closed ? j + 1 : n;
      continue;
    }
    if (c === "`") {
      dynamic = true;
      cur += c;
      i++;
      continue;
    }
    if (c === "$" && i + 1 < n && /[A-Za-z_{('0-9@*#?$!-]/.test(cmd[i + 1]!)) {
      dynamic = true;
      cur += c;
      i++;
      continue;
    }
    cur += c;
    i++;
  }
  endStatement();
  return statements;
}

/**
 * Split a NODE_OPTIONS value the way Node does: whitespace separated, with
 * double quotes grouping a value that holds spaces. Returns null when a
 * quote is unterminated.
 */
function splitNodeOptions(value: string): string[] | null {
  const out: string[] = [];
  let cur = "";
  let started = false;
  for (let i = 0; i < value.length; i++) {
    const c = value[i]!;
    if (c === " " || c === "\t" || c === "\n") {
      if (started) out.push(cur);
      cur = "";
      started = false;
      continue;
    }
    started = true;
    if (c === "\\" && i + 1 < value.length) {
      cur += value[++i];
      continue;
    }
    if (c === '"') {
      const end = value.indexOf('"', i + 1);
      if (end < 0) return null;
      cur += value.slice(i + 1, end);
      i = end;
      continue;
    }
    cur += c;
  }
  if (started) out.push(cur);
  return out;
}

/** Node accepts `_` for `-` in flag names. */
function normalizeFlag(name: string): string {
  return "--" + name.slice(2).replace(/_/g, "-");
}

/**
 * True when a NODE_OPTIONS value uses only allowed flags with valid values.
 * An empty value (no flags) is allowed: it adds nothing.
 */
export function isAllowedNodeOptionsValue(value: string): boolean {
  const toks = splitNodeOptions(value);
  if (toks === null) return false;
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i]!;
    if (!t.startsWith("--") || t.length <= 2) return false;
    const eq = t.indexOf("=");
    const rawName = eq >= 0 ? t.slice(0, eq) : t;
    if (rawName.length <= 2) return false;
    const name = normalizeFlag(rawName);
    if (BARE_FLAGS.has(name)) {
      if (eq >= 0) return false;
      continue;
    }
    const check = VALUE_FLAGS[name];
    if (!check) return false;
    let v: string | undefined;
    if (eq >= 0) {
      v = t.slice(eq + 1);
    } else {
      v = toks[i + 1];
      i++;
    }
    if (v === undefined || !check(v)) return false;
  }
  return true;
}

const ASSIGN_WORD = /^NODE_OPTIONS(\+?)=/;
const ANY_ASSIGN = /^[A-Za-z_][A-Za-z0-9_]*\+?=/;
const EMBEDDED_ASSIGN = /(^|[^A-Za-z0-9_])NODE_OPTIONS\+?=/;
const NESTED = /[\s;|&()<>]/;

/** Words that run the next word as a program; NODE_OPTIONS= after them is still an assignment. */
const WRAPPERS = new Set(["sudo", "doas", "env", "command", "exec", "nohup", "nice", "time", "builtin"]);

/** Programs whose string argument is run as shell code. */
const SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh", "eval", "su"]);

/**
 * Programs whose arguments are never run or assigned, so `echo NODE_OPTIONS=x`
 * is just text. Any other program's arguments are checked (fail closed).
 */
const TEXT_ONLY = new Set(["echo", "printf", "grep", "egrep", "fgrep", "rg", "cat", "head", "tail", "ls", "wc", "jq"]);

/** One NODE_OPTIONS=... assignment word: true when it is not allowed. */
function badAssignment(w: Word, m: RegExpMatchArray): boolean {
  if (w.dynamic || m[1] === "+") return true;
  return !isAllowedNodeOptionsValue(w.text.slice(m[0].length));
}

/** A word in argument position that mentions NODE_OPTIONS: true when it is not allowed. */
function badArgument(w: Word, prev: string, setter: boolean, shell: boolean, depth: number): boolean {
  const t = w.text;
  if (t === "NODE_OPTIONS") {
    // `unset NODE_OPTIONS` and `env -u NODE_OPTIONS` only remove it; after a
    // setter (export, read, printf -v, declare) the value is hidden.
    if (prev === "unset" || prev === "-u" || prev === "--unset") return false;
    return setter;
  }
  if (t === "--unset=NODE_OPTIONS" || t === "-uNODE_OPTIONS") return false;
  const m = t.match(ASSIGN_WORD);
  if (NESTED.test(t)) {
    // An inner command string: sh -c, bash -lc, zsh -c, dash -c, eval, su -c.
    if (w.dynamic) return true;
    // After export/declare the whole word is one value. After a shell or
    // eval it is a command. For any other program, both readings must pass.
    if (m && setter) return badAssignment(w, m);
    if (hasDisallowedNodeOptions(t, depth + 1)) return true;
    return !shell && m !== null && badAssignment(w, m);
  }
  if (m) return badAssignment(w, m);
  const e = t.match(EMBEDDED_ASSIGN);
  if (e && e.index !== undefined) {
    // e.g. --env=NODE_OPTIONS=...: check the value after it.
    if (w.dynamic) return true;
    const rest = t.slice(e.index + e[0].length);
    return /\+=$/.test(e[0]) || !isAllowedNodeOptionsValue(rest);
  }
  return false;
}

/**
 * True when `cmd` sets NODE_OPTIONS to anything outside the allow list, or
 * in a way that cannot be checked. Every statement is checked (after ; && ||
 * & | and newlines), including a lone assignment with no program, export and
 * the other setters, and the inner command of sh/bash/zsh/dash -c and eval,
 * up to a fixed depth. Never throws.
 */
export function hasDisallowedNodeOptions(cmd: string, depth = 0): boolean {
  if (!cmd.includes("NODE_OPTIONS")) return false;
  if (depth > MAX_DEPTH) return true;
  let statements: Word[][];
  try {
    statements = splitStatements(cmd);
  } catch {
    return true;
  }
  for (const words of statements) {
    let program: string | null = null;
    let setter = false;
    let textOnly = false;
    for (let k = 0; k < words.length; k++) {
      const w = words[k]!;
      const prev = k > 0 ? words[k - 1]!.text : "";
      if (program === null) {
        // Assignment position: VAR=..., wrappers and their flags.
        const m = w.text.match(ASSIGN_WORD);
        if (m) {
          if (badAssignment(w, m)) return true;
          continue;
        }
        if (ANY_ASSIGN.test(w.text)) continue;
        const base = w.text.slice(w.text.lastIndexOf("/") + 1);
        if (WRAPPERS.has(base)) continue;
        if (w.text.startsWith("-")) {
          if (w.text.includes("NODE_OPTIONS") && badArgument(w, prev, false, false, depth)) return true;
          continue;
        }
        program = base;
        const hasV = words.slice(k + 1).some((x) => x.text === "-v");
        setter = SETTER_COMMANDS.has(base) && (base !== "printf" || hasV);
        textOnly = TEXT_ONLY.has(base) && !setter;
        if (w.dynamic && w.text.includes("NODE_OPTIONS")) return true;
        continue;
      }
      if (textOnly || !w.text.includes("NODE_OPTIONS")) continue;
      if (badArgument(w, prev, setter, SHELLS.has(program), depth)) return true;
    }
  }
  return false;
}
