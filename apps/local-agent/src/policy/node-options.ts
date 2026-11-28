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

interface Statement {
  words: Word[];
  /** Operator that follows this statement: "|", "||", "|&", "&&", "&", ";", "\n", "(", ")", or "". */
  after: string;
  hereString: Word | null;
  hereDoc: { body: string; quoted: boolean } | null;
  /** A heredoc was opened but its body was not in the command text. */
  hereDocMissing: boolean;
  /** Filled after heredoc bodies are read; not used outside the splitter. */
  boxes?: { body: string | null; quoted: boolean }[];
}

/**
 * Split a command into statements of words with shell quoting removed.
 * Multi-character operators (`||`, `&&`, `|&`, `<<`, `<<<`) are kept together.
 * `<<< word` and `<<[ - ]delim` plus an inline body are attached to the
 * statement they belong to. An unterminated quote, `$` before a name, `{` or
 * `(`, `$'...'` and backticks mark the word dynamic.
 */
function splitStatements(cmd: string): Statement[] {
  const statements: Statement[] = [];
  let words: Word[] = [];
  let hereString: Word | null = null;
  let hereDoc: { body: string; quoted: boolean } | null = null;
  let hereDocMissing = false;
  type HereBox = { body: string | null; quoted: boolean };
  type PendingHere = { box: HereBox; delim: string; stripTabs: boolean };
  let pendingHere: PendingHere[] = [];
  let stmtHereBoxes: HereBox[] = [];
  let cur = "";
  let started = false;
  let dynamic = false;

  const endWord = (): Word | null => {
    if (!started) return null;
    const w = { text: cur, dynamic };
    words.push(w);
    cur = "";
    started = false;
    dynamic = false;
    return w;
  };

  const endStatement = (after: string) => {
    endWord();
    if (words.length || hereString || hereDoc || hereDocMissing || stmtHereBoxes.length) {
      statements.push({ words, after, hereString, hereDoc, hereDocMissing, boxes: stmtHereBoxes });
    }
    words = [];
    hereString = null;
    hereDoc = null;
    hereDocMissing = false;
    stmtHereBoxes = [];
  };

  let i = 0;
  const n = cmd.length;

  const skipSpaces = () => {
    while (i < n && (cmd[i] === " " || cmd[i] === "\t")) i++;
  };

  const readWord = (): Word => {
    skipSpaces();
    cur = "";
    started = false;
    dynamic = false;
    while (i < n) {
      const c = cmd[i]!;
      if (c === " " || c === "\t" || c === "\n" || c === ";" || c === "|" || c === "&" || c === "(" || c === ")" || c === "<" || c === ">") {
        break;
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
          if (d === "\\" && j + 1 < n && "$`\"\\\n".includes(cmd[j + 1]!)) {
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
    const w = started ? { text: cur, dynamic } : { text: "", dynamic: true };
    cur = "";
    started = false;
    dynamic = false;
    return w;
  };

  const fillHeredocs = () => {
    if (!pendingHere.length) return;
    for (const h of pendingHere) {
      const start = i;
      let body: string | null = null;
      while (i < n) {
        const nl = cmd.indexOf("\n", i);
        const lineEnd = nl < 0 ? n : nl;
        const line = cmd.slice(i, lineEnd);
        const cmp = h.stripTabs ? line.replace(/^\t+/, "") : line;
        if (cmp === h.delim) {
          body = cmd.slice(start, i);
          i = nl < 0 ? n : nl + 1;
          break;
        }
        if (nl < 0) {
          i = n;
          break;
        }
        i = nl + 1;
      }
      h.box.body = body;
    }
    pendingHere = [];
  };

  const readDelim = (): { delim: string; quoted: boolean } => {
    skipSpaces();
    if (i >= n || cmd[i] === "\n") return { delim: "", quoted: true };
    const q = cmd[i];
    if (q === "'" || q === '"') {
      const end = cmd.indexOf(q, i + 1);
      if (end < 0) {
        const d = cmd.slice(i + 1);
        i = n;
        return { delim: d, quoted: true };
      }
      const d = cmd.slice(i + 1, end);
      i = end + 1;
      return { delim: d, quoted: true };
    }
    if (q === "\\") {
      // <<\EOF : the rest of the word is the delimiter, quoted.
      i++;
      const w = readWord();
      return { delim: w.text, quoted: true };
    }
    const w = readWord();
    return { delim: w.text, quoted: false };
  };

  while (i < n) {
    const c = cmd[i]!;
    if (c === " " || c === "\t") {
      endWord();
      i++;
      continue;
    }
    if (c === "<") {
      endWord();
      if (cmd.startsWith("<<<", i)) {
        i += 3;
        hereString = readWord();
        continue;
      }
      if (cmd.startsWith("<<", i)) {
        i += 2;
        const stripTabs = cmd[i] === "-" ? (i++, true) : false;
        const { delim, quoted } = readDelim();
        if (!delim) {
          hereDocMissing = true;
          continue;
        }
        const box = { body: null as string | null, quoted };
        stmtHereBoxes.push(box);
        pendingHere.push({ box, delim, stripTabs });
        continue;
      }
      // Plain < redirect: skip the target word, stay in the statement.
      i++;
      if (cmd[i] === "&") i++;
      readWord();
      continue;
    }
    if (c === ">") {
      endWord();
      i++;
      if (cmd[i] === ">") i++;
      if (cmd[i] === "&") i++;
      readWord();
      continue;
    }
    if (c === "\n" || c === ";" || c === "|" || c === "&" || c === "(" || c === ")") {
      let op = c;
      let next = i + 1;
      if (c === "|" && cmd[i + 1] === "|") {
        op = "||";
        next = i + 2;
      } else if (c === "|" && cmd[i + 1] === "&") {
        op = "|&";
        next = i + 2;
      } else if (c === "&" && cmd[i + 1] === "&") {
        op = "&&";
        next = i + 2;
      }
      endStatement(op);
      i = next;
      if (c === "\n") fillHeredocs();
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
        if (d === "\\" && j + 1 < n && "$`\"\\\n".includes(cmd[j + 1]!)) {
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
  endStatement("");
  if (pendingHere.length) fillHeredocs();
  for (const st of statements) {
    const b = st.boxes?.[0];
    if (!b) continue;
    if (b.body === null) st.hereDocMissing = true;
    else st.hereDoc = { body: b.body, quoted: b.quoted };
    delete st.boxes;
  }
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
const SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "eval", "su"]);

/** Shells that will run stdin as a script when there is no -c. */
const STDIN_SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish", "csh", "tcsh"]);

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

interface ProgramView {
  program: string | null;
  setter: boolean;
  textOnly: boolean;
  /** True when the program is a stdin shell (including busybox sh/ash) and has no -c. */
  bareStdinShell: boolean;
  args: Word[];
}

function viewOf(stmt: Statement): ProgramView {
  let program: string | null = null;
  let setter = false;
  let textOnly = false;
  const args: Word[] = [];
  let hasC = false;
  for (let k = 0; k < stmt.words.length; k++) {
    const w = stmt.words[k]!;
    if (program === null) {
      if (ASSIGN_WORD.test(w.text) || ANY_ASSIGN.test(w.text)) continue;
      const base = w.text.slice(w.text.lastIndexOf("/") + 1);
      if (WRAPPERS.has(base)) continue;
      if (w.text.startsWith("-")) continue;
      program = base;
      const rest = stmt.words.slice(k + 1);
      const hasV = rest.some((x) => x.text === "-v");
      setter = SETTER_COMMANDS.has(base) && (base !== "printf" || hasV);
      textOnly = TEXT_ONLY.has(base) && !setter;
      hasC = rest.some((x) => x.text === "-c" || /^-[a-zA-Z]*c[a-zA-Z]*$/.test(x.text));
      continue;
    }
    args.push(w);
  }
  const busyboxSh = program === "busybox" && (args[0]?.text === "sh" || args[0]?.text === "ash");
  const bareStdinShell = program !== null && !hasC && (STDIN_SHELLS.has(program) || busyboxSh);
  return { program, setter, textOnly, bareStdinShell, args };
}

const PRINTF_ESC: Record<string, string> = {
  a: "\x07",
  b: "\b",
  e: "\x1b",
  f: "\f",
  n: "\n",
  r: "\r",
  t: "\t",
  v: "\v",
  "\\": "\\",
  "'": "'",
  '"': '"',
};

/** Expand printf / echo -e backslash escapes. Returns null if the text cannot be expanded. */
function expandBackslashEscapes(s: string): string | null {
  let out = "";
  for (let i = 0; i < s.length; i++) {
    if (s[i] !== "\\") {
      out += s[i];
      continue;
    }
    const n = s[i + 1];
    if (n === undefined) return null;
    if (n in PRINTF_ESC) {
      out += PRINTF_ESC[n];
      i++;
      continue;
    }
    if (n === "x") {
      const hex = s.slice(i + 2, i + 4);
      if (!/^[0-9A-Fa-f]{2}$/.test(hex)) return null;
      out += String.fromCharCode(parseInt(hex, 16));
      i += 3;
      continue;
    }
    if (n === "0" || n === "1" || n === "2" || n === "3" || n === "4" || n === "5" || n === "6" || n === "7") {
      let oct = n;
      let j = i + 2;
      while (oct.length < 3 && j < s.length && /[0-7]/.test(s[j]!)) {
        oct += s[j]!;
        j++;
      }
      out += String.fromCharCode(parseInt(oct, 8));
      i = j - 1;
      continue;
    }
    // Unknown escape: fail closed.
    return null;
  }
  return out;
}

/**
 * Rebuild the text a TEXT_ONLY command would write to a pipe. Returns null
 * when that text cannot be known (printf %s, a dynamic word, a missing
 * heredoc, an unquoted heredoc with expansions).
 */
function textOnlyOutput(stmt: Statement): string | null {
  if (stmt.hereDocMissing) return null;
  if (stmt.hereString) {
    if (stmt.hereString.dynamic) return null;
    return stmt.hereString.text;
  }
  if (stmt.hereDoc) {
    if (!stmt.hereDoc.quoted && /[$`]/.test(stmt.hereDoc.body)) return null;
    return stmt.hereDoc.body;
  }
  const v = viewOf(stmt);
  if (v.program === "printf") {
    const args = v.args.filter((a) => a.text !== "--" && !(/^-[A-Za-z]+$/.test(a.text) && a.text !== "--"));
    // Drop leading flags (-v is a setter and not textOnly).
    const starts = args.findIndex((a) => !a.text.startsWith("-") || a.text === "--" || a.text === "-");
    const rest = starts < 0 ? [] : args[starts]!.text === "--" ? args.slice(starts + 1) : args.slice(starts);
    if (!rest.length) return "";
    if (rest.some((a) => a.dynamic)) return null;
    const format = rest[0]!.text;
    // A conversion other than %% needs an argument we may not be able to place
    // exactly (flags, widths). Fail closed.
    if (/%(?:[^%]|$)/.test(format.replace(/%%/g, ""))) return null;
    return expandBackslashEscapes(format.replace(/%%/g, "%"));
  }
  // echo and the other TEXT_ONLY programs: join non-flag arguments.
  const ev = v.program === "echo" && v.args.some((a) => /^-[A-Za-z]*e[A-Za-z]*$/.test(a.text));
  const parts: string[] = [];
  let flagsDone = v.program === "echo";
  for (const a of v.args) {
    if (!flagsDone && /^-[A-Za-z]+$/.test(a.text)) continue;
    flagsDone = true;
    if (a.dynamic) return null;
    parts.push(a.text);
  }
  const joined = parts.join(" ");
  if (ev) return expandBackslashEscapes(joined);
  return joined;
}

/** Scan text as a nested command, or deny if it cannot be parsed. */
function nestedDisallowed(text: string | null, depth: number): boolean {
  if (text === null) return true;
  return hasDisallowedNodeOptions(text, depth + 1);
}

/**
 * Stages that pipe into `shellIndex` (not including the shell). Empty when
 * the shell is not fed by `|` or `|&`.
 */
function pipelineSources(stmts: Statement[], shellIndex: number): Statement[] | null {
  if (shellIndex <= 0) return null;
  const prev = stmts[shellIndex - 1]!;
  if (prev.after !== "|" && prev.after !== "|&") return null;
  let start = shellIndex - 1;
  while (start > 0 && (stmts[start - 1]!.after === "|" || stmts[start - 1]!.after === "|&")) start--;
  return stmts.slice(start, shellIndex);
}

/** True when anything sits between the text source and the shell. */
function hasIntermediatePipeStage(sources: Statement[]): boolean {
  return sources.length !== 1;
}

/**
 * A bare stdin shell (sh, bash, zsh, dash, ksh, mksh, ash, busybox sh/ash)
 * with no -c runs its stdin as a script. Allow only when exactly one
 * TEXT_ONLY source stage with fully scannable text is piped directly into
 * the shell and that text passes the allow list. Any stage between the
 * text source and the shell is SELF005.
 */
function pipelineIntoShellIsDisallowed(stmts: Statement[], shellIndex: number, depth: number): boolean {
  if (!viewOf(stmts[shellIndex]!).bareStdinShell) return false;
  const sources = pipelineSources(stmts, shellIndex);
  if (!sources) return false;
  if (hasIntermediatePipeStage(sources)) return true;
  // Intermediate stages are handled only by the rule above. A single source
  // that is not a scannable TEXT_ONLY command fails closed.
  if (sources.length !== 1) return false;
  const src = sources[0]!;
  if (!viewOf(src).textOnly) return true;
  return nestedDisallowed(textOnlyOutput(src), depth);
}

/**
 * A here-string (`sh <<< '...'`) or an inline heredoc (`bash <<EOF ... EOF`)
 * on a shell is the script it will run, when the body is in the command text.
 */
function shellHereInputIsDisallowed(stmt: Statement, depth: number): boolean {
  const v = viewOf(stmt);
  // busybox sh/ash is a stdin shell too; STDIN_SHELLS.has(program) would miss it.
  if (!v.bareStdinShell) return false;
  if (stmt.hereDocMissing) return true;
  if (stmt.hereString) {
    if (stmt.hereString.dynamic) return true;
    return nestedDisallowed(stmt.hereString.text, depth);
  }
  if (stmt.hereDoc) {
    if (!stmt.hereDoc.quoted && /[$`]/.test(stmt.hereDoc.body)) return true;
    return nestedDisallowed(stmt.hereDoc.body, depth);
  }
  return false;
}

/**
 * Raw-text backstop (primary rule): if the literal NODE_OPTIONS appears
 * anywhere and we cannot prove every occurrence is a safe set, a proven
 * read, a proven unset, or non-executed TEXT_ONLY data, deny. The
 * structured parse above is the prove-safe path and still runs first so
 * known forms keep a precise check; this backstop catches constructs the
 * splitter does not model (subshell groups, process substitution, xargs).
 */
const NODE_OPTIONS_LIT = "NODE_OPTIONS";

function isIdentChar(c: string | undefined): boolean {
  return c !== undefined && /[A-Za-z0-9_]/.test(c);
}

function skipSpacesRaw(cmd: string, i: number): number {
  while (i < cmd.length && (cmd[i] === " " || cmd[i] === "\t")) i++;
  return i;
}

/** Index just after the `)` that matches `cmd[openAt] === "("`. */
function skipToMatchingParen(cmd: string, openAt: number): number {
  let depth = 1;
  let i = openAt + 1;
  let quote: "'" | '"' | "`" | null = null;
  while (i < cmd.length && depth > 0) {
    const c = cmd[i]!;
    if (quote) {
      if (quote !== "'" && c === "\\" && i + 1 < cmd.length) {
        i += 2;
        continue;
      }
      if (c === quote) quote = null;
      i++;
      continue;
    }
    if (c === "'" || c === '"' || c === "`") {
      quote = c;
      i++;
      continue;
    }
    if (c === "\\") {
      i += 2;
      continue;
    }
    if (c === "(") depth++;
    else if (c === ")") depth--;
    i++;
  }
  return i;
}

function collectRanges(
  cmd: string,
  from: number,
  to: number,
  proc: Array<[number, number]>,
  pipedGroup: Array<[number, number]>,
): void {
  let i = from;

  let quote: "'" | '"' | "`" | null = null;
  while (i < to) {
    const c = cmd[i]!;

    if (quote) {
      if (quote !== "'" && c === "\\" && i + 1 < cmd.length) {
        i += 2;
        continue;
      }
      if (c === quote) quote = null;
      i++;
      continue;
    }
    if (c === "'" || c === '"' || c === "`") {
      quote = c;
      i++;
      continue;
    }
    if (c === "\\") {
      i += 2;
      continue;
    }
    if ((c === "<" || c === ">") && cmd[i + 1] === "(") {
      const start = i;
      const after = skipToMatchingParen(cmd, i + 1);
      proc.push([start, after]);
      collectRanges(cmd, i + 2, after - 1, proc, pipedGroup);
      i = after;
      continue;
    }
    if (c === "(") {
      const start = i;
      const after = skipToMatchingParen(cmd, i);
      const j = skipSpacesRaw(cmd, after);
      if (cmd[j] === "|") pipedGroup.push([start, after]);
      collectRanges(cmd, i + 1, after - 1, proc, pipedGroup);
      i = after;
      continue;
    }
    i++;
  }
}

function inRanges(ranges: Array<[number, number]>, index: number): boolean {
  return ranges.some(([a, b]) => index >= a && index < b);
}

function readRawWord(cmd: string, i: number, end: number): { text: string; next: number } {
  let text = "";
  while (i < end && (cmd[i] === " " || cmd[i] === "\t")) i++;
  while (i < end) {
    const c = cmd[i]!;
    if (c === " " || c === "\t" || c === "\n" || c === ";" || c === "|" || c === "&" || c === "(" || c === ")" || c === "<" || c === ">") {
      break;
    }
    if (c === "\\") {
      if (i + 1 < end && cmd[i + 1] !== "\n") text += cmd[i + 1];
      i += 2;
      continue;
    }
    if (c === "'") {
      const q = cmd.indexOf("'", i + 1);
      if (q < 0 || q >= end) {
        text += cmd.slice(i + 1, end);
        return { text, next: end };
      }
      text += cmd.slice(i + 1, q);
      i = q + 1;
      continue;
    }
    if (c === '"') {
      let j = i + 1;
      while (j < end) {
        const d = cmd[j]!;
        if (d === "\\" && j + 1 < end) {
          text += cmd[j + 1];
          j += 2;
          continue;
        }
        if (d === '"') break;
        text += d;
        j++;
      }
      i = j < end ? j + 1 : end;
      continue;
    }
    text += c;
    i++;
  }
  return { text, next: i };
}

/**
 * Span of the statement that holds `index`, plus whether that statement is
 * piped (`|` or `|&` after it, or `cmd <<EOF | sh` with the heredoc body).
 */
function statementSpan(cmd: string, index: number): { start: number; end: number; piped: boolean } {
  let i = 0;
  let quote: "'" | '"' | "`" | null = null;
  let start = 0;
  let paren = 0;
  let pendingDelim: string | null = null;
  let pendingQuoted = false;
  let pendingStrip = false;
  let bodyStart = -1;
  let spanStart = 0;
  let spanEnd = cmd.length;
  let spanPiped = false;
  let found = false;

  const endStmt = (at: number, piped: boolean) => {
    const end = at;
    if (!found && index >= spanStart && index < end) {
      found = true;
      start = spanStart;
      spanEnd = end;
      spanPiped = piped;
    }
    spanStart = at;
  };

  while (i < cmd.length) {
    const step = i;
    const c = cmd[i]!;

    if (pendingDelim !== null && quote === null && paren === 0 && c === "\n" && bodyStart < 0) {
      bodyStart = i + 1;
      i++;
      continue;
    }
    if (pendingDelim !== null && bodyStart >= 0 && quote === null && c === "\n" || (pendingDelim !== null && bodyStart >= 0 && i === 0)) {
      // handled below per line
    }
    if (pendingDelim !== null && bodyStart >= 0 && quote === null) {
      // Check whether this line is the closer.
      const nl = cmd.indexOf("\n", i);
      const lineEnd = nl < 0 ? cmd.length : nl;
      const line = cmd.slice(i, lineEnd);
      const cmp = pendingStrip ? line.replace(/^\t+/, "") : line;
      if (cmp === pendingDelim) {
        pendingDelim = null;
        bodyStart = -1;
        i = nl < 0 ? cmd.length : nl + 1;
        continue;
      }
      i = nl < 0 ? cmd.length : nl + 1;
      continue;
    }
    if (quote) {
      if (quote !== "'" && c === "\\" && i + 1 < cmd.length) {
        i += 2;
        continue;
      }
      if (c === quote) quote = null;
      i++;
      continue;
    }
    if (c === "'" || c === '"' || c === "`") {
      quote = c;
      i++;
      continue;
    }
    if (c === "\\") {
      i += 2;
      continue;
    }
    if (c === "<" && cmd.startsWith("<<<", i)) {
      i += 3;
      const w = readRawWord(cmd, i, cmd.length);
      i = w.next;
      continue;
    }
    if (c === "<" && cmd.startsWith("<<", i)) {
      i += 2;
      pendingStrip = cmd[i] === "-";
      if (pendingStrip) i++;
      i = skipSpacesRaw(cmd, i);
      if (cmd[i] === "'" || cmd[i] === '"') {
        const q = cmd[i]!;
        const end = cmd.indexOf(q, i + 1);
        pendingQuoted = true;
        pendingDelim = end < 0 ? cmd.slice(i + 1) : cmd.slice(i + 1, end);
        i = end < 0 ? cmd.length : end + 1;
      } else {
        pendingQuoted = false;
        const w = readRawWord(cmd, i, cmd.length);
        pendingDelim = w.text;
        i = w.next > i ? w.next : i + 1;
      }
      if (!pendingDelim) pendingDelim = null;
      bodyStart = -1;
      void pendingQuoted;
      continue;
    }
    if ((c === "<" || c === ">") && cmd[i + 1] === "(") {
      i = skipToMatchingParen(cmd, i + 1);
      continue;
    }
    if (c === "<" || c === ">") {
      i++;
      if (cmd[i] === c) i++;
      if (cmd[i] === "&") i++;
      const w = readRawWord(cmd, i, cmd.length);
      i = w.next;
      continue;
    }
    if (c === "(") {
      paren++;
      i++;
      continue;
    }
    if (c === ")") {
      if (paren > 0) paren--;
      i++;
      continue;
    }
    if (paren === 0 && (c === "\n" || c === ";" || c === "|" || c === "&")) {
      let piped = c === "|";
      let next = i + 1;
      if (c === "|" && cmd[i + 1] === "|") {
        piped = false;
        next = i + 2;
      } else if (c === "|" && cmd[i + 1] === "&") {
        piped = true;
        next = i + 2;
      } else if (c === "&" && cmd[i + 1] === "&") {
        piped = false;
        next = i + 2;
      }
      endStmt(i, piped);
      i = next;
      continue;
    }
    i++;
    if (i <= step) i = step + 1;
  }
  if (!found) {
    start = spanStart;
    spanEnd = cmd.length;
    spanPiped = false;
  }
  return { start, end: spanEnd, piped: spanPiped };
}

function firstProgram(cmd: string, start: number, end: number): string | null {
  let i = start;
  while (i < end) {
    while (i < end && /[ \t\n]/.test(cmd[i]!)) i++;
    if (i >= end) break;
    if (cmd[i] === "(" || cmd[i] === ")" || cmd[i] === ";" || cmd[i] === "|" || cmd[i] === "&") {
      i++;
      continue;
    }
    if (cmd[i] === "<" || cmd[i] === ">") break;
    const { text, next } = readRawWord(cmd, i, end);
    if (next <= i) {
      i++;
      continue;
    }
    i = next;
    if (!text) continue;
    if (ASSIGN_WORD.test(text) || ANY_ASSIGN.test(text)) continue;
    const base = text.slice(text.lastIndexOf("/") + 1);
    if (WRAPPERS.has(base)) continue;
    if (text.startsWith("-")) continue;
    return base;
  }
  return null;
}

function wordsBefore(cmd: string, start: number, index: number): string[] {
  const words: string[] = [];
  let j = start;
  while (j < index) {
    while (j < index && /[ \t]/.test(cmd[j]!)) j++;
    if (j >= index) break;
    if (cmd[j] === "\n" || cmd[j] === ";" || cmd[j] === "|" || cmd[j] === "&" || cmd[j] === "(" || cmd[j] === ")") {
      j++;
      continue;
    }
    const { text, next } = readRawWord(cmd, j, index);
    if (next === j) {
      j++;
      continue;
    }
    if (text) words.push(text);
    j = next;
  }
  return words;
}

function parseUnquotedOrQuotedValue(cmd: string, eqAfter: number): string | null {
  const j = eqAfter;
  if (j >= cmd.length) return "";
  if (cmd[j] === "'") {
    const end = cmd.indexOf("'", j + 1);
    if (end < 0) return null;
    return cmd.slice(j + 1, end);
  }
  if (cmd[j] === '"') {
    let k = j + 1;
    let out = "";
    while (k < cmd.length) {
      const d = cmd[k]!;
      if (d === "\\" && k + 1 < cmd.length) {
        out += cmd[k + 1];
        k += 2;
        continue;
      }
      if (d === '"') return out;
      if (d === "`" || d === "$") return null;
      out += d;
      k++;
    }
    return null;
  }
  let k = j;
  while (k < cmd.length && !/[\s;|&()<>'"\\]/.test(cmd[k]!)) k++;
  const v = cmd.slice(j, k);
  if (/[$`]/.test(v)) return null;
  return v;
}

/**
 * True when the NODE_OPTIONS at `index` is proven safe: an allow-listed
 * assignment, a plain read, an unset / env -u, or non-executed TEXT_ONLY data.
 */
function leadingProgram(words: string[]): { prog: string | null; rest: string[] } {
  const named = new Set(["env", "unset", "printenv", "grep", "egrep", "fgrep", "rg"]);
  let i = 0;
  while (i < words.length) {
    const base = words[i]!.slice(words[i]!.lastIndexOf("/") + 1);
    if (named.has(base)) return { prog: base, rest: words.slice(i + 1) };
    if (WRAPPERS.has(base) || base.startsWith("-")) {
      i++;
      continue;
    }
    return { prog: base, rest: words.slice(i + 1) };
  }
  return { prog: null, rest: [] };
}

function occurrenceIsProvenSafe(cmd: string, index: number, proc: Array<[number, number]>, pipedGroup: Array<[number, number]>): boolean {
  const after = index + NODE_OPTIONS_LIT.length;
  const gluedUnset =
    (index >= 2 && cmd.slice(index - 2, index) === "-u") || cmd.slice(0, index).endsWith("--unset=");
  // A longer identifier (NODE_OPTIONS_FOO, FOO_NODE_OPTIONS) is not this variable.
  if (!gluedUnset && (isIdentChar(cmd[index - 1]) || isIdentChar(cmd[after]))) return true;

  // $NODE_OPTIONS (not $NODE_OPTIONS_FOO)
  if (cmd[index - 1] === "$" && !isIdentChar(cmd[after])) return true;

  // ${NODE_OPTIONS} and ${NODE_OPTIONS...} parameter expansions
  if (cmd[index - 2] === "$" && cmd[index - 1] === "{") {
    const c = cmd[after];
    if (c === "}") return true;
    if (c === "=" || (c === ":" && cmd[after + 1] === "=")) {
      const valStart = c === ":" ? after + 2 : after + 1;
      const end = cmd.indexOf("}", valStart);
      if (end < 0) return false;
      return isAllowedNodeOptionsValue(cmd.slice(valStart, end));
    }
    if (c === ":" || c === "-" || c === "+" || c === "?" || c === "#" || c === "%" || c === "/" || c === "^" || c === ",") {
      return true;
    }
    return false;
  }

  // --unset=NODE_OPTIONS or -uNODE_OPTIONS
  if (cmd.slice(0, index).endsWith("--unset=")) return true;
  if (index >= 2 && cmd.slice(index - 2, index) === "-u" && !isIdentChar(cmd[index - 3])) return true;

  const span = statementSpan(cmd, index);
  const words = wordsBefore(cmd, span.start, index).filter((w) => w !== "--");
  const lead = leadingProgram(words);
  const progWord = lead.prog ?? firstProgram(cmd, span.start, span.end);
  const flags = lead.rest;

  // unset NODE_OPTIONS, unset -v NODE_OPTIONS
  if (progWord === "unset" && flags.every((w) => w.startsWith("-")) && !isIdentChar(cmd[after])) return true;
  // env -u NODE_OPTIONS, env --unset NODE_OPTIONS
  if (
    progWord === "env" &&
    flags.some((w) => w === "-u" || w === "--unset" || w.startsWith("--unset=") || /^-[a-zA-Z]*u$/.test(w) && w.includes("u")) &&
    !isIdentChar(cmd[after]) &&
    cmd[after] !== "="
  ) {
    return true;
  }

  // printenv NODE_OPTIONS
  if (progWord === "printenv" && cmd[after] !== "=" && !isIdentChar(cmd[after])) return true;
  // env | grep NODE_OPTIONS  (or egrep/fgrep/rg)
  if (
    (progWord === "grep" || progWord === "egrep" || progWord === "fgrep" || progWord === "rg") &&
    cmd[after] !== "=" &&
    !isIdentChar(cmd[after])
  ) {
    return true;
  }

  // NODE_OPTIONS=allow-listed-value (export/env/declare/bare, or inside quotes)
  if (cmd[after] === "=" && cmd[after + 1] !== "+") {
    if (cmd.startsWith("+=", after)) return false;
    const value = parseUnquotedOrQuotedValue(cmd, after + 1);
    if (value !== null && isAllowedNodeOptionsValue(value)) return true;
    // A bad or dynamic value is only acceptable as non-executed TEXT_ONLY data.
  } else if (cmd.startsWith("+=", after)) {
    return false;
  }

  // Non-executed TEXT_ONLY data (unpiped echo/cat/printf, cat heredoc, ...).
  if (inRanges(proc, index) || inRanges(pipedGroup, index)) return false;
  if (span.piped) return false;
  const program = firstProgram(cmd, span.start, span.end);
  return program !== null && TEXT_ONLY.has(program);
}

/** Primary backstop: any unproven NODE_OPTIONS occurrence is SELF005. */
function unprovenNodeOptionsBackstop(cmd: string): boolean {
  const proc: Array<[number, number]> = [];
  const pipedGroup: Array<[number, number]> = [];
  collectRanges(cmd, 0, cmd.length, proc, pipedGroup);
  let i = 0;
  while (i < cmd.length) {
    const at = cmd.indexOf(NODE_OPTIONS_LIT, i);
    if (at < 0) return false;
    if (!occurrenceIsProvenSafe(cmd, at, proc, pipedGroup)) return true;
    i = at + NODE_OPTIONS_LIT.length;
  }
  return false;
}

/**
 * True when `cmd` sets NODE_OPTIONS to anything outside the allow list, or
 * in a way that cannot be checked. Every statement is checked (after ; && ||
 * & | and newlines), including a lone assignment with no program, export and
 * the other setters, the inner command of sh/bash/zsh/dash -c and eval, a
 * TEXT_ONLY command piped directly into a bare stdin shell with no -c (also
 * ksh, mksh, ash, and busybox sh/ash), a pipeline that places any stage
 * between that text and the shell, and a here-string or inline heredoc on
 * those shells, up to a fixed depth. After the structured parse, a raw-text
 * backstop denies unless every NODE_OPTIONS occurrence is a proven-safe set,
 * a proven read or unset, or non-executed TEXT_ONLY data. Never throws.
 */
export function hasDisallowedNodeOptions(cmd: string, depth = 0): boolean {
  if (!cmd.includes("NODE_OPTIONS")) return false;
  if (depth > MAX_DEPTH) return true;
  let statements: Statement[];
  try {
    statements = splitStatements(cmd);
  } catch {
    return true;
  }
  for (let s = 0; s < statements.length; s++) {
    const stmt = statements[s]!;
    if (pipelineIntoShellIsDisallowed(statements, s, depth)) return true;
    if (shellHereInputIsDisallowed(stmt, depth)) return true;
    let program: string | null = null;
    let setter = false;
    let textOnly = false;
    const words = stmt.words;
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
  if (unprovenNodeOptionsBackstop(cmd)) return true;
  return false;
}
