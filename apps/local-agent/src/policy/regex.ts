import vm from "node:vm";

export const MAX_REGEX_LENGTH = 300;
export const REGEX_TIMEOUT_MS = 50;
export const MAX_REGEX_CACHE_SIZE = 256;
const MAX_QUANTIFIER_BOUND = 100;
const MAX_GROUP_DEPTH = 16;

const CHARSET_SIZE = 130; // 0..127 ASCII, 128 = non-ASCII space, 129 = non-ASCII non-space
const NON_ASCII_SPACE = 128;
const NON_ASCII_NON_SPACE = 129;

type CharSet = Uint8Array;

interface GroupFrame {
  hasQuantifier: boolean;
  hasAlternation: boolean;
}

interface SeqToken {
  kind: "atom" | "group" | "assertion";
  charSet: CharSet;
  min: number;
  unbounded: boolean;
  isWhitespaceEscape: boolean;
}

function emptyCharSet(): CharSet {
  return new Uint8Array(CHARSET_SIZE);
}

function universalCharSet(): CharSet {
  const s = new Uint8Array(CHARSET_SIZE);
  s.fill(1);
  return s;
}

function addAsciiCode(set: CharSet, code: number): void {
  if (code < 0 || code > 127) return;
  set[code] = 1;
  // Fold ASCII case so disjointness holds under both case-sensitive and /i matching.
  if (code >= 65 && code <= 90) {
    set[code + 32] = 1;
  } else if (code >= 97 && code <= 122) {
    set[code - 32] = 1;
  }
}

function addChar(set: CharSet, ch: string): { exactNonAscii: boolean } {
  const code = ch.charCodeAt(0);
  if (code < 128) {
    addAsciiCode(set, code);
    return { exactNonAscii: true };
  }
  if (/\s/.test(ch)) {
    set[NON_ASCII_SPACE] = 1;
  } else {
    set[NON_ASCII_NON_SPACE] = 1;
  }
  return { exactNonAscii: false };
}

function unionInto(target: CharSet, src: CharSet): void {
  for (let i = 0; i < CHARSET_SIZE; i++) {
    if (src[i]) target[i] = 1;
  }
}

function areDisjoint(a: CharSet, b: CharSet): boolean {
  for (let i = 0; i < CHARSET_SIZE; i++) {
    if (a[i] && b[i]) return false;
  }
  return true;
}

function buildSpaceSet(): CharSet {
  const s = emptyCharSet();
  for (const code of [9, 10, 11, 12, 13, 32]) s[code] = 1;
  s[NON_ASCII_SPACE] = 1;
  return s;
}

function buildDigitSet(): CharSet {
  const s = emptyCharSet();
  for (let c = 48; c <= 57; c++) s[c] = 1;
  return s;
}

function buildWordSet(): CharSet {
  const s = emptyCharSet();
  for (let c = 48; c <= 57; c++) s[c] = 1;
  for (let c = 65; c <= 90; c++) addAsciiCode(s, c);
  s[95] = 1; // '_'
  return s;
}

function complementExact(src: CharSet): CharSet {
  const out = emptyCharSet();
  for (let i = 0; i < CHARSET_SIZE; i++) {
    out[i] = src[i] ? 0 : 1;
  }
  return out;
}

const SPACE_SET = buildSpaceSet();
const NON_SPACE_SET = complementExact(SPACE_SET);
const DIGIT_SET = buildDigitSet();
const NON_DIGIT_SET = complementExact(DIGIT_SET);
const WORD_SET = buildWordSet();
const NON_WORD_SET = complementExact(WORD_SET);

const CONTROL_ESCAPES: Record<string, number> = {
  t: 9,
  n: 10,
  v: 11,
  f: 12,
  r: 13,
  "0": 0,
};

function escapeToCharSet(
  next: string,
  inCharClass: boolean,
): {
  set: CharSet;
  isWhitespaceEscape: boolean;
  isAssertion: boolean;
  isShorthandClass: boolean;
  singleCode: number | null;
} {
  if (!inCharClass && (next === "b" || next === "B")) {
    return {
      set: emptyCharSet(),
      isWhitespaceEscape: false,
      isAssertion: true,
      isShorthandClass: false,
      singleCode: null,
    };
  }
  if (next === "s") {
    return {
      set: SPACE_SET,
      isWhitespaceEscape: true,
      isAssertion: false,
      isShorthandClass: true,
      singleCode: null,
    };
  }
  if (next === "S") {
    return {
      set: NON_SPACE_SET,
      isWhitespaceEscape: false,
      isAssertion: false,
      isShorthandClass: true,
      singleCode: null,
    };
  }
  if (next === "d") {
    return {
      set: DIGIT_SET,
      isWhitespaceEscape: false,
      isAssertion: false,
      isShorthandClass: true,
      singleCode: null,
    };
  }
  if (next === "D") {
    return {
      set: NON_DIGIT_SET,
      isWhitespaceEscape: false,
      isAssertion: false,
      isShorthandClass: true,
      singleCode: null,
    };
  }
  if (next === "w") {
    return {
      set: WORD_SET,
      isWhitespaceEscape: false,
      isAssertion: false,
      isShorthandClass: true,
      singleCode: null,
    };
  }
  if (next === "W") {
    return {
      set: NON_WORD_SET,
      isWhitespaceEscape: false,
      isAssertion: false,
      isShorthandClass: true,
      singleCode: null,
    };
  }
  if (Object.prototype.hasOwnProperty.call(CONTROL_ESCAPES, next)) {
    const code = CONTROL_ESCAPES[next]!;
    const set = emptyCharSet();
    set[code] = 1;
    return {
      set,
      isWhitespaceEscape: false,
      isAssertion: false,
      isShorthandClass: false,
      singleCode: code,
    };
  }
  // Unmodeled escapes (\x, \u, \p, \P, \c, or unknown ASCII letters) conservatively overlap everything.
  if ((next >= "a" && next <= "z") || (next >= "A" && next <= "Z")) {
    return {
      set: universalCharSet(),
      isWhitespaceEscape: false,
      isAssertion: false,
      isShorthandClass: true,
      singleCode: null,
    };
  }
  // Punctuation / literal escape (\|, \., \/, \-, \\, etc.)
  const set = emptyCharSet();
  addChar(set, next);
  const code = next.charCodeAt(0);
  return {
    set,
    isWhitespaceEscape: false,
    isAssertion: false,
    isShorthandClass: false,
    singleCode: code < 128 ? code : null,
  };
}

function parseCharClass(
  pattern: string,
  start: number,
): { end: number; set: CharSet } | null {
  if (pattern[start] !== "[") return null;
  let i = start + 1;
  let negated = false;
  if (pattern[i] === "^") {
    negated = true;
    i++;
  }

  const pos = emptyCharSet();
  let exactNonAscii = true;
  let prevSingleCode: number | null = null;
  let firstItem = true;

  while (i < pattern.length) {
    const ch = pattern[i]!;
    if (ch === "]" && !firstItem) {
      let set = pos;
      if (negated) {
        set = complementExact(pos);
        if (!exactNonAscii) {
          set[NON_ASCII_SPACE] = 1;
          set[NON_ASCII_NON_SPACE] = 1;
        }
      }
      return { end: i, set };
    }
    firstItem = false;

    // Range like a-z or 0-9 (only when preceded by a single literal and followed by non-']')
    if (ch === "-" && prevSingleCode !== null && i + 1 < pattern.length && pattern[i + 1] !== "]") {
      i++;
      let endCode: number | null = null;
      if (pattern[i] === "\\") {
        const next = pattern[i + 1];
        if (next === undefined) return null;
        const esc = escapeToCharSet(next, true);
        if (esc.isShorthandClass || esc.singleCode === null) {
          unionInto(pos, universalCharSet());
          exactNonAscii = false;
        } else {
          endCode = esc.singleCode;
        }
        i += 2;
      } else {
        const c = pattern[i]!.charCodeAt(0);
        endCode = c < 128 ? c : null;
        if (endCode === null) {
          pos[NON_ASCII_SPACE] = 1;
          pos[NON_ASCII_NON_SPACE] = 1;
          exactNonAscii = false;
        }
        i++;
      }
      if (endCode !== null) {
        if (endCode < prevSingleCode) return null;
        for (let code = prevSingleCode; code <= endCode; code++) {
          addAsciiCode(pos, code);
        }
      }
      prevSingleCode = null;
      continue;
    }

    if (ch === "\\") {
      const next = pattern[i + 1];
      if (next === undefined) return null;
      const esc = escapeToCharSet(next, true);
      unionInto(pos, esc.set);
      if (esc.set[NON_ASCII_SPACE] && esc.set[NON_ASCII_NON_SPACE] && esc.singleCode === null && !esc.isShorthandClass) {
        exactNonAscii = false;
      }
      prevSingleCode = esc.isShorthandClass ? null : esc.singleCode;
      i += 2;
      continue;
    }

    const added = addChar(pos, ch);
    if (!added.exactNonAscii) exactNonAscii = false;
    const code = ch.charCodeAt(0);
    prevSingleCode = code < 128 ? code : null;
    i++;
  }

  return null;
}

function validateBranchUnboundedTokens(tokens: SeqToken[]): boolean {
  const unboundedIdx: number[] = [];
  for (let i = 0; i < tokens.length; i++) {
    if (tokens[i]!.unbounded) unboundedIdx.push(i);
  }
  if (unboundedIdx.length <= 1) return true;

  for (let k = 0; k < unboundedIdx.length - 1; k++) {
    const aIdx = unboundedIdx[k]!;
    const bIdx = unboundedIdx[k + 1]!;
    const tokA = tokens[aIdx]!;
    const tokB = tokens[bIdx]!;

    // (a) Mandatory literal or character class strictly between A and B disjoint from both.
    let hasDisjointBarrier = false;
    for (let m = aIdx + 1; m < bIdx; m++) {
      const mid = tokens[m]!;
      if (
        mid.kind === "atom" &&
        mid.min >= 1 &&
        areDisjoint(mid.charSet, tokA.charSet) &&
        areDisjoint(mid.charSet, tokB.charSet)
      ) {
        hasDisjointBarrier = true;
        break;
      }
    }
    if (hasDisjointBarrier) continue;

    // (b) Directly adjacent where one atom is a mandatory whitespace escape (\s+ / \s{n,})
    // and both atoms have disjoint character sets (e.g. \s+\w+ in (DROP|TRUNCATE)\s+TABLE\s+\w+).
    if (
      bIdx === aIdx + 1 &&
      ((tokA.isWhitespaceEscape && tokA.min >= 1) ||
        (tokB.isWhitespaceEscape && tokB.min >= 1)) &&
      areDisjoint(tokA.charSet, tokB.charSet)
    ) {
      continue;
    }

    return false;
  }

  // Also reject any non-consecutive pair (u_a, u_b) where every intermediate token
  // can match empty (min === 0), since u_a can meet u_b directly (e.g. \w+\s*\w+, \s+[a-z]*\s+).
  for (let a = 0; a < unboundedIdx.length; a++) {
    for (let b = a + 2; b < unboundedIdx.length; b++) {
      let allSkippable = true;
      for (let m = unboundedIdx[a]! + 1; m < unboundedIdx[b]!; m++) {
        if (tokens[m]!.min >= 1) {
          allSkippable = false;
          break;
        }
      }
      if (allSkippable) return false;
    }
  }

  return true;
}

const regexVmContext = vm.createContext({});
const compileScript = new vm.Script("new RegExp(pattern, flags)");
const testScript = new vm.Script("re.test(text)");
const compiledRegexCache = new Map<string, RegExp | null>();

function isVmTimeoutError(err: unknown): boolean {
  if (!err || typeof err !== "object") return false;
  const e = err as { code?: unknown; message?: unknown };
  if (e.code === "ERR_SCRIPT_EXECUTION_TIMEOUT") return true;
  if (
    typeof e.message === "string" &&
    e.message.includes("Script execution timed out")
  ) {
    return true;
  }
  return false;
}

export function clearRegexCache(): void {
  compiledRegexCache.clear();
}

export function getRegexCacheSize(): number {
  return compiledRegexCache.size;
}

function setCachedRegex(key: string, value: RegExp | null): void {
  if (compiledRegexCache.has(key)) {
    compiledRegexCache.delete(key);
  } else if (compiledRegexCache.size >= MAX_REGEX_CACHE_SIZE) {
    const oldest = compiledRegexCache.keys().next().value;
    if (oldest !== undefined) {
      compiledRegexCache.delete(oldest);
    }
  }
  compiledRegexCache.set(key, value);
}

function parseBraceQuantifier(
  pattern: string,
  start: number,
): {
  end: number;
  min: number;
  repeating: boolean;
  unbounded: boolean;
  tooLarge: boolean;
  invalidRange: boolean;
} | null {
  if (pattern[start] !== "{") return null;
  let i = start + 1;
  let minStr = "";
  while (i < pattern.length && pattern[i]! >= "0" && pattern[i]! <= "9") {
    minStr += pattern[i];
    i++;
  }
  if (minStr.length === 0) return null;

  let maxStr: string | null = minStr;
  if (pattern[i] === ",") {
    i++;
    maxStr = "";
    while (i < pattern.length && pattern[i]! >= "0" && pattern[i]! <= "9") {
      maxStr += pattern[i];
      i++;
    }
  }
  if (pattern[i] !== "}") return null;

  const min = Number(minStr);
  const max = maxStr === "" ? Infinity : Number(maxStr);
  const unbounded = max === Infinity;
  const invalidRange = Number.isFinite(max) && max < min;
  const tooLarge =
    min > MAX_QUANTIFIER_BOUND ||
    (Number.isFinite(max) && max > MAX_QUANTIFIER_BOUND);
  const repeating = max > 1 || unbounded;
  return { end: i, min, repeating, unbounded, tooLarge, invalidRange };
}

/**
 * Checks that a pattern stays within an RE2-safe subset without nested
 * repeating quantifiers, alternation-plus-quantifier groups, overlapping
 * multiple unbounded quantifiers, lookarounds, or backreferences.
 */
export function isRe2SafePattern(pattern: string): boolean {
  if (typeof pattern !== "string") return false;
  if (pattern.length > MAX_REGEX_LENGTH) return false;

  const stack: GroupFrame[] = [
    { hasQuantifier: false, hasAlternation: false },
  ];
  const topBranches: SeqToken[][] = [[]];
  let currentBranch = topBranches[0]!;
  let lastAtomWasQuantifiedGroup = false;
  let lastAtomWasAlternationGroup = false;
  let lastAtomWasGroup = false;
  let justOpenedGroup = false;
  let totalUnbounded = 0;
  let hasUnboundedInsideGroup = false;

  const pushTopToken = (tok: SeqToken): void => {
    if (stack.length === 1) {
      currentBranch.push(tok);
    }
  };

  const applyQuantifierToLast = (min: number, unbounded: boolean): void => {
    if (unbounded) {
      totalUnbounded++;
      if (stack.length > 1) {
        hasUnboundedInsideGroup = true;
      }
    }
    if (stack.length === 1 && currentBranch.length > 0) {
      const last = currentBranch[currentBranch.length - 1]!;
      last.min = min;
      if (unbounded) {
        last.unbounded = true;
        if (last.kind === "group") {
          last.charSet = universalCharSet();
          last.isWhitespaceEscape = false;
        }
      }
    }
  };

  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i]!;
    const wasGroupStart = justOpenedGroup;
    justOpenedGroup = false;

    if (wasGroupStart && ch === "?") {
      if (pattern[i + 1] === ":") {
        i++;
      } else if (pattern[i + 1] === "<") {
        const closeAngle = pattern.indexOf(">", i + 2);
        if (closeAngle === -1) return false;
        i = closeAngle;
      }
      continue;
    }

    if (ch === "\\") {
      const next = pattern[i + 1];
      if (next === undefined) return false;
      if (next >= "1" && next <= "9") return false;
      if (next === "k" && pattern[i + 2] === "<") return false;

      const esc = escapeToCharSet(next, false);
      if (esc.isAssertion) {
        pushTopToken({
          kind: "assertion",
          charSet: esc.set,
          min: 0,
          unbounded: false,
          isWhitespaceEscape: false,
        });
      } else {
        pushTopToken({
          kind: "atom",
          charSet: esc.set,
          min: 1,
          unbounded: false,
          isWhitespaceEscape: esc.isWhitespaceEscape,
        });
      }
      lastAtomWasGroup = false;
      lastAtomWasQuantifiedGroup = false;
      lastAtomWasAlternationGroup = false;
      i++;
      continue;
    }

    if (ch === "[") {
      const parsed = parseCharClass(pattern, i);
      if (!parsed) return false;
      pushTopToken({
        kind: "atom",
        charSet: parsed.set,
        min: 1,
        unbounded: false,
        isWhitespaceEscape: false,
      });
      i = parsed.end;
      lastAtomWasGroup = false;
      lastAtomWasQuantifiedGroup = false;
      lastAtomWasAlternationGroup = false;
      continue;
    }

    if (ch === "|") {
      stack[stack.length - 1]!.hasAlternation = true;
      if (stack.length === 1) {
        currentBranch = [];
        topBranches.push(currentBranch);
      }
      lastAtomWasGroup = false;
      lastAtomWasQuantifiedGroup = false;
      lastAtomWasAlternationGroup = false;
      continue;
    }

    if (ch === "(") {
      if (stack.length > MAX_GROUP_DEPTH) return false;
      if (pattern[i + 1] === "?") {
        const marker = pattern[i + 2];
        if (marker === "=" || marker === "!") return false;
        if (
          marker === "<" &&
          (pattern[i + 3] === "=" || pattern[i + 3] === "!")
        ) {
          return false;
        }
      }
      stack.push({ hasQuantifier: false, hasAlternation: false });
      justOpenedGroup = true;
      lastAtomWasGroup = false;
      lastAtomWasQuantifiedGroup = false;
      lastAtomWasAlternationGroup = false;
      continue;
    }

    if (ch === ")") {
      if (stack.length <= 1) return false;
      const closed = stack.pop()!;
      const parent = stack[stack.length - 1]!;
      if (closed.hasQuantifier) {
        parent.hasQuantifier = true;
      }
      if (closed.hasAlternation) {
        parent.hasAlternation = true;
      }
      pushTopToken({
        kind: "group",
        charSet: universalCharSet(),
        min: 1,
        unbounded: false,
        isWhitespaceEscape: false,
      });
      lastAtomWasGroup = true;
      lastAtomWasQuantifiedGroup = closed.hasQuantifier;
      lastAtomWasAlternationGroup = closed.hasAlternation;
      continue;
    }

    if (ch === "*" || ch === "+") {
      if (
        lastAtomWasGroup &&
        (lastAtomWasQuantifiedGroup || lastAtomWasAlternationGroup)
      ) {
        return false;
      }
      applyQuantifierToLast(ch === "*" ? 0 : 1, true);
      stack[stack.length - 1]!.hasQuantifier = true;
      if (pattern[i + 1] === "?") i++;
      lastAtomWasGroup = false;
      lastAtomWasQuantifiedGroup = false;
      lastAtomWasAlternationGroup = false;
      continue;
    }

    if (ch === "?") {
      applyQuantifierToLast(0, false);
      stack[stack.length - 1]!.hasQuantifier = true;
      if (pattern[i + 1] === "?") i++;
      lastAtomWasGroup = false;
      lastAtomWasQuantifiedGroup = false;
      lastAtomWasAlternationGroup = false;
      continue;
    }

    if (ch === "{") {
      const parsed = parseBraceQuantifier(pattern, i);
      if (parsed) {
        if (parsed.tooLarge || parsed.invalidRange) return false;
        if (parsed.repeating) {
          if (
            lastAtomWasGroup &&
            (lastAtomWasQuantifiedGroup || lastAtomWasAlternationGroup)
          ) {
            return false;
          }
        }
        applyQuantifierToLast(parsed.min, parsed.unbounded);
        stack[stack.length - 1]!.hasQuantifier = true;
        i = parsed.end;
        if (pattern[i + 1] === "?") i++;
        lastAtomWasGroup = false;
        lastAtomWasQuantifiedGroup = false;
        lastAtomWasAlternationGroup = false;
        continue;
      }
    }

    if (ch === "^" || ch === "$") {
      pushTopToken({
        kind: "assertion",
        charSet: emptyCharSet(),
        min: 0,
        unbounded: false,
        isWhitespaceEscape: false,
      });
    } else if (ch === ".") {
      pushTopToken({
        kind: "atom",
        charSet: universalCharSet(),
        min: 1,
        unbounded: false,
        isWhitespaceEscape: false,
      });
    } else {
      const set = emptyCharSet();
      addChar(set, ch);
      pushTopToken({
        kind: "atom",
        charSet: set,
        min: 1,
        unbounded: false,
        isWhitespaceEscape: false,
      });
    }

    lastAtomWasGroup = false;
    lastAtomWasQuantifiedGroup = false;
    lastAtomWasAlternationGroup = false;
  }

  if (stack.length !== 1) return false;

  if (totalUnbounded > 1) {
    if (hasUnboundedInsideGroup) return false;
    for (const branch of topBranches) {
      if (!validateBranchUnboundedTokens(branch)) return false;
    }
  }

  try {
    // Syntax check only (never executes regex matching).
    new RegExp(pattern);
  } catch {
    return false;
  }

  return true;
}

export interface SafeRegexOptions {
  caseSensitive?: boolean;
  timeoutMs?: number;
  onTimeout?: () => void;
}

/**
 * Compiles an RE2-safe regex with a length cap, bounded compile cache, and
 * timeout guard. Returns null if invalid, over-length, or unsafe. Never throws.
 */
export function compileSafeRegex(
  pattern: string,
  opts: SafeRegexOptions = {},
): RegExp | null {
  if (typeof pattern !== "string") return null;
  if (pattern.length > MAX_REGEX_LENGTH) return null;

  const flags = opts.caseSensitive ? "" : "i";
  const cacheKey = `${flags}\0${pattern}`;
  if (compiledRegexCache.has(cacheKey)) {
    const cached = compiledRegexCache.get(cacheKey) ?? null;
    setCachedRegex(cacheKey, cached);
    return cached;
  }

  if (!isRe2SafePattern(pattern)) {
    setCachedRegex(cacheKey, null);
    return null;
  }

  const timeoutMs = opts.timeoutMs ?? REGEX_TIMEOUT_MS;
  try {
    regexVmContext.pattern = pattern;
    regexVmContext.flags = flags;
    compileScript.runInContext(regexVmContext, {
      timeout: timeoutMs,
    });
    const compiled = new RegExp(pattern, flags);
    setCachedRegex(cacheKey, compiled);
    return compiled;
  } catch (err) {
    if (isVmTimeoutError(err)) {
      // Never cache transient VM timeouts as permanent failures.
      opts.onTimeout?.();
      return null;
    }
    setCachedRegex(cacheKey, null);
    return null;
  } finally {
    regexVmContext.pattern = undefined;
    regexVmContext.flags = undefined;
  }
}

/**
 * Tests text against a compiled RegExp under a VM timeout guard.
 * Returns false on timeout or error without throwing.
 */
export function testSafeRegex(
  re: RegExp,
  text: string,
  timeoutMs: number = REGEX_TIMEOUT_MS,
  onTimeout?: () => void,
): boolean {
  try {
    regexVmContext.re = re;
    regexVmContext.text = text;
    return Boolean(testScript.runInContext(regexVmContext, { timeout: timeoutMs }));
  } catch (err) {
    if (isVmTimeoutError(err)) {
      onTimeout?.();
    }
    return false;
  } finally {
    regexVmContext.re = undefined;
    regexVmContext.text = undefined;
  }
}
