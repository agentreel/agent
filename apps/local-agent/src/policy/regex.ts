import vm from "node:vm";

export const MAX_REGEX_LENGTH = 300;
export const REGEX_TIMEOUT_MS = 50;
export const MAX_REGEX_CACHE_SIZE = 256;
const MAX_QUANTIFIER_BOUND = 100;
const MAX_GROUP_DEPTH = 16;
const MAX_UNICODE_CODE_POINT = 0x10ffff;

const CHARSET_SIZE = 130; // 0..127 ASCII, 128 = non-ASCII space, 129 = non-ASCII non-space
const NON_ASCII_SPACE = 128;
const NON_ASCII_NON_SPACE = 129;

type CharSet = Uint8Array;

interface GroupFrame {
  hasQuantifier: boolean;
  hasAlternation: boolean;
  allBranchesLiteralOnly: boolean;
  currentBranchLiteralOnly: boolean;
  currentBranchTokenCount: number;
  lastTokenIsLiteralLike: boolean;
  currentBranchLastCharSet: CharSet | null;
  allBranchesLastCharSet: CharSet;
}

interface SeqToken {
  kind: "atom" | "group" | "assertion";
  charSet: CharSet;
  groupLastCharSet: CharSet | null;
  min: number;
  unbounded: boolean;
  isWhitespaceEscape: boolean;
  isLiteral: boolean;
  isLiteralOnlyGroup: boolean;
  isCaret: boolean;
}

interface ParsedEscape {
  end: number;
  set: CharSet;
  isWhitespaceEscape: boolean;
  isAssertion: boolean;
  isShorthandClass: boolean;
  isLiteral: boolean;
  singleCode: number | null;
  exactNonAscii: boolean;
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

function addCodePoint(set: CharSet, code: number): { exactNonAscii: boolean } {
  if (code >= 0 && code < 128) {
    addAsciiCode(set, code);
    return { exactNonAscii: true };
  }
  // Non-ASCII literals (decoded \x / \u / \u{...} escapes included) are
  // modelled as the universal set so disjointness stays conservative under
  // both /i and /iu. JS /iu case-folds U+212A (Kelvin) to "k" and U+017F
  // (long s) to "s"; /i without /u does not, but the charset model cannot
  // see the eventual compile flags. Shorthands such as \w and \s are
  // unchanged.
  set.fill(1);
  return { exactNonAscii: false };
}

function addChar(set: CharSet, ch: string): { exactNonAscii: boolean } {
  const code = ch.codePointAt(0) ?? ch.charCodeAt(0);
  return addCodePoint(set, code);
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

function isHexDigit(ch: string | undefined): boolean {
  if (ch === undefined) return false;
  return (
    (ch >= "0" && ch <= "9") ||
    (ch >= "a" && ch <= "f") ||
    (ch >= "A" && ch <= "F")
  );
}

/**
 * Parses an escape sequence starting at pattern[start] === '\\'.
 * Returns null if the escape is forbidden (\p, \P, \c, backreferences) or malformed.
 */
function parseEscape(
  pattern: string,
  start: number,
  inCharClass: boolean,
): ParsedEscape | null {
  const next = pattern[start + 1];
  if (next === undefined) return null;

  // Reject Unicode property escapes and control-letter escapes anywhere.
  if (next === "p" || next === "P" || next === "c") {
    return null;
  }

  // Reject backreferences (\1..\9 anywhere to also block octal escapes in [...], and \k<...>).
  if (next >= "1" && next <= "9") return null;
  if (!inCharClass && next === "k" && pattern[start + 2] === "<") return null;

  // Reject \0 followed by any digit (octal escape like \012 or \00) outside and inside [...].
  // Plain \0 not followed by a digit stays a NUL literal.
  if (next === "0") {
    const afterZero = pattern[start + 2];
    if (afterZero !== undefined && afterZero >= "0" && afterZero <= "9") {
      return null;
    }
  }

  // \xHH hex escape
  if (next === "x") {
    const h1 = pattern[start + 2];
    const h2 = pattern[start + 3];
    if (!isHexDigit(h1) || !isHexDigit(h2)) return null;
    const code = parseInt(`${h1}${h2}`, 16);
    const set = emptyCharSet();
    const { exactNonAscii } = addCodePoint(set, code);
    return {
      end: start + 3,
      set,
      isWhitespaceEscape: false,
      isAssertion: false,
      isShorthandClass: false,
      isLiteral: true,
      singleCode: code,
      exactNonAscii,
    };
  }

  // \uHHHH or \u{H...} Unicode escape
  if (next === "u") {
    if (pattern[start + 2] === "{") {
      const closeBrace = pattern.indexOf("}", start + 3);
      if (closeBrace === -1) return null;
      const hex = pattern.slice(start + 3, closeBrace);
      if (hex.length === 0) return null;
      for (let k = 0; k < hex.length; k++) {
        if (!isHexDigit(hex[k])) return null;
      }
      const code = parseInt(hex, 16);
      if (!Number.isFinite(code) || code > MAX_UNICODE_CODE_POINT) return null;
      const set = emptyCharSet();
      const { exactNonAscii } = addCodePoint(set, code);
      return {
        end: closeBrace,
        set,
        isWhitespaceEscape: false,
        isAssertion: false,
        isShorthandClass: false,
        isLiteral: true,
        singleCode: code,
        exactNonAscii,
      };
    }

    const h1 = pattern[start + 2];
    const h2 = pattern[start + 3];
    const h3 = pattern[start + 4];
    const h4 = pattern[start + 5];
    if (
      !isHexDigit(h1) ||
      !isHexDigit(h2) ||
      !isHexDigit(h3) ||
      !isHexDigit(h4)
    ) {
      return null;
    }
    const code = parseInt(`${h1}${h2}${h3}${h4}`, 16);
    const set = emptyCharSet();
    const { exactNonAscii } = addCodePoint(set, code);
    return {
      end: start + 5,
      set,
      isWhitespaceEscape: false,
      isAssertion: false,
      isShorthandClass: false,
      isLiteral: true,
      singleCode: code,
      exactNonAscii,
    };
  }

  if (!inCharClass && (next === "b" || next === "B")) {
    return {
      end: start + 1,
      set: emptyCharSet(),
      isWhitespaceEscape: false,
      isAssertion: true,
      isShorthandClass: false,
      isLiteral: false,
      singleCode: null,
      exactNonAscii: true,
    };
  }

  if (inCharClass && next === "b") {
    const set = emptyCharSet();
    set[8] = 1;
    return {
      end: start + 1,
      set,
      isWhitespaceEscape: false,
      isAssertion: false,
      isShorthandClass: false,
      isLiteral: true,
      singleCode: 8,
      exactNonAscii: true,
    };
  }

  if (next === "s") {
    return {
      end: start + 1,
      set: SPACE_SET,
      isWhitespaceEscape: true,
      isAssertion: false,
      isShorthandClass: true,
      isLiteral: false,
      singleCode: null,
      exactNonAscii: true,
    };
  }
  if (next === "S") {
    return {
      end: start + 1,
      set: NON_SPACE_SET,
      isWhitespaceEscape: false,
      isAssertion: false,
      isShorthandClass: true,
      isLiteral: false,
      singleCode: null,
      exactNonAscii: true,
    };
  }
  if (next === "d") {
    return {
      end: start + 1,
      set: DIGIT_SET,
      isWhitespaceEscape: false,
      isAssertion: false,
      isShorthandClass: true,
      isLiteral: false,
      singleCode: null,
      exactNonAscii: true,
    };
  }
  if (next === "D") {
    return {
      end: start + 1,
      set: NON_DIGIT_SET,
      isWhitespaceEscape: false,
      isAssertion: false,
      isShorthandClass: true,
      isLiteral: false,
      singleCode: null,
      exactNonAscii: true,
    };
  }
  if (next === "w") {
    return {
      end: start + 1,
      set: WORD_SET,
      isWhitespaceEscape: false,
      isAssertion: false,
      isShorthandClass: true,
      isLiteral: false,
      singleCode: null,
      exactNonAscii: true,
    };
  }
  if (next === "W") {
    return {
      end: start + 1,
      set: NON_WORD_SET,
      isWhitespaceEscape: false,
      isAssertion: false,
      isShorthandClass: true,
      isLiteral: false,
      singleCode: null,
      exactNonAscii: true,
    };
  }
  if (Object.prototype.hasOwnProperty.call(CONTROL_ESCAPES, next)) {
    const code = CONTROL_ESCAPES[next]!;
    const set = emptyCharSet();
    set[code] = 1;
    return {
      end: start + 1,
      set,
      isWhitespaceEscape: false,
      isAssertion: false,
      isShorthandClass: false,
      isLiteral: true,
      singleCode: code,
      exactNonAscii: true,
    };
  }
  // Unknown ASCII letter escapes conservatively overlap everything.
  if ((next >= "a" && next <= "z") || (next >= "A" && next <= "Z")) {
    return {
      end: start + 1,
      set: universalCharSet(),
      isWhitespaceEscape: false,
      isAssertion: false,
      isShorthandClass: true,
      isLiteral: false,
      singleCode: null,
      exactNonAscii: false,
    };
  }
  // Punctuation / literal escape (\|, \., \/, \-, \\, etc.)
  const set = emptyCharSet();
  const { exactNonAscii } = addChar(set, next);
  const code = next.codePointAt(0) ?? next.charCodeAt(0);
  return {
    end: start + 1,
    set,
    isWhitespaceEscape: false,
    isAssertion: false,
    isShorthandClass: false,
    isLiteral: true,
    singleCode: code,
    exactNonAscii,
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
        if (!exactNonAscii) {
          // Complementing a non-exact (non-ASCII or approximate) class
          // would shrink it unsafely; keep it universal.
          set = universalCharSet();
        } else {
          set = complementExact(pos);
        }
      }
      return { end: i, set };
    }
    firstItem = false;

    // Range like a-z, 0-9, or \x41-\x5A (only when preceded by a single literal and followed by non-']')
    if (
      ch === "-" &&
      prevSingleCode !== null &&
      i + 1 < pattern.length &&
      pattern[i + 1] !== "]"
    ) {
      i++;
      let endCode: number | null = null;
      if (pattern[i] === "\\") {
        const esc = parseEscape(pattern, i, true);
        if (!esc) return null;
        if (esc.isShorthandClass || esc.singleCode === null) {
          unionInto(pos, universalCharSet());
          exactNonAscii = false;
        } else {
          endCode = esc.singleCode;
        }
        i = esc.end + 1;
      } else {
        endCode = pattern[i]!.charCodeAt(0);
        i++;
      }
      if (endCode !== null) {
        if (endCode < prevSingleCode) return null;
        const asciiEnd = Math.min(endCode, 127);
        for (let code = prevSingleCode; code <= asciiEnd; code++) {
          addAsciiCode(pos, code);
        }
        if (endCode >= 128 || prevSingleCode >= 128) {
          // A range that includes any non-ASCII code point is universal,
          // matching addCodePoint's conservative model for literals.
          pos.fill(1);
          exactNonAscii = false;
        }
      }
      prevSingleCode = null;
      continue;
    }

    if (ch === "\\") {
      const esc = parseEscape(pattern, i, true);
      if (!esc) return null;
      unionInto(pos, esc.set);
      if (!esc.exactNonAscii) {
        exactNonAscii = false;
      }
      prevSingleCode = esc.isShorthandClass ? null : esc.singleCode;
      i = esc.end + 1;
      continue;
    }

    const added = addChar(pos, ch);
    if (!added.exactNonAscii) exactNonAscii = false;
    prevSingleCode = ch.charCodeAt(0);
    i++;
  }

  return null;
}

function isMandatoryLeadingLiteralToken(tok: SeqToken): boolean {
  if (tok.unbounded || tok.min < 1) return false;
  return (tok.kind === "atom" && tok.isLiteral) ||
    (tok.kind === "group" && tok.isLiteralOnlyGroup);
}

function leadingTokenLastCharSet(tok: SeqToken): CharSet {
  if (tok.kind === "group" && tok.groupLastCharSet) {
    return tok.groupLastCharSet;
  }
  return tok.charSet;
}

function hasMandatoryLeadingLiteral(
  tokens: SeqToken[],
  firstUnboundedIdx: number,
): boolean {
  let idx = 0;
  if (idx < tokens.length && tokens[idx]!.isCaret) {
    idx++;
  }
  const limit = firstUnboundedIdx === -1 ? tokens.length : firstUnboundedIdx;
  if (idx >= limit) return false;
  if (!isMandatoryLeadingLiteralToken(tokens[idx]!)) return false;

  // Find the end of the contiguous mandatory leading literal run before firstUnboundedIdx.
  let runEnd = idx;
  while (runEnd < limit && isMandatoryLeadingLiteralToken(tokens[runEnd]!)) {
    runEnd++;
  }

  if (firstUnboundedIdx === -1) return true;

  const firstUnbounded = tokens[firstUnboundedIdx]!;
  const lastLeading = tokens[runEnd - 1]!;
  if (!areDisjoint(leadingTokenLastCharSet(lastLeading), firstUnbounded.charSet)) {
    return false;
  }

  // If there are additional mandatory tokens between the leading literal run and
  // the first unbounded atom, ensure the last mandatory token is also disjoint.
  let lastMandatoryAfterRun: SeqToken | null = null;
  for (let m = runEnd; m < firstUnboundedIdx; m++) {
    const mid = tokens[m]!;
    if (mid.min >= 1 && (mid.kind === "atom" || mid.kind === "group")) {
      lastMandatoryAfterRun = mid;
    }
  }
  if (
    lastMandatoryAfterRun &&
    !areDisjoint(
      leadingTokenLastCharSet(lastMandatoryAfterRun),
      firstUnbounded.charSet,
    )
  ) {
    return false;
  }

  return true;
}

function validateBranchUnboundedTokens(tokens: SeqToken[]): boolean {
  const unboundedIdx: number[] = [];
  for (let i = 0; i < tokens.length; i++) {
    if (tokens[i]!.unbounded) unboundedIdx.push(i);
  }
  const firstUnboundedIdx = unboundedIdx.length > 0 ? unboundedIdx[0]! : -1;
  if (!hasMandatoryLeadingLiteral(tokens, firstUnboundedIdx)) return false;
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

/**
 * Rewrites valid BMP \u{H...} escapes to \uHHHH so JS RegExp without the /u
 * flag interprets them as the intended Unicode character rather than Annex B
 * repetition of 'u'. Patterns using astral \u{10000}..code points request /u.
 */
function normalizePatternForRegExp(pattern: string): {
  source: string;
  needsUnicodeFlag: boolean;
} {
  let out = "";
  let needsUnicodeFlag = false;
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i]!;
    if (ch !== "\\") {
      out += ch;
      continue;
    }
    const next = pattern[i + 1];
    if (next === "u" && pattern[i + 2] === "{") {
      const closeBrace = pattern.indexOf("}", i + 3);
      if (closeBrace !== -1) {
        const hex = pattern.slice(i + 3, closeBrace);
        const code = parseInt(hex, 16);
        if (Number.isFinite(code) && code <= 0xffff) {
          out += `\\u${code.toString(16).padStart(4, "0")}`;
          i = closeBrace;
          continue;
        }
        if (Number.isFinite(code) && code <= MAX_UNICODE_CODE_POINT) {
          needsUnicodeFlag = true;
          out += pattern.slice(i, closeBrace + 1);
          i = closeBrace;
          continue;
        }
      }
    }
    if (next !== undefined) {
      out += ch + next;
      i++;
    } else {
      out += ch;
    }
  }
  return { source: out, needsUnicodeFlag };
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

function createGroupFrame(): GroupFrame {
  return {
    hasQuantifier: false,
    hasAlternation: false,
    allBranchesLiteralOnly: true,
    currentBranchLiteralOnly: true,
    currentBranchTokenCount: 0,
    lastTokenIsLiteralLike: false,
    currentBranchLastCharSet: null,
    allBranchesLastCharSet: emptyCharSet(),
  };
}

/**
 * Checks that a pattern stays within an RE2-safe subset without nested
 * repeating quantifiers, alternation-plus-quantifier groups, overlapping
 * multiple unbounded quantifiers, unanchored/unprefixed multi-unbounded
 * quantifiers, lookarounds, backreferences, or forbidden/malformed escapes.
 */
export function isRe2SafePattern(pattern: string): boolean {
  if (typeof pattern !== "string") return false;
  if (pattern.length === 0 || pattern.length > MAX_REGEX_LENGTH) return false;

  const stack: GroupFrame[] = [createGroupFrame()];
  const topBranches: SeqToken[][] = [[]];
  let currentBranch = topBranches[0]!;
  let lastAtomWasQuantifiedGroup = false;
  let lastAtomWasAlternationGroup = false;
  let lastAtomWasGroup = false;
  let justOpenedGroup = false;
  let totalUnbounded = 0;
  let hasUnboundedInsideGroup = false;

  const recordGroupItem = (
    isLiteralLike: boolean,
    lastCharSet: CharSet | null,
  ): void => {
    if (stack.length > 1) {
      const frame = stack[stack.length - 1]!;
      frame.currentBranchTokenCount++;
      if (!isLiteralLike) {
        frame.currentBranchLiteralOnly = false;
        frame.currentBranchLastCharSet = null;
      } else {
        frame.currentBranchLastCharSet = lastCharSet;
      }
      frame.lastTokenIsLiteralLike = isLiteralLike;
    }
  };

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
    if (stack.length > 1) {
      const frame = stack[stack.length - 1]!;
      if (unbounded || min < 1 || !frame.lastTokenIsLiteralLike) {
        frame.currentBranchLiteralOnly = false;
        frame.currentBranchLastCharSet = null;
      }
    } else if (currentBranch.length > 0) {
      const last = currentBranch[currentBranch.length - 1]!;
      last.min = min;
      if (unbounded) {
        last.unbounded = true;
        if (last.kind === "group") {
          last.charSet = universalCharSet();
          last.groupLastCharSet = null;
          last.isWhitespaceEscape = false;
          last.isLiteralOnlyGroup = false;
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
      const esc = parseEscape(pattern, i, false);
      if (!esc) return false;

      if (esc.isAssertion) {
        recordGroupItem(false, null);
        pushTopToken({
          kind: "assertion",
          charSet: esc.set,
          groupLastCharSet: null,
          min: 0,
          unbounded: false,
          isWhitespaceEscape: false,
          isLiteral: false,
          isLiteralOnlyGroup: false,
          isCaret: false,
        });
      } else {
        recordGroupItem(esc.isLiteral, esc.isLiteral ? esc.set : null);
        pushTopToken({
          kind: "atom",
          charSet: esc.set,
          groupLastCharSet: null,
          min: 1,
          unbounded: false,
          isWhitespaceEscape: esc.isWhitespaceEscape,
          isLiteral: esc.isLiteral,
          isLiteralOnlyGroup: false,
          isCaret: false,
        });
      }
      lastAtomWasGroup = false;
      lastAtomWasQuantifiedGroup = false;
      lastAtomWasAlternationGroup = false;
      i = esc.end;
      continue;
    }

    if (ch === "[") {
      const parsed = parseCharClass(pattern, i);
      if (!parsed) return false;
      recordGroupItem(false, null);
      pushTopToken({
        kind: "atom",
        charSet: parsed.set,
        groupLastCharSet: null,
        min: 1,
        unbounded: false,
        isWhitespaceEscape: false,
        isLiteral: false,
        isLiteralOnlyGroup: false,
        isCaret: false,
      });
      i = parsed.end;
      lastAtomWasGroup = false;
      lastAtomWasQuantifiedGroup = false;
      lastAtomWasAlternationGroup = false;
      continue;
    }

    if (ch === "|") {
      const frame = stack[stack.length - 1]!;
      frame.hasAlternation = true;
      if (stack.length > 1) {
        if (
          frame.currentBranchTokenCount === 0 ||
          !frame.currentBranchLiteralOnly ||
          !frame.currentBranchLastCharSet
        ) {
          frame.allBranchesLiteralOnly = false;
        } else {
          unionInto(frame.allBranchesLastCharSet, frame.currentBranchLastCharSet);
        }
        frame.currentBranchLiteralOnly = true;
        frame.currentBranchTokenCount = 0;
        frame.lastTokenIsLiteralLike = false;
        frame.currentBranchLastCharSet = null;
      } else {
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
      stack.push(createGroupFrame());
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
      const closedLiteralOnly =
        closed.allBranchesLiteralOnly &&
        closed.currentBranchLiteralOnly &&
        closed.currentBranchTokenCount > 0 &&
        closed.currentBranchLastCharSet !== null;
      let closedLastCharSet: CharSet | null = null;
      if (closedLiteralOnly) {
        unionInto(closed.allBranchesLastCharSet, closed.currentBranchLastCharSet!);
        closedLastCharSet = closed.allBranchesLastCharSet;
      }
      recordGroupItem(closedLiteralOnly, closedLastCharSet);
      pushTopToken({
        kind: "group",
        charSet: universalCharSet(),
        groupLastCharSet: closedLastCharSet,
        min: 1,
        unbounded: false,
        isWhitespaceEscape: false,
        isLiteral: false,
        isLiteralOnlyGroup: closedLiteralOnly,
        isCaret: false,
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
      recordGroupItem(false, null);
      pushTopToken({
        kind: "assertion",
        charSet: emptyCharSet(),
        groupLastCharSet: null,
        min: 0,
        unbounded: false,
        isWhitespaceEscape: false,
        isLiteral: false,
        isLiteralOnlyGroup: false,
        isCaret: ch === "^",
      });
    } else if (ch === ".") {
      recordGroupItem(false, null);
      pushTopToken({
        kind: "atom",
        charSet: universalCharSet(),
        groupLastCharSet: null,
        min: 1,
        unbounded: false,
        isWhitespaceEscape: false,
        isLiteral: false,
        isLiteralOnlyGroup: false,
        isCaret: false,
      });
    } else {
      const set = emptyCharSet();
      addChar(set, ch);
      recordGroupItem(true, set);
      pushTopToken({
        kind: "atom",
        charSet: set,
        groupLastCharSet: null,
        min: 1,
        unbounded: false,
        isWhitespaceEscape: false,
        isLiteral: true,
        isLiteralOnlyGroup: false,
        isCaret: false,
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
    const normalized = normalizePatternForRegExp(pattern);
    new RegExp(normalized.source, normalized.needsUnicodeFlag ? "u" : "");
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
  if (pattern.length === 0 || pattern.length > MAX_REGEX_LENGTH) return null;

  const baseFlags = opts.caseSensitive ? "" : "i";
  const cacheKey = `${baseFlags}\0${pattern}`;
  if (compiledRegexCache.has(cacheKey)) {
    const cached = compiledRegexCache.get(cacheKey) ?? null;
    setCachedRegex(cacheKey, cached);
    return cached;
  }

  if (!isRe2SafePattern(pattern)) {
    setCachedRegex(cacheKey, null);
    return null;
  }

  const normalized = normalizePatternForRegExp(pattern);
  const flags = normalized.needsUnicodeFlag ? `${baseFlags}u` : baseFlags;

  const timeoutMs = opts.timeoutMs ?? REGEX_TIMEOUT_MS;
  try {
    regexVmContext.pattern = normalized.source;
    regexVmContext.flags = flags;
    compileScript.runInContext(regexVmContext, {
      timeout: timeoutMs,
    });
    const compiled = new RegExp(normalized.source, flags);
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
