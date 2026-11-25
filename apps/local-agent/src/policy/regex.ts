import vm from "node:vm";

export const MAX_REGEX_LENGTH = 300;
export const REGEX_TIMEOUT_MS = 50;
const MAX_QUANTIFIER_BOUND = 100;
const MAX_GROUP_DEPTH = 16;

interface GroupFrame {
  hasRepeatingQuantifier: boolean;
}

const regexVmContext = vm.createContext({});
const compileScript = new vm.Script("new RegExp(pattern, flags)");
const testScript = new vm.Script("re.test(text)");

function parseBraceQuantifier(
  pattern: string,
  start: number,
): { end: number; repeating: boolean; tooLarge: boolean } | null {
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
  const tooLarge =
    min > MAX_QUANTIFIER_BOUND ||
    (Number.isFinite(max) && max > MAX_QUANTIFIER_BOUND);
  const repeating = max > 1 || max === Infinity;
  return { end: i, repeating, tooLarge };
}

/**
 * Checks that a pattern stays within an RE2-safe subset without nested
 * repeating quantifiers, lookarounds, or backreferences.
 */
export function isRe2SafePattern(pattern: string): boolean {
  if (pattern.length > MAX_REGEX_LENGTH) return false;

  let inCharClass = false;
  const stack: GroupFrame[] = [{ hasRepeatingQuantifier: false }];
  let lastAtomWasRepeatingGroup = false;
  let lastAtomWasGroup = false;

  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i]!;

    if (ch === "\\") {
      const next = pattern[i + 1];
      if (next === undefined) return false;
      if (!inCharClass) {
        if (next >= "1" && next <= "9") return false;
        if (next === "k" && pattern[i + 2] === "<") return false;
      }
      lastAtomWasGroup = false;
      lastAtomWasRepeatingGroup = false;
      i++;
      continue;
    }

    if (inCharClass) {
      if (ch === "]") {
        inCharClass = false;
      }
      continue;
    }

    if (ch === "[") {
      inCharClass = true;
      lastAtomWasGroup = false;
      lastAtomWasRepeatingGroup = false;
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
      stack.push({ hasRepeatingQuantifier: false });
      lastAtomWasGroup = false;
      lastAtomWasRepeatingGroup = false;
      continue;
    }

    if (ch === ")") {
      if (stack.length <= 1) return false;
      const closed = stack.pop()!;
      const parent = stack[stack.length - 1]!;
      if (closed.hasRepeatingQuantifier) {
        parent.hasRepeatingQuantifier = true;
      }
      lastAtomWasGroup = true;
      lastAtomWasRepeatingGroup = closed.hasRepeatingQuantifier;
      continue;
    }

    if (ch === "*" || ch === "+") {
      if (lastAtomWasGroup && lastAtomWasRepeatingGroup) return false;
      stack[stack.length - 1]!.hasRepeatingQuantifier = true;
      if (pattern[i + 1] === "?") i++;
      lastAtomWasGroup = false;
      lastAtomWasRepeatingGroup = false;
      continue;
    }

    if (ch === "?") {
      if (pattern[i + 1] === "?") i++;
      lastAtomWasGroup = false;
      lastAtomWasRepeatingGroup = false;
      continue;
    }

    if (ch === "{") {
      const parsed = parseBraceQuantifier(pattern, i);
      if (parsed) {
        if (parsed.tooLarge) return false;
        if (parsed.repeating) {
          if (lastAtomWasGroup && lastAtomWasRepeatingGroup) return false;
          stack[stack.length - 1]!.hasRepeatingQuantifier = true;
        }
        i = parsed.end;
        if (pattern[i + 1] === "?") i++;
        lastAtomWasGroup = false;
        lastAtomWasRepeatingGroup = false;
        continue;
      }
    }

    lastAtomWasGroup = false;
    lastAtomWasRepeatingGroup = false;
  }

  return !inCharClass && stack.length === 1;
}

export interface SafeRegexOptions {
  caseSensitive?: boolean;
  timeoutMs?: number;
}

/**
 * Compiles an RE2-safe regex with a length cap and timeout guard.
 * Returns null if the pattern is invalid, over-length, or unsafe. Never throws.
 */
export function compileSafeRegex(
  pattern: string,
  opts: SafeRegexOptions = {},
): RegExp | null {
  if (typeof pattern !== "string") return null;
  if (!isRe2SafePattern(pattern)) return null;

  const flags = opts.caseSensitive ? "" : "i";
  const timeoutMs = opts.timeoutMs ?? REGEX_TIMEOUT_MS;
  try {
    regexVmContext.pattern = pattern;
    regexVmContext.flags = flags;
    compileScript.runInContext(regexVmContext, {
      timeout: timeoutMs,
    });
    return new RegExp(pattern, flags);
  } catch {
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
): boolean {
  try {
    regexVmContext.re = re;
    regexVmContext.text = text;
    return Boolean(testScript.runInContext(regexVmContext, { timeout: timeoutMs }));
  } catch {
    return false;
  } finally {
    regexVmContext.re = undefined;
    regexVmContext.text = undefined;
  }
}
