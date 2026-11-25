import vm from "node:vm";

export const MAX_REGEX_LENGTH = 300;
export const REGEX_TIMEOUT_MS = 50;
export const MAX_REGEX_CACHE_SIZE = 256;
const MAX_QUANTIFIER_BOUND = 100;
const MAX_GROUP_DEPTH = 16;

interface GroupFrame {
  hasQuantifier: boolean;
  hasAlternation: boolean;
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
 * repeating quantifiers, alternation-plus-quantifier groups, lookarounds,
 * or backreferences.
 */
export function isRe2SafePattern(pattern: string): boolean {
  if (pattern.length > MAX_REGEX_LENGTH) return false;

  let inCharClass = false;
  const stack: GroupFrame[] = [
    { hasQuantifier: false, hasAlternation: false },
  ];
  let lastAtomWasQuantifiedGroup = false;
  let lastAtomWasAlternationGroup = false;
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
      lastAtomWasQuantifiedGroup = false;
      lastAtomWasAlternationGroup = false;
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
      lastAtomWasQuantifiedGroup = false;
      lastAtomWasAlternationGroup = false;
      continue;
    }

    if (ch === "|") {
      stack[stack.length - 1]!.hasAlternation = true;
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
      stack[stack.length - 1]!.hasQuantifier = true;
      if (pattern[i + 1] === "?") i++;
      lastAtomWasGroup = false;
      lastAtomWasQuantifiedGroup = false;
      lastAtomWasAlternationGroup = false;
      continue;
    }

    if (ch === "?") {
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
        if (parsed.tooLarge) return false;
        if (parsed.repeating) {
          if (
            lastAtomWasGroup &&
            (lastAtomWasQuantifiedGroup || lastAtomWasAlternationGroup)
          ) {
            return false;
          }
        }
        stack[stack.length - 1]!.hasQuantifier = true;
        i = parsed.end;
        if (pattern[i + 1] === "?") i++;
        lastAtomWasGroup = false;
        lastAtomWasQuantifiedGroup = false;
        lastAtomWasAlternationGroup = false;
        continue;
      }
    }

    lastAtomWasGroup = false;
    lastAtomWasQuantifiedGroup = false;
    lastAtomWasAlternationGroup = false;
  }

  return !inCharClass && stack.length === 1;
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
