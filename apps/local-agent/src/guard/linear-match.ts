/**
 * Linear-time matchers for the built-in command rules that used to be
 * superlinear regexes.
 *
 * The old patterns had the shape `head \s+ [^|&;]* tail`, for example
 * /git\s+push\s+[^|&;]*--force/i. The `\s+` and the `[^|&;]*` overlap on
 * whitespace, so on "git push" plus N spaces they try every split of the
 * run (quadratic, and cubic for INSTALL001, which has a third overlapping
 * `\s*`). On inputs with many repeated heads ("git push git push ...") every
 * head also rescans to the end of the command.
 *
 * Every one of them is a statement about a single command segment, where a
 * segment is a maximal run of characters that are not `|`, `&` or `;`:
 * "a head occurs in the segment, and later in the same segment a tail
 * occurs". Only the first head in a segment matters, because any later head
 * has a smaller remainder. So these helpers find the first head, test the
 * tail once on the rest of its segment, and jump to the next segment. Each
 * character is looked at a constant number of times.
 *
 * test/guard-linear-rules.test.ts keeps the old regexes and checks that the
 * new matchers return the same answer on a corpus and on random input.
 */

/** Finds the next segment terminator at or after `from`, or the length. */
function segmentEnd(cmd: string, from: number): number {
  for (let i = from; i < cmd.length; i++) {
    const c = cmd.charCodeAt(i);
    // | & ;
    if (c === 0x7c || c === 0x26 || c === 0x3b) return i;
  }
  return cmd.length;
}

/**
 * True when, in some segment, `head` matches and `tail` matches somewhere in
 * the rest of that segment after the head. `head` must be a global regex and
 * must not be able to match a terminator character. `tail` must not use
 * lookbehind or anchors that depend on text before the head.
 */
export function headThenTailInSegment(
  cmd: string,
  head: RegExp,
  tail: RegExp,
): boolean {
  let pos = 0;
  while (pos <= cmd.length) {
    head.lastIndex = pos;
    const m = head.exec(cmd);
    if (!m) return false;
    const from = m.index + m[0].length;
    const end = segmentEnd(cmd, from);
    if (tail.test(cmd.slice(from, end))) return true;
    pos = end;
  }
  return false;
}

const GIT_PUSH_HEAD = /git\s+push\s/gi;
const FORCE_TAIL = /--force|-f\b/i;

/** git push ... --force | -f, within one command segment (GIT001). */
export function hasGitForcePush(cmd: string): boolean {
  return headThenTailInSegment(cmd, GIT_PUSH_HEAD, FORCE_TAIL);
}

const GIT_PUSH_HEAD_WB = /\bgit\s+push\s/gi;
const DELETE_TAIL = /--delete/i;
const BRANCH_DELETE = /\bgit\s+branch\s+-D/i;

/** git branch -D, or git push ... --delete (GIT003). */
export function hasGitBranchDelete(cmd: string): boolean {
  return BRANCH_DELETE.test(cmd) || headThenTailInSegment(cmd, GIT_PUSH_HEAD_WB, DELETE_TAIL);
}

const GIT_COMMIT_PUSH_HEAD = /\bgit\s+(?:commit|push)\s/gi;
const NO_VERIFY_TAIL = /--no-verify/i;

/** git commit|push ... --no-verify, within one command segment (SAFETY002). */
export function hasGitNoVerify(cmd: string): boolean {
  return headThenTailInSegment(cmd, GIT_COMMIT_PUSH_HEAD, NO_VERIFY_TAIL);
}

// A keyword, one whitespace character, then at least one more character of
// the same segment. (The old pattern needed \s+ then [^|&;]+, which is at
// least two characters starting with whitespace.)
const CURL_HEAD = /\b(?:curl|wget)\s[^]/i;
const SHELL_AFTER_PIPE = /\s*(?:sh|bash|zsh|fish|python)/iy;

/**
 * curl|wget <args> | sh|bash|zsh|fish|python (INSTALL001). The old pattern
 * was /\b(curl|wget)\s+[^|&;]+\s*\|\s*(sh|bash|zsh|fish|python)/i: the `|`
 * has to be the first terminator after the keyword, so the check is per
 * segment that ends in `|`.
 */
export function hasCurlPipeShell(cmd: string): boolean {
  let pos = 0;
  while (pos < cmd.length) {
    const end = segmentEnd(cmd, pos);
    if (end >= cmd.length) return false;
    if (cmd.charCodeAt(end) === 0x7c) {
      if (CURL_HEAD.test(cmd.slice(pos, end))) {
        SHELL_AFTER_PIPE.lastIndex = end + 1;
        if (SHELL_AFTER_PIPE.test(cmd)) return true;
      }
    }
    pos = end + 1;
  }
  return false;
}
