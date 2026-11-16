import { diffLines, structuredPatch } from "diff";
import DiffMatchPatch from "diff-match-patch";

export interface DiffResult {
  /** diff-match-patch wire format — compact, reversible. Stored on the event. */
  patch: string;
  /** Line-level adds/removes — surfaced in the dashboard list. */
  added: number;
  removed: number;
  /**
   * Line-level hunks with 2 lines of context, for the replay's diff view.
   * DMP patches only carry a few characters of context, which reads badly.
   * Capped so a huge rewrite doesn't bloat the event.
   */
  hunks: DiffHunk[];
  hunksTruncated: boolean;
}

export interface DiffHunk {
  /** 1-based first line in the old file. */
  oldStart: number;
  newStart: number;
  /** Text before / after, context lines included in both. */
  old: string;
  new: string;
}

const MAX_HUNKS = 40;
const MAX_HUNK_CHARS = 64 * 1024;

const dmp = new DiffMatchPatch.diff_match_patch();
// Allow expensive cleanup on small diffs; cap at 1MB to avoid pathological inputs.
dmp.Diff_Timeout = 1.0;

export function computeDiff(before: string, after: string): DiffResult {
  // Patch — compact DMP format, much smaller than unified diff for small edits.
  const patches = dmp.patch_make(before, after);
  const patch = dmp.patch_toText(patches);

  // Line-level stats (cheap; users see these in the timeline list).
  let added = 0;
  let removed = 0;
  for (const part of diffLines(before, after)) {
    const n =
      part.count ??
      (part.value.match(/\n/g)?.length ?? (part.value.length > 0 ? 1 : 0));
    if (part.added) added += n;
    else if (part.removed) removed += n;
  }

  const hunks: DiffHunk[] = [];
  let hunksTruncated = false;
  let chars = 0;
  for (const h of structuredPatch("a", "b", before, after, "", "", { context: 2 }).hunks) {
    const oldLines: string[] = [];
    const newLines: string[] = [];
    for (const line of h.lines) {
      const tag = line[0];
      const text = line.slice(1);
      if (tag === "\\") continue; // "\ No newline at end of file"
      if (tag !== "+") oldLines.push(text);
      if (tag !== "-") newLines.push(text);
    }
    const hunk = { oldStart: h.oldStart, newStart: h.newStart, old: oldLines.join("\n"), new: newLines.join("\n") };
    chars += hunk.old.length + hunk.new.length;
    if (hunks.length >= MAX_HUNKS || chars > MAX_HUNK_CHARS) {
      hunksTruncated = true;
      break;
    }
    hunks.push(hunk);
  }

  return { patch, added, removed, hunks, hunksTruncated };
}
