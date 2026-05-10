import { diffLines } from "diff";
import DiffMatchPatch from "diff-match-patch";

export interface DiffResult {
  /** diff-match-patch wire format — compact, reversible. Stored on the event. */
  patch: string;
  /** Line-level adds/removes — surfaced in the dashboard list. */
  added: number;
  removed: number;
}

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

  return { patch, added, removed };
}
