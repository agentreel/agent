/**
 * Claude Code hook deny output, kept free of imports so the CLI entry can use
 * it before the rest of the application loads.
 */

export function formatClaudePreToolUseDeny(reason: string): string {
  return JSON.stringify({
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: reason,
    },
  });
}

/**
 * Deny output for a hook event, in the shape that event understands. Only
 * PreToolUse has a deny decision. Other events (lifecycle, capture-only) have
 * nothing to deny, and a PreToolUse-shaped object is not valid for them, so
 * they get null.
 */
export function claudeDenyForEvent(event: string | undefined, reason: string): string | null {
  return event === "PreToolUse" ? formatClaudePreToolUseDeny(reason) : null;
}
