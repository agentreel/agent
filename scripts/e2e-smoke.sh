#!/usr/bin/env bash
# AgentReel — local agent end-to-end smoke test.
#
# Verifies: hooks fire → events land in SQLite → push reaches the
# configured cloud → status reflects last sync.
#
# Run from the repo root after `pnpm -r build`.
#
#   ./scripts/e2e-smoke.sh                     # uses ~/.agentreel
#   AGENTREEL_HOME=/tmp/ar-smoke ./scripts/e2e-smoke.sh   # isolated

set -euo pipefail

CLI="${CLI:-$PWD/apps/local-agent/dist/cli.js}"
if [[ ! -f "$CLI" ]]; then
  echo "✗ CLI bundle not found at $CLI — run pnpm -r build first." >&2
  exit 1
fi

# Run in an isolated home so we never pollute the user's real ~/.agentreel.
SMOKE_HOME="${SMOKE_HOME:-/tmp/agentreel-smoke-$$}"
rm -rf "$SMOKE_HOME"
mkdir -p "$SMOKE_HOME/.agentreel" "$SMOKE_HOME/.claude"
export HOME="$SMOKE_HOME"

run() {
  echo "→ $*"
  node "$CLI" "$@"
}

step() { echo; echo "── $* ──"; }

step "init"
run init

step "fire a synthetic PreToolUse hook"
SESSION_ID="smoke-$(date +%s)"
TS=$(date +%s%3N)
cat <<JSON | node "$CLI" hook PreToolUse
{
  "session_id": "$SESSION_ID",
  "hook_event_name": "PreToolUse",
  "cwd": "/tmp/smoke",
  "tool_name": "Edit",
  "tool_input": { "file_path": "/tmp/smoke/x.ts" }
}
JSON
echo "  ✓ hook accepted (no stdout = success per Claude Code contract)"

step "verify event landed in SQLite"
COUNT=$(sqlite3 "$SMOKE_HOME/.agentreel/sessions.db" \
  "SELECT COUNT(*) FROM events WHERE session_id='$SESSION_ID'")
if [[ "$COUNT" -ne 1 ]]; then
  echo "✗ expected 1 event for session $SESSION_ID, got $COUNT" >&2
  exit 1
fi
echo "  ✓ 1 event found"

step "status"
run status

step "push (will fail if not linked — that's fine)"
if node "$CLI" push 2>&1 | tee /tmp/smoke-push.log; then
  echo "  ✓ push succeeded"
else
  if grep -q "Not linked" /tmp/smoke-push.log; then
    echo "  · push skipped: not linked (expected for unauthenticated smoke)"
  else
    echo "✗ push failed unexpectedly" >&2
    exit 1
  fi
fi

step "uninstall"
run uninstall

echo
echo "✅ smoke test passed"
echo "   sandbox: $SMOKE_HOME (delete with: rm -rf $SMOKE_HOME)"
