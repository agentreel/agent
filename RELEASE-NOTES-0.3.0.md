# AgentReel Local Agent v0.3.0 (Draft Release Notes)

AgentReel v0.3.0 introduces **AgentReel Govern**: organization policy syncing, local pre-execution policy enforcement, remote admin approvals, offline fail-open handling, v2 audit decision uploads, and enforcement diagnostics for Claude Code and Cursor.

## Highlights

### Pre-Execution Policy Enforcement
- **Claude Code (`PreToolUse`)**: evaluates every tool call locally against the cached organization policy before execution. `block` returns `hookSpecificOutput` with `permissionDecision: "deny"` and a clear organization policy message. `flag` and `allow` print nothing, preserving existing behavior.
- **Cursor (`beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`, `preToolUse`)**: installs and evaluates pre-execution hooks and responds via `cursorHookResponse` with `permission` (`"allow"` or `"deny"`), `user_message`, and `agent_message`.
- **Observe mode safety**: policies in `"observe"` mode never block execution and never trigger approval requests.
- **Fail-open on crashes, fail-closed on evaluation timeouts**: any unexpected exception thrown during evaluation or hook handling still fails open to allow and writes a diagnostic line to `~/.agentreel/agent.log`. If local rule evaluation hits the 50ms deadline, all matches collected so far are preserved; if any `block` or `require_approval` rule was unevaluated or timed out, enforcement fails closed with reason `eval_timeout` and records a `policy_decision` (subject to `observe` and stale `fail_open` modifiers). If only `flag` rules remain unevaluated, the strictest collected result is returned alongside a recorded `eval_timeout` flag.
- **Pause and `AGENTREEL_DISABLE=1` behavior**: `agentreel pause` and `AGENTREEL_DISABLE=1` stop local session recording and capture, while organization policy enforcement remains active on Claude Code and Cursor pre-execution hooks (no capture events are written beyond the `policy_decision` audit records required by enforcement).
- **Expanded built-in detection**: adds `SECRET004` to catch direct reads of `.env` files, SSH keys, AWS credentials, and production credential files, and updates `FS001` to match `rm -rf ~` with or without a trailing slash.

### Remote Admin Approvals
- Rules configured with `action: "require_approval"` invoke the remote approval client (`POST /api/v1/approvals` followed by `GET /api/v1/approvals/:id?wait=25s` long-polling).
- Sends a stable idempotency key (`decision_id`) per decision so retries reuse the same approval, and scrubs `summary` through the local secret scrubber before transmitting.
- Per-rule optional `approval` configuration: `expires_s` (default `120`) and `offline_fallback` (`"deny"` or `"allow"`, default `"deny"`).
- Denies on timeout, expiry, or admin denial; allows only on explicit approval (or when the server is unreachable/failing and `offline_fallback: "allow"` is configured).
- Prints a clear waiting status (`Waiting for admin approval (<rule name>), up to <N>s`) to stderr without corrupting hook stdout JSON.
- Strictly isolated networking: only the `require_approval` path can load the approval client; every other decision path is synchronous and network-free.

### Offline Modes (`last_known` vs `fail_open`)
- `last_known` (default): continues enforcing the cached policy indefinitely when offline.
- `fail_open`: continues evaluating and recording audit decisions, but downgrades `block` and `require_approval` to `flag` with reason `"policy stale, fail_open"` when the cached policy is older than 24 hours (`POLICY_STALE_MS`, clock-skew safe) or no server policy exists.

### Policy Cache, Evaluator, and Performance Hardening
- Fetches `GET /api/v1/policy` with Bearer authentication and `If-None-Match` ETag caching, atomically writing `~/.agentreel/policy.json` with mode `0600`.
- Refreshes cached policy every 5 minutes in `agentreel daemon` and once on `agentreel link` and linked `agentreel init`.
- Adds a bounded 256-entry regex compile cache, deterministic evaluation ordering (built-in rules and cheap matchers before regex rules, and enforcing regex rules before `flag` regex rules), a 50ms total local evaluation deadline that preserves collected matches and fails closed when enforcing rules are unevaluated, and a stricter RE2-safe regex subset that statically rejects alternation-plus-quantifier patterns (`(a|aa)+$`, `(a|a?)+`, `(x|xy)*`) and patterns with more than one unbounded quantifier (`*`, `+`, `{n,}` such as `a.*a.*b` or `.*x.*y`).

### Audit Trail (`policy_decisions` v2)
- Writes every non-allow policy decision locally as a `policy_decision` event (`id`, `ts`, `session_id`, `rule_id`, `rule_ids`, `action`, `enforced`, `downgraded`, `policy_etag`, `tool`).
- Uploads decisions in the existing session ingest batch under `policy_decisions` (`version: 2`) next to `guard_findings` (`version: 1`), which remains unchanged and backward compatible.

### Hook Timeouts and CLI Commands
- `agentreel init` idempotently sets longer timeouts (130s by default, or max rule expiry plus 10s) only on hooks that can reach `require_approval` (Claude `PreToolUse` and Cursor `preToolUse`, `beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`). Other hooks keep their 5s timeout.
- `agentreel policy` displays policy source, ETag, clock-skew-safe cache age, mode, offline setting, and rule/allow counts.
- `agentreel doctor` reports enforcement readiness: whether a policy is loaded, active mode, ETag age, and whether pre-exec hooks are installed with the expected timeouts.

## Upgrading

You must re-run `npx @agentreel/agent init` after upgrading to 0.3.0 so approval rules work. Upgrading without re-running `init` leaves the legacy 5s hook timeout in place, which causes `require_approval` rules to deny with a prompt to run `npx @agentreel/agent init`. Re-running `init` registers the new Cursor pre-execution hooks, updates pre-execution hook timeouts to 130s (or max rule `expires_s` plus 10s), and records the installed timeouts per host in `~/.agentreel/config.json`. Run `agentreel doctor` afterward to verify your setup.
