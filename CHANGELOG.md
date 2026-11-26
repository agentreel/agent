# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Organization policy cache and local evaluator (`src/policy/*`): fetches `GET /api/v1/policy` with Bearer auth and `If-None-Match`, validates the policy schema, writes `~/.agentreel/policy.json` atomically with mode `0600`, refreshes every 5 minutes in the daemon and once on `agentreel link` and linked `agentreel init`, and falls back offline to the last-known cache or local `guard-config.json` in observe mode.
- Synchronous, network-free policy evaluator supporting built-in Guard rule overrides, scoped custom rules (`contains`, `starts_with`, `equals`, `glob`, and RE2-safe capped `regex`), allow-list exemptions, strictest-wins precedence, and observe-mode downgrading.
- `agentreel policy` CLI command showing policy source, ETag, cache age (clock-skew safe), mode, offline setting, and rule/allow counts.
- Pre-execution policy enforcement in Claude Code (`PreToolUse`) and Cursor (`beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`, `preToolUse`) hooks: blocks matching rules under `enforce` mode with clear org policy messages, prints nothing on `allow`/`flag` in Claude Code, answers through `cursorHookResponse` with `permission`, `user_message`, and `agent_message` in Cursor, and fails open with a local log line on any error.
- Built-in `SECRET004` rule for direct reads of `.env` and credential files, plus `FS001` matching `rm -rf ~` without a trailing slash.
- Remote approval workflow (`src/policy/approval.ts`) reachable only through the `require_approval` path: posts idempotent approval requests (`POST /api/v1/approvals` with scrubbed summary and stable `decision_id`), long-polls `GET /api/v1/approvals/:id?wait=25s`, honors per-rule `approval.expires_s` (default 120s) and `approval.offline_fallback` (default `"deny"`), and writes waiting status to stderr.
- Distinct offline policy modes: `last_known` enforces cached policies indefinitely; `fail_open` evaluates and records decisions while downgrading `block` and `require_approval` to `flag` with reason `"policy stale, fail_open"` when the cached policy exceeds 24 hours (`POLICY_STALE_MS`) or no server policy exists.
- Local `policy_decision` audit events uploaded in ingest batches as `policy_decisions` (v2) next to the unchanged `guard_findings` (v1) payload.
- Performance and regex safety hardening: bounded 256-entry regex compile cache, deterministic evaluation ordering (built-in rules and cheap matchers before regex rules; enforcing regex rules before flag regex rules), 50ms total local evaluation deadline that preserves collected matches and fails closed with reason `eval_timeout` when any `block` or `require_approval` rule is unevaluated or timed out (or emits a recorded `eval_timeout` flag when only `flag` rules remain, with `observe` and stale `fail_open` modifiers still applying and thrown hook crashes still failing open), and static RE2-safe regex validation that rejects nested quantifiers, quantified alternations, and overlapping unbounded quantifiers (`(a|aa)+$`, `(a|a?)+`, `(x|xy)*`, `a.*a.*b`, `.*x.*y`, `curl.*\|\s*(ba)?sh`, `\w+\s*\w+`) while allowing multiple unbounded quantifiers separated by a mandatory disjoint literal or character class (`rm\s+-rf\s+/`, `curl\s+\|\s*sh`, `curl\s+\S+\s+\|\s*(ba)?sh`, `(DROP|TRUNCATE)\s+TABLE\s+\w+`, `aws\s+s3\s+rb`).
- Policy validation and defense-in-depth for unsupported regexes: `validatePolicy` rejects policies containing custom rules that fail `isRe2SafePattern` (naming the rule ID and condition index), keeps the last-known cached policy intact, logs the rejection, and surfaces `policy rejected by agent: rule <id> has an unsupported regex; last known policy still in use` in `agentreel doctor`; if an uncompilable regex ever exists in the cache at evaluation time, enforcing rules fail closed with reason `invalid_rule` and `flag` rules record an `invalid_rule` flag instead of being silently skipped.
- `agentreel pause` and `AGENTREEL_DISABLE=1` stop session recording and capture while keeping organization policy enforcement active on Claude Code and Cursor hooks; updated CLI help text, `agentreel status`, `agentreel doctor`, and README.
- Pre-execution hook timeout installation in `agentreel init` (130s default, or max rule expiry plus 10s, applied idempotently only to Claude `PreToolUse` and Cursor `preToolUse`, `beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`; other hooks remain at 5s), recorded per host in `~/.agentreel/config.json`, enforced via a process-start hook deadline (installed timeout minus 5s margin) and pre-request `expires_s` check so hooks never time out into an unapproved allow.
- `agentreel doctor` CLI command reporting enforcement state, policy load status, mode, cache ETag age, recorded per-host pre-exec hook timeouts, re-init warnings when policy max `expires_s` exceeds installed timeouts, and pre-exec hook installation and timeout checks.
- Govern API v1 (C1) additive policy and approval fields: `GET /api/v1/policy` uses Bearer auth and `If-None-Match` against the single global cache without sending `?repo=` (per-repo policy caching and `?repo=` fetching is a follow-up). On `304`, keeps cache, updates `fetched_at`, clears `policy.json.rejected.json`, and logs nothing alarming; accepts `200` no-org payloads (`org_id: null`, `mode: "observe"`, empty `builtin`/`custom`/`allow`, cached with no enforcement and `agentreel doctor` reporting `no org policy`) when no org policy is cached; pins a cached org policy during normal refreshes so neither a no-org 200 nor a different non-null `org_id` 200 can replace it (logging and surfacing warnings in `agentreel doctor`, with `run \`npx @agentreel/agent auth\` to switch orgs` on org mismatch), while explicit `agentreel auth`/`link` fetches a fresh policy (no ETag) and atomically replaces the policy cache, ETag, and sidecar only once it validates (a failed auth or policy fetch keeps the previous cache in force), and `agentreel logout` clears them; validates `org_id` equal to `workspace_id` when both are present (rejecting mismatches with a clear doctor warning), accepts `fetched_at` and `approval_defaults` (merged under per-rule `approval` and over built-in defaults `120` / `"deny"` for builtin and custom `require_approval` entries), accepts `scope.teams` as display-only metadata (team filtering happens on the server and the ETag varies per caller, so the CLI always applies delivered rules subject to other scope fields and ignores unknown top-level fields such as `current_user_teams`); enforces integer `expires_s` bounds `10..3600` in `validatePolicy` naming the rule; keeps `severity` (`info|warn|high|critical`) required on custom rules and optional on builtin overrides; treats `POST /api/v1/approvals` `201` and `200` (same-payload replay) identically, logs `409` conflicts as a client bug and applies effective `offline_fallback` (default `"deny"`, still bounded by the deadline guard), and reads `expires_at` on `GET /api/v1/approvals/:id` using `min(local expiry, server expires_at)` as the effective expiry.

### Changed

- Changed: now rejected (regex patterns accepted in 0.2.x that are now rejected by the linear-time RE2-safe subset, with verified replacements):
  - `curl[^|]*\|\s*(ba)?sh`: use `curl\s+\S+\s+\|\s*(ba)?sh`, or the single-unbounded `curl[^|]*\|`.
  - `(curl|wget)[^|]*\|\s*(ba|z)?sh`: use `(curl|wget)\s+\S+\s+\|\s*(ba|z)?sh`.
  - `\w+\s+\w+`: add a leading literal whose last char is disjoint from `\w`, e.g. `git\s+\w+\s+--force`.
  - `\S+\s+\S+`: add a leading literal disjoint from `\S`, e.g. `rm\s+\S+\s+/`.
  - `\u{1F600}\s+\w+` (non-ASCII literals are now treated as overlapping every character): use `\u{1F600}\s+\w`, which matches the same commands because rules match anywhere in the input.

### Fixed

- Non-ASCII literals (decoded `\x` / `\u` / `\u{...}` escapes, including inside `[...]`) are modelled as the universal set for disjointness, so a leading Kelvin (`\u212A`) or long s (`\u017F`) cannot bypass the last-char rule under `/iu` (or `/i`). This rejects `\u212A\w+\s+\w+\u{1F600}?`, `\u017F\w+\s+\w+\u{1F600}?`, `\u212A\w+\s+\w+`, `x\u212A[a-z]+\s+\w+`, `\w+\u212A\w+`, and the previously accepted `\u{1F600}\s+\w+`. Single-unbounded patterns and all existing ASCII accepts are unchanged.

- Regex escape decoding, octal rejection, case-folded leading-literal disjointness, and `agentreel doctor` no-cache rejection wording: `isRe2SafePattern` now decodes `\xHH`, `\uHHHH`, and `\u{H...}` as single characters (both outside and inside `[...]`) while rejecting `\p{...}`, `\P{...}`, `\cX`, octal escapes (`\0` followed by any digit, outside and inside `[...]`, while keeping plain `\0` as a NUL literal), and malformed hex/Unicode escapes (`> 0x10FFFF` or bad hex); patterns with 2+ unbounded quantifiers now require a mandatory leading literal (or literal-only bounded token, including a literal-only alternation group like `(DROP|TRUNCATE)`) after an optional `^` before the first unbounded quantifier whose last character set is disjoint under ASCII case folding from the first unbounded atom (rejecting `\w+\s+\w+`, `\S+\s+\S+`, `[a-z]+@[a-z]+`, `a+\s+b+`, `A\w+\s+\w+`, `\x41\w+\s+\w+`, `a[a-z]+\s+\w+`, `(DROP|TRUNCATE)\w+\s+\w+`, `foo[\x41-\x5A]+@[\x41-\x5A]+`, and `curl[^|]*\|\s*(ba)?sh`, while leaving single-unbounded patterns unaffected); and `agentreel doctor` / `fetchPolicy` now report `the rejected policy was not installed and org enforcement is off until a valid policy is cached` instead of `last known policy still in use` when a first fetch is rejected with no cached server policy.

## [0.2.4] - 2026-11-21

### Fixed

- CLI telemetry now saves `anon_id` and `notice_shown` to `~/.agentreel/telemetry.json` as soon as they are created or printed, even when the POST fails or the process exits quickly (for example `--version`). `first_run_sent` and `last_heartbeat_at` are still written only after a successful 2xx response.

## [0.2.3] - 2026-11-21

### Fixed

- First-run CLI telemetry is no longer lost on short-lived commands such as `--version`, `--help`, or fast error exits. Delivery markers (`first_run_sent`, `last_heartbeat_at`) are written only after a successful POST, and in-flight telemetry is flushed with an at-most 800ms wait before process exit.

## [0.2.2] - 2026-11-21

### Added

- Anonymous CLI telemetry: one event on first run, then at most one daily heartbeat, carrying CLI version, OS type, and recorded session count. Opt out with `AGENTREEL_TELEMETRY=0`, `false`, `off`, or `no`, or `DO_NOT_TRACK=1`. Telemetry is always off in CI.

### Changed

- README: refreshed brand logo and layout.

### Fixed

- Telemetry `session_count` no longer stalls when `sessions.db` is locked: the database is opened read-only with a zero busy timeout so the CLI keeps moving.

## [0.2.1] - 2026-11-19

### Changed

- License changed to Apache License 2.0 from this release onward; versions 0.2.0 and earlier remain under the MIT License.
- README: documented Guard default-on behavior and upload-time scanning (not during hook recording), Cursor install notes, and corrected GitHub footer link.
- CONTRIBUTING: Developer Certificate of Origin (DCO) sign-off required (`git commit -s`).

## [0.2.0] - 2026-11-17

### Added

- AgentReel Guard: local pattern detection for risky agent behavior, with scan command and upload-time findings.
- GitHub Actions OIDC workflow to publish `@agentreel/agent` to npm.

### Changed

- Guard rule rationales neutralized with sourced threat research references and gitleaks config updates.

## [0.1.7] - 2026-11-16

### Added

- Cursor agent hooks capture and session attribution (who/where for Cursor sessions).

### Fixed

- Honor `.agentreelignore` for Claude Code tool call payloads.
- Node 24 install compatibility, wider secret scrubbing, per-session plan limits, and Cursor line hunk handling.

## [0.1.5] - 2026-05-10

### Added

- User-consent controls: `pause`, `resume`, and `forget`, plus `AGENTREEL_DISABLE` to stop capture.

## [0.1.4] - 2026-05-10

### Added

- Daemon detach and stop commands, init onboarding polish, and smoke test coverage.

## [0.1.3] - 2026-05-10

### Added

- Real cost and token totals derived from transcript JSONL.

## [0.1.2] - 2026-05-10

### Changed

- CLI version is baked into the bundle via tsup `define` so `--version` matches the published package.

## [0.1.1] - 2026-05-10

### Added

- `agentreel daemon` background uploader for queued replays.

## [0.1.0] - 2026-05-10

### Added

- Initial `@agentreel/agent` release: local SQLite buffer, Claude Code hooks, Cursor history watcher, secret scrubbing, push and status commands, and MIT-licensed npm package.

[Unreleased]: https://github.com/agentreel/agent/compare/v0.2.4...HEAD
[0.2.4]: https://github.com/agentreel/agent/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/agentreel/agent/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/agentreel/agent/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/agentreel/agent/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/agentreel/agent/compare/v0.1.7...v0.2.0
[0.1.7]: https://github.com/agentreel/agent/compare/v0.1.5...v0.1.7
[0.1.5]: https://github.com/agentreel/agent/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/agentreel/agent/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/agentreel/agent/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/agentreel/agent/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/agentreel/agent/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/agentreel/agent/releases/tag/v0.1.0