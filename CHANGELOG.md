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
- Performance and regex safety hardening: bounded 256-entry regex compile cache, 50ms total local evaluation deadline (fail-open on expiry), and static rejection of alternation-plus-quantifier ReDoS patterns (`(a|aa)+$`, `(a|a?)+`, `(x|xy)*`).
- Pre-execution hook timeout installation in `agentreel init` (130s default, or max rule expiry plus 10s, applied idempotently only to Claude `PreToolUse` and Cursor `preToolUse`, `beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`; other hooks remain at 5s), recorded per host in `~/.agentreel/config.json`, enforced via a process-start hook deadline (installed timeout minus 5s margin) and pre-request `expires_s` check so hooks never time out into an unapproved allow.
- `agentreel doctor` CLI command reporting enforcement state, policy load status, mode, cache ETag age, recorded per-host pre-exec hook timeouts, re-init warnings when policy max `expires_s` exceeds installed timeouts, and pre-exec hook installation and timeout checks.

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