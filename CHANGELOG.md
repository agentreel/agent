# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/agentreel/agent/compare/v0.2.3...HEAD
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