# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Self-protection under an enforcing org policy (`src/policy/self-protect.ts`, reason `self_protect`, rule IDs `SELF001` to `SELF005`, not part of the 31 Guard rules and not overridable by policy). Pre-exec hooks now block:
  - shell commands that may write to `~/.agentreel/**`, `.claude/settings.json`, `.claude/settings.local.json`, `.cursor/hooks.json`, the managed directories `/etc/claude-code/`, `/etc/cursor/`, and their macOS (`/Library/Application Support/ClaudeCode/`, `/Library/Application Support/Cursor/`, case-insensitive, with or without a trailing slash) and Windows equivalents, plus the hook binary (`node_modules/@agentreel/agent`, a path whose basename is `agentreel`, and the binary taken from the managed hook command at match time; an unreadable hook file is skipped). Reads with `cat`, `grep`, `jq`, `ls` and similar stay allowed;
  - Write/Edit-style tool calls to those paths;
  - `agentreel uninstall`, `logout` and `pause` (including through `npx`), removing the `@agentreel/agent` package, and `agentreel managed ...` other than `--dry-run`. The `managed` match is on the command text, so it still holds when sudo has stripped `CLAUDECODE` or `CURSOR_AGENT`;
  - `disableAllHooks` and `claude --settings` / `--setting-sources`;
  - unsetting or overriding `HOME`, `CLAUDE_CONFIG_DIR`, `CLAUDECODE`, `CLAUDE_CODE_CHILD_SESSION`, `CURSOR_AGENT` or `AGENTREEL_*` (`unset`, `env -u`, `env -i`, `export HOME=`, `HOME=... claude`).
  Matching NFKC-normalizes and strips quotes and escapes first, and is a single linear pass. With no org policy, or an `observe` policy, nothing changes. Removing stale AgentReel entries from `~/.cursor/hooks.json` (when the managed pack owns the Cursor hooks), and writing that file on `agentreel init` when the managed pack does not, never write through a symlink: if `~/.cursor` or `~/.cursor/hooks.json` is a symlink (for example to the managed `/etc/cursor/hooks.json`), or the file is not a regular file, or lstat fails with anything other than ENOENT (EACCES, ELOOP, ENOTDIR), the path is left untouched and `agentreel init` prints a warning. A missing `~/.cursor` directory is still treated as nothing to clean, and a fresh install creates it. The same rule as `agentreel managed install`. `agentreel uninstall` (and `logout`-style uninstall of the Cursor hooks) uses the same check and prints the warning instead of reporting a removal. Every write of that file (install, cleanup, uninstall) goes through one helper that backs the file up through an `O_NOFOLLOW` fd to a unique name (timestamp, pid, a monotonic counter and a short random suffix; a same-millisecond `EEXIST` is retried, never overwritten) and aborts the write, reporting a warning rather than a successful no-op, only if the backup truly cannot be made (EACCES, ENOSPC and the like), re-lstats the parent directory right before the open, and writes through a single fd opened with `O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW` keeping the existing mode (0600 for a new file), so a symlink swapped in after the check is refused (ELOOP) and never written through; without `O_NOFOLLOW` (Windows) it lstats immediately before the open. `NODE_OPTIONS` joins the protected environment names (`export`, `unset` and a prefix on `claude` are SELF005), and a `NODE_OPTIONS=` prefix, bare or via `env`, disables the `node .../dist/cli.js` allowance so the script path is checked as SELF001. `node <prefix>/node_modules/@agentreel/agent/dist/cli.js ...` (node, nodejs or a path to node, no flags other than a few value-less ones, no `..` in the script path) is treated like `agentreel ...`: `doctor`, `status` and `managed install --dry-run` are allowed, `managed install`, `uninstall`, `logout` and `pause` are SELF003, and any other protected path on the command line, `node -e`, `-r`, `--require` and `--import` are still SELF001.
- `agentreel init` skips writing `~/.cursor/hooks.json` when the system Cursor hooks file (`/etc/cursor/hooks.json`, macOS `/Library/Application Support/Cursor/hooks.json`) already has AgentReel entries, or exists but cannot be read (fail-safe: treated as managed so a second copy is never written). It then removes only stale AgentReel entries from this user's `~/.cursor/hooks.json` after a backup, leaving other tools' hooks untouched, and prints that the managed pack owns them. `agentreel doctor` also reads the system file and reports the hooks as owned by the managed pack instead of telling the user to run `agentreel init`.

- `agentreel managed install`: writes an enterprise managed policy to `/etc/claude-code/managed-settings.json` and `/etc/cursor/hooks.json` (macOS: `/Library/Application Support/ClaudeCode/managed-settings.json` and `/Library/Application Support/Cursor/hooks.json`). The Claude Code file sets `allowManagedHooksOnly`, disables bypass-permissions mode, forces the sandbox on (`failIfUnavailable: true`, `allowUnsandboxedCommands: false`), and carries all 9 AgentReel hooks with `onFailure: "block"` on `PreToolUse`. The Cursor file carries all 14 AgentReel hooks with `failClosed: true` on the 4 pre-exec hooks. It also removes only AgentReel-owned entries (the same ones `agentreel uninstall` removes) from the invoking user's `~/.cursor/hooks.json`, resolved from `SUDO_USER` under sudo or set with `--user-home`, after a backup and keeping other tools' hooks, unknown keys, owner and mode, so Cursor does not capture events twice. Needs root for the system paths, merges into existing files, backs up anything it changes, is a no-op when files already match. The default hook binary (this process) is refused on a real run when it is not root-owned, is group- or world-writable, or a parent directory is writable by a non-root user; `--dry-run` warns and continues, `--allow-user-writable-hook` accepts the risk with a warning, and an explicit `--hook-command` gets the same check as a warning only (on macOS, root or the admin group is accepted when the mode is not group-writable; with `--root` the check uses the target path). Supports `--dry-run` (prints a diff, including the user-file removal), `--root`, `--user-home`, `--hook-command`, `--allow-user-writable-hook`, `--platform`, `--no-claude` and `--no-cursor`, refuses to write from inside an agent session, and makes no network calls (CLI telemetry skips `managed`). Docs in `docs/managed-settings.md`, templates in `docs/managed/`.
- Pull request CI (`.github/workflows/ci.yml`): every pull request and every push to `main` runs `pnpm install --frozen-lockfile`, `pnpm typecheck`, `pnpm test` and `pnpm build` on Node 20 and 22, with a read-only token, no secrets, pinned actions, a 15 minute timeout and per-ref cancel-in-progress. `publish.yml` is unchanged.
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
- Govern API v1 (C1) additive policy and approval fields: `GET /api/v1/policy` uses Bearer auth and `If-None-Match` against the single global cache without sending `?repo=` (per-repo policy caching and `?repo=` fetching is a follow-up). On `304`, keeps cache, updates `fetched_at`, clears a payload-rejection sidecar (`invalid_policy`, `unsupported_regex`) while keeping `org_mismatch_ignored` and `no_org_ignored` until explicit `auth` or `logout`, and logs nothing alarming; accepts `200` no-org payloads (`org_id: null`, `mode: "observe"`, empty `builtin`/`custom`/`allow`, cached with no enforcement and `agentreel doctor` reporting `no org policy`) when no org policy is cached; pins a cached org policy during normal refreshes so neither a no-org 200 nor a different non-null `org_id` 200 can replace it (logging and surfacing warnings in `agentreel doctor`, with `run \`npx @agentreel/agent auth\` to switch orgs` on org mismatch), while explicit `agentreel auth`/`link` fetches a fresh policy (no ETag) and atomically replaces the policy cache, ETag, and sidecar only once it validates (a failed auth or policy fetch keeps the previous cache in force), and `agentreel logout` clears them; validates `org_id` equal to `workspace_id` when both are present (rejecting mismatches with a clear doctor warning), accepts `fetched_at` and `approval_defaults` (merged under per-rule `approval` and over built-in defaults `120` / `"deny"` for builtin and custom `require_approval` entries), accepts `scope.teams` as display-only metadata (team filtering happens on the server and the ETag varies per caller, so the CLI always applies delivered rules subject to other scope fields and ignores unknown top-level fields such as `current_user_teams`); enforces integer `expires_s` bounds `10..3600` in `validatePolicy` naming the rule; keeps `severity` (`info|warn|high|critical`) required on custom rules and optional on builtin overrides; treats `POST /api/v1/approvals` `201` and `200` (same-payload replay) identically, logs `409` conflicts as a client bug and applies effective `offline_fallback` (default `"deny"`, still bounded by the deadline guard), and reads `expires_at` on `GET /api/v1/approvals/:id` using `min(local expiry, server expires_at)` as the effective expiry.
- ESLint flat config (`eslint.config.mjs`, `@eslint/js` and `typescript-eslint` recommended rules, Node globals) with a root `pnpm lint` script and a `lint` workflow (`.github/workflows/lint.yml`) on pull requests and pushes to `main`. `no-useless-escape` and `no-unused-vars` start as warnings (32 existing hits, mostly regex literals in `src/guard/rules.ts` and `src/redact/patterns.ts`), and the stray `eslint-disable` comment in the Cursor watcher is removed.
- CI packs `@agentreel/agent` after the build and runs `npm audit --omit=dev --audit-level=high` against that published production tree, so a high or critical advisory in what `npm i @agentreel/agent` installs fails the job.

### Changed

- `agentreel init` installs the pre-exec hooks fail-closed: Claude Code `PreToolUse` gets `"onFailure": "block"` (Claude Code v2.1.295+) and the 4 Cursor pre-exec hooks (`preToolUse`, `beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`) get `"failClosed": true`, so a crash, timeout or missing binary blocks the action instead of letting it run. Lifecycle hooks stay fail-open. `agentreel doctor` warns when an installed pre-exec hook is missing either setting.

- Changed: now rejected (regex patterns accepted in 0.2.x that are now rejected by the linear-time RE2-safe subset, with verified replacements):
  - `curl[^|]*\|\s*(ba)?sh`: use `curl\s+\S+\s+\|\s*(ba)?sh`, or the single-unbounded `curl[^|]*\|`.
  - `(curl|wget)[^|]*\|\s*(ba|z)?sh`: use `(curl|wget)\s+\S+\s+\|\s*(ba|z)?sh`.
  - `\w+\s+\w+`: add a leading literal whose last char is disjoint from `\w`, e.g. `git\s+\w+\s+--force`.
  - `\S+\s+\S+`: add a leading literal disjoint from `\S`, e.g. `rm\s+\S+\s+/`.
  - `\u{1F600}\s+\w+` (non-ASCII literals are now treated as overlapping every character): use `\u{1F600}\s+\w`, which matches the same commands because rules match anywhere in the input.

### Fixed

- Upload timeout and retry: `postIngest` (used by `agentreel push`, the daemon flush and `agentreel link` validation) had no timeout, so a hung ingest could stall forever. Each attempt now aborts after 15s (`INGEST_TIMEOUT_MS`, covering the response body too) and fails with a transient `IngestError` (status 0). Timeouts, network errors, 5xx, 408 and 429 are retried up to 4 attempts in total with exponential backoff and full jitter (base 500ms, cap 8s), honoring a `Retry-After` header up to the cap. Other 4xx and a 2xx with `ok:false` still fail at once without a retry.

- Enforced-org marker: a missing, unreadable, invalid or edited `policy.json` no longer means allow once an org has enforced. Whenever the agent caches an org policy in `enforce` mode it writes `policy.json.enforced.json` (mode 0600) with the org and a SHA-256 of the policy. While that marker exists, a missing, unreadable or invalid cache, or one whose policy no longer matches the hash (for example edited to `mode:"observe"` or with a block rule removed), loads a lockdown policy: every built-in Guard rule enabled with action `block`, in enforce mode, under the org's name. `agentreel doctor` and `agentreel policy` show the lockdown and its reason. Fetching a non-enforcing policy, or an explicit `agentreel auth` or `logout`, removes the marker. An enforcing cache written by an older agent gets its marker on first load. This is a tamper alarm for honest mistakes and simple edits. The signed policy verifier (Ed25519 over the `GET /api/v1/policy` payload) is the real fix and lands separately once the web contract is published.


- Guard shell evasions: the built-in rules matched only the literal command text, so the 19 evasions in the re-audit (section 3.2) ran unblocked under an enforcing policy. In the pre-exec policy check each command rule now also runs on a normalized form of the command (NFKC, quotes and backslashes dropped, `$(echo X)` and backticks inlined, simple `VAR=value` expanded, `--recursive`/`--force` shortened, SQL `/**/` comments removed) and on synthetic equivalents: `find ~ -delete` and `python -c`/`node -e` home deletes read as `rm -rf ~`, a `base64 -d | sh` payload is decoded and checked, `bash <(curl ...)` and `sh -c "$(curl ...)"` read as `curl | sh`, `git push origin +main` reads as a force push, and a secret file or secret variable sent with `wget --post-file`, `nc`, a pipe, or in a URL or `-d` value reads as secret exfiltration. SQL files run with `psql -f`, `--file=` or `mysql <` are read (regular files, 256 KiB cap) and checked for `DROP TABLE` and friends. All passes are linear time; `matchRule` and `src/guard/linear-match.ts` are unchanged, findings still show the original command, and localhost targets and auth headers are not treated as exfiltration.



- Local `policyMode: "block"` now blocks: `guard-config.json` with `policyMode: "block"` was silently treated as observe. With no org policy cached, it now loads as an enforcing policy with every one of the 31 built-in rules at `block` (rules listed with `enabled: false` stay off, severity overrides and allowlists still apply). `"warn"` (the default) and `"off"` are unchanged, and a server org policy always takes precedence. Docs and the precision-test notes now say 31 built-in rules, not 30.




- Fail closed on malformed hook input and unknown policy values when an org enforces its policy. Malformed, empty or non-object JSON on a Claude Code `PreToolUse` hook or a Cursor pre-exec hook (`preToolUse`, `beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`) now denies with a clear org message instead of allowing, and so does an internal error in the hook or in `enforcePreExec` (reason `internal_error`). With no org policy, or an `observe` policy, these paths still fail open as before. `tool_input` sent as a JSON string is parsed, and a `command` sent as an argv array is joined, instead of skipping the rules. A Cursor payload (`cursor_version`) on the Claude hook path is now enforced when the native Cursor hooks are not installed, instead of returning before the policy check. Unknown enum strings in a policy (`mode`, `offline`, rule `action`, `severity`, `approval.offline_fallback`) now read as the strictest known value (`enforce`, `last_known`, `block`, `critical`, `deny`) instead of rejecting the whole policy, which used to leave no policy and allow everything. Non-string values are still rejected.

- Test suite: the wall-clock checks in `test/policy-eval.test.ts` (adversarial 32KB regex inputs under 5ms, and p95 policy evaluation under 50ms) and in `test/guard-scanner-deadline.test.ts` (the 120ms bound on a blast-radius timeout, plus the other 120ms "deadline fires promptly" checks in that file) no longer flake on busy machines ([#26](https://github.com/agentreel/agent/issues/26)). The base bounds are unchanged and are now scaled by a runner-speed factor measured on the same runner against a fixed baseline workload (`test/perf-calibration.ts`), clamped to 1x to 4x. `AGENTREEL_PERF_MULTIPLIER` overrides it (a positive number, clamped to 1 to 10; invalid values fail the run). Adversarial inputs and the blast-radius scan take the best of 3 attempts, a p95 sample that hits the evaluation deadline is retried up to twice, and a failure prints the measured time, the effective bound and the factor. Clamp tests in `test/perf-calibration.test.ts` pin the limits to the literals 4, 1 and 10 (a 100x-slow baseline is exactly 4, a fast baseline is exactly 1, `AGENTREEL_PERF_MULTIPLIER=1000` is exactly 10 and `0.5` is exactly 1), so loosening `MAX_FACTOR`, `MIN_FACTOR` or `MAX_ENV_MULTIPLIER` fails the suite. Test files only; no `src/` changes.


- Policy check before any DB write: the Claude Code `PreToolUse` and Cursor pre-exec hooks now run `enforcePreExec` first and record the session and event afterwards, inside a try. A corrupt `sessions.db`, a DB path that can't be opened (a directory, disk full, a better-sqlite3 ABI mismatch, a lock) used to throw from `upsertSession`/`insertEvent`/`recordCursorHook` before the policy check, which was caught and turned into an allow. Such a DB error is now logged to `~/.agentreel/agent.log` and the decision stands. Repo and branch scoped rules still apply on a session's first event: when no stored attribution exists, git info is collected in memory without writing.
- Guard scanner hard regex deadline, failing closed: the session scanner (`src/guard/scanner.ts`, used by `agentreel scan` and by the upload batch that builds `guard_findings` in `agentreel push` and the daemon) now runs each event's built-in rule pass and blast-radius stats in one call under the same hard VM watchdog as the policy evaluator (`runWithTimeout`), which preempts a running native regex. The per-event budget is 50ms plus 0.5ms per KB of command and payload, capped at 1000ms, so linear work on large legitimate payloads stays inside it. On timeout the rule that was running and every enabled rule after it are reported as findings at their effective severity with `reason: "scan_timeout"` and `scan_timeout:` evidence (no command text), disabled rules and allowlists still apply, rules that finished keep their real results, the summary sets `timedOut` and `timedOutRuleIds`, `agentreel scan` prints the timed-out rules, and one `scan_timeout` line per session goes to `~/.agentreel/agent.log`. A blast-radius timeout keeps partial stats and is logged without failing closed. `git push` plus 32KB of spaces took 3.3s and now stops at about 83ms; `curl` plus spaces (cubic in `INSTALL001`, 16s at 4KB) stops at the deadline. A timeout is never reported as clean.

- Guard scanner follow-ups: `INSTALL001` (cubic on `curl` plus spaces), `GIT001`, `GIT003` and `SAFETY002` (quadratic on spaces) are now linear-time per-segment matchers (`src/guard/linear-match.ts`) that match exactly what the old regexes matched (checked against the old patterns on a corpus and 200k random commands), so padded commands no longer hit `scan_timeout` or `eval_timeout`. One batch's guard scan now shares a 1500ms total budget (`ScanBudget`, `takePendingBatch`): events left unscanned fail closed as one `scan_budget_exceeded` finding per enabled rule per session, with one log line per batch. A rule-pass timeout no longer counts as a blast-radius timeout in the `scan_timeout` log line, and the scanner budget comment now says 82.5ms for a 32KB command.
- Path constants in `src/paths.ts` are functions (`agentreelDir()`, `logPath()`, `policyPath()`, and so on) that read `HOME` on each call instead of at import, so tests and probes that set `HOME` later no longer touch the real `~/.agentreel`. The test suite now runs every file with its own temporary `HOME`.
- Event payload strings are truncated before upload, with a marker `\n[agentreel: truncated, original length N chars]`, so one oversized string no longer gets a whole session rejected by the cloud ingest route. Caps sit below the server limits and include the marker: 64,000 UTF-16 code units for `prompt`, `output`, `patch`, `stdout`, `stderr` and `contents` (server 100,000), 9,500 for `title`, `label`, `rule_name`, `summary`, `detail`, `description`, `rationale`, `message` and any other string key or array element (server 10,000), and 950 for `reason` (server 1,000). Ids, tool and model names, versions, shas, branches, repos, cwd and file paths are never truncated. Surrogate pairs are never split. The guard scan still runs on the full text first. Limits live in one exported map, `INGEST_FIELD_LIMITS` (`src/upload/payload-caps.ts`).

- Regex input cap and hard built-in preemption: custom `regex` conditions are tested against at most the first 3072 UTF-16 code units of a field (`REGEX_INPUT_CAP`), cut so a surrogate pair is never split. If the value is longer and the capped prefix does not match, an enforcing regex rule fails closed: any such `block` rule makes the result `block`, otherwise any such `require_approval` rule makes it `require_approval`, and `flag` rules are skipped. Observe mode downgrades as usual. The policy decision records reason `input_too_long` and the agent log names the rule IDs. A rule whose non-regex condition is definitely false does not fail closed. Literal, glob, and built-in rules still see the full input. Built-in Guard rules, which use native regexes outside the safe subset, now run under the same VM watchdog as custom regexes, so the 50ms evaluation deadline preempts them mid-match (previously a 32KB `git push` plus spaces command held the hook for about 1.7s).

- A later `304` or same-org `200` on a normal policy refresh no longer clears an `org_mismatch_ignored` or `no_org_ignored` sidecar, so `agentreel doctor` keeps the org-mismatch warning (`run \`npx @agentreel/agent auth\` to switch orgs`) and the no-org ignore notice until explicit `auth` or `logout`. `fetched_at` is still updated on `304`. Other rejection reasons (`invalid_policy`, `unsupported_regex`) are still cleared by a successful `304` or same-org `200`.

- Non-ASCII literals (decoded `\x` / `\u` / `\u{...}` escapes, including inside `[...]`) are modelled as the universal set for disjointness, so a leading Kelvin (`\u212A`) or long s (`\u017F`) cannot bypass the last-char rule under `/iu` (or `/i`). This rejects `\u212A\w+\s+\w+\u{1F600}?`, `\u017F\w+\s+\w+\u{1F600}?`, `\u212A\w+\s+\w+`, `x\u212A[a-z]+\s+\w+`, `\w+\u212A\w+`, and the previously accepted `\u{1F600}\s+\w+`. Single-unbounded patterns and all existing ASCII accepts are unchanged.

- Regex escape decoding, octal rejection, case-folded leading-literal disjointness, and `agentreel doctor` no-cache rejection wording: `isRe2SafePattern` now decodes `\xHH`, `\uHHHH`, and `\u{H...}` as single characters (both outside and inside `[...]`) while rejecting `\p{...}`, `\P{...}`, `\cX`, octal escapes (`\0` followed by any digit, outside and inside `[...]`, while keeping plain `\0` as a NUL literal), and malformed hex/Unicode escapes (`> 0x10FFFF` or bad hex); patterns with 2+ unbounded quantifiers now require a mandatory leading literal (or literal-only bounded token, including a literal-only alternation group like `(DROP|TRUNCATE)`) after an optional `^` before the first unbounded quantifier whose last character set is disjoint under ASCII case folding from the first unbounded atom (rejecting `\w+\s+\w+`, `\S+\s+\S+`, `[a-z]+@[a-z]+`, `a+\s+b+`, `A\w+\s+\w+`, `\x41\w+\s+\w+`, `a[a-z]+\s+\w+`, `(DROP|TRUNCATE)\w+\s+\w+`, `foo[\x41-\x5A]+@[\x41-\x5A]+`, and `curl[^|]*\|\s*(ba)?sh`, while leaving single-unbounded patterns unaffected); and `agentreel doctor` / `fetchPolicy` now report `the rejected policy was not installed and org enforcement is off until a valid policy is cached` instead of `last known policy still in use` when a first fetch is rejected with no cached server policy.

- Production dependency `diff` bumped from `^7.0.0` to `^8.0.4` to pick up the GHSA-73rr-hh4g-fpgx patch (denial of service in `parsePatch` and `applyPatch` on versions `>=6.0.0 <8.0.3`). The CLI only uses `diffLines` and `structuredPatch`, which were not in the advisory, but the old range still failed `npm audit`. The redundant `@types/diff` devDependency is removed; jsdiff 8 ships its own types.

- `better-sqlite3` stays on `^12.11.1`. That is what pulls in the deprecated `prebuild-install@7.1.3` install helper. `better-sqlite3@13` and `node:sqlite` both require Node 22+, and this package still supports Node 20 (engines and CI). The deprecation is not a vulnerability. A Node 22+ migration can drop the native addon later.

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