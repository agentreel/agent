<!-- PNGs rasterized from the SVGs with resvg at 2x and 3x (160px and 240px). -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/assets/agentreel-logo-dark.png">
  <img src=".github/assets/agentreel-logo-light.png" alt="AgentReel" width="80" height="80">
</picture>

# AgentReel Local Agent

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![npm version](https://img.shields.io/npm/v/@agentreel/agent)](https://www.npmjs.com/package/@agentreel/agent)

Open-source [agent session replay](https://agentreel.dev) for your machine. This repo is the local CLI that captures **Claude Code** and **Cursor** sessions, buffers them in SQLite on disk, and uploads scrubbed events to [AgentReel](https://agentreel.dev) when you link an account. The cloud dashboard, sharing, and export pipeline live in the separate [agentreel/web](https://github.com/agentreel/web) repo.

## Quickstart

```bash
npx @agentreel/agent init
npx @agentreel/agent link <api-key>
npx @agentreel/agent daemon
```

Get an API key at [agentreel.dev/dashboard/settings](https://agentreel.dev/dashboard/settings).

`init` installs Claude Code hooks (`~/.claude/settings.json`), Cursor observe-only hooks (`~/.cursor/hooks.json`), and creates `~/.agentreel/sessions.db`. Use `agentreel init --no-claude` or `--no-cursor` if you only need one client.

## What it does

- **Capture**: Claude Code lifecycle hooks and Cursor hooks record tool use, shell output, prompts, and session boundaries into `~/.agentreel/sessions.db`. Optional `agentreel watch` adds manual edits from Cursor local history.
- **Redaction**: Sensitive patterns (tokens, keys, emails, and similar) are scrubbed when events are written to SQLite, before any upload.
- **Attribution**: Sessions can record OS user, hostname (plain, salted hash, or omitted via `agentreel config hostname`), git user, repo remote with credentials stripped, and branch/commit at start and end (`agentreel config attribution off` disables this).
- **Upload**: `agentreel daemon` or `agentreel push` sends batches over HTTPS (30 s or 1 MB thresholds, exponential backoff, persistent queue). The SQLite file itself is not uploaded.
- **AgentReel Guard**: Local pattern detection for risky agent behavior. Default `policyMode` is **warn** (findings are recorded; hooks do not block Claude or Cursor). Set `policyMode` to `"block"` in `~/.agentreel/guard-config.json` to block all 31 built-in rules locally when no org policy is cached. Scans run on upload and via `agentreel scan`. See [docs/threat-research.md](docs/threat-research.md) and [docs/detections.md](docs/detections.md).
- **Custom policy regex subset**: Custom policy `regex` conditions must stay within a linear-time RE2-safe subset (max 300 characters, no lookarounds or backreferences, no `\p{...}`, `\P{...}`, `\cX`, octal escapes like `\012` / `\00`, or malformed hex/Unicode escapes, no nested quantifiers, no quantified alternations, and no consecutive unbounded quantifiers whose character sets can overlap). Plain `\0` (not followed by a digit) remains a NUL literal, and `\xHH`, `\uHHHH`, and `\u{H...}` escapes are decoded to the single character they represent (both outside and inside `[...]`). You can use multiple unbounded quantifiers (`*`, `+`, `{n,}`) when the pattern begins (after an optional `^`) with at least one mandatory literal or literal-only bounded token before the first unbounded quantifier (a literal-only alternation group such as `(DROP|TRUNCATE)` counts as a leading literal), the last character of that leading literal run (or every possible last character of a leading literal-only group) is disjoint under ASCII case folding from the first unbounded quantifier's character set, and every consecutive pair of unbounded quantifiers is separated by a mandatory literal or character class that cannot match either neighbor (for example `rm\s+-rf\s+/`, `aws\s+s3\s+rb`, `^git\s+push\s+--force`, `(DROP|TRUNCATE)\s+TABLE\s+\w+`, `curl\s+\|\s*sh`, or `curl\s+\S+\s+\|\s*(ba)?sh`). Single-unbounded patterns (such as `curl[^|]*\|`) are unaffected by the leading-literal rule. Tip: avoid `.*` before a literal (for example, prefer `curl\s+\S+\s+\|\s*(ba)?sh` or a single-unbounded `curl[^|]*\|` over `curl.*\|\s*(ba)?sh`, because `.` overlaps `|`, and note that unanchored `curl[^|]*\|\s*(ba)?sh` is also rejected because `l` overlaps `[^|]`). Policies with unsupported regexes are rejected at validation while keeping any last-known cached policy (or leaving org enforcement off when no cache exists) and surfacing a warning in `agentreel doctor`.
- **Regex input cap**: custom `regex` conditions only see the first 3072 characters (UTF-16 code units, never splitting a surrogate pair) of a field. When the value is longer and the prefix does not match, enforcing regex rules fail closed: a `block` rule blocks, otherwise a `require_approval` rule asks, and `flag` rules are skipped, with reason `input_too_long` on the policy decision. Literal, glob, and built-in rules still check the full input, and built-in rules are preempted at the 50ms evaluation deadline like custom regexes.
- **Govern API v1 (C1) policy sync & scoping**: `GET /api/v1/policy` uses Bearer auth and `If-None-Match` against the single global policy cache (per-repo `?repo=` policy fetching is a follow-up until the cache is per-repo). A `304 Not Modified` keeps the cached policy, bumps `fetched_at`, and clears a payload-rejection sidecar (`invalid_policy` or `unsupported_regex`), but keeps `org_mismatch_ignored` and `no_org_ignored` until explicit `auth` or `logout`. A `200` with `org_id: null`, `mode: "observe"`, and empty `builtin`/`custom`/`allow` is cached as "no org" (no enforcement; `agentreel doctor` reports `no org policy`) when no org policy is cached, while `404` remains tolerated. Once an org policy is cached, normal refreshes ignore both no-org responses (`no-org response ignored; keeping cached org policy <org_id>`) and responses for a different non-null org (`policy for org <B> ignored; keeping cached org <A>`) and surface them in `agentreel doctor` (with the hint to run `npx @agentreel/agent auth` to switch orgs). Explicit `agentreel auth` / `agentreel link` fetches a fresh policy (no ETag) and atomically replaces the cached policy, ETag, and sidecar only once it validates, so a failed auth or policy fetch keeps the previous cache in force; `agentreel logout` clears them. Policies may include `org_id` (must match `workspace_id` when both are present), `fetched_at`, `approval_defaults` (`{ expires_s, offline_fallback }` merged under per-rule `approval` and over built-in defaults `120` / `"deny"` for both builtin and custom `require_approval` rules; `expires_s` must be an integer in `10..3600`), and `scope.teams`. Team filtering happens on the server (the ETag varies per caller), so `scope.teams` is display-only in the CLI: rules with `scope.teams` are always applied (subject to the other scope fields) and unknown top-level fields (such as `current_user_teams`) are ignored. Remote approvals treat `POST /api/v1/approvals` `201` (created) and `200` (same-payload replay) identically, log `409` (reused `decision_id` with different payload) as a client bug and apply effective `offline_fallback` (default `"deny"`, still bounded by the deadline guard), and tighten effective expiry to `min(local expiry, server expires_at)` whenever `expires_at` is echoed on `POST` or `GET`.
- **Ignore lists**: Per-project `.agentreelignore` (gitignore syntax) can drop file contents from payloads.

## Commands

| Command | Description |
| --- | --- |
| `agentreel init` | Install hooks and create local DB (`--no-claude`, `--no-cursor`) |
| `agentreel link [api-key]` | Authenticate with agentreel.dev |
| `agentreel daemon` | Run the background uploader (`--detach` to fork) |
| `agentreel push` | Upload pending events once (`--retry-held` for plan-limit refusals) |
| `agentreel status` | Queue depth, capture state, last sync/error |
| `agentreel scan [session-id]` | Guard scan (local, no network) |
| `agentreel watch` | Optional Cursor history watcher |
| `agentreel config [key] [value]` | `hostname plain\|hash\|omit`, `attribution on\|off` |
| `agentreel pause` / `agentreel resume` | Pause or resume local recording (`AGENTREEL_DISABLE=1` skips one session; org policy is still enforced) |
| `agentreel forget` | Remove sessions from the local buffer |
| `agentreel logout` | Clear local API credentials |
| `agentreel uninstall` | Remove installed hooks |
| `sudo agentreel managed install` | Enterprise managed policy: system-wide Claude Code managed settings and Cursor hooks (`--dry-run`, `--root`). See [docs/managed-settings.md](docs/managed-settings.md) |

## Secret scanning (gitleaks)

There is no CI, so run gitleaks locally before you push. The repo config is `.gitleaks.toml`: the default rules, plus one allowlist for the fake secrets in `apps/local-agent/test/*.test.ts`, limited to the `generic-api-key` and `private-key` rules.

```bash
# full history, all branches
gitleaks git --log-opts=--all --redact .

# working tree, including untracked files
gitleaks dir --redact .

# only the commits you are about to push
gitleaks git --log-opts="origin/main..HEAD" --redact .
```

Each command should end with "no leaks found". If one finds a real secret, rotate it first, then remove it. Never widen the allowlist to hide a real secret.

## Telemetry

The agentreel CLI sends anonymous usage data so we know how many people use it: one event the first time it runs, then at most one heartbeat a day. Each event carries the CLI version, OS type, and the number of sessions recorded. It never includes session content, prompts, code, file paths, or your IP address. It's identified only by a random ID stored in ~/.agentreel. To turn it off, set AGENTREEL_TELEMETRY=0 (or false, off, no) or DO_NOT_TRACK=1. Telemetry is always off in CI.

## Roadmap

`/govern` and `/defend` are coming soon on [agentreel.dev](https://agentreel.dev).

## Development

pnpm workspace, Node 20+.

```bash
pnpm install
pnpm -r build
pnpm --filter @agentreel/agent typecheck
pnpm --filter @agentreel/agent test
```

## License

Apache License 2.0 from **v0.2.1** onward. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).

Versions **0.2.0 and earlier** were released under the [MIT License](https://opensource.org/licenses/MIT).