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
- **AgentReel Guard**: Local pattern detection for risky agent behavior. Default `policyMode` is **warn** (findings are recorded; hooks do not block Claude or Cursor). Scans run on upload and via `agentreel scan`. See [docs/threat-research.md](docs/threat-research.md) and [docs/detections.md](docs/detections.md).
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
| `agentreel pause` / `agentreel resume` | Pause or resume local capture |
| `agentreel forget` | Remove sessions from the local buffer |
| `agentreel logout` | Clear local API credentials |
| `agentreel uninstall` | Remove installed hooks |

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