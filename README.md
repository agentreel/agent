# AgentReel Local Agent

The on-device half of [AgentReel](https://agentreel.dev) — Loom for AI coding sessions.

This repo contains the open-source **local agent** that runs on a developer's
machine and captures Claude Code and Cursor sessions. The cloud dashboard,
sharing, and MP4 export pipeline are not part of this repo.

## What it does

- Hooks into Claude Code's lifecycle events (`PreToolUse`, `PostToolUse`,
  `UserPromptSubmit`, `SessionStart`, `SessionEnd`) and writes them to a local
  SQLite buffer at `~/.agentreel/sessions.db`.
- Watches Cursor's local history directory and captures before/after edits as
  compact diff-match-patch deltas.
- Scrubs PII (AWS / GitHub / OpenAI / Anthropic / Stripe / Slack / Google / npm
  tokens, JWTs, PEM keys, dotenv `KEY=VAL`, emails, IPv4 addresses) **before**
  any data leaves the machine.
- Honours per-project `.agentreelignore` files (gitignore syntax).
- Ships events to the AgentReel cloud over HTTPS, batched every 30 s or 1 MB,
  with exponential backoff and a persistent queue. Network-loss-safe.

## Install

```bash
npx @agentreel/agent init
```

That writes the Claude Code hooks into `~/.claude/settings.json` and creates
the local SQLite buffer. Then link the agent to your account:

```bash
npx @agentreel/agent link <your-api-key>
```

Generate the key from your dashboard at
[agentreel.dev](https://agentreel.dev/dashboard/settings).

## Run the background uploader

```bash
npx @agentreel/agent daemon
```

Ticks every 30 seconds, flushes early when the local queue exceeds 1 MB,
records `last_sync_at` / `last_error_at` to the SQLite meta table, and uses
exponential backoff (1 s → 5 min, with jitter) on transient failures.

## All commands

| Command | Description |
|---|---|
| `agentreel init` | Install Claude Code hooks + create local DB |
| `agentreel link <key>` | Authenticate with agentreel.dev |
| `agentreel watch` | Watch Cursor's history dir |
| `agentreel daemon` | Run the background uploader |
| `agentreel push` | Drain the queue once and exit |
| `agentreel status` | Show capture state, queue depth, last sync, last error |
| `agentreel logout` | Clear local credentials |
| `agentreel uninstall` | Remove Claude Code hooks |

## Privacy

PII scrubbing is **default-on** and runs on every event before it touches the
network. The SQLite buffer is local-only and never uploaded as a file. The
`config.json` containing your API key is written with mode `0600`.

If you find a regex pattern that misses a credential shape, please open an
issue or PR — `apps/local-agent/src/redact/patterns.ts` is the file.

## Development

This is a pnpm workspace. Node 20+ required.

```bash
pnpm install
pnpm -r build
pnpm --filter @agentreel/agent typecheck
```

## License

MIT — see [LICENSE](./LICENSE).
