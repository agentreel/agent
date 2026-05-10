# @agentreel/agent

> **Loom for AI coding sessions.** The local agent for [AgentReel](https://agentreel.dev) — captures every Claude Code and Cursor session on your machine, scrubs PII before anything leaves it, and ships replays you can share, scrub, and export to MP4.

## Install

```sh
npx @agentreel/agent init
```

`init` writes Claude Code hooks into `~/.claude/settings.json` and creates a local SQLite buffer at `~/.agentreel/sessions.db`. That's the entire setup.

For faster cold-starts on every hook fire, install globally instead:

```sh
npm install -g @agentreel/agent
agentreel init
```

## What it does

- **Claude Code** — installs hooks for every lifecycle event (`PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `SessionStart`, `SessionEnd`, plus the rest). Each event is normalized and persisted locally.
- **Cursor** — watches `~/Library/Application Support/Cursor/User/History/` and turns every saved snapshot into a unified diff against the previous version. Distinguishes AI-driven (Composer) edits from manual ones.
- **PII scrubbing, default-on** — AWS / GitHub / OpenAI / Anthropic / Stripe / Slack / Google / npm tokens, JWTs, PEM private keys, dotenv `KEY=VAL` lines, emails, IPv4. Scrubs *before* anything is persisted, never after.
- **`.agentreelignore`** — gitignore-syntax exclusions per workspace.
- **Local first** — works offline. Sign in only when you want to share.

## Usage

```sh
agentreel init                        # install Claude Code hooks + create local DB
agentreel watch                       # start the Cursor filesystem watcher
agentreel status                      # what's captured, what's pending upload
agentreel link <api-key>              # authenticate with agentreel.dev
agentreel push                        # upload pending events to the cloud
agentreel uninstall                   # remove hooks from ~/.claude/settings.json
agentreel logout                      # clear local credentials
```

Get an API key at [agentreel.dev/dashboard/settings](https://agentreel.dev/dashboard/settings).

## Where things live

| Path                      | What                                              |
| ------------------------- | ------------------------------------------------- |
| `~/.agentreel/sessions.db`| SQLite buffer for sessions + events               |
| `~/.agentreel/config.json`| API key (if linked), API base URL                 |
| `~/.agentreel/agent.log`  | Hook-handler error log                            |
| `~/.claude/settings.json` | Claude Code hooks (added by `agentreel init`)     |
| `<workspace>/.agentreelignore` | Per-project exclusions, gitignore syntax     |

## Privacy

PII scrubbing runs at the source, not in the cloud. The unified diff stored on each Cursor edit is computed against the **scrubbed** versions of the file, so secrets never enter the patch text. Verify it yourself:

```sh
agentreel status
sqlite3 ~/.agentreel/sessions.db "SELECT payload FROM events LIMIT 5;" | grep -E "AKIA|ghp_|sk-"
# (no matches expected)
```

## Requirements

- Node 20+
- macOS, Linux, or Windows (WSL recommended)
- Claude Code or Cursor (or both)

## License

MIT — see [LICENSE](./LICENSE).

---

Built by [Black Highlights](https://blackhighlights.com). Source: [github.com/agentreel/agentreel](https://github.com/agentreel/agentreel).
