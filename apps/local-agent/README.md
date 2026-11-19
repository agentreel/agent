# @agentreel/agent

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

> **Loom for AI coding sessions.** The local agent for [AgentReel](https://agentreel.dev). It captures every Claude Code and Cursor session on your machine, scrubs PII before anything leaves it, and ships replays you can share, scrub, and export to MP4.

## Install

```sh
npx @agentreel/agent init
```

`init` writes Claude Code hooks into `~/.claude/settings.json`, Cursor observe-only
hooks into `~/.cursor/hooks.json`, and creates a local SQLite buffer at
`~/.agentreel/sessions.db`. Use `agentreel init --no-cursor` or `--no-claude` if you
only need one client.

For faster cold-starts on every hook fire, install globally instead:

```sh
npm install -g @agentreel/agent
agentreel init
```

## What it does

- **Claude Code**: installs hooks for every lifecycle event (`PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `SessionStart`, `SessionEnd`, plus the rest). Each event is normalized and persisted locally.
- **Cursor (hooks)**: `agentreel init` adds observe-only hooks to `~/.cursor/hooks.json` (`sessionStart`, `sessionEnd`, `beforeSubmitPrompt`, `postToolUse`, `postToolUseFailure`, `afterShellExecution`, `afterMCPExecution`, `afterFileEdit`, `subagentStop`, `stop`). That records the agent's shell commands with output, exit code and duration, MCP and other tool calls, file reads and edits, and prompts. None of these hooks can approve or block anything.
- **Cursor (watcher, optional)**: `agentreel watch` follows Cursor's local history and turns saved snapshots into diffs. With the hooks installed it records manual edits only.
- **Who and where**: each session records the OS user, hostname, git user, repo remote (credentials stripped), branch and commit at start and end, and the agent and agentreel versions. `agentreel config hostname hash` stores a salted hash instead of the machine name, `omit` leaves it out, and `agentreel config attribution off` turns all of it off.
- **PII scrubbing, default-on**: AWS / GitHub / OpenAI / Anthropic / Stripe / Slack / Google / npm tokens, JWTs, PEM private keys, dotenv `KEY=VAL` lines, emails, IPv4. Scrubs *before* anything is persisted, never after.
- **`.agentreelignore`**: gitignore-syntax exclusions per workspace.
- **Local first**: works offline. Sign in only when you want to share.

## Usage

```sh
agentreel init                        # install Claude Code + Cursor hooks, create local DB
agentreel init --no-cursor            # Claude Code only (or --no-claude)
agentreel watch                       # optional: Cursor history watcher (manual edits)
agentreel config hostname hash        # plain | hash | omit
agentreel config attribution off      # stop recording user/host/git
agentreel status                      # what's captured, what's pending upload
agentreel link <api-key>              # authenticate with agentreel.dev
agentreel push                        # upload pending events to the cloud
agentreel push --retry-held           # retry sessions refused for the plan limit (after upgrading)
agentreel uninstall                   # remove hooks from ~/.claude/settings.json and ~/.cursor/hooks.json
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
| `~/.cursor/hooks.json`    | Cursor hooks (added by `agentreel init`)          |
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

Apache License 2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).

Versions **0.2.0 and earlier** were released under the [MIT License](https://opensource.org/licenses/MIT).

---

Built by [Black Highlights](https://blackhighlights.com). Source: [github.com/agentreel/agent](https://github.com/agentreel/agent).
