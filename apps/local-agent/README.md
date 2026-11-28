# @agentreel/agent

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

The local agent for [AgentReel](https://agentreel.dev). It captures coding-agent sessions on your machine, scrubs PII before anything leaves it, and ships replays you can share and scrub.

## Install

```sh
npx @agentreel/agent init
```

`init` writes hooks into `~/.claude/settings.json` and `~/.cursor/hooks.json`, and
creates a local SQLite buffer at `~/.agentreel/sessions.db`. Use
`agentreel init --no-cursor` or `--no-claude` if you only need one client.

For faster cold-starts on every hook fire, install globally instead:

```sh
npm install -g @agentreel/agent
agentreel init
```

## What it does

- **Hooks in `~/.claude/settings.json`**: `agentreel init` installs `SessionStart`, `SessionEnd`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `Notification`, `Stop`, `SubagentStop`, and `PreCompact`. Each event is normalized and persisted locally. `PreToolUse` can enforce org policy.
- **Hooks in `~/.cursor/hooks.json`**: `agentreel init` installs `sessionStart`, `sessionEnd`, `beforeSubmitPrompt`, `preToolUse`, `beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`, `postToolUse`, `postToolUseFailure`, `afterShellExecution`, `afterMCPExecution`, `afterFileEdit`, `subagentStop`, and `stop`. That records shell commands with output, exit code and duration, MCP and other tool calls, file reads and edits, and prompts. The four pre-exec hooks (`preToolUse`, `beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`) can enforce org policy.
- **Local history watcher (optional)**: `agentreel watch` follows local history and turns saved snapshots into diffs. With the hooks installed it records manual edits only.
- **Who and where**: each session records the OS user, hostname, git user, repo remote (credentials stripped), branch and commit at start and end, and the agent and agentreel versions. `agentreel config hostname hash` stores a salted hash instead of the machine name, `omit` leaves it out, and `agentreel config attribution off` turns all of it off.
- **PII scrubbing, default-on**: AWS / GitHub / Stripe / Slack / Google / npm tokens, other cloud API keys, JWTs, PEM private keys, dotenv `KEY=VAL` lines, emails, IPv4. Scrubs *before* anything is persisted, never after.
- **`.agentreelignore`**: gitignore-syntax exclusions per workspace.
- **Local first**: works offline. Sign in only when you want to share.

## Usage

```sh
agentreel init                        # install hooks, create the local SQLite buffer
agentreel init --no-cursor            # skip ~/.cursor/hooks.json (or --no-claude)
agentreel watch                       # optional: watch local history (manual edits)
agentreel config hostname hash        # hostname <plain|hash|omit>
agentreel config attribution off      # attribution <on|off>
agentreel status                      # local capture status, recent sessions, queue depth
agentreel link|auth [api-key]         # authenticate with agentreel.dev (--api <url>)
agentreel daemon                      # background uploader (--detach)
agentreel stop                        # stop the running background uploader
agentreel push                        # upload pending events once
agentreel push --retry-held           # retry sessions refused earlier (e.g. after upgrading your plan)
agentreel scan [session-id]           # scan a session for risky patterns (local, no network)
agentreel policy                      # cached policy source, etag, age, mode, rule counts
agentreel doctor                      # policy enforcement state, etag age, pre-exec hook timeouts
agentreel pause                       # pause local capture (org policy is still enforced)
agentreel resume                      # resume local capture after pause
agentreel forget [session-ids...]     # delete sessions from the local buffer (--all, --force)
agentreel uninstall                   # remove hooks from ~/.claude/settings.json and ~/.cursor/hooks.json
agentreel logout                      # clear local credentials
sudo agentreel managed install        # system-wide managed settings and hooks (see --help)
```

Get an API key at [agentreel.dev/dashboard/settings](https://agentreel.dev/dashboard/settings).

## Where things live

| Path                      | What                                              |
| ------------------------- | ------------------------------------------------- |
| `~/.agentreel/sessions.db`| SQLite buffer for sessions + events               |
| `~/.agentreel/config.json`| API key (if linked), API base URL                 |
| `~/.agentreel/agent.log`  | Hook-handler error log                            |
| `~/.claude/settings.json` | Hooks added by `agentreel init`                   |
| `~/.cursor/hooks.json`    | Hooks added by `agentreel init`                   |
| `<workspace>/.agentreelignore` | Per-project exclusions, gitignore syntax     |

## Privacy

PII scrubbing runs at the source, not in the cloud. The unified diff stored on each captured file edit is computed against the **scrubbed** versions of the file, so secrets never enter the patch text. Verify it yourself:

```sh
agentreel status
sqlite3 ~/.agentreel/sessions.db "SELECT payload FROM events LIMIT 5;" | grep -E "AKIA|ghp_|sk-"
# (no matches expected)
```

## Requirements

- Node 20+
- macOS, Linux, or Windows (WSL recommended)
- A supported local coding agent (hooks install into `~/.claude/settings.json` and/or `~/.cursor/hooks.json`)

## License

Apache License 2.0, Copyright 2026 Navjot Singh. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).

Apache License 2.0 applies from **v0.2.1** onward. Versions **0.2.0 and earlier** were released under the [MIT License](https://opensource.org/licenses/MIT).

---

Built by Navjot Singh. Source: [github.com/agentreel/agent](https://github.com/agentreel/agent).
