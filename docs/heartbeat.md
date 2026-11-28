# Daemon heartbeat and hook gaps

While `agentreel daemon` runs it can send a small heartbeat to AgentReel. The server uses it to tell a covered device from one that went quiet (the daemon died, the machine is offline, or the hooks were removed).

## What is sent

Counts, states and gaps only. Never command text.

- `capture`: active or paused.
- `hooks_installed` for the Claude Code and Cursor hooks (a yes or no).
- The cached policy mode (`observe` or `enforce`).
- Transcript watcher counters: state, files watched, tool calls seen, gap total, last scan time, error counts.
- Upload queue depth, last sync time, consecutive failures.
- Agent version, OS family and a random device id stored locally. Never the hostname.
- For each **hook gap**: the tool name, the `tool_use` id and the session id, plus timestamps. Never the command, arguments, file paths, prompts or output.

Run `agentreel heartbeat status` to see this summary and whether the heartbeat is on.

## Hook gaps: Claude Code only

The transcript watcher reads Claude Code transcripts (`~/.claude/projects/**/*.jsonl`, or `CLAUDE_CONFIG_DIR/projects`, or `AGENTREEL_CLAUDE_PROJECTS_DIR`). A tool call in the transcript with no matching hook event is a gap. Gap detection is Claude Code only. Cursor has no transcript source for this, so Cursor tool calls are never checked for gaps.

## When it is on

| Install | Default | How to change |
| --- | --- | --- |
| Linked to an org workspace (`org_default`) | on | `agentreel heartbeat off` (the org dashboard then shows the device as uncovered) |
| Personal or unlinked install | off | opt in with `agentreel heartbeat on` (config `heartbeat: true`) |
| Any install with `AGENTREEL_HEARTBEAT=0` | off, always | unset the variable |

`AGENTREEL_HEARTBEAT=0` (also `false`, `no`, `off`) always wins over config and the org default. A device counts as org-linked when its cached policy comes from an org (`org_id` set) or the config records an org. Until the first policy sync the device is treated as personal.

`agentreel doctor` and `agentreel status` show the state and the reason: org default, opt-in, opted out, personal install, or disabled by env. Turn the transcript watcher off separately with `AGENTREEL_TRANSCRIPT_WATCH=0`.

## Server

`POST /api/v1/agent/heartbeat` (contract in agentreel/web, PR #65, route PR #67; migration `agent_heartbeats`, numbered 0024 at merge). Beats every 60 s by default, the server can ask for 30 to 900 s. Failures retry with exponential backoff and jitter. A `401` pauses until `agentreel link` changes the key.
