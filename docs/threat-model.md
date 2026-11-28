# Self-protection denial codes

If a hook or the CLI blocks work with a `SELF00x` code, this is what it means.
The wording is taken from `src/policy/self-protect.ts` (`SELF_PROTECT_NAMES`
and the checks in `checkCommand` / `checkTool`) and from the NODE_OPTIONS
runtime self-check.

SELF001 to SELF005 in the command text are only enforced while an org policy
is **enforcing**. The runtime NODE_OPTIONS self-check (below) is always on and
does not need an org policy.

Where you see a code:

- A tool call denied by a command-text rule shows the code in the deny
  message Claude Code or Cursor gives the agent.
- A hook or CLI start denied by the runtime self-check prints the same
  message on stderr (`agentreel: Blocked by self-protection, SELF005: ...`),
  and for `hook PreToolUse` and `cursor-hook` pre-exec events also on the
  deny JSON. It is also appended to `~/.agentreel/agent.log`.

| Code | Meaning |
| --- | --- |
| SELF001 | The shell command would change AgentReel state (`~/.agentreel`), Claude Code settings, Cursor hooks, the managed policy files under `/etc/claude-code` or `/etc/cursor` (and the macOS and Windows equivalents), or the hook binary. |
| SELF002 | A Write/Edit-style tool call would change one of those same protected files. |
| SELF003 | The command would uninstall, log out of, or pause AgentReel, remove the `@agentreel/agent` package, or run `agentreel managed` other than `--dry-run`. |
| SELF004 | The command would disable hooks (`disableAllHooks`, or `claude --settings` / `--setting-sources`). |
| SELF005 | The command would unset or override a protected environment variable (`HOME`, `CLAUDE_CONFIG_DIR`, `CLAUDECODE`, `CLAUDE_CODE_CHILD_SESSION`, `CURSOR_AGENT`, or `AGENTREEL_*`), or set `NODE_OPTIONS` to anything off the six-flag allow list. Command-text triggers: `unset NAME`, `export NAME=...`, `export -n NAME`, `NAME=... claude` (and `cursor`, `cursor-agent`, `code`), `env -u NAME` / `env --unset=NAME`, and `env -i` / `env --ignore-environment` / `env -` (which clear all of them). At runtime: `process.env.NODE_OPTIONS` off the allow list, or a preload, loader, eval or inspector flag in `process.execArgv`. |

# Threat model: NODE_OPTIONS

The command-text NODE_OPTIONS check (self-protect SELF005) is a best-effort
guard, not a sandbox. It inspects the hook or CLI command string and denies
assignments that are not on the six-flag allow list
(`--max-old-space-size`, `--max-semi-space-size`, `--enable-source-maps`,
`--no-warnings`, `--trace-warnings`, `--dns-result-order`).

It cannot see names built at runtime, including:

- `eval` with hex escapes
- `printf ... | bash`
- `base64 ... | bash`
- string concatenation

## What closes the preload bypass: the installed hook command

Node applies `NODE_OPTIONS` (`--require`, `-r`, `--import`, `--loader`) before
any application code runs. Nothing inside the AgentReel process can stop a
preload from running, and a preload can `delete process.env.NODE_OPTIONS` so
that any in-process check sees nothing. This was confirmed on the built
bundle for `--require`, `-r` and `--import`.

So the hook commands that `agentreel init` writes drop `NODE_OPTIONS` before
Node starts:

| Host | Installed command |
| --- | --- |
| macOS, Linux | `env -u NODE_OPTIONS <agentreel> hook <Event>` (Cursor: `cursor-hook <event>`) |
| Windows | `cmd /d /s /c "set NODE_OPTIONS=&& <agentreel> hook <Event>"` |

A preload set in `NODE_OPTIONS` never loads in the hook process. If `env` or
`cmd` cannot be started the command fails: Claude Code PreToolUse entries are
written with `onFailure: "block"` and Cursor pre-exec entries with
`failClosed: true`, so the tool call is denied.

Limits:

- Hooks installed by an earlier version are not scrubbed. `agentreel doctor`
  warns about them and `agentreel init` rewrites them.
- The managed pack (`agentreel managed`) writes its own hook commands and does
  not scrub `NODE_OPTIONS` yet.
- The Windows form has not been run on a Windows host. A Windows host that
  runs hook commands through a POSIX shell (for example Git Bash) may need
  `AGENTREEL_HOOK_COMMAND` set to a command that works there.
- Only `NODE_OPTIONS` is scrubbed. Other ways to run code in a process the
  agent starts, such as a modified `PATH` or `node` binary, are out of scope.

## The runtime self-check is detection only

At CLI startup AgentReel reads `process.env.NODE_OPTIONS` and `process.execArgv`
in the first code its own bundle runs, before commander, telemetry, hooks and
the database load. (The bundle still evaluates its third-party imports,
`better-sqlite3`, `picocolors`, `ignore` and `diff`, first, so this is not
"before anything else".) If `NODE_OPTIONS` contains any token outside the allow
list, if it cannot be parsed, or if `execArgv` has a preload, loader, eval or
inspector flag (`--require`, `-r`, `--import`, `--loader`,
`--experimental-loader`, `--eval`, `-p`, `--inspect*`), the process fails
closed with SELF005:

- `hook PreToolUse` prints the Claude Code deny JSON on stdout and the reason
  on stderr, and exits 2.
- `cursor-hook` pre-exec events (`preToolUse`, `beforeShellExecution`,
  `beforeMCPExecution`, `beforeReadFile`) print the Cursor deny JSON and the
  reason on stderr, and exit 2. An unknown Cursor event is treated the same way.
- Claude lifecycle events and Cursor capture-only hooks have no deny shape.
  They print the reason on stderr, exit 1, and record nothing.
- Every other command prints the reason on stderr and exits 1.

Unset or empty values, and allow-listed flags, pass. Harmless `execArgv` such
as `--conditions` passes.

This check only sees what is still visible when it runs. A preload that
deletes `NODE_OPTIONS` runs first and leaves it nothing to see, so it is a
second layer for installs the scrub does not cover, not the fix. It is on for
every run, with or without an org policy.
