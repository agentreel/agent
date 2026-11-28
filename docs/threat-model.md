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
| SELF005 | The command would unset or override a protected environment variable (`HOME`, `CLAUDE_CONFIG_DIR`, `CLAUDECODE`, `CLAUDE_CODE_CHILD_SESSION`, `CURSOR_AGENT`, or `AGENTREEL_*`), or set `NODE_OPTIONS` to anything off the six-flag allow list. Command-text triggers: `unset NAME`, `export NAME=...`, `export -n NAME`, `declare` / `typeset` (including `declare -n` and `typeset -n`), `NAME=... claude` (and `cursor`, `cursor-agent`, `code`), `env -u NAME` / `env --unset=NAME`, and `env -i` / `env --ignore-environment` / `env -` (which clear all of them). Also `npm` / `pnpm` / `yarn` / `bun config set node-options`, and a write or edit of `~/.npmrc` (or another `.npmrc`) whose content sets `node-options`. At runtime: `process.env.NODE_OPTIONS` off the allow list, or a preload, loader, eval or inspector flag in `process.execArgv`. A visible runtime failure on `hook PreToolUse` and `cursor-hook` pre-exec events exits 2 with deny JSON; `hook Stop` and the other lifecycle or capture-only events exit 1 with the reason (see below). |

Runtime SELF005 exit codes: `hook PreToolUse` and the Cursor pre-exec events (`preToolUse`, `beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`) print the host deny JSON, print the reason on stderr, and exit 2, which Claude Code and Cursor treat as a block. `hook Stop` and the other Claude lifecycle events (`SessionStart`, `SessionEnd`, `UserPromptSubmit`, `PostToolUse`, `Notification`, `SubagentStop`, `PreCompact`) and Cursor capture-only hooks have no deny shape, so they print the reason on stderr and exit 1, not 2. Exit 2 on `Stop` is "keep going" in Claude Code and would prevent the session from ending.

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

So the hook commands that `agentreel init` and `agentreel managed install`
write drop `NODE_OPTIONS` and `npm_config_node_options` before Node starts.
`npx` and `bunx` prefixes also get `--node-options=` (empty), because npm
would otherwise inject `NODE_OPTIONS` from `~/.npmrc` or
`npm_config_node_options` after `env -u NODE_OPTIONS` alone:

| Host | Installed command |
| --- | --- |
| macOS, Linux | `env -u NODE_OPTIONS -u npm_config_node_options -u NPM_CONFIG_NODE_OPTIONS <agentreel> hook <Event>` (Cursor: `cursor-hook <event>`). An `npx` or `bunx` prefix also gets `--node-options=`. |
| Windows, Claude Code | The same POSIX `env -u` form, with the hook entry's `shell` field set to `"bash"`. Claude Code's default host shell on Windows is Git Bash when Git is installed. The older `cmd /d /s /c "set NODE_OPTIONS=&& ..."` form is mis-tokenized there: a path with spaces breaks the command, and `/d` `/s` `/c` can be path-mangled, which would block every PreToolUse and stop lifecycle capture. If bash is missing, PreToolUse fails closed via `onFailure: "block"`. |
| Windows, Cursor | PowerShell 7 (`pwsh`) via `-File`: set `$OutputEncoding` and `[Console]::InputEncoding` / `OutputEncoding` to UTF-8 with no BOM, `Remove-Item Env:NODE_OPTIONS`, `Env:npm_config_node_options` and `Env:NPM_CONFIG_NODE_OPTIONS`, then `$input |` the prefix and `cursor-hook` event. `& node` does not inherit PowerShell's stdin, so `$input` has to be piped. Cursor has no hook `shell` field; the desktop app runs hooks through PowerShell. The windows-latest job proves this form with `pwsh -File` and the hook JSON opened as stdin. Windows PowerShell 5.1 hangs when stdin is redirected, until the hook timeout (130s for pre-exec), then fails closed. `powershell -Command` and Node `spawnSync` `input` also hang. No real Cursor-on-Windows launch was tested. |

A preload set in `NODE_OPTIONS` never loads in the hook process. If `env`
or PowerShell cannot be started the command fails: Claude Code PreToolUse
entries are written with `onFailure: "block"` and Cursor pre-exec entries
with `failClosed: true`, so the tool call is denied.

Limits:

- Hooks installed by an earlier version are not scrubbed. `agentreel doctor`
  warns about them. Users must re-run `agentreel init` (or `agentreel managed
  install` for a managed pack) to get the scrubbed hook commands.
- The managed pack writes the same scrubbed commands as the per-user
  installers (POSIX `env -u` on linux and darwin, and the Claude `shell:
  "bash"` / Cursor PowerShell forms when the builders are asked for win32).
  `agentreel managed install` itself still supports only Linux, WSL and
  macOS.
- The windows-latest CI job runs the installed command through Git Bash
  `bash.exe` (Claude) and PowerShell 7 `pwsh -File` (Cursor), including a
  prefix path with spaces and a non-ASCII hook JSON payload. A custom
  `AGENTREEL_HOOK_COMMAND` is still untested as a host integration. No
  real Cursor-on-Windows launch was tested. Windows PowerShell 5.1 hangs
  when stdin is redirected, until the hook timeout (130s for pre-exec),
  then fails closed, so it is not used in that job.
- Only `NODE_OPTIONS`, `npm_config_node_options` and
  `NPM_CONFIG_NODE_OPTIONS` are scrubbed (plus `--node-options=` for
  `npx` / `bunx`). A shell rc file (`bashrc` and friends) or
  `launchctl setenv` can put `NODE_OPTIONS` back depending on how the
  host starts the shell; that is a known follow-up, not claimed coverage.
  `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES` and `BASH_ENV` are out of scope
  for this wrapper: they can still inject code into `env` or the hook
  process, and are not unset. Other ways to run code in a process the
  agent starts, such as a modified `PATH` or `node` binary, are also out
  of scope.

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
