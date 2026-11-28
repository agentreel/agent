# Self-protection denial codes

If a hook or the CLI blocks work with a `SELF00x` code, this is what it means.
The wording is taken from `src/policy/self-protect.ts` (`SELF_PROTECT_NAMES`
and the checks in `checkCommand` / `checkTool`) and from the NODE_OPTIONS
runtime self-check.

| Code | Meaning |
| --- | --- |
| SELF001 | The shell command would change AgentReel state (`~/.agentreel`), Claude Code settings, Cursor hooks, the managed policy files under `/etc/claude-code` or `/etc/cursor` (and the macOS and Windows equivalents), or the hook binary. |
| SELF002 | A Write/Edit-style tool call would change one of those same protected files. |
| SELF003 | The command would uninstall, log out of, or pause AgentReel, remove the `@agentreel/agent` package, or run `agentreel managed` other than `--dry-run`. |
| SELF004 | The command would disable hooks (`disableAllHooks`, or `claude --settings` / `--setting-sources`). |
| SELF005 | The command would unset or override protected environment variables (`HOME`, `CLAUDE_CONFIG_DIR`, `CLAUDECODE`, `CLAUDE_CODE_CHILD_SESSION`, `CURSOR_AGENT`, or `AGENTREEL_*`), or `NODE_OPTIONS` is not on the six-flag allow list (in the command text, or in `process.env.NODE_OPTIONS` at hook-runner or CLI startup). |

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

Those paths are covered by the runtime self-check. At hook-runner startup and
CLI startup, AgentReel reads `process.env.NODE_OPTIONS` before loading
anything else. If the effective value contains any token outside the allow
list, the process fails closed with SELF005: the CLI exits non-zero, and a
hook denies the call. Unset or empty values, and allow-listed flags, pass.
Unparseable values fail closed.

The runtime check is the backstop on the value Node actually applied to this
process.
