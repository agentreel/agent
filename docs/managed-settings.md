# Enterprise managed policy (Claude Code and Cursor)

`agentreel init` installs AgentReel's hooks in each developer's **user** settings (`~/.claude/settings.json` and `~/.cursor/hooks.json`). Those files belong to the user, so an agent running as that user can edit them, delete them, or start a session with hooks turned off.

A managed policy moves the hooks into **system** files that only root can write, and that Claude Code and Cursor rank above every user and project setting:

| Tool | Linux and WSL | macOS | Windows |
| --- | --- | --- | --- |
| Claude Code | `/etc/claude-code/managed-settings.json` | `/Library/Application Support/ClaudeCode/managed-settings.json` | `C:\Program Files\ClaudeCode\managed-settings.json` |
| Cursor | `/etc/cursor/hooks.json` | `/Library/Application Support/Cursor/hooks.json` | `C:\ProgramData\Cursor\hooks.json` |

`agentreel managed install` writes the Linux and macOS files. On Windows, deploy the [templates](#templates) with your MDM.

## What the policy sets

### Claude Code (`managed-settings.json`)

| Key | Value | Effect |
| --- | --- | --- |
| `allowManagedHooksOnly` | `true` | Only managed hooks run. User, project and local hooks, and hooks from plugins that managed settings don't force-enable, are ignored, so an agent cannot add, change or switch off hooks through its own settings. This key is read only from a managed source. |
| `hooks` | the 9 AgentReel events | The same events, commands and timeouts `agentreel init` installs: `SessionStart`, `SessionEnd`, `UserPromptSubmit`, `PreToolUse`, `PostToolUse`, `Notification`, `Stop`, `SubagentStop`, `PreCompact`. Under `allowManagedHooksOnly` the user-level copies stop running, so the managed file carries all of them. |
| `PreToolUse` hook `onFailure` | `"block"` | If the AgentReel binary is missing, crashes or times out, the tool call is blocked instead of allowed. Needs Claude Code v2.1.295 or later. Timeout 130s (120s approval wait plus 10s). |
| `permissions.disableBypassPermissionsMode` | `"disable"` | No `bypassPermissions` mode (`--dangerously-skip-permissions`). |
| `sandbox.enabled` | `true` | Bash commands run in the OS sandbox (Seatbelt on macOS, bubblewrap on Linux and WSL2). |
| `sandbox.failIfUnavailable` | `true` | Claude Code refuses to start if the sandbox can't run, instead of quietly running unsandboxed. |
| `sandbox.allowUnsandboxedCommands` | `false` | Claude can't retry a failed command outside the sandbox (`dangerouslyDisableSandbox` is ignored). |

The installer **merges** into an existing file: it keeps every key your organization already set (for example `model`, `sandbox.excludedCommands`, other hooks), forces the keys above, and replaces only AgentReel's own hook groups (marked `"__agentreel": "agentreel:v1"`).

The sandbox needs its dependencies on Linux (`bubblewrap` and `socat`). With `failIfUnavailable`, Claude Code exits at startup on machines without them and on native Windows. Install them first, or remove `failIfUnavailable` from the file for those machines. Add `sandbox.excludedCommands` for approved tools that must run without isolation, and `sandbox.credentials` entries for `~/.aws`, `~/.ssh` and secret environment variables.

### Cursor (`hooks.json`)

All 14 events `agentreel init` installs, with the same commands and timeouts. The four pre-exec hooks (`preToolUse`, `beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`) set `"failClosed": true`, so a crash, timeout or missing binary blocks the action instead of letting it through. Enterprise hooks rank above team, project and user hooks.

Cursor runs every hooks file, not just the highest one, so AgentReel's per-user entries would capture each event a second time. The installer therefore also cleans the **invoking user's** `~/.cursor/hooks.json`:

- it removes only AgentReel's entries, found the same way `agentreel uninstall` finds them (the command runs `agentreel cursor-hook`); other tools' hooks and any other keys stay exactly as they were;
- it backs the file up first, keeps its owner and mode, and leaves a valid file (`{"version": 1, "hooks": {}}`) if AgentReel's were the only hooks;
- it does nothing when the file is missing, has no AgentReel entries, isn't valid JSON, or is a symlink;
- `--dry-run` shows the removal in its diff;
- under `sudo`, the user is `SUDO_USER` and the home comes from the account database (`getent passwd` on Linux, `dscl` on macOS), never root's own home. If that lookup fails it warns and skips the user file; pass `--user-home <dir>` instead.

Claude Code needs no cleanup: `allowManagedHooksOnly` already ignores user-level hooks. The uploader keeps running.

## Install

**Run these from a normal terminal, not from inside a Claude Code or Cursor agent session.** AgentReel's self-protection guard rules (shipping in a separate change) block agents from writing hook files, the policy cache, `/etc/claude-code/managed-settings.json` and `/etc/cursor/hooks.json`. The installer is your own CLI run by you, not a hook, so the guard does not get in its way. On a real run (not `--dry-run`) the installer also refuses when it can tell an agent is driving it, with three checks that run in this order:

1. **Environment markers.** `CLAUDECODE`, `CLAUDE_CODE_CHILD_SESSION` or `CURSOR_AGENT` is set.
2. **Process ancestry.** `sudo` clears those variables, so the installer also walks its parent processes (Linux: `/proc/<pid>/stat`, `cmdline` and `environ`; macOS: `ps -o ppid=,comm=`) and refuses if an ancestor is a Claude Code or Cursor process, or if an ancestor's own environment, which `sudo` does not clear, carries one of those markers. That includes the process that started `sudo`. `--yes` does not override this check. If the parent chain cannot be read, this check passes and the next one decides. Note that a person who runs it from Cursor's integrated terminal has Cursor as an ancestor and is refused too: use a separate terminal.
3. **A terminal.** If stdin is not a TTY, the installer refuses unless you pass `--yes`. Agents usually run commands without a terminal; people at a prompt do. Use `--yes` for provisioning scripts run by a person or by your MDM.

`--dry-run` is always allowed and skips all of these. These checks stop an agent that does not know about them, not a determined local attacker with root; the sudo password prompt and the guard rules are still the main defences.

1. Install AgentReel as root, so the hook binary is root-owned and an agent running as the user can't replace it:

   ```bash
   sudo npm install -g @agentreel/agent
   ```

   Don't point managed hooks at an `npx` cache; the installer refuses that.

   If you run the installer from a user-owned copy (for example `sudo` of an npm prefix under your home), it refuses to write: the hook command would point at a binary you or an agent can replace. Pass `--hook-command /usr/local/bin/agentreel` (or another root-owned path), or `--allow-user-writable-hook` to accept the risk. `--dry-run` warns and continues. An explicit `--hook-command` is always allowed, with a warning if the path fails the same check.

   The check walks the resolved real path of the binary and every parent directory up to `/` (or up to `--root`, not including the staging directory itself). It refuses when the binary is not root-owned, is group- or world-writable, or a parent directory is writable by a non-root user. On macOS, a binary owned by the `admin` group is accepted when it is not group-writable, which covers a root:admin `0755` `/usr/local`. With `--root`, the check looks at the path as it will be on the target (`<root>/usr/local/bin/agentreel` for `--hook-command /usr/local/bin/agentreel`).

2. Preview the change. Nothing is written:

   ```bash
   sudo agentreel managed install --dry-run
   ```

   It prints a unified diff for each file.

3. Write the files:

   ```bash
   sudo agentreel managed install
   ```

   The installer:
   - needs root to write the system paths, and says so if it isn't root;
   - backs up any file it changes to `<file>.agentreel-backup-<timestamp>`;
   - removes AgentReel's own entries from your `~/.cursor/hooks.json` (see [Cursor](#cursor-hooksjson));
   - writes atomically (temporary file, then rename), mode `0644`;
   - leaves a file alone, with no backup, when it already matches, so re-running is safe;
   - refuses to touch a file that isn't valid JSON;
   - makes **no network calls** and sends no telemetry.

4. Check it took effect. In a new Claude Code session, run `/status`: `Setting sources` should list `Enterprise managed settings (file)`. In Cursor, open the Hooks tab in Customize, or the Hooks output channel.

### Options

| Option | Effect |
| --- | --- |
| `--dry-run` | Print the diff and write nothing. Works without root. |
| `--hook-command <path>` | Absolute path to a root-owned `agentreel` binary. Default: the binary you ran, which is refused on a real run if it or a parent directory is writable by a non-root user. An explicit path gets the same check as a warning only. The installer also warns if the file is missing. |
| `--yes` | Allow a real run when stdin is not a terminal (scripts, MDM, CI image builds). It never overrides the environment or process-ancestry checks. |
| `--allow-user-writable-hook` | On a real run with the default hook binary, accept a user-writable path and print a loud warning. |
| `--root <dir>` | Write under `<dir>` instead of `/`, for example to stage files into an OS image or for MDM packaging. Works without root. |
| `--user-home <dir>` | Home whose `~/.cursor/hooks.json` loses AgentReel's entries, used as given. Default: the sudo user's home (or `HOME` without sudo), placed under `--root` when one is set. |
| `--platform linux\|darwin` | Choose the path layout. Default: this machine. |
| `--no-claude`, `--no-cursor` | Skip one of the two files. `--no-cursor` also leaves `~/.cursor/hooks.json` alone. |

## Templates

Ready-made files, generated by the same code as the installer, with the hook binary at `/usr/local/bin/agentreel`:

- [`managed/managed-settings.json`](managed/managed-settings.json): Claude Code
- [`managed/cursor-hooks.json`](managed/cursor-hooks.json): Cursor

Deploy them with your MDM or image tooling, and change the binary path if yours differs. A test keeps them in step with the installer. On macOS you can deliver the Claude Code keys as a configuration profile for the `com.anthropic.claudecode` preferences domain instead of the file.

## Limits

- The hooks still see only what the tools report, and rule matching is string based. The OS sandbox is the real boundary for Bash commands; it does not cover Claude's Edit and Write tools, and Cursor has no equivalent setting here.
- On WSL, `/etc/claude-code` is user-writable. Use the Windows policy (`wslInheritsWindowsSettings`) there.
- Cursor Enterprise dashboard hooks can't set `failClosed`; use the file for the pre-exec hooks.
- `sudo` usually clears the environment, so the environment check alone is easy to get around. The process-ancestry and terminal checks close that gap for agents that do not know about them, and they are still a second line of defence behind the guard rules and the sudo password prompt, not the main one. Ancestry is best effort: it is not read on platforms other than Linux and macOS, and on Linux a parent's environment is readable only by root or the same user. When it cannot be read, the terminal check is the fallback, and an agent that passes `--yes` with no agent ancestor visible is not stopped by these checks.

## Remove

Restore the newest `*.agentreel-backup-*` next to each file, or delete the file if the installer created it:

```bash
sudo rm /etc/claude-code/managed-settings.json /etc/cursor/hooks.json
```

Then run `agentreel init` as your own user to go back to user-level hooks.
