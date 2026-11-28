import { execFileSync } from "node:child_process";
import { realpathSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import pc from "picocolors";
import { quotePath } from "../hooks/install.js";
import {
  applyManagedInstall,
  ManagedInstallError,
  planManagedInstall,
  resolveManagedPlatform,
  underRoot,
} from "../managed/install.js";
import type { ManagedPlatform } from "../managed/pack.js";
import {
  hookPathRefusalMessage,
  hookPathWarningMessage,
  inspectHookCommandPath,
  type RealpathFn,
  type StatPath,
} from "../managed/hook-path.js";

export interface ManagedInstallCliOptions {
  dryRun?: boolean;
  root?: string;
  hookCommand?: string;
  platform?: string;
  /** Home directory whose ~/.cursor/hooks.json loses AgentReel's entries. Used as given, not placed under --root. */
  userHome?: string;
  allowUserWritableHook?: boolean;
  /** commander maps --no-claude / --no-cursor to claude:false / cursor:false */
  claude?: boolean;
  cursor?: boolean;
}

export interface ManagedInstallDeps {
  env?: NodeJS.ProcessEnv;
  uid?: number | null;
  log?: (line: string) => void;
  error?: (line: string) => void;
  now?: Date;
  /** Test seam: replaces the writer so a test can prove nothing is written. */
  apply?: typeof applyManagedInstall;
  /** Test seam: looks up a user's home directory (default: getent on Linux, dscl on macOS). */
  lookupHome?: (user: string, platform: ManagedPlatform) => string | null;
  /** Test seam: ownership checks must not touch the real filesystem. */
  stat?: StatPath;
  realpath?: RealpathFn;
}

const SAFE_USER = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$/;

function systemLookupHome(user: string, platform: ManagedPlatform): string | null {
  try {
    if (platform === "darwin") {
      const out = execFileSync("/usr/bin/dscl", [".", "-read", `/Users/${user}`, "NFSHomeDirectory"], {
        encoding: "utf8",
        timeout: 3000,
        stdio: ["ignore", "pipe", "ignore"],
      });
      return out.match(/NFSHomeDirectory:\s*(\S.*)$/m)?.[1]?.trim() ?? null;
    }
    const out = execFileSync("getent", ["passwd", user], {
      encoding: "utf8",
      timeout: 3000,
      stdio: ["ignore", "pipe", "ignore"],
    });
    return out.trim().split(":")[5] ?? null;
  } catch {
    return null;
  }
}

/**
 * The invoking user's home. Under sudo that is SUDO_USER's home from the
 * account database, never root's. With a staging root the home is placed under it.
 */
export function resolveInvokingUserHome(
  opts: { root: string; userHome?: string; platform: ManagedPlatform },
  env: NodeJS.ProcessEnv,
  uid: number | null,
  lookup: (user: string, platform: ManagedPlatform) => string | null,
): { home: string | null; warning?: string } {
  if (opts.userHome !== undefined) {
    if (!isAbsolute(opts.userHome)) throw new ManagedInstallError(`--user-home must be an absolute path, got ${opts.userHome}`);
    return { home: resolve(opts.userHome) };
  }
  let home: string | null;
  const sudoUser = env.SUDO_USER;
  if (uid === 0 && sudoUser && sudoUser !== "root") {
    if (!SAFE_USER.test(sudoUser)) {
      return { home: null, warning: "SUDO_USER is not a valid user name, so ~/.cursor/hooks.json was left alone. Use --user-home." };
    }
    home = lookup(sudoUser, opts.platform);
    if (!home || !isAbsolute(home) || resolve(home) === "/") {
      return { home: null, warning: `Could not find ${sudoUser}'s home directory, so ~/.cursor/hooks.json was left alone. Use --user-home.` };
    }
  } else {
    home = env.HOME || homedir();
  }
  home = resolve(home);
  return { home: opts.root === "/" ? home : underRoot(opts.root, home) };
}

/** Environment variables that mean we are running inside an agent's tool call. */
export function agentSessionMarker(env: NodeJS.ProcessEnv): string | null {
  if (env.CLAUDECODE === "1") return "CLAUDECODE";
  if (env.CLAUDE_CODE_CHILD_SESSION === "1") return "CLAUDE_CODE_CHILD_SESSION";
  if (env.CURSOR_AGENT) return "CURSOR_AGENT";
  return null;
}

export function defaultHookCommand(): string {
  const real = realpathSync(fileURLToPath(import.meta.url));
  if (real.includes(`${sep}_npx${sep}`) || real.includes("/_npx/")) {
    throw new ManagedInstallError(
      "agentreel is running from an npx cache, which the agent can overwrite. Install it as root (sudo npm i -g @agentreel/agent) or pass --hook-command <absolute path to a root-owned agentreel>.",
    );
  }
  return quotePath(real);
}

function parsePlatform(value: string | undefined): ManagedPlatform {
  if (value === undefined) return resolveManagedPlatform();
  if (value === "linux" || value === "darwin") return value;
  throw new ManagedInstallError(`--platform must be linux or darwin, got ${value}`);
}

/**
 * `agentreel managed install`: write the system-wide Claude Code managed
 * settings and Cursor enterprise hooks. Returns the process exit code.
 */
export function managedInstallCommand(opts: ManagedInstallCliOptions, deps: ManagedInstallDeps = {}): number {
  const env = deps.env ?? process.env;
  const uid = deps.uid !== undefined ? deps.uid : typeof process.getuid === "function" ? process.getuid() : null;
  const log = deps.log ?? ((l: string) => console.log(l));
  const error = deps.error ?? ((l: string) => console.error(l));
  const root = opts.root ?? "/";
  const dryRun = opts.dryRun === true;

  try {
    if (!dryRun) {
      const marker = agentSessionMarker(env);
      if (marker) {
        throw new ManagedInstallError(
          `Refusing to write managed policy from inside an agent session (${marker} is set). Run this from a normal terminal. --dry-run is allowed.`,
        );
      }
      if (root === "/" && uid !== 0) {
        throw new ManagedInstallError(
          "Writing system policy files needs root. Re-run with sudo: sudo agentreel managed install. Use --dry-run to preview, or --root <dir> to stage the files into a directory.",
        );
      }
    }

    const platform = parsePlatform(opts.platform);
    const hookCommandExplicit = opts.hookCommand !== undefined;
    const hookCommand = opts.hookCommand ?? defaultHookCommand();
    const warnings: string[] = [];
    const inspection = inspectHookCommandPath(hookCommand, {
      platform,
      root,
      stat: deps.stat,
      realpath: deps.realpath,
    });
    if (inspection.missing && inspection.issues.length === 0) {
      warnings.push(
        `${inspection.checkedPath ?? hookCommand} was not found. Hooks that block on failure will block every tool call until it exists.`,
      );
    }
    if (inspection.issues.length > 0) {
      const allowed = hookCommandExplicit || opts.allowUserWritableHook === true || dryRun;
      if (!allowed) {
        throw new ManagedInstallError(hookPathRefusalMessage(inspection.issues));
      }
      const detail = hookPathWarningMessage(inspection.issues);
      warnings.push(
        opts.allowUserWritableHook
          ? `WARNING: installing a hook binary a non-root user can replace (--allow-user-writable-hook).
${detail}`
          : hookCommandExplicit
            ? `${detail}
The path was set with --hook-command, so install continues. Point it at a root-owned binary to silence this.`
            : `${detail}
This is a dry run, so install was not refused. A real run needs --hook-command <root-owned path>, or --allow-user-writable-hook to accept the risk.`,
      );
    }
    let cursorUserHooksPath: string | undefined;
    if (opts.cursor !== false) {
      const user = resolveInvokingUserHome(
        { root, userHome: opts.userHome, platform },
        env,
        uid,
        deps.lookupHome ?? systemLookupHome,
      );
      if (user.warning) warnings.push(user.warning);
      if (user.home) cursorUserHooksPath = join(user.home, ".cursor", "hooks.json");
    }
    const plans = planManagedInstall({
      root,
      platform,
      hookCommand,
      claude: opts.claude,
      cursor: opts.cursor,
      cursorUserHooksPath,
      onWarning: (w) => warnings.push(w),
    });

    log(pc.bold(dryRun ? "agentreel managed install (dry run, nothing is written)" : "agentreel managed install"));
    log(pc.dim(`  Hook command: ${hookCommand}`));
    if (root !== "/") log(pc.dim(`  Root: ${root}`));

    for (const w of warnings) log(pc.yellow(`  Warning: ${w}`));

    const results = dryRun ? plans.map((p) => ({ ...p, backup: null })) : (deps.apply ?? applyManagedInstall)(plans, deps.now);
    for (const r of results) {
      const verb =
        r.action === "unchanged"
          ? "unchanged"
          : dryRun
            ? r.action === "create"
              ? "would create"
              : "would update"
            : r.action === "create"
              ? "created"
              : "updated";
      log("");
      const label =
        r.target === "claude"
          ? "Claude Code"
          : r.target === "cursor"
            ? "Cursor"
            : "Cursor user hooks (removing AgentReel's entries; the managed file replaces them)";
      log(`${pc.bold(label)}: ${r.systemPath} ${pc.dim(`(${verb})`)}`);
      if (r.path !== r.systemPath) log(pc.dim(`  written at ${r.path}`));
      if (r.backup) log(pc.dim(`  backup: ${r.backup}`));
      if (r.diff) log(r.diff.trimEnd());
    }

    if (!dryRun && results.some((r) => r.action !== "unchanged")) {
      log("");
      log(pc.dim("Next: open a new Claude Code session and run /status. Setting sources should list Enterprise managed settings (file)."));
    }
    return 0;
  } catch (err) {
    if (err instanceof ManagedInstallError) {
      error(pc.red(`agentreel managed install: ${err.message}`));
      return 1;
    }
    throw err;
  }
}
