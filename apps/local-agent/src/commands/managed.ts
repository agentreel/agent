import { realpathSync } from "node:fs";
import { sep } from "node:path";
import { fileURLToPath } from "node:url";
import pc from "picocolors";
import { quotePath } from "../hooks/install.js";
import {
  applyManagedInstall,
  hookBinaryOwnerUid,
  ManagedInstallError,
  planManagedInstall,
  resolveManagedPlatform,
} from "../managed/install.js";
import type { ManagedPlatform } from "../managed/pack.js";

export interface ManagedInstallCliOptions {
  dryRun?: boolean;
  root?: string;
  hookCommand?: string;
  platform?: string;
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
}

/** Environment variables that mean we are running inside an agent's tool call. */
export function agentSessionMarker(env: NodeJS.ProcessEnv): string | null {
  if (env.CLAUDECODE === "1") return "CLAUDECODE";
  if (env.CLAUDE_CODE_CHILD_SESSION === "1") return "CLAUDE_CODE_CHILD_SESSION";
  if (env.CURSOR_AGENT) return "CURSOR_AGENT";
  return null;
}

function defaultHookCommand(): string {
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
    const hookCommand = opts.hookCommand ?? defaultHookCommand();
    const plans = planManagedInstall({
      root,
      platform,
      hookCommand,
      claude: opts.claude,
      cursor: opts.cursor,
    });

    log(pc.bold(dryRun ? "agentreel managed install (dry run, nothing is written)" : "agentreel managed install"));
    log(pc.dim(`  Hook command: ${hookCommand}`));
    if (root !== "/") log(pc.dim(`  Root: ${root}`));

    const owner = hookBinaryOwnerUid(hookCommand);
    if (owner === null) {
      log(pc.yellow(`  Warning: ${hookCommand} was not found. Hooks that block on failure will block every tool call until it exists.`));
    } else if (owner !== 0) {
      log(pc.yellow(`  Warning: ${hookCommand} is not owned by root (uid ${owner}), so an agent running as the user could replace it. Install agentreel as root.`));
    }

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
      log(`${pc.bold(r.target === "claude" ? "Claude Code" : "Cursor")}: ${r.systemPath} ${pc.dim(`(${verb})`)}`);
      if (r.path !== r.systemPath) log(pc.dim(`  written at ${r.path}`));
      if (r.backup) log(pc.dim(`  backup: ${r.backup}`));
      if (r.diff) log(r.diff.trimEnd());
    }

    if (!dryRun && results.some((r) => r.action !== "unchanged")) {
      log("");
      log(pc.dim("Next: open a new Claude Code session and run /status. Setting sources should list Enterprise managed settings (file)."));
      log(pc.dim("Cursor still runs AgentReel's entries in ~/.cursor/hooks.json too. Remove them so events are not captured twice: `agentreel uninstall` as your own user (no sudo), then `agentreel daemon --detach`, because uninstall also stops the uploader."));
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
