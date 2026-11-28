import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { sep } from "node:path";
import pc from "picocolors";
import { installClaudeCodeHooks, quotePath } from "../hooks/install.js";
import { installCursorHooks } from "../cursor/hooks-install.js";
import { readConfig, writeConfig } from "../config.js";
import { getDb } from "../db.js";
import { ensureAgentreelDir } from "../paths.js";
import { loadEffectivePolicy } from "../policy/cache.js";
import { fetchPolicy } from "../policy/fetch.js";
import { computePreExecTimeoutS } from "../policy/types.js";

const PACKAGE_NAME = "@agentreel/agent";

interface ResolvedBinary {
  absolutePath: string;
  isEphemeral: boolean; // true when running from an npx temp dir
}

function resolveAgentBinary(): ResolvedBinary {
  // tsup builds to dist/cli.js with a node shebang; npm symlinks it to
  // <prefix>/bin/agentreel. The realpath through that symlink is stable for
  // npm i -g and for in-tree development. For `npx` installs it points
  // inside ~/.npm/_npx/<hash>/ which gets cleaned eventually — we detect
  // that and fall back to an `npx -y …` hook command instead.
  const here = fileURLToPath(import.meta.url);
  const real = realpathSync(here);
  const isEphemeral = real.includes(`${sep}_npx${sep}`) || real.includes("/_npx/");
  return { absolutePath: real, isEphemeral };
}

function chooseHookPrefix(bin: ResolvedBinary): { prefix: string; mode: "absolute" | "npx" } {
  if (process.env.AGENTREEL_HOOK_COMMAND) {
    return { prefix: process.env.AGENTREEL_HOOK_COMMAND, mode: "absolute" };
  }
  if (bin.isEphemeral) {
    return { prefix: `npx -y ${PACKAGE_NAME}`, mode: "npx" };
  }
  return { prefix: quotePath(bin.absolutePath), mode: "absolute" };
}

export interface InitOptions {
  /** commander maps --no-claude / --no-cursor to claude:false / cursor:false */
  claude?: boolean;
  cursor?: boolean;
  claudeSettingsPath?: string;
  cursorHooksPath?: string;
  /** System Cursor hooks file (default /etc/cursor/hooks.json); injectable for tests. */
  systemCursorHooksPath?: string;
  cachePath?: string;
  guardConfigPath?: string;
}

export async function initCommand(opts: InitOptions = {}): Promise<void> {
  ensureAgentreelDir();

  // Touch the DB so the file exists and migrations run.
  getDb();

  const cfg = readConfig();
  if (!cfg.installedAt) cfg.installedAt = Date.now();
  cfg.hooksInstalled = true;
  writeConfig(cfg);

  if (cfg.apiKey) {
    await fetchPolicy({ config: cfg, cachePath: opts.cachePath });
  }

  const loadedPolicy = loadEffectivePolicy({
    cachePath: opts.cachePath,
    guardConfigPath: opts.guardConfigPath,
  });
  const preExecTimeoutS = computePreExecTimeoutS(loadedPolicy.policy);

  const binary = resolveAgentBinary();
  const { prefix, mode } = chooseHookPrefix(binary);
  const result =
    opts.claude === false
      ? null
      : installClaudeCodeHooks(prefix, {
          settingsPath: opts.claudeSettingsPath,
          preExecTimeoutS,
        });
  const cursor =
    opts.cursor === false
      ? null
      : installCursorHooks(prefix, opts.cursorHooksPath, {
          preExecTimeoutS,
          ...(opts.systemCursorHooksPath ? { systemHooksPath: opts.systemCursorHooksPath } : {}),
        });

  const cursorInstalled = cursor && !cursor.skipped ? cursor : null;
  if (result || cursorInstalled) {
    const nextTimeouts = { ...(cfg.installedHookTimeouts ?? {}) };
    if (result) nextTimeouts.claude = preExecTimeoutS;
    if (cursorInstalled) nextTimeouts.cursor = preExecTimeoutS;
    cfg.installedHookTimeouts = nextTimeouts;
    writeConfig(cfg);
  }

  console.log(pc.bold(pc.cyan("\n  AgentReel  ")) + pc.dim("Loom for AI coding sessions\n"));
  console.log(pc.green("✓") + " Created ~/.agentreel/sessions.db");
  console.log(pc.green("✓") + " Wrote ~/.agentreel/config.json");
  if (result) {
    console.log(
      pc.green("✓") +
        ` Installed ${result.installedEvents.length} Claude Code hooks → ~/.claude/settings.json`,
    );
    if (result.backup) console.log(pc.dim(`  (backup: ${result.backup})`));
  }
  if (cursor?.skipped) {
    console.log(
      pc.green("✓") +
        ` Cursor hooks are owned by the managed pack (${cursor.managedPath}); skipped ~/.cursor/hooks.json so nothing is captured twice`,
    );
    if (cursor.warning) console.log(pc.yellow("!") + ` ${cursor.warning}`);
  } else if (cursor) {
    console.log(
      pc.green("✓") +
        ` Installed ${cursor.installedEvents.length} Cursor hooks → ~/.cursor/hooks.json` +
        pc.dim(" (commands, tool calls, MCP, edits, prompts)"),
    );
    if (cursor.backup) console.log(pc.dim(`  (backup: ${cursor.backup})`));
  }
  console.log();
  console.log(pc.dim("  Hook commands: ") + pc.dim(`${prefix} hook <Event>` + (cursorInstalled ? `, ${prefix} cursor-hook <event>` : "")));
  if (mode === "npx") {
    console.log(
      pc.dim("  ") +
        pc.yellow("•") +
        pc.dim(
          ` Hooks resolve via npx every time Claude Code fires an event.\n  ` +
            `  For faster cold starts, run: npm i -g ${PACKAGE_NAME}`,
        ),
    );
  }
  console.log();
  if (!cfg.apiKey) {
    console.log(pc.bold("Next steps:"));
    console.log(
      "  " + pc.dim("1.") + " " + pc.cyan("agentreel link <key>") +
        pc.dim("   — get a key from https://agentreel.dev/dashboard/settings"),
    );
    console.log(
      "  " + pc.dim("2.") + " " + pc.cyan("agentreel daemon --detach") +
        pc.dim("  — start the background uploader"),
    );
    console.log(
      "  " + pc.dim("3.") + " open Claude Code or Cursor and work as normal.",
    );
  } else {
    console.log(pc.bold("Next:"));
    console.log(
      "  " + pc.cyan("agentreel daemon --detach") +
        pc.dim("  — start the background uploader (already linked)"),
    );
  }
  console.log(
    "\n" + pc.dim("Anything: ") + pc.cyan("agentreel status") + pc.dim(" shows queue, last sync, last error."),
  );
  console.log(
    pc.dim("Privacy: ") +
      pc.cyan("agentreel pause") +
      pc.dim(" to stop recording temporarily (org policy is still enforced), ") +
      pc.cyan("agentreel forget --all") +
      pc.dim(" to wipe local sessions."),
  );
  console.log(
    pc.dim("         Or set ") +
      pc.cyan("AGENTREEL_DISABLE=1") +
      pc.dim(" before launching Claude Code to skip recording a single session (org policy is still enforced).\n"),
  );
}
