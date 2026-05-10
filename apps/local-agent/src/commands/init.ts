import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { sep } from "node:path";
import pc from "picocolors";
import { installClaudeCodeHooks, quotePath } from "../hooks/install.js";
import { readConfig, writeConfig } from "../config.js";
import { getDb } from "../db.js";
import { ensureAgentreelDir } from "../paths.js";

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

export async function initCommand(): Promise<void> {
  ensureAgentreelDir();

  // Touch the DB so the file exists and migrations run.
  getDb();

  const cfg = readConfig();
  if (!cfg.installedAt) cfg.installedAt = Date.now();
  cfg.hooksInstalled = true;
  writeConfig(cfg);

  const binary = resolveAgentBinary();
  const { prefix, mode } = chooseHookPrefix(binary);
  const result = installClaudeCodeHooks(prefix);

  console.log(pc.bold(pc.cyan("\n  AgentReel  ")) + pc.dim("Loom for AI coding sessions\n"));
  console.log(pc.green("✓") + " Created ~/.agentreel/sessions.db");
  console.log(pc.green("✓") + " Wrote ~/.agentreel/config.json");
  console.log(
    pc.green("✓") +
      ` Installed ${result.installedEvents.length} Claude Code hooks → ~/.claude/settings.json`,
  );
  if (result.backup) {
    console.log(pc.dim(`  (backup: ${result.backup})`));
  }
  console.log();
  console.log(pc.dim("  Hook command: ") + pc.dim(`${prefix} hook <Event>`));
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
  console.log(pc.bold("Next:") + " open Claude Code and run a prompt.");
  console.log("      then " + pc.cyan("agentreel status") + " to see captured events.\n");
}
