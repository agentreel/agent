import pc from "picocolors";
import { readConfig, writeConfig } from "../config.js";
import { postIngest } from "../upload/client.js";

export async function logoutCommand(): Promise<void> {
  const cfg = readConfig();
  cfg.apiKey = undefined;
  cfg.workspaceId = undefined;
  writeConfig(cfg);
  console.log(pc.green("✓") + " Cleared local credentials.");
}

interface LinkOpts {
  api?: string;
}

export async function linkCommand(rawKey: string | undefined, opts: LinkOpts): Promise<void> {
  const key = (rawKey ?? (await promptHidden("Paste your AgentReel API key: "))).trim();
  if (!key) {
    console.error(pc.red("✗ No key provided."));
    process.exit(1);
  }
  if (!key.startsWith("ar_live_")) {
    console.error(pc.red("✗ Keys start with `ar_live_`. Did you paste the right value?"));
    process.exit(1);
  }

  const cfg = readConfig();
  cfg.apiKey = key;
  if (opts.api) cfg.apiBaseUrl = opts.api;

  console.log(pc.dim(`  validating against ${cfg.apiBaseUrl}…`));
  try {
    await postIngest(cfg, {});
  } catch (err) {
    console.error(pc.red("✗ Validation failed: ") + (err as Error).message);
    process.exit(1);
  }
  writeConfig(cfg);
  console.log(pc.green("✓") + " Linked.");
  console.log(pc.dim("  api: ") + cfg.apiBaseUrl);
  console.log(pc.dim("  key: ") + key.slice(0, 12) + "…");
}

export async function uninstallCommand(): Promise<void> {
  const { uninstallClaudeCodeHooks } = await import("../hooks/install.js");
  const { stopCommand } = await import("./daemon.js");
  // Stop first so we don't leave a daemon flushing into a half-uninstalled
  // setup. stopCommand() is idempotent — silent when nothing is running.
  stopCommand();
  const { backup } = uninstallClaudeCodeHooks();
  console.log(pc.green("✓") + " Removed AgentReel hooks from ~/.claude/settings.json");
  if (backup) console.log(pc.dim(`  (backup: ${backup})`));
}

const CTRL_C = 0x03;
const BACKSPACE = 0x7f;
const BACKSPACE_ALT = 0x08;
const NEWLINE = 0x0a;
const CARRIAGE = 0x0d;

function promptHidden(prompt: string): Promise<string> {
  return new Promise((resolve) => {
    process.stdout.write(prompt);
    let buf = "";
    const stdin = process.stdin;
    stdin.setRawMode?.(true);
    stdin.resume();
    stdin.setEncoding("utf8");
    const onData = (chunk: string) => {
      for (const ch of chunk) {
        const code = ch.charCodeAt(0);
        if (code === NEWLINE || code === CARRIAGE) {
          stdin.setRawMode?.(false);
          stdin.pause();
          stdin.removeListener("data", onData);
          process.stdout.write("\n");
          return resolve(buf);
        }
        if (code === CTRL_C) {
          stdin.setRawMode?.(false);
          process.exit(130);
        }
        if (code === BACKSPACE || code === BACKSPACE_ALT) {
          buf = buf.slice(0, -1);
        } else {
          buf += ch;
        }
      }
    };
    stdin.on("data", onData);
  });
}
