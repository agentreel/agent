import { Command } from "commander";
import { initCommand } from "./commands/init.js";

// Replaced at build time by tsup's `define`. Fallback covers running via
// ts-node where the literal isn't substituted.
declare const __AGENTREEL_VERSION__: string;
const VERSION =
  typeof __AGENTREEL_VERSION__ === "string" ? __AGENTREEL_VERSION__ : "dev";
import { statusCommand } from "./commands/status.js";
import { linkCommand, logoutCommand, uninstallCommand } from "./commands/auth.js";
import { watchCommand } from "./commands/watch.js";
import { pushCommand } from "./commands/push.js";
import { daemonCommand } from "./commands/daemon.js";
import { runHook } from "./hooks/handler.js";

const program = new Command();

program
  .name("agentreel")
  .description("AgentReel — capture Claude Code and Cursor sessions locally")
  .version(VERSION);

program
  .command("init")
  .description("install Claude Code hooks and create the local SQLite buffer")
  .action(async () => {
    await initCommand();
  });

program
  .command("status")
  .description("show local capture status, recent sessions, queue depth")
  .action(async () => {
    await statusCommand();
  });

program
  .command("watch")
  .description("watch Cursor's local history and capture edits as events")
  .action(async () => {
    await watchCommand();
  });

program
  .command("link [api-key]")
  .description("authenticate the local agent with agentreel.dev")
  .option("--api <url>", "override the API base URL (default https://api.agentreel.dev)")
  .action(async (apiKey: string | undefined, opts: { api?: string }) => {
    await linkCommand(apiKey, opts);
  });

program
  .command("push")
  .description("upload pending events to agentreel.dev")
  .action(async () => {
    await pushCommand();
  });

program
  .command("daemon")
  .description("run the background uploader (30s ticks, 1MB early-flush, exponential backoff)")
  .action(async () => {
    await daemonCommand();
  });

program
  .command("logout")
  .description("clear local credentials")
  .action(async () => {
    await logoutCommand();
  });

program
  .command("uninstall")
  .description("remove AgentReel hooks from ~/.claude/settings.json")
  .action(async () => {
    await uninstallCommand();
  });

program
  .command("hook <event>")
  .description("internal: hook handler invoked by Claude Code (reads JSON from stdin)")
  .action(async (event: string) => {
    await runHook(event);
  });

program.parseAsync(process.argv).catch((err) => {
  // Top-level: if we got this far on a hook invocation, something is very wrong.
  // For all other commands, print and exit non-zero.
  const cmd = process.argv[2];
  if (cmd === "hook") {
    process.exit(0);
  }
  console.error(err);
  process.exit(1);
});
