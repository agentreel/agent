import { Command, CommanderError } from "commander";
import { initCommand } from "./commands/init.js";
import { flushCliTelemetry, runCliTelemetry } from "./telemetry.js";

// Replaced at build time by tsup's `define`. Fallback covers running via
// ts-node where the literal isn't substituted.
declare const __AGENTREEL_VERSION__: string;
const VERSION =
  typeof __AGENTREEL_VERSION__ === "string" ? __AGENTREEL_VERSION__ : "dev";
import { statusCommand } from "./commands/status.js";
import { linkCommand, logoutCommand, uninstallCommand } from "./commands/auth.js";
import { watchCommand } from "./commands/watch.js";
import { pushCommand } from "./commands/push.js";
import { daemonCommand, stopCommand } from "./commands/daemon.js";
import {
  forgetCommand,
  pauseCommand,
  resumeCommand,
} from "./commands/privacy.js";
import { runHook } from "./hooks/handler.js";
import { runCursorHook } from "./cursor/hook-runner.js";
import { configCommand } from "./commands/config.js";
import { scanCommand } from "./commands/scan.js";
import { policyCommand } from "./commands/policy.js";
import { doctorCommand } from "./commands/doctor.js";

const program = new Command();

program
  .name("agentreel")
  .description("AgentReel: capture Claude Code and Cursor sessions locally")
  .version(VERSION);

program
  .command("init")
  .description("install Claude Code and Cursor hooks and create the local SQLite buffer")
  .option("--no-claude", "skip the Claude Code hooks")
  .option("--no-cursor", "skip the Cursor hooks (~/.cursor/hooks.json)")
  .action(async (opts: { claude?: boolean; cursor?: boolean }) => {
    await initCommand(opts);
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
  .option("--retry-held", "retry sessions the server refused earlier (e.g. after upgrading your plan)")
  .action(async (opts: { retryHeld?: boolean }) => {
    await pushCommand(opts);
  });

program
  .command("daemon")
  .description("run the background uploader (30s ticks, 1MB early-flush, exponential backoff)")
  .option("--detach", "fork into the background and return immediately; logs to ~/.agentreel/daemon.log")
  .action(async (opts: { detach?: boolean }) => {
    await daemonCommand({ detach: opts.detach });
  });

program
  .command("stop")
  .description("stop the running background uploader")
  .action(() => {
    stopCommand();
  });

program
  .command("pause")
  .description("pause local capture — hooks and watcher no-op until `resume`")
  .action(() => {
    pauseCommand();
  });

program
  .command("resume")
  .description("resume local capture after `pause`")
  .action(() => {
    resumeCommand();
  });

program
  .command("forget [session-ids...]")
  .description("delete captured sessions from the local SQLite buffer")
  .option("--all", "wipe every session (asks for confirmation)")
  .option("--force", "skip the confirmation prompt (use with care)")
  .action(async (ids: string[], opts: { all?: boolean; force?: boolean }) => {
    await forgetCommand(ids ?? [], opts);
  });

program
  .command("logout")
  .description("clear local credentials")
  .action(async () => {
    await logoutCommand();
  });

program
  .command("uninstall")
  .description("remove AgentReel hooks from ~/.claude/settings.json and ~/.cursor/hooks.json")
  .action(async () => {
    await uninstallCommand();
  });

program
  .command("hook <event>")
  .description("internal: hook handler invoked by Claude Code (reads JSON from stdin)")
  .action(async (event: string) => {
    await runHook(event);
  });

program
  .command("cursor-hook <event>")
  .description("internal: hook handler invoked by Cursor (reads JSON from stdin)")
  .action(async (event: string) => {
    await runCursorHook(event);
  });

program
  .command("config [key] [value]")
  .description("show or change settings: hostname <plain|hash|omit>, attribution <on|off>")
  .action((key?: string, value?: string) => {
    configCommand(key, value);
  });

program
  .command("scan [session-id]")
  .description("scan a session for risky agent behavior patterns (local, no network calls)")
  .action(async (sessionId?: string) => {
    await scanCommand(sessionId ? [sessionId] : []);
  });

program
  .command("policy")
  .description("show cached policy source, etag, age, mode, offline setting, and rule counts")
  .action(() => {
    policyCommand();
  });

program
  .command("doctor")
  .description("check policy enforcement state, etag age, and pre-exec hook timeouts")
  .action(() => {
    doctorCommand();
  });

program.exitOverride();

async function main(): Promise<void> {
  void runCliTelemetry(VERSION);
  let exitCode = 0;
  try {
    await program.parseAsync(process.argv);
  } catch (err) {
    if (err instanceof CommanderError) {
      exitCode = err.exitCode;
    } else {
      const cmd = process.argv[2];
      if (cmd === "hook" || cmd === "cursor-hook") {
        exitCode = 0;
      } else {
        console.error(err);
        exitCode = 1;
      }
    }
  } finally {
    await flushCliTelemetry();
  }
  if (exitCode !== 0) {
    process.exit(exitCode);
  }
}

void main();
