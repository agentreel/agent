import { randomBytes } from "node:crypto";
import pc from "picocolors";
import { readConfig, writeConfig } from "../config.js";
import { policyPath } from "../paths.js";
import {
  clearCachedPolicy,
  clearPolicyRejection,
  writeCachedPolicyAtomic,
} from "../policy/cache.js";
import { fetchPolicy, type FetchPolicyResult } from "../policy/fetch.js";
import { postIngest } from "../upload/client.js";

export interface LogoutOpts {
  cachePath?: string;
}

export async function logoutCommand(opts: LogoutOpts = {}): Promise<void> {
  const cfg = readConfig();
  cfg.apiKey = undefined;
  cfg.workspaceId = undefined;
  writeConfig(cfg);
  clearCachedPolicy(opts.cachePath);
  console.log(pc.green("✓") + " Cleared local credentials.");
}

interface LinkOpts {
  api?: string;
  cachePath?: string;
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
  const nextCfg = {
    ...cfg,
    apiKey: key,
    ...(opts.api ? { apiBaseUrl: opts.api } : {}),
  };

  console.log(pc.dim(`  validating against ${nextCfg.apiBaseUrl}…`));
  try {
    await postIngest(nextCfg, {});
  } catch (err) {
    console.error(pc.red("✗ Validation failed: ") + (err as Error).message);
    process.exit(1);
  }
  writeConfig(nextCfg);
  // Explicit auth is the only path allowed to change the cached org. It always
  // fetches fresh (no ETag) and swaps the cache only once the new policy validates.
  const policyRes = await replacePolicyCacheForAuth(
    nextCfg,
    opts.cachePath ?? policyPath(),
  );
  console.log(pc.green("✓") + " Linked.");
  console.log(pc.dim("  api: ") + nextCfg.apiBaseUrl);
  console.log(pc.dim("  key: ") + key.slice(0, 12) + "…");
  if (policyRes.status === "updated" || policyRes.status === "not_modified") {
    console.log(
      pc.dim("  policy: ") + `${policyRes.policy.mode} (etag ${policyRes.etag})`,
    );
  }
}

/**
 * Explicit auth replaces the cached policy, etag, and sidecar only after a fresh
 * policy (fetched without If-None-Match into a private staging file) validates.
 * The swap is an atomic rename, so hooks never see a gap with no policy. If the
 * fetch fails for any reason the previous cache stays in force (fail closed).
 */
async function replacePolicyCacheForAuth(
  cfg: ReturnType<typeof readConfig>,
  cachePath: string,
): Promise<FetchPolicyResult> {
  const stagingPath = `${cachePath}.auth.${process.pid}.${randomBytes(6).toString("hex")}`;
  try {
    const staged = await fetchPolicy({ config: cfg, cachePath: stagingPath });
    if (staged.status === "updated") {
      writeCachedPolicyAtomic(
        { policy: staged.policy, etag: staged.etag, fetched_at: staged.fetchedAt },
        cachePath,
      );
      clearPolicyRejection(cachePath);
    } else {
      console.error(
        pc.yellow("!") +
          " Could not fetch a valid policy; keeping the previously cached policy, if any. Run `npx @agentreel/agent auth` again to retry.",
      );
    }
    return staged;
  } finally {
    clearCachedPolicy(stagingPath);
  }
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
  const { uninstallCursorHooks } = await import("../cursor/hooks-install.js");
  // The user removed the hooks on purpose, so the transcript watcher must not
  // call every tool call a hook gap from now on.
  const after = readConfig();
  if (after.hooksInstalled) {
    after.hooksInstalled = false;
    writeConfig(after);
  }
  const cur = uninstallCursorHooks();
  if (cur.refused) {
    console.log(pc.yellow("!") + ` ${cur.refused}`);
  } else if (cur.removed > 0) {
    console.log(pc.green("✓") + " Removed AgentReel hooks from ~/.cursor/hooks.json");
    if (cur.backup) console.log(pc.dim(`  (backup: ${cur.backup})`));
  }
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
