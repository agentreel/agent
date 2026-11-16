import pc from "picocolors";
import { readConfig } from "../config.js";
import { flushOnce } from "../upload/flush.js";
import { IngestError } from "../upload/client.js";
import { listHeldSessions, releaseHeldSessions } from "../db.js";

export async function pushCommand(opts: { retryHeld?: boolean } = {}): Promise<void> {
  const cfg = readConfig();
  if (!cfg.apiKey) {
    console.error(pc.red("✗ Not linked. Run ") + pc.cyan("agentreel link <api-key>"));
    process.exit(1);
  }

  if (opts.retryHeld) {
    const n = releaseHeldSessions();
    if (n > 0) console.log(pc.dim(`  retrying ${n} held session(s)`));
  }

  let totalSessions = 0;
  let totalEvents = 0;
  let limitMessage: string | undefined;
  const held = new Set<string>();

  // Drain in batches of MAX_BATCH_EVENTS / MAX_BATCH_BYTES until empty.
  for (;;) {
    let res;
    try {
      res = await flushOnce();
    } catch (err) {
      const e = err as Error;
      if (err instanceof IngestError) {
        console.error(pc.red("✗ ") + e.message);
        if (err.isPermanent) {
          console.error(
            pc.dim("  not retrying — fix the cause (re-link, upgrade plan, etc.) and run push again."),
          );
        }
      } else {
        console.error(pc.red("✗ ") + e.message);
      }
      process.exit(1);
    }
    totalSessions += res.uploadedSessions;
    totalEvents += res.uploadedEvents;
    for (const id of res.heldSessions) held.add(id);
    if (res.limitMessage) limitMessage = res.limitMessage;
    if (!res.moreAvailable) break;
  }

  const stillHeld = listHeldSessions();
  if (held.size > 0 || stillHeld.length > 0) {
    const n = Math.max(held.size, stillHeld.length);
    console.log(
      pc.yellow("!") +
        ` ${n} session(s) not uploaded: ${limitMessage ?? "over your plan's session limit"}`,
    );
    console.log(
      pc.dim("  they stay on this machine and are retried automatically; after upgrading run ") +
        pc.cyan("agentreel push --retry-held"),
    );
  }

  if (totalEvents === 0) {
    console.log(pc.green("✓") + " queue is empty — nothing to upload.");
    return;
  }
  console.log(
    pc.green("✓") +
      ` uploaded ${totalEvents} events · ${totalSessions} session rows touched`,
  );
}
