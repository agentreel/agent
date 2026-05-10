import pc from "picocolors";
import { readConfig } from "../config.js";
import { flushOnce } from "../upload/flush.js";
import { IngestError } from "../upload/client.js";

export async function pushCommand(): Promise<void> {
  const cfg = readConfig();
  if (!cfg.apiKey) {
    console.error(pc.red("✗ Not linked. Run ") + pc.cyan("agentreel link <api-key>"));
    process.exit(1);
  }

  let totalSessions = 0;
  let totalEvents = 0;

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
    if (!res.moreAvailable) break;
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
