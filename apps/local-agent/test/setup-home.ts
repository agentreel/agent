import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Every test file starts with HOME pointing at its own empty temp directory,
// so nothing in the suite can read or write the real ~/.agentreel (logs,
// policy cache, queue db). paths.ts reads HOME on each call, so a test that
// sets process.env.HOME again later is also honored.
const home = mkdtempSync(join(tmpdir(), "agentreel-suite-home-"));
process.env.HOME = home;
process.env.USERPROFILE = home;
process.on("exit", () => {
  try {
    rmSync(home, { recursive: true, force: true });
  } catch {
    // Best effort cleanup.
  }
});
