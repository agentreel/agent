import pc from "picocolors";
import { readConfig, writeConfig } from "../config.js";
import { describeHeartbeatReason, heartbeatDecision, heartbeatEnabled } from "../heartbeat/heartbeat.js";

/** What a beat carries. Printed by `agentreel heartbeat status`. Keep in step with docs/heartbeat.md. */
export const HEARTBEAT_SENDS_SUMMARY =
  "counts, states and gaps only: capture on or paused, hooks installed, policy mode, watcher counters, queue depth, and for each hook gap the tool name, tool_use id and session id. Never command text, paths, prompts or hostname.";

export function heartbeatCommand(action?: string): void {
  const cfg = readConfig();
  if (action === "on" || action === "off") {
    writeConfig({ ...cfg, heartbeat: action === "on" });
    console.log(pc.green("✓") + ` heartbeat ${action}`);
    if (action === "on" && !heartbeatEnabled()) {
      console.log(pc.yellow("  note: AGENTREEL_HEARTBEAT=0 is set in this shell and still wins."));
    }
    if (action === "on" && !cfg.apiKey) {
      console.log(pc.dim("  no API key yet: run `agentreel link` first."));
    }
    if (action === "off" && cfg.apiKey) {
      console.log(pc.dim("  If this device belongs to an org, the org dashboard will show it as uncovered."));
    }
    return;
  }
  if (action !== undefined && action !== "status") {
    console.error("Usage: agentreel heartbeat [on|off|status]");
    process.exitCode = 1;
    return;
  }
  const d = heartbeatDecision(cfg);
  console.log(`heartbeat: ${d.enabled ? pc.green(describeHeartbeatReason(d)) : pc.yellow(describeHeartbeatReason(d))}`);
  console.log(pc.dim(`  sends: ${HEARTBEAT_SENDS_SUMMARY}`));
  console.log(pc.dim("  hook-gap detection reads Claude Code transcripts only (Claude Code only)."));
}
