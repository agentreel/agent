import pc from "picocolors";
import { readConfig, writeConfig, type HostnameMode } from "../config.js";
import { resolveHostnameMode } from "../attribution.js";

const MODES: HostnameMode[] = ["plain", "hash", "omit"];

export function configCommand(key?: string, value?: string): void {
  const cfg = readConfig();
  if (!key) {
    console.log(`hostname     ${resolveHostnameMode(cfg)}` + pc.dim("   (plain | hash | omit; env AGENTREEL_HOSTNAME overrides)"));
    console.log(`attribution  ${cfg.attribution === false ? "off" : "on"}` + pc.dim("    (who/where: OS user, host, git user, repo, branch, commit)"));
    return;
  }
  if (key === "hostname") {
    if (!value || !MODES.includes(value as HostnameMode)) {
      console.error(`Usage: agentreel config hostname <${MODES.join("|")}>`);
      process.exitCode = 1;
      return;
    }
    writeConfig({ ...cfg, hostnameMode: value as HostnameMode });
    console.log(pc.green("✓") + ` hostname will be recorded as: ${value}` + pc.dim(" (new sessions)"));
    return;
  }
  if (key === "attribution") {
    if (value !== "on" && value !== "off") {
      console.error("Usage: agentreel config attribution <on|off>");
      process.exitCode = 1;
      return;
    }
    writeConfig({ ...cfg, attribution: value === "on" });
    console.log(pc.green("✓") + ` attribution ${value}` + pc.dim(" (new sessions)"));
    return;
  }
  console.error(`Unknown setting "${key}". Known: hostname, attribution`);
  process.exitCode = 1;
}
