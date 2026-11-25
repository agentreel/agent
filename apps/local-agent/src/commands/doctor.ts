import pc from "picocolors";
import { isCapturePaused } from "../config.js";
import { inspectCursorPreExecHooks } from "../cursor/hooks-install.js";
import { inspectClaudePreExecHook } from "../hooks/install.js";
import {
  CLAUDE_SETTINGS_PATH,
  CURSOR_HOOKS_PATH,
  GUARD_CONFIG_PATH,
  POLICY_PATH,
} from "../paths.js";
import {
  getPolicyCacheAgeMs,
  isPolicyCacheStale,
  loadEffectivePolicy,
  type PolicySource,
} from "../policy/cache.js";
import { computePreExecTimeoutS } from "../policy/types.js";

function formatDuration(ms: number): string {
  const totalSec = Math.floor(ms / 1000);
  if (totalSec < 60) return `${totalSec}s`;
  const totalMin = Math.floor(totalSec / 60);
  if (totalMin < 60) return `${totalMin}m ${totalSec % 60}s`;
  const totalHours = Math.floor(totalMin / 60);
  if (totalHours < 24) return `${totalHours}h ${totalMin % 60}m`;
  const days = Math.floor(totalHours / 24);
  return `${days}d ${totalHours % 24}h`;
}

export interface DoctorInspectOptions {
  cachePath?: string;
  guardConfigPath?: string;
  claudeSettingsPath?: string;
  cursorHooksPath?: string;
  now?: number;
}

export interface DoctorReport {
  policyLoaded: boolean;
  policySource: PolicySource;
  mode: string;
  offline: string;
  etag: string | null;
  etagAgeMs: number | null;
  etagAgeLabel: string;
  clockSkewed: boolean;
  stale: boolean;
  capturePaused: boolean;
  enforcementActive: boolean;
  expectedPreExecTimeoutS: number;
  claude: {
    fileExists: boolean;
    preToolUseInstalled: boolean;
    preToolUseTimeoutS: number | null;
    timeoutOk: boolean;
  };
  cursor: {
    fileExists: boolean;
    hooks: Array<{
      event: string;
      installed: boolean;
      timeoutS: number | null;
      timeoutOk: boolean;
    }>;
    allInstalled: boolean;
    allTimeoutsOk: boolean;
  };
}

export function inspectDoctorState(opts: DoctorInspectOptions = {}): DoctorReport {
  const now = opts.now ?? Date.now();
  const loaded = loadEffectivePolicy({
    cachePath: opts.cachePath ?? POLICY_PATH,
    guardConfigPath: opts.guardConfigPath ?? GUARD_CONFIG_PATH,
  });

  const policy = loaded.policy;
  let etagAgeMs: number | null = null;
  let etagAgeLabel = "none";
  let clockSkewed = false;
  if (loaded.fetchedAt !== null) {
    const ageInfo = getPolicyCacheAgeMs(loaded.fetchedAt, now);
    etagAgeMs = ageInfo.ageMs;
    clockSkewed = ageInfo.clockSkewed;
    etagAgeLabel = ageInfo.clockSkewed
      ? `${formatDuration(ageInfo.ageMs)} ago (clock skew detected)`
      : `${formatDuration(ageInfo.ageMs)} ago`;
  }

  const stale =
    loaded.source === "server_cache"
      ? isPolicyCacheStale(loaded.fetchedAt, now)
      : false;

  const capturePaused = isCapturePaused();

  const enforcementActive =
    !capturePaused &&
    loaded.source === "server_cache" &&
    policy !== null &&
    policy.mode === "enforce" &&
    !(policy.offline === "fail_open" && stale);

  const expectedPreExecTimeoutS = computePreExecTimeoutS(policy);

  const claudeRaw = inspectClaudePreExecHook(
    opts.claudeSettingsPath ?? CLAUDE_SETTINGS_PATH,
  );
  const claudeTimeoutOk =
    claudeRaw.preToolUseInstalled &&
    claudeRaw.preToolUseTimeoutS !== null &&
    claudeRaw.preToolUseTimeoutS >= expectedPreExecTimeoutS;

  const cursorRaw = inspectCursorPreExecHooks(
    opts.cursorHooksPath ?? CURSOR_HOOKS_PATH,
  );
  const cursorHooks = cursorRaw.hooks.map((h) => ({
    ...h,
    timeoutOk:
      h.installed &&
      h.timeoutS !== null &&
      h.timeoutS >= expectedPreExecTimeoutS,
  }));

  return {
    policyLoaded: policy !== null,
    policySource: loaded.source,
    mode: policy ? policy.mode : "none",
    offline: policy ? policy.offline : "none",
    etag: loaded.etag,
    etagAgeMs,
    etagAgeLabel,
    clockSkewed,
    stale,
    capturePaused,
    enforcementActive,
    expectedPreExecTimeoutS,
    claude: {
      ...claudeRaw,
      timeoutOk: claudeTimeoutOk,
    },
    cursor: {
      fileExists: cursorRaw.fileExists,
      hooks: cursorHooks,
      allInstalled: cursorHooks.every((h) => h.installed),
      allTimeoutsOk: cursorHooks.every((h) => h.timeoutOk),
    },
  };
}

function formatTimeoutLabel(timeoutS: number | null): string {
  return timeoutS === null ? "unset" : `${timeoutS}s`;
}

export function formatDoctorReport(report: DoctorReport): string {
  const enforcementLabel = report.capturePaused
    ? pc.yellow("paused (capture disabled)")
    : report.enforcementActive
      ? pc.green("active (enforce)")
      : report.policySource === "server_cache" &&
          report.mode === "enforce" &&
          report.offline === "fail_open" &&
          report.stale
        ? pc.yellow("paused (policy stale, fail_open)")
        : report.policyLoaded
          ? pc.yellow(`observe only (${report.mode})`)
          : pc.dim("inactive (no policy loaded)");

  const claudeLine = !report.claude.preToolUseInstalled
    ? pc.yellow("PreToolUse not installed (run `agentreel init`)")
    : report.claude.timeoutOk
      ? pc.green(`PreToolUse installed (timeout ${report.claude.preToolUseTimeoutS}s)`)
      : pc.yellow(
          `PreToolUse timeout ${formatTimeoutLabel(report.claude.preToolUseTimeoutS)} < expected ${report.expectedPreExecTimeoutS}s (run \`agentreel init\`)`,
        );

  const cursorSummary =
    report.cursor.allInstalled && report.cursor.allTimeoutsOk
      ? pc.green(
          `all ${report.cursor.hooks.length} pre-exec hooks installed (timeout >= ${report.expectedPreExecTimeoutS}s)`,
        )
      : pc.yellow("missing hooks or short timeout (run `agentreel init`)");

  const lines = [
    pc.bold(pc.cyan("AgentReel doctor")),
    "",
    `  enforcement:    ${enforcementLabel}`,
    `  policy loaded:  ${report.policyLoaded ? pc.green("yes") : pc.dim("no")} (${report.policySource})`,
    `  mode:           ${report.policyLoaded ? report.mode : pc.dim("none")}`,
    `  offline:        ${report.policyLoaded ? report.offline : pc.dim("none")}`,
    `  etag:           ${report.etag ?? pc.dim("none")}`,
    `  etag age:       ${report.etagAgeMs !== null ? report.etagAgeLabel : pc.dim("none")}${report.stale ? pc.yellow(" (stale > 24h)") : ""}`,
    `  hook timeout:   expected >= ${report.expectedPreExecTimeoutS}s on pre-exec hooks`,
    `  claude hooks:   ${claudeLine}`,
    `  cursor hooks:   ${cursorSummary}`,
  ];

  for (const h of report.cursor.hooks) {
    const status = !h.installed
      ? pc.yellow("missing")
      : h.timeoutOk
        ? pc.green(`ok (${h.timeoutS}s)`)
        : pc.yellow(`timeout ${formatTimeoutLabel(h.timeoutS)} < ${report.expectedPreExecTimeoutS}s`);
    lines.push(`    - ${h.event.padEnd(21)} ${status}`);
  }

  return lines.join("\n");
}

export function doctorCommand(opts: DoctorInspectOptions = {}): void {
  const report = inspectDoctorState(opts);
  console.log(formatDoctorReport(report));
}
