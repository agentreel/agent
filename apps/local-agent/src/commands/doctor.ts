import pc from "picocolors";
import {
  getInstalledPreExecTimeoutS,
  getRecordedPreExecTimeoutS,
  isCapturePaused,
  readConfig,
  type AgentConfig,
} from "../config.js";
import {
  inspectCursorPreExecHooks,
  inspectSystemCursorHooks,
  systemCursorHooksPath,
  type SystemCursorHooksState,
} from "../cursor/hooks-install.js";
import { inspectClaudePreExecHook } from "../hooks/install.js";
import {
  claudeSettingsPath,
  cursorHooksPath,
  guardConfigPath,
  policyPath,
} from "../paths.js";
import {
  getPolicyCacheAgeMs,
  isPolicyCacheStale,
  loadEffectivePolicy,
  readPolicyRejection,
  type PolicyRejectionRecord,
  type PolicySource,
} from "../policy/cache.js";
import {
  computeMaxPolicyApprovalExpiresS,
  computePreExecTimeoutS,
  HOOK_DEADLINE_MARGIN_S,
  isNoOrgPolicy,
} from "../policy/types.js";

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
  /** System Cursor hooks file (default /etc/cursor/hooks.json); injectable for tests. */
  systemCursorHooksPath?: string;
  config?: AgentConfig;
  now?: number;
}

export interface DoctorReport {
  policyLoaded: boolean;
  noOrgPolicy: boolean;
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
  /** Set when the org enforces but its cached policy is missing, invalid or edited. */
  lockdownReason: string | null;
  lastRejection: PolicyRejectionRecord | null;
  expectedPreExecTimeoutS: number;
  maxPolicyApprovalExpiresS: number | null;
  needsReinit: boolean;
  claude: {
    fileExists: boolean;
    preToolUseInstalled: boolean;
    preToolUseTimeoutS: number | null;
    preToolUseFailClosed: boolean;
    timeoutOk: boolean;
    recordedTimeoutS: number | null;
    effectiveInstalledTimeoutS: number;
    needsReinitForApproval: boolean;
  };
  cursor: {
    fileExists: boolean;
    hooks: Array<{
      event: string;
      installed: boolean;
      timeoutS: number | null;
      failClosed: boolean;
      timeoutOk: boolean;
    }>;
    allInstalled: boolean;
    allTimeoutsOk: boolean;
    allFailClosed: boolean;
    recordedTimeoutS: number | null;
    effectiveInstalledTimeoutS: number;
    needsReinitForApproval: boolean;
    /**
     * True when the system Cursor hooks file has AgentReel entries, or exists
     * but cannot be read (fail-safe: treated as managed).
     */
    managed: boolean;
    managedPath: string;
    managedState: SystemCursorHooksState;
  };
}

export function inspectDoctorState(opts: DoctorInspectOptions = {}): DoctorReport {
  const now = opts.now ?? Date.now();
  const cfg = opts.config ?? readConfig();
  const loaded = loadEffectivePolicy({
    cachePath: opts.cachePath ?? policyPath(),
    guardConfigPath: opts.guardConfigPath ?? guardConfigPath(),
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

  const capturePaused = isCapturePaused(cfg);
  const lastRejection = readPolicyRejection(opts.cachePath ?? policyPath());
  const noOrgPolicy =
    loaded.source === "server_cache" && isNoOrgPolicy(policy);

  const enforcementActive =
    loaded.source === "enforced_lockdown" ||
    (loaded.source === "server_cache" &&
    policy !== null &&
    !noOrgPolicy &&
    policy.mode === "enforce" &&
    !(policy.offline === "fail_open" && stale));

  const expectedPreExecTimeoutS = computePreExecTimeoutS(policy);
  const maxPolicyApprovalExpiresS = computeMaxPolicyApprovalExpiresS(policy);

  const claudeRecordedTimeoutS = getRecordedPreExecTimeoutS(cfg, "claude");
  const claudeEffectiveTimeoutS = getInstalledPreExecTimeoutS(cfg, "claude");
  const claudeNeedsReinit =
    maxPolicyApprovalExpiresS !== null &&
    maxPolicyApprovalExpiresS > claudeEffectiveTimeoutS - HOOK_DEADLINE_MARGIN_S;

  const cursorRecordedTimeoutS = getRecordedPreExecTimeoutS(cfg, "cursor");
  const cursorEffectiveTimeoutS = getInstalledPreExecTimeoutS(cfg, "cursor");
  const claudeRaw = inspectClaudePreExecHook(
    opts.claudeSettingsPath ?? claudeSettingsPath(),
  );
  const claudeTimeoutOk =
    claudeRaw.preToolUseInstalled &&
    claudeRaw.preToolUseTimeoutS !== null &&
    claudeRaw.preToolUseTimeoutS >= expectedPreExecTimeoutS;

  const managedPath = opts.systemCursorHooksPath ?? systemCursorHooksPath();
  const managedState = inspectSystemCursorHooks(managedPath);
  const cursorManaged = managedState === "owned" || managedState === "unreadable";
  // When the managed pack owns the hooks, report the system file, not the
  // (possibly empty or stale) per-user file, so doctor does not tell the
  // user to run `agentreel init`.
  const cursorRaw = inspectCursorPreExecHooks(
    cursorManaged && managedState === "owned"
      ? managedPath
      : (opts.cursorHooksPath ?? cursorHooksPath()),
  );
  const cursorHooks = cursorRaw.hooks.map((h) => ({
    ...h,
    timeoutOk:
      h.installed &&
      h.timeoutS !== null &&
      h.timeoutS >= expectedPreExecTimeoutS,
  }));
  const cursorNeedsReinit =
    !cursorManaged &&
    maxPolicyApprovalExpiresS !== null &&
    maxPolicyApprovalExpiresS > cursorEffectiveTimeoutS - HOOK_DEADLINE_MARGIN_S;

  return {
    policyLoaded: policy !== null,
    noOrgPolicy,
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
    lockdownReason: loaded.lockdownReason ?? null,
    lastRejection,
    expectedPreExecTimeoutS,
    maxPolicyApprovalExpiresS,
    needsReinit: claudeNeedsReinit || cursorNeedsReinit,
    claude: {
      ...claudeRaw,
      timeoutOk: claudeTimeoutOk,
      recordedTimeoutS: claudeRecordedTimeoutS,
      effectiveInstalledTimeoutS: claudeEffectiveTimeoutS,
      needsReinitForApproval: claudeNeedsReinit,
    },
    cursor: {
      fileExists: cursorRaw.fileExists,
      hooks: cursorHooks,
      allInstalled: cursorHooks.every((h) => h.installed),
      allTimeoutsOk: cursorHooks.every((h) => h.timeoutOk),
      allFailClosed: cursorHooks.every((h) => h.failClosed),
      recordedTimeoutS: cursorRecordedTimeoutS,
      effectiveInstalledTimeoutS: cursorEffectiveTimeoutS,
      needsReinitForApproval: cursorNeedsReinit,
      managed: cursorManaged,
      managedPath,
      managedState,
    },
  };
}

function formatTimeoutLabel(timeoutS: number | null): string {
  return timeoutS === null ? "unset" : `${timeoutS}s`;
}

function formatRecordedTimeoutLabel(
  recordedS: number | null,
  effectiveS: number,
): string {
  return recordedS === null ? `unset (assumed ${effectiveS}s)` : `${recordedS}s`;
}

export function formatDoctorReport(report: DoctorReport): string {
  const enforcementLabel = report.enforcementActive
    ? pc.green("active (enforce)")
    : report.noOrgPolicy
      ? pc.dim("inactive (no org policy)")
      : report.policySource === "server_cache" &&
          report.mode === "enforce" &&
          report.offline === "fail_open" &&
          report.stale
        ? pc.yellow("paused (policy stale, fail_open)")
        : report.policyLoaded
          ? pc.yellow(`observe only (${report.mode})`)
          : pc.dim("inactive (no policy loaded)");

  const captureLabel = report.capturePaused
    ? pc.yellow("paused (recording stopped; org policy still enforced)")
    : pc.green("active");

  const claudeLine = !report.claude.preToolUseInstalled
    ? pc.yellow("PreToolUse not installed (run `agentreel init`)")
    : !report.claude.preToolUseFailClosed
      ? pc.yellow('PreToolUse fails open: onFailure "block" not set (run `agentreel init`)')
    : report.claude.timeoutOk
      ? pc.green(`PreToolUse installed (timeout ${report.claude.preToolUseTimeoutS}s)`)
      : pc.yellow(
          `PreToolUse timeout ${formatTimeoutLabel(report.claude.preToolUseTimeoutS)} < expected ${report.expectedPreExecTimeoutS}s (run \`agentreel init\`)`,
        );

  const cursorSummary = report.cursor.managed
    ? report.cursor.managedState === "unreadable"
      ? pc.yellow(
          `managed pack at ${report.cursor.managedPath} is unreadable; treated as managed (not installing per-user hooks)`,
        )
      : pc.green(`owned by the managed pack (${report.cursor.managedPath})`)
    : report.cursor.allInstalled && !report.cursor.allFailClosed
      ? pc.yellow("pre-exec hooks fail open: failClosed not set (run `agentreel init`)")
      : report.cursor.allInstalled && report.cursor.allTimeoutsOk
      ? pc.green(
          `all ${report.cursor.hooks.length} pre-exec hooks installed (timeout >= ${report.expectedPreExecTimeoutS}s)`,
        )
      : pc.yellow("missing hooks or short timeout (run `agentreel init`)");

  const recordedSummary = `claude ${formatRecordedTimeoutLabel(report.claude.recordedTimeoutS, report.claude.effectiveInstalledTimeoutS)}, cursor ${formatRecordedTimeoutLabel(report.cursor.recordedTimeoutS, report.cursor.effectiveInstalledTimeoutS)}`;

  const lines = [
    pc.bold(pc.cyan("AgentReel doctor")),
    "",
    `  capture:        ${captureLabel}`,
    `  enforcement:    ${enforcementLabel}`,
    `  policy loaded:  ${report.noOrgPolicy ? pc.dim("no org policy (cached)") : report.policyLoaded ? `${pc.green("yes")} (${report.policySource})` : `${pc.dim("no")} (${report.policySource})`}`,
    `  mode:           ${report.policyLoaded ? report.mode : pc.dim("none")}`,
    `  offline:        ${report.policyLoaded ? report.offline : pc.dim("none")}`,
    `  etag:           ${report.etag ?? pc.dim("none")}`,
    `  etag age:       ${report.etagAgeMs !== null ? report.etagAgeLabel : pc.dim("none")}${report.stale ? pc.yellow(" (stale > 24h)") : ""}`,
    `  hook timeout:   expected >= ${report.expectedPreExecTimeoutS}s on pre-exec hooks`,
    `  recorded:       ${recordedSummary}`,
    `  claude hooks:   ${claudeLine}`,
    `  cursor hooks:   ${cursorSummary}`,
  ];

  if (!(report.cursor.managed && report.cursor.managedState === "unreadable")) {
    for (const h of report.cursor.hooks) {
      const status = !h.installed
        ? pc.yellow("missing")
        : !h.failClosed
          ? pc.yellow("fails open (failClosed not set)")
        : h.timeoutOk
          ? pc.green(`ok (${h.timeoutS}s)`)
          : pc.yellow(`timeout ${formatTimeoutLabel(h.timeoutS)} < ${report.expectedPreExecTimeoutS}s`);
      lines.push(`    - ${h.event.padEnd(21)} ${status}`);
    }
  }

  if (report.lockdownReason) {
    lines.push(
      `  ${pc.red("!")} lockdown: this org enforces its policy, but the cached policy is ${report.lockdownReason.replace("policy_", "")}. Every built-in rule blocks until \`npx @agentreel/agent auth\` fetches it again.`,
    );
  }
  if (report.lastRejection) {
    const hasCachedServerPolicy =
      report.policySource === "server_cache" && !report.noOrgPolicy;
    const suffix = hasCachedServerPolicy
      ? "last known policy still in use"
      : "the rejected policy was not installed and org enforcement is off until a valid policy is cached";
    const rejectionMsg =
      report.lastRejection.reason === "no_org_ignored"
        ? report.lastRejection.error
        : report.lastRejection.reason === "org_mismatch_ignored"
          ? `${report.lastRejection.error}; run \`npx @agentreel/agent auth\` to switch orgs`
          : report.lastRejection.reason === "unsupported_regex" &&
              report.lastRejection.rule_id
            ? `policy rejected by agent: rule ${report.lastRejection.rule_id} has an unsupported regex; ${suffix}`
            : `policy rejected by agent: ${report.lastRejection.error}; ${suffix}`;
    lines.push("", pc.yellow(`  warning:        ${rejectionMsg}`));
  }

  if (report.needsReinit && report.maxPolicyApprovalExpiresS !== null) {
    const hosts: string[] = [];
    if (report.claude.needsReinitForApproval) {
      hosts.push(`claude (${report.claude.effectiveInstalledTimeoutS}s)`);
    }
    if (report.cursor.needsReinitForApproval) {
      hosts.push(`cursor (${report.cursor.effectiveInstalledTimeoutS}s)`);
    }
    lines.push(
      "",
      pc.yellow(
        `  warning:        policy max approval expires_s (${report.maxPolicyApprovalExpiresS}s) needs a longer hook timeout than installed for ${hosts.join(", ")}. Run \`npx @agentreel/agent init\` to update hook timeouts.`,
      ),
    );
  }

  return lines.join("\n");
}

export function doctorCommand(opts: DoctorInspectOptions = {}): void {
  const report = inspectDoctorState(opts);
  console.log(formatDoctorReport(report));
}
