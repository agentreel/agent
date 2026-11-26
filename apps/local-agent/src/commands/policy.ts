import pc from "picocolors";
import {
  getPolicyCacheAgeMs,
  loadEffectivePolicy,
  type LoadedPolicy,
  type LoadPolicyOptions,
  type PolicySource,
} from "../policy/cache.js";
import { isNoOrgPolicy } from "../policy/types.js";

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

function formatSourceLabel(source: PolicySource): string {
  switch (source) {
    case "server_cache":
      return "server cache";
    case "local_fallback":
      return "local fallback";
    case "none":
      return "none";
  }
}

export interface PolicySummaryLines {
  source: string;
  etag: string;
  age: string;
  mode: string;
  offline: string;
  builtinOverrides: number;
  customRules: number;
  allowEntries: number;
  allowBreakdown: {
    commands: number;
    paths: number;
    repos: number;
  };
}

export function buildPolicySummary(
  loaded: LoadedPolicy,
  now: number = Date.now(),
): PolicySummaryLines {
  const policy = loaded.policy;

  let age = "none";
  if (loaded.fetchedAt !== null) {
    const info = getPolicyCacheAgeMs(loaded.fetchedAt, now);
    age = info.clockSkewed
      ? `${formatDuration(info.ageMs)} ago (clock skew detected)`
      : `${formatDuration(info.ageMs)} ago`;
  }

  const builtinOverrides = policy ? Object.keys(policy.builtin).length : 0;
  const customRules = policy ? policy.custom.length : 0;
  const commands = policy ? policy.allow.commands.length : 0;
  const paths = policy ? policy.allow.paths.length : 0;
  const repos = policy ? policy.allow.repos.length : 0;

  const noOrg = isNoOrgPolicy(policy);
  return {
    source: noOrg ? "no org policy (server cache)" : formatSourceLabel(loaded.source),
    etag: loaded.etag ?? "none",
    age,
    mode: policy ? policy.mode : "none",
    offline: policy ? policy.offline : "none",
    builtinOverrides,
    customRules,
    allowEntries: commands + paths + repos,
    allowBreakdown: { commands, paths, repos },
  };
}

export function formatPolicySummary(
  loaded: LoadedPolicy,
  now: number = Date.now(),
): string {
  const s = buildPolicySummary(loaded, now);
  const sourceColored =
    loaded.source === "server_cache"
      ? pc.green(s.source)
      : loaded.source === "local_fallback"
        ? pc.yellow(s.source)
        : pc.dim(s.source);

  const lines = [
    pc.bold(pc.cyan("AgentReel policy")),
    "",
    `  source:            ${sourceColored}`,
    `  etag:              ${loaded.etag ? s.etag : pc.dim(s.etag)}`,
    `  age:               ${loaded.fetchedAt !== null ? s.age : pc.dim(s.age)}`,
    `  mode:              ${loaded.policy ? s.mode : pc.dim(s.mode)}`,
    `  offline:           ${loaded.policy ? s.offline : pc.dim(s.offline)}`,
    `  builtin overrides: ${s.builtinOverrides}`,
    `  custom rules:      ${s.customRules}`,
    `  allow entries:     ${s.allowEntries} (${s.allowBreakdown.commands} commands, ${s.allowBreakdown.paths} paths, ${s.allowBreakdown.repos} repos)`,
  ];

  return lines.join("\n");
}

export function policyCommand(opts: LoadPolicyOptions = {}): void {
  const loaded = loadEffectivePolicy(opts);
  console.log(formatPolicySummary(loaded));
}
