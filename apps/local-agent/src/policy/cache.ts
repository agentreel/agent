import { randomBytes } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname } from "node:path";
import { RULES } from "../guard/rules.js";
import type { GuardConfig } from "../guard/types.js";
import { guardConfigPath as defaultGuardConfigPath, policyPath } from "../paths.js";
import {
  isValidSeverity,
  validateCachedPolicyFile,
  type BuiltinRuleOverride,
  type CachedPolicyFile,
  type Policy,
} from "./types.js";

export const POLICY_REFRESH_INTERVAL_MS = 5 * 60_000;
export const POLICY_STALE_MS = 24 * 60 * 60_000;

export type PolicySource = "server_cache" | "local_fallback" | "none";

export interface LoadedPolicy {
  source: PolicySource;
  policy: Policy | null;
  etag: string | null;
  fetchedAt: number | null;
}

export interface PolicyAgeInfo {
  ageMs: number;
  clockSkewed: boolean;
}

export type PolicyRejectionReason =
  | "unsupported_regex"
  | "invalid_policy"
  | "no_org_ignored"
  | "org_mismatch_ignored";

export interface PolicyRejectionRecord {
  ts: number;
  error: string;
  rule_id?: string;
  condition_index?: number;
  cached_org_id?: string;
  incoming_org_id?: string | null;
  reason: PolicyRejectionReason;
}

const POLICY_REJECTION_REASONS = new Set<string>([
  "unsupported_regex",
  "invalid_policy",
  "no_org_ignored",
  "org_mismatch_ignored",
]);

export function policyRejectionPath(cachePath: string = policyPath()): string {
  return `${cachePath}.rejected.json`;
}

export function readPolicyRejection(
  cachePath: string = policyPath(),
): PolicyRejectionRecord | null {
  try {
    const p = policyRejectionPath(cachePath);
    if (!existsSync(p)) return null;
    const parsed = JSON.parse(readFileSync(p, "utf8")) as Record<string, unknown>;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return null;
    }
    if (
      typeof parsed.ts !== "number" ||
      typeof parsed.error !== "string" ||
      typeof parsed.reason !== "string" ||
      !POLICY_REJECTION_REASONS.has(parsed.reason)
    ) {
      return null;
    }
    return {
      ts: parsed.ts,
      error: parsed.error,
      reason: parsed.reason as PolicyRejectionReason,
      ...(typeof parsed.rule_id === "string" ? { rule_id: parsed.rule_id } : {}),
      ...(typeof parsed.condition_index === "number"
        ? { condition_index: parsed.condition_index }
        : {}),
      ...(typeof parsed.cached_org_id === "string"
        ? { cached_org_id: parsed.cached_org_id }
        : {}),
      ...(typeof parsed.incoming_org_id === "string" ||
      parsed.incoming_org_id === null
        ? { incoming_org_id: parsed.incoming_org_id }
        : {}),
    };
  } catch {
    return null;
  }
}

export function writePolicyRejectionAtomic(
  record: PolicyRejectionRecord,
  cachePath: string = policyPath(),
): void {
  const target = policyRejectionPath(cachePath);
  const dir = dirname(target);
  mkdirSync(dir, { recursive: true });
  const suffix = randomBytes(6).toString("hex");
  const tmpPath = `${target}.tmp.${process.pid}.${suffix}`;
  const serialized = JSON.stringify(record, null, 2) + "\n";
  try {
    writeFileSync(tmpPath, serialized, { encoding: "utf8", mode: 0o600 });
    try {
      chmodSync(tmpPath, 0o600);
    } catch {
      // Best effort on non-Unix filesystems.
    }
    renameSync(tmpPath, target);
  } catch (err) {
    try {
      unlinkSync(tmpPath);
    } catch {
      // Ignore cleanup failures.
    }
    throw err;
  }
}

export function clearPolicyRejection(cachePath: string = policyPath()): void {
  try {
    const target = policyRejectionPath(cachePath);
    if (existsSync(target)) {
      unlinkSync(target);
    }
  } catch {
    // Never throw on rejection sidecar cleanup.
  }
}

/**
 * Clears payload-rejection sidecars (invalid_policy, unsupported_regex) after
 * a successful 304 or same-org 200. Leaves org_mismatch_ignored and
 * no_org_ignored in place until explicit auth or logout.
 */
export function clearTransientPolicyRejection(
  cachePath: string = policyPath(),
): void {
  const existing = readPolicyRejection(cachePath);
  if (
    existing &&
    (existing.reason === "org_mismatch_ignored" ||
      existing.reason === "no_org_ignored")
  ) {
    return;
  }
  clearPolicyRejection(cachePath);
}

export function clearCachedPolicy(cachePath: string = policyPath()): void {
  try {
    if (existsSync(cachePath)) {
      unlinkSync(cachePath);
    }
  } catch {
    // Never throw on cache cleanup.
  }
  clearPolicyRejection(cachePath);
}

/**
 * Reads and validates ~/.agentreel/policy.json.
 * Corrupt, invalid, or unreadable cache files are treated as no cache and never throw.
 */
export function readCachedPolicy(
  cachePath: string = policyPath(),
): CachedPolicyFile | null {
  try {
    if (!existsSync(cachePath)) return null;
    const raw = readFileSync(cachePath, "utf8");
    const parsed: unknown = JSON.parse(raw);
    const validated = validateCachedPolicyFile(parsed);
    return validated.ok ? validated.value : null;
  } catch {
    return null;
  }
}

/**
 * Atomically writes the cached policy file with 0600 permissions (temp file then rename).
 */
export function writeCachedPolicyAtomic(
  entry: CachedPolicyFile,
  cachePath: string = policyPath(),
): void {
  const dir = dirname(cachePath);
  mkdirSync(dir, { recursive: true });
  const suffix = randomBytes(6).toString("hex");
  const tmpPath = `${cachePath}.tmp.${process.pid}.${suffix}`;
  const serialized = JSON.stringify(entry, null, 2) + "\n";

  try {
    writeFileSync(tmpPath, serialized, { encoding: "utf8", mode: 0o600 });
    try {
      chmodSync(tmpPath, 0o600);
    } catch {
      // Non-Unix filesystem without mode bits: best effort.
    }
    renameSync(tmpPath, cachePath);
  } catch (err) {
    try {
      unlinkSync(tmpPath);
    } catch {
      // Ignore cleanup failures.
    }
    throw err;
  }
}

function toStringArray(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  return v.filter((item): item is string => typeof item === "string");
}

/**
 * Converts a local guard-config.json object into an observe-mode Policy.
 */
/**
 * Converts local guard-config.json into a policy.
 *
 * policyMode "warn" (the default) keeps observe mode: listed rules only flag.
 * policyMode "block" makes the local config actually block: the policy runs in
 * enforce mode and every built-in rule is set to block unless the config
 * disables it (built-ins missing from `rules` stay enabled).
 */
export function guardConfigToPolicy(guardConfig: Partial<GuardConfig>): Policy {
  const blocking = guardConfig.policyMode === "block";
  const builtin: Record<string, BuiltinRuleOverride> = {};
  if (blocking) {
    for (const rule of RULES) {
      builtin[rule.id] = { enabled: true, action: "block" };
    }
  }
  if (
    guardConfig.rules &&
    typeof guardConfig.rules === "object" &&
    !Array.isArray(guardConfig.rules)
  ) {
    for (const [ruleId, ruleCfg] of Object.entries(guardConfig.rules)) {
      if (!ruleId.trim() || !ruleCfg || typeof ruleCfg !== "object") continue;
      if (typeof ruleCfg.enabled !== "boolean") continue;
      builtin[ruleId] = {
        enabled: ruleCfg.enabled,
        action: blocking ? "block" : "flag",
        ...(isValidSeverity(ruleCfg.severity)
          ? { severity: ruleCfg.severity }
          : {}),
      };
    }
  }

  return {
    version: 1,
    etag: blocking ? "local-guard-config-block" : "local-guard-config",
    workspace_id: "local",
    updated_at: 0,
    mode: blocking ? "enforce" : "observe",
    offline: "last_known",
    ...(blocking ? { org_name: "your local Guard config" } : {}),
    builtin,
    custom: [],
    allow: {
      commands: toStringArray(guardConfig.allowlists?.commands),
      paths: toStringArray(guardConfig.allowlists?.paths),
      repos: [],
    },
  };
}

function readLocalGuardFallback(guardConfigPath: string): Policy | null {
  try {
    if (!existsSync(guardConfigPath)) return null;
    const raw = readFileSync(guardConfigPath, "utf8");
    const parsed: unknown = JSON.parse(raw);
    if (
      typeof parsed !== "object" ||
      parsed === null ||
      Array.isArray(parsed)
    ) {
      return null;
    }
    const cfg = parsed as Partial<GuardConfig>;
    if (cfg.enabled === false || cfg.policyMode === "off") {
      return null;
    }
    return guardConfigToPolicy(cfg);
  } catch {
    return null;
  }
}

export interface LoadPolicyOptions {
  cachePath?: string;
  guardConfigPath?: string;
}

/**
 * Loads the active policy from the server cache, falling back to local
 * guard-config.json in observe mode when no valid server policy is cached.
 * Never throws.
 */
export function loadEffectivePolicy(
  opts: LoadPolicyOptions = {},
): LoadedPolicy {
  const cachePath = opts.cachePath ?? policyPath();
  const guardConfigPath = opts.guardConfigPath ?? defaultGuardConfigPath();

  const cached = readCachedPolicy(cachePath);
  if (cached) {
    return {
      source: "server_cache",
      policy: cached.policy,
      etag: cached.etag,
      fetchedAt: cached.fetched_at,
    };
  }

  const fallback = readLocalGuardFallback(guardConfigPath);
  if (fallback) {
    return {
      source: "local_fallback",
      policy: fallback,
      etag: null,
      fetchedAt: null,
    };
  }

  return {
    source: "none",
    policy: null,
    etag: null,
    fetchedAt: null,
  };
}

/**
 * Returns non-negative cache age and whether fetched_at lies in the future.
 */
export function getPolicyCacheAgeMs(
  fetchedAt: number,
  now: number = Date.now(),
): PolicyAgeInfo {
  if (!Number.isFinite(fetchedAt)) {
    return { ageMs: 0, clockSkewed: true };
  }
  if (fetchedAt > now) {
    return { ageMs: 0, clockSkewed: true };
  }
  return { ageMs: now - fetchedAt, clockSkewed: false };
}

/**
 * Returns true if the cached policy is missing, stale, or skewed into the future.
 */
export function shouldRefreshPolicy(
  cached: CachedPolicyFile | null,
  now: number = Date.now(),
  intervalMs: number = POLICY_REFRESH_INTERVAL_MS,
): boolean {
  if (!cached) return true;
  if (!Number.isFinite(cached.fetched_at)) return true;
  if (cached.fetched_at > now) return true;
  return now - cached.fetched_at >= intervalMs;
}

export function isPolicyCacheStale(
  fetchedAt: number | null,
  now: number = Date.now(),
  staleMs: number = POLICY_STALE_MS,
): boolean {
  if (fetchedAt === null || !Number.isFinite(fetchedAt)) return true;
  const { ageMs } = getPolicyCacheAgeMs(fetchedAt, now);
  return ageMs > staleMs;
}
