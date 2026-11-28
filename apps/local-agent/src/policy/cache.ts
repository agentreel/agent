import { createHash, randomBytes } from "node:crypto";
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
  isNoOrgPolicy,
  isValidSeverity,
  validateCachedPolicyFile,
  type BuiltinRuleOverride,
  type CachedPolicyFile,
  type Policy,
} from "./types.js";

export const POLICY_REFRESH_INTERVAL_MS = 5 * 60_000;
export const POLICY_STALE_MS = 24 * 60 * 60_000;

export type PolicySource =
  | "server_cache"
  | "local_fallback"
  | "none"
  /** The org enforces, but its cached policy is missing, unreadable, invalid or edited. */
  | "enforced_lockdown";

export interface LoadedPolicy {
  source: PolicySource;
  policy: Policy | null;
  etag: string | null;
  fetchedAt: number | null;
  /** Why the lockdown policy is in force (source "enforced_lockdown" only). */
  lockdownReason?: LockdownReason;
}

export type LockdownReason = "policy_missing" | "policy_invalid" | "policy_edited";

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
  clearEnforcementMarker(cachePath);
}

/**
 * Sticky "this org enforces" marker, next to the policy cache. It is written
 * whenever the agent itself caches an enforcing org policy and records a hash
 * of that policy. While it exists, a missing, unreadable, invalid or edited
 * policy.json loads a lockdown policy (every built-in rule blocks) instead of
 * silently falling back to observe. Only explicit `auth`/`logout` (through
 * clearCachedPolicy) or a fetched non-enforcing policy removes it.
 */
export interface EnforcementMarker {
  version: 1;
  org_id?: string | null;
  workspace_id: string | null;
  org_name?: string;
  org_slug?: string;
  policy_sha256: string;
  since: number;
}

export function enforcementMarkerPath(cachePath: string = policyPath()): string {
  return `${cachePath}.enforced.json`;
}

/** Stable JSON: object keys sorted, so the hash doesn't depend on key order. */
function canonicalJson(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  if (v && typeof v === "object") {
    const o = v as Record<string, unknown>;
    return `{${Object.keys(o)
      .filter((k) => o[k] !== undefined)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonicalJson(o[k])}`)
      .join(",")}}`;
  }
  return JSON.stringify(v) ?? "null";
}

export function policySha256(policy: unknown): string {
  return createHash("sha256").update(canonicalJson(policy)).digest("hex");
}

export function readEnforcementMarker(
  cachePath: string = policyPath(),
): EnforcementMarker | null {
  try {
    const p = enforcementMarkerPath(cachePath);
    if (!existsSync(p)) return null;
    const parsed = JSON.parse(readFileSync(p, "utf8")) as Record<string, unknown>;
    if (
      !parsed ||
      typeof parsed !== "object" ||
      typeof parsed.policy_sha256 !== "string"
    ) {
      // A marker file that exists but can't be read still means "enforcing":
      // treat it as a marker whose hash matches nothing.
      return { version: 1, workspace_id: "unknown", policy_sha256: "", since: 0 };
    }
    return parsed as unknown as EnforcementMarker;
  } catch {
    return existsSync(enforcementMarkerPath(cachePath))
      ? { version: 1, workspace_id: "unknown", policy_sha256: "", since: 0 }
      : null;
  }
}

export function clearEnforcementMarker(cachePath: string = policyPath()): void {
  try {
    const p = enforcementMarkerPath(cachePath);
    if (existsSync(p)) unlinkSync(p);
  } catch {
    // Never throw on marker cleanup.
  }
}

function isEnforcingOrgPolicy(policy: Policy): boolean {
  return policy.mode === "enforce" && !isNoOrgPolicy(policy);
}

function writeEnforcementMarkerAtomic(policy: Policy, rawPolicy: unknown, cachePath: string): void {
  const existing = readEnforcementMarker(cachePath);
  const marker: EnforcementMarker = {
    version: 1,
    ...(policy.org_id !== undefined ? { org_id: policy.org_id } : {}),
    workspace_id: policy.workspace_id,
    ...(policy.org_name !== undefined ? { org_name: policy.org_name } : {}),
    ...(policy.org_slug !== undefined ? { org_slug: policy.org_slug } : {}),
    policy_sha256: policySha256(rawPolicy),
    since: existing && existing.since > 0 ? existing.since : Date.now(),
  };
  const target = enforcementMarkerPath(cachePath);
  const tmp = `${target}.tmp.${process.pid}.${randomBytes(6).toString("hex")}`;
  try {
    writeFileSync(tmp, JSON.stringify(marker, null, 2) + "\n", { encoding: "utf8", mode: 0o600 });
    renameSync(tmp, target);
  } catch (err) {
    try {
      unlinkSync(tmp);
    } catch {
      // Ignore cleanup failures.
    }
    throw err;
  }
}

/** Keeps the marker in step with a policy the agent itself just cached. */
function syncEnforcementMarker(policy: Policy, cachePath: string): void {
  if (isEnforcingOrgPolicy(policy)) {
    writeEnforcementMarkerAtomic(policy, policy, cachePath);
  } else {
    clearEnforcementMarker(cachePath);
  }
}

/**
 * The policy used while the org enforces but its cached policy can't be
 * trusted: every built-in Guard rule enabled with action "block", no custom
 * rules and no allow-list, in enforce mode. `agentreel auth` fetches a fresh
 * policy and lifts it.
 */
export function lockdownPolicy(marker: EnforcementMarker): Policy {
  const builtin: Record<string, BuiltinRuleOverride> = {};
  for (const rule of RULES) builtin[rule.id] = { enabled: true, action: "block" };
  return {
    version: 1,
    etag: "enforced-lockdown",
    workspace_id: marker.workspace_id,
    ...(marker.org_id ? { org_id: marker.org_id } : {}),
    ...(marker.org_name ? { org_name: marker.org_name } : {}),
    ...(marker.org_slug ? { org_slug: marker.org_slug } : {}),
    updated_at: 0,
    mode: "enforce",
    offline: "last_known",
    builtin,
    custom: [],
    allow: { commands: [], paths: [], repos: [] },
  };
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

/** The raw `policy` object in the cache file, as written (for hashing). */
function rawCachedPolicy(cachePath: string): unknown {
  try {
    const parsed = JSON.parse(readFileSync(cachePath, "utf8")) as { policy?: unknown };
    return parsed?.policy;
  } catch {
    return undefined;
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
    syncEnforcementMarker(entry.policy, cachePath);
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
  const marker = readEnforcementMarker(cachePath);
  if (marker) {
    const lockdown = (lockdownReason: LockdownReason): LoadedPolicy => ({
      source: "enforced_lockdown",
      policy: lockdownPolicy(marker),
      etag: null,
      fetchedAt: null,
      lockdownReason,
    });
    if (!cached) {
      return lockdown(existsSync(cachePath) ? "policy_invalid" : "policy_missing");
    }
    if (policySha256(rawCachedPolicy(cachePath)) !== marker.policy_sha256) {
      return lockdown("policy_edited");
    }
  } else if (cached && isEnforcingOrgPolicy(cached.policy)) {
    // First load of an enforcing policy cached before this agent version
    // wrote markers: record it now (trust on first use).
    try {
      writeEnforcementMarkerAtomic(cached.policy, rawCachedPolicy(cachePath), cachePath);
    } catch {
      // Best effort; the next policy refresh writes it too.
    }
  }
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
