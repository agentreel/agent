import type { Severity } from "../guard/types.js";
import { isRe2SafePattern } from "./regex.js";

export type PolicyMode = "observe" | "enforce";
export type PolicyOfflineMode = "last_known" | "fail_open";
export type PolicyAction = "flag" | "block" | "require_approval";
export type PolicyDecisionAction = "allow" | PolicyAction;
export type PolicyTool = "claude-code" | "cursor";
export type ApprovalOfflineFallback = "deny" | "allow";

export const DEFAULT_APPROVAL_EXPIRES_S = 120;
export const DEFAULT_APPROVAL_OFFLINE_FALLBACK: ApprovalOfflineFallback = "deny";
export const MIN_APPROVAL_EXPIRES_S = 10;
export const MAX_APPROVAL_EXPIRES_S = 3600;
export const PRE_EXEC_TIMEOUT_BUFFER_S = 10;
export const DEFAULT_PRE_EXEC_HOOK_TIMEOUT_S =
  DEFAULT_APPROVAL_EXPIRES_S + PRE_EXEC_TIMEOUT_BUFFER_S;
export const DEFAULT_HOOK_TIMEOUT_S = 5;
export const HOOK_DEADLINE_MARGIN_S = 5;

export type HookHost = "claude" | "cursor";

export function policyToolToHookHost(tool: PolicyTool): HookHost {
  return tool === "claude-code" ? "claude" : "cursor";
}

export function computeHookDeadlineMs(
  installedTimeoutS: number,
  startMs: number,
): number {
  const usableS = Math.max(0, installedTimeoutS - HOOK_DEADLINE_MARGIN_S);
  return startMs + usableS * 1000;
}

export function repoSlugFromRemoteUrl(
  remoteUrl: string | undefined,
): string | undefined {
  if (!remoteUrl) return undefined;
  const trimmed = remoteUrl.trim();
  if (!trimmed) return undefined;
  if (trimmed.includes("://")) {
    try {
      const u = new URL(trimmed);
      if (
        u.protocol !== "https:" &&
        u.protocol !== "http:" &&
        u.protocol !== "ssh:"
      ) {
        return undefined;
      }
      const slug = u.pathname
        .replace(/^\/+/, "")
        .replace(/\/+$/, "")
        .replace(/\.git$/i, "");
      return slug || undefined;
    } catch {
      return undefined;
    }
  }
  const scp = /^[^@]+@[^:]+:(.+)$/.exec(trimmed);
  if (scp && scp[1]) {
    const slug = scp[1]
      .replace(/^\/+/, "")
      .replace(/\/+$/, "")
      .replace(/\.git$/i, "");
    return slug || undefined;
  }
  return undefined;
}

export interface RuleApprovalConfig {
  expires_s?: number;
  offline_fallback?: ApprovalOfflineFallback;
}

export interface ResolvedApprovalConfig {
  expires_s: number;
  offline_fallback: ApprovalOfflineFallback;
}

export function resolveEffectiveRuleApproval(
  ruleApproval?: RuleApprovalConfig,
  policyDefaults?: RuleApprovalConfig,
): ResolvedApprovalConfig {
  const ruleExp = ruleApproval?.expires_s;
  const defaultExp = policyDefaults?.expires_s;
  const expires_s =
    typeof ruleExp === "number" && Number.isFinite(ruleExp) && ruleExp > 0
      ? ruleExp
      : typeof defaultExp === "number" &&
          Number.isFinite(defaultExp) &&
          defaultExp > 0
        ? defaultExp
        : DEFAULT_APPROVAL_EXPIRES_S;
  const offline_fallback =
    ruleApproval?.offline_fallback ??
    policyDefaults?.offline_fallback ??
    DEFAULT_APPROVAL_OFFLINE_FALLBACK;
  return { expires_s, offline_fallback };
}

export function isNoOrgPolicy(policy: Policy | null | undefined): boolean {
  return policy !== null && policy !== undefined && policy.org_id === null;
}

export function getPolicyOrgId(policy: Policy | null | undefined): string | null {
  if (!policy) return null;
  if (policy.org_id === null) return null;
  if (typeof policy.org_id === "string" && policy.org_id.trim().length > 0) {
    return policy.org_id;
  }
  if (
    typeof policy.workspace_id === "string" &&
    policy.workspace_id.trim().length > 0
  ) {
    return policy.workspace_id;
  }
  return null;
}

/**
 * Returns the largest effective approval expires_s across enabled require_approval
 * rules in a policy, or null if the policy has no enabled require_approval rules.
 */
export function computeMaxPolicyApprovalExpiresS(
  policy?: Policy | null,
): number | null {
  if (!policy || isNoOrgPolicy(policy)) return null;
  let maxExpiresS: number | null = null;

  for (const override of Object.values(policy.builtin)) {
    if (override.enabled === false) continue;
    if (override.action !== "require_approval") continue;
    const exp = resolveEffectiveRuleApproval(
      override.approval,
      policy.approval_defaults,
    ).expires_s;
    maxExpiresS = maxExpiresS === null ? exp : Math.max(maxExpiresS, exp);
  }

  for (const rule of policy.custom) {
    if (!rule.enabled) continue;
    if (rule.action !== "require_approval") continue;
    const exp = resolveEffectiveRuleApproval(
      rule.approval,
      policy.approval_defaults,
    ).expires_s;
    maxExpiresS = maxExpiresS === null ? exp : Math.max(maxExpiresS, exp);
  }

  return maxExpiresS;
}

export function computePreExecTimeoutS(policy?: Policy | null): number {
  let maxExpiresS = DEFAULT_APPROVAL_EXPIRES_S;
  if (policy && !isNoOrgPolicy(policy)) {
    const defaultExp = policy.approval_defaults?.expires_s;
    if (
      typeof defaultExp === "number" &&
      Number.isFinite(defaultExp) &&
      defaultExp > maxExpiresS
    ) {
      maxExpiresS = defaultExp;
    }
    for (const override of Object.values(policy.builtin)) {
      const exp = override.approval?.expires_s;
      if (typeof exp === "number" && Number.isFinite(exp) && exp > maxExpiresS) {
        maxExpiresS = exp;
      }
    }
    for (const rule of policy.custom) {
      const exp = rule.approval?.expires_s;
      if (typeof exp === "number" && Number.isFinite(exp) && exp > maxExpiresS) {
        maxExpiresS = exp;
      }
    }
  }
  return Math.ceil(maxExpiresS) + PRE_EXEC_TIMEOUT_BUFFER_S;
}

export type RuleConditionField =
  | "command"
  | "file_path"
  | "tool"
  | "url"
  | "mcp_tool"
  | "any";

export type RuleConditionOp =
  | "contains"
  | "starts_with"
  | "equals"
  | "glob"
  | "regex";

export interface BuiltinRuleOverride {
  enabled: boolean;
  action: PolicyAction;
  severity?: Severity;
  approval?: RuleApprovalConfig;
}

export interface CustomRuleCondition {
  field: RuleConditionField;
  op: RuleConditionOp;
  value: string;
  case_sensitive?: boolean;
}

export interface CustomRuleScope {
  repos?: string[];
  branches?: string[];
  members?: string[];
  teams?: string[];
  tools?: PolicyTool[];
}

export interface CustomRule {
  id: string;
  name: string;
  enabled: boolean;
  version: number;
  message: string;
  when: CustomRuleCondition[];
  action: PolicyAction;
  severity: Severity;
  scope?: CustomRuleScope;
  approval?: RuleApprovalConfig;
}

export interface PolicyAllowLists {
  commands: string[];
  paths: string[];
  repos: string[];
}

export interface Policy {
  version: 1;
  etag: string;
  workspace_id: string | null;
  org_id?: string | null;
  org_name?: string;
  org_slug?: string;
  updated_at: string | number;
  fetched_at?: string | number;
  mode: PolicyMode;
  offline: PolicyOfflineMode;
  approval_defaults?: RuleApprovalConfig;
  builtin: Record<string, BuiltinRuleOverride>;
  custom: CustomRule[];
  allow: PolicyAllowLists;
}

export interface CachedPolicyFile {
  policy: Policy;
  etag: string;
  fetched_at: number;
}

export type ValidationResult<T> =
  | { ok: true; value: T }
  | {
      ok: false;
      error: string;
      rejectedReason?: "unsupported_regex" | "invalid_policy";
      rejectedRuleId?: string;
      rejectedConditionIndex?: number;
    };

export interface ValidatePolicyOptions {
  /** Skip regex subset checks (used only when reading already-cached files so defense-in-depth eval handles them). */
  skipRegexValidation?: boolean;
}

const POLICY_MODES = new Set<string>(["observe", "enforce"]);
const OFFLINE_MODES = new Set<string>(["last_known", "fail_open"]);
const POLICY_ACTIONS = new Set<string>(["flag", "block", "require_approval"]);
const SEVERITIES = new Set<string>(["info", "warn", "high", "critical"]);
const CONDITION_FIELDS = new Set<string>([
  "command",
  "file_path",
  "tool",
  "url",
  "mcp_tool",
  "any",
]);
const CONDITION_OPS = new Set<string>([
  "contains",
  "starts_with",
  "equals",
  "glob",
  "regex",
]);
const POLICY_TOOLS = new Set<string>(["claude-code", "cursor"]);
const APPROVAL_OFFLINE_FALLBACKS = new Set<string>(["deny", "allow"]);

/**
 * Unknown enum strings (a newer server, or a value this agent predates) are
 * read as the strictest known value instead of rejecting the whole policy.
 * Rejecting it used to leave no policy at all, which meant allow. Non-string
 * values are still invalid.
 */
export const STRICTEST_MODE: PolicyMode = "enforce";
export const STRICTEST_OFFLINE: PolicyOfflineMode = "last_known";
export const STRICTEST_ACTION: PolicyAction = "block";
export const STRICTEST_SEVERITY: Severity = "critical";
export const STRICTEST_APPROVAL_FALLBACK: ApprovalOfflineFallback = "deny";

function knownOrStrictest<T extends string>(v: string, known: Set<string>, strictest: T): T {
  return (known.has(v) ? v : strictest) as T;
}

function validateRuleApproval(
  input: unknown,
  path: string,
  ruleId?: string,
): ValidationResult<RuleApprovalConfig> {
  if (!isPlainObject(input)) {
    return { ok: false, error: `${path} must be an object` };
  }
  const out: RuleApprovalConfig = {};
  if (input.expires_s !== undefined) {
    if (
      typeof input.expires_s !== "number" ||
      !Number.isInteger(input.expires_s) ||
      input.expires_s < MIN_APPROVAL_EXPIRES_S ||
      input.expires_s > MAX_APPROVAL_EXPIRES_S
    ) {
      const target = ruleId ? `rule ${ruleId} (${path}.expires_s)` : `${path}.expires_s`;
      return {
        ok: false,
        error: `${target} must be an integer between ${MIN_APPROVAL_EXPIRES_S} and ${MAX_APPROVAL_EXPIRES_S}`,
        rejectedReason: "invalid_policy",
        ...(ruleId ? { rejectedRuleId: ruleId } : {}),
      };
    }
    out.expires_s = input.expires_s;
  }
  if (input.offline_fallback !== undefined) {
    if (typeof input.offline_fallback !== "string") {
      return {
        ok: false,
        error: `${path}.offline_fallback must be "deny" or "allow"`,
      };
    }
    out.offline_fallback = knownOrStrictest(
      input.offline_fallback,
      APPROVAL_OFFLINE_FALLBACKS,
      STRICTEST_APPROVAL_FALLBACK,
    );
  }
  return { ok: true, value: out };
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function isNonEmptyString(v: unknown): v is string {
  return typeof v === "string" && v.trim().length > 0;
}

function isStringArray(v: unknown): v is string[] {
  return Array.isArray(v) && v.every((item) => typeof item === "string");
}

export function isValidSeverity(v: unknown): v is Severity {
  return typeof v === "string" && SEVERITIES.has(v);
}

function validateCondition(
  input: unknown,
  path: string,
  ruleId: string,
  condIndex: number,
  skipRegexValidation: boolean,
): ValidationResult<CustomRuleCondition> {
  if (!isPlainObject(input)) {
    return { ok: false, error: `${path} must be an object` };
  }
  if (typeof input.field !== "string" || !CONDITION_FIELDS.has(input.field)) {
    return { ok: false, error: `${path}.field is invalid` };
  }
  if (typeof input.op !== "string" || !CONDITION_OPS.has(input.op)) {
    return { ok: false, error: `${path}.op is invalid` };
  }
  if (typeof input.value !== "string") {
    return { ok: false, error: `${path}.value must be a string` };
  }
  if (
    input.case_sensitive !== undefined &&
    typeof input.case_sensitive !== "boolean"
  ) {
    return { ok: false, error: `${path}.case_sensitive must be a boolean` };
  }
  if (
    input.op === "regex" &&
    !skipRegexValidation &&
    !isRe2SafePattern(input.value)
  ) {
    return {
      ok: false,
      error: `rule ${ruleId} has an unsupported regex at when[${condIndex}]`,
      rejectedReason: "unsupported_regex",
      rejectedRuleId: ruleId,
      rejectedConditionIndex: condIndex,
    };
  }
  return {
    ok: true,
    value: {
      field: input.field as RuleConditionField,
      op: input.op as RuleConditionOp,
      value: input.value,
      ...(input.case_sensitive !== undefined
        ? { case_sensitive: input.case_sensitive }
        : {}),
    },
  };
}

function validateScope(
  input: unknown,
  path: string,
): ValidationResult<CustomRuleScope> {
  if (!isPlainObject(input)) {
    return { ok: false, error: `${path} must be an object` };
  }
  const scope: CustomRuleScope = {};
  if (input.repos !== undefined) {
    if (!isStringArray(input.repos)) {
      return { ok: false, error: `${path}.repos must be a string array` };
    }
    scope.repos = [...input.repos];
  }
  if (input.branches !== undefined) {
    if (!isStringArray(input.branches)) {
      return { ok: false, error: `${path}.branches must be a string array` };
    }
    scope.branches = [...input.branches];
  }
  if (input.members !== undefined) {
    if (!isStringArray(input.members)) {
      return { ok: false, error: `${path}.members must be a string array` };
    }
    scope.members = [...input.members];
  }
  if (input.teams !== undefined) {
    if (!isStringArray(input.teams)) {
      return { ok: false, error: `${path}.teams must be a string array` };
    }
    scope.teams = [...input.teams];
  }
  if (input.tools !== undefined) {
    if (
      !Array.isArray(input.tools) ||
      !input.tools.every((t) => typeof t === "string" && POLICY_TOOLS.has(t))
    ) {
      return {
        ok: false,
        error: `${path}.tools must contain only "claude-code" or "cursor"`,
      };
    }
    scope.tools = [...(input.tools as PolicyTool[])];
  }
  return { ok: true, value: scope };
}

function validateCustomRule(
  input: unknown,
  index: number,
  skipRegexValidation: boolean,
): ValidationResult<CustomRule> {
  const path = `custom[${index}]`;
  if (!isPlainObject(input)) {
    return { ok: false, error: `${path} must be an object` };
  }
  if (!isNonEmptyString(input.id)) {
    return { ok: false, error: `${path}.id must be a non-empty string` };
  }
  if (!isNonEmptyString(input.name)) {
    return { ok: false, error: `${path}.name must be a non-empty string` };
  }
  if (typeof input.enabled !== "boolean") {
    return { ok: false, error: `${path}.enabled must be a boolean` };
  }
  if (
    typeof input.version !== "number" ||
    !Number.isInteger(input.version) ||
    input.version < 0
  ) {
    return { ok: false, error: `${path}.version must be a non-negative integer` };
  }
  if (typeof input.message !== "string") {
    return { ok: false, error: `${path}.message must be a string` };
  }
  if (!Array.isArray(input.when) || input.when.length === 0) {
    return { ok: false, error: `${path}.when must be a non-empty array` };
  }
  const when: CustomRuleCondition[] = [];
  for (let i = 0; i < input.when.length; i++) {
    const cond = validateCondition(
      input.when[i],
      `${path}.when[${i}]`,
      input.id,
      i,
      skipRegexValidation,
    );
    if (!cond.ok) return cond;
    when.push(cond.value);
  }
  if (typeof input.action !== "string") {
    return { ok: false, error: `${path}.action is invalid` };
  }
  if (typeof input.severity !== "string") {
    return { ok: false, error: `${path}.severity is invalid` };
  }
  let scope: CustomRuleScope | undefined;
  if (input.scope !== undefined) {
    const s = validateScope(input.scope, `${path}.scope`);
    if (!s.ok) return s;
    scope = s.value;
  }
  let approval: RuleApprovalConfig | undefined;
  if (input.approval !== undefined) {
    const a = validateRuleApproval(input.approval, `${path}.approval`, input.id);
    if (!a.ok) return a;
    approval = a.value;
  }
  return {
    ok: true,
    value: {
      id: input.id,
      name: input.name,
      enabled: input.enabled,
      version: input.version,
      message: input.message,
      when,
      action: knownOrStrictest(input.action, POLICY_ACTIONS, STRICTEST_ACTION),
      severity: knownOrStrictest(input.severity, SEVERITIES, STRICTEST_SEVERITY),
      ...(scope !== undefined ? { scope } : {}),
      ...(approval !== undefined ? { approval } : {}),
    },
  };
}

export function validatePolicy(
  input: unknown,
  opts: ValidatePolicyOptions = {},
): ValidationResult<Policy> {
  if (!isPlainObject(input)) {
    return { ok: false, error: "policy must be an object" };
  }
  if (input.version !== 1) {
    return { ok: false, error: "policy.version must be 1" };
  }
  if (!isNonEmptyString(input.etag)) {
    return { ok: false, error: "policy.etag must be a non-empty string" };
  }

  let orgId: string | null | undefined;
  let workspaceId: string | null;
  if (input.org_id === null) {
    orgId = null;
    if (
      input.workspace_id !== undefined &&
      input.workspace_id !== null &&
      typeof input.workspace_id !== "string"
    ) {
      return {
        ok: false,
        error: "policy.workspace_id must be a string or null when org_id is null",
      };
    }
    workspaceId =
      typeof input.workspace_id === "string" && input.workspace_id.trim().length > 0
        ? input.workspace_id
        : null;
  } else if (input.org_id !== undefined) {
    if (!isNonEmptyString(input.org_id)) {
      return {
        ok: false,
        error: "policy.org_id must be a non-empty string or null",
      };
    }
    orgId = input.org_id;
    if (input.workspace_id !== undefined && input.workspace_id !== null) {
      if (!isNonEmptyString(input.workspace_id)) {
        return {
          ok: false,
          error: "policy.workspace_id must be a non-empty string",
        };
      }
      if (input.org_id !== input.workspace_id) {
        return {
          ok: false,
          error: `policy org_id (${input.org_id}) does not match workspace_id (${input.workspace_id})`,
          rejectedReason: "invalid_policy",
        };
      }
    }
    workspaceId = input.org_id;
  } else {
    if (!isNonEmptyString(input.workspace_id)) {
      return { ok: false, error: "policy.workspace_id must be a non-empty string" };
    }
    workspaceId = input.workspace_id;
  }

  if (input.org_name !== undefined && !isNonEmptyString(input.org_name)) {
    return { ok: false, error: "policy.org_name must be a non-empty string" };
  }
  if (input.org_slug !== undefined && !isNonEmptyString(input.org_slug)) {
    return { ok: false, error: "policy.org_slug must be a non-empty string" };
  }
  const validUpdatedAt =
    isNonEmptyString(input.updated_at) ||
    (typeof input.updated_at === "number" && Number.isFinite(input.updated_at));
  if (!validUpdatedAt) {
    return {
      ok: false,
      error: "policy.updated_at must be a non-empty string or finite number",
    };
  }
  let fetchedAt: string | number | undefined;
  if (input.fetched_at !== undefined) {
    const validFetchedAt =
      isNonEmptyString(input.fetched_at) ||
      (typeof input.fetched_at === "number" &&
        Number.isFinite(input.fetched_at) &&
        input.fetched_at >= 0);
    if (!validFetchedAt) {
      return {
        ok: false,
        error: "policy.fetched_at must be a non-empty string or finite non-negative number",
      };
    }
    fetchedAt = input.fetched_at as string | number;
  }
  if (typeof input.mode !== "string") {
    return { ok: false, error: 'policy.mode must be "observe" or "enforce"' };
  }
  const mode = knownOrStrictest(input.mode, POLICY_MODES, STRICTEST_MODE);
  if (typeof input.offline !== "string") {
    return {
      ok: false,
      error: 'policy.offline must be "last_known" or "fail_open"',
    };
  }
  const offline = knownOrStrictest(input.offline, OFFLINE_MODES, STRICTEST_OFFLINE);

  let approvalDefaults: RuleApprovalConfig | undefined;
  if (input.approval_defaults !== undefined) {
    const ad = validateRuleApproval(
      input.approval_defaults,
      "policy.approval_defaults",
    );
    if (!ad.ok) return ad;
    approvalDefaults = ad.value;
  }

  if (!isPlainObject(input.builtin)) {
    return { ok: false, error: "policy.builtin must be an object" };
  }
  const builtin: Record<string, BuiltinRuleOverride> = {};
  for (const [ruleId, rawOverride] of Object.entries(input.builtin)) {
    if (!ruleId.trim()) {
      return { ok: false, error: "policy.builtin keys must be non-empty" };
    }
    if (!isPlainObject(rawOverride)) {
      return { ok: false, error: `policy.builtin.${ruleId} must be an object` };
    }
    if (typeof rawOverride.enabled !== "boolean") {
      return {
        ok: false,
        error: `policy.builtin.${ruleId}.enabled must be a boolean`,
      };
    }
    if (typeof rawOverride.action !== "string") {
      return {
        ok: false,
        error: `policy.builtin.${ruleId}.action is invalid`,
      };
    }
    if (
      rawOverride.severity !== undefined &&
      typeof rawOverride.severity !== "string"
    ) {
      return {
        ok: false,
        error: `policy.builtin.${ruleId}.severity is invalid`,
      };
    }
    let approval: RuleApprovalConfig | undefined;
    if (rawOverride.approval !== undefined) {
      const a = validateRuleApproval(
        rawOverride.approval,
        `policy.builtin.${ruleId}.approval`,
        ruleId,
      );
      if (!a.ok) return a;
      approval = a.value;
    }
    builtin[ruleId] = {
      enabled: rawOverride.enabled,
      action: knownOrStrictest(rawOverride.action, POLICY_ACTIONS, STRICTEST_ACTION),
      ...(rawOverride.severity !== undefined
        ? {
            severity: knownOrStrictest(
              rawOverride.severity,
              SEVERITIES,
              STRICTEST_SEVERITY,
            ),
          }
        : {}),
      ...(approval !== undefined ? { approval } : {}),
    };
  }

  if (!Array.isArray(input.custom)) {
    return { ok: false, error: "policy.custom must be an array" };
  }
  const custom: CustomRule[] = [];
  const skipRegexValidation = opts.skipRegexValidation === true;
  for (let i = 0; i < input.custom.length; i++) {
    const r = validateCustomRule(input.custom[i], i, skipRegexValidation);
    if (!r.ok) return r;
    custom.push(r.value);
  }

  if (!isPlainObject(input.allow)) {
    return { ok: false, error: "policy.allow must be an object" };
  }
  if (!isStringArray(input.allow.commands)) {
    return { ok: false, error: "policy.allow.commands must be a string array" };
  }
  if (!isStringArray(input.allow.paths)) {
    return { ok: false, error: "policy.allow.paths must be a string array" };
  }
  if (!isStringArray(input.allow.repos)) {
    return { ok: false, error: "policy.allow.repos must be a string array" };
  }

  if (orgId === null) {
    const isEmptyAllow =
      input.allow.commands.length === 0 &&
      input.allow.paths.length === 0 &&
      input.allow.repos.length === 0;
    if (
      mode !== "observe" ||
      Object.keys(builtin).length > 0 ||
      custom.length > 0 ||
      !isEmptyAllow
    ) {
      return {
        ok: false,
        error:
          'policy with org_id null must have mode "observe" and empty builtin, custom, and allow',
        rejectedReason: "invalid_policy",
      };
    }
  }

  return {
    ok: true,
    value: {
      version: 1,
      etag: input.etag,
      workspace_id: workspaceId,
      ...(orgId !== undefined ? { org_id: orgId } : {}),
      ...(input.org_name !== undefined ? { org_name: input.org_name } : {}),
      ...(input.org_slug !== undefined ? { org_slug: input.org_slug } : {}),
      updated_at: input.updated_at as string | number,
      ...(fetchedAt !== undefined ? { fetched_at: fetchedAt } : {}),
      mode,
      offline,
      ...(approvalDefaults !== undefined
        ? { approval_defaults: approvalDefaults }
        : {}),
      builtin,
      custom,
      allow: {
        commands: [...input.allow.commands],
        paths: [...input.allow.paths],
        repos: [...input.allow.repos],
      },
    },
  };
}

export function isValidPolicy(input: unknown): input is Policy {
  return validatePolicy(input).ok;
}

export function validateCachedPolicyFile(
  input: unknown,
): ValidationResult<CachedPolicyFile> {
  if (!isPlainObject(input)) {
    return { ok: false, error: "cached policy must be an object" };
  }
  if (!isNonEmptyString(input.etag)) {
    return { ok: false, error: "cached policy etag must be a non-empty string" };
  }
  if (
    typeof input.fetched_at !== "number" ||
    !Number.isFinite(input.fetched_at) ||
    input.fetched_at < 0
  ) {
    return {
      ok: false,
      error: "cached policy fetched_at must be a finite non-negative number",
    };
  }
  const validatedPolicy = validatePolicy(input.policy, {
    skipRegexValidation: true,
  });
  if (!validatedPolicy.ok) {
    return validatedPolicy;
  }
  return {
    ok: true,
    value: {
      policy: validatedPolicy.value,
      etag: input.etag,
      fetched_at: input.fetched_at,
    },
  };
}
