import type { Severity } from "../guard/types.js";

export type PolicyMode = "observe" | "enforce";
export type PolicyOfflineMode = "last_known" | "fail_open";
export type PolicyAction = "flag" | "block" | "require_approval";
export type PolicyDecisionAction = "allow" | PolicyAction;
export type PolicyTool = "claude-code" | "cursor";

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
}

export interface PolicyAllowLists {
  commands: string[];
  paths: string[];
  repos: string[];
}

export interface Policy {
  version: 1;
  etag: string;
  workspace_id: string;
  updated_at: string | number;
  mode: PolicyMode;
  offline: PolicyOfflineMode;
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
  | { ok: false; error: string };

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
    const cond = validateCondition(input.when[i], `${path}.when[${i}]`);
    if (!cond.ok) return cond;
    when.push(cond.value);
  }
  if (typeof input.action !== "string" || !POLICY_ACTIONS.has(input.action)) {
    return { ok: false, error: `${path}.action is invalid` };
  }
  if (!isValidSeverity(input.severity)) {
    return { ok: false, error: `${path}.severity is invalid` };
  }
  let scope: CustomRuleScope | undefined;
  if (input.scope !== undefined) {
    const s = validateScope(input.scope, `${path}.scope`);
    if (!s.ok) return s;
    scope = s.value;
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
      action: input.action as PolicyAction,
      severity: input.severity,
      ...(scope !== undefined ? { scope } : {}),
    },
  };
}

export function validatePolicy(input: unknown): ValidationResult<Policy> {
  if (!isPlainObject(input)) {
    return { ok: false, error: "policy must be an object" };
  }
  if (input.version !== 1) {
    return { ok: false, error: "policy.version must be 1" };
  }
  if (!isNonEmptyString(input.etag)) {
    return { ok: false, error: "policy.etag must be a non-empty string" };
  }
  if (!isNonEmptyString(input.workspace_id)) {
    return { ok: false, error: "policy.workspace_id must be a non-empty string" };
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
  if (typeof input.mode !== "string" || !POLICY_MODES.has(input.mode)) {
    return { ok: false, error: 'policy.mode must be "observe" or "enforce"' };
  }
  if (typeof input.offline !== "string" || !OFFLINE_MODES.has(input.offline)) {
    return {
      ok: false,
      error: 'policy.offline must be "last_known" or "fail_open"',
    };
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
    if (
      typeof rawOverride.action !== "string" ||
      !POLICY_ACTIONS.has(rawOverride.action)
    ) {
      return {
        ok: false,
        error: `policy.builtin.${ruleId}.action is invalid`,
      };
    }
    if (
      rawOverride.severity !== undefined &&
      !isValidSeverity(rawOverride.severity)
    ) {
      return {
        ok: false,
        error: `policy.builtin.${ruleId}.severity is invalid`,
      };
    }
    builtin[ruleId] = {
      enabled: rawOverride.enabled,
      action: rawOverride.action as PolicyAction,
      ...(rawOverride.severity !== undefined
        ? { severity: rawOverride.severity }
        : {}),
    };
  }

  if (!Array.isArray(input.custom)) {
    return { ok: false, error: "policy.custom must be an array" };
  }
  const custom: CustomRule[] = [];
  for (let i = 0; i < input.custom.length; i++) {
    const r = validateCustomRule(input.custom[i], i);
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

  return {
    ok: true,
    value: {
      version: 1,
      etag: input.etag,
      workspace_id: input.workspace_id,
      updated_at: input.updated_at as string | number,
      mode: input.mode as PolicyMode,
      offline: input.offline as PolicyOfflineMode,
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
  const validatedPolicy = validatePolicy(input.policy);
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
