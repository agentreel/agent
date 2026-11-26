import { createHash } from "node:crypto";
import { appendFileSync } from "node:fs";
import type { AgentEvent } from "@agentreel/shared-types";
import {
  getInstalledPreExecTimeoutS,
  readConfig,
  type AgentConfig,
} from "../config.js";
import { insertEvent } from "../db.js";
import { RULES } from "../guard/rules.js";
import { ensureAgentreelDir, LOG_PATH } from "../paths.js";
import { scrubAny, scrubString } from "../redact/scrubber.js";
import { isPolicyCacheStale, loadEffectivePolicy } from "./cache.js";
import {
  EVAL_TIMEOUT_REASON,
  evaluatePolicy,
  INVALID_RULE_REASON,
  POLICY_EVAL_DEADLINE_MS,
  type PolicyEvalInput,
  type PolicyRuleMatch,
} from "./eval.js";
import {
  computeHookDeadlineMs,
  DEFAULT_APPROVAL_EXPIRES_S,
  HOOK_DEADLINE_MARGIN_S,
  isNoOrgPolicy,
  policyToolToHookHost,
  repoSlugFromRemoteUrl,
  resolveEffectiveRuleApproval,
  type ApprovalOfflineFallback,
  type Policy,
  type PolicyAction,
  type PolicyDecisionAction,
  type PolicyTool,
  type RuleApprovalConfig,
} from "./types.js";

export { EVAL_TIMEOUT_REASON, INVALID_RULE_REASON, repoSlugFromRemoteUrl };
export const STALE_FAIL_OPEN_REASON = "policy stale, fail_open";
export const HOOK_TIMEOUT_TOO_SHORT_REASON = "hook_timeout_too_short";

export function formatHookTimeoutTooShortMessage(ruleName: string): string {
  return `Admin approval for ${ruleName} needs a longer hook timeout than is installed. Run \`npx @agentreel/agent init\` to update hook timeouts.`;
}

export interface PolicyDecisionRecord {
  id: string;
  ts: number;
  session_id: string;
  rule_id: string;
  rule_ids: string[];
  action: PolicyAction;
  enforced: boolean;
  downgraded: boolean;
  policy_etag: string | null;
  tool: PolicyTool;
  tool_name?: string;
  reason?: string;
  original_action?: PolicyAction;
  approval_id?: string;
  approval_status?: string;
  decided_by?: string;
}

export interface PreExecRequest {
  sessionId: string;
  tool: PolicyTool;
  toolName: string;
  toolUseId?: string;
  cwd?: string;
  command?: string;
  file_path?: string;
  url?: string;
  mcp_tool?: string;
  toolInput?: unknown;
  repo?: string;
  branch?: string;
  member?: string;
  ts?: number;
}

export interface PreExecOutcome {
  permitted: boolean;
  action: PolicyDecisionAction;
  enforced: boolean;
  downgraded: boolean;
  message?: string;
  reason?: string;
  decision?: PolicyDecisionRecord;
  timedOut?: boolean;
  error?: boolean;
}

export interface PreExecDeps {
  cachePath?: string;
  guardConfigPath?: string;
  config?: AgentConfig;
  now?: () => number;
  evalNowMs?: () => number;
  sleep?: (ms: number) => Promise<void>;
  evalDeadlineMs?: number;
  hookDeadlineMs?: number;
  installedTimeoutS?: number;
  fetchImpl?: typeof fetch;
  onWaiting?: (message: string) => void;
  recordDecision?: (event: AgentEvent) => void;
  log?: (message: string) => void;
  evaluateFn?: typeof evaluatePolicy;
  minPollDelayMs?: number;
  retryDelayMs?: number;
  postRetries?: number;
}

function defaultLog(message: string): void {
  try {
    ensureAgentreelDir();
    appendFileSync(
      LOG_PATH,
      `[${new Date().toISOString()}] policy enforce: ${message}\n`,
    );
  } catch {
    // Logging must never crash or block a hook.
  }
}

function defaultOnWaiting(message: string): void {
  try {
    process.stderr.write(`${message}\n`);
  } catch {
    // Ignore stderr write failures.
  }
}

export function formatBlockMessage(
  ruleName: string,
  policy: Policy | null,
  config: AgentConfig,
): string {
  const org = policy?.org_name?.trim() || config.orgName?.trim() || "your org";
  const slug = policy?.org_slug?.trim() || config.orgSlug?.trim();
  const url = slug ? `agentreel.dev/org/${slug}` : "agentreel.dev";
  return `Blocked by ${org} policy: ${ruleName}. Ask an admin or see ${url}`;
}

export function formatEvalTimeoutBlockMessage(
  policy: Policy | null,
  config: AgentConfig,
): string {
  const org = policy?.org_name?.trim() || config.orgName?.trim() || "your org";
  const slug = policy?.org_slug?.trim() || config.orgSlug?.trim();
  const url = slug ? `agentreel.dev/org/${slug}` : "agentreel.dev";
  return `Blocked by ${org} policy: policy check timed out. Ask an admin or see ${url}`;
}

export function formatInvalidRuleBlockMessage(
  ruleId: string,
  policy: Policy | null,
  config: AgentConfig,
): string {
  const org = policy?.org_name?.trim() || config.orgName?.trim() || "your org";
  const slug = policy?.org_slug?.trim() || config.orgSlug?.trim();
  const url = slug ? `agentreel.dev/org/${slug}` : "agentreel.dev";
  return `Blocked by ${org} policy: rule ${ruleId} has an unsupported regex and could not be evaluated. Ask an admin or see ${url}`;
}

export function formatWaitingMessage(
  ruleName: string,
  expiresS: number,
): string {
  return `Waiting for admin approval (${ruleName}), up to ${Math.ceil(expiresS)}s`;
}

const MAX_APPROVAL_SUMMARY_CHARS = 500;

export function buildActionSummary(req: PreExecRequest): string {
  if (req.command) return `${req.toolName}: ${req.command}`;
  if (req.file_path) return `${req.toolName}: ${req.file_path}`;
  if (req.url) return `${req.toolName}: ${req.url}`;
  if (req.mcp_tool) return `${req.toolName} (${req.mcp_tool})`;
  return req.toolName;
}

export function buildScrubbedApprovalSummary(req: PreExecRequest): string {
  let raw: string;
  if (req.command) {
    raw = `${req.toolName}: ${scrubString(req.command)}`;
  } else if (req.file_path) {
    raw = `${req.toolName}: ${scrubString(req.file_path)}`;
  } else if (req.url) {
    raw = `${req.toolName}: ${scrubString(req.url)}`;
  } else if (req.mcp_tool) {
    raw = `${req.toolName} (${scrubString(req.mcp_tool)})`;
  } else {
    raw = req.toolName;
  }
  const scrubbed = scrubString(raw);
  if (scrubbed.length <= MAX_APPROVAL_SUMMARY_CHARS) return scrubbed;
  return `${scrubbed.slice(0, MAX_APPROVAL_SUMMARY_CHARS - 3)}...`;
}

export function computeDecisionId(params: {
  sessionId: string;
  ruleId: string;
  tool: PolicyTool;
  toolUseId?: string;
  summary: string;
}): string {
  const hash = createHash("sha256")
    .update(
      JSON.stringify([
        params.sessionId,
        params.ruleId,
        params.tool,
        params.toolUseId ?? "",
        params.summary,
      ]),
    )
    .digest("hex");
  return `dec_${hash.slice(0, 24)}`;
}

function selectPrimaryMatch(
  matches: PolicyRuleMatch[],
  targetAction: PolicyAction,
): PolicyRuleMatch {
  return matches.find((m) => m.action === targetAction) ?? matches[0]!;
}

function resolveApprovalConfig(
  matches: PolicyRuleMatch[],
  policyDefaults?: RuleApprovalConfig,
): {
  expiresS: number;
  offlineFallback: ApprovalOfflineFallback;
} {
  const approvalMatches = matches.filter((m) => m.action === "require_approval");
  const candidates = approvalMatches.length > 0 ? approvalMatches : matches;

  if (candidates.length === 0) {
    const eff = resolveEffectiveRuleApproval(undefined, policyDefaults);
    return {
      expiresS: eff.expires_s,
      offlineFallback: eff.offline_fallback,
    };
  }

  let minExpiresS: number | undefined;
  let allAllowOffline = true;

  for (const m of candidates) {
    const eff = resolveEffectiveRuleApproval(m.approval, policyDefaults);
    minExpiresS =
      minExpiresS === undefined ? eff.expires_s : Math.min(minExpiresS, eff.expires_s);
    if (eff.offline_fallback !== "allow") {
      allAllowOffline = false;
    }
  }

  return {
    expiresS: minExpiresS ?? DEFAULT_APPROVAL_EXPIRES_S,
    offlineFallback: allAllowOffline ? "allow" : "deny",
  };
}

function persistDecisionEvent(
  record: PolicyDecisionRecord,
  cwd: string | undefined,
  recordDecision: (event: AgentEvent) => void,
  log: (message: string) => void,
): void {
  try {
    const safePayload = scrubAny(record) as PolicyDecisionRecord;
    // Preserve admin approver identity verbatim; scrubAny redacts emails.
    if (record.decided_by !== undefined) {
      safePayload.decided_by = record.decided_by;
    }
    recordDecision({
      id: record.id,
      sessionId: record.session_id,
      tool: record.tool,
      type: "policy_decision",
      ts: record.ts,
      cwd,
      payload: safePayload,
    });
  } catch (err) {
    log(
      `failed to persist policy_decision event: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

function formatApprovalDenyMessage(
  ruleName: string,
  policy: Policy | null,
  config: AgentConfig,
  outcome: string,
  decidedBy?: string,
  reason?: string,
  expiresS?: number,
): string {
  const org = policy?.org_name?.trim() || config.orgName?.trim() || "your org";
  const slug = policy?.org_slug?.trim() || config.orgSlug?.trim();
  const url = slug ? `agentreel.dev/org/${slug}` : "agentreel.dev";
  let detail = outcome;
  if (outcome === "denied") {
    detail = decidedBy ? `denied by ${decidedBy}` : "denied by admin";
    if (reason) detail += `: ${reason}`;
  } else if (outcome === "expired") {
    detail = "approval expired";
  } else if (outcome === "timeout") {
    detail = `approval timed out after ${Math.ceil(expiresS ?? DEFAULT_APPROVAL_EXPIRES_S)}s`;
  } else if (outcome === "offline_deny") {
    detail = "approval server unavailable";
  }
  return `Blocked by ${org} policy: ${ruleName} (${detail}). Ask an admin or see ${url}`;
}

/**
 * Evaluates cached policy for a pre-execution tool call, handles offline modes,
 * optionally runs the remote approval flow only for require_approval, records
 * non-allow policy_decision events locally, and always fails open on errors.
 */
export async function enforcePreExec(
  req: PreExecRequest,
  deps: PreExecDeps = {},
): Promise<PreExecOutcome> {
  const log = deps.log ?? defaultLog;
  const nowFn = deps.now ?? Date.now;
  const recordDecision = deps.recordDecision ?? insertEvent;
  const onWaiting = deps.onWaiting ?? defaultOnWaiting;
  const evaluateFn = deps.evaluateFn ?? evaluatePolicy;

  try {
    const loaded = loadEffectivePolicy({
      cachePath: deps.cachePath,
      guardConfigPath: deps.guardConfigPath,
    });

    if (!loaded.policy || isNoOrgPolicy(loaded.policy)) {
      return {
        permitted: true,
        action: "allow",
        enforced: false,
        downgraded: false,
      };
    }

    const evalInput: PolicyEvalInput = {
      tool: req.tool,
      toolName: req.toolName,
      command: req.command,
      file_path: req.file_path,
      url: req.url,
      mcp_tool: req.mcp_tool,
      toolInput: req.toolInput,
      repo: req.repo,
      branch: req.branch,
      member: req.member,
    };

    const evalResult = evaluateFn(evalInput, loaded.policy, RULES, {
      deadlineMs: deps.evalDeadlineMs ?? POLICY_EVAL_DEADLINE_MS,
      ...(deps.evalNowMs ? { nowMs: deps.evalNowMs } : {}),
    });

    if (evalResult.timed_out) {
      log(
        `evaluation exceeded ${deps.evalDeadlineMs ?? POLICY_EVAL_DEADLINE_MS}ms deadline for ${req.toolName}; action=${evalResult.action}`,
      );
    }

    if (evalResult.invalid_rule) {
      log(
        `unsupported regex failed to compile during eval for rule(s) ${(evalResult.invalid_rule_ids ?? []).join(", ") || "unknown"}; action=${evalResult.action}`,
      );
    }

    if (evalResult.action === "allow") {
      return {
        permitted: true,
        action: "allow",
        enforced: false,
        downgraded: false,
      };
    }

    const ts = req.ts ?? nowFn();
    const targetAction = evalResult.original_action ?? evalResult.action;
    const primaryMatch =
      evalResult.matches.length > 0
        ? selectPrimaryMatch(evalResult.matches, targetAction)
        : null;
    const isInvalidRuleFailClosed =
      Boolean(evalResult.invalid_rule) &&
      Boolean(evalResult.unevaluated_enforcing) &&
      (!primaryMatch || primaryMatch.action !== "block");
    const firstInvalidRuleId = evalResult.invalid_rule_ids?.[0];
    const primaryRuleId = isInvalidRuleFailClosed
      ? (firstInvalidRuleId ?? INVALID_RULE_REASON)
      : (primaryMatch?.rule_id ??
          firstInvalidRuleId ??
          (evalResult.invalid_rule ? INVALID_RULE_REASON : EVAL_TIMEOUT_REASON));
    const primaryRuleName =
      primaryMatch?.name ??
      (evalResult.invalid_rule
        ? `rule ${firstInvalidRuleId ?? "unknown"} has an unsupported regex`
        : "policy check timed out");
    const effectiveRuleIds =
      evalResult.invalid_rule && evalResult.invalid_rule_ids?.length
        ? Array.from(new Set([...evalResult.rule_ids, ...evalResult.invalid_rule_ids]))
        : evalResult.rule_ids;
    const summary = buildActionSummary(req);
    const decisionId = computeDecisionId({
      sessionId: req.sessionId,
      ruleId: primaryRuleId,
      tool: req.tool,
      toolUseId: req.toolUseId,
      summary,
    });

    const isStaleFailOpen =
      loaded.policy.offline === "fail_open" &&
      (loaded.source !== "server_cache" ||
        isPolicyCacheStale(loaded.fetchedAt, nowFn()));

    if (
      isStaleFailOpen &&
      (evalResult.action === "block" || evalResult.action === "require_approval")
    ) {
      const record: PolicyDecisionRecord = {
        id: decisionId,
        ts,
        session_id: req.sessionId,
        rule_id: primaryRuleId,
        rule_ids: effectiveRuleIds,
        action: "flag",
        enforced: false,
        downgraded: true,
        original_action: evalResult.action,
        reason: STALE_FAIL_OPEN_REASON,
        policy_etag: loaded.etag,
        tool: req.tool,
        tool_name: req.toolName,
      };
      persistDecisionEvent(record, req.cwd, recordDecision, log);
      return {
        permitted: true,
        action: "flag",
        enforced: false,
        downgraded: true,
        reason: STALE_FAIL_OPEN_REASON,
        decision: record,
        ...(evalResult.timed_out ? { timedOut: true } : {}),
      };
    }

    if (evalResult.action === "flag") {
      const record: PolicyDecisionRecord = {
        id: decisionId,
        ts,
        session_id: req.sessionId,
        rule_id: primaryRuleId,
        rule_ids: effectiveRuleIds,
        action: "flag",
        enforced: false,
        downgraded: evalResult.downgraded,
        ...(evalResult.original_action
          ? { original_action: evalResult.original_action }
          : {}),
        ...(evalResult.reason ? { reason: evalResult.reason } : {}),
        policy_etag: loaded.etag,
        tool: req.tool,
        tool_name: req.toolName,
      };
      persistDecisionEvent(record, req.cwd, recordDecision, log);
      return {
        permitted: true,
        action: "flag",
        enforced: false,
        downgraded: evalResult.downgraded,
        ...(evalResult.reason ? { reason: evalResult.reason } : {}),
        decision: record,
        ...(evalResult.timed_out ? { timedOut: true } : {}),
      };
    }

    const cfg = deps.config ?? readConfig();

    const recordPartialFlags = (): void => {
      if (evalResult.timed_out && !evalResult.unevaluated_enforcing) {
        const flagRecord: PolicyDecisionRecord = {
          id: `${decisionId}_timeout`,
          ts,
          session_id: req.sessionId,
          rule_id: EVAL_TIMEOUT_REASON,
          rule_ids: [EVAL_TIMEOUT_REASON],
          action: "flag",
          enforced: false,
          downgraded: false,
          reason: EVAL_TIMEOUT_REASON,
          policy_etag: loaded.etag,
          tool: req.tool,
          tool_name: req.toolName,
        };
        persistDecisionEvent(flagRecord, req.cwd, recordDecision, log);
      }
      if (evalResult.invalid_rule && !evalResult.unevaluated_enforcing) {
        const invalidIds = evalResult.invalid_rule_ids?.length
          ? evalResult.invalid_rule_ids
          : [INVALID_RULE_REASON];
        const flagRecord: PolicyDecisionRecord = {
          id: `${decisionId}_invalid_rule`,
          ts,
          session_id: req.sessionId,
          rule_id: invalidIds[0]!,
          rule_ids: invalidIds,
          action: "flag",
          enforced: false,
          downgraded: false,
          reason: INVALID_RULE_REASON,
          policy_etag: loaded.etag,
          tool: req.tool,
          tool_name: req.toolName,
        };
        persistDecisionEvent(flagRecord, req.cwd, recordDecision, log);
      }
    };

    if (evalResult.action === "block") {
      const isTimeoutFailClosed =
        Boolean(evalResult.timed_out) &&
        Boolean(evalResult.unevaluated_enforcing) &&
        (!primaryMatch || primaryMatch.action !== "block");
      const message = isInvalidRuleFailClosed
        ? formatInvalidRuleBlockMessage(primaryRuleId, loaded.policy, cfg)
        : isTimeoutFailClosed
          ? formatEvalTimeoutBlockMessage(loaded.policy, cfg)
          : formatBlockMessage(primaryRuleName, loaded.policy, cfg);
      const reason = isInvalidRuleFailClosed
        ? INVALID_RULE_REASON
        : isTimeoutFailClosed
          ? EVAL_TIMEOUT_REASON
          : (evalResult.reason ?? primaryMatch?.message ?? EVAL_TIMEOUT_REASON);
      const record: PolicyDecisionRecord = {
        id: decisionId,
        ts,
        session_id: req.sessionId,
        rule_id: primaryRuleId,
        rule_ids: effectiveRuleIds,
        action: "block",
        enforced: true,
        downgraded: false,
        reason,
        policy_etag: loaded.etag,
        tool: req.tool,
        tool_name: req.toolName,
      };
      persistDecisionEvent(record, req.cwd, recordDecision, log);
      recordPartialFlags();
      return {
        permitted: false,
        action: "block",
        enforced: true,
        downgraded: false,
        message,
        reason,
        decision: record,
        ...(evalResult.timed_out ? { timedOut: true } : {}),
      };
    }

    // require_approval: the only hook path permitted to reach the network.
    if (evalResult.action === "require_approval") {
      recordPartialFlags();
      const approvalCfg = resolveApprovalConfig(
        evalResult.matches,
        loaded.policy.approval_defaults,
      );
      const installedTimeoutS =
        deps.installedTimeoutS ??
        getInstalledPreExecTimeoutS(cfg, policyToolToHookHost(req.tool));
      const maxWaitBudgetS = installedTimeoutS - HOOK_DEADLINE_MARGIN_S;

      if (approvalCfg.expiresS > maxWaitBudgetS) {
        const message = formatHookTimeoutTooShortMessage(primaryRuleName);
        const reason = HOOK_TIMEOUT_TOO_SHORT_REASON;
        const record: PolicyDecisionRecord = {
          id: decisionId,
          ts,
          session_id: req.sessionId,
          rule_id: primaryRuleId,
          rule_ids: evalResult.rule_ids,
          action: "require_approval",
          enforced: true,
          downgraded: false,
          policy_etag: loaded.etag,
          tool: req.tool,
          tool_name: req.toolName,
          approval_status: HOOK_TIMEOUT_TOO_SHORT_REASON,
          reason,
        };
        persistDecisionEvent(record, req.cwd, recordDecision, log);

        return {
          permitted: false,
          action: "require_approval",
          enforced: true,
          downgraded: false,
          message,
          reason,
          decision: record,
          ...(evalResult.timed_out ? { timedOut: true } : {}),
        };
      }

      const effectiveHookDeadlineMs =
        deps.hookDeadlineMs ?? computeHookDeadlineMs(installedTimeoutS, ts);

      onWaiting(formatWaitingMessage(primaryRuleName, approvalCfg.expiresS));

      const { requestRemoteApproval } = await import("./approval.js");
      const approval = await requestRemoteApproval({
        decisionId,
        ruleId: primaryRuleId,
        sessionId: req.sessionId,
        repo: req.repo,
        tool: req.tool,
        summary: buildScrubbedApprovalSummary(req),
        config: cfg,
        expiresS: approvalCfg.expiresS,
        offlineFallback: approvalCfg.offlineFallback,
        hookDeadlineMs: effectiveHookDeadlineMs,
        fetchImpl: deps.fetchImpl,
        now: nowFn,
        sleep: deps.sleep,
        minPollDelayMs: deps.minPollDelayMs,
        retryDelayMs: deps.retryDelayMs,
        postRetries: deps.postRetries,
        log,
      });

      const downgraded = approval.outcome === "offline_allow";
      const enforced = !approval.permitted;
      const message = approval.permitted
        ? undefined
        : formatApprovalDenyMessage(
            primaryRuleName,
            loaded.policy,
            cfg,
            approval.outcome,
            approval.decidedBy,
            approval.reason,
            approvalCfg.expiresS,
          );

      const record: PolicyDecisionRecord = {
        id: decisionId,
        ts,
        session_id: req.sessionId,
        rule_id: primaryRuleId,
        rule_ids: evalResult.rule_ids,
        action: "require_approval",
        enforced,
        downgraded,
        policy_etag: loaded.etag,
        tool: req.tool,
        tool_name: req.toolName,
        ...(approval.approvalId ? { approval_id: approval.approvalId } : {}),
        approval_status: approval.outcome,
        ...(approval.decidedBy ? { decided_by: approval.decidedBy } : {}),
        ...(approval.reason ? { reason: approval.reason } : {}),
      };
      persistDecisionEvent(record, req.cwd, recordDecision, log);

      return {
        permitted: approval.permitted,
        action: "require_approval",
        enforced,
        downgraded,
        ...(message ? { message } : {}),
        ...(approval.reason ? { reason: approval.reason } : {}),
        decision: record,
        ...(evalResult.timed_out ? { timedOut: true } : {}),
      };
    }

    return {
      permitted: true,
      action: "allow",
      enforced: false,
      downgraded: false,
    };
  } catch (err) {
    log(
      `unexpected error during pre-exec enforcement; failing open: ${
        err instanceof Error ? err.stack ?? err.message : String(err)
      }`,
    );
    return {
      permitted: true,
      action: "allow",
      enforced: false,
      downgraded: false,
      error: true,
    };
  }
}
