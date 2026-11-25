import type { AgentConfig } from "../config.js";
import { scrubString } from "../redact/scrubber.js";
import {
  DEFAULT_APPROVAL_EXPIRES_S,
  type ApprovalOfflineFallback,
  type PolicyTool,
} from "./types.js";

export const APPROVAL_LONG_POLL_WAIT_S = 25;
export const APPROVAL_POST_TIMEOUT_MS = 10_000;
export const APPROVAL_POLL_BUFFER_MS = 5_000;
export const DEFAULT_APPROVAL_OFFLINE_FALLBACK: ApprovalOfflineFallback = "deny";

export interface ApprovalRequestParams {
  decisionId: string;
  ruleId: string;
  sessionId: string;
  repo?: string;
  tool: PolicyTool;
  summary: string;
  config: AgentConfig;
  expiresS?: number;
  offlineFallback?: ApprovalOfflineFallback;
  hookDeadlineMs?: number;
  fetchImpl?: typeof fetch;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
  minPollDelayMs?: number;
  retryDelayMs?: number;
  postRetries?: number;
  pollRetries?: number;
}

export type ApprovalOutcome =
  | "approved"
  | "denied"
  | "expired"
  | "timeout"
  | "offline_deny"
  | "offline_allow";

export interface ApprovalResult {
  permitted: boolean;
  outcome: ApprovalOutcome;
  decisionId: string;
  approvalId?: string;
  decidedBy?: string;
  reason?: string;
}

interface ApprovalPostResponse {
  approval_id?: string;
  status?: string;
  poll_after_ms?: number;
  expires_at?: string | number;
  decided_by?: string;
  reason?: string;
}

interface ApprovalPollResponse {
  status?: string;
  decided_by?: string;
  reason?: string;
}

function defaultSleep(ms: number): Promise<void> {
  if (ms <= 0) return Promise.resolve();
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function parseExpiresAtMs(expiresAt: string | number | undefined): number | null {
  if (typeof expiresAt === "number" && Number.isFinite(expiresAt)) {
    return expiresAt < 1e12 ? expiresAt * 1000 : expiresAt;
  }
  if (typeof expiresAt === "string" && expiresAt.trim()) {
    const parsed = Date.parse(expiresAt);
    if (Number.isFinite(parsed)) return parsed;
  }
  return null;
}

function offlineResult(
  decisionId: string,
  fallback: ApprovalOfflineFallback,
  reason: string,
  approvalId?: string,
): ApprovalResult {
  return {
    permitted: fallback === "allow",
    outcome: fallback === "allow" ? "offline_allow" : "offline_deny",
    decisionId,
    ...(approvalId ? { approvalId } : {}),
    reason,
  };
}

interface FetchJsonResult<T> {
  ok: boolean;
  status: number;
  data?: T;
  invalidJson?: boolean;
  abortedByTimeout: boolean;
  networkError?: string;
}

async function fetchJsonWithTimeout<T>(
  fetchImpl: typeof fetch,
  url: string,
  init: RequestInit,
  timeoutMs: number,
): Promise<FetchJsonResult<T>> {
  const controller = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, Math.max(1, timeoutMs));
  try {
    const res = await fetchImpl(url, { ...init, signal: controller.signal });
    if (!res.ok) {
      return {
        ok: false,
        status: res.status,
        abortedByTimeout: false,
      };
    }
    try {
      const data = (await res.json()) as T;
      return {
        ok: true,
        status: res.status,
        data,
        abortedByTimeout: false,
      };
    } catch (err) {
      if (timedOut || isAbortError(err)) {
        return {
          ok: false,
          status: 0,
          abortedByTimeout: timedOut,
          networkError: err instanceof Error ? err.message : "request aborted",
        };
      }
      return {
        ok: false,
        status: res.status,
        invalidJson: true,
        abortedByTimeout: false,
      };
    }
  } catch (err) {
    return {
      ok: false,
      status: 0,
      abortedByTimeout: timedOut,
      networkError: err instanceof Error ? err.message : "network error",
    };
  } finally {
    clearTimeout(timer);
  }
}

function isAbortError(err: unknown): boolean {
  return err instanceof Error && err.name === "AbortError";
}

function resolveTerminalStatus(
  status: string | undefined,
  decisionId: string,
  approvalId: string | undefined,
  decidedBy: string | undefined,
  reason: string | undefined,
): ApprovalResult | null {
  if (status === "approved") {
    return {
      permitted: true,
      outcome: "approved",
      decisionId,
      ...(approvalId ? { approvalId } : {}),
      ...(decidedBy ? { decidedBy } : {}),
      ...(reason ? { reason } : {}),
    };
  }
  if (status === "denied") {
    return {
      permitted: false,
      outcome: "denied",
      decisionId,
      ...(approvalId ? { approvalId } : {}),
      ...(decidedBy ? { decidedBy } : {}),
      ...(reason ? { reason } : {}),
    };
  }
  if (status === "expired") {
    return {
      permitted: false,
      outcome: "expired",
      decisionId,
      ...(approvalId ? { approvalId } : {}),
      ...(decidedBy ? { decidedBy } : {}),
      ...(reason ? { reason } : {}),
    };
  }
  return null;
}

/**
 * Contacts the AgentReel approval API for a require_approval policy decision.
 * This is the only module reachable from pre-exec hooks that touches the network.
 */
export async function requestRemoteApproval(
  params: ApprovalRequestParams,
): Promise<ApprovalResult> {
  const nowFn = params.now ?? Date.now;
  const sleepFn = params.sleep ?? defaultSleep;
  const fetchImpl = params.fetchImpl ?? globalThis.fetch;
  const fallback = params.offlineFallback ?? DEFAULT_APPROVAL_OFFLINE_FALLBACK;
  const expiresS = params.expiresS ?? DEFAULT_APPROVAL_EXPIRES_S;
  const minPollDelayMs = params.minPollDelayMs ?? 100;
  const retryDelayMs = params.retryDelayMs ?? 100;
  const postRetries = params.postRetries ?? 1;
  const pollRetries = params.pollRetries ?? 2;

  if (!params.config.apiKey) {
    return offlineResult(
      params.decisionId,
      fallback,
      "agent not linked (missing API key)",
    );
  }

  if (
    typeof params.config.apiBaseUrl !== "string" ||
    !params.config.apiBaseUrl.trim()
  ) {
    return offlineResult(
      params.decisionId,
      fallback,
      "missing API base URL",
    );
  }

  const startMs = nowFn();
  let effectiveDeadlineMs = startMs + expiresS * 1000;
  if (
    params.hookDeadlineMs !== undefined &&
    params.hookDeadlineMs < effectiveDeadlineMs
  ) {
    effectiveDeadlineMs = params.hookDeadlineMs;
  }

  const baseUrl = params.config.apiBaseUrl.trim().replace(/\/$/, "");
  const postUrl = `${baseUrl}/api/v1/approvals`;
  const authHeaders: Record<string, string> = {
    accept: "application/json",
    authorization: `Bearer ${params.config.apiKey}`,
  };
  const postBody = JSON.stringify({
    decision_id: params.decisionId,
    rule_id: params.ruleId,
    session_id: params.sessionId,
    repo: params.repo ?? null,
    tool: params.tool,
    summary: scrubString(params.summary),
  });

  let postData: ApprovalPostResponse | null = null;
  let lastErrorReason = "approval server unavailable";

  for (let attempt = 0; attempt <= postRetries; attempt++) {
    const remainingMs = effectiveDeadlineMs - nowFn();
    if (remainingMs <= 0) {
      return {
        permitted: false,
        outcome: "timeout",
        decisionId: params.decisionId,
        reason: "approval timed out",
      };
    }

    const cappedToDeadline = remainingMs <= APPROVAL_POST_TIMEOUT_MS;
    const reqTimeoutMs = cappedToDeadline ? remainingMs : APPROVAL_POST_TIMEOUT_MS;
    const result = await fetchJsonWithTimeout<ApprovalPostResponse>(
      fetchImpl,
      postUrl,
      {
        method: "POST",
        headers: { ...authHeaders, "content-type": "application/json" },
        body: postBody,
      },
      reqTimeoutMs,
    );

    if (result.abortedByTimeout && (cappedToDeadline || nowFn() >= effectiveDeadlineMs)) {
      return {
        permitted: false,
        outcome: "timeout",
        decisionId: params.decisionId,
        reason: "approval timed out",
      };
    }

    if (result.invalidJson) {
      return offlineResult(
        params.decisionId,
        fallback,
        "invalid JSON from approval server",
      );
    }

    if (result.networkError !== undefined || result.status >= 500) {
      lastErrorReason =
        result.networkError !== undefined
          ? result.networkError
          : `approval server returned HTTP ${result.status}`;
      if (attempt < postRetries && effectiveDeadlineMs - nowFn() > retryDelayMs) {
        await sleepFn(Math.min(retryDelayMs, effectiveDeadlineMs - nowFn()));
        continue;
      }
      return offlineResult(params.decisionId, fallback, lastErrorReason);
    }

    if (!result.ok) {
      return offlineResult(
        params.decisionId,
        fallback,
        `approval server returned HTTP ${result.status}`,
      );
    }

    postData = result.data ?? null;
    break;
  }

  if (!postData || typeof postData.approval_id !== "string" || !postData.approval_id) {
    return offlineResult(
      params.decisionId,
      fallback,
      "missing approval_id from approval server",
    );
  }

  const approvalId = postData.approval_id;
  const immediate = resolveTerminalStatus(
    postData.status,
    params.decisionId,
    approvalId,
    postData.decided_by,
    postData.reason,
  );
  if (immediate) return immediate;

  const serverExpiresMs = parseExpiresAtMs(postData.expires_at);
  if (serverExpiresMs !== null && serverExpiresMs < effectiveDeadlineMs) {
    effectiveDeadlineMs = serverExpiresMs;
  }

  let nextDelayMs =
    typeof postData.poll_after_ms === "number" && postData.poll_after_ms > 0
      ? postData.poll_after_ms
      : 0;
  let consecutivePollErrors = 0;

  while (nowFn() < effectiveDeadlineMs) {
    if (nextDelayMs > 0) {
      const waitMs = Math.min(nextDelayMs, effectiveDeadlineMs - nowFn());
      if (waitMs > 0) await sleepFn(waitMs);
      nextDelayMs = 0;
      if (nowFn() >= effectiveDeadlineMs) break;
    }

    const remainingMs = effectiveDeadlineMs - nowFn();
    if (remainingMs <= 0) break;

    const waitSec = Math.max(
      1,
      Math.min(APPROVAL_LONG_POLL_WAIT_S, Math.ceil(remainingMs / 1000)),
    );
    const pollUrl = `${baseUrl}/api/v1/approvals/${encodeURIComponent(approvalId)}?wait=${waitSec}s`;
    const maxSinglePollMs = waitSec * 1000 + APPROVAL_POLL_BUFFER_MS;
    const cappedToDeadline = remainingMs <= maxSinglePollMs;
    const pollTimeoutMs = cappedToDeadline ? remainingMs : maxSinglePollMs;

    const pollStartedAt = nowFn();
    const result = await fetchJsonWithTimeout<ApprovalPollResponse>(
      fetchImpl,
      pollUrl,
      { method: "GET", headers: authHeaders },
      pollTimeoutMs,
    );

    if (result.abortedByTimeout && (cappedToDeadline || nowFn() >= effectiveDeadlineMs)) {
      return {
        permitted: false,
        outcome: "timeout",
        decisionId: params.decisionId,
        approvalId,
        reason: "approval timed out",
      };
    }

    if (result.invalidJson) {
      return offlineResult(
        params.decisionId,
        fallback,
        "invalid JSON from approval poll",
        approvalId,
      );
    }

    if (result.networkError !== undefined || result.status >= 500) {
      const reason =
        result.networkError !== undefined
          ? result.networkError
          : `approval poll returned HTTP ${result.status}`;
      consecutivePollErrors++;
      if (
        consecutivePollErrors <= pollRetries &&
        effectiveDeadlineMs - nowFn() > retryDelayMs
      ) {
        await sleepFn(Math.min(retryDelayMs, effectiveDeadlineMs - nowFn()));
        continue;
      }
      return offlineResult(params.decisionId, fallback, reason, approvalId);
    }

    if (!result.ok) {
      return offlineResult(
        params.decisionId,
        fallback,
        `approval poll returned HTTP ${result.status}`,
        approvalId,
      );
    }

    consecutivePollErrors = 0;
    const pollData = result.data ?? {};

    const resolved = resolveTerminalStatus(
      pollData.status,
      params.decisionId,
      approvalId,
      pollData.decided_by,
      pollData.reason,
    );
    if (resolved) return resolved;

    if (pollData.status !== "pending") {
      return offlineResult(
        params.decisionId,
        fallback,
        `unexpected approval status: ${String(pollData.status)}`,
        approvalId,
      );
    }

    const elapsed = nowFn() - pollStartedAt;
    if (elapsed < minPollDelayMs) {
      nextDelayMs = minPollDelayMs - elapsed;
    }
  }

  return {
    permitted: false,
    outcome: "timeout",
    decisionId: params.decisionId,
    approvalId,
    reason: "approval timed out",
  };
}
