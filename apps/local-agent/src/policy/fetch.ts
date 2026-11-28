import { appendFileSync } from "node:fs";
import { readConfig, type AgentConfig } from "../config.js";
import { ensureAgentreelDir, logPath, policyPath } from "../paths.js";
import {
  clearTransientPolicyRejection,
  POLICY_REFRESH_INTERVAL_MS,
  readCachedPolicy,
  shouldRefreshPolicy,
  writeCachedPolicyAtomic,
  writePolicyRejectionAtomic,
} from "./cache.js";
import { hasSignatureField } from "./signature.js";
import { checkPolicyTrust, signedAtOf } from "./trust.js";
import {
  getPolicyOrgId,
  repoSlugFromRemoteUrl,
  validatePolicy,
  type CachedPolicyFile,
  type Policy,
} from "./types.js";

export { POLICY_REFRESH_INTERVAL_MS, repoSlugFromRemoteUrl, shouldRefreshPolicy };

/**
 * Contract steps 2 to 5 for a 200 body: signature against a pinned key
 * (required for an enforcing org policy), body etag equal to the ETag
 * header, and no rollback to an older signed_at for the same org. Returns
 * an error string, or null when the policy may be installed.
 */
function signedPolicyError(
  policy: Policy,
  body: unknown,
  res: Response,
  cached: CachedPolicyFile | null,
): string | null {
  const trust = checkPolicyTrust(policy, body);
  if (!trust.ok) return `${trust.reason}: ${trust.detail}`;
  if (!trust.signed) return null;
  const header = normalizeEtagToken(res.headers.get("etag"));
  if (header !== policy.etag) {
    return `etag_mismatch: body etag ${policy.etag} does not match ETag header ${header ?? "(missing)"}`;
  }
  const cachedSignedAt = cached?.signed_body ? signedAtOf(cached.signed_body) : null;
  if (
    cachedSignedAt &&
    trust.signedAt &&
    getPolicyOrgId(cached?.policy) === getPolicyOrgId(policy) &&
    Date.parse(trust.signedAt) < Date.parse(cachedSignedAt)
  ) {
    return `rollback: signed_at ${trust.signedAt} is older than the cached ${cachedSignedAt}`;
  }
  return null;
}

/** Strips a weak validator and quotes, as the web contract's normalizeEtagToken. */
export function normalizeEtagToken(raw: string | null | undefined): string | null {
  if (typeof raw !== "string") return null;
  let t = raw.trim();
  if (t.startsWith("W/")) t = t.slice(2);
  if (t.length >= 2 && t.startsWith('"') && t.endsWith('"')) t = t.slice(1, -1);
  return t.length > 0 ? t : null;
}

export const POLICY_FETCH_TIMEOUT_MS = 10_000;

export type FetchPolicyResult =
  | { status: "unlinked" }
  | {
      status: "updated";
      policy: Policy;
      etag: string;
      fetchedAt: number;
      /** Raw signed body, when the server signed it (stored for re-verification). */
      signedBody?: Record<string, unknown>;
    }
  | { status: "not_modified"; policy: Policy; etag: string; fetchedAt: number }
  | { status: "invalid_policy"; error: string; keptCache: boolean }
  | {
      status: "kept_cache";
      reason: string;
      httpStatus?: number;
      keptCache: boolean;
    };

export interface FetchPolicyOptions {
  config?: AgentConfig;
  cachePath?: string;
  cwd?: string;
  repo?: string | null;
  timeoutMs?: number;
  now?: () => number;
  fetchImpl?: typeof fetch;
  log?: (message: string) => void;
}

function defaultLog(message: string): void {
  try {
    ensureAgentreelDir();
    appendFileSync(
      logPath(),
      `[${new Date().toISOString()}] policy: ${message}\n`,
    );
  } catch {
    // Logging must never crash the daemon or CLI.
  }
}

/**
 * Fetches GET ${apiBaseUrl}/api/v1/policy using the linked API key and cached ETag.
 * Keeps the last-known cache on any error, non-200/304 status, or invalid payload.
 * Never throws.
 */
export async function fetchPolicy(
  opts: FetchPolicyOptions = {},
): Promise<FetchPolicyResult> {
  const log = opts.log ?? defaultLog;
  const cachePath = opts.cachePath ?? policyPath();
  const nowFn = opts.now ?? Date.now;
  const timeoutMs = opts.timeoutMs ?? POLICY_FETCH_TIMEOUT_MS;
  const fetchImpl = opts.fetchImpl ?? globalThis.fetch;

  try {
    const cfg = opts.config ?? readConfig();
    if (!cfg.apiKey) {
      return { status: "unlinked" };
    }

    const cached = readCachedPolicy(cachePath);
    // Do not send ?repo= until the policy cache is per-repo; a single global
    // cache cannot safely mix repo-scoped responses across working directories.
    const url = `${cfg.apiBaseUrl.replace(/\/$/, "")}/api/v1/policy`;
    const headers: Record<string, string> = {
      accept: "application/json",
      authorization: `Bearer ${cfg.apiKey}`,
    };
    if (cached?.etag) {
      headers["if-none-match"] = cached.etag;
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    let res: Response;
    try {
      res = await fetchImpl(url, {
        method: "GET",
        headers,
        signal: controller.signal,
      });
    } catch (err) {
      const e = err as Error;
      const reason =
        e?.name === "AbortError"
          ? `timeout after ${timeoutMs}ms`
          : e?.message || "network error";
      log(`fetch failed (${reason}); keeping last-known cache`);
      return { status: "kept_cache", reason, keptCache: cached !== null };
    } finally {
      clearTimeout(timer);
    }

    if (res.status === 304) {
      if (!cached) {
        log("received 304 Not Modified without a valid cached policy");
        return {
          status: "kept_cache",
          reason: "http-304 without cached policy",
          httpStatus: 304,
          keptCache: false,
        };
      }
      const fetchedAt = nowFn();
      writeCachedPolicyAtomic(
        {
          policy: cached.policy,
          etag: cached.etag,
          fetched_at: fetchedAt,
          ...(cached.signed_body ? { signed_body: cached.signed_body } : {}),
        },
        cachePath,
      );
      clearTransientPolicyRejection(cachePath);
      return {
        status: "not_modified",
        policy: cached.policy,
        etag: cached.etag,
        fetchedAt,
      };
    }

    if (res.status === 200) {
      let body: unknown;
      try {
        body = await res.json();
      } catch {
        log(
          cached
            ? "received invalid JSON from policy endpoint; keeping last-known cache"
            : "received invalid JSON from policy endpoint; no cached policy available, org enforcement is off until a valid policy is cached",
        );
        try {
          writePolicyRejectionAtomic(
            {
              ts: nowFn(),
              error: "invalid JSON body",
              reason: "invalid_policy",
            },
            cachePath,
          );
        } catch {
          // Never fail fetch on sidecar write error.
        }
        return {
          status: "invalid_policy",
          error: "invalid JSON body",
          keptCache: cached !== null,
        };
      }

      const validated = validatePolicy(body);
      if (!validated.ok) {
        log(
          cached
            ? `rejected invalid policy (${validated.error}); keeping last-known cache`
            : `rejected invalid policy (${validated.error}); the rejected policy was not installed and org enforcement is off until a valid policy is cached`,
        );
        try {
          writePolicyRejectionAtomic(
            {
              ts: nowFn(),
              error: validated.error,
              reason:
                validated.rejectedReason === "unsupported_regex"
                  ? "unsupported_regex"
                  : "invalid_policy",
              ...(validated.rejectedRuleId
                ? { rule_id: validated.rejectedRuleId }
                : {}),
              ...(validated.rejectedConditionIndex !== undefined
                ? { condition_index: validated.rejectedConditionIndex }
                : {}),
            },
            cachePath,
          );
        } catch {
          // Never fail fetch on sidecar write error.
        }
        return {
          status: "invalid_policy",
          error: validated.error,
          keptCache: cached !== null,
        };
      }

      const policy = validated.value;
      const cachedOrgId = getPolicyOrgId(cached?.policy);
      const incomingOrgId = getPolicyOrgId(policy);

      if (cachedOrgId !== null && incomingOrgId === null) {
        const msg = `no-org response ignored; keeping cached org policy ${cachedOrgId}`;
        log(msg);
        try {
          writePolicyRejectionAtomic(
            {
              ts: nowFn(),
              error: msg,
              reason: "no_org_ignored",
              cached_org_id: cachedOrgId,
              incoming_org_id: null,
            },
            cachePath,
          );
        } catch {
          // Never fail fetch on sidecar write error.
        }
        return {
          status: "kept_cache",
          reason: "no_org_ignored",
          httpStatus: 200,
          keptCache: true,
        };
      }

      if (
        cachedOrgId !== null &&
        incomingOrgId !== null &&
        incomingOrgId !== cachedOrgId
      ) {
        const msg = `policy for org ${incomingOrgId} ignored; keeping cached org ${cachedOrgId}`;
        log(msg);
        try {
          writePolicyRejectionAtomic(
            {
              ts: nowFn(),
              error: msg,
              reason: "org_mismatch_ignored",
              cached_org_id: cachedOrgId,
              incoming_org_id: incomingOrgId,
            },
            cachePath,
          );
        } catch {
          // Never fail fetch on sidecar write error.
        }
        return {
          status: "kept_cache",
          reason: "org_mismatch_ignored",
          httpStatus: 200,
          keptCache: true,
        };
      }

      const trustError = signedPolicyError(policy, body, res, cached);
      if (trustError) {
        log(
          cached
            ? `rejected policy signature (${trustError}); keeping last verified cache`
            : `rejected policy signature (${trustError}); the policy was not installed and org enforcement is off until a verified policy is cached`,
        );
        try {
          writePolicyRejectionAtomic(
            { ts: nowFn(), error: trustError, reason: "invalid_signature" },
            cachePath,
          );
        } catch {
          // Never fail fetch on sidecar write error.
        }
        return {
          status: "invalid_policy",
          error: trustError,
          keptCache: cached !== null,
        };
      }
      const signedBody = hasSignatureField(body)
        ? (body as Record<string, unknown>)
        : undefined;

      const etag = policy.etag;
      const fetchedAt = nowFn();
      writeCachedPolicyAtomic(
        {
          policy,
          etag,
          fetched_at: fetchedAt,
          ...(signedBody ? { signed_body: signedBody } : {}),
        },
        cachePath,
      );
      clearTransientPolicyRejection(cachePath);
      return {
        status: "updated",
        policy,
        etag,
        fetchedAt,
        ...(signedBody ? { signedBody } : {}),
      };
    }

    log(`policy endpoint returned HTTP ${res.status}; keeping last-known cache`);
    return {
      status: "kept_cache",
      reason: `http-${res.status}`,
      httpStatus: res.status,
      keptCache: cached !== null,
    };
  } catch (err) {
    const e = err as Error;
    const reason = e?.message || "unexpected error";
    log(`unexpected policy fetch error (${reason})`);
    const hasCache = readCachedPolicy(cachePath) !== null;
    return { status: "kept_cache", reason, keptCache: hasCache };
  }
}
