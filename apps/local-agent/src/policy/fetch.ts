import { execFileSync } from "node:child_process";
import { appendFileSync } from "node:fs";
import { readConfig, type AgentConfig } from "../config.js";
import { ensureAgentreelDir, LOG_PATH, POLICY_PATH } from "../paths.js";
import {
  clearPolicyRejection,
  POLICY_REFRESH_INTERVAL_MS,
  readCachedPolicy,
  shouldRefreshPolicy,
  writeCachedPolicyAtomic,
  writePolicyRejectionAtomic,
} from "./cache.js";
import {
  repoSlugFromRemoteUrl,
  validatePolicy,
  type Policy,
} from "./types.js";

export { POLICY_REFRESH_INTERVAL_MS, repoSlugFromRemoteUrl, shouldRefreshPolicy };

export const POLICY_FETCH_TIMEOUT_MS = 10_000;

export function detectOriginRepo(cwd: string = process.cwd()): string | undefined {
  try {
    const out = execFileSync("git", ["-C", cwd, "remote", "get-url", "origin"], {
      encoding: "utf8",
      timeout: 1500,
      stdio: ["ignore", "pipe", "ignore"],
      env: { ...process.env, GIT_TERMINAL_PROMPT: "0", GIT_OPTIONAL_LOCKS: "0" },
    }).trim();
    if (!out) return undefined;
    return repoSlugFromRemoteUrl(out);
  } catch {
    return undefined;
  }
}

export type FetchPolicyResult =
  | { status: "unlinked" }
  | { status: "updated"; policy: Policy; etag: string; fetchedAt: number }
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
      LOG_PATH,
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
  const cachePath = opts.cachePath ?? POLICY_PATH;
  const nowFn = opts.now ?? Date.now;
  const timeoutMs = opts.timeoutMs ?? POLICY_FETCH_TIMEOUT_MS;
  const fetchImpl = opts.fetchImpl ?? globalThis.fetch;

  try {
    const cfg = opts.config ?? readConfig();
    if (!cfg.apiKey) {
      return { status: "unlinked" };
    }

    const cached = readCachedPolicy(cachePath);
    const repoSlug =
      opts.repo !== undefined
        ? opts.repo?.trim() || undefined
        : detectOriginRepo(opts.cwd ?? process.cwd());
    const basePolicyUrl = `${cfg.apiBaseUrl.replace(/\/$/, "")}/api/v1/policy`;
    const url = repoSlug
      ? `${basePolicyUrl}?repo=${encodeURIComponent(repoSlug)}`
      : basePolicyUrl;
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
        },
        cachePath,
      );
      clearPolicyRejection(cachePath);
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
      const etag = policy.etag;
      const fetchedAt = nowFn();
      writeCachedPolicyAtomic(
        {
          policy,
          etag,
          fetched_at: fetchedAt,
        },
        cachePath,
      );
      clearPolicyRejection(cachePath);
      return {
        status: "updated",
        policy,
        etag,
        fetchedAt,
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
