import type { AgentConfig } from "../config.js";

export interface IngestSession {
  id: string;
  tool: string;
  started_at: number;
  ended_at?: number | null;
  cwd?: string | null;
  total_cost_cents?: number | null;
  total_tokens?: number | null;
  /** Who/where ran the agent (agent >= 0.1.7). Older servers ignore it. */
  attribution?: unknown;
  /** AgentReel Guard findings (agent >= 0.2.0). Optional, additive field. */
  guard_findings?: {
    version: number;
    risk_score: number;
    findings: Array<{
      rule_id: string;
      severity: string;
      category: string;
      timestamp: number;
      evidence: string;
    }>;
  };
}

export interface IngestEvent {
  id: string;
  session_id: string;
  ts: number;
  type: string;
  tool: string;
  cwd?: string | null;
  payload: unknown;
}

export interface IngestResponse {
  ok: boolean;
  sessions_written?: number;
  events_written?: number;
  error?: string;
  reason?: string;
  message?: string;
  /** Sessions the server refused (e.g. over the plan's active-session limit). */
  rejected_sessions?: Array<{ id: string; reason: string }>;
  plan_limit?: {
    plan: string;
    limit: number;
    active_sessions: number;
    retry_after_seconds?: number;
    message: string;
  };
}

export class IngestError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly body: IngestResponse | null,
  ) {
    super(message);
    this.name = "IngestError";
  }
  /** 4xx (except 408/429) — payload-shaped problem the agent can't fix by retrying. */
  get isPermanent(): boolean {
    return this.status >= 400 && this.status < 500 && this.status !== 408 && this.status !== 429;
  }
}

export async function postIngest(
  cfg: AgentConfig,
  body: { sessions?: IngestSession[]; events?: IngestEvent[] },
): Promise<IngestResponse> {
  if (!cfg.apiKey) {
    throw new Error("Not linked. Run: agentreel link <key>");
  }
  const url = `${cfg.apiBaseUrl.replace(/\/$/, "")}/api/v1/sessions/ingest`;
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${cfg.apiKey}`,
      // Tells the server we understand per-session rejections, so it can
      // accept the rest of the batch with a 200 instead of a 402.
      "x-agentreel-partial": "1",
    },
    body: JSON.stringify(body),
  });
  let data: IngestResponse | null = null;
  try {
    data = (await res.json()) as IngestResponse;
  } catch {
    // Non-JSON body — treat as transient if 5xx, permanent otherwise.
  }
  if (!res.ok || !data?.ok) {
    const reason = data?.reason ? ` (${data.reason})` : "";
    const tag = data?.error ?? `http-${res.status}`;
    throw new IngestError(`${tag}${reason}`, res.status, data);
  }
  return data;
}
