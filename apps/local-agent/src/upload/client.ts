import type { AgentConfig } from "../config.js";

export interface IngestSession {
  id: string;
  tool: string;
  started_at: number;
  ended_at?: number | null;
  cwd?: string | null;
  total_cost_cents?: number | null;
  total_tokens?: number | null;
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
