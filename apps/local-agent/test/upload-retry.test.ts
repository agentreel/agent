import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { describe, expect, it } from "vitest";

const client = await import("../src/upload/client.js");
const { IngestError, postIngest, backoffDelayMs } = client;

const cfg = { apiBaseUrl: "http://ingest.invalid", apiKey: "ar_test", schemaVersion: 1 } as never;

function jsonResponse(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
}

function scripted(steps: Array<() => Promise<Response>>) {
  let calls = 0;
  const fetchImpl = (async () => {
    const step = steps[Math.min(calls, steps.length - 1)]!;
    calls++;
    return step();
  }) as unknown as typeof fetch;
  return { fetchImpl, calls: () => calls };
}

const hang = (_url: unknown, init?: RequestInit) =>
  new Promise<Response>((_, reject) => {
    init?.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
  });

describe("postIngest timeout and retry", () => {
  it("times out a hung request and retries, then fails with a timeout IngestError", async () => {
    let calls = 0;
    const sleeps: number[] = [];
    const fetchImpl = ((url: unknown, init?: RequestInit) => {
      calls++;
      return hang(url, init);
    }) as unknown as typeof fetch;
    const err = await postIngest(cfg, { events: [] }, {
      fetchImpl,
      timeoutMs: 30,
      sleep: async (ms) => void sleeps.push(ms),
      random: () => 0.5,
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(IngestError);
    expect((err as InstanceType<typeof IngestError>).status).toBe(0);
    expect((err as Error).message).toContain("timeout after 30ms");
    expect((err as InstanceType<typeof IngestError>).isPermanent).toBe(false);
    expect(calls).toBe(client.INGEST_MAX_ATTEMPTS);
    expect(sleeps).toEqual([250, 500, 1000]);
  });

  it("retries a 503 and returns the later success", async () => {
    const s = scripted([
      async () => jsonResponse(503, { ok: false, error: "unavailable" }),
      async () => jsonResponse(200, { ok: true, events_written: 3 }),
    ]);
    const res = await postIngest(cfg, { events: [] }, { fetchImpl: s.fetchImpl, sleep: async () => {} });
    expect(res.events_written).toBe(3);
    expect(s.calls()).toBe(2);
  });

  it("does not retry a permanent 400 (denied path)", async () => {
    const s = scripted([async () => jsonResponse(400, { ok: false, error: "bad_payload" })]);
    const err = await postIngest(cfg, { events: [] }, { fetchImpl: s.fetchImpl, sleep: async () => {} }).catch((e) => e);
    expect((err as InstanceType<typeof IngestError>).status).toBe(400);
    expect((err as InstanceType<typeof IngestError>).isPermanent).toBe(true);
    expect(s.calls()).toBe(1);
  });

  it("does not retry a 200 with ok:false", async () => {
    const s = scripted([async () => jsonResponse(200, { ok: false, error: "rejected" })]);
    await expect(postIngest(cfg, {}, { fetchImpl: s.fetchImpl, sleep: async () => {} })).rejects.toThrow("rejected");
    expect(s.calls()).toBe(1);
  });

  it("honors Retry-After on 429, capped at the max delay", async () => {
    const sleeps: number[] = [];
    const s = scripted([
      async () => jsonResponse(429, { ok: false, error: "rate_limited" }, { "retry-after": "2" }),
      async () => jsonResponse(429, { ok: false, error: "rate_limited" }, { "retry-after": "600" }),
      async () => jsonResponse(200, { ok: true }),
    ]);
    await postIngest(cfg, {}, { fetchImpl: s.fetchImpl, sleep: async (ms) => void sleeps.push(ms) });
    expect(sleeps).toEqual([2000, client.INGEST_BACKOFF_MAX_MS]);
  });

  it("retries network errors and rethrows the last one", async () => {
    let calls = 0;
    const fetchImpl = (async () => {
      calls++;
      throw new TypeError("fetch failed");
    }) as unknown as typeof fetch;
    await expect(postIngest(cfg, {}, { fetchImpl, sleep: async () => {}, maxAttempts: 3 })).rejects.toThrow("fetch failed");
    expect(calls).toBe(3);
  });

  it("times out a response whose body never finishes", async () => {
    const fetchImpl = (async (_u: unknown, init?: RequestInit) =>
      ({
        ok: true,
        status: 200,
        headers: new Headers(),
        json: () => hang(undefined, init),
      }) as unknown as Response) as unknown as typeof fetch;
    const err = await postIngest(cfg, {}, { fetchImpl, timeoutMs: 30, maxAttempts: 1 }).catch((e) => e);
    expect((err as Error).message).toContain("timeout");
  });

  it("aborts a real hung HTTP server", async () => {
    const sockets = new Set<import("node:net").Socket>();
    const srv = createServer(() => {
      // never respond
    });
    srv.on("connection", (s) => sockets.add(s));
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    const port = (srv.address() as AddressInfo).port;
    try {
      const t0 = Date.now();
      const err = await postIngest(
        { apiBaseUrl: `http://127.0.0.1:${port}`, apiKey: "k", schemaVersion: 1 } as never,
        {},
        { timeoutMs: 100, maxAttempts: 2, sleep: async () => {} },
      ).catch((e) => e);
      expect((err as InstanceType<typeof IngestError>).status).toBe(0);
      expect(Date.now() - t0).toBeLessThan(5000);
    } finally {
      for (const s of sockets) s.destroy();
      await new Promise((r) => srv.close(r));
    }
  });
});

describe("backoffDelayMs", () => {
  it("grows exponentially with full jitter and is capped", () => {
    const top = () => 0.999999;
    const d = [0, 1, 2, 3, 4, 5].map((n) => backoffDelayMs(n, 500, 8000, top));
    expect(d).toEqual([499, 999, 1999, 3999, 7999, 7999]);
    expect(backoffDelayMs(3, 500, 8000, () => 0)).toBe(0);
    for (let i = 0; i < 200; i++) {
      const v = backoffDelayMs(2, 500, 8000);
      expect(v).toBeGreaterThanOrEqual(0);
      expect(v).toBeLessThan(2000);
    }
  });
});
