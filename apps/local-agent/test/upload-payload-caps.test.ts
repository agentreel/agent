import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  DEFAULT_FREE_TEXT_LIMIT,
  INGEST_FIELD_LIMITS,
  UNTRUNCATED_IDENTIFIER_KEYS,
  capPayloadFields,
  truncateField,
  truncationMarker,
} from "../src/upload/payload-caps.js";

type Db = typeof import("../src/db.js");
type Queue = typeof import("../src/upload/queue.js");
let db: Db;
let queue: Queue;

beforeAll(async () => {
  db = await import("../src/db.js");
  queue = await import("../src/upload/queue.js");
});
afterAll(() => {
  db.closeDb();
});

const CAP = 64_000;
const PAYLOAD_FIELDS = ["prompt", "output", "patch", "stdout", "stderr", "contents"] as const;
const FREE_TEXT_FIELDS = [
  "title", "label", "rule_name", "summary", "detail", "description", "rationale", "message",
] as const;
const FIELDS = [...PAYLOAD_FIELDS, ...FREE_TEXT_FIELDS, "reason"] as const;
// The server limits from apps/web/lib/govern/contract.ts (agentreel/web main
// 55dac0a): INGEST_LIMITS lines 1625-1645, field caps lines 3235-3308.
const SERVER = { payloadText: 100_000, freeText: 10_000, reason: 1_000 } as const;
const serverCap = (field: string): number =>
  (PAYLOAD_FIELDS as readonly string[]).includes(field)
    ? SERVER.payloadText
    : field === "reason"
      ? SERVER.reason
      : SERVER.freeText;
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

describe("INGEST_FIELD_LIMITS", () => {
  it("is one map: six payload fields at 64,000, eight free-text fields at 9,500, reason at 950", () => {
    expect(Object.keys(INGEST_FIELD_LIMITS).sort()).toEqual([...FIELDS].sort());
    for (const f of PAYLOAD_FIELDS) expect(INGEST_FIELD_LIMITS[f]).toBe(64_000);
    for (const f of FREE_TEXT_FIELDS) expect(INGEST_FIELD_LIMITS[f]).toBe(9_500);
    expect(INGEST_FIELD_LIMITS.reason).toBe(950);
    expect(DEFAULT_FREE_TEXT_LIMIT).toBe(9_500);
  });

  for (const field of FIELDS) {
    it(`${field}: cap ${INGEST_FIELD_LIMITS[field]} is below the server cap ${serverCap(field)} and holds the marker`, () => {
      const cap = INGEST_FIELD_LIMITS[field]!;
      expect(cap).toBeLessThan(serverCap(field));
      // Worst case marker: a 12 digit original length.
      expect(truncationMarker(999_999_999_999).length).toBeLessThan(cap);
      // The cap is the longest value that passes untouched.
      const exact = "k".repeat(cap);
      expect(truncateField(exact, cap)).toBe(exact);
      // One over, and far over, both come back at most the cap, so the
      // server (cap + margin) accepts them.
      for (const n of [cap + 1, cap + 2, serverCap(field) + 1, serverCap(field) * 50]) {
        const out = truncateField("k".repeat(n), cap);
        expect(out.length, `${field} n=${n}`).toBeLessThanOrEqual(cap);
        expect(out.length, `${field} n=${n}`).toBeLessThan(serverCap(field));
        expect(out.endsWith(truncationMarker(n))).toBe(true);
      }
      expect(truncateField("k".repeat(cap + 1), cap).length).toBe(cap);
    });
  }

  it("keeps the identifier keys the server caps at 4,096 or less out of the cap map", () => {
    for (const key of UNTRUNCATED_IDENTIFIER_KEYS) {
      expect(Object.hasOwn(INGEST_FIELD_LIMITS, key), key).toBe(false);
    }
    for (const key of ["id", "session_id", "tool_name", "cwd", "file_path", "repo", "branch"]) {
      expect(UNTRUNCATED_IDENTIFIER_KEYS.has(key), key).toBe(true);
    }
  });
});

describe("truncateField", () => {
  it("leaves a value at exactly the cap untouched", () => {
    const v = "a".repeat(CAP);
    expect(truncateField(v, CAP)).toBe(v);
  });

  it("truncates one over the cap to exactly the cap, with the original length in the marker", () => {
    const v = "a".repeat(CAP + 1);
    const out = truncateField(v, CAP);
    expect(out.length).toBe(CAP);
    expect(out.endsWith(truncationMarker(CAP + 1))).toBe(true);
    expect(truncationMarker(CAP + 1)).toBe(`\n[agentreel: truncated, original length ${CAP + 1} chars]`);
    expect(out.startsWith("a".repeat(100))).toBe(true);
  });

  it("keeps the total, marker included, at or under the cap for huge inputs", () => {
    for (const n of [CAP + 1, CAP + 2, 70_000, 99_999, 100_000, 100_001, 5_000_000]) {
      const out = truncateField("z".repeat(n), CAP);
      expect(out.length, `n=${n}`).toBeLessThanOrEqual(CAP);
      expect(out).toContain(`original length ${n} chars`);
    }
  });

  it("never splits a surrogate pair at the cut", () => {
    const n = 70_000;
    const keep = CAP - truncationMarker(n).length;
    // High surrogate at keep-1, low surrogate at keep: the cut would land between them.
    const v = "a".repeat(keep - 1) + "\u{1F600}" + "b".repeat(n - keep - 1);
    expect(v.length).toBe(n);
    const out = truncateField(v, CAP);
    expect(out).toBe("a".repeat(keep - 1) + truncationMarker(n));
    expect(LONE_SURROGATE.test(out)).toBe(false);
    expect(out.length).toBeLessThanOrEqual(CAP);
  });

  it("keeps a surrogate pair that ends exactly at the cut", () => {
    const n = 70_000;
    const keep = CAP - truncationMarker(n).length;
    const v = "a".repeat(keep - 2) + "\u{1F600}" + "b".repeat(n - keep);
    expect(v.length).toBe(n);
    const out = truncateField(v, CAP);
    expect(out).toBe("a".repeat(keep - 2) + "\u{1F600}" + truncationMarker(n));
    expect(out.length).toBe(CAP);
    expect(LONE_SURROGATE.test(out)).toBe(false);
  });

  it("never splits a surrogate pair at the cut of a 9,500 free-text cap either", () => {
    const cap = 9_500;
    const n = 20_000;
    const keep = cap - truncationMarker(n).length;
    const v = "a".repeat(keep - 1) + "\u{1F600}" + "b".repeat(n - keep - 1);
    const out = truncateField(v, cap);
    expect(out).toBe("a".repeat(keep - 1) + truncationMarker(n));
    expect(LONE_SURROGATE.test(out)).toBe(false);
  });

  it("a cap too small for the marker is a plain cut, still within the cap and well formed", () => {
    const out = truncateField("\u{1F600}".repeat(100), 21);
    expect(out.length).toBeLessThanOrEqual(21);
    expect(LONE_SURROGATE.test(out)).toBe(false);
  });

  it("stays well formed on a field made only of emoji", () => {
    const v = "\u{1F600}".repeat(60_000); // 120,000 code units
    const out = truncateField(v, CAP);
    expect(LONE_SURROGATE.test(out)).toBe(false);
    expect(out.length).toBeLessThanOrEqual(CAP);
    expect(out).toContain("original length 120000 chars");
  });
});

describe("capPayloadFields: one test per field", () => {
  for (const field of FIELDS) {
    const cap = INGEST_FIELD_LIMITS[field]!;
    it(`${field}: over ${cap} is truncated at the top level, nested and in arrays of objects`, () => {
      const big = "q".repeat(serverCap(field) + 1);
      const payload = {
        tool_name: "Bash",
        [field]: big,
        tool_response: { [field]: big, exit_code: 0 },
        list: [{ [field]: big }],
      };
      const out = capPayloadFields(payload) as typeof payload & Record<string, unknown>;
      const top = out[field] as string;
      expect(top.length).toBe(cap);
      expect(top.endsWith(`\n[agentreel: truncated, original length ${big.length} chars]`)).toBe(true);
      expect((out.tool_response[field] as string).length).toBe(cap);
      expect((out.list[0]![field] as string).length).toBe(cap);
      expect(out.tool_name).toBe("Bash");
      expect(out.tool_response.exit_code).toBe(0);
      // The input is not mutated.
      expect(payload[field]).toBe(big);
    });

    it(`${field}: a value at exactly ${cap} and a short value are untouched`, () => {
      const exact = "e".repeat(cap);
      const payload = { [field]: exact, nested: { [field]: "short" } };
      const out = capPayloadFields(payload);
      expect(out).toBe(payload); // same object: nothing to change
      expect((out as Record<string, string>)[field]).toBe(exact);
    });
  }

  it("caps any other key, and array elements, at the 9,500 default (the server's free-text default)", () => {
    const big = "y".repeat(12_000);
    const out = capPayloadFields({ command: big, content: big, nested: { note: big }, items: [big, "ok"] }) as {
      command: string; content: string; nested: { note: string }; items: string[];
    };
    for (const v of [out.command, out.content, out.nested.note, out.items[0]!]) {
      expect(v.length).toBe(9_500);
      expect(v).toContain("original length 12000 chars");
    }
    expect(out.items[1]).toBe("ok");
    const exact = "z".repeat(9_500);
    const same = { command: exact };
    expect(capPayloadFields(same)).toBe(same);
  });

  it("never truncates identifier, version and path keys", () => {
    const long = "p".repeat(20_000);
    const payload = { id: long, tool_use_id: long, file_path: long, cwd: long, repo: long, tool_name: long };
    expect(capPayloadFields(payload)).toBe(payload);
  });

  it("handles non-object payloads and an own __proto__ key", () => {
    expect(capPayloadFields("text")).toBe("text");
    expect(capPayloadFields(null)).toBeNull();
    expect(capPayloadFields(7)).toBe(7);
    const payload = JSON.parse(`{"__proto__":{"stdout":"${"s".repeat(70_000)}"}}`);
    const out = capPayloadFields(payload) as Record<string, unknown>;
    const own = Object.getOwnPropertyDescriptor(out, "__proto__")!.value as { stdout: string };
    expect(own.stdout.length).toBe(CAP);
    expect(Object.getPrototypeOf(out)).toBe(Object.prototype);
  });
});

describe("takePendingBatch applies the cap after the guard scan", () => {
  const T0 = 1_700_000_000_000;
  function seedEvent(sessionId: string, id: string, type: string, payload: unknown) {
    db.upsertSession({ id: sessionId, tool: "claude-code", startedAt: T0 } as never);
    db.insertEvent({ id, sessionId, tool: "claude-code", type, ts: T0, payload } as never);
  }

  for (const field of FIELDS) {
    it(`${field}: the uploaded event carries the truncated field`, () => {
      const sid = `cap-${field}`;
      const big = "w".repeat(serverCap(field) + 1);
      seedEvent(sid, `${sid}-e0`, "tool_use_post", { tool_name: "Bash", tool_response: { [field]: big } });
      const batch = queue.takePendingBatch(500, 10 * 1024 * 1024, Date.now());
      const ev = batch.events.find((e) => e.id === `${sid}-e0`)!;
      const value = (ev.payload as { tool_response: Record<string, string> }).tool_response[field]!;
      expect(value.length).toBe(INGEST_FIELD_LIMITS[field]);
      expect(value).toContain(`original length ${big.length} chars`);
    });
  }

  it("scans the full text first: a risky string past the cut is still found, but not uploaded", () => {
    const sid = "cap-scan-order";
    const stdout = "x".repeat(70_000) + " DROP TABLE users;";
    seedEvent(sid, `${sid}-e0`, "tool_use_post", { tool_name: "Bash", tool_response: { stdout } });
    const batch = queue.takePendingBatch(500, 10 * 1024 * 1024, Date.now());
    const session = batch.sessions.find((s) => s.id === sid)!;
    expect(session.guard_findings!.findings.some((f) => f.rule_id === "DB001")).toBe(true);
    const ev = batch.events.find((e) => e.id === `${sid}-e0`)!;
    const uploaded = (ev.payload as { tool_response: { stdout: string } }).tool_response.stdout;
    expect(uploaded.length).toBeLessThanOrEqual(CAP);
    expect(uploaded).not.toContain("DROP TABLE");
  });

  it("leaves an ordinary event byte for byte as stored", () => {
    const sid = "cap-ordinary";
    const payload = { tool_name: "Bash", tool_input: { command: "ls -la" }, tool_response: { stdout: "total 0\n", stderr: "" } };
    seedEvent(sid, `${sid}-e0`, "tool_use_post", payload);
    const batch = queue.takePendingBatch(500, 10 * 1024 * 1024, Date.now());
    const ev = batch.events.find((e) => e.id === `${sid}-e0`)!;
    expect(ev.payload).toEqual(payload);
  });
});

describe("capped payloads pass a mirror of the server's string check", () => {
  // Mirror of hasValidIngestStringLengths in apps/web/lib/govern/contract.ts
  // (agentreel/web main 55dac0a, lines 3324-3352), with the event payload
  // caps from lines 3300-3308 and the free-text caps from lines 3289-3297.
  // Identifier keys are left out: the CLI does not touch them.
  const serverCaps: Record<string, number> = { reason: 1_000 };
  for (const f of FREE_TEXT_FIELDS) serverCaps[f] = 10_000;
  for (const f of PAYLOAD_FIELDS) serverCaps[f] = 100_000;
  function serverAccepts(value: unknown, key?: string): boolean {
    if (typeof value === "string") {
      const cap = key !== undefined && Object.hasOwn(serverCaps, key) ? serverCaps[key]! : 10_000;
      return value.length <= cap;
    }
    if (value === null || typeof value !== "object") return true;
    if (Array.isArray(value)) return value.every((v) => serverAccepts(v, undefined));
    return Object.entries(value).every(([k, v]) => serverAccepts(v, k));
  }

  it("rejects the raw payload and accepts the capped one", () => {
    const huge = "h".repeat(250_000);
    const payload: Record<string, unknown> = {
      tool_name: "Bash",
      command: huge,
      content: huge,
      list: [huge],
      tool_response: { nested: { deep: huge } },
    };
    for (const f of FIELDS) payload[f] = huge;
    expect(serverAccepts(payload)).toBe(false);
    expect(serverAccepts(capPayloadFields(payload))).toBe(true);
  });
});
