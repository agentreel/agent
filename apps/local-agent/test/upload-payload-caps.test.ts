import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  INGEST_FIELD_LIMITS,
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
const FIELDS = ["prompt", "output", "patch", "stdout", "stderr", "contents"] as const;
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

describe("INGEST_FIELD_LIMITS", () => {
  it("is one map covering exactly the six big fields at 64,000", () => {
    expect(Object.keys(INGEST_FIELD_LIMITS).sort()).toEqual([...FIELDS].sort());
    for (const f of FIELDS) expect(INGEST_FIELD_LIMITS[f]).toBe(CAP);
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
    it(`${field}: over the cap is truncated at the top level and nested, other fields untouched`, () => {
      const big = "q".repeat(100_001);
      const payload = {
        tool_name: "Bash",
        command: "ls",
        [field]: big,
        tool_response: { [field]: big, exit_code: 0 },
        list: [{ [field]: big }],
      };
      const out = capPayloadFields(payload) as typeof payload & Record<string, unknown>;
      const top = out[field] as string;
      expect(top.length).toBe(CAP);
      expect(top.endsWith("\n[agentreel: truncated, original length 100001 chars]")).toBe(true);
      expect((out.tool_response[field] as string).length).toBe(CAP);
      expect((out.list[0]![field] as string).length).toBe(CAP);
      expect(out.tool_name).toBe("Bash");
      expect(out.command).toBe("ls");
      expect(out.tool_response.exit_code).toBe(0);
      // The input is not mutated.
      expect(payload[field]).toBe(big);
    });

    it(`${field}: a value at exactly the cap and a short value are untouched`, () => {
      const exact = "e".repeat(CAP);
      const payload = { [field]: exact, nested: { [field]: "short" } };
      const out = capPayloadFields(payload);
      expect(out).toBe(payload); // same object: nothing to change
      expect((out as Record<string, string>)[field]).toBe(exact);
    });
  }

  it("does not touch long strings under other keys", () => {
    const big = "y".repeat(120_000);
    const payload = { command: big, content: big, note: big };
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
      const big = "w".repeat(100_001);
      seedEvent(sid, `${sid}-e0`, "tool_use_post", { tool_name: "Bash", tool_response: { [field]: big } });
      const batch = queue.takePendingBatch(500, 10 * 1024 * 1024, Date.now());
      const ev = batch.events.find((e) => e.id === `${sid}-e0`)!;
      const value = (ev.payload as { tool_response: Record<string, string> }).tool_response[field]!;
      expect(value.length).toBe(CAP);
      expect(value).toContain("original length 100001 chars");
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
