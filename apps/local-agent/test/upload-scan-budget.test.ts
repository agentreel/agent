import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { AgentEvent } from "@agentreel/shared-types";
import { RULES } from "../src/guard/rules.js";
import {
  SCAN_BATCH_BUDGET_MS,
  SCAN_BUDGET_REASON,
  ScanBudget,
  scanSession,
} from "../src/guard/scanner.js";
import type { Rule } from "../src/guard/types.js";

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

function bash(command: string, id: string): AgentEvent {
  return {
    id,
    sessionId: "s1",
    tool: "claude-code",
    type: "tool_use_pre",
    ts: 1,
    payload: { tool_name: "Bash", tool_input: { command } },
  };
}

/** A clock that advances by `step` every time it is read. */
function steppingClock(step: number): () => number {
  let t = 0;
  return () => {
    const now = t;
    t += step;
    return now;
  };
}

const ENABLED = RULES.filter((r) => r.enabled).length;

describe("ScanBudget", () => {
  it("defaults to 1500ms and counts down on the injected clock", () => {
    expect(SCAN_BATCH_BUDGET_MS).toBe(1500);
    let now = 5;
    const b = new ScanBudget(1000, () => now);
    expect(b.totalMs).toBe(1000);
    expect(b.remainingMs()).toBe(1000);
    expect(b.exhausted).toBe(false);
    now = 600;
    expect(b.remainingMs()).toBe(405);
    now = 1005;
    expect(b.remainingMs()).toBe(0);
    expect(b.exhausted).toBe(true);
  });
});

describe("scanSession with a batch budget", () => {
  it("scans everything and adds no findings while the budget lasts", () => {
    const budget = new ScanBudget(1000, () => 0);
    const events = [bash("ls", "e1"), bash("git status", "e2")];
    const withBudget = scanSession("s1", events, undefined, { budget });
    const without = scanSession("s1", events);
    expect(withBudget.findings.map((f) => f.ruleId)).toEqual(without.findings.map((f) => f.ruleId));
    expect(withBudget.unscannedEvents).toBeUndefined();
    expect(budget.unscannedEvents).toBe(0);
    expect(withBudget.summary).toMatch(/Session clean/);
  });

  it("an exhausted budget fails every enabled rule closed, never clean", () => {
    const budget = new ScanBudget(0, () => 0);
    const events = [bash("ls", "e1"), bash("echo hi", "e2"), bash("pwd", "e3")];
    const s = scanSession("s1", events, undefined, { budget });
    expect(s.unscannedEvents).toBe(3);
    expect(s.findings).toHaveLength(ENABLED);
    expect(s.findings.every((f) => f.reason === SCAN_BUDGET_REASON)).toBe(true);
    expect(s.findings.find((f) => f.ruleId === "GIT001")?.severity).toBe("high");
    expect(s.riskScore).toBeGreaterThan(0);
    expect(s.summary).not.toMatch(/Session clean/);
    expect(s.findings[0]!.evidence).toMatch(
      /^scan_budget_exceeded: 3 event\(s\) not scanned within the 0ms batch scan budget; counted as a match$/,
    );
    // No command text in the evidence or context.
    expect(JSON.stringify(s.findings)).not.toContain("echo hi");
    expect(budget.unscannedEvents).toBe(3);
    expect(budget.unscannedSessions).toBe(1);
  });

  it("keeps real results for events scanned before the budget ran out", () => {
    // Clock steps 400ms per read: construction reads 0, then events see
    // 600, 200 and then no time left.
    const budget = new ScanBudget(1000, steppingClock(400));
    const events = [
      bash("git push --force origin main", "e1"),
      bash("ls", "e2"),
      bash("echo three", "e3"),
      bash("echo four", "e4"),
      bash("echo five", "e5"),
    ];
    const s = scanSession("s1", events, undefined, { budget });
    expect(s.unscannedEvents).toBe(3);
    const real = s.findings.filter((f) => f.reason === undefined);
    expect(real.map((f) => f.ruleId)).toContain("GIT001");
    const failed = s.findings.filter((f) => f.reason === SCAN_BUDGET_REASON);
    expect(failed).toHaveLength(ENABLED);
    expect(failed[0]!.evidence).toContain("3 event(s) not scanned");
  });

  it("one finding per rule, not per event, however many events are skipped", () => {
    const budget = new ScanBudget(0, () => 0);
    const events = Array.from({ length: 500 }, (_, i) => bash(`echo ${i}`, `e${i}`));
    const s = scanSession("s1", events, undefined, { budget });
    expect(s.unscannedEvents).toBe(500);
    expect(s.findings).toHaveLength(ENABLED);
  });

  it("the budget is shared across sessions", () => {
    const budget = new ScanBudget(0, () => 0);
    const a = scanSession("a", [bash("ls", "a1")], undefined, { budget });
    const b = scanSession("b", [bash("ls", "b1"), bash("pwd", "b2")], undefined, { budget });
    expect(a.unscannedEvents).toBe(1);
    expect(b.unscannedEvents).toBe(2);
    expect(budget.unscannedEvents).toBe(3);
    expect(budget.unscannedSessions).toBe(2);
  });

  it("caps an event's own deadline at what is left of the budget", () => {
    const spin: Rule = {
      id: "SLOW", version: 1, severity: "high", category: "safety-bypass",
      name: "SLOW", description: "SLOW", rationale: "SLOW", enabled: true,
      matcher: {
        type: "command",
        customMatcher: () => {
          const end = Date.now() + 3000;
          while (Date.now() < end) { /* busy */ }
          return false;
        },
      },
    };
    // Real clock, 15ms budget. The event's own deadline would be about 50ms.
    const budget = new ScanBudget(15);
    const t0 = performance.now();
    const s = scanSession("s1", [bash("echo hi", "e1")], undefined, {
      budget,
      rules: [spin],
      log: () => {},
    });
    const ms = performance.now() - t0;
    expect(ms).toBeLessThan(45);
    expect(s.timedOut).toBe(true);
    expect(s.findings[0]).toMatchObject({ ruleId: "SLOW", reason: "scan_timeout" });
  });

  it("honors rule overrides and the command allowlist for fail-closed findings", async () => {
    const { writeGuardConfig, readGuardConfig } = await import("../src/guard/config.js");
    const { ensureAgentreelDir } = await import("../src/paths.js");
    ensureAgentreelDir();
    const base = readGuardConfig();
    writeGuardConfig({
      ...base,
      rules: { ...base.rules, GIT001: { enabled: true, severity: "critical" }, FS001: { enabled: false } },
      allowlists: { ...base.allowlists, commands: ["make deploy"] },
    });
    try {
      const flagged = scanSession("s1", [bash("echo hi", "e1")], undefined, { budget: new ScanBudget(0, () => 0) });
      expect(flagged.findings.find((f) => f.ruleId === "GIT001")?.severity).toBe("critical");
      expect(flagged.findings.some((f) => f.ruleId === "FS001")).toBe(false);
      const allowed = scanSession("s1", [bash("make deploy", "e1")], undefined, { budget: new ScanBudget(0, () => 0) });
      expect(allowed.findings).toEqual([]);
    } finally {
      writeGuardConfig(base);
    }
  });
});

describe("takePendingBatch scan budget", () => {
  const T0 = 1_700_000_000_000;
  function seed(sessionId: string, n: number, payload: (i: number) => unknown) {
    db.upsertSession({ id: sessionId, tool: "claude-code", startedAt: T0 } as never);
    for (let i = 0; i < n; i++) {
      db.insertEvent({
        id: `${sessionId}-e${i}`,
        sessionId,
        tool: "claude-code",
        type: "tool_use_pre",
        ts: T0 + i,
        payload: payload(i),
      } as never);
    }
  }

  it("bounds one flush of crafted events and fails the unscanned ones closed", () => {
    // "file:" repeated is slow in the blast-radius stats pass (about 80ms per
    // 32KB event, hit at its own deadline), which is what 3b1145b took 2.7s
    // on for 32 events. 40 of them under a 300ms batch budget.
    const crafted = "file:".repeat(6_000); // 30KB
    seed("crafted", 40, () => ({ tool_name: "Bash", tool_input: { command: "ls" }, note: crafted }));
    const lines: string[] = [];
    const budget = new ScanBudget(300);
    const t0 = performance.now();
    const batch = queue.takePendingBatch(500, 10 * 1024 * 1024, Date.now(), {
      scanBudget: budget,
      scanLog: (m) => lines.push(m),
    });
    const ms = performance.now() - t0;
    // 40 events x ~80ms would be 3s without a batch budget.
    expect(ms).toBeLessThan(1000);
    expect(batch.events).toHaveLength(40); // nothing dropped, still uploaded
    expect(budget.unscannedEvents).toBeGreaterThan(0);

    const session = batch.sessions.find((s) => s.id === "crafted")!;
    const findings = session.guard_findings!.findings;
    expect(findings.length).toBeGreaterThan(0);
    expect(session.guard_findings!.risk_score).toBeGreaterThan(0);
    const failed = findings.filter((f) => f.evidence.startsWith("scan_budget_exceeded:"));
    expect(failed).toHaveLength(ENABLED);
    expect(failed[0]!.evidence).toContain("batch scan budget");

    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatch(/^scan_budget_exceeded: batch scan budget of 300ms used up; \d+ event\(s\) in 1 session\(s\) were not scanned and are counted as findings$/);
  });

  it("fails the whole batch closed when the budget is already spent, across sessions", () => {
    seed("sess-a", 2, (i) => ({ tool_name: "Bash", tool_input: { command: `echo a${i}` } }));
    seed("sess-b", 3, (i) => ({ tool_name: "Bash", tool_input: { command: `echo b${i}` } }));
    const lines: string[] = [];
    const budget = new ScanBudget(0, () => 0);
    const batch = queue.takePendingBatch(500, 10 * 1024 * 1024, Date.now(), {
      scanBudget: budget,
      scanLog: (m) => lines.push(m),
    });
    for (const id of ["sess-a", "sess-b"]) {
      const findings = batch.sessions.find((s) => s.id === id)!.guard_findings!.findings;
      expect(findings.length).toBeGreaterThanOrEqual(ENABLED);
      expect(findings.some((f) => f.evidence.startsWith("scan_budget_exceeded:"))).toBe(true);
    }
    expect(lines).toHaveLength(1);
    expect(lines[0]).toContain("in 3 session(s)"); // crafted, sess-a, sess-b all still pending
  });

  it("logs nothing and adds nothing for an ordinary batch under the default budget", () => {
    db.upsertSession({ id: "plain", tool: "claude-code", startedAt: T0 } as never);
    db.insertEvent({
      id: "plain-e0", sessionId: "plain", tool: "claude-code", type: "tool_use_pre", ts: T0,
      payload: { tool_name: "Bash", tool_input: { command: "ls" } },
    } as never);
    queue.markUploaded(
      (db.getDb().prepare("SELECT id FROM events WHERE session_id != 'plain'").all() as Array<{ id: string }>).map((r) => r.id),
    );
    const lines: string[] = [];
    const batch = queue.takePendingBatch(500, 10 * 1024 * 1024, Date.now(), { scanLog: (m) => lines.push(m) });
    expect(batch.sessions.map((s) => s.id)).toEqual(["plain"]);
    expect(batch.sessions[0]!.guard_findings!.findings).toEqual([]);
    expect(lines).toEqual([]);
  });
});
