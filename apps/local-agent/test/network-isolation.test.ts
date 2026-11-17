import { describe, it, expect } from "vitest";
import { scanSession } from "../src/guard/scanner.js";
import type { AgentEvent } from "@agentreel/shared-types";

describe("AgentReel Guard Network Isolation", () => {
  it("scanSession is synchronous and deterministic", () => {
    const events: AgentEvent[] = [
      {
        id: "evt1",
        sessionId: "sess1",
        tool: "cursor",
        type: "tool_use_pre",
        ts: Date.now(),
        payload: { command: "rm -rf ~/" },
      },
      {
        id: "evt2",
        sessionId: "sess1",
        tool: "cursor",
        type: "tool_use_post",
        ts: Date.now(),
        payload: { result: "deleted" },
      },
      {
        id: "evt3",
        sessionId: "sess1",
        tool: "cursor",
        type: "tool_use_pre",
        ts: Date.now(),
        payload: { command: "DROP TABLE users" },
      },
    ];

    const summary1 = scanSession("sess1", events);
    const summary2 = scanSession("sess1", events);

    expect(summary1.findings.length).toBeGreaterThan(0);
    
    expect(summary1.findings.length).toBe(summary2.findings.length);
    expect(summary1.riskScore).toBe(summary2.riskScore);

    expect(summary1.findings[0]?.ruleId).toBe(summary2.findings[0]?.ruleId);
  });

  it("scanning does not require async operations", () => {
    const events: AgentEvent[] = [
      {
        id: "evt-1",
        sessionId: "sess-1",
        tool: "claude-code",
        type: "tool_use_pre",
        ts: Date.now(),
        payload: { command: "terraform destroy" },
      },
    ];

    const start = Date.now();
    const summary = scanSession("sess-1", events);
    const duration = Date.now() - start;

    expect(summary.findings.length).toBeGreaterThan(0);
    
    expect(duration).toBeLessThan(100);
  });
});
