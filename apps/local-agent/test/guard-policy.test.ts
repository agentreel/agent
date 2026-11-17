import { describe, it, expect } from "vitest";
import { readGuardConfig } from "../src/guard/config.js";
import { scanSession } from "../src/guard/scanner.js";
import type { AgentEvent } from "@agentreel/shared-types";

describe("Guard Policy Mode", () => {
  it("default config has block mode disabled (observe-only)", () => {
    const config = readGuardConfig();
    
    expect(config.policyMode).toBe("warn");
    expect(config.policyMode).not.toBe("block");
  });

  it("scanning with no config never blocks or exits non-zero", () => {
    const dangerousEvents: AgentEvent[] = [
      {
        id: "evt1",
        sessionId: "sess1",
        tool: "cursor",
        type: "shell",
        ts: Date.now(),
        payload: { command: "rm -rf ~/Documents", exitCode: 0 },
      },
      {
        id: "evt2",
        sessionId: "sess1",
        tool: "cursor",
        type: "shell",
        ts: Date.now(),
        payload: { command: "DROP TABLE users", exitCode: 0 },
      },
    ];

    const sessionMeta = {
      id: "sess1",
      tool: "cursor" as const,
      startedAt: Date.now(),
    };

    // Should not throw or block
    expect(() => {
      const result = scanSession("sess1", dangerousEvents, sessionMeta);
      
      // Should return findings without blocking
      expect(result.findings.length).toBeGreaterThan(0);
      expect(result.riskScore).toBeGreaterThan(0);
    }).not.toThrow();
  });

  it("scanning returns findings but never prevents execution", () => {
    const config = readGuardConfig();
    
    // Even if somehow set to block, current implementation never blocks
    expect(config.policyMode).toBe("warn");
    
    const event: AgentEvent = {
      id: "evt1",
      sessionId: "sess1",
      tool: "cursor",
      type: "shell",
      ts: Date.now(),
      payload: { command: "git push --force origin main", exitCode: 0 },
    };

    const result = scanSession("sess1", [event], {
      id: "sess1",
      tool: "cursor",
      startedAt: Date.now(),
    });

    // Findings detected but execution not prevented
    expect(result.findings.length).toBeGreaterThan(0);
    // Scanner always returns results, never throws
  });
});
