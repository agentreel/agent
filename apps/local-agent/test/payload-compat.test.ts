import { describe, it, expect } from "vitest";

describe("Session Payload Backward Compatibility", () => {
  it("new client payload (with guard_findings) accepted by old server shape", () => {
    interface OldServerSession {
      id: string;
      tool: string;
      started_at: number;
      ended_at?: number | null;
      attribution?: unknown;
    }

    const newClientPayload = {
      id: "session-123",
      tool: "cursor",
      started_at: Date.now(),
      ended_at: Date.now() + 1000,
      attribution: { user: "test" },
      guard_findings: {
        version: 1,
        risk_score: 50,
        findings: [
          {
            rule_id: "FS001",
            severity: "critical",
            category: "filesystem-destruction",
            timestamp: Date.now(),
            evidence: "rm -rf ~/",
          },
        ],
      },
    };

    const oldServerShape: OldServerSession = {
      id: newClientPayload.id,
      tool: newClientPayload.tool,
      started_at: newClientPayload.started_at,
      ended_at: newClientPayload.ended_at,
      attribution: newClientPayload.attribution,
    };

    expect(oldServerShape.id).toBe("session-123");
    expect(oldServerShape.tool).toBe("cursor");
  });

  it("old client payload (no guard_findings) handled by new code", () => {
    interface NewClientSession {
      id: string;
      tool: string;
      started_at: number;
      ended_at?: number | null;
      attribution?: unknown;
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

    const oldClientPayload = {
      id: "session-456",
      tool: "claude-code",
      started_at: Date.now(),
      ended_at: Date.now() + 1000,
      attribution: { user: "test" },
    };

    const newCodeShape: NewClientSession = oldClientPayload;

    expect(newCodeShape.id).toBe("session-456");
    expect(newCodeShape.guard_findings).toBeUndefined();
    expect(newCodeShape.tool).toBe("claude-code");
  });

  it("guard_findings field is optional and additive", () => {
    type IngestSession = {
      id: string;
      tool: string;
      started_at: number;
      guard_findings?: {
        version: number;
        risk_score: number;
        findings: unknown[];
      };
    };

    const withoutFindings: IngestSession = {
      id: "a",
      tool: "cursor",
      started_at: 1,
    };

    const withFindings: IngestSession = {
      id: "b",
      tool: "cursor",
      started_at: 2,
      guard_findings: {
        version: 1,
        risk_score: 80,
        findings: [],
      },
    };

    expect(() => JSON.stringify(withoutFindings)).not.toThrow();
    expect(() => JSON.stringify(withFindings)).not.toThrow();
    
    const parsed1 = JSON.parse(JSON.stringify(withoutFindings));
    const parsed2 = JSON.parse(JSON.stringify(withFindings));
    
    expect(parsed1.guard_findings).toBeUndefined();
    expect(parsed2.guard_findings.version).toBe(1);
  });
});
