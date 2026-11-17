export type Severity = "info" | "warn" | "high" | "critical";

export type Category =
  | "filesystem-destruction"
  | "database-destruction"
  | "cloud-destruction"
  | "production-targeting"
  | "secret-exfiltration"
  | "git-tampering"
  | "safety-bypass"
  | "risky-install"
  | "prompt-injection"
  | "multi-step-attack";

export interface RuleMatcher {
  type: "command" | "db-operation" | "url-pattern" | "sequence" | "content-pattern";
  pattern?: RegExp | string;
  patterns?: Array<RegExp | string>;
  sequenceWindow?: number;
  customMatcher?: (context: MatchContext) => boolean;
}

export interface Rule {
  id: string;
  version: number;
  severity: Severity;
  category: Category;
  name: string;
  description: string;
  rationale: string;
  matcher: RuleMatcher;
  enabled: boolean;
}

export interface MatchContext {
  command?: string;
  cwd?: string;
  payload?: unknown;
  type?: string;
  recentEvents?: Array<{
    type: string;
    ts: number;
    payload: unknown;
  }>;
}

export interface Finding {
  ruleId: string;
  severity: Severity;
  category: Category;
  timestamp: number;
  evidence: string;
  context?: {
    command?: string;
    file?: string;
    location?: string;
  };
}

export interface SessionSummary {
  sessionId: string;
  tool: string;
  startedAt: number;
  endedAt?: number;
  findings: Finding[];
  riskScore: number;
  blastRadius: {
    filesAccessed: number;
    commandsExecuted: number;
    hostsContacted: string[];
    criticalPaths: string[];
  };
  summary: string;
}

export interface GuardConfig {
  enabled: boolean;
  policyMode: "warn" | "block" | "off";
  rules: {
    [ruleId: string]: {
      enabled: boolean;
      severity?: Severity;
    };
  };
  allowlists: {
    commands?: string[];
    paths?: string[];
    hosts?: string[];
  };
}

export interface RuleFixture {
  description: string;
  shouldMatch: boolean;
  context: MatchContext;
}
