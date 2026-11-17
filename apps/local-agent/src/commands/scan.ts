import { getDb, listRecentSessions } from "../db.js";
import type { AgentEvent } from "@agentreel/shared-types";
import { scanSession } from "../guard/scanner.js";
import pc from "picocolors";
import { readGuardConfig } from "../guard/config.js";

export async function scanCommand(args: string[]): Promise<void> {
  const config = readGuardConfig();

  if (!config.enabled) {
    console.log(
      pc.yellow("⚠ AgentReel Guard is disabled in config. Enable it to scan sessions.")
    );
    return;
  }

  let sessionId: string;

  if (args.length > 0) {
    sessionId = args[0]!;
  } else {
    const recent = listRecentSessions(1);
    if (recent.length === 0) {
      console.log(pc.red("No sessions found. Run some agent commands first."));
      return;
    }
    sessionId = recent[0]!.id;
    console.log(
      pc.dim(`No session ID provided, scanning most recent: ${sessionId}`)
    );
  }

  const db = getDb();
  const session = db
    .prepare("SELECT * FROM sessions WHERE id = ?")
    .get(sessionId) as
    | {
        id: string;
        tool: string;
        started_at: number;
        ended_at?: number;
        cwd?: string;
      }
    | undefined;

  if (!session) {
    console.log(pc.red(`Session not found: ${sessionId}`));
    return;
  }

  const events = db
    .prepare(
      "SELECT id, session_id, tool, type, ts, cwd, payload FROM events WHERE session_id = ? ORDER BY ts ASC"
    )
    .all(sessionId) as Array<{
    id: string;
    session_id: string;
    tool: string;
    type: string;
    ts: number;
    cwd?: string;
    payload: string;
  }>;

  const parsedEvents: AgentEvent[] = events.map((e) => ({
    id: e.id,
    sessionId: e.session_id,
    tool: e.tool as "claude-code" | "cursor",
    type: e.type as AgentEvent["type"],
    ts: e.ts,
    cwd: e.cwd,
    payload: JSON.parse(e.payload),
  }));

  console.log(
    pc.bold(
      `\n🔍 AgentReel Guard: Scanning session ${sessionId.slice(0, 8)}...\n`
    )
  );
  console.log(
    pc.dim(
      `Tool: ${session.tool} | Events: ${parsedEvents.length} | Started: ${new Date(session.started_at).toLocaleString()}\n`
    )
  );

  const summary = scanSession(sessionId, parsedEvents, {
    id: session.id,
    tool: session.tool as "claude-code" | "cursor",
    startedAt: session.started_at,
    endedAt: session.ended_at,
    cwd: session.cwd,
  });

  printSummary(summary);
}

function printSummary(summary: ReturnType<typeof scanSession>): void {
  const { findings, riskScore, blastRadius } = summary;

  if (findings.length === 0) {
    console.log(
      pc.green("✓ No risky patterns detected. Session appears safe.\n")
    );
    console.log(pc.dim(`Risk Score: ${riskScore}/100`));
    console.log(
      pc.dim(
        `Blast Radius: ${blastRadius.commandsExecuted} commands, ${blastRadius.filesAccessed} files accessed\n`
      )
    );
    return;
  }

  const critical = findings.filter((f) => f.severity === "critical");
  const high = findings.filter((f) => f.severity === "high");
  const warn = findings.filter((f) => f.severity === "warn");
  const info = findings.filter((f) => f.severity === "info");

  if (critical.length > 0) {
    console.log(
      pc.red(pc.bold(`🚨 ${critical.length} CRITICAL findings:\n`))
    );
    for (const f of critical) {
      printFinding(f, "critical");
    }
  }

  if (high.length > 0) {
    console.log(pc.red(pc.bold(`⚠️  ${high.length} HIGH severity findings:\n`)));
    for (const f of high) {
      printFinding(f, "high");
    }
  }

  if (warn.length > 0) {
    console.log(pc.yellow(`⚠  ${warn.length} warnings:\n`));
    for (const f of warn) {
      printFinding(f, "warn");
    }
  }

  if (info.length > 0) {
    console.log(pc.blue(`ℹ  ${info.length} informational:\n`));
    for (const f of info) {
      printFinding(f, "info");
    }
  }

  console.log(pc.bold(`\n📊 Summary:`));
  console.log(`  Risk Score: ${riskScore >= 50 ? pc.red(riskScore) : pc.yellow(riskScore)}/100`);
  console.log(
    `  Blast Radius: ${blastRadius.commandsExecuted} commands, ${blastRadius.filesAccessed} files`
  );
  if (blastRadius.hostsContacted.length > 0) {
    console.log(
      `  Network: ${blastRadius.hostsContacted.length} external hosts contacted`
    );
  }
  if (blastRadius.criticalPaths.length > 0) {
    console.log(
      pc.red(
        `  Critical paths accessed: ${blastRadius.criticalPaths.slice(0, 3).join(", ")}${blastRadius.criticalPaths.length > 3 ? "..." : ""}`
      )
    );
  }

  console.log(pc.dim(`\n${summary.summary}\n`));

  if (riskScore >= 50) {
    console.log(
      pc.red(
        pc.bold(
          "⚠️  HIGH RISK SESSION. Review the findings above and consider restoring from backup if damage occurred.\n"
        )
      )
    );
  }
}

function printFinding(
  finding: ReturnType<typeof scanSession>["findings"][number],
  severity: "critical" | "high" | "warn" | "info"
): void {
  const icons = {
    critical: "🚨",
    high: "⚠️ ",
    warn: "⚠ ",
    info: "ℹ ",
  };

  const colors = {
    critical: pc.red,
    high: pc.red,
    warn: pc.yellow,
    info: pc.blue,
  };

  const color = colors[severity];

  console.log(
    color(
      `  ${icons[severity]} [${finding.ruleId}] ${finding.category.toUpperCase()}`
    )
  );
  console.log(pc.dim(`     ${finding.evidence.slice(0, 100)}${finding.evidence.length > 100 ? "..." : ""}`));
  if (finding.context?.location) {
    console.log(pc.dim(`     Location: ${finding.context.location}`));
  }
  console.log();
}
