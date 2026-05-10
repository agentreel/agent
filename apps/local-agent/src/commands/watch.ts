import pc from "picocolors";
import { existsSync } from "node:fs";
import { basename } from "node:path";
import { cursorHistoryDir } from "../cursor/paths.js";
import { startCursorWatcher } from "../cursor/watcher.js";
import { CursorSessionManager } from "../cursor/session.js";
import { ensureAgentreelDir } from "../paths.js";
import { getDb } from "../db.js";

export async function watchCommand(): Promise<void> {
  ensureAgentreelDir();
  // Touch DB so the schema exists.
  getDb();

  const dir = cursorHistoryDir();
  if (!existsSync(dir)) {
    console.error(pc.red("✗ Cursor history directory not found:"));
    console.error("  " + dir);
    console.error();
    console.error(pc.dim("Open Cursor at least once, edit a file, then re-run."));
    console.error(pc.dim("(Or set AGENTREEL_CURSOR_HISTORY_DIR to a custom path.)"));
    process.exit(1);
  }

  console.log(pc.bold(pc.cyan("AgentReel · Cursor watcher\n")));
  console.log(pc.dim("  watching ") + dir);
  console.log(pc.dim("  press Ctrl+C to stop\n"));

  const sessions = new CursorSessionManager();

  const watcher = startCursorWatcher(dir, async (snap) => {
    const { sessionId, isNew } = sessions.ingest(snap);
    const ts = new Date(snap.timestamp).toLocaleTimeString();
    const ws = snap.workspace ? basename(snap.workspace) : pc.dim("no-workspace");
    const file = snap.filePath.split("/").slice(-2).join("/");
    const sourceLabel =
      snap.source === "cursor-ai"
        ? pc.magenta("ai")
        : snap.source === "cursor-manual"
          ? pc.cyan("man")
          : pc.dim("?");
    const stats = snap.binary
      ? pc.dim("binary")
      : `${pc.green("+" + snap.added)} ${pc.red("-" + snap.removed)}`;
    if (isNew) {
      console.log(
        `${pc.dim(ts)}  ${pc.yellow("session")}  ${pc.dim(sessionId)}  ${ws}`,
      );
    }
    console.log(`${pc.dim(ts)}  edit     ${sourceLabel}  ${file.padEnd(36)}  ${stats}`);
  });

  // Graceful shutdown — flush sessions, close watcher.
  const shutdown = async () => {
    console.log(pc.dim("\n  closing sessions…"));
    sessions.closeAll();
    await watcher.close();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}
