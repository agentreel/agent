import { nanoid } from "nanoid";
import { insertEvent, upsertSession } from "../db.js";
import type { AgentEvent } from "@agentreel/shared-types";
import type { SnapshotEvent } from "./watcher.js";

const IDLE_MS = 5 * 60 * 1000; // 5 minute gap = new session
const GLOBAL_KEY = "__global__";

interface OpenSession {
  id: string;
  startedAt: number;
  lastTs: number;
  cwd: string;
}

export class CursorSessionManager {
  private open = new Map<string, OpenSession>();

  ingest(snapshot: SnapshotEvent): { sessionId: string; isNew: boolean } {
    const key = snapshot.workspace ?? GLOBAL_KEY;
    const ts = snapshot.timestamp;
    const cwd = snapshot.workspace ?? "";

    let session = this.open.get(key);
    let isNew = false;
    if (!session || ts - session.lastTs > IDLE_MS) {
      // Close out the previous session for this key, if any.
      if (session) this.closeSession(session, session.lastTs);
      session = {
        id: `cur_${nanoid(10)}`,
        startedAt: ts,
        lastTs: ts,
        cwd,
      };
      this.open.set(key, session);
      isNew = true;
      upsertSession({
        id: session.id,
        tool: "cursor",
        startedAt: ts,
        cwd,
      });
    } else {
      session.lastTs = ts;
    }

    const event: AgentEvent = {
      id: nanoid(),
      sessionId: session.id,
      tool: "cursor",
      type: "tool_use_post",
      ts,
      cwd,
      payload: {
        tool_name: "Edit",
        file_path: snapshot.filePath,
        added: snapshot.added,
        removed: snapshot.removed,
        binary: snapshot.binary,
        source: snapshot.source,
        patch: snapshot.patch,
      },
    };
    insertEvent(event);
    return { sessionId: session.id, isNew };
  }

  /** Stamp ended_at on every open session — call on shutdown. */
  closeAll(): void {
    const now = Date.now();
    for (const s of this.open.values()) this.closeSession(s, Math.max(s.lastTs, now));
    this.open.clear();
  }

  private closeSession(s: OpenSession, endedAt: number) {
    upsertSession({
      id: s.id,
      tool: "cursor",
      startedAt: s.startedAt,
      endedAt,
      cwd: s.cwd,
    });
  }
}
