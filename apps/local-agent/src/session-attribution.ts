import {
  collectAttribution,
  collectGit,
  gitHead,
  mergeAttribution,
  type Attribution,
  type CollectOptions,
} from "./attribution.js";
import { getSessionAttribution, setSessionAttribution } from "./db.js";

/** Take the who/where snapshot the first time we see a session. */
export function ensureSessionAttribution(
  sessionId: string,
  input: Omit<CollectOptions, "toolVersion"> & { toolVersion?: string | (() => string | undefined) },
): void {
  const existing = getSessionAttribution<Attribution>(sessionId);
  // Version lookups can read a file; only do it when we still need one.
  const needVersion = !existing?.agent?.version;
  const toolVersion =
    typeof input.toolVersion === "function" ? (needVersion ? input.toolVersion() : undefined) : input.toolVersion;
  const opts: CollectOptions = { ...input, toolVersion };
  if (existing) {
    // Fill in an agent version / model we didn't know at the first event.
    const a = existing.agent;
    if ((opts.toolVersion && !a?.version) || (opts.model && !a?.model)) {
      setSessionAttribution(
        sessionId,
        mergeAttribution(existing, { agent: { tool: opts.tool, version: opts.toolVersion, model: opts.model } }),
      );
    }
    return;
  }
  const snap = collectAttribution(opts);
  if (snap) setSessionAttribution(sessionId, snap);
}

/** Record branch + HEAD at the end of a turn / session. */
export function recordSessionEndGit(sessionId: string, cwd: string | undefined): void {
  const base = getSessionAttribution<Attribution>(sessionId);
  if (!base) return;
  const { branch, head } = gitHead(base.git?.root ?? cwd);
  if (!head) return;
  setSessionAttribution(sessionId, mergeAttribution(base, { git: { branch_end: branch, head_end: head } }));
}

/**
 * Attribution for a pre-exec policy check. Reads the stored snapshot, and when
 * there is none yet (first event of a session) or the DB can't be read,
 * collects git info in memory. It never writes, so the policy check can run
 * before any DB write and still apply repo and branch scoped rules.
 */
export function preExecAttribution(sessionId: string, cwd: string | undefined): Attribution | null {
  try {
    const stored = getSessionAttribution<Attribution>(sessionId);
    if (stored) return stored;
  } catch {
    // Corrupt or unusable sessions.db: fall through to the live snapshot.
  }
  try {
    const git = collectGit(cwd);
    return git ? { v: 1, git } : null;
  } catch {
    return null;
  }
}
