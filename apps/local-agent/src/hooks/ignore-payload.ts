import { isAbsolute, resolve } from "node:path";
import { isIgnored } from "../redact/ignore.js";

export const IGNORED_MARK = "[IGNORED:.agentreelignore]";

/** Fields that can carry file contents in Claude Code tool inputs. */
const CONTENT_KEYS = ["content", "old_string", "new_string", "new_source", "edits"] as const;

interface HookLike {
  cwd?: string;
  tool_input?: Record<string, unknown>;
  tool_response?: unknown;
}

/**
 * Honor `.agentreelignore` for Claude Code tool calls. If the tool targets
 * an ignored path, keep the event (the timeline still shows that the file
 * was touched) but drop everything that could contain its contents: the
 * edit strings, written content, and the tool's response (e.g. Read output).
 */
export function applyIgnoreRules<T extends HookLike>(input: T): T {
  const ti = input.tool_input;
  if (!ti || typeof ti !== "object") return input;
  const raw = [ti.file_path, ti.notebook_path, ti.path].find((v): v is string => typeof v === "string" && v.length > 0);
  if (!raw || !input.cwd) return input;
  const abs = isAbsolute(raw) ? raw : resolve(input.cwd, raw);
  if (!isIgnored(input.cwd, abs)) return input;
  const cleaned: Record<string, unknown> = { ...ti, ignored: true };
  for (const k of CONTENT_KEYS) if (k in cleaned) cleaned[k] = IGNORED_MARK;
  return {
    ...input,
    tool_input: cleaned,
    ...(input.tool_response !== undefined ? { tool_response: { ignored: true } } : {}),
  };
}
