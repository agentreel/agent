import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { basename } from "node:path";

/**
 * Two ways to tell that `agentreel managed install` is being run by an AI agent
 * instead of a person.
 *
 * 1. Environment markers (CLAUDECODE and friends). `sudo` clears these by default,
 *    so on their own they are easy to get around.
 * 2. Process ancestry. `sudo` cannot hide who its parent is: walk the parent PIDs
 *    and refuse if an ancestor is a Claude Code or Cursor agent process, or if
 *    an ancestor's own environment (which `sudo` did not clear) carries a marker.
 *
 * Reading ancestry is best effort. A read that fails returns what was found so far
 * and never throws, and the caller falls back to the TTY check.
 */

/** Environment variables that mean we are running inside an agent's tool call. */
export function agentSessionMarker(env: NodeJS.ProcessEnv): string | null {
  if (env.CLAUDECODE === "1") return "CLAUDECODE";
  if (env.CLAUDE_CODE_CHILD_SESSION === "1") return "CLAUDE_CODE_CHILD_SESSION";
  if (env.CURSOR_AGENT) return "CURSOR_AGENT";
  return null;
}

export const AGENT_ENV_KEYS = ["CLAUDECODE", "CLAUDE_CODE_CHILD_SESSION", "CURSOR_AGENT"] as const;

export interface AncestorProcess {
  pid: number;
  /** Process name as the OS reports it (Linux comm, macOS comm which may be a path). */
  comm: string;
  /** Full argument list when it could be read (Linux only). */
  cmdline?: string[];
  /** Only the agent marker variables of this process's environment, when readable (Linux only). */
  env?: Record<string, string>;
}

export type AncestryReader = () => AncestorProcess[];

const AGENT_COMM = new Set(["claude", "claude-code", "cursor", "cursor-agent", "cursor-server"]);
const AGENT_CMDLINE = /@anthropic-ai\/claude-code|\/\.cursor-server\/|\/cursor-agent(?:\/|$)|\/claude-code\//i;

/** Why this ancestor looks like an agent, or null. Never includes environment values. */
export function agentAncestorReason(p: AncestorProcess): string | null {
  const name = basename(p.comm).toLowerCase();
  if (AGENT_COMM.has(name) || name.startsWith("cursor helper")) return `process ${basename(p.comm)} (pid ${p.pid})`;
  if (p.cmdline?.some((arg) => AGENT_CMDLINE.test(arg))) return `process ${basename(p.comm)} (pid ${p.pid}) running an agent`;
  if (p.env) {
    const marker = agentSessionMarker(p.env);
    if (marker) return `process ${basename(p.comm)} (pid ${p.pid}) with ${marker} set in its environment`;
  }
  return null;
}

/** The first ancestor that looks like an agent, as a short reason, or null. */
export function findAgentAncestor(ancestors: AncestorProcess[]): string | null {
  for (const p of ancestors) {
    const reason = agentAncestorReason(p);
    if (reason) return reason;
  }
  return null;
}

/** Fields after the `)` that ends comm in /proc/<pid>/stat: state, then ppid. */
export function parseProcStat(stat: string): { comm: string; ppid: number } | null {
  const open = stat.indexOf("(");
  const close = stat.lastIndexOf(")");
  if (open < 0 || close < open) return null;
  const rest = stat.slice(close + 1).trim().split(/\s+/);
  const ppid = Number(rest[1]);
  if (!Number.isInteger(ppid) || ppid < 0) return null;
  return { comm: stat.slice(open + 1, close), ppid };
}

export interface AncestryDeps {
  platform?: NodeJS.Platform;
  /** The process whose parents are walked. Default: this process. */
  pid?: number;
  maxDepth?: number;
  readFile?: (path: string) => Buffer | string;
  /** Runs `ps` for macOS and returns its stdout. */
  ps?: (args: string[]) => string;
}

function defaultPs(args: string[]): string {
  return execFileSync("/bin/ps", args, { encoding: "utf8", timeout: 3000, stdio: ["ignore", "pipe", "ignore"] });
}

function markerEnv(raw: string): Record<string, string> | undefined {
  const out: Record<string, string> = {};
  for (const entry of raw.split("\0")) {
    const eq = entry.indexOf("=");
    if (eq <= 0) continue;
    const key = entry.slice(0, eq);
    if ((AGENT_ENV_KEYS as readonly string[]).includes(key)) out[key] = entry.slice(eq + 1);
  }
  return out;
}

/**
 * Walk the parent PIDs from this process up to init. Linux reads /proc/<pid>/stat,
 * cmdline and environ; macOS runs `ps -o ppid=,comm=`. Best effort: any read that
 * fails ends the walk and returns what was collected. Other platforms return [].
 */
export function readProcessAncestry(deps: AncestryDeps = {}): AncestorProcess[] {
  const platform = deps.platform ?? process.platform;
  const maxDepth = deps.maxDepth ?? 64;
  const start = deps.pid ?? process.pid;
  const out: AncestorProcess[] = [];
  const seen = new Set<number>([start]);

  if (platform === "linux") {
    const read = deps.readFile ?? ((p: string) => readFileSync(p));
    const text = (p: string): string | null => {
      try {
        return read(p).toString();
      } catch {
        return null;
      }
    };
    const self = text(`/proc/${start}/stat`);
    let pid = self ? (parseProcStat(self)?.ppid ?? 0) : 0;
    while (pid > 1 && out.length < maxDepth && !seen.has(pid)) {
      seen.add(pid);
      const stat = text(`/proc/${pid}/stat`);
      const parsed = stat ? parseProcStat(stat) : null;
      if (!parsed) break;
      const cmdline = text(`/proc/${pid}/cmdline`);
      const environ = text(`/proc/${pid}/environ`);
      out.push({
        pid,
        comm: parsed.comm,
        cmdline: cmdline ? cmdline.split("\0").filter(Boolean) : undefined,
        env: environ ? markerEnv(environ) : undefined,
      });
      pid = parsed.ppid;
    }
    return out;
  }

  if (platform === "darwin") {
    const ps = deps.ps ?? defaultPs;
    // One `ps -o ppid=,comm=` call per ancestor: its parent's pid and its own name.
    const row = (pid: number): { ppid: number; comm: string } | null => {
      try {
        const m = /^(\d+)\s+(.+)$/.exec(ps(["-o", "ppid=,comm=", "-p", String(pid)]).trim());
        return m ? { ppid: Number(m[1]), comm: m[2]! } : null;
      } catch {
        return null;
      }
    };
    let pid = row(start)?.ppid ?? 0;
    while (pid > 1 && out.length < maxDepth && !seen.has(pid)) {
      seen.add(pid);
      const r = row(pid);
      if (!r) break;
      out.push({ pid, comm: r.comm });
      pid = r.ppid;
    }
    return out;
  }

  return out;
}
