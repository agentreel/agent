import { execFileSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { closeSync, openSync, readSync } from "node:fs";
import { hostname, platform, userInfo } from "node:os";
import { readConfig, writeConfig, type AgentConfig, type HostnameMode } from "./config.js";

declare const __AGENTREEL_VERSION__: string;
export const AGENTREEL_VERSION =
  typeof __AGENTREEL_VERSION__ === "string" ? __AGENTREEL_VERSION__ : "dev";

/**
 * Who ran the agent and where. Stored on the session (local SQLite and
 * server). Every field is optional: a missing git binary, a folder that
 * isn't a repo, or a privacy setting just leaves it out.
 */
export interface Attribution {
  v: 1;
  os_user?: string;
  /** Plain hostname, or "sha256:<16 hex>" when hostnameMode is "hash". */
  hostname?: string;
  hostname_mode?: HostnameMode;
  platform?: string;
  git?: GitInfo;
  agent?: { tool: string; version?: string; model?: string };
  agentreel_version?: string;
}

export interface GitInfo {
  root?: string;
  user_name?: string;
  user_email?: string;
  /** origin (or first remote) with any credentials stripped. */
  remote_url?: string;
  branch_start?: string;
  head_start?: string;
  branch_end?: string;
  head_end?: string;
}

/** Remove user:password@ (or token@) from URL-style remotes. scp-style
 *  `git@host:org/repo.git` has no secret and is kept as is. */
export function sanitizeRemoteUrl(url: string | undefined | null): string | undefined {
  if (!url) return undefined;
  const u = url.trim();
  if (!u) return undefined;
  const m = /^([a-z][a-z0-9+.-]*:\/\/)([^/@]*@)?(.*)$/i.exec(u);
  if (m) {
    const [, scheme, userinfo, rest] = m;
    if (!userinfo) return u;
    // ssh://git@host/... keeps a bare user name; anything with a password
    // or token-looking user is dropped.
    const user = userinfo.slice(0, -1);
    const keep = /^ssh/i.test(scheme!) && /^[a-z0-9._-]{1,32}$/i.test(user) && !user.includes(":");
    return `${scheme}${keep ? userinfo : ""}${rest}`;
  }
  return u;
}

export function hostnameFor(mode: HostnameMode, raw: string, salt: string): string | undefined {
  if (mode === "omit") return undefined;
  if (mode === "hash") {
    return "sha256:" + createHash("sha256").update(`${salt}:${raw}`).digest("hex").slice(0, 16);
  }
  return raw;
}

export function resolveHostnameMode(cfg: AgentConfig): HostnameMode {
  const env = process.env.AGENTREEL_HOSTNAME?.toLowerCase();
  if (env === "plain" || env === "hash" || env === "omit") return env;
  return cfg.hostnameMode ?? "plain";
}

function attributionDisabled(cfg: AgentConfig): boolean {
  const env = process.env.AGENTREEL_ATTRIBUTION?.toLowerCase();
  if (env === "0" || env === "off" || env === "false") return true;
  return cfg.attribution === false;
}

function git(cwd: string, args: string[]): string | undefined {
  try {
    const out = execFileSync("git", ["-C", cwd, ...args], {
      encoding: "utf8",
      timeout: 1500,
      stdio: ["ignore", "pipe", "ignore"],
      env: { ...process.env, GIT_TERMINAL_PROMPT: "0", GIT_OPTIONAL_LOCKS: "0" },
    }).trim();
    return out || undefined;
  } catch {
    return undefined;
  }
}

/** Branch + HEAD only; cheap enough to call on every Stop. */
export function gitHead(cwd: string | undefined): { branch?: string; head?: string } {
  if (!cwd) return {};
  const head = git(cwd, ["rev-parse", "HEAD"]);
  if (!head) return {};
  const branch = git(cwd, ["rev-parse", "--abbrev-ref", "HEAD"]);
  return { branch: branch === "HEAD" ? "(detached)" : branch, head };
}

export function collectGit(cwd: string | undefined): GitInfo | undefined {
  if (!cwd) return undefined;
  const root = git(cwd, ["rev-parse", "--show-toplevel"]);
  if (!root) return undefined;
  const remotes = (git(cwd, ["remote"]) ?? "").split("\n").filter(Boolean);
  const remote = remotes.includes("origin") ? "origin" : remotes[0];
  const { branch, head } = gitHead(cwd);
  const info: GitInfo = {
    root,
    user_name: git(cwd, ["config", "user.name"]),
    user_email: git(cwd, ["config", "user.email"]),
    remote_url: remote ? sanitizeRemoteUrl(git(cwd, ["remote", "get-url", remote])) : undefined,
    branch_start: branch,
    head_start: head,
  };
  return stripUndefined(info);
}

function ensureSalt(cfg: AgentConfig): string {
  if (cfg.installSalt) return cfg.installSalt;
  const salt = randomBytes(16).toString("hex");
  try {
    writeConfig({ ...readConfig(), installSalt: salt });
  } catch {
    // best effort; a fresh salt next time only changes the hash
  }
  return salt;
}

export interface CollectOptions {
  cwd?: string;
  tool: string;
  toolVersion?: string;
  model?: string;
}

/** Full snapshot taken when a session is first seen. */
export function collectAttribution(opts: CollectOptions, cfg: AgentConfig = readConfig()): Attribution | null {
  if (attributionDisabled(cfg)) return null;
  const mode = resolveHostnameMode(cfg);
  let user: string | undefined;
  try {
    user = userInfo().username;
  } catch {
    user = process.env.USER ?? process.env.USERNAME;
  }
  const host = hostnameFor(mode, hostname(), mode === "hash" ? ensureSalt(cfg) : "");
  return stripUndefined({
    v: 1 as const,
    os_user: user,
    hostname: host,
    hostname_mode: mode,
    platform: platform(),
    git: collectGit(opts.cwd),
    agent: stripUndefined({ tool: opts.tool, version: opts.toolVersion, model: opts.model }),
    agentreel_version: AGENTREEL_VERSION,
  });
}

/** Merge a later observation (session end) into the stored snapshot. */
export function mergeAttribution(base: Attribution | null, patch: Partial<Attribution> & { git?: Partial<GitInfo> }): Attribution | null {
  if (!base) return null;
  const out: Attribution = { ...base };
  if (patch.git) out.git = stripUndefined({ ...(base.git ?? {}), ...patch.git });
  if (patch.agent) {
    out.agent = stripUndefined({
      tool: patch.agent.tool ?? base.agent?.tool ?? "unknown",
      version: patch.agent.version ?? base.agent?.version,
      model: patch.agent.model ?? base.agent?.model,
    });
  }
  return out;
}

/** Claude Code writes its version on every transcript line. Read the head only. */
export function claudeVersionFromTranscript(path: string | undefined): string | undefined {
  if (!path) return undefined;
  let fd: number | null = null;
  try {
    fd = openSync(path, "r");
    const buf = Buffer.alloc(64 * 1024);
    const n = readSync(fd, buf, 0, buf.length, 0);
    const m = /"version"\s*:\s*"(\d+\.\d+\.\d+[^"]{0,20})"/.exec(buf.subarray(0, n).toString("utf8"));
    return m?.[1];
  } catch {
    return undefined;
  } finally {
    if (fd != null) closeSync(fd);
  }
}

function stripUndefined<T extends object>(o: T): T {
  for (const k of Object.keys(o) as Array<keyof T>) if (o[k] === undefined) delete o[k];
  return o;
}
