import { afterAll, describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const home = mkdtempSync(join(tmpdir(), "agentreel-attr-"));
process.env.HOME = home;
const { sanitizeRemoteUrl, hostnameFor, collectGit, collectAttribution, gitHead, mergeAttribution } = await import(
  "../src/attribution.js"
);

afterAll(() => rmSync(home, { recursive: true, force: true }));

function makeRepo(): string {
  const dir = mkdtempSync(join(tmpdir(), "agentreel-repo-"));
  const g = (...a: string[]) => execFileSync("git", ["-C", dir, ...a], { stdio: "pipe" });
  g("init", "-q", "-b", "main");
  g("config", "user.name", "Test Dev");
  g("config", "user.email", "test.dev@example.com");
  g("remote", "add", "origin", "https://x-access-token:ghp_abcdefghijklmnopqrstuvwxyz0123456789@github.com/acme/api.git");
  g("-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", "init");
  return dir;
}

describe("sanitizeRemoteUrl", () => {
  it.each([
    ["https://user:pass@github.com/acme/api.git", "https://github.com/acme/api.git"],
    ["https://ghp_abcdefghijklmnopqrstuvwxyz0123456789@github.com/acme/api", "https://github.com/acme/api"],
    ["https://github.com/acme/api.git", "https://github.com/acme/api.git"],
    ["ssh://git@github.com/acme/api.git", "ssh://git@github.com/acme/api.git"],
    ["ssh://git:secret@github.com/acme/api.git", "ssh://github.com/acme/api.git"],
    ["git@github.com:acme/api.git", "git@github.com:acme/api.git"],
  ])("%s", (input, out) => {
    expect(sanitizeRemoteUrl(input)).toBe(out);
  });
  it("handles empty", () => {
    expect(sanitizeRemoteUrl("")).toBeUndefined();
    expect(sanitizeRemoteUrl(undefined)).toBeUndefined();
  });
});

describe("hostnameFor", () => {
  it("plain, hash (stable, salted) and omit", () => {
    expect(hostnameFor("plain", "navjot-mbp", "s")).toBe("navjot-mbp");
    const a = hostnameFor("hash", "navjot-mbp", "salt1");
    expect(a).toMatch(/^sha256:[0-9a-f]{16}$/);
    expect(hostnameFor("hash", "navjot-mbp", "salt1")).toBe(a);
    expect(hostnameFor("hash", "navjot-mbp", "salt2")).not.toBe(a);
    expect(a).not.toContain("navjot");
    expect(hostnameFor("omit", "navjot-mbp", "s")).toBeUndefined();
  });
});

describe("git attribution", () => {
  it("reads user, remote without credentials, branch and HEAD", () => {
    const repo = makeRepo();
    const g = collectGit(repo)!;
    expect(g.user_name).toBe("Test Dev");
    expect(g.user_email).toBe("test.dev@example.com");
    expect(g.remote_url).toBe("https://github.com/acme/api.git");
    expect(g.branch_start).toBe("main");
    expect(g.head_start).toMatch(/^[0-9a-f]{40}$/);
    rmSync(repo, { recursive: true, force: true });
  });
  it("returns undefined outside a repo", () => {
    const dir = mkdtempSync(join(tmpdir(), "agentreel-norepo-"));
    expect(collectGit(dir)).toBeUndefined();
    expect(gitHead(dir)).toEqual({});
  });
  it("records the end commit via merge", () => {
    const repo = makeRepo();
    const start = collectAttribution({ cwd: repo, tool: "claude-code", toolVersion: "2.0.1" })!;
    execFileSync("git", ["-C", repo, "-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", "fix"]);
    const end = gitHead(repo);
    const merged = mergeAttribution(start, { git: { branch_end: end.branch, head_end: end.head } })!;
    expect(merged.git!.head_start).not.toBe(merged.git!.head_end);
    expect(merged.git!.user_email).toBe("test.dev@example.com");
    expect(merged.agent).toEqual({ tool: "claude-code", version: "2.0.1" });
    expect(merged.agentreel_version).toBe("test");
    rmSync(repo, { recursive: true, force: true });
  });
});

describe("privacy switches", () => {
  it("AGENTREEL_HOSTNAME=omit drops the host, hash hides it", () => {
    process.env.AGENTREEL_HOSTNAME = "omit";
    const a = collectAttribution({ tool: "cursor" })!;
    expect(a.hostname).toBeUndefined();
    expect(a.hostname_mode).toBe("omit");
    expect(a.os_user).toBeTruthy();
    process.env.AGENTREEL_HOSTNAME = "hash";
    expect(collectAttribution({ tool: "cursor" })!.hostname).toMatch(/^sha256:/);
    delete process.env.AGENTREEL_HOSTNAME;
  });
  it("AGENTREEL_ATTRIBUTION=off records nothing", () => {
    process.env.AGENTREEL_ATTRIBUTION = "off";
    expect(collectAttribution({ tool: "cursor" })).toBeNull();
    delete process.env.AGENTREEL_ATTRIBUTION;
  });
});
