import { describe, expect, it } from "vitest";
import { join } from "node:path";
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import {
  DARWIN_ADMIN_GID,
  hookCommandBinaryPath,
  hookPathChain,
  hookPathRefusalMessage,
  inspectHookCommandPath,
  isTrustedOwner,
  isWritableByNonRoot,
  type PathIdentity,
  type RealpathFn,
  type StatPath,
} from "../src/managed/hook-path.js";
import { defaultHookCommand, managedInstallCommand } from "../src/commands/managed.js";

const BIN = "/usr/local/bin/agentreel";
const ROOT_FILE: PathIdentity = { uid: 0, gid: 0, mode: 0o755 };
const ROOT_DIR: PathIdentity = { uid: 0, gid: 0, mode: 0o755 };
const USER_FILE: PathIdentity = { uid: 1000, gid: 1000, mode: 0o755 };
const USER_DIR: PathIdentity = { uid: 1000, gid: 1000, mode: 0o755 };

function chainEntries(file: string, fileId: PathIdentity, dirId: PathIdentity = ROOT_DIR): Record<string, PathIdentity> {
  const entries: Record<string, PathIdentity> = { [file]: fileId };
  let dir = file;
  while (true) {
    const parent = dir === "/" ? "/" : dir.slice(0, dir.lastIndexOf("/")) || "/";
    if (!entries[parent]) entries[parent] = dirId;
    if (parent === "/") break;
    dir = parent;
  }
  return entries;
}

function inspect(
  entries: Record<string, PathIdentity | undefined>,
  hookCommand = BIN,
  opts: { platform?: "linux" | "darwin"; root?: string } = {},
) {
  const stat: StatPath = (p) => entries[p] ?? null;
  const realpath: RealpathFn = (p) => (entries[p] ? p : null);
  return inspectHookCommandPath(hookCommand, {
    platform: opts.platform ?? "linux",
    root: opts.root,
    stat,
    realpath,
  });
}

describe("inspectHookCommandPath", () => {
  it("accepts a root-owned binary under root-owned 0755 directories", () => {
    const result = inspect(chainEntries(BIN, ROOT_FILE));
    expect(result.missing).toBe(false);
    expect(result.checkedPath).toBe(BIN);
    expect(result.issues).toEqual([]);
  });

  it("rejects a user-owned binary", () => {
    const result = inspect(chainEntries(BIN, USER_FILE, ROOT_DIR));
    expect(result.issues.map((i) => i.path)).toEqual([BIN]);
    expect(result.issues[0]!.reason).toContain("is not owned by root");
    expect(result.issues[0]!.reason).toContain("uid 1000");
  });

  it("rejects a group- or world-writable binary even when root-owned", () => {
    const group = inspect(chainEntries(BIN, { uid: 0, gid: 0, mode: 0o775 }));
    expect(group.issues.some((i) => i.reason.includes("group- or world-writable"))).toBe(true);
    const world = inspect(chainEntries(BIN, { uid: 0, gid: 0, mode: 0o757 }));
    expect(world.issues.some((i) => i.reason.includes("group- or world-writable"))).toBe(true);
  });

  it("rejects a parent directory writable by a non-root user", () => {
    const entries = chainEntries(BIN, ROOT_FILE, ROOT_DIR);
    entries["/usr/local"] = USER_DIR;
    const result = inspect(entries);
    expect(result.issues).toEqual([
      expect.objectContaining({
        path: "/usr/local",
        reason: expect.stringContaining("writable by a non-root user"),
      }),
    ]);
  });

  it("rejects a group-writable parent even when it is owned by root", () => {
    const entries = chainEntries(BIN, ROOT_FILE, ROOT_DIR);
    entries["/usr/local"] = { uid: 0, gid: 0, mode: 0o775 };
    const result = inspect(entries);
    expect(result.issues[0]!.path).toBe("/usr/local");
    expect(result.issues[0]!.reason).toContain("writable by a non-root user");
  });

  it("on macOS accepts a root or admin-group owner when the mode is not group-writable", () => {
    expect(isTrustedOwner({ uid: 0, gid: DARWIN_ADMIN_GID, mode: 0o755 }, "darwin")).toBe(true);
    expect(isTrustedOwner({ uid: 501, gid: DARWIN_ADMIN_GID, mode: 0o755 }, "darwin")).toBe(true);
    expect(isTrustedOwner({ uid: 501, gid: DARWIN_ADMIN_GID, mode: 0o775 }, "darwin")).toBe(false);
    expect(isTrustedOwner({ uid: 501, gid: DARWIN_ADMIN_GID, mode: 0o755 }, "linux")).toBe(false);

    const ok = inspect(chainEntries(BIN, { uid: 0, gid: DARWIN_ADMIN_GID, mode: 0o755 }, { uid: 0, gid: DARWIN_ADMIN_GID, mode: 0o755 }), BIN, {
      platform: "darwin",
    });
    expect(ok.issues).toEqual([]);

    const adminFile = inspect(chainEntries(BIN, { uid: 501, gid: DARWIN_ADMIN_GID, mode: 0o755 }, { uid: 0, gid: DARWIN_ADMIN_GID, mode: 0o755 }), BIN, {
      platform: "darwin",
    });
    expect(adminFile.issues).toEqual([]);

    const groupWritable = inspect(
      chainEntries(BIN, { uid: 0, gid: DARWIN_ADMIN_GID, mode: 0o755 }, { uid: 0, gid: DARWIN_ADMIN_GID, mode: 0o775 }),
      BIN,
      { platform: "darwin" },
    );
    expect(groupWritable.issues.some((i) => i.path === "/usr/local" || i.path === "/usr/local/bin")).toBe(true);
  });

  it("with --root, checks the path under the staging root and does not walk above it", () => {
    const root = "/tmp/stage";
    const target = "/tmp/stage/usr/local/bin/agentreel";
    const entries: Record<string, PathIdentity> = {
      [target]: ROOT_FILE,
      "/tmp/stage/usr/local/bin": ROOT_DIR,
      "/tmp/stage/usr/local": ROOT_DIR,
      "/tmp/stage/usr": ROOT_DIR,
      // Staging root and host /usr are user-owned; they must not be inspected.
      "/tmp/stage": USER_DIR,
      "/usr/local/bin/agentreel": USER_FILE,
      "/usr/local": USER_DIR,
    };
    const result = inspect(entries, BIN, { root });
    expect(result.missing).toBe(false);
    expect(result.checkedPath).toBe(target);
    expect(result.issues).toEqual([]);
    expect(hookPathChain(BIN, root)).toEqual({
      file: target,
      parents: ["/tmp/stage/usr/local/bin", "/tmp/stage/usr/local", "/tmp/stage/usr"],
      stop: "/tmp/stage",
    });
  });

  it("follows a symlink into a user-writable tree", () => {
    const real = "/home/alice/.nvm/bin/agentreel";
    const entries: Record<string, PathIdentity> = {
      ...chainEntries(real, USER_FILE, USER_DIR),
      [BIN]: ROOT_FILE,
      "/usr/local/bin": ROOT_DIR,
      "/usr/local": ROOT_DIR,
      "/usr": ROOT_DIR,
      "/": ROOT_DIR,
    };
    const result = inspectHookCommandPath(BIN, {
      platform: "linux",
      stat: (p) => entries[p] ?? null,
      realpath: (p) => (p === BIN ? real : entries[p] ? p : null),
    });
    expect(result.checkedPath).toBe(real);
    expect(result.issues.some((i) => i.path === real && i.reason.includes("not owned by root"))).toBe(true);
    expect(result.issues.some((i) => i.path === "/home/alice/.nvm" || i.path === "/home/alice/.nvm/bin")).toBe(true);
  });

  it("reports a missing file without a tamper issue", () => {
    const result = inspect({}, BIN);
    expect(result.missing).toBe(true);
    expect(result.issues).toEqual([]);
  });

  it("flags a non-absolute hook command", () => {
    const result = inspect({}, "npx -y @agentreel/agent");
    expect(result.missing).toBe(true);
    expect(result.issues[0]!.reason).toContain("not an absolute path");
    expect(hookCommandBinaryPath('"/usr/local/bin/agent reel" hook')).toBe("/usr/local/bin/agent reel");
  });
});

describe("agentreel managed install hook-path guard", () => {
  const defaultBin = defaultHookCommand();
  const safe = chainEntries(defaultBin, ROOT_FILE, ROOT_DIR);

  function run(
    cli: Record<string, unknown>,
    entries: Record<string, PathIdentity | undefined> = safe,
    extra: { dryRun?: boolean; hookCommand?: string; allowUserWritableHook?: boolean; uid?: number } = {},
  ) {
    const lines: string[] = [];
    const root = mkdtempSync(join(tmpdir(), "agentreel-hookpath-root-"));
    try {
      const code = managedInstallCommand(
        { root, platform: "linux", hookCommand: extra.hookCommand, dryRun: extra.dryRun, allowUserWritableHook: extra.allowUserWritableHook, ...cli },
        {
          uid: extra.uid ?? 0,
          env: {},
          log: (l) => lines.push(l),
          error: (l) => lines.push(l),
          // A person at a terminal with no agent above them.
          isTTY: true,
          ancestry: () => [],
          stat: (p) => entries[p] ?? null,
          realpath: (p) => (entries[p] ? p : null),
        },
      );
      return { code, out: lines.join("\n"), root };
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }

  it("installs when the default binary is root-owned under root-owned directories", () => {
    const { code, out } = run({});
    expect(code).toBe(0);
    expect(out).not.toContain("Refusing");
    expect(out).not.toContain("writable by a non-root user");
  });

  it("refuses a real run when the default binary is user-owned", () => {
    const { code, out } = run({}, chainEntries(defaultBin, USER_FILE, ROOT_DIR));
    expect(code).toBe(1);
    expect(out).toContain("Refusing to install hooks that point at a binary a non-root user can replace");
    expect(out).toContain(defaultBin);
    expect(out).toContain("is not owned by root");
    expect(out).toContain("--hook-command");
    expect(out).toContain("--allow-user-writable-hook");
    expect(hookPathRefusalMessage(inspect(chainEntries(defaultBin, USER_FILE, ROOT_DIR), defaultBin).issues)).toContain(defaultBin);
  });

  it("refuses a real run when a parent directory is writable by a non-root user", () => {
    const entries = chainEntries(defaultBin, ROOT_FILE, ROOT_DIR);
    const parent = defaultBin.slice(0, defaultBin.lastIndexOf("/")) || "/";
    entries[parent] = USER_DIR;
    const { code, out } = run({}, entries);
    expect(code).toBe(1);
    expect(out).toContain("Refusing");
    expect(out).toContain(parent);
    expect(out).toContain("writable by a non-root user");
  });

  it("dry-run warns and continues, writing nothing, when the default binary is user-owned", () => {
    const lines: string[] = [];
    const root = mkdtempSync(join(tmpdir(), "agentreel-hookpath-dry-"));
    const entries = chainEntries(defaultBin, USER_FILE, ROOT_DIR);
    try {
      const code = managedInstallCommand(
        { root, platform: "linux", dryRun: true },
        {
          uid: 1000,
          env: {},
          log: (l) => lines.push(l),
          error: (l) => lines.push(l),
          // A person at a terminal with no agent above them.
          isTTY: true,
          ancestry: () => [],
          stat: (p) => entries[p] ?? null,
          realpath: (p) => (entries[p] ? p : null),
        },
      );
      const out = lines.join("\n");
      expect(code).toBe(0);
      expect(out).toContain("dry run");
      expect(out).toContain("The hook binary is writable by a non-root user");
      expect(out).toContain("is not owned by root");
      expect(out).toContain("This is a dry run, so install was not refused");
      expect(out).not.toContain("Refusing");
      expect(readdirSync(root)).toEqual([]);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("--allow-user-writable-hook continues with a loud warning", () => {
    const { code, out } = run({}, chainEntries(defaultBin, USER_FILE, ROOT_DIR), { allowUserWritableHook: true });
    expect(code).toBe(0);
    expect(out).toContain("WARNING: installing a hook binary a non-root user can replace (--allow-user-writable-hook)");
    expect(out).toContain("is not owned by root");
    expect(out).not.toContain("Refusing");
    expect(out).toContain("created");
  });

  it("an explicit --hook-command warns and continues", () => {
    const { code, out } = run({}, chainEntries(BIN, USER_FILE, ROOT_DIR), { hookCommand: BIN });
    expect(code).toBe(0);
    expect(out).toContain("The hook binary is writable by a non-root user");
    expect(out).toContain("The path was set with --hook-command, so install continues");
    expect(out).not.toContain("Refusing");
    expect(out).toContain("created");
  });

  it("falls back to the hook path when the staged copy is missing, using only the mock", () => {
    const seen: string[] = [];
    const lines: string[] = [];
    const root = mkdtempSync(join(tmpdir(), "agentreel-hookpath-nousr-"));
    const entries = chainEntries(BIN, USER_FILE, ROOT_DIR);
    try {
      const code = managedInstallCommand(
        { root, platform: "linux", hookCommand: BIN },
        {
          uid: 0,
          env: {},
          log: (l) => lines.push(l),
          error: (l) => lines.push(l),
          // A person at a terminal with no agent above them.
          isTTY: true,
          ancestry: () => [],
          stat: (p) => {
            seen.push(p);
            return entries[p] ?? null;
          },
          realpath: (p) => (entries[p] ? p : null),
        },
      );
      expect(code).toBe(0);
      expect(seen).toContain(BIN);
      expect(seen.some((p) => p.startsWith(root))).toBe(false);
      expect(lines.join("\n")).toContain("The path was set with --hook-command, so install continues");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

describe("isWritableByNonRoot", () => {
  it("treats owner-writable user directories and any group- or world-writable directory as unsafe", () => {
    expect(isWritableByNonRoot(USER_DIR, "linux")).toBe(true);
    expect(isWritableByNonRoot({ uid: 0, gid: 0, mode: 0o755 }, "linux")).toBe(false);
    expect(isWritableByNonRoot({ uid: 0, gid: 0, mode: 0o775 }, "linux")).toBe(true);
    expect(isWritableByNonRoot({ uid: 0, gid: 0, mode: 0o757 }, "linux")).toBe(true);
    expect(isWritableByNonRoot({ uid: 0, gid: DARWIN_ADMIN_GID, mode: 0o755 }, "darwin")).toBe(false);
    expect(isWritableByNonRoot({ uid: 0, gid: DARWIN_ADMIN_GID, mode: 0o775 }, "darwin")).toBe(true);
  });
});
