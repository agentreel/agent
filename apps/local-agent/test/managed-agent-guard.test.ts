import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { existsSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { managedInstallCommand } from "../src/commands/managed.js";
import {
  findAgentAncestor,
  parseProcStat,
  readProcessAncestry,
  type AncestorProcess,
} from "../src/managed/agent-guard.js";

const HOOK = "/usr/local/bin/agentreel";

let root: string;
let lines: string[];

function filesUnder(dir: string): string[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir, { recursive: true, withFileTypes: true }).filter((d) => d.isFile()).map((d) => d.name);
}

/** What `sudo` leaves behind: no agent variables at all. */
const SUDO_ENV = { SUDO_USER: "dev" } as NodeJS.ProcessEnv;

const shell: AncestorProcess = { pid: 4000, comm: "bash" };
const sudo: AncestorProcess = { pid: 4001, comm: "sudo" };
const claude: AncestorProcess = { pid: 3000, comm: "claude", cmdline: ["claude"] };
const cursor: AncestorProcess = { pid: 3001, comm: "cursor" };

function run(
  opts: { yes?: boolean; dryRun?: boolean } = {},
  deps: { ancestry?: () => AncestorProcess[]; isTTY?: boolean; env?: NodeJS.ProcessEnv; apply?: never } = {},
): number {
  return managedInstallCommand(
    { root, hookCommand: HOOK, platform: "linux", ...opts },
    {
      log: (l) => lines.push(l),
      error: (l) => lines.push(l),
      uid: 0,
      env: SUDO_ENV,
      ancestry: () => [],
      isTTY: true,
      ...deps,
    },
  );
}

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "agentreel-managed-guard-"));
  lines = [];
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

describe("managed install: agent ancestry (sudo cleared the env)", () => {
  it("refuses when an ancestor is a Claude Code process", () => {
    expect(run({ yes: true }, { ancestry: () => [sudo, shell, claude] })).toBe(1);
    expect(lines.join("\n")).toContain("an agent is an ancestor");
    expect(lines.join("\n")).toContain("claude");
    expect(filesUnder(root)).toEqual([]);
  });

  it("refuses when an ancestor is a Cursor process, and --yes does not override it", () => {
    expect(run({ yes: true }, { ancestry: () => [sudo, shell, cursor], isTTY: true })).toBe(1);
    expect(lines.join("\n")).toContain("an agent is an ancestor");
    expect(filesUnder(root)).toEqual([]);
  });

  it("refuses when an ancestor's own environment carries an agent marker even though the process name is generic", () => {
    const parent: AncestorProcess = { pid: 4000, comm: "bash", env: { CLAUDECODE: "1" } };
    expect(run({}, { ancestry: () => [sudo, parent] })).toBe(1);
    expect(lines.join("\n")).toContain("CLAUDECODE set in its environment");
    expect(filesUnder(root)).toEqual([]);
  });

  it("refuses when the command line shows an agent runtime under a generic process name", () => {
    const node: AncestorProcess = {
      pid: 3100,
      comm: "node",
      cmdline: ["node", "/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js"],
    };
    expect(run({}, { ancestry: () => [sudo, shell, node] })).toBe(1);
    expect(filesUnder(root)).toEqual([]);
  });

  it("does not print environment values", () => {
    const parent: AncestorProcess = { pid: 4000, comm: "bash", env: { CURSOR_AGENT: "super-secret-value" } };
    run({}, { ancestry: () => [parent] });
    expect(lines.join("\n")).not.toContain("super-secret-value");
  });

  it("allows an ordinary terminal ancestry", () => {
    const ancestors: AncestorProcess[] = [sudo, shell, { pid: 900, comm: "sshd" }, { pid: 800, comm: "systemd" }];
    expect(run({}, { ancestry: () => ancestors })).toBe(0);
    expect(filesUnder(root)).toHaveLength(2);
  });
});

describe("managed install: no terminal", () => {
  it("refuses a real run when stdin is not a TTY and --yes is not passed", () => {
    expect(run({}, { isTTY: false })).toBe(1);
    expect(lines.join("\n")).toContain("stdin is not a terminal");
    expect(lines.join("\n")).toContain("--yes");
    expect(filesUnder(root)).toEqual([]);
  });

  it("proceeds when stdin is not a TTY, --yes is passed and no agent is an ancestor", () => {
    expect(run({ yes: true }, { isTTY: false, ancestry: () => [sudo, shell] })).toBe(0);
    expect(filesUnder(root)).toHaveLength(2);
  });

  it("proceeds for a person at a terminal without --yes", () => {
    expect(run({}, { isTTY: true, ancestry: () => [sudo, shell] })).toBe(0);
    expect(filesUnder(root)).toHaveLength(2);
  });

  it("still refuses on the env check when a TTY and --yes are both present", () => {
    expect(run({ yes: true }, { isTTY: true, env: { ...SUDO_ENV, CLAUDECODE: "1" } })).toBe(1);
    expect(lines.join("\n")).toContain("inside an agent session");
    expect(filesUnder(root)).toEqual([]);
  });
});

describe("managed install: --dry-run is always allowed", () => {
  it("works with an agent ancestor, an agent env and no TTY", () => {
    const code = run(
      { dryRun: true },
      { isTTY: false, ancestry: () => [sudo, shell, claude], env: { ...SUDO_ENV, CLAUDECODE: "1", CURSOR_AGENT: "1" } },
    );
    expect(code).toBe(0);
    expect(filesUnder(root)).toEqual([]);
  });

  it("does not even read the process chain", () => {
    const ancestry = vi.fn(() => [claude]);
    expect(run({ dryRun: true }, { ancestry })).toBe(0);
    expect(ancestry).not.toHaveBeenCalled();
  });
});

describe("managed install: an ancestry read error falls back safely", () => {
  it("does not block a person at a terminal on a read error alone", () => {
    const ancestry = () => {
      throw new Error("EACCES: /proc is hidden");
    };
    expect(run({}, { ancestry, isTTY: true })).toBe(0);
    expect(lines.join("\n")).toContain("could not read the parent process chain");
    expect(filesUnder(root)).toHaveLength(2);
  });

  it("falls back to the TTY check: a read error with no terminal and no --yes still refuses", () => {
    const ancestry = () => {
      throw new Error("EACCES");
    };
    expect(run({}, { ancestry, isTTY: false })).toBe(1);
    expect(lines.join("\n")).toContain("stdin is not a terminal");
    expect(filesUnder(root)).toEqual([]);
  });

  it("with --yes and a read error and no terminal, the TTY check is satisfied and the run proceeds", () => {
    const ancestry = () => {
      throw new Error("EACCES");
    };
    expect(run({ yes: true }, { ancestry, isTTY: false })).toBe(0);
  });
});

describe("findAgentAncestor", () => {
  it("matches agent names regardless of path and case, and not look-alikes", () => {
    expect(findAgentAncestor([{ pid: 1, comm: "/Applications/Cursor.app/Contents/MacOS/Cursor" }])).toContain("Cursor");
    expect(findAgentAncestor([{ pid: 2, comm: "Cursor Helper (Plugin)" }])).not.toBeNull();
    expect(findAgentAncestor([{ pid: 3, comm: "claude" }])).not.toBeNull();
    expect(findAgentAncestor([{ pid: 4, comm: "bash" }, { pid: 5, comm: "sshd" }, { pid: 6, comm: "claudette" }])).toBeNull();
  });

  it("ignores marker variables that are unset or not 1", () => {
    expect(findAgentAncestor([{ pid: 1, comm: "bash", env: { CLAUDECODE: "0" } }])).toBeNull();
    expect(findAgentAncestor([{ pid: 1, comm: "bash", env: {} }])).toBeNull();
  });
});

describe("parseProcStat", () => {
  it("reads ppid after the last closing parenthesis, even when comm has spaces and parens", () => {
    expect(parseProcStat("123 (my (odd) name) S 77 123 123 0 -1")).toEqual({ comm: "my (odd) name", ppid: 77 });
  });
  it("returns null for garbage", () => {
    expect(parseProcStat("nonsense")).toBeNull();
    expect(parseProcStat("1 (x) S notanumber")).toBeNull();
  });
});

describe("readProcessAncestry", () => {
  const stat = (pid: number, comm: string, ppid: number) => `${pid} (${comm}) S ${ppid} 0 0 0 -1`;
  const nul = (...parts: string[]) => parts.join("\0") + "\0";

  function fakeProc(files: Record<string, string>) {
    return (path: string) => {
      if (path in files) return files[path]!;
      throw new Error(`ENOENT ${path}`);
    };
  }

  it("walks Linux /proc parents nearest first, keeping only agent marker variables", () => {
    const files = {
      "/proc/5000/stat": stat(5000, "agentreel", 4001),
      "/proc/4001/stat": stat(4001, "sudo", 4000),
      "/proc/4001/cmdline": nul("sudo", "agentreel", "managed", "install"),
      "/proc/4000/stat": stat(4000, "bash", 3000),
      "/proc/4000/environ": nul("PATH=/usr/bin", "CLAUDECODE=1", "AWS_SECRET_ACCESS_KEY=shh"),
      "/proc/3000/stat": stat(3000, "claude", 1),
    };
    const list = readProcessAncestry({ platform: "linux", pid: 5000, readFile: fakeProc(files) });
    expect(list.map((p) => [p.pid, p.comm])).toEqual([
      [4001, "sudo"],
      [4000, "bash"],
      [3000, "claude"],
    ]);
    expect(list[1]!.env).toEqual({ CLAUDECODE: "1" });
    expect(JSON.stringify(list)).not.toContain("shh");
    expect(findAgentAncestor(list)).not.toBeNull();
  });

  it("returns what it found when a later read fails, and never throws", () => {
    const files = {
      "/proc/5000/stat": stat(5000, "agentreel", 4001),
      "/proc/4001/stat": stat(4001, "sudo", 4000),
    };
    const list = readProcessAncestry({ platform: "linux", pid: 5000, readFile: fakeProc(files) });
    expect(list.map((p) => p.pid)).toEqual([4001]);
    expect(readProcessAncestry({ platform: "linux", pid: 5000, readFile: fakeProc({}) })).toEqual([]);
  });

  it("stops on a parent cycle and at the depth limit", () => {
    const files = {
      "/proc/10/stat": stat(10, "a", 11),
      "/proc/11/stat": stat(11, "b", 12),
      "/proc/12/stat": stat(12, "c", 11),
    };
    expect(readProcessAncestry({ platform: "linux", pid: 10, readFile: fakeProc(files) }).map((p) => p.pid)).toEqual([11, 12]);
    expect(readProcessAncestry({ platform: "linux", pid: 10, maxDepth: 1, readFile: fakeProc(files) })).toHaveLength(1);
  });

  it("walks macOS parents with ps -o ppid=,comm=", () => {
    const table: Record<string, string> = {
      "500": "400 /usr/local/bin/node",
      "400": "300 /bin/zsh",
      "300": "1 /Applications/Cursor.app/Contents/MacOS/Cursor",
    };
    const ps = vi.fn((args: string[]) => {
      expect(args.slice(0, 2)).toEqual(["-o", "ppid=,comm="]);
      const row = table[args[3]!];
      if (!row) throw new Error("no such process");
      return `${row}\n`;
    });
    const list = readProcessAncestry({ platform: "darwin", pid: 500, ps });
    expect(list.map((p) => p.pid)).toEqual([400, 300]);
    expect(findAgentAncestor(list)).toContain("Cursor");
  });

  it("returns an empty list on a platform it cannot read", () => {
    expect(readProcessAncestry({ platform: "win32" })).toEqual([]);
  });
});
