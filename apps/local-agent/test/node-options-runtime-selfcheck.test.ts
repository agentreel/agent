import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  envNodeOptionsIsDisallowed,
  enforceCliEnvNodeOptions,
  enforceHookEnvNodeOptions,
  RUNTIME_SELF005_MESSAGE,
  RUNTIME_SELF005_RULE,
} from "../src/policy/node-options-runtime.js";
import { startAgentreelCli } from "../src/cli-start.js";
import { formatClaudePreToolUseDeny } from "../src/hooks/handler.js";
import { cursorHookResponse } from "../src/cursor/hook-normalize.js";

const priorHome = process.env.HOME;
const priorNodeOptions = process.env.NODE_OPTIONS;
let testHome: string;

beforeEach(() => {
  testHome = mkdtempSync(join(tmpdir(), "agentreel-node-options-runtime-"));
  process.env.HOME = testHome;
  delete process.env.NODE_OPTIONS;
});

afterEach(() => {
  if (priorNodeOptions === undefined) delete process.env.NODE_OPTIONS;
  else process.env.NODE_OPTIONS = priorNodeOptions;
  if (priorHome === undefined) delete process.env.HOME;
  else process.env.HOME = priorHome;
  rmSync(testHome, { recursive: true, force: true });
});

describe("process.env NODE_OPTIONS allow list", () => {
  const allowed = [
    undefined,
    "",
    "--max-old-space-size=4096",
    "--max-semi-space-size=64",
    "--enable-source-maps",
    "--no-warnings",
    "--trace-warnings",
    "--dns-result-order=ipv4first",
    "  --max-old-space-size=4096   --no-warnings  ",
    '--max-old-space-size "4096"',
    '--max-old-space-size=4096 --enable-source-maps --no-warnings',
  ];
  for (const value of allowed) {
    it(`allows: ${JSON.stringify(value)}`, () => {
      expect(envNodeOptionsIsDisallowed(value)).toBe(false);
    });
  }

  const denied = [
    "--require=/tmp/evil.js",
    "--require /tmp/evil.js",
    "-r /tmp/evil.js",
    "--import=/tmp/evil.mjs",
    "--import /tmp/evil.mjs",
    "--loader=/tmp/l.mjs",
    "--experimental-loader=/tmp/l.mjs",
    "--inspect",
    "--max-old-space-size=4096 --require=/tmp/evil.js",
    "--no-warnings --unknown-flag",
    '--no-warnings "--require=x',
  ];
  for (const value of denied) {
    it(`denies: ${JSON.stringify(value)}`, () => {
      expect(envNodeOptionsIsDisallowed(value)).toBe(true);
    });
  }
});

describe("CLI startup self-check", () => {
  it("denies --require and exits non-zero", () => {
    const exits: number[] = [];
    const logs: string[] = [];
    const denied = enforceCliEnvNodeOptions({
      value: "--require=/tmp/evil.js",
      exit: (code) => exits.push(code),
      log: (line) => logs.push(line),
    });
    expect(denied).toBe(true);
    expect(exits).toEqual([1]);
    expect(logs.join("")).toContain(RUNTIME_SELF005_RULE);
  });

  it("denies -r, --import, --loader and --experimental-loader", () => {
    for (const value of ["-r /tmp/x.js", "--import=/tmp/x.mjs", "--loader=/tmp/l.mjs", "--experimental-loader=/tmp/l.mjs"]) {
      const exits: number[] = [];
      expect(
        enforceCliEnvNodeOptions({
          value,
          exit: (code) => exits.push(code),
          log: () => {},
        }),
      ).toBe(true);
      expect(exits).toEqual([1]);
    }
  });

  it("allows listed flags, unset and empty, and does not exit", () => {
    for (const deps of [
      { value: "--max-old-space-size=4096", valueProvided: true },
      { value: undefined, valueProvided: true },
      { value: "", valueProvided: true },
    ] as const) {
      const exits: number[] = [];
      expect(enforceCliEnvNodeOptions({ ...deps, exit: (code) => exits.push(code), log: () => {} })).toBe(false);
      expect(exits).toEqual([]);
    }
  });

  it("denies unparseable input", () => {
    const exits: number[] = [];
    expect(
      enforceCliEnvNodeOptions({
        value: '--no-warnings "--require=x',
        exit: (code) => exits.push(code),
        log: () => {},
      }),
    ).toBe(true);
    expect(exits).toEqual([1]);
  });
});

describe("hook-runner startup self-check", () => {
  it("denies --require at the hook entry", () => {
    const logs: string[] = [];
    process.env.NODE_OPTIONS = "--require=/tmp/evil.js";
    expect(enforceHookEnvNodeOptions({ log: (line) => logs.push(line) })).toBe(true);
    expect(logs.join("")).toContain(RUNTIME_SELF005_RULE);
  });

  it("Claude hook entry writes a SELF005 deny and does not run the rest", async () => {
    process.env.NODE_OPTIONS = "--require=/tmp/evil.js";
    const { runHook } = await import("../src/hooks/handler.js");
    let out = "";
    let stdinReads = 0;
    await runHook("PreToolUse", {
      readStdin: async () => {
        stdinReads += 1;
        return JSON.stringify({
          session_id: "s",
          hook_event_name: "PreToolUse",
          cwd: "/tmp",
          tool_name: "Bash",
          tool_input: { command: "echo hi" },
        });
      },
      writeStdout: (s) => {
        out += s;
      },
    });
    expect(stdinReads).toBe(0);
    expect(out).toContain(formatClaudePreToolUseDeny(RUNTIME_SELF005_MESSAGE));
    expect(out).toContain("deny");
    expect(out).toContain("SELF005");
  });

  it("Cursor hook entry writes a SELF005 deny and does not run the rest", async () => {
    process.env.NODE_OPTIONS = "--require=/tmp/evil.js";
    const { runCursorHook } = await import("../src/cursor/hook-runner.js");
    let out = "";
    let stdinReads = 0;
    await runCursorHook("beforeShellExecution", {
      readStdin: async () => {
        stdinReads += 1;
        return JSON.stringify({
          hook_event_name: "beforeShellExecution",
          command: "echo hi",
        });
      },
      writeStdout: (s) => {
        out += s;
      },
    });
    expect(stdinReads).toBe(0);
    const parsed = JSON.parse(out) as { permission?: string; user_message?: string };
    expect(parsed.permission).toBe("deny");
    expect(parsed.user_message).toBe(RUNTIME_SELF005_MESSAGE);
    expect(out).toContain("SELF005");
    const expected = cursorHookResponse("beforeShellExecution", {
      permission: "deny",
      user_message: RUNTIME_SELF005_MESSAGE,
      agent_message: RUNTIME_SELF005_MESSAGE,
    });
    expect(out).toContain(expected);
  });

  it("denies -r, --import, --loader and --experimental-loader at the hook entry", () => {
    for (const value of ["-r /tmp/x.js", "--import=/tmp/x.mjs", "--loader=/tmp/l.mjs", "--experimental-loader=/tmp/l.mjs"]) {
      process.env.NODE_OPTIONS = value;
      expect(enforceHookEnvNodeOptions({ log: () => {} })).toBe(true);
    }
  });

  it("allows listed flags, unset and empty at the hook entry", () => {
    process.env.NODE_OPTIONS = "--no-warnings --enable-source-maps";
    expect(enforceHookEnvNodeOptions({ log: () => {} })).toBe(false);
    delete process.env.NODE_OPTIONS;
    expect(enforceHookEnvNodeOptions({ log: () => {} })).toBe(false);
    process.env.NODE_OPTIONS = "";
    expect(enforceHookEnvNodeOptions({ log: () => {} })).toBe(false);
  });

  it("denies unparseable input at the hook entry", () => {
    process.env.NODE_OPTIONS = '--no-warnings "--require=x';
    expect(enforceHookEnvNodeOptions({ log: () => {} })).toBe(true);
  });
});

describe("CLI loads the rest of the app only after the self-check", () => {
  it("entry and cli-start call the check before the dynamic import of the CLI", () => {
    const entry = readFileSync(new URL("../src/entry.ts", import.meta.url), "utf8");
    const start = readFileSync(new URL("../src/cli-start.ts", import.meta.url), "utf8");
    expect(entry).toMatch(/startAgentreelCli\(\)/);
    expect(start.indexOf("enforceCliEnvNodeOptions")).toBeGreaterThanOrEqual(0);
    expect(start.indexOf("enforceCliEnvNodeOptions")).toBeLessThan(start.indexOf('import("./cli.js")'));
  });

  it("startAgentreelCli exits before loading the CLI when NODE_OPTIONS is disallowed", async () => {
    const exits: number[] = [];
    const logs: string[] = [];
    await startAgentreelCli({
      value: "--require=/tmp/evil.js",
      exit: (code) => exits.push(code),
      log: (line) => logs.push(line),
    });
    expect(exits).toEqual([1]);
    expect(logs.join("")).toContain(RUNTIME_SELF005_RULE);
  });
});
