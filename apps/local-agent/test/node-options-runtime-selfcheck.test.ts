import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  envNodeOptionsIsDisallowed,
  enforceCliEnvNodeOptions,
  enforceHookEnvNodeOptions,
  execArgvIsDisallowed,
  RUNTIME_SELF005_EXEC_ARGV_MESSAGE,
  RUNTIME_SELF005_MESSAGE,
  RUNTIME_SELF005_RULE,
} from "../src/policy/node-options-runtime.js";
import { HOOK_DENY_EXIT_CODE, startAgentreelCli } from "../src/cli-start.js";
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
    expect(enforceHookEnvNodeOptions({ log: (line) => logs.push(line) })).toBe("node_options");
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

  it("Claude events other than PreToolUse get no PreToolUse-shaped deny", async () => {
    process.env.NODE_OPTIONS = "--require=/tmp/evil.js";
    const { runHook } = await import("../src/hooks/handler.js");
    for (const event of ["SessionStart", "UserPromptSubmit", "PostToolUse", "Stop"]) {
      let out = "";
      await runHook(event, {
        readStdin: async () => "{}",
        writeStdout: (s) => {
          out += s;
        },
      });
      expect(out, event).toBe("");
    }
  });

  it("a preload flag in execArgv is denied at the hook entry too", () => {
    expect(enforceHookEnvNodeOptions({ log: () => {}, execArgv: ["--require", "/tmp/e.js"] })).toBe("exec_argv");
    expect(RUNTIME_SELF005_EXEC_ARGV_MESSAGE).toContain("SELF005");
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
      expect(enforceHookEnvNodeOptions({ log: () => {} })).toBe("node_options");
    }
  });

  it("allows listed flags, unset and empty at the hook entry", () => {
    process.env.NODE_OPTIONS = "--no-warnings --enable-source-maps";
    expect(enforceHookEnvNodeOptions({ log: () => {}, execArgv: [] })).toBeNull();
    delete process.env.NODE_OPTIONS;
    expect(enforceHookEnvNodeOptions({ log: () => {}, execArgv: [] })).toBeNull();
    process.env.NODE_OPTIONS = "";
    expect(enforceHookEnvNodeOptions({ log: () => {}, execArgv: [] })).toBeNull();
  });

  it("denies unparseable input at the hook entry", () => {
    process.env.NODE_OPTIONS = '--no-warnings "--require=x';
    expect(enforceHookEnvNodeOptions({ log: () => {} })).toBe("node_options");
  });
});

describe("execArgv preload flags", () => {
  const denied = [
    ["--require", "/tmp/e.js"],
    ["--require=/tmp/e.js"],
    ["-r", "/tmp/e.js"],
    ["-r=/tmp/e.js"],
    ["-r/tmp/e.js"],
    ["--import", "/tmp/e.mjs"],
    ["--import=/tmp/e.mjs"],
    ["--loader=/tmp/l.mjs"],
    ["--experimental-loader", "/tmp/l.mjs"],
    ["--eval", "1"],
    ["-e", "1"],
    ["-p", "1"],
    ["--inspect"],
    ["--inspect-brk=0"],
    ["--conditions", "node", "--require", "/tmp/e.js"],
    ["--REQUIRE=/tmp/e.js"],
    ["--\uFF52equire=/tmp/e.js"],
  ];
  for (const argv of denied) {
    it(`denies ${JSON.stringify(argv)}`, () => {
      expect(execArgvIsDisallowed(argv)).toBe(true);
    });
  }

  const allowed = [
    [],
    ["--conditions", "node", "--conditions", "development"],
    ["--max-old-space-size=4096"],
    ["--enable-source-maps", "--no-warnings"],
  ];
  for (const argv of allowed) {
    it(`allows ${JSON.stringify(argv)}`, () => {
      expect(execArgvIsDisallowed(argv)).toBe(false);
    });
  }

  it("CLI startup denies a preload flag in execArgv and exits 1", () => {
    const exits: number[] = [];
    const logs: string[] = [];
    expect(
      enforceCliEnvNodeOptions({
        value: undefined,
        execArgv: ["--require", "/tmp/e.js"],
        exit: (c) => exits.push(c),
        log: (l) => logs.push(l),
      }),
    ).toBe(true);
    expect(exits).toEqual([1]);
    expect(logs.join("")).toContain(RUNTIME_SELF005_RULE);
  });
});

describe("entry answers hook and cursor-hook with the host's deny and exit 2", () => {
  async function entry(argv: string[], value = "--require=/tmp/evil.js") {
    const exits: number[] = [];
    let stdout = "";
    let stderr = "";
    const logs: string[] = [];
    await startAgentreelCli({
      value,
      argv,
      exit: (c) => exits.push(c),
      log: (l) => logs.push(l),
      writeStdout: (t) => {
        stdout += t;
      },
      writeStderr: (t) => {
        stderr += t;
      },
    });
    return { exits, stdout, stderr, logs };
  }

  it("`hook PreToolUse` writes the Claude PreToolUse deny, a stderr reason, and exits 2", async () => {
    const r = await entry(["hook", "PreToolUse"]);
    expect(r.exits).toEqual([HOOK_DENY_EXIT_CODE]);
    expect(HOOK_DENY_EXIT_CODE).toBe(2);
    expect(JSON.parse(r.stdout)).toEqual({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "deny",
        permissionDecisionReason: RUNTIME_SELF005_MESSAGE,
      },
    });
    expect(r.stderr).toContain("SELF005");
    expect(r.logs.join("")).toContain(RUNTIME_SELF005_RULE);
  });

  it("Claude events without a deny shape print nothing on stdout and exit 1 with the reason on stderr", async () => {
    for (const event of ["SessionStart", "SessionEnd", "UserPromptSubmit", "PostToolUse", "Stop"]) {
      const r = await entry(["hook", event]);
      expect(r.exits, event).toEqual([1]);
      expect(r.stdout, event).toBe("");
      expect(r.stderr, event).toContain("SELF005");
    }
  });

  it("`cursor-hook` pre-exec events write the Cursor deny shape and exit 2", async () => {
    for (const event of ["preToolUse", "beforeShellExecution", "beforeMCPExecution", "beforeReadFile"]) {
      const r = await entry(["cursor-hook", event]);
      expect(r.exits, event).toEqual([2]);
      const body = JSON.parse(r.stdout) as Record<string, unknown>;
      expect(body.permission, event).toBe("deny");
      expect(body.user_message, event).toBe(RUNTIME_SELF005_MESSAGE);
      expect(r.stderr, event).toContain("SELF005");
    }
  });

  it("`cursor-hook` with an unknown or missing event fails closed with the pre-exec shape", async () => {
    for (const argv of [["cursor-hook", "somethingNew"], ["cursor-hook"]]) {
      const r = await entry(argv);
      expect(r.exits, argv.join(" ")).toEqual([2]);
      expect((JSON.parse(r.stdout) as { permission: string }).permission).toBe("deny");
    }
  });

  it("`cursor-hook` capture-only events print nothing and exit 1", async () => {
    for (const event of ["afterFileEdit", "postToolUse", "stop"]) {
      const r = await entry(["cursor-hook", event]);
      expect(r.exits, event).toEqual([1]);
      expect(r.stdout, event).toBe("");
    }
  });

  it("finds the subcommand after leading flags", async () => {
    const r = await entry(["--no-color", "hook", "PreToolUse"]);
    expect(r.exits).toEqual([2]);
  });

  it("an execArgv preload is denied for hooks with exit 2 and the execArgv reason", async () => {
    const exits: number[] = [];
    let stdout = "";
    let stderr = "";
    await startAgentreelCli({
      value: undefined,
      execArgv: ["--import", "/tmp/e.mjs"],
      argv: ["hook", "PreToolUse"],
      exit: (c) => exits.push(c),
      log: () => {},
      writeStdout: (t) => {
        stdout += t;
      },
      writeStderr: (t) => {
        stderr += t;
      },
    });
    expect(exits).toEqual([2]);
    expect(stdout).toContain(RUNTIME_SELF005_EXEC_ARGV_MESSAGE);
    expect(stderr).toContain("preload or loader flag");
  });

  it("other commands exit 1 and print no hook JSON", async () => {
    const r = await entry(["doctor"]);
    expect(r.exits).toEqual([1]);
    expect(r.stdout).toBe("");
    expect(r.logs.join("")).toContain(RUNTIME_SELF005_RULE);
  });
});
