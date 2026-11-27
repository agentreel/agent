import { describe, expect, it } from "vitest";
import { chooseHookPrefix, npxHookPrefix } from "../src/commands/hook-prefix.js";

const base = { isEphemeral: true, quotedAbsolutePath: "'/usr/lib/agentreel/dist/cli.js'" };

describe("npxHookPrefix", () => {
  it("pins a stable version exactly", () => {
    expect(npxHookPrefix("0.3.0")).toBe("npx -y @agentreel/agent@0.3.0");
  });

  it("pins an alpha prerelease exactly, so hooks never drift to latest", () => {
    expect(npxHookPrefix("0.3.0-alpha.1")).toBe("npx -y @agentreel/agent@0.3.0-alpha.1");
  });

  it("pins a beta prerelease exactly, not the moving @beta dist-tag", () => {
    const prefix = npxHookPrefix("0.3.0-beta.12");
    expect(prefix).toBe("npx -y @agentreel/agent@0.3.0-beta.12");
    expect(prefix).not.toMatch(/@beta$/);
    expect(prefix).not.toMatch(/@latest$/);
  });

  it("leaves unreleased build placeholders unpinned", () => {
    for (const v of ["dev", "test", "", "0.3", "v0.3.0", "0.3.0 && rm -rf ~", "0.3.0-beta.1;id"]) {
      expect(npxHookPrefix(v)).toBe("npx -y @agentreel/agent");
    }
  });
});

describe("chooseHookPrefix", () => {
  it("uses the pinned npx prefix for an npx install", () => {
    expect(chooseHookPrefix({ ...base, version: "0.3.0-beta.1" })).toEqual({
      prefix: "npx -y @agentreel/agent@0.3.0-beta.1",
      mode: "npx",
    });
  });

  it("uses the absolute path for a global or in-tree install, whatever the version", () => {
    expect(chooseHookPrefix({ ...base, isEphemeral: false, version: "0.3.0-beta.1" })).toEqual({
      prefix: "'/usr/lib/agentreel/dist/cli.js'",
      mode: "absolute",
    });
  });

  it("lets AGENTREEL_HOOK_COMMAND override everything", () => {
    expect(
      chooseHookPrefix({ ...base, hookCommandOverride: "/opt/agentreel", version: "0.3.0-alpha.2" }),
    ).toEqual({ prefix: "/opt/agentreel", mode: "absolute" });
  });

  it("ignores an empty AGENTREEL_HOOK_COMMAND", () => {
    expect(chooseHookPrefix({ ...base, hookCommandOverride: "", version: "0.3.0" }).prefix).toBe(
      "npx -y @agentreel/agent@0.3.0",
    );
  });
});
