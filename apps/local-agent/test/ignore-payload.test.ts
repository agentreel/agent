import { describe, expect, it } from "vitest";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { IGNORED_MARK, applyIgnoreRules } from "../src/hooks/ignore-payload.js";

const ws = mkdtempSync(join(tmpdir(), "ar-ignore-"));
writeFileSync(join(ws, ".agentreelignore"), "secrets/\n*.pem\n");

describe("applyIgnoreRules (Claude Code)", () => {
  it("drops contents of edits to ignored files but keeps the event", () => {
    const out = applyIgnoreRules({
      cwd: ws,
      tool_name: "Edit",
      tool_input: { file_path: join(ws, "secrets/prod.yaml"), old_string: "a: 1", new_string: "a: 2" },
      tool_response: { ok: true },
    });
    expect(out.tool_input).toMatchObject({ file_path: join(ws, "secrets/prod.yaml"), old_string: IGNORED_MARK, new_string: IGNORED_MARK, ignored: true });
    expect(out.tool_response).toEqual({ ignored: true });
  });

  it("drops Read output and Write content, including relative paths", () => {
    const read = applyIgnoreRules({ cwd: ws, tool_input: { file_path: "server.pem" }, tool_response: { file: "-----BEGIN" } });
    expect(read.tool_response).toEqual({ ignored: true });
    const write = applyIgnoreRules({ cwd: ws, tool_input: { file_path: "secrets/x.env", content: "K=V" } });
    expect(write.tool_input?.content).toBe(IGNORED_MARK);
  });

  it("leaves other files alone", () => {
    const input = { cwd: ws, tool_input: { file_path: join(ws, "src/app.ts"), new_string: "x" } };
    expect(applyIgnoreRules(input)).toBe(input);
  });
});
